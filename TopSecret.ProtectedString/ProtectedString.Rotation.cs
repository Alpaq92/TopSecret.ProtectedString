using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TopSecret.Cryptography;

namespace TopSecret;

/// <summary>Process-key rotation: the registry walk, per-instance re-encryption, and the periodic timer. See the main file for the static protector slot and registration.</summary>
public sealed partial class ProtectedString
{
    // ---- process-key rotation -------------------------------------------

    /// <summary>
    /// Generates a fresh master AES key, swaps it in as the current process
    /// protector, and re-encrypts every live <see cref="ProtectedString"/>
    /// under the new key. The superseded protector is disposed — its master
    /// zeroed, any hardware-backed transient slot released — as soon as its
    /// last holder lets go (tracked by <see cref="ProtectorLifetime"/>); when
    /// every live instance migrates successfully and nothing else references
    /// it, that happens before this method returns. Holders that outlive the
    /// rotation (failed migrations, instances constructed under a
    /// <see cref="ProcessKeyRotation.Disabled"/> policy, and
    /// <c>ProtectedBlob</c> instances, which rotation never re-encrypts)
    /// keep the old protector alive until they are disposed.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// <see cref="ProtectedStringOptions.ProcessKeyRotationPolicy"/> is
    /// <see cref="ProcessKeyRotation.Disabled"/> — the registry of live
    /// instances is not maintained, so rotation cannot be performed.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Lock semantics: <see cref="s_rotationLock"/> is held only for the
    /// brief swap-and-snapshot phase. Per-instance migration runs outside
    /// that lock and acquires each instance's <c>_sync</c> in turn — concurrent
    /// operations on instances <i>not</i> currently being migrated proceed
    /// unblocked.
    /// </para>
    /// <para>
    /// Reentrancy: a second concurrent call returns immediately without
    /// rotating, guarded by <see cref="s_rotationInFlight"/>. The periodic
    /// timer relies on this so a slow rotation cannot pile up callbacks.
    /// </para>
    /// </remarks>
    public static void RotateProcessKey() => TryRotateProcessKey();

    /// <summary>
    /// Same as <see cref="RotateProcessKey"/>, but reports whether this call
    /// performed the rotation. Returns <see langword="false"/> when another
    /// rotation was already in flight and this call was dropped — the case
    /// <see cref="RotateProcessKey"/> cannot distinguish. A caller reacting
    /// to a compromise signal can loop on <see langword="false"/> (or
    /// otherwise confirm) instead of assuming the key moved.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> if a rotation pass ran to completion in this
    /// call; <see langword="false"/> if a concurrent pass was already running.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// <see cref="ProtectedStringOptions.ProcessKeyRotationPolicy"/> is
    /// <see cref="ProcessKeyRotation.Disabled"/>.
    /// </exception>
    public static bool TryRotateProcessKey()
    {
        if (ProtectedStringOptions.ProcessKeyRotationPolicy == ProcessKeyRotation.Disabled)
        {
            throw new InvalidOperationException(
                "ProtectedString: process-key rotation is disabled. " +
                $"Set {nameof(ProtectedStringOptions)}.{nameof(ProtectedStringOptions.ProcessKeyRotationPolicy)} " +
                $"to {nameof(ProcessKeyRotation.OnDemand)} or {nameof(ProcessKeyRotation.Periodic)} " +
                "before any ProtectedString is constructed.");
        }

        if (Interlocked.CompareExchange(ref s_rotationInFlight, 1, 0) != 0)
        {
            // Another rotation is already running — drop this call.
            return false;
        }

        try
        {
            RotateInternal();
            return true;
        }
        finally
        {
            Volatile.Write(ref s_rotationInFlight, 0);
        }
    }

    private static void RotateInternal()
    {
        KeyAtRestProtector oldProtector;
        KeyAtRestProtector newProtector;
        List<ProtectedString> toMigrate;

        // Brief lock: build the new protector, swap globally, snapshot live
        // instances that still hold the old reference, prune dead refs.
        lock (s_rotationLock)
        {
            oldProtector = GetOrInitProtectorLocked();

            var newMaster = GC.AllocateArray<byte>(KeySize, pinned: true);
            RandomNumberGenerator.Fill(newMaster);
            newProtector = KeyAtRestProtectorFactory.Create(newMaster);

            // Once swapped, every new construction snapshots the new protector.
            s_keyProtector = newProtector;

            toMigrate = new List<ProtectedString>(s_liveInstances.Count);
            for (int i = s_liveInstances.Count - 1; i >= 0; i--)
            {
                if (s_liveInstances[i].TryGetTarget(out var instance))
                {
                    if (ReferenceEquals(instance._instanceProtector, oldProtector))
                    {
                        toMigrate.Add(instance);
                    }
                }
                else
                {
                    s_liveInstances.RemoveAt(i);
                }
            }

            // From this point no new holder can acquire oldProtector (the
            // swap above is visible before ProtectorLifetime's full-fence
            // count read — see SnapshotProtectorWithRef). Mark it rotated
            // out; ProtectorLifetime disposes it the moment the holder count
            // hits zero.
            ProtectorLifetime.MarkSuperseded(oldProtector);
        }

        // Outside the rotation lock — migrate one instance at a time. Each
        // migration takes the per-instance _sync, so concurrent ops on an
        // un-migrated instance complete (under the old key) before the
        // migration runs.
        int failed = 0;
        foreach (var instance in toMigrate)
        {
            try
            {
                instance.RotateUnderNewKey(newProtector);
            }
            catch
            {
                failed++;
                // The instance still references the old protector; do not
                // dispose old yet.
            }
        }

        // The old protector was marked superseded above; ProtectorLifetime
        // disposes it (zeroing its master, releasing any TPM / Secure
        // Element transient slot) the moment its holder count reaches zero.
        // For a fully successful pass over registry-tracked instances that
        // already happened inside the loop, when the last migrated instance
        // released its reference. Holders that keep the old protector alive
        // longer — instances that failed to migrate, instances constructed
        // while the policy was Disabled (not in the registry), and
        // ProtectedBlob instances (rotation never re-encrypts blobs) — delay
        // disposal exactly as long as something can still decrypt through it.
        if (failed > 0)
        {
            Trace.TraceWarning(
                $"ProtectedString: process-key rotation completed with {failed} instance(s) " +
                "failing to re-encrypt; those instances still reference the previous master.");
        }
    }

    /// <summary>
    /// Re-encrypts this instance under <paramref name="newProtector"/>. Holds
    /// <see cref="_sync"/> for the entire decrypt-with-old / encrypt-with-new
    /// dance so concurrent operations cannot observe a half-migrated state.
    /// </summary>
    private void RotateUnderNewKey(KeyAtRestProtector newProtector)
    {
        lock (_sync)
        {
            if (_disposed) return;
            if (ReferenceEquals(_instanceProtector, newProtector)) return;
            var old = _instanceProtector;

            // In build mode the plaintext lives in _buildBuffer rather than in
            // ciphertext under the old protector. There is no encrypted state
            // to migrate — just adopt the new protector so the next
            // CommitBuildBuffer (e.g. via MakeReadOnly) encrypts under it.
            if (_buildBuffer is not null)
            {
                ProtectorLifetime.AddRef(newProtector);
                _instanceProtector = newProtector;
                ProtectorLifetime.Release(old);
                return;
            }

            LockedScratchPool.Lease? lease = null;
            try
            {
                var plain = RentPlaintextLocked(out lease);
                ProtectorLifetime.AddRef(newProtector);
                _instanceProtector = newProtector;
                try
                {
                    EncryptInternal(plain);
                }
                catch
                {
                    // Roll the swap back: the ciphertext is still under the
                    // old key, so leaving the new protector installed would
                    // fail every subsequent decrypt with a tag mismatch.
                    _instanceProtector = old;
                    ProtectorLifetime.Release(newProtector);
                    throw;
                }
            }
            finally
            {
                lease?.Return();
            }
            ProtectorLifetime.Release(old);
        }
    }

    private static int s_warnedTransientSlotRotation;

    private static void EnsurePeriodicRotationTimer()
    {
        if (Volatile.Read(ref s_rotationTimer) is not null) return;

        bool shouldWarn = false;
        lock (s_rotationLock)
        {
            if (s_rotationTimer is not null) return;
            var interval = ProtectedStringOptions.ProcessKeyRotationInterval;
            if (interval <= TimeSpan.Zero) return;

            shouldWarn = ShouldWarnRotatingAgainstTransientSlotProvider();

            s_rotationTimer = new Timer(static _ =>
            {
                try { RotateProcessKey(); }
                catch (Exception ex)
                {
                    Trace.TraceError("ProtectedString: periodic rotation failed: " + ex);
                }
            }, null, interval, interval);
        }

        // Emit the warning outside s_rotationLock so a pathological
        // TraceListener cannot stall the global rotation lock.
        if (shouldWarn) EmitTransientSlotRotationWarning();
    }

    /// <summary>
    /// Decide (under the caller's lock) whether the transient-slot warning
    /// should fire on this <see cref="EnsurePeriodicRotationTimer"/> pass.
    /// The actual <see cref="Trace.TraceWarning(string)"/> call runs in
    /// <see cref="EmitTransientSlotRotationWarning"/> after the lock has
    /// been released.
    /// </summary>
    private static bool ShouldWarnRotatingAgainstTransientSlotProvider()
    {
        var mode = ProtectedStringOptions.KeyAtRestProtection;
        if (mode != KeyAtRestProtection.HardwareBackedRequired &&
            mode != KeyAtRestProtection.HardwareBackedPreferred)
        {
            return false;
        }
        if (!KeyAtRestProtectorFactory.HasTransientSlotConstrainedProvider()) return false;
        return Interlocked.CompareExchange(ref s_warnedTransientSlotRotation, 1, 0) == 0;
    }

    /// <summary>
    /// Periodic rotation creates a fresh master each cycle; hardware-backed
    /// providers built on top of transient secure-element slots (TPM 2.0 in
    /// particular — commodity TPMs hold ≤3 transient keys) can still run out
    /// when holders pin superseded protectors across several cycles.
    /// <see cref="ProtectorLifetime"/> releases a superseded protector's slot
    /// deterministically once its last holder migrates or is disposed, so a
    /// clean migration pass frees the slot within the rotation itself — the
    /// residual risk is long-lived <c>ProtectedBlob</c> instances (rotation
    /// never re-encrypts blobs) and failed migrations. Emit a one-shot
    /// warning so the operator knows what to watch for before
    /// <c>TPM_RC_RESOURCES</c> starts surfacing.
    /// </summary>
    private static void EmitTransientSlotRotationWarning()
    {
        Trace.TraceWarning(
            "ProtectedString: ProcessKeyRotation.Periodic with a transient-slot-constrained " +
            "hardware-backed provider (e.g. Windows TPM). Superseded masters release their " +
            "secure-element slot as soon as the last instance encrypted under them migrates or " +
            "is disposed — but long-lived ProtectedBlob instances (never re-encrypted by " +
            "rotation) and failed migrations pin old slots across cycles. Commodity TPMs hold " +
            "≤3 transient keys, so pinned slots can surface as TPM_RC_RESOURCES; if blobs " +
            "routinely outlive several rotation intervals, reduce the rotation cadence, " +
            "dispose and rebuild blobs periodically, or use KeyAtRestProtection.Obscurity / None.");
    }
}
