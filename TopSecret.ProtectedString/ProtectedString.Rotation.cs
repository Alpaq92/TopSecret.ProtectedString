using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TopSecret.Cryptography;

namespace TopSecret;

public sealed partial class ProtectedString
{
    // ---- process-key rotation -------------------------------------------

    public static void RotateProcessKey() => TryRotateProcessKey();

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

            ProtectorLifetime.MarkSuperseded(oldProtector);
        }

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

        if (failed > 0)
        {
            Trace.TraceWarning(
                $"ProtectedString: process-key rotation completed with {failed} instance(s) " +
                "failing to re-encrypt; those instances still reference the previous master.");
        }
    }

    private void RotateUnderNewKey(KeyAtRestProtector newProtector)
    {
        lock (_sync)
        {
            if (_disposed) return;
            if (ReferenceEquals(_instanceProtector, newProtector)) return;
            var old = _instanceProtector;

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
