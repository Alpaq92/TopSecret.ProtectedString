using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TopSecret.Cryptography;

namespace TopSecret;

/// <summary>Pinned / locked / dump-excluded buffer allocation and the matching wipe helpers shared with the satellite assemblies.</summary>
public sealed partial class ProtectedString
{
    /// <summary>
    /// Allocates a pinned array for encrypted state (ciphertext / nonce /
    /// tag). Deliberately <b>not</b> locked or dump-excluded: the contents
    /// are safe to swap or dump by construction, and keeping these high-churn
    /// buffers off the page-granular, non-refcounted lock/unlock path removes
    /// their interference with pages legitimately locked for plaintext and
    /// key material.
    /// </summary>
    internal static byte[] AllocatePinnedEncryptedState(int length) =>
        GC.AllocateArray<byte>(length, pinned: true);

    /// <summary>
    /// Wipes encrypted state without the unlock / dump re-include step —
    /// these buffers are never locked (see
    /// <see cref="AllocatePinnedEncryptedState"/>), and an <c>munlock</c> on
    /// their pages could drop a lock legitimately held by a neighbouring
    /// locked buffer.
    /// </summary>
    internal static void ZeroOnly(byte[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>
    /// Allocates a pinned <see cref="byte"/> array and locks it into resident
    /// memory; on lock failure the policy in
    /// <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/> is
    /// applied via <see cref="HardeningPolicy.OnFailure(string)"/>.
    /// </summary>
    /// <param name="length">Number of bytes to allocate.</param>
    /// <param name="excludeFromDumps">
    /// <see langword="true"/> for buffers that will hold plaintext or key
    /// material — the buffer is additionally excluded from OS crash dumps via
    /// <see cref="DumpExclusion"/> where the platform supports it. Ciphertext,
    /// nonce, and tag buffers pass <see langword="false"/>: their contents are
    /// already safe to dump, and on Windows each exclusion consumes one of
    /// WER's 512 registration slots.
    /// </param>
    /// <param name="lockContext">
    /// Noun phrase interpolated into the policy failure for the lock step —
    /// lets protector call sites keep their site-specific messages while
    /// sharing this one allocate/lock/exclude implementation.
    /// </param>
    internal static byte[] AllocatePinnedBytes(
        int length, bool excludeFromDumps = false, string lockContext = "memory locking") =>
        AllocatePinnedCore<byte>(length, excludeFromDumps, lockContext);

    /// <summary>
    /// Allocates a pinned <see cref="char"/> array and locks it into resident
    /// memory; on lock failure the policy in
    /// <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/> is
    /// applied via <see cref="HardeningPolicy.OnFailure(string)"/>.
    /// </summary>
    private static char[] AllocatePinnedChars(int length) =>
        // Every char[] this type allocates holds plaintext (build buffer,
        // decrypt scratch, materialized copies) — always dump-exclude.
        AllocatePinnedCore<char>(length, excludeFromDumps: true, lockContext: "memory locking");

    private static T[] AllocatePinnedCore<T>(int length, bool excludeFromDumps, string lockContext)
        where T : unmanaged
    {
        var buffer = GC.AllocateArray<T>(length, pinned: true);
        if (length > 0 && !MemoryLocker.TryLock(buffer))
        {
            HardeningPolicy.OnFailure(lockContext);
        }
        if (excludeFromDumps && length > 0 && !DumpExclusion.TryExclude(buffer))
        {
            try
            {
                HardeningPolicy.OnFailure("core-dump exclusion");
            }
            catch
            {
                // Throw policy: GC reclaim does not munlock — release the
                // lock before surfacing, or every retried operation leaks
                // locked pages until the RLIMIT_MEMLOCK / working-set budget
                // is gone.
                MemoryLocker.TryUnlock(buffer);
                throw;
            }
        }
        return buffer;
    }

    /// <summary>
    /// Zeroes and unlocks a pinned, locked buffer. Internal so sibling
    /// assemblies (<c>TopSecret.ProtectedBlob</c>) share the one
    /// wipe-before-unlock implementation, mirroring
    /// <see cref="AllocatePinnedBytes"/>.
    /// </summary>
    /// <remarks>
    /// Residual: <c>VirtualLock</c>/<c>mlock</c> are page-granular and
    /// non-refcounted, so unlocking this buffer may drop the residency lock
    /// of a POH page it shares with another still-live locked buffer.
    /// <see cref="LockedScratchPool"/> removed this decay for the hot
    /// per-operation scratch (pooled slabs are never unlocked); what remains
    /// on this per-buffer path are short-lived standalone buffers (legacy
    /// <c>char[]</c> access copies, UTF-8/Argon2 byte staging, protector
    /// ephemerals, <c>ProtectedBlob</c> scratch), so the exposure is a narrow
    /// transient-overlap window rather than systematic decay. Encrypted state
    /// (ciphertext / nonce / tag) is no longer locked at all and bypasses
    /// this method entirely.
    /// </remarks>
    internal static void ZeroBytes(byte[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
            // Wipe before unlock: the data is overwritten with zeros while the
            // page is still guaranteed resident. Once unlocked, the OS may
            // page it out, but it now contains zeros so paging is harmless.
            CryptographicOperations.ZeroMemory(buffer);
            MemoryLocker.TryUnlock(buffer);
        }
    }

    private static void ZeroChars(char[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));
            MemoryLocker.TryUnlock(buffer);
        }
    }
}
