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
    internal static byte[] AllocatePinnedEncryptedState(int length) =>
        GC.AllocateArray<byte>(length, pinned: true);

    internal static void ZeroOnly(byte[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    internal static byte[] AllocatePinnedBytes(
        int length, bool excludeFromDumps = false, string lockContext = "memory locking") =>
        AllocatePinnedCore<byte>(length, excludeFromDumps, lockContext);

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
                MemoryLocker.TryUnlock(buffer);
                throw;
            }
        }
        return buffer;
    }

    internal static void ZeroBytes(byte[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
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
