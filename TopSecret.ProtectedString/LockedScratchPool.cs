using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TopSecret;

internal static class LockedScratchPool
{
    private const int MinChunk = 64;
    private const int MaxChunk = 4 * 1024;
    private const int SlabBytes = 16 * 1024;
    private const int ClassCount = 7; // 64, 128, ..., 4096

    private static readonly object s_lock = new();
    private static readonly Stack<(byte[] Slab, int Offset)>[] s_free = CreateFreeLists();

    private static byte[]? s_currentSlab;
    private static int s_currentEnd;   // exclusive end of the aligned window
    private static int s_bump;         // next uncarved offset in the current slab

    private static Stack<(byte[], int)>[] CreateFreeLists()
    {
        var lists = new Stack<(byte[], int)>[ClassCount];
        for (int i = 0; i < lists.Length; i++) lists[i] = new Stack<(byte[], int)>();
        return lists;
    }

    public static Lease Rent(int sizeBytes)
    {
        if (sizeBytes > MaxChunk)
        {
            return new Lease(
                ProtectedString.AllocatePinnedBytes(sizeBytes, excludeFromDumps: true),
                offset: 0, size: sizeBytes, pooled: false);
        }

        int cls = ClassIndex(sizeBytes);
        int chunk = MinChunk << cls;
        lock (s_lock)
        {
            if (s_free[cls].TryPop(out var entry))
            {
                return new Lease(entry.Slab, entry.Offset, chunk, pooled: true);
            }

            if (s_currentSlab is null || s_bump + chunk > s_currentEnd)
            {
                NewSlabLocked();
            }

            var lease = new Lease(s_currentSlab!, s_bump, chunk, pooled: true);
            s_bump += chunk;
            return lease;
        }
    }

    private static int ClassIndex(int sizeBytes)
    {
        uint size = (uint)Math.Max(sizeBytes, MinChunk);
        int cls = BitOperations.Log2(BitOperations.RoundUpToPowerOf2(size)) - 6;
        return cls;
    }

    private static void NewSlabLocked()
    {
        long page = Environment.SystemPageSize;
        var raw = GC.AllocateArray<byte>(SlabBytes + (int)page, pinned: true);
        long addr0 = Marshal.UnsafeAddrOfPinnedArrayElement(raw, 0).ToInt64();
        int baseOffset = (int)((page - (addr0 % page)) % page);
        var alignedAddr = (IntPtr)(addr0 + baseOffset);

        HardeningPolicy.LockAndExcludeRange(alignedAddr, SlabBytes, "memory locking");

        s_currentSlab = raw;
        s_bump = baseOffset;
        s_currentEnd = baseOffset + SlabBytes;
    }

    internal static void ReturnChunk(byte[] slab, int offset, int size)
    {
        lock (s_lock)
        {
            s_free[ClassIndex(size)].Push((slab, offset));
        }
    }

    internal sealed class Lease
    {
        private readonly byte[] _array;
        private readonly int _offset;
        private readonly int _size;
        private readonly bool _pooled;
        private int _returned;

        internal Lease(byte[] array, int offset, int size, bool pooled)
        {
            _array = array;
            _offset = offset;
            _size = size;
            _pooled = pooled;
        }

        internal bool IsPooled => _pooled;

        internal int Offset => _offset;

        internal Span<byte> Bytes(int length)
        {
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, _size);
            return _array.AsSpan(_offset, length);
        }

        internal Span<char> Chars(int lengthChars) =>
            MemoryMarshal.Cast<byte, char>(_array.AsSpan(_offset, _size))[..lengthChars];

        internal void Return()
        {
            if (Interlocked.Exchange(ref _returned, 1) != 0) return;
            if (_pooled)
            {
                CryptographicOperations.ZeroMemory(_array.AsSpan(_offset, _size));
                ReturnChunk(_array, _offset, _size);
            }
            else
            {
                ProtectedString.ZeroBytes(_array);
            }
        }
    }
}
