using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TopSecret;

/// <summary>
/// Process-wide pool of page-aligned, locked, dump-excluded slabs serving the
/// transient plaintext scratch that <see cref="ProtectedString"/> rents on
/// every decrypt/encrypt operation.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a pool.</b> <c>VirtualLock</c> / <c>mlock</c> and
/// <c>madvise(MADV_DONTDUMP)</c> are page-granular and non-refcounted, while
/// per-operation scratch buffers are arbitrary pinned-object-heap arrays that
/// share pages with unrelated allocations. Under the per-buffer scheme, every
/// scratch wipe's unlock could silently drop the residency lock (and dump
/// exclusion) of a page shared with a still-live locked buffer — the master
/// key being the most likely victim, since it is allocated early amid the
/// first operation's scratch. Slabs fix this class of decay: the pool locks
/// and dump-excludes each slab's page-aligned interior once at creation, the
/// pages are used exclusively for sensitive scratch, and they are never
/// unlocked or re-included for the life of the process. Renting and returning
/// a chunk touches no syscalls.
/// </para>
/// <para>
/// <b>Sizing.</b> Chunks are power-of-two classes from 64 B to 4 KiB; a
/// request above 4 KiB bypasses the pool onto a dedicated
/// pinned+locked+excluded array (the pre-pool behaviour). Slabs are 16 KiB
/// plus one page of alignment slack — deliberately a quarter of the legacy
/// 64 KiB unprivileged <c>RLIMIT_MEMLOCK</c> default on Linux, so the first
/// slab cannot single-handedly exhaust a tightly-limited container's budget
/// that the master key and per-buffer allocations also draw from — and the
/// slab count grows only with peak concurrent scratch demand. Slabs are
/// deliberately never retired: retirement would reintroduce the
/// unlock/re-include aliasing this type exists to remove, and the
/// steady-state footprint (typically one slab) is small.
/// </para>
/// <para>
/// <b>Ownership discipline.</b> A rented chunk's backing slab array must never
/// escape to caller-supplied code — a captured slab reference would alias
/// every future secret staged in that slab. Pool consumers hand out only
/// <see cref="Span{T}"/> views (which the <c>ref struct</c> rules keep from
/// escaping); anything that must expose a real <c>byte[]</c>/<c>char[]</c> to
/// external code (the legacy <c>Access(Action&lt;char[]&gt;)</c> family,
/// <c>KeyAccessor</c> buffers, <c>Stream.Write</c> staging) stays on
/// dedicated per-buffer allocations.
/// </para>
/// <para>
/// <see cref="Lease.Return"/> zeroes the full chunk before it re-enters the
/// free list, and a double-<c>Return</c> is a guarded no-op — a chunk can
/// never sit in the free list twice.
/// </para>
/// </remarks>
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

    /// <summary>
    /// Rents a wiped chunk of at least <paramref name="sizeBytes"/> bytes of
    /// locked, dump-excluded scratch. Requests above 4 KiB fall back to a
    /// dedicated pinned+locked+excluded array with identical
    /// <see cref="Lease"/> semantics.
    /// </summary>
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

        // Policy applies once per slab instead of once per buffer; Throw
        // still fails at the first allocation that needed the guarantee.
        // Field assignment happens after the policy calls so a Throw leaves
        // no half-initialised slab behind.
        if (!MemoryLocker.TryLockRange(alignedAddr, SlabBytes))
        {
            HardeningPolicy.OnFailure("memory locking");
        }
        if (!DumpExclusion.TryExcludeRange(alignedAddr, SlabBytes))
        {
            try
            {
                HardeningPolicy.OnFailure("core-dump exclusion");
            }
            catch
            {
                // Throw policy: release the just-taken lock before
                // surfacing — otherwise every retried Rent would abandon a
                // permanently locked slab, bleeding the process's
                // RLIMIT_MEMLOCK / working-set budget.
                MemoryLocker.TryUnlockRange(alignedAddr, SlabBytes);
                throw;
            }
        }

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

    /// <summary>
    /// A rented scratch chunk. Expose only <see cref="Bytes"/> /
    /// <see cref="Chars"/> spans to consuming code — never the backing array —
    /// and call <see cref="Return"/> in a <c>finally</c>. <see cref="Return"/>
    /// zeroes the full chunk; double-return is a no-op.
    /// </summary>
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

        /// <summary>Whether this lease came from a slab (vs. the oversize bypass). Test hook.</summary>
        internal bool IsPooled => _pooled;

        /// <summary>Chunk offset within the backing array. Test hook.</summary>
        internal int Offset => _offset;

        internal Span<byte> Bytes(int length)
        {
            // The slab bounds-check alone would let an oversized length
            // silently alias the NEXT live chunk in the shared slab — clamp
            // to this lease's chunk explicitly.
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, _size);
            return _array.AsSpan(_offset, length);
        }

        /// <summary>
        /// A <see cref="char"/> view over the chunk. Chunks are carved in
        /// 64-byte units from a window that is page-aligned in absolute
        /// address space, so every chunk's address is 64-byte aligned and the
        /// 2-byte view is always well-aligned.
        /// </summary>
        internal Span<char> Chars(int lengthChars) =>
            MemoryMarshal.Cast<byte, char>(_array.AsSpan(_offset, _size))[..lengthChars];

        internal void Return()
        {
            // Interlocked: the guard is the pool's last line of defence for
            // the no-aliasing invariant, so it must hold even if two threads
            // race a double-Return — a chunk must never enter the free list
            // twice.
            if (Interlocked.Exchange(ref _returned, 1) != 0) return;
            if (_pooled)
            {
                CryptographicOperations.ZeroMemory(_array.AsSpan(_offset, _size));
                ReturnChunk(_array, _offset, _size);
            }
            else
            {
                // Dedicated oversize array (offset 0, full length): identical
                // teardown to every other standalone locked buffer via the
                // shared wipe funnel (zero, unlock, dump re-include).
                ProtectedString.ZeroBytes(_array);
            }
        }
    }
}
