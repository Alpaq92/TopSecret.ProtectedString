using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TopSecret;

/// <summary>
/// Holds the master AES key on its own dedicated page, marked
/// <see cref="PageAccess.NoAccess"/> (Windows <c>PAGE_NOACCESS</c> / POSIX
/// <c>PROT_NONE</c>) except during the brief window of an
/// <see cref="UnwrapKey"/>. A passive scan that walks the process's mapped
/// memory <b>faults</b> on the key page between operations instead of reading
/// the master — the first mechanism in the library that raises the bar against
/// the arbitrary-read in-process attacker the threat model otherwise concedes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a dedicated OS mapping.</b> The page is mapped straight from the OS
/// via <see cref="MemoryProtection.TryAllocatePage"/> (<c>VirtualAlloc</c> /
/// <c>mmap</c>), not from the managed heap or the C runtime heap. Marking a
/// GC-owned page <c>PROT_NONE</c> would risk a collector touch faulting; a heap
/// block would put allocator metadata beside the page and return it to a
/// reusable heap on free. A standalone mapping the GC never inspects and the OS
/// reclaims outright on <see cref="MemoryProtection.FreePage"/> sidesteps both.
/// </para>
/// <para>
/// <b>What it does and does not protect.</b> Between operations the only copy
/// of the master lives on the faulting page. During an unwrap the key is
/// briefly copied into a pinned, locked, dump-excluded ephemeral (the same
/// shape the hardware-backed and obscurity tiers already use), which
/// <see cref="KeyAccessor.Dispose"/> wipes — that in-flight window is the one
/// the threat model already accepts. Pair with
/// <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/> to amortise the
/// per-op protect/copy/protect cost on hot paths.
/// </para>
/// <para>
/// Not available on browser-wasm (no page-protection primitive); the factory
/// falls back to the obscurity tier there.
/// </para>
/// </remarks>
internal sealed class PageGuardedKeyProtector : KeyAtRestProtector, IDisposable
{
    private const int MasterKeySize = 32;

    private readonly object _gate = new();
    private readonly IntPtr _page;
    private readonly nuint _pageSize;
    private bool _disposed;

    private PageGuardedKeyProtector(IntPtr page, nuint pageSize)
    {
        _page = page;
        _pageSize = pageSize;
    }

    /// <summary>
    /// Copies <paramref name="master"/> onto a freshly mapped guarded page and
    /// returns the sealed protector — or <see langword="null"/> when this tier
    /// declines, in which case <paramref name="master"/> is left <b>intact</b>
    /// for the factory's obscurity fallback. It declines on: no page-protection
    /// primitive (browser-wasm), a mapping failure, or a seal failure under a
    /// non-<see cref="MemoryLockingFailureBehavior.Throw"/> policy. Under a
    /// <c>Throw</c> policy a hardening failure throws instead (and the master
    /// residue is wiped first).
    /// </summary>
    /// <remarks>
    /// Declining on a seal failure — rather than returning a "guarded" page
    /// that never became no-access — hands the intact master to the obscurity
    /// tier, a strictly stronger posture than a readable page: obscurity at
    /// least wraps the key. The input is zeroed only once the page is sealed,
    /// so the fallback still receives a usable master.
    /// </remarks>
    internal static PageGuardedKeyProtector? TryCreate(byte[] master)
    {
        if (master.Length != MasterKeySize) return null;

        IntPtr page = MemoryProtection.TryAllocatePage(out nuint pageSize);
        if (page == IntPtr.Zero) return null; // unsupported / mapping failed — master intact

        bool masterConsumed = false;
        try
        {
            // Copy the master onto the page. Do NOT zero the input yet: if
            // sealing fails under a non-Throw policy we decline and the intact
            // master feeds the obscurity fallback.
            Marshal.Copy(master, 0, page, MasterKeySize);

            // Lock resident, dump-exclude, and wipe-on-fork the dedicated page.
            // The mapping is ours alone, so page-granular primitives have no
            // neighbour to disturb. (Throws under a Throw policy on failure.)
            HardeningPolicy.LockAndExcludeRange(page, (int)pageSize, "memory locking the guarded master page");

            // Seal: no access until an unwrap opens the window.
            if (!MemoryProtection.TryProtect(page, pageSize, PageAccess.NoAccess))
            {
                HardeningPolicy.OnFailure("page protection of the guarded master key"); // throws under Throw
                // Non-Throw policy: decline so the factory falls back to
                // obscurity (which wraps the key) instead of shipping a
                // guarded page that is actually readable.
                TearDown(page, pageSize);
                return null; // master intact
            }

            CryptographicOperations.ZeroMemory(master);
            masterConsumed = true;
            return new PageGuardedKeyProtector(page, pageSize);
        }
        catch
        {
            // Throw policy (or any failure): wipe the master residue (input and
            // the page copy) and release the mapping.
            if (!masterConsumed) CryptographicOperations.ZeroMemory(master);
            TearDown(page, pageSize);
            throw;
        }
    }

    public override KeyAccessor UnwrapKey()
    {
        // Ephemeral copy out of the guarded page, matching the hardware-backed
        // and obscurity tiers' KeyAccessor.Dispose contract (zero + unlock on
        // dispose). The page is readable only for the length of the memcpy.
        var ephemeral = ProtectedString.AllocatePinnedBytes(
            MasterKeySize, excludeFromDumps: true, lockContext: "memory locking unwrapped key");

        bool ok = false;
        try
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                try
                {
                    // Only read the page if it actually became readable —
                    // dereferencing a page still marked NoAccess faults with an
                    // AccessViolation that no catch/finally can handle.
                    if (!MemoryProtection.TryProtect(_page, _pageSize, PageAccess.ReadOnly))
                    {
                        throw new CryptographicException(
                            "PageGuardedKeyProtector: failed to make the guarded master page readable for unwrap.");
                    }
                    Marshal.Copy(_page, ephemeral, 0, MasterKeySize);
                    ok = true;
                }
                finally
                {
                    MemoryProtection.TryProtect(_page, _pageSize, PageAccess.NoAccess);
                }
            }
        }
        finally
        {
            // Wipe + release the ephemeral on any failure path — including the
            // disposed-check throw, which fires before the inner try above.
            if (!ok)
            {
                CryptographicOperations.ZeroMemory(ephemeral);
                MemoryLocker.TryUnlock(ephemeral);
            }
        }
        return KeyAccessor.Ephemeral(ephemeral);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            TearDown(_page, _pageSize);
        }
        GC.SuppressFinalize(this);
    }

    ~PageGuardedKeyProtector()
    {
        // Match every other protector's finalizer safety net. No lock: a
        // finalizer-eligible object is unreachable from other threads.
        if (_disposed) return;
        try { TearDown(_page, _pageSize); } catch { /* finalizer must not throw */ }
    }

    private static void TearDown(IntPtr page, nuint pageSize)
    {
        if (page == IntPtr.Zero) return;
        // Reopen for writing, zero the key bytes, then release the residency
        // lock, the dump-exclusion entry, and the mapping. Only zero if the
        // page actually became writable — writing a still-NoAccess page would
        // fault (fatal in a finalizer). If the reprotect failed the key bytes
        // aren't wiped before free, but that beats crashing; the failure is a
        // near-impossibility on a page we sealed ourselves.
        if (MemoryProtection.TryProtect(page, pageSize, PageAccess.ReadWrite))
        {
            unsafe { NativeMemory.Clear((void*)page, (nuint)MasterKeySize); }
        }
        MemoryLocker.TryUnlockRange(page, (int)pageSize);
        // Return the Windows WER slot; on libc this is a no-op (the advice is
        // discarded when FreePage unmaps the pages back to the OS anyway).
        DumpExclusion.TryIncludeRange(page, (int)pageSize);
        MemoryProtection.FreePage(page, pageSize);
    }
}
