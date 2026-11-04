using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TopSecret;

/// <summary>
/// Holds the master AES key on its own dedicated page, marked
/// <see cref="PageAccess.NoAccess"/> (Windows <c>PAGE_NOACCESS</c> / POSIX
/// <c>PROT_NONE</c>) except during the brief window of an
/// <see cref="KeyAtRestProtector.UnwrapKey"/>. A passive scan that walks the
/// process's mapped memory <b>faults</b> on the key page between operations
/// instead of reading the master — the first mechanism in the library that
/// raises the bar against the arbitrary-read in-process attacker the threat
/// model otherwise concedes.
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
/// <b>Locking.</b> The protect → copy → re-protect window and the teardown
/// both run under <c>_gate</c>, so a concurrent
/// <see cref="DisposableKeyAtRestProtector.Dispose"/> can
/// never unmap the page while a copy out of it is in flight, and two
/// concurrent unwraps cannot interleave their reprotect calls. The
/// finalizer path takes the same lock; it is uncontended there because the
/// base class's <see cref="GC.KeepAlive(object)"/> in
/// <see cref="KeyAtRestProtector.UnwrapKey"/> guarantees no unwrap is in
/// flight on a finalizable instance.
/// </para>
/// <para>
/// Not available on browser-wasm (no page-protection primitive); the factory
/// falls back to the obscurity tier there.
/// </para>
/// </remarks>
internal sealed class PageGuardedKeyProtector : DisposableKeyAtRestProtector
{
    private readonly object _gate = new();
    private readonly IntPtr _page;
    private readonly nuint _pageSize;

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
    /// so the fallback still receives a usable master. Deliberately not routed
    /// through the base <c>TryCreate</c> helper: this tier surfaces
    /// <c>Throw</c>-policy failures instead of mapping them to
    /// <see langword="null"/>.
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

    protected override KeyAccessor UnwrapCore()
    {
        // Ephemeral copy out of the guarded page, matching the hardware-backed
        // and obscurity tiers' KeyAccessor.Dispose contract (zero + unlock on
        // dispose). The page is readable only for the length of the memcpy,
        // which goes straight from the page into the locked ephemeral — no
        // intermediate copy.
        lock (_gate)
        {
            // Re-check under the gate: Dispose flips the flag before it takes
            // _gate, so a caller that lost the race to a concurrent Dispose
            // must not touch a page that is about to be unmapped.
            ThrowIfDisposed();
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
                unsafe
                {
                    return EphemeralFrom(new ReadOnlySpan<byte>((void*)_page, MasterKeySize));
                }
            }
            finally
            {
                MemoryProtection.TryProtect(_page, _pageSize, PageAccess.NoAccess);
            }
        }
    }

    protected override void ReleaseResources()
    {
        // The base has already flipped the disposed flag; taking _gate here
        // waits for any in-flight unwrap to finish its copy and re-seal
        // before the page is wiped and unmapped.
        lock (_gate)
        {
            TearDown(_page, _pageSize);
        }
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
