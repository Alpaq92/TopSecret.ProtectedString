using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TopSecret;

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

    internal static PageGuardedKeyProtector? TryCreate(byte[] master)
    {
        if (master.Length != MasterKeySize) return null;

        IntPtr page = MemoryProtection.TryAllocatePage(out nuint pageSize);
        if (page == IntPtr.Zero) return null; // unsupported / mapping failed — master intact

        bool masterConsumed = false;
        try
        {
            Marshal.Copy(master, 0, page, MasterKeySize);

            HardeningPolicy.LockAndExcludeRange(page, (int)pageSize, "memory locking the guarded master page");

            // Seal: no access until an unwrap opens the window.
            if (!MemoryProtection.TryProtect(page, pageSize, PageAccess.NoAccess))
            {
                HardeningPolicy.OnFailure("page protection of the guarded master key"); // throws under Throw
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
        lock (_gate)
        {
            ThrowIfDisposed();
            try
            {
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
        lock (_gate)
        {
            TearDown(_page, _pageSize);
        }
    }

    private static void TearDown(IntPtr page, nuint pageSize)
    {
        if (page == IntPtr.Zero) return;
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
