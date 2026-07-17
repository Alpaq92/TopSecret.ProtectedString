using System.Runtime.InteropServices;

namespace TopSecret;

/// <summary>
/// Page-protection mode for <see cref="MemoryProtection"/>.
/// </summary>
internal enum PageAccess
{
    /// <summary>No access — reads and writes fault. Windows <c>PAGE_NOACCESS</c> / POSIX <c>PROT_NONE</c>.</summary>
    NoAccess,
    /// <summary>Read-only. Windows <c>PAGE_READONLY</c> / POSIX <c>PROT_READ</c>.</summary>
    ReadOnly,
    /// <summary>Read/write. Windows <c>PAGE_READWRITE</c> / POSIX <c>PROT_READ | PROT_WRITE</c>.</summary>
    ReadWrite,
}

/// <summary>
/// Thin cross-platform wrapper around the page-protection primitives:
/// <c>VirtualProtect</c> on Windows and <c>mprotect</c> from libc elsewhere,
/// plus a <b>dedicated page allocator</b> (<c>VirtualAlloc</c> / <c>mmap</c>)
/// so a guarded page is a standalone OS mapping rather than a heap block.
/// Used by <see cref="PageGuardedKeyProtector"/> to keep the master key on a
/// page that faults on access except during the brief window of an unwrap.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a dedicated mapping.</b> <see cref="TryAllocatePage"/> maps one page
/// straight from the OS (not from the C runtime heap): no allocator metadata
/// lives in or beside it, so marking it <c>PROT_NONE</c> can never disturb the
/// allocator or a neighbouring allocation, and <see cref="FreePage"/> returns
/// the pages to the OS (<c>munmap</c> / <c>VirtualFree</c>) rather than to a
/// reusable heap — so any lock / dump-exclusion / wipe-on-fork advice on the
/// page dies with the mapping instead of persisting onto whatever the heap
/// later hands out.
/// </para>
/// <para>
/// Browser-wasm has no page-protection primitive, so <see cref="IsSupported"/>
/// is <see langword="false"/> there and the guarded tier declines to construct.
/// </para>
/// </remarks>
internal static class MemoryProtection
{
    // Windows page-protection constants.
    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;

    // Windows VirtualAlloc / VirtualFree constants.
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;

    // POSIX mprotect flags.
    private const int PROT_NONE = 0x0;
    private const int PROT_READ = 0x1;
    private const int PROT_WRITE = 0x2;

    // POSIX mmap flags. MAP_ANONYMOUS differs by platform (Linux/Android 0x20,
    // Apple 0x1000); MAP_PRIVATE is 0x02 everywhere. mmap fails with (void*)-1.
    private const int MAP_PRIVATE = 0x02;
    private const int MAP_ANONYMOUS_LINUX = 0x20;
    private const int MAP_ANONYMOUS_APPLE = 0x1000;
    private static readonly IntPtr MAP_FAILED = new(-1);

    private static readonly Lazy<bool> s_supported =
        new(Probe, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>
    /// Whether page protection is reachable on this platform. <see langword="false"/>
    /// on browser-wasm; the probe runs at most once per process.
    /// </summary>
    public static bool IsSupported => s_supported.Value;

    /// <summary>
    /// Maps a single OS page as a dedicated, read/write, page-aligned mapping
    /// (<c>VirtualAlloc</c> / <c>mmap MAP_ANONYMOUS</c>). Zero-initialised by
    /// the OS. Returns <see cref="IntPtr.Zero"/> on unsupported platforms or a
    /// mapping failure; free with <see cref="FreePage"/>.
    /// </summary>
    public static IntPtr TryAllocatePage(out nuint pageSize)
    {
        pageSize = (nuint)Environment.SystemPageSize;
        if (!IsSupported) return IntPtr.Zero;
        return AllocatePageRaw(pageSize);
    }

    /// <summary>Releases a <see cref="TryAllocatePage"/> mapping back to the OS. Best-effort.</summary>
    public static void FreePage(IntPtr page, nuint pageSize)
    {
        if (page == IntPtr.Zero) return;
        try
        {
            if (OperatingSystem.IsWindows()) VirtualFree(page, 0, MEM_RELEASE);
            else munmap(page, pageSize);
        }
        catch
        {
            // Best-effort teardown; nothing actionable if the OS rejects it.
        }
    }

    /// <summary>The raw mapping, with no <see cref="IsSupported"/> guard, so <see cref="Probe"/> can use it.</summary>
    private static IntPtr AllocatePageRaw(nuint pageSize)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                return VirtualAlloc(IntPtr.Zero, pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            }
            int mapAnon = (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
                ? MAP_ANONYMOUS_APPLE
                : MAP_ANONYMOUS_LINUX;
            IntPtr p = mmap(IntPtr.Zero, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | mapAnon, -1, 0);
            return p == MAP_FAILED ? IntPtr.Zero : p;
        }
        catch
        {
            return IntPtr.Zero;
        }
    }

    /// <summary>
    /// Sets the protection of a page-aligned, whole-page range. Returns
    /// <see langword="true"/> on success. A <see langword="false"/> return
    /// means the platform primitive exists but rejected the call — the caller
    /// applies the configured hardening policy.
    /// </summary>
    public static bool TryProtect(IntPtr addr, nuint size, PageAccess access)
    {
        if (size == 0) return true;
        if (!IsSupported) return false;
        return ProtectRaw(addr, size, access);
    }

    /// <summary>
    /// The raw platform dispatch, with no <see cref="IsSupported"/> guard —
    /// so <see cref="Probe"/> can use it without re-entering the still-
    /// initializing <see cref="Lazy{T}"/>. Owns the sole
    /// <see cref="PageAccess"/> → native-flag mapping.
    /// </summary>
    private static bool ProtectRaw(IntPtr addr, nuint size, PageAccess access)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                uint flag = access switch
                {
                    PageAccess.NoAccess => PAGE_NOACCESS,
                    PageAccess.ReadOnly => PAGE_READONLY,
                    _ => PAGE_READWRITE,
                };
                return VirtualProtect(addr, size, flag, out _);
            }

            int prot = access switch
            {
                PageAccess.NoAccess => PROT_NONE,
                PageAccess.ReadOnly => PROT_READ,
                _ => PROT_READ | PROT_WRITE,
            };
            return mprotect(addr, size, prot) == 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool Probe()
    {
        // Only browser-wasm lacks the primitive; every desktop/mobile target
        // has VirtualProtect or mprotect. Gate explicitly rather than by
        // accident, then exercise a real alloc/protect round trip through the
        // same dispatch TryProtect uses.
        if (!OperatingSystem.IsWindows() &&
            !OperatingSystem.IsLinux() &&
            !OperatingSystem.IsAndroid() &&
            !OperatingSystem.IsMacOS() &&
            !OperatingSystem.IsIOS() &&
            !OperatingSystem.IsMacCatalyst())
        {
            return false;
        }

        nuint pageSize = (nuint)Environment.SystemPageSize;
        IntPtr page = AllocatePageRaw(pageSize);
        if (page == IntPtr.Zero) return false;
        try
        {
            // Exercise the real alloc + protect round trip the guarded tier uses.
            return ProtectRaw(page, pageSize, PageAccess.NoAccess)
                   && ProtectRaw(page, pageSize, PageAccess.ReadWrite);
        }
        catch
        {
            return false;
        }
        finally
        {
            FreePage(page, pageSize);
        }
    }

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualProtect(IntPtr lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualFree(IntPtr lpAddress, nuint dwSize, uint dwFreeType);

    [DllImport("libc", SetLastError = true)]
    private static extern int mprotect(IntPtr addr, nuint len, int prot);

    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr mmap(IntPtr addr, nuint length, int prot, int flags, int fd, nint offset);

    [DllImport("libc", SetLastError = true)]
    private static extern int munmap(IntPtr addr, nuint length);
}
