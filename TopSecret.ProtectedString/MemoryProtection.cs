using System.Runtime.InteropServices;

namespace TopSecret;

internal enum PageAccess
{
    NoAccess,
    ReadOnly,
    ReadWrite,
}

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

    public static bool IsSupported => s_supported.Value;

    public static IntPtr TryAllocatePage(out nuint pageSize)
    {
        pageSize = (nuint)Environment.SystemPageSize;
        if (!IsSupported) return IntPtr.Zero;
        return AllocatePageRaw(pageSize);
    }

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

    public static bool TryProtect(IntPtr addr, nuint size, PageAccess access)
    {
        if (size == 0) return true;
        if (!IsSupported) return false;
        return ProtectRaw(addr, size, access);
    }

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
