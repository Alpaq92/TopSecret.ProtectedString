using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace TopSecret;

internal static class MemoryLocker
{
    private static readonly Lazy<bool> s_supported =
        new(Probe, LazyThreadSafetyMode.ExecutionAndPublication);

    public static bool IsSupported => s_supported.Value;

    public static bool TryLock<T>(T[] buffer) where T : unmanaged
    {
        if (buffer.Length == 0) return true;
        if (!IsSupported) return false;
        return TryLockNative(
            Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0),
            ByteSize(buffer));
    }

    public static bool TryUnlock<T>(T[] buffer) where T : unmanaged
    {
        if (buffer.Length == 0) return true;
        DumpExclusion.TryInclude(buffer);
        if (!IsSupported) return true;
        return TryUnlockNative(
            Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0),
            ByteSize(buffer));
    }

    public static bool TryLockRange(IntPtr addr, int size)
    {
        if (size == 0) return true;
        if (!IsSupported) return false;
        return TryLockNative(addr, (nuint)size);
    }

    public static bool TryUnlockRange(IntPtr addr, int size)
    {
        if (size == 0) return true;
        if (!IsSupported) return true;
        return TryUnlockNative(addr, (nuint)size);
    }

    internal static nuint ByteSize<T>(T[] buffer) where T : unmanaged =>
        (nuint)((long)buffer.Length * Unsafe.SizeOf<T>());

    private static bool Probe()
    {
        try
        {
            var probe = GC.AllocateArray<byte>(64, pinned: true);
            var addr = Marshal.UnsafeAddrOfPinnedArrayElement(probe, 0);
            var size = (nuint)probe.Length;

            if (OperatingSystem.IsWindows())
            {
                if (!VirtualLock(addr, size)) return false;
                VirtualUnlock(addr, size);
                return true;
            }

            if (mlock(addr, size) != 0) return false;
            munlock(addr, size);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryLockNative(IntPtr addr, nuint size)
    {
        if (size == 0) return true;
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                return mlock(addr, size) == 0;
            }

            if (VirtualLock(addr, size)) return true;

            if (Marshal.GetLastPInvokeError() != ERROR_WORKING_SET_QUOTA) return false;
            return TryBumpWorkingSetAndRelock(addr, size);
        }
        catch
        {
            return false;
        }
    }

    private const int ERROR_WORKING_SET_QUOTA = 1453;

    private static readonly object s_workingSetLock = new();

    private static bool TryBumpWorkingSetAndRelock(IntPtr addr, nuint size)
    {
        lock (s_workingSetLock)
        {
            IntPtr process = GetCurrentProcess();
            if (!GetProcessWorkingSetSize(process, out nuint min, out nuint max)) return false;

            // Add the requested bytes plus one page of slack to the minimum; keep
            // the maximum at least the new minimum.
            nuint pageSlack = (nuint)Environment.SystemPageSize;
            nuint bump = size + pageSlack;
            nuint newMin = min + bump;
            if (newMin < min) return false; // nuint overflow — refuse rather than wrap
            nuint newMax = max >= newMin ? max : newMin;

            if (!SetProcessWorkingSetSize(process, newMin, newMax)) return false;
        }
        return VirtualLock(addr, size);
    }

    private static bool TryUnlockNative(IntPtr addr, nuint size)
    {
        if (size == 0) return true;
        try
        {
            return OperatingSystem.IsWindows()
                ? VirtualUnlock(addr, size)
                : munlock(addr, size) == 0;
        }
        catch
        {
            return false;
        }
    }

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualLock(IntPtr lpAddress, nuint dwSize);

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualUnlock(IntPtr lpAddress, nuint dwSize);

    [DllImport("kernel32")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessWorkingSetSize(IntPtr hProcess, out nuint lpMinimumWorkingSetSize, out nuint lpMaximumWorkingSetSize);

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, nuint dwMinimumWorkingSetSize, nuint dwMaximumWorkingSetSize);

    [DllImport("libc", SetLastError = true)]
    private static extern int mlock(IntPtr addr, nuint len);

    [DllImport("libc", SetLastError = true)]
    private static extern int munlock(IntPtr addr, nuint len);
}
