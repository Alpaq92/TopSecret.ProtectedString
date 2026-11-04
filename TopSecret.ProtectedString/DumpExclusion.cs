using System.Runtime.InteropServices;

namespace TopSecret;

internal static class DumpExclusion
{
    private const int MADV_DONTDUMP = 16;
    private const int MADV_DODUMP = 17;
    private const int MADV_WIPEONFORK = 18;
    private const int MADV_KEEPONFORK = 19;

    private static readonly Lazy<bool> s_supported =
        new(Probe, LazyThreadSafetyMode.ExecutionAndPublication);

    private static readonly Lazy<bool> s_wipeOnForkSupported =
        new(ProbeWipeOnFork, LazyThreadSafetyMode.ExecutionAndPublication);

    public static bool IsSupported => s_supported.Value;

    public static bool TryExclude<T>(T[] buffer) where T : unmanaged
    {
        if (buffer.Length == 0) return true;
        return TryExcludeRange(
            Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0), checked((int)ByteSize(buffer)));
    }

    public static void TryInclude<T>(T[] buffer) where T : unmanaged
    {
        if (buffer.Length == 0) return;
        TryIncludeRange(
            Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0), checked((int)ByteSize(buffer)));
    }

    public static bool TryExcludeRange(IntPtr addr, int size)
    {
        if (size == 0) return true;
        if (!IsSupported) return true;
        return TryAdvise(addr, (nuint)size, exclude: true);
    }

    public static void TryIncludeRange(IntPtr addr, int size)
    {
        if (size == 0 || !IsSupported) return;
        if (!OperatingSystem.IsWindows()) return;
        TryAdvise(addr, (nuint)size, exclude: false);
    }

    public static bool IsWipeOnForkSupported => s_wipeOnForkSupported.Value;

    public static bool TryWipeOnForkRange(IntPtr addr, int size)
    {
        if (size == 0 || !IsWipeOnForkSupported) return true;
        try { return Madvise(addr, (nuint)size, MADV_WIPEONFORK) == 0; }
        catch { return false; }
    }

    private static bool ProbeWipeOnFork()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsAndroid()) return false;
        return ProbePinned(Environment.SystemPageSize, static (addr, size) =>
        {
            if (Madvise(addr, size, MADV_WIPEONFORK) != 0) return false;
            // Reset the probe page's advice so this transient POH page does not
            // carry WIPEONFORK once it is recycled.
            Madvise(addr, size, MADV_KEEPONFORK);
            return true;
        });
    }

    private static nuint ByteSize<T>(T[] buffer) where T : unmanaged =>
        MemoryLocker.ByteSize(buffer);

    private static bool Probe()
    {
        if (!OperatingSystem.IsWindows() &&
            !OperatingSystem.IsLinux() &&
            !OperatingSystem.IsAndroid())
        {
            return false;
        }

        return ProbePinned(64, static (addr, size) =>
        {
            if (!TryAdvise(addr, size, exclude: true)) return false;
            TryAdvise(addr, size, exclude: false);
            return true;
        });
    }

    private static bool ProbePinned(int size, Func<IntPtr, nuint, bool> roundTrip)
    {
        try
        {
            var probe = GC.AllocateArray<byte>(size, pinned: true);
            var addr = Marshal.UnsafeAddrOfPinnedArrayElement(probe, 0);
            return roundTrip(addr, (nuint)probe.Length);
        }
        catch
        {
            return false;
        }
    }

    private static bool TryAdvise(IntPtr addr, nuint size, bool exclude)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                if (exclude)
                {
                    return WerRegisterExcludedMemoryBlock(addr, (uint)size) == 0;
                }
                // Not-registered is indistinguishable from success for our
                // purposes (the entry is gone either way).
                WerUnregisterExcludedMemoryBlock(addr);
                return true;
            }

            return Madvise(addr, size, exclude ? MADV_DONTDUMP : MADV_DODUMP) == 0;
        }
        catch
        {
            return false;
        }
    }

    private static int Madvise(IntPtr addr, nuint size, int advice)
    {
        long page = Environment.SystemPageSize;
        long start = addr.ToInt64() & ~(page - 1);
        long end = (addr.ToInt64() + (long)size + page - 1) & ~(page - 1);
        return madvise((IntPtr)start, (nuint)(end - start), advice);
    }

    [DllImport("kernel32", ExactSpelling = true)]
    private static extern int WerRegisterExcludedMemoryBlock(IntPtr address, uint size);

    [DllImport("kernel32", ExactSpelling = true)]
    private static extern int WerUnregisterExcludedMemoryBlock(IntPtr address);

    [DllImport("libc", SetLastError = true)]
    private static extern int madvise(IntPtr addr, nuint length, int advice);
}
