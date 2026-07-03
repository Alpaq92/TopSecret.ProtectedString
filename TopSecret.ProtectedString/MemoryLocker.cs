using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace TopSecret;

/// <summary>
/// Thin cross-platform wrapper around the OS memory-locking primitives:
/// <c>VirtualLock</c> / <c>VirtualUnlock</c> on Windows and <c>mlock</c> /
/// <c>munlock</c> from libc on Linux, macOS, Android, iOS, and Mac Catalyst.
/// Locked pages are kept resident in RAM and excluded from paging to disk.
/// </summary>
/// <remarks>
/// <para>
/// Reachability is probed lazily on first use by attempting to lock a 64-byte
/// pinned scratch buffer; the probe result is cached for the lifetime of the
/// process. Unprivileged processes are bounded by <c>RLIMIT_MEMLOCK</c> on the
/// libc targets (typical default 64 KiB), so <see cref="TryLock{T}"/> can
/// succeed during the probe and still fail later under budget pressure.
/// Callers must therefore handle a <see langword="false"/> return at any time.
/// </para>
/// <para>
/// Pages locked through this helper hold an OS-level lock count: each
/// <c>mlock</c> / <c>VirtualLock</c> on a page sets it locked, each matching
/// unlock returns it. To avoid leaking the per-process budget, every successful
/// <see cref="TryLock{T}"/> should be balanced by a <see cref="TryUnlock{T}"/>
/// before the array is allowed to be reclaimed.
/// </para>
/// </remarks>
internal static class MemoryLocker
{
    private static readonly Lazy<bool> s_supported =
        new(Probe, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>
    /// Whether memory locking is reachable on this platform — i.e., whether the
    /// OS primitive can be invoked successfully against a small probe buffer.
    /// The probe runs at most once per process.
    /// </summary>
    public static bool IsSupported => s_supported.Value;

    /// <summary>
    /// Attempts to lock the entire <paramref name="buffer"/> into resident
    /// memory. Returns <see langword="true"/> on success or for an empty
    /// buffer; returns <see langword="false"/> if the platform does not
    /// support locking or the OS rejected the call (typically
    /// <c>RLIMIT_MEMLOCK</c> exhaustion on libc targets, or working-set
    /// shortfall on Windows).
    /// </summary>
    /// <remarks>
    /// <paramref name="buffer"/> must already be pinned (e.g., allocated via
    /// <see cref="GC.AllocateArray{T}(int, bool)"/> with <c>pinned: true</c>).
    /// </remarks>
    public static bool TryLock<T>(T[] buffer) where T : unmanaged
    {
        if (buffer.Length == 0) return true;
        if (!IsSupported) return false;
        return TryLockNative(
            Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0),
            ByteSize(buffer));
    }

    /// <summary>
    /// Releases a prior <see cref="TryLock{T}"/>. Safe to call even if the
    /// preceding lock failed; returns <see langword="true"/> when the unlock
    /// either succeeded or was unnecessary.
    /// </summary>
    public static bool TryUnlock<T>(T[] buffer) where T : unmanaged
    {
        if (buffer.Length == 0) return true;
        if (!IsSupported) return true;
        return TryUnlockNative(
            Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0),
            ByteSize(buffer));
    }

    private static nuint ByteSize<T>(T[] buffer) where T : unmanaged =>
        (nuint)((long)buffer.Length * Unsafe.SizeOf<T>());

    private static bool Probe()
    {
        try
        {
            var probe = GC.AllocateArray<byte>(64, pinned: true);
            var addr = Marshal.UnsafeAddrOfPinnedArrayElement(probe, 0);
            var size = (nuint)probe.Length;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
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
            // DllNotFoundException, EntryPointNotFoundException, or any other
            // platform-resolution failure — treat as unsupported. We never want
            // probing to crash the type initializer.
            return false;
        }
    }

    private static bool TryLockNative(IntPtr addr, nuint size)
    {
        if (size == 0) return true;
        try
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? VirtualLock(addr, size)
                : mlock(addr, size) == 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryUnlockNative(IntPtr addr, nuint size)
    {
        if (size == 0) return true;
        try
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
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

    [DllImport("libc", SetLastError = true)]
    private static extern int mlock(IntPtr addr, nuint len);

    [DllImport("libc", SetLastError = true)]
    private static extern int munlock(IntPtr addr, nuint len);
}
