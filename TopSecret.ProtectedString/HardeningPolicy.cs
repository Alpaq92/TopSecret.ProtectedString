using System.Diagnostics;

namespace TopSecret;

/// <summary>
/// Centralised handler for memory-hardening primitive failures
/// (<c>VirtualLock</c>/<c>mlock</c>, <c>madvise(MADV_DONTDUMP)</c>,
/// <c>prctl(PR_SET_DUMPABLE, 0)</c>, <c>setrlimit(RLIMIT_CORE, 0)</c>,
/// Apple Secure Enclave / Android Keystore key wrapping). All paths funnel
/// here so the configured
/// <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/> applies
/// uniformly and a single one-shot warning is emitted across all categories.
/// </summary>
internal static class HardeningPolicy
{
    private static int s_warningLogged;

    /// <summary>
    /// Applies the full hardening sequence to a caller-supplied pinned
    /// buffer — lock into resident memory, exclude from crash dumps —
    /// routing each failure through <see cref="OnFailure"/>. The allocating
    /// sibling is <c>ProtectedString.AllocatePinnedBytes</c>; this overload
    /// exists for buffers the caller had to allocate itself (e.g. a master
    /// key array whose ownership is being transferred).
    /// </summary>
    public static void LockAndExclude(byte[] buffer, string lockContext)
    {
        if (buffer.Length == 0) return;
        if (!MemoryLocker.TryLock(buffer)) OnFailure(lockContext);
        if (!DumpExclusion.TryExclude(buffer)) OnFailure("core-dump exclusion");
    }

    /// <summary>
    /// Applies <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/>
    /// to a hardening primitive failure. <paramref name="primitive"/> is a
    /// short noun phrase describing what failed (e.g.,
    /// <c>"memory locking"</c>, <c>"core-dump suppression"</c>,
    /// <c>"hardware-backed key wrapping"</c>) and is interpolated into the
    /// thrown exception / logged warning.
    /// </summary>
    public static void OnFailure(string primitive)
    {
        var behavior = ProtectedStringOptions.MemoryLockingFailureBehavior;
        if (behavior == MemoryLockingFailureBehavior.Throw)
        {
            throw new PlatformNotSupportedException(
                $"ProtectedString: {primitive} failed or is unavailable on this platform, " +
                $"and {nameof(ProtectedStringOptions)}.{nameof(ProtectedStringOptions.MemoryLockingFailureBehavior)} " +
                $"is set to {nameof(MemoryLockingFailureBehavior.Throw)}. Set it to " +
                $"{nameof(MemoryLockingFailureBehavior.LogWarning)} or {nameof(MemoryLockingFailureBehavior.Ignore)} " +
                "to proceed without this protection.");
        }

        if (behavior == MemoryLockingFailureBehavior.LogWarning &&
            Interlocked.CompareExchange(ref s_warningLogged, 1, 0) == 0)
        {
            Trace.TraceWarning(
                $"ProtectedString: {primitive} failed or is unavailable on this platform. " +
                "Other hardening defences (AES-GCM, AAD binding, pinned wipes, constant-time compare) still hold. " +
                $"Set {nameof(ProtectedStringOptions)}.{nameof(ProtectedStringOptions.MemoryLockingFailureBehavior)} " +
                $"to {nameof(MemoryLockingFailureBehavior.Throw)} to fail loudly or " +
                $"{nameof(MemoryLockingFailureBehavior.Ignore)} to silence this warning.");
        }
    }
}
