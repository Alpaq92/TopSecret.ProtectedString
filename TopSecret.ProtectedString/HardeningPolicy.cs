namespace TopSecret;

internal static class HardeningPolicy
{
    private static int s_warningLogged;

    public static void LockAndExclude(byte[] buffer, string lockContext)
    {
        if (buffer.Length == 0) return;
        if (!MemoryLocker.TryLock(buffer)) OnFailure(lockContext);
        if (!DumpExclusion.TryExclude(buffer)) OnFailure("core-dump exclusion");
    }

    public static void LockAndExcludeRange(IntPtr addr, int size, string lockContext)
    {
        if (size == 0) return;
        if (!MemoryLocker.TryLockRange(addr, size)) OnFailure(lockContext);
        if (!DumpExclusion.TryExcludeRange(addr, size))
        {
            try
            {
                OnFailure("core-dump exclusion");
            }
            catch
            {
                MemoryLocker.TryUnlockRange(addr, size);
                throw;
            }
        }
        DumpExclusion.TryWipeOnForkRange(addr, size);
    }

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

        if (behavior == MemoryLockingFailureBehavior.LogWarning)
        {
            WarnOnce.Trace(ref s_warningLogged,
                $"ProtectedString: {primitive} failed or is unavailable on this platform. " +
                "Other hardening defences (AES-GCM, AAD binding, pinned wipes, constant-time compare) still hold. " +
                $"Set {nameof(ProtectedStringOptions)}.{nameof(ProtectedStringOptions.MemoryLockingFailureBehavior)} " +
                $"to {nameof(MemoryLockingFailureBehavior.Throw)} to fail loudly or " +
                $"{nameof(MemoryLockingFailureBehavior.Ignore)} to silence this warning.");
        }
    }
}
