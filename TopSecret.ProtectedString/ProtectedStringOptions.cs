using System.Diagnostics;

namespace TopSecret;

public enum MemoryLockingFailureBehavior
{
    Ignore,

    LogWarning,

    Throw,
}

public enum ProcessKeyRotation
{
    Disabled,

    OnDemand,

    Periodic,
}

public enum KeyAtRestProtection
{
    None,

    Obscurity,

    HardwareBackedRequired,

    HardwareBackedPreferred,

    GuardedPage,
}

public static class ProtectedStringOptions
{
    public static MemoryLockingFailureBehavior MemoryLockingFailureBehavior
    {
        get => s_memoryLockingFailureBehavior;
        set
        {
            ThrowIfUndefined(value);
            s_memoryLockingFailureBehavior = value;
        }
    }
    private static MemoryLockingFailureBehavior s_memoryLockingFailureBehavior = MemoryLockingFailureBehavior.LogWarning;

    public static ProcessKeyRotation ProcessKeyRotationPolicy
    {
        get => s_processKeyRotationPolicy;
        set
        {
            ThrowIfUndefined(value);
            s_processKeyRotationPolicy = value;
        }
    }
    private static ProcessKeyRotation s_processKeyRotationPolicy = ProcessKeyRotation.Disabled;

    public static TimeSpan ProcessKeyRotationInterval
    {
        get => s_processKeyRotationInterval;
        set
        {
            ThrowIfOutsideTimerRange(value, nameof(value));
            WarnIfLateMutation(nameof(ProcessKeyRotationInterval));
            s_processKeyRotationInterval = value;
        }
    }
    private static TimeSpan s_processKeyRotationInterval = TimeSpan.FromHours(1);

    public static KeyAtRestProtection KeyAtRestProtection
    {
        get => s_keyAtRestProtection;
        set
        {
            ThrowIfUndefined(value);
            WarnIfLateMutation(nameof(KeyAtRestProtection));
            s_keyAtRestProtection = value;
        }
    }
    private static KeyAtRestProtection s_keyAtRestProtection = KeyAtRestProtection.Obscurity;

    public static TimeSpan UnwrappedKeyCacheTtl
    {
        get => s_unwrappedKeyCacheTtl;
        set
        {
            if (value < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(value), value,
                    "UnwrappedKeyCacheTtl must be non-negative. Use TimeSpan.Zero to disable caching.");
            }
            ThrowIfOutsideTimerRange(value, nameof(value));
            WarnIfLateMutation(nameof(UnwrappedKeyCacheTtl));
            s_unwrappedKeyCacheTtl = value;
        }
    }
    private static TimeSpan s_unwrappedKeyCacheTtl = TimeSpan.Zero;

    // ---- validation --------------------------------------------------------

    public static readonly TimeSpan MaxTimerDuration = TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    private static void ThrowIfUndefined<TEnum>(TEnum value) where TEnum : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(nameof(value), value,
                $"{typeof(TEnum).Name} value {Convert.ToInt64(value)} is not a defined member. " +
                "Integer casts and bitwise combinations of members are not accepted.");
        }
    }

    private static void ThrowIfOutsideTimerRange(TimeSpan value, string paramName)
    {
        if (value < TimeSpan.Zero || value > MaxTimerDuration)
        {
            throw new ArgumentOutOfRangeException(paramName, value,
                $"Value must be between TimeSpan.Zero and {nameof(MaxTimerDuration)} ({MaxTimerDuration}).");
        }
    }

    // ---- late-mutation diagnostic --------------------------------------

    private static int s_warnedLateMutation;

    private static void WarnIfLateMutation(string memberName)
    {
        if (!ProtectedString.IsKeyProtectorInitialized) return;
        if (Interlocked.CompareExchange(ref s_warnedLateMutation, 1, 0) != 0) return;

        Trace.TraceWarning(
            $"ProtectedString: {nameof(ProtectedStringOptions)}.{memberName} was set after the " +
            "first ProtectedString construction. Read-once options (KeyAtRestProtection, " +
            "UnwrappedKeyCacheTtl, ProcessKeyRotationInterval) are sampled when the lazy " +
            "process-wide protector is initialised; this change has no effect on the running " +
            "protector or the live rotation timer. Set ProtectedStringOptions in your composition " +
            "root before any ProtectedString is constructed, or call ProtectedString.RotateProcessKey() " +
            "to swap protectors at runtime under the new option values.");
    }

    internal static void _ResetLateMutationWarningForTests() =>
        Volatile.Write(ref s_warnedLateMutation, 0);
}
