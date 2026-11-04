namespace TopSecret;

internal static class ProtectorLifetime
{
    public static void AddRef(KeyAtRestProtector protector) =>
        Interlocked.Increment(ref protector.LifetimeHolderCount);

    public static void Release(KeyAtRestProtector protector)
    {
        if (Interlocked.Decrement(ref protector.LifetimeHolderCount) == 0 &&
            protector.LifetimeSuperseded)
        {
            (protector as IDisposable)?.Dispose();
        }
    }

    public static void MarkSuperseded(KeyAtRestProtector protector)
    {
        protector.LifetimeSuperseded = true;
        if (Interlocked.CompareExchange(ref protector.LifetimeHolderCount, 0, 0) == 0)
        {
            (protector as IDisposable)?.Dispose();
        }
    }
}
