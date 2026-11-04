namespace TopSecret;

internal static class WarnOnce
{
    public static bool Trace(ref int gate, string message)
    {
        if (Interlocked.CompareExchange(ref gate, 1, 0) != 0) return false;
        System.Diagnostics.Trace.TraceWarning(message);
        return true;
    }
}
