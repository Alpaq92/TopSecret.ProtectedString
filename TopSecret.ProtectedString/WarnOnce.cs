namespace TopSecret;

/// <summary>
/// One-shot <see cref="System.Diagnostics.Trace.TraceWarning(string)"/>:
/// emits a message the first time a given gate is tripped and nothing on
/// every subsequent call. Replaces the hand-rolled
/// <c>Interlocked.CompareExchange(ref s_gate, 1, 0)</c> idiom that each
/// diagnostic used to carry.
/// </summary>
internal static class WarnOnce
{
    /// <summary>
    /// Emits <paramref name="message"/> as a trace warning if
    /// <paramref name="gate"/> has not been tripped yet, and trips it.
    /// Thread-safe: exactly one caller per gate ever observes
    /// <see langword="true"/>.
    /// </summary>
    /// <param name="gate">
    /// A static <see cref="int"/> field owned by the call site, initially
    /// <c>0</c>. Tests may reset it to <c>0</c> to re-arm the warning.
    /// </param>
    /// <param name="message">The warning text.</param>
    /// <returns><see langword="true"/> if this call emitted the warning.</returns>
    public static bool Trace(ref int gate, string message)
    {
        if (Interlocked.CompareExchange(ref gate, 1, 0) != 0) return false;
        System.Diagnostics.Trace.TraceWarning(message);
        return true;
    }
}
