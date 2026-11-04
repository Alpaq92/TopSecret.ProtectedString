using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace TopSecret;

/// <summary>
/// Binds <see cref="ProtectedStringOptions"/> from a
/// <see cref="IConfiguration"/> source — typically
/// <c>appsettings.json</c> via the host builder. Keeps the main
/// <c>TopSecret.ProtectedString</c> package free of any
/// <c>Microsoft.Extensions.Configuration</c> dependency; consumers
/// who don't want the binder pay no extra dependency cost.
/// </summary>
/// <remarks>
/// <para>
/// <b>Skip-on-missing, warn-on-malformed.</b> Keys absent from the
/// section leave the corresponding property at its current value
/// silently — partial configuration is the common case and is not an
/// error. Keys *present but malformed* (invalid enum value, malformed
/// <see cref="TimeSpan"/>, negative <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/>,
/// non-positive <see cref="ProtectedStringOptions.ProcessKeyRotationInterval"/>)
/// also leave the property unchanged but emit a one-shot
/// <see cref="Trace.TraceWarning(string)"/> per misconfigured key, so
/// configuration typos surface in logs without crashing the host at
/// startup. Wire up a <see cref="TraceListener"/> in your composition
/// root to actually see these:
/// <code>
/// System.Diagnostics.Trace.Listeners.Add(new System.Diagnostics.ConsoleTraceListener());
/// </code>
/// </para>
/// <para>
/// <b>Strict enum names.</b> Enum-typed options accept only the
/// declared member names (case-insensitively). Integer strings such as
/// <c>"42"</c> and comma-separated combinations such as
/// <c>"HardwareBackedRequired,GuardedPage"</c> — both of which
/// <see cref="Enum.TryParse{TEnum}(string, bool, out TEnum)"/> would
/// otherwise accept and turn into an undefined value — are treated as
/// malformed and warn-and-skip.
/// </para>
/// <para>
/// <b>Culture-invariant parsing.</b> <see cref="TimeSpan"/> values are
/// parsed with <see cref="CultureInfo.InvariantCulture"/>, matching the
/// behaviour of <c>Microsoft.Extensions.Configuration.Binder</c>, so
/// the same <c>appsettings.json</c> binds identically regardless of the
/// host's current culture.
/// </para>
/// <para>
/// <b>Read-once vs read-every-time semantics.</b> Three of the five
/// options are read once at the first <see cref="ProtectedString"/>
/// construction and ignored after:
/// </para>
/// <list type="bullet">
///   <item><see cref="ProtectedStringOptions.KeyAtRestProtection"/></item>
///   <item><see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/></item>
///   <item><see cref="ProtectedStringOptions.ProcessKeyRotationInterval"/></item>
/// </list>
/// <para>
/// The other two
/// (<see cref="ProtectedStringOptions.ProcessKeyRotationPolicy"/>,
/// <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/>)
/// are read every time a relevant code path runs, so subsequent
/// re-binds (e.g. via <see cref="IConfiguration.GetReloadToken"/>) take
/// effect for future operations.
/// </para>
/// <para>
/// <b>Why static.</b> <see cref="ProtectedStringOptions"/> is a static
/// class with static properties because the AES master key it gates is
/// process-wide by design — there is no meaningful "per-scope" or
/// "per-tenant" rotation. The binder reflects that: it mutates the
/// process-wide static, not an <c>IOptions&lt;T&gt;</c> instance.
/// </para>
/// </remarks>
public static class ProtectedStringConfigurationExtensions
{
    /// <summary>The default configuration section path.</summary>
    public const string DefaultSectionPath = "TopSecret:ProtectedString";

    /// <summary>
    /// Binds <see cref="ProtectedStringOptions"/> from
    /// <paramref name="configuration"/>'s
    /// <see cref="DefaultSectionPath"/> (<c>"TopSecret:ProtectedString"</c>).
    /// Equivalent to
    /// <c>configuration.GetSection(DefaultSectionPath).BindProtectedStringOptions()</c>.
    /// </summary>
    /// <param name="configuration">The configuration root.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="configuration"/> is null.
    /// </exception>
    public static void BindProtectedStringOptions(this IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        BindProtectedStringOptions(configuration.GetSection(DefaultSectionPath));
    }

    /// <summary>
    /// Binds <see cref="ProtectedStringOptions"/> from a specific
    /// <see cref="IConfigurationSection"/>. Use this when your
    /// configuration layout doesn't match the default
    /// <c>"TopSecret:ProtectedString"</c> path.
    /// </summary>
    /// <remarks>
    /// This is an extension method so that
    /// <c>configuration.GetSection("Crypto:Options").BindProtectedStringOptions()</c>
    /// resolves here (the more specific parameter type) rather than to
    /// the <see cref="IConfiguration"/> overload — which, because
    /// <see cref="IConfigurationSection"/> derives from
    /// <see cref="IConfiguration"/>, would otherwise be chosen and read
    /// <c>Crypto:Options:TopSecret:ProtectedString</c>, silently binding
    /// nothing. The static-call form
    /// <c>ProtectedStringConfigurationExtensions.BindProtectedStringOptions(section)</c>
    /// continues to work.
    /// </remarks>
    /// <param name="section">The section to bind from.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="section"/> is null.
    /// </exception>
    public static void BindProtectedStringOptions(this IConfigurationSection section)
    {
        ArgumentNullException.ThrowIfNull(section);

        if (TryGetEnum<KeyAtRestProtection>(
                section, nameof(ProtectedStringOptions.KeyAtRestProtection),
                out var keyAtRestProtection))
        {
            ProtectedStringOptions.KeyAtRestProtection = keyAtRestProtection;
        }

        if (TryGetTimeSpan(
                section, nameof(ProtectedStringOptions.UnwrappedKeyCacheTtl),
                TimeSpanRange.NonNegative,
                out var unwrappedKeyCacheTtl))
        {
            ProtectedStringOptions.UnwrappedKeyCacheTtl = unwrappedKeyCacheTtl;
        }

        if (TryGetEnum<MemoryLockingFailureBehavior>(
                section, nameof(ProtectedStringOptions.MemoryLockingFailureBehavior),
                out var memoryLockingFailureBehavior))
        {
            ProtectedStringOptions.MemoryLockingFailureBehavior = memoryLockingFailureBehavior;
        }

        if (TryGetEnum<ProcessKeyRotation>(
                section, nameof(ProtectedStringOptions.ProcessKeyRotationPolicy),
                out var processKeyRotationPolicy))
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = processKeyRotationPolicy;
        }

        if (TryGetTimeSpan(
                section, nameof(ProtectedStringOptions.ProcessKeyRotationInterval),
                TimeSpanRange.Positive,
                out var processKeyRotationInterval))
        {
            ProtectedStringOptions.ProcessKeyRotationInterval = processKeyRotationInterval;
        }
    }

    /// <summary>
    /// Which range of <see cref="TimeSpan"/> values a property accepts;
    /// values outside the range warn-and-skip instead of being bound.
    /// </summary>
    private enum TimeSpanRange
    {
        /// <summary>
        /// Zero or greater. <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/>
        /// uses <see cref="TimeSpan.Zero"/> as its "off" switch, so zero
        /// is a legitimate, meaningful value there.
        /// </summary>
        NonNegative,

        /// <summary>
        /// Strictly greater than zero. The periodic rotation timer behind
        /// <see cref="ProtectedStringOptions.ProcessKeyRotationInterval"/>
        /// silently never starts for a non-positive interval, so a zero
        /// or negative value from configuration is almost certainly a
        /// mistake and must surface as a warning rather than disable
        /// rotation without a trace.
        /// </summary>
        Positive,
    }

    /// <summary>
    /// Reads <paramref name="key"/> from <paramref name="section"/> and
    /// parses it as <typeparamref name="TEnum"/>. Returns
    /// <see langword="false"/> when the key is absent (silent — the
    /// caller leaves the property at its current value) or when the
    /// value fails to parse (emits a one-shot
    /// <see cref="Trace.TraceWarning(string)"/> identifying the bad
    /// key + value before returning false). Distinguishing the two
    /// matters: missing keys are normal in partial configuration; bad
    /// values are usually typos and should surface in logs.
    /// </summary>
    /// <remarks>
    /// Values that <see cref="Enum.TryParse{TEnum}(string, bool, out TEnum)"/>
    /// accepts but that do not name a declared member — integer strings
    /// (<c>"42"</c>) and comma-separated combinations
    /// (<c>"HardwareBackedRequired,GuardedPage"</c>, which it bitwise-ORs)
    /// — are rejected via <see cref="Enum.IsDefined{TEnum}(TEnum)"/>.
    /// The check happens here, before the
    /// <see cref="ProtectedStringOptions"/> setter runs, so the binder's
    /// warn-and-skip contract holds even if the setter itself validates
    /// and throws.
    /// </remarks>
    private static bool TryGetEnum<TEnum>(
        IConfigurationSection section,
        string key,
        out TEnum value)
        where TEnum : struct, Enum
    {
        var raw = section[key];
        if (raw is null)
        {
            value = default;
            return false;
        }

        if (Enum.TryParse<TEnum>(raw, ignoreCase: true, out value) && Enum.IsDefined(value))
        {
            return true;
        }

        Warn(section, key, raw,
            $"is not a valid {typeof(TEnum).Name} " +
            $"(expected one of: {string.Join(", ", Enum.GetNames<TEnum>())})");
        value = default;
        return false;
    }

    /// <summary>
    /// Reads <paramref name="key"/> from <paramref name="section"/> and
    /// parses it as a <see cref="TimeSpan"/> using
    /// <see cref="CultureInfo.InvariantCulture"/>. Same skip-on-missing /
    /// warn-on-malformed semantics as
    /// <see cref="TryGetEnum{TEnum}(IConfigurationSection, string, out TEnum)"/>.
    /// A successfully parsed value outside <paramref name="range"/> also
    /// warns and returns false — the
    /// <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/> setter
    /// throws on negative values, and crashing the host at bind time
    /// would defeat the point of having a soft binder; a non-positive
    /// <see cref="ProtectedStringOptions.ProcessKeyRotationInterval"/>
    /// would silently disable periodic rotation.
    /// </summary>
    private static bool TryGetTimeSpan(
        IConfigurationSection section,
        string key,
        TimeSpanRange range,
        out TimeSpan value)
    {
        var raw = section[key];
        if (raw is null)
        {
            value = default;
            return false;
        }

        if (!TimeSpan.TryParse(raw, CultureInfo.InvariantCulture, out value))
        {
            Warn(section, key, raw,
                "is not a valid TimeSpan (expected e.g. '00:00:00.250' or '01:00:00')");
            return false;
        }

        switch (range)
        {
            case TimeSpanRange.NonNegative when value < TimeSpan.Zero:
                Warn(section, key, raw,
                    "is negative; this property does not accept negative TimeSpans");
                value = default;
                return false;

            case TimeSpanRange.Positive when value <= TimeSpan.Zero:
                Warn(section, key, raw,
                    "is not positive; this property requires a TimeSpan greater than zero " +
                    "(a zero or negative interval would silently disable periodic rotation)");
                value = default;
                return false;

            default:
                return true;
        }
    }

    /// <summary>
    /// Emits the single warn-and-skip diagnostic every malformed-value
    /// path shares, so the message shape (package prefix, fully
    /// qualified key, truncated offending value, reason, and the
    /// "property keeps its current value" tail) stays identical across
    /// enum, TimeSpan and range failures.
    /// </summary>
    private static void Warn(IConfigurationSection section, string key, string raw, string reason) =>
        Trace.TraceWarning(
            $"TopSecret.ProtectedString.Configuration: '{section.Path}:{key}' " +
            $"has value '{TruncateForLog(raw)}' which {reason}. " +
            "Skipping; the property keeps its current value.");

    /// <summary>
    /// Caps a configuration value at 64 chars in log output so a
    /// malicious or pathological config (e.g. an enormous string)
    /// cannot flood the trace listener with unbounded text.
    /// </summary>
    private static string TruncateForLog(string raw) =>
        raw.Length <= 64 ? raw : raw[..64] + "…";
}
