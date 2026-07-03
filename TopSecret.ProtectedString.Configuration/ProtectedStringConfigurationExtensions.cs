using System.Diagnostics;
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
/// <see cref="TimeSpan"/>, negative <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/>)
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
    /// <c>BindProtectedStringOptions(configuration.GetSection(DefaultSectionPath))</c>.
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
    /// <param name="section">The section to bind from.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="section"/> is null.
    /// </exception>
    public static void BindProtectedStringOptions(IConfigurationSection section)
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
                requireNonNegative: true,
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
                requireNonNegative: false,
                out var processKeyRotationInterval))
        {
            ProtectedStringOptions.ProcessKeyRotationInterval = processKeyRotationInterval;
        }
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

        if (Enum.TryParse<TEnum>(raw, ignoreCase: true, out value))
        {
            return true;
        }

        Trace.TraceWarning(
            $"TopSecret.ProtectedString.Configuration: '{section.Path}:{key}' " +
            $"has value '{TruncateForLog(raw)}' which is not a valid " +
            $"{typeof(TEnum).Name} (expected one of: {string.Join(", ", Enum.GetNames(typeof(TEnum)))}). " +
            $"Skipping; the property keeps its current value.");
        return false;
    }

    /// <summary>
    /// Reads <paramref name="key"/> from <paramref name="section"/> and
    /// parses it as a <see cref="TimeSpan"/>. Same skip-on-missing /
    /// warn-on-malformed semantics as
    /// <see cref="TryGetEnum{TEnum}(IConfigurationSection, string, out TEnum)"/>.
    /// When <paramref name="requireNonNegative"/> is set, a successfully
    /// parsed but negative value also warns and returns false — the
    /// <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/> setter
    /// throws on negative values, and crashing the host at bind time
    /// would defeat the point of having a soft binder.
    /// </summary>
    private static bool TryGetTimeSpan(
        IConfigurationSection section,
        string key,
        bool requireNonNegative,
        out TimeSpan value)
    {
        var raw = section[key];
        if (raw is null)
        {
            value = default;
            return false;
        }

        if (!TimeSpan.TryParse(raw, out value))
        {
            Trace.TraceWarning(
                $"TopSecret.ProtectedString.Configuration: '{section.Path}:{key}' " +
                $"has value '{TruncateForLog(raw)}' which is not a valid TimeSpan " +
                $"(expected e.g. '00:00:00.250' or '01:00:00'). " +
                $"Skipping; the property keeps its current value.");
            return false;
        }

        if (requireNonNegative && value < TimeSpan.Zero)
        {
            Trace.TraceWarning(
                $"TopSecret.ProtectedString.Configuration: '{section.Path}:{key}' " +
                $"has negative value '{TruncateForLog(raw)}'; this property does not " +
                $"accept negative TimeSpans. Skipping; the property keeps its current value.");
            value = default;
            return false;
        }

        return true;
    }

    /// <summary>
    /// Caps a configuration value at 64 chars in log output so a
    /// malicious or pathological config (e.g. an enormous string)
    /// cannot flood the trace listener with unbounded text.
    /// </summary>
    private static string TruncateForLog(string raw) =>
        raw.Length <= 64 ? raw : raw[..64] + "…";
}
