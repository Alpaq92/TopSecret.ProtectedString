using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace TopSecret;

public static class ProtectedStringConfigurationExtensions
{
    public const string DefaultSectionPath = "TopSecret:ProtectedString";

    public static void BindProtectedStringOptions(this IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        // A section passed here (cfg.GetSection(..).BindProtectedStringOptions())
        // binds itself, not a TopSecret:ProtectedString child of it.
        BindProtectedStringOptions(configuration as IConfigurationSection ?? configuration.GetSection(DefaultSectionPath));
    }

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

    private enum TimeSpanRange
    {
        NonNegative,

        Positive,
    }

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

    private static void Warn(IConfigurationSection section, string key, string raw, string reason) =>
        Trace.TraceWarning(
            $"TopSecret.ProtectedString.Configuration: '{section.Path}:{key}' " +
            $"has value '{TruncateForLog(raw)}' which {reason}. " +
            "Skipping; the property keeps its current value.");

    private static string TruncateForLog(string raw) =>
        raw.Length <= 64 ? raw : raw[..64] + "…";
}
