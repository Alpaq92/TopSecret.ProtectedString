using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using TopSecret;

namespace TopSecret.ConfigurationTests;

/// <summary>
/// Captures every <c>Write</c> / <c>WriteLine</c> the trace pipeline
/// pushes at this listener so a test can assert on the formatted
/// message content.
/// </summary>
internal sealed class CapturingTraceListener : TraceListener
{
    public List<string> Messages { get; } = new();

    public override void Write(string? message)
    {
        if (!string.IsNullOrEmpty(message)) Messages.Add(message);
    }

    public override void WriteLine(string? message)
    {
        if (!string.IsNullOrEmpty(message)) Messages.Add(message);
    }
}

/// <summary>
/// Tests <see cref="ProtectedStringConfigurationExtensions.BindProtectedStringOptions(IConfiguration)"/>
/// (and its <see cref="IConfigurationSection"/> overload) against an
/// in-memory <see cref="IConfiguration"/> built from key/value pairs.
/// Each test snapshots and restores the relevant
/// <see cref="ProtectedStringOptions"/> property so the suite can run
/// in any order without polluting subsequent runs.
/// </summary>
[TestFixture]
public class ProtectedStringConfigurationExtensionsTests
{
    private static IConfigurationRoot BuildConfiguration(params (string Key, string Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e =>
                new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    // ---- Each option binds correctly ------------------------------------

    [Test]
    public void Binds_KeyAtRestProtection_from_default_section()
    {
        var prior = ProtectedStringOptions.KeyAtRestProtection;
        try
        {
            var cfg = BuildConfiguration(
                ("TopSecret:ProtectedString:KeyAtRestProtection", "HardwareBackedPreferred"));
            cfg.BindProtectedStringOptions();
            Assert.That(ProtectedStringOptions.KeyAtRestProtection,
                Is.EqualTo(KeyAtRestProtection.HardwareBackedPreferred));
        }
        finally
        {
            ProtectedStringOptions.KeyAtRestProtection = prior;
        }
    }

    [Test]
    public void Binds_UnwrappedKeyCacheTtl_from_default_section()
    {
        var prior = ProtectedStringOptions.UnwrappedKeyCacheTtl;
        try
        {
            var cfg = BuildConfiguration(
                ("TopSecret:ProtectedString:UnwrappedKeyCacheTtl", "00:00:00.250"));
            cfg.BindProtectedStringOptions();
            Assert.That(ProtectedStringOptions.UnwrappedKeyCacheTtl,
                Is.EqualTo(TimeSpan.FromMilliseconds(250)));
        }
        finally
        {
            ProtectedStringOptions.UnwrappedKeyCacheTtl = prior;
        }
    }

    [Test]
    public void Binds_MemoryLockingFailureBehavior_from_default_section()
    {
        var prior = ProtectedStringOptions.MemoryLockingFailureBehavior;
        try
        {
            var cfg = BuildConfiguration(
                ("TopSecret:ProtectedString:MemoryLockingFailureBehavior", "Throw"));
            cfg.BindProtectedStringOptions();
            Assert.That(ProtectedStringOptions.MemoryLockingFailureBehavior,
                Is.EqualTo(MemoryLockingFailureBehavior.Throw));
        }
        finally
        {
            ProtectedStringOptions.MemoryLockingFailureBehavior = prior;
        }
    }

    [Test]
    public void Binds_ProcessKeyRotationPolicy_from_default_section()
    {
        var prior = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            var cfg = BuildConfiguration(
                ("TopSecret:ProtectedString:ProcessKeyRotationPolicy", "OnDemand"));
            cfg.BindProtectedStringOptions();
            Assert.That(ProtectedStringOptions.ProcessKeyRotationPolicy,
                Is.EqualTo(ProcessKeyRotation.OnDemand));
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = prior;
        }
    }

    [Test]
    public void Binds_ProcessKeyRotationInterval_from_default_section()
    {
        var prior = ProtectedStringOptions.ProcessKeyRotationInterval;
        try
        {
            var cfg = BuildConfiguration(
                ("TopSecret:ProtectedString:ProcessKeyRotationInterval", "00:30:00"));
            cfg.BindProtectedStringOptions();
            Assert.That(ProtectedStringOptions.ProcessKeyRotationInterval,
                Is.EqualTo(TimeSpan.FromMinutes(30)));
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationInterval = prior;
        }
    }

    // ---- Skip-on-missing semantics --------------------------------------

    [Test]
    public void Missing_keys_leave_existing_values_unchanged()
    {
        var priorPolicy = ProtectedStringOptions.ProcessKeyRotationPolicy;
        var priorBehavior = ProtectedStringOptions.MemoryLockingFailureBehavior;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;
            ProtectedStringOptions.MemoryLockingFailureBehavior = MemoryLockingFailureBehavior.Throw;

            // Empty configuration — the bind should be a no-op for every key.
            var cfg = BuildConfiguration();
            cfg.BindProtectedStringOptions();

            Assert.That(ProtectedStringOptions.ProcessKeyRotationPolicy,
                Is.EqualTo(ProcessKeyRotation.OnDemand));
            Assert.That(ProtectedStringOptions.MemoryLockingFailureBehavior,
                Is.EqualTo(MemoryLockingFailureBehavior.Throw));
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = priorPolicy;
            ProtectedStringOptions.MemoryLockingFailureBehavior = priorBehavior;
        }
    }

    // ---- Skip-on-malformed semantics ------------------------------------
    // For each "value present but malformed" case, assert (a) the
    // property keeps its prior value AND (b) a Trace.TraceWarning is
    // emitted naming the bad key — the warning is the only signal that
    // an `appsettings.json` typo was silently dropped, and verifying
    // it fires here pins the diagnostic so a future "let's just delete
    // the warning" refactor is caught.

    [Test]
    [NonParallelizable] // mutates Trace.Listeners
    public void Malformed_enum_value_warns_and_leaves_existing_value_unchanged()
    {
        var prior = ProtectedStringOptions.MemoryLockingFailureBehavior;
        var listener = new CapturingTraceListener();
        Trace.Listeners.Add(listener);
        try
        {
            ProtectedStringOptions.MemoryLockingFailureBehavior = MemoryLockingFailureBehavior.Throw;

            var cfg = BuildConfiguration(
                ("TopSecret:ProtectedString:MemoryLockingFailureBehavior", "NotARealValue"));
            cfg.BindProtectedStringOptions();

            Assert.That(ProtectedStringOptions.MemoryLockingFailureBehavior,
                Is.EqualTo(MemoryLockingFailureBehavior.Throw),
                "malformed enum should leave the property at its prior value");
            Assert.That(
                listener.Messages.Any(m =>
                    m.Contains("MemoryLockingFailureBehavior") &&
                    m.Contains("NotARealValue") &&
                    m.Contains("not a valid")),
                Is.True,
                "Trace.TraceWarning must fire for malformed enum value. " +
                "Captured messages: " + string.Join(" | ", listener.Messages));
        }
        finally
        {
            Trace.Listeners.Remove(listener);
            listener.Dispose();
            ProtectedStringOptions.MemoryLockingFailureBehavior = prior;
        }
    }

    [Test]
    [NonParallelizable]
    public void Malformed_TimeSpan_value_warns_and_leaves_existing_value_unchanged()
    {
        var prior = ProtectedStringOptions.UnwrappedKeyCacheTtl;
        var listener = new CapturingTraceListener();
        Trace.Listeners.Add(listener);
        try
        {
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.FromMilliseconds(100);

            var cfg = BuildConfiguration(
                ("TopSecret:ProtectedString:UnwrappedKeyCacheTtl", "not-a-timespan"));
            cfg.BindProtectedStringOptions();

            Assert.That(ProtectedStringOptions.UnwrappedKeyCacheTtl,
                Is.EqualTo(TimeSpan.FromMilliseconds(100)));
            Assert.That(
                listener.Messages.Any(m =>
                    m.Contains("UnwrappedKeyCacheTtl") &&
                    m.Contains("not-a-timespan") &&
                    m.Contains("not a valid TimeSpan")),
                Is.True,
                "Trace.TraceWarning must fire for malformed TimeSpan value. " +
                "Captured messages: " + string.Join(" | ", listener.Messages));
        }
        finally
        {
            Trace.Listeners.Remove(listener);
            listener.Dispose();
            ProtectedStringOptions.UnwrappedKeyCacheTtl = prior;
        }
    }

    [Test]
    [NonParallelizable]
    public void Negative_TimeSpan_for_UnwrappedKeyCacheTtl_warns_and_does_not_throw()
    {
        // The property setter throws on negative values; the binder
        // pre-filters so a misconfiguration warns rather than crashing
        // the host on startup.
        var prior = ProtectedStringOptions.UnwrappedKeyCacheTtl;
        var listener = new CapturingTraceListener();
        Trace.Listeners.Add(listener);
        try
        {
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.FromMilliseconds(50);

            var cfg = BuildConfiguration(
                ("TopSecret:ProtectedString:UnwrappedKeyCacheTtl", "-00:00:01"));
            Assert.DoesNotThrow(() => cfg.BindProtectedStringOptions());

            Assert.That(ProtectedStringOptions.UnwrappedKeyCacheTtl,
                Is.EqualTo(TimeSpan.FromMilliseconds(50)));
            Assert.That(
                listener.Messages.Any(m =>
                    m.Contains("UnwrappedKeyCacheTtl") &&
                    m.Contains("negative")),
                Is.True,
                "Trace.TraceWarning must fire for negative TimeSpan. " +
                "Captured messages: " + string.Join(" | ", listener.Messages));
        }
        finally
        {
            Trace.Listeners.Remove(listener);
            listener.Dispose();
            ProtectedStringOptions.UnwrappedKeyCacheTtl = prior;
        }
    }

    [Test]
    [NonParallelizable]
    public void Missing_keys_do_not_trigger_warnings()
    {
        // Skip-on-missing is silent — only skip-on-malformed warns.
        // Partial configuration (only some keys set) is the common
        // case, not an error.
        var listener = new CapturingTraceListener();
        Trace.Listeners.Add(listener);
        try
        {
            // Configuration has only KeyAtRestProtection set, the other
            // four keys are absent.
            var cfg = BuildConfiguration(
                ("TopSecret:ProtectedString:KeyAtRestProtection", "Obscurity"));

            var prior = ProtectedStringOptions.KeyAtRestProtection;
            try
            {
                cfg.BindProtectedStringOptions();
                Assert.That(listener.Messages, Is.Empty,
                    "no warning should fire for absent keys; " +
                    "captured messages: " + string.Join(" | ", listener.Messages));
            }
            finally
            {
                ProtectedStringOptions.KeyAtRestProtection = prior;
            }
        }
        finally
        {
            Trace.Listeners.Remove(listener);
            listener.Dispose();
        }
    }

    // ---- Section overload + custom section path -------------------------

    [Test]
    public void Section_overload_binds_from_explicit_section()
    {
        var prior = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            // Custom layout: not under "TopSecret:ProtectedString".
            var cfg = BuildConfiguration(
                ("Crypto:Options:ProcessKeyRotationPolicy", "Periodic"));
            ProtectedStringConfigurationExtensions.BindProtectedStringOptions(
                cfg.GetSection("Crypto:Options"));

            Assert.That(ProtectedStringOptions.ProcessKeyRotationPolicy,
                Is.EqualTo(ProcessKeyRotation.Periodic));
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = prior;
        }
    }

    // ---- Null-argument validation ---------------------------------------

    [Test]
    public void Throws_on_null_IConfiguration()
    {
        Assert.Throws<ArgumentNullException>(() =>
            ProtectedStringConfigurationExtensions.BindProtectedStringOptions((IConfiguration)null!));
    }

    [Test]
    public void Throws_on_null_IConfigurationSection()
    {
        Assert.Throws<ArgumentNullException>(() =>
            ProtectedStringConfigurationExtensions.BindProtectedStringOptions((IConfigurationSection)null!));
    }

    // ---- Case-insensitive enum parsing ----------------------------------

    [Test]
    public void Enum_values_are_case_insensitive()
    {
        var prior = ProtectedStringOptions.MemoryLockingFailureBehavior;
        try
        {
            var cfg = BuildConfiguration(
                ("TopSecret:ProtectedString:MemoryLockingFailureBehavior", "throw"));
            cfg.BindProtectedStringOptions();
            Assert.That(ProtectedStringOptions.MemoryLockingFailureBehavior,
                Is.EqualTo(MemoryLockingFailureBehavior.Throw));
        }
        finally
        {
            ProtectedStringOptions.MemoryLockingFailureBehavior = prior;
        }
    }
}
