using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

public class KeyAtRestProtectorFactoryCoverageTests
{
    private static bool IsApplePlatform =>
        OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst();

    private static readonly FieldInfo s_warnedNoProviderField =
        typeof(KeyAtRestProtectorFactory).GetField(
            "s_warnedNoProvider", BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException(
            "KeyAtRestProtectorFactory.s_warnedNoProvider not found via reflection");

    private static void ResetNoProviderWarningGate() =>
        s_warnedNoProviderField.SetValue(null, 0);

    private sealed class FakeHardwareBackedProtector : KeyAtRestProtector, IDisposable
    {
        private readonly byte[] _master;

        public FakeHardwareBackedProtector(byte[] master)
        {
            _master = master.ToArray();
            CryptographicOperations.ZeroMemory(master);
        }

        public override KeyAccessor UnwrapKey() => KeyAccessor.Ephemeral(_master.ToArray());

        public void Dispose() => CryptographicOperations.ZeroMemory(_master);
    }

    // ---- KeyAtRestProtectorFactory.Create: tier walk --------------------

    [TestFixture]
    [NonParallelizable] // Mutates process-global options + provider registry; restores both in teardown.
    public class CreateTierWalk
    {
        private KeyAtRestProtection _priorMode;
        private TimeSpan _priorTtl;
        private MemoryLockingFailureBehavior _priorBehavior;

        [SetUp]
        public void SetUp()
        {
            _priorMode = ProtectedStringOptions.KeyAtRestProtection;
            _priorTtl = ProtectedStringOptions.UnwrappedKeyCacheTtl;
            _priorBehavior = ProtectedStringOptions.MemoryLockingFailureBehavior;
            TestAccessors.ResetFactoryRegistrations();
        }

        [TearDown]
        public void TearDown()
        {
            ProtectedStringOptions.KeyAtRestProtection = _priorMode;
            ProtectedStringOptions.UnwrappedKeyCacheTtl = _priorTtl;
            ProtectedStringOptions.MemoryLockingFailureBehavior = _priorBehavior;
            TestAccessors.ResetFactoryRegistrations();
        }

        // Covers KeyAtRestProtector.cs 392,398-402,404,406-407,410-412 (one-shot no-provider warning)
        // plus 423-427,460,479-481,501 (tier-1 miss) and 439-443,506,516 (obscurity fall-through).
        [Test]
        public void Preferred_with_empty_registry_warns_once_and_falls_back_to_obscurity()
        {
            if (IsApplePlatform)
            {
                Assert.Ignore("Apple has a built-in SEP provider; the no-provider warning path returns early there.");
                return;
            }

            ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.HardwareBackedPreferred;
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero;

            // Make the one-shot gate deterministic regardless of test ordering.
            ResetNoProviderWarningGate();

            var listener = new CapturingTraceListener();
            Trace.Listeners.Add(listener);
            KeyAtRestProtector? first = null;
            KeyAtRestProtector? second = null;
            try
            {
                var master = RandomNumberGenerator.GetBytes(32);
                var expected = master.ToArray();

                first = KeyAtRestProtectorFactory.Create(master);

                Assert.That(first, Is.Not.Null);
                Assert.That(first, Is.Not.InstanceOf<NoopKeyAtRestProtector>(),
                    "Preferred must fall back to the obscurity tier, not straight to no-op");
                using (var unwrapped = first.UnwrapKey())
                {
                    Assert.That(unwrapped.Key, Is.EqualTo(expected),
                        "the obscurity fallback must round-trip the master");
                }

                bool WarningMatch(string m) => m.Contains("no hardware-backed provider");
                Assert.That(listener.Messages.Count(WarningMatch), Is.EqualTo(1),
                    "first HW-mode Create with an empty registry emits exactly one warning");
                var warning = listener.Messages.Single(WarningMatch);
                if (OperatingSystem.IsLinux())
                {
                    Assert.That(warning, Does.Contain("TopSecret.ProtectedString.LinuxTpm"));
                }
                else if (OperatingSystem.IsWindows())
                {
                    Assert.That(warning, Does.Contain("TopSecret.ProtectedString.WindowsTpm"));
                }

                // Second Create: gate already tripped, no second warning.
                second = KeyAtRestProtectorFactory.Create(RandomNumberGenerator.GetBytes(32));
                Assert.That(listener.Messages.Count(WarningMatch), Is.EqualTo(1),
                    "the no-provider warning is one-shot per process");
            }
            finally
            {
                Trace.Listeners.Remove(listener);
                (first as IDisposable)?.Dispose();
                (second as IDisposable)?.Dispose();
            }
        }

        // Covers KeyAtRestProtector.cs 429,433 (Required-mode hard failure) and
        // 519-521,523-524,529-533 (BuildRequiredFailureMessage, Linux hint branch).
        [Test]
        public void Required_with_empty_registry_throws_PlatformNotSupported_with_platform_hint()
        {
            if (IsApplePlatform)
            {
                Assert.Ignore("Apple has a built-in SEP provider; Required may succeed there instead of throwing.");
                return;
            }

            ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.HardwareBackedRequired;
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero;

            var master = RandomNumberGenerator.GetBytes(32);
            var ex = Assert.Throws<PlatformNotSupportedException>(
                () => KeyAtRestProtectorFactory.Create(master));

            Assert.That(ex!.Message, Does.Contain("HardwareBackedRequired"));
            Assert.That(ex.Message, Does.Contain("HardwareBackedPreferred"),
                "the failure message must point at the fallback-permitting mode");
            if (OperatingSystem.IsLinux())
            {
                Assert.That(ex.Message, Does.Contain("TopSecret.ProtectedString.LinuxTpm"));
            }
            else if (OperatingSystem.IsWindows())
            {
                Assert.That(ex.Message, Does.Contain("TopSecret.ProtectedString.WindowsTpm"));
            }
        }

        [Test]
        public void Preferred_returns_protector_from_registered_provider()
        {
            if (IsApplePlatform)
            {
                Assert.Ignore("Apple tries the built-in SEP provider before external registrations; result is nondeterministic on Apple CI hosts.");
                return;
            }

            ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.HardwareBackedPreferred;
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero;

            FakeHardwareBackedProtector? constructed = null;
            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: m => constructed = new FakeHardwareBackedProtector(m),
                availabilityProbe: () => true);

            var master = RandomNumberGenerator.GetBytes(32);
            var expected = master.ToArray();

            var protector = KeyAtRestProtectorFactory.Create(master);
            try
            {
                Assert.That(protector, Is.SameAs(constructed),
                    "Create must hand back the registered provider's protector");
                Assert.That(master, Is.All.EqualTo((byte)0),
                    "the provider takes ownership of the master and zeros the input array");
                using var unwrapped = protector.UnwrapKey();
                Assert.That(unwrapped.Key, Is.EqualTo(expected));
            }
            finally
            {
                (protector as IDisposable)?.Dispose();
            }
        }

        // Covers KeyAtRestProtector.cs 485,489-492,498 (throwing provider swallowed
        // by the catch, loop continues) and 501 (all providers miss → return null).
        [Test]
        public void Throwing_and_declining_providers_are_skipped_then_obscurity_fallback_is_used()
        {
            if (IsApplePlatform)
            {
                Assert.Ignore("Apple tries the built-in SEP provider before external registrations; result is nondeterministic on Apple CI hosts.");
                return;
            }

            ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.HardwareBackedPreferred;
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero;

            bool throwingCalled = false, decliningCalled = false;
            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: _ => { throwingCalled = true; throw new InvalidOperationException("simulated provider failure"); });
            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: _ => { decliningCalled = true; return null; });

            var master = RandomNumberGenerator.GetBytes(32);
            var expected = master.ToArray();

            var protector = KeyAtRestProtectorFactory.Create(master);
            try
            {
                Assert.Multiple(() =>
                {
                    Assert.That(throwingCalled, Is.True, "the throwing provider must have been tried");
                    Assert.That(decliningCalled, Is.True, "the loop must continue past a throwing provider");
                    Assert.That(protector, Is.Not.InstanceOf<NoopKeyAtRestProtector>(),
                        "Preferred with an all-miss registry falls back to the obscurity tier");
                });
                using var unwrapped = protector.UnwrapKey();
                Assert.That(unwrapped.Key, Is.EqualTo(expected));
            }
            finally
            {
                (protector as IDisposable)?.Dispose();
            }
        }

        // Covers KeyAtRestProtector.cs 371 (positive UnwrappedKeyCacheTtl wraps a
        // non-noop protector in TtlCachingKeyAtRestProtector) plus 439-443,506,516.
        [Test]
        public void Positive_cache_ttl_wraps_non_noop_protector_in_ttl_cache()
        {
            // Obscurity skips tier 1 entirely, so this runs unguarded on every OS.
            ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.Obscurity;
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.FromSeconds(5);

            var master = RandomNumberGenerator.GetBytes(32);
            var expected = master.ToArray();

            var protector = KeyAtRestProtectorFactory.Create(master);
            try
            {
                Assert.That(protector, Is.InstanceOf<TtlCachingKeyAtRestProtector>(),
                    "a positive TTL must wrap the obscurity protector in the caching decorator");
                using var unwrapped = protector.UnwrapKey();
                Assert.That(unwrapped.Key, Is.EqualTo(expected));
            }
            finally
            {
                (protector as IDisposable)?.Dispose();
            }
        }

        // The obscurity tier is AES-GCM-wrap on every platform (AesGcmShim is
        // cross-platform); HKDF is reached only if AES-GCM construction declines.
        [Test]
        public void Obscurity_selects_AesGcmWrapProtector_on_every_platform()
        {
            ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.Obscurity;
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero;

            var master = RandomNumberGenerator.GetBytes(32);
            var expected = master.ToArray();

            var protector = KeyAtRestProtectorFactory.Create(master);
            try
            {
                Assert.That(protector, Is.InstanceOf<AesGcmWrapProtector>(),
                    "the obscurity tier must pick the AES-GCM wrap regardless of OS");
                Assert.That(master, Is.All.EqualTo((byte)0),
                    "the obscurity protector takes ownership of the master and zeros the input array");
                using var unwrapped = protector.UnwrapKey();
                Assert.That(unwrapped.Key, Is.EqualTo(expected));
            }
            finally
            {
                (protector as IDisposable)?.Dispose();
            }
        }

        // Covers KeyAtRestProtector.cs 445,450 (obscurity tier total miss →
        // HardeningPolicy.OnFailure) and 454 (final no-op fallback).
        [Test]
        public void Obscurity_with_invalid_master_size_falls_back_to_noop_under_Ignore_policy()
        {
            ProtectedStringOptions.MemoryLockingFailureBehavior = MemoryLockingFailureBehavior.Ignore;
            ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.Obscurity;
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero;

            var master = RandomNumberGenerator.GetBytes(16); // wrong size on purpose
            var protector = KeyAtRestProtectorFactory.Create(master);

            Assert.That(protector, Is.InstanceOf<NoopKeyAtRestProtector>(),
                "when every obscurity path declines, Create falls back to the no-op protector");
            ((IDisposable)protector).Dispose();
        }
    }

    // ---- IsHardwareBackedAvailableForCurrentPlatform: all-probes-false ---

    [TestFixture]
    [NonParallelizable] // Mutates the process-global provider registry; restores in teardown.
    public class AvailabilityAllProbesFalse
    {
        [SetUp]
        public void SetUp() => TestAccessors.ResetFactoryRegistrations();

        [TearDown]
        public void TearDown() => TestAccessors.ResetFactoryRegistrations();

        // Covers KeyAtRestProtector.cs 313 (registry non-empty but every probe false → unavailable).
        [Test]
        public void Registry_with_only_false_probes_reports_unavailable()
        {
            if (IsApplePlatform)
            {
                Assert.Ignore("Apple answers availability via the built-in SEP probe before consulting the registry.");
                return;
            }

            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: _ => null, availabilityProbe: () => false);
            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: _ => null, availabilityProbe: () => false);

            Assert.Multiple(() =>
            {
                Assert.That(KeyAtRestProtectorFactory.IsHardwareBackedAvailableForCurrentPlatform(),
                    Is.False, "a registry where every probe declines must report unavailable");
                Assert.That(ProtectedString.HardwareBackedAvailability,
                    Is.EqualTo(HardwareBackedAvailability.NoProviderForThisPlatform));
            });
        }
    }
}
