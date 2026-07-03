using System.Diagnostics;
using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

/// <summary>
/// Direct unit tests for the individual <see cref="KeyAtRestProtector"/>
/// implementations and the factory's registration surface. The end-to-end
/// path through <see cref="ProtectedString"/> is covered by
/// <see cref="ProtectedStringTests"/>; these tests target the seams that
/// the end-to-end suite cannot reach without spinning up a fresh process
/// per protection mode.
/// </summary>
public class KeyAtRestProtectorTests
{
    // ---- HkdfWrapProtector ---------------------------------------------

    [TestFixture]
    public class HkdfWrap
    {
        [Test]
        public void Round_trips_master()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var expected = master.ToArray();

            var protector = HkdfWrapProtector.TryCreate(master);
            Assert.That(protector, Is.Not.Null);

            using (protector as IDisposable)
            using (var unwrapped = protector!.UnwrapKey())
            {
                Assert.That(unwrapped.Key, Is.EqualTo(expected));
            }
        }

        [Test]
        public void TryCreate_zeros_input_master()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var protector = HkdfWrapProtector.TryCreate(master);

            Assert.That(protector, Is.Not.Null);
            Assert.That(master, Is.All.EqualTo((byte)0),
                "TryCreate must zero the input master once it is wrapped");

            (protector as IDisposable)?.Dispose();
        }

        [Test]
        public void TryCreate_rejects_wrong_size()
        {
            Assert.That(HkdfWrapProtector.TryCreate(new byte[16]), Is.Null);
            Assert.That(HkdfWrapProtector.TryCreate(new byte[33]), Is.Null);
            Assert.That(HkdfWrapProtector.TryCreate(Array.Empty<byte>()), Is.Null);
        }

        [Test]
        public void UnwrapKey_returns_fresh_buffer_per_call()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var protector = HkdfWrapProtector.TryCreate(master)!;

            try
            {
                using var first = protector.UnwrapKey();
                using var second = protector.UnwrapKey();
                Assert.Multiple(() =>
                {
                    Assert.That(first.Key, Is.EqualTo(second.Key),
                        "every unwrap should produce the same plaintext");
                    Assert.That(first.Key, Is.Not.SameAs(second.Key),
                        "every unwrap should hand out a fresh buffer");
                });
            }
            finally
            {
                (protector as IDisposable)?.Dispose();
            }
        }

        [Test]
        public void UnwrapKey_throws_after_dispose()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var protector = HkdfWrapProtector.TryCreate(master)!;
            (protector as IDisposable)!.Dispose();

            Assert.Throws<ObjectDisposedException>(() => protector.UnwrapKey());
        }
    }

    // ---- WindowsAesGcmEphemeralProtector -------------------------------

    [TestFixture]
    [Platform(Include = "Win")]
    public class WindowsAesGcmEphemeral
    {
        [Test]
        public void Round_trips_master()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var expected = master.ToArray();

            var protector = WindowsAesGcmEphemeralProtector.TryCreate(master);
            Assert.That(protector, Is.Not.Null);

            using (protector as IDisposable)
            using (var unwrapped = protector!.UnwrapKey())
            {
                Assert.That(unwrapped.Key, Is.EqualTo(expected));
            }
        }

        [Test]
        public void TryCreate_zeros_input_master()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var protector = WindowsAesGcmEphemeralProtector.TryCreate(master);

            Assert.That(protector, Is.Not.Null);
            Assert.That(master, Is.All.EqualTo((byte)0),
                "TryCreate must zero the input master once it is wrapped");

            (protector as IDisposable)?.Dispose();
        }

        [Test]
        public void TryCreate_rejects_wrong_size()
        {
            Assert.That(WindowsAesGcmEphemeralProtector.TryCreate(new byte[16]), Is.Null);
            Assert.That(WindowsAesGcmEphemeralProtector.TryCreate(new byte[33]), Is.Null);
        }

        [Test]
        public void UnwrapKey_returns_fresh_buffer_per_call()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var protector = WindowsAesGcmEphemeralProtector.TryCreate(master)!;

            try
            {
                using var first = protector.UnwrapKey();
                using var second = protector.UnwrapKey();
                Assert.Multiple(() =>
                {
                    Assert.That(first.Key, Is.EqualTo(second.Key));
                    Assert.That(first.Key, Is.Not.SameAs(second.Key));
                });
            }
            finally
            {
                (protector as IDisposable)?.Dispose();
            }
        }

        [Test]
        public void UnwrapKey_throws_after_dispose()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var protector = WindowsAesGcmEphemeralProtector.TryCreate(master)!;
            (protector as IDisposable)!.Dispose();

            Assert.Throws<ObjectDisposedException>(() => protector.UnwrapKey());
        }
    }

    // ---- TtlCachingKeyAtRestProtector ----------------------------------

    [TestFixture]
    public class TtlCaching
    {
        /// <summary>
        /// Test double that counts UnwrapKey calls so we can assert on
        /// cache hits vs. misses.
        /// </summary>
        private sealed class CountingProtector : KeyAtRestProtector
        {
            private readonly byte[] _master;
            public int UnwrapCount;

            public CountingProtector(byte[] master) => _master = master;

            public override KeyAccessor UnwrapKey()
            {
                Interlocked.Increment(ref UnwrapCount);
                // Persistent so dispose is a no-op; the decorator is supposed
                // to copy the bytes into its own ephemeral buffer.
                return KeyAccessor.Persistent(_master);
            }
        }

        [Test]
        public void First_unwrap_calls_inner_once()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var inner = new CountingProtector(master);
            using var cache = new TtlCachingKeyAtRestProtector(inner, TimeSpan.FromSeconds(10));

            using var unwrapped = cache.UnwrapKey();
            Assert.That(inner.UnwrapCount, Is.EqualTo(1));
            Assert.That(unwrapped.Key, Is.EqualTo(master));
        }

        [Test]
        public void Second_unwrap_within_ttl_is_a_cache_hit()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var inner = new CountingProtector(master);
            using var cache = new TtlCachingKeyAtRestProtector(inner, TimeSpan.FromSeconds(10));

            using (cache.UnwrapKey()) { }
            using (cache.UnwrapKey()) { }
            using (cache.UnwrapKey()) { }

            Assert.That(inner.UnwrapCount, Is.EqualTo(1),
                "subsequent unwraps within the TTL should reuse the cached master");
        }

        [Test]
        public void Unwrap_returns_fresh_ephemeral_buffer_not_the_cache()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var inner = new CountingProtector(master);
            using var cache = new TtlCachingKeyAtRestProtector(inner, TimeSpan.FromSeconds(10));

            using var first = cache.UnwrapKey();
            using var second = cache.UnwrapKey();

            Assert.That(first.Key, Is.EqualTo(second.Key));
            Assert.That(first.Key, Is.Not.SameAs(second.Key),
                "the decorator must hand out a copy, never the long-lived cache buffer");
            Assert.That(first.Key, Is.Not.SameAs(master),
                "the decorator must not expose the inner protector's master directly");
        }

        [Test]
        public void Unwrap_after_ttl_expiry_refreshes_from_inner()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var inner = new CountingProtector(master);
            using var cache = new TtlCachingKeyAtRestProtector(inner, TimeSpan.FromMilliseconds(50));

            using (cache.UnwrapKey()) { }
            Assert.That(inner.UnwrapCount, Is.EqualTo(1));

            // Sleep past the TTL. The decorator uses Environment.TickCount64
            // which advances at OS clock resolution; 200 ms is comfortably
            // past 50 ms on every platform we target.
            Thread.Sleep(200);

            using (cache.UnwrapKey()) { }
            Assert.That(inner.UnwrapCount, Is.EqualTo(2),
                "an unwrap after the TTL elapses must call the inner protector again");
        }

        [Test]
        public void Dispose_blocks_further_unwraps()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var inner = new CountingProtector(master);
            var cache = new TtlCachingKeyAtRestProtector(inner, TimeSpan.FromSeconds(10));

            using (cache.UnwrapKey()) { }
            cache.Dispose();

            Assert.Throws<ObjectDisposedException>(() => cache.UnwrapKey());
        }

        [Test]
        public void Dispose_is_idempotent()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var inner = new CountingProtector(master);
            var cache = new TtlCachingKeyAtRestProtector(inner, TimeSpan.FromSeconds(10));

            cache.Dispose();
            Assert.DoesNotThrow(() => cache.Dispose());
        }
    }

    // ---- NoopKeyAtRestProtector ----------------------------------------

    [TestFixture]
    public class Noop
    {
        [Test]
        public void UnwrapKey_returns_persistent_master_without_copy()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            using var protector = new NoopKeyAtRestProtector(master);

            using var first = protector.UnwrapKey();
            using var second = protector.UnwrapKey();

            Assert.Multiple(() =>
            {
                Assert.That(first.Key, Is.SameAs(master),
                    "Noop should hand out the master directly (Persistent KeyAccessor)");
                Assert.That(second.Key, Is.SameAs(first.Key),
                    "every Noop unwrap should hand out the same buffer");
            });
        }

        [Test]
        public void Dispose_zeros_master_and_is_idempotent()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            // Track whether the master was non-zero before disposal.
            Assert.That(master.Any(b => b != 0), Is.True,
                "RandomNumberGenerator must produce a non-zero master for this test");

            var protector = new NoopKeyAtRestProtector(master);
            protector.Dispose();

            Assert.That(master, Is.All.EqualTo((byte)0),
                "Dispose must zero the master in place");
            Assert.DoesNotThrow(() => protector.Dispose(), "Dispose should be idempotent");
        }

        [Test]
        public void Dispose_handles_zero_length_master()
        {
            var protector = new NoopKeyAtRestProtector(Array.Empty<byte>());
            Assert.DoesNotThrow(() => protector.Dispose());
        }
    }

    // ---- Late-mutation diagnostic warning ------------------------------

    [TestFixture]
    [NonParallelizable] // Mutates the process-global Trace listeners + warning gate.
    public class LateMutationWarning
    {
        private sealed class CapturingListener : TraceListener
        {
            public readonly List<string> Warnings = new();
            public override void Write(string? message) { }
            public override void WriteLine(string? message)
            {
                if (message is not null) Warnings.Add(message);
            }
            public override void TraceEvent(TraceEventCache? eventCache, string source,
                TraceEventType eventType, int id, string? message)
            {
                if (eventType == TraceEventType.Warning && message is not null)
                {
                    Warnings.Add(message);
                }
            }
        }

        [Test]
        public void First_late_mutation_emits_warning_and_subsequent_ones_do_not()
        {
            // Force the lazy protector init so subsequent option mutations
            // count as "late."
            using (new ProtectedString()) { }

            // Reset the one-shot gate so we exercise the warning path even
            // if a prior test in this run already tripped it.
            ProtectedStringOptions._ResetLateMutationWarningForTests();

            var listener = new CapturingListener();
            Trace.Listeners.Add(listener);
            var priorTtl = ProtectedStringOptions.UnwrappedKeyCacheTtl;
            var priorMode = ProtectedStringOptions.KeyAtRestProtection;
            var priorInterval = ProtectedStringOptions.ProcessKeyRotationInterval;
            try
            {
                // First late mutation: warning fires.
                ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.FromMilliseconds(50);
                Assert.That(listener.Warnings, Has.Count.EqualTo(1),
                    "first late mutation should emit one Trace.TraceWarning");
                Assert.That(listener.Warnings[0],
                    Does.Contain("UnwrappedKeyCacheTtl").And.Contain("ProtectedString"));

                // Subsequent late mutations of any read-once option must
                // NOT emit a second warning (the gate is process-wide).
                ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.Obscurity;
                ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.FromMinutes(30);
                Assert.That(listener.Warnings, Has.Count.EqualTo(1),
                    "the warning gate is one-shot per process across all read-once options");
            }
            finally
            {
                ProtectedStringOptions.UnwrappedKeyCacheTtl = priorTtl;
                ProtectedStringOptions.KeyAtRestProtection = priorMode;
                ProtectedStringOptions.ProcessKeyRotationInterval = priorInterval;
                Trace.Listeners.Remove(listener);
            }
        }
    }

    // ---- KeyAtRestProtectorFactory: registration surface ---------------

    [TestFixture]
    [NonParallelizable] // Mutates the process-global registry.
    public class FactoryRegistration
    {
        [SetUp]
        public void Setup()
        {
            // Snapshot any registrations a previous test (or a module
            // initializer in a referenced assembly) might have added, so we
            // can isolate this fixture's mutations from the rest of the suite.
            // Routed through TestAccessors to bypass the [Obsolete(error: true)]
            // compile-time block on ResetRegistrationsForTests.
            TestAccessors.ResetFactoryRegistrations();
        }

        [TearDown]
        public void Teardown()
        {
            TestAccessors.ResetFactoryRegistrations();
        }

        [Test]
        public void Empty_registry_reports_no_transient_slot_provider()
        {
            Assert.That(KeyAtRestProtectorFactory.HasTransientSlotConstrainedProvider(), Is.False);
        }

        [Test]
        public void Registered_provider_with_flag_is_visible_via_HasTransientSlotConstrainedProvider()
        {
            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: _ => null, // never actually constructs
                availabilityProbe: () => false,
                transientSlotConstrained: true);

            Assert.That(KeyAtRestProtectorFactory.HasTransientSlotConstrainedProvider(), Is.True);
        }

        [Test]
        public void Registered_provider_without_flag_does_not_set_HasTransientSlotConstrainedProvider()
        {
            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: _ => null,
                availabilityProbe: () => true);
            // transientSlotConstrained defaults to false.

            Assert.That(KeyAtRestProtectorFactory.HasTransientSlotConstrainedProvider(), Is.False);
        }

        [Test]
        public void Reset_clears_all_registrations()
        {
            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: _ => null,
                availabilityProbe: () => true,
                transientSlotConstrained: true);
            Assert.That(KeyAtRestProtectorFactory.HasTransientSlotConstrainedProvider(), Is.True);

            TestAccessors.ResetFactoryRegistrations();

            Assert.That(KeyAtRestProtectorFactory.HasTransientSlotConstrainedProvider(), Is.False);
        }

        [Test]
        public void RegisterHardwareBacked_throws_on_null_factory()
        {
            Assert.Throws<ArgumentNullException>(() =>
                KeyAtRestProtectorFactory.RegisterHardwareBacked(factory: null!));
        }

        [Test]
        public void Probe_marks_registry_available_when_at_least_one_probe_passes()
        {
            // Don't run the platform-default branches on Apple — those
            // assertions live in HardwareBackedAvailability_reports_known_state_for_this_host.
            if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
            {
                Assert.Ignore("Platform has built-in Apple SEP; this test only covers the registered-provider path.");
                return;
            }

            // Empty registry → not available.
            Assert.That(ProtectedString.HardwareBackedAvailability,
                Is.EqualTo(HardwareBackedAvailability.NoProviderForThisPlatform));

            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: _ => null,
                availabilityProbe: () => true);

            Assert.That(ProtectedString.HardwareBackedAvailability,
                Is.EqualTo(HardwareBackedAvailability.Available));
        }

        [Test]
        public void Probe_treats_provider_with_no_probe_as_available()
        {
            if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
            {
                Assert.Ignore("Platform has built-in Apple SEP; this test only covers the registered-provider path.");
                return;
            }

            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: _ => null,
                availabilityProbe: null); // omitted probe

            Assert.That(ProtectedString.HardwareBackedAvailability,
                Is.EqualTo(HardwareBackedAvailability.Available));
        }
    }
}
