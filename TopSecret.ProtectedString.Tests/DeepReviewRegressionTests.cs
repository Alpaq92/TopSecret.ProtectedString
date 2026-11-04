using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

[TestFixture]
[NonParallelizable]
public class DeepReviewRegressionTests
{
    // ---- option validation --------------------------------------------------

    [Test]
    public void KeyAtRestProtection_rejects_undefined_enum_values()
    {
        var prior = ProtectedStringOptions.KeyAtRestProtection;
        try
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => ProtectedStringOptions.KeyAtRestProtection = (KeyAtRestProtection)42,
                "an integer cast outside the defined members must not reach the factory");
            Assert.Throws<ArgumentOutOfRangeException>(
                () => ProtectedStringOptions.KeyAtRestProtection =
                    KeyAtRestProtection.HardwareBackedRequired | KeyAtRestProtection.GuardedPage,
                "a bitwise combination of members is not a defined member");
            Assert.That(ProtectedStringOptions.KeyAtRestProtection, Is.EqualTo(prior),
                "a rejected assignment must leave the option untouched");
        }
        finally
        {
            ProtectedStringOptions.KeyAtRestProtection = prior;
        }
    }

    [Test]
    public void ProcessKeyRotationPolicy_and_MemoryLockingFailureBehavior_reject_undefined_values()
    {
        var priorPolicy = ProtectedStringOptions.ProcessKeyRotationPolicy;
        var priorBehavior = ProtectedStringOptions.MemoryLockingFailureBehavior;
        try
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => ProtectedStringOptions.ProcessKeyRotationPolicy = (ProcessKeyRotation)99);
            Assert.Throws<ArgumentOutOfRangeException>(
                () => ProtectedStringOptions.MemoryLockingFailureBehavior = (MemoryLockingFailureBehavior)99);
            Assert.That(ProtectedStringOptions.ProcessKeyRotationPolicy, Is.EqualTo(priorPolicy));
            Assert.That(ProtectedStringOptions.MemoryLockingFailureBehavior, Is.EqualTo(priorBehavior));

            // Every defined member still round-trips.
            foreach (var v in Enum.GetValues<ProcessKeyRotation>())
            {
                ProtectedStringOptions.ProcessKeyRotationPolicy = v;
                Assert.That(ProtectedStringOptions.ProcessKeyRotationPolicy, Is.EqualTo(v));
            }
            foreach (var v in Enum.GetValues<MemoryLockingFailureBehavior>())
            {
                ProtectedStringOptions.MemoryLockingFailureBehavior = v;
                Assert.That(ProtectedStringOptions.MemoryLockingFailureBehavior, Is.EqualTo(v));
            }
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = priorPolicy;
            ProtectedStringOptions.MemoryLockingFailureBehavior = priorBehavior;
        }
    }

    [Test]
    public void Timer_fed_durations_are_capped_at_MaxTimerDuration()
    {
        var priorTtl = ProtectedStringOptions.UnwrappedKeyCacheTtl;
        var priorInterval = ProtectedStringOptions.ProcessKeyRotationInterval;
        try
        {
            Assert.That(ProtectedStringOptions.MaxTimerDuration.TotalMilliseconds,
                Is.EqualTo(4_294_967_294d));

            Assert.Throws<ArgumentOutOfRangeException>(
                () => ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.MaxValue);
            Assert.Throws<ArgumentOutOfRangeException>(
                () => ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.FromDays(50));
            Assert.Throws<ArgumentOutOfRangeException>(
                () => ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.FromDays(50));
            Assert.Throws<ArgumentOutOfRangeException>(
                () => ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.FromSeconds(-1));

            // The ceiling itself and ordinary values are accepted.
            ProtectedStringOptions.UnwrappedKeyCacheTtl = ProtectedStringOptions.MaxTimerDuration;
            Assert.That(ProtectedStringOptions.UnwrappedKeyCacheTtl, Is.EqualTo(ProtectedStringOptions.MaxTimerDuration));
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero;
            ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.FromMinutes(5);
            Assert.That(ProtectedStringOptions.ProcessKeyRotationInterval, Is.EqualTo(TimeSpan.FromMinutes(5)));
        }
        finally
        {
            ProtectedStringOptions.UnwrappedKeyCacheTtl = priorTtl;
            ProtectedStringOptions.ProcessKeyRotationInterval = priorInterval;
        }
    }

    // ---- TryRotateProcessKey ---------------------------------------------------

    [Test]
    public void TryRotateProcessKey_returns_true_when_it_rotates_and_the_value_survives()
    {
        var prior = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;
            using var ps = new ProtectedString("survives-rotation".AsSpan());

            Assert.That(ProtectedString.TryRotateProcessKey(), Is.True,
                "an uncontended call must perform the rotation and say so");
            Assert.That(ps.Access(p => new string(p)), Is.EqualTo("survives-rotation"));
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = prior;
        }
    }

    [Test]
    public void TryRotateProcessKey_throws_like_RotateProcessKey_when_policy_is_Disabled()
    {
        var prior = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.Disabled;
            Assert.Throws<InvalidOperationException>(() => ProtectedString.TryRotateProcessKey());
            Assert.Throws<InvalidOperationException>(() => ProtectedString.RotateProcessKey());
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = prior;
        }
    }

    [Test]
    public void TryRotateProcessKey_reports_false_for_the_call_that_lost_the_race()
    {
        var prior = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;

            using var ps = new ProtectedString("slow".AsSpan());
            var gate = new ManualResetEventSlim(false);
            var entered = new ManualResetEventSlim(false);
            var slow = new BlockingProtector(ProtectedString.GetOrInitProcessProtector(), gate, entered);
            TestAccessors.SetInstanceProtector(ps, slow);
            TestAccessors.SetProcessKeyProtector(slow);

            bool? firstResult = null;
            var first = new Thread(() => firstResult = ProtectedString.TryRotateProcessKey());
            first.Start();
            Assert.That(entered.Wait(TimeSpan.FromSeconds(10)), Is.True, "rotation never reached the stalled protector");

            bool second = ProtectedString.TryRotateProcessKey();
            gate.Set();
            first.Join();

            Assert.That(second, Is.False, "the call made while a pass was in flight must report that it was dropped");
            Assert.That(firstResult, Is.True, "the pass that held the in-flight gate must report success");
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = prior;
        }
    }

    private sealed class BlockingProtector : KeyAtRestProtector
    {
        private readonly KeyAtRestProtector _inner;
        private readonly ManualResetEventSlim _gate;
        private readonly ManualResetEventSlim _entered;
        private int _blocked;

        public BlockingProtector(KeyAtRestProtector inner, ManualResetEventSlim gate, ManualResetEventSlim entered)
        {
            _inner = inner; _gate = gate; _entered = entered;
        }

        public override KeyAccessor UnwrapKey()
        {
            if (Interlocked.Exchange(ref _blocked, 1) == 0)
            {
                _entered.Set();
                _gate.Wait();
            }
            return _inner.UnwrapKey();
        }
    }

    // ---- Build factory ---------------------------------------------------------

    [Test]
    public void Build_produces_a_read_only_instance_with_the_appended_value()
    {
        using var ps = ProtectedString.Build(b =>
        {
            b.AppendChars("corr".AsSpan());
            b.AppendChar('e');
            b.AppendUtf8("ct"u8);
        });

        Assert.That(ps.IsReadOnly, Is.True);
        Assert.That(ps.Access(p => new string(p)), Is.EqualTo("correct"));
    }

    [Test]
    public void Build_disposes_the_half_built_instance_when_fill_throws()
    {
        ProtectedString? leaked = null;
        var ex = Assert.Throws<InvalidOperationException>(() => ProtectedString.Build(b =>
        {
            b.AppendChars("partial".AsSpan());
            leaked = b;
            throw new InvalidOperationException("boom");
        }));

        Assert.That(ex!.Message, Is.EqualTo("boom"), "the caller's exception must propagate unchanged");
        Assert.That(leaked, Is.Not.Null);
        Assert.That(leaked!.IsDisposed, Is.True, "a failed Build must not leave a live instance holding plaintext");
    }

    [Test]
    public void Build_rejects_null_fill() =>
        Assert.Throws<ArgumentNullException>(() => ProtectedString.Build(null!));

    // ---- Argon2 contract -------------------------------------------------------

    [Test]
    public void VerifyArgon2idHash_returns_false_for_a_stored_hash_shorter_than_the_minimum()
    {
        using var ps = new ProtectedString("hunter2".AsSpan());
        var salt = RandomNumberGenerator.GetBytes(16);

        // A 15-byte verifier can never have been produced by ComputeArgon2idHash
        // (16-byte floor), so it is a non-match, not an argument error.
        Assert.That(ps.VerifyArgon2idHash(new byte[15], salt, iterations: 1, memoryKb: 8), Is.False);
        Assert.That(ps.VerifyArgon2idHash(Array.Empty<byte>(), salt, iterations: 1, memoryKb: 8), Is.False);
    }

    [Test]
    public void Argon2id_calibration_overloads_match_the_explicit_parameter_overloads()
    {
        using var ps = new ProtectedString("hunter2".AsSpan());
        var salt = RandomNumberGenerator.GetBytes(16);
        var calibration = new Argon2idCalibration(Iterations: 2, MemoryKb: 64, Parallelism: 1, Measured: TimeSpan.Zero);

        var viaCalibration = ps.ComputeArgon2idHash(salt, calibration);
        var viaExplicit = ps.ComputeArgon2idHash(salt, iterations: 2, memoryKb: 64, parallelism: 1);

        Assert.That(viaCalibration, Is.EqualTo(viaExplicit));
        Assert.That(ps.VerifyArgon2idHash(viaExplicit, salt, calibration), Is.True);
        viaExplicit[0] ^= 0xFF;
        Assert.That(ps.VerifyArgon2idHash(viaExplicit, salt, calibration), Is.False);
    }

    [Test]
    public void Argon2id_hash_leaves_the_instance_fully_usable_and_disposable()
    {
        using var ps = new ProtectedString("hunter2".AsSpan());
        var salt = RandomNumberGenerator.GetBytes(16);
        _ = ps.ComputeArgon2idHash(salt, iterations: 1, memoryKb: 8);

        Assert.That(ps.Access(p => new string(p)), Is.EqualTo("hunter2"));
        using var copy = ps.Copy();
        Assert.That(copy.Equals(ps), Is.True);
    }
}
