using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

[TestFixture]
public class Argon2CalibratorTests
{
    [Test]
    public void Tune_never_returns_below_the_OWASP_floors()
    {
        // A tiny target that the floor already exceeds must return the floor,
        // not something weaker.
        var result = Argon2Calibrator.Tune(TimeSpan.FromMilliseconds(1));

        Assert.That(result.Iterations, Is.GreaterThanOrEqualTo(ProtectedString.DefaultArgon2idIterations));
        Assert.That(result.MemoryKb, Is.GreaterThanOrEqualTo(ProtectedString.DefaultArgon2idMemoryKb));
        Assert.That(result.Parallelism, Is.EqualTo(ProtectedString.DefaultArgon2idParallelism));
        Assert.That(result.Measured, Is.GreaterThan(TimeSpan.Zero));
    }

    [Test]
    public void Tune_scales_memory_up_for_a_larger_target()
    {
        // A modest but non-trivial target: the calibrator should raise memory
        // above the floor to reach it (unless the host is unusually slow, in
        // which case the floor already meets the target — allowed).
        var floorTime = Argon2Calibrator.Tune(TimeSpan.FromMilliseconds(1)).Measured;
        var target = TimeSpan.FromMilliseconds(floorTime.TotalMilliseconds * 4);

        var result = Argon2Calibrator.Tune(target);

        Assert.That(result.MemoryKb, Is.GreaterThanOrEqualTo(ProtectedString.DefaultArgon2idMemoryKb));
        // The produced parameters must actually be usable by the hasher.
        using var ps = new ProtectedString("calibrated".AsSpan());
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = ps.ComputeArgon2idHash(salt, result.Iterations, result.MemoryKb, result.Parallelism);
        Assert.That(ps.VerifyArgon2idHash(hash, salt, result.Iterations, result.MemoryKb, result.Parallelism), Is.True);
    }

    [Test]
    public void Tune_respects_a_parallelism_override()
    {
        var result = Argon2Calibrator.Tune(TimeSpan.FromMilliseconds(1), parallelism: 2);
        Assert.That(result.Parallelism, Is.EqualTo(2));
    }

    [Test]
    public void Tune_validates_its_arguments()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2Calibrator.Tune(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2Calibrator.Tune(TimeSpan.FromMilliseconds(100), parallelism: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2Calibrator.Tune(TimeSpan.FromMilliseconds(100), maxMemoryKb: 1024));
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2Calibrator.Tune(TimeSpan.FromMilliseconds(100), tolerance: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2Calibrator.Tune(TimeSpan.FromMilliseconds(100), tolerance: 1));
    }
}
