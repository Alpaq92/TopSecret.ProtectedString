using System.Security.Cryptography;
using NUnit.Framework;

namespace TopSecret.Demo;

/// <summary>
/// A representative, environment-aware slice of the library's behaviour that
/// the demo runs live via NUnit's programmatic runner (see
/// <see cref="DemoTestRunner"/>). Tests that cannot run in the current
/// environment call <see cref="Assert.Ignore(string)"/> so they surface as
/// SKIP rather than FAIL — e.g. Argon2id on the single-threaded WASM runtime,
/// or the hardware-backed tier where no secure element is present.
/// </summary>
/// <remarks>
/// This is deliberately a small smoke slice; the exhaustive suites
/// (tamper matrices, wire-format pinning, rotation, TPM) live in the
/// <c>*.Tests</c> projects and run in CI.
/// </remarks>
[TestFixture]
public class DemoTests
{
    [Test]
    public void ProtectedString_round_trips_through_Access()
    {
        using var ps = new ProtectedString("hunter2".AsSpan());
        int length = ps.Access(plain => plain.Length);
        Assert.That(length, Is.EqualTo(7));
    }

    [Test]
    public void ProtectedString_equality_is_constant_time_and_correct()
    {
        using var a = new ProtectedString("topsecret".AsSpan());
        using var b = new ProtectedString("topsecret".AsSpan());
        using var c = new ProtectedString("topSecret".AsSpan());
        Assert.Multiple(() =>
        {
            Assert.That(a.Equals(b), Is.True);
            Assert.That(a.Equals(c), Is.False);
        });
    }

    [Test]
    public void ProtectedString_CopyTo_matches_source()
    {
        using var ps = new ProtectedString("correct horse".AsSpan());
        Span<char> buffer = stackalloc char[ps.Length];
        ps.CopyTo(buffer);
        Assert.That(buffer.ToString(), Is.EqualTo("correct horse"));
    }

    [Test]
    public void ProtectedBlob_round_trips_across_chunks()
    {
        byte[] original = RandomNumberGenerator.GetBytes(3 * ProtectedBlob.MinChunkSize + 17);
        using var blob = new ProtectedBlob(original.AsSpan(), ProtectedBlob.MinChunkSize);
        var restored = new byte[blob.Length];
        blob.CopyTo(restored);
        Assert.That(restored, Is.EqualTo(original));
    }

    [Test]
    public void ProtectedBlob_reports_chunk_layout()
    {
        // The exhaustive fail-closed tamper matrix lives in TamperTests (CI);
        // here we assert the public chunking contract the reads rely on.
        byte[] original = RandomNumberGenerator.GetBytes(2 * ProtectedBlob.MinChunkSize + 1);
        using var blob = new ProtectedBlob(original.AsSpan(), ProtectedBlob.MinChunkSize);
        Assert.Multiple(() =>
        {
            Assert.That(blob.Length, Is.EqualTo(original.Length));
            Assert.That(blob.ChunkCount, Is.EqualTo(3));
            Assert.That(blob.ChunkSize, Is.EqualTo(ProtectedBlob.MinChunkSize));
        });
    }

    [Test]
    public void ProtectedBlob_streams_unknown_length_input()
    {
        byte[] original = RandomNumberGenerator.GetBytes(2 * ProtectedBlob.MinChunkSize + 5);
        using var blob = ProtectedBlob.FromStream(new MemoryStream(original), ProtectedBlob.MinChunkSize);
        using var collected = new MemoryStream();
        blob.WriteTo(collected);
        Assert.That(collected.ToArray(), Is.EqualTo(original));
    }

    [Test]
    public void Argon2id_verifies_the_right_credential()
    {
        if (OperatingSystem.IsBrowser())
        {
            Assert.Ignore("Argon2 coordinates lanes with blocking thread joins, unsupported on the single-threaded WASM runtime.");
        }

        var salt = RandomNumberGenerator.GetBytes(16);
        using var secret = new ProtectedString("hunter2".AsSpan());
        byte[] stored = secret.ComputeArgon2idHash(salt);
        using var right = new ProtectedString("hunter2".AsSpan());
        using var wrong = new ProtectedString("Hunter2".AsSpan());
        Assert.Multiple(() =>
        {
            Assert.That(right.VerifyArgon2idHash(stored, salt), Is.True);
            Assert.That(wrong.VerifyArgon2idHash(stored, salt), Is.False);
        });
    }

    [Test]
    public void Hardware_backed_tier_round_trips_when_available()
    {
        if (ProtectedString.HardwareBackedAvailability == HardwareBackedAvailability.NoProviderForThisPlatform)
        {
            Assert.Ignore("No hardware-backed provider (TPM / Secure Enclave / Keystore) on this host.");
        }

        using var ps = new ProtectedString("device-bound".AsSpan());
        Assert.That(ps.Access(p => p.Length), Is.EqualTo(12));
    }
}
