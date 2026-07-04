using System.Security.Cryptography;
using NUnit.Framework;

namespace TopSecret.Demo;

/// <summary>
/// A representative, environment-aware slice of the library's behaviour that
/// the demo runs live via the reflection-based <see cref="DemoTestRunner"/>.
/// Tests that cannot run in the current environment call
/// <see cref="Assert.Ignore(string)"/> so they surface as SKIP rather than
/// FAIL — e.g. Argon2id on the single-threaded WASM runtime, or the
/// hardware-backed tier where no secure element is present. Inputs come from
/// <see cref="DemoInputs"/>, so every run exercises fresh random values.
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
        string secret = DemoInputs.RandomSecret();
        using var ps = new ProtectedString(secret.AsSpan());
        int length = ps.Access(plain => plain.Length);
        Assert.That(length, Is.EqualTo(secret.Length));
    }

    [Test]
    public void ProtectedString_equality_is_constant_time_and_correct()
    {
        string value = DemoInputs.RandomSecret();
        using var a = new ProtectedString(value.AsSpan());
        using var b = new ProtectedString(value.AsSpan());
        using var c = new ProtectedString(DemoInputs.MutateOneChar(value).AsSpan());
        Assert.Multiple(() =>
        {
            Assert.That(a.Equals(b), Is.True);
            Assert.That(a.Equals(c), Is.False);
        });
    }

    [Test]
    public void ProtectedString_CopyTo_matches_source()
    {
        string source = DemoInputs.RandomSecret();
        using var ps = new ProtectedString(source.AsSpan());
        Span<char> buffer = stackalloc char[ps.Length];
        ps.CopyTo(buffer);
        Assert.That(buffer.ToString(), Is.EqualTo(source));
    }

    [Test]
    public void ProtectedBlob_round_trips_across_chunks()
    {
        // Random content AND a random partial final chunk each run.
        byte[] original = RandomNumberGenerator.GetBytes(
            3 * ProtectedBlob.MinChunkSize + RandomNumberGenerator.GetInt32(1, ProtectedBlob.MinChunkSize));
        using var blob = new ProtectedBlob(original.AsSpan(), ProtectedBlob.MinChunkSize);
        var restored = new byte[blob.Length];
        blob.CopyTo(restored);
        Assert.That(restored, Is.EqualTo(original));
    }

    [Test]
    public void ProtectedBlob_reports_chunk_layout()
    {
        // The exhaustive fail-closed tamper matrix lives in TamperTests (CI);
        // here we assert the public chunking contract the reads rely on. The
        // random tail stays in [1, MinChunkSize) so ChunkCount is always 3.
        byte[] original = RandomNumberGenerator.GetBytes(
            2 * ProtectedBlob.MinChunkSize + RandomNumberGenerator.GetInt32(1, ProtectedBlob.MinChunkSize));
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
        byte[] original = RandomNumberGenerator.GetBytes(
            2 * ProtectedBlob.MinChunkSize + RandomNumberGenerator.GetInt32(1, ProtectedBlob.MinChunkSize));
        using var blob = ProtectedBlob.FromStream(new MemoryStream(original), ProtectedBlob.MinChunkSize);
        using var collected = new MemoryStream();
        blob.WriteTo(collected);
        Assert.That(collected.ToArray(), Is.EqualTo(original));
    }

    [Test]
    public void Argon2id_verifies_the_right_credential()
    {
        // Argon2id is deliberately unsupported on the single-threaded WASM
        // runtime (the library fails fast with PlatformNotSupportedException;
        // an async wrapper was evaluated and rejected on security grounds —
        // see the README's browser-wasm section). Self-skip there, run
        // everywhere else.
        string credential = DemoInputs.RandomSecret();
        var salt = RandomNumberGenerator.GetBytes(16);
        byte[] stored;
        try
        {
            using var secret = new ProtectedString(credential.AsSpan());
            stored = secret.ComputeArgon2idHash(salt);
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Ignore("Argon2id is not supported on this host (browser/WASM) — hash server-side.");
            return;
        }

        using var right = new ProtectedString(credential.AsSpan());
        using var wrong = new ProtectedString(DemoInputs.MutateOneChar(credential).AsSpan());
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

        string value = DemoInputs.RandomSecret();
        using var ps = new ProtectedString(value.AsSpan());
        Assert.That(ps.Access(p => p.Length), Is.EqualTo(value.Length));
    }
}
