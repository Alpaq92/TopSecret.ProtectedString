using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedBlobTests;

[TestFixture]
public class LifecycleTests
{
    [Test]
    public void Dispose_Marks_Disposed_And_Every_Member_Throws()
    {
        var blob = new ProtectedBlob(RandomNumberGenerator.GetBytes(100).AsSpan());
        blob.Dispose();

        Assert.Multiple(() =>
        {
            Assert.That(blob.IsDisposed, Is.True);
            Assert.That(blob.ToString(), Is.EqualTo("ProtectedBlob[disposed]"));
            Assert.Throws<ObjectDisposedException>(() => _ = blob.Length);
            Assert.Throws<ObjectDisposedException>(() => _ = blob.ChunkCount);
            Assert.Throws<ObjectDisposedException>(() => _ = blob.ChunkSize);
            Assert.Throws<ObjectDisposedException>(() => blob.AccessChunk(0, _ => { }));
            Assert.Throws<ObjectDisposedException>(() => blob.AccessChunk(0, _ => 0));
            Assert.Throws<ObjectDisposedException>(() => blob.AccessChunks(_ => { }));
            Assert.Throws<ObjectDisposedException>(() =>
            {
                Span<byte> sink = stackalloc byte[100];
                blob.CopyTo(sink);
            });
            Assert.Throws<ObjectDisposedException>(() => blob.WriteTo(Stream.Null));
        });
    }

    [Test]
    public void Double_Dispose_Is_Harmless()
    {
        var blob = new ProtectedBlob([1, 2, 3]);
        blob.Dispose();
        Assert.DoesNotThrow(blob.Dispose);
    }

    [Test]
    public void Concurrent_Readers_See_Consistent_Plaintext()
    {
        byte[] original = RandomNumberGenerator.GetBytes(8 * ProtectedBlob.MinChunkSize + 11);
        using var blob = new ProtectedBlob(original.AsSpan(), ProtectedBlob.MinChunkSize);

        Parallel.For(0, 32, _ =>
        {
            var result = new byte[blob.Length];
            blob.CopyTo(result);
            Assert.That(result, Is.EqualTo(original));

            int index = Random.Shared.Next(blob.ChunkCount);
            int offset = index * blob.ChunkSize;
            byte[] expected = original.AsSpan(offset, Math.Min(blob.ChunkSize, original.Length - offset)).ToArray();
            byte[] chunk = blob.AccessChunk(index, c => c.ToArray());
            Assert.That(chunk, Is.EqualTo(expected));
        });
    }
}

[TestFixture]
public class RotationInterplayTests
{
    /// <summary>
    /// Pins the invariant the blob's rotation story rests on: blobs snapshot
    /// the process protector at construction, RotateProcessKey never disposes
    /// superseded protectors, so a pre-rotation blob keeps decrypting — and
    /// blobs are (documented as) NOT re-keyed by rotation.
    /// </summary>
    [Test]
    public void Blob_Survives_RotateProcessKey()
    {
        var originalPolicy = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;

            byte[] original = RandomNumberGenerator.GetBytes(3 * ProtectedBlob.MinChunkSize);
            using var preRotation = new ProtectedBlob(original.AsSpan(), ProtectedBlob.MinChunkSize);
            using var protectedString = new ProtectedString("still-works".AsSpan());

            ProtectedString.RotateProcessKey();

            var afterRotation = new byte[preRotation.Length];
            preRotation.CopyTo(afterRotation);
            Assert.That(afterRotation, Is.EqualTo(original), "A pre-rotation blob must keep decrypting after rotation.");

            // A post-rotation blob (fresh protector snapshot) must work too.
            using var postRotation = new ProtectedBlob(original.AsSpan(), ProtectedBlob.MinChunkSize);
            var postRead = new byte[postRotation.Length];
            postRotation.CopyTo(postRead);
            Assert.That(postRead, Is.EqualTo(original));
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = originalPolicy;
        }
    }
}

[TestFixture]
public class KeyProtectionTests
{
    /// <summary>
    /// Hardware-tier smoke: on hosts with a hardware-backed provider the
    /// whole path (DEK wrap under the hardware-wrapped master) round-trips;
    /// elsewhere the test self-skips, matching the TPM suites' pattern.
    /// </summary>
    [Test]
    public void RoundTrip_Under_Ambient_Key_Protection_Tier()
    {
        if (ProtectedString.HardwareBackedAvailability == HardwareBackedAvailability.NoProviderForThisPlatform)
        {
            Assert.Ignore("No hardware-backed provider on this host — ambient tier already covered by the rest of the suite.");
        }

        byte[] original = RandomNumberGenerator.GetBytes(2 * ProtectedBlob.MinChunkSize);
        using var blob = new ProtectedBlob(original.AsSpan(), ProtectedBlob.MinChunkSize);
        var result = new byte[blob.Length];
        blob.CopyTo(result);
        Assert.That(result, Is.EqualTo(original));
    }
}
