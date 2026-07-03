using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedBlobTests;

/// <summary>
/// The fail-closed matrix: every way an attacker (or memory corruption) can
/// mutate the encrypted state must surface as <see cref="CryptographicException"/>,
/// never as wrong plaintext.
/// </summary>
[TestFixture]
public class TamperTests
{
    private const int SmallChunk = ProtectedBlob.MinChunkSize;

    private static ProtectedBlob MakeBlob(int chunks = 3) =>
        new(RandomNumberGenerator.GetBytes(chunks * SmallChunk).AsSpan(), SmallChunk);

    private static void AssertAllReadsThrow(ProtectedBlob blob)
    {
        Assert.Multiple(() =>
        {
            Assert.Catch<CryptographicException>(() =>
            {
                var sink = new byte[blob.Length];
                blob.CopyTo(sink);
            }, "CopyTo must fail closed");
            Assert.Catch<CryptographicException>(() => blob.AccessChunks(_ => { }), "AccessChunks must fail closed");
            Assert.Catch<CryptographicException>(() => blob.WriteTo(Stream.Null), "WriteTo must fail closed");
        });
    }

    [Test]
    public void Flipped_Ciphertext_Bit_Fails_The_Tag()
    {
        using var blob = MakeBlob();
        blob.FramesForTests[1][100] ^= 0x01;
        AssertAllReadsThrow(blob);
    }

    [Test]
    public void Flipped_Tag_Bit_Fails_The_Tag()
    {
        using var blob = MakeBlob();
        var frame = blob.FramesForTests[0];
        frame[^1] ^= 0x80; // last tag byte
        Assert.Catch<CryptographicException>(() => blob.AccessChunk(0, _ => { }));
    }

    [Test]
    public void Swapped_Chunks_Fail_The_Tag()
    {
        using var blob = MakeBlob();
        var frames = blob.FramesForTests;

        // Swap the contents of two equal-size frames in place — the reorder
        // an attacker with memory access would perform.
        byte[] tmp = (byte[])frames[0].Clone();
        frames[1].CopyTo(frames[0].AsSpan());
        tmp.CopyTo(frames[1].AsSpan());

        AssertAllReadsThrow(blob);
    }

    [Test]
    public void Transplanted_Chunk_From_Another_Blob_Fails_The_Tag()
    {
        using var blobA = MakeBlob();
        using var blobB = MakeBlob();

        // Same chunk index, same size, same position — but a different blob
        // (different DEK, different instance id in the AAD).
        blobB.FramesForTests[1].CopyTo(blobA.FramesForTests[1].AsSpan());

        AssertAllReadsThrow(blobA);
    }

    [Test]
    public void Truncation_Dropping_The_Final_Chunk_Fails_The_Tag()
    {
        // Format-level statement of the secretstream truncation defence: a
        // chunk encrypted as non-final never authenticates as final, so a
        // reader that expects its last chunk to carry the final flag detects
        // any shortened frame sequence.
        byte[] dek = RandomNumberGenerator.GetBytes(32);
        byte[] prefix = RandomNumberGenerator.GetBytes(8);
        byte[] plaintext = RandomNumberGenerator.GetBytes(100);

        byte[] nonFinalFrame = ChunkFormat.EncryptChunk(dek, prefix, blobInstanceId: 9, chunkIndex: 0, isFinalChunk: false, plaintext);

        var destination = new byte[plaintext.Length];
        Assert.Catch<CryptographicException>(() =>
            ChunkFormat.DecryptChunk(dek, prefix, blobInstanceId: 9, chunkIndex: 0, isFinalChunk: true, nonFinalFrame, destination));
    }

    [Test]
    public void Chunk_Moved_To_A_Different_Index_Fails_The_Tag()
    {
        byte[] dek = RandomNumberGenerator.GetBytes(32);
        byte[] prefix = RandomNumberGenerator.GetBytes(8);
        byte[] plaintext = RandomNumberGenerator.GetBytes(100);

        byte[] frame = ChunkFormat.EncryptChunk(dek, prefix, blobInstanceId: 9, chunkIndex: 2, isFinalChunk: false, plaintext);

        var destination = new byte[plaintext.Length];
        Assert.Catch<CryptographicException>(() =>
            ChunkFormat.DecryptChunk(dek, prefix, blobInstanceId: 9, chunkIndex: 5, isFinalChunk: false, frame, destination));
    }

    [Test]
    public void Dek_Envelope_Bound_To_Instance_Id()
    {
        // Wrapping under one blob id and unwrapping under another must fail —
        // the transplant defence for the key envelope itself.
        var protector = ProtectedString.GetOrInitProcessProtector();
        byte[] dek = RandomNumberGenerator.GetBytes(32);

        var envelope = BlobDekEnvelope.Wrap(protector, dek, blobInstanceId: 1);
        var destination = new byte[32];

        Assert.Catch<CryptographicException>(() => envelope.UnwrapInto(protector, destination, blobInstanceId: 2));
        envelope.Zero();
    }

    [Test]
    public void Tampered_Empty_Blob_Still_Fails_Closed()
    {
        // An empty blob is one empty final chunk — its tag still authenticates
        // emptiness, so even a zero-length read detects tampering.
        using var blob = new ProtectedBlob(ReadOnlySpan<byte>.Empty);
        blob.FramesForTests[0][0] ^= 0x01; // frame is just the 16-byte tag

        Assert.Catch<CryptographicException>(() =>
        {
            var sink = new byte[0];
            blob.CopyTo(sink);
        });
    }

    [Test]
    public void Failed_CopyTo_Zeroes_Everything_It_Wrote()
    {
        using var blob = MakeBlob(chunks: 3);
        blob.FramesForTests[2][0] ^= 0x01; // corrupt the LAST chunk; first two decrypt fine

        var destination = new byte[blob.Length];
        Assert.Catch<CryptographicException>(() => blob.CopyTo(destination));

        Assert.That(destination, Is.All.Zero,
            "CopyTo must not leave the already-authenticated prefix in the caller's buffer after a failure.");
    }
}
