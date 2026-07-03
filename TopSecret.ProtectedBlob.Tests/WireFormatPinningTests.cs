using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedBlobTests;

/// <summary>
/// Freezes <see cref="ChunkFormat"/>'s byte-level wire format. A failure in
/// this fixture means the chunk envelope format changed — that is a BREAKING
/// FORMAT CHANGE for TopSecret.ProtectedBlob and requires a new magic value
/// ("TPB2"), not an edit to these expectations.
/// </summary>
[TestFixture]
public class WireFormatPinningTests
{
    [Test]
    public void ChunkNonce_Is_Prefix8_Then_BigEndian32_Counter()
    {
        ReadOnlySpan<byte> prefix = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        Span<byte> nonce = stackalloc byte[12];

        ChunkFormat.FillChunkNonce(nonce, prefix, 0x0A0B0C0D);

        Assert.That(nonce.ToArray(), Is.EqualTo(new byte[]
        {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // prefix, verbatim
            0x0A, 0x0B, 0x0C, 0x0D,                         // counter, big-endian
        }), "Chunk nonce layout changed — breaking format change.");
    }

    [Test]
    public void ChunkAad_Is_Magic_IdLe64_IndexBe32_FinalFlag()
    {
        Span<byte> aad = stackalloc byte[ChunkFormat.ChunkAadSize];

        ChunkFormat.FillChunkAad(aad, blobInstanceId: 0x1122334455667788, chunkIndex: 0x0A0B0C0D, isFinalChunk: true);

        Assert.That(aad.ToArray(), Is.EqualTo(new byte[]
        {
            (byte)'T', (byte)'P', (byte)'B', (byte)'1',     // magic / version
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // instance id, little-endian
            0x0A, 0x0B, 0x0C, 0x0D,                         // chunk index, big-endian
            0x01,                                           // final-chunk flag
        }), "Chunk AAD layout changed — breaking format change.");
    }

    [Test]
    public void ChunkAad_NonFinal_Flag_Is_Zero()
    {
        Span<byte> aad = stackalloc byte[ChunkFormat.ChunkAadSize];
        ChunkFormat.FillChunkAad(aad, blobInstanceId: 1, chunkIndex: 0, isFinalChunk: false);
        Assert.That(aad[16], Is.Zero);
    }

    [Test]
    public void DekWrapAad_Is_Magic_IdLe64()
    {
        Span<byte> aad = stackalloc byte[ChunkFormat.DekWrapAadSize];

        ChunkFormat.FillDekWrapAad(aad, blobInstanceId: 0x1122334455667788);

        Assert.That(aad.ToArray(), Is.EqualTo(new byte[]
        {
            (byte)'T', (byte)'P', (byte)'B', (byte)'K',     // magic
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // instance id, little-endian
        }), "DEK-wrap AAD layout changed — breaking format change.");
    }

    /// <summary>
    /// Pins the full frame construction against an independent in-test
    /// build of the same format straight on top of the in-box
    /// <see cref="AesGcm"/>: same key, hand-assembled nonce and AAD, and the
    /// ciphertext ‖ tag frame layout. If <see cref="ChunkFormat"/> drifts in
    /// any byte, the two disagree.
    /// </summary>
    [Test]
    public void EncryptChunk_Frame_Matches_Independent_Reference_Construction()
    {
        byte[] dek = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] prefix = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
        const long id = 0x0000000000000042;
        const int index = 3;
        const bool isFinal = true;
        byte[] plaintext = System.Text.Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");

        byte[] frame = ChunkFormat.EncryptChunk(dek, prefix, id, index, isFinal, plaintext);

        // Independent reference: hand-built nonce/AAD, raw AesGcm.
        byte[] refNonce = new byte[12];
        prefix.CopyTo(refNonce, 0);
        refNonce[8] = 0x00; refNonce[9] = 0x00; refNonce[10] = 0x00; refNonce[11] = 0x03; // BE32 counter
        byte[] refAad = new byte[17];
        "TPB1"u8.ToArray().CopyTo(refAad, 0);
        refAad[4] = 0x42; // id LE64: 42 00 00 00 00 00 00 00
        refAad[12] = 0x00; refAad[13] = 0x00; refAad[14] = 0x00; refAad[15] = 0x03; // index BE32
        refAad[16] = 0x01; // final
        byte[] refCiphertext = new byte[plaintext.Length];
        byte[] refTag = new byte[16];
        using (var aes = new AesGcm(dek, 16))
        {
            aes.Encrypt(refNonce, plaintext, refCiphertext, refTag, refAad);
        }

        Assert.Multiple(() =>
        {
            Assert.That(frame, Has.Length.EqualTo(plaintext.Length + 16), "Frame is ciphertext ‖ 16-byte tag.");
            Assert.That(frame.AsSpan(0, plaintext.Length).ToArray(), Is.EqualTo(refCiphertext),
                "Ciphertext bytes diverged from the reference construction — breaking format change.");
            Assert.That(frame.AsSpan(plaintext.Length, 16).ToArray(), Is.EqualTo(refTag),
                "Tag bytes diverged from the reference construction — breaking format change.");
        });
    }

    [Test]
    public void DecryptChunk_RoundTrips_EncryptChunk()
    {
        byte[] dek = RandomNumberGenerator.GetBytes(32);
        byte[] prefix = RandomNumberGenerator.GetBytes(8);
        byte[] plaintext = RandomNumberGenerator.GetBytes(1000);

        byte[] frame = ChunkFormat.EncryptChunk(dek, prefix, blobInstanceId: 7, chunkIndex: 5, isFinalChunk: false, plaintext);
        byte[] decrypted = new byte[plaintext.Length];
        ChunkFormat.DecryptChunk(dek, prefix, blobInstanceId: 7, chunkIndex: 5, isFinalChunk: false, frame, decrypted);

        Assert.That(decrypted, Is.EqualTo(plaintext));
    }

    [Test]
    public void ChunkAadSize_And_DekWrapAadSize_Are_Frozen()
    {
        Assert.Multiple(() =>
        {
            Assert.That(ChunkFormat.ChunkAadSize, Is.EqualTo(17), "Chunk AAD size changed — breaking format change.");
            Assert.That(ChunkFormat.DekWrapAadSize, Is.EqualTo(12), "DEK-wrap AAD size changed — breaking format change.");
            Assert.That(ChunkFormat.NonceSize, Is.EqualTo(12));
            Assert.That(ChunkFormat.TagSize, Is.EqualTo(16));
            Assert.That(ChunkFormat.KeySize, Is.EqualTo(32));
            Assert.That(ChunkFormat.NoncePrefixSize, Is.EqualTo(8));
        });
    }
}
