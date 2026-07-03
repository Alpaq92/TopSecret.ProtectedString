using System.Buffers.Binary;
using System.Diagnostics;

namespace TopSecret;

/// <summary>
/// The byte-level wire format of <see cref="ProtectedBlob"/>'s chunked
/// AES-GCM-256 envelope. This is the single source of truth for nonce and
/// associated-data construction; <c>WireFormatPinningTests</c> freezes every
/// layout produced here — changing any of it is a breaking format change and
/// requires a new magic value.
/// </summary>
/// <remarks>
/// <para>
/// <b>Frame layout.</b> Each chunk is stored as one ordinary (unpinned,
/// unlocked) <c>byte[]</c> <i>frame</i> of <c>plaintextLength + 16</c> bytes:
/// the AES-GCM ciphertext followed by the 16-byte tag. Ciphertext requires no
/// pinning or locking — it leaks nothing if paged, dumped, or copied by the
/// GC, and integrity never trusts the memory it sits in.
/// </para>
/// <para>
/// <b>Chunk nonce (12 bytes)</b> = 8-byte per-blob random prefix ‖ 4-byte
/// big-endian chunk counter — the deterministic construction of NIST
/// SP 800-38D §8.2.1. Each blob encrypts under a fresh random 256-bit DEK, so
/// within a DEK the counter makes nonce collisions impossible, and the 32-bit
/// counter structurally enforces the §8.3 2³²-invocations-per-key bound. The
/// random prefix is defence-in-depth only: if a bug ever reused a DEK across
/// blobs, colliding (prefix, counter) pairs would still be a 2⁻⁶⁴-per-pair
/// event. Nonces are never stored — they are recomputed from the prefix and
/// the chunk index.
/// </para>
/// <para>
/// <b>Chunk associated data (17 bytes)</b> = ASCII <c>"TPB1"</c> ‖ blob
/// instance id (LE64, matching <see cref="ProtectedString"/>'s AAD
/// convention) ‖ chunk index (BE32) ‖ final-chunk flag (1 byte, 0 or 1) —
/// libsodium's <c>secretstream</c> pattern. Reordering chunks, truncating the
/// blob (dropping the final chunk), transplanting a chunk between blobs, and
/// flipping any ciphertext bit all fail the GCM tag check. There is no
/// total-length field: the final flag alone makes truncation fail closed, and
/// omitting it is what lets <see cref="ProtectedBlob.FromStream(Stream)"/> encrypt
/// unknown-length input as it streams.
/// </para>
/// <para>
/// <b>DEK-wrap associated data (12 bytes)</b> = ASCII <c>"TPBK"</c> ‖ blob
/// instance id (LE64). The distinct magic (and AAD length) domain-separates
/// the per-blob key envelope from both chunk frames and
/// <see cref="ProtectedString"/> ciphertext (whose AAD is exactly 8 bytes)
/// under the shared process master.
/// </para>
/// </remarks>
internal static class ChunkFormat
{
    internal const int NonceSize = 12;
    internal const int TagSize = AesGcmShim.TagSize; // single source of truth with the AEAD shim
    internal const int KeySize = 32;
    internal const int NoncePrefixSize = 8;
    internal const int CounterSize = 4;
    internal const int ChunkAadSize = 4 + sizeof(long) + CounterSize + 1; // magic + id + index + finalFlag = 17
    internal const int DekWrapAadSize = 4 + sizeof(long);                 // magic + id = 12

    private static ReadOnlySpan<byte> ChunkMagic => "TPB1"u8;
    private static ReadOnlySpan<byte> DekWrapMagic => "TPBK"u8;

    /// <summary>
    /// Writes the 12-byte chunk nonce: <paramref name="noncePrefix"/> (8
    /// bytes) followed by <paramref name="chunkIndex"/> as a big-endian
    /// 32-bit counter.
    /// </summary>
    internal static void FillChunkNonce(Span<byte> nonce, ReadOnlySpan<byte> noncePrefix, int chunkIndex)
    {
        Debug.Assert(nonce.Length == NonceSize);
        Debug.Assert(noncePrefix.Length == NoncePrefixSize);
        Debug.Assert(chunkIndex >= 0);
        noncePrefix.CopyTo(nonce);
        BinaryPrimitives.WriteInt32BigEndian(nonce.Slice(NoncePrefixSize, CounterSize), chunkIndex);
    }

    /// <summary>
    /// Writes the 17-byte chunk associated data:
    /// <c>"TPB1"</c> ‖ <paramref name="blobInstanceId"/> (LE64) ‖
    /// <paramref name="chunkIndex"/> (BE32) ‖ final-chunk flag.
    /// </summary>
    internal static void FillChunkAad(Span<byte> aad, long blobInstanceId, int chunkIndex, bool isFinalChunk)
    {
        Debug.Assert(aad.Length == ChunkAadSize);
        Debug.Assert(chunkIndex >= 0);
        ChunkMagic.CopyTo(aad);
        BinaryPrimitives.WriteInt64LittleEndian(aad.Slice(4, sizeof(long)), blobInstanceId);
        BinaryPrimitives.WriteInt32BigEndian(aad.Slice(12, CounterSize), chunkIndex);
        aad[16] = isFinalChunk ? (byte)1 : (byte)0;
    }

    /// <summary>
    /// Writes the 12-byte DEK-wrap associated data:
    /// <c>"TPBK"</c> ‖ <paramref name="blobInstanceId"/> (LE64).
    /// </summary>
    internal static void FillDekWrapAad(Span<byte> aad, long blobInstanceId)
    {
        Debug.Assert(aad.Length == DekWrapAadSize);
        DekWrapMagic.CopyTo(aad);
        BinaryPrimitives.WriteInt64LittleEndian(aad.Slice(4, sizeof(long)), blobInstanceId);
    }

    /// <summary>
    /// Encrypts one chunk of plaintext into a freshly allocated frame
    /// (ciphertext ‖ tag) under <paramref name="dek"/>. The plaintext is read
    /// directly from the caller's span — no staging copy is made.
    /// </summary>
    internal static byte[] EncryptChunk(
        ReadOnlySpan<byte> dek,
        ReadOnlySpan<byte> noncePrefix,
        long blobInstanceId,
        int chunkIndex,
        bool isFinalChunk,
        ReadOnlySpan<byte> plaintext)
    {
        var frame = new byte[plaintext.Length + TagSize];
        Span<byte> nonce = stackalloc byte[NonceSize];
        Span<byte> aad = stackalloc byte[ChunkAadSize];
        FillChunkNonce(nonce, noncePrefix, chunkIndex);
        FillChunkAad(aad, blobInstanceId, chunkIndex, isFinalChunk);
        AesGcmShim.Encrypt(
            dek,
            nonce,
            plaintext,
            frame.AsSpan(0, plaintext.Length),
            frame.AsSpan(plaintext.Length, TagSize),
            aad);
        return frame;
    }

    /// <summary>
    /// Decrypts one frame into <paramref name="plaintextDestination"/>, which
    /// must be exactly <c>frame.Length - 16</c> bytes. No plaintext byte is
    /// released before the chunk's tag verifies — both AEAD paths behind
    /// <see cref="AesGcmShim"/> guarantee this (the in-box
    /// <see cref="System.Security.Cryptography.AesGcm"/> zeroes the
    /// destination on tag mismatch; the BouncyCastle path copies out only
    /// after <c>DoFinal</c> succeeds).
    /// </summary>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// The tag check failed — the frame was tampered with, reordered,
    /// truncated, or transplanted from another blob.
    /// </exception>
    internal static void DecryptChunk(
        ReadOnlySpan<byte> dek,
        ReadOnlySpan<byte> noncePrefix,
        long blobInstanceId,
        int chunkIndex,
        bool isFinalChunk,
        ReadOnlySpan<byte> frame,
        Span<byte> plaintextDestination)
    {
        Debug.Assert(plaintextDestination.Length == frame.Length - TagSize);
        Span<byte> nonce = stackalloc byte[NonceSize];
        Span<byte> aad = stackalloc byte[ChunkAadSize];
        FillChunkNonce(nonce, noncePrefix, chunkIndex);
        FillChunkAad(aad, blobInstanceId, chunkIndex, isFinalChunk);
        AesGcmShim.Decrypt(
            dek,
            nonce,
            frame[..plaintextDestination.Length],
            frame.Slice(plaintextDestination.Length, TagSize),
            plaintextDestination,
            aad);
    }
}
