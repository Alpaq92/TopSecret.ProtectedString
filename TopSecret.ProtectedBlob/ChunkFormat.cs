using System.Buffers.Binary;
using System.Diagnostics;

namespace TopSecret;

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

    internal static void FillChunkNonce(Span<byte> nonce, ReadOnlySpan<byte> noncePrefix, int chunkIndex)
    {
        Debug.Assert(nonce.Length == NonceSize);
        Debug.Assert(noncePrefix.Length == NoncePrefixSize);
        Debug.Assert(chunkIndex >= 0);
        noncePrefix.CopyTo(nonce);
        BinaryPrimitives.WriteInt32BigEndian(nonce.Slice(NoncePrefixSize, CounterSize), chunkIndex);
    }

    internal static void FillChunkAad(Span<byte> aad, long blobInstanceId, int chunkIndex, bool isFinalChunk)
    {
        Debug.Assert(aad.Length == ChunkAadSize);
        Debug.Assert(chunkIndex >= 0);
        ChunkMagic.CopyTo(aad);
        BinaryPrimitives.WriteInt64LittleEndian(aad.Slice(4, sizeof(long)), blobInstanceId);
        BinaryPrimitives.WriteInt32BigEndian(aad.Slice(12, CounterSize), chunkIndex);
        aad[16] = isFinalChunk ? (byte)1 : (byte)0;
    }

    internal static void FillDekWrapAad(Span<byte> aad, long blobInstanceId)
    {
        Debug.Assert(aad.Length == DekWrapAadSize);
        DekWrapMagic.CopyTo(aad);
        BinaryPrimitives.WriteInt64LittleEndian(aad.Slice(4, sizeof(long)), blobInstanceId);
    }

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
