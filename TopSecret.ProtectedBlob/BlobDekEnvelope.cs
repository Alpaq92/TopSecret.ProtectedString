using System.Security.Cryptography;

namespace TopSecret;

internal sealed class BlobDekEnvelope
{
    private readonly byte[] _ciphertext; // ChunkFormat.KeySize bytes, pinned
    private readonly byte[] _nonce;      // ChunkFormat.NonceSize bytes, pinned
    private readonly byte[] _tag;        // ChunkFormat.TagSize bytes, pinned

    private BlobDekEnvelope(byte[] ciphertext, byte[] nonce, byte[] tag)
    {
        _ciphertext = ciphertext;
        _nonce = nonce;
        _tag = tag;
    }

    internal static BlobDekEnvelope Wrap(KeyAtRestProtector protector, ReadOnlySpan<byte> dek, long blobInstanceId)
    {
        var ciphertext = ProtectedString.AllocatePinnedEncryptedState(ChunkFormat.KeySize);
        var nonce = ProtectedString.AllocatePinnedEncryptedState(ChunkFormat.NonceSize);
        var tag = ProtectedString.AllocatePinnedEncryptedState(ChunkFormat.TagSize);
        bool ok = false;
        try
        {
            RandomNumberGenerator.Fill(nonce);
            Span<byte> aad = stackalloc byte[ChunkFormat.DekWrapAadSize];
            ChunkFormat.FillDekWrapAad(aad, blobInstanceId);

            using var master = protector.UnwrapKey();
            AesGcmShim.Encrypt(master.Key, nonce, dek, ciphertext, tag, aad);
            ok = true;
            return new BlobDekEnvelope(ciphertext, nonce, tag);
        }
        finally
        {
            if (!ok)
            {
                ProtectedString.ZeroOnly(ciphertext);
                ProtectedString.ZeroOnly(nonce);
                ProtectedString.ZeroOnly(tag);
            }
        }
    }

    internal void UnwrapInto(KeyAtRestProtector protector, Span<byte> dekDestination, long blobInstanceId)
    {
        Span<byte> aad = stackalloc byte[ChunkFormat.DekWrapAadSize];
        ChunkFormat.FillDekWrapAad(aad, blobInstanceId);

        using var master = protector.UnwrapKey();
        AesGcmShim.Decrypt(master.Key, _nonce, _ciphertext, _tag, dekDestination, aad);
    }

    internal void Zero()
    {
        ProtectedString.ZeroOnly(_ciphertext);
        ProtectedString.ZeroOnly(_nonce);
        ProtectedString.ZeroOnly(_tag);
    }
}
