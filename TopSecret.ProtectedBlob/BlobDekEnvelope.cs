using System.Security.Cryptography;

namespace TopSecret;

/// <summary>
/// The at-rest form of a <see cref="ProtectedBlob"/>'s per-blob
/// data-encryption key (DEK): the 32-byte DEK encrypted with AES-GCM-256
/// under the process-wide master key, bound to the owning blob's instance id
/// via <see cref="ChunkFormat.FillDekWrapAad"/>. Roughly 60 bytes of state
/// (ciphertext ‖ nonce ‖ tag), held in pinned, locked memory like the core's
/// own encrypted state, and zeroed on blob disposal.
/// </summary>
/// <remarks>
/// Exactly one master-key protector exists per process (shared with
/// <see cref="ProtectedString"/>), so wrapping any number of blobs consumes
/// no additional hardware-backed key slots, and the plaintext DEK exists only
/// inside bounded operations that immediately wipe their scratch.
/// </remarks>
internal sealed class BlobDekEnvelope
{
    private readonly byte[] _ciphertext; // ChunkFormat.KeySize bytes, pinned + locked
    private readonly byte[] _nonce;      // ChunkFormat.NonceSize bytes, pinned + locked
    private readonly byte[] _tag;        // ChunkFormat.TagSize bytes, pinned + locked

    private BlobDekEnvelope(byte[] ciphertext, byte[] nonce, byte[] tag)
    {
        _ciphertext = ciphertext;
        _nonce = nonce;
        _tag = tag;
    }

    /// <summary>
    /// Wraps <paramref name="dek"/> under <paramref name="protector"/>'s
    /// master key. The master is unwrapped only for the duration of the
    /// single 32-byte AES-GCM encrypt.
    /// </summary>
    internal static BlobDekEnvelope Wrap(KeyAtRestProtector protector, ReadOnlySpan<byte> dek, long blobInstanceId)
    {
        var ciphertext = ProtectedString.AllocatePinnedBytes(ChunkFormat.KeySize);
        var nonce = ProtectedString.AllocatePinnedBytes(ChunkFormat.NonceSize);
        var tag = ProtectedString.AllocatePinnedBytes(ChunkFormat.TagSize);
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
                ProtectedString.ZeroBytes(ciphertext);
                ProtectedString.ZeroBytes(nonce);
                ProtectedString.ZeroBytes(tag);
            }
        }
    }

    /// <summary>
    /// Unwraps the DEK into <paramref name="dekDestination"/> (exactly 32
    /// bytes, caller-owned pinned+locked scratch the caller must wipe). The
    /// master is unwrapped only for the duration of the single 32-byte
    /// AES-GCM decrypt.
    /// </summary>
    /// <exception cref="CryptographicException">
    /// The envelope failed authentication — tampered, or transplanted from
    /// another blob.
    /// </exception>
    internal void UnwrapInto(KeyAtRestProtector protector, Span<byte> dekDestination, long blobInstanceId)
    {
        Span<byte> aad = stackalloc byte[ChunkFormat.DekWrapAadSize];
        ChunkFormat.FillDekWrapAad(aad, blobInstanceId);

        using var master = protector.UnwrapKey();
        AesGcmShim.Decrypt(master.Key, _nonce, _ciphertext, _tag, dekDestination, aad);
    }

    /// <summary>Zeroes and unlocks the envelope's state. Idempotent.</summary>
    internal void Zero()
    {
        ProtectedString.ZeroBytes(_ciphertext);
        ProtectedString.ZeroBytes(_nonce);
        ProtectedString.ZeroBytes(_tag);
    }
}
