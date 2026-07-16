using System.Security.Cryptography;

namespace TopSecret;

/// <summary>
/// The at-rest form of a <see cref="ProtectedBlob"/>'s per-blob
/// data-encryption key (DEK): the 32-byte DEK encrypted with AES-GCM-256
/// under the process-wide master key, bound to the owning blob's instance id
/// via <see cref="ChunkFormat.FillDekWrapAad"/>. Roughly 60 bytes of state
/// (ciphertext ‖ nonce ‖ tag), held in pinned memory — deliberately not
/// locked or dump-excluded, matching the core's policy for encrypted state
/// (see <see cref="ProtectedString.AllocatePinnedEncryptedState"/>: the
/// contents are safe by construction, and keeping them off the page-granular
/// lock/unlock path avoids interfering with pages legitimately locked for
/// plaintext) — and zeroed on blob disposal.
/// </summary>
/// <remarks>
/// Exactly one master-key protector exists per process (shared with
/// <see cref="ProtectedString"/>), so wrapping any number of blobs consumes
/// no additional hardware-backed key slots, and the plaintext DEK exists only
/// inside bounded operations that immediately wipe their scratch.
/// </remarks>
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

    /// <summary>
    /// Wraps <paramref name="dek"/> under <paramref name="protector"/>'s
    /// master key. The master is unwrapped only for the duration of the
    /// single 32-byte AES-GCM encrypt.
    /// </summary>
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

    /// <summary>
    /// Unwraps the DEK into <paramref name="dekDestination"/> (exactly 32
    /// bytes of caller-owned locked scratch — in practice a pooled lease the
    /// caller returns, which wipes it). The master is unwrapped only for the
    /// duration of the single 32-byte AES-GCM decrypt.
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

    /// <summary>Zeroes the envelope's state. Idempotent.</summary>
    internal void Zero()
    {
        ProtectedString.ZeroOnly(_ciphertext);
        ProtectedString.ZeroOnly(_nonce);
        ProtectedString.ZeroOnly(_tag);
    }
}
