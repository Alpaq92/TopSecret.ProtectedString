using System.Security.Cryptography;

#if BROWSER
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
#endif

namespace TopSecret;

/// <summary>
/// Cross-platform AES-GCM-256 wrapper. Delegates to
/// <see cref="System.Security.Cryptography.AesGcm"/> on every TFM where it
/// works at runtime, and to BouncyCastle's <c>GcmBlockCipher</c> on the
/// <c>net10.0-browser</c> TFM where <see cref="AesGcm.IsSupported"/> is
/// <see langword="false"/> and constructing <see cref="AesGcm"/> throws
/// <see cref="PlatformNotSupportedException"/>.
/// </summary>
/// <remarks>
/// <para>
/// The two implementations agree on the AES-GCM-256 wire format — same
/// 12-byte nonce, same 16-byte tag, same AAD binding — so ciphertext
/// produced on one platform decrypts cleanly on another. (Not that this
/// library serialises ciphertext across processes, but the equivalence
/// guarantees the build and verify paths agree on what a "valid"
/// ciphertext looks like.)
/// </para>
/// <para>
/// On the BouncyCastle path, key / nonce / AAD / plaintext / ciphertext
/// are copied into <see cref="byte"/>[] arrays allocated on the pinned
/// object heap (<see cref="GC.AllocateArray{T}(int, bool)"/> with
/// <c>pinned: true</c>) so the GC cannot relocate (and therefore copy)
/// them between the BC operation and our wipe. Each of those buffers is
/// zeroed with
/// <see cref="CryptographicOperations.ZeroMemory(System.Span{byte})"/>
/// in a <c>finally</c> block on the way out.
/// </para>
/// <para>
/// <b>Residual: BouncyCastle holds non-zeroable copies.</b> BC's
/// <c>KeyParameter</c> and <c>AeadParameters</c> wrap the byte arrays we
/// allocate; <c>GcmBlockCipher</c>'s internal state may further derive
/// from them. We zero our buffers, but BC may retain copies inside its
/// own state until those objects become unreachable and the GC reclaims
/// them. Memory locking (<c>mlock</c>) is not reachable from inside the
/// WASM sandbox so this byte-residue lives in the WASM linear memory
/// for the GC's reclaim window. The threat model on browser-wasm is
/// "secrets do not escape the WebAssembly module"; the WASM linear
/// memory is not paged to disk and is sandboxed away from other
/// origins, so the residue does not leak. If your threat model is
/// stricter, do not rely on the browser-wasm TFM.
/// </para>
/// </remarks>
internal static class AesGcmShim
{
    /// <summary>The AES-GCM tag size, in bytes (128 bits).</summary>
    public const int TagSize = 16;

    /// <summary>
    /// AEAD-encrypts <paramref name="plaintext"/> under
    /// <paramref name="key"/> with the supplied <paramref name="nonce"/>
    /// and <paramref name="associatedData"/>, writing the ciphertext into
    /// <paramref name="ciphertext"/> (must be the same length as
    /// <paramref name="plaintext"/>) and the authentication tag into
    /// <paramref name="tag"/> (must be exactly <see cref="TagSize"/> bytes).
    /// </summary>
    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
#if BROWSER
        BouncyEncrypt(key, nonce, plaintext, ciphertext, tag, associatedData);
#else
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
#endif
    }

    /// <summary>
    /// AEAD-decrypts <paramref name="ciphertext"/> under
    /// <paramref name="key"/> with the supplied <paramref name="nonce"/>,
    /// <paramref name="tag"/>, and <paramref name="associatedData"/>. Throws
    /// <see cref="CryptographicException"/> if the tag does not validate —
    /// e.g., on cross-instance ciphertext swap or memory corruption.
    /// </summary>
    public static void Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
#if BROWSER
        BouncyDecrypt(key, nonce, ciphertext, tag, plaintext, associatedData);
#else
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
#endif
    }

#if BROWSER
    /// <summary>
    /// Allocates a pinned byte array on the pinned object heap. Locking is
    /// not attempted on the browser TFM (no <c>mlock</c> primitive in the
    /// WASM sandbox), but pinning still prevents the GC from relocating
    /// (and therefore copying) the buffer between the caller's
    /// <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> wipe
    /// and the eventual reclaim.
    /// </summary>
    private static byte[] AllocatePinnedScratch(int length) =>
        GC.AllocateArray<byte>(length, pinned: true);

    private static void BouncyEncrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        // BC's AeadParameters / KeyParameter take byte[] by reference and
        // hold them internally. We allocate pinned copies so the GC cannot
        // duplicate them mid-op, and zero-then-orphan them on the way out.
        // The KeyParameter / AeadParameters instances themselves still hold
        // references to the (now-zeroed) buffers until the GC reclaims
        // them — see remarks at the top of the type for the trade-off.
        byte[]? keyCopy = null;
        byte[]? nonceCopy = null;
        byte[]? aadCopy = null;
        byte[]? inputCopy = null;
        byte[]? output = null;
        try
        {
            keyCopy = AllocatePinnedScratch(key.Length);
            key.CopyTo(keyCopy);
            nonceCopy = AllocatePinnedScratch(nonce.Length);
            nonce.CopyTo(nonceCopy);
            aadCopy = AllocatePinnedScratch(associatedData.Length);
            associatedData.CopyTo(aadCopy);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(keyCopy),
                macSize: TagSize * 8,
                nonce: nonceCopy,
                associatedText: aadCopy);
            cipher.Init(forEncryption: true, parameters);

            int outputSize = cipher.GetOutputSize(plaintext.Length);
            inputCopy = AllocatePinnedScratch(plaintext.Length);
            plaintext.CopyTo(inputCopy);
            output = AllocatePinnedScratch(outputSize);

            int written = cipher.ProcessBytes(inputCopy, 0, inputCopy.Length, output, 0);
            written += cipher.DoFinal(output, written);

            output.AsSpan(0, ciphertext.Length).CopyTo(ciphertext);
            output.AsSpan(ciphertext.Length, TagSize).CopyTo(tag);
        }
        finally
        {
            if (keyCopy is not null) CryptographicOperations.ZeroMemory(keyCopy);
            if (nonceCopy is not null) CryptographicOperations.ZeroMemory(nonceCopy);
            if (aadCopy is not null) CryptographicOperations.ZeroMemory(aadCopy);
            if (inputCopy is not null) CryptographicOperations.ZeroMemory(inputCopy);
            if (output is not null) CryptographicOperations.ZeroMemory(output);
        }
    }

    private static void BouncyDecrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        byte[]? keyCopy = null;
        byte[]? nonceCopy = null;
        byte[]? aadCopy = null;
        byte[]? input = null;
        byte[]? output = null;
        try
        {
            keyCopy = AllocatePinnedScratch(key.Length);
            key.CopyTo(keyCopy);
            nonceCopy = AllocatePinnedScratch(nonce.Length);
            nonce.CopyTo(nonceCopy);
            aadCopy = AllocatePinnedScratch(associatedData.Length);
            associatedData.CopyTo(aadCopy);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(keyCopy),
                macSize: TagSize * 8,
                nonce: nonceCopy,
                associatedText: aadCopy);
            cipher.Init(forEncryption: false, parameters);

            // BC expects ciphertext || tag in one contiguous input.
            input = AllocatePinnedScratch(ciphertext.Length + tag.Length);
            ciphertext.CopyTo(input);
            tag.CopyTo(input.AsSpan(ciphertext.Length));
            output = AllocatePinnedScratch(cipher.GetOutputSize(input.Length));

            int written;
            try
            {
                written = cipher.ProcessBytes(input, 0, input.Length, output, 0);
                written += cipher.DoFinal(output, written);
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException ex)
            {
                // BC throws InvalidCipherTextException on tag-verification
                // failure; the in-box `AesGcm.Decrypt` throws
                // CryptographicException. Translate so callers (and the
                // library itself, in places where a tag mismatch is part
                // of the contract — e.g. cross-instance ciphertext swap
                // verification) see the same exception type on every TFM.
                // Wrap rather than swallow: the original BC message and
                // stack are preserved as InnerException for diagnostics.
                throw new CryptographicException(
                    "AES-GCM authentication tag did not verify (BouncyCastle path on net10.0-browser).",
                    ex);
            }

            if (written != plaintext.Length)
            {
                throw new CryptographicException(
                    $"AES-GCM decrypt produced {written} bytes; expected {plaintext.Length}.");
            }

            output.AsSpan(0, written).CopyTo(plaintext);
        }
        finally
        {
            if (keyCopy is not null) CryptographicOperations.ZeroMemory(keyCopy);
            if (nonceCopy is not null) CryptographicOperations.ZeroMemory(nonceCopy);
            if (aadCopy is not null) CryptographicOperations.ZeroMemory(aadCopy);
            if (input is not null) CryptographicOperations.ZeroMemory(input);
            if (output is not null) CryptographicOperations.ZeroMemory(output);
        }
    }
#endif
}
