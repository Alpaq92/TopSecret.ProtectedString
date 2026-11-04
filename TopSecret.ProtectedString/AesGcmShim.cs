using System.Security.Cryptography;

#if BROWSER
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
#endif

namespace TopSecret;

internal static class AesGcmShim
{
    public const int TagSize = 16;

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
        // We allocate pinned copies of key/nonce/AAD/plaintext/ciphertext so
        // the GC cannot duplicate them mid-op, and zero them on the way out.
        // BC's KeyParameter, AesEngine, and GcmBlockCipher separately hold
        // THEIR OWN unreachable copies/derivations of the key material (see
        // remarks at the top of the type) — cipher/keyParameter/parameters
        // are declared here, outside the try, so ReleaseBouncyState can null
        // every reference to them in finally.
        byte[]? keyCopy = null;
        byte[]? nonceCopy = null;
        byte[]? aadCopy = null;
        byte[]? inputCopy = null;
        byte[]? output = null;
        GcmBlockCipher? cipher = null;
        KeyParameter? keyParameter = null;
        AeadParameters? parameters = null;
        try
        {
            keyCopy = AllocatePinnedScratch(key.Length);
            key.CopyTo(keyCopy);
            nonceCopy = AllocatePinnedScratch(nonce.Length);
            nonce.CopyTo(nonceCopy);
            aadCopy = AllocatePinnedScratch(associatedData.Length);
            associatedData.CopyTo(aadCopy);

            cipher = new GcmBlockCipher(new AesEngine());
            keyParameter = new KeyParameter(keyCopy);
            parameters = new AeadParameters(
                keyParameter,
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
            ReleaseBouncyState(ref cipher, ref keyParameter, ref parameters);
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
        GcmBlockCipher? cipher = null;
        KeyParameter? keyParameter = null;
        AeadParameters? parameters = null;
        try
        {
            keyCopy = AllocatePinnedScratch(key.Length);
            key.CopyTo(keyCopy);
            nonceCopy = AllocatePinnedScratch(nonce.Length);
            nonce.CopyTo(nonceCopy);
            aadCopy = AllocatePinnedScratch(associatedData.Length);
            associatedData.CopyTo(aadCopy);

            cipher = new GcmBlockCipher(new AesEngine());
            keyParameter = new KeyParameter(keyCopy);
            parameters = new AeadParameters(
                keyParameter,
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
            ReleaseBouncyState(ref cipher, ref keyParameter, ref parameters);
        }
    }

    /// <summary>
    /// Drops every reference to the BC objects that hold their own
    /// unreachable copies/derivations of the key material (see the type's
    /// remarks) and forces a Gen0 collection so they become eligible for
    /// reclaim immediately, rather than whenever the runtime next happens to
    /// collect on its own. Gen0-only: these objects are allocated and
    /// released within a single call and are not expected to have been
    /// promoted. Shrinks the reachability window; does not zero the
    /// underlying bytes — see the type-level remarks for the exact trade-off.
    /// </summary>
    private static void ReleaseBouncyState(
        ref GcmBlockCipher? cipher, ref KeyParameter? keyParameter, ref AeadParameters? parameters)
    {
        cipher = null;
        keyParameter = null;
        parameters = null;
        GC.Collect(0, GCCollectionMode.Forced, blocking: true);
    }
#endif
}
