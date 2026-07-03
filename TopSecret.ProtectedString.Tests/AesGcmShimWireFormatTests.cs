using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace TopSecret.ProtectedStringTests;

/// <summary>
/// Wire-format compatibility tests between
/// <see cref="System.Security.Cryptography.AesGcm"/> and BouncyCastle's
/// <c>GcmBlockCipher</c>. The main library uses BouncyCastle only on the
/// <c>net10.0-browser</c> TFM (where <c>AesGcm.IsSupported</c> is
/// <see langword="false"/>); these tests run on <c>net10.0</c> and verify
/// that the two implementations agree on the AES-GCM-256 wire format under
/// the parameter shapes the library actually uses (12-byte nonce, 16-byte
/// tag, 8-byte AAD, 32-byte key).
/// </summary>
/// <remarks>
/// The browser-wasm path is otherwise build-verified only — without a wasm
/// test runner, we cannot run the suite end-to-end on
/// <c>net10.0-browser</c>. These tests close the gap by proving the BC
/// primitives the shim wraps produce ciphertext byte-for-byte identical to
/// what the in-box <see cref="AesGcm"/> produces under the same inputs.
/// If that holds, the shim's thin <c>BouncyEncrypt</c> / <c>BouncyDecrypt</c>
/// wrappers (which only marshal between <see cref="ReadOnlySpan{T}"/> and
/// the BC byte-array API) are correct by construction.
/// </remarks>
[TestFixture]
public class AesGcmShimWireFormatTests
{
    private const int TagSize = 16;
    private const int NonceSize = 12;
    private const int KeySize = 32;
    private const int AadSize = 8;

    private static byte[] Random(int length)
    {
        var b = new byte[length];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(15)]
    [TestCase(16)]
    [TestCase(64)]
    [TestCase(1024)]
    public void AesGcm_encrypt_BC_decrypt_round_trips(int plaintextLength)
    {
        var key = Random(KeySize);
        var nonce = Random(NonceSize);
        var aad = Random(AadSize);
        var plaintext = Random(plaintextLength);

        // Encrypt with the in-box AesGcm.
        var ciphertext = new byte[plaintextLength];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }

        // Decrypt with BouncyCastle.
        var bc = new GcmBlockCipher(new AesEngine());
        bc.Init(forEncryption: false,
            new AeadParameters(new KeyParameter(key), TagSize * 8, nonce, aad));

        // BC expects ciphertext || tag concatenated.
        var bcInput = new byte[plaintextLength + TagSize];
        Buffer.BlockCopy(ciphertext, 0, bcInput, 0, plaintextLength);
        Buffer.BlockCopy(tag, 0, bcInput, plaintextLength, TagSize);

        var bcOutput = new byte[bc.GetOutputSize(bcInput.Length)];
        int written = bc.ProcessBytes(bcInput, 0, bcInput.Length, bcOutput, 0);
        written += bc.DoFinal(bcOutput, written);

        Assert.That(written, Is.EqualTo(plaintextLength));
        Assert.That(bcOutput.AsSpan(0, plaintextLength).SequenceEqual(plaintext), Is.True);
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(15)]
    [TestCase(16)]
    [TestCase(64)]
    [TestCase(1024)]
    public void BC_encrypt_AesGcm_decrypt_round_trips(int plaintextLength)
    {
        var key = Random(KeySize);
        var nonce = Random(NonceSize);
        var aad = Random(AadSize);
        var plaintext = Random(plaintextLength);

        // Encrypt with BouncyCastle.
        var bc = new GcmBlockCipher(new AesEngine());
        bc.Init(forEncryption: true,
            new AeadParameters(new KeyParameter(key), TagSize * 8, nonce, aad));

        var bcOutput = new byte[bc.GetOutputSize(plaintextLength)];
        int written = bc.ProcessBytes(plaintext, 0, plaintextLength, bcOutput, 0);
        written += bc.DoFinal(bcOutput, written);

        // Split BC's output into ciphertext and tag.
        var ciphertext = new byte[plaintextLength];
        var tag = new byte[TagSize];
        Buffer.BlockCopy(bcOutput, 0, ciphertext, 0, plaintextLength);
        Buffer.BlockCopy(bcOutput, plaintextLength, tag, 0, TagSize);

        // Decrypt with the in-box AesGcm.
        var roundTripped = new byte[plaintextLength];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, roundTripped, aad);

        Assert.That(roundTripped.SequenceEqual(plaintext), Is.True);
    }

    [Test]
    public void AesGcm_and_BC_produce_identical_ciphertext_for_identical_inputs()
    {
        // Stronger than round-trip: with the same key, nonce, AAD, and
        // plaintext, both implementations must emit the same bytes —
        // GCM is deterministic on (key, nonce, plaintext, AAD), so any
        // disagreement here points at a wire-format mismatch the shim
        // would inherit on the browser-wasm path.
        var key = Random(KeySize);
        var nonce = Random(NonceSize);
        var aad = Random(AadSize);
        var plaintext = Random(64);

        var aesCt = new byte[plaintext.Length];
        var aesTag = new byte[TagSize];
        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Encrypt(nonce, plaintext, aesCt, aesTag, aad);
        }

        var bc = new GcmBlockCipher(new AesEngine());
        bc.Init(forEncryption: true,
            new AeadParameters(new KeyParameter(key), TagSize * 8, nonce, aad));
        var bcOutput = new byte[bc.GetOutputSize(plaintext.Length)];
        int written = bc.ProcessBytes(plaintext, 0, plaintext.Length, bcOutput, 0);
        written += bc.DoFinal(bcOutput, written);

        Assert.That(bcOutput.AsSpan(0, plaintext.Length).SequenceEqual(aesCt), Is.True,
            "AesGcm and BC must produce the same ciphertext bytes under identical inputs");
        Assert.That(bcOutput.AsSpan(plaintext.Length, TagSize).SequenceEqual(aesTag), Is.True,
            "AesGcm and BC must produce the same authentication tag under identical inputs");
    }

    [Test]
    public void Wrong_aad_fails_decrypt_under_BC_when_encrypted_under_AesGcm()
    {
        // The shim binds the per-instance id as AAD on every operation. A
        // wrong-AAD decrypt must fail the tag check — verify this on the
        // BC side, since AesGcm's behaviour is well-tested already.
        var key = Random(KeySize);
        var nonce = Random(NonceSize);
        var rightAad = Random(AadSize);
        var wrongAad = Random(AadSize);
        var plaintext = Random(32);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, rightAad);
        }

        var bc = new GcmBlockCipher(new AesEngine());
        bc.Init(forEncryption: false,
            new AeadParameters(new KeyParameter(key), TagSize * 8, nonce, wrongAad));

        var bcInput = new byte[plaintext.Length + TagSize];
        Buffer.BlockCopy(ciphertext, 0, bcInput, 0, plaintext.Length);
        Buffer.BlockCopy(tag, 0, bcInput, plaintext.Length, TagSize);

        var bcOutput = new byte[bc.GetOutputSize(bcInput.Length)];
        Assert.Throws<Org.BouncyCastle.Crypto.InvalidCipherTextException>(() =>
        {
            int written = bc.ProcessBytes(bcInput, 0, bcInput.Length, bcOutput, 0);
            bc.DoFinal(bcOutput, written);
        });
    }

    [Test]
    public void Tampered_ciphertext_fails_decrypt_under_BC()
    {
        var key = Random(KeySize);
        var nonce = Random(NonceSize);
        var aad = Random(AadSize);
        var plaintext = Random(32);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }

        // Flip one bit in the ciphertext.
        ciphertext[0] ^= 0x01;

        var bc = new GcmBlockCipher(new AesEngine());
        bc.Init(forEncryption: false,
            new AeadParameters(new KeyParameter(key), TagSize * 8, nonce, aad));

        var bcInput = new byte[plaintext.Length + TagSize];
        Buffer.BlockCopy(ciphertext, 0, bcInput, 0, plaintext.Length);
        Buffer.BlockCopy(tag, 0, bcInput, plaintext.Length, TagSize);

        var bcOutput = new byte[bc.GetOutputSize(bcInput.Length)];
        Assert.Throws<Org.BouncyCastle.Crypto.InvalidCipherTextException>(() =>
        {
            int written = bc.ProcessBytes(bcInput, 0, bcInput.Length, bcOutput, 0);
            bc.DoFinal(bcOutput, written);
        });
    }
}
