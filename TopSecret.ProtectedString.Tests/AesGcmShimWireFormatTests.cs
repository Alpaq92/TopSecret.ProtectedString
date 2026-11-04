using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace TopSecret.ProtectedStringTests;

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
