using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace TopSecret.ProtectedStringTests;

[TestFixture]
public class NistGoldenVectorTests
{
    private static IEnumerable<TestCaseData> Vectors()
    {
        yield return new TestCaseData(
            "TC13: 256-bit zero key, zero IV, empty P/A",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b");

        yield return new TestCaseData(
            "TC14: 256-bit zero key, zero IV, single zero block P",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919");
    }

    private static byte[] Hex(string hex) =>
        hex.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(hex);

    [TestCaseSource(nameof(Vectors))]
    public void In_box_AesGcm_matches_NIST_vector(
        string label, string keyHex, string ivHex, string aadHex,
        string plaintextHex, string expectedCiphertextHex, string expectedTagHex)
    {
        var key = Hex(keyHex);
        var iv = Hex(ivHex);
        var aad = Hex(aadHex);
        var plaintext = Hex(plaintextHex);
        var expectedCt = Hex(expectedCiphertextHex);
        var expectedTag = Hex(expectedTagHex);

        var actualCt = new byte[plaintext.Length];
        var actualTag = new byte[expectedTag.Length];
        using var aes = new AesGcm(key, expectedTag.Length);
        aes.Encrypt(iv, plaintext, actualCt, actualTag, aad);

        Assert.That(actualCt, Is.EqualTo(expectedCt), $"{label}: ciphertext mismatch");
        Assert.That(actualTag, Is.EqualTo(expectedTag), $"{label}: tag mismatch");

        // Round-trip: decrypt the spec-matching ciphertext + tag back to
        // plaintext to prove decrypt also conforms.
        var roundTripped = new byte[plaintext.Length];
        aes.Decrypt(iv, expectedCt, expectedTag, roundTripped, aad);
        Assert.That(roundTripped, Is.EqualTo(plaintext), $"{label}: round-trip mismatch");
    }

    [TestCaseSource(nameof(Vectors))]
    public void BouncyCastle_GcmBlockCipher_matches_NIST_vector(
        string label, string keyHex, string ivHex, string aadHex,
        string plaintextHex, string expectedCiphertextHex, string expectedTagHex)
    {
        var key = Hex(keyHex);
        var iv = Hex(ivHex);
        var aad = Hex(aadHex);
        var plaintext = Hex(plaintextHex);
        var expectedCt = Hex(expectedCiphertextHex);
        var expectedTag = Hex(expectedTagHex);

        // BC's GcmBlockCipher emits ciphertext || tag in one contiguous buffer.
        var bc = new GcmBlockCipher(new AesEngine());
        bc.Init(forEncryption: true,
            new AeadParameters(new KeyParameter(key), expectedTag.Length * 8, iv, aad));
        var output = new byte[bc.GetOutputSize(plaintext.Length)];
        int written = bc.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        written += bc.DoFinal(output, written);

        Assert.That(written, Is.EqualTo(plaintext.Length + expectedTag.Length),
            $"{label}: output size mismatch");

        var actualCt = output[..plaintext.Length];
        var actualTag = output[plaintext.Length..(plaintext.Length + expectedTag.Length)];
        Assert.That(actualCt, Is.EqualTo(expectedCt), $"{label}: BC ciphertext mismatch");
        Assert.That(actualTag, Is.EqualTo(expectedTag), $"{label}: BC tag mismatch");

        // Round-trip: BC decrypt of the spec ct||tag back to plaintext.
        var bcDec = new GcmBlockCipher(new AesEngine());
        bcDec.Init(forEncryption: false,
            new AeadParameters(new KeyParameter(key), expectedTag.Length * 8, iv, aad));
        var bcInput = new byte[expectedCt.Length + expectedTag.Length];
        Buffer.BlockCopy(expectedCt, 0, bcInput, 0, expectedCt.Length);
        Buffer.BlockCopy(expectedTag, 0, bcInput, expectedCt.Length, expectedTag.Length);
        var bcDecOut = new byte[bcDec.GetOutputSize(bcInput.Length)];
        int decWritten = bcDec.ProcessBytes(bcInput, 0, bcInput.Length, bcDecOut, 0);
        decWritten += bcDec.DoFinal(bcDecOut, decWritten);
        Assert.That(bcDecOut[..decWritten], Is.EqualTo(plaintext),
            $"{label}: BC round-trip mismatch");
    }
}
