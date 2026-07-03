using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace TopSecret.ProtectedStringTests;

/// <summary>
/// Conformance tests against published AES-GCM-256 test vectors. Both
/// the in-box <see cref="AesGcm"/> (the implementation used on every
/// non-browser TFM) and BouncyCastle's <c>GcmBlockCipher</c> (the
/// implementation the <c>net10.0-browser</c> shim wraps) must reproduce
/// these vectors exactly.
/// </summary>
/// <remarks>
/// <para>
/// The cross-implementation parity tests in
/// <see cref="AesGcmShimWireFormatTests"/> prove the two implementations
/// agree with each other; these tests prove they both also agree with
/// the spec — i.e., that "internal consistency" doesn't mask a shared
/// bug both implementations have inherited from the same broken source.
/// </para>
/// <para>
/// Vectors are drawn from:
/// </para>
/// <list type="bullet">
///   <item>The NIST SP 800-38D specification (Appendix B test cases).</item>
///   <item>The original GCM paper (McGrew &amp; Viega, 2004), test vectors
///   reproduced verbatim across BC's, OpenSSL's, libsodium's, and Go's
///   crypto suites — a vector that fails one of these would have been
///   reported decades ago.</item>
/// </list>
/// <para>
/// All vectors below use 256-bit keys, 96-bit IVs, and 128-bit tags —
/// the only AES-GCM variant the library uses.
/// </para>
/// </remarks>
[TestFixture]
public class NistGoldenVectorTests
{
    /// <summary>
    /// Test vectors as (label, key, iv, aad, plaintext, expectedCiphertext, expectedTag),
    /// all hex-encoded. Empty fields are the empty string.
    /// </summary>
    /// <remarks>
    /// All vectors verified at the time of writing against both
    /// <see cref="AesGcm"/> and BouncyCastle's <c>GcmBlockCipher</c>. A
    /// new vector should be added only after manually verifying its
    /// expected ciphertext / tag against an independent implementation
    /// — recalling values from memory has bitten this fixture before.
    /// </remarks>
    private static IEnumerable<TestCaseData> Vectors()
    {
        // GCM paper Test Case 13: 256-bit zero key, zero IV, empty
        // plaintext, empty AAD. Tag is the GHASH of an empty stream
        // under H = E(K, 0^128) — the degenerate but well-defined case.
        yield return new TestCaseData(
            "TC13: 256-bit zero key, zero IV, empty P/A",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b");

        // GCM paper Test Case 14: 256-bit zero key, zero IV, single
        // block (16 bytes) of zero plaintext. Exercises the encrypt
        // path through one GHASH iteration.
        yield return new TestCaseData(
            "TC14: 256-bit zero key, zero IV, single zero block P",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919");

        // Multi-block + AAD vectors (e.g. GCM paper TC16) are
        // intentionally omitted: recalling them from memory bit me
        // once. Add them only after pulling the values directly from
        // a primary source (NIST CAVS gcmEncryptExtIV256.rsp, the
        // McGrew/Viega 2004 paper, or BC's AesGcmTest fixture) and
        // verifying via at least one independent implementation.
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
