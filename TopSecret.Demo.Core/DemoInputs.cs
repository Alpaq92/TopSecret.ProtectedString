using System.Security.Cryptography;

namespace TopSecret.Demo;

/// <summary>
/// Fresh random inputs for every demo run — including "Run again" in the
/// browser — so the printed lengths, hashes and checksums visibly change
/// between runs instead of replaying canned values. The generated values are
/// demo inputs, not real credentials.
/// </summary>
internal static class DemoInputs
{
    // Password-shaped printable ASCII: lower- and upper-case letters, digits,
    // and special symbols. The values themselves are never printed (the demo
    // never prints plaintext), only their lengths, hashes and checksums.
    private const string Charset =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-_?@^~=";

    /// <summary>A fresh random secret of <paramref name="minLength"/>–<paramref name="maxLength"/> (inclusive, default 5–20) characters.</summary>
    internal static string RandomSecret(int minLength = 5, int maxLength = 20) =>
        RandomNumberGenerator.GetString(Charset, RandomNumberGenerator.GetInt32(minLength, maxLength + 1));

    /// <summary>
    /// A copy of <paramref name="secret"/> differing in exactly one character —
    /// the "wrong attempt" counterpart for the equality and credential
    /// verification scenarios.
    /// </summary>
    internal static string MutateOneChar(string secret)
    {
        var chars = secret.ToCharArray();
        int position = RandomNumberGenerator.GetInt32(chars.Length);
        char replacement;
        do
        {
            replacement = Charset[RandomNumberGenerator.GetInt32(Charset.Length)];
        } while (replacement == chars[position]);
        chars[position] = replacement;
        var result = new string(chars);
        // Wipe the intermediate copy — the input/output strings are immutable
        // and unwipeable (the accepted demo-input caveat, see the class doc),
        // but this scratch array is wipeable, so the demo's own copy-hygiene
        // discipline applies.
        chars.AsSpan().Clear();
        return result;
    }
}
