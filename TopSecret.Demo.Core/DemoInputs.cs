using System.Security.Cryptography;

namespace TopSecret.Demo;

internal static class DemoInputs
{
    private const string Charset =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-_?@^~=";

    internal static string RandomSecret(int minLength = 5, int maxLength = 20) =>
        RandomNumberGenerator.GetString(Charset, RandomNumberGenerator.GetInt32(minLength, maxLength + 1));

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
        chars.AsSpan().Clear();
        return result;
    }
}
