using System.Security;

namespace TopSecret;

public static class SecureStringInterop
{
    public static SecureString ToSecureString(this ProtectedString source)
    {
        ArgumentNullException.ThrowIfNull(source);
        SecureString? result = null;
        try
        {
            source.Access((ReadOnlySpan<char> plain) =>
            {
                if (plain.IsEmpty)
                {
                    result = new SecureString();
                    return;
                }
                unsafe
                {
                    fixed (char* p = plain)
                    {
                        result = new SecureString(p, plain.Length);
                    }
                }
            });
            result!.MakeReadOnly();
            return result;
        }
        catch
        {
            result?.Dispose();
            throw;
        }
    }
}
