using System.Security;

namespace TopSecret;

/// <summary>
/// Bridges <see cref="ProtectedString"/> to APIs whose signatures demand a
/// genuine <see cref="SecureString"/> — <c>SqlCredential</c>,
/// <c>PSCredential</c>, the <c>X509Certificate2</c> password overloads.
/// This is a hand-off, not an impersonation: <see cref="SecureString"/> is
/// sealed, its consumers dispatch on the concrete type, and no substitute can
/// be injected (see the README's "Replacing SecureString" section and FAQ).
/// </summary>
public static class SecureStringInterop
{
    /// <summary>
    /// Copies the plaintext into a new read-only <see cref="SecureString"/>
    /// in a single pass, using the public unsafe
    /// <see cref="SecureString(char*, int)"/> constructor — one copy under
    /// <c>fixed</c>, with none of the intermediate growth states a
    /// per-character <see cref="SecureString.AppendChar"/> loop leaves
    /// behind.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Caveats to carry to the consuming API: <see cref="SecureString"/>
    /// encrypts its buffer on Windows only (elsewhere it is plaintext in
    /// unmanaged, non-GC memory, zeroed on dispose); its constructor caps
    /// values at 65,536 characters (longer sources throw
    /// <see cref="ArgumentOutOfRangeException"/>); and <c>SqlCredential</c>
    /// caps passwords at 128 characters and requires exactly the read-only
    /// state this method already applies.
    /// </para>
    /// <para>
    /// The caller owns the result: dispose it when the consuming API no
    /// longer reads it — but not earlier. A cached <c>SqlCredential</c>, for
    /// example, re-reads the <see cref="SecureString"/> whenever the
    /// connection pool opens a new physical connection, so there it must
    /// stay undisposed for the credential's lifetime.
    /// </para>
    /// </remarks>
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
