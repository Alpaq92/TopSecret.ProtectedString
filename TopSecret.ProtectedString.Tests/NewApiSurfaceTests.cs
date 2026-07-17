using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

/// <summary>
/// Behavioural tests for the members added alongside the locked-scratch
/// pool: <c>AppendChars</c>, <c>Utf8Access</c>,
/// <c>WriteUtf8To(IBufferWriter&lt;byte&gt;)</c>, and
/// <c>SecureStringInterop.ToSecureString</c>.
/// </summary>
[TestFixture]
public class NewApiSurfaceTests
{
    // ---- AppendChars -------------------------------------------------------

    [Test]
    public void AppendChars_round_trips_and_mixes_with_AppendChar()
    {
        using var ps = new ProtectedString();
        ps.AppendChars("corr".AsSpan());
        ps.AppendChar('e');
        ps.AppendChars("ct horse".AsSpan());
        ps.MakeReadOnly();

        Assert.That(ps.Length, Is.EqualTo("correct horse".Length));
        ps.Access(plain => Assert.That(new string(plain), Is.EqualTo("correct horse")));
    }

    [Test]
    public void AppendChars_lifts_existing_ciphertext_like_AppendChar()
    {
        using var ps = new ProtectedString("prefix-".AsSpan());
        ps.AppendChars("suffix".AsSpan());
        ps.MakeReadOnly();
        ps.Access(plain => Assert.That(new string(plain), Is.EqualTo("prefix-suffix")));
    }

    [Test]
    public void AppendChars_survives_source_aliasing_the_build_buffer_across_growth()
    {
        using var ps = new ProtectedString();
        ps.AppendChars("0123456789abcdef".AsSpan()); // exactly fills the initial 16-char capacity

        // Reentrant self-append: the handler's span aliases the live build
        // buffer, and the append forces growth, which wipes that buffer —
        // the staged-copy path must preserve the source.
        ps.Access(plain => ps.AppendChars(plain));

        Assert.That(ps.Length, Is.EqualTo(32));
        ps.Access(plain => Assert.That(
            new string(plain), Is.EqualTo("0123456789abcdef0123456789abcdef")));
    }

    [Test]
    public void AppendChars_empty_span_is_a_no_op_and_readonly_throws()
    {
        using var ps = new ProtectedString("x".AsSpan());
        ps.AppendChars(ReadOnlySpan<char>.Empty);
        Assert.That(ps.Length, Is.EqualTo(1));

        ps.MakeReadOnly();
        Assert.Throws<InvalidOperationException>(() => ps.AppendChars("y".AsSpan()));
    }

    // ---- AppendUtf8 / FromUtf8 --------------------------------------------

    [Test]
    public void FromUtf8_round_trips_non_ascii_bytes()
    {
        const string value = "naïve café ☕ пароль";
        var utf8 = System.Text.Encoding.UTF8.GetBytes(value);

        using var ps = ProtectedString.FromUtf8(utf8);

        Assert.That(ps.IsReadOnly, Is.True);
        ps.Access(plain => Assert.That(new string(plain), Is.EqualTo(value)));
    }

    [Test]
    public void FromUtf8_empty_yields_empty_readonly_instance()
    {
        using var ps = ProtectedString.FromUtf8(ReadOnlySpan<byte>.Empty);
        Assert.That(ps.Length, Is.EqualTo(0));
        Assert.That(ps.IsReadOnly, Is.True);
    }

    [Test]
    public void AppendUtf8_composes_with_char_appends()
    {
        using var ps = new ProtectedString();
        ps.AppendChars("id=".AsSpan());
        ps.AppendUtf8(System.Text.Encoding.UTF8.GetBytes("café"));
        ps.AppendChar('!');
        ps.MakeReadOnly();
        ps.Access(plain => Assert.That(new string(plain), Is.EqualTo("id=café!")));
    }

    [Test]
    public void AppendUtf8_read_only_throws_and_empty_is_a_no_op()
    {
        using var ps = new ProtectedString();
        ps.AppendChars("x".AsSpan());
        ps.AppendUtf8(ReadOnlySpan<byte>.Empty); // no-op, still writable
        Assert.That(ps.Length, Is.EqualTo(1));

        ps.MakeReadOnly();
        Assert.Throws<InvalidOperationException>(
            () => ps.AppendUtf8(System.Text.Encoding.UTF8.GetBytes("y")));
    }

    [Test]
    public void FromUtf8_rejects_invalid_utf8_instead_of_silently_substituting()
    {
        // A lone continuation byte is not valid UTF-8; strict decoding must
        // throw rather than corrupt the secret with a U+FFFD replacement.
        Assert.Throws<System.Text.DecoderFallbackException>(
            () => ProtectedString.FromUtf8(new byte[] { 0x80 }));
    }

    // ---- Utf8Access --------------------------------------------------------

    [Test]
    public void Utf8Access_hands_out_the_utf8_encoding_of_the_plaintext()
    {
        const string value = "zażółć gęślą jaźń"; // non-ASCII: bytes ≠ chars
        using var ps = new ProtectedString(value.AsSpan());
        var expected = Encoding.UTF8.GetBytes(value);

        ps.Utf8Access(bytes => Assert.That(bytes.SequenceEqual(expected), Is.True));
        Assert.That(ps.Utf8Access(bytes => bytes.Length), Is.EqualTo(expected.Length));
    }

    [Test]
    public void Utf8Access_on_empty_instance_hands_out_an_empty_span()
    {
        using var ps = new ProtectedString();
        ps.Utf8Access(bytes => Assert.That(bytes.IsEmpty, Is.True));
    }

    [Test]
    public void Utf8Access_works_in_build_mode()
    {
        using var ps = new ProtectedString();
        ps.AppendChars("build-mode".AsSpan());
        ps.Utf8Access(bytes => Assert.That(
            bytes.SequenceEqual(Encoding.UTF8.GetBytes("build-mode")), Is.True));
    }

    // ---- WriteUtf8To(IBufferWriter<byte>) ----------------------------------

    [Test]
    public void WriteUtf8To_buffer_writer_round_trips()
    {
        const string value = "writer-target ✓";
        using var ps = new ProtectedString(value.AsSpan());
        var writer = new ArrayBufferWriter<byte>();

        int written = ps.WriteUtf8To(writer);

        var expected = Encoding.UTF8.GetBytes(value);
        Assert.That(written, Is.EqualTo(expected.Length));
        Assert.That(writer.WrittenSpan.SequenceEqual(expected), Is.True);
    }

    [Test]
    public void WriteUtf8To_buffer_writer_on_empty_instance_writes_nothing()
    {
        using var ps = new ProtectedString();
        var writer = new ArrayBufferWriter<byte>();
        Assert.That(ps.WriteUtf8To(writer), Is.Zero);
        Assert.That(writer.WrittenCount, Is.Zero);
    }

    // ---- SecureStringInterop.ToSecureString --------------------------------

    [Test]
    public void ToSecureString_produces_a_readonly_copy_with_matching_content()
    {
        const string value = "bridge-me-🔑";
        using var ps = new ProtectedString(value.AsSpan());

        var sec = ps.ToSecureString();
        try
        {
            Assert.That(sec.IsReadOnly(), Is.True,
                "consumers like SqlCredential require MakeReadOnly()");
            Assert.That(sec.Length, Is.EqualTo(value.Length));

            nint bstr = Marshal.SecureStringToBSTR(sec);
            try
            {
                Assert.That(Marshal.PtrToStringBSTR(bstr), Is.EqualTo(value));
            }
            finally
            {
                Marshal.ZeroFreeBSTR(bstr);
            }
        }
        finally
        {
            sec.Dispose();
        }

        // The source is unaffected by the hand-off.
        ps.Access(plain => Assert.That(new string(plain), Is.EqualTo(value)));
    }

    [Test]
    public void ToSecureString_of_empty_instance_is_an_empty_readonly_SecureString()
    {
        using var ps = new ProtectedString();
        using var sec = ps.ToSecureString();
        Assert.That(sec.Length, Is.Zero);
        Assert.That(sec.IsReadOnly(), Is.True);
    }
}
