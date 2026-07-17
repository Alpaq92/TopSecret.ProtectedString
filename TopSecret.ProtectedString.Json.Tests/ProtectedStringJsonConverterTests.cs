using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TopSecret;

namespace TopSecret.JsonTests;

[TestFixture]
public class ProtectedStringJsonConverterTests
{
    private sealed record Login
    {
        public string User { get; init; } = "";

        [JsonConverter(typeof(ProtectedStringJsonConverter))]
        public ProtectedString? Password { get; init; }
    }

    private static readonly JsonSerializerOptions OptionsWithConverter = new()
    {
        Converters = { new ProtectedStringJsonConverter() },
    };

    [Test]
    public void Deserializes_a_string_property_into_a_ProtectedString()
    {
        const string json = """{ "User": "alice", "Password": "correct horse battery staple" }""";

        var login = JsonSerializer.Deserialize<Login>(json)!;

        Assert.That(login.User, Is.EqualTo("alice"));
        Assert.That(login.Password, Is.Not.Null);
        Assert.That(login.Password!.IsReadOnly, Is.True);
        login.Password.Access(plain =>
            Assert.That(new string(plain), Is.EqualTo("correct horse battery staple")));
    }

    [Test]
    public void Unescapes_json_escapes_without_corruption()
    {
        // The secret contains a quote, a backslash, a unicode escape, and a
        // multi-byte UTF-8 character — CopyString must unescape all of them.
        const string secret = "a\"b\\cé🔑"; // a"b\cé🔑
        string json = JsonSerializer.Serialize(new { Password = secret });

        var value = JsonSerializer.Deserialize<Login>(json, OptionsWithConverter)!;
        value.Password!.Access(plain =>
            Assert.That(new string(plain), Is.EqualTo(secret)));
    }

    [Test]
    public void Handles_empty_string()
    {
        const string json = """{ "Password": "" }""";
        var value = JsonSerializer.Deserialize<Login>(json, OptionsWithConverter)!;
        Assert.That(value.Password!.Length, Is.EqualTo(0));
    }

    [Test]
    public void Deserializes_directly_via_options_converter()
    {
        using var ps = JsonSerializer.Deserialize<ProtectedString>("\"token-value\"", OptionsWithConverter)!;
        ps.Access(plain => Assert.That(new string(plain), Is.EqualTo("token-value")));
    }

    [Test]
    public void Rejects_a_non_string_token()
    {
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ProtectedString>("12345", OptionsWithConverter));
    }

    [Test]
    public void Rejects_invalid_utf8_escape_content()
    {
        // A JSON string escaping a lone high surrogate is invalid Unicode;
        // System.Text.Json rejects it before or during CopyString.
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ProtectedString>("\"\\ud83d\"", OptionsWithConverter));
    }

    [Test]
    public void Serialization_is_refused_to_avoid_materializing_the_plaintext()
    {
        using var ps = new ProtectedString("secret".AsSpan());
        var ex = Assert.Throws<NotSupportedException>(
            () => JsonSerializer.Serialize(ps, OptionsWithConverter));
        Assert.That(ex!.Message, Does.Contain("deserialization-only"));
    }

    [Test]
    public void Large_secret_beyond_the_pool_chunk_ceiling_round_trips()
    {
        // Larger than the pool's 4 KiB max chunk, exercising the oversize
        // dedicated-buffer path inside the converter's Rent.
        var big = new string('x', 10_000);
        string json = JsonSerializer.Serialize(new { Password = big });
        var value = JsonSerializer.Deserialize<Login>(json, OptionsWithConverter)!;
        value.Password!.Access(plain => Assert.That(plain.Length, Is.EqualTo(10_000)));
    }
}
