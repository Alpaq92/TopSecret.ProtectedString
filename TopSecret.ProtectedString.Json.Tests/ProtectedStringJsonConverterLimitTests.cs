using System.Text.Json;
using TopSecret;

namespace TopSecret.JsonTests;

/// <summary>
/// The converter refuses oversized JSON strings before allocating any scratch
/// for them, so a mis-bound field (a certificate body, a file) cannot grow the
/// locked build buffer until the memory-locking policy fires.
/// </summary>
[TestFixture]
public class ProtectedStringJsonConverterLimitTests
{
    private static string Read(ProtectedString ps) => ps.Access(plain => new string(plain));

    private static JsonSerializerOptions With(ProtectedStringJsonConverter converter) =>
        new() { Converters = { converter } };

    [Test]
    public void Default_ceiling_is_one_MiB_and_the_parameterless_converter_uses_it()
    {
        Assert.That(ProtectedStringJsonConverter.DefaultMaxUtf8Bytes, Is.EqualTo(1024 * 1024));
        Assert.That(new ProtectedStringJsonConverter().MaxUtf8Bytes, Is.EqualTo(ProtectedStringJsonConverter.DefaultMaxUtf8Bytes));
    }

    [Test]
    public void Ctor_rejects_non_positive_ceiling()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProtectedStringJsonConverter(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProtectedStringJsonConverter(-1));
    }

    [Test]
    public void Token_at_the_ceiling_binds_and_one_byte_over_is_rejected()
    {
        var options = With(new ProtectedStringJsonConverter(maxUtf8Bytes: 8));

        using var exact = JsonSerializer.Deserialize<ProtectedString>("\"12345678\"", options)!;
        Assert.That(Read(exact), Is.EqualTo("12345678"));

        var ex = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ProtectedString>("\"123456789\"", options));
        Assert.That(ex!.Message, Does.Contain("8-byte ceiling"));
    }

    [Test]
    public void Ceiling_is_measured_on_the_raw_token_so_escapes_count_toward_it()
    {
        // Raw token "AB" is 12 bytes although it unescapes to "AB".
        var options = With(new ProtectedStringJsonConverter(maxUtf8Bytes: 11));
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ProtectedString>("\"\\u0041\\u0042\"", options));

        var roomy = With(new ProtectedStringJsonConverter(maxUtf8Bytes: 12));
        using var ps = JsonSerializer.Deserialize<ProtectedString>("\"\\u0041\\u0042\"", roomy)!;
        Assert.That(Read(ps), Is.EqualTo("AB"));
    }

    [Test]
    public void Oversized_token_in_a_multi_segment_sequence_is_rejected_too()
    {
        // A tiny buffer forces Utf8JsonReader onto the ValueSequence path.
        var options = With(new ProtectedStringJsonConverter(maxUtf8Bytes: 16));
        var json = "\"" + new string('x', 64) + "\"";
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(json));
        var readerOptions = new JsonSerializerOptions(options) { DefaultBufferSize = 1 };

        Assert.That(
            async () => { await JsonSerializer.DeserializeAsync<ProtectedString>(stream, readerOptions); },
            Throws.TypeOf<JsonException>());
    }
}
