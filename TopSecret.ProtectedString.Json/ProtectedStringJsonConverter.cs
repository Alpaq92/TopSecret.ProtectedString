using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TopSecret;

public sealed class ProtectedStringJsonConverter : JsonConverter<ProtectedString>
{
    public override ProtectedString Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException(
                $"Expected a JSON string to bind into a {nameof(ProtectedString)}, got {reader.TokenType}.");
        }

        long rawLength = reader.HasValueSequence ? reader.ValueSequence.Length : reader.ValueSpan.Length;
        if (rawLength > _maxUtf8Bytes)
        {
            throw new JsonException(
                $"JSON string is {rawLength} UTF-8 bytes, above this converter's {_maxUtf8Bytes}-byte ceiling " +
                $"for a {nameof(ProtectedString)}. If the value is legitimately that large, register " +
                $"new {nameof(ProtectedStringJsonConverter)}(maxUtf8Bytes) with a higher ceiling.");
        }
        int maxBytes = (int)rawLength;

        if (maxBytes == 0)
        {
            return ProtectedString.FromUtf8(ReadOnlySpan<byte>.Empty);
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(maxBytes);
        try
        {
            int written = reader.CopyString(buffer);
            return ProtectedString.FromUtf8(buffer.AsSpan(0, written));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, maxBytes));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public const int DefaultMaxUtf8Bytes = 1024 * 1024;

    private readonly int _maxUtf8Bytes;

    public ProtectedStringJsonConverter() : this(DefaultMaxUtf8Bytes) { }

    public ProtectedStringJsonConverter(int maxUtf8Bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxUtf8Bytes);
        _maxUtf8Bytes = maxUtf8Bytes;
    }

    public int MaxUtf8Bytes => _maxUtf8Bytes;

    public override void Write(
        Utf8JsonWriter writer, ProtectedString value, JsonSerializerOptions options) =>
        throw new NotSupportedException(
            "Serializing a ProtectedString to JSON would materialize the plaintext as a JSON " +
            "string. This converter is deserialization-only by design; send the plaintext under " +
            "TLS to a fresh ProtectedString on the other side instead.");
}
