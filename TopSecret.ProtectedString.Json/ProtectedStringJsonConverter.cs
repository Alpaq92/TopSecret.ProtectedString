using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TopSecret;

/// <summary>
/// A <see cref="JsonConverter{T}"/> that reads a JSON string value straight
/// into a <see cref="ProtectedString"/> without the secret ever materializing
/// as a managed <see cref="string"/>: the token is unescaped
/// (<c>Utf8JsonReader.CopyString</c>) into a transient, wiped staging buffer
/// and handed to <see cref="ProtectedString.FromUtf8"/>, which places it in the
/// core's locked scratch. The staging buffer is an <see cref="ArrayPool{T}"/>
/// rental wiped in a <c>finally</c> — the same "already-unlocked boundary"
/// trade-off as writing to a <see cref="System.IO.Stream"/>: the JSON document
/// the secret arrives in is itself unlocked, so this package needs no access to
/// the core's internals.
/// </summary>
/// <remarks>
/// <para>
/// Register it on a property with
/// <c>[JsonConverter(typeof(ProtectedStringJsonConverter))]</c>, or add it to
/// <c>JsonSerializerOptions.Converters</c> to cover every
/// <see cref="ProtectedString"/> in a graph.
/// </para>
/// <para>
/// <b>Read-only by design.</b> <see cref="Write"/> throws
/// <see cref="NotSupportedException"/>: serializing a
/// <see cref="ProtectedString"/> back out would materialize the plaintext as a
/// JSON string, exactly the exposure this library exists to avoid (see the
/// project's FAQ on why <see cref="ProtectedString"/> is not serializable).
/// The converter's job is to get a secret <i>into</i> protection at the
/// deserialization boundary, not out of it.
/// </para>
/// </remarks>
public sealed class ProtectedStringJsonConverter : JsonConverter<ProtectedString>
{
    /// <inheritdoc/>
    public override ProtectedString Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException(
                $"Expected a JSON string to bind into a {nameof(ProtectedString)}, got {reader.TokenType}.");
        }

        // Unescaped output is never longer than the raw token, so sizing the
        // scratch to the raw length is always sufficient for CopyString. The
        // ceiling is enforced on the raw length too, BEFORE any allocation,
        // so an oversized token never reaches the locked build buffer.
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

    /// <summary>
    /// Default ceiling on the raw UTF-8 length of a JSON string this converter
    /// will bind: 1 MiB. A secret larger than that is almost certainly a
    /// mis-bound field (a certificate blob, a file body) and would otherwise
    /// grow the locked, dump-excluded build buffer until the memory-locking
    /// policy fires. Raise it through
    /// <see cref="ProtectedStringJsonConverter(int)"/> for a legitimately
    /// large value; it is not a hard limit of the type.
    /// </summary>
    public const int DefaultMaxUtf8Bytes = 1024 * 1024;

    private readonly int _maxUtf8Bytes;

    /// <summary>Converter with the <see cref="DefaultMaxUtf8Bytes"/> ceiling (the shape <c>[JsonConverter]</c> attributes need).</summary>
    public ProtectedStringJsonConverter() : this(DefaultMaxUtf8Bytes) { }

    /// <summary>
    /// Converter that rejects any JSON string whose raw UTF-8 token is longer
    /// than <paramref name="maxUtf8Bytes"/> with a <see cref="JsonException"/>
    /// before allocating any scratch for it. Register it through
    /// <see cref="JsonSerializerOptions.Converters"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxUtf8Bytes"/> is not positive.</exception>
    public ProtectedStringJsonConverter(int maxUtf8Bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxUtf8Bytes);
        _maxUtf8Bytes = maxUtf8Bytes;
    }

    /// <summary>The raw UTF-8 token length ceiling this instance enforces.</summary>
    public int MaxUtf8Bytes => _maxUtf8Bytes;

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always — see the type remarks.</exception>
    public override void Write(
        Utf8JsonWriter writer, ProtectedString value, JsonSerializerOptions options) =>
        throw new NotSupportedException(
            "Serializing a ProtectedString to JSON would materialize the plaintext as a JSON " +
            "string. This converter is deserialization-only by design; send the plaintext under " +
            "TLS to a fresh ProtectedString on the other side instead.");
}
