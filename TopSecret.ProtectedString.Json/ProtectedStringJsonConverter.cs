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
        // scratch to the raw length is always sufficient for CopyString.
        int maxBytes = reader.HasValueSequence
            ? checked((int)reader.ValueSequence.Length)
            : reader.ValueSpan.Length;

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

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always — see the type remarks.</exception>
    public override void Write(
        Utf8JsonWriter writer, ProtectedString value, JsonSerializerOptions options) =>
        throw new NotSupportedException(
            "Serializing a ProtectedString to JSON would materialize the plaintext as a JSON " +
            "string. This converter is deserialization-only by design; send the plaintext under " +
            "TLS to a fresh ProtectedString on the other side instead.");
}
