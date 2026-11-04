using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Xml;

namespace TopSecret;

public static class ProtectedStringXml
{
    public const int DefaultMaxLength = 1024 * 1024;

    public static ProtectedString ReadElementContent(XmlReader reader) =>
        ReadElementContent(reader, DefaultMaxLength);

    public static ProtectedString ReadElementContent(XmlReader reader, int maxLength)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxLength);
        if (reader.NodeType != XmlNodeType.Element)
        {
            throw new InvalidOperationException(
                $"Reader must be positioned on an element to read its content; it is on {reader.NodeType}.");
        }

        // ProtectedString.Build disposes (and wipes) the half-built instance
        // if anything below throws, so no local try/catch is needed here.
        return ProtectedString.Build(ps =>
        {
            if (reader.IsEmptyElement) return;
            if (!reader.CanReadValueChunk)
            {
                throw new InvalidOperationException(
                    "This XmlReader does not support value chunking (CanReadValueChunk is false), which is " +
                    "required to read the value without materializing a managed string. Use a reader from " +
                    "XmlReader.Create, or one of the FromXml overloads.");
            }

            char[] buf = ArrayPool<char>.Shared.Rent(4096);
            try
            {
                reader.Read(); // Element -> first content node
                while (reader.NodeType != XmlNodeType.EndElement && !reader.EOF)
                {
                    switch (reader.NodeType)
                    {
                        case XmlNodeType.Text:
                        case XmlNodeType.CDATA:
                        case XmlNodeType.SignificantWhitespace:
                        case XmlNodeType.Whitespace:
                            int read;
                            while ((read = reader.ReadValueChunk(buf, 0, buf.Length)) > 0)
                            {
                                if (ps.Length + read > maxLength)
                                {
                                    throw new XmlException(
                                        $"Element content exceeds the {maxLength}-character ceiling for a " +
                                        $"{nameof(ProtectedString)}. If the value is legitimately that large, " +
                                        "use an overload with an explicit maxLength.");
                                }
                                ps.AppendChars(buf.AsSpan(0, read));
                            }
                            break;
                        case XmlNodeType.Comment:
                        case XmlNodeType.ProcessingInstruction:
                            break; // metadata — skip, keep reading text
                        default:
                            throw new InvalidOperationException(
                                $"Element content contains a {reader.NodeType} node; only text, CDATA, and " +
                                "comments are supported for a secret value element (child elements or " +
                                "unresolved entity references cannot be flattened into a ProtectedString).");
                    }
                    reader.Read(); // advance exactly one node per iteration
                }

                if (reader.NodeType != XmlNodeType.EndElement)
                {
                    throw new XmlException(
                        "Input ended before the element's end tag; refusing to return a possibly truncated value.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buf.AsSpan()));
                ArrayPool<char>.Shared.Return(buf);
            }
        });
    }

    public static ProtectedString FromXml(string xml, string elementLocalName) =>
        FromXml(xml, elementLocalName, DefaultMaxLength);

    public static ProtectedString FromXml(string xml, string elementLocalName, int maxLength)
    {
        ArgumentNullException.ThrowIfNull(xml);
        using var text = new StringReader(xml);
        using var reader = XmlReader.Create(text, s_xxeSafeSettings);
        return ReadNamedElement(reader, elementLocalName, maxLength);
    }

    public static ProtectedString FromXml(Stream xml, string elementLocalName) =>
        FromXml(xml, elementLocalName, DefaultMaxLength);

    public static ProtectedString FromXml(Stream xml, string elementLocalName, int maxLength)
    {
        ArgumentNullException.ThrowIfNull(xml);
        using var reader = XmlReader.Create(xml, s_xxeSafeSettings);
        return ReadNamedElement(reader, elementLocalName, maxLength);
    }

    private static ProtectedString ReadNamedElement(XmlReader reader, string elementLocalName, int maxLength)
    {
        ArgumentException.ThrowIfNullOrEmpty(elementLocalName);
        if (!reader.ReadToFollowing(elementLocalName))
        {
            throw new InvalidOperationException(
                $"No element named '{elementLocalName}' was found in the XML.");
        }
        return ReadElementContent(reader, maxLength);
    }

    private static readonly XmlReaderSettings s_xxeSafeSettings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        CloseInput = false,
    };
}
