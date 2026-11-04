using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Xml;

namespace TopSecret;

/// <summary>
/// Reads an XML element's text content straight into a <see cref="ProtectedString"/>
/// without the secret ever materializing as a managed <see cref="string"/>:
/// <see cref="XmlReader.ReadValueChunk(char[], int, int)"/> streams the decoded
/// value (entities resolved) chunk-by-chunk into a transient, wiped buffer that
/// feeds <see cref="ProtectedString.AppendChars(ReadOnlySpan{char})"/>.
/// </summary>
/// <remarks>
/// <para>
/// Unlike <c>System.Text.Json</c>, <c>XmlSerializer</c> / <c>DataContractSerializer</c>
/// have no per-member converter hook, so this ships as an explicit reader helper
/// rather than an attribute you decorate a property with. Call
/// <see cref="ReadElementContent(XmlReader)"/> from your own <see cref="XmlReader"/> loop
/// or from inside a type's <c>IXmlSerializable.ReadXml</c>; use the hardened
/// <see cref="FromXml(Stream, string)"/> / <see cref="FromXml(string, string)"/>
/// convenience overloads when you just have the document.
/// </para>
/// <para>
/// <b>XXE.</b> <see cref="ReadElementContent(XmlReader)"/> reads from a reader <i>you</i>
/// create, so <i>you</i> own its <see cref="XmlReaderSettings"/> — configure it
/// XXE-safe for untrusted input (<see cref="DtdProcessing.Prohibit"/>,
/// <c>XmlResolver = null</c>). The <see cref="FromXml(Stream, string)"/> /
/// <see cref="FromXml(string, string)"/> overloads build the reader themselves
/// and bake in exactly those settings.
/// </para>
/// <para>
/// <b>Read-only by design.</b> There is no write path — serializing a
/// <see cref="ProtectedString"/> back to XML would materialize the plaintext,
/// exactly the exposure this library avoids.
/// </para>
/// </remarks>
public static class ProtectedStringXml
{
    /// <summary>
    /// Default ceiling on the number of characters an element's content may
    /// contribute to a <see cref="ProtectedString"/>: 1 Mi chars. A secret
    /// larger than that is almost certainly a mis-targeted element (a
    /// certificate body, an embedded file) and would otherwise grow the
    /// locked, dump-excluded build buffer until the memory-locking policy
    /// fires. Every reader overload has a sibling taking an explicit
    /// <c>maxLength</c> for legitimately large values.
    /// </summary>
    public const int DefaultMaxLength = 1024 * 1024;

    /// <summary>
    /// Reads the text content of the element the <paramref name="reader"/> is
    /// positioned on into a new read-only <see cref="ProtectedString"/>, with no
    /// managed <see cref="string"/>. An empty element (<c>&lt;x/&gt;</c> or
    /// <c>&lt;x&gt;&lt;/x&gt;</c>) yields an empty instance. Entity references
    /// and CDATA sections in the content are decoded. The <paramref name="reader"/>
    /// is left positioned on the element's end tag (or the empty element),
    /// matching the usual content-reading convention.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="reader"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The reader is not positioned on an element, or does not support value
    /// chunking (<see cref="XmlReader.CanReadValueChunk"/> is <see langword="false"/>).
    /// </exception>
    public static ProtectedString ReadElementContent(XmlReader reader) =>
        ReadElementContent(reader, DefaultMaxLength);

    /// <summary>
    /// <see cref="ReadElementContent(XmlReader)"/> with an explicit ceiling on
    /// the number of characters the element may contribute. Content beyond
    /// <paramref name="maxLength"/> characters throws
    /// <see cref="XmlException"/> and the partially built value is wiped.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxLength"/> is not positive.</exception>
    /// <exception cref="XmlException">
    /// The content exceeds <paramref name="maxLength"/>, or the reader ran out
    /// of input before the element's end tag (a truncated document from a
    /// reader that reports <see cref="XmlReader.EOF"/> instead of throwing).
    /// </exception>
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
                // Walk content to the end tag. ReadValueChunk drains the
                // current text/CDATA node in chunks and returns 0 at its end
                // without advancing, so each such node is drained then Read()
                // past. Comments / PIs are metadata and are skipped (a value
                // element may legitimately contain them). Anything else —
                // a child element or an unresolved entity reference — is
                // structure we cannot flatten into a secret, so throw rather
                // than silently truncate the value.
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

                // A conformant reader throws XmlException on a truncated
                // document before we get here; a custom reader that merely
                // reports EOF would otherwise hand back a silently truncated
                // secret. Fail closed either way.
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

    /// <summary>
    /// Parses <paramref name="xml"/> with DTD processing prohibited (XXE-safe),
    /// finds the first element named <paramref name="elementLocalName"/>, and
    /// reads its content into a <see cref="ProtectedString"/>.
    /// </summary>
    /// <remarks>
    /// The secret already exists inside the <paramref name="xml"/> string the
    /// caller holds, so this overload's benefit is the XXE-safe parse plus never
    /// creating an <i>additional</i> string; for a true no-string ingress read
    /// from a <see cref="Stream"/> via <see cref="FromXml(Stream, string)"/>.
    /// <paramref name="elementLocalName"/> is matched against the element's
    /// qualified name (<see cref="XmlReader.ReadToFollowing(string)"/>), so it
    /// finds an unprefixed <c>&lt;Password&gt;</c> even under a default
    /// namespace, but not a <i>prefixed</i> <c>&lt;ns:Password&gt;</c> — for
    /// namespaced documents drive your own reader and call
    /// <see cref="ReadElementContent(XmlReader)"/>.
    /// </remarks>
    /// <exception cref="InvalidOperationException">No element named <paramref name="elementLocalName"/> was found.</exception>
    public static ProtectedString FromXml(string xml, string elementLocalName) =>
        FromXml(xml, elementLocalName, DefaultMaxLength);

    /// <summary>
    /// <see cref="FromXml(string, string)"/> with an explicit ceiling on the
    /// element's content length — see <see cref="ReadElementContent(XmlReader, int)"/>.
    /// </summary>
    public static ProtectedString FromXml(string xml, string elementLocalName, int maxLength)
    {
        ArgumentNullException.ThrowIfNull(xml);
        using var text = new StringReader(xml);
        using var reader = XmlReader.Create(text, s_xxeSafeSettings);
        return ReadNamedElement(reader, elementLocalName, maxLength);
    }

    /// <summary>
    /// Parses <paramref name="xml"/> from a stream with DTD processing
    /// prohibited (XXE-safe), finds the first element named
    /// <paramref name="elementLocalName"/>, and reads its content into a
    /// <see cref="ProtectedString"/> — a true no-managed-string ingress.
    /// </summary>
    /// <exception cref="InvalidOperationException">No element named <paramref name="elementLocalName"/> was found.</exception>
    public static ProtectedString FromXml(Stream xml, string elementLocalName) =>
        FromXml(xml, elementLocalName, DefaultMaxLength);

    /// <summary>
    /// <see cref="FromXml(Stream, string)"/> with an explicit ceiling on the
    /// element's content length — see <see cref="ReadElementContent(XmlReader, int)"/>.
    /// </summary>
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

    // Shared across both FromXml overloads. XmlReader.Create takes a read-only
    // snapshot of the settings, so one frozen instance is safe to reuse. The
    // XXE-critical values (Prohibit / null resolver) are set explicitly rather
    // than relying on the net10.0 defaults, to pin intent for a security
    // library against a future default change.
    private static readonly XmlReaderSettings s_xxeSafeSettings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        CloseInput = false,
    };
}
