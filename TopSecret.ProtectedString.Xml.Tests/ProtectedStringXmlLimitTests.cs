using System.Text;
using System.Xml;
using TopSecret;

namespace TopSecret.XmlTests;

/// <summary>
/// Content-length ceiling and truncation hardening for the XML reader.
/// </summary>
[TestFixture]
public class ProtectedStringXmlLimitTests
{
    private static string Read(ProtectedString ps) => ps.Access(plain => new string(plain));

    private static XmlReader ReaderOn(string xml, string element)
    {
        var reader = XmlReader.Create(new StringReader(xml));
        reader.ReadToFollowing(element);
        return reader;
    }

    [Test]
    public void Default_ceiling_is_one_Mi_chars()
    {
        Assert.That(ProtectedStringXml.DefaultMaxLength, Is.EqualTo(1024 * 1024));
    }

    [Test]
    public void Content_at_the_ceiling_binds_and_one_char_over_throws_XmlException()
    {
        using (var reader = ReaderOn("<r><P>12345678</P></r>", "P"))
        using (var ps = ProtectedStringXml.ReadElementContent(reader, maxLength: 8))
        {
            Assert.That(Read(ps), Is.EqualTo("12345678"));
        }

        using var over = ReaderOn("<r><P>123456789</P></r>", "P");
        var ex = Assert.Throws<XmlException>(() => ProtectedStringXml.ReadElementContent(over, maxLength: 8));
        Assert.That(ex!.Message, Does.Contain("8-character ceiling"));
    }

    [Test]
    public void Ceiling_applies_across_chunk_boundaries_and_mixed_text_and_cdata()
    {
        var big = new string('a', 5000);
        var xml = $"<r><P>{big}<![CDATA[{big}]]></P></r>";

        using (var reader = ReaderOn(xml, "P"))
        using (var ps = ProtectedStringXml.ReadElementContent(reader, maxLength: 10_000))
        {
            Assert.That(ps.Length, Is.EqualTo(10_000));
        }

        using var over = ReaderOn(xml, "P");
        Assert.Throws<XmlException>(() => ProtectedStringXml.ReadElementContent(over, maxLength: 9_999));
    }

    [Test]
    public void FromXml_overloads_accept_an_explicit_ceiling()
    {
        const string xml = "<r><P>secret</P></r>";

        using (var ps = ProtectedStringXml.FromXml(xml, "P", maxLength: 6))
            Assert.That(Read(ps), Is.EqualTo("secret"));
        Assert.Throws<XmlException>(() => ProtectedStringXml.FromXml(xml, "P", maxLength: 5));

        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        using (var ps = ProtectedStringXml.FromXml(stream, "P", maxLength: 6))
            Assert.That(Read(ps), Is.EqualTo("secret"));
        stream.Position = 0;
        Assert.Throws<XmlException>(() => ProtectedStringXml.FromXml(stream, "P", maxLength: 5));
    }

    [Test]
    public void Non_positive_ceiling_is_rejected()
    {
        using var reader = ReaderOn("<r><P>x</P></r>", "P");
        Assert.Throws<ArgumentOutOfRangeException>(() => ProtectedStringXml.ReadElementContent(reader, maxLength: 0));
    }

    [Test]
    public void Truncated_document_fails_closed_instead_of_returning_a_partial_value()
    {
        // The conformant reader throws its own XmlException on the missing
        // end tag; the point is that no ProtectedString with a partial
        // value is ever handed back.
        using var reader = ReaderOn("<r><P>partial-secr", "P");
        Assert.Throws<XmlException>(() => ProtectedStringXml.ReadElementContent(reader));
    }

    [Test]
    public void Reader_that_reports_EOF_without_throwing_is_rejected()
    {
        using var inner = ReaderOn("<r><P>partial</P></r>", "P");
        using var reader = new EofAfterFirstTextReader(inner);
        var ex = Assert.Throws<XmlException>(() => ProtectedStringXml.ReadElementContent(reader));
        Assert.That(ex!.Message, Does.Contain("before the element's end tag"));
    }

    /// <summary>
    /// Wraps a real reader but pretends the input ended right after the first
    /// text node — the "custom reader that reports EOF instead of throwing"
    /// shape the fail-closed check exists for.
    /// </summary>
    private sealed class EofAfterFirstTextReader : XmlReader
    {
        private readonly XmlReader _inner;
        private bool _sawText;
        private bool _eof;

        public EofAfterFirstTextReader(XmlReader inner) => _inner = inner;

        public override bool Read()
        {
            if (_sawText)
            {
                _eof = true;
                return false;
            }
            bool ok = _inner.Read();
            if (_inner.NodeType == XmlNodeType.Text) _sawText = true;
            return ok;
        }

        public override bool EOF => _eof;
        public override XmlNodeType NodeType => _eof ? XmlNodeType.None : _inner.NodeType;
        public override bool CanReadValueChunk => _inner.CanReadValueChunk;
        public override int ReadValueChunk(char[] buffer, int index, int count) =>
            _eof ? 0 : _inner.ReadValueChunk(buffer, index, count);
        public override bool IsEmptyElement => _inner.IsEmptyElement;

        // Everything else delegates; none of it is exercised by the test.
        public override int AttributeCount => _inner.AttributeCount;
        public override string BaseURI => _inner.BaseURI;
        public override int Depth => _inner.Depth;
        public override string LocalName => _inner.LocalName;
        public override string NamespaceURI => _inner.NamespaceURI;
        public override XmlNameTable NameTable => _inner.NameTable;
        public override string Prefix => _inner.Prefix;
        public override ReadState ReadState => _eof ? ReadState.EndOfFile : _inner.ReadState;
        public override string Value => _inner.Value;
        public override string GetAttribute(int i) => _inner.GetAttribute(i);
        public override string? GetAttribute(string name) => _inner.GetAttribute(name);
        public override string? GetAttribute(string name, string? namespaceURI) => _inner.GetAttribute(name, namespaceURI);
        public override string? LookupNamespace(string prefix) => _inner.LookupNamespace(prefix);
        public override bool MoveToAttribute(string name) => _inner.MoveToAttribute(name);
        public override bool MoveToAttribute(string name, string? ns) => _inner.MoveToAttribute(name, ns);
        public override bool MoveToElement() => _inner.MoveToElement();
        public override bool MoveToFirstAttribute() => _inner.MoveToFirstAttribute();
        public override bool MoveToNextAttribute() => _inner.MoveToNextAttribute();
        public override bool ReadAttributeValue() => _inner.ReadAttributeValue();
        public override void ResolveEntity() => _inner.ResolveEntity();
    }
}
