using System.Text;
using System.Xml;
using TopSecret;

namespace TopSecret.XmlTests;

[TestFixture]
public class ProtectedStringXmlTests
{
    private static string Read(ProtectedString ps) => ps.Access(plain => new string(plain));

    private static XmlReader ReaderOn(string xml, string element)
    {
        var reader = XmlReader.Create(new StringReader(xml));
        reader.ReadToFollowing(element);
        return reader;
    }

    // ---- ReadElementContent -----------------------------------------------

    [Test]
    public void Reads_simple_element_text()
    {
        using var reader = ReaderOn("<root><Password>correct horse battery staple</Password></root>", "Password");
        using var ps = ProtectedStringXml.ReadElementContent(reader);
        Assert.That(ps.IsReadOnly, Is.True);
        Assert.That(Read(ps), Is.EqualTo("correct horse battery staple"));
    }

    [Test]
    public void Decodes_entities_and_numeric_char_refs()
    {
        // &amp; &lt; &gt; &#x41; (A) &#233; (é) must all decode.
        using var reader = ReaderOn("<r><P>a&amp;b&lt;c&gt;&#x41;&#233;</P></r>", "P");
        using var ps = ProtectedStringXml.ReadElementContent(reader);
        Assert.That(Read(ps), Is.EqualTo("a&b<c>Aé"));
    }

    [Test]
    public void Reads_cdata_and_mixed_content()
    {
        using var reader = ReaderOn("<r><P>abc<![CDATA[d<e>f]]>ghi</P></r>", "P");
        using var ps = ProtectedStringXml.ReadElementContent(reader);
        Assert.That(Read(ps), Is.EqualTo("abcd<e>fghi"));
    }

    [Test]
    public void Skips_comments_and_processing_instructions_without_truncating()
    {
        // Default XmlReader.Create surfaces comment / PI nodes; the value must
        // be read in full across them, not truncated at the first one.
        using var reader = ReaderOn("<r><P>sec<!--note-->ret<?pi data?> end</P></r>", "P");
        using var ps = ProtectedStringXml.ReadElementContent(reader);
        Assert.That(Read(ps), Is.EqualTo("secret end")); // "sec" + "ret" + " end", comment/PI skipped
    }

    [Test]
    public void Leading_comment_does_not_drop_the_value()
    {
        using var reader = ReaderOn("<r><P><!--x-->secret</P></r>", "P");
        using var ps = ProtectedStringXml.ReadElementContent(reader);
        Assert.That(Read(ps), Is.EqualTo("secret"));
    }

    [Test]
    public void Throws_on_a_child_element_in_the_value()
    {
        // A nested element cannot be flattened into a secret — throw loudly
        // rather than silently truncate.
        using var reader = ReaderOn("<r><P>a<b/>c</P></r>", "P");
        Assert.Throws<InvalidOperationException>(() => ProtectedStringXml.ReadElementContent(reader));
    }

    [Test]
    public void FromXml_matches_an_unprefixed_element_under_a_default_namespace()
    {
        const string xml = "<config xmlns=\"urn:x\"><Password>s3cr3t</Password></config>";
        using var ps = ProtectedStringXml.FromXml(xml, "Password");
        Assert.That(Read(ps), Is.EqualTo("s3cr3t"));
    }

    [Test]
    public void FromXml_does_not_find_a_prefixed_element_by_local_name()
    {
        // Documented limitation: ReadToFollowing matches the qualified name,
        // so a prefixed element is not found by its local name. Namespaced
        // documents should drive their own reader.
        const string xml = "<config xmlns:s=\"urn:x\"><s:Password>x</s:Password></config>";
        Assert.Throws<InvalidOperationException>(() => ProtectedStringXml.FromXml(xml, "Password"));
    }

    [Test]
    public void Reads_value_larger_than_the_chunk_buffer()
    {
        // Exceeds the 4 KiB rent so ReadValueChunk loops.
        var big = new string('x', 10_000);
        using var reader = ReaderOn($"<r><P>{big}</P></r>", "P");
        using var ps = ProtectedStringXml.ReadElementContent(reader);
        Assert.That(ps.Length, Is.EqualTo(10_000));
        Assert.That(Read(ps), Is.EqualTo(big));
    }

    [Test]
    public void Reads_large_multibyte_value_spanning_chunk_and_surrogate_boundaries()
    {
        // 3000 emoji = 6000 UTF-16 code units, so the value crosses the 4 KiB
        // ReadValueChunk buffer — and a surrogate pair can land on the seam.
        // Correct output proves chunk concatenation reconstructs split pairs.
        var sb = new StringBuilder();
        for (int i = 0; i < 3000; i++) sb.Append("\U0001F511"); // 🔑
        string big = sb.ToString();

        using var reader = ReaderOn($"<r><P>{big}</P></r>", "P");
        using var ps = ProtectedStringXml.ReadElementContent(reader);
        Assert.That(ps.Length, Is.EqualTo(6000));
        Assert.That(Read(ps), Is.EqualTo(big));
    }

    [Test]
    public void Empty_self_closing_element_yields_empty_instance()
    {
        using var reader = ReaderOn("<r><P/></r>", "P");
        using var ps = ProtectedStringXml.ReadElementContent(reader);
        Assert.That(ps.Length, Is.EqualTo(0));
        Assert.That(ps.IsReadOnly, Is.True);
    }

    [Test]
    public void Empty_open_close_element_yields_empty_instance()
    {
        using var reader = ReaderOn("<r><P></P></r>", "P");
        using var ps = ProtectedStringXml.ReadElementContent(reader);
        Assert.That(ps.Length, Is.EqualTo(0));
    }

    [Test]
    public void Throws_when_not_positioned_on_an_element()
    {
        using var reader = XmlReader.Create(new StringReader("<r>text</r>"));
        reader.ReadToFollowing("r");
        reader.Read(); // move onto the text node
        Assert.That(reader.NodeType, Is.EqualTo(XmlNodeType.Text));
        Assert.Throws<InvalidOperationException>(() => ProtectedStringXml.ReadElementContent(reader));
    }

    // ---- FromXml (hardened) -----------------------------------------------

    [Test]
    public void FromXml_string_reads_the_named_element()
    {
        const string xml = "<config><Db><Password>s3cr3t</Password></Db></config>";
        using var ps = ProtectedStringXml.FromXml(xml, "Password");
        Assert.That(Read(ps), Is.EqualTo("s3cr3t"));
    }

    [Test]
    public void FromXml_stream_reads_the_named_element()
    {
        var bytes = Encoding.UTF8.GetBytes("<config><Token>abc.def.ghi</Token></config>");
        using var stream = new MemoryStream(bytes);
        using var ps = ProtectedStringXml.FromXml(stream, "Token");
        Assert.That(Read(ps), Is.EqualTo("abc.def.ghi"));
    }

    [Test]
    public void FromXml_throws_when_element_absent()
    {
        Assert.Throws<InvalidOperationException>(
            () => ProtectedStringXml.FromXml("<config><User>bob</User></config>", "Password"));
    }

    [Test]
    public void FromXml_rejects_a_dtd_defeating_XXE()
    {
        // A document declaring an external entity: DtdProcessing.Prohibit must
        // reject the DTD outright rather than resolve the entity.
        const string xxe =
            "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>" +
            "<config><Password>&xxe;</Password></config>";
        Assert.Throws<XmlException>(() => ProtectedStringXml.FromXml(xxe, "Password"));
    }

    [Test]
    public void FromXml_stream_leaves_the_stream_open()
    {
        var bytes = Encoding.UTF8.GetBytes("<c><P>x</P></c>");
        using var stream = new MemoryStream(bytes);
        using (var ps = ProtectedStringXml.FromXml(stream, "P")) { }
        // CloseInput = false — the caller still owns the stream.
        Assert.That(stream.CanRead, Is.True);
    }
}
