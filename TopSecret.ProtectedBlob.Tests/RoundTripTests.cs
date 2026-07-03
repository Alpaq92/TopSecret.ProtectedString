using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedBlobTests;

[TestFixture]
public class RoundTripTests
{
    // Small chunk size keeps multi-chunk scenarios cheap.
    private const int SmallChunk = ProtectedBlob.MinChunkSize; // 4 KiB

    private static byte[] RandomBytes(int count) => RandomNumberGenerator.GetBytes(count);

    private static byte[] ReadBack(ProtectedBlob blob)
    {
        var result = new byte[blob.Length];
        blob.CopyTo(result);
        return result;
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(SmallChunk - 1)]
    [TestCase(SmallChunk)]
    [TestCase(SmallChunk + 1)]
    [TestCase(3 * SmallChunk + SmallChunk / 2)]
    public void Span_Constructor_RoundTrips_At_Boundary_Sizes(int size)
    {
        byte[] original = RandomBytes(size);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        Assert.Multiple(() =>
        {
            Assert.That(blob.Length, Is.EqualTo(size));
            Assert.That(blob.ChunkSize, Is.EqualTo(SmallChunk));
            Assert.That(blob.ChunkCount, Is.EqualTo(size == 0 ? 1 : (size + SmallChunk - 1) / SmallChunk));
            Assert.That(ReadBack(blob), Is.EqualTo(original));
        });
    }

    [Test]
    public void Empty_Blob_Holds_One_Empty_Final_Chunk()
    {
        using var blob = new ProtectedBlob(ReadOnlySpan<byte>.Empty);

        Assert.Multiple(() =>
        {
            Assert.That(blob.Length, Is.Zero);
            Assert.That(blob.ChunkCount, Is.EqualTo(1));
        });

        int calls = 0, lastLength = -1;
        blob.AccessChunks(chunk => { calls++; lastLength = chunk.Length; });
        Assert.Multiple(() =>
        {
            Assert.That(calls, Is.EqualTo(1), "An empty blob invokes the handler once with its single empty final chunk.");
            Assert.That(lastLength, Is.Zero);
        });
    }

    [Test]
    public void Default_ChunkSize_Is_64KiB()
    {
        using var blob = new ProtectedBlob([1, 2, 3]);
        Assert.That(blob.ChunkSize, Is.EqualTo(64 * 1024));
        Assert.That(ProtectedBlob.DefaultChunkSize, Is.EqualTo(64 * 1024));
    }

    [TestCase(ProtectedBlob.MinChunkSize)]
    [TestCase(ProtectedBlob.MaxChunkSize)]
    public void ChunkSize_Bounds_Are_Accepted(int chunkSize)
    {
        byte[] original = RandomBytes(100);
        using var blob = new ProtectedBlob(original.AsSpan(), chunkSize);
        Assert.That(ReadBack(blob), Is.EqualTo(original));
    }

    [TestCase(ProtectedBlob.MinChunkSize - 1)]
    [TestCase(ProtectedBlob.MaxChunkSize + 1)]
    [TestCase(0)]
    [TestCase(-1)]
    public void ChunkSize_Out_Of_Bounds_Throws(int chunkSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProtectedBlob(new byte[10].AsSpan(), chunkSize));
    }

    [Test]
    public void ByteArray_Constructor_With_ClearSource_Zeroes_The_Input()
    {
        byte[] original = RandomBytes(1000);
        byte[] copy = (byte[])original.Clone();

        using var blob = new ProtectedBlob(original, clearSource: true);

        Assert.Multiple(() =>
        {
            Assert.That(original, Is.All.Zero, "clearSource must wipe the caller's array.");
            Assert.That(ReadBack(blob), Is.EqualTo(copy));
        });
    }

    [Test]
    public void ByteArray_Constructor_Without_ClearSource_Leaves_Input_Intact()
    {
        byte[] original = RandomBytes(100);
        byte[] copy = (byte[])original.Clone();
        using var blob = new ProtectedBlob(original);
        Assert.That(original, Is.EqualTo(copy));
    }

    [Test]
    public void ByteArray_Constructor_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new ProtectedBlob(null!));
    }

    [Test]
    public void AccessChunk_Exposes_Chunk_Slices_In_Order()
    {
        byte[] original = RandomBytes(2 * SmallChunk + 100);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        Assert.That(blob.ChunkCount, Is.EqualTo(3));
        for (int i = 0; i < blob.ChunkCount; i++)
        {
            int offset = i * SmallChunk;
            byte[] expected = original.AsSpan(offset, Math.Min(SmallChunk, original.Length - offset)).ToArray();
            byte[] actual = blob.AccessChunk(i, chunk => chunk.ToArray());
            Assert.That(actual, Is.EqualTo(expected), $"chunk {i}");
        }
    }

    [Test]
    public void AccessChunk_Index_Out_Of_Range_Throws()
    {
        using var blob = new ProtectedBlob(RandomBytes(10).AsSpan(), SmallChunk);
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => blob.AccessChunk(-1, _ => { }));
            Assert.Throws<ArgumentOutOfRangeException>(() => blob.AccessChunk(1, _ => { }));
        });
    }

    [Test]
    public void AccessChunks_Concatenation_Equals_Original()
    {
        byte[] original = RandomBytes(3 * SmallChunk + 17);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        using var collected = new MemoryStream();
        blob.AccessChunks(chunk => collected.Write(chunk));

        Assert.That(collected.ToArray(), Is.EqualTo(original));
    }

    [Test]
    public void WriteTo_Streams_The_Plaintext()
    {
        byte[] original = RandomBytes(2 * SmallChunk + 5);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        using var sink = new MemoryStream();
        blob.WriteTo(sink);

        Assert.That(sink.ToArray(), Is.EqualTo(original));
    }

    [Test]
    public void WriteTo_Rejects_Null_And_Unwritable_Streams()
    {
        using var blob = new ProtectedBlob(RandomBytes(10).AsSpan(), SmallChunk);
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentNullException>(() => blob.WriteTo(null!));
            using var readOnly = new MemoryStream([1, 2, 3], writable: false);
            Assert.Throws<ArgumentException>(() => blob.WriteTo(readOnly));
        });
    }

    [Test]
    public void CopyTo_Too_Small_Destination_Throws()
    {
        using var blob = new ProtectedBlob(RandomBytes(100).AsSpan(), SmallChunk);
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> tooSmall = stackalloc byte[99];
            blob.CopyTo(tooSmall);
        });
    }

    [Test]
    public void ToString_Never_Contains_Content()
    {
        using var blob = new ProtectedBlob(RandomBytes(1234).AsSpan(), SmallChunk);
        Assert.That(blob.ToString(), Is.EqualTo("ProtectedBlob[length=1234]"));
    }
}

[TestFixture]
public class FromStreamTests
{
    private const int SmallChunk = ProtectedBlob.MinChunkSize;

    /// <summary>Non-seekable, unknown-length wrapper — the hostile end of the Stream contract, plus single-byte reads to exercise the fill loop.</summary>
    private sealed class NonSeekableStream(byte[] content) : Stream
    {
        private readonly MemoryStream _inner = new(content);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) =>
            _inner.Read(buffer, offset, Math.Min(count, 7)); // ragged reads on purpose
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(SmallChunk - 1)]
    [TestCase(SmallChunk)]        // exact multiple: full-size final chunk
    [TestCase(2 * SmallChunk)]    // exact multiple, several chunks
    [TestCase(2 * SmallChunk + 3)]
    public void FromStream_RoundTrips(int size)
    {
        byte[] original = System.Security.Cryptography.RandomNumberGenerator.GetBytes(size);
        using var blob = ProtectedBlob.FromStream(new NonSeekableStream(original), SmallChunk);

        Assert.Multiple(() =>
        {
            Assert.That(blob.Length, Is.EqualTo(size));
            Assert.That(blob.ChunkCount, Is.EqualTo(size == 0 ? 1 : (size + SmallChunk - 1) / SmallChunk));
        });

        var result = new byte[size];
        blob.CopyTo(result);
        Assert.That(result, Is.EqualTo(original));
    }

    [Test]
    public void FromStream_Exact_Multiple_Marks_FullSize_Final_Chunk()
    {
        byte[] original = System.Security.Cryptography.RandomNumberGenerator.GetBytes(2 * SmallChunk);
        using var blob = ProtectedBlob.FromStream(new NonSeekableStream(original), SmallChunk);

        // Exactly 2 chunks — no trailing empty chunk is emitted for exact multiples.
        Assert.That(blob.ChunkCount, Is.EqualTo(2));
        Assert.That(blob.AccessChunk(1, c => c.Length), Is.EqualTo(SmallChunk));
    }

    [Test]
    public void FromStream_Rejects_Null_And_Unreadable_Sources()
    {
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentNullException>(() => ProtectedBlob.FromStream(null!));
            var write0nly = new MemoryStream();
            write0nly.Close(); // CanRead false once closed
            Assert.Throws<ArgumentException>(() => ProtectedBlob.FromStream(write0nly));
        });
    }

    [Test]
    [Explicit("64 MiB smoke test — run on demand; excluded from the per-PR suite.")]
    [Category("Slow")]
    public void FromStream_64MiB_Smoke()
    {
        const int size = 64 * 1024 * 1024;
        byte[] original = new byte[size];
        System.Security.Cryptography.RandomNumberGenerator.Fill(original);
        byte[] originalHash = System.Security.Cryptography.SHA256.HashData(original);

        using var blob = ProtectedBlob.FromStream(new MemoryStream(original));

        using var sink = new MemoryStream(size);
        blob.WriteTo(sink);
        Assert.Multiple(() =>
        {
            Assert.That(blob.Length, Is.EqualTo(size));
            Assert.That(System.Security.Cryptography.SHA256.HashData(sink.ToArray()), Is.EqualTo(originalHash));
        });
    }
}
