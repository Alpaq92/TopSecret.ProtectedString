using System.Buffers;
using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedBlobTests;

[TestFixture]
public class AsyncStreamTests
{
    private const int SmallChunk = ProtectedBlob.MinChunkSize;

    private static byte[] RandomBytes(int count) => RandomNumberGenerator.GetBytes(count);

    private sealed class AsyncOnlyStream(byte[] content) : Stream
    {
        private readonly MemoryStream _inner = new(content);
        public MemoryStream Written { get; } = new();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("sync Read must not be used by the async path");
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            return _inner.Read(buffer.Span[..Math.Min(buffer.Length, 7)]);
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new InvalidOperationException("sync Write must not be used by the async path");
        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            Written.Write(buffer, offset, count);
        }
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(SmallChunk - 1)]
    [TestCase(SmallChunk)]
    [TestCase(2 * SmallChunk)]
    [TestCase(2 * SmallChunk + 3)]
    public async Task FromStreamAsync_RoundTrips(int size)
    {
        byte[] original = RandomBytes(size);
        using var blob = await ProtectedBlob.FromStreamAsync(new AsyncOnlyStream(original), SmallChunk);

        Assert.Multiple(() =>
        {
            Assert.That(blob.Length, Is.EqualTo(size));
            Assert.That(blob.ChunkSize, Is.EqualTo(SmallChunk));
            Assert.That(blob.ChunkCount, Is.EqualTo(size == 0 ? 1 : (size + SmallChunk - 1) / SmallChunk));
        });

        var result = new byte[size];
        blob.CopyTo(result);
        Assert.That(result, Is.EqualTo(original));
    }

    [Test]
    public async Task FromStreamAsync_Default_Overload_Uses_The_Process_Default_Chunk_Size()
    {
        using var blob = await ProtectedBlob.FromStreamAsync(new MemoryStream(RandomBytes(10)));
        Assert.That(blob.ChunkSize, Is.EqualTo(ProtectedBlobOptions.DefaultChunkSize));
    }

    [Test]
    public void FromStreamAsync_Validates_Arguments_Synchronously()
    {
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentNullException>(() => ProtectedBlob.FromStreamAsync(null!));
            Assert.Throws<ArgumentNullException>(() => ProtectedBlob.FromStreamAsync(null!, SmallChunk));
            var closed = new MemoryStream();
            closed.Close();
            Assert.Throws<ArgumentException>(() => ProtectedBlob.FromStreamAsync(closed));
            Assert.Throws<ArgumentOutOfRangeException>(() => ProtectedBlob.FromStreamAsync(new MemoryStream(), SmallChunk - 1));
            Assert.Throws<ArgumentOutOfRangeException>(() => ProtectedBlob.FromStreamAsync(new MemoryStream(), ProtectedBlob.MaxChunkSize + 1));
        });
    }

    [Test]
    public async Task FromStreamAsync_Honours_Cancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.CatchAsync<OperationCanceledException>(() =>
            ProtectedBlob.FromStreamAsync(new AsyncOnlyStream(RandomBytes(3 * SmallChunk)), SmallChunk, cts.Token));
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(SmallChunk)]
    [TestCase(2 * SmallChunk + 5)]
    public async Task WriteToAsync_Streams_The_Plaintext(int size)
    {
        byte[] original = RandomBytes(size);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        var sink = new AsyncOnlyStream([]);
        await blob.WriteToAsync(sink);

        Assert.That(sink.Written.ToArray(), Is.EqualTo(original));
    }

    [Test]
    public void WriteToAsync_Validates_Arguments_Synchronously()
    {
        using var blob = new ProtectedBlob(RandomBytes(10).AsSpan(), SmallChunk);
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentNullException>(() => blob.WriteToAsync(null!));
            using var readOnly = new MemoryStream([1, 2, 3], writable: false);
            Assert.Throws<ArgumentException>(() => blob.WriteToAsync(readOnly));
        });
    }

    [Test]
    public async Task WriteToAsync_Throws_When_Disposed()
    {
        var blob = new ProtectedBlob(RandomBytes(10).AsSpan(), SmallChunk);
        blob.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => blob.WriteToAsync(new MemoryStream()));
    }

    [Test]
    public async Task WriteToAsync_Honours_Cancellation_And_Instance_Stays_Usable()
    {
        byte[] original = RandomBytes(3 * SmallChunk);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.CatchAsync<OperationCanceledException>(() => blob.WriteToAsync(new AsyncOnlyStream([]), cts.Token));

        var sink = new AsyncOnlyStream([]);
        await blob.WriteToAsync(sink);
        Assert.That(sink.Written.ToArray(), Is.EqualTo(original));
    }

    [Test]
    public async Task WriteToAsync_Fails_Closed_On_Tampered_Frames()
    {
        using var blob = new ProtectedBlob(RandomBytes(3 * SmallChunk).AsSpan(), SmallChunk);
        blob.FramesForTests[1][0] ^= 0x01;
        await Assert.CatchAsync<CryptographicException>(() => blob.WriteToAsync(Stream.Null));
    }

    [Test]
    public async Task Async_Ingress_And_Egress_Compose()
    {
        byte[] original = RandomBytes(4 * SmallChunk + 99);
        using var blob = await ProtectedBlob.FromStreamAsync(new AsyncOnlyStream(original), SmallChunk);
        var sink = new AsyncOnlyStream([]);
        await blob.WriteToAsync(sink);
        Assert.That(sink.Written.ToArray(), Is.EqualTo(original));
    }

    [Test]
    public async Task Concurrent_WriteToAsync_Passes_Round_Trip()
    {
        byte[] original = RandomBytes(4 * SmallChunk + 1);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        var sinks = Enumerable.Range(0, 8).Select(_ => new AsyncOnlyStream([])).ToArray();
        await Task.WhenAll(sinks.Select(s => blob.WriteToAsync(s)));

        foreach (var sink in sinks)
        {
            Assert.That(sink.Written.ToArray(), Is.EqualTo(original));
        }
    }
}

[TestFixture]
public class ReadOnlySequenceIngressTests
{
    private const int SmallChunk = ProtectedBlob.MinChunkSize;

    private static byte[] RandomBytes(int count) => RandomNumberGenerator.GetBytes(count);

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory, long runningIndex)
        {
            Memory = memory;
            RunningIndex = runningIndex;
        }

        public Segment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new Segment(memory, RunningIndex + Memory.Length);
            Next = next;
            return next;
        }
    }

    private static ReadOnlySequence<byte> Segmented(byte[] content, params int[] segmentLengths)
    {
        int consumed = 0;
        Segment? first = null, last = null;
        foreach (int length in segmentLengths)
        {
            var memory = content.AsMemory(consumed, length);
            consumed += length;
            if (first is null) first = last = new Segment(memory, 0);
            else last = last!.Append(memory);
        }
        var tail = content.AsMemory(consumed);
        if (first is null) first = last = new Segment(tail, 0);
        else last = last!.Append(tail);
        return new ReadOnlySequence<byte>(first, 0, last!, last!.Memory.Length);
    }

    private static byte[] ReadBack(ProtectedBlob blob)
    {
        var result = new byte[blob.Length];
        blob.CopyTo(result);
        return result;
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(SmallChunk)]
    [TestCase(3 * SmallChunk + 17)]
    public void Single_Segment_Sequence_Matches_The_Span_Constructor(int size)
    {
        byte[] original = RandomBytes(size);
        using var blob = new ProtectedBlob(new ReadOnlySequence<byte>(original), SmallChunk);

        Assert.Multiple(() =>
        {
            Assert.That(blob.Length, Is.EqualTo(size));
            Assert.That(blob.ChunkCount, Is.EqualTo(size == 0 ? 1 : (size + SmallChunk - 1) / SmallChunk));
            Assert.That(ReadBack(blob), Is.EqualTo(original));
        });
    }

    [Test]
    public void Segments_Aligned_To_Chunks_Encrypt_Straight_From_Each_Segment()
    {
        byte[] original = RandomBytes(3 * SmallChunk);
        using var blob = new ProtectedBlob(Segmented(original, SmallChunk, SmallChunk), SmallChunk);

        Assert.That(blob.ChunkCount, Is.EqualTo(3));
        Assert.That(ReadBack(blob), Is.EqualTo(original));
    }

    [Test]
    public void Chunks_Straddling_Segment_Boundaries_Are_Gathered_Correctly()
    {
        byte[] original = RandomBytes(3 * SmallChunk + 100);
        // Tiny, odd-sized segments: every chunk spans several segments.
        using var blob = new ProtectedBlob(Segmented(original, 1, 700, 3, 5000, 2, 1500), SmallChunk);

        Assert.That(blob.ChunkCount, Is.EqualTo(4));
        Assert.That(ReadBack(blob), Is.EqualTo(original));
        for (int i = 0; i < blob.ChunkCount; i++)
        {
            int offset = i * SmallChunk;
            byte[] expected = original.AsSpan(offset, Math.Min(SmallChunk, original.Length - offset)).ToArray();
            Assert.That(blob.AccessChunk(i, c => c.ToArray()), Is.EqualTo(expected), $"chunk {i}");
        }
    }

    [Test]
    public void Mixed_Layout_Some_Chunks_Direct_Some_Gathered()
    {
        byte[] original = RandomBytes(4 * SmallChunk);
        // Segment 0 holds chunks 0 and 1 exactly (direct); chunks 2 and 3 straddle.
        using var blob = new ProtectedBlob(Segmented(original, 2 * SmallChunk, SmallChunk / 2, SmallChunk), SmallChunk);

        Assert.That(ReadBack(blob), Is.EqualTo(original));
    }

    [Test]
    public void Multi_Segment_Empty_Sequence_Is_An_Empty_Blob()
    {
        using var blob = new ProtectedBlob(Segmented([], 0), SmallChunk);
        Assert.Multiple(() =>
        {
            Assert.That(blob.Length, Is.Zero);
            Assert.That(blob.ChunkCount, Is.EqualTo(1));
        });
    }

    [Test]
    public void Sequence_Constructor_Never_Mutates_The_Source()
    {
        byte[] original = RandomBytes(2 * SmallChunk + 9);
        byte[] copy = (byte[])original.Clone();
        using var blob = new ProtectedBlob(Segmented(original, 100, SmallChunk), SmallChunk);
        Assert.That(original, Is.EqualTo(copy));
    }

    [Test]
    public void Sequence_Constructor_Default_Overload_Uses_The_Process_Default_Chunk_Size()
    {
        using var blob = new ProtectedBlob(new ReadOnlySequence<byte>(RandomBytes(10)));
        Assert.That(blob.ChunkSize, Is.EqualTo(ProtectedBlobOptions.DefaultChunkSize));
    }

    [TestCase(ProtectedBlob.MinChunkSize - 1)]
    [TestCase(ProtectedBlob.MaxChunkSize + 1)]
    public void Sequence_Constructor_Validates_Chunk_Size(int chunkSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProtectedBlob(new ReadOnlySequence<byte>(new byte[10]), chunkSize));
    }

    [Test]
    public void Sequence_Blob_Is_Tamper_Evident_Like_Any_Other()
    {
        using var blob = new ProtectedBlob(Segmented(RandomBytes(2 * SmallChunk + 1), 300, 3000), SmallChunk);
        blob.FramesForTests[1][5] ^= 0x01;
        Assert.Catch<CryptographicException>(() => blob.CopyTo(new byte[blob.Length]));
    }
}
