using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedBlobTests;

/// <summary>
/// <c>CopyTo(long offset, Span&lt;byte&gt;)</c>: windowed reads that let a
/// blob larger than a single <see cref="Span{T}"/> can address be consumed
/// piecewise, with the same fail-closed and zero-on-failure contract as the
/// whole-blob overload.
/// </summary>
[TestFixture]
public class RangedCopyToTests
{
    private const int SmallChunk = ProtectedBlob.MinChunkSize;

    private static byte[] RandomBytes(int count) => RandomNumberGenerator.GetBytes(count);

    private static byte[] CopyRange(ProtectedBlob blob, long offset, int length)
    {
        var result = new byte[length];
        blob.CopyTo(offset, result);
        return result;
    }

    [TestCase(0, 0)]
    [TestCase(0, 1)]
    [TestCase(0, SmallChunk)]                       // exactly chunk 0
    [TestCase(0, SmallChunk + 1)]                   // chunk 0 + 1 byte of chunk 1
    [TestCase(1, SmallChunk - 1)]                   // interior of chunk 0
    [TestCase(1, SmallChunk)]                       // straddles chunks 0/1, both partial
    [TestCase(SmallChunk, SmallChunk)]              // exactly chunk 1
    [TestCase(SmallChunk - 1, 2)]                   // one byte either side of a boundary
    [TestCase(SmallChunk / 2, 2 * SmallChunk)]      // partial, full, partial
    [TestCase(3 * SmallChunk, 17)]                  // the short final chunk, whole
    [TestCase(3 * SmallChunk + 5, 12)]              // tail of the short final chunk
    [TestCase(3 * SmallChunk + 17, 0)]              // empty window at the very end
    [TestCase(0, 3 * SmallChunk + 17)]              // whole blob through the ranged overload
    public void Ranged_CopyTo_Returns_The_Requested_Window(int offset, int length)
    {
        byte[] original = RandomBytes(3 * SmallChunk + 17);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        Assert.That(CopyRange(blob, offset, length), Is.EqualTo(original.AsSpan(offset, length).ToArray()));
    }

    [Test]
    public void Ranged_CopyTo_Covers_The_Whole_Blob_When_Walked_In_Odd_Windows()
    {
        byte[] original = RandomBytes(5 * SmallChunk + 123);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        const int window = 1000; // deliberately not a divisor of the chunk size
        var reassembled = new byte[original.Length];
        for (long offset = 0; offset < blob.Length; offset += window)
        {
            int take = (int)Math.Min(window, blob.Length - offset);
            blob.CopyTo(offset, reassembled.AsSpan((int)offset, take));
        }

        Assert.That(reassembled, Is.EqualTo(original));
    }

    [Test]
    public void Ranged_CopyTo_On_An_Empty_Blob_Accepts_Only_The_Empty_Window()
    {
        using var blob = new ProtectedBlob(ReadOnlySpan<byte>.Empty, SmallChunk);

        Assert.Multiple(() =>
        {
            Assert.DoesNotThrow(() => blob.CopyTo(0, Span<byte>.Empty));
            Assert.Throws<ArgumentException>(() =>
            {
                Span<byte> one = stackalloc byte[1];
                blob.CopyTo(0, one);
            });
            Assert.Throws<ArgumentOutOfRangeException>(() => blob.CopyTo(1, Span<byte>.Empty));
        });
    }

    [Test]
    public void Ranged_CopyTo_On_A_Tampered_Empty_Blob_Still_Fails_Closed()
    {
        using var blob = new ProtectedBlob(ReadOnlySpan<byte>.Empty, SmallChunk);
        blob.FramesForTests[0][0] ^= 0x01;
        Assert.Catch<CryptographicException>(() => blob.CopyTo(0, Span<byte>.Empty));
    }

    [Test]
    public void Ranged_CopyTo_Validates_The_Window()
    {
        using var blob = new ProtectedBlob(RandomBytes(100).AsSpan(), SmallChunk);

        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => blob.CopyTo(-1, new byte[1]));
            Assert.Throws<ArgumentOutOfRangeException>(() => blob.CopyTo(101, Span<byte>.Empty));
            Assert.Throws<ArgumentOutOfRangeException>(() => blob.CopyTo(long.MaxValue, Span<byte>.Empty));
            Assert.Throws<ArgumentException>(() => blob.CopyTo(0, new byte[101]));
            Assert.Throws<ArgumentException>(() => blob.CopyTo(50, new byte[51]));
            Assert.Throws<ArgumentException>(() => blob.CopyTo(100, new byte[1]));
            Assert.DoesNotThrow(() => blob.CopyTo(50, new byte[50]));
            Assert.DoesNotThrow(() => blob.CopyTo(100, Span<byte>.Empty));
        });
    }

    [Test]
    public void Ranged_CopyTo_Empty_Window_On_A_Non_Empty_Blob_Touches_No_Chunk()
    {
        using var blob = new ProtectedBlob(RandomBytes(2 * SmallChunk).AsSpan(), SmallChunk);
        blob.FramesForTests[0][0] ^= 0x01;
        blob.FramesForTests[1][0] ^= 0x01;

        // Nothing overlaps an empty window, so nothing is authenticated and
        // nothing can fail — the whole-blob overload (which must read every
        // chunk) is the one that detects this tampering.
        Assert.DoesNotThrow(() => blob.CopyTo(SmallChunk, Span<byte>.Empty));
        Assert.Catch<CryptographicException>(() => blob.CopyTo(new byte[blob.Length]));
    }

    [Test]
    public void Ranged_CopyTo_Fails_Closed_And_Zeroes_What_It_Wrote()
    {
        using var blob = new ProtectedBlob(RandomBytes(3 * SmallChunk).AsSpan(), SmallChunk);
        blob.FramesForTests[2][0] ^= 0x01; // corrupt the last chunk only

        // Window: tail of chunk 0, all of chunk 1, head of chunk 2 — the
        // first two decrypt fine, the third fails.
        var destination = new byte[2 * SmallChunk];
        Assert.Catch<CryptographicException>(() => blob.CopyTo(SmallChunk / 2, destination));
        Assert.That(destination, Is.All.Zero, "The authenticated prefix must not be left in the caller's buffer.");

        // A window that avoids the corrupt chunk still works.
        Assert.DoesNotThrow(() => blob.CopyTo(0, new byte[2 * SmallChunk]));
    }

    [Test]
    public void Ranged_CopyTo_Partial_Chunk_Only_Writes_The_Requested_Bytes()
    {
        byte[] original = RandomBytes(2 * SmallChunk);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        // Sentinel-filled oversized buffer; the ranged copy must touch
        // exactly the slice it was given.
        var buffer = new byte[SmallChunk];
        buffer.AsSpan().Fill(0xAA);
        blob.CopyTo(SmallChunk - 8, buffer.AsSpan(4, 16));

        Assert.Multiple(() =>
        {
            Assert.That(buffer.AsSpan(0, 4).ToArray(), Is.All.EqualTo(0xAA));
            Assert.That(buffer.AsSpan(4, 16).ToArray(), Is.EqualTo(original.AsSpan(SmallChunk - 8, 16).ToArray()));
            Assert.That(buffer.AsSpan(20).ToArray(), Is.All.EqualTo(0xAA));
        });
    }

    [Test]
    public void Ranged_CopyTo_Throws_When_Disposed()
    {
        var blob = new ProtectedBlob(RandomBytes(10).AsSpan(), SmallChunk);
        blob.Dispose();
        Assert.Throws<ObjectDisposedException>(() => blob.CopyTo(0, Span<byte>.Empty));
    }

    [Test]
    public void Ranged_CopyTo_Works_With_FromStream_Blobs()
    {
        byte[] original = RandomBytes(4 * SmallChunk);
        using var blob = ProtectedBlob.FromStream(new MemoryStream(original), SmallChunk);

        Assert.That(CopyRange(blob, SmallChunk + 100, 2 * SmallChunk),
            Is.EqualTo(original.AsSpan(SmallChunk + 100, 2 * SmallChunk).ToArray()));
    }
}
