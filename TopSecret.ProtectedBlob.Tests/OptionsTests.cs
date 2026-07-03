using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedBlobTests;

[TestFixture]
[NonParallelizable] // mutates the process-wide ProtectedBlobOptions
public class OptionsTests
{
    [TearDown]
    public void ResetOptions() => ProtectedBlobOptions.DefaultChunkSize = ProtectedBlob.DefaultChunkSize;

    [Test]
    public void DefaultChunkSize_Defaults_To_The_Const()
    {
        Assert.That(ProtectedBlobOptions.DefaultChunkSize, Is.EqualTo(ProtectedBlob.DefaultChunkSize));
    }

    [Test]
    public void DefaultChunkSize_Is_Read_At_Each_Construction()
    {
        ProtectedBlobOptions.DefaultChunkSize = ProtectedBlob.MinChunkSize;
        byte[] payload = RandomNumberGenerator.GetBytes(2 * ProtectedBlob.MinChunkSize);

        using var viaSpanCtor = new ProtectedBlob(payload.AsSpan());
        using var viaArrayCtor = new ProtectedBlob(payload);
        using var viaFromStream = ProtectedBlob.FromStream(new MemoryStream(payload));

        Assert.Multiple(() =>
        {
            Assert.That(viaSpanCtor.ChunkSize, Is.EqualTo(ProtectedBlob.MinChunkSize));
            Assert.That(viaArrayCtor.ChunkSize, Is.EqualTo(ProtectedBlob.MinChunkSize));
            Assert.That(viaFromStream.ChunkSize, Is.EqualTo(ProtectedBlob.MinChunkSize));
            Assert.That(viaSpanCtor.ChunkCount, Is.EqualTo(2));
        });

        // Blobs constructed before a change keep their captured chunk size.
        ProtectedBlobOptions.DefaultChunkSize = 2 * ProtectedBlob.MinChunkSize;
        Assert.That(viaSpanCtor.ChunkSize, Is.EqualTo(ProtectedBlob.MinChunkSize));
    }

    [Test]
    public void Explicit_ChunkSize_Wins_Over_The_Option()
    {
        ProtectedBlobOptions.DefaultChunkSize = ProtectedBlob.MinChunkSize;
        using var blob = new ProtectedBlob(RandomNumberGenerator.GetBytes(100).AsSpan(), 2 * ProtectedBlob.MinChunkSize);
        Assert.That(blob.ChunkSize, Is.EqualTo(2 * ProtectedBlob.MinChunkSize));
    }

    [TestCase(ProtectedBlob.MinChunkSize - 1)]
    [TestCase(ProtectedBlob.MaxChunkSize + 1)]
    [TestCase(0)]
    public void DefaultChunkSize_Setter_Validates_Bounds(int value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ProtectedBlobOptions.DefaultChunkSize = value);
        Assert.That(ProtectedBlobOptions.DefaultChunkSize, Is.EqualTo(ProtectedBlob.DefaultChunkSize),
            "A rejected value must leave the option unchanged.");
    }
}
