using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedBlobTests;

[TestFixture]
[NonParallelizable] // observes the process-wide scratch pool and protector holder count
public class ReadDisciplineTests
{
    private const int SmallChunk = ProtectedBlob.MinChunkSize;

    private static byte[] RandomBytes(int count) => RandomNumberGenerator.GetBytes(count);

    private sealed class FaultingReadStream(int goodBytes) : Stream
    {
        private int _served;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_served >= goodBytes) throw new IOException("simulated mid-read failure");
            int n = Math.Min(count, goodBytes - _served);
            RandomNumberGenerator.Fill(buffer.AsSpan(offset, n));
            _served += n;
            return n;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class FaultingWriteStream(int goodBytes) : Stream
    {
        private int _accepted;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_accepted + count > goodBytes) throw new IOException("simulated mid-write failure");
            _accepted += count;
        }
    }

    internal static int ProtectorHolderCount()
    {
        var protector = ProtectedString.GetOrInitProcessProtector();
        try
        {
            return protector.LifetimeHolderCount;
        }
        finally
        {
            ProtectorLifetime.Release(protector);
        }
    }

    internal static int SettledProtectorHolderCount()
    {
        // Finalizers of blobs/strings leaked by other fixtures could
        // otherwise decrement the count between two measurements.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        return ProtectorHolderCount();
    }

    // ---- item 1: DEK lease returned before the handler runs --------------

    [Test]
    public void AccessChunk_Returns_The_Dek_Lease_Before_Invoking_The_Handler()
    {
        using var blob = new ProtectedBlob(RandomBytes(100).AsSpan(), SmallChunk);

        // Prime the 64-byte free list (LIFO) with two known chunks: top = a, then b.
        var a = LockedScratchPool.Rent(ChunkFormat.KeySize);
        var b = LockedScratchPool.Rent(ChunkFormat.KeySize);
        Assume.That(a.IsPooled && b.IsPooled, "32-byte rents must come from the pool for this probe to mean anything.");
        Assume.That(a.Offset, Is.Not.EqualTo(b.Offset));
        b.Return();
        a.Return();

        int probeOffset = -1;
        blob.AccessChunk(0, _ =>
        {
            var probe = LockedScratchPool.Rent(ChunkFormat.KeySize);
            probeOffset = probe.Offset;
            probe.Return();
        });

        Assert.That(probeOffset, Is.EqualTo(a.Offset),
            "The unwrapped DEK must be back in the pool (wiped) before user code runs.");
    }

    [Test]
    public void AccessChunk_Generic_Returns_The_Dek_Lease_Before_Invoking_The_Handler()
    {
        using var blob = new ProtectedBlob(RandomBytes(100).AsSpan(), SmallChunk);

        var a = LockedScratchPool.Rent(ChunkFormat.KeySize);
        var b = LockedScratchPool.Rent(ChunkFormat.KeySize);
        Assume.That(a.IsPooled && b.IsPooled);
        Assume.That(a.Offset, Is.Not.EqualTo(b.Offset));
        b.Return();
        a.Return();

        int probeOffset = blob.AccessChunk(0, _ =>
        {
            var probe = LockedScratchPool.Rent(ChunkFormat.KeySize);
            try { return probe.Offset; }
            finally { probe.Return(); }
        });

        Assert.That(probeOffset, Is.EqualTo(a.Offset));
    }

    [Test]
    public void AccessChunk_Plaintext_Is_Still_Valid_Inside_The_Handler_After_Dek_Return()
    {
        byte[] original = RandomBytes(SmallChunk + 100);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        // Rent and return pool chunks from inside the handler: the returned
        // DEK chunk gets recycled, the plaintext scratch must not be.
        bool matches = blob.AccessChunk(1, plain =>
        {
            var churn = LockedScratchPool.Rent(ChunkFormat.KeySize);
            churn.Bytes(ChunkFormat.KeySize).Fill(0xFF);
            churn.Return();
            return plain.SequenceEqual(original.AsSpan(SmallChunk));
        });

        Assert.That(matches, Is.True);
    }

    // ---- item 3: construction failure releases the protector ref ---------

    [Test]
    public void FromStream_Failure_Mid_Read_Leaks_No_Protector_Reference()
    {
        int before = SettledProtectorHolderCount();

        Assert.Throws<IOException>(() => ProtectedBlob.FromStream(new FaultingReadStream(SmallChunk + 10), SmallChunk));

        Assert.That(ProtectorHolderCount(), Is.EqualTo(before),
            "A constructor that fails after the protector snapshot must release its holder reference immediately.");

        // The process protector is untouched: a subsequent blob still works.
        byte[] payload = RandomBytes(SmallChunk + 1);
        using var ok = ProtectedBlob.FromStream(new MemoryStream(payload), SmallChunk);
        var result = new byte[ok.Length];
        ok.CopyTo(result);
        Assert.That(result, Is.EqualTo(payload));
    }

    [Test]
    public async Task FromStreamAsync_Failure_Mid_Read_Leaks_No_Protector_Reference()
    {
        int before = SettledProtectorHolderCount();

        await Assert.ThrowsAsync<IOException>(() => ProtectedBlob.FromStreamAsync(new FaultingReadStream(SmallChunk + 10), SmallChunk));

        Assert.That(ProtectorHolderCount(), Is.EqualTo(before));

        byte[] payload = RandomBytes(SmallChunk + 1);
        using var ok = await ProtectedBlob.FromStreamAsync(new MemoryStream(payload), SmallChunk);
        Assert.That(ok.Length, Is.EqualTo(payload.Length));
    }

    [Test]
    public async Task FromStreamAsync_Cancellation_Leaks_No_Protector_Reference()
    {
        int before = SettledProtectorHolderCount();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.CatchAsync<OperationCanceledException>(() =>
            ProtectedBlob.FromStreamAsync(new MemoryStream(RandomBytes(3 * SmallChunk)), SmallChunk, cts.Token));

        Assert.That(ProtectorHolderCount(), Is.EqualTo(before));
    }

    [Test]
    public void Successful_Construction_And_Dispose_Are_Net_Zero_On_The_Holder_Count()
    {
        int before = SettledProtectorHolderCount();
        var blob = new ProtectedBlob(RandomBytes(10).AsSpan(), SmallChunk);
        Assert.That(ProtectorHolderCount(), Is.EqualTo(before + 1));
        blob.Dispose();
        Assert.That(ProtectorHolderCount(), Is.EqualTo(before));
    }

    // ---- item 8: callbacks that misbehave --------------------------------

    [Test]
    public void Dispose_From_Inside_AccessChunks_Fails_Closed_On_The_Next_Chunk()
    {
        var blob = new ProtectedBlob(RandomBytes(3 * SmallChunk).AsSpan(), SmallChunk);
        int chunksSeen = 0;

        Assert.Catch<CryptographicException>(() => blob.AccessChunks(_ =>
        {
            chunksSeen++;
            if (chunksSeen == 1) blob.Dispose(); // reentrant: Monitor lets the callback in
        }), "The pass must fail closed on the zeroed frames, never hand out wrong plaintext.");

        Assert.Multiple(() =>
        {
            Assert.That(chunksSeen, Is.EqualTo(1), "No chunk after the dispose may reach the handler.");
            Assert.That(blob.IsDisposed, Is.True);
            Assert.Throws<ObjectDisposedException>(() => blob.AccessChunks(_ => { }));
        });
    }

    [Test]
    public void Dispose_From_Inside_AccessChunk_Handler_Completes_And_Leaves_Instance_Disposed()
    {
        var blob = new ProtectedBlob(RandomBytes(2 * SmallChunk).AsSpan(), SmallChunk);

        int seen = blob.AccessChunk(0, plain =>
        {
            blob.Dispose();
            return plain.Length; // plaintext scratch is still ours until we return
        });

        Assert.Multiple(() =>
        {
            Assert.That(seen, Is.EqualTo(SmallChunk));
            Assert.That(blob.IsDisposed, Is.True);
        });
    }

    [Test]
    public void Throwing_Handler_Inside_AccessChunks_Propagates_And_Instance_Stays_Usable()
    {
        byte[] original = RandomBytes(3 * SmallChunk);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        var thrown = Assert.Throws<InvalidOperationException>(() => blob.AccessChunks(_ => throw new InvalidOperationException("handler boom")));
        Assert.That(thrown!.Message, Is.EqualTo("handler boom"));

        // Leases were returned: every read path still works, repeatedly.
        for (int i = 0; i < 3; i++)
        {
            var result = new byte[blob.Length];
            blob.CopyTo(result);
            Assert.That(result, Is.EqualTo(original));
            Assert.That(blob.AccessChunk(2, c => c.Length), Is.EqualTo(SmallChunk));
            using var sink = new MemoryStream();
            blob.WriteTo(sink);
            Assert.That(sink.ToArray(), Is.EqualTo(original));
        }
    }

    [Test]
    public void Throwing_Handler_Inside_AccessChunk_Propagates_And_Instance_Stays_Usable()
    {
        byte[] original = RandomBytes(SmallChunk + 5);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        Assert.Throws<InvalidOperationException>(() => blob.AccessChunk(1, _ => throw new InvalidOperationException()));
        Assert.Throws<InvalidOperationException>(() => blob.AccessChunk<int>(1, _ => throw new InvalidOperationException()));
        Assert.Throws<InvalidOperationException>(() => blob.AccessChunk(1, 0, (_, _) => throw new InvalidOperationException()));

        Assert.That(blob.AccessChunk(1, c => c.ToArray()), Is.EqualTo(original.AsSpan(SmallChunk).ToArray()));
    }

    [Test]
    public void Failing_Destination_Inside_WriteTo_Propagates_And_Instance_Stays_Usable()
    {
        byte[] original = RandomBytes(3 * SmallChunk);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        Assert.Throws<IOException>(() => blob.WriteTo(new FaultingWriteStream(SmallChunk)));

        using var sink = new MemoryStream();
        blob.WriteTo(sink);
        Assert.That(sink.ToArray(), Is.EqualTo(original));
    }

    [Test]
    public async Task Failing_Destination_Inside_WriteToAsync_Propagates_And_Instance_Stays_Usable()
    {
        byte[] original = RandomBytes(3 * SmallChunk);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        await Assert.ThrowsAsync<IOException>(() => blob.WriteToAsync(new FaultingWriteStream(SmallChunk)));

        using var sink = new MemoryStream();
        await blob.WriteToAsync(sink);
        Assert.That(sink.ToArray(), Is.EqualTo(original));
    }

    [Test]
    public void FromStream_With_MaxChunkSize_RoundTrips()
    {
        byte[] original = RandomBytes(ProtectedBlob.MaxChunkSize + 1);
        using var blob = ProtectedBlob.FromStream(new MemoryStream(original), ProtectedBlob.MaxChunkSize);

        Assert.Multiple(() =>
        {
            Assert.That(blob.ChunkSize, Is.EqualTo(ProtectedBlob.MaxChunkSize));
            Assert.That(blob.ChunkCount, Is.EqualTo(2));
            Assert.That(blob.AccessChunk(0, c => c.Length), Is.EqualTo(ProtectedBlob.MaxChunkSize));
            Assert.That(blob.AccessChunk(1, c => c.Length), Is.EqualTo(1));
        });

        var result = new byte[blob.Length];
        blob.CopyTo(result);
        Assert.That(result, Is.EqualTo(original));
    }

    [Test]
    public void Live_Blob_Reports_ChunkSize_And_Not_Disposed()
    {
        using var blob = new ProtectedBlob(RandomBytes(10).AsSpan(), 2 * SmallChunk);

        Assert.Multiple(() =>
        {
            Assert.That(blob.IsDisposed, Is.False);
            Assert.That(blob.ChunkSize, Is.EqualTo(2 * SmallChunk));
            Assert.That(blob.ChunkCount, Is.EqualTo(1));
            Assert.That(blob.Length, Is.EqualTo(10));
        });
    }

    // ---- item 5: AccessChunk<T> and AccessChunk<TState> directly ---------

    [Test]
    public void AccessChunk_Generic_Propagates_Value_And_Reference_Results()
    {
        byte[] original = RandomBytes(SmallChunk + 7);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        (int Length, byte First) summary = blob.AccessChunk(1, c => (c.Length, c[0]));
        string hex = blob.AccessChunk(1, c => Convert.ToHexString(c));

        Assert.Multiple(() =>
        {
            Assert.That(summary.Length, Is.EqualTo(7));
            Assert.That(summary.First, Is.EqualTo(original[SmallChunk]));
            Assert.That(hex, Is.EqualTo(Convert.ToHexString(original.AsSpan(SmallChunk))));
        });
    }

    [Test]
    public void AccessChunk_With_State_Threads_State_Through_A_Static_Lambda()
    {
        byte[] original = RandomBytes(2 * SmallChunk + 3);
        using var blob = new ProtectedBlob(original.AsSpan(), SmallChunk);

        var collected = new MemoryStream();
        for (int index = 0; index < blob.ChunkCount; index++)
        {
            blob.AccessChunk(index, collected, static (plain, sink) => sink.Write(plain));
        }

        Assert.That(collected.ToArray(), Is.EqualTo(original));
    }

    [Test]
    public void AccessChunk_With_State_Accepts_Value_Type_State_And_Validates()
    {
        using var blob = new ProtectedBlob(RandomBytes(10).AsSpan(), SmallChunk);

        int observed = -1;
        blob.AccessChunk(0, 42, (plain, state) => observed = state + plain.Length);
        Assert.That(observed, Is.EqualTo(52));

        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentNullException>(() => blob.AccessChunk(0, 0, (System.Buffers.ReadOnlySpanAction<byte, int>)null!));
            Assert.Throws<ArgumentOutOfRangeException>(() => blob.AccessChunk(1, 0, (_, _) => { }));
            Assert.Throws<ArgumentOutOfRangeException>(() => blob.AccessChunk(-1, 0, (_, _) => { }));
        });

        blob.Dispose();
        Assert.Throws<ObjectDisposedException>(() => blob.AccessChunk(0, 0, (_, _) => { }));
    }
}
