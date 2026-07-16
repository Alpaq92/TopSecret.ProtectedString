using TopSecret;

namespace TopSecret.ProtectedStringTests;

[TestFixture]
[NonParallelizable] // Asserts exact free-list behaviour of process-global pool state.
public class LockedScratchPoolTests
{
    [Test]
    public void Pooled_chunk_serves_byte_and_char_views()
    {
        var lease = LockedScratchPool.Rent(64);
        try
        {
            Assert.That(lease.IsPooled, Is.True);
            // Chunks are carved in 64-byte units from a window that is
            // page-aligned in *absolute address* space (the array-index
            // offset is arbitrary), so the char view's 2-byte alignment
            // always holds. Verify both views round-trip.
            var chars = lease.Chars(32);
            chars.Fill('x');
            Assert.That(chars[31], Is.EqualTo('x'));
            Assert.That(lease.Bytes(2)[0], Is.EqualTo((byte)'x'));
        }
        finally
        {
            lease.Return();
        }
    }

    [Test]
    public void Returned_chunk_is_wiped_and_reused()
    {
        var first = LockedScratchPool.Rent(128);
        first.Bytes(128).Fill(0xAB);
        int offset = first.Offset;
        first.Return();

        // Same size class immediately after return → the freshly wiped chunk
        // comes back off the free list.
        var second = LockedScratchPool.Rent(128);
        try
        {
            Assert.That(second.Offset, Is.EqualTo(offset));
            Assert.That(second.Bytes(128).IndexOfAnyExcept((byte)0), Is.EqualTo(-1),
                "chunk must be zeroed before it re-enters circulation");
        }
        finally
        {
            second.Return();
        }
    }

    [Test]
    public void Double_return_is_a_guarded_no_op()
    {
        var a = LockedScratchPool.Rent(64);
        a.Return();
        a.Return(); // must not push the chunk onto the free list twice

        var b = LockedScratchPool.Rent(64);
        var c = LockedScratchPool.Rent(64);
        try
        {
            // If the double return had corrupted the free list, b and c would
            // alias the same chunk: writing through one would be visible
            // through the other.
            b.Bytes(64).Fill(1);
            Assert.That(c.Bytes(64).IndexOfAnyExcept((byte)0), Is.EqualTo(-1),
                "two live leases must never share a chunk");
        }
        finally
        {
            b.Return();
            c.Return();
        }
    }

    [Test]
    public void Oversize_requests_bypass_the_pool()
    {
        var lease = LockedScratchPool.Rent(64 * 1024);
        try
        {
            Assert.That(lease.IsPooled, Is.False);
            Assert.That(lease.Offset, Is.Zero);
            lease.Bytes(64 * 1024).Fill(0xCD);
        }
        finally
        {
            lease.Return();
        }
    }

    [Test]
    public void Concurrent_rent_and_return_hand_out_disjoint_chunks()
    {
        Parallel.For(0, 64, _ =>
        {
            for (int i = 0; i < 200; i++)
            {
                var lease = LockedScratchPool.Rent(256);
                try
                {
                    var span = lease.Bytes(256);
                    Assert.That(span.IndexOfAnyExcept((byte)0), Is.EqualTo(-1),
                        "rented chunk must arrive zeroed — a nonzero byte means chunk aliasing");
                    span.Fill(0x5A);
                }
                finally
                {
                    lease.Return();
                }
            }
        });
    }
}
