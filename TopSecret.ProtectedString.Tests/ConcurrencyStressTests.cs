using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

/// <summary>
/// Hammers the locked-scratch pool, the <c>ProtectorLifetime</c> refcount, and
/// the rotation-vs-construct ordering under concurrent load, asserting the two
/// invariants they rest on continuously: <b>round-trip integrity</b> (every
/// instance's <c>Access</c> returns exactly what it was constructed with, even
/// across rotations) and <b>no chunk aliasing</b> (a freshly rented pool chunk
/// always arrives zeroed — a non-zero byte means two live leases overlapped).
/// </summary>
/// <remarks>
/// Seeded RNG (per test parameter) so any failure reproduces. This fixture is
/// <see cref="NonParallelizableAttribute"/> versus other fixtures because it
/// drives process-global rotation state, but spins its own worker threads.
/// The correctness of the machinery here was previously established only by
/// interleaving argument and code review; this turns that into execution.
/// </remarks>
[TestFixture]
[NonParallelizable]
public class ConcurrencyStressTests
{
    private const int Seed = 1234567;

    [TearDown]
    public void ResetRotationPolicy()
    {
        // Leave the process in the default no-rotation posture for other fixtures.
        ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.Disabled;
    }

    [Test]
    public void ProtectedString_survives_concurrent_ops_and_rotations_with_intact_round_trips()
    {
        ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;

        const int workers = 16;
        const int perWorker = 400;
        var failures = new System.Collections.Concurrent.ConcurrentQueue<string>();
        using var start = new ManualResetEventSlim(false);

        // A rotator thread churns the process key while the workers operate,
        // so migrations race construction / Access / mutation.
        var rotating = true;
        var rotator = new Thread(() =>
        {
            var rng = new Random(Seed ^ 0x5555);
            start.Wait();
            while (Volatile.Read(ref rotating))
            {
                try { ProtectedString.RotateProcessKey(); }
                catch (Exception ex) { failures.Enqueue("rotate: " + ex); }
                Thread.SpinWait(rng.Next(50, 500));
            }
        });
        rotator.Start();

        var threads = new Thread[workers];
        for (int t = 0; t < workers; t++)
        {
            int worker = t;
            threads[t] = new Thread(() =>
            {
                var rng = new Random(Seed + worker);
                start.Wait();
                for (int i = 0; i < perWorker; i++)
                {
                    try
                    {
                        string expected = RandomSecret(rng);
                        using var ps = Build(rng, expected);

                        // A mix of the operations that all rent pooled scratch.
                        switch (rng.Next(5))
                        {
                            case 0:
                                AssertRoundTrip(ps, expected, failures, worker);
                                break;
                            case 1:
                                using (var copy = ps.Copy())
                                    AssertRoundTrip(copy, expected, failures, worker);
                                break;
                            case 2:
                                using (var other = new ProtectedString(expected.AsSpan()))
                                    if (!ps.Equals(other))
                                        failures.Enqueue($"w{worker}: Equals false for identical secrets");
                                break;
                            case 3:
                                if (!CopyToMatches(ps, expected))
                                    failures.Enqueue($"w{worker}: CopyTo mismatch");
                                break;
                            case 4:
                                int len = ps.Utf8Access(bytes => bytes.Length);
                                if (len != System.Text.Encoding.UTF8.GetByteCount(expected))
                                    failures.Enqueue($"w{worker}: Utf8Access length mismatch");
                                break;
                        }
                    }
                    catch (Exception ex)
                    {
                        failures.Enqueue($"w{worker}#{i}: {ex}");
                    }
                }
            });
            threads[t].Start();
        }

        start.Set();
        foreach (var thread in threads) thread.Join();
        Volatile.Write(ref rotating, false);
        rotator.Join();

        Assert.That(failures, Is.Empty,
            "concurrent operations under rotation must preserve round-trips:\n  " +
            string.Join("\n  ", failures.Take(20)));
    }

    [Test]
    public void Pool_hands_out_disjoint_zeroed_chunks_under_saturating_concurrency()
    {
        // Directly stresses the no-aliasing invariant across every size class
        // at once, so a race in bump-allocation vs free-list reuse surfaces as
        // a chunk arriving non-zeroed (an overlap with another live lease).
        const int workers = 24;
        const int perWorker = 2000;
        var failures = new System.Collections.Concurrent.ConcurrentQueue<string>();
        using var start = new ManualResetEventSlim(false);

        var threads = new Thread[workers];
        for (int t = 0; t < workers; t++)
        {
            int worker = t;
            threads[t] = new Thread(() =>
            {
                var rng = new Random(Seed + worker);
                start.Wait();
                for (int i = 0; i < perWorker; i++)
                {
                    int size = rng.Next(1, 4096);
                    var lease = LockedScratchPool.Rent(size);
                    try
                    {
                        var span = lease.Bytes(size);
                        int dirty = span.IndexOfAnyExcept((byte)0);
                        if (dirty >= 0)
                        {
                            failures.Enqueue($"w{worker}: rented chunk not zeroed at {dirty} (size {size}) — live-lease aliasing");
                        }
                        span.Fill((byte)(worker + 1)); // dirty it so a leaked overlap is detectable
                    }
                    finally
                    {
                        lease.Return();
                    }
                }
            });
            threads[t].Start();
        }

        start.Set();
        foreach (var thread in threads) thread.Join();

        Assert.That(failures, Is.Empty,
            "saturating pool concurrency must never alias two live leases:\n  " +
            string.Join("\n  ", failures.Take(20)));
    }

    // ---- helpers ----------------------------------------------------------

    private static string RandomSecret(Random rng)
    {
        int len = rng.Next(0, 40);
        var chars = new char[len];
        for (int i = 0; i < len; i++) chars[i] = (char)('!' + rng.Next(0, 90));
        return new string(chars);
    }

    private static ProtectedString Build(Random rng, string value)
    {
        // Exercise both construction shapes and the build-buffer path.
        switch (rng.Next(3))
        {
            case 0: return new ProtectedString(value.AsSpan());
            case 1: return new ProtectedString(value);
            default:
                var ps = new ProtectedString();
                foreach (var c in value) ps.AppendChar(c);
                ps.MakeReadOnly();
                return ps;
        }
    }

    private static bool CopyToMatches(ProtectedString ps, string expected)
    {
        var buf = new char[expected.Length];
        int written = ps.CopyTo(buf);
        return written == expected.Length && buf.AsSpan().SequenceEqual(expected.AsSpan());
    }

    private static void AssertRoundTrip(
        ProtectedString ps, string expected,
        System.Collections.Concurrent.ConcurrentQueue<string> failures, int worker)
    {
        var actual = ps.Access(plain => new string(plain));
        if (actual != expected)
        {
            failures.Enqueue($"w{worker}: round-trip mismatch (len {expected.Length} vs {actual.Length})");
        }
    }
}
