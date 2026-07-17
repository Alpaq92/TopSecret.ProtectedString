using TopSecret;

namespace TopSecret.ProtectedBlobTests;

/// <summary>
/// Drives concurrent chunk reads against a shared blob while the process key
/// rotates underneath, asserting every read round-trips. Blobs snapshot the
/// protector at construction and are never migrated, so a rotation must not
/// disturb an in-flight DEK unwrap (which rents pooled scratch under the blob's
/// own lock).
/// </summary>
[TestFixture]
[NonParallelizable]
public class ConcurrencyStressTests
{
    [TearDown]
    public void ResetRotationPolicy() =>
        ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.Disabled;

    [Test]
    public void Concurrent_blob_reads_round_trip_under_rotation()
    {
        ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;

        var rng = new Random(0x7777);
        var payload = new byte[64 * 1024];
        rng.NextBytes(payload);
        using var blob = new ProtectedBlob(payload);

        const int workers = 12;
        const int perWorker = 200;
        var failures = new System.Collections.Concurrent.ConcurrentQueue<string>();
        using var start = new ManualResetEventSlim(false);

        var rotating = true;
        var rotator = new Thread(() =>
        {
            start.Wait();
            while (Volatile.Read(ref rotating))
            {
                try { ProtectedString.RotateProcessKey(); }
                catch (Exception ex) { failures.Enqueue("rotate: " + ex); }
                Thread.SpinWait(200);
            }
        });
        rotator.Start();

        var threads = new Thread[workers];
        for (int t = 0; t < workers; t++)
        {
            int worker = t;
            threads[t] = new Thread(() =>
            {
                start.Wait();
                var actual = new byte[payload.Length];
                for (int i = 0; i < perWorker; i++)
                {
                    try
                    {
                        blob.CopyTo(actual);
                        if (!actual.AsSpan().SequenceEqual(payload))
                            failures.Enqueue($"w{worker}#{i}: blob round-trip mismatch");
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
            "concurrent blob reads under rotation must round-trip:\n  " +
            string.Join("\n  ", failures.Take(20)));
    }
}
