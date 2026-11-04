using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using TopSecret;
using TopSecret.LinuxTpm;
using Tpm2Lib;

namespace TopSecret.LinuxTpm.Tests;

[TestFixture]
[Platform(Include = "Linux")]
public class LinuxTpmProtectorTests
{
    private const string SwtpmHost = "127.0.0.1";
    private const int SwtpmCommandPort = 2321;

    [Test]
    public void IsAvailable_round_trips_master_when_tpm_present()
    {
        if (!LinuxTpmProtector.IsAvailable())
        {
            Assert.Ignore("No accessible Linux TPM 2.0 device on this host (/dev/tpmrm0 or /dev/tpm0).");
            return;
        }

        Span<byte> master = stackalloc byte[32];
        RandomNumberGenerator.Fill(master);
        byte[] expected = master.ToArray();

        // Hand the protector its own copy — TryCreate zeros the input array
        // on success.
        var input = master.ToArray();
        var protector = LinuxTpmProtector.TryCreate(input);
        Assert.That(protector, Is.Not.Null,
            "TryCreate returned null on a host where IsAvailable() is true.");

        try
        {
            using var first = protector!.UnwrapKey();
            using var second = protector.UnwrapKey();

            Assert.Multiple(() =>
            {
                Assert.That(first.Key, Is.EqualTo(expected),
                    "first UnwrapKey did not round-trip the master");
                Assert.That(second.Key, Is.EqualTo(expected),
                    "second UnwrapKey did not round-trip the master");
                Assert.That(first.Key, Is.Not.SameAs(second.Key),
                    "UnwrapKey should hand out a fresh ephemeral buffer per call");
                Assert.That(input, Is.EqualTo(new byte[32]),
                    "TryCreate must zero the input master on success");
            });
        }
        finally
        {
            (protector as IDisposable)?.Dispose();
        }
    }

    [Test]
    public void TryCreate_returns_null_when_no_tpm()
    {
        if (LinuxTpmProtector.IsAvailable())
        {
            Assert.Ignore("TPM available; this test only covers the no-TPM path.");
            return;
        }

        var master = new byte[32];
        RandomNumberGenerator.Fill(master);
        Assert.That(LinuxTpmProtector.TryCreate(master), Is.Null);
    }

    [Test]
    public void TryCreate_rejects_wrong_size_master()
    {
        // Behavior independent of TPM presence — short-circuits before any
        // TPM interaction.
        Assert.That(LinuxTpmProtector.TryCreate(new byte[16]), Is.Null);
        Assert.That(LinuxTpmProtector.TryCreate(new byte[33]), Is.Null);
    }

    [Test]
    public void Round_trip_against_swtpm_simulator()
    {
        if (!IsSwtpmListening())
        {
            Assert.Ignore(
                $"No swtpm simulator listening on {SwtpmHost}:{SwtpmCommandPort}. " +
                "Start swtpm in socket mode to exercise this test locally — see " +
                "ci.yml for the GitHub Actions setup.");
            return;
        }

        Span<byte> master = stackalloc byte[32];
        RandomNumberGenerator.Fill(master);
        byte[] expected = master.ToArray();
        var input = master.ToArray();

        var device = new TcpTpmDevice(SwtpmHost, SwtpmCommandPort, stopTpm: false, linuxTrm: true);
        device.Connect();

        var protector = LinuxTpmProtector.TryCreateWithDevice(input, device);
        Assert.That(protector, Is.Not.Null,
            "TryCreateWithDevice returned null against a connected swtpm simulator.");

        try
        {
            using var first = protector!.UnwrapKey();
            using var second = protector.UnwrapKey();

            Assert.Multiple(() =>
            {
                Assert.That(first.Key, Is.EqualTo(expected),
                    "first UnwrapKey did not round-trip the master through swtpm");
                Assert.That(second.Key, Is.EqualTo(expected),
                    "second UnwrapKey did not round-trip the master through swtpm");
                Assert.That(first.Key, Is.Not.SameAs(second.Key),
                    "UnwrapKey should hand out a fresh ephemeral buffer per call");
                Assert.That(input, Is.EqualTo(new byte[32]),
                    "TryCreateWithDevice must zero the input master on success");
            });
        }
        finally
        {
            (protector as IDisposable)?.Dispose();
        }
    }

    [Test]
    public void Parallel_unwraps_against_swtpm_never_overlap_on_the_command_pipe()
    {
        if (!IsSwtpmListening())
        {
            Assert.Ignore(
                $"No swtpm simulator listening on {SwtpmHost}:{SwtpmCommandPort}. " +
                "Start swtpm in socket mode to exercise this test locally — see " +
                "ci.yml for the GitHub Actions setup.");
            return;
        }

        var input = RandomNumberGenerator.GetBytes(32);
        byte[] expected = input.ToArray();

        var inner = new TcpTpmDevice(SwtpmHost, SwtpmCommandPort, stopTpm: false, linuxTrm: true);
        inner.Connect();
        var counting = new ConcurrencyCountingDevice(inner);

        var protector = LinuxTpmProtector.TryCreateWithDevice(input, counting);
        Assert.That(protector, Is.Not.Null,
            "TryCreateWithDevice returned null against a connected swtpm simulator.");

        try
        {
            counting.ResetMax();
            const int threads = 8, iterations = 10;
            using var start = new ManualResetEventSlim(false);
            var failures = new System.Collections.Concurrent.ConcurrentBag<string>();
            var workers = Enumerable.Range(0, threads).Select(t => new Thread(() =>
            {
                start.Wait();
                for (int i = 0; i < iterations; i++)
                {
                    using var key = protector!.UnwrapKey();
                    if (!key.Key.AsSpan().SequenceEqual(expected))
                    {
                        failures.Add($"thread {t} iteration {i}: unwrapped key did not match the master");
                    }
                }
            })).ToArray();
            foreach (var w in workers) w.Start();
            start.Set();
            foreach (var w in workers) w.Join();

            Assert.Multiple(() =>
            {
                Assert.That(failures, Is.Empty);
                Assert.That(counting.MaxInFlight, Is.EqualTo(1),
                    "RSA_Decrypt commands must be serialised on the protector's gate — " +
                    "Tpm2 is a single command/response pipe");
                Assert.That(counting.Dispatched, Is.GreaterThanOrEqualTo(threads * iterations),
                    "every unwrap should have reached the device");
            });
        }
        finally
        {
            (protector as IDisposable)?.Dispose();
        }
    }

    private sealed class ConcurrencyCountingDevice : Tpm2Device
    {
        private readonly Tpm2Device _inner;
        private int _inFlight;
        private int _maxInFlight;
        private int _dispatched;

        public ConcurrencyCountingDevice(Tpm2Device inner) => _inner = inner;

        public int MaxInFlight => Volatile.Read(ref _maxInFlight);
        public int Dispatched => Volatile.Read(ref _dispatched);

        public void ResetMax()
        {
            Volatile.Write(ref _maxInFlight, 0);
            Volatile.Write(ref _dispatched, 0);
        }

        public override void DispatchCommand(CommandModifier mod, byte[] cmdBuf, out byte[] respBuf)
        {
            int now = Interlocked.Increment(ref _inFlight);
            try
            {
                int seen;
                do
                {
                    seen = Volatile.Read(ref _maxInFlight);
                    if (now <= seen) break;
                } while (Interlocked.CompareExchange(ref _maxInFlight, now, seen) != seen);

                Interlocked.Increment(ref _dispatched);
                // Widen the overlap window so an unguarded caller would be
                // caught deterministically rather than by luck.
                Thread.Sleep(1);
                _inner.DispatchCommand(mod, cmdBuf, out respBuf);
            }
            finally
            {
                Interlocked.Decrement(ref _inFlight);
            }
        }

        public override void Connect() => _inner.Connect();
        public override void Close() => _inner.Close();
        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
        }
        public override bool PlatformAvailable() => _inner.PlatformAvailable();
        public override bool HasRM() => _inner.HasRM();
        public override bool UsesTbs() => _inner.UsesTbs();
        public override bool PowerCtlAvailable() => _inner.PowerCtlAvailable();
        public override bool LocalityCtlAvailable() => _inner.LocalityCtlAvailable();
        public override bool NvCtlAvailable() => _inner.NvCtlAvailable();
        public override bool ImplementsPhysicalPresence() => _inner.ImplementsPhysicalPresence();
        public override bool ImplementsCancel() => _inner.ImplementsCancel();
    }

    private static bool IsSwtpmListening()
    {
        try
        {
            using var socket = new TcpClient();
            var task = socket.ConnectAsync(IPAddress.Parse(SwtpmHost), SwtpmCommandPort);
            return task.Wait(TimeSpan.FromMilliseconds(250)) && socket.Connected;
        }
        catch
        {
            return false;
        }
    }
}

[TestFixture]
public class LinuxTpmRegistrationTests
{
    [Test]
    public void Registration_sets_transient_slot_constrained_flag()
    {
        LinuxTpmRegistration.Register();

        Assert.That(KeyAtRestProtectorFactory.HasTransientSlotConstrainedProvider(), Is.True,
            "LinuxTpmRegistration.Register() must register with transientSlotConstrained: true; " +
            "without it the rotation-warning safety net silently disengages.");
    }
}
