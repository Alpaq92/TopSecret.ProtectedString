using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using TopSecret;
using TopSecret.LinuxTpm;
using Tpm2Lib;

namespace TopSecret.LinuxTpm.Tests;

/// <summary>
/// Smoke tests for the Linux TPM protector. Mirror the
/// <c>WindowsTpmProtectorTests</c> shape: a round-trip test against the
/// real device, a no-TPM null-return test, and a wrong-size-master
/// rejection. Each test self-skips when the runtime is not Linux or no
/// TPM device is available, so the suite can run on Windows / macOS / on
/// Linux CI legs without a TPM without any conditional gating in the
/// workflow files.
///
/// Plus a fourth test that exercises the protector against a software
/// TPM 2.0 simulator (<c>swtpm</c>) over <see cref="TcpTpmDevice"/>. CI
/// installs and starts swtpm on the ubuntu-latest leg before running
/// these tests, so this is the path that actually validates the
/// TSS.MSR call shape on every PR.
/// </summary>
[TestFixture]
[Platform(Include = "Linux")]
public class LinuxTpmProtectorTests
{
    // swtpm launched with `--server type=tcp,port=2321 --ctrl
    // type=tcp,port=2322` — these are the conventional ports used by the
    // TSS.MSR test suite. TcpTpmDevice's serverPort is the command port;
    // it derives the platform port as serverPort + 1.
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

    /// <summary>
    /// Round-trip the master through a full provision + encrypt + decrypt
    /// cycle against a software TPM 2.0 simulator (<c>swtpm</c>) over TCP.
    /// This is the test that actually validates the TSS.MSR call shape end
    /// to end — CI installs and starts swtpm before running it. Skips
    /// silently when nothing is listening on the simulator port (i.e.
    /// developers running the test suite locally without swtpm).
    /// </summary>
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

        // Hand a connected TcpTpmDevice to the protector via the internal
        // test seam. On success the protector takes ownership and disposes
        // the device on protector dispose.
        var device = new TcpTpmDevice(SwtpmHost, SwtpmCommandPort);
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

    /// <summary>
    /// Best-effort liveness probe: try to TCP-connect to the swtpm command
    /// port. If the connect succeeds within a short timeout, the simulator
    /// is up. This avoids a multi-second timeout when no swtpm is running.
    /// </summary>
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

/// <summary>
/// Regression tests for <see cref="LinuxTpmRegistration"/> metadata. Kept
/// in their own fixture because they are platform-agnostic — the factory
/// delegate self-skips on non-Linux hosts, but the registration metadata
/// itself is a property of the call we make to
/// <see cref="KeyAtRestProtectorFactory.RegisterHardwareBacked"/> regardless
/// of host.
/// </summary>
[TestFixture]
public class LinuxTpmRegistrationTests
{
    /// <summary>
    /// The load-bearing <c>transientSlotConstrained: true</c> flag on
    /// <see cref="LinuxTpmRegistration.Register"/>. The whole
    /// <c>EmitTransientSlotRotationWarning</c> safety net (which warns when
    /// periodic process-key rotation is paired with a TPM-backed provider)
    /// depends on this flag. If a future refactor drops the named arg or
    /// flips it to <see langword="false"/>, this test fails — without it
    /// the regression would land silently and consumers would get
    /// <c>TPM_RC_RESOURCES</c> in production with no warning.
    /// </summary>
    [Test]
    public void Registration_sets_transient_slot_constrained_flag()
    {
        // Register() is idempotent; the [ModuleInitializer] has likely
        // already fired by now, but call again as belt-and-braces against
        // unusual loading scenarios.
        LinuxTpmRegistration.Register();

        Assert.That(KeyAtRestProtectorFactory.HasTransientSlotConstrainedProvider(), Is.True,
            "LinuxTpmRegistration.Register() must register with transientSlotConstrained: true; " +
            "without it the rotation-warning safety net silently disengages.");
    }
}
