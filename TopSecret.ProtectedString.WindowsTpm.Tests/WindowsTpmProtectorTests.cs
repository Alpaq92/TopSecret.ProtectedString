using System.Security.Cryptography;
using TopSecret;
using TopSecret.WindowsTpm;

namespace TopSecret.WindowsTpm.Tests;

[TestFixture]
[Platform(Include = "Win")]
public class WindowsTpmProtectorTests
{
    [Test]
    public void IsAvailable_round_trips_master_when_tpm_present()
    {
        if (!WindowsTpmProtector.IsAvailable())
        {
            Assert.Ignore("No Microsoft Platform Crypto Provider on this host (no TPM).");
            return;
        }

        Span<byte> master = stackalloc byte[32];
        RandomNumberGenerator.Fill(master);
        byte[] expected = master.ToArray();

        // Hand the protector its own copy — TryCreate zeros the input array
        // on success.
        var input = master.ToArray();
        var protector = WindowsTpmProtector.TryCreate(input);
        Assert.That(protector, Is.Not.Null,
            "TryCreate returned null on a host where IsAvailable() is true.");

        try
        {
            // Two consecutive unwraps should both yield the original master,
            // each via a fresh ephemeral buffer.
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
        if (WindowsTpmProtector.IsAvailable())
        {
            // Covered by the round-trip test above.
            Assert.Ignore("TPM available; this test only covers the no-TPM path.");
            return;
        }

        var master = new byte[32];
        RandomNumberGenerator.Fill(master);
        Assert.That(WindowsTpmProtector.TryCreate(master), Is.Null);
    }

    [Test]
    public void TryCreate_rejects_wrong_size_master()
    {
        // Behavior independent of TPM presence.
        Assert.That(WindowsTpmProtector.TryCreate(new byte[16]), Is.Null);
        Assert.That(WindowsTpmProtector.TryCreate(new byte[33]), Is.Null);
    }
}

[TestFixture]
public class WindowsTpmRegistrationTests
{
    [Test]
    public void Registration_sets_transient_slot_constrained_flag()
    {
        WindowsTpmRegistration.Register();

        Assert.That(KeyAtRestProtectorFactory.HasTransientSlotConstrainedProvider(), Is.True,
            "WindowsTpmRegistration.Register() must register with transientSlotConstrained: true; " +
            "without it the rotation-warning safety net silently disengages.");
    }
}
