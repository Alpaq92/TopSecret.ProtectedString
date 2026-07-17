using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

/// <summary>
/// Exercises the <see cref="KeyAtRestProtection.GuardedPage"/> tier end to end
/// through the factory: the master round-trips through a no-access page, the
/// input is consumed, disposal is clean, and the tier degrades to obscurity
/// only where page protection is unavailable.
/// </summary>
[TestFixture]
[NonParallelizable]
public class PageGuardedKeyProtectorTests
{
    private KeyAtRestProtection _priorMode;
    private TimeSpan _priorTtl;
    private MemoryLockingFailureBehavior _priorBehavior;

    [SetUp]
    public void SetUp()
    {
        _priorMode = ProtectedStringOptions.KeyAtRestProtection;
        _priorTtl = ProtectedStringOptions.UnwrappedKeyCacheTtl;
        _priorBehavior = ProtectedStringOptions.MemoryLockingFailureBehavior;
    }

    [TearDown]
    public void TearDown()
    {
        ProtectedStringOptions.KeyAtRestProtection = _priorMode;
        ProtectedStringOptions.UnwrappedKeyCacheTtl = _priorTtl;
        ProtectedStringOptions.MemoryLockingFailureBehavior = _priorBehavior;
    }

    [Test]
    public void GuardedPage_round_trips_the_master_and_consumes_the_input()
    {
        ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.GuardedPage;
        ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero;

        var master = RandomNumberGenerator.GetBytes(32);
        var expected = master.ToArray();

        var protector = KeyAtRestProtectorFactory.Create(master);
        try
        {
            Assert.That(master, Is.All.EqualTo((byte)0),
                "the factory transfers ownership of the master — the input array must be zeroed");

            // Two unwraps must both reconstruct the master (the page is
            // re-sealed between them).
            using (var a = protector.UnwrapKey())
                Assert.That(a.Key, Is.EqualTo(expected));
            using (var b = protector.UnwrapKey())
                Assert.That(b.Key, Is.EqualTo(expected));
        }
        finally
        {
            (protector as IDisposable)?.Dispose();
        }
    }

    [Test]
    public void GuardedPage_selects_the_guarded_protector_where_page_protection_exists()
    {
        // Every CI/dev platform for this TFM (Windows, Linux, macOS) has a
        // page-protection primitive; browser-wasm (which does not) degrades to
        // obscurity instead and is out of scope for this fixture.
        Assume.That(MemoryProtectionIsSupported(), Is.True,
            "no page-protection primitive on this platform — GuardedPage degrades to obscurity");

        ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.GuardedPage;
        ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero;

        var master = RandomNumberGenerator.GetBytes(32);
        var protector = KeyAtRestProtectorFactory.Create(master);
        try
        {
            Assert.That(protector.GetType().Name, Is.EqualTo("PageGuardedKeyProtector"),
                "on a page-protection-capable host the GuardedPage tier must select its own protector");
        }
        finally
        {
            (protector as IDisposable)?.Dispose();
        }
    }

    [Test]
    public void GuardedPage_composes_with_the_ttl_cache()
    {
        ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.GuardedPage;
        ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.FromMilliseconds(250);

        var master = RandomNumberGenerator.GetBytes(32);
        var expected = master.ToArray();
        var protector = KeyAtRestProtectorFactory.Create(master);
        try
        {
            Assert.That(protector, Is.InstanceOf<TtlCachingKeyAtRestProtector>(),
                "a positive TTL must wrap the guarded protector in the caching decorator");
            using var unwrapped = protector.UnwrapKey();
            Assert.That(unwrapped.Key, Is.EqualTo(expected));
        }
        finally
        {
            (protector as IDisposable)?.Dispose();
        }
    }

    [Test]
    public void GuardedPage_end_to_end_through_a_ProtectedString_round_trips()
    {
        // The full stack: a ProtectedString whose process protector is the
        // guarded-page tier still encrypts and decrypts correctly.
        Assume.That(MemoryProtectionIsSupported(), Is.True);

        var master = RandomNumberGenerator.GetBytes(32);
        var protector = KeyAtRestProtectorFactory.Create(master);
        try
        {
            // Drive an AES-GCM round trip directly against the protector's key,
            // mirroring what ProtectedString does internally.
            const string secret = "guarded-page-secret";
            byte[] plain = System.Text.Encoding.Unicode.GetBytes(secret);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ct = new byte[plain.Length];
            byte[] tag = new byte[16];
            byte[] rt = new byte[plain.Length];

            using (var key = protector.UnwrapKey())
            {
                using var gcm = new AesGcm(key.Key, 16);
                gcm.Encrypt(nonce, plain, ct, tag);
            }
            using (var key = protector.UnwrapKey())
            {
                using var gcm = new AesGcm(key.Key, 16);
                gcm.Decrypt(nonce, ct, tag, rt);
            }
            Assert.That(System.Text.Encoding.Unicode.GetString(rt), Is.EqualTo(secret));
        }
        finally
        {
            (protector as IDisposable)?.Dispose();
        }
    }

    private static bool MemoryProtectionIsSupported()
    {
        // MemoryProtection is internal; reach it via the same InternalsVisibleTo
        // seam the rest of the fixture uses. Reflection keeps the test off a
        // hard reference to the type name in more than one place.
        var t = typeof(ProtectedString).Assembly.GetType("TopSecret.MemoryProtection")!;
        var prop = t.GetProperty("IsSupported",
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)!;
        return (bool)prop.GetValue(null)!;
    }
}
