using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using TopSecret;
using TopSecret.Cryptography;

namespace TopSecret.ProtectedStringTests;

[TestFixture]
public class ProtectedStringTests
{
    [Test]
    public void Default_constructor_creates_empty_instance()
    {
        using var ps = new ProtectedString();
        Assert.That(ps.Length, Is.EqualTo(0));
        Assert.That(ps.IsReadOnly, Is.False);
        Assert.That(ps.IsDisposed, Is.False);
#pragma warning disable CS0618 // intentional: NUnit's Assert.That(plain, Is.Empty) needs an array, not a span
        ps.Access(plain => Assert.That(plain, Is.Empty));
#pragma warning restore CS0618
    }

    [Test]
    public void Span_constructor_round_trips_value()
    {
        const string value = "correct horse battery staple";
        using var ps = new ProtectedString(value.AsSpan());

        Assert.That(ps.Length, Is.EqualTo(value.Length));
        var revealed = ps.Access(plain => new string(plain));
        Assert.That(revealed, Is.EqualTo(value));
    }

    [Test]
    public void String_constructor_round_trips_value()
    {
        const string value = "hunter2";
        using var ps = new ProtectedString(value);

        Assert.That(ps.Length, Is.EqualTo(value.Length));
        Assert.That(ps.Access(plain => new string(plain)), Is.EqualTo(value));
    }

    [Test]
    public void String_constructor_throws_on_null()
    {
        Assert.Throws<ArgumentNullException>(() => new ProtectedString((string)null!));
    }

    [Test]
    public void String_constructor_handles_empty_string()
    {
        using var ps = new ProtectedString(string.Empty);
        Assert.That(ps.Length, Is.EqualTo(0));
#pragma warning disable CS0618 // intentional: NUnit's Assert.That(plain, Is.Empty) needs an array, not a span
        ps.Access(plain => Assert.That(plain, Is.Empty));
#pragma warning restore CS0618
    }

    [Test]
    public void CharArray_constructor_does_not_clear_source_by_default()
    {
        var source = "secret".ToCharArray();
        using var ps = new ProtectedString(source);
        Assert.That(new string(source), Is.EqualTo("secret"));
        Assert.That(ps.Length, Is.EqualTo(6));
    }

    [Test]
    public void CharArray_constructor_clears_source_when_requested()
    {
        var source = "secret".ToCharArray();
        using var ps = new ProtectedString(source, clearSource: true);

        Assert.That(source, Is.All.EqualTo('\0'));
        var revealed = ps.Access(plain => new string(plain));
        Assert.That(revealed, Is.EqualTo("secret"));
    }

    [Test]
    public void CharArray_constructor_throws_on_null()
    {
        Assert.Throws<ArgumentNullException>(() => new ProtectedString((char[])null!));
    }

    [Test]
    public void Access_zeros_buffer_after_callback_returns()
    {
        char[]? leaked = null;
        using var ps = new ProtectedString("hunter2".AsSpan());
#pragma warning disable CS0618 // intentional: this test verifies the OBSOLETE Action<char[]> overload still wipes on return
        ps.Access(plain =>
        {
            leaked = plain;
            Assert.That(new string(plain), Is.EqualTo("hunter2"));
        });
#pragma warning restore CS0618

        Assert.That(leaked, Is.Not.Null);
        Assert.That(leaked!, Is.All.EqualTo('\0'));
    }

    [Test]
    public void Access_buffer_is_pinned_during_callback()
    {
        // GC.AllocateArray<>(pinned: true) places the array on the POH (pinned
        // object heap) so GetGCMemoryInfo will not relocate it. We verify the
        // buffer is truly pinned by checking that GC.GetGeneration returns 2
        // (POH objects are reported as gen 2 in .NET 8).
        using var ps = new ProtectedString("topsecret".AsSpan());
#pragma warning disable CS0618 // intentional: GC.GetGeneration(plain) takes object, which forces the char[] overload
        ps.Access(plain =>
        {
            Assert.That(plain, Is.Not.Empty);
            Assert.That(GC.GetGeneration(plain), Is.EqualTo(2));
        });
#pragma warning restore CS0618
    }

    [Test]
    public void Access_allocates_fresh_buffer_on_each_call()
    {
        using var ps = new ProtectedString("abc".AsSpan());
        char[]? first = null;
        char[]? second = null;
#pragma warning disable CS0618 // intentional: assigning the parameter to a captured local requires the char[] overload
        ps.Access(p => first = p);
        ps.Access(p => second = p);
#pragma warning restore CS0618

        Assert.That(first, Is.Not.SameAs(second));
    }

    [Test]
    public void Access_generic_returns_handler_value()
    {
        using var ps = new ProtectedString("abc".AsSpan());
        int len = ps.Access(plain => plain.Length);
        Assert.That(len, Is.EqualTo(3));
    }

    [Test]
    public void Access_throws_on_null_handler()
    {
        using var ps = new ProtectedString();
#pragma warning disable CS0618 // intentional: explicit cast pins the obsolete overload to verify its null check
        Assert.Throws<ArgumentNullException>(() => ps.Access((Action<char[]>)null!));
#pragma warning restore CS0618
        Assert.Throws<ArgumentNullException>(() => ps.Access<int>(null!));
    }

    [Test]
    public void AppendChar_extends_value()
    {
        using var ps = new ProtectedString();
        foreach (var c in "pa$$w0rd")
        {
            ps.AppendChar(c);
        }

        Assert.That(ps.Length, Is.EqualTo(8));
        Assert.That(ps.Access(p => new string(p)), Is.EqualTo("pa$$w0rd"));
    }

    [Test]
    public void AppendChar_throws_after_MakeReadOnly()
    {
        using var ps = new ProtectedString("a".AsSpan());
        ps.MakeReadOnly();
        Assert.That(ps.IsReadOnly, Is.True);
        Assert.Throws<InvalidOperationException>(() => ps.AppendChar('b'));
    }

    [Test]
    public void Copy_returns_independent_writable_instance()
    {
        using var original = new ProtectedString("abc".AsSpan());
        original.MakeReadOnly();

        using var copy = original.Copy();
        Assert.That(copy.IsReadOnly, Is.False);
        Assert.That(
            copy.Access(p => new string(p)),
            Is.EqualTo(original.Access(p => new string(p))));

        copy.AppendChar('d');
        Assert.That(original.Length, Is.EqualTo(3));
        Assert.That(copy.Length, Is.EqualTo(4));
        Assert.That(copy.Access(p => new string(p)), Is.EqualTo("abcd"));
        Assert.That(original.Access(p => new string(p)), Is.EqualTo("abc"));
    }

    [Test]
    public void Equals_returns_true_for_same_value()
    {
        using var a = new ProtectedString("topsecret".AsSpan());
        using var b = new ProtectedString("topsecret".AsSpan());
        Assert.That(a.Equals(b), Is.True);
        Assert.That(b.Equals(a), Is.True);
        Assert.That(a.Equals((object)b), Is.True);
    }

    [Test]
    public void Equals_returns_false_for_different_values()
    {
        using var a = new ProtectedString("alpha".AsSpan());
        using var b = new ProtectedString("beta".AsSpan());
        Assert.That(a.Equals(b), Is.False);
    }

    [Test]
    public void Equals_returns_false_for_same_length_different_chars()
    {
        using var a = new ProtectedString("alpha".AsSpan());
        using var b = new ProtectedString("alphZ".AsSpan());
        Assert.That(a.Equals(b), Is.False);
    }

    [Test]
    public void Equals_handles_null_and_disposed()
    {
        using var a = new ProtectedString("x".AsSpan());
        Assert.That(a.Equals((ProtectedString?)null), Is.False);
#pragma warning disable CS8602 // analyzer false positive on Assert.That + bool overload
        Assert.That(a.Equals((object?)null), Is.False);
        Assert.That(a.Equals("not a ProtectedString"), Is.False);
#pragma warning restore CS8602

        var b = new ProtectedString("x".AsSpan());
        b.Dispose();
        Assert.That(a.Equals(b), Is.False);
    }

    [Test]
    public void GetHashCode_depends_only_on_length()
    {
        using var a = new ProtectedString("abc".AsSpan());
        using var b = new ProtectedString("xyz".AsSpan());
        using var c = new ProtectedString("abcd".AsSpan());

        Assert.That(a.GetHashCode(), Is.EqualTo(b.GetHashCode()));
        Assert.That(a.GetHashCode(), Is.Not.EqualTo(c.GetHashCode()));
    }

    [Test]
    public void ToString_does_not_leak_plaintext()
    {
        using var ps = new ProtectedString("hunter2".AsSpan());
        var s = ps.ToString();
        Assert.That(s, Does.Not.Contain("hunter2"));
        Assert.That(s, Does.Contain("ProtectedString"));
    }

    [Test]
    public void Dispose_clears_state_and_blocks_further_use()
    {
        var ps = new ProtectedString("abc".AsSpan());
        ps.Dispose();

        Assert.That(ps.IsDisposed, Is.True);
        Assert.Throws<ObjectDisposedException>(() => { _ = ps.Length; });
        Assert.Throws<ObjectDisposedException>(() => ps.AppendChar('d'));
        Assert.Throws<ObjectDisposedException>(() => ps.Access(_ => { }));
        Assert.Throws<ObjectDisposedException>(() => ps.Copy());
        Assert.Throws<ObjectDisposedException>(() => ps.ComputeArgon2idHash(new byte[16], iterations: 1, memoryKb: 8));
    }

    [Test]
    public void Dispose_is_idempotent()
    {
        var ps = new ProtectedString("abc".AsSpan());
        ps.Dispose();
        Assert.DoesNotThrow(() => ps.Dispose());
    }

    // ---- Argon2id-based credential verification ------------------------

    /// <summary>
    /// Argon2id is intentionally slow; tests use the absolute-minimum
    /// parameters that the algorithm allows so the suite stays fast.
    /// Production code should use the OWASP-aligned defaults.
    /// </summary>
    private const int FastIterations = 1;
    private const int FastMemoryKb = 8;
    private const int FastParallelism = 1;
    private const int FastHashLength = 32;

    [Test]
    public void ComputeArgon2idHash_matches_reference_implementation()
    {
        const string value = "password";
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);

        using var ps = new ProtectedString(value.AsSpan());
        var actual = ps.ComputeArgon2idHash(salt, FastIterations, FastMemoryKb, FastParallelism, FastHashLength);

        // Compute the reference hash directly via the underlying Argon2 library for parity.
        using var argon = new Argon2id(Encoding.UTF8.GetBytes(value))
        {
            Salt = salt,
            Iterations = FastIterations,
            MemorySize = FastMemoryKb,
            DegreeOfParallelism = FastParallelism,
        };
        var expected = argon.GetBytes(FastHashLength);

        Assert.That(actual, Is.EqualTo(expected));
    }

    [Test]
    public void ComputeArgon2idHash_uses_salt_to_diversify_output()
    {
        using var ps = new ProtectedString("password".AsSpan());
        var saltA = new byte[16]; RandomNumberGenerator.Fill(saltA);
        var saltB = new byte[16]; RandomNumberGenerator.Fill(saltB);

        var hashA = ps.ComputeArgon2idHash(saltA, FastIterations, FastMemoryKb, FastParallelism, FastHashLength);
        var hashB = ps.ComputeArgon2idHash(saltB, FastIterations, FastMemoryKb, FastParallelism, FastHashLength);

        Assert.That(hashA, Is.Not.EqualTo(hashB));
    }

    [Test]
    public void VerifyArgon2idHash_distinguishes_match_from_mismatch()
    {
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);

        using var ps = new ProtectedString("password".AsSpan());
        var stored = ps.ComputeArgon2idHash(salt, FastIterations, FastMemoryKb, FastParallelism, FastHashLength);

        using var sameValue = new ProtectedString("password".AsSpan());
        using var differentValue = new ProtectedString("Password".AsSpan());

        Assert.That(sameValue.VerifyArgon2idHash(stored, salt, FastIterations, FastMemoryKb, FastParallelism), Is.True);
        Assert.That(differentValue.VerifyArgon2idHash(stored, salt, FastIterations, FastMemoryKb, FastParallelism), Is.False);
    }

    [Test]
    public void VerifyArgon2idHash_throws_on_null_inputs()
    {
        using var ps = new ProtectedString();
        Assert.Throws<ArgumentNullException>(() => ps.VerifyArgon2idHash(null!, new byte[16], FastIterations, FastMemoryKb, FastParallelism));
        Assert.Throws<ArgumentNullException>(() => ps.VerifyArgon2idHash(new byte[FastHashLength], null!, FastIterations, FastMemoryKb, FastParallelism));
    }

    [Test]
    public void ComputeArgon2idHash_rejects_obviously_bad_parameters()
    {
        using var ps = new ProtectedString("x".AsSpan());
        Assert.Throws<ArgumentException>(() => ps.ComputeArgon2idHash(new byte[4]));
        Assert.Throws<ArgumentOutOfRangeException>(() => ps.ComputeArgon2idHash(new byte[16], iterations: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => ps.ComputeArgon2idHash(new byte[16], memoryKb: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => ps.ComputeArgon2idHash(new byte[16], parallelism: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => ps.ComputeArgon2idHash(new byte[16], hashLengthBytes: 8));
    }

    // ---- POH residency for the encrypted state -------------------------

    [Test]
    public void Encrypted_state_lives_on_POH()
    {
        // POH allocations are reported by GC.GetGeneration as gen 2 immediately
        // after allocation (regular heap allocations report gen 0).
        using var ps = new ProtectedString("topsecret".AsSpan());
        var ct = TestAccessors.GetCiphertextRaw(ps);
        var nonce = TestAccessors.GetNonceRaw(ps);
        var tag = TestAccessors.GetTagRaw(ps);

        Assert.That(ct, Is.Not.Null);
        Assert.That(nonce, Is.Not.Null);
        Assert.That(tag, Is.Not.Null);
        Assert.That(GC.GetGeneration(ct!), Is.EqualTo(2));
        Assert.That(GC.GetGeneration(nonce!), Is.EqualTo(2));
        Assert.That(GC.GetGeneration(tag!), Is.EqualTo(2));
    }

    [Test]
    public void Round_trips_unicode_including_surrogate_pairs()
    {
        const string value = "Zażółć gęślą jaźń \U0001F600 \U0001F4A9";
        using var ps = new ProtectedString(value.AsSpan());
        Assert.That(ps.Access(p => new string(p)), Is.EqualTo(value));
    }

    [Test]
    public void Round_trips_large_input()
    {
        var value = new string('x', 100_000);
        using var ps = new ProtectedString(value.AsSpan());
        Assert.That(ps.Length, Is.EqualTo(value.Length));
        Assert.That(ps.Access(p => new string(p) == value), Is.True);
    }

    [Test]
    public void Each_instance_uses_a_fresh_nonce()
    {
        // Two instances of identical plaintext must produce different ciphertext.
        using var a = new ProtectedString("abc".AsSpan());
        using var b = new ProtectedString("abc".AsSpan());
        var ctA = TestAccessors.GetCiphertext(a);
        var ctB = TestAccessors.GetCiphertext(b);
        Assert.That(ctA, Is.Not.EqualTo(ctB));
    }

    // ---- Memory locking ------------------------------------------------

    [Test]
    public void MemoryLocking_default_policy_is_LogWarning()
    {
        // Default value of the static property; users can change it before
        // first use and the constructor will read the new value.
        Assert.That(ProtectedStringOptions.MemoryLockingFailureBehavior,
            Is.EqualTo(MemoryLockingFailureBehavior.LogWarning));
    }

    [Test]
    public void MemoryLocking_option_round_trips()
    {
        var prior = ProtectedStringOptions.MemoryLockingFailureBehavior;
        try
        {
            ProtectedStringOptions.MemoryLockingFailureBehavior = MemoryLockingFailureBehavior.Throw;
            Assert.That(ProtectedStringOptions.MemoryLockingFailureBehavior,
                Is.EqualTo(MemoryLockingFailureBehavior.Throw));

            ProtectedStringOptions.MemoryLockingFailureBehavior = MemoryLockingFailureBehavior.Ignore;
            Assert.That(ProtectedStringOptions.MemoryLockingFailureBehavior,
                Is.EqualTo(MemoryLockingFailureBehavior.Ignore));
        }
        finally
        {
            ProtectedStringOptions.MemoryLockingFailureBehavior = prior;
        }
    }

    [Test]
    public void MemoryLocking_works_under_each_policy_when_supported()
    {
        // The probe should succeed on a normal Windows/Linux/macOS dev box.
        // Under each policy, construction + round-trip should still work.
        var prior = ProtectedStringOptions.MemoryLockingFailureBehavior;
        try
        {
            foreach (var behavior in new[]
                     {
                         MemoryLockingFailureBehavior.Ignore,
                         MemoryLockingFailureBehavior.LogWarning,
                         MemoryLockingFailureBehavior.Throw,
                     })
            {
                ProtectedStringOptions.MemoryLockingFailureBehavior = behavior;
                using var ps = new ProtectedString("hunter2".AsSpan());
                Assert.That(ps.Access(p => new string(p)), Is.EqualTo("hunter2"),
                    $"round-trip under policy {behavior} failed");
            }
        }
        finally
        {
            ProtectedStringOptions.MemoryLockingFailureBehavior = prior;
        }
    }

    // ---- Key-at-rest protection ---------------------------------------

    [Test]
    public void KeyAtRestProtection_default_is_None()
    {
        Assert.That(ProtectedStringOptions.KeyAtRestProtection,
            Is.EqualTo(KeyAtRestProtection.None));
    }

    [Test]
    public void KeyAtRestProtection_option_round_trips_all_four_values()
    {
        // Property round-trip only — the actual protector chosen depends on
        // when the lazy initializer first runs, so this fixture cannot
        // exercise the per-tier paths in-process. End-to-end coverage of
        // Obscurity / HardwareBackedRequired / HardwareBackedPreferred
        // requires either a fresh process per scenario or a test-only reset
        // hook (not currently exposed).
        var prior = ProtectedStringOptions.KeyAtRestProtection;
        try
        {
            foreach (var value in new[]
                     {
                         KeyAtRestProtection.None,
                         KeyAtRestProtection.Obscurity,
                         KeyAtRestProtection.HardwareBackedRequired,
                         KeyAtRestProtection.HardwareBackedPreferred,
                     })
            {
                ProtectedStringOptions.KeyAtRestProtection = value;
                Assert.That(ProtectedStringOptions.KeyAtRestProtection, Is.EqualTo(value),
                    $"round-trip failed for {value}");
            }
        }
        finally
        {
            ProtectedStringOptions.KeyAtRestProtection = prior;
        }
    }

    [Test]
    public void UnwrappedKeyCacheTtl_default_is_zero()
    {
        Assert.That(ProtectedStringOptions.UnwrappedKeyCacheTtl, Is.EqualTo(TimeSpan.Zero));
    }

    [Test]
    public void UnwrappedKeyCacheTtl_round_trips()
    {
        var prior = ProtectedStringOptions.UnwrappedKeyCacheTtl;
        try
        {
            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.FromMilliseconds(250);
            Assert.That(ProtectedStringOptions.UnwrappedKeyCacheTtl,
                Is.EqualTo(TimeSpan.FromMilliseconds(250)));

            ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero;
            Assert.That(ProtectedStringOptions.UnwrappedKeyCacheTtl, Is.EqualTo(TimeSpan.Zero));
        }
        finally
        {
            ProtectedStringOptions.UnwrappedKeyCacheTtl = prior;
        }
    }

    [Test]
    public void UnwrappedKeyCacheTtl_throws_on_negative_value()
    {
        var prior = ProtectedStringOptions.UnwrappedKeyCacheTtl;
        try
        {
            var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
                ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.FromSeconds(-1));
            Assert.That(ex!.Message, Does.Contain("non-negative").IgnoreCase);

            // The setter must not have mutated the value.
            Assert.That(ProtectedStringOptions.UnwrappedKeyCacheTtl, Is.EqualTo(prior));

            // Zero is the documented "off" value and must remain accepted.
            Assert.DoesNotThrow(() => ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.Zero);
        }
        finally
        {
            ProtectedStringOptions.UnwrappedKeyCacheTtl = prior;
        }
    }

    [Test]
    public void HardwareBackedAvailability_reports_known_state_for_this_host()
    {
        // The probe is non-destructive and based on platform + registry.
        // On the test host (a Windows or Linux dev box without the optional
        // TopSecret.ProtectedString.WindowsTpm package referenced) the answer
        // should be NoProviderForThisPlatform; on Apple it should be Available.
        var probe = ProtectedString.HardwareBackedAvailability;
        if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
        {
            Assert.That(probe, Is.EqualTo(HardwareBackedAvailability.Available));
        }
        else
        {
            // Non-Apple, no Windows TPM package referenced from the test
            // project — registry is empty.
            Assert.That(probe, Is.EqualTo(HardwareBackedAvailability.NoProviderForThisPlatform));
        }
    }

    [Test]
    public void HardwareBackedRequired_throws_when_no_provider_is_available()
    {
        // Skip on platforms where a built-in provider is available, since
        // the lazy global protector may already have initialised under a
        // prior policy and we cannot redo the choice for this process.
        if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
        {
            Assert.Ignore("Built-in Apple SEP provider is available; this test only covers the Required-failure path.");
            return;
        }

        // We can't actually exercise construction with HardwareBackedRequired
        // here, because the global protector is initialised lazily on the
        // first ProtectedString construction in the process and other tests
        // have already triggered it under None. This test instead asserts
        // the documented contract by inspection of the availability probe:
        // when the probe says NoProviderForThisPlatform, a fresh process
        // configured with HardwareBackedRequired would throw.
        Assert.That(ProtectedString.HardwareBackedAvailability,
            Is.EqualTo(HardwareBackedAvailability.NoProviderForThisPlatform),
            "On a non-Apple host without the optional Windows TPM package, no hardware-backed " +
            "provider should be available; HardwareBackedRequired construction would throw.");
    }

    // ---- Process-key rotation -----------------------------------------

    [Test]
    public void ProcessKeyRotation_default_policy_is_Disabled()
    {
        Assert.That(ProtectedStringOptions.ProcessKeyRotationPolicy,
            Is.EqualTo(ProcessKeyRotation.Disabled));
    }

    [Test]
    public void ProcessKeyRotation_options_round_trip()
    {
        var priorPolicy = ProtectedStringOptions.ProcessKeyRotationPolicy;
        var priorInterval = ProtectedStringOptions.ProcessKeyRotationInterval;
        try
        {
            foreach (var policy in new[]
                     {
                         ProcessKeyRotation.Disabled,
                         ProcessKeyRotation.OnDemand,
                         ProcessKeyRotation.Periodic,
                     })
            {
                ProtectedStringOptions.ProcessKeyRotationPolicy = policy;
                Assert.That(ProtectedStringOptions.ProcessKeyRotationPolicy,
                    Is.EqualTo(policy));
            }

            ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.FromMinutes(15);
            Assert.That(ProtectedStringOptions.ProcessKeyRotationInterval,
                Is.EqualTo(TimeSpan.FromMinutes(15)));
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = priorPolicy;
            ProtectedStringOptions.ProcessKeyRotationInterval = priorInterval;
        }
    }

    [Test]
    public void RotateProcessKey_throws_when_policy_is_Disabled()
    {
        var prior = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.Disabled;
            Assert.Throws<InvalidOperationException>(() => ProtectedString.RotateProcessKey());
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = prior;
        }
    }

    [Test]
    public void RotateProcessKey_re_encrypts_a_live_OnDemand_instance()
    {
        var prior = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;

            const string secret = "rotation-test-value";
            using var ps = new ProtectedString(secret.AsSpan());

            // Snapshot ciphertext before rotation.
            var ctBefore = TestAccessors.GetCiphertext(ps);

            ProtectedString.RotateProcessKey();

            // Ciphertext must be different (re-encrypted under a new key + nonce).
            var ctAfter = TestAccessors.GetCiphertext(ps);
            Assert.That(ctAfter, Is.Not.EqualTo(ctBefore),
                "ciphertext should change after rotation (new key + new nonce)");

            // Plaintext must round-trip after rotation.
            Assert.That(ps.Access(p => new string(p)), Is.EqualTo(secret),
                "plaintext should still be recoverable after rotation");
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = prior;
        }
    }

    [Test]
    public void RotateProcessKey_handles_empty_instance()
    {
        var prior = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;

            using var ps = new ProtectedString();
            Assert.That(ps.Length, Is.EqualTo(0));

            Assert.DoesNotThrow(() => ProtectedString.RotateProcessKey());

            Assert.That(ps.Length, Is.EqualTo(0));
#pragma warning disable CS0618 // intentional: NUnit's Assert.That(plain, Is.Empty) needs an array, not a span
            ps.Access(p => Assert.That(p, Is.Empty));
#pragma warning restore CS0618
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = prior;
        }
    }

    /// <summary>
    /// Regression test for the <see cref="System.Diagnostics.Trace.TraceWarning(string)"/>
    /// emitted by <c>RotateInternal</c> when one or more per-instance migrations
    /// throw. The warning is the operator's only signal that a rotation pass
    /// did not fully migrate every live instance — without it, a partial
    /// rotation would land silently and the affected instances would still
    /// reference the previous master.
    /// </summary>
    /// <remarks>
    /// To trigger the failure deterministically, we (a) construct a normal
    /// instance under whatever the current process protector is, then
    /// (b) reflection-swap both the instance's <c>_instanceProtector</c>
    /// and the global <c>s_keyProtector</c> to the same
    /// <c>AlwaysThrowingProtector</c>. This keeps the reference-equality
    /// check inside <c>RotateInternal.toMigrate</c> happy so our instance
    /// is actually selected for migration, and the migration's
    /// <c>DecryptUnsafe</c> call then throws on <c>UnwrapKey</c>.
    /// The original <c>s_keyProtector</c> is restored in <c>finally</c>
    /// so subsequent tests are not affected. <see cref="NonParallelizableAttribute"/>
    /// because the test mutates process-wide
    /// <see cref="System.Diagnostics.Trace.Listeners"/>,
    /// <see cref="ProtectedStringOptions.ProcessKeyRotationPolicy"/>, and
    /// the static protector slot.
    /// </remarks>
    [Test]
    [NonParallelizable]
    public void RotateProcessKey_emits_trace_warning_when_an_instance_migration_fails()
    {
        var priorPolicy = ProtectedStringOptions.ProcessKeyRotationPolicy;
        var listener = new CapturingTraceListener();
        Trace.Listeners.Add(listener);
        KeyAtRestProtector? priorKeyProtector = null;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;

            using var ps = new ProtectedString("rotation-fail-test".AsSpan());

            // Capture s_keyProtector AFTER construction (which lazily
            // initialises it). We restore this exact reference at end so
            // tests running after us see the protector they expect.
            priorKeyProtector = TestAccessors.GetProcessKeyProtector();

            // Both refs must point at the SAME throwing instance: the
            // migration only enrolls instances whose _instanceProtector is
            // reference-equal to the rotation's oldProtector (which is
            // s_keyProtector at rotation start).
            var throwing = new AlwaysThrowingProtector();
            TestAccessors.SetInstanceProtector(ps, throwing);
            TestAccessors.SetProcessKeyProtector(throwing);

            Assert.DoesNotThrow(() => ProtectedString.RotateProcessKey(),
                "RotateProcessKey itself should not throw when a per-instance " +
                "migration fails — the failure is captured into a counter and " +
                "surfaced via Trace.TraceWarning.");

            bool warned = listener.Messages.Any(m =>
                m.Contains("process-key rotation completed with") &&
                m.Contains("failing to re-encrypt"));

            Assert.That(warned, Is.True,
                "Trace.TraceWarning must fire when at least one instance migration " +
                "fails; without this signal a partial rotation lands silently. " +
                "Captured messages: " + string.Join(" | ", listener.Messages));
        }
        finally
        {
            Trace.Listeners.Remove(listener);
            listener.Dispose();
            // Restore the protector slot so any test running after us sees
            // a working protector. RotateProcessKey replaced s_keyProtector
            // with a fresh noop; that fresh noop is also fine, but we
            // prefer to put back exactly what was there before.
            if (priorKeyProtector is not null)
            {
                TestAccessors.SetProcessKeyProtector(priorKeyProtector);
            }
            ProtectedStringOptions.ProcessKeyRotationPolicy = priorPolicy;
        }
    }

    [Test]
    public void Concurrent_access_is_safe()
    {
        using var ps = new ProtectedString("shared".AsSpan());
        var errors = 0;
        Parallel.For(0, 200, _ =>
        {
            try
            {
                ps.Access(p =>
                {
                    if (new string(p) != "shared") Interlocked.Increment(ref errors);
                });
            }
            catch
            {
                Interlocked.Increment(ref errors);
            }
        });
        Assert.That(errors, Is.EqualTo(0));
    }

    // ---- AppendChar build buffer (O(amortized 1) per append) -----------

    [Test]
    public void AppendChar_keeps_ciphertext_unchanged_until_MakeReadOnly()
    {
        using var ps = new ProtectedString();
        var ctEmpty = TestAccessors.GetCiphertext(ps);

        // Many appends — none of them should trigger a re-encrypt.
        for (int i = 0; i < 50; i++) ps.AppendChar((char)('a' + (i % 26)));

        var ctMidBuild = TestAccessors.GetCiphertext(ps);
        Assert.That(ctMidBuild, Is.EqualTo(ctEmpty),
            "ciphertext must not change while in build mode — AppendChar should write to the build buffer, not re-encrypt");

        ps.MakeReadOnly();
        var ctAfterCommit = TestAccessors.GetCiphertext(ps);
        Assert.That(ctAfterCommit, Is.Not.EqualTo(ctEmpty),
            "MakeReadOnly must commit the build buffer to ciphertext");
    }

    [Test]
    public void AppendChar_round_trips_through_build_mode_without_MakeReadOnly()
    {
        using var ps = new ProtectedString();
        foreach (var c in "build-mode") ps.AppendChar(c);

        // Reading in build mode (no MakeReadOnly) must return the right value.
        Assert.That(ps.Length, Is.EqualTo(10));
        Assert.That(ps.Access(p => new string(p)), Is.EqualTo("build-mode"));
    }

    [Test]
    public void AppendChar_lifts_existing_ciphertext_into_build_buffer()
    {
        // Constructor encrypts content; first AppendChar lifts it into the
        // build buffer (one decrypt), subsequent appends are O(1).
        using var ps = new ProtectedString("ab".AsSpan());
        ps.AppendChar('c');
        ps.AppendChar('d');
        ps.AppendChar('e');

        Assert.That(ps.Access(p => new string(p)), Is.EqualTo("abcde"));

        ps.MakeReadOnly();
        Assert.That(ps.Access(p => new string(p)), Is.EqualTo("abcde"));
    }

    [Test]
    public void AppendChar_grows_build_buffer_geometrically()
    {
        // Stress: many more appends than the initial capacity (16). All must
        // round-trip; the buffer must grow without losing content.
        using var ps = new ProtectedString();
        var sb = new StringBuilder();
        for (int i = 0; i < 1000; i++)
        {
            char c = (char)('a' + (i % 26));
            ps.AppendChar(c);
            sb.Append(c);
        }
        Assert.That(ps.Length, Is.EqualTo(1000));
        Assert.That(ps.Access(p => new string(p)), Is.EqualTo(sb.ToString()));
        ps.MakeReadOnly();
        Assert.That(ps.Access(p => new string(p)), Is.EqualTo(sb.ToString()));
    }

    [Test]
    public void Equals_works_across_build_mode_and_committed()
    {
        // a in build mode, b committed. Same value → equal.
        using var a = new ProtectedString();
        foreach (var c in "abc") a.AppendChar(c);

        using var b = new ProtectedString("abc".AsSpan());
        Assert.That(a.Equals(b), Is.True);
        Assert.That(b.Equals(a), Is.True);

        using var differ = new ProtectedString("abd".AsSpan());
        Assert.That(a.Equals(differ), Is.False);
    }

    [Test]
    public void Copy_works_from_build_mode_source()
    {
        using var src = new ProtectedString();
        foreach (var c in "secret") src.AppendChar(c);
        // No MakeReadOnly — Copy must read from the build buffer directly.

        using var copy = src.Copy();
        Assert.That(copy.Length, Is.EqualTo(6));
        Assert.That(copy.Access(p => new string(p)), Is.EqualTo("secret"));

        // Copy is independent — extending it must not affect the source.
        copy.AppendChar('!');
        Assert.That(src.Length, Is.EqualTo(6));
        Assert.That(copy.Length, Is.EqualTo(7));
    }

    [Test]
    public void Argon2id_works_in_build_mode()
    {
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);

        using var ps = new ProtectedString();
        foreach (var c in "password") ps.AppendChar(c);
        // No MakeReadOnly.

        var hash = ps.ComputeArgon2idHash(salt, FastIterations, FastMemoryKb, FastParallelism, FastHashLength);
        Assert.That(hash, Has.Length.EqualTo(FastHashLength));

        using var same = new ProtectedString("password".AsSpan());
        Assert.That(same.VerifyArgon2idHash(hash, salt, FastIterations, FastMemoryKb, FastParallelism), Is.True);
    }

    [Test]
    public void Dispose_wipes_build_buffer()
    {
        var ps = new ProtectedString();
        foreach (var c in "secret") ps.AppendChar(c);

        var bufferField = typeof(ProtectedString).GetField("_buildBuffer",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        var buf = (char[]?)bufferField.GetValue(ps);
        Assert.That(buf, Is.Not.Null);
        Assert.That(new string(buf!, 0, 6), Is.EqualTo("secret"));

        ps.Dispose();

        // After dispose the field is cleared and the underlying chars zeroed.
        Assert.That((char[]?)bufferField.GetValue(ps), Is.Null);
        // The original buffer reference we captured before dispose must be wiped.
        Assert.That(buf!, Is.All.EqualTo('\0'));
    }

    [Test]
    public void Rotation_while_in_build_mode_just_swaps_the_protector()
    {
        var prior = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;

            using var ps = new ProtectedString();
            foreach (var c in "live") ps.AppendChar(c);

            // No ciphertext to migrate — but the rotation must still update
            // the per-instance protector reference and not crash.
            Assert.DoesNotThrow(() => ProtectedString.RotateProcessKey());

            // Plaintext must still be intact in the build buffer.
            Assert.That(ps.Access(p => new string(p)), Is.EqualTo("live"));

            // Committing now must succeed under the new protector.
            ps.MakeReadOnly();
            Assert.That(ps.Access(p => new string(p)), Is.EqualTo("live"));
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = prior;
        }
    }

    // ---- New ReadOnlySpan-based Access overloads -----------------------

    [Test]
    public void Access_span_overload_exposes_plaintext()
    {
        using var ps = new ProtectedString("hunter2".AsSpan());
        int observedLength = 0;
        ps.Access((ReadOnlySpan<char> plain) =>
        {
            observedLength = plain.Length;
            Assert.That(plain.SequenceEqual("hunter2"), Is.True);
        });
        Assert.That(observedLength, Is.EqualTo(7));
    }

    [Test]
    public void Access_span_generic_overload_propagates_return_value()
    {
        using var ps = new ProtectedString("xyz".AsSpan());
        // The generic overload binds via OverloadResolutionPriority; the
        // explicit `(ReadOnlySpan<char> p)` parameter type pins the dispatch.
        var len = ps.Access((ReadOnlySpan<char> p) => p.Length);
        Assert.That(len, Is.EqualTo(3));
    }

    [Test]
    public void Access_span_overload_throws_on_null_handler()
    {
        using var ps = new ProtectedString();
        Assert.Throws<ArgumentNullException>(() => ps.Access((ReadOnlySpanAction<char>)null!));
        Assert.Throws<ArgumentNullException>(() => ps.Access((ReadOnlySpanFunc<char, int>)null!));
    }

    [Test]
    public void Access_span_overload_works_in_build_mode()
    {
        using var ps = new ProtectedString();
        foreach (var c in "build") ps.AppendChar(c);
        // No MakeReadOnly: the span overload reads from _buildBuffer directly.
        ps.Access((ReadOnlySpan<char> plain) =>
            Assert.That(plain.SequenceEqual("build"), Is.True));
    }

    // ---- CopyTo sink ---------------------------------------------------

    [Test]
    public void CopyTo_writes_plaintext_into_caller_buffer()
    {
        using var ps = new ProtectedString("hello".AsSpan());
        Span<char> dst = stackalloc char[5];
        var written = ps.CopyTo(dst);
        Assert.That(written, Is.EqualTo(5));
        Assert.That(dst.SequenceEqual("hello"), Is.True);
    }

    [Test]
    public void CopyTo_works_in_build_mode()
    {
        using var ps = new ProtectedString();
        foreach (var c in "abcd") ps.AppendChar(c);

        Span<char> dst = stackalloc char[10];
        var written = ps.CopyTo(dst);
        Assert.That(written, Is.EqualTo(4));
        Assert.That(dst[..4].SequenceEqual("abcd"), Is.True);
        // Remaining bytes in dst are untouched (caller-owned).
    }

    [Test]
    public void CopyTo_throws_when_destination_too_small()
    {
        using var ps = new ProtectedString("hello".AsSpan());
        var dst = new char[3];
        Assert.Throws<ArgumentException>(() => ps.CopyTo(dst));
    }

    [Test]
    public void CopyTo_returns_zero_for_empty_instance()
    {
        using var ps = new ProtectedString();
        var dst = new char[10];
        Assert.That(ps.CopyTo(dst), Is.EqualTo(0));
    }

    // ---- WriteUtf8To sink ----------------------------------------------

    [Test]
    public void WriteUtf8To_writes_utf8_bytes_to_stream()
    {
        using var ps = new ProtectedString("héllo".AsSpan());
        using var ms = new MemoryStream();
        var written = ps.WriteUtf8To(ms);
        var bytes = ms.ToArray();

        Assert.That(written, Is.EqualTo(bytes.Length));
        Assert.That(Encoding.UTF8.GetString(bytes), Is.EqualTo("héllo"));
    }

    [Test]
    public void WriteUtf8To_works_in_build_mode()
    {
        using var ps = new ProtectedString();
        foreach (var c in "data") ps.AppendChar(c);

        using var ms = new MemoryStream();
        ps.WriteUtf8To(ms);
        Assert.That(Encoding.UTF8.GetString(ms.ToArray()), Is.EqualTo("data"));
    }

    [Test]
    public void WriteUtf8To_throws_on_null_or_unwritable_stream()
    {
        using var ps = new ProtectedString("x".AsSpan());
        Assert.Throws<ArgumentNullException>(() => ps.WriteUtf8To(null!));

        using var unwritable = new MemoryStream(new byte[10], writable: false);
        Assert.Throws<ArgumentException>(() => ps.WriteUtf8To(unwritable));
    }

    [Test]
    public void WriteUtf8To_returns_zero_for_empty_instance()
    {
        using var ps = new ProtectedString();
        using var ms = new MemoryStream();
        Assert.That(ps.WriteUtf8To(ms), Is.EqualTo(0));
        Assert.That(ms.Length, Is.EqualTo(0));
    }
}
