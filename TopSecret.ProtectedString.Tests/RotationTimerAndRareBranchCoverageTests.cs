using System.Diagnostics;
using System.Reflection;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

[TestFixture]
[NonParallelizable] // Mutates process-global options, the rotation timer slot, and Trace listeners.
public class RotationTimerAndRareBranchCoverageTests
{
    // ---- reflection seams (same idiom as TestAccessors) ------------------

    private static FieldInfo StaticField(string name) =>
        typeof(ProtectedString).GetField(name, BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException($"Field {name} not found");

    private static MethodInfo StaticMethod(string name) =>
        typeof(ProtectedString).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException($"Method {name} not found");

    private static readonly FieldInfo s_rotationTimerField = StaticField("s_rotationTimer");
    private static readonly FieldInfo s_rotationInFlightField = StaticField("s_rotationInFlight");
    private static readonly FieldInfo s_rotationLockField = StaticField("s_rotationLock");
    private static readonly FieldInfo s_warnedTransientSlotField = StaticField("s_warnedTransientSlotRotation");
    private static readonly MethodInfo s_ensureTimerMethod = StaticMethod("EnsurePeriodicRotationTimer");
    private static readonly MethodInfo s_shouldWarnMethod = StaticMethod("ShouldWarnRotatingAgainstTransientSlotProvider");

    private static void DisposeAndClearRotationTimer()
    {
        var timer = (Timer?)s_rotationTimerField.GetValue(null);
        if (timer is not null)
        {
            using var drained = new ManualResetEvent(false);
            if (timer.Dispose(drained))
            {
                drained.WaitOne(TimeSpan.FromSeconds(10));
            }
            s_rotationTimerField.SetValue(null, null);
        }
    }

    private static bool WaitUntil(Func<bool> condition, TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (condition()) return true;
            Thread.Sleep(25);
        }
        return condition();
    }

    private sealed class ConcurrentCapturingTraceListener : TraceListener
    {
        private readonly object _gate = new();
        private readonly List<string> _messages = new();

        public override void Write(string? message) => Add(message);
        public override void WriteLine(string? message) => Add(message);

        private void Add(string? message)
        {
            if (string.IsNullOrEmpty(message)) return;
            lock (_gate) _messages.Add(message);
        }

        public bool AnyContains(string fragment)
        {
            lock (_gate) return _messages.Any(m => m.Contains(fragment));
        }

        public string Dump()
        {
            lock (_gate) return string.Join(" | ", _messages);
        }
    }

    [SetUp]
    public void Setup() => DisposeAndClearRotationTimer();

    [TearDown]
    public void Teardown() => DisposeAndClearRotationTimer();

    [Test]
    [NonParallelizable]
    public void Rotation_disposes_superseded_protector_when_last_holder_migrates()
    {
        var priorPolicy = ProtectedStringOptions.ProcessKeyRotationPolicy;
        var priorProtector = TestAccessors.GetProcessKeyProtector();
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;

            var master = GC.AllocateArray<byte>(32, pinned: true);
            System.Security.Cryptography.RandomNumberGenerator.Fill(master);
            var fresh = KeyAtRestProtectorFactory.Create(master);
            TestAccessors.SetProcessKeyProtector(fresh);

            using var ps = new ProtectedString("refcounted-rotation".AsSpan());

            ProtectedString.RotateProcessKey();

            Assert.That(IsProtectorDisposed(fresh), Is.True,
                "the superseded protector must be disposed as soon as its last holder " +
                "migrated — deterministically, not on some later GC");
            Assert.That(ps.Access(plain => new string(plain)), Is.EqualTo("refcounted-rotation"),
                "the migrated instance must decrypt under the new protector");
        }
        finally
        {
            TestAccessors.SetProcessKeyProtector(priorProtector);
            ProtectedStringOptions.ProcessKeyRotationPolicy = priorPolicy;
        }
    }

    [Test]
    [NonParallelizable]
    public void Rotation_keeps_superseded_protector_alive_while_a_holder_remains()
    {
        var priorPolicy = ProtectedStringOptions.ProcessKeyRotationPolicy;
        var priorProtector = TestAccessors.GetProcessKeyProtector();
        try
        {
            var master = GC.AllocateArray<byte>(32, pinned: true);
            System.Security.Cryptography.RandomNumberGenerator.Fill(master);
            var fresh = KeyAtRestProtectorFactory.Create(master);
            TestAccessors.SetProcessKeyProtector(fresh);

            // Constructed under Disabled ⇒ holds a reference but is not in
            // the rotation registry, so it will not be migrated.
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.Disabled;
            using var unregistered = new ProtectedString("pinned-holder".AsSpan());

            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;
            ProtectedString.RotateProcessKey();

            Assert.That(IsProtectorDisposed(fresh), Is.False,
                "a superseded protector with a live holder must stay undisposed");
            Assert.That(unregistered.Access(plain => new string(plain)), Is.EqualTo("pinned-holder"),
                "the unmigrated instance must still decrypt under the old protector");

            unregistered.Dispose();
            Assert.That(IsProtectorDisposed(fresh), Is.True,
                "disposing the last holder must dispose the superseded protector");
        }
        finally
        {
            TestAccessors.SetProcessKeyProtector(priorProtector);
            ProtectedStringOptions.ProcessKeyRotationPolicy = priorPolicy;
        }
    }

    private static bool IsProtectorDisposed(KeyAtRestProtector protector)
    {
        for (var t = protector.GetType(); t is not null; t = t.BaseType)
        {
            var field = t.GetField("_disposed", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            if (field is null) continue;
            return field.GetValue(protector) switch
            {
                bool b => b,
                int i => i != 0,
                var other => throw new InvalidOperationException($"unexpected _disposed type {other?.GetType().Name}"),
            };
        }
        throw new InvalidOperationException($"_disposed not found on {protector.GetType().Name} or its bases");
    }

    [Test]
    [NonParallelizable]
    public void Periodic_policy_starts_rotation_timer_whose_callback_rotates_and_logs_failures()
    {
        var priorPolicy = ProtectedStringOptions.ProcessKeyRotationPolicy;
        var priorInterval = ProtectedStringOptions.ProcessKeyRotationInterval;
        var listener = new ConcurrentCapturingTraceListener();
        Trace.Listeners.Add(listener);
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.Periodic;
            ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.FromMilliseconds(30);

            // Snapshot the protector BEFORE construction so a timer-driven
            // rotation is observable as a reference swap of the global slot.
            var protectorBefore = ProtectedString.GetOrInitProcessProtector();

            using var ps = new ProtectedString("periodic-timer".AsSpan());

            Assert.That(s_rotationTimerField.GetValue(null), Is.Not.Null,
                "constructing under ProcessKeyRotation.Periodic must start the rotation timer");

            // Success path of the callback: RotateProcessKey swaps s_keyProtector.
            bool rotated = WaitUntil(
                () => !ReferenceEquals(TestAccessors.GetProcessKeyProtector(), protectorBefore),
                TimeSpan.FromSeconds(15));
            Assert.That(rotated, Is.True,
                "the periodic timer callback should have performed at least one rotation");

            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.Disabled;
            bool logged = WaitUntil(
                () => listener.AnyContains("periodic rotation failed"),
                TimeSpan.FromSeconds(15));
            Assert.That(logged, Is.True,
                "a failing periodic rotation must be reported via Trace.TraceError, " +
                "not thrown on the timer thread. Captured: " + listener.Dump());

            // The migrated instance must still decrypt after the rotations.
            Assert.That(ps.Access(plain => new string(plain)), Is.EqualTo("periodic-timer"));
        }
        finally
        {
            DisposeAndClearRotationTimer();
            ProtectedStringOptions.ProcessKeyRotationPolicy = priorPolicy;
            ProtectedStringOptions.ProcessKeyRotationInterval = priorInterval;
            Trace.Listeners.Remove(listener);
            listener.Dispose();
        }
    }

    // Exercises ProtectedString.cs line 1329: EnsurePeriodicRotationTimer bails out
    // without creating a timer when ProcessKeyRotationInterval is non-positive.
    [Test]
    [NonParallelizable]
    public void EnsurePeriodicRotationTimer_does_not_start_a_timer_for_non_positive_interval()
    {
        var priorInterval = ProtectedStringOptions.ProcessKeyRotationInterval;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.Zero;

            s_ensureTimerMethod.Invoke(null, null);

            Assert.That(s_rotationTimerField.GetValue(null), Is.Null,
                "a non-positive rotation interval must leave the timer slot empty");
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationInterval = priorInterval;
        }
    }

    // Exercises ProtectedString.cs line 1327: the double-checked-locking early return when
    // another thread installs the timer while this one is blocked on s_rotationLock.
    [Test]
    [NonParallelizable]
    public void EnsurePeriodicRotationTimer_double_check_returns_when_timer_appears_under_the_lock()
    {
        var priorInterval = ProtectedStringOptions.ProcessKeyRotationInterval;
        var rotationLock = s_rotationLockField.GetValue(null)
            ?? throw new InvalidOperationException("s_rotationLock is null");
        Timer? dummy = null;
        try
        {
            // Long interval so the dummy/real timer could never actually fire.
            ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.FromHours(6);

            Task worker;
            Monitor.Enter(rotationLock);
            try
            {
                // Worker passes the lock-free fast check (timer is null),
                // then blocks on s_rotationLock, which we are holding.
                worker = Task.Run(() => s_ensureTimerMethod.Invoke(null, null));
                Thread.Sleep(250);

                // Install a timer while the worker waits, so its second
                // (under-lock) check sees a non-null slot and returns.
                dummy = new Timer(static _ => { }, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
                s_rotationTimerField.SetValue(null, dummy);
            }
            finally
            {
                Monitor.Exit(rotationLock);
            }

            Assert.That(worker.Wait(TimeSpan.FromSeconds(15)), Is.True,
                "EnsurePeriodicRotationTimer must return once the lock is released");
            Assert.That(s_rotationTimerField.GetValue(null), Is.SameAs(dummy),
                "the pre-installed timer must win; no second timer may be created");
        }
        finally
        {
            var current = (Timer?)s_rotationTimerField.GetValue(null);
            s_rotationTimerField.SetValue(null, null);
            current?.Dispose();
            if (dummy is not null && !ReferenceEquals(dummy, s_rotationTimerField.GetValue(null)))
            {
                dummy.Dispose();
            }
            ProtectedStringOptions.ProcessKeyRotationInterval = priorInterval;
        }
    }

    [Test]
    [NonParallelizable]
    public void Periodic_rotation_with_transient_slot_provider_emits_one_shot_trace_warning()
    {
        var priorMode = ProtectedStringOptions.KeyAtRestProtection;
        var priorInterval = ProtectedStringOptions.ProcessKeyRotationInterval;
        var priorWarned = (int)s_warnedTransientSlotField.GetValue(null)!;
        var listener = new CapturingTraceListener();
        Trace.Listeners.Add(listener);
        try
        {
            TestAccessors.ResetFactoryRegistrations();
            KeyAtRestProtectorFactory.RegisterHardwareBacked(
                factory: _ => null, // never actually constructs
                availabilityProbe: () => false,
                transientSlotConstrained: true);
            ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.HardwareBackedPreferred;
            ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.FromHours(6);
            s_warnedTransientSlotField.SetValue(null, 0);

            s_ensureTimerMethod.Invoke(null, null);

            Assert.That(s_rotationTimerField.GetValue(null), Is.Not.Null,
                "the timer must still be created; the warning is advisory");
            bool warned = listener.Messages.Any(m => m.Contains("TPM_RC_RESOURCES"));
            Assert.That(warned, Is.True,
                "enabling periodic rotation alongside a transient-slot-constrained " +
                "provider must emit the slot-exhaustion warning. Captured: " +
                string.Join(" | ", listener.Messages));

            // The gate is one-shot: a second evaluation must decline to warn.
            var secondPass = (bool)s_shouldWarnMethod.Invoke(null, null)!;
            Assert.That(secondPass, Is.False,
                "the transient-slot warning must fire at most once per process");
        }
        finally
        {
            DisposeAndClearRotationTimer();
            TestAccessors.ResetFactoryRegistrations();
            ProtectedStringOptions.KeyAtRestProtection = priorMode;
            ProtectedStringOptions.ProcessKeyRotationInterval = priorInterval;
            s_warnedTransientSlotField.SetValue(null, priorWarned);
            Trace.Listeners.Remove(listener);
            listener.Dispose();
        }
    }

    [Test]
    [NonParallelizable]
    public void RotateProcessKey_drops_the_call_when_another_rotation_is_in_flight()
    {
        var priorPolicy = ProtectedStringOptions.ProcessKeyRotationPolicy;
        try
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.OnDemand;
            using var ps = new ProtectedString("reentrancy-guard".AsSpan());
            var ciphertextBefore = TestAccessors.GetCiphertext(ps);
            var protectorBefore = TestAccessors.GetProcessKeyProtector();

            // Simulate a concurrent rotation holding the in-flight flag.
            s_rotationInFlightField.SetValue(null, 1);
            try
            {
                Assert.DoesNotThrow(() => ProtectedString.RotateProcessKey(),
                    "a reentrant rotation call must be dropped, not fail");
            }
            finally
            {
                s_rotationInFlightField.SetValue(null, 0);
            }

            Assert.That(TestAccessors.GetCiphertext(ps), Is.EqualTo(ciphertextBefore),
                "the dropped call must not have re-encrypted the instance");
            Assert.That(TestAccessors.GetProcessKeyProtector(), Is.SameAs(protectorBefore),
                "the dropped call must not have swapped the process protector");
        }
        finally
        {
            ProtectedStringOptions.ProcessKeyRotationPolicy = priorPolicy;
        }
    }

    [Test]
    public void GetOrInitProcessProtector_returns_the_stable_process_wide_protector()
    {
        var first = ProtectedString.GetOrInitProcessProtector();
        var second = ProtectedString.GetOrInitProcessProtector();

        Assert.That(first, Is.Not.Null);
        Assert.That(second, Is.SameAs(first),
            "repeated calls must hand out the same process-wide protector");
        Assert.That(TestAccessors.GetProcessKeyProtector(), Is.SameAs(first),
            "the accessor must expose the same reference as the s_keyProtector slot");
    }

    [Test]
    public void AppendChar_rethrows_and_leaves_instance_intact_when_lift_decrypt_fails()
    {
        var goodProtector = ProtectedString.GetOrInitProcessProtector();
        using var ps = new ProtectedString("lift-me".AsSpan());

        TestAccessors.SetInstanceProtector(ps, new AlwaysThrowingProtector());
        Assert.Throws<InvalidOperationException>(() => ps.AppendChar('!'),
            "the decrypt failure must propagate out of AppendChar");

        // Restore the real protector: the committed ciphertext was never
        // touched, so the original value must still round-trip.
        TestAccessors.SetInstanceProtector(ps, goodProtector);
        Assert.That(ps.Length, Is.EqualTo("lift-me".Length),
            "a failed lift must not change the logical length");
        Assert.That(ps.Access(plain => new string(plain)), Is.EqualTo("lift-me"),
            "a failed lift must leave the committed ciphertext decryptable");
    }

    // Exercises ProtectedString.cs lines 1538-1540: EncryptInternal's failure path zeroes
    // the not-yet-installed nonce/tag/ciphertext buffers when encryption throws mid-commit.
    [Test]
    public void MakeReadOnly_commit_failure_wipes_staged_buffers_and_is_retryable()
    {
        var goodProtector = ProtectedString.GetOrInitProcessProtector();
        using var ps = new ProtectedString();
        ps.AppendChar('a'); // empty instance: lift skips decrypt, so build mode works
        ps.AppendChar('b'); // even with the throwing protector swapped in later

        TestAccessors.SetInstanceProtector(ps, new AlwaysThrowingProtector());
        Assert.Throws<InvalidOperationException>(() => ps.MakeReadOnly(),
            "the commit encryption failure must propagate out of MakeReadOnly");
        Assert.That(ps.IsReadOnly, Is.False,
            "the read-only flag must not be set when the commit failed");

        // The build buffer survives a failed commit, so restoring a working
        // protector makes the same MakeReadOnly succeed.
        TestAccessors.SetInstanceProtector(ps, goodProtector);
        Assert.DoesNotThrow(() => ps.MakeReadOnly());
        Assert.That(ps.IsReadOnly, Is.True);
        Assert.That(ps.Access(plain => new string(plain)), Is.EqualTo("ab"));
    }

    [Test]
    public void Copy_of_empty_committed_instance_yields_an_independent_empty_copy()
    {
        using var ps = new ProtectedString();
        using var copy = ps.Copy();

        Assert.That(copy.Length, Is.EqualTo(0));
        Assert.That(copy, Is.Not.SameAs(ps));
        Assert.That(copy.IsReadOnly, Is.False, "copies are read-write by contract");
    }
}
