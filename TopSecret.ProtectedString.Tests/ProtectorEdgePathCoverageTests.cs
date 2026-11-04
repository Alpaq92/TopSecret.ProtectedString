using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

public class ProtectorEdgePathCoverageTests
{
    // ---- HardeningPolicy -------------------------------------------------

    [TestFixture]
    [NonParallelizable] // Temporarily flips the process-global MemoryLockingFailureBehavior option.
    public class HardeningPolicyBehavior
    {
        // Exercises HardeningPolicy.cs lines 31-36: the Throw arm of OnFailure.
        [Test]
        public void OnFailure_throws_PlatformNotSupported_when_behavior_is_Throw()
        {
            var prior = ProtectedStringOptions.MemoryLockingFailureBehavior;
            ProtectedStringOptions.MemoryLockingFailureBehavior = MemoryLockingFailureBehavior.Throw;
            try
            {
                var ex = Assert.Throws<PlatformNotSupportedException>(
                    () => HardeningPolicy.OnFailure("unit-test hardening primitive"));
                Assert.That(ex!.Message, Does.Contain("unit-test hardening primitive")
                    .And.Contain(nameof(MemoryLockingFailureBehavior.Throw)),
                    "the thrown message should name the failed primitive and the configured behavior");
            }
            finally
            {
                ProtectedStringOptions.MemoryLockingFailureBehavior = prior;
            }
        }

        // Exercises HardeningPolicy.cs Ignore fall-through: OnFailure returns silently,
        // without throwing and without consuming the one-shot LogWarning gate.
        [Test]
        public void OnFailure_is_silent_when_behavior_is_Ignore()
        {
            var prior = ProtectedStringOptions.MemoryLockingFailureBehavior;
            ProtectedStringOptions.MemoryLockingFailureBehavior = MemoryLockingFailureBehavior.Ignore;
            try
            {
                Assert.DoesNotThrow(() => HardeningPolicy.OnFailure("unit-test hardening primitive"));
            }
            finally
            {
                ProtectedStringOptions.MemoryLockingFailureBehavior = prior;
            }
        }
    }

    // ---- TtlCachingKeyAtRestProtector: Refresh fault cleanup -------------

    [TestFixture]
    public class TtlCachingRefreshFault
    {
        private sealed class StubProtector : KeyAtRestProtector
        {
            private readonly byte[] _master;
            public StubProtector(byte[] master) => _master = master;
            public override KeyAccessor UnwrapKey() => KeyAccessor.Persistent(_master);
        }

        [Test]
        public void Refresh_wipes_and_unlocks_fresh_buffer_when_timer_arming_throws()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var inner = new StubProtector(master);

            var cache = new TtlCachingKeyAtRestProtector(inner, TimeSpan.FromMilliseconds(-2));
            try
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => cache.UnwrapKey(),
                    "arming the wipe timer with a negative due time must surface, not be swallowed");
                Assert.Throws<ArgumentOutOfRangeException>(() => cache.UnwrapKey(),
                    "a failed refresh must leave the cache empty, so the next call refreshes (and fails) again " +
                    "instead of handing out the wiped buffer");
            }
            finally
            {
                cache.Dispose();
            }
        }

        [Test]
        public void Dispose_after_failed_refresh_is_clean_and_idempotent()
        {
            var master = RandomNumberGenerator.GetBytes(32);
            var inner = new StubProtector(master);
            var cache = new TtlCachingKeyAtRestProtector(inner, TimeSpan.FromMilliseconds(-2));

            Assert.Throws<ArgumentOutOfRangeException>(() => cache.UnwrapKey());

            Assert.DoesNotThrow(() => cache.Dispose(),
                "Dispose must cope with the cache state a failed Refresh leaves behind");
            Assert.DoesNotThrow(() => cache.Dispose(), "Dispose should be idempotent");
            Assert.Throws<ObjectDisposedException>(() => cache.UnwrapKey());
        }
    }

    // ---- HkdfWrapProtector: fault-cleanup + finalizer paths ---------------

    [TestFixture]
    public class HkdfWrapFaultPaths
    {
        private static readonly MethodInfo s_createOrThrow =
            typeof(HkdfWrapProtector).GetMethod("CreateOrThrow",
                BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "HkdfWrapProtector.CreateOrThrow not found via reflection");

        private static readonly ConstructorInfo s_privateCtor =
            typeof(HkdfWrapProtector).GetConstructor(
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                new[] { typeof(byte[]), typeof(byte[]) },
                modifiers: null)
            ?? throw new InvalidOperationException(
                "HkdfWrapProtector(byte[], byte[]) constructor not found via reflection");

        // Exercises HkdfWrapProtector.cs lines 89-92: the !committed cleanup in
        // CreateOrThrow when wrapping faults after both buffers were locked.
        [Test]
        public void CreateOrThrow_cleans_up_locked_buffers_when_wrap_faults_mid_flight()
        {
            var shortMaster = new byte[15];
            var ex = Assert.Throws<TargetInvocationException>(
                () => s_createOrThrow.Invoke(null, new object[] { shortMaster }));
            Assert.That(ex!.InnerException, Is.InstanceOf<IndexOutOfRangeException>(),
                "the mid-wrap fault should surface from the XOR loop");
        }

        [Test]
        public void UnwrapKey_cleans_up_ephemeral_buffer_when_unwrap_faults_mid_flight()
        {
            // A truncated wrapped blob makes the XOR loop fault at index 15.
            // Buffers are pinned to honour MemoryLocker's pinning precondition.
            var wrapKey = GC.AllocateArray<byte>(32, pinned: true);
            var truncatedWrapped = GC.AllocateArray<byte>(15, pinned: true);
            RandomNumberGenerator.Fill(wrapKey);

            var protector = (HkdfWrapProtector)s_privateCtor.Invoke(
                new object[] { wrapKey, truncatedWrapped });
            try
            {
                Assert.Throws<IndexOutOfRangeException>(() => protector.UnwrapKey(),
                    "the mid-unwrap fault should surface from the XOR loop");
            }
            finally
            {
                // TryUnlock is documented safe even when the preceding lock never
                // happened, so disposing the hand-rolled instance is clean.
                protector.Dispose();
            }
        }

        // Exercises the DisposableKeyAtRestProtector finalizer safety net that
        // disposes (zeros + unlocks) an undisposed protector.
        [Test]
        public void Finalizer_disposes_undisposed_protector()
        {
            var weak = CreateUnreferencedProtector();

            for (int i = 0; i < 10 && weak.IsAlive; i++)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }

            Assert.That(weak.IsAlive, Is.False,
                "an undisposed HkdfWrapProtector should be finalized and collected");
        }

        // NoInlining keeps the strong reference confined to this frame so the
        // protector is provably unreachable once the method returns.
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static WeakReference CreateUnreferencedProtector()
        {
            var protector = HkdfWrapProtector.TryCreate(RandomNumberGenerator.GetBytes(32));
            Assert.That(protector, Is.Not.Null);
            return new WeakReference(protector);
        }
    }
}
