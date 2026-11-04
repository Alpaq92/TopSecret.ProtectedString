using System.Security.Cryptography;

namespace TopSecret;

/// <summary>
/// Decorator that caches the unwrapped master from another
/// <see cref="KeyAtRestProtector"/> in a pinned, locked, dump-excluded buffer
/// for at most a configurable TTL, amortising the per-op round-trip to a
/// secure element (Apple SEP, Android Keystore, Windows TPM) on hot paths.
/// </summary>
/// <remarks>
/// <para>
/// Wired in by <see cref="KeyAtRestProtectorFactory.Create"/> when
/// <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/> is greater than
/// <see cref="TimeSpan.Zero"/> and the chosen inner protector is not the
/// no-op. Caller-facing semantics of <see cref="UnwrapKey"/> are unchanged:
/// the returned <see cref="KeyAccessor"/> is always
/// <see cref="KeyAccessor.Ephemeral(byte[])"/> over a freshly allocated /
/// pinned / locked buffer that the caller must dispose. The cache only
/// avoids the round-trip to the inner protector — it does not expose the
/// cached buffer directly.
/// </para>
/// <para>
/// <b>Threat-model trade-off.</b> Caching widens the window in which the
/// unwrapped master sits in process memory beyond the in-flight
/// <see cref="ProtectedString.Access(System.Action{char[]})"/> window the
/// library already accepts. Choose a TTL that does not materially extend
/// it. Default is off because there is no universally safe value.
/// </para>
/// <para>
/// <b>Concurrency.</b> Every <see cref="UnwrapKey"/> call — including cache
/// hits — serialises through a single <c>_cacheLock</c>. The hit path is a
/// 32-byte memcpy plus a pinned-buffer allocation, so the contention window
/// is microseconds, but workloads with heavy parallel
/// <see cref="ProtectedString.Access(System.Action{char[]})"/> against a
/// single <see cref="ProtectedString"/> will serialise here. A lock-free
/// snapshot path is possible but trades subtle memory-ordering complexity
/// for marginal wins; if you measure contention in practice, please file an
/// issue.
/// </para>
/// <para>
/// <b>Lifetime contract — no finalizer.</b> Unlike the other protectors
/// (which derive from <see cref="DisposableKeyAtRestProtector"/>), this
/// decorator deliberately has no finalizer. The wipe-timer it creates
/// in <see cref="UnwrapKey"/> captures <c>this</c> as its
/// <see cref="System.Threading.Timer"/> state, and the runtime's timer
/// queue holds the timer strongly. Once the timer is armed, the decorator
/// is reachable for the lifetime of the timer regardless of caller
/// references — a finalizer would never fire while there's locked /
/// pinned memory to wipe. The supported lifetime model is therefore:
/// <see cref="KeyAtRestProtectorFactory.Create"/> caches one of these in
/// <see cref="ProtectedString"/>'s static protector slot for the lifetime
/// of the process; explicit <see cref="Dispose"/> is reserved for tests
/// and composition-root teardown. If you ever construct one outside the
/// factory, you are responsible for calling <see cref="Dispose"/>.
/// </para>
/// <para>
/// <b>Timer horizon.</b> <see cref="System.Threading.Timer"/> rejects due
/// times above <see cref="MaxTimerDueMs"/> (≈49.7 days). A longer TTL is
/// honoured logically — the expiry tick is computed from the full TTL —
/// while the wipe timer is armed in <see cref="MaxTimerDueMs"/> hops and
/// simply re-arms when it fires early (see <see cref="TryWipeIfExpired"/>).
/// </para>
/// </remarks>
internal sealed class TtlCachingKeyAtRestProtector : KeyAtRestProtector, IDisposable
{
    /// <summary>
    /// Largest due time <see cref="Timer.Change(TimeSpan, TimeSpan)"/> accepts:
    /// <c>uint.MaxValue - 1</c> milliseconds.
    /// </summary>
    internal const long MaxTimerDueMs = 4294967294L;

    private readonly KeyAtRestProtector _inner;
    private readonly TimeSpan _ttl;
    private readonly object _cacheLock = new();
    private byte[]? _cachedKey;
    private long _expiryTickMs;
    private Timer? _wipeTimer;
    private bool _disposed;

    public TtlCachingKeyAtRestProtector(KeyAtRestProtector inner, TimeSpan ttl)
    {
        _inner = inner;
        _ttl = ttl;
    }

    public override KeyAccessor UnwrapKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        lock (_cacheLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            var nowMs = Environment.TickCount64;
            if (_cachedKey is null || nowMs >= _expiryTickMs)
            {
                Refresh(nowMs);
            }

            // Hand back an ephemeral copy so the caller's existing
            // KeyAccessor.Dispose contract holds (zero + unlock on dispose)
            // and we never expose the long-lived cache buffer to caller
            // code. Both the allocation and the copy stay under _cacheLock:
            // the wipe timer zeroes _cachedKey in place, so copying outside
            // the lock could hand the caller an all-zero or torn key when
            // the TTL expires in exactly that window — a silent
            // encrypt-under-wrong-key data-loss path. Refresh already
            // allocates under this lock, so the cost profile is unchanged.
            return DisposableKeyAtRestProtector.EphemeralFrom(_cachedKey!);
        }
    }

    private void Refresh(long nowMs)
    {
        // Caller holds _cacheLock.
        WipeCachedLocked();

        using var unwrapped = _inner.UnwrapKey();
        int len = unwrapped.Key.Length;
        var fresh = ProtectedString.AllocatePinnedBytes(
            len, excludeFromDumps: true, lockContext: "memory locking cached unwrapped key");

        bool ok = false;
        try
        {
            Array.Copy(unwrapped.Key, fresh, len);

            // Arm the timer BEFORE publishing the new cache entry. Timer.Change
            // can throw (a due time outside [-1, MaxTimerDueMs] ms); if it
            // does, the finally below wipes `fresh` and _cachedKey is still
            // null from WipeCachedLocked above — so the next UnwrapKey
            // refreshes again instead of handing out the wiped (all-zero)
            // buffer under a far-future expiry.
            long expiry = nowMs + (long)_ttl.TotalMilliseconds;
            _wipeTimer ??= new Timer(static state => ((TtlCachingKeyAtRestProtector)state!).TryWipeIfExpired(),
                this, Timeout.Infinite, Timeout.Infinite);
            ArmWipeTimer((long)_ttl.TotalMilliseconds);

            // Publish last: both fields flip together under _cacheLock, after
            // every throwing operation has completed.
            _cachedKey = fresh;
            _expiryTickMs = expiry;
            ok = true;
        }
        finally
        {
            if (!ok && len > 0)
            {
                CryptographicOperations.ZeroMemory(fresh);
                MemoryLocker.TryUnlock(fresh);
            }
        }
    }

    /// <summary>
    /// Arms the wipe timer for <paramref name="dueMs"/> clamped to the
    /// <see cref="Timer"/> maximum. Negative values are passed through so a
    /// genuinely invalid TTL still surfaces as
    /// <see cref="ArgumentOutOfRangeException"/> rather than being masked.
    /// Caller holds <c>_cacheLock</c> and has created <c>_wipeTimer</c>.
    /// </summary>
    private void ArmWipeTimer(long dueMs)
    {
        _wipeTimer!.Change(
            TimeSpan.FromMilliseconds(Math.Min(dueMs, MaxTimerDueMs)),
            Timeout.InfiniteTimeSpan);
    }

    private void TryWipeIfExpired()
    {
        lock (_cacheLock)
        {
            if (_disposed || _cachedKey is null) return;
            var nowMs = Environment.TickCount64;
            if (nowMs >= _expiryTickMs)
            {
                WipeCachedLocked();
            }
            else
            {
                // Either another UnwrapKey call refreshed the cache after this
                // timer was scheduled, or the TTL exceeds the Timer horizon
                // and this is an intermediate hop; reschedule for the (clamped)
                // remaining time.
                ArmWipeTimer(_expiryTickMs - nowMs);
            }
        }
    }

    private void WipeCachedLocked()
    {
        // Caller holds _cacheLock.
        if (_cachedKey is null) return;
        if (_cachedKey.Length > 0)
        {
            CryptographicOperations.ZeroMemory(_cachedKey);
            MemoryLocker.TryUnlock(_cachedKey);
        }
        _cachedKey = null;
        _expiryTickMs = 0;
    }

    public void Dispose()
    {
        // No finalizer (see class-level "Lifetime contract" remark): the
        // armed Timer's strong reference to `this` defeats finalization
        // anyway, so a finalizer would only ever fire when there's
        // nothing to clean up. Explicit Dispose is the only path; the
        // factory-cached singleton lives until process exit.
        Timer? timer;
        lock (_cacheLock)
        {
            if (_disposed) return;
            _disposed = true;
            WipeCachedLocked();
            timer = _wipeTimer;
            _wipeTimer = null;
        }
        // Dispose the timer outside the lock: Timer.Dispose can synchronise
        // with the callback thread, which itself wants _cacheLock.
        timer?.Dispose();
        if (_inner is IDisposable d) d.Dispose();
    }
}
