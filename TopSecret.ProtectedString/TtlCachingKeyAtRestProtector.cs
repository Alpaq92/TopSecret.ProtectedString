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
/// <b>Lifetime contract — no finalizer.</b> Unlike the other protectors,
/// this decorator deliberately has no finalizer. The wipe-timer it creates
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
/// </remarks>
internal sealed class TtlCachingKeyAtRestProtector : KeyAtRestProtector, IDisposable
{
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

        byte[] snapshot;
        int snapshotLength;
        lock (_cacheLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            var nowMs = Environment.TickCount64;
            if (_cachedKey is null || nowMs >= _expiryTickMs)
            {
                Refresh(nowMs);
            }

            snapshot = _cachedKey!;
            snapshotLength = snapshot.Length;
        }

        // Hand back an ephemeral copy so the caller's existing
        // KeyAccessor.Dispose contract holds (zero + unlock on dispose) and
        // we never expose the long-lived cache buffer to caller code.
        var ephemeral = GC.AllocateArray<byte>(snapshotLength, pinned: true);
        if (snapshotLength > 0 && !MemoryLocker.TryLock(ephemeral))
        {
            HardeningPolicy.OnFailure("memory locking unwrapped key");
        }

        bool ok = false;
        try
        {
            Array.Copy(snapshot, ephemeral, snapshotLength);
            ok = true;
            return KeyAccessor.Ephemeral(ephemeral);
        }
        finally
        {
            if (!ok && snapshotLength > 0)
            {
                CryptographicOperations.ZeroMemory(ephemeral);
                MemoryLocker.TryUnlock(ephemeral);
            }
        }
    }

    private void Refresh(long nowMs)
    {
        // Caller holds _cacheLock.
        WipeCachedLocked();

        using var unwrapped = _inner.UnwrapKey();
        int len = unwrapped.Key.Length;
        var fresh = GC.AllocateArray<byte>(len, pinned: true);
        if (len > 0 && !MemoryLocker.TryLock(fresh))
        {
            HardeningPolicy.OnFailure("memory locking cached unwrapped key");
        }

        bool ok = false;
        try
        {
            Array.Copy(unwrapped.Key, fresh, len);
            _cachedKey = fresh;
            _expiryTickMs = nowMs + (long)_ttl.TotalMilliseconds;

            _wipeTimer ??= new Timer(static state => ((TtlCachingKeyAtRestProtector)state!).TryWipeIfExpired(),
                this, Timeout.Infinite, Timeout.Infinite);
            _wipeTimer.Change(_ttl, Timeout.InfiniteTimeSpan);

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
                // Another UnwrapKey call refreshed the cache after this
                // timer was scheduled; reschedule for the new expiry.
                _wipeTimer?.Change(TimeSpan.FromMilliseconds(_expiryTickMs - nowMs), Timeout.InfiniteTimeSpan);
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
