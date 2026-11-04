using System.Security.Cryptography;

namespace TopSecret;

internal sealed class TtlCachingKeyAtRestProtector : KeyAtRestProtector, IDisposable
{
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
