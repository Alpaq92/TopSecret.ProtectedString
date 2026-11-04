using System.Security.Cryptography;

namespace TopSecret;

/// <summary>
/// Shared base for every <see cref="KeyAtRestProtector"/> that owns
/// resources — locked buffers, native key handles, secure-element slots —
/// and therefore needs a disposal story. Centralises the pieces every
/// concrete protector used to re-implement by hand: the thread-safe
/// disposed flag, the <see cref="UnwrapKey"/> disposed-check, the
/// finalizer-safety <see cref="GC.KeepAlive(object)"/>, once-only
/// <see cref="Dispose"/>, the finalizer safety net, and the
/// allocate-pinned-locked-copy tail that turns an unwrapped plaintext into
/// an <see cref="KeyAccessor.Ephemeral(byte[])"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Disposed check-then-use.</b> <see cref="UnwrapKey"/> reads the
/// disposed flag once, up front, and then runs <see cref="UnwrapCore"/>
/// without re-checking. That is only sound because the one production
/// caller of <see cref="Dispose"/> — <see cref="ProtectorLifetime"/> —
/// guarantees no <c>Dispose</c> while a holder is inside <c>UnwrapKey</c>:
/// a protector is disposed only once it has been superseded by a rotation
/// <i>and</i> its holder count has dropped to zero, and every
/// <see cref="ProtectedString"/> / <c>ProtectedBlob</c> that could call
/// <c>UnwrapKey</c> holds a reference until it is itself disposed. A
/// concrete protector whose <see cref="UnwrapCore"/> cannot tolerate a
/// concurrent <see cref="ReleaseResources"/> for other reasons (an
/// in-process page that is unmapped, a shared command pipe to a TPM)
/// still serialises those two internally — see
/// <see cref="PageGuardedKeyProtector"/> — but the base contract does not
/// require it.
/// </para>
/// <para>
/// <b>Finalizer safety.</b> <see cref="UnwrapKey"/> wraps
/// <see cref="UnwrapCore"/> in <c>try/finally { GC.KeepAlive(this); }</c>.
/// Without it, the JIT may treat <c>this</c> as dead as soon as the last
/// field read has been issued, and the finalizer could run — releasing a
/// Secure Enclave key reference, deleting a Keystore alias, flushing a TPM
/// handle, unmapping the guarded page — while the native round-trip or
/// the copy out of that resource is still in flight.
/// </para>
/// </remarks>
internal abstract class DisposableKeyAtRestProtector : KeyAtRestProtector, IDisposable
{
    /// <summary>Length of the AES-256 master every protector wraps.</summary>
    protected const int MasterKeySize = 32;

    private const string UnwrappedKeyLockContext = "memory locking unwrapped key";

    // 0 = live, 1 = disposed. Interlocked so Dispose is once-only even when
    // ProtectorLifetime.Release and ProtectorLifetime.MarkSuperseded race
    // each other, and so the finalizer cannot double-release.
    private int _disposed;

    /// <summary>Whether <see cref="Dispose"/> has run (or is running).</summary>
    protected bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>Throws <see cref="ObjectDisposedException"/> once disposed.</summary>
    protected void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(IsDisposed, this);

    /// <inheritdoc/>
    /// <remarks>
    /// Sealed: the disposed guard and the <see cref="GC.KeepAlive(object)"/>
    /// are the contract this base exists to enforce. Implement
    /// <see cref="UnwrapCore"/> instead.
    /// </remarks>
    public sealed override KeyAccessor UnwrapKey()
    {
        // Load-bearing since ProtectorLifetime made disposal deterministic:
        // without this guard a lifetime-accounting bug would hand back a
        // zeroed master (or hit a freed handle) and encrypt silently under
        // an all-zero key instead of failing loudly.
        //
        // Check-then-use without a lock: this single up-front read is
        // sufficient only because ProtectorLifetime guarantees Dispose is
        // never called while a holder is inside UnwrapKey (a protector is
        // disposed only after it was superseded AND its holder count hit
        // zero, and every holder keeps its reference for as long as it can
        // call UnwrapKey). See the class remarks.
        ThrowIfDisposed();
        try
        {
            return UnwrapCore();
        }
        finally
        {
            GC.KeepAlive(this);
        }
    }

    /// <summary>
    /// Unwraps the master. Called only while not disposed; <c>this</c> is
    /// guaranteed reachable for the whole call.
    /// </summary>
    protected abstract KeyAccessor UnwrapCore();

    /// <summary>
    /// Releases everything the protector owns: zero wrapped blobs and wrap
    /// keys, unlock buffers, free native handles / secure-element slots.
    /// Called exactly once, from <see cref="Dispose"/> or the finalizer.
    /// Must not throw from the finalizer path; the base swallows there.
    /// </summary>
    protected abstract void ReleaseResources();

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        ReleaseResources();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Safety net for an undisposed protector — one the caller forgot to
    /// dispose, or one that fell out of every reference without going
    /// through <see cref="ProtectorLifetime"/>. Bounds the
    /// <c>RLIMIT_MEMLOCK</c> / working-set growth of locked pages and the
    /// transient-slot consumption of TPM / Secure Element keys.
    /// </summary>
    ~DisposableKeyAtRestProtector()
    {
        try { Dispose(); } catch { /* finalizer must not throw */ }
    }

    /// <summary>
    /// Copies <paramref name="plaintext"/> into a freshly allocated pinned,
    /// locked, dump-excluded buffer and wraps it as an
    /// <see cref="KeyAccessor.Ephemeral(byte[])"/> that zeros and unlocks
    /// the buffer on dispose. On any failure after allocation the buffer is
    /// zeroed and unlocked before the exception propagates. The caller
    /// remains responsible for wiping <paramref name="plaintext"/>.
    /// </summary>
    /// <param name="plaintext">The unwrapped master.</param>
    /// <param name="lockContext">
    /// Noun phrase interpolated into the hardening-policy failure message
    /// should the residency lock fail.
    /// </param>
    /// <remarks>
    /// <c>protected internal</c> rather than <c>protected</c> so
    /// <see cref="TtlCachingKeyAtRestProtector"/> — which deliberately does
    /// not derive from this base (it has no finalizer by design) — can share
    /// the one allocate/copy/wipe-on-failure implementation.
    /// </remarks>
    protected internal static KeyAccessor EphemeralFrom(
        ReadOnlySpan<byte> plaintext, string lockContext = UnwrappedKeyLockContext)
    {
        var buffer = ProtectedString.AllocatePinnedBytes(
            plaintext.Length, excludeFromDumps: true, lockContext: lockContext);
        try
        {
            plaintext.CopyTo(buffer);
            return KeyAccessor.Ephemeral(buffer);
        }
        catch
        {
            if (buffer.Length > 0)
            {
                CryptographicOperations.ZeroMemory(buffer);
                MemoryLocker.TryUnlock(buffer);
            }
            throw;
        }
    }

    /// <summary>
    /// The shared <c>TryCreate</c> shape: declines (returns
    /// <see langword="null"/>, master untouched) for anything but a
    /// <see cref="MasterKeySize"/>-byte master, otherwise runs
    /// <paramref name="createOrThrow"/> and maps any exception to
    /// <see langword="null"/> so <see cref="KeyAtRestProtectorFactory"/> can
    /// fall back to the next tier. <paramref name="createOrThrow"/> owns the
    /// zero-the-master-on-success contract.
    /// </summary>
    protected static T? TryCreate<T>(byte[] master, Func<byte[], T> createOrThrow) where T : class
    {
        if (master.Length != MasterKeySize) return null;
        try
        {
            return createOrThrow(master);
        }
        catch
        {
            return null;
        }
    }
}
