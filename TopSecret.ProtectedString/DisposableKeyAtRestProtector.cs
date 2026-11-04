using System.Security.Cryptography;

namespace TopSecret;

internal abstract class DisposableKeyAtRestProtector : KeyAtRestProtector, IDisposable
{
    protected const int MasterKeySize = 32;

    private const string UnwrappedKeyLockContext = "memory locking unwrapped key";

    private int _disposed;

    protected bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    protected void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(IsDisposed, this);

    public sealed override KeyAccessor UnwrapKey()
    {
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

    protected abstract KeyAccessor UnwrapCore();

    protected abstract void ReleaseResources();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        ReleaseResources();
        GC.SuppressFinalize(this);
    }

    ~DisposableKeyAtRestProtector()
    {
        try { Dispose(); } catch { }
    }

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
