using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TopSecret.Cryptography;

namespace TopSecret;

public sealed partial class ProtectedString : IDisposable, IEquatable<ProtectedString>
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;

    public const int DefaultArgon2idIterations = 3;
    public const int DefaultArgon2idMemoryKb = 19_456;
    public const int DefaultArgon2idParallelism = 1;
    public const int DefaultArgon2idHashLength = 32;

    private static volatile KeyAtRestProtector? s_keyProtector;

    internal static bool IsKeyProtectorInitialized => s_keyProtector is not null;

    private static readonly object s_rotationLock = new();

    private static readonly List<WeakReference<ProtectedString>> s_liveInstances = new();

    private static int s_rotationInFlight;

    private static Timer? s_rotationTimer;

    private static long s_lastInstanceId;

    private byte[]? _ciphertext;
    private byte[]? _nonce;
    private byte[]? _tag;
    private int _length;
    private bool _readOnly;
    private volatile bool _disposed;
    private readonly object _sync = new();

    private char[]? _buildBuffer;

    private const int BuildBufferInitialCapacity = 16;

    private KeyAtRestProtector _instanceProtector = null!;

    private readonly long _instanceId = Interlocked.Increment(ref s_lastInstanceId);

    public ProtectedString()
    {
        InitInstance();
        EncryptInternal(ReadOnlySpan<char>.Empty);
        RegisterForRotation();
    }

    public ProtectedString(ReadOnlySpan<char> value)
    {
        InitInstance();
        EncryptInternal(value);
        RegisterForRotation();
    }

    public ProtectedString(char[] value, bool clearSource = false)
    {
        ArgumentNullException.ThrowIfNull(value);
        InitInstance();
        try
        {
            EncryptInternal(value);
        }
        finally
        {
            if (clearSource && value.Length > 0)
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(value.AsSpan()));
            }
        }
        RegisterForRotation();
    }

    private void InitInstance()
    {
        _instanceProtector = SnapshotProtectorWithRef();
    }

    private void RegisterForRotation()
    {
        var policy = ProtectedStringOptions.ProcessKeyRotationPolicy;
        if (policy == ProcessKeyRotation.Disabled) return;

        lock (s_rotationLock)
        {
            if ((++s_addsSincePrune & 63) == 0)
            {
                PruneDeadInstancesLocked();
            }
            s_liveInstances.Add(new WeakReference<ProtectedString>(this));
        }

        if (policy == ProcessKeyRotation.Periodic)
        {
            EnsurePeriodicRotationTimer();
        }
    }

    private static int s_addsSincePrune;

    private static void PruneDeadInstancesLocked()
    {
        for (int i = s_liveInstances.Count - 1; i >= 0; i--)
        {
            if (!s_liveInstances[i].TryGetTarget(out _))
            {
                s_liveInstances.RemoveAt(i);
            }
        }
    }

    private static KeyAtRestProtector SnapshotProtectorWithRef()
    {
        while (true)
        {
            var p = GetOrInitProtectorUnlocked();
            ProtectorLifetime.AddRef(p);
            if (ReferenceEquals(p, s_keyProtector))
            {
                return p;
            }
            ProtectorLifetime.Release(p);
        }
    }

    private static KeyAtRestProtector GetOrInitProtectorUnlocked()
    {
        var p = s_keyProtector;
        if (p is not null) return p;
        lock (s_rotationLock) return GetOrInitProtectorLocked();
    }

    internal static KeyAtRestProtector GetOrInitProcessProtector() => SnapshotProtectorWithRef();

    private static KeyAtRestProtector GetOrInitProtectorLocked()
    {
        // Caller must hold s_rotationLock.
        var p = s_keyProtector;
        if (p is not null) return p;
        var master = GC.AllocateArray<byte>(KeySize, pinned: true);
        RandomNumberGenerator.Fill(master);
        s_keyProtector = KeyAtRestProtectorFactory.Create(master);
        return s_keyProtector;
    }

    public ProtectedString(string value) : this((value ?? throw new ArgumentNullException(nameof(value))).AsSpan()) { }

    public int Length
    {
        get
        {
            ThrowIfDisposed();
            return _length;
        }
    }

    public bool IsReadOnly
    {
        get
        {
            ThrowIfDisposed();
            return _readOnly;
        }
    }

    public bool IsDisposed => _disposed;

    public static HardwareBackedAvailability HardwareBackedAvailability =>
        KeyAtRestProtectorFactory.IsHardwareBackedAvailableForCurrentPlatform()
            ? HardwareBackedAvailability.Available
            : HardwareBackedAvailability.NoProviderForThisPlatform;

    public void MakeReadOnly()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            CommitBuildBuffer();
            _readOnly = true;
        }
    }

    public void AppendChar(char c) => AppendChars([c]);

    public void AppendChars(ReadOnlySpan<char> value)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_readOnly)
            {
                throw new InvalidOperationException("ProtectedString is read-only.");
            }
            if (value.IsEmpty) return;

            int required = checked(_length + value.Length);
            if (_buildBuffer is null)
            {
                LiftIntoBuildBuffer(required);
            }
            else if (required > _buildBuffer.Length)
            {
                if (value.Overlaps(_buildBuffer))
                {
                    var stage = LockedScratchPool.Rent(checked(value.Length * 2));
                    try
                    {
                        var copy = stage.Chars(value.Length);
                        value.CopyTo(copy);
                        GrowBuildBuffer(Math.Max(required, checked(_buildBuffer.Length * 2)));
                        copy.CopyTo(_buildBuffer.AsSpan(_length));
                        _length = required;
                        return;
                    }
                    finally
                    {
                        stage.Return();
                    }
                }
                GrowBuildBuffer(Math.Max(required, checked(_buildBuffer.Length * 2)));
            }

            // Same-array overlap without growth is safe: Span.CopyTo has
            // memmove semantics.
            value.CopyTo(_buildBuffer.AsSpan(_length));
            _length = required;
        }
    }

    public void AppendUtf8(ReadOnlySpan<byte> utf8)
    {
        if (utf8.IsEmpty)
        {
            // Preserve the disposed / read-only contract even for an empty append.
            lock (_sync)
            {
                ThrowIfDisposed();
                if (_readOnly) throw new InvalidOperationException("ProtectedString is read-only.");
            }
            return;
        }

        var lease = LockedScratchPool.Rent(checked(utf8.Length * 2));
        try
        {
            var chars = lease.Chars(utf8.Length);
            int written = s_strictUtf8.GetChars(utf8, chars);
            AppendChars(chars[..written]);
        }
        finally
        {
            lease.Return();
        }
    }

    private static readonly UTF8Encoding s_strictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static ProtectedString FromUtf8(ReadOnlySpan<byte> utf8)
    {
        var ps = new ProtectedString();
        try
        {
            ps.AppendUtf8(utf8);
            ps.MakeReadOnly();
            return ps;
        }
        catch
        {
            ps.Dispose();
            throw;
        }
    }

    public static ProtectedString Build(Action<ProtectedString> fill)
    {
        ArgumentNullException.ThrowIfNull(fill);
        var ps = new ProtectedString();
        try
        {
            fill(ps);
            ps.MakeReadOnly();
            return ps;
        }
        catch
        {
            ps.Dispose();
            throw;
        }
    }

    private void LiftIntoBuildBuffer(int minimumCapacity)
    {
        Debug.Assert(_buildBuffer is null, "build buffer already allocated");

        int capacity = Math.Max(BuildBufferInitialCapacity, minimumCapacity);
        var buffer = AllocatePinnedChars(capacity);

        if (_length > 0)
        {
            try
            {
                // Decrypt straight into the front of the new build buffer —
                // no intermediate copy.
                DecryptInto(buffer.AsSpan(0, _length));
            }
            catch
            {
                ZeroChars(buffer);
                throw;
            }
        }

        _buildBuffer = buffer;
    }

    private void GrowBuildBuffer(int newCapacity)
    {
        Debug.Assert(_buildBuffer is not null);
        Debug.Assert(newCapacity > _buildBuffer.Length);

        var grown = AllocatePinnedChars(newCapacity);
        _buildBuffer.AsSpan(0, _length).CopyTo(grown);
        ZeroChars(_buildBuffer);
        _buildBuffer = grown;
    }

    private void CommitBuildBuffer()
    {
        if (_buildBuffer is null) return;

        EncryptInternal(_buildBuffer.AsSpan(0, _length));

        ZeroChars(_buildBuffer);
        _buildBuffer = null;
    }

    [OverloadResolutionPriority(1)]
    public void Access(ReadOnlySpanAction<char> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        UsePlaintext(handler, static (plain, h) => { h(plain); return 0; });
    }

    [OverloadResolutionPriority(1)]
    public T Access<T>(ReadOnlySpanFunc<char, T> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return UsePlaintext(handler, static (plain, h) => h(plain));
    }

    [Obsolete(
        "Prefer Access(ReadOnlySpanAction<char>) — ReadOnlySpan<char> is a " +
        "ref struct that the compiler refuses to let escape, eliminating the " +
        "most common accidental-leak patterns of this overload. Suppress with " +
        "#pragma warning disable CS0618 if you genuinely need a char[] for an " +
        "external API.",
        error: false)]
    public void Access(Action<char[]> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        AccessCore(handler, static (h, plain) => { h(plain); return 0; });
    }

    [Obsolete(
        "Prefer Access<T>(ReadOnlySpanFunc<char, T>) — ReadOnlySpan<char> is a " +
        "ref struct that the compiler refuses to let escape, eliminating the " +
        "most common accidental-leak patterns of this overload. Suppress with " +
        "#pragma warning disable CS0618 if you genuinely need a char[] for an " +
        "external API.",
        error: false)]
    public T Access<T>(Func<char[], T> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return AccessCore(handler, static (h, plain) => h(plain));
    }

    public int CopyTo(Span<char> destination)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (destination.Length < _length)
            {
                throw new ArgumentException(
                    $"Destination span is too small: needs at least {_length} chars, got {destination.Length}.",
                    nameof(destination));
            }

            if (_length == 0) return 0;

            if (_buildBuffer is not null)
            {
                _buildBuffer.AsSpan(0, _length).CopyTo(destination);
                return _length;
            }

            DecryptInto(destination[.._length]);
            return _length;
        }
    }

    public int WriteUtf8To(Stream destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite)
        {
            throw new ArgumentException("Destination stream is not writable.", nameof(destination));
        }

        return UsePlaintext(destination, static (source, stream) =>
        {
            if (source.IsEmpty) return 0;

            int byteCount = Encoding.UTF8.GetByteCount(source);
            byte[] bytes = AllocatePinnedBytes(byteCount, excludeFromDumps: true);
            try
            {
                int written = Encoding.UTF8.GetBytes(source, bytes);
                Debug.Assert(written == byteCount);
                stream.Write(bytes, 0, written);
                return written;
            }
            finally
            {
                ZeroBytes(bytes);
            }
        });
    }

    public int WriteUtf8To(IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        return UsePlaintext(destination, static (source, writer) =>
        {
            if (source.IsEmpty) return 0;
            int byteCount = Encoding.UTF8.GetByteCount(source);
            var span = writer.GetSpan(byteCount);
            int written = Encoding.UTF8.GetBytes(source, span);
            Debug.Assert(written == byteCount);
            writer.Advance(written);
            return written;
        });
    }

    public void Utf8Access(ReadOnlySpanAction<byte> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        UsePlaintext(handler, static (source, h) =>
        {
            int byteCount = Encoding.UTF8.GetByteCount(source);
            if (byteCount == 0)
            {
                h(ReadOnlySpan<byte>.Empty);
                return 0;
            }
            var utf8Lease = LockedScratchPool.Rent(byteCount);
            try
            {
                var bytes = utf8Lease.Bytes(byteCount);
                int written = Encoding.UTF8.GetBytes(source, bytes);
                Debug.Assert(written == byteCount);
                h(bytes);
                return 0;
            }
            finally
            {
                utf8Lease.Return();
            }
        });
    }

    public T Utf8Access<T>(ReadOnlySpanFunc<byte, T> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_sync)
        {
            ThrowIfDisposed();
            LockedScratchPool.Lease? lease = null;
            LockedScratchPool.Lease? utf8Lease = null;
            try
            {
                ReadOnlySpan<char> source = RentPlaintextLocked(out lease);
                int byteCount = Encoding.UTF8.GetByteCount(source);
                if (byteCount == 0)
                {
                    return handler(ReadOnlySpan<byte>.Empty);
                }
                utf8Lease = LockedScratchPool.Rent(byteCount);
                var bytes = utf8Lease.Bytes(byteCount);
                int written = Encoding.UTF8.GetBytes(source, bytes);
                Debug.Assert(written == byteCount);
                return handler(bytes);
            }
            finally
            {
                utf8Lease?.Return();
                lease?.Return();
            }
        }
    }

    public ProtectedString Copy() =>
        // The constructor copies the span immediately, so pooled scratch
        // never outlives the callback.
        UsePlaintext(0, static (plain, _) => new ProtectedString(plain));

    public bool Equals(ProtectedString? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        if (_disposed || other._disposed) return false;

        ProtectedString first, second;
        if (_instanceId < other._instanceId)
        {
            first = this; second = other;
        }
        else
        {
            first = other; second = this;
        }

        lock (first._sync)
        {
            lock (second._sync)
            {
                if (_disposed || other._disposed) return false;
                if (_length != other._length) return false;

                LockedScratchPool.Lease? leaseA = null;
                LockedScratchPool.Lease? leaseB = null;
                try
                {
                    var a = RentPlaintextLocked(out leaseA);
                    var b = other.RentPlaintextLocked(out leaseB);
                    return CryptographicOperations.FixedTimeEquals(
                        MemoryMarshal.AsBytes(a),
                        MemoryMarshal.AsBytes(b));
                }
                finally
                {
                    leaseA?.Return();
                    leaseB?.Return();
                }
            }
        }
    }

    public override bool Equals(object? obj) => Equals(obj as ProtectedString);

    public override int GetHashCode() => _disposed ? 0 : _length;

    public override string ToString() =>
        _disposed
            ? "ProtectedString[disposed]"
            : $"ProtectedString[length={_length}]";

    public void Dispose()
    {
        lock (_sync)
        {
            DisposeUnlocked();
        }
        GC.SuppressFinalize(this);
    }

    ~ProtectedString()
    {
        try { DisposeUnlocked(); } catch { }
    }

    private void DisposeUnlocked()
    {
        if (_disposed) return;
        ZeroOnly(_ciphertext);
        ZeroOnly(_nonce);
        ZeroOnly(_tag);
        if (_buildBuffer is { Length: > 0 }) ZeroChars(_buildBuffer);
        _ciphertext = null;
        _nonce = null;
        _tag = null;
        _buildBuffer = null;
        _length = 0;
        _disposed = true;
        if (_instanceProtector is not null)
        {
            ProtectorLifetime.Release(_instanceProtector);
        }
    }

    // ---- internals -------------------------------------------------------

    private delegate TResult PlaintextFunc<in TState, out TResult>(ReadOnlySpan<char> plain, TState state);

    private TResult UsePlaintext<TState, TResult>(TState state, PlaintextFunc<TState, TResult> body)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            LockedScratchPool.Lease? lease = null;
            try
            {
                return body(RentPlaintextLocked(out lease), state);
            }
            finally
            {
                lease?.Return();
            }
        }
    }

    private TResult AccessCore<TState, TResult>(TState state, Func<TState, char[], TResult> body)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            char[]? plain = null;
            try
            {
                plain = MaterializePlaintext();   // already pinned
                return body(state, plain);
            }
            finally
            {
                if (plain is { Length: > 0 }) ZeroChars(plain);
            }
        }
    }

    private char[] MaterializePlaintext()
    {
        if (_length == 0) return Array.Empty<char>();

        var dst = AllocatePinnedChars(_length);
        if (_buildBuffer is not null)
        {
            _buildBuffer.AsSpan(0, _length).CopyTo(dst);
            return dst;
        }

        bool ok = false;
        try
        {
            DecryptInto(dst);
            ok = true;
            return dst;
        }
        finally
        {
            if (!ok) ZeroChars(dst);
        }
    }

    private void DecryptInto(Span<char> destination)
    {
        Debug.Assert(_ciphertext is not null && _nonce is not null && _tag is not null);
        Debug.Assert(destination.Length == _length);

        Span<byte> aad = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(aad, _instanceId);

        using var keyAccess = _instanceProtector.UnwrapKey();
        AesGcmShim.Decrypt(keyAccess.Key, _nonce!, _ciphertext!, _tag!, MemoryMarshal.AsBytes(destination), aad);
    }

    private ReadOnlySpan<char> RentPlaintextLocked(out LockedScratchPool.Lease? lease)
    {
        if (_buildBuffer is not null)
        {
            lease = null;
            return _buildBuffer.AsSpan(0, _length);
        }
        if (_length == 0)
        {
            lease = null;
            return ReadOnlySpan<char>.Empty;
        }

        var rented = LockedScratchPool.Rent(checked(_length * 2));
        try
        {
            var chars = rented.Chars(_length);
            DecryptInto(chars);
            lease = rented;
            return chars;
        }
        catch
        {
            rented.Return();
            throw;
        }
    }

    private void EncryptInternal(ReadOnlySpan<char> plain)
    {
        // Snapshot the per-instance protector so concurrent rotation cannot
        // change which key we encrypt under mid-operation.
        Debug.Assert(_instanceProtector is not null, "InitInstance must run before EncryptInternal");

        int byteLen = checked(plain.Length * 2);

        byte[]? newNonce = null;
        byte[]? newTag = null;
        byte[]? newCiphertext = null;
        LockedScratchPool.Lease? plainLease = null;
        bool committed = false;
        try
        {
            newNonce = AllocatePinnedEncryptedState(NonceSize);
            newTag = AllocatePinnedEncryptedState(TagSize);
            newCiphertext = AllocatePinnedEncryptedState(byteLen);

            RandomNumberGenerator.Fill(newNonce);

            Span<byte> aad = stackalloc byte[sizeof(long)];
            BinaryPrimitives.WriteInt64LittleEndian(aad, _instanceId);

            if (byteLen == 0)
            {
                using var keyAccess = _instanceProtector.UnwrapKey();
                AesGcmShim.Encrypt(keyAccess.Key, newNonce, ReadOnlySpan<byte>.Empty, newCiphertext, newTag, aad);
            }
            else
            {
                plainLease = LockedScratchPool.Rent(byteLen);
                var staging = plainLease.Bytes(byteLen);
                MemoryMarshal.AsBytes(plain).CopyTo(staging);
                using var keyAccess = _instanceProtector.UnwrapKey();
                AesGcmShim.Encrypt(keyAccess.Key, newNonce, staging, newCiphertext, newTag, aad);
            }

            // Commit: tear down old state, install new.
            ZeroOnly(_ciphertext);
            ZeroOnly(_nonce);
            ZeroOnly(_tag);
            _nonce = newNonce;
            _tag = newTag;
            _ciphertext = newCiphertext;
            _length = plain.Length;
            committed = true;
        }
        finally
        {
            // Always wipe the staging plaintext.
            plainLease?.Return();
            // On failure, also wipe the not-yet-installed state.
            if (!committed)
            {
                ZeroOnly(newNonce);
                ZeroOnly(newTag);
                ZeroOnly(newCiphertext);
            }
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(ProtectedString));
        }
    }
}
