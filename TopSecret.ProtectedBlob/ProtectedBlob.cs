using System.Buffers;
using System.Security.Cryptography;

namespace TopSecret;

public sealed class ProtectedBlob : IDisposable
{
    public const int DefaultChunkSize = 64 * 1024;

    public const int MinChunkSize = 4 * 1024;

    public const int MaxChunkSize = 1024 * 1024;

    private static long s_lastInstanceId;

    private readonly long _instanceId = Interlocked.Increment(ref s_lastInstanceId);
    private readonly object _sync = new();

    private readonly KeyAtRestProtector _protector;

    private readonly int _chunkSize;
    private BlobDekEnvelope? _dekEnvelope;
    private byte[]? _noncePrefix;   // 8 bytes; nonces are public — ordinary array
    private byte[][]? _frames;      // ordinary arrays: ciphertext ‖ 16-byte tag
    private long _length;
    private volatile bool _disposed;

    public ProtectedBlob(ReadOnlySpan<byte> value) : this(value, ProtectedBlobOptions.DefaultChunkSize) { }

    public ProtectedBlob(ReadOnlySpan<byte> value, int chunkSize) : this(chunkSize)
    {
        try
        {
            InitFromSpan(value);
        }
        catch
        {
            AbortConstruction();
            throw;
        }
    }

    public ProtectedBlob(byte[] value, bool clearSource = false)
        : this(value, clearSource, ProtectedBlobOptions.DefaultChunkSize) { }

    public ProtectedBlob(byte[] value, bool clearSource, int chunkSize)
        : this(ThrowIfNullThenChunkSize(value, chunkSize))
    {
        try
        {
            InitFromSpan(value);
        }
        catch
        {
            AbortConstruction();
            throw;
        }
        finally
        {
            if (clearSource && value.Length > 0)
            {
                CryptographicOperations.ZeroMemory(value);
            }
        }
    }

    public ProtectedBlob(ReadOnlySequence<byte> value) : this(value, ProtectedBlobOptions.DefaultChunkSize) { }

    public ProtectedBlob(ReadOnlySequence<byte> value, int chunkSize) : this(chunkSize)
    {
        try
        {
            InitFromSequence(value);
        }
        catch
        {
            AbortConstruction();
            throw;
        }
    }

    private ProtectedBlob(int chunkSize)
    {
        ValidateChunkSize(chunkSize);
        _chunkSize = chunkSize;
        _protector = ProtectedString.GetOrInitProcessProtector();
    }

    private static int ThrowIfNullThenChunkSize(byte[] value, int chunkSize)
    {
        ArgumentNullException.ThrowIfNull(value);
        return chunkSize;
    }

    private void AbortConstruction()
    {
        DisposeUnlocked();
        GC.SuppressFinalize(this);
    }

    public static ProtectedBlob FromStream(Stream source) =>
        FromStream(source, ProtectedBlobOptions.DefaultChunkSize);

    public static ProtectedBlob FromStream(Stream source, int chunkSize)
    {
        ValidateReadableSource(source);
        var blob = new ProtectedBlob(chunkSize);
        try
        {
            blob.IngestStream(source);
        }
        catch
        {
            blob.AbortConstruction();
            throw;
        }
        return blob;
    }

    public static Task<ProtectedBlob> FromStreamAsync(Stream source, CancellationToken cancellationToken = default) =>
        FromStreamAsync(source, ProtectedBlobOptions.DefaultChunkSize, cancellationToken);

    public static Task<ProtectedBlob> FromStreamAsync(Stream source, int chunkSize, CancellationToken cancellationToken = default)
    {
        ValidateReadableSource(source);
        ValidateChunkSize(chunkSize);
        return FromStreamAsyncCore(source, chunkSize, cancellationToken);
    }

    private static async Task<ProtectedBlob> FromStreamAsyncCore(Stream source, int chunkSize, CancellationToken cancellationToken)
    {
        var blob = new ProtectedBlob(chunkSize);
        try
        {
            await blob.IngestStreamAsync(source, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            blob.AbortConstruction();
            throw;
        }
        return blob;
    }

    private static void ValidateReadableSource(Stream source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!source.CanRead)
        {
            throw new ArgumentException("Source stream is not readable.", nameof(source));
        }
    }

    // ---- ingress ---------------------------------------------------------

    private void InitFromSpan(ReadOnlySpan<byte> value)
    {
        using var ingest = new Ingest(this, withStaging: false);

        // long arithmetic: for lengths within chunkSize of int.MaxValue the
        // int ceil-division would wrap negative (Array.MaxLength inputs are real).
        int chunkCount = value.IsEmpty ? 1 : (int)(((long)value.Length + _chunkSize - 1) / _chunkSize);
        var frames = new byte[chunkCount][];
        for (int index = 0; index < chunkCount; index++)
        {
            int offset = index * _chunkSize;
            int plainLength = Math.Min(_chunkSize, value.Length - offset);
            frames[index] = ingest.EncryptChunk(index, isFinal: index == chunkCount - 1, value.Slice(offset, plainLength));
        }

        ingest.Commit(frames, value.Length);
    }

    private void InitFromSequence(in ReadOnlySequence<byte> value)
    {
        if (value.IsSingleSegment)
        {
            InitFromSpan(value.FirstSpan);
            return;
        }

        using var ingest = new Ingest(this, withStaging: false);

        long length = value.Length;
        int chunkCount = length == 0 ? 1 : checked((int)((length + _chunkSize - 1) / _chunkSize));
        var frames = new byte[chunkCount][];
        LockedScratchPool.Lease? staging = null;
        try
        {
            for (int index = 0; index < chunkCount; index++)
            {
                long offset = (long)index * _chunkSize;
                int plainLength = (int)Math.Min(_chunkSize, length - offset);
                bool isFinal = index == chunkCount - 1;
                var slice = value.Slice(offset, plainLength);
                if (slice.IsSingleSegment)
                {
                    // The common case for PipeReader buffers: a chunk that
                    // lands inside one segment is encrypted straight from it.
                    frames[index] = ingest.EncryptChunk(index, isFinal, slice.FirstSpan);
                }
                else
                {
                    staging ??= LockedScratchPool.Rent(_chunkSize);
                    var plain = staging.Bytes(plainLength);
                    slice.CopyTo(plain);
                    frames[index] = ingest.EncryptChunk(index, isFinal, plain);
                }
            }
        }
        finally
        {
            staging?.Return();
        }

        ingest.Commit(frames, length);
    }

    private void IngestStream(Stream source)
    {
        using var ingest = new Ingest(this, withStaging: true);
        var frames = new List<byte[]>();
        long total = 0;

        int currentLength = source.ReadAtLeast(ingest.Current, _chunkSize, throwOnEndOfStream: false);
        for (int index = 0; ; index++)
        {
            int lookaheadLength = currentLength < _chunkSize
                ? 0
                : source.ReadAtLeast(ingest.Lookahead, _chunkSize, throwOnEndOfStream: false);
            bool isFinal = lookaheadLength == 0;

            frames.Add(ingest.EncryptChunk(index, isFinal, ingest.Current.AsSpan(0, currentLength)));
            total += currentLength;

            if (isFinal) break;
            ingest.SwapStaging();
            currentLength = lookaheadLength;
        }

        ingest.Commit(frames.ToArray(), total);
    }

    private async Task IngestStreamAsync(Stream source, CancellationToken cancellationToken)
    {
        using var ingest = new Ingest(this, withStaging: true);
        var frames = new List<byte[]>();
        long total = 0;

        int currentLength = await source
            .ReadAtLeastAsync(ingest.Current, _chunkSize, throwOnEndOfStream: false, cancellationToken)
            .ConfigureAwait(false);
        for (int index = 0; ; index++)
        {
            int lookaheadLength = currentLength < _chunkSize
                ? 0
                : await source
                    .ReadAtLeastAsync(ingest.Lookahead, _chunkSize, throwOnEndOfStream: false, cancellationToken)
                    .ConfigureAwait(false);
            bool isFinal = lookaheadLength == 0;

            frames.Add(ingest.EncryptChunk(index, isFinal, ingest.Current.AsSpan(0, currentLength)));
            total += currentLength;

            if (isFinal) break;
            ingest.SwapStaging();
            currentLength = lookaheadLength;
        }

        ingest.Commit(frames.ToArray(), total);
    }

    private sealed class Ingest : IDisposable
    {
        private readonly ProtectedBlob _owner;
        private readonly byte[] _noncePrefix;
        private byte[]? _dek;
        private byte[]? _current;
        private byte[]? _lookahead;

        internal Ingest(ProtectedBlob owner, bool withStaging)
        {
            _owner = owner;
            _noncePrefix = new byte[ChunkFormat.NoncePrefixSize];
            try
            {
                _dek = ProtectedString.AllocatePinnedBytes(ChunkFormat.KeySize, excludeFromDumps: true);
                RandomNumberGenerator.Fill(_dek);
                RandomNumberGenerator.Fill(_noncePrefix);
                if (withStaging)
                {
                    _current = ProtectedString.AllocatePinnedBytes(owner._chunkSize, excludeFromDumps: true);
                    _lookahead = ProtectedString.AllocatePinnedBytes(owner._chunkSize, excludeFromDumps: true);
                }
            }
            catch
            {
                // A lock/exclusion policy failure mid-allocation must not
                // leave an earlier buffer locked until the GC gets to it.
                Dispose();
                throw;
            }
        }

        internal byte[] Current => _current!;

        internal byte[] Lookahead => _lookahead!;

        internal void SwapStaging() => (_current, _lookahead) = (_lookahead, _current);

        internal byte[] EncryptChunk(int chunkIndex, bool isFinal, ReadOnlySpan<byte> plaintext) =>
            ChunkFormat.EncryptChunk(_dek!, _noncePrefix, _owner._instanceId, chunkIndex, isFinal, plaintext);

        internal void Commit(byte[][] frames, long length)
        {
            _owner._dekEnvelope = BlobDekEnvelope.Wrap(_owner._protector, _dek!, _owner._instanceId);
            _owner._noncePrefix = _noncePrefix;
            _owner._frames = frames;
            _owner._length = length;
        }

        public void Dispose()
        {
            ProtectedString.ZeroBytes(_current);
            ProtectedString.ZeroBytes(_lookahead);
            ProtectedString.ZeroBytes(_dek);
            _current = null;
            _lookahead = null;
            _dek = null;
        }
    }

    // ---- inspection ------------------------------------------------------

    public long Length
    {
        get
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                return _length;
            }
        }
    }

    public int ChunkCount
    {
        get
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                return _frames!.Length;
            }
        }
    }

    public int ChunkSize
    {
        get
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                return _chunkSize;
            }
        }
    }

    public bool IsDisposed => _disposed;

    internal byte[][] FramesForTests => _frames!;

    // ---- reads -----------------------------------------------------------

    public void AccessChunk(int chunkIndex, ReadOnlySpanAction<byte> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        AccessChunkCore(chunkIndex, handler, static (plain, h) =>
        {
            h(plain);
            return 0;
        });
    }

    public T AccessChunk<T>(int chunkIndex, ReadOnlySpanFunc<byte, T> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return AccessChunkCore(chunkIndex, handler, static (plain, h) => h(plain));
    }

    public void AccessChunk<TState>(int chunkIndex, TState state, ReadOnlySpanAction<byte, TState> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        AccessChunkCore(chunkIndex, (state, handler), static (plain, s) =>
        {
            s.handler(plain, s.state);
            return 0;
        });
    }

    private delegate TResult ChunkHandler<in TState, out TResult>(ReadOnlySpan<byte> plaintext, TState state);

    private TResult AccessChunkCore<TState, TResult>(int chunkIndex, TState state, ChunkHandler<TState, TResult> handler)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            ValidateChunkIndex(chunkIndex);
            using var session = BeginRead();
            int plainLength = session.PlainLength(chunkIndex);
            var scratch = LockedScratchPool.Rent(plainLength);
            try
            {
                var plain = scratch.Bytes(plainLength);
                session.Decrypt(chunkIndex, plain);
                session.ReturnDek();
                return handler(plain, state);
            }
            finally
            {
                scratch.Return();
            }
        }
    }

    public void AccessChunks(ReadOnlySpanAction<byte> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_sync)
        {
            using var session = BeginRead();
            var scratch = LockedScratchPool.Rent(_chunkSize);
            try
            {
                for (int index = 0; index < session.ChunkCount; index++)
                {
                    int plainLength = session.PlainLength(index);
                    var plain = scratch.Bytes(plainLength);
                    session.Decrypt(index, plain);
                    handler(plain);
                }
            }
            finally
            {
                scratch.Return();
            }
        }
    }

    public void CopyTo(Span<byte> destination)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (destination.Length < _length)
            {
                throw new ArgumentException(
                    $"Destination span is too small: needs at least {_length} bytes, got {destination.Length}.",
                    nameof(destination));
            }

            CopyRangeUnlocked(0, destination[..(int)_length]);
        }
    }

    public void CopyTo(long offset, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (offset > _length)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(offset), offset, $"Offset must be between 0 and the blob length ({_length}).");
            }
            if (destination.Length > _length - offset)
            {
                throw new ArgumentException(
                    $"Range [{offset}, {offset + destination.Length}) extends past the blob length ({_length}).",
                    nameof(destination));
            }

            CopyRangeUnlocked(offset, destination);
        }
    }

    private void CopyRangeUnlocked(long offset, Span<byte> destination)
    {
        if (destination.IsEmpty && _length != 0)
        {
            return;
        }

        int firstChunk = (int)(offset / _chunkSize);
        int lastChunk = destination.IsEmpty ? firstChunk : (int)((offset + destination.Length - 1) / _chunkSize);

        using var session = BeginRead();
        LockedScratchPool.Lease? scratch = null;
        int written = 0;
        try
        {
            for (int index = firstChunk; index <= lastChunk; index++)
            {
                int plainLength = session.PlainLength(index);
                int skip = (int)Math.Max(0, offset - (long)index * _chunkSize);
                int take = Math.Min(plainLength - skip, destination.Length - written);
                var target = destination.Slice(written, take);
                if (skip == 0 && take == plainLength)
                {
                    session.Decrypt(index, target);
                }
                else
                {
                    scratch ??= LockedScratchPool.Rent(_chunkSize);
                    var plain = scratch.Bytes(plainLength);
                    session.Decrypt(index, plain);
                    plain.Slice(skip, take).CopyTo(target);
                }
                written += take;
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(destination[..written]);
            throw;
        }
        finally
        {
            scratch?.Return();
        }
    }

    public void WriteTo(Stream destination)
    {
        ValidateWritableDestination(destination);
        lock (_sync)
        {
            using var session = BeginRead();
            byte[]? scratch = null;
            try
            {
                scratch = ProtectedString.AllocatePinnedBytes(_chunkSize, excludeFromDumps: true);
                for (int index = 0; index < session.ChunkCount; index++)
                {
                    int plainLength = session.PlainLength(index);
                    session.Decrypt(index, scratch.AsSpan(0, plainLength));
                    destination.Write(scratch, 0, plainLength);
                }
            }
            finally
            {
                ProtectedString.ZeroBytes(scratch);
            }
        }
    }

    public Task WriteToAsync(Stream destination, CancellationToken cancellationToken = default)
    {
        ValidateWritableDestination(destination);
        return WriteToAsyncCore(destination, cancellationToken);
    }

    private async Task WriteToAsyncCore(Stream destination, CancellationToken cancellationToken)
    {
        ReadSession session;
        lock (_sync)
        {
            session = BeginRead();
        }

        byte[]? scratch = null;
        try
        {
            // Dedicated (non-pooled) for the same reason as WriteTo: the
            // array is handed to an arbitrary Stream implementation.
            scratch = ProtectedString.AllocatePinnedBytes(_chunkSize, excludeFromDumps: true);
            for (int index = 0; index < session.ChunkCount; index++)
            {
                int plainLength = session.PlainLength(index);
                session.Decrypt(index, scratch.AsSpan(0, plainLength));
                await destination.WriteAsync(scratch, 0, plainLength, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ProtectedString.ZeroBytes(scratch);
            session.Dispose();
        }
    }

    private static void ValidateWritableDestination(Stream destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite)
        {
            throw new ArgumentException("Destination stream is not writable.", nameof(destination));
        }
    }

    public override string ToString() =>
        _disposed
            ? "ProtectedBlob[disposed]"
            : $"ProtectedBlob[length={_length}]";

    public void Dispose()
    {
        lock (_sync)
        {
            DisposeUnlocked();
        }
        GC.SuppressFinalize(this);
    }

    ~ProtectedBlob()
    {
        try { DisposeUnlocked(); } catch { }
    }

    private void DisposeUnlocked()
    {
        if (_disposed) return;
        _dekEnvelope?.Zero();
        if (_frames is not null)
        {
            foreach (var frame in _frames)
            {
                CryptographicOperations.ZeroMemory(frame);
            }
        }
        _dekEnvelope = null;
        _frames = null;
        _noncePrefix = null;
        _length = 0;
        _disposed = true;
        if (_protector is not null)
        {
            ProtectorLifetime.Release(_protector);
        }
    }

    // ---- internals -------------------------------------------------------

    private ReadSession BeginRead()
    {
        ThrowIfDisposed();
        return new ReadSession(this, RentDek());
    }

    private LockedScratchPool.Lease RentDek()
    {
        var dek = LockedScratchPool.Rent(ChunkFormat.KeySize);
        bool ok = false;
        try
        {
            _dekEnvelope!.UnwrapInto(_protector, dek.Bytes(ChunkFormat.KeySize), _instanceId);
            ok = true;
            return dek;
        }
        finally
        {
            if (!ok) dek.Return();
        }
    }

    private struct ReadSession : IDisposable
    {
        private readonly ProtectedBlob _owner;
        private readonly byte[][] _frames;
        private readonly byte[] _noncePrefix;
        private LockedScratchPool.Lease? _dek;

        internal ReadSession(ProtectedBlob owner, LockedScratchPool.Lease dek)
        {
            _owner = owner;
            _frames = owner._frames!;
            _noncePrefix = owner._noncePrefix!;
            _dek = dek;
        }

        internal readonly int ChunkCount => _frames.Length;

        internal readonly int PlainLength(int chunkIndex) => _frames[chunkIndex].Length - ChunkFormat.TagSize;

        internal readonly void Decrypt(int chunkIndex, Span<byte> plaintextDestination)
        {
            var dek = _dek ?? throw new InvalidOperationException("The DEK lease has already been returned for this read.");
            ChunkFormat.DecryptChunk(
                dek.Bytes(ChunkFormat.KeySize),
                _noncePrefix,
                _owner._instanceId,
                chunkIndex,
                isFinalChunk: chunkIndex == _frames.Length - 1,
                _frames[chunkIndex],
                plaintextDestination);
        }

        internal void ReturnDek()
        {
            _dek?.Return();
            _dek = null;
        }

        public void Dispose() => ReturnDek();
    }

    internal static void ValidateChunkSize(int chunkSize, string paramName = "chunkSize")
    {
        if (chunkSize is < MinChunkSize or > MaxChunkSize)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                chunkSize,
                $"Chunk size must be between {MinChunkSize} and {MaxChunkSize} bytes.");
        }
    }

    private void ValidateChunkIndex(int chunkIndex)
    {
        if (chunkIndex < 0 || chunkIndex >= _frames!.Length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(chunkIndex),
                chunkIndex,
                $"Chunk index must be between 0 and {_frames!.Length - 1}.");
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(ProtectedBlob));
        }
    }
}
