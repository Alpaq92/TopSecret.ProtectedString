using System.Buffers;
using System.Security.Cryptography;

namespace TopSecret;

/// <summary>
/// A write-once container for multi-megabyte secret <b>byte</b> blobs —
/// the bulk-data companion to <see cref="ProtectedString"/>. The plaintext
/// is stored as fixed-size AES-GCM-256 chunks in ordinary memory; reads
/// decrypt one chunk at a time into a pinned, locked, wiped-on-exit scratch
/// buffer exposed through <see cref="ReadOnlySpan{T}"/> callbacks or
/// streaming sinks.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why not <see cref="ProtectedString"/>?</b> <c>ProtectedString</c> is
/// sized for credentials: every <c>Access</c> decrypts the whole value, and
/// its buffers are pinned and <c>mlock</c>ed — per-process locked-memory
/// budgets (<c>RLIMIT_MEMLOCK</c>) make that the wrong shape for bulk data.
/// <see cref="ProtectedBlob"/> inverts the layout: the bulk ciphertext lives
/// in ordinary unpinned, unlocked arrays (ciphertext leaks nothing if paged,
/// dumped, or copied by the GC), and only the transient plaintext gets the
/// locked+wiped treatment — the unwrapped DEK and the one-chunk plaintext
/// scratch alive during a read, both rented from the shared
/// locked-scratch pool. The ~60-byte wrapped key envelope is pinned but
/// deliberately not locked (encrypted state, same policy as the core's
/// ciphertext).
/// </para>
/// <para>
/// <b>Key custody.</b> Each blob encrypts under its own random 256-bit
/// data-encryption key (DEK). At rest the DEK exists only as an AES-GCM
/// envelope wrapped under the same process-wide master-key protector that
/// guards <see cref="ProtectedString"/> — so
/// <see cref="ProtectedStringOptions.KeyAtRestProtection"/> (including the
/// hardware-backed TPM / Secure Enclave / Keystore tiers) and
/// <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/> apply to blobs
/// with no extra configuration, and any number of blobs consume exactly one
/// hardware-backed key slot. Multi-chunk operations unwrap the DEK once per
/// operation into locked scratch and wipe it on exit, so streaming 200 MB
/// through <see cref="WriteTo"/> costs one master unwrap (one hardware
/// round-trip on those tiers), not one per chunk. Note that first
/// construction of either <see cref="ProtectedBlob"/> or
/// <see cref="ProtectedString"/> samples the read-once
/// <see cref="ProtectedStringOptions"/> keys — set them in your composition
/// root before constructing either type.
/// </para>
/// <para>
/// <b>Integrity (libsodium <c>secretstream</c> pattern).</b> Every chunk's
/// nonce is <c>per-blob random prefix ‖ chunk counter</c> and its associated
/// data binds the blob instance id, the chunk index, and a final-chunk flag
/// (see <see cref="ChunkFormat"/>). Flipping a ciphertext bit, reordering
/// chunks, truncating the blob, or transplanting a chunk from another blob
/// all throw <see cref="CryptographicException"/> instead of decrypting to
/// wrong plaintext. No plaintext byte is released before its chunk's tag
/// verifies. A blob always holds at least one chunk — an empty blob is a
/// single empty final chunk, which is what makes truncation-to-nothing
/// detectable.
/// </para>
/// <para>
/// <b>Process-key rotation.</b> Blobs snapshot the process protector at
/// construction and keep decrypting correctly after
/// <see cref="ProtectedString.RotateProcessKey"/> (superseded protectors are
/// never disposed), but they do <b>not</b> participate in rotation: this
/// blob's DEK and chunk ciphertext are never re-keyed for the blob's
/// lifetime. A memory dump captured while the blob is alive — on the
/// software tiers that includes the master-key material — can decrypt this
/// blob's ciphertext image regardless of later rotations. Dispose blobs to
/// end their exposure; rotation participation is a planned follow-up.
/// </para>
/// <para>
/// <b>Threat model</b> — same honesty as the core library: this raises the
/// bar against <i>accidental</i> disclosure (heap dumps, swap, GC copies of
/// bulk plaintext) and detects ciphertext tampering. It is no defence
/// against an attacker who can read the live process, and the plaintext
/// chunk handed to your callback is yours to not leak (avoid
/// <c>ToArray()</c> / copying it into long-lived buffers).
/// </para>
/// <para>
/// Instances are thread-safe (synchronous operations serialize on a
/// per-instance lock; <see cref="WriteToAsync"/> holds it only while
/// snapshotting, see there) and immutable after construction — there is
/// deliberately no <c>AppendByte</c> build mode, no whole-blob
/// <c>Access</c>, and no equality over content.
/// </para>
/// </remarks>
public sealed class ProtectedBlob : IDisposable
{
    /// <summary>Default chunk size: 64 KiB. Frames stay under the large-object-heap threshold and per-chunk tag overhead is ~0.02 %.</summary>
    public const int DefaultChunkSize = 64 * 1024;

    /// <summary>Smallest allowed chunk size (4 KiB) — below this, the 16-byte-per-chunk tag overhead and per-chunk AEAD cost dominate.</summary>
    public const int MinChunkSize = 4 * 1024;

    /// <summary>Largest allowed chunk size (1 MiB) — the read scratch (and, during <see cref="FromStream(Stream)"/>, two of them) is pinned and locked, so the cap bounds the locked-memory footprint the type can demand.</summary>
    public const int MaxChunkSize = 1024 * 1024;

    /// <summary>Monotonic counter assigning each blob a unique id, bound into every AEAD call as associated data.</summary>
    private static long s_lastInstanceId;

    private readonly long _instanceId = Interlocked.Increment(ref s_lastInstanceId);
    private readonly object _sync = new();

    /// <summary>
    /// Snapshot of the process protector taken at construction. Valid for
    /// the blob's lifetime because the snapshot carries a
    /// <c>ProtectorLifetime</c> holder reference (released exactly once in
    /// <see cref="DisposeUnlocked"/>) — a superseded protector is disposed
    /// only after its last holder lets go. Do NOT hand this reference to a
    /// second holder without its own <c>ProtectorLifetime.AddRef</c>.
    /// </summary>
    private readonly KeyAtRestProtector _protector;

    private readonly int _chunkSize;
    private BlobDekEnvelope? _dekEnvelope;
    private byte[]? _noncePrefix;   // 8 bytes; nonces are public — ordinary array
    private byte[][]? _frames;      // ordinary arrays: ciphertext ‖ 16-byte tag
    private long _length;
    private volatile bool _disposed;

    /// <summary>
    /// Creates a <see cref="ProtectedBlob"/> from <paramref name="value"/>
    /// with the process-wide <see cref="ProtectedBlobOptions.DefaultChunkSize"/>.
    /// The bytes are encrypted chunk-by-chunk directly from the span — no
    /// whole-blob staging copy is made.
    /// </summary>
    public ProtectedBlob(ReadOnlySpan<byte> value) : this(value, ProtectedBlobOptions.DefaultChunkSize) { }

    /// <summary>
    /// Creates a <see cref="ProtectedBlob"/> from <paramref name="value"/>,
    /// split into chunks of <paramref name="chunkSize"/> bytes.
    /// </summary>
    /// <param name="value">Source bytes. Copied (encrypted); never mutated.</param>
    /// <param name="chunkSize">
    /// Chunk size in bytes, between <see cref="MinChunkSize"/> and
    /// <see cref="MaxChunkSize"/>. Fixed for the blob's lifetime.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="chunkSize"/> is out of range.</exception>
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

    /// <summary>
    /// Creates a <see cref="ProtectedBlob"/> from <paramref name="value"/>
    /// with the process-wide <see cref="ProtectedBlobOptions.DefaultChunkSize"/>.
    /// </summary>
    /// <param name="value">Source bytes. Copied (encrypted); optionally zeroed.</param>
    /// <param name="clearSource">
    /// When <see langword="true"/>, the source array is zeroed when
    /// construction completes — including on failure (fail-secure), matching
    /// <see cref="ProtectedString(char[], bool)"/>.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    public ProtectedBlob(byte[] value, bool clearSource = false)
        : this(value, clearSource, ProtectedBlobOptions.DefaultChunkSize) { }

    /// <summary>
    /// Creates a <see cref="ProtectedBlob"/> from <paramref name="value"/>,
    /// split into chunks of <paramref name="chunkSize"/> bytes.
    /// </summary>
    /// <param name="value">Source bytes. Copied (encrypted); optionally zeroed.</param>
    /// <param name="clearSource">
    /// When <see langword="true"/>, the source array is zeroed when
    /// construction completes — including on failure (fail-secure), matching
    /// <see cref="ProtectedString(char[], bool)"/>.
    /// </param>
    /// <param name="chunkSize">Chunk size in bytes; see <see cref="ProtectedBlob(ReadOnlySpan{byte}, int)"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="chunkSize"/> is out of range.</exception>
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

    /// <summary>
    /// Creates a <see cref="ProtectedBlob"/> from a possibly multi-segment
    /// <see cref="ReadOnlySequence{T}"/> (the <c>System.IO.Pipelines</c> /
    /// <c>PipeReader</c> buffer shape) with the process-wide
    /// <see cref="ProtectedBlobOptions.DefaultChunkSize"/>. Same semantics as
    /// <see cref="ProtectedBlob(ReadOnlySpan{byte})"/>: the bytes are
    /// encrypted chunk-by-chunk directly from the sequence's segments and
    /// never mutated. Only a chunk that straddles a segment boundary is
    /// staged, through a pinned, locked, wiped-on-exit scratch buffer.
    /// </summary>
    /// <param name="value">Source bytes. Copied (encrypted); never mutated. The caller still owns (and advances / returns) the underlying buffers.</param>
    public ProtectedBlob(ReadOnlySequence<byte> value) : this(value, ProtectedBlobOptions.DefaultChunkSize) { }

    /// <summary>
    /// Creates a <see cref="ProtectedBlob"/> from a possibly multi-segment
    /// <see cref="ReadOnlySequence{T}"/>, split into chunks of
    /// <paramref name="chunkSize"/> bytes; see
    /// <see cref="ProtectedBlob(ReadOnlySequence{byte})"/>.
    /// </summary>
    /// <param name="value">Source bytes. Copied (encrypted); never mutated.</param>
    /// <param name="chunkSize">Chunk size in bytes; see <see cref="ProtectedBlob(ReadOnlySpan{byte}, int)"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="chunkSize"/> is out of range.</exception>
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

    /// <summary>
    /// The one place a blob takes its protector snapshot (an AddRef on the
    /// process protector). Every construction path funnels through here
    /// first and must then either complete an <c>Init*</c>/<c>Ingest*</c>
    /// or call <see cref="AbortConstruction"/>, so the holder reference is
    /// never left to the finalizer.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="chunkSize"/> is out of range.</exception>
    private ProtectedBlob(int chunkSize)
    {
        ValidateChunkSize(chunkSize);
        _chunkSize = chunkSize;
        _protector = ProtectedString.GetOrInitProcessProtector();
    }

    /// <summary>Keeps the <c>byte[]</c> constructor's argument-check order (null before chunk size) while still chaining to the snapshot constructor.</summary>
    private static int ThrowIfNullThenChunkSize(byte[] value, int chunkSize)
    {
        ArgumentNullException.ThrowIfNull(value);
        return chunkSize;
    }

    /// <summary>
    /// Construction failed after the protector snapshot: wipe whatever
    /// partial state exists, release the protector holder reference now
    /// (rather than at finalization), and take the never-published instance
    /// off the finalizer queue.
    /// </summary>
    private void AbortConstruction()
    {
        DisposeUnlocked();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Creates a <see cref="ProtectedBlob"/> by reading
    /// <paramref name="source"/> to its end. This is the
    /// "never materialise the whole plaintext" constructor: bytes stream
    /// through two pinned, locked, chunk-sized buffers (one being encrypted,
    /// one reading ahead to detect the final chunk), each wiped before
    /// return — plaintext residency never exceeds two chunks, regardless of
    /// blob size. Works with non-seekable and unknown-length streams; blobs
    /// larger than 2 GiB are supported (<see cref="Length"/> is a
    /// <see langword="long"/>).
    /// </summary>
    /// <param name="source">The stream to consume. Must be readable; read to end-of-stream.</param>
    /// <exception cref="ArgumentNullException"><paramref name="source"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="source"/> is not readable.</exception>
    public static ProtectedBlob FromStream(Stream source) =>
        FromStream(source, ProtectedBlobOptions.DefaultChunkSize);

    /// <summary>
    /// Like <see cref="FromStream(Stream)"/>, with an explicit chunk size.
    /// </summary>
    /// <param name="source">The stream to consume. Must be readable; read to end-of-stream.</param>
    /// <param name="chunkSize">Chunk size in bytes; see <see cref="ProtectedBlob(ReadOnlySpan{byte}, int)"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="source"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="source"/> is not readable.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="chunkSize"/> is out of range.</exception>
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

    /// <summary>
    /// Asynchronous counterpart of <see cref="FromStream(Stream)"/>: reads
    /// <paramref name="source"/> to its end with
    /// <see cref="Stream.ReadAtLeastAsync"/>, encrypting as it goes. Same
    /// memory model — two pinned, locked, chunk-sized staging buffers, both
    /// wiped before the returned task completes on every path, including
    /// cancellation and read failure — and no partially built blob or
    /// protector reference survives a failure.
    /// </summary>
    /// <param name="source">The stream to consume. Must be readable; read to end-of-stream.</param>
    /// <param name="cancellationToken">Observed by every read; a cancelled ingest wipes its staging and throws <see cref="OperationCanceledException"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="source"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="source"/> is not readable.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    public static Task<ProtectedBlob> FromStreamAsync(Stream source, CancellationToken cancellationToken = default) =>
        FromStreamAsync(source, ProtectedBlobOptions.DefaultChunkSize, cancellationToken);

    /// <summary>
    /// Like <see cref="FromStreamAsync(Stream, CancellationToken)"/>, with an
    /// explicit chunk size. Argument validation throws synchronously.
    /// </summary>
    /// <param name="source">The stream to consume. Must be readable; read to end-of-stream.</param>
    /// <param name="chunkSize">Chunk size in bytes; see <see cref="ProtectedBlob(ReadOnlySpan{byte}, int)"/>.</param>
    /// <param name="cancellationToken">Observed by every read.</param>
    /// <exception cref="ArgumentNullException"><paramref name="source"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="source"/> is not readable.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="chunkSize"/> is out of range.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
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
                    // Straddles a segment boundary — gather into locked,
                    // dump-excluded scratch (wiped on Return) and encrypt
                    // from there. One rent per construction, reused.
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
            // A short read means ReadAtLeast hit end-of-stream, so the
            // current chunk is definitely final; otherwise the lookahead
            // read decides (zero lookahead bytes ⇒ the stream's length is
            // an exact multiple of chunkSize and current is a full-size
            // final chunk).
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
        // Mirrors IngestStream line for line; the staging buffers are
        // dedicated pinned arrays (never pooled slabs), so handing them to
        // an arbitrary Stream's ReadAsync is as safe as the sync path's
        // ReadAtLeast. Spans are never held across an await.
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

    /// <summary>
    /// Per-construction encryption state shared by every ingress path: the
    /// fresh random DEK (pinned, locked, dump-excluded, wiped on dispose),
    /// the random nonce prefix, and — for the streaming paths — the two
    /// chunk-sized staging buffers with the same treatment. The DEK is
    /// wrapped into the owner's envelope only in <see cref="Commit"/>, so a
    /// failure anywhere before that leaves the owner with no key material to
    /// clean up beyond what <see cref="Dispose"/> here wipes.
    /// </summary>
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

        /// <summary>The staging buffer holding the chunk being encrypted (streaming paths only).</summary>
        internal byte[] Current => _current!;

        /// <summary>The staging buffer the next chunk is read into (streaming paths only).</summary>
        internal byte[] Lookahead => _lookahead!;

        internal void SwapStaging() => (_current, _lookahead) = (_lookahead, _current);

        internal byte[] EncryptChunk(int chunkIndex, bool isFinal, ReadOnlySpan<byte> plaintext) =>
            ChunkFormat.EncryptChunk(_dek!, _noncePrefix, _owner._instanceId, chunkIndex, isFinal, plaintext);

        /// <summary>Wraps the DEK under the owner's protector snapshot and publishes the finished state onto the owner.</summary>
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

    /// <summary>The total number of plaintext bytes held by this blob.</summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public long Length
    {
        get
        {
            // Under _sync so a concurrent Dispose cannot slip between the
            // disposed check and the field read — the getters share the
            // ObjectDisposedException contract of every other member.
            lock (_sync)
            {
                ThrowIfDisposed();
                return _length;
            }
        }
    }

    /// <summary>
    /// The number of chunks. Always at least 1 — an empty blob holds a single
    /// empty final chunk so that truncation stays detectable.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
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

    /// <summary>The chunk size this blob was constructed with. Every chunk except possibly the final one holds exactly this many plaintext bytes.</summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
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

    /// <summary>Whether <see cref="Dispose"/> has been called.</summary>
    public bool IsDisposed => _disposed;

    /// <summary>
    /// Test seam: direct access to the ciphertext frames so the tamper-matrix
    /// tests can flip bits, swap chunks, and transplant frames the way an
    /// attacker with memory access would. Never consumed by library code.
    /// </summary>
    internal byte[][] FramesForTests => _frames!;

    // ---- reads -----------------------------------------------------------

    /// <summary>
    /// Decrypts chunk <paramref name="chunkIndex"/> and invokes
    /// <paramref name="handler"/> with its plaintext as a
    /// <see cref="ReadOnlySpan{T}"/> over a pinned, locked scratch buffer
    /// that is wiped when the call returns. The span is a <c>ref struct</c> —
    /// the compiler refuses to let it be captured, stored, returned, or
    /// crossed by an <c>await</c>. The unwrapped DEK is wiped <i>before</i>
    /// the handler runs, so a slow or blocking handler extends plaintext
    /// residency of this one chunk only, never of the key.
    /// </summary>
    /// <param name="chunkIndex">Zero-based chunk index; see <see cref="ChunkCount"/>.</param>
    /// <param name="handler">Receives the chunk plaintext (up to <see cref="ChunkSize"/> bytes; the final chunk may be shorter, including empty).</param>
    /// <exception cref="ArgumentNullException"><paramref name="handler"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="chunkIndex"/> is negative or ≥ <see cref="ChunkCount"/>.</exception>
    /// <exception cref="CryptographicException">The chunk failed authentication.</exception>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public void AccessChunk(int chunkIndex, ReadOnlySpanAction<byte> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        AccessChunkCore(chunkIndex, handler, static (plain, h) =>
        {
            h(plain);
            return 0;
        });
    }

    /// <summary>
    /// Like <see cref="AccessChunk(int, ReadOnlySpanAction{byte})"/>, but
    /// <paramref name="handler"/>'s return value is propagated to the caller.
    /// </summary>
    public T AccessChunk<T>(int chunkIndex, ReadOnlySpanFunc<byte, T> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return AccessChunkCore(chunkIndex, handler, static (plain, h) => h(plain));
    }

    /// <summary>
    /// Like <see cref="AccessChunk(int, ReadOnlySpanAction{byte})"/>, with a
    /// caller-supplied <paramref name="state"/> threaded through to
    /// <paramref name="handler"/> so hot loops can pass a <c>static</c>
    /// lambda and allocate no closure per chunk.
    /// </summary>
    /// <typeparam name="TState">Any state the handler needs; passed through unchanged.</typeparam>
    /// <param name="chunkIndex">Zero-based chunk index; see <see cref="ChunkCount"/>.</param>
    /// <param name="state">Passed to <paramref name="handler"/> as its second argument.</param>
    /// <param name="handler">Receives the chunk plaintext and <paramref name="state"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="handler"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="chunkIndex"/> is negative or ≥ <see cref="ChunkCount"/>.</exception>
    /// <exception cref="CryptographicException">The chunk failed authentication.</exception>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public void AccessChunk<TState>(int chunkIndex, TState state, ReadOnlySpanAction<byte, TState> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        AccessChunkCore(chunkIndex, (state, handler), static (plain, s) =>
        {
            s.handler(plain, s.state);
            return 0;
        });
    }

    /// <summary>Internal shape of every <c>AccessChunk</c> overload: plaintext plus caller state in, result out. Private so the public surface stays on the BCL/core delegate types.</summary>
    private delegate TResult ChunkHandler<in TState, out TResult>(ReadOnlySpan<byte> plaintext, TState state);

    /// <summary>
    /// The single implementation behind the three public
    /// <c>AccessChunk</c> overloads (which differ only in how they adapt
    /// their delegate to <see cref="ChunkHandler{TState, TResult}"/> with a
    /// cached static lambda — no per-call allocation).
    /// </summary>
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
                // The DEK's work is done once the chunk is authenticated —
                // return (wipe) it before user code runs so a blocking
                // handler cannot extend key residency. The plaintext scratch
                // stays rented until the handler returns.
                session.ReturnDek();
                return handler(plain, state);
            }
            finally
            {
                scratch.Return();
            }
        }
    }

    /// <summary>
    /// Sequentially decrypts every chunk, invoking
    /// <paramref name="handler"/> once per chunk (in order) with the chunk
    /// plaintext over a single reused pinned, locked scratch buffer that is
    /// wiped on exit. Plaintext residency is one chunk at any moment. The DEK
    /// is unwrapped once for the whole pass — on hardware-backed tiers a full
    /// read of any size costs one secure-element round-trip.
    /// </summary>
    /// <param name="handler">
    /// Receives each chunk in order. An empty blob invokes the handler once
    /// with an empty span (its single empty final chunk). The span contents
    /// are only valid inside the callback — the buffer is overwritten by the
    /// next chunk.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="handler"/> is null.</exception>
    /// <exception cref="CryptographicException">
    /// A chunk failed authentication. Chunks before the failing one have
    /// already been handed to <paramref name="handler"/> — sequential
    /// consumers of a stream-shaped API necessarily see the authenticated
    /// prefix (the <c>secretstream</c> model); the final-chunk flag
    /// guarantees the failure itself cannot be silent.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
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

    /// <summary>
    /// Decrypts the whole blob into <paramref name="destination"/>,
    /// chunk-by-chunk, directly into the caller's buffer — the library makes
    /// no plaintext copy of its own. The caller owns the destination and is
    /// responsible for wiping it after use.
    /// </summary>
    /// <remarks>
    /// A <see cref="Span{T}"/> addresses at most <see cref="int.MaxValue"/>
    /// bytes, so this overload can only serve blobs up to 2 GiB. Larger
    /// blobs (see <see cref="FromStream(Stream)"/>) are read in pieces with
    /// <see cref="CopyTo(long, Span{byte})"/>, or streamed with
    /// <see cref="WriteTo"/> / <see cref="AccessChunks"/>.
    /// </remarks>
    /// <param name="destination">A buffer of at least <see cref="Length"/> bytes.</param>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is shorter than <see cref="Length"/>.</exception>
    /// <exception cref="CryptographicException">
    /// A chunk failed authentication. Everything this call wrote into
    /// <paramref name="destination"/> is zeroed before the exception
    /// propagates — a failed <see cref="CopyTo(Span{byte})"/> never leaves
    /// partial plaintext in the caller's buffer.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
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

    /// <summary>
    /// Decrypts <c>destination.Length</c> plaintext bytes starting at
    /// <paramref name="offset"/> into <paramref name="destination"/> — the
    /// ranged form of <see cref="CopyTo(Span{byte})"/> that lets a blob of
    /// any size (including &gt; 2 GiB) be read in caller-sized windows.
    /// Chunks that fall entirely inside the window are decrypted straight
    /// into the caller's buffer; a chunk the window only partly covers is
    /// decrypted into pinned, locked, wiped-on-exit scratch and the covered
    /// part copied out, so the library never materialises plaintext the
    /// caller did not ask for. The DEK is unwrapped once per call.
    /// </summary>
    /// <param name="offset">Zero-based plaintext offset of the first byte to copy; between 0 and <see cref="Length"/>.</param>
    /// <param name="destination">Receives exactly <c>destination.Length</c> bytes; <c>offset + destination.Length</c> must not exceed <see cref="Length"/>. An empty span copies nothing.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="offset"/> is negative or greater than <see cref="Length"/>.</exception>
    /// <exception cref="ArgumentException">The window <c>[offset, offset + destination.Length)</c> extends past <see cref="Length"/>.</exception>
    /// <exception cref="CryptographicException">A chunk failed authentication. Everything this call wrote into <paramref name="destination"/> is zeroed before the exception propagates.</exception>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
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

    /// <summary>
    /// Shared body of both <c>CopyTo</c> overloads. Caller holds
    /// <see cref="_sync"/> and has validated the window. An empty window on a
    /// non-empty blob touches no chunk; an empty blob's single empty final
    /// chunk is always authenticated (that is what makes
    /// truncation-to-nothing detectable).
    /// </summary>
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
            // Exception-path hygiene: a single atomic-looking call must
            // not leave the already-authenticated prefix sitting in a
            // buffer the caller has no reason to know is populated.
            CryptographicOperations.ZeroMemory(destination[..written]);
            throw;
        }
        finally
        {
            scratch?.Return();
        }
    }

    /// <summary>
    /// Decrypts the blob chunk-by-chunk and writes the plaintext to
    /// <paramref name="destination"/>. Plaintext passes through a single
    /// reused pinned, locked, wiped-on-exit scratch buffer — residency is one
    /// chunk at any moment; the DEK is unwrapped once for the whole pass.
    /// </summary>
    /// <param name="destination">The stream to write to. Must be writable.</param>
    /// <exception cref="ArgumentNullException"><paramref name="destination"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is not writable.</exception>
    /// <exception cref="CryptographicException">
    /// A chunk failed authentication. Chunks before the failing one have
    /// already been written to <paramref name="destination"/> — the
    /// <c>secretstream</c> model; see <see cref="AccessChunks"/>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <remarks>
    /// The caller decides what the destination does with the bytes (TLS
    /// encrypts, a <see cref="FileStream"/> persists to disk) — the
    /// library's job ends at the <c>Stream.Write</c> boundary, exactly like
    /// <see cref="ProtectedString.WriteUtf8To(Stream)"/>.
    /// </remarks>
    public void WriteTo(Stream destination)
    {
        ValidateWritableDestination(destination);
        lock (_sync)
        {
            using var session = BeginRead();
            byte[]? scratch = null;
            try
            {
                // scratch stays a dedicated array (not pooled): it is handed
                // to an arbitrary Stream implementation below, and a stream
                // that captured a pooled slab reference could read every
                // future secret staged there.
                scratch = ProtectedString.AllocatePinnedBytes(_chunkSize, excludeFromDumps: true);
                for (int index = 0; index < session.ChunkCount; index++)
                {
                    int plainLength = session.PlainLength(index);
                    session.Decrypt(index, scratch.AsSpan(0, plainLength));
                    // Deliberately the byte[] overload: Stream.Write(ReadOnlySpan<byte>)'s
                    // base implementation copies through an unwiped ArrayPool rental on
                    // streams that don't override it.
                    destination.Write(scratch, 0, plainLength);
                }
            }
            finally
            {
                ProtectedString.ZeroBytes(scratch);
            }
        }
    }

    /// <summary>
    /// Asynchronous counterpart of <see cref="WriteTo"/>: decrypts the blob
    /// chunk-by-chunk and writes the plaintext with
    /// <see cref="Stream.WriteAsync(byte[], int, int, CancellationToken)"/>.
    /// Same memory model — one dedicated pinned, locked scratch buffer,
    /// wiped before the returned task completes on every path including
    /// cancellation and write failure; the DEK is unwrapped once for the
    /// whole pass. Argument validation throws synchronously.
    /// </summary>
    /// <param name="destination">The stream to write to. Must be writable.</param>
    /// <param name="cancellationToken">Observed by every write; a cancelled pass wipes its scratch and throws <see cref="OperationCanceledException"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="destination"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is not writable.</exception>
    /// <exception cref="CryptographicException">A chunk failed authentication; see <see cref="WriteTo"/>.</exception>
    /// <exception cref="ObjectDisposedException">The instance was already disposed when the pass started.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    /// <remarks>
    /// A <see cref="Monitor"/> cannot be held across an <c>await</c>, so this
    /// method takes the per-instance lock only to snapshot the frames and
    /// unwrap the DEK; the decrypt-and-write loop then runs outside it,
    /// reading only immutable ciphertext. Concurrent operations are not
    /// blocked. A <see cref="Dispose"/> that lands mid-pass zeroes the
    /// frames under the pass, which then fails closed on its next chunk with
    /// <see cref="CryptographicException"/> — never wrong plaintext.
    /// </remarks>
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

    /// <summary>
    /// Returns a sentinel string that does <i>not</i> contain the plaintext,
    /// so accidental logging is safe.
    /// </summary>
    public override string ToString() =>
        _disposed
            ? "ProtectedBlob[disposed]"
            : $"ProtectedBlob[length={_length}]";

    /// <summary>
    /// Zeroes the wrapped-DEK envelope and every ciphertext frame, and marks
    /// the instance as disposed. Zeroing the frames is dispose hygiene
    /// (matching the core's convention), not a confidentiality requirement —
    /// they hold only ciphertext.
    /// </summary>
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
        // Best-effort cleanup if the caller forgot Dispose; same shape and
        // rationale as ProtectedString's finalizer (no lock — a
        // finalizer-eligible object is unreachable from other threads).
        try { DisposeUnlocked(); } catch { /* finalizer must not throw */ }
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
        // Release the ProtectorLifetime holder reference taken at
        // construction (see GetOrInitProcessProtector). Runs at most once
        // (guarded by _disposed above), Interlocked-based and safe from the
        // finalizer thread. Null only if the constructor threw before the
        // protector snapshot.
        if (_protector is not null)
        {
            ProtectorLifetime.Release(_protector);
        }
    }

    // ---- internals -------------------------------------------------------

    /// <summary>
    /// Opens a read operation: throws if disposed, snapshots the frame and
    /// nonce-prefix references, and unwraps the DEK into pooled locked
    /// scratch — the one master unwrap the whole operation amortises. Caller
    /// holds <see cref="_sync"/> and must dispose the session (which returns
    /// and wipes the DEK) in a <c>using</c> / <c>finally</c>. This is the
    /// single place the rent/return discipline for the DEK lives.
    /// </summary>
    private ReadSession BeginRead()
    {
        ThrowIfDisposed();
        return new ReadSession(this, RentDek());
    }

    /// <summary>
    /// Unwraps the DEK into pooled locked scratch the caller must
    /// <c>Return()</c> in a <c>finally</c> (which wipes it). Caller holds
    /// <see cref="_sync"/>. Renting from <see cref="LockedScratchPool"/>
    /// keeps the per-operation cost syscall-free.
    /// </summary>
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

    /// <summary>
    /// One read operation's rented state: the frame / nonce-prefix snapshot
    /// taken at the start of the pass plus the unwrapped-DEK lease.
    /// <see cref="Monitor"/> is reentrant, so a user callback that calls
    /// <see cref="Dispose"/> mid-pass nulls the owner's fields under our
    /// feet — decrypting through the snapshot instead sees the zeroed frames
    /// and fails closed with a <see cref="CryptographicException"/>. A plain
    /// (non-<c>ref</c>) struct so the async path can hold one across awaits;
    /// private, never copied.
    /// </summary>
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

        /// <summary>Decrypts frame <paramref name="chunkIndex"/> into <paramref name="plaintextDestination"/> (exactly the chunk's plaintext length).</summary>
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

        /// <summary>Returns (wipes) the DEK lease early — for operations that finish with the key before they finish with the plaintext. Idempotent.</summary>
        internal void ReturnDek()
        {
            _dek?.Return();
            _dek = null;
        }

        public void Dispose() => ReturnDek();
    }

    /// <summary>Shared with <see cref="ProtectedBlobOptions.DefaultChunkSize"/>'s setter so the bounds and message live in one place.</summary>
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
