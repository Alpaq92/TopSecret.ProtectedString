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
/// Instances are thread-safe (operations serialize on a per-instance lock)
/// and immutable after construction — there is deliberately no
/// <c>AppendByte</c> build mode, no whole-blob <c>Access</c>, and no
/// equality over content.
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
    public ProtectedBlob(ReadOnlySpan<byte> value, int chunkSize)
    {
        ValidateChunkSize(chunkSize);
        _protector = ProtectedString.GetOrInitProcessProtector();
        _chunkSize = chunkSize;
        InitFromSpan(value);
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
    {
        ArgumentNullException.ThrowIfNull(value);
        ValidateChunkSize(chunkSize);
        _protector = ProtectedString.GetOrInitProcessProtector();
        _chunkSize = chunkSize;
        try
        {
            InitFromSpan(value);
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
        ArgumentNullException.ThrowIfNull(source);
        if (!source.CanRead)
        {
            throw new ArgumentException("Source stream is not readable.", nameof(source));
        }
        ValidateChunkSize(chunkSize);
        return new ProtectedBlob(source, chunkSize);
    }

    private ProtectedBlob(Stream source, int chunkSize)
    {
        _protector = ProtectedString.GetOrInitProcessProtector();
        _chunkSize = chunkSize;

        var frames = new List<byte[]>();
        byte[]? current = null;
        byte[]? lookahead = null;
        byte[]? dek = null;
        try
        {
            dek = ProtectedString.AllocatePinnedBytes(ChunkFormat.KeySize, excludeFromDumps: true);
            RandomNumberGenerator.Fill(dek);
            var noncePrefix = new byte[ChunkFormat.NoncePrefixSize];
            RandomNumberGenerator.Fill(noncePrefix);

            current = ProtectedString.AllocatePinnedBytes(chunkSize, excludeFromDumps: true);
            lookahead = ProtectedString.AllocatePinnedBytes(chunkSize, excludeFromDumps: true);

            long total = 0;
            int currentLength = source.ReadAtLeast(current, current.Length, throwOnEndOfStream: false);
            for (int index = 0; ; index++)
            {
                // A short read means ReadAtLeast hit end-of-stream, so the
                // current chunk is definitely final; otherwise the lookahead
                // read decides (zero lookahead bytes ⇒ the stream's length is
                // an exact multiple of chunkSize and current is a full-size
                // final chunk).
                int lookaheadLength = currentLength < chunkSize ? 0 : source.ReadAtLeast(lookahead, lookahead.Length, throwOnEndOfStream: false);
                bool isFinal = lookaheadLength == 0;

                frames.Add(ChunkFormat.EncryptChunk(
                    dek, noncePrefix, _instanceId, index, isFinal, current.AsSpan(0, currentLength)));
                total += currentLength;

                if (isFinal) break;
                (current, lookahead) = (lookahead, current);
                currentLength = lookaheadLength;
            }

            _dekEnvelope = BlobDekEnvelope.Wrap(_protector, dek, _instanceId);
            _noncePrefix = noncePrefix;
            _frames = frames.ToArray();
            _length = total;
        }
        finally
        {
            ProtectedString.ZeroBytes(current);
            ProtectedString.ZeroBytes(lookahead);
            ProtectedString.ZeroBytes(dek);
        }
    }

    private void InitFromSpan(ReadOnlySpan<byte> value)
    {
        byte[]? dek = null;
        try
        {
            dek = ProtectedString.AllocatePinnedBytes(ChunkFormat.KeySize, excludeFromDumps: true);
            RandomNumberGenerator.Fill(dek);
            var noncePrefix = new byte[ChunkFormat.NoncePrefixSize];
            RandomNumberGenerator.Fill(noncePrefix);

            // long arithmetic: for lengths within chunkSize of int.MaxValue the
            // int ceil-division would wrap negative (Array.MaxLength inputs are real).
            int chunkCount = value.IsEmpty ? 1 : (int)(((long)value.Length + _chunkSize - 1) / _chunkSize);
            var frames = new byte[chunkCount][];
            for (int index = 0; index < chunkCount; index++)
            {
                int offset = index * _chunkSize;
                int plainLength = Math.Min(_chunkSize, value.Length - offset);
                bool isFinal = index == chunkCount - 1;
                frames[index] = ChunkFormat.EncryptChunk(
                    dek, noncePrefix, _instanceId, index, isFinal, value.Slice(offset, plainLength));
            }

            _dekEnvelope = BlobDekEnvelope.Wrap(_protector, dek, _instanceId);
            _noncePrefix = noncePrefix;
            _frames = frames;
            _length = value.Length;
        }
        finally
        {
            ProtectedString.ZeroBytes(dek);
        }
    }

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

    /// <summary>
    /// Decrypts chunk <paramref name="chunkIndex"/> and invokes
    /// <paramref name="handler"/> with its plaintext as a
    /// <see cref="ReadOnlySpan{T}"/> over a pinned, locked scratch buffer
    /// that is wiped when the call returns. The span is a <c>ref struct</c> —
    /// the compiler refuses to let it be captured, stored, returned, or
    /// crossed by an <c>await</c>.
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
        lock (_sync)
        {
            ThrowIfDisposed();
            ValidateChunkIndex(chunkIndex);
            var frames = _frames!;
            var noncePrefix = _noncePrefix!;
            int plainLength = frames[chunkIndex].Length - ChunkFormat.TagSize;
            LockedScratchPool.Lease? dek = null;
            LockedScratchPool.Lease? scratch = null;
            try
            {
                dek = RentDek();
                scratch = LockedScratchPool.Rent(plainLength);
                var plain = scratch.Bytes(plainLength);
                DecryptChunkInto(dek.Bytes(ChunkFormat.KeySize), frames, noncePrefix, chunkIndex, plain);
                handler(plain);
            }
            finally
            {
                scratch?.Return();
                dek?.Return();
            }
        }
    }

    /// <summary>
    /// Like <see cref="AccessChunk(int, ReadOnlySpanAction{byte})"/>, but
    /// <paramref name="handler"/>'s return value is propagated to the caller.
    /// </summary>
    public T AccessChunk<T>(int chunkIndex, ReadOnlySpanFunc<byte, T> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_sync)
        {
            ThrowIfDisposed();
            ValidateChunkIndex(chunkIndex);
            var frames = _frames!;
            var noncePrefix = _noncePrefix!;
            int plainLength = frames[chunkIndex].Length - ChunkFormat.TagSize;
            LockedScratchPool.Lease? dek = null;
            LockedScratchPool.Lease? scratch = null;
            try
            {
                dek = RentDek();
                scratch = LockedScratchPool.Rent(plainLength);
                var plain = scratch.Bytes(plainLength);
                DecryptChunkInto(dek.Bytes(ChunkFormat.KeySize), frames, noncePrefix, chunkIndex, plain);
                return handler(plain);
            }
            finally
            {
                scratch?.Return();
                dek?.Return();
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
            ThrowIfDisposed();
            var frames = _frames!;
            var noncePrefix = _noncePrefix!;
            LockedScratchPool.Lease? dek = null;
            LockedScratchPool.Lease? scratch = null;
            try
            {
                dek = RentDek();
                scratch = LockedScratchPool.Rent(_chunkSize);
                for (int index = 0; index < frames.Length; index++)
                {
                    int plainLength = frames[index].Length - ChunkFormat.TagSize;
                    var plain = scratch.Bytes(plainLength);
                    DecryptChunkInto(dek.Bytes(ChunkFormat.KeySize), frames, noncePrefix, index, plain);
                    handler(plain);
                }
            }
            finally
            {
                scratch?.Return();
                dek?.Return();
            }
        }
    }

    /// <summary>
    /// Decrypts the whole blob into <paramref name="destination"/>,
    /// chunk-by-chunk, directly into the caller's buffer — the library makes
    /// no plaintext copy of its own. The caller owns the destination and is
    /// responsible for wiping it after use.
    /// </summary>
    /// <param name="destination">A buffer of at least <see cref="Length"/> bytes.</param>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is shorter than <see cref="Length"/>.</exception>
    /// <exception cref="CryptographicException">
    /// A chunk failed authentication. Everything this call wrote into
    /// <paramref name="destination"/> is zeroed before the exception
    /// propagates — a failed <see cref="CopyTo"/> never leaves partial
    /// plaintext in the caller's buffer.
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

            var frames = _frames!;
            var noncePrefix = _noncePrefix!;
            LockedScratchPool.Lease? dek = null;
            int written = 0;
            try
            {
                dek = RentDek();
                for (int index = 0; index < frames.Length; index++)
                {
                    int plainLength = frames[index].Length - ChunkFormat.TagSize;
                    DecryptChunkInto(dek.Bytes(ChunkFormat.KeySize), frames, noncePrefix, index, destination.Slice(written, plainLength));
                    written += plainLength;
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
                dek?.Return();
            }
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
        ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite)
        {
            throw new ArgumentException("Destination stream is not writable.", nameof(destination));
        }

        lock (_sync)
        {
            ThrowIfDisposed();
            var frames = _frames!;
            var noncePrefix = _noncePrefix!;
            LockedScratchPool.Lease? dek = null;
            byte[]? scratch = null;
            try
            {
                dek = RentDek();
                // scratch stays a dedicated array (not pooled): it is handed
                // to an arbitrary Stream implementation below, and a stream
                // that captured a pooled slab reference could read every
                // future secret staged there.
                scratch = ProtectedString.AllocatePinnedBytes(_chunkSize, excludeFromDumps: true);
                for (int index = 0; index < frames.Length; index++)
                {
                    int plainLength = frames[index].Length - ChunkFormat.TagSize;
                    DecryptChunkInto(dek.Bytes(ChunkFormat.KeySize), frames, noncePrefix, index, scratch.AsSpan(0, plainLength));
                    // Deliberately the byte[] overload: Stream.Write(ReadOnlySpan<byte>)'s
                    // base implementation copies through an unwiped ArrayPool rental on
                    // streams that don't override it.
                    destination.Write(scratch, 0, plainLength);
                }
            }
            finally
            {
                ProtectedString.ZeroBytes(scratch);
                dek?.Return();
            }
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
    /// Unwraps the DEK into pooled locked scratch the caller must
    /// <c>Return()</c> in a <c>finally</c> (which wipes it). Caller holds
    /// <see cref="_sync"/>. One rent per public operation — this is the
    /// master-unwrap the whole operation amortises — and renting from
    /// <see cref="LockedScratchPool"/> keeps the per-operation cost
    /// syscall-free.
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
    /// Decrypts frame <paramref name="chunkIndex"/> into
    /// <paramref name="plaintextDestination"/> (exactly the chunk's plaintext
    /// length). Caller holds <see cref="_sync"/> and passes state snapshotted
    /// at the start of the pass: <see cref="Monitor"/> is reentrant, so a
    /// user callback that calls <see cref="Dispose"/> mid-pass nulls the
    /// fields under our feet — with snapshots the pass instead sees the
    /// zeroed frames and fails closed with a
    /// <see cref="System.Security.Cryptography.CryptographicException"/>.
    /// </summary>
    private void DecryptChunkInto(
        ReadOnlySpan<byte> dek,
        byte[][] frames,
        byte[] noncePrefix,
        int chunkIndex,
        Span<byte> plaintextDestination)
    {
        ChunkFormat.DecryptChunk(
            dek,
            noncePrefix,
            _instanceId,
            chunkIndex,
            isFinalChunk: chunkIndex == frames.Length - 1,
            frames[chunkIndex],
            plaintextDestination);
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
