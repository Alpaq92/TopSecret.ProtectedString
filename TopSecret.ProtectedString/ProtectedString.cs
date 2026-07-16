using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TopSecret.Cryptography;

namespace TopSecret;

/// <summary>
/// A cross-platform replacement for <see cref="System.Security.SecureString"/>.
/// Stores sensitive characters encrypted in memory (AES-GCM with a per-process key)
/// and exposes the plaintext only briefly through <see cref="Access(ReadOnlySpanAction{char})"/>
/// or <see cref="Access{T}(ReadOnlySpanFunc{char, T})"/>. Inspired by Evolveum's
/// <c>GuardedString</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Threat model.</b> Encrypting at rest in process memory makes accidental
/// disclosure (heap dumps, swap files, accidental logging) less likely. It is
/// not a defence against an attacker that already has arbitrary read access to
/// the running process — at some point the AES key has to live in memory.
/// </para>
/// <para>
/// <b>Defence-in-depth measures applied here:</b>
/// </para>
/// <list type="bullet">
///   <item>The 32-byte AES key is held in pinned memory
///   (<see cref="GC.AllocateArray{T}(int, bool)"/>) so the GC never relocates
///   (and therefore never copies) it, and locked with <c>VirtualLock</c> /
///   <c>mlock</c> on first use so the OS will not page it out to swap.</item>
///   <item>Every plaintext buffer used during encrypt, decrypt, append, and
///   <see cref="Access(ReadOnlySpanAction{char})"/> lives in pinned memory that
///   is locked into resident RAM and excluded from OS crash dumps where the
///   platform offers a primitive (WER dumps on Windows, kernel core dumps on
///   Linux/Android — see <see cref="DumpExclusion"/> for exact coverage and
///   limits), and is wiped with
///   <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> on the way
///   out — the JIT is forbidden from optimizing the wipe away. Hot-path
///   scratch rents from <see cref="LockedScratchPool"/>, whose page-aligned
///   slabs are locked and excluded once and deliberately never unlocked (see
///   its remarks for why); standalone buffers unlock when wiped.</item>
///   <item>Equality and hash verification use
///   <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
///   so the comparison does not leak through timing.</item>
///   <item><see cref="GetHashCode"/> depends only on length, so a hash table
///   bucket never reveals plaintext.</item>
///   <item><see cref="ToString"/> never includes the protected value.</item>
///   <item>The per-instance 64-bit id is bound into every AES-GCM call as
///   associated data, so swapping <c>_ciphertext</c>, <c>_nonce</c>, and
///   <c>_tag</c> from one instance onto another causes the tag check to fail
///   instead of silently revealing the wrong plaintext.</item>
/// </list>
/// <para>
/// Memory locking failure behaviour (platform unsupported or
/// <c>RLIMIT_MEMLOCK</c> exhausted) is governed by
/// <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/>.
/// </para>
/// <para>
/// Instances are thread-safe. Characters are held as UTF-16 little-endian bytes,
/// matching the in-memory layout of <see cref="char"/>.
/// </para>
/// </remarks>
public sealed class ProtectedString : IDisposable, IEquatable<ProtectedString>
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;

    /// <summary>OWASP-recommended Argon2id parameters for interactive logins (m=19 MiB, t=3, p=1).</summary>
    /// <remarks>https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html</remarks>
    public const int DefaultArgon2idIterations = 3;
    /// <summary>OWASP-recommended Argon2id memory cost: 19 456 KiB (≈19 MiB).</summary>
    public const int DefaultArgon2idMemoryKb = 19_456;
    /// <summary>OWASP-recommended Argon2id parallelism degree.</summary>
    public const int DefaultArgon2idParallelism = 1;
    /// <summary>Default Argon2id output length, 32 bytes (256 bits).</summary>
    public const int DefaultArgon2idHashLength = 32;

    /// <summary>
    /// The current process-wide master-key protector. Lazily created on first
    /// <see cref="ProtectedString"/> construction so consumers can set
    /// <see cref="ProtectedStringOptions.KeyAtRestProtection"/> in their
    /// composition root before the master generates. Replaced atomically by
    /// <see cref="RotateProcessKey"/> when key rotation is enabled.
    /// </summary>
    private static volatile KeyAtRestProtector? s_keyProtector;

    /// <summary>
    /// Whether the lazy process-wide protector has been initialised yet.
    /// Used by <see cref="ProtectedStringOptions"/> setters to decide
    /// whether a configuration change is taking effect or being silently
    /// ignored.
    /// </summary>
    internal static bool IsKeyProtectorInitialized => s_keyProtector is not null;

    /// <summary>
    /// Guards lazy initialisation of <see cref="s_keyProtector"/>, the swap
    /// during rotation, and additions to <see cref="s_liveInstances"/>. Held
    /// briefly only — the per-instance migration runs outside this lock.
    /// </summary>
    private static readonly object s_rotationLock = new();

    /// <summary>
    /// Weak-reference registry of live <see cref="ProtectedString"/> instances,
    /// populated only when <see cref="ProtectedStringOptions.ProcessKeyRotationPolicy"/>
    /// is not <see cref="ProcessKeyRotation.Disabled"/>. Walked by
    /// <see cref="RotateProcessKey"/> to re-encrypt every live instance under
    /// the new master.
    /// </summary>
    private static readonly List<WeakReference<ProtectedString>> s_liveInstances = new();

    /// <summary>0 = no rotation in flight; 1 = a rotation pass is currently running.</summary>
    private static int s_rotationInFlight;

    /// <summary>Periodic rotation timer; created on the first construction when policy is Periodic.</summary>
    private static Timer? s_rotationTimer;

    /// <summary>Monotonic counter used to assign each instance a unique id for lock ordering.</summary>
    private static long s_lastInstanceId;

    private byte[]? _ciphertext;
    private byte[]? _nonce;
    private byte[]? _tag;
    private int _length;
    private bool _readOnly;
    private volatile bool _disposed;
    private readonly object _sync = new();

    /// <summary>
    /// Pinned, locked plaintext build buffer. Non-<see langword="null"/> only
    /// while the instance is in <i>build mode</i> — i.e., between the first
    /// <see cref="AppendChar"/> on a not-yet-committed instance and the next
    /// <see cref="MakeReadOnly"/> / <see cref="Dispose"/> / rotation that
    /// commits the buffer to ciphertext. While set, <see cref="_length"/> is
    /// the number of valid characters at the start of this buffer; the rest
    /// of the buffer is zeroed reserve capacity for further appends. Mutated
    /// only under <see cref="_sync"/>.
    /// </summary>
    /// <remarks>
    /// Geometric growth gives <see cref="AppendChar"/> O(amortized 1) cost,
    /// rather than the O(n) per call (and O(n²) cumulative) it would pay if
    /// each character triggered a fresh AES-GCM encrypt — particularly
    /// expensive on hardware-backed wraps where each encrypt is a TPM /
    /// Secure-Element round-trip. The plaintext lives in pinned, locked,
    /// dump-excluded memory for the duration of the build, which is the
    /// trade-off documented in the README's "AppendChar build mode" section.
    /// </remarks>
    private char[]? _buildBuffer;

    /// <summary>Initial capacity for a freshly lifted build buffer.</summary>
    private const int BuildBufferInitialCapacity = 16;

    /// <summary>
    /// The protector that encrypted this instance's current ciphertext.
    /// Replaced by <see cref="RotateUnderNewKey"/> during a rotation pass so
    /// every per-op <see cref="System.Security.Cryptography.AesGcm"/>
    /// construction goes through the right key. Only mutated under
    /// <see cref="_sync"/>.
    /// </summary>
    private KeyAtRestProtector _instanceProtector = null!;

    /// <summary>
    /// Per-instance unique id assigned at construction. Used as a total order
    /// for nested-lock acquisition in <see cref="Equals(ProtectedString)"/>,
    /// guaranteeing the same lock order regardless of which side called.
    /// A 64-bit counter is wide enough to never wrap in any plausible process
    /// lifetime, so we never observe id collisions and never deadlock.
    /// </summary>
    private readonly long _instanceId = Interlocked.Increment(ref s_lastInstanceId);

    /// <summary>Creates an empty <see cref="ProtectedString"/>.</summary>
    public ProtectedString()
    {
        InitInstance();
        EncryptInternal(ReadOnlySpan<char>.Empty);
        RegisterForRotation();
    }

    /// <summary>
    /// Creates a <see cref="ProtectedString"/> from <paramref name="value"/>.
    /// The span content is copied; nothing is mutated through the span.
    /// </summary>
    public ProtectedString(ReadOnlySpan<char> value)
    {
        InitInstance();
        EncryptInternal(value);
        RegisterForRotation();
    }

    /// <summary>
    /// Creates a <see cref="ProtectedString"/> from <paramref name="value"/>.
    /// </summary>
    /// <param name="value">Source characters. Copied into the encrypted buffer.</param>
    /// <param name="clearSource">
    /// When <see langword="true"/>, the source array is zeroed after encryption,
    /// matching <c>GuardedString</c>'s "consume the input" pattern. The default is
    /// <see langword="false"/> so callers do not lose data they did not opt in to.
    /// </param>
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

    /// <summary>
    /// Snapshots the current process protector, registers this instance for
    /// rotation if the policy is non-<c>Disabled</c>, and starts the periodic
    /// rotation timer on first construction if the policy is <c>Periodic</c>.
    /// Holds <see cref="s_rotationLock"/> only briefly.
    /// </summary>
    private void InitInstance()
    {
        // Snapshot only. Registration into the rotation registry happens in
        // RegisterForRotation, AFTER the constructor's initial encryption:
        // the registry is what makes an instance visible to RotateProcessKey,
        // and a rotation pass migrating a half-constructed instance would
        // race the constructor's unsynchronized EncryptInternal — torn
        // nonce/tag/ciphertext, or an encrypt under a protector the
        // migration's Release just allowed to be disposed.
        _instanceProtector = SnapshotProtectorWithRef();
    }

    /// <summary>
    /// Enters this instance into the rotation registry (when the policy is
    /// non-<c>Disabled</c>) and arms the periodic timer. Every constructor
    /// calls this AFTER its initial <see cref="EncryptInternal"/> — until it
    /// runs, <see cref="RotateProcessKey"/> cannot see the instance, so a
    /// migration cannot race the constructor. An instance whose construction
    /// straddles a rotation may snapshot the outgoing protector and miss
    /// that pass; it simply keeps (and ref-counts) the old protector, like
    /// an instance created under a Disabled policy.
    /// </summary>
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

    /// <summary>Adds since the last dead-reference sweep of <see cref="s_liveInstances"/>.</summary>
    private static int s_addsSincePrune;

    /// <summary>
    /// Drops dead <see cref="WeakReference{T}"/> entries. Rotation passes
    /// prune too, but under <see cref="ProcessKeyRotation.OnDemand"/> with
    /// high instance churn and rare rotations the list would otherwise grow
    /// without bound. Caller holds <see cref="s_rotationLock"/>.
    /// </summary>
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

    /// <summary>
    /// Snapshots the current process protector and takes a
    /// <see cref="ProtectorLifetime"/> reference on it, retrying if a
    /// concurrent <see cref="RotateProcessKey"/> swapped the protector
    /// between the snapshot and the AddRef. The Interlocked increment inside
    /// <see cref="ProtectorLifetime.AddRef"/> is a full fence, so either this
    /// re-validation observes the swap (and retries), or the rotation's
    /// superseded-count check observes this reference — a disposed protector
    /// can never be returned.
    /// </summary>
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

    /// <summary>
    /// Returns the process-wide master-key protector, lazily initialising it
    /// (and thereby sampling the read-once <see cref="ProtectedStringOptions"/>
    /// keys) exactly like a <see cref="ProtectedString"/> construction would.
    /// Consumed by sibling assemblies (<c>TopSecret.ProtectedBlob</c>) so the
    /// whole process shares one protector, one hardware-backed key slot, and
    /// one <see cref="ProtectedStringOptions.KeyAtRestProtection"/> posture.
    /// The returned reference carries a <see cref="ProtectorLifetime"/>
    /// holder reference — the caller must call
    /// <see cref="ProtectorLifetime.Release"/> exactly once when done (on
    /// dispose), and the protector is guaranteed to stay undisposed until
    /// then even across <see cref="RotateProcessKey"/>.
    /// </summary>
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

    /// <summary>
    /// Creates a <see cref="ProtectedString"/> from <paramref name="value"/>.
    /// </summary>
    /// <remarks>
    /// <b>Caveat.</b> A <see cref="string"/> is immutable, deduplicated by the
    /// runtime (interning), and may be copied by the GC. Once a secret has been
    /// materialized as a <see cref="string"/>, it cannot be reliably erased
    /// from memory. Prefer <see cref="ProtectedString(ReadOnlySpan{char})"/>
    /// over a <see cref="char"/> array you control, or build the value
    /// incrementally with <see cref="AppendChar"/>. Use this overload only when
    /// you already hold an unavoidable <see cref="string"/> (e.g. from a
    /// configuration system).
    /// </remarks>
    public ProtectedString(string value) : this((value ?? throw new ArgumentNullException(nameof(value))).AsSpan()) { }

    /// <summary>The number of characters held by this instance.</summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public int Length
    {
        get
        {
            ThrowIfDisposed();
            return _length;
        }
    }

    /// <summary>Whether <see cref="MakeReadOnly"/> has been called.</summary>
    public bool IsReadOnly
    {
        get
        {
            ThrowIfDisposed();
            return _readOnly;
        }
    }

    /// <summary>Whether <see cref="Dispose"/> has been called.</summary>
    public bool IsDisposed => _disposed;

    /// <summary>
    /// Reports whether at least one hardware-backed master-key protector
    /// claims to be available on this host. Non-destructive — does not
    /// initialise the secure element.
    /// </summary>
    /// <remarks>
    /// Use this in your composition root to decide between
    /// <see cref="KeyAtRestProtection.HardwareBackedRequired"/> (will throw
    /// here if the answer is <see cref="HardwareBackedAvailability.NoProviderForThisPlatform"/>)
    /// and <see cref="KeyAtRestProtection.HardwareBackedPreferred"/> (will
    /// fall back to obscurity).
    /// </remarks>
    public static HardwareBackedAvailability HardwareBackedAvailability =>
        KeyAtRestProtectorFactory.IsHardwareBackedAvailableForCurrentPlatform()
            ? HardwareBackedAvailability.Available
            : HardwareBackedAvailability.NoProviderForThisPlatform;

    /// <summary>
    /// Marks the instance as read-only. After this call, mutating operations
    /// such as <see cref="AppendChar"/> throw <see cref="InvalidOperationException"/>.
    /// If the instance is in build mode (one or more <see cref="AppendChar"/>
    /// calls without a subsequent commit), the plaintext build buffer is
    /// encrypted into the AES-GCM ciphertext slot and wiped before the
    /// read-only flag is set.
    /// </summary>
    public void MakeReadOnly()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            CommitBuildBuffer();
            _readOnly = true;
        }
    }

    /// <summary>Appends <paramref name="c"/> to the end of the protected value.</summary>
    /// <remarks>
    /// <para>
    /// Each call appends to a pinned, locked, dump-excluded plaintext
    /// <i>build buffer</i>; geometric growth keeps amortised cost at O(1)
    /// per character. The build buffer is committed to AES-GCM ciphertext
    /// at the next <see cref="MakeReadOnly"/> (or <see cref="Dispose"/> /
    /// process-key rotation), so a typical
    /// <c>new ProtectedString(); foreach c: AppendChar(c); MakeReadOnly()</c>
    /// pays a single encryption regardless of secret length — this matters
    /// in particular under <see cref="KeyAtRestProtection.HardwareBackedRequired"/>
    /// or <see cref="KeyAtRestProtection.HardwareBackedPreferred"/>, where a
    /// per-call encrypt would round-trip to the TPM / Secure Element on
    /// every character.
    /// </para>
    /// <para>
    /// <b>Trade-off.</b> While the instance is in build mode (between the
    /// first <see cref="AppendChar"/> after construction and the next
    /// <see cref="MakeReadOnly"/>), the plaintext lives in pinned, locked,
    /// dump-excluded memory rather than encrypted. Call
    /// <see cref="MakeReadOnly"/> as soon as the secret is fully assembled
    /// to close that window.
    /// </para>
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The instance is read-only.</exception>
    public void AppendChar(char c) => AppendChars([c]);

    /// <summary>
    /// Appends every character of <paramref name="value"/> — the bulk
    /// sibling of <see cref="AppendChar"/>, paying one capacity check and
    /// one copy for the whole span instead of per-character calls.
    /// </summary>
    /// <remarks>
    /// Same build-mode semantics and trade-off as <see cref="AppendChar"/>:
    /// the plaintext lives in the pinned, locked, dump-excluded build buffer
    /// until the next <see cref="MakeReadOnly"/> commits it to ciphertext.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The instance is read-only.</exception>
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

            // Lift from ciphertext into the build buffer on the first append
            // after construction. Subsequent calls just write to the buffer
            // (growing geometrically when capacity is exhausted).
            int required = checked(_length + value.Length);
            if (_buildBuffer is null)
            {
                LiftIntoBuildBuffer(required);
            }
            else if (required > _buildBuffer.Length)
            {
                if (value.Overlaps(_buildBuffer))
                {
                    // The source aliases the live build buffer (a reentrant
                    // Access handler appending the plaintext to itself), and
                    // growth wipes the old buffer before the copy below would
                    // read it — stage the source in pooled scratch first.
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

    /// <summary>
    /// Allocates a pinned/locked build buffer of at least
    /// <paramref name="minimumCapacity"/> characters, decrypting any existing
    /// ciphertext into the front of it. Caller holds <see cref="_sync"/>.
    /// </summary>
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

    /// <summary>
    /// Grows the build buffer to <paramref name="newCapacity"/>, copying
    /// <see cref="_length"/> chars from the old buffer and wiping it.
    /// Caller holds <see cref="_sync"/>.
    /// </summary>
    private void GrowBuildBuffer(int newCapacity)
    {
        Debug.Assert(_buildBuffer is not null);
        Debug.Assert(newCapacity > _buildBuffer.Length);

        var grown = AllocatePinnedChars(newCapacity);
        _buildBuffer.AsSpan(0, _length).CopyTo(grown);
        ZeroChars(_buildBuffer);
        _buildBuffer = grown;
    }

    /// <summary>
    /// Encrypts the build buffer into <see cref="_ciphertext"/> /
    /// <see cref="_nonce"/> / <see cref="_tag"/>, wipes and releases the
    /// build buffer, and clears <see cref="_buildBuffer"/>. No-op if not
    /// in build mode. Caller holds <see cref="_sync"/>.
    /// </summary>
    private void CommitBuildBuffer()
    {
        if (_buildBuffer is null) return;

        // EncryptInternal reads the span first, then commits the new
        // ciphertext / nonce / tag and updates _length. Pass the active
        // slice so trailing reserve capacity isn't included in the
        // ciphertext.
        EncryptInternal(_buildBuffer.AsSpan(0, _length));

        ZeroChars(_buildBuffer);
        _buildBuffer = null;
    }

    /// <summary>
    /// Invokes <paramref name="handler"/> with the plaintext as a
    /// <see cref="ReadOnlySpan{T}"/> over a pinned, locked, dump-excluded
    /// buffer. The buffer is wiped (or, in build mode, left in place but
    /// no longer accessible to <paramref name="handler"/>) when the call
    /// returns.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Recommended over the <see cref="Access(Action{char[]})"/>
    /// overload.</b> The <see cref="ReadOnlySpan{T}"/> parameter is a
    /// <c>ref struct</c> — the C# compiler refuses to let it be captured
    /// by a closure, stored in a field, returned from the lambda, or
    /// crossed by an <c>await</c>, which closes the most common
    /// accidental-leak patterns of the <c>Action&lt;char[]&gt;</c> shape.
    /// </para>
    /// <para>
    /// You can still copy the contents (e.g.,
    /// <c>new string(plain)</c>) — that footgun is a language limit, not
    /// a library one. The optional
    /// <c>TopSecret.ProtectedString.Analyzers</c> package adds a
    /// build-time diagnostic for the most common copy patterns. Prefer
    /// the purpose-built sinks (<see cref="CopyTo(Span{char})"/>,
    /// <see cref="WriteUtf8To(Stream)"/>) when they fit the use case.
    /// </para>
    /// </remarks>
    [OverloadResolutionPriority(1)]
    public void Access(ReadOnlySpanAction<char> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_sync)
        {
            ThrowIfDisposed();
            LockedScratchPool.Lease? lease = null;
            try
            {
                handler(RentPlaintextLocked(out lease));
            }
            finally
            {
                lease?.Return();
            }
        }
    }

    /// <summary>
    /// Like <see cref="Access(ReadOnlySpanAction{char})"/>, but
    /// <paramref name="handler"/>'s return value is propagated to the
    /// caller.
    /// </summary>
    [OverloadResolutionPriority(1)]
    public T Access<T>(ReadOnlySpanFunc<char, T> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_sync)
        {
            ThrowIfDisposed();
            LockedScratchPool.Lease? lease = null;
            try
            {
                return handler(RentPlaintextLocked(out lease));
            }
            finally
            {
                lease?.Return();
            }
        }
    }

    /// <summary>
    /// Materializes the plaintext into a freshly allocated, <b>pinned</b>
    /// <see cref="char"/> array, invokes <paramref name="handler"/>, then zeros
    /// the array with <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Prefer the <see cref="Access(ReadOnlySpanAction{char})"/>
    /// overload.</b> The <see cref="char"/>[] parameter can be captured by
    /// a closure, stored, or returned from the lambda; the
    /// <see cref="ReadOnlySpan{T}"/> overload is structurally incapable of
    /// any of those leaks. This overload remains for compatibility and
    /// for the rare case where you genuinely need a heap-allocated
    /// <see cref="char"/>[] inside the callback (e.g., to pass to a
    /// pre-existing API that demands <c>char[]</c>).
    /// </para>
    /// <para>
    /// Do not retain a reference to the array passed to <paramref name="handler"/>
    /// past the end of the callback — the contents are zeroed on return.
    /// </para>
    /// </remarks>
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

    /// <summary>
    /// Materializes the plaintext into a freshly allocated, <b>pinned</b>
    /// <see cref="char"/> array, invokes <paramref name="handler"/>, then zeros
    /// the array. The handler's return value is propagated to the caller.
    /// </summary>
    /// <remarks>
    /// Prefer <see cref="Access{T}(ReadOnlySpanFunc{char, T})"/>; see the
    /// remarks on <see cref="Access(Action{char[]})"/> for why.
    /// </remarks>
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

    /// <summary>
    /// Copies the plaintext into <paramref name="destination"/>. The
    /// destination is filled with exactly <see cref="Length"/> characters
    /// starting at offset 0; characters beyond that are not touched.
    /// </summary>
    /// <param name="destination">
    /// A buffer at least <see cref="Length"/> characters long. Typically a
    /// <c>stackalloc char[N]</c> or a fixed-size local array — the library
    /// does not own the destination, so the caller is responsible for
    /// wiping it after use (or letting it fall out of scope on a
    /// <c>stackalloc</c>).
    /// </param>
    /// <returns>The number of characters written (equal to <see cref="Length"/>).</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="destination"/> is shorter than <see cref="Length"/>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// The stored ciphertext failed authentication. Decryption happens
    /// directly into <paramref name="destination"/> (no intermediate copy),
    /// so on failure the written region is cleared — or, on the browser TFM,
    /// left untouched — rather than preserved.
    /// </exception>
    /// <remarks>
    /// Useful when the consumer needs the plaintext as a contiguous
    /// <c>Span&lt;char&gt;</c> they can pass to UTF-16-friendly APIs (e.g.
    /// <see cref="Convert.ToBase64CharArray(byte[], int, int, char[], int)"/>'s
    /// span-taking siblings, span overloads of <c>Encoding</c>) without
    /// allocating a fresh <c>char[]</c> inside an
    /// <see cref="Access(ReadOnlySpanAction{char})"/> body.
    /// </remarks>
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

            // Decrypt straight into the caller's span — no intermediate
            // buffer at all. The caller owns the destination's wipe; on a
            // tag-check failure the runtime clears it before throwing.
            DecryptInto(destination[.._length]);
            return _length;
        }
    }

    /// <summary>
    /// Encodes the plaintext as UTF-8 and writes the bytes to
    /// <paramref name="destination"/>. The encoded bytes flow straight
    /// into the stream — no intermediate <c>byte[]</c> or <c>string</c>
    /// touches the managed heap outside of a pinned, locked, wiped-on-exit
    /// staging buffer.
    /// </summary>
    /// <param name="destination">The stream to write to. Must be writable.</param>
    /// <returns>The number of UTF-8 bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="destination"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is not writable.</exception>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <remarks>
    /// <para>
    /// Designed for the "send the secret over a network / pipe / file"
    /// case. The caller still has to think about what the destination
    /// stream does with the bytes (TLS encrypts, a plain
    /// <see cref="System.IO.FileStream"/> persists to disk, etc.) — the
    /// library's job ends at the <c>Stream.Write</c> boundary.
    /// </para>
    /// <para>
    /// <b>Stream contract.</b> This method calls
    /// <see cref="Stream.Write(byte[], int, int)"/> exactly once with the
    /// full encoded length and lets exceptions propagate. The
    /// <see cref="Stream"/> contract permits <i>some</i> derived
    /// implementations to short-write (write fewer bytes than asked,
    /// without throwing) — this method does not retry. For production
    /// use, prefer streams that either fully write or throw
    /// (<see cref="System.IO.FileStream"/>, <see cref="System.IO.MemoryStream"/>,
    /// <see cref="System.Net.Sockets.NetworkStream"/>, and
    /// <see cref="System.Net.Security.SslStream"/> all satisfy this on
    /// .NET); if you must wrap a short-writing stream, do the
    /// loop-until-done dance in your own wrapper before calling
    /// <see cref="WriteUtf8To(Stream)"/>. Keeping the loop out of the library
    /// keeps the wipe-on-exit window deterministic.
    /// </para>
    /// </remarks>
    public int WriteUtf8To(Stream destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite)
        {
            throw new ArgumentException("Destination stream is not writable.", nameof(destination));
        }

        lock (_sync)
        {
            ThrowIfDisposed();
            if (_length == 0) return 0;

            LockedScratchPool.Lease? lease = null;
            byte[]? bytes = null;
            try
            {
                ReadOnlySpan<char> source = RentPlaintextLocked(out lease);

                // The UTF-8 staging stays a dedicated array (not pooled
                // scratch): it is handed to an arbitrary Stream
                // implementation, and a stream that captured a pooled slab
                // reference could read every future secret staged there.
                int byteCount = Encoding.UTF8.GetByteCount(source);
                bytes = AllocatePinnedBytes(byteCount, excludeFromDumps: true);
                int written = Encoding.UTF8.GetBytes(source, bytes);
                Debug.Assert(written == byteCount);
                destination.Write(bytes, 0, written);
                return written;
            }
            finally
            {
                lease?.Return();
                if (bytes is not null) ZeroBytes(bytes);
            }
        }
    }

    /// <summary>
    /// Encodes the plaintext as UTF-8 directly into
    /// <paramref name="destination"/>'s buffer via
    /// <see cref="IBufferWriter{T}.GetSpan(int)"/> — no intermediate copy at
    /// all.
    /// </summary>
    /// <returns>The number of UTF-8 bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="destination"/> is null.</exception>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <remarks>
    /// The library's wipe guarantee ends at the writer boundary: an
    /// <see cref="IBufferWriter{T}"/>'s backing memory (often an
    /// <c>ArrayPool</c> rental) is owned by the writer and is <b>not</b>
    /// wiped by this method — the same contract as
    /// <see cref="WriteUtf8To(Stream)"/>'s stream boundary. Use a writer
    /// whose lifecycle you control and clear it after the bytes have been
    /// consumed.
    /// </remarks>
    public int WriteUtf8To(IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_length == 0) return 0;

            LockedScratchPool.Lease? lease = null;
            try
            {
                ReadOnlySpan<char> source = RentPlaintextLocked(out lease);
                int byteCount = Encoding.UTF8.GetByteCount(source);
                var span = destination.GetSpan(byteCount);
                int written = Encoding.UTF8.GetBytes(source, span);
                Debug.Assert(written == byteCount);
                destination.Advance(written);
                return written;
            }
            finally
            {
                lease?.Return();
            }
        }
    }

    /// <summary>
    /// Invokes <paramref name="handler"/> with the plaintext encoded as
    /// UTF-8 over pinned, locked, dump-excluded scratch that is wiped when
    /// the call returns — the byte-oriented sibling of
    /// <see cref="Access(ReadOnlySpanAction{char})"/>.
    /// </summary>
    /// <remarks>
    /// For consumers that need bytes rather than characters — HTTP Basic
    /// credentials, key-derivation inputs, <c>Utf8JsonWriter</c> values.
    /// Prefer this over hand-encoding inside an <c>Access</c> callback: the
    /// encoding target here is locked scratch with a guaranteed wipe, and the
    /// <see cref="ReadOnlySpan{T}"/> is a <c>ref struct</c> the compiler
    /// refuses to let escape.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public void Utf8Access(ReadOnlySpanAction<byte> handler)
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
                    handler(ReadOnlySpan<byte>.Empty);
                    return;
                }
                utf8Lease = LockedScratchPool.Rent(byteCount);
                var bytes = utf8Lease.Bytes(byteCount);
                int written = Encoding.UTF8.GetBytes(source, bytes);
                Debug.Assert(written == byteCount);
                handler(bytes);
            }
            finally
            {
                utf8Lease?.Return();
                lease?.Return();
            }
        }
    }

    /// <summary>
    /// Like <see cref="Utf8Access(ReadOnlySpanAction{byte})"/>, but
    /// <paramref name="handler"/>'s return value is propagated to the caller.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
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

    /// <summary>Returns an independent copy of this instance.</summary>
    /// <remarks>The copy is read-write even if the source is read-only.</remarks>
    public ProtectedString Copy()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            LockedScratchPool.Lease? lease = null;
            try
            {
                // The constructor copies the span immediately, so pooled
                // scratch never outlives this frame.
                return new ProtectedString(RentPlaintextLocked(out lease));
            }
            finally
            {
                lease?.Return();
            }
        }
    }

    /// <summary>
    /// Constant-time equality (via
    /// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>).
    /// Returns <see langword="false"/> if either side is disposed. Lengths are
    /// compared first; characters are compared in constant time only when
    /// lengths agree.
    /// </summary>
    public bool Equals(ProtectedString? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        if (_disposed || other._disposed) return false;

        // Order locks by per-instance id to avoid deadlocks when two threads
        // call a.Equals(b) and b.Equals(a) concurrently. Ids come from a
        // monotonic 64-bit counter, so they are unique and total-ordered —
        // unlike RuntimeHelpers.GetHashCode, which is 32-bit and can collide.
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

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as ProtectedString);

    /// <summary>
    /// Returns a length-only hash code. The actual characters intentionally do
    /// not contribute, so collections do not need to decrypt to bucket — and a
    /// dictionary lookup never reveals plaintext through its hash function.
    /// </summary>
    public override int GetHashCode() => _disposed ? 0 : _length;

    /// <summary>
    /// Computes an Argon2id hash of the UTF-8 encoded plaintext using the
    /// supplied <paramref name="salt"/> and parameters. Suitable for storing
    /// password verifiers; <see cref="VerifyArgon2idHash"/> is the matching
    /// constant-time verifier.
    /// </summary>
    /// <param name="salt">
    /// A unique, per-secret random salt of at least 8 bytes. <see cref="RandomNumberGenerator.GetBytes(int)"/>
    /// with a length of 16 is a sane default. The same salt must be supplied to
    /// <see cref="VerifyArgon2idHash"/> for the comparison to succeed.
    /// </param>
    /// <param name="iterations">Time cost. OWASP recommends ≥3 for interactive logins; defaults to <see cref="DefaultArgon2idIterations"/>.</param>
    /// <param name="memoryKb">Memory cost in KiB. OWASP recommends ≥19 456 (≈19 MiB) for interactive logins; defaults to <see cref="DefaultArgon2idMemoryKb"/>.</param>
    /// <param name="parallelism">Number of lanes. Defaults to <see cref="DefaultArgon2idParallelism"/>.</param>
    /// <param name="hashLengthBytes">Output length in bytes. Defaults to <see cref="DefaultArgon2idHashLength"/> (32, i.e. 256 bits).</param>
    /// <remarks>
    /// The plaintext is decrypted into a pinned buffer for the duration of the
    /// hash computation and wiped on the way out. Argon2id is intentionally
    /// slow — picking parameters too low defeats the point, picking them too
    /// high stalls your authentication path. Tune for your hardware.
    /// Works on the single-threaded browser (WASM) runtime at the default
    /// <paramref name="parallelism"/> = 1 (see <see cref="DefaultArgon2idParallelism"/>);
    /// raising <paramref name="parallelism"/> above 1 there throws
    /// <see cref="PlatformNotSupportedException"/> — see the README's
    /// browser-wasm section for why that ceiling is permanent, not a bug.
    /// See the <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html">OWASP
    /// Password Storage Cheat Sheet</a> for current guidance.
    /// </remarks>
    public byte[] ComputeArgon2idHash(
        byte[] salt,
        int iterations = DefaultArgon2idIterations,
        int memoryKb = DefaultArgon2idMemoryKb,
        int parallelism = DefaultArgon2idParallelism,
        int hashLengthBytes = DefaultArgon2idHashLength)
    {
        ArgumentNullException.ThrowIfNull(salt);
        if (salt.Length < 8) throw new ArgumentException("Salt must be at least 8 bytes.", nameof(salt));
        if (iterations < 1) throw new ArgumentOutOfRangeException(nameof(iterations));
        if (memoryKb < 8) throw new ArgumentOutOfRangeException(nameof(memoryKb));
        if (parallelism < 1) throw new ArgumentOutOfRangeException(nameof(parallelism));
        if (hashLengthBytes < 16) throw new ArgumentOutOfRangeException(nameof(hashLengthBytes));

        lock (_sync)
        {
            ThrowIfDisposed();
            LockedScratchPool.Lease? lease = null;
            byte[]? bytes = null;
            try
            {
                ReadOnlySpan<char> plain = RentPlaintextLocked(out lease);
                int byteCount = Encoding.UTF8.GetByteCount(plain);
                // Dedicated array (not pooled scratch): Argon2id's constructor
                // requires a real byte[] and the reference crosses into the
                // external KDF implementation.
                bytes = AllocatePinnedBytes(byteCount, excludeFromDumps: true);
                Encoding.UTF8.GetBytes(plain, bytes);

                using var argon = new Argon2id(bytes)
                {
                    Salt = salt,
                    Iterations = iterations,
                    MemorySize = memoryKb,
                    DegreeOfParallelism = parallelism,
                };
                return argon.GetBytes(hashLengthBytes);
            }
            finally
            {
                lease?.Return();
                if (bytes is { Length: > 0 }) ZeroBytes(bytes);
            }
        }
    }

    /// <summary>
    /// Constant-time comparison of an Argon2id hash of this instance (computed
    /// with <paramref name="salt"/> and the supplied parameters) against
    /// <paramref name="expectedHash"/>. The parameters must match the ones used
    /// when <paramref name="expectedHash"/> was originally produced.
    /// </summary>
    public bool VerifyArgon2idHash(
        byte[] expectedHash,
        byte[] salt,
        int iterations = DefaultArgon2idIterations,
        int memoryKb = DefaultArgon2idMemoryKb,
        int parallelism = DefaultArgon2idParallelism)
    {
        ArgumentNullException.ThrowIfNull(expectedHash);
        var actual = ComputeArgon2idHash(salt, iterations, memoryKb, parallelism, expectedHash.Length);
        try
        {
            return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    /// <summary>
    /// Returns a sentinel string that does <i>not</i> contain the plaintext.
    /// Override exists to make accidental logging safe.
    /// </summary>
    public override string ToString() =>
        _disposed
            ? "ProtectedString[disposed]"
            : $"ProtectedString[length={_length}]";

    /// <summary>Zeros the encrypted buffer, nonce, and tag, and marks the instance as disposed.</summary>
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
        // Best-effort cleanup if the caller forgot Dispose. Skip the
        // _sync acquisition: a finalizer-eligible object is by definition
        // unreachable from any other thread, so the lock would be either
        // uncontended (no benefit) or — if the type were ever resurrected
        // by something exotic like a cycle through a static cache — a way
        // to stall the finalizer queue. Match the shape every other
        // protector's finalizer uses.
        try { DisposeUnlocked(); } catch { /* finalizer must not throw */ }
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
        // Runs at most once (guarded by _disposed above) from Dispose or the
        // finalizer; ProtectorLifetime is Interlocked-based and safe on the
        // finalizer thread. Null only if the constructor threw before
        // InitInstance completed.
        if (_instanceProtector is not null)
        {
            ProtectorLifetime.Release(_instanceProtector);
        }
    }

    // ---- process-key rotation -------------------------------------------

    /// <summary>
    /// Generates a fresh master AES key, swaps it in as the current process
    /// protector, and re-encrypts every live <see cref="ProtectedString"/>
    /// under the new key. The superseded protector is disposed — its master
    /// zeroed, any hardware-backed transient slot released — as soon as its
    /// last holder lets go (tracked by <see cref="ProtectorLifetime"/>); when
    /// every live instance migrates successfully and nothing else references
    /// it, that happens before this method returns. Holders that outlive the
    /// rotation (failed migrations, instances constructed under a
    /// <see cref="ProcessKeyRotation.Disabled"/> policy, and
    /// <c>ProtectedBlob</c> instances, which rotation never re-encrypts)
    /// keep the old protector alive until they are disposed.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// <see cref="ProtectedStringOptions.ProcessKeyRotationPolicy"/> is
    /// <see cref="ProcessKeyRotation.Disabled"/> — the registry of live
    /// instances is not maintained, so rotation cannot be performed.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Lock semantics: <see cref="s_rotationLock"/> is held only for the
    /// brief swap-and-snapshot phase. Per-instance migration runs outside
    /// that lock and acquires each instance's <c>_sync</c> in turn — concurrent
    /// operations on instances <i>not</i> currently being migrated proceed
    /// unblocked.
    /// </para>
    /// <para>
    /// Reentrancy: a second concurrent call returns immediately without
    /// rotating, guarded by <see cref="s_rotationInFlight"/>. The periodic
    /// timer relies on this so a slow rotation cannot pile up callbacks.
    /// </para>
    /// </remarks>
    public static void RotateProcessKey()
    {
        if (ProtectedStringOptions.ProcessKeyRotationPolicy == ProcessKeyRotation.Disabled)
        {
            throw new InvalidOperationException(
                "ProtectedString: process-key rotation is disabled. " +
                $"Set {nameof(ProtectedStringOptions)}.{nameof(ProtectedStringOptions.ProcessKeyRotationPolicy)} " +
                $"to {nameof(ProcessKeyRotation.OnDemand)} or {nameof(ProcessKeyRotation.Periodic)} " +
                "before any ProtectedString is constructed.");
        }

        if (Interlocked.CompareExchange(ref s_rotationInFlight, 1, 0) != 0)
        {
            // Another rotation is already running — drop this call.
            return;
        }

        try
        {
            RotateInternal();
        }
        finally
        {
            Volatile.Write(ref s_rotationInFlight, 0);
        }
    }

    private static void RotateInternal()
    {
        KeyAtRestProtector oldProtector;
        KeyAtRestProtector newProtector;
        List<ProtectedString> toMigrate;

        // Brief lock: build the new protector, swap globally, snapshot live
        // instances that still hold the old reference, prune dead refs.
        lock (s_rotationLock)
        {
            oldProtector = GetOrInitProtectorLocked();

            var newMaster = GC.AllocateArray<byte>(KeySize, pinned: true);
            RandomNumberGenerator.Fill(newMaster);
            newProtector = KeyAtRestProtectorFactory.Create(newMaster);

            // Once swapped, every new construction snapshots the new protector.
            s_keyProtector = newProtector;

            toMigrate = new List<ProtectedString>(s_liveInstances.Count);
            for (int i = s_liveInstances.Count - 1; i >= 0; i--)
            {
                if (s_liveInstances[i].TryGetTarget(out var instance))
                {
                    if (ReferenceEquals(instance._instanceProtector, oldProtector))
                    {
                        toMigrate.Add(instance);
                    }
                }
                else
                {
                    s_liveInstances.RemoveAt(i);
                }
            }

            // From this point no new holder can acquire oldProtector (the
            // swap above is visible before ProtectorLifetime's full-fence
            // count read — see SnapshotProtectorWithRef). Mark it rotated
            // out; ProtectorLifetime disposes it the moment the holder count
            // hits zero.
            ProtectorLifetime.MarkSuperseded(oldProtector);
        }

        // Outside the rotation lock — migrate one instance at a time. Each
        // migration takes the per-instance _sync, so concurrent ops on an
        // un-migrated instance complete (under the old key) before the
        // migration runs.
        int failed = 0;
        foreach (var instance in toMigrate)
        {
            try
            {
                instance.RotateUnderNewKey(newProtector);
            }
            catch
            {
                failed++;
                // The instance still references the old protector; do not
                // dispose old yet.
            }
        }

        // The old protector was marked superseded above; ProtectorLifetime
        // disposes it (zeroing its master, releasing any TPM / Secure
        // Element transient slot) the moment its holder count reaches zero.
        // For a fully successful pass over registry-tracked instances that
        // already happened inside the loop, when the last migrated instance
        // released its reference. Holders that keep the old protector alive
        // longer — instances that failed to migrate, instances constructed
        // while the policy was Disabled (not in the registry), and
        // ProtectedBlob instances (rotation never re-encrypts blobs) — delay
        // disposal exactly as long as something can still decrypt through it.
        if (failed > 0)
        {
            Trace.TraceWarning(
                $"ProtectedString: process-key rotation completed with {failed} instance(s) " +
                "failing to re-encrypt; those instances still reference the previous master.");
        }
    }

    /// <summary>
    /// Re-encrypts this instance under <paramref name="newProtector"/>. Holds
    /// <see cref="_sync"/> for the entire decrypt-with-old / encrypt-with-new
    /// dance so concurrent operations cannot observe a half-migrated state.
    /// </summary>
    private void RotateUnderNewKey(KeyAtRestProtector newProtector)
    {
        lock (_sync)
        {
            if (_disposed) return;
            if (ReferenceEquals(_instanceProtector, newProtector)) return;
            var old = _instanceProtector;

            // In build mode the plaintext lives in _buildBuffer rather than in
            // ciphertext under the old protector. There is no encrypted state
            // to migrate — just adopt the new protector so the next
            // CommitBuildBuffer (e.g. via MakeReadOnly) encrypts under it.
            if (_buildBuffer is not null)
            {
                ProtectorLifetime.AddRef(newProtector);
                _instanceProtector = newProtector;
                ProtectorLifetime.Release(old);
                return;
            }

            LockedScratchPool.Lease? lease = null;
            try
            {
                var plain = RentPlaintextLocked(out lease);
                ProtectorLifetime.AddRef(newProtector);
                _instanceProtector = newProtector;
                try
                {
                    EncryptInternal(plain);
                }
                catch
                {
                    // Roll the swap back: the ciphertext is still under the
                    // old key, so leaving the new protector installed would
                    // fail every subsequent decrypt with a tag mismatch.
                    _instanceProtector = old;
                    ProtectorLifetime.Release(newProtector);
                    throw;
                }
            }
            finally
            {
                lease?.Return();
            }
            ProtectorLifetime.Release(old);
        }
    }

    private static int s_warnedTransientSlotRotation;

    private static void EnsurePeriodicRotationTimer()
    {
        if (Volatile.Read(ref s_rotationTimer) is not null) return;

        bool shouldWarn = false;
        lock (s_rotationLock)
        {
            if (s_rotationTimer is not null) return;
            var interval = ProtectedStringOptions.ProcessKeyRotationInterval;
            if (interval <= TimeSpan.Zero) return;

            shouldWarn = ShouldWarnRotatingAgainstTransientSlotProvider();

            s_rotationTimer = new Timer(static _ =>
            {
                try { RotateProcessKey(); }
                catch (Exception ex)
                {
                    Trace.TraceError("ProtectedString: periodic rotation failed: " + ex);
                }
            }, null, interval, interval);
        }

        // Emit the warning outside s_rotationLock so a pathological
        // TraceListener cannot stall the global rotation lock.
        if (shouldWarn) EmitTransientSlotRotationWarning();
    }

    /// <summary>
    /// Decide (under the caller's lock) whether the transient-slot warning
    /// should fire on this <see cref="EnsurePeriodicRotationTimer"/> pass.
    /// The actual <see cref="Trace.TraceWarning(string)"/> call runs in
    /// <see cref="EmitTransientSlotRotationWarning"/> after the lock has
    /// been released.
    /// </summary>
    private static bool ShouldWarnRotatingAgainstTransientSlotProvider()
    {
        var mode = ProtectedStringOptions.KeyAtRestProtection;
        if (mode != KeyAtRestProtection.HardwareBackedRequired &&
            mode != KeyAtRestProtection.HardwareBackedPreferred)
        {
            return false;
        }
        if (!KeyAtRestProtectorFactory.HasTransientSlotConstrainedProvider()) return false;
        return Interlocked.CompareExchange(ref s_warnedTransientSlotRotation, 1, 0) == 0;
    }

    /// <summary>
    /// Periodic rotation creates a fresh master each cycle; hardware-backed
    /// providers built on top of transient secure-element slots (TPM 2.0 in
    /// particular — commodity TPMs hold ≤3 transient keys) can still run out
    /// when holders pin superseded protectors across several cycles.
    /// <see cref="ProtectorLifetime"/> releases a superseded protector's slot
    /// deterministically once its last holder migrates or is disposed, so a
    /// clean migration pass frees the slot within the rotation itself — the
    /// residual risk is long-lived <c>ProtectedBlob</c> instances (rotation
    /// never re-encrypts blobs) and failed migrations. Emit a one-shot
    /// warning so the operator knows what to watch for before
    /// <c>TPM_RC_RESOURCES</c> starts surfacing.
    /// </summary>
    private static void EmitTransientSlotRotationWarning()
    {
        Trace.TraceWarning(
            "ProtectedString: ProcessKeyRotation.Periodic with a transient-slot-constrained " +
            "hardware-backed provider (e.g. Windows TPM). Superseded masters release their " +
            "secure-element slot as soon as the last instance encrypted under them migrates or " +
            "is disposed — but long-lived ProtectedBlob instances (never re-encrypted by " +
            "rotation) and failed migrations pin old slots across cycles. Commodity TPMs hold " +
            "≤3 transient keys, so pinned slots can surface as TPM_RC_RESOURCES; if blobs " +
            "routinely outlive several rotation intervals, reduce the rotation cadence, " +
            "dispose and rebuild blobs periodically, or use KeyAtRestProtection.Obscurity / None.");
    }

    // ---- internals -------------------------------------------------------

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

    /// <summary>
    /// Returns a fresh, pinned, locked <c>char[]</c> of length
    /// <see cref="_length"/> holding the plaintext, regardless of whether
    /// the instance is in build mode (read from <see cref="_buildBuffer"/>)
    /// or committed (decrypted from <see cref="_ciphertext"/>). Caller
    /// holds <see cref="_sync"/> and is responsible for zeroing the
    /// returned buffer with <see cref="ZeroChars(char[])"/>.
    /// </summary>
    /// <remarks>
    /// Used only by the obsolete <c>Access(Action&lt;char[]&gt;)</c> family,
    /// which has to hand out a heap-allocated <c>char[]</c> the caller might
    /// mutate or capture — that is exactly why this path cannot use
    /// <see cref="LockedScratchPool"/>: a captured pooled-slab reference
    /// would alias every future secret staged in that slab. Every internal
    /// consumer rents pooled scratch via
    /// <see cref="RentPlaintextLocked"/> instead.
    /// </remarks>
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

    /// <summary>
    /// Decrypts the stored ciphertext into <paramref name="destination"/>,
    /// which must be exactly <see cref="_length"/> characters. Caller holds
    /// <see cref="_sync"/> and owns the destination's wipe discipline. On a
    /// tag-check failure the runtime clears the destination before throwing.
    /// </summary>
    private void DecryptInto(Span<char> destination)
    {
        Debug.Assert(_ciphertext is not null && _nonce is not null && _tag is not null);
        Debug.Assert(destination.Length == _length);

        Span<byte> aad = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(aad, _instanceId);

        using var keyAccess = _instanceProtector.UnwrapKey();
        AesGcmShim.Decrypt(keyAccess.Key, _nonce!, _ciphertext!, _tag!, MemoryMarshal.AsBytes(destination), aad);
    }

    /// <summary>
    /// Hands back this instance's plaintext as a span: the live build-buffer
    /// span in build mode, an empty span for a zero-length value, or pooled
    /// locked scratch (<see cref="LockedScratchPool"/>) filled via
    /// <see cref="DecryptInto"/> otherwise. Caller holds <see cref="_sync"/>
    /// and must <c>Return()</c> the lease (when non-<see langword="null"/>)
    /// in a <c>finally</c>. The span must never escape to caller-supplied
    /// code as an array — pooled chunks share slabs with other secrets.
    /// </summary>
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

        // Allocate the new state up front. If anything in here throws, the
        // existing instance state is still intact and the just-allocated
        // buffers are torn down in the finally below.
        byte[]? newNonce = null;
        byte[]? newTag = null;
        byte[]? newCiphertext = null;
        LockedScratchPool.Lease? plainLease = null;
        bool committed = false;
        try
        {
            newNonce = AllocatePinnedEncryptedState(NonceSize);
            newTag = AllocatePinnedEncryptedState(TagSize);
            // Always pin the ciphertext array — even at length 0 — so the
            // invariant "all encrypted state is POH-resident" holds without
            // exception. The empty case used to alias Array.Empty<byte>() (a
            // runtime-shared, non-pinned singleton); that broke the invariant
            // the rest of the type documents.
            newCiphertext = AllocatePinnedEncryptedState(byteLen);

            RandomNumberGenerator.Fill(newNonce);

            // Bind every AEAD call to this instance: an attacker (or memory
            // corruption) that swaps _ciphertext/_nonce/_tag onto a different
            // instance will fail the GCM tag check instead of silently revealing
            // the wrong plaintext.
            Span<byte> aad = stackalloc byte[sizeof(long)];
            BinaryPrimitives.WriteInt64LittleEndian(aad, _instanceId);

            if (byteLen == 0)
            {
                using var keyAccess = _instanceProtector.UnwrapKey();
                AesGcmShim.Encrypt(keyAccess.Key, newNonce, ReadOnlySpan<byte>.Empty, newCiphertext, newTag, aad);
            }
            else
            {
                // Stage the plaintext bytes in pooled locked scratch so the
                // GC cannot relocate (and copy) the unencrypted material
                // before the lease wipes it on return.
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

    /// <summary>
    /// Allocates a pinned array for encrypted state (ciphertext / nonce /
    /// tag). Deliberately <b>not</b> locked or dump-excluded: the contents
    /// are safe to swap or dump by construction, and keeping these high-churn
    /// buffers off the page-granular, non-refcounted lock/unlock path removes
    /// their interference with pages legitimately locked for plaintext and
    /// key material.
    /// </summary>
    internal static byte[] AllocatePinnedEncryptedState(int length) =>
        GC.AllocateArray<byte>(length, pinned: true);

    /// <summary>
    /// Wipes encrypted state without the unlock / dump re-include step —
    /// these buffers are never locked (see
    /// <see cref="AllocatePinnedEncryptedState"/>), and an <c>munlock</c> on
    /// their pages could drop a lock legitimately held by a neighbouring
    /// locked buffer.
    /// </summary>
    internal static void ZeroOnly(byte[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>
    /// Allocates a pinned <see cref="byte"/> array and locks it into resident
    /// memory; on lock failure the policy in
    /// <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/> is
    /// applied via <see cref="HardeningPolicy.OnFailure(string)"/>.
    /// </summary>
    /// <param name="length">Number of bytes to allocate.</param>
    /// <param name="excludeFromDumps">
    /// <see langword="true"/> for buffers that will hold plaintext or key
    /// material — the buffer is additionally excluded from OS crash dumps via
    /// <see cref="DumpExclusion"/> where the platform supports it. Ciphertext,
    /// nonce, and tag buffers pass <see langword="false"/>: their contents are
    /// already safe to dump, and on Windows each exclusion consumes one of
    /// WER's 512 registration slots.
    /// </param>
    /// <param name="lockContext">
    /// Noun phrase interpolated into the policy failure for the lock step —
    /// lets protector call sites keep their site-specific messages while
    /// sharing this one allocate/lock/exclude implementation.
    /// </param>
    internal static byte[] AllocatePinnedBytes(
        int length, bool excludeFromDumps = false, string lockContext = "memory locking") =>
        AllocatePinnedCore<byte>(length, excludeFromDumps, lockContext);

    /// <summary>
    /// Allocates a pinned <see cref="char"/> array and locks it into resident
    /// memory; on lock failure the policy in
    /// <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/> is
    /// applied via <see cref="HardeningPolicy.OnFailure(string)"/>.
    /// </summary>
    private static char[] AllocatePinnedChars(int length) =>
        // Every char[] this type allocates holds plaintext (build buffer,
        // decrypt scratch, materialized copies) — always dump-exclude.
        AllocatePinnedCore<char>(length, excludeFromDumps: true, lockContext: "memory locking");

    private static T[] AllocatePinnedCore<T>(int length, bool excludeFromDumps, string lockContext)
        where T : unmanaged
    {
        var buffer = GC.AllocateArray<T>(length, pinned: true);
        if (length > 0 && !MemoryLocker.TryLock(buffer))
        {
            HardeningPolicy.OnFailure(lockContext);
        }
        if (excludeFromDumps && length > 0 && !DumpExclusion.TryExclude(buffer))
        {
            try
            {
                HardeningPolicy.OnFailure("core-dump exclusion");
            }
            catch
            {
                // Throw policy: GC reclaim does not munlock — release the
                // lock before surfacing, or every retried operation leaks
                // locked pages until the RLIMIT_MEMLOCK / working-set budget
                // is gone.
                MemoryLocker.TryUnlock(buffer);
                throw;
            }
        }
        return buffer;
    }

    /// <summary>
    /// Zeroes and unlocks a pinned, locked buffer. Internal so sibling
    /// assemblies (<c>TopSecret.ProtectedBlob</c>) share the one
    /// wipe-before-unlock implementation, mirroring
    /// <see cref="AllocatePinnedBytes"/>.
    /// </summary>
    /// <remarks>
    /// Residual: <c>VirtualLock</c>/<c>mlock</c> are page-granular and
    /// non-refcounted, so unlocking this buffer may drop the residency lock
    /// of a POH page it shares with another still-live locked buffer.
    /// <see cref="LockedScratchPool"/> removed this decay for the hot
    /// per-operation scratch (pooled slabs are never unlocked); what remains
    /// on this per-buffer path are short-lived standalone buffers (legacy
    /// <c>char[]</c> access copies, UTF-8/Argon2 byte staging, protector
    /// ephemerals, <c>ProtectedBlob</c> scratch), so the exposure is a narrow
    /// transient-overlap window rather than systematic decay. Encrypted state
    /// (ciphertext / nonce / tag) is no longer locked at all and bypasses
    /// this method entirely.
    /// </remarks>
    internal static void ZeroBytes(byte[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
            // Wipe before unlock: the data is overwritten with zeros while the
            // page is still guaranteed resident. Once unlocked, the OS may
            // page it out, but it now contains zeros so paging is harmless.
            CryptographicOperations.ZeroMemory(buffer);
            MemoryLocker.TryUnlock(buffer);
        }
    }

    private static void ZeroChars(char[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));
            MemoryLocker.TryUnlock(buffer);
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
