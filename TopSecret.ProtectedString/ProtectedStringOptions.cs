using System.Diagnostics;

namespace TopSecret;

/// <summary>
/// What <see cref="ProtectedString"/> does when memory locking
/// (<c>VirtualLock</c> / <c>mlock</c>) is unavailable or a specific lock call
/// fails — for example because the platform does not expose the primitive, or
/// because the per-process <c>RLIMIT_MEMLOCK</c> budget is exhausted on
/// Linux/macOS/Android/iOS.
/// </summary>
public enum MemoryLockingFailureBehavior
{
    /// <summary>
    /// Continue silently. Memory locking is best-effort; if it is unavailable,
    /// secret buffers may still be paged to disk under memory pressure but
    /// every other defence (AES-GCM, pinned wipes, AAD binding) still holds.
    /// </summary>
    Ignore,

    /// <summary>
    /// Default. Emit a one-shot warning via <see cref="System.Diagnostics.Trace.TraceWarning(string)"/>
    /// the first time a lock fails, then proceed as with <see cref="Ignore"/>.
    /// </summary>
    LogWarning,

    /// <summary>
    /// Throw <see cref="System.PlatformNotSupportedException"/> from any
    /// constructor or mutation that needs to lock memory and cannot. Use this
    /// when paging-to-disk is in your threat model and a silent downgrade is
    /// unacceptable.
    /// </summary>
    Throw,
}

/// <summary>
/// Process-key rotation policy. Controls whether <see cref="ProtectedString"/>
/// instances are tracked in a process-wide registry so they can be re-encrypted
/// under a fresh master AES key.
/// </summary>
/// <remarks>
/// Rotation bounds the blast radius of a *historical* disclosure (an old core
/// file, a crash dump captured at time T): once rotated, the old key is zeroed
/// and ciphertext encrypted under it cannot be decrypted. It does <i>not</i>
/// defend against a live attacker — they read the new key as easily as the old.
/// </remarks>
public enum ProcessKeyRotation
{
    /// <summary>
    /// Default. No registry of live instances is kept and
    /// <see cref="ProtectedString.RotateProcessKey"/> throws if called. Zero
    /// per-construction overhead.
    /// </summary>
    Disabled,

    /// <summary>
    /// Live instances are registered in a weak-reference registry; rotations
    /// happen only when <see cref="ProtectedString.RotateProcessKey"/> is
    /// called explicitly. Construction takes a brief shared lock; nothing
    /// rotates automatically.
    /// </summary>
    OnDemand,

    /// <summary>
    /// Like <see cref="OnDemand"/>, plus a background timer fires
    /// <see cref="ProtectedString.RotateProcessKey"/> at the interval set by
    /// <see cref="ProtectedStringOptions.ProcessKeyRotationInterval"/>. The
    /// timer starts on the first <see cref="ProtectedString"/> construction
    /// and runs for the lifetime of the process.
    /// </summary>
    Periodic,
}

/// <summary>
/// Whether and how to keep the per-process AES master key encrypted at rest in
/// memory between <see cref="System.Security.Cryptography.AesGcm"/> operations.
/// </summary>
/// <remarks>
/// <para>
/// The plaintext master key is otherwise pinned in process memory for the
/// process lifetime. Hardware-backed wrapping pushes the wrapping key into a
/// secure element so it never enters process memory at all, raising the bar
/// against a cold heap dump. There is no software-only scheme that
/// achieves this: AES-GCM with a per-protector random wrap key (Windows /
/// the <see cref="Obscurity"/> tier here) keeps both pieces in process
/// memory; HKDF wrapping, Boojum, and white-box AES are likewise
/// obscurity-only against an attacker with the heap dump.
/// </para>
/// <para>
/// <b>Important.</b> The cross-platform package only ships a built-in
/// hardware-backed provider for Apple (Secure Enclave) and, on the
/// <c>net10.0-android</c> TFM, Android Keystore. Windows TPM support is
/// delivered by the optional <c>TopSecret.ProtectedString.WindowsTpm</c> NuGet
/// and Linux TPM support by <c>TopSecret.ProtectedString.LinuxTpm</c>; both
/// auto-register via a <c>ModuleInitializer</c> when referenced.
/// </para>
/// </remarks>
public enum KeyAtRestProtection
{
    /// <summary>
    /// Default. The master AES key is held plaintext in pinned, locked,
    /// dump-excluded memory. No per-operation wrap/unwrap cost.
    /// </summary>
    None,

    /// <summary>
    /// Software-only obscurity wrap. Per platform:
    /// <list type="bullet">
    ///   <item>Windows — AES-GCM-256 with a per-protector random wrap
    ///   key (no fixed system-wide key, unlike the legacy
    ///   <c>CryptProtectMemory</c> default this replaces). Both wrap key
    ///   and ciphertext live in pinned/locked process memory.</item>
    ///   <item>Anywhere else — HKDF-derived stream-XOR wrap from a per-process
    ///   random key; pure obscurity, both keys remain in the process heap.</item>
    /// </list>
    /// Cheaper than the hardware-backed tier and always available, but raises
    /// the bar only against attackers who don't know the wrapping scheme.
    /// </summary>
    Obscurity,

    /// <summary>
    /// Hardware-backed wrapping is required. If no hardware-backed provider
    /// is registered for the current platform, construction throws
    /// <see cref="System.PlatformNotSupportedException"/> immediately —
    /// <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/> is
    /// intentionally <i>not</i> consulted, because silently downgrading a
    /// hard security request defeats the point of asking for it.
    /// <para>
    /// Built-in providers: Apple Secure Enclave (macOS / iOS / Mac Catalyst
    /// with SEP), Android Keystore (TEE on API 23+, on <c>net10.0-android</c>).
    /// External providers: register via
    /// <see cref="KeyAtRestProtectorFactory.RegisterHardwareBacked"/> — the
    /// optional <c>TopSecret.ProtectedString.WindowsTpm</c> and
    /// <c>TopSecret.ProtectedString.LinuxTpm</c> NuGets do this at module init
    /// for TPM 2.0 on their respective platforms.
    /// </para>
    /// <para>
    /// Per-op cost: low single-digit ms on Apple Silicon SEP, ~50–500 ms on
    /// Android TEE, ~5–15 ms on a discrete TPM. See
    /// <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/> for the
    /// opt-in cache that amortises the round-trip on hot paths.
    /// </para>
    /// </summary>
    HardwareBackedRequired,

    /// <summary>
    /// Best effort: try the hardware-backed tier first, fall back to
    /// <see cref="Obscurity"/> if no hardware-backed provider succeeds, fall
    /// back to <see cref="None"/> silently if obscurity also fails. The "mixed"
    /// path — recommended when you want to take whatever hardware-backed
    /// protection the platform offers without a hard failure on platforms
    /// that don't have any. Per-op cost is whatever the active tier costs.
    /// </summary>
    HardwareBackedPreferred,
}

/// <summary>
/// Process-wide configuration for <see cref="ProtectedString"/>.
/// </summary>
/// <remarks>
/// <para>
/// Set properties before the first <see cref="ProtectedString"/> instance is
/// constructed; values are read at construction time. The class deliberately
/// has no dependency on <c>Microsoft.Extensions.Configuration</c> — bind from
/// <c>appsettings.json</c> in your composition root, e.g.:
/// </para>
/// <code>
/// // appsettings.json
/// // "TopSecret": {
/// //   "ProtectedString": {
/// //     "MemoryLockingFailureBehavior": "Throw"
/// //   }
/// // }
///
/// if (Enum.TryParse&lt;MemoryLockingFailureBehavior&gt;(
///         configuration["TopSecret:ProtectedString:MemoryLockingFailureBehavior"],
///         ignoreCase: true, out var behavior))
/// {
///     ProtectedStringOptions.MemoryLockingFailureBehavior = behavior;
/// }
/// </code>
/// </remarks>
public static class ProtectedStringOptions
{
    /// <summary>
    /// Behavior when a <c>VirtualLock</c> / <c>mlock</c> call fails or the
    /// primitive is unavailable on this platform. Also governs failures of
    /// other hardening primitives (<c>madvise(MADV_DONTDUMP)</c>,
    /// <c>prctl(PR_SET_DUMPABLE, 0)</c>, <c>setrlimit(RLIMIT_CORE, 0)</c>,
    /// and Apple Secure Enclave / Android Keystore key wrapping when
    /// <see cref="KeyAtRestProtection"/> is
    /// <see cref="TopSecret.KeyAtRestProtection.HardwareBackedRequired"/>). Defaults
    /// to <see cref="MemoryLockingFailureBehavior.LogWarning"/>.
    /// </summary>
    public static MemoryLockingFailureBehavior MemoryLockingFailureBehavior { get; set; }
        = MemoryLockingFailureBehavior.LogWarning;

    /// <summary>
    /// Process-key rotation policy. Defaults to
    /// <see cref="TopSecret.ProcessKeyRotation.Disabled"/> — no registry,
    /// no overhead.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When set to <see cref="TopSecret.ProcessKeyRotation.OnDemand"/> or
    /// <see cref="TopSecret.ProcessKeyRotation.Periodic"/>, every
    /// <see cref="ProtectedString"/> constructed thereafter is added to a
    /// weak-reference registry so it can be re-encrypted under a fresh master
    /// when <see cref="ProtectedString.RotateProcessKey"/> is invoked.
    /// </para>
    /// <para>
    /// Constructors hold a brief shared rotation lock while they snapshot the
    /// current protector and register themselves; rotations hold the same lock
    /// while they swap the protector and snapshot the registry. Both phases
    /// are short — the per-instance migration runs outside the global lock.
    /// </para>
    /// <para>
    /// <b>Threat-model honesty.</b> Rotation does <i>not</i> defend against an
    /// attacker who can read the running process — they can read the new key
    /// just as easily as the old one. Where it earns its keep is bounding the
    /// blast radius of a one-shot historical disclosure (an old core file, a
    /// crash dump captured at time T): ciphertext encrypted under a key that
    /// has since rotated cannot be decrypted without that old key, and the old
    /// key has been zeroed from process memory.
    /// </para>
    /// </remarks>
    public static ProcessKeyRotation ProcessKeyRotationPolicy { get; set; }
        = ProcessKeyRotation.Disabled;

    /// <summary>
    /// Interval between automatic rotations when
    /// <see cref="ProcessKeyRotationPolicy"/> is
    /// <see cref="TopSecret.ProcessKeyRotation.Periodic"/>. Defaults to one
    /// hour. Read once when the rotation timer is first started; changing it
    /// after that has no effect on the running timer — a one-shot
    /// <see cref="System.Diagnostics.Trace.TraceWarning(string)"/> fires when
    /// any read-once option is mutated late so the silent no-op is at least
    /// loud.
    /// </summary>
    public static TimeSpan ProcessKeyRotationInterval
    {
        get => s_processKeyRotationInterval;
        set
        {
            WarnIfLateMutation(nameof(ProcessKeyRotationInterval));
            s_processKeyRotationInterval = value;
        }
    }
    private static TimeSpan s_processKeyRotationInterval = TimeSpan.FromHours(1);

    /// <summary>
    /// Whether to wrap the per-process AES master key with a hardware-resident
    /// wrapping key. Defaults to
    /// <see cref="TopSecret.KeyAtRestProtection.None"/> — opt in by setting to
    /// <see cref="TopSecret.KeyAtRestProtection.HardwareBackedRequired"/> or
    /// <see cref="TopSecret.KeyAtRestProtection.HardwareBackedPreferred"/>
    /// before the first <see cref="ProtectedString"/> is constructed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Built-in hardware-backed providers ship on Apple (Secure Enclave) and
    /// on the <c>net10.0-android</c> TFM (Android Keystore TEE). For Windows
    /// or Linux TPM 2.0 wrapping, reference the optional
    /// <c>TopSecret.ProtectedString.WindowsTpm</c> or
    /// <c>TopSecret.ProtectedString.LinuxTpm</c> NuGet — both auto-register a
    /// hardware-backed provider via <c>ModuleInitializer</c> when their
    /// assembly loads.
    /// </para>
    /// <para>
    /// Per-op cost is paid on every encrypt and decrypt round-trip to the
    /// secure element:
    /// </para>
    /// <list type="bullet">
    /// <item>Apple Silicon SEP: low single-digit ms per op.</item>
    /// <item>Android Keystore via TEE: ~50–500 ms per op.</item>
    /// <item>Discrete TPM 2.0 RSA-2048 decrypt: ~5–15 ms per op.</item>
    /// <item>Android StrongBox: seconds for large payloads; ruinous on a hot path.</item>
    /// </list>
    /// <para>
    /// See <see cref="UnwrappedKeyCacheTtl"/> for the opt-in cache that
    /// amortises the round-trip on hot paths.
    /// </para>
    /// <para>
    /// <b>Read once at the first <see cref="ProtectedString"/> construction.</b>
    /// Mutating this property after that point has no effect on the running
    /// process protector — a one-shot
    /// <see cref="System.Diagnostics.Trace.TraceWarning(string)"/> fires the
    /// first time any read-once option is mutated late. Use
    /// <see cref="ProtectedString.RotateProcessKey"/> to swap protectors at
    /// runtime instead.
    /// </para>
    /// </remarks>
    public static KeyAtRestProtection KeyAtRestProtection
    {
        get => s_keyAtRestProtection;
        set
        {
            WarnIfLateMutation(nameof(KeyAtRestProtection));
            s_keyAtRestProtection = value;
        }
    }
    private static KeyAtRestProtection s_keyAtRestProtection = KeyAtRestProtection.None;

    /// <summary>
    /// How long an unwrapped master key may be held in pinned, locked memory
    /// after the hardware/obscurity wrapping was reversed, before the next
    /// operation is required to re-unwrap. Defaults to
    /// <see cref="TimeSpan.Zero"/>, which disables caching: every encrypt and
    /// decrypt pays the full unwrap cost.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Setting this to a small positive value (e.g. 250 ms) makes
    /// <see cref="TopSecret.KeyAtRestProtection.HardwareBackedRequired"/> /
    /// <see cref="TopSecret.KeyAtRestProtection.HardwareBackedPreferred"/>
    /// usable on hot paths where the per-op TPM / Keystore round-trip would
    /// otherwise dominate. The unwrapped master is held in a pinned, locked,
    /// dump-excluded buffer for at most the TTL; an idle timer wipes the
    /// buffer with <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory(System.Span{byte})"/>
    /// once the TTL elapses without further use.
    /// </para>
    /// <para>
    /// <b>Trade-off.</b> Caching widens the window in which a heap dump finds
    /// the unwrapped master in memory, even when no
    /// <see cref="ProtectedString"/> operation is in flight. The library's
    /// threat model already accepts an in-flight <see cref="ProtectedString.Access(System.Action{char[]})"/>
    /// window — choose a TTL that does not materially extend it. Default is
    /// off because there is no universally safe value.
    /// </para>
    /// <para>
    /// Read once at the first <see cref="ProtectedString"/> construction (or
    /// at the next process-key rotation, when applicable). Changing the value
    /// later does not retroactively expand or shrink an existing cache.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The value is negative. Use <see cref="TimeSpan.Zero"/> to disable
    /// caching.
    /// </exception>
    public static TimeSpan UnwrappedKeyCacheTtl
    {
        get => s_unwrappedKeyCacheTtl;
        set
        {
            if (value < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(value), value,
                    "UnwrappedKeyCacheTtl must be non-negative. Use TimeSpan.Zero to disable caching.");
            }
            WarnIfLateMutation(nameof(UnwrappedKeyCacheTtl));
            s_unwrappedKeyCacheTtl = value;
        }
    }
    private static TimeSpan s_unwrappedKeyCacheTtl = TimeSpan.Zero;

    // ---- late-mutation diagnostic --------------------------------------

    private static int s_warnedLateMutation;

    /// <summary>
    /// Emit a one-shot <see cref="Trace.TraceWarning(string)"/> when a
    /// read-once option is mutated after the lazy process-wide protector
    /// has already been initialised. The warning is gated by an
    /// <see cref="Interlocked.CompareExchange(ref int, int, int)"/> so it
    /// fires once per process across all watched options.
    /// </summary>
    /// <remarks>
    /// Wire up <see cref="System.Diagnostics.TextWriterTraceListener"/> (or
    /// any other <see cref="TraceListener"/>) in your composition root if
    /// you want to see this warning — the default trace configuration in
    /// .NET libraries discards <see cref="Trace.TraceWarning(string)"/>
    /// output.
    /// </remarks>
    private static void WarnIfLateMutation(string memberName)
    {
        if (!ProtectedString.IsKeyProtectorInitialized) return;
        if (Interlocked.CompareExchange(ref s_warnedLateMutation, 1, 0) != 0) return;

        Trace.TraceWarning(
            $"ProtectedString: {nameof(ProtectedStringOptions)}.{memberName} was set after the " +
            "first ProtectedString construction. Read-once options (KeyAtRestProtection, " +
            "UnwrappedKeyCacheTtl, ProcessKeyRotationInterval) are sampled when the lazy " +
            "process-wide protector is initialised; this change has no effect on the running " +
            "protector or the live rotation timer. Set ProtectedStringOptions in your composition " +
            "root before any ProtectedString is constructed, or call ProtectedString.RotateProcessKey() " +
            "to swap protectors at runtime under the new option values.");
    }

    /// <summary>
    /// Test-only hook. Clears the one-shot late-mutation-warning gate so a
    /// test can exercise the "first mutation emits a warning" path even
    /// after a previous test (or production code) has already triggered
    /// it. The leading underscore signals that production code must not
    /// call this.
    /// </summary>
    internal static void _ResetLateMutationWarningForTests() =>
        Volatile.Write(ref s_warnedLateMutation, 0);
}
