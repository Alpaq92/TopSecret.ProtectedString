using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;

namespace TopSecret;

/// <summary>
/// Abstracts how the per-process AES master key is held at rest in memory.
/// </summary>
/// <remarks>
/// <para>
/// Two shapes ship in the box:
/// </para>
/// <list type="bullet">
///   <item><c>NoopKeyAtRestProtector</c> — the master key is held plaintext in
///   a pinned, locked, dump-excluded byte array; <see cref="UnwrapKey"/> hands
///   the same array out without copying or zeroing.</item>
///   <item><see cref="AppleSecKeyProtector"/> /
///   <c>AndroidKeystoreProtector</c> (the latter compiled only into the
///   <c>net10.0-android</c> TFM) — the master is wrapped at init with a
///   hardware-resident key (Apple Secure Enclave EC P-256 ECIES, Android
///   Keystore AES-GCM); the unwrap on each call returns a freshly allocated,
///   pinned, locked, dump-excluded buffer that <see cref="KeyAccessor.Dispose"/>
///   zeros and unlocks.</item>
/// </list>
/// <para>
/// Additional providers can be registered through
/// <see cref="KeyAtRestProtectorFactory.RegisterHardwareBacked"/>. The
/// <c>TopSecret.ProtectedString.WindowsTpm</c> NuGet uses this mechanism to
/// register a TPM 2.0 protector via <c>ModuleInitializer</c>.
/// </para>
/// <para>
/// Selected by <see cref="ProtectedStringOptions.KeyAtRestProtection"/> via
/// <see cref="KeyAtRestProtectorFactory"/>.
/// </para>
/// </remarks>
public abstract class KeyAtRestProtector
{
    /// <summary>
    /// Returns a disposable scope holding the unwrapped 32-byte master key.
    /// Caller must dispose it as soon as the <see cref="AesGcm"/> operation
    /// completes — the buffer is zeroed and unlocked on dispose for the
    /// hardware-backed implementations.
    /// </summary>
    public abstract KeyAccessor UnwrapKey();

    /// <summary>
    /// Holder count maintained by <see cref="ProtectorLifetime"/> — internal
    /// lifetime bookkeeping, not part of the protector contract. Lives on
    /// the protector itself (rather than a side table) so AddRef/Release are
    /// bare Interlocked operations.
    /// </summary>
    internal int LifetimeHolderCount;

    /// <summary>Set once this protector has been rotated out; see <see cref="ProtectorLifetime.MarkSuperseded"/>.</summary>
    internal volatile bool LifetimeSuperseded;
}

/// <summary>
/// Disposable scope around an unwrapped master-key byte array. For the
/// no-op protector this just hands back the long-lived master without
/// touching it; for the hardware-backed protectors the array is freshly
/// allocated, pinned, locked, dump-excluded, and zeroed + unlocked on
/// dispose.
/// </summary>
public sealed class KeyAccessor : IDisposable
{
    private readonly byte[] _key;
    private readonly bool _zeroOnDispose;

    /// <summary>Wraps the long-lived master without copying. Dispose is a no-op.</summary>
    public static KeyAccessor Persistent(byte[] master) => new(master, zeroOnDispose: false);

    /// <summary>Wraps a freshly allocated pinned/locked/dontdumped buffer; Dispose zeros + unlocks it.</summary>
    public static KeyAccessor Ephemeral(byte[] buffer) => new(buffer, zeroOnDispose: true);

    private KeyAccessor(byte[] key, bool zeroOnDispose)
    {
        _key = key;
        _zeroOnDispose = zeroOnDispose;
    }

    /// <summary>The unwrapped 32-byte AES master key. Valid until this scope is disposed.</summary>
    public byte[] Key => _key;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!_zeroOnDispose || _key.Length == 0) return;
        CryptographicOperations.ZeroMemory(_key);
        MemoryLocker.TryUnlock(_key);
    }
}

/// <summary>
/// No-op protector — the master key sits plaintext in pinned, locked,
/// dump-excluded memory for the process lifetime. Default behaviour, used on
/// any platform when <see cref="ProtectedStringOptions.KeyAtRestProtection"/>
/// is <see cref="KeyAtRestProtection.None"/>.
/// </summary>
/// <remarks>
/// <para>
/// Implements <see cref="IDisposable"/> so process-key rotation can release
/// the mlocked / VirtualLocked master when the protector is replaced. The
/// finalizer is the safety net for the rotation-orphans-old-protector path
/// (see <see cref="ProtectedString.RotateProcessKey"/>) — without it, every
/// rotated-out master would stay locked until process exit, eating the
/// <c>RLIMIT_MEMLOCK</c> budget on libc targets.
/// </para>
/// <para>
/// <b>Disposal contract.</b> <see cref="UnwrapKey"/> hands back the master
/// via <see cref="KeyAccessor.Persistent(byte[])"/> — i.e. the caller's
/// <see cref="KeyAccessor.Key"/> aliases the protector's <c>_master</c>
/// without copying. <see cref="Dispose"/> zeros that array in place, which
/// invalidates every outstanding <see cref="KeyAccessor"/> that came from
/// this protector. Production code never reaches this from a live code
/// path: Dispose fires via <see cref="ProtectorLifetime"/> only after a
/// rotation superseded this protector <i>and</i> the last holder
/// (<see cref="ProtectedString"/> / <c>ProtectedBlob</c> instance) released
/// it — at which point no operation can be in flight — or from the GC
/// finalizer safety net. If you ever construct a
/// <see cref="NoopKeyAtRestProtector"/> by hand and call Dispose, do it
/// after every accessor it issued has been disposed.
/// </para>
/// </remarks>
internal sealed class NoopKeyAtRestProtector : KeyAtRestProtector, IDisposable
{
    private readonly byte[] _master;
    private bool _disposed;

    public NoopKeyAtRestProtector(byte[] master)
    {
        _master = master;

        // Lock the master into resident memory and dump-exclude it once. Any
        // failure applies the user-configured policy (Throw / LogWarning /
        // Ignore) via HardeningPolicy.
        HardeningPolicy.LockAndExclude(master, "memory locking the master AES key");
    }

    public override KeyAccessor UnwrapKey()
    {
        // Load-bearing since ProtectorLifetime made disposal deterministic:
        // without this guard a lifetime-accounting bug would hand back the
        // zeroed master and encrypt silently under an all-zero key instead
        // of failing loudly.
        ObjectDisposedException.ThrowIf(_disposed, this);
        return KeyAccessor.Persistent(_master);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_master.Length > 0)
        {
            CryptographicOperations.ZeroMemory(_master);
            MemoryLocker.TryUnlock(_master);
        }
        GC.SuppressFinalize(this);
    }

    ~NoopKeyAtRestProtector()
    {
        try { Dispose(); } catch { /* finalizer must not throw */ }
    }
}

/// <summary>
/// Selects the appropriate <see cref="KeyAtRestProtector"/> based on
/// <see cref="ProtectedStringOptions.KeyAtRestProtection"/>, the current
/// platform, and any hardware-backed providers registered through
/// <see cref="RegisterHardwareBacked"/>.
/// </summary>
/// <remarks>
/// <para>
/// The factory takes ownership of the master byte array: for every
/// non-<see cref="NoopKeyAtRestProtector"/> outcome, the master is wrapped
/// and the original array is zeroed before <see cref="Create"/> returns.
/// </para>
/// <para>
/// Two protection tiers are walked depending on the configured mode:
/// </para>
/// <list type="number">
///   <item><b>Hardware-backed</b> — <see cref="AppleSecKeyProtector"/> on
///   macOS / iOS / Mac Catalyst (built-in), <c>AndroidKeystoreProtector</c>
///   on the <c>net10.0-android</c> TFM (built-in), plus any external providers
///   registered via <see cref="RegisterHardwareBacked"/>. The
///   <c>TopSecret.ProtectedString.WindowsTpm</c> and
///   <c>TopSecret.ProtectedString.LinuxTpm</c> NuGets register TPM 2.0
///   providers here.</item>
///   <item><b>Obscurity (software wrap)</b> —
///   <see cref="WindowsAesGcmEphemeralProtector"/> on Windows,
///   <see cref="HkdfWrapProtector"/> as the universal fallback.</item>
/// </list>
/// <para>
/// <see cref="KeyAtRestProtection.HardwareBackedRequired"/> stops at tier 1
/// and throws <see cref="PlatformNotSupportedException"/> on tier-1 failure —
/// independently of <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/>,
/// because silently downgrading a hard security request defeats the point.
/// <see cref="KeyAtRestProtection.Obscurity"/> skips tier 1 and stops at
/// tier 2 (which always succeeds via the HKDF fallback).
/// <see cref="KeyAtRestProtection.HardwareBackedPreferred"/> walks tier 1 →
/// tier 2 → no-op silently.
/// </para>
/// <para>
/// When <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/> is greater
/// than <see cref="TimeSpan.Zero"/> and the chosen protector is not the
/// no-op, the result is wrapped in <see cref="TtlCachingKeyAtRestProtector"/>
/// to amortise the per-op unwrap cost.
/// </para>
/// </remarks>
public static class KeyAtRestProtectorFactory
{
    /// <summary>
    /// A registered hardware-backed factory. <paramref name="master"/> is
    /// the 32-byte AES master that the protector takes ownership of. Return
    /// <see langword="null"/> to indicate this provider cannot construct on
    /// the current platform / configuration; the factory will continue
    /// walking other registered providers and the built-in tiers.
    /// </summary>
    public delegate KeyAtRestProtector? HardwareBackedFactory(byte[] master);

    /// <summary>
    /// A predicate reporting whether this provider would (probably) succeed
    /// on the current platform without consuming a master key. Used by
    /// <see cref="ProtectedString.HardwareBackedAvailability"/> to surface
    /// availability without a destructive probe.
    /// </summary>
    public delegate bool HardwareBackedAvailabilityProbe();

    private readonly record struct Registration(
        HardwareBackedFactory Factory,
        HardwareBackedAvailabilityProbe? Probe,
        bool TransientSlotConstrained);

    private static readonly object s_registerLock = new();
    private static readonly List<Registration> s_registered = new();

    /// <summary>
    /// Registers an external hardware-backed protector factory. Intended for
    /// platform-specific subpackages (e.g. <c>TopSecret.ProtectedString.WindowsTpm</c>
    /// for TPM 2.0) to plug in without the main package taking a hard
    /// dependency on Windows / Linux native APIs.
    /// </summary>
    /// <param name="factory">
    /// Builds a protector wrapping the master byte array passed in. Returns
    /// <see langword="null"/> when the provider cannot construct on the
    /// current host.
    /// </param>
    /// <param name="availabilityProbe">
    /// Optional. Reports whether this provider <i>would</i> succeed without
    /// actually consuming a master. Used by
    /// <see cref="ProtectedString.HardwareBackedAvailability"/>. If omitted,
    /// the registration counts as "available" whenever the registry is
    /// queried — providers that do real probing should supply one.
    /// </param>
    /// <param name="transientSlotConstrained">
    /// Set to <see langword="true"/> when the provider's underlying secure
    /// element keeps generated keys in a small pool of transient slots that
    /// the consuming code is responsible for releasing — TPM 2.0 is the
    /// canonical example (commodity TPMs hold only ≤3 transient keys, so
    /// repeated process-key rotations under
    /// <see cref="ProcessKeyRotation.Periodic"/> would exhaust them in a
    /// few cycles). When any registered provider has this flag set,
    /// enabling periodic rotation emits a one-shot
    /// <see cref="System.Diagnostics.Trace.TraceWarning(string)"/> so the
    /// operator notices before <c>TPM_RC_RESOURCES</c> starts surfacing.
    /// </param>
    /// <remarks>
    /// Registration order matters only as a fallback ranking: the factory
    /// tries each registered provider in registration order and returns the
    /// first non-null result. Built-in providers (Apple SEP, Android
    /// Keystore) are tried <i>before</i> external registrations on the
    /// platforms where they ship.
    /// </remarks>
    public static void RegisterHardwareBacked(
        HardwareBackedFactory factory,
        HardwareBackedAvailabilityProbe? availabilityProbe = null,
        bool transientSlotConstrained = false)
    {
        ArgumentNullException.ThrowIfNull(factory);
        lock (s_registerLock)
        {
            s_registered.Add(new Registration(factory, availabilityProbe, transientSlotConstrained));
        }
    }

    /// <summary>
    /// Whether at least one hardware-backed provider (built-in or registered)
    /// claims to be available for the current host.
    /// </summary>
    /// <remarks>
    /// On Apple platforms the built-in is consulted via a destructive but
    /// cached probe (<see cref="AppleSecKeyProtector.IsActuallyAvailable"/>)
    /// so that <c>iOS Simulator on x86_64</c> and pre-T1 Intel Macs report
    /// <see langword="false"/>. On Android (the <c>net10.0-android</c> TFM),
    /// the built-in is likewise consulted via a destructive but cached probe
    /// (<c>AndroidKeystoreProtector.IsActuallyAvailable</c>), so that
    /// emulators and hardware-less devices — where the Keystore silently
    /// hands back a software-level key — report <see langword="false"/>
    /// instead of a value <see cref="KeyAtRestProtectorFactory.Create"/>
    /// would then contradict. Otherwise, returns <see langword="true"/> if
    /// any registered provider's availability probe returns
    /// <see langword="true"/>, or — if the provider registered without a
    /// probe — if any registration exists at all. Returns
    /// <see langword="false"/> when nothing claims availability.
    /// </remarks>
    internal static bool IsHardwareBackedAvailableForCurrentPlatform()
    {
        if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
        {
            // Destructive (generate-and-discard) probe with a process-lifetime
            // cache, so the Simulator and pre-T1 Intel Macs report false even
            // though the built-in provider ships in the assembly.
            return AppleSecKeyProtector.IsActuallyAvailable();
        }

#if ANDROID
        if (OperatingSystem.IsAndroid())
        {
            // Destructive (generate-and-discard) probe with a process-lifetime
            // cache, mirroring the Apple path — emulators and hardware-less
            // devices report false instead of a value construction would
            // then contradict via the residency check in CreateOrThrow.
            return AndroidKeystoreProtector.IsActuallyAvailable();
        }
#endif

        lock (s_registerLock)
        {
            if (s_registered.Count == 0) return false;
            foreach (var reg in s_registered)
            {
                if (reg.Probe is null) return true;
                if (reg.Probe()) return true;
            }
            return false;
        }
    }

    /// <summary>
    /// Whether any registered hardware-backed provider declared itself
    /// transient-slot constrained (e.g. TPM 2.0). Used by
    /// <see cref="ProtectedString"/> to emit a one-shot warning when periodic
    /// rotation is enabled alongside such a provider.
    /// </summary>
    internal static bool HasTransientSlotConstrainedProvider()
    {
        lock (s_registerLock)
        {
            foreach (var reg in s_registered)
            {
                if (reg.TransientSlotConstrained) return true;
            }
            return false;
        }
    }

    /// <summary>
    /// Test-only hook. Clears the external-provider registry so a test can
    /// exercise the empty-registry path after another test (or a module
    /// initializer) has registered something. Marked <c>internal</c>;
    /// production code is blocked at compile time by
    /// <see cref="ObsoleteAttribute"/> with <c>error: true</c> — any direct
    /// source-level reference produces CS0619 and fails to compile, and
    /// <see cref="EditorBrowsableAttribute"/> additionally hides this member
    /// from IntelliSense in consumer assemblies. The cross-platform test
    /// fixture invokes the method via <c>TestAccessors.ResetFactoryRegistrations</c>,
    /// which uses reflection — that bypasses the compile-time check (the
    /// only legitimate way out of CS0619) while still requiring
    /// <c>[InternalsVisibleTo]</c> for the runtime metadata lookup. If you
    /// are reading this from production code, you are about to make a
    /// mistake.
    /// </summary>
    [Obsolete("test-only; do not call from production code", error: true)]
    [EditorBrowsable(EditorBrowsableState.Never)]
    internal static void ResetRegistrationsForTests()
    {
        lock (s_registerLock) s_registered.Clear();
    }

    /// <summary>
    /// Builds the protector that holds <paramref name="master"/> at rest.
    /// </summary>
    internal static KeyAtRestProtector Create(byte[] master)
    {
        var mode = ProtectedStringOptions.KeyAtRestProtection;
        WarnIfHardwareBackedRequestedButNoProviderRegistered(mode);

        var inner = CreateInner(master, mode);

        var ttl = ProtectedStringOptions.UnwrappedKeyCacheTtl;
        if (ttl > TimeSpan.Zero && inner is not NoopKeyAtRestProtector)
        {
            return new TtlCachingKeyAtRestProtector(inner, ttl);
        }
        return inner;
    }

    private static int s_warnedNoProvider;

    private static void WarnIfHardwareBackedRequestedButNoProviderRegistered(KeyAtRestProtection mode)
    {
        if (mode != KeyAtRestProtection.HardwareBackedRequired &&
            mode != KeyAtRestProtection.HardwareBackedPreferred)
        {
            return;
        }

        // Built-in providers ship for Apple and (on the right TFM) Android.
        // For other platforms, an unregistered hardware tier almost always
        // means the consumer forgot to either install the matching subpackage
        // or call <Subpackage>Registration.Register() before the first
        // ProtectedString construction. Emit one-shot guidance to make the
        // diagnostic obvious instead of mysterious.
        if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
            return;
#if ANDROID
        if (OperatingSystem.IsAndroid()) return;
#endif

        bool registryEmpty;
        lock (s_registerLock) registryEmpty = s_registered.Count == 0;
        if (!registryEmpty) return;

        if (Interlocked.CompareExchange(ref s_warnedNoProvider, 1, 0) != 0) return;

        string platformHint = OperatingSystem.IsWindows()
            ? "Reference the optional 'TopSecret.ProtectedString.WindowsTpm' NuGet (and ensure its ModuleInitializer fires before the first ProtectedString construction; if you use lazy assembly loading, call WindowsTpmRegistration.Register() explicitly in your composition root), or register your own hardware-backed provider via KeyAtRestProtectorFactory.RegisterHardwareBacked()."
            : OperatingSystem.IsLinux()
                ? "Reference the optional 'TopSecret.ProtectedString.LinuxTpm' NuGet (and ensure its ModuleInitializer fires before the first ProtectedString construction; if you use lazy assembly loading, call LinuxTpmRegistration.Register() explicitly in your composition root), or register your own hardware-backed provider via KeyAtRestProtectorFactory.RegisterHardwareBacked()."
                : "No hardware-backed provider is registered for this platform; register one via KeyAtRestProtectorFactory.RegisterHardwareBacked() before the first ProtectedString construction.";

        Trace.TraceWarning(
            $"ProtectedString: KeyAtRestProtection is {mode} but no hardware-backed provider " +
            $"is registered for this platform. {platformHint}");
    }

    private static KeyAtRestProtector CreateInner(byte[] master, KeyAtRestProtection mode)
    {
        if (mode == KeyAtRestProtection.None)
        {
            return new NoopKeyAtRestProtector(master);
        }

        // Tier 1 — hardware-backed.
        if (mode == KeyAtRestProtection.HardwareBackedRequired ||
            mode == KeyAtRestProtection.HardwareBackedPreferred)
        {
            var hw = TryCreateHardwareBacked(master);
            if (hw is not null) return hw;

            if (mode == KeyAtRestProtection.HardwareBackedRequired)
            {
                // Loud, unconditional failure — bypass MemoryLockingFailureBehavior
                // because the whole point of Required is "don't downgrade me".
                throw new PlatformNotSupportedException(BuildRequiredFailureMessage());
            }
            // Preferred: fall through to obscurity tier silently.
        }

        // Tier 2 — software obscurity.
        if (mode == KeyAtRestProtection.Obscurity ||
            mode == KeyAtRestProtection.HardwareBackedPreferred)
        {
            var soft = TryCreateObscurity(master);
            if (soft is not null) return soft;

            if (mode == KeyAtRestProtection.Obscurity)
            {
                // The HKDF fallback inside TryCreateObscurity should have
                // succeeded. If we got here, every cross-platform path
                // failed — apply the configured policy.
                HardeningPolicy.OnFailure("software-obscurity key wrapping");
            }
        }

        return new NoopKeyAtRestProtector(master);
    }

    private static KeyAtRestProtector? TryCreateHardwareBacked(byte[] master)
    {
        // Built-in: Apple Secure Enclave on macOS / iOS / Mac Catalyst.
        if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
        {
            var apple = AppleSecKeyProtector.TryCreate(master);
            if (apple is not null) return apple;
        }

        // Built-in: Android Keystore on the net10.0-android TFM.
#if ANDROID
        if (OperatingSystem.IsAndroid())
        {
            var android = AndroidKeystoreProtector.TryCreate(master);
            if (android is not null) return android;
        }
#endif

        // External registrations (e.g. TopSecret.ProtectedString.WindowsTpm TPM).
        // Snapshot under lock so a concurrent RegisterHardwareBacked call
        // cannot perturb the iteration.
        Registration[] snapshot;
        lock (s_registerLock)
        {
            if (s_registered.Count == 0) return null;
            snapshot = s_registered.ToArray();
        }

        foreach (var reg in snapshot)
        {
            try
            {
                var protector = reg.Factory(master);
                if (protector is not null) return protector;
            }
            catch
            {
                // A failing registered provider should not crash construction;
                // try the next one. Required-mode callers will still get the
                // PlatformNotSupportedException from CreateInner if every
                // provider returns null / throws.
            }
        }

        return null;
    }

    private static KeyAtRestProtector? TryCreateObscurity(byte[] master)
    {
        if (OperatingSystem.IsWindows())
        {
            var windows = WindowsAesGcmEphemeralProtector.TryCreate(master);
            if (windows is not null) return windows;
            // Fall through to HKDF if AES-GCM construction declined
            // (vanishingly unlikely — no external dependencies — but the
            // contract permits null).
        }

        // Universal fallback. Always succeeds for a 32-byte master.
        return HkdfWrapProtector.TryCreate(master);
    }

    private static string BuildRequiredFailureMessage()
    {
        var hint = OperatingSystem.IsWindows()
            ? " Reference the optional 'TopSecret.ProtectedString.WindowsTpm' NuGet to enable TPM-backed wrapping on Windows."
            : OperatingSystem.IsLinux()
                ? " Reference the optional 'TopSecret.ProtectedString.LinuxTpm' NuGet to enable TPM-backed wrapping on Linux."
                : (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
                    ? " Apple Secure Enclave is unavailable on this host (e.g. iOS Simulator on x86_64, or a pre-T1 Intel Mac)."
                    : string.Empty;

        return
            "ProtectedString: KeyAtRestProtection.HardwareBackedRequired is set but no hardware-backed " +
            "protector is available for this platform." + hint +
            " Set KeyAtRestProtection.HardwareBackedPreferred to fall back to obscurity, or set " +
            "KeyAtRestProtection.Obscurity / None to opt out of hardware-backed wrapping.";
    }
}
