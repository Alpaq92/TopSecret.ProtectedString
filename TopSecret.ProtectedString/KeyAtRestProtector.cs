using System.ComponentModel;
using System.Security.Cryptography;

namespace TopSecret;

public abstract class KeyAtRestProtector
{
    public abstract KeyAccessor UnwrapKey();

    internal int LifetimeHolderCount;

    internal volatile bool LifetimeSuperseded;
}

public sealed class KeyAccessor : IDisposable
{
    private readonly byte[] _key;
    private readonly bool _zeroOnDispose;

    public static KeyAccessor Persistent(byte[] master) => new(master, zeroOnDispose: false);

    public static KeyAccessor Ephemeral(byte[] buffer) => new(buffer, zeroOnDispose: true);

    private KeyAccessor(byte[] key, bool zeroOnDispose)
    {
        _key = key;
        _zeroOnDispose = zeroOnDispose;
    }

    public byte[] Key => _key;

    public void Dispose()
    {
        if (!_zeroOnDispose || _key.Length == 0) return;
        CryptographicOperations.ZeroMemory(_key);
        MemoryLocker.TryUnlock(_key);
    }
}

internal sealed class NoopKeyAtRestProtector : DisposableKeyAtRestProtector
{
    private readonly byte[] _master;

    public NoopKeyAtRestProtector(byte[] master)
    {
        _master = master;

        HardeningPolicy.LockAndExclude(master, "memory locking the master AES key");
    }

    protected override KeyAccessor UnwrapCore() => KeyAccessor.Persistent(_master);

    protected override void ReleaseResources()
    {
        if (_master.Length > 0)
        {
            CryptographicOperations.ZeroMemory(_master);
            MemoryLocker.TryUnlock(_master);
        }
    }
}

public static class KeyAtRestProtectorFactory
{
    public delegate KeyAtRestProtector? HardwareBackedFactory(byte[] master);

    public delegate bool HardwareBackedAvailabilityProbe();

    private readonly record struct Registration(
        HardwareBackedFactory Factory,
        HardwareBackedAvailabilityProbe? Probe,
        bool TransientSlotConstrained);

    private static readonly object s_registerLock = new();
    private static readonly List<Registration> s_registered = new();

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

    internal static bool IsHardwareBackedAvailableForCurrentPlatform()
    {
        if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
        {
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

    [Obsolete("test-only; do not call from production code", error: true)]
    [EditorBrowsable(EditorBrowsableState.Never)]
    internal static void ResetRegistrationsForTests()
    {
        lock (s_registerLock) s_registered.Clear();
    }

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

        if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
            return;
#if ANDROID
        if (OperatingSystem.IsAndroid()) return;
#endif

        bool registryEmpty;
        lock (s_registerLock) registryEmpty = s_registered.Count == 0;
        if (!registryEmpty) return;

        // Cheap pre-check so the (long) message is not built on every Create
        // once the gate has tripped; WarnOnce.Trace re-checks atomically.
        if (Volatile.Read(ref s_warnedNoProvider) != 0) return;

        string platformHint = OperatingSystem.IsWindows()
            ? "Reference the optional 'TopSecret.ProtectedString.WindowsTpm' NuGet (and ensure its ModuleInitializer fires before the first ProtectedString construction; if you use lazy assembly loading, call WindowsTpmRegistration.Register() explicitly in your composition root), or register your own hardware-backed provider via KeyAtRestProtectorFactory.RegisterHardwareBacked()."
            : OperatingSystem.IsLinux()
                ? "Reference the optional 'TopSecret.ProtectedString.LinuxTpm' NuGet (and ensure its ModuleInitializer fires before the first ProtectedString construction; if you use lazy assembly loading, call LinuxTpmRegistration.Register() explicitly in your composition root), or register your own hardware-backed provider via KeyAtRestProtectorFactory.RegisterHardwareBacked()."
                : "No hardware-backed provider is registered for this platform; register one via KeyAtRestProtectorFactory.RegisterHardwareBacked() before the first ProtectedString construction.";

        WarnOnce.Trace(ref s_warnedNoProvider,
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

        if (mode == KeyAtRestProtection.GuardedPage)
        {
            var guarded = PageGuardedKeyProtector.TryCreate(master);
            if (guarded is not null) return guarded;
            // TryCreate returned null without consuming the master (no page
            // protection on this platform) — degrade to obscurity.
        }

        // Tier 2 — software obscurity.
        if (mode == KeyAtRestProtection.Obscurity ||
            mode == KeyAtRestProtection.GuardedPage ||
            mode == KeyAtRestProtection.HardwareBackedPreferred)
        {
            var soft = TryCreateObscurity(master);
            if (soft is not null) return soft;

            if (mode == KeyAtRestProtection.Obscurity || mode == KeyAtRestProtection.GuardedPage)
            {
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
            }
        }

        return null;
    }

    private static KeyAtRestProtector? TryCreateObscurity(byte[] master)
    {
        return (KeyAtRestProtector?)AesGcmWrapProtector.TryCreate(master)
            ?? HkdfWrapProtector.TryCreate(master);
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

internal static class HardwareProviderRegistration
{
    public static void RegisterOnce(
        ref int gate,
        KeyAtRestProtectorFactory.HardwareBackedFactory factory,
        KeyAtRestProtectorFactory.HardwareBackedAvailabilityProbe probe,
        bool transientSlotConstrained)
    {
        if (Interlocked.CompareExchange(ref gate, 1, 0) != 0) return;
        KeyAtRestProtectorFactory.RegisterHardwareBacked(factory, probe, transientSlotConstrained);
    }
}
