#if ANDROID
using System.Diagnostics;
using System.Security.Cryptography;
using Android.App;
using Android.Provider;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using CipherMode = Javax.Crypto.CipherMode;

namespace TopSecret;

/// <summary>
/// Wraps the per-process AES master key with an AES-GCM-256 key generated
/// inside the <c>AndroidKeyStore</c> provider. The Keystore-resident wrapping
/// key never enters the app process — encrypt and decrypt cross a Binder IPC
/// boundary into the system <c>keystore2</c> daemon, which forwards them to
/// the Keymaster/KeyMint trusted application running in the TEE (or, on
/// StrongBox devices that were asked for it, a discrete secure element —
/// this provider requests plain TEE; see below).
/// </summary>
/// <remarks>
/// <para>
/// <b>Hardware residency is verified, not assumed.</b> Android Keystore
/// silently falls back to a software implementation when no hardware
/// keymaster is available (emulators, some low-end devices) — no exception
/// is thrown. After generating the wrapping key this provider introspects it
/// via <see cref="KeyInfo"/> (<c>getSecurityLevel()</c> on API 31+,
/// <c>isInsideSecureHardware()</c> before that) and refuses software-level
/// keys: <see cref="TryCreate"/> returns <see langword="null"/> so the
/// factory falls back per the configured tier policy
/// (<see cref="KeyAtRestProtection.HardwareBackedRequired"/> fails closed,
/// <see cref="KeyAtRestProtection.HardwareBackedPreferred"/> drops to the
/// obscurity tier), with a one-shot <see cref="Trace.TraceWarning(string)"/>
/// explaining the demotion. The same residency check backs
/// <see cref="IsActuallyAvailable"/>, so
/// <see cref="ProtectedString.HardwareBackedAvailability"/> agrees with what
/// construction will actually do.
/// </para>
/// <para>
/// We deliberately do <i>not</i> request StrongBox via
/// <c>SetIsStrongBoxBacked(true)</c>: it is markedly slower per operation
/// (roughly 2× for a 32-byte unwrap) and absent on most devices, and TEE
/// already keeps the key out of the app process. A StrongBox opt-in (with
/// <c>StrongBoxUnavailableException</c> fallback) is a possible future tier
/// for threat models that include TEE compromise.
/// </para>
/// <para>
/// <b>Alias lifecycle.</b> Each protector instance generates its own
/// uniquely-named alias, tagged with the current boot session
/// (<c>Settings.Global.BootCount</c>), so constructing a new protector (e.g.
/// via <see cref="ProtectedString.RotateProcessKey"/>, which never disposes
/// the protector it supersedes) never invalidates a still-live protector's
/// key. <see cref="Dispose"/> deletes the instance's own alias; a finalizer
/// covers the forgot-to-dispose case. Aliases are namespaced per UID, not per
/// process, so on every first construction this provider also sweeps aliases
/// tagged with an <i>earlier</i> boot session — those can only belong to
/// processes that no longer exist (Android does not preserve process state
/// across a reboot), so the sweep can never touch a key any currently-running
/// process (this one or a sibling) depends on. A crashed or force-killed
/// process's alias from the <i>current</i> boot session is not swept — it is
/// reclaimed on the next reboot instead. This also covers upgraders from
/// versions before 2.0.0, which used a single fixed, unversioned alias.
/// </para>
/// </remarks>
internal sealed class AndroidKeystoreProtector : KeyAtRestProtector, IDisposable
{
    private const string KeystoreName = "AndroidKeyStore";
    private const string AliasPrefix = "TopSecret.ProtectedString.MasterWrap.";
    private const string LegacyV1Alias = "TopSecret.ProtectedString.MasterWrap"; // fixed alias used by <= 1.x
    private const string Transformation = "AES/GCM/NoPadding";
    private const int GcmTagBits = 128;

    private readonly KeyStore _keystore;
    private readonly string _keyAlias;
    private readonly IKey _wrappingKey;
    private readonly byte[] _wrappedBlob;
    private readonly byte[] _iv;
    private bool _disposed;

    // 0 = not yet swept, 1 = swept. CAS'd up front; the sweep predicate
    // (strictly-earlier boot session only) makes the ordering race with a
    // concurrent creation benign — a fresh alias always carries the CURRENT
    // boot token, so no sweep pass, in progress or not, can ever match it.
    private static int s_sweptStaleAliases;

    // One-shot guard for the software-fallback demotion warning.
    private static int s_warnedSoftwareLevel;

    // Process-lifetime cache for IsActuallyAvailable(), mirroring
    // AppleSecKeyProtector's probe cache. 0 = unknown, 1 = available, 2 = not.
    private static int s_availabilityState;

    public static AndroidKeystoreProtector? TryCreate(byte[] master)
    {
        if (master.Length != 32) return null;
        try
        {
            return CreateOrThrow(master);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Cached probe backing <see cref="ProtectedString.HardwareBackedAvailability"/>:
    /// generates a throwaway Keystore key, verifies hardware residency via the
    /// same check <see cref="TryCreate"/> applies, and deletes it. Needed
    /// because the Keystore can silently hand back a software-level key
    /// (emulators, hardware-less devices) — a bare "Keystore API exists"
    /// check would report available on hosts where construction then fails
    /// the residency check and falls back.
    /// </summary>
    internal static bool IsActuallyAvailable()
    {
        var snapshot = Volatile.Read(ref s_availabilityState);
        if (snapshot != 0) return snapshot == 1;

        bool available;
        try
        {
            var probeMaster = new byte[32];
            using (var probe = CreateOrThrow(probeMaster))
            {
                available = true;
            }
        }
        catch
        {
            available = false;
        }

        Volatile.Write(ref s_availabilityState, available ? 1 : 2);
        return available;
    }

    private static AndroidKeystoreProtector CreateOrThrow(byte[] master)
    {
        var keystore = KeyStore.GetInstance(KeystoreName)
            ?? throw new InvalidOperationException("AndroidKeyStore unavailable.");
        keystore.Load(null);

        SweepStaleAliasesOnce(keystore);

        // Collision odds are ~2^-122 (128-bit Guid); even so, keystore2's
        // generateKey silently rebinds an existing alias rather than erroring,
        // so a collision would invalidate — not merely fail to create — an
        // unrelated live protector's key. Deemed acceptable at this
        // probability rather than adding a check-then-create round trip.
        string keyAlias = AliasPrefix + CurrentBootToken() + "." + Guid.NewGuid().ToString("N");

        var spec = new KeyGenParameterSpec.Builder(
                keyAlias,
                KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
            .SetBlockModes(KeyProperties.BlockModeGcm)!
            .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)!
            .SetKeySize(256)!
            .Build()!;

        var keyGen = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, KeystoreName)
            ?? throw new InvalidOperationException("KeyGenerator(AES, AndroidKeyStore) unavailable.");
        keyGen.Init(spec);
        var wrappingKey = keyGen.GenerateKey()
            ?? throw new InvalidOperationException("KeyGenerator.GenerateKey returned null.");

        // From here on, ANY failure must delete the alias we just created —
        // otherwise it leaks until the next reboot (this boot session's sweep
        // never touches it; see the class remarks).
        try
        {
            // Keystore degrades to a software security level silently
            // (emulators, hardware-less keymasters). A software-level key
            // would make the hardware-tier claim a lie, so verify before
            // wrapping anything and let the caller fall back per policy.
            if (!IsHardwareResident(wrappingKey))
            {
                if (Interlocked.CompareExchange(ref s_warnedSoftwareLevel, 1, 0) == 0)
                {
                    Trace.TraceWarning(
                        "ProtectedString: Android Keystore returned a software-level key " +
                        "(no hardware keymaster on this device/emulator). The hardware-backed " +
                        "tier is unavailable; falling back per the configured KeyAtRestProtection policy.");
                }
                throw new PlatformNotSupportedException(
                    "Android Keystore key is not hardware-resident (software security level).");
            }

            var cipher = Cipher.GetInstance(Transformation)
                ?? throw new InvalidOperationException("Cipher.GetInstance(AES/GCM/NoPadding) unavailable.");
            cipher.Init(CipherMode.EncryptMode, wrappingKey);
            var wrappedBlob = cipher.DoFinal(master)
                ?? throw new InvalidOperationException("Cipher.DoFinal returned null.");
            var iv = cipher.GetIV()
                ?? throw new InvalidOperationException("Cipher.GetIV returned null (Keystore did not assign an IV).");

            // Master is now wrapped against a Keystore-resident key.
            CryptographicOperations.ZeroMemory(master);

            return new AndroidKeystoreProtector(keystore, keyAlias, wrappingKey, wrappedBlob, iv);
        }
        catch
        {
            try { keystore.DeleteEntry(keyAlias); } catch { /* best effort */ }
            throw;
        }
    }

    /// <summary>
    /// Android's boot counter (<c>Settings.Global.BootCount</c>,
    /// world-readable, no permission required), API 24+. Used to tag aliases
    /// with the boot session that created them, so the stale-alias sweep can
    /// identify aliases that can only belong to processes that no longer
    /// exist. Below API 24 (this provider's floor is API 23) the counter
    /// doesn't exist; every alias then tags as boot 0, which makes the sweep
    /// a permanent no-op — safe (nothing is ever swept) rather than a guess.
    /// </summary>
    private static int CurrentBootToken()
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(24)) return 0;

        try
        {
            return Settings.Global.GetInt(Application.Context.ContentResolver, Settings.Global.BootCount!, 0);
        }
        catch
        {
            // If the counter is ever unreadable, treat every alias as
            // "current boot" (token 0 for both) so the sweep degrades to
            // never deleting anything, rather than guessing wrong.
            return 0;
        }
    }

    private static void SweepStaleAliasesOnce(KeyStore keystore)
    {
        if (Interlocked.CompareExchange(ref s_sweptStaleAliases, 1, 0) != 0) return;

        int currentBoot = CurrentBootToken();
        try
        {
            var aliases = keystore.Aliases();
            if (aliases is null) return;
            while (aliases.HasMoreElements)
            {
                if (aliases.NextElement()?.ToString() is not string alias) continue;

                if (alias == LegacyV1Alias)
                {
                    // Pre-2.0.0 fixed alias, no boot tagging at all — always
                    // superseded, safe to remove unconditionally.
                    try { keystore.DeleteEntry(alias); } catch { /* best effort */ }
                    continue;
                }

                if (!alias.StartsWith(AliasPrefix, StringComparison.Ordinal)) continue;

                string remainder = alias[AliasPrefix.Length..];
                int dot = remainder.IndexOf('.');
                if (dot < 0 || !int.TryParse(remainder[..dot], out int aliasBoot))
                {
                    // Unrecognised shape — do not guess; leave it for a
                    // future sweep/manual cleanup rather than risk deleting
                    // something live.
                    continue;
                }

                // Only delete aliases from a STRICTLY earlier boot session.
                // Every process that could have created a current-boot alias
                // is either still running (and owns its key) or has already
                // disposed/finalized it — either way this sweep must not
                // touch it.
                if (aliasBoot < currentBoot)
                {
                    try { keystore.DeleteEntry(alias); } catch { /* best effort */ }
                }
            }
        }
        catch
        {
            // Sweeping is hygiene, not correctness — a failure here must not
            // block protector construction.
        }
    }

    /// <summary>
    /// True when the Keystore reports the key as TEE- or StrongBox-resident.
    /// API 31+ exposes the exact level via <c>getSecurityLevel()</c>
    /// (UNKNOWN_SECURE counts as hardware; UNKNOWN and SOFTWARE do not);
    /// older API levels only have the boolean <c>isInsideSecureHardware()</c>.
    /// </summary>
    private static bool IsHardwareResident(ISecretKey wrappingKey)
    {
        var factory = SecretKeyFactory.GetInstance(wrappingKey.Algorithm, KeystoreName)
            ?? throw new InvalidOperationException("SecretKeyFactory(AndroidKeyStore) unavailable.");
        var keyInfo = factory.GetKeySpec(wrappingKey, Java.Lang.Class.FromType(typeof(KeyInfo))) as KeyInfo
            ?? throw new InvalidOperationException("KeyInfo unavailable for the generated Keystore key.");

        if (OperatingSystem.IsAndroidVersionAtLeast(31))
        {
            return keyInfo.SecurityLevel switch
            {
                (int)KeyStoreSecurityLevel.TrustedEnvironment => true,
                (int)KeyStoreSecurityLevel.Strongbox => true,
                (int)KeyStoreSecurityLevel.UnknownSecure => true,
                _ => false,
            };
        }

#pragma warning disable CA1422 // isInsideSecureHardware is deprecated in API 31; this branch only runs below 31.
        return keyInfo.IsInsideSecureHardware;
#pragma warning restore CA1422
    }

    private AndroidKeystoreProtector(KeyStore keystore, string keyAlias, IKey wrappingKey, byte[] wrappedBlob, byte[] iv)
    {
        _keystore = keystore;
        _keyAlias = keyAlias;
        _wrappingKey = wrappingKey;
        _wrappedBlob = wrappedBlob;
        _iv = iv;
    }

    public override KeyAccessor UnwrapKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            var cipher = Cipher.GetInstance(Transformation)
                ?? throw new InvalidOperationException("Cipher.GetInstance failed during unwrap.");
            var ivSpec = new GCMParameterSpec(GcmTagBits, _iv);
            cipher.Init(CipherMode.DecryptMode, _wrappingKey, ivSpec);

            var unwrapped = cipher.DoFinal(_wrappedBlob)
                ?? throw new InvalidOperationException("Cipher.DoFinal returned null during unwrap.");

            // Promote into a pinned, locked buffer so the rest of the library
            // can wipe it deterministically. The transient byte[] returned by
            // DoFinal is on the regular managed heap and can move under the GC.
            var pinned = ProtectedString.AllocatePinnedBytes(
                unwrapped.Length, excludeFromDumps: true, lockContext: "memory locking unwrapped key");

            bool ok = false;
            try
            {
                unwrapped.CopyTo(pinned, 0);
                ok = true;
                return KeyAccessor.Ephemeral(pinned);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(unwrapped);
                if (!ok)
                {
                    CryptographicOperations.ZeroMemory(pinned);
                    MemoryLocker.TryUnlock(pinned);
                }
            }
        }
        finally
        {
            // Keeps `this` reachable through the Binder round-trip above, so
            // the finalizer can never fire (deleting the Keystore alias out
            // from under an in-flight decrypt) while UnwrapKey is executing.
            GC.KeepAlive(this);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_wrappedBlob);
        CryptographicOperations.ZeroMemory(_iv);
        // Delete this instance's own alias — never anyone else's. The key
        // bytes never lived in this process; deletion just retires the
        // Keystore entry so orphans can't accumulate across rotations.
        try { _keystore.DeleteEntry(_keyAlias); } catch { /* best effort during dispose */ }
        GC.SuppressFinalize(this);
    }

    ~AndroidKeystoreProtector()
    {
        // Safety net for the two undisposed paths: a protector the caller
        // forgot to Dispose, and a protector RotateProcessKey superseded
        // (rotation never disposes the protector it replaces; the rotation
        // registry holds only WeakReference<ProtectedString>, so the old
        // protector becomes unreachable and finalizes once nothing still
        // references it). Deleting its alias here is best-effort; if the
        // process dies before this runs, the alias is reclaimed by the next
        // reboot's sweep instead.
        try { Dispose(); } catch { /* finalizer must not throw */ }
    }
}
#endif
