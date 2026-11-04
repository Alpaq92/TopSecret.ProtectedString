using System.Security.Cryptography;
using Tpm2Lib;
using TopSecret;

namespace TopSecret.LinuxTpm;

/// <summary>
/// Wraps the per-process AES master key with an ephemeral RSA-2048 keypair
/// generated inside a Linux TPM 2.0 device via Microsoft TSS.MSR
/// (<c>Microsoft.TSS</c> on NuGet). The RSA private key never leaves the
/// TPM; the wrapped master is held in process memory as OAEP-SHA256
/// ciphertext, and every <see cref="KeyAtRestProtector.UnwrapKey"/> call
/// performs a TPM round-trip via <c>RSA_Decrypt</c>.
/// </summary>
/// <remarks>
/// <para>
/// Registered with the main <see cref="KeyAtRestProtectorFactory"/> by
/// <see cref="ModuleInit"/> at assembly load. Consumers do not need to call
/// anything explicit — referencing the
/// <c>TopSecret.ProtectedString.LinuxTpm</c> NuGet is enough.
/// </para>
/// <para>
/// <b>Per-op cost.</b> ~5–15 ms per <c>RSA_Decrypt</c> on a discrete TPM,
/// ~1–3 ms on Intel PTT / AMD fTPM. Set
/// <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/> to amortise the
/// round-trip on hot paths.
/// </para>
/// <para>
/// <b>Device path.</b> Prefers <c>/dev/tpmrm0</c> (the kernel resource
/// manager — handles transient-slot scheduling for us), falling back to
/// <c>/dev/tpm0</c> when the resource manager isn't exposed <i>or cannot be
/// opened</i>. <see cref="IsAvailable"/> and <see cref="TryCreate(byte[])"/>
/// walk the candidates identically — a device that exists but fails to open
/// (permissions, busy) is skipped by both — so availability never reports
/// <see langword="true"/> for a device construction then cannot use. On most
/// modern Linux distros (kernel 4.12+ with CONFIG_TCG_TPM2_HMAC),
/// <c>/dev/tpmrm0</c> is the right path; <c>/dev/tpm0</c> is the raw
/// character device that requires the caller to manage transient slots
/// manually.
/// </para>
/// <para>
/// <b>Permissions.</b> Both device files typically require membership in
/// the <c>tss</c> group on Debian/Ubuntu or the <c>tpm</c> group on Fedora.
/// If the process can't open either device, <see cref="IsAvailable"/>
/// returns <see langword="false"/> and <see cref="TryCreate(byte[])"/>
/// returns <see langword="null"/>; under
/// <see cref="KeyAtRestProtection.HardwareBackedRequired"/> the factory
/// throws <see cref="PlatformNotSupportedException"/>.
/// </para>
/// <para>
/// <b>Hierarchy.</b> Uses the Owner hierarchy (<see cref="TpmRh.Owner"/>)
/// with empty auth — the default on a freshly-provisioned TPM and on every
/// TPM accessed through <c>/dev/tpmrm0</c>. If the host has a non-empty
/// owner password, construction will fail; that's a configuration issue
/// outside the library's scope.
/// </para>
/// <para>
/// <b>Concurrency.</b> A TSS.MSR <see cref="Tpm2"/> is a single
/// command/response pipe over one device handle and is not thread-safe:
/// two overlapping commands interleave their bytes on the wire. Every TPM
/// command this protector issues after construction — <c>RSA_Decrypt</c>
/// in <see cref="UnwrapCore"/>, <c>FlushContext</c> and the device close in
/// <see cref="ReleaseResources"/> — is serialised through <c>_tpmGate</c>.
/// Parallel <see cref="KeyAtRestProtector.UnwrapKey"/> callers therefore
/// queue on the TPM, which is the device's real throughput limit anyway;
/// pair with <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/> on
/// hot paths.
/// </para>
/// <para>
/// <b>Accepted residue.</b> TSS.MSR marshals every command and response
/// through ordinary managed <c>byte[]</c> buffers it owns: the plaintext
/// master is serialised into the <c>RSA_Encrypt</c> command buffer at wrap
/// time, and the <c>RSA_Decrypt</c> response buffer (plus the
/// <c>byte[]</c> TSS hands back) carries it at unwrap time. The returned
/// array is zeroed as soon as it has been copied into the locked
/// ephemeral, but TSS's internal command/response buffers are unpinned,
/// unlocked heap arrays the library cannot reach or wipe — those transient
/// copies are part of this tier's accepted window.
/// </para>
/// </remarks>
internal sealed class LinuxTpmProtector : DisposableKeyAtRestProtector
{
    private const int RsaKeyBits = 2048;

    private static readonly string[] CandidateDevicePaths =
        ["/dev/tpmrm0", "/dev/tpm0"];

    private readonly object _tpmGate = new();
    private readonly Tpm2 _tpm;
    private TpmHandle? _keyHandle;
    private readonly byte[] _wrappedBlob;

    /// <summary>
    /// Probe whether a Linux TPM 2.0 device is reachable from this process.
    /// Non-destructive — opens and immediately closes the device, does not
    /// generate a key. Walks the same candidate list, with the same
    /// skip-on-open-failure rule, as <see cref="TryCreate(byte[])"/>.
    /// </summary>
    public static bool IsAvailable()
    {
        if (!OperatingSystem.IsLinux()) return false;
        return OpenableDevicePaths().Any();
    }

    /// <summary>
    /// Builds a TPM-backed protector wrapping <paramref name="master"/>. On
    /// success the master array is zeroed in place and ownership transfers
    /// to the returned protector. Returns <see langword="null"/> on any
    /// failure (TPM unavailable, permission denied, owner password set, TPM
    /// command failure) so the factory can fall back.
    /// </summary>
    public static KeyAtRestProtector? TryCreate(byte[] master)
    {
        if (master.Length != MasterKeySize) return null;
        if (!OperatingSystem.IsLinux()) return null;

        Tpm2Device? device = null;
        try
        {
            device = OpenLinuxDevice();
            return CreateOrThrow(master, device);
        }
        catch
        {
            try { device?.Dispose(); } catch { }
            return null;
        }
    }

    /// <summary>
    /// Test-only seam. Builds the protector against an already-connected
    /// <see cref="Tpm2Device"/> — typically a <c>TcpTpmDevice</c> pointing
    /// at a software TPM 2.0 simulator (swtpm). Production code uses
    /// <see cref="TryCreate(byte[])"/>, which opens <c>/dev/tpmrm0</c>
    /// directly. On success the protector takes ownership of the device and
    /// disposes it as part of <see cref="DisposableKeyAtRestProtector.Dispose"/>;
    /// on failure the device is disposed before returning <see langword="null"/>.
    /// </summary>
    internal static KeyAtRestProtector? TryCreateWithDevice(byte[] master, Tpm2Device device)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (master.Length != MasterKeySize)
        {
            try { device.Dispose(); } catch { }
            return null;
        }
        try
        {
            return CreateOrThrow(master, device);
        }
        catch
        {
            try { device.Dispose(); } catch { }
            return null;
        }
    }

    /// <summary>
    /// The candidate device paths that exist <i>and</i> can be opened
    /// read-write by this process, in preference order. Shared by
    /// <see cref="IsAvailable"/> and <see cref="OpenLinuxDevice"/> so the two
    /// can never disagree about which device is usable.
    /// </summary>
    private static IEnumerable<string> OpenableDevicePaths()
    {
        foreach (var path in CandidateDevicePaths)
        {
            if (CanOpenReadWrite(path)) yield return path;
        }
    }

    private static bool CanOpenReadWrite(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            // Open the device read-write so we exercise the same permission
            // check TSS.MSR will hit. The handle is closed before we return —
            // /dev/tpm0 (the raw device) admits only one opener at a time.
            using var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            return true;
        }
        catch
        {
            // Device exists but we can't access it (permission, busy, etc.).
            return false;
        }
    }

    private static Tpm2Device OpenLinuxDevice()
    {
        foreach (var path in OpenableDevicePaths())
        {
            LinuxTpmDevice? device = null;
            try
            {
                device = new LinuxTpmDevice(path);
                device.Connect();
                return device;
            }
            catch
            {
                // Openable a moment ago but TSS could not connect (raced with
                // another opener on /dev/tpm0, driver hiccup) — try the next
                // candidate rather than failing on the first.
                try { device?.Dispose(); } catch { }
            }
        }

        throw new PlatformNotSupportedException(
            "No accessible TPM 2.0 device at /dev/tpmrm0 or /dev/tpm0.");
    }

    /// <summary>
    /// Provisions the wrapping key inside <paramref name="device"/> and
    /// returns a protector that owns the device. The caller is responsible
    /// for disposing <paramref name="device"/> if this method throws.
    /// </summary>
    private static LinuxTpmProtector CreateOrThrow(byte[] master, Tpm2Device device)
    {
        Tpm2? tpm = null;
        TpmHandle? primary = null;
        TpmHandle? loaded = null;
        bool ownershipTransferred = false;

        try
        {
            tpm = new Tpm2(device);

            // 1. Create a transient RSA primary key under the Owner hierarchy.
            //    Restricted | Decrypt is the standard "storage parent" shape;
            //    we only need it to wrap the child, then we flush it out.
            var primaryTemplate = new TpmPublic(
                TpmAlgId.Sha256,
                ObjectAttr.Restricted | ObjectAttr.Decrypt
                    | ObjectAttr.FixedTPM | ObjectAttr.FixedParent
                    | ObjectAttr.SensitiveDataOrigin | ObjectAttr.UserWithAuth
                    | ObjectAttr.NoDA,
                Array.Empty<byte>(),
                new RsaParms(
                    new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                    new NullAsymScheme(),
                    2048,
                    0),
                new Tpm2bPublicKeyRsa());

            primary = tpm.CreatePrimary(
                TpmRh.Owner,
                new SensitiveCreate(Array.Empty<byte>(), Array.Empty<byte>()),
                primaryTemplate,
                Array.Empty<byte>(),
                Array.Empty<PcrSelection>(),
                out _, out _, out _, out _);

            // 2. Create the encryption child key. Decrypt-only RSA-2048 with
            //    OAEP-SHA256 padding — the same scheme NCrypt uses on Windows.
            var childTemplate = new TpmPublic(
                TpmAlgId.Sha256,
                ObjectAttr.Decrypt
                    | ObjectAttr.FixedTPM | ObjectAttr.FixedParent
                    | ObjectAttr.SensitiveDataOrigin | ObjectAttr.UserWithAuth
                    | ObjectAttr.NoDA,
                Array.Empty<byte>(),
                new RsaParms(
                    new SymDefObject(),
                    new SchemeOaep(TpmAlgId.Sha256),
                    RsaKeyBits,
                    0),
                new Tpm2bPublicKeyRsa());

            // TSS.MSR's Tpm2.Create returns the private blob and writes the
            // matching public area + creation receipt through out params.
            TpmPrivate childPrivate = tpm.Create(
                primary!,
                new SensitiveCreate(Array.Empty<byte>(), Array.Empty<byte>()),
                childTemplate,
                Array.Empty<byte>(),
                Array.Empty<PcrSelection>(),
                out TpmPublic childPublic,
                out _, out _, out _);

            loaded = tpm.Load(primary!, childPrivate, childPublic);

            // 3. Flush the primary — we don't need it anymore. The child key
            //    is now self-contained inside the TPM (the Load brought it
            //    into a transient slot of its own).
            tpm.FlushContext(primary);
            primary = null;

            // 4. RSA-OAEP encrypt the master under the loaded child key.
            //    label = empty, matches our decrypt path.
            //    Accepted residue: TSS serialises `master` into its own
            //    command buffer for the wire (see class remarks).
            byte[] wrapped = tpm.RsaEncrypt(
                loaded,
                master,
                new SchemeOaep(TpmAlgId.Sha256),
                Array.Empty<byte>());

            // Master is now wrapped under a TPM-resident private key. Zero
            // the input array; the only places the master plaintext exists
            // from here on are inside the TPM and inside transient unwrap
            // buffers that callers immediately dispose.
            CryptographicOperations.ZeroMemory(master);

            var protector = new LinuxTpmProtector(tpm, loaded!, wrapped);
            ownershipTransferred = true;
            return protector;
        }
        finally
        {
            if (!ownershipTransferred)
            {
                // CreateOrThrow failed mid-way: flush whatever we managed to
                // create so we don't leak transient slots. Note that we do
                // *not* dispose the device here — the caller (TryCreate or
                // TryCreateWithDevice) decides whether to dispose, since
                // they may want to retry against the same device.
                try { if (loaded is not null) tpm?.FlushContext(loaded); } catch { }
                try { if (primary is not null) tpm?.FlushContext(primary); } catch { }
                try { tpm?.Dispose(); } catch { }
            }
        }
    }

    private LinuxTpmProtector(Tpm2 tpm, TpmHandle keyHandle, byte[] wrappedBlob)
    {
        _tpm = tpm;
        _keyHandle = keyHandle;
        _wrappedBlob = wrappedBlob;
    }

    protected override KeyAccessor UnwrapCore()
    {
        // RSA_Decrypt round-trip to the TPM, serialised on _tpmGate: the
        // Tpm2 pipe is single-command. Returns the plaintext (32-byte master)
        // in a fresh TSS-owned byte[] which we promote into a pinned, locked
        // buffer matching the contract for hardware-backed protectors.
        // Accepted residue: TSS's response buffer also carried it (see class
        // remarks).
        byte[] plaintext;
        lock (_tpmGate)
        {
            // Re-check under the gate: ReleaseResources flushes the handle
            // under the same lock, so a caller that lost the race to a
            // concurrent Dispose must not issue a command against it.
            var handle = _keyHandle;
            ObjectDisposedException.ThrowIf(handle is null, this);

            plaintext = _tpm.RsaDecrypt(
                handle,
                _wrappedBlob,
                new SchemeOaep(TpmAlgId.Sha256),
                Array.Empty<byte>());
        }

        try
        {
            return EphemeralFrom(plaintext);
        }
        finally
        {
            // Wipe the TSS.MSR-allocated plaintext since it lives on the
            // regular managed heap until the GC reclaims it.
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    protected override void ReleaseResources()
    {
        CryptographicOperations.ZeroMemory(_wrappedBlob);
        // FlushContext is a TPM 2.0 command issued via the TSS pipe; take the
        // same gate as UnwrapCore so it cannot interleave with an in-flight
        // RSA_Decrypt. Safe from the finalizer thread — the base class's
        // GC.KeepAlive guarantees no unwrap is in flight on a finalizable
        // instance, so the lock is uncontended there.
        lock (_tpmGate)
        {
            try
            {
                if (_keyHandle is not null)
                {
                    _tpm.FlushContext(_keyHandle);
                    _keyHandle = null;
                }
            }
            catch { /* best-effort during dispose */ }
            // Tpm2.Dispose closes the underlying Tpm2Device.
            try { _tpm.Dispose(); } catch { }
        }
    }
}
