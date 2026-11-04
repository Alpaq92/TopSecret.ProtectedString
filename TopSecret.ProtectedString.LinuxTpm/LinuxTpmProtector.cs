using System.Security.Cryptography;
using Tpm2Lib;
using TopSecret;

namespace TopSecret.LinuxTpm;

internal sealed class LinuxTpmProtector : DisposableKeyAtRestProtector
{
    private const int RsaKeyBits = 2048;

    private static readonly string[] CandidateDevicePaths =
        ["/dev/tpmrm0", "/dev/tpm0"];

    private readonly object _tpmGate = new();
    private readonly Tpm2 _tpm;
    private TpmHandle? _keyHandle;
    private readonly byte[] _wrappedBlob;

    public static bool IsAvailable()
    {
        if (!OperatingSystem.IsLinux()) return false;
        return OpenableDevicePaths().Any();
    }

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
            try { device?.Close(); } catch { }
            try { device?.Dispose(); } catch { }
            return null;
        }
    }

    internal static KeyAtRestProtector? TryCreateWithDevice(byte[] master, Tpm2Device device)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (master.Length != MasterKeySize)
        {
            try { device.Close(); } catch { }
            try { device.Dispose(); } catch { }
            return null;
        }
        try
        {
            return CreateOrThrow(master, device);
        }
        catch
        {
            try { device.Close(); } catch { }
            try { device.Dispose(); } catch { }
            return null;
        }
    }

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
                try { device?.Close(); } catch { }
                try { device?.Dispose(); } catch { }
            }
        }

        throw new PlatformNotSupportedException(
            "No accessible TPM 2.0 device at /dev/tpmrm0 or /dev/tpm0.");
    }

    private static LinuxTpmProtector CreateOrThrow(byte[] master, Tpm2Device device)
    {
        Tpm2? tpm = null;
        TpmHandle? primary = null;
        TpmHandle? loaded = null;
        bool ownershipTransferred = false;

        try
        {
            tpm = new Tpm2(device);

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

            tpm.FlushContext(primary);
            primary = null;

            byte[] wrapped = tpm.RsaEncrypt(
                loaded,
                master,
                new SchemeOaep(TpmAlgId.Sha256),
                Array.Empty<byte>());

            CryptographicOperations.ZeroMemory(master);

            var protector = new LinuxTpmProtector(tpm, loaded!, wrapped);
            ownershipTransferred = true;
            return protector;
        }
        finally
        {
            if (!ownershipTransferred)
            {
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
        byte[] plaintext;
        lock (_tpmGate)
        {
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
            catch { }
            try { _tpm._GetUnderlyingDevice()?.Close(); } catch { }
            try { _tpm.Dispose(); } catch { }
        }
    }
}
