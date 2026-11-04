using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TopSecret;

#pragma warning disable CA1416

namespace TopSecret.WindowsTpm;

internal sealed class WindowsTpmProtector : DisposableKeyAtRestProtector
{
    private const string PlatformProvider = "Microsoft Platform Crypto Provider";
    private const string AlgorithmRsa = "RSA";
    private const string OaepHashAlgorithm = "SHA256";
    private const int RsaKeyBits = 2048;

    private const uint NCRYPT_PAD_OAEP_FLAG = 0x4;
    private const string NcryptLengthProperty = "Length";

    // SECURITY_STATUS / NTSTATUS success.
    private const int ErrorSuccess = 0;

    private static readonly byte[] s_oaepAlgIdUtf16 = AllocatePinnedAlgId();

    private static byte[] AllocatePinnedAlgId()
    {
        ReadOnlySpan<char> name = (OaepHashAlgorithm + "\0").AsSpan();
        int byteCount = Encoding.Unicode.GetByteCount(name);
        var buffer = GC.AllocateUninitializedArray<byte>(byteCount, pinned: true);
        Encoding.Unicode.GetBytes(name, buffer);
        return buffer;
    }

    private nint _hProvider;
    private nint _hKey;
    private readonly byte[] _wrappedBlob;

    public static bool IsAvailable()
    {
        if (!OperatingSystem.IsWindows()) return false;

        try
        {
            int status = NCryptOpenStorageProvider(out nint hProvider, PlatformProvider, 0);
            if (status != ErrorSuccess) return false;
            NCryptFreeObject(hProvider);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static KeyAtRestProtector? TryCreate(byte[] master)
    {
        if (!OperatingSystem.IsWindows()) return null;
        return TryCreate(master, CreateOrThrow);
    }

    private static WindowsTpmProtector CreateOrThrow(byte[] master)
    {
        nint hProvider = 0;
        nint hKey = 0;
        bool ownershipTransferred = false;

        try
        {
            int status = NCryptOpenStorageProvider(out hProvider, PlatformProvider, 0);
            ThrowIfNCryptFailed(status, $"NCryptOpenStorageProvider({PlatformProvider}) failed.");

            // pszKeyName: null => ephemeral. Lifetime tied to the key handle.
            status = NCryptCreatePersistedKey(hProvider, out hKey, AlgorithmRsa, null, 0, 0);
            ThrowIfNCryptFailed(status, "NCryptCreatePersistedKey(RSA) failed.");

            byte[] lengthBytes = BitConverter.GetBytes(RsaKeyBits);
            status = NCryptSetProperty(hKey, NcryptLengthProperty, lengthBytes, lengthBytes.Length, 0);
            ThrowIfNCryptFailed(status, "NCryptSetProperty(Length=2048) failed.");

            status = NCryptFinalizeKey(hKey, 0);
            ThrowIfNCryptFailed(status, "NCryptFinalizeKey failed.");

            byte[] wrapped = EncryptOaep(hKey, master);

            CryptographicOperations.ZeroMemory(master);

            var protector = new WindowsTpmProtector(hProvider, hKey, wrapped);
            ownershipTransferred = true;
            return protector;
        }
        finally
        {
            if (!ownershipTransferred)
            {
                if (hKey != 0) NCryptFreeObject(hKey);
                if (hProvider != 0) NCryptFreeObject(hProvider);
            }
        }
    }

    private static byte[] EncryptOaep(nint hKey, byte[] master)
    {
        // BCRYPT_OAEP_PADDING_INFO { LPCWSTR pszAlgId; PUCHAR pbLabel; ULONG cbLabel; }
        var paddingInfo = new BcryptOaepPaddingInfo
        {
            pszAlgId = AlgIdPointer(),
            pbLabel = nint.Zero,
            cbLabel = 0,
        };

        int status = NCryptEncrypt(hKey, master, master.Length, ref paddingInfo,
            null, 0, out int requiredLen, NCRYPT_PAD_OAEP_FLAG);
        ThrowIfNCryptFailed(status, "NCryptEncrypt size probe failed.");

        byte[] wrapped = new byte[requiredLen];
        status = NCryptEncrypt(hKey, master, master.Length, ref paddingInfo,
            wrapped, wrapped.Length, out int actualLen, NCRYPT_PAD_OAEP_FLAG);
        ThrowIfNCryptFailed(status, "NCryptEncrypt failed.");

        if (actualLen != wrapped.Length)
        {
            Array.Resize(ref wrapped, actualLen);
        }
        return wrapped;
    }

    private WindowsTpmProtector(nint hProvider, nint hKey, byte[] wrappedBlob)
    {
        _hProvider = hProvider;
        _hKey = hKey;
        _wrappedBlob = wrappedBlob;
    }

    protected override KeyAccessor UnwrapCore()
    {
        // The base's GC.KeepAlive(this) keeps _hKey alive through the TPM
        // round-trip, so the finalizer cannot NCryptFreeObject it mid-decrypt.
        var paddingInfo = new BcryptOaepPaddingInfo
        {
            pszAlgId = AlgIdPointer(),
            pbLabel = nint.Zero,
            cbLabel = 0,
        };

        int status = NCryptDecrypt(_hKey, _wrappedBlob, _wrappedBlob.Length, ref paddingInfo,
            null, 0, out int requiredLen, NCRYPT_PAD_OAEP_FLAG);
        ThrowIfNCryptFailed(status, "NCryptDecrypt size probe failed.");

        var staging = ProtectedString.AllocatePinnedBytes(
            requiredLen, excludeFromDumps: true, lockContext: "memory locking unwrapped key");
        try
        {
            status = NCryptDecrypt(_hKey, _wrappedBlob, _wrappedBlob.Length, ref paddingInfo,
                staging, staging.Length, out int actualLen, NCRYPT_PAD_OAEP_FLAG);
            ThrowIfNCryptFailed(status, "NCryptDecrypt failed.");

            return EphemeralFrom(staging.AsSpan(0, actualLen));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(staging);
            MemoryLocker.TryUnlock(staging);
        }
    }

    protected override void ReleaseResources()
    {
        CryptographicOperations.ZeroMemory(_wrappedBlob);
        if (_hKey != 0) { NCryptFreeObject(_hKey); _hKey = 0; }
        if (_hProvider != 0) { NCryptFreeObject(_hProvider); _hProvider = 0; }
    }

    private static nint AlgIdPointer() =>
        Marshal.UnsafeAddrOfPinnedArrayElement(s_oaepAlgIdUtf16, 0);

    private static void ThrowIfNCryptFailed(int status, string message)
    {
        if (status == ErrorSuccess) return;

        var inner = Marshal.GetExceptionForHR(status);
        throw new InvalidOperationException(
            $"{message} (HRESULT 0x{status:X8}).",
            inner);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BcryptOaepPaddingInfo
    {
        public nint pszAlgId;
        public nint pbLabel;
        public uint cbLabel;
    }

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptOpenStorageProvider(out nint phProvider, string pszProviderName, uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptCreatePersistedKey(nint hProvider, out nint phKey, string pszAlgId, string? pszKeyName, uint dwLegacyKeySpec, uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptSetProperty(nint hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFinalizeKey(nint hKey, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptEncrypt(nint hKey, byte[] pbInput, int cbInput,
        ref BcryptOaepPaddingInfo pPaddingInfo, byte[]? pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptDecrypt(nint hKey, byte[] pbInput, int cbInput,
        ref BcryptOaepPaddingInfo pPaddingInfo, byte[]? pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeObject(nint hObject);
}
