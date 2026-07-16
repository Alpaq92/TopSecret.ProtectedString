using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using TopSecret;

// CA1416: every NCrypt call site below is runtime-guarded by either
// OperatingSystem.IsWindows() at the public entry point or by the call
// graph from those entry points. The analyzer cannot prove it across
// helper boundaries, so we suppress at file scope.
#pragma warning disable CA1416

namespace TopSecret.WindowsTpm;

/// <summary>
/// Wraps the per-process AES master key with an ephemeral RSA-2048 keypair
/// generated inside the TPM via the CNG <c>NCrypt</c> API and the
/// <i>Microsoft Platform Crypto Provider</i>. The RSA private key never
/// leaves the TPM; the wrapped master is held in process memory as
/// OAEP-SHA256 ciphertext, and every <see cref="UnwrapKey"/> call performs
/// a TPM round-trip via <c>NCryptDecrypt</c>.
/// </summary>
/// <remarks>
/// <para>
/// Registered with the main <see cref="KeyAtRestProtectorFactory"/> by
/// <see cref="ModuleInit"/> at assembly load. Consumers do not need to call
/// anything explicit — referencing the
/// <c>TopSecret.ProtectedString.WindowsTpm</c> NuGet is enough.
/// </para>
/// <para>
/// <b>Per-op cost.</b> TPM 2.0 RSA-2048 decrypt is typically ~5–15 ms on a
/// discrete TPM and ~1–3 ms on Intel PTT / AMD fTPM. Set
/// <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/> to amortise the
/// round-trip on hot paths.
/// </para>
/// <para>
/// The keypair is created without a name (ephemeral): when the
/// <see cref="WindowsTpmProtector"/> instance is disposed (typically on
/// process exit, or at the end of a <see cref="ProtectedString.RotateProcessKey"/>
/// pass), <c>NCryptFreeObject</c> on the key handle releases the TPM's
/// reference and the keypair becomes unreachable. A finalizer covers the
/// case where a protector becomes unreachable without explicit
/// <see cref="Dispose"/> — for instance, an old protector orphaned by
/// process-key rotation under <see cref="ProcessKeyRotation.Periodic"/>.
/// Without the finalizer, repeated rotations would exhaust TPM transient
/// slots (commodity TPMs hold ≤3, enterprise TPMs 4–8) and subsequent
/// <c>NCryptCreatePersistedKey</c> calls would fail with
/// <c>TPM_RC_RESOURCES (0x80284001)</c>.
/// </para>
/// </remarks>
internal sealed class WindowsTpmProtector : KeyAtRestProtector, IDisposable
{
    private const string PlatformProvider = "Microsoft Platform Crypto Provider";
    private const string AlgorithmRsa = "RSA";
    private const string OaepHashAlgorithm = "SHA256";
    private const int RsaKeyBits = 2048;
    private const int MasterKeySize = 32;

    private const uint NCRYPT_PAD_OAEP_FLAG = 0x4;
    private const string NcryptLengthProperty = "Length";

    // SECURITY_STATUS / NTSTATUS success.
    private const int ErrorSuccess = 0;

    // Cached UTF-16LE bytes of the OAEP hash algorithm name with NUL terminator.
    // BCRYPT_OAEP_PADDING_INFO.pszAlgId is a LPCWSTR, so we hand NCrypt a
    // pinned pointer into this array on every Encrypt / Decrypt without
    // reallocating per call. Allocated on the pinned object heap so the GC
    // never relocates it; we can take its address with no GCHandle pin.
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
    private bool _disposed;

    /// <summary>
    /// Reports whether the Microsoft Platform Crypto Provider can be opened
    /// on the current host. Non-destructive — opens and immediately closes
    /// the provider, does not generate a key.
    /// </summary>
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

    /// <summary>
    /// Builds a TPM-backed protector wrapping <paramref name="master"/>. On
    /// success the master array is zeroed in place and ownership transfers
    /// to the returned protector. Returns <see langword="null"/> on any
    /// failure (TPM unavailable, NCrypt error) so the factory can fall back.
    /// </summary>
    public static KeyAtRestProtector? TryCreate(byte[] master)
    {
        if (master.Length != MasterKeySize) return null;
        if (!OperatingSystem.IsWindows()) return null;

        try
        {
            return CreateOrThrow(master);
        }
        catch
        {
            return null;
        }
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

            // Master is now wrapped under a TPM-resident private key. Zero
            // the input array; the only places the master plaintext exists
            // from here on are inside the TPM and inside transient unwrap
            // buffers that callers immediately dispose.
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

        // RSA-2048 OAEP encryption of a 32-byte plaintext yields a 256-byte
        // ciphertext, but ask NCrypt rather than hard-code in case of
        // provider variance.
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

    public override KeyAccessor UnwrapKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var paddingInfo = new BcryptOaepPaddingInfo
        {
            pszAlgId = AlgIdPointer(),
            pbLabel = nint.Zero,
            cbLabel = 0,
        };

        int status = NCryptDecrypt(_hKey, _wrappedBlob, _wrappedBlob.Length, ref paddingInfo,
            null, 0, out int requiredLen, NCRYPT_PAD_OAEP_FLAG);
        ThrowIfNCryptFailed(status, "NCryptDecrypt size probe failed.");

        // Allocate the destination as a pinned + locked buffer up front.
        // It is sized to NCrypt's reported max, then trimmed if NCrypt
        // returns less.
        var staging = ProtectedString.AllocatePinnedBytes(
            requiredLen, excludeFromDumps: true, lockContext: "memory locking unwrapped key");

        bool ok = false;
        byte[] result = staging;
        try
        {
            status = NCryptDecrypt(_hKey, _wrappedBlob, _wrappedBlob.Length, ref paddingInfo,
                staging, staging.Length, out int actualLen, NCRYPT_PAD_OAEP_FLAG);
            ThrowIfNCryptFailed(status, "NCryptDecrypt failed.");

            if (actualLen != staging.Length)
            {
                // Promote the actual plaintext into a right-sized pinned/locked
                // buffer and wipe the oversized staging buffer.
                var sized = ProtectedString.AllocatePinnedBytes(
                    actualLen, excludeFromDumps: true, lockContext: "memory locking unwrapped key");
                Array.Copy(staging, sized, actualLen);
                CryptographicOperations.ZeroMemory(staging);
                MemoryLocker.TryUnlock(staging);
                result = sized;
            }

            ok = true;
            return KeyAccessor.Ephemeral(result);
        }
        finally
        {
            if (!ok)
            {
                CryptographicOperations.ZeroMemory(staging);
                MemoryLocker.TryUnlock(staging);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_wrappedBlob);
        if (_hKey != 0) { NCryptFreeObject(_hKey); _hKey = 0; }
        if (_hProvider != 0) { NCryptFreeObject(_hProvider); _hProvider = 0; }
        GC.SuppressFinalize(this);
    }

    ~WindowsTpmProtector()
    {
        try { Dispose(); }
        catch { /* finalizer must not throw */ }
    }

    private static nint AlgIdPointer() =>
        Marshal.UnsafeAddrOfPinnedArrayElement(s_oaepAlgIdUtf16, 0);

    private static void ThrowIfNCryptFailed(int status, string message)
    {
        if (status == ErrorSuccess) return;

        // NCrypt returns SECURITY_STATUS values which are HRESULTs (e.g.
        // NTE_BAD_KEYSET = 0x80090016), not Win32 error codes.
        // Marshal.GetExceptionForHR renders the canonical HRESULT message;
        // chain it as the inner so the caller gets both our context and
        // the system text.
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
