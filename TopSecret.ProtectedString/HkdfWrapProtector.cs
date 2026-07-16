using System.Security.Cryptography;
using System.Text;

namespace TopSecret;

/// <summary>
/// Pure-managed obscurity wrap: at init, generate a 32-byte random wrap key,
/// HKDF-SHA256-derive a 32-byte stream from it, XOR the master against the
/// stream, and store the wrap key + the wrapped master in two separate pinned
/// buffers. <see cref="UnwrapKey"/> re-derives the stream from the wrap key
/// and XORs the wrapped master back to plaintext.
/// </summary>
/// <remarks>
/// <para>
/// Both buffers live in the process heap, so a heap dump still contains
/// everything an attacker needs — they just have to know to recombine via the
/// HKDF info string and the XOR. This is intentional: the protector exists as
/// the cross-platform <see cref="KeyAtRestProtection.Obscurity"/> tier when no
/// stronger primitive (Windows DPAPI, Linux AF_ALG, hardware-backed) is
/// available.
/// </para>
/// <para>
/// Why XOR-with-HKDF-stream instead of AES? AES keyed by another in-process
/// key is no stronger here — the wrap key is in the same dump as the wrapped
/// blob — and adds an <see cref="AesGcm"/> instance per op on top of the AES
/// instance the library is already running. XOR keeps the per-op cost
/// negligible.
/// </para>
/// </remarks>
internal sealed class HkdfWrapProtector : KeyAtRestProtector, IDisposable
{
    private const int MasterKeySize = 32;
    private static readonly byte[] s_hkdfInfo = Encoding.UTF8.GetBytes("TopSecret.ProtectedString/HkdfWrap/v1");

    private readonly byte[] _wrapKey;
    private readonly byte[] _wrappedMaster;
    private bool _disposed;

    public static HkdfWrapProtector? TryCreate(byte[] master)
    {
        if (master.Length != MasterKeySize) return null;
        try
        {
            return CreateOrThrow(master);
        }
        catch
        {
            return null;
        }
    }

    private static HkdfWrapProtector CreateOrThrow(byte[] master)
    {
        var wrapKey = ProtectedString.AllocatePinnedBytes(
            MasterKeySize, excludeFromDumps: true, lockContext: "memory locking obscurity wrap key");
        var wrapped = ProtectedString.AllocatePinnedBytes(
            MasterKeySize, lockContext: "memory locking obscurity wrapped blob");

        bool committed = false;
        try
        {
            RandomNumberGenerator.Fill(wrapKey);

            // Stream is allocated on the regular heap; zero it after use. Its
            // window is briefer than the wrap key's, and re-deriving it on
            // every UnwrapKey is what the protector does anyway.
            var stream = HKDF.DeriveKey(HashAlgorithmName.SHA256, wrapKey, MasterKeySize, info: s_hkdfInfo);
            try
            {
                for (int i = 0; i < MasterKeySize; i++)
                {
                    wrapped[i] = (byte)(master[i] ^ stream[i]);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stream);
            }

            // Master is now wrapped — zero it.
            CryptographicOperations.ZeroMemory(master);
            committed = true;
            return new HkdfWrapProtector(wrapKey, wrapped);
        }
        finally
        {
            if (!committed)
            {
                CryptographicOperations.ZeroMemory(wrapKey);
                CryptographicOperations.ZeroMemory(wrapped);
                MemoryLocker.TryUnlock(wrapKey);
                MemoryLocker.TryUnlock(wrapped);
            }
        }
    }

    private HkdfWrapProtector(byte[] wrapKey, byte[] wrappedMaster)
    {
        _wrapKey = wrapKey;
        _wrappedMaster = wrappedMaster;
    }

    public override KeyAccessor UnwrapKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var unwrapped = ProtectedString.AllocatePinnedBytes(
            MasterKeySize, excludeFromDumps: true, lockContext: "memory locking unwrapped key");

        bool ok = false;
        try
        {
            var stream = HKDF.DeriveKey(HashAlgorithmName.SHA256, _wrapKey, MasterKeySize, info: s_hkdfInfo);
            try
            {
                for (int i = 0; i < MasterKeySize; i++)
                {
                    unwrapped[i] = (byte)(_wrappedMaster[i] ^ stream[i]);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stream);
            }
            ok = true;
            return KeyAccessor.Ephemeral(unwrapped);
        }
        finally
        {
            if (!ok)
            {
                CryptographicOperations.ZeroMemory(unwrapped);
                MemoryLocker.TryUnlock(unwrapped);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_wrapKey);
        CryptographicOperations.ZeroMemory(_wrappedMaster);
        MemoryLocker.TryUnlock(_wrapKey);
        MemoryLocker.TryUnlock(_wrappedMaster);
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~HkdfWrapProtector()
    {
        // Bound RLIMIT_MEMLOCK / working-set growth when callers forget to
        // dispose: the wrap key and wrapped master are mlocked / VirtualLocked
        // pages, and only Dispose unlocks them.
        try { Dispose(); } catch { /* finalizer must not throw */ }
    }
}
