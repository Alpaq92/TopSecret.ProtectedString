using System.Security.Cryptography;
using System.Text;

namespace TopSecret;

internal sealed class HkdfWrapProtector : DisposableKeyAtRestProtector
{
    private static readonly byte[] s_hkdfInfo = Encoding.UTF8.GetBytes("TopSecret.ProtectedString/HkdfWrap/v1");

    private readonly byte[] _wrapKey;
    private readonly byte[] _wrappedMaster;

    public static HkdfWrapProtector? TryCreate(byte[] master) => TryCreate(master, CreateOrThrow);

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

    protected override KeyAccessor UnwrapCore()
    {
        Span<byte> plaintext = stackalloc byte[MasterKeySize];
        try
        {
            var stream = HKDF.DeriveKey(HashAlgorithmName.SHA256, _wrapKey, MasterKeySize, info: s_hkdfInfo);
            try
            {
                for (int i = 0; i < MasterKeySize; i++)
                {
                    plaintext[i] = (byte)(_wrappedMaster[i] ^ stream[i]);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stream);
            }
            return EphemeralFrom(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    protected override void ReleaseResources()
    {
        CryptographicOperations.ZeroMemory(_wrapKey);
        CryptographicOperations.ZeroMemory(_wrappedMaster);
        MemoryLocker.TryUnlock(_wrapKey);
        MemoryLocker.TryUnlock(_wrappedMaster);
    }
}
