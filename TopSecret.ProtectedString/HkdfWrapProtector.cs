using System.Security.Cryptography;
using System.Text;

namespace TopSecret;

/// <summary>
/// Pure-managed obscurity wrap: at init, generate a 32-byte random wrap key,
/// HKDF-SHA256-derive a 32-byte stream from it, XOR the master against the
/// stream, and store the wrap key + the wrapped master in two separate pinned
/// buffers. <see cref="KeyAtRestProtector.UnwrapKey"/> re-derives the stream
/// from the wrap key and XORs the wrapped master back to plaintext.
/// </summary>
/// <remarks>
/// <para>
/// Both buffers live in the process heap, so a heap dump still contains
/// everything an attacker needs — they just have to know to recombine via the
/// HKDF info string and the XOR. This is intentional: the protector exists as
/// the last-resort <see cref="KeyAtRestProtection.Obscurity"/> tier when no
/// stronger primitive (hardware-backed, guarded page,
/// <see cref="AesGcmWrapProtector"/>) is available.
/// </para>
/// <para>
/// <b>Role in the factory.</b> <see cref="AesGcmWrapProtector"/> is the
/// obscurity tier's first choice on every platform. This protector is the
/// fallback the factory reaches only when AES-GCM construction declines —
/// it has no dependencies beyond <see cref="HKDF"/> and raw XOR, so it
/// always succeeds for a 32-byte master. Security-wise the two are
/// equivalent against the in-process dump attacker (the wrap key sits in
/// the same dump as the wrapped blob either way); the AEAD variant is
/// preferred because a torn or corrupted envelope fails the tag check
/// instead of silently unwrapping to garbage.
/// </para>
/// </remarks>
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

    protected override KeyAccessor UnwrapCore()
    {
        // XOR onto the stack, promote into the locked ephemeral, wipe the
        // stack copy. The HKDF stream itself is a regular-heap byte[] that
        // is zeroed as soon as the XOR completes.
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
