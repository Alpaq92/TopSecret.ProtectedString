using System.Security.Cryptography;
using System.Text;

namespace TopSecret;

internal sealed class AesGcmWrapProtector : DisposableKeyAtRestProtector
{
    private const int WrapKeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int EnvelopeSize = NonceSize + MasterKeySize + TagSize;

    private static readonly byte[] s_aad =
        Encoding.UTF8.GetBytes("TopSecret.ProtectedString/AesGcmWrap/v1");

    private readonly byte[] _wrapKey;
    private readonly byte[] _envelope;

    public static AesGcmWrapProtector? TryCreate(byte[] master) => TryCreate(master, CreateOrThrow);

    private static AesGcmWrapProtector CreateOrThrow(byte[] master)
    {
        var wrapKey = ProtectedString.AllocatePinnedBytes(
            WrapKeySize, excludeFromDumps: true, lockContext: "memory locking AES-GCM wrap key");
        var envelope = ProtectedString.AllocatePinnedBytes(
            EnvelopeSize, lockContext: "memory locking AES-GCM envelope");

        bool committed = false;
        try
        {
            RandomNumberGenerator.Fill(wrapKey);
            RandomNumberGenerator.Fill(envelope.AsSpan(0, NonceSize));

            var nonce = envelope.AsSpan(0, NonceSize);
            var ciphertext = envelope.AsSpan(NonceSize, MasterKeySize);
            var tag = envelope.AsSpan(NonceSize + MasterKeySize, TagSize);

            AesGcmShim.Encrypt(wrapKey, nonce, master, ciphertext, tag, s_aad);

            // Master is wrapped; zero the input.
            CryptographicOperations.ZeroMemory(master);
            committed = true;
            return new AesGcmWrapProtector(wrapKey, envelope);
        }
        finally
        {
            if (!committed)
            {
                CryptographicOperations.ZeroMemory(wrapKey);
                CryptographicOperations.ZeroMemory(envelope);
                MemoryLocker.TryUnlock(wrapKey);
                MemoryLocker.TryUnlock(envelope);
            }
        }
    }

    private AesGcmWrapProtector(byte[] wrapKey, byte[] envelope)
    {
        _wrapKey = wrapKey;
        _envelope = envelope;
    }

    protected override KeyAccessor UnwrapCore()
    {
        var nonce = _envelope.AsSpan(0, NonceSize);
        var ciphertext = _envelope.AsSpan(NonceSize, MasterKeySize);
        var tag = _envelope.AsSpan(NonceSize + MasterKeySize, TagSize);

        Span<byte> plaintext = stackalloc byte[MasterKeySize];
        try
        {
            AesGcmShim.Decrypt(_wrapKey, nonce, ciphertext, tag, plaintext, s_aad);
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
        CryptographicOperations.ZeroMemory(_envelope);
        MemoryLocker.TryUnlock(_wrapKey);
        MemoryLocker.TryUnlock(_envelope);
    }
}
