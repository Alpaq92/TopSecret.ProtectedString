using System.Security.Cryptography;
using System.Text;

namespace TopSecret;

/// <summary>
/// Wraps the master AES key with AES-GCM-256 under a fresh per-protector
/// random wrap key. The wrap key and the nonce/ciphertext/tag envelope
/// live in two separately allocated, pinned, locked, dump-excluded
/// buffers; <see cref="UnwrapKey"/> AES-GCM-decrypts into a third
/// freshly-allocated pinned/locked buffer that is wiped and unlocked
/// when the returned <see cref="KeyAccessor"/> is disposed.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this beats DPAPI's <c>CryptProtectMemory(SAME_PROCESS)</c>.</b>
/// DPAPI derives its unwrap key from session state that a public PoC
/// reproduces from a passive dump alone. The ephemeral-key scheme has
/// no fixed system-wide key — the wrap key is 32 bytes of
/// <see cref="RandomNumberGenerator"/> output, unique to this protector
/// instance, and an attacker has to read both the wrap key buffer and
/// the envelope buffer from the live process to reverse the wrap.
/// </para>
/// <para>
/// <b>Why this isn't immune to a determined dump.</b> Both buffers still
/// live in this process's address space. A heap-dump-capable attacker
/// who knows the layout walks the pinned object heap, finds both, and
/// reverses the AEAD. The win is "no fixed reproducible key", not
/// "memory-dump-proof"; for the latter, opt into the hardware-backed
/// tier (Apple SEP / Android Keystore / Windows TPM via the optional
/// <c>TopSecret.ProtectedString.WindowsTpm</c> NuGet) where the wrap
/// key lives in a secure element instead of process memory.
/// </para>
/// </remarks>
internal sealed class WindowsAesGcmEphemeralProtector : KeyAtRestProtector, IDisposable
{
    private const int MasterKeySize = 32;
    private const int WrapKeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int EnvelopeSize = NonceSize + MasterKeySize + TagSize;

    private static readonly byte[] s_aad =
        Encoding.UTF8.GetBytes("TopSecret.ProtectedString/WindowsAesGcmEphemeral/v1");

    private readonly byte[] _wrapKey;
    private readonly byte[] _envelope;
    private bool _disposed;

    public static WindowsAesGcmEphemeralProtector? TryCreate(byte[] master)
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

    private static WindowsAesGcmEphemeralProtector CreateOrThrow(byte[] master)
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
            return new WindowsAesGcmEphemeralProtector(wrapKey, envelope);
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

    private WindowsAesGcmEphemeralProtector(byte[] wrapKey, byte[] envelope)
    {
        _wrapKey = wrapKey;
        _envelope = envelope;
    }

    public override KeyAccessor UnwrapKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var unwrapped = ProtectedString.AllocatePinnedBytes(
            MasterKeySize, excludeFromDumps: true, lockContext: "memory locking unwrapped key");

        bool ok = false;
        try
        {
            var nonce = _envelope.AsSpan(0, NonceSize);
            var ciphertext = _envelope.AsSpan(NonceSize, MasterKeySize);
            var tag = _envelope.AsSpan(NonceSize + MasterKeySize, TagSize);

            AesGcmShim.Decrypt(_wrapKey, nonce, ciphertext, tag, unwrapped, s_aad);
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
        CryptographicOperations.ZeroMemory(_envelope);
        MemoryLocker.TryUnlock(_wrapKey);
        MemoryLocker.TryUnlock(_envelope);
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~WindowsAesGcmEphemeralProtector()
    {
        try { Dispose(); } catch { /* finalizer must not throw */ }
    }
}
