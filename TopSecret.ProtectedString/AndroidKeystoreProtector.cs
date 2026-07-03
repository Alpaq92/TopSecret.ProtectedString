#if ANDROID
using System.Security.Cryptography;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using CipherMode = Javax.Crypto.CipherMode;

namespace TopSecret;

/// <summary>
/// Wraps the per-process AES master key with an AES-GCM-256 key generated
/// inside the <c>AndroidKeyStore</c> provider (TEE on API 23+; StrongBox on
/// API 28+ devices that expose it). The Keystore-resident wrapping key never
/// enters the app process — encrypt and decrypt cross a Binder IPC boundary
/// into the system <c>keystore2</c> daemon, which holds the actual key bytes
/// in the secure element.
/// </summary>
/// <remarks>
/// <para>
/// We deliberately do <i>not</i> request StrongBox via
/// <c>SetIsStrongBoxBacked(true)</c>. StrongBox is markedly slower per
/// operation (the research cited ~3 s for 1 MiB AES-GCM on a Pixel 8) and
/// the per-call latency on a hot path would dominate. TEE is the right
/// trade-off here.
/// </para>
/// <para>
/// The wrapping-key alias is regenerated on every process start: the prior
/// alias (if any) is deleted, a fresh AES-256-GCM key is generated, and the
/// master is wrapped against it. Process death therefore wipes both the
/// wrapping key and any lingering relationship between this process's wrapped
/// blob and a Keystore key.
/// </para>
/// </remarks>
internal sealed class AndroidKeystoreProtector : KeyAtRestProtector, IDisposable
{
    private const string KeystoreName = "AndroidKeyStore";
    private const string KeyAlias = "TopSecret.ProtectedString.MasterWrap";
    private const string Transformation = "AES/GCM/NoPadding";
    private const int GcmTagBits = 128;

    private readonly IKey _wrappingKey;
    private readonly byte[] _wrappedBlob;
    private readonly byte[] _iv;
    private bool _disposed;

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

    private static AndroidKeystoreProtector CreateOrThrow(byte[] master)
    {
        var keystore = KeyStore.GetInstance(KeystoreName)
            ?? throw new InvalidOperationException("AndroidKeyStore unavailable.");
        keystore.Load(null);

        if (keystore.ContainsAlias(KeyAlias))
        {
            keystore.DeleteEntry(KeyAlias);
        }

        var spec = new KeyGenParameterSpec.Builder(
                KeyAlias,
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

        var cipher = Cipher.GetInstance(Transformation)
            ?? throw new InvalidOperationException("Cipher.GetInstance(AES/GCM/NoPadding) unavailable.");
        cipher.Init(CipherMode.EncryptMode, wrappingKey);
        var wrappedBlob = cipher.DoFinal(master)
            ?? throw new InvalidOperationException("Cipher.DoFinal returned null.");
        var iv = cipher.GetIV()
            ?? throw new InvalidOperationException("Cipher.GetIV returned null (Keystore did not assign an IV).");

        // Master is now wrapped against a Keystore-resident key.
        CryptographicOperations.ZeroMemory(master);

        return new AndroidKeystoreProtector(wrappingKey, wrappedBlob, iv);
    }

    private AndroidKeystoreProtector(IKey wrappingKey, byte[] wrappedBlob, byte[] iv)
    {
        _wrappingKey = wrappingKey;
        _wrappedBlob = wrappedBlob;
        _iv = iv;
    }

    public override KeyAccessor UnwrapKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var cipher = Cipher.GetInstance(Transformation)
            ?? throw new InvalidOperationException("Cipher.GetInstance failed during unwrap.");
        var ivSpec = new GCMParameterSpec(GcmTagBits, _iv);
        cipher.Init(CipherMode.DecryptMode, _wrappingKey, ivSpec);

        var unwrapped = cipher.DoFinal(_wrappedBlob)
            ?? throw new InvalidOperationException("Cipher.DoFinal returned null during unwrap.");

        // Promote into a pinned, locked buffer so the rest of the library can
        // wipe it deterministically. The transient byte[] returned by DoFinal
        // is on the regular managed heap and can move under the GC.
        var pinned = GC.AllocateArray<byte>(unwrapped.Length, pinned: true);
        if (!MemoryLocker.TryLock(pinned))
            HardeningPolicy.OnFailure("memory locking unwrapped key");

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

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_wrappedBlob);
        CryptographicOperations.ZeroMemory(_iv);
        // The Keystore-resident wrapping key has no managed disposal — its
        // alias remains until the next process start replaces it (or the OS
        // garbage-collects it). The IKey reference is just a handle; the key
        // bytes never lived in this process.
        _disposed = true;
    }
}
#endif
