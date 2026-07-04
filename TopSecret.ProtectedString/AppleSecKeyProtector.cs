using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TopSecret;

/// <summary>
/// Wraps the per-process AES master key with an EC P-256 key generated inside
/// the Apple Secure Enclave (<c>kSecAttrTokenIDSecureEnclave</c>) using
/// ECIES-AES-GCM (<c>kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM</c>
/// — the variable-IV variant Apple recommends; the older fixed-IV forms are
/// documented as legacy in <c>SecKey.h</c>). The SEP-resident private key
/// never enters process memory; only its reference (<c>SecKeyRef</c>) and
/// the wrapped ciphertext blob are held in the .NET heap.
/// </summary>
/// <remarks>
/// <para>
/// The key is generated with a <c>SecAccessControl</c> of
/// <c>kSecAccessControlPrivateKeyUsage</c> +
/// <c>kSecAttrAccessibleAlwaysThisDeviceOnly</c> — the access control Apple
/// documents for SEP private-key operations, with an accessibility class
/// that carries no unlock-state requirement. <c>privateKeyUsage</c> adds no
/// user prompts (no biometric/PIN flags). The key is never persisted
/// (<c>kSecAttrIsPermanent: false</c> — it lives only in process memory and
/// dies with the process), so none of the data-at-rest accessibility classes
/// apply; <c>AfterFirstUnlock</c> in particular would make SEP key generation
/// fail for any process that runs before the device's first unlock since
/// boot (background app launches, VoIP/push wake-ups), which this library
/// has no reason to require.
/// </para>
/// <para>
/// Each call to <see cref="UnwrapKey"/> performs a SEP roundtrip via
/// <c>SecKeyCreateDecryptedData</c>. Per-op latency is platform-dependent —
/// low single-digit milliseconds on Apple Silicon, more on older A-series
/// devices. Callers must dispose the returned <see cref="KeyAccessor"/> as
/// soon as the AES-GCM operation completes; the buffer is zeroed and unlocked
/// on dispose.
/// </para>
/// <para>
/// When SEP is not available — typically the iOS Simulator on Intel hosts
/// (simulators on Apple-Silicon hosts do expose a SEP), pre-T1 Intel Macs, or
/// any non-Apple platform — <see cref="TryCreate"/> returns
/// <see langword="null"/> and <see cref="KeyAtRestProtectorFactory"/> falls
/// back to the next tier (obscurity, then no-op) per the configured
/// <see cref="KeyAtRestProtection"/> policy; <see cref="HardeningPolicy"/>
/// only governs failures within a tier (e.g. a memory-locking failure), not
/// the hardware-to-obscurity fallback itself.
/// </para>
/// </remarks>
internal sealed class AppleSecKeyProtector : KeyAtRestProtector, IDisposable
{
    private const int MasterKeySize = 32;

    private readonly IntPtr _privateKeyRef;   // SecKeyRef, retained
    private readonly byte[] _wrappedBlob;
    private bool _disposed;

    // Process-lifetime cache for IsActuallyAvailable().
    // 0 = unknown, 1 = available, 2 = unavailable.
    private static int s_availabilityState;

    /// <summary>
    /// Attempts to wrap <paramref name="master"/> using a freshly generated
    /// SEP-resident P-256 key. On success the master array is zeroed in place
    /// and ownership transfers to the returned protector. Returns
    /// <see langword="null"/> on any failure (SEP unavailable, framework load
    /// failure, ECIES error) so <see cref="KeyAtRestProtectorFactory"/> can
    /// fall back to the next tier.
    /// </summary>
    public static AppleSecKeyProtector? TryCreate(byte[] master)
    {
        if (master.Length != MasterKeySize) return null;
        if (!OperatingSystem.IsMacOS() && !OperatingSystem.IsIOS() && !OperatingSystem.IsMacCatalyst())
            return null;

        try
        {
            return CreateOrThrow(master);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Destructive but cached probe: generate a SEP-resident EC key and
    /// immediately discard it, recording the result for the rest of the
    /// process. Returns <see langword="false"/> on hosts where the
    /// <c>AppleSecKeyProtector</c> assembly ships but no actual Secure
    /// Enclave is present — pre-T1 Intel Macs, iOS Simulator on x86_64.
    /// </summary>
    /// <remarks>
    /// Cost: a single <c>SecKeyCreateRandomKey</c> + <c>CFRelease</c> on
    /// first call (low single-digit ms on Apple Silicon, more on older
    /// hardware). Subsequent calls are a single <c>Volatile.Read</c>.
    /// </remarks>
    internal static bool IsActuallyAvailable()
    {
        var snapshot = Volatile.Read(ref s_availabilityState);
        if (snapshot != 0) return snapshot == 1;

        if (!OperatingSystem.IsMacOS() && !OperatingSystem.IsIOS() && !OperatingSystem.IsMacCatalyst())
        {
            Volatile.Write(ref s_availabilityState, 2);
            return false;
        }

        bool available = ProbeOnce();
        // Race between concurrent probes is benign: both writes are the same
        // value, so a CAS would be churn for no benefit.
        Volatile.Write(ref s_availabilityState, available ? 1 : 2);
        return available;
    }

    private static bool ProbeOnce()
    {
        IntPtr paramDict = IntPtr.Zero;
        IntPtr privateKey = IntPtr.Zero;
        try
        {
            Native.EnsureLoaded();
            paramDict = Native.BuildKeyGenParameters();
            IntPtr error = IntPtr.Zero;
            privateKey = Native.SecKeyCreateRandomKey(paramDict, ref error);
            if (privateKey == IntPtr.Zero)
            {
                if (error != IntPtr.Zero) Native.CFRelease(error);
                return false;
            }
            return true;
        }
        catch
        {
            // EnsureLoaded can throw if the Security / CoreFoundation
            // frameworks fail to load (treat as unavailable).
            return false;
        }
        finally
        {
            if (privateKey != IntPtr.Zero) Native.CFRelease(privateKey);
            if (paramDict != IntPtr.Zero) Native.CFRelease(paramDict);
        }
    }

    private static AppleSecKeyProtector CreateOrThrow(byte[] master)
    {
        Native.EnsureLoaded();

        IntPtr privateKey = IntPtr.Zero;
        IntPtr publicKey = IntPtr.Zero;
        IntPtr paramDict = IntPtr.Zero;
        IntPtr plaintextData = IntPtr.Zero;
        IntPtr encryptedData = IntPtr.Zero;
        IntPtr error;

        try
        {
            paramDict = Native.BuildKeyGenParameters();

            error = IntPtr.Zero;
            privateKey = Native.SecKeyCreateRandomKey(paramDict, ref error);
            if (privateKey == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    Native.DescribeAndReleaseError(error, "SecKeyCreateRandomKey"));
            }

            publicKey = Native.SecKeyCopyPublicKey(privateKey);
            if (publicKey == IntPtr.Zero)
                throw new InvalidOperationException("SecKeyCopyPublicKey returned NULL.");

            plaintextData = Native.CFDataCreateWithBytes(master);

            error = IntPtr.Zero;
            encryptedData = Native.SecKeyCreateEncryptedData(
                publicKey, Native.AlgorithmECIES, plaintextData, ref error);
            if (encryptedData == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    Native.DescribeAndReleaseError(error, "SecKeyCreateEncryptedData"));
            }

            byte[] wrapped = Native.CFDataCopyToManaged(encryptedData);

            // Master is now wrapped; zero the input array. After this point
            // the only place the master exists is inside the SEP and inside
            // ECIES output that only SEP can decrypt.
            CryptographicOperations.ZeroMemory(master);

            var protector = new AppleSecKeyProtector(privateKey, wrapped);
            privateKey = IntPtr.Zero; // ownership transferred; do not release in finally
            return protector;
        }
        finally
        {
            if (publicKey != IntPtr.Zero) Native.CFRelease(publicKey);
            if (paramDict != IntPtr.Zero) Native.CFRelease(paramDict);
            if (plaintextData != IntPtr.Zero) Native.CFRelease(plaintextData);
            if (encryptedData != IntPtr.Zero) Native.CFRelease(encryptedData);
            if (privateKey != IntPtr.Zero) Native.CFRelease(privateKey);
        }
    }

    private AppleSecKeyProtector(IntPtr privateKeyRef, byte[] wrappedBlob)
    {
        _privateKeyRef = privateKeyRef;
        _wrappedBlob = wrappedBlob;
    }

    public override KeyAccessor UnwrapKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        IntPtr ciphertext = IntPtr.Zero;
        IntPtr decrypted = IntPtr.Zero;
        byte[]? unwrapped = null;
        bool ok = false;
        try
        {
            ciphertext = Native.CFDataCreateWithBytes(_wrappedBlob);

            IntPtr error = IntPtr.Zero;
            decrypted = Native.SecKeyCreateDecryptedData(
                _privateKeyRef, Native.AlgorithmECIES, ciphertext, ref error);
            if (decrypted == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    Native.DescribeAndReleaseError(error, "SecKeyCreateDecryptedData"));
            }

            int len = checked((int)Native.CFDataGetLength(decrypted));
            unwrapped = GC.AllocateArray<byte>(len, pinned: true);
            // Best-effort lock — fold into the same policy as the rest of the
            // hardening surface.
            if (!MemoryLocker.TryLock(unwrapped)) HardeningPolicy.OnFailure("memory locking unwrapped key");

            Native.CFDataCopyToBuffer(decrypted, unwrapped);
            ok = true;
            return KeyAccessor.Ephemeral(unwrapped);
        }
        finally
        {
            if (decrypted != IntPtr.Zero) Native.CFRelease(decrypted);
            if (ciphertext != IntPtr.Zero) Native.CFRelease(ciphertext);
            if (!ok && unwrapped is { Length: > 0 })
            {
                CryptographicOperations.ZeroMemory(unwrapped);
                MemoryLocker.TryUnlock(unwrapped);
            }
            // Keeps `this` reachable through the SEP round-trip above, so the
            // finalizer can never fire (releasing _privateKeyRef out from
            // under an in-flight decrypt) while UnwrapKey is executing.
            GC.KeepAlive(this);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        if (_privateKeyRef != IntPtr.Zero) Native.CFRelease(_privateKeyRef);
        CryptographicOperations.ZeroMemory(_wrappedBlob);
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~AppleSecKeyProtector()
    {
        // Best-effort cleanup if the caller forgot Dispose. CFRelease is a
        // CoreFoundation P/Invoke with no managed re-entry, so it is safe
        // from the finalizer thread.
        try { Dispose(); } catch { /* finalizer must not throw */ }
    }

    // ---- Native / CoreFoundation interop -----------------------------

    private static class Native
    {
        private const string SecurityFramework = "/System/Library/Frameworks/Security.framework/Security";
        private const string CoreFoundationFramework = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

        // CFNumberType.kCFNumberIntType = 9.
        private const int kCFNumberIntType = 9;

        // CFStringEncoding kCFStringEncodingUTF8.
        private const uint kCFStringEncodingUTF8 = 0x08000100;

        // SecAccessControlCreateFlags.privateKeyUsage — permits SEP
        // private-key operations without any user-presence requirement.
        private const nuint kSecAccessControlPrivateKeyUsage = 1u << 30;

        private static int s_loaded; // 0 = not loaded, 1 = loaded

        internal static IntPtr AlgorithmECIES { get; private set; }
        private static IntPtr s_attrKeyType;
        private static IntPtr s_attrKeyTypeECSECPrimeRandom;
        private static IntPtr s_attrKeySizeInBits;
        private static IntPtr s_attrTokenID;
        private static IntPtr s_attrTokenIDSecureEnclave;
        private static IntPtr s_attrIsPermanent;
        private static IntPtr s_attrAccessControl;
        private static IntPtr s_privateKeyAttrs;
        private static IntPtr s_attrAccessibleAlwaysThisDeviceOnly;
        private static IntPtr s_cfBooleanFalse;
        private static IntPtr s_cfTypeDictionaryKeyCallBacks;
        private static IntPtr s_cfTypeDictionaryValueCallBacks;

        public static void EnsureLoaded()
        {
            if (Volatile.Read(ref s_loaded) == 1) return;

            var sec = NativeLibrary.Load(SecurityFramework);
            var cf = NativeLibrary.Load(CoreFoundationFramework);

            // CFStringRef constants — variable holds a pointer; dereference once.
            // The fixed-IV ECIES forms are documented as legacy in SecKey.h
            // (they use an all-zero GCM IV); the VariableIV variant is Apple's
            // recommended algorithm for SEP ECIES.
            AlgorithmECIES = ReadIntPtrSymbol(sec, "kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM");
            s_attrKeyType = ReadIntPtrSymbol(sec, "kSecAttrKeyType");
            s_attrKeyTypeECSECPrimeRandom = ReadIntPtrSymbol(sec, "kSecAttrKeyTypeECSECPrimeRandom");
            s_attrKeySizeInBits = ReadIntPtrSymbol(sec, "kSecAttrKeySizeInBits");
            s_attrTokenID = ReadIntPtrSymbol(sec, "kSecAttrTokenID");
            s_attrTokenIDSecureEnclave = ReadIntPtrSymbol(sec, "kSecAttrTokenIDSecureEnclave");
            s_attrIsPermanent = ReadIntPtrSymbol(sec, "kSecAttrIsPermanent");
            s_attrAccessControl = ReadIntPtrSymbol(sec, "kSecAttrAccessControl");
            s_privateKeyAttrs = ReadIntPtrSymbol(sec, "kSecPrivateKeyAttrs");
            s_attrAccessibleAlwaysThisDeviceOnly = ReadIntPtrSymbol(sec, "kSecAttrAccessibleAlwaysThisDeviceOnly");

            // CFBooleanRef constants.
            s_cfBooleanFalse = ReadIntPtrSymbol(cf, "kCFBooleanFalse");

            // Struct globals — symbol address is the struct address; do NOT dereference.
            s_cfTypeDictionaryKeyCallBacks = NativeLibrary.GetExport(cf, "kCFTypeDictionaryKeyCallBacks");
            s_cfTypeDictionaryValueCallBacks = NativeLibrary.GetExport(cf, "kCFTypeDictionaryValueCallBacks");

            Volatile.Write(ref s_loaded, 1);
        }

        private static IntPtr ReadIntPtrSymbol(IntPtr handle, string name) =>
            Marshal.ReadIntPtr(NativeLibrary.GetExport(handle, name));

        public static IntPtr BuildKeyGenParameters()
        {
            // { kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            //   kSecAttrKeySizeInBits: 256,
            //   kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            //   kSecPrivateKeyAttrs: {
            //       kSecAttrIsPermanent: false,
            //       kSecAttrAccessControl: SecAccessControl(
            //           kSecAttrAccessibleAlwaysThisDeviceOnly,
            //           privateKeyUsage) } }
            //
            // privateKeyUsage is the access control Apple documents for SEP
            // private-key operations; it carries no user-presence flags, so
            // no prompt is ever shown. AlwaysThisDeviceOnly carries no
            // unlock-state requirement either — appropriate since this key
            // is never persisted (kSecAttrIsPermanent: false below) and so
            // has no at-rest state for an accessibility class to protect;
            // it also keeps key generation working for processes that start
            // before the device's first unlock since boot.
            int keySize = 256;
            IntPtr keySizeNumber = IntPtr.Zero;
            IntPtr accessControl = IntPtr.Zero;
            IntPtr privateKeyAttrs = IntPtr.Zero;
            try
            {
                keySizeNumber = CFNumberCreate(IntPtr.Zero, kCFNumberIntType, ref keySize);

                IntPtr aclError = IntPtr.Zero;
                accessControl = SecAccessControlCreateWithFlags(
                    IntPtr.Zero,
                    s_attrAccessibleAlwaysThisDeviceOnly,
                    kSecAccessControlPrivateKeyUsage,
                    ref aclError);
                if (accessControl == IntPtr.Zero)
                {
                    throw new InvalidOperationException(
                        DescribeAndReleaseError(aclError, "SecAccessControlCreateWithFlags"));
                }

                privateKeyAttrs = CreateCFDictionary(
                    [s_attrIsPermanent, s_attrAccessControl],
                    [s_cfBooleanFalse, accessControl]);

                return CreateCFDictionary(
                    [s_attrKeyType, s_attrKeySizeInBits, s_attrTokenID, s_privateKeyAttrs],
                    [s_attrKeyTypeECSECPrimeRandom, keySizeNumber, s_attrTokenIDSecureEnclave, privateKeyAttrs]);
            }
            finally
            {
                // CFDictionaryCreate with kCFType callbacks retains its keys
                // and values, so our references can be dropped unconditionally.
                if (privateKeyAttrs != IntPtr.Zero) CFRelease(privateKeyAttrs);
                if (accessControl != IntPtr.Zero) CFRelease(accessControl);
                if (keySizeNumber != IntPtr.Zero) CFRelease(keySizeNumber);
            }
        }

        private static IntPtr CreateCFDictionary(IntPtr[] keys, IntPtr[] values)
        {
            var keysHandle = GCHandle.Alloc(keys, GCHandleType.Pinned);
            var valuesHandle = GCHandle.Alloc(values, GCHandleType.Pinned);
            try
            {
                return CFDictionaryCreate(
                    IntPtr.Zero,
                    Marshal.UnsafeAddrOfPinnedArrayElement(keys, 0),
                    Marshal.UnsafeAddrOfPinnedArrayElement(values, 0),
                    keys.Length,
                    s_cfTypeDictionaryKeyCallBacks,
                    s_cfTypeDictionaryValueCallBacks);
            }
            finally
            {
                keysHandle.Free();
                valuesHandle.Free();
            }
        }

        /// <summary>
        /// Extracts a human-readable description from a <c>CFErrorRef</c>
        /// (releasing it), for exception messages. Returns a generic message
        /// when the error is NULL or its description can't be read.
        /// </summary>
        public static string DescribeAndReleaseError(IntPtr error, string operation)
        {
            if (error == IntPtr.Zero) return operation + " failed.";
            try
            {
                IntPtr description = CFErrorCopyDescription(error);
                if (description == IntPtr.Zero) return operation + " failed.";
                try
                {
                    nint utf16Length = CFStringGetLength(description);
                    nint maxBytes = CFStringGetMaximumSizeForEncoding(utf16Length, kCFStringEncodingUTF8) + 1;
                    var buffer = new byte[maxBytes];
                    if (!CFStringGetCString(description, buffer, maxBytes, kCFStringEncodingUTF8))
                        return operation + " failed.";
                    int terminator = Array.IndexOf(buffer, (byte)0);
                    if (terminator < 0) terminator = buffer.Length;
                    return operation + " failed: " + System.Text.Encoding.UTF8.GetString(buffer, 0, terminator);
                }
                finally
                {
                    CFRelease(description);
                }
            }
            finally
            {
                CFRelease(error);
            }
        }

        public static IntPtr CFDataCreateWithBytes(byte[] data)
        {
            var handle = GCHandle.Alloc(data, GCHandleType.Pinned);
            try
            {
                return CFDataCreate(
                    IntPtr.Zero,
                    Marshal.UnsafeAddrOfPinnedArrayElement(data, 0),
                    (nint)data.Length);
            }
            finally
            {
                handle.Free();
            }
        }

        public static byte[] CFDataCopyToManaged(IntPtr cfData)
        {
            int len = checked((int)CFDataGetLength(cfData));
            var managed = new byte[len];
            CFDataCopyToBuffer(cfData, managed);
            return managed;
        }

        public static void CFDataCopyToBuffer(IntPtr cfData, byte[] destination)
        {
            int len = checked((int)CFDataGetLength(cfData));
            if (destination.Length < len)
                throw new ArgumentException("destination buffer too small", nameof(destination));
            IntPtr src = CFDataGetBytePtr(cfData);
            Marshal.Copy(src, destination, 0, len);
        }

        // ---- P/Invoke surface -------------------------------------------

        [DllImport(CoreFoundationFramework)]
        public static extern void CFRelease(IntPtr cf);

        [DllImport(CoreFoundationFramework)]
        public static extern IntPtr CFDataCreate(IntPtr allocator, IntPtr bytes, nint length);

        [DllImport(CoreFoundationFramework)]
        public static extern IntPtr CFDataGetBytePtr(IntPtr theData);

        [DllImport(CoreFoundationFramework)]
        public static extern nint CFDataGetLength(IntPtr theData);

        [DllImport(CoreFoundationFramework)]
        public static extern IntPtr CFNumberCreate(IntPtr allocator, int theType, ref int valuePtr);

        [DllImport(CoreFoundationFramework)]
        public static extern IntPtr CFDictionaryCreate(
            IntPtr allocator,
            IntPtr keys,
            IntPtr values,
            nint numValues,
            IntPtr keyCallBacks,
            IntPtr valueCallBacks);

        [DllImport(SecurityFramework)]
        public static extern IntPtr SecKeyCreateRandomKey(IntPtr parameters, ref IntPtr error);

        [DllImport(SecurityFramework)]
        public static extern IntPtr SecKeyCopyPublicKey(IntPtr key);

        [DllImport(SecurityFramework)]
        public static extern IntPtr SecKeyCreateEncryptedData(
            IntPtr key,
            IntPtr algorithm,
            IntPtr plaintext,
            ref IntPtr error);

        [DllImport(SecurityFramework)]
        public static extern IntPtr SecKeyCreateDecryptedData(
            IntPtr key,
            IntPtr algorithm,
            IntPtr ciphertext,
            ref IntPtr error);

        [DllImport(SecurityFramework)]
        public static extern IntPtr SecAccessControlCreateWithFlags(
            IntPtr allocator,
            IntPtr protection,
            nuint flags,
            ref IntPtr error);

        [DllImport(CoreFoundationFramework)]
        public static extern IntPtr CFErrorCopyDescription(IntPtr err);

        [DllImport(CoreFoundationFramework)]
        public static extern nint CFStringGetLength(IntPtr theString);

        [DllImport(CoreFoundationFramework)]
        public static extern nint CFStringGetMaximumSizeForEncoding(nint length, uint encoding);

        [DllImport(CoreFoundationFramework)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool CFStringGetCString(
            IntPtr theString,
            byte[] buffer,
            nint bufferSize,
            uint encoding);
    }
}
