using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TopSecret;

internal sealed class AppleSecKeyProtector : DisposableKeyAtRestProtector
{
    private readonly IntPtr _privateKeyRef;   // SecKeyRef, retained
    private readonly byte[] _wrappedBlob;

    // Process-lifetime cache for IsActuallyAvailable().
    // 0 = unknown, 1 = available, 2 = unavailable.
    private static int s_availabilityState;

    private static bool IsApplePlatform =>
        OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst();

    public static AppleSecKeyProtector? TryCreate(byte[] master)
    {
        if (!IsApplePlatform) return null;
        return TryCreate(master, CreateOrThrow);
    }

    internal static bool IsActuallyAvailable()
    {
        var snapshot = Volatile.Read(ref s_availabilityState);
        if (snapshot != 0) return snapshot == 1;

        if (!IsApplePlatform)
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

    protected override KeyAccessor UnwrapCore()
    {
        // The base's GC.KeepAlive(this) keeps _privateKeyRef alive through the
        // SEP round-trip, so the finalizer cannot CFRelease it mid-decrypt.
        IntPtr ciphertext = IntPtr.Zero;
        IntPtr decrypted = IntPtr.Zero;
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
            unsafe
            {
                // Copy straight from the CFData backing store into the locked
                // ephemeral — no managed intermediate.
                return EphemeralFrom(new ReadOnlySpan<byte>((void*)Native.CFDataGetBytePtr(decrypted), len));
            }
        }
        finally
        {
            if (decrypted != IntPtr.Zero) Native.CFRelease(decrypted);
            if (ciphertext != IntPtr.Zero) Native.CFRelease(ciphertext);
        }
    }

    protected override void ReleaseResources()
    {
        // CFRelease is a CoreFoundation P/Invoke with no managed re-entry, so
        // it is safe from the finalizer thread.
        if (_privateKeyRef != IntPtr.Zero) Native.CFRelease(_privateKeyRef);
        CryptographicOperations.ZeroMemory(_wrappedBlob);
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
            Marshal.Copy(CFDataGetBytePtr(cfData), managed, 0, len);
            return managed;
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
