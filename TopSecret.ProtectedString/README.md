# TopSecret.ProtectedString

A cross-platform .NET 10 alternative to `System.Security.SecureString` that **actually encrypts its contents at rest in process memory on every supported platform** — Windows, Linux, macOS, Android, iOS, Mac Catalyst, and browser WebAssembly.

> Microsoft recommends against `SecureString` for new code — on non-Windows platforms it does not encrypt the buffer at all. `ProtectedString` fills that gap with the same usage shape.

```
dotnet add package TopSecret.ProtectedString
```

## Quick start

```csharp
using TopSecret;

// Wrap a secret (span overload preferred — no string copy lingers in the GC heap).
using var ps = new ProtectedString("hunter2".AsSpan());

// Use it briefly: the plaintext is a ref-struct ReadOnlySpan<char> the compiler
// refuses to let escape; the buffer is wiped when the callback returns.
ps.Access(plain =>
{
    // HMAC it, write it to a stream, hand it to an API…
});

// Or stream it without materializing a managed string.
ps.WriteUtf8To(networkStream);

// Constant-time compare, and Argon2id credential verification (OWASP defaults).
bool same = ps.Equals(other);
byte[] verifier = ps.ComputeArgon2idHash(salt);
```

## What you get

- **AES-GCM-256 encryption at rest** on every platform, per-instance AEAD binding (ciphertext swapped between instances fails the tag check).
- **Pinned + `VirtualLock`/`mlock`ed buffers** — the GC never copies the secret, the OS never pages it to swap; JIT-resistant wipes on every exit path.
- **Escape-resistant access**: plaintext is exposed only as a `ref struct` span inside a callback — no capture, no field, no return, no `await`.
- **Opt-in hardware-backed key wrapping**: Apple Secure Enclave and Android Keystore built in; Windows/Linux TPM 2.0 via the `TopSecret.ProtectedString.WindowsTpm` / `.LinuxTpm` packages. Choose fail-closed (`HardwareBackedRequired`) or graceful fallback (`HardwareBackedPreferred`).
- **Build-time analyzer** (TPS001/TPS002) that flags plaintext escaping your `Access` callbacks.
- **Argon2id** credential hashing with OWASP-aligned defaults and constant-time verification.
- Opt-in **process-key rotation**; logging-safe `ToString()`; honest, documented threat model.

## When you need bulk data instead

`ProtectedString` is sized for credentials. For multi-megabyte secret **byte** blobs (model weights, sealed assets, uploaded files), use the companion package [`TopSecret.ProtectedBlob`](https://www.nuget.org/packages/TopSecret.ProtectedBlob) — chunked AES-GCM with the same key-protection tiers.

## Threat model, honestly

This defends against **accidental** disclosure — heap dumps, swap files, GC copies, accidental logging. It is not a defence against an attacker who can already read the live process. The full security model, platform matrix, performance notes, FAQ, and a live browser demo are in the [repository README](https://github.com/Alpaq92/TopSecret.ProtectedString#readme).

## License

[MIT](https://github.com/Alpaq92/TopSecret.ProtectedString/blob/master/LICENSE).
