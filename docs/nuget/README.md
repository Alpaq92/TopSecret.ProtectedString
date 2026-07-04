# TopSecret

A small suite of .NET packages for keeping secrets safe **in memory**. It exists because `SecureString` never got a cross-platform story — its encryption is Windows-only and Microsoft advises against it for new code — yet real applications still hold passwords, API tokens, and cryptographic key material in plain strings and arrays that any heap dump, swap file, crash report, or memory scan can read. With TopSecret, secrets live AES-GCM-256-encrypted under a per-process (optionally hardware-backed) key, plaintext surfaces only briefly inside escape-resistant span callbacks, and every scratch buffer is pinned, locked, and wiped on exit.

## Packages

- **[TopSecret.ProtectedString](https://www.nuget.org/packages/TopSecret.ProtectedString)** — the core: a cross-platform `SecureString` replacement for text secrets, with constant-time equality, Argon2id credential hashing (OWASP defaults), opt-in hardware-backed key wrapping (Apple Secure Enclave / Android Keystore built in), and a bundled Roslyn analyzer that flags plaintext escaping the access callbacks.
- **[TopSecret.ProtectedBlob](https://www.nuget.org/packages/TopSecret.ProtectedBlob)** — multi-megabyte **binary** secrets (key stores, sealed assets, model shards): write-once, chunked AES-GCM-256, streamed chunk-at-a-time reads that fail closed on tampering.
- **[TopSecret.ProtectedString.WindowsTpm](https://www.nuget.org/packages/TopSecret.ProtectedString.WindowsTpm)** — opt-in Windows TPM 2.0 wrapping of the process master key.
- **[TopSecret.ProtectedString.LinuxTpm](https://www.nuget.org/packages/TopSecret.ProtectedString.LinuxTpm)** — the same for Linux TPM 2.0 (`/dev/tpmrm0`).
- **[TopSecret.ProtectedString.Configuration](https://www.nuget.org/packages/TopSecret.ProtectedString.Configuration)** — binds `appsettings.json` / `IConfiguration` values straight into `ProtectedString`, with no plaintext `string` detour.

[Documentation & threat model](https://github.com/Alpaq92/TopSecret.ProtectedString#readme) · [Live browser demo](https://alpaq92.github.io/TopSecret.ProtectedString/) · [Changelog](https://github.com/Alpaq92/TopSecret.ProtectedString/blob/master/CHANGELOG.md) · MIT

*The threat model defends secrets at rest in memory (dumps, swap, scraping) — not an attacker already executing code inside your process. Read it before relying on any in-memory protection.*
