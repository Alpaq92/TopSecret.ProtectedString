# Changelog

<!--
This file is maintained automatically by release-please
(.github/workflows/release.yml): each release lands at the top as
`## [x.y.z](compare-link) (YYYY-MM-DD)` with Features / Bug Fixes /
Dependencies / Documentation / Refactoring sections generated from
Conventional Commit messages (feat:, fix:, deps:, docs:, refactor:).
Do not hand-edit released sections — correct the record with a follow-up
commit instead. The baseline section below predates the automated history
and is kept for reference.
-->

## Pre-release baseline

The initial feature set, per platform:

- **Windows** (`net10.0`) — AES-GCM-256 contents encryption. Master-key wrap: AES-GCM-256 under a per-protector random key (no fixed system-wide key). Optional TPM 2.0 hardware-backed wrap via `TopSecret.ProtectedString.WindowsTpm`.
- **Linux** (`net10.0`) — AES-GCM-256 contents encryption. Master-key wrap: HKDF stream-XOR. Optional TPM 2.0 hardware-backed wrap via `TopSecret.ProtectedString.LinuxTpm` (against `/dev/tpmrm0`).
- **macOS / iOS / Mac Catalyst** (`net10.0-macos` / `-ios` / `-maccatalyst`) — AES-GCM-256 contents encryption. Master-key wrap: Apple Secure Enclave (built-in; M1+ / T1 / T2 hosts only). HKDF fallback on pre-T1 Intel Macs and x86_64 iOS Simulator.
- **Android** (`net10.0-android`, API 23+) — AES-GCM-256 contents encryption. Master-key wrap: Android Keystore TEE (built-in; not StrongBox). HKDF fallback when Keystore is unavailable.
- **Browser WebAssembly** (`net10.0-browser`) — AES-GCM-256 via BouncyCastle (in-box `AesGcm.IsSupported` is `false` on wasm). Master-key wrap: HKDF stream-XOR. No hardware-backed tier — the WASM sandbox has no SEP / Keystore / TPM.

Shared across all TFMs: per-instance 64-bit AEAD AAD binding, pinned/locked/dump-excluded buffers with `CryptographicOperations.ZeroMemory` wipes, `Access(ReadOnlySpanAction<char>)` / `CopyTo` / `WriteUtf8To` plaintext access shapes, Argon2id credentials with constant-time verify, opt-in process-key rotation, TPS001/TPS002 build-time analyzer, optional `TopSecret.ProtectedString.Configuration` binder.

Additions leading up to `0.1.0`:

- **`TopSecret.ProtectedBlob`** — multi-megabyte secret byte blobs: write-once, chunked AES-GCM-256 in ordinary memory (64 KiB default, 4 KiB–1 MiB via ctor or `ProtectedBlobOptions.DefaultChunkSize`), per-blob DEK wrapped under the shared process master (hardware tiers apply automatically; one hardware key slot regardless of blob count), secretstream-style fail-closed integrity (bit flips / reordering / truncation / cross-blob transplants all fail the tag), chunked reads via `AccessChunk(s)` / `CopyTo` / `WriteTo`, streaming `FromStream` construction with ≤ 2 chunks plaintext residency. Frozen wire format pinned by golden-vector tests.
- **`TopSecret.Demo`** (renamed from `TopSecret.ProtectedString.Demo`) — shared `DemoApp` scenarios incl. the blob showcase and run metrics.
- **`TopSecret.Demo.Wasm`** — the same demo fully client-side in the browser (xterm.js + .NET WebAssembly), deployed to GitHub Pages on every release.
- Per-package icons (`assets/string`, `assets/blob`, `assets/rest`) and focused NuGet readmes for the two library packages.
