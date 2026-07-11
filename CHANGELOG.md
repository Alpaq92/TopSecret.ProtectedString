# Changelog

## [2.2.1](https://github.com/Alpaq92/TopSecret.ProtectedString/compare/v2.2.0...v2.2.1) (2026-07-11)


### Documentation

* **notices:** credit Sun Microsystems as GuardedString copyright holder ([420e4b9](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/420e4b9004ce381d2a3dc1913d0c01c22ab8ff5e))

## [2.2.0](https://github.com/Alpaq92/TopSecret.ProtectedString/compare/v2.1.1...v2.2.0) (2026-07-06)


### Features

* **security:** add SECURITY.md, CodeQL scanning, and CI least-privilege hardening ([332bf3f](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/332bf3ff1118d3520fdac0eb25bb56d1d9d7b1ca))


### Bug Fixes

* **demo:** theme the xterm viewport background to remove the black bar in light mode ([2a54df0](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/2a54df0a093ddf798cf6efbe1a7a706c786aa470))
* **security:** address CodeQL workflow review feedback ([0688074](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/0688074510363b8efe48a8e9871dc50206644faf))
* **security:** guard against 32-bit overflow when sizing ciphertext buffers ([1ece169](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/1ece169658be8ff1e4dd33d1ee090b97fbaf751e))

## [2.1.1](https://github.com/Alpaq92/TopSecret.ProtectedString/compare/v2.1.0...v2.1.1) (2026-07-05)


### Bug Fixes

* **demo:** drop the loading-dot animation, use a static ellipsis ([57594da](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/57594dab48b9d116362339ade10ed82fd948a4fa))

## [2.1.0](https://github.com/Alpaq92/TopSecret.ProtectedString/compare/v2.0.0...v2.1.0) (2026-07-05)


### Features

* **demo:** use the package icon as the WASM demo's favicon ([fdda87d](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/fdda87dd748e0afabce270d0a013cbebb2051c3b))


### Bug Fixes

* **demo:** fix cursor homing and simplify the loading-dot animation ([ddbedef](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/ddbedeff3787348ae4a03c50a741ffce2ad075f3))

## [2.0.0](https://github.com/Alpaq92/TopSecret.ProtectedString/compare/v1.1.0...v2.0.0) (2026-07-04)


### ⚠ BREAKING CHANGES

* **security:** KeyAtRestProtectorFactory now performs a destructive (generate-and-discard) availability probe on Android the first time KeyAtRestProtection.HardwareBackedRequired or HardwareBackedPreferred is used and no external provider is registered, mirroring the existing Apple behavior. Also, protectors built under earlier 1.x releases wrapped their master key under a single fixed Keystore alias; that alias is now superseded (swept on next construction) and no attempt is made to migrate a key wrapped under it — restart any long-lived process holding a 1.x Android hardware-tier protector across the upgrade.

### Features

* **security:** fix Android Keystore rotation bug, harden SEP key generation ([f95219c](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/f95219c7c21475ea10c9b788b75f681844592337))


### Bug Fixes

* **demo:** paint the first loading dot immediately, tighten cadence to 150ms ([9b3d11c](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/9b3d11cfc47d5add3a7fb94af652a9cafff74cc7))

## [1.1.0](https://github.com/Alpaq92/TopSecret.ProtectedString/compare/v1.0.1...v1.1.0) (2026-07-04)


### Features

* **demo:** animate loading dots, theme the terminal scrollbar, fix rerun freeze ([dd4e844](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/dd4e8446c9cc28f9f5fc798af755b88ad8cf3d77))

## [1.0.1](https://github.com/Alpaq92/TopSecret.ProtectedString/compare/v1.0.0...v1.0.1) (2026-07-04)


### Bug Fixes

* **deps:** update all outdated packages — Argon2 fork to 2.1.6, Roslyn to 5.6.0 ([88240cf](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/88240cf953264bd54ce998de386dd6e15d646c56))


### Documentation

* fix stale Demo section claim that Argon2id skips in the browser ([5f2a36c](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/5f2a36c7d1a73a2032fb19c4afe6a7a0c28c969f))

## [1.0.0](https://github.com/Alpaq92/TopSecret.ProtectedString/compare/v0.1.2...v1.0.0) (2026-07-04)


### ⚠ BREAKING CHANGES

* **argon2:** ComputeArgon2idHash / VerifyArgon2idHash no longer throw PlatformNotSupportedException on net10.0-browser at the default DegreeOfParallelism = 1 — they now complete successfully. Callers that were catching PlatformNotSupportedException specifically to detect "running in the browser" for this API will no longer see it for the default case; calls with DegreeOfParallelism > 1 still throw on a single-threaded host.

### Features

* **argon2:** switch to TopSecret.Cryptography.Argon2 — Argon2id now runs in the browser ([91f8b10](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/91f8b102ae0bd2f1f30b37395d4d3602acac2fbd))


### Bug Fixes

* **browser:** shrink BouncyCastle's key-material reclaim window ([e74358d](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/e74358ddf6064e0c468c9c69afc83203669993c4))


### Documentation

* cite libsodium's identical mlock fallback in References ([fd1f7c0](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/fd1f7c08452d7734b7e8520c027689260b2a199d))
* manual device-check policy; honest swap/BC-residue wording ([f35b4d5](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/f35b4d5e5671d7baa2bdadb578ad1fb04953580e))

## [0.1.2](https://github.com/Alpaq92/TopSecret.ProtectedString/compare/v0.1.1...v0.1.2) (2026-07-04)


### Bug Fixes

* **review:** let CodeRabbit actually approve PRs ([66fc6ad](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/66fc6add8aa639754b3a4dd04b82ac76bf8653b6))

## [0.1.1](https://github.com/Alpaq92/TopSecret.ProtectedString/compare/v0.1.0...v0.1.1) (2026-07-04)


### Bug Fixes

* **ci:** never cancel an in-flight Pages deployment ([ab9c243](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/ab9c243bfdd03ce8aedb2e9d2262488ef56d89c6))


### Documentation

* **nuget:** lengthen the suite intro (API tokens, cryptographic, swap file) ([969e0c9](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/969e0c9f1eb5d4bb99d89e6015f8538c305ae926))
* Release workflow badge, matching Fluid.Avalonia ([2c54084](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/2c54084e2f57b0969279faa65b3696f92a898e8c))

## 0.1.0 (2026-07-04)


### Features

* Bump the nuget-minor-and-patch group with 3 updates ([1f4538a](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/1f4538ad1e56ce9147c5b7bf32c6f5825eeed19e))
* Bump the nuget-minor-and-patch group with 3 updates ([017c553](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/017c553779e4a4c3955372426426067618babe7d))
* **demo:** fresh random inputs every run; async-aware test runner ([610819b](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/610819b8029fd1c4823e6d8e4e17c90ed26664d6))
* **demo:** run Argon2 in the browser at p=1; lengthen intro; run-again status text ([dbc97aa](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/dbc97aa392d174e03bd83a390a9a8e0e86e24e0b))
* live NUnit test run in the demo; line-by-line output; metric + UX fixes ([a8052d8](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/a8052d8cef1c763fe00dd8b07cb0abdd93d0ff1a))
* ProtectedString and ProtectedBlob — encrypted in-memory secrets for .NET ([830ab1d](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/830ab1df224714eb7bebc73d729fdfa9cd5e0967))


### Bug Fixes

* **argon2:** fail fast on the browser instead of wedging inside the KDF ([20949e1](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/20949e169b5204960bc505186a6ddffeda4aca17))
* CI restore across TFMs, wasm demo run-again, larger demo blob ([597e5bd](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/597e5bd2d8c90b6f331e0ed84e21424ddbe07d61))
* **ci:** unhang the ubuntu leg — drive swtpm in linuxTrm raw mode ([077ad45](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/077ad45077588114d5fc3484b6342e9e964c0b2b))
* **demo:** Run again shows immediate status, no blank, no delay ([c004cae](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/c004caef268519752020a5f9dfa2449ea533e5a8))
* **deps:** Bump actions/checkout from 4 to 7 ([3cba776](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/3cba776116f61c0434a9d15b06638ed3403a0fe4))
* **deps:** Bump actions/checkout from 4 to 7 ([b426b48](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/b426b48a486d58d01720ebf781f13d7f6fffd0b9))
* **deps:** Bump actions/deploy-pages from 4 to 5 ([48a80c4](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/48a80c4755a97cefd50c1eb2fa1b4fe99e1d580d))
* **deps:** Bump actions/deploy-pages from 4 to 5 ([bede632](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/bede6328505cfcd46d0afc5f288e140cd48acf75))
* **deps:** Bump actions/setup-dotnet from 4 to 5 ([5916d5b](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/5916d5b213537cedb746180502a4909e3c0a76ce))
* **deps:** Bump actions/setup-dotnet from 4 to 5 ([a77452b](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/a77452bc37a7b77622dd61a03f38b105c9090db6))
* **deps:** Bump actions/upload-pages-artifact from 3 to 5 ([649baa3](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/649baa323c30d255a385a10f4fe9373f8229e4c1))
* **deps:** Bump actions/upload-pages-artifact from 3 to 5 ([a7f3a4c](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/a7f3a4cb7a65dc1b30f5a115081d68af16ce4fc4))
* **deps:** Bump dependabot/fetch-metadata from 2 to 3 ([4e01fd4](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/4e01fd47d975203c108c761596eac4035c7d743c))
* **deps:** Bump dependabot/fetch-metadata from 2 to 3 ([09bd445](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/09bd44536cac011a6642ee4f2914faf343024495))
* green CI, working Run-again, Pages registration, 0.1.0 bootstrap ([127e77d](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/127e77deabc8c860bada8f7cbaebf824add17261))
* revert stray Roslyn bump, scope Pages restore, harden dependabot ([a9e00a8](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/a9e00a8482fe3c9dfeb286af7755aab5620fbd52))


### Documentation

* badges in one flowing row, no forced line breaks ([0c8bf85](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/0c8bf8563e25df29d0c481e3c4170ec6676d34a4))
* HTML badge tags (deterministic render), drop blank lines in header ([8d86020](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/8d86020d029ee6ab2b034b9be18666a2ed85eb12))
* left-align the live-demo call-to-action, lengthen it ([fcc13e9](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/fcc13e957855a92334a0240f3a41466ecaf3f03c))
* MIT-only LICENSE for auto-detection; full-height demo terminal ([0324cc3](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/0324cc377dd226de30294bde919af8b6bca6f289))
* shared NuGet readme for all five packages; honest Argon2 browser status ([5be18af](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/5be18af9a4717fe8bf33e8551d1ac697e76f3e17))
* spacing below badges; demo(wasm): autoscroll xterm as output streams ([978b80f](https://github.com/Alpaq92/TopSecret.ProtectedString/commit/978b80feb9142065106234eb6ce492e3f9f8a8b4))

## Changelog

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
