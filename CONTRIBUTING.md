# Contributing to TopSecret.ProtectedString

Thanks for your interest! This document covers what you need to build, test, and land a change. For the security model and API rationale, read the [README](README.md) first — most "why is it like this?" questions are answered there, and design honesty is a core value of this project.

## Prerequisites

- **.NET SDK 10.0.300 or newer** — enforced by `global.json` (`rollForward: latestFeature`). The floor exists because the Roslyn analyzer references `Microsoft.CodeAnalysis.CSharp` 5.6.0, which needs a matching compiler — that ships in SDK 10.0.300+. **Do not bump the Roslyn package** without reading the maintainer notes in the README — it is consumer-breaking and Dependabot is configured to leave it alone.
- Building the platform TFMs (`net10.0-android/-ios/-macos/-maccatalyst/-browser`) additionally requires workloads: `dotnet workload restore` (or `install android ios macos maccatalyst wasm-tools`). Day-to-day development only needs plain `net10.0` — build individual projects rather than the solution if you don't have the workloads.

## Build, test, run

```bash
dotnet build TopSecret.ProtectedString.Tests/TopSecret.ProtectedString.Tests.csproj   # core + analyzer, net10.0 only
dotnet test  TopSecret.ProtectedString.Tests/TopSecret.ProtectedString.Tests.csproj
dotnet test  TopSecret.ProtectedBlob.Tests/TopSecret.ProtectedBlob.Tests.csproj
dotnet run --project TopSecret.Demo                                                   # end-to-end demo, console
dotnet publish TopSecret.Demo.Wasm/TopSecret.Demo.Wasm.csproj -c Release              # browser demo (needs wasm-tools)
```

A solution-wide build attempts every TFM and needs all workloads; CI builds leaf projects individually for exactly that reason (see the comment in `.github/workflows/ci.yml`).

## Project map

| Project | What it is |
| --- | --- |
| `TopSecret.ProtectedString` | Core library (multi-TFM). |
| `TopSecret.ProtectedBlob` | Large-blob sibling package (net10.0; consumes core internals via `InternalsVisibleTo`). |
| `TopSecret.ProtectedString.Analyzers` | Roslyn analyzer (TPS001/TPS002), packed inside both library NuGets. |
| `TopSecret.ProtectedString.{WindowsTpm,LinuxTpm}` | Optional TPM 2.0 key-wrap providers. |
| `TopSecret.ProtectedString.Configuration` | Optional `IConfiguration` binder. |
| `*.Tests` | NUnit 4 suites, one per package. |
| `TopSecret.Demo` / `TopSecret.Demo.Wasm` | Console demo and its xterm.js browser host (deployed to GitHub Pages per release). |

## Rules that will fail your build or review

1. **Warnings are errors** everywhere (`TreatWarningsAsErrors`), including nullable and AOT/trim analyzers.
2. **The ProtectedBlob wire format is frozen.** `WireFormatPinningTests` pins the chunk nonce/AAD layouts byte-for-byte. If it fails, you changed the format — that is a breaking change requiring a new magic (`"TPB2"`) and a major version, not an edit to the test.
3. **Internal members consumed across assemblies keep TFM-invariant signatures.** `TopSecret.ProtectedBlob` and the TPM packages consume core internals (`AesGcmShim`, `MemoryLocker`, `MemoryProtection`, `DumpExclusion`, `LockedScratchPool`, `AllocatePinnedBytes`/`AllocatePinnedEncryptedState`, `ZeroBytes`/`ZeroOnly`, `ProtectorLifetime`, …) via `InternalsVisibleTo`. Put `#if` inside method bodies, never on the declarations of such members. Satellites that only need public surface (e.g. `TopSecret.ProtectedString.Json`, which stages through `ArrayPool` + `FromUtf8`) take **no** `InternalsVisibleTo` — keep it that way.
4. **README API tables are drift-guarded.** Tests assert every public member of `ProtectedString` (README `## API surface`) and `ProtectedBlob` (`### ProtectedBlob API surface`) is mentioned in its section, and that all public enum values appear in their sections. Add the doc row in the same PR as the member.
5. **Security-sensitive buffer discipline**: in the core and its internals-consuming assemblies, transient plaintext and key scratch rents from `LockedScratchPool` and is returned via `Lease.Return()` in a `finally` (Return wipes); buffers that must be real arrays handed to external code use `ProtectedString.AllocatePinnedBytes` (pinned + locked + dump-excluded via the `excludeFromDumps` flag) and are wiped via `ProtectedString.ZeroBytes` in a `finally`; encrypted state (ciphertext / nonce / tag) uses `AllocatePinnedEncryptedState` / `ZeroOnly` and is deliberately never locked. **Pure-public satellites** (no `InternalsVisibleTo`, per rule 3) cannot reach locked scratch, so they stage through `ArrayPool<byte>` wiped with `CryptographicOperations.ZeroMemory` in a `finally` — acceptable only where the source is already unlocked (e.g. the JSON converter's already-in-memory document). The invariant is unchanged across both: every plaintext copy is wiped on *every* exit path, including exceptions. Reviews treat a missing wipe — or a pooled slab array handed to caller-supplied code — as a bug, not a nit.
6. **Analyzer rules**: new diagnostics go into `AnalyzerReleases.Unshipped.md` (the release workflow promotes them). Never hand-edit `AnalyzerReleases.Shipped.md`. Every rule needs positive and negative cases in `TopSecret.ProtectedString.Analyzers.Tests`.
7. **Coverage gates**: the Linux CI leg enforces 65% line coverage separately for `TopSecret.ProtectedString` and `TopSecret.ProtectedBlob`. Never lower a floor without a documented reason.
8. **Threat-model honesty**: documentation must not overclaim. If your feature has a residual weakness, document it (see the README's "What this library does not do" section for the house style).

## CI and releases (what your PR triggers)

- `ci.yml` — every push/PR: build + full test matrix on ubuntu/windows/macos-14 (Linux TPM tests run against a `swtpm` simulator), AOT publish dry-run, coverage gates.
- `build-platform-tfms.yml` — manual: compile checks for iOS/Android/browser TFMs and the wasm demo host. Run it if you touched `AesGcmShim`, TFM-conditional code, or the `DemoApp`/wasm interop surface.
- `release.yml` — on every push to master, [release-please](https://github.com/googleapis/release-please) maintains a Release PR from your commit messages; when it merges (it auto-merges once checks pass), the tag + GitHub Release are created and the publish job packs all six NuGets on macos-14, pushes to NuGet.org, attaches them to the release, and redeploys the live demo.
- `pages.yml` — deploys the browser demo to GitHub Pages (dispatched by the publish job; also manually runnable).

## Before a major or security-relevant release: a manual device check

No CI runner exists for real iOS/Android hardware (see [CI matrix and runner availability](README.md#ci-matrix-and-runner-availability) and the README's [mobile support](README.md#mobile-support-net100-ios--net100-android) caveats) — the cross-platform suite runs on desktop CoreCLR only, so Mono-specific behavior (POH pinning semantics, `ZeroMemory` JIT-resistance, finalizer ordering) and real Secure Enclave / Android Keystore round-trips are inferred, not observed. Setting up device-farm CI (AWS Device Farm, Firebase Test Lab, BrowserStack App Automate) for this is real ongoing cost for a project with no confirmed mobile-production consumer yet, so instead: **before tagging a major or security-relevant release**, run this one-off manual check on a borrowed or owned device (cheap, doesn't scale, but catches gross breakage):

1. Build and run `TopSecret.Demo` (or a minimal test host) targeting `net10.0-ios` / `net10.0-android` and deploy to a real device — not just the simulator/emulator, which typically report `HardwareBackedAvailability.NoProviderForThisPlatform` regardless of what real hardware would say.
2. Confirm `ProtectedString.HardwareBackedAvailability` reports the expected tier (Secure Enclave on a real iPhone, Android Keystore on a real Android device) and that a construct → `Access` → dispose round-trip through that tier succeeds.
3. Run `ComputeArgon2idHash` / `VerifyArgon2idHash` on-device — the underlying KDF (`TopSecret.Cryptography.Argon2`) still touches the thread pool for lanes beyond the first, and mobile OS thread-pool scheduling can differ from desktop.
4. Watch for crashes or wrong output around `AppendChar` build-mode buffers, `Access` callbacks, and `ToString()` — this can't verify wipe *timing* precisely without device-level memory tooling, but it does catch a Mono-specific regression before a user does.
5. File a GitHub issue for anything observed, even if it doesn't block the release — the point is to keep this a *tracked* coverage gap, not a silent one.

This is deliberately lightweight, not a substitute for device-farm CI — if you're shipping this library to mobile in production yourself, still run the fuller device-farm check described in the README before relying on its in-process secrecy claims there.

## Commit messages (they drive releases)

Use **[Conventional Commits](https://www.conventionalcommits.org/)** — release-please derives the version and the changelog from them:

- `feat: …` → minor bump, appears under **Features**
- `fix: …` → patch bump, **Bug Fixes**
- `deps: …` → **Dependencies** (Dependabot uses this prefix automatically)
- `docs:` / `refactor:` / `perf:` → respective sections, patch-level
- `feat!: …` or a `BREAKING CHANGE:` footer → major bump
- `test:` / `chore:` → no release impact

A non-conventional subject line won't break anything, but it also won't appear in the changelog or trigger a release — assume your PR title becomes the squash commit subject and write it accordingly.

## Changelog

`CHANGELOG.md` is generated by release-please — do not hand-edit released sections; write good Conventional Commit messages instead. Correct a wrong entry with a follow-up commit.

## Reporting security issues

Please do not open public issues for suspected vulnerabilities in the memory-protection guarantees — use GitHub's private vulnerability reporting on this repository instead.
