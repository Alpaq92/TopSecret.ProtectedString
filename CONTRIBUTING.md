# Contributing

## Prerequisites

- .NET SDK 10.0.300 or newer (`global.json`, `rollForward: latestFeature`). Do not bump `Microsoft.CodeAnalysis.*`; see the README maintainer notes.
- Workloads `android ios macos maccatalyst wasm-tools` for a solution-wide build; a single test project builds `net10.0` only.

## Build and test

```bash
dotnet test TopSecret.ProtectedString.Tests/TopSecret.ProtectedString.Tests.csproj
dotnet test TopSecret.ProtectedBlob.Tests/TopSecret.ProtectedBlob.Tests.csproj
dotnet run --project TopSecret.Demo
```

## Rules

1. Warnings are errors everywhere, including nullable and AOT/trim analyzers.
2. The ProtectedBlob wire format is frozen by `WireFormatPinningTests`; changing it is a major-version break with a new magic.
3. Internal members consumed across assemblies (`ProtectedBlob`, TPM packages) keep TFM-invariant signatures; put `#if` inside bodies. `.Json` and `.Xml` take no `InternalsVisibleTo`.
4. README API tables are drift-guarded: add the row for every new public member of `ProtectedString` or `ProtectedBlob` in the same PR, and keep every public enum value in its section.
5. Transient plaintext and key scratch rent from `LockedScratchPool` and are returned in a `finally`; arrays handed to external code use `AllocatePinnedBytes` and `ZeroBytes`; encrypted state uses `AllocatePinnedEncryptedState` and `ZeroOnly`. Every plaintext copy is wiped on every exit path.
6. New analyzer rules go into `AnalyzerReleases.Unshipped.md` with positive and negative tests.
7. The Linux CI leg enforces 65% line coverage for `TopSecret.ProtectedString` and `TopSecret.ProtectedBlob`.
8. Documentation must not overclaim; document residual weaknesses.

## Commits and releases

Conventional Commits drive release-please: `feat:` minor, `fix:` patch, `feat!:` or `BREAKING CHANGE:` major, `test:` / `chore:` no release. The PR title becomes the squash commit subject. `CHANGELOG.md` is generated; do not hand-edit it. The release PR needs a manual merge.

## Security issues

Use GitHub private vulnerability reporting, not public issues. See [SECURITY.md](SECURITY.md).
