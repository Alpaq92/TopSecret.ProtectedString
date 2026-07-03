; Unshipped analyzer release
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md
;
; ─────────────────────────────────────────────────────────────────────────
; Release-time runbook
; ─────────────────────────────────────────────────────────────────────────
; When cutting a NuGet release, every rule listed below must move into
; AnalyzerReleases.Shipped.md under a `## Release X.Y.Z` heading, and this
; file must be left empty (with the header preserved). Forgetting either
; step makes the next analyzer build fail with diagnostic RS2007 (or
; RS2008 for "rule changed without release").
;
; The release.yml workflow performs this move automatically before
; `dotnet pack` — see the `Promote analyzer rules to Shipped` step.
; That step is idempotent: a re-run on the same version shifts nothing
; if the rules are already in Shipped.md under the matching heading. If
; you are cutting a release manually (no workflow), run:
;
;   PWSH:
;     $unshipped = "TopSecret.ProtectedString.Analyzers/AnalyzerReleases.Unshipped.md"
;     $shipped   = "TopSecret.ProtectedString.Analyzers/AnalyzerReleases.Shipped.md"
;     # 1. Append "## Release vX.Y.Z" + the rules block to $shipped
;     # 2. Truncate $unshipped to just the header lines (lines starting with `;`)
;     # 3. Commit
;
; ─────────────────────────────────────────────────────────────────────────

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|--------
TPS001  | Security | Warning  | Plaintext copied into a managed string inside ProtectedString.Access
TPS002  | Security | Warning  | ProtectedString.Access plaintext array reference escapes the callback
