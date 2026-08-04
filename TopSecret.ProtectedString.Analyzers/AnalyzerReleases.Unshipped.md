; Unshipped analyzer release
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md
;
; ─────────────────────────────────────────────────────────────────────────
; Release-time runbook
; ─────────────────────────────────────────────────────────────────────────
; What actually fails the build is an implemented rule that is *listed
; nowhere*: RS2007 ("missing or invalid entry") fires when a DiagnosticId
; the analyzer reports has no row in either tracking file, and RS2008 when
; a shipped rule's severity/category changes without a new release entry.
; Rules sitting in *this* file are fully valid for the build and may stay
; here indefinitely — TPS001-TPS003 have shipped in released NuGets from
; here, and nothing broke.
;
; Promoting them into AnalyzerReleases.Shipped.md under a `## Release X.Y.Z`
; heading is therefore a deliberate maintainer choice, not a hard gate. No
; workflow does it for you: release.yml has no promotion step, so a release
; that should record its rules as shipped needs this done by hand and
; folded into the release PR before it merges. Promote under the version
; that first shipped each rule — do not sweep long-standing rules under
; whatever version happens to be cutting now, since that misdates them.
;
; To promote by hand:
;     $unshipped = "TopSecret.ProtectedString.Analyzers/AnalyzerReleases.Unshipped.md"
;     $shipped   = "TopSecret.ProtectedString.Analyzers/AnalyzerReleases.Shipped.md"
;     # 1. Append "## Release X.Y.Z" + a `### New Rules` block with the rows
;     #    that first shipped in X.Y.Z to $shipped
;     # 2. Remove those rows from $unshipped, preserving the `;` header and
;     #    the `### New Rules` table header
;     # 3. Commit
;
; ─────────────────────────────────────────────────────────────────────────

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|--------
TPS001  | Security | Warning  | Plaintext copied into a managed string inside ProtectedString.Access
TPS002  | Security | Warning  | ProtectedString.Access plaintext array reference escapes the callback
TPS003  | Security | Warning  | Plaintext copied into a new array inside ProtectedString.Access
