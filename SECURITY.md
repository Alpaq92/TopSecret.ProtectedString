# Security Policy

## Supported versions

Only the latest published version of each package (currently `2.x`) receives
security fixes. There is no LTS branch — given the release cadence, upgrading
is expected to be the fix.

## Reporting a vulnerability

Please **do not open a public GitHub issue** for a suspected vulnerability —
in the memory-protection guarantees (secrets recoverable from a memory or
core dump, a key-wrapping tier not doing what it claims, a timing
side-channel in a comparison, a wipe that doesn't happen on some exit path)
or in the supply chain (a CI/release workflow that could be tricked into
running untrusted code or exfiltrating secrets).

Instead, use GitHub's private vulnerability reporting for this repository:
[Report a vulnerability](https://github.com/Alpaq92/TopSecret.ProtectedString/security/advisories/new).

Include, where you can:

- The affected package(s) and version.
- A description of the weakness and, if possible, a minimal repro.
- The platform/TFM it applies to, if platform-specific — this library's
  security guarantees differ by key-at-rest tier; see the README's
  [Security model](README.md#security-model) section.

## Response

This is a solo-maintained project with no formal SLA. Reports are triaged
and acknowledged as soon as reasonably possible, and a confirmed
vulnerability is prioritized over new feature work.

## Scope

**In scope:** the packages in this repository (`TopSecret.ProtectedString`,
`TopSecret.ProtectedBlob`, the TPM/Configuration/Json/Xml satellites, and the
Roslyn analyzer) and the GitHub Actions workflows that build, test, and
release them.

**Out of scope:** the demo apps (`TopSecret.Demo`, `TopSecret.Demo.Wasm`)
except where a demo bug points at a real library issue, and anything already
documented as a known, deliberate limitation in the README's
["What this library does **not** do"](README.md#what-this-library-does-not-do-and-why)
section — those are accepted trade-offs, not vulnerabilities, unless you can
show the trade-off is worse in practice than documented.
