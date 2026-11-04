# TopSecret.ProtectedString

<div align="center">
<a href="https://www.nuget.org/packages/TopSecret.ProtectedString"><img alt="NuGet: TopSecret.ProtectedString" src="https://img.shields.io/nuget/v/TopSecret.ProtectedString.svg?label=TopSecret.ProtectedString"></a>
<a href="https://www.nuget.org/packages/TopSecret.ProtectedBlob"><img alt="NuGet: TopSecret.ProtectedBlob" src="https://img.shields.io/nuget/v/TopSecret.ProtectedBlob.svg?label=TopSecret.ProtectedBlob"></a>
<a href="https://github.com/Alpaq92/TopSecret.ProtectedString/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Alpaq92/TopSecret.ProtectedString/ci.yml?branch=master&label=CI"></a>
<a href="https://alpaq92.github.io/TopSecret.ProtectedString/"><img alt="Live demo" src="https://img.shields.io/badge/demo-GitHub%20Pages-2ea44f"></a>
<a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
</div>

A cross-platform .NET 10 replacement for `System.Security.SecureString`. Secrets are held AES-GCM-256-encrypted in process memory on every supported platform (Windows, Linux, macOS, Android, iOS, Mac Catalyst, browser WebAssembly) and exposed only briefly through span callbacks.

Packages: `TopSecret.ProtectedString` (credential-sized text secrets), `TopSecret.ProtectedBlob` (multi-MB byte blobs), and optional satellites for TPM key wrapping (`.WindowsTpm`, `.LinuxTpm`), configuration binding (`.Configuration`), JSON (`.Json`) and XML (`.Xml`) ingress. [Live demo](https://alpaq92.github.io/TopSecret.ProtectedString/).

## Install

```
dotnet add package TopSecret.ProtectedString
dotnet add package TopSecret.ProtectedBlob
```

## Usage

```csharp
using TopSecret;

using var ps = new ProtectedString("hunter2".AsSpan());   // or new ProtectedString(string), or build:
using var built = new ProtectedString();
foreach (var c in ReadPasswordChars()) built.AppendChar(c);
built.MakeReadOnly();

// Plaintext is a ReadOnlySpan<char> (ref struct): it cannot be captured, stored or awaited across.
ps.Access(plain =>
{
    Span<byte> utf8 = stackalloc byte[Encoding.UTF8.GetMaxByteCount(plain.Length)];
    int written = Encoding.UTF8.GetBytes(plain, utf8);
});
int length = ps.Access(plain => plain.Length);
ps.WriteUtf8To(stream);                    // UTF-8 straight to a sink, no managed string
Span<char> scratch = stackalloc char[ps.Length];
ps.CopyTo(scratch);

bool same = ps.Equals(other);              // constant time
byte[] salt = RandomNumberGenerator.GetBytes(16);
byte[] stored = ps.ComputeArgon2idHash(salt);   // Argon2id, OWASP defaults (t=3, m=19 MiB, p=1)
bool ok = attempt.VerifyArgon2idHash(stored, salt);
```

For APIs that demand a `SecureString` use `ps.ToSecureString()`. For APIs that demand a `string`, materialise it inside `Access` as late as possible and suppress the analyzer locally (see [Build-time analyzer](#build-time-analyzer)).

## ProtectedBlob (large secret blobs)

Write-once, byte-oriented container storing the plaintext as fixed-size AES-GCM-256 chunks (64 KiB default) in ordinary memory. Each blob has its own random DEK wrapped under the same process master protector as `ProtectedString`. Chunk AAD binds blob id, chunk index and a final flag, so reorder, truncation, transplant and bit flips fail the tag check.

```csharp
using var blob = new ProtectedBlob(modelWeights.AsSpan());
using var fromStream = ProtectedBlob.FromStream(httpUploadStream);
blob.AccessChunks(chunk => hasher.AppendData(chunk));
long magic = blob.AccessChunk(0, chunk => BinaryPrimitives.ReadInt64LittleEndian(chunk));
blob.CopyTo(buffer);
blob.WriteTo(destinationStream);
```

### ProtectedBlob API surface

| Member | Purpose |
| --- | --- |
| `ProtectedBlob(ReadOnlySpan<byte>)` / `ProtectedBlob(ReadOnlySpan<byte>, int chunkSize)` | Wrap a copy of the bytes, encrypted chunk by chunk from the span. |
| `ProtectedBlob(byte[], bool clearSource = false)` / `ProtectedBlob(byte[], bool, int chunkSize)` | Wrap a `byte[]`, optionally zeroing the source. |
| `ProtectedBlob(ReadOnlySequence<byte>)` / `ProtectedBlob(ReadOnlySequence<byte>, int chunkSize)` | Wrap a multi-segment `ReadOnlySequence<byte>` (`PipeReader` shape). |
| `static FromStream(Stream)` / `static FromStream(Stream, int chunkSize)` | Read a stream to its end; plaintext residency is at most two chunks; > 2 GiB supported. |
| `static FromStreamAsync(Stream, CancellationToken)` / `static FromStreamAsync(Stream, int chunkSize, CancellationToken)` | Asynchronous `FromStream`; a failed or cancelled ingest leaves nothing behind. |
| `Length` / `ChunkCount` / `ChunkSize` / `IsDisposed` | Inspection. `Length` is a `long`; an empty blob is one empty final chunk. |
| `AccessChunk(int, ReadOnlySpanAction<byte>)` / `AccessChunk<T>(int, ReadOnlySpanFunc<byte, T>)` | Decrypt one chunk into wiped scratch and hand it to the callback. The unwrapped key is wiped before the callback runs. |
| `AccessChunk<TState>(int, TState, ReadOnlySpanAction<byte, TState>)` | Same, with caller state so hot loops allocate no closure. |
| `AccessChunks(ReadOnlySpanAction<byte>)` | Sequential pass over every chunk; one master unwrap per pass. |
| `CopyTo(Span<byte>)` | Decrypt the whole blob into a caller-owned buffer; zeroes what it wrote on failure. Limited to 2 GiB by `Span<byte>`. |
| `CopyTo(long offset, Span<byte>)` | Ranged read of `destination.Length` bytes from `offset`. |
| `WriteTo(Stream)` | Stream the plaintext out through one reused chunk scratch. |
| `WriteToAsync(Stream, CancellationToken)` | Asynchronous `WriteTo`; the lock is held only to snapshot and unwrap, so a `Dispose` mid-pass fails closed. |
| `ToString()` | `ProtectedBlob[length=N]` / `ProtectedBlob[disposed]`. |
| `Dispose()` | Zero the key envelope and all ciphertext frames. |

Chunk size is bounded by `DefaultChunkSize` (64 KiB), `MinChunkSize` (4 KiB) and `MaxChunkSize` (1 MiB); `ProtectedBlobOptions.DefaultChunkSize` sets the process-wide default and is read at each construction. Blobs do not participate in process-key rotation. Wire format: `ciphertext ‖ 16-byte tag` per chunk, nonce = 8-byte random prefix ‖ 4-byte big-endian counter, chunk AAD `"TPB1" ‖ blob id (LE64) ‖ index (BE32) ‖ final flag`, envelope AAD `"TPBK" ‖ blob id`. Frozen by `WireFormatPinningTests`.

## API surface

| Member | Purpose |
| --- | --- |
| `ProtectedString()` | Empty instance, build with `AppendChar`. |
| `ProtectedString(string)` | Wrap a string. The string itself cannot be erased; prefer the span overload. |
| `ProtectedString(ReadOnlySpan<char>)` | Wrap a copy of the characters. |
| `ProtectedString(char[], bool clearSource = false)` | Wrap a `char[]`, optionally zeroing the source. |
| `Length` / `IsReadOnly` / `IsDisposed` | Inspection. |
| `AppendChar(char)` / `AppendChars(ReadOnlySpan<char>)` / `AppendUtf8(ReadOnlySpan<byte>)` | Append into a pinned, locked build buffer; committed to ciphertext by `MakeReadOnly()`. Plaintext stays in the build buffer until then. |
| `MakeReadOnly()` | Commit the build buffer and forbid further mutation. |
| `Access(ReadOnlySpanAction<char>)` / `Access<T>(ReadOnlySpanFunc<char, T>)` | Run a callback against the plaintext span. Recommended. |
| `Access(Action<char[]>)` / `Access<T>(Func<char[], T>)` | Obsolete `char[]` variants for APIs that need an array; the array is zeroed on return. |
| `CopyTo(Span<char> destination)` | Copy the plaintext into a caller-owned buffer; returns `Length`. |
| `WriteUtf8To(Stream destination)` / `WriteUtf8To(IBufferWriter<byte> destination)` | Encode as UTF-8 straight into the sink. |
| `Utf8Access(ReadOnlySpanAction<byte>)` / `Utf8Access<T>(ReadOnlySpanFunc<byte, T>)` | Callback over the plaintext as UTF-8 in wiped scratch. |
| `static FromUtf8(ReadOnlySpan<byte>)` | Read-only instance from UTF-8 bytes. |
| `static Build(Action<ProtectedString> fill)` | Append inside `fill`, then `MakeReadOnly`; disposes the half-built instance if `fill` throws. |
| `ToSecureString()` *(extension, `SecureStringInterop`)* | Single-copy bridge to a read-only `SecureString`. |
| `Copy()` | Independent writable copy. |
| `Equals(ProtectedString)` | Constant-time comparison; `Equals(object?)` defers to it. |
| `GetHashCode()` | Length only. |
| `ToString()` | `ProtectedString[length=N]` / `ProtectedString[disposed]`. |
| `ComputeArgon2idHash(salt, iterations, memoryKb, parallelism, hashLengthBytes)` | Argon2id over the plaintext; OWASP defaults. `parallelism > 1` throws on browser-wasm. |
| `VerifyArgon2idHash(expectedHash, salt, iterations, memoryKb, parallelism)` | Constant-time verify; `false` for a stored hash under 16 bytes. |
| `ComputeArgon2idHash(salt, Argon2idCalibration, hashLengthBytes)` / `VerifyArgon2idHash(expectedHash, salt, Argon2idCalibration)` | Same, with parameters from `Argon2Calibrator.Tune`. |
| `Dispose()` | Zero ciphertext, nonce, tag and any build buffer. |
| `static HardwareBackedAvailability` | Whether a hardware-backed protector is available on this host. |
| `static RotateProcessKey()` | Re-encrypt every live instance under a fresh master. Requires `ProcessKeyRotationPolicy != Disabled`. |
| `static TryRotateProcessKey()` | As above, returning `false` when dropped because a rotation was already in flight. |

`Argon2Calibrator.Tune(TimeSpan target)` benchmarks the host and returns an `Argon2idCalibration` (`Iterations`, `MemoryKb`, `Parallelism`, `Measured`) that never drops below the OWASP floors. Run it once at deploy time, not on a hot path.

## Security model

### Threat model

Best-effort defence against accidental memory disclosure: heap dumps, swap, crash reports, scraping. Not a defence against code already running in the process or anything with `PROCESS_VM_READ` / `ptrace` access.

### What this library does

- AES-GCM-256 with a random 12-byte nonce per encryption and the per-instance id as AAD; swapped state fails the tag check.
- Pinned (POH) storage for key and encrypted state; plaintext scratch from a page-aligned pool that is locked and dump-excluded once and never unlocked.
- `CryptographicOperations.ZeroMemory` wipes on every exit path.
- `VirtualLock` / `mlock` on every plaintext- and key-bearing buffer; `WerRegisterExcludedMemoryBlock` on Windows and `madvise(MADV_DONTDUMP)` on Linux/Android; `MADV_WIPEONFORK` on the scratch slabs.
- Tiered wrapping of the process master key (below), constant-time comparison, a logging-safe `ToString()`, a finalizer, and a Roslyn analyzer (TPS001–TPS003).

### What this library does **not** do (and why)

- Protect against an attacker reading the live process. The unwrapped 32-byte master must exist in memory for every AES-GCM operation, and for the whole `UnwrappedKeyCacheTtl` window when caching is on.
- Protect a secret once you have turned it into a `string`. `new string(plain)` inside `Access` ends the protection; the analyzer flags it.

### Key-at-rest wrapping (opt-in, tiered)

`ProtectedStringOptions.KeyAtRestProtection` controls how the master key is held at rest. All `ProtectedStringOptions` are read once at the first construction; set them in your composition root.

| Value | What happens | Per-op cost |
| --- | --- | --- |
| `None` | Master sits plaintext in pinned, locked, dump-excluded memory. | None |
| `Obscurity` *(default)* | AES-GCM-256 wrap under a per-protector random key on every platform (HKDF stream-XOR only if AES-GCM construction declines). Both buffers are in the process heap. | ~µs |
| `GuardedPage` | Master lives on a dedicated no-access page (`PAGE_NOACCESS` / `PROT_NONE`) except during an unwrap, so a passive scan faults. Falls back to `Obscurity` on browser-wasm. | Page-protect pair per unwrap |
| `HardwareBackedRequired` | Hardware-resident wrap key only; throws `PlatformNotSupportedException` at first construction when none is available, ignoring `MemoryLockingFailureBehavior`. | ~ms |
| `HardwareBackedPreferred` | Hardware, then obscurity, then none, silently. | Whatever the active tier costs |

| Platform | Hardware tier | Obscurity tier |
| --- | --- | --- |
| macOS / iOS / Mac Catalyst | Apple Secure Enclave, EC P-256 + ECIES-AES-GCM (built in; Apple Silicon, T1/T2 Macs). | AES-GCM-256 wrap |
| Android (API 23+) | `AndroidKeyStore` AES-GCM-256 in the TEE, hardware residency verified at key generation (built in on `net10.0-android`). | AES-GCM-256 wrap |
| Windows | TPM 2.0 via NCrypt / Platform Crypto Provider, RSA-2048 OAEP (`TopSecret.ProtectedString.WindowsTpm`). | AES-GCM-256 wrap |
| Linux | TPM 2.0 via TSS.MSR against `/dev/tpmrm0`, RSA-2048 OAEP (`TopSecret.ProtectedString.LinuxTpm`). | AES-GCM-256 wrap |
| Browser WebAssembly | none | AES-GCM-256 wrap via the BouncyCastle shim |

The TPM packages register through a `[ModuleInitializer]`; call `WindowsTpmRegistration.Register()` / `LinuxTpmRegistration.Register()` explicitly under trimming or lazy assembly loading. `ProtectedStringOptions.UnwrappedKeyCacheTtl` (default off, capped at `MaxTimerDuration`, about 49.7 days) caches the unwrapped master to amortise hardware round-trips at the cost of a longer in-memory window. Hardware tiers narrow the window in which the master is readable; they do not remove it.

### Diagnostics

One-shot `Trace.TraceWarning` calls, visible only with a `TraceListener` attached: no hardware-backed provider registered under `HardwareBacked*`; a read-once option mutated after first construction; `Periodic` rotation with a transient-slot-constrained TPM provider; a memory-locking failure under `LogWarning`; and, per call, a partial rotation failure.

### Build-time analyzer

Shipped inside the NuGet at `analyzers/dotnet/cs/`.

| ID | Severity | Triggers on |
| --- | --- | --- |
| **TPS001** | Warning | Plaintext copied into a `string` inside an `Access` callback: `new string(plain)`, `ToString()`, `string.Concat` / `Create`, `Encoding.GetString`, interpolation, `StringBuilder.Append`, `Convert.ToBase64String` / `ToHexString`, including through `AsSpan` / `Slice` / range views. |
| **TPS002** | Warning | The `char[]` parameter of the array overloads assigned to a captured local, field, property or array slot, stored in a collection, or returned from the callback. |
| **TPS003** | Warning | `plain.ToArray()`, an array-returning `Encoding.GetBytes(plain)`, or range-indexing the `char[]` parameter. |

```csharp
#pragma warning disable TPS001 // external API requires a string
ps.Access(plain => client.Authenticate(new string(plain)));
#pragma warning restore TPS001
```

### Process-key rotation (opt-in)

```csharp
ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.Periodic;
ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.FromHours(1);
ProtectedString.RotateProcessKey();   // or on demand; TryRotateProcessKey() reports a dropped call
```

| Policy | Behavior |
| --- | --- |
| `Disabled` *(default)* | No registry; `RotateProcessKey()` throws. |
| `OnDemand` | Registry maintained; rotate by calling `RotateProcessKey()`. |
| `Periodic` | `OnDemand` plus a timer firing every `ProcessKeyRotationInterval`. |

Rotation generates a fresh master, swaps it in, then re-encrypts each registered instance under its own lock. Concurrent rotations are deduplicated. Instances created while the policy was `Disabled` are never migrated. Rotation bounds historical exposure only.

### Memory-locking policy

`ProtectedStringOptions.MemoryLockingFailureBehavior` decides what happens when `VirtualLock` / `mlock` or dump exclusion fails:

| Value | What it does |
| --- | --- |
| `LogWarning` *(default)* | One `Trace.TraceWarning` per process, then proceed unlocked. |
| `Throw` | `PlatformNotSupportedException` from the operation that needed the lock. |
| `Ignore` | Proceed silently. |

Unprivileged Linux processes default to about 64 KiB of `RLIMIT_MEMLOCK`; the pooled scratch slabs are 16 KiB each. Encrypted state (ciphertext, nonce, tag) is pinned but never locked.

## Configuration binding from `appsettings.json`

```
dotnet add package TopSecret.ProtectedString.Configuration
```

```csharp
configuration.BindProtectedStringOptions();                                 // reads TopSecret:ProtectedString
configuration.GetSection("Crypto:Options").BindProtectedStringOptions();    // explicit section
```

Skip on missing, warn and skip on malformed: undefined enum names, integer strings and comma lists are rejected, `TimeSpan`s parse with the invariant culture, and a non-positive `ProcessKeyRotationInterval` is refused. Without the package, bind manually with `Enum.TryParse` against `ProtectedStringOptions.*`.

| Key | When a new value takes effect |
| --- | --- |
| `ProcessKeyRotationPolicy` | Next construction. |
| `MemoryLockingFailureBehavior` | Next locking failure. |
| `KeyAtRestProtection` / `UnwrappedKeyCacheTtl` | Never on a live process; use `RotateProcessKey()` to swap protectors. |
| `ProcessKeyRotationInterval` | Never once the timer has started. Setter rejects negatives and values above `MaxTimerDuration`. |

## Binding a secret from JSON

```csharp
public sealed record Login
{
    public string User { get; init; } = "";
    [JsonConverter(typeof(ProtectedStringJsonConverter))]
    public ProtectedString? Password { get; init; }
}
```

`TopSecret.ProtectedString.Json` unescapes the token into wiped scratch; no managed `string` exists. Deserialization only (`Write` throws). Tokens above `DefaultMaxUtf8Bytes` (1 MiB) are rejected before allocation; raise it with `new ProtectedStringJsonConverter(maxUtf8Bytes)`.

## Binding a secret from XML

```csharp
using var password = ProtectedStringXml.FromXml(configStream, "Password");              // XXE-safe reader settings
using var token = ProtectedStringXml.FromXml(configStream, "ApiToken", maxLength: 8192);
using var fromReader = ProtectedStringXml.ReadElementContent(myReader);                // you own the reader's settings
```

`TopSecret.ProtectedString.Xml` streams element content through `ReadValueChunk` into wiped scratch. Content above `DefaultMaxLength` (1 Mi chars) throws `XmlException`; input ending before the end tag fails closed. Read only.

## Build & test

```
dotnet build
dotnet test
```

SDK floor is 10.0.300 (`global.json`, `rollForward: latestFeature`) because the analyzer references `Microsoft.CodeAnalysis.CSharp` 5.6.0. The full solution builds all six TFMs and needs the `android ios macos maccatalyst wasm-tools` workloads; build a test project directly for `net10.0` only. CI runs on ubuntu, windows and macos-14 (Linux TPM tests against `swtpm`; the concurrency stress fixture is repeated on the macOS leg). Releases are cut by release-please from Conventional Commits and published from `release.yml`, which packs all seven packages on macos-14. Every public member of `ProtectedString` and `ProtectedBlob` must appear in the API tables above (drift tests).

Maintainer notes:

- `Microsoft.CodeAnalysis.*` is pinned at 5.6.0; bumping it means a matching `global.json` floor bump and a major release. Dependabot ignores minor/major bumps for it.
- `github/codeql-action/init` and `analyze` must share one SHA; Dependabot groups them.
- Analyzer rules move from `AnalyzerReleases.Unshipped.md` to `Shipped.md` by hand in the release PR.
- `coverlet.msbuild` needs a rebuild; keep the coverage step last on the Linux leg.

## License

[MIT](LICENSE). Third-party material is catalogued in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
