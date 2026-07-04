# TopSecret.ProtectedString

<div align="center">
<a href="https://www.nuget.org/packages/TopSecret.ProtectedString"><img alt="NuGet: TopSecret.ProtectedString" src="https://img.shields.io/nuget/v/TopSecret.ProtectedString.svg?label=TopSecret.ProtectedString"></a>
<a href="https://www.nuget.org/packages/TopSecret.ProtectedString.WindowsTpm"><img alt="NuGet: .WindowsTpm" src="https://img.shields.io/nuget/v/TopSecret.ProtectedString.WindowsTpm.svg?label=.WindowsTpm"></a>
<a href="https://www.nuget.org/packages/TopSecret.ProtectedString.LinuxTpm"><img alt="NuGet: .LinuxTpm" src="https://img.shields.io/nuget/v/TopSecret.ProtectedString.LinuxTpm.svg?label=.LinuxTpm"></a>
<a href="https://www.nuget.org/packages/TopSecret.ProtectedString.Configuration"><img alt="NuGet: .Configuration" src="https://img.shields.io/nuget/v/TopSecret.ProtectedString.Configuration.svg?label=.Configuration"></a>
<a href="https://www.nuget.org/packages/TopSecret.ProtectedBlob"><img alt="NuGet: TopSecret.ProtectedBlob" src="https://img.shields.io/nuget/v/TopSecret.ProtectedBlob.svg?label=TopSecret.ProtectedBlob"></a>
<a href="https://github.com/Alpaq92/TopSecret.ProtectedString/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Alpaq92/TopSecret.ProtectedString/ci.yml?branch=master&label=CI"></a>
<a href="https://github.com/Alpaq92/TopSecret.ProtectedString/actions/workflows/release.yml"><img alt="Release" src="https://img.shields.io/github/actions/workflow/status/Alpaq92/TopSecret.ProtectedString/release.yml?branch=master&label=Release"></a>
<a href="https://alpaq92.github.io/TopSecret.ProtectedString/"><img alt="Live demo" src="https://img.shields.io/badge/demo-GitHub%20Pages-2ea44f"></a>
<a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
</div>

<br>

**▶ [Try the live demo in your browser](https://alpaq92.github.io/TopSecret.ProtectedString/)** — the full scenario walkthrough plus a live NUnit run, all executing on the actual library, entirely client-side on .NET WebAssembly with no server involved.

A cross-platform, .NET 10 alternative to `System.Security.SecureString` that actually encrypts its contents at rest in live process memory, using authenticated AES-GCM-256 encryption, on every single supported platform — Windows, Linux, macOS, Android, iOS, Mac Catalyst, and browser WebAssembly.

> Microsoft now [recommends against using `SecureString` for new code](https://learn.microsoft.com/dotnet/api/system.security.securestring#remarks), partly because on non-Windows platforms it does not encrypt the buffer at all. This library is meant to fill that gap with the same usage shape developers already know. See [Replacing `SecureString`](#replacing-securestring) for the side-by-side and the migration mapping.

Two front-line packages ship from this repo and cover the two ends of the spectrum: **`TopSecret.ProtectedString`** for credential-sized secrets like passwords and tokens, and **[`TopSecret.ProtectedBlob`](#protectedblob-large-secret-blobs)** for multi-MB secret byte blobs — plus optional satellite packages for [TPM-backed key wrapping](#key-at-rest-wrapping-opt-in-tiered) and [configuration binding](#configuration-binding-from-appsettingsjson).

## Table of contents

- [Install](#install)
- [Usage](#usage)
  - [Construct](#construct)
  - [Use briefly](#use-briefly)
  - [Compare and verify credentials](#compare-and-verify-credentials)
  - [Interop with string-only APIs](#interop-with-string-only-apis)
- [ProtectedBlob (large secret blobs)](#protectedblob-large-secret-blobs)
  - [ProtectedBlob usage](#protectedblob-usage)
  - [ProtectedBlob API surface](#protectedblob-api-surface)
  - [Wire format](#wire-format)
  - [Performance shape](#performance-shape)
  - [ProtectedBlob security notes](#protectedblob-security-notes)
- [Demo](#demo)
- [API surface](#api-surface)
- [Replacing `SecureString`](#replacing-securestring)
  - [At a glance](#at-a-glance)
  - [On Windows](#on-windows)
  - [Migration mapping](#migration-mapping)
- [Compared to `GuardedString`](#compared-to-guardedstring)
  - [At a glance](#at-a-glance-1)
  - [Where the gap matters](#where-the-gap-matters)
  - [Where they overlap](#where-they-overlap)
  - [The one place `GuardedString` is more featureful](#the-one-place-guardedstring-is-more-featureful)
- [Security model](#security-model)
  - [Threat model](#threat-model)
  - [What this library does](#what-this-library-does)
  - [What this library does **not** do (and why)](#what-this-library-does-not-do-and-why)
  - [Key-at-rest wrapping (opt-in, tiered)](#key-at-rest-wrapping-opt-in-tiered)
  - [Diagnostics](#diagnostics)
  - [Build-time analyzer (TPS001 / TPS002)](#build-time-analyzer-tps001--tps002)
  - [Process-key rotation (opt-in)](#process-key-rotation-opt-in)
  - [Memory-locking policy](#memory-locking-policy)
- [Performance](#performance)
  - [Default tier (no hardware-backed wrap)](#default-tier-no-hardware-backed-wrap)
  - [Hardware-backed tier](#hardware-backed-tier)
  - [Argon2id (credential KDF)](#argon2id-credential-kdf)
  - [Memory footprint](#memory-footprint)
- [Build & test](#build--test)
  - [CI matrix and runner availability](#ci-matrix-and-runner-availability)
  - [Release & publishing flow](#release--publishing-flow)
  - [Mobile support (`net10.0-ios` / `net10.0-android`)](#mobile-support-net100-ios--net100-android)
  - [`browser-wasm` support](#browser-wasm-support)
- [Configuration binding from `appsettings.json`](#configuration-binding-from-appsettingsjson)
  - [Option 1 — the companion package (one line, recommended)](#option-1--the-companion-package-one-line-recommended)
  - [Option 2 — manual binding (zero extra dependency)](#option-2--manual-binding-zero-extra-dependency)
  - [Hot-reload semantics](#hot-reload-semantics)
  - [Why static, not `IOptions<T>`?](#why-static-not-ioptionst)
- [FAQ](#faq)
- [Development](#development)
  - [Maintainer notes — version pins worth knowing](#maintainer-notes--version-pins-worth-knowing)
- [Inspiration](#inspiration)
- [References](#references)
  - [`SecureString` deprecation context](#securestring-deprecation-context)
  - [Pinned memory, secret zeroing, and POH allocation](#pinned-memory-secret-zeroing-and-poh-allocation)
  - [AES-GCM, its strengths, and its sharp edges](#aes-gcm-its-strengths-and-its-sharp-edges)
  - [Password hashing (Argon2id)](#password-hashing-argon2id)
- [Repository layout](#repository-layout)
- [Icon](#icon)
- [License](#license)

## Install

```
dotnet add package TopSecret.ProtectedString   # credentials — the SecureString replacement
dotnet add package TopSecret.ProtectedBlob     # multi-MB secret byte blobs
```

`TopSecret.ProtectedString` pulls in [`Konscious.Security.Cryptography.Argon2`](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2) as a transitive dependency for credential verification. The optional satellite packages — [TPM-backed key wrapping](#key-at-rest-wrapping-opt-in-tiered) for Windows / Linux and the [`appsettings.json` binder](#configuration-binding-from-appsettingsjson) — are covered in their own sections.

## Usage

```csharp
using TopSecret;
```

### Construct

```csharp
// Wrap an existing string (see caveat in API surface below).
using var ps = new ProtectedString("hunter2");

// Or wrap a span — preferred, no string copy lingers in the GC heap.
using var fromSpan = new ProtectedString("hunter2".AsSpan());

// Or build one character at a time, e.g. while reading a console password.
using var built = new ProtectedString();
foreach (var c in ReadPasswordChars()) built.AppendChar(c);
built.MakeReadOnly();
```

### Use briefly

```csharp
// The plaintext is exposed as ReadOnlySpan<char> — a ref struct. The C#
// compiler refuses to let the span be captured by a closure, stored in a
// field, returned from the lambda, or crossed by an `await`, which closes
// the most common accidental-leak patterns. The underlying buffer is
// wiped on return.
ps.Access(plain =>
{
    Span<byte> utf8 = stackalloc byte[Encoding.UTF8.GetMaxByteCount(plain.Length)];
    int written = Encoding.UTF8.GetBytes(plain, utf8);
    // ... use utf8[..written] for HMAC, signature, network write, etc.
});

// Or get a value back from the callback:
int length = ps.Access(plain => plain.Length);

// Or stream the plaintext as UTF-8 directly into a sink — the bytes never
// touch a managed string.
using var ms = new MemoryStream();
ps.WriteUtf8To(ms);

// Or copy into a stackalloc buffer for further processing.
Span<char> scratch = stackalloc char[ps.Length];
ps.CopyTo(scratch);
```

### Compare and verify credentials

```csharp
// Constant-time plaintext comparison.
using var other = new ProtectedString("hunter2");
bool same = ps.Equals(other);

// Argon2id with OWASP-aligned defaults. Generate a fresh salt per credential
// and store it alongside the hash.
byte[] salt   = RandomNumberGenerator.GetBytes(16);
byte[] stored = ps.ComputeArgon2idHash(salt);   // t=3, m=19 MiB, p=1, 32-byte output

// ... later, on a login attempt:
using var attempt = new ProtectedString(submittedPassword);
bool ok = attempt.VerifyArgon2idHash(stored, salt);
// Not on browser-wasm: Argon2id throws PlatformNotSupportedException there —
// hash server-side (see the browser-wasm section for the full rationale).
```

### Interop with string-only APIs

`ProtectedString` deliberately offers no `ToManagedString()` — once a secret has been hashed into a `string`, the runtime may intern, deduplicate, or copy it across GC cycles in ways nothing in user code can erase. The cookbook below works through the cases where you reach for `string` in idiomatic .NET; pick the one that fits your boundary.

The general rule: **prefer streaming sinks** (`WriteUtf8To` / `CopyTo`) when the API exposes a `Stream` / `Span<char>` / `byte[]`, and **materialize inside `Access` then suppress [TPS001](#build-time-analyzer-tps001--tps002) narrowly** when the BCL truly forces a `string` — the analyzer exists to make sure you reach for that escape hatch deliberately.

`ToString()` deliberately does **not** include the plaintext — it returns `ProtectedString[length=N]` so that accidental logging is safe.

**Approaches in order of preference:**

1. **Stream the bytes** (`WriteUtf8To`, `CopyTo`) into a `Stream` / `Span<char>` / `byte[]` API — no managed `string` materialises. Use this whenever the boundary allows it.
2. **Use the obsolete `Access(Action<char[]>)` overload** when an external API genuinely requires a mutable `char[]`. The buffer is wiped on return; the `char[]` has the same heap caveats as a `string`, but you can pass it to APIs that mutate or re-encode in place. TPS002 catches captures that outlive the callback.
3. **`new string(plain)` inside `Access`.** Last resort when the BCL truly forces a `string`. Keep the materialization as close to the call as possible and suppress TPS001 with a justifying comment. Strictly weaker than every option above — see [How safe is `new string(plain)` inside `Access`?](#11-how-safe-is-new-stringplain-inside-access) in the FAQ for the full breakdown of what you give up.
4. **Reconsider the protocol.** Mutual TLS, workload-identity tokens minted per-call, and federated credentials that never see a process-local secret are structurally stronger than any in-process secret protection — see the SO citation in [Inspiration](#inspiration).

#### HTTP request body

Use `WriteUtf8To` inside a custom `HttpContent`. The plaintext flows from the decrypted, pinned, wipe-on-exit buffer straight into the request stream — no managed `string`, no `byte[]` you have to remember to clear.

```csharp
sealed class ProtectedStringContent : HttpContent
{
    private readonly ProtectedString _ps;
    public ProtectedStringContent(ProtectedString ps, string mediaType = "text/plain")
    {
        _ps = ps;
        Headers.ContentType = new MediaTypeHeaderValue(mediaType) { CharSet = "utf-8" };
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? ctx)
    {
        _ps.WriteUtf8To(stream);
        return Task.CompletedTask;
    }

    protected override bool TryComputeLength(out long length) { length = -1; return false; }
}

using var req = new HttpRequestMessage(HttpMethod.Post, url)
{
    Content = new ProtectedStringContent(secret),
};
await http.SendAsync(req);
```

For JSON where the secret is one field, drive a `Utf8JsonWriter` over the same stream and call `WriteUtf8To` for that property's value — same principle.

#### HTTP headers and other string-only credential APIs

Many APIs — `AuthenticationHeaderValue`, `HttpRequestMessage.RequestUri`, `Headers.TryAddWithoutValidation`, `AzureKeyCredential`, `TokenCredential.GetToken`, gRPC `Metadata` — take `string` and offer no streaming overload. The pattern is the same in every case: materialize inside `Access`, hand the result straight to the call, and let it fall out of scope when the call completes. Push the materialization into a `DelegatingHandler` (or the SDK's per-call interceptor equivalent) so the string never lives in a field or client-wide header — never assign to `HttpClient.DefaultRequestHeaders.Authorization`, which would pin a managed copy for the lifetime of the client.

```csharp
sealed class ProtectedBearerHandler : DelegatingHandler
{
    private readonly ProtectedString _token;
    public ProtectedBearerHandler(ProtectedString token) => _token = token;

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        _token.Access(plain =>
        {
#pragma warning disable TPS001 // HttpClient header API requires string
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", new string(plain));
#pragma warning restore TPS001
        });
        return base.SendAsync(request, ct);
    }
}

// composition root
services.AddTransient<ProtectedBearerHandler>();
services.AddHttpClient("api", c => c.BaseAddress = new Uri("https://api.example.com"))
        .AddHttpMessageHandler<ProtectedBearerHandler>();
```

The `string` is constructed inside `SendAsync`, attached to that single `HttpRequestMessage`, and becomes unreachable as soon as the response completes — no field, no captured closure, no client-wide header. The `ProtectedString` itself stays encrypted at rest between sends. The same shape applies elsewhere: gRPC `CallCredentials.FromInterceptor` materializes per-call into `Metadata`; a custom `TokenCredential.GetToken` returns an `AccessToken` built inside `Access`; an `AzureKeyCredential` is constructed inside `Access` and handed straight to the SDK client constructor, which copies what it needs internally.

#### ADO.NET — `SqlCredential` and connection strings

For SQL Server, prefer `SqlCredential` over inlining the password into the connection string. `SqlCredential` takes a `SecureString` — which is weaker than `ProtectedString` (see [Replacing `SecureString`](#replacing-securestring)) but is what the ADO.NET API will accept. Build the `SecureString` inside `Access` and hand it straight to `SqlCredential`; the `ProtectedString` stays encrypted at rest, and the `SecureString`'s lifetime is bounded by the `using`.

```csharp
using var sec = new SecureString();
password.Access(plain =>
{
    foreach (var ch in plain) sec.AppendChar(ch);
    sec.MakeReadOnly();
});

var cred = new SqlCredential(username, sec);
using var conn = new SqlConnection("Server=...;Database=...;", cred);
await conn.OpenAsync();
```

For drivers that take only a `string` connection string (Npgsql, MySqlConnector, Oracle ManagedDataAccess), build the connection string inside `Access`, open the connection inside the same callback, and never store the connection-string `string` in a field. Pool the `DbConnection` itself — not the password.

#### Child processes — `ProcessStartInfo` and stdin

Don't pass secrets on the command line — `argv` is visible to any local user via `/proc/<pid>/cmdline` (Linux) or `Get-Process` (Windows with sufficient rights). Two safer paths:

**Stdin (preferred when the child cooperates).** `WriteUtf8To` streams straight into the child's stdin — no managed `string` materialises in *this* process, and the child reads it from a pipe.

```csharp
var psi = new ProcessStartInfo("gpg", "--batch --passphrase-fd 0 --decrypt file.gpg")
{
    RedirectStandardInput = true,
    UseShellExecute = false,
};
using var proc = Process.Start(psi)!;
secret.WriteUtf8To(proc.StandardInput.BaseStream);
proc.StandardInput.Close();
await proc.WaitForExitAsync();
```

**Environment variables** are visible only to the child (and to other processes running as the same user). `ProcessStartInfo.Environment` is a `IDictionary<string, string>` — same TPS001 escape, but the secret never crosses the process boundary in the clear:

```csharp
var psi = new ProcessStartInfo("my-tool", "deploy");
secret.Access(plain =>
{
#pragma warning disable TPS001 // Environment dictionary requires string
    psi.Environment["DEPLOY_TOKEN"] = new string(plain);
#pragma warning restore TPS001
});
using var proc = Process.Start(psi);
```

#### What not to do

`secret.Access(p => new string(p))` returned from a method (or stashed in a field / static / singleton) defeats the protection entirely — see [How safe is `new string(plain)` inside `Access`?](#11-how-safe-is-new-stringplain-inside-access) for why. The pattern across every recipe above is the same: materialize at the boundary, hand to the BCL, let it die with the operation. Cache the `ProtectedString`, not the materialized string.

## ProtectedBlob (large secret blobs)

`ProtectedString` is sized for credentials: every `Access` decrypts the whole value, and its buffers are pinned and locked — the per-process locked-memory budget (see [Memory-locking policy](#memory-locking-policy)) makes that the wrong shape for multi-MB data. `ProtectedBlob` is the bulk-data companion: a write-once, **byte**-oriented container that stores the plaintext as fixed-size AES-GCM-256 chunks (64 KiB default) in ordinary unpinned memory — ciphertext leaks nothing if paged, dumped, or copied by the GC — while only the ~60-byte wrapped key envelope and the one-chunk read scratch get the pinned+locked+wiped treatment.

Each blob encrypts under its own random 256-bit DEK, wrapped under the **same process master protector** as `ProtectedString`: the [key-at-rest tiers](#key-at-rest-wrapping-opt-in-tiered) (including TPM / Secure Enclave / Keystore) and `UnwrappedKeyCacheTtl` apply to blobs with no extra configuration, and any number of blobs consume exactly one hardware-backed key slot. Integrity follows libsodium's `secretstream` pattern — every chunk's AAD binds the blob id, the chunk index, and a final-chunk flag (exact byte layout in [Wire format](#wire-format)), so bit flips, chunk reordering, truncation, and cross-blob chunk transplants all fail the GCM tag check instead of decrypting to wrong plaintext.

Typical payloads: ML model weights that shouldn't sit plaintext in a heap dump between inferences, sealed assets decrypted from disk into RAM, user uploads buffered in memory before processing, and license / entitlement blobs that live for the process lifetime.

### ProtectedBlob usage

```csharp
using TopSecret;

// Wrap bytes you already hold (encrypted chunk-by-chunk straight from the span).
using var blob = new ProtectedBlob(modelWeights.AsSpan());

// Or consume a byte[] and wipe the source.
using var consumed = new ProtectedBlob(uploadedBytes, clearSource: true);

// Or stream unknown-length input — plaintext residency never exceeds two chunks.
using var fromStream = ProtectedBlob.FromStream(httpUploadStream);

// Sequential read, one chunk at a time; the span is a ref struct and the
// scratch buffer is wiped when the pass completes.
blob.AccessChunks(chunk => hasher.AppendData(chunk));

// Chunk-granular random access — transform inside the callback rather than
// copying the protected span out (same discipline as ProtectedString.Access).
long magic = blob.AccessChunk(0, chunk => BinaryPrimitives.ReadInt64LittleEndian(chunk));

// Contiguous plaintext into a caller-owned buffer (you wipe it after use).
var buffer = new byte[blob.Length];
blob.CopyTo(buffer);

// Or stream the plaintext out.
blob.WriteTo(destinationStream);
```

### ProtectedBlob API surface

| Member | Purpose |
| --- | --- |
| `ProtectedBlob(ReadOnlySpan<byte>)` / `ProtectedBlob(ReadOnlySpan<byte>, int chunkSize)` | Wrap a copy of the given bytes, encrypted chunk-by-chunk directly from the span (no whole-blob staging copy). |
| `ProtectedBlob(byte[], bool clearSource = false)` / `ProtectedBlob(byte[], bool, int chunkSize)` | Wrap a `byte[]`, optionally zeroing the source. |
| `static FromStream(Stream)` / `static FromStream(Stream, int chunkSize)` | Read a stream to its end, encrypting as it goes — plaintext residency ≤ 2 chunks regardless of blob size; works with non-seekable, unknown-length streams; > 2 GiB supported. |
| `Length` / `ChunkCount` / `ChunkSize` / `IsDisposed` | Inspection. `Length` is a `long`. A blob always holds ≥ 1 chunk — an empty blob is one empty *final* chunk, which keeps truncation detectable. |
| `AccessChunk(int, ReadOnlySpanAction<byte>)` / `AccessChunk<T>(int, ReadOnlySpanFunc<byte, T>)` | Decrypt one chunk into a pinned, locked, wiped-on-return scratch and hand it to the callback as a `ReadOnlySpan<byte>` (`ref struct` — cannot escape). Chunk-granular random access. |
| `AccessChunks(ReadOnlySpanAction<byte>)` | Sequential pass over every chunk through one reused scratch; the per-blob key is unwrapped once for the whole pass (one secure-element round-trip on hardware tiers). |
| `CopyTo(Span<byte>)` | Decrypt the whole blob into a caller-owned buffer. On a tamper failure everything already written is zeroed before the exception propagates. The caller owns (and wipes) the destination. |
| `WriteTo(Stream)` | Stream the plaintext out through a reused one-chunk scratch — the blob-shaped sibling of `WriteUtf8To`. |
| `ToString()` | `ProtectedBlob[length=N]` / `ProtectedBlob[disposed]` — never the contents. |
| `Dispose()` | Zero the key envelope and all ciphertext frames; finalizer covers the forget-to-dispose case. |

Chunk-size configuration: the public constants `DefaultChunkSize` (64 KiB), `MinChunkSize` (4 KiB), and `MaxChunkSize` (1 MiB) bound the valid range, and the static `ProtectedBlobOptions.DefaultChunkSize` sets the process-wide default used when no explicit `chunkSize` is passed. Unlike the read-once `ProtectedStringOptions` keys it is read at *each* construction and captured per blob. The security posture (key-at-rest tier, unwrap cache, locking policy) is deliberately shared with `ProtectedString` via `ProtectedStringOptions`; bind `ProtectedBlobOptions` from `IConfiguration` manually (`int.TryParse(configuration["TopSecret:ProtectedBlob:DefaultChunkSize"], ...)`) — the `.Configuration` companion package intentionally does not reference the blob assembly.

Deliberate divergences from `ProtectedString`: **no whole-blob `Access`** (a multi-MB pinned plaintext buffer would defeat the design — use `CopyTo` into a buffer you own, or the chunk callbacks), **no build mode** (`AppendChar` exists for `SecureString` migration parity; there is no byte-at-a-time source for bulk data — use `FromStream`), and **no `Equals`/`Copy`** (no multi-MB credential-verification use case; blobs are immutable and thread-safe, so share the instance).

### Wire format

Every chunk is stored as an ordinary (unpinned) `byte[]` frame laid out as `ciphertext ‖ 16-byte GCM tag`. Nonces are never stored: the 12-byte nonce for each chunk is rebuilt deterministically as an **8-byte per-blob random prefix ‖ 4-byte big-endian chunk counter** — the deterministic construction from [NIST SP 800-38D §8.2.1](https://csrc.nist.gov/pubs/sp/800/38/d/final). Because every blob encrypts under a fresh random 256-bit DEK, nonce uniqueness within a blob is structural (the counter cannot repeat under one key), and SP 800-38D's 2³²-invocations-per-key cap is likewise enforced structurally by the 32-bit counter rather than by bookkeeping.

Associated data binds every ciphertext to its identity and position:

| AAD | Layout | Size |
| --- | --- | --- |
| Chunk AAD | `"TPB1"` ‖ blob id (LE64) ‖ chunk index (BE32) ‖ final-flag byte | 17 B |
| DEK envelope AAD | `"TPBK"` ‖ blob id (LE64) | 12 B |

The format is frozen by `WireFormatPinningTests` in `TopSecret.ProtectedBlob.Tests` — changing the frame layout, nonce construction, or either AAD is a breaking change and requires a new magic.

### Performance shape

| Operation | Cost shape |
| --- | --- |
| Construction (span / `byte[]` / `FromStream`) | One AES-GCM encrypt per chunk, fed straight from the caller's span — no whole-blob staging copy. |
| `AccessChunk` | One master-key unwrap + one 32-byte envelope decrypt + one chunk decrypt. |
| Multi-chunk passes (`AccessChunks` / `CopyTo` / `WriteTo`) | **One master unwrap per pass** — a 200 MB `WriteTo` on the hardware tier costs a single secure-element round-trip plus AES-NI streaming, not one round-trip per chunk. |
| `Dispose` | Zero the key envelope + all ciphertext frames. |

Per-provider round-trip costs for the hardware tier are in [Performance: hardware-backed tier](#hardware-backed-tier).

### ProtectedBlob security notes

- **What it adds over a plain `byte[]`:** encryption at rest in process memory (a heap dump between reads sees ciphertext), no GC-copied plaintext residue for the bulk (only the one-chunk scratch, which is pinned/locked/wiped), and fail-closed integrity over reorder/truncate/transplant/bit-flip. What it does **not** add: any defence against an attacker reading the live process — same [threat model](#threat-model) honesty as the core.
- **Plaintext residency:** one chunk during reads; two chunks during `FromStream` construction (a lookahead buffer decides the final-chunk flag). Locked-memory footprint scales with `chunkSize` (4 KiB–1 MiB, default 64 KiB), not blob size — see [Memory-locking policy](#memory-locking-policy) for the per-process budget. `mlock`/`VirtualLock` operate at page granularity, so small scratches still cost at least a 4 KiB page; page granularity also means unlock is not refcounted: wiping-and-unlocking one buffer can unlock a page shared with another still-live locked buffer (a residual shared with the core library's own scratch handling; a pooled locked-scratch allocator is a planned follow-up for both).
- **Process-key rotation:** blobs snapshot the process protector at construction and keep working after [`RotateProcessKey()`](#process-key-rotation-opt-in), but they do **not** participate in rotation — this blob's DEK and chunk ciphertext are never re-keyed during its lifetime. A memory dump captured while a blob is alive (which, on the software tiers, includes master-key material) can decrypt that blob's ciphertext image regardless of later rotations. Dispose blobs to end their exposure. O(1) re-wrap participation is a planned follow-up.
- **Read-once options:** the first construction of *either* `ProtectedBlob` or `ProtectedString` samples the read-once `ProtectedStringOptions` keys (`KeyAtRestProtection`, `UnwrappedKeyCacheTtl`) — set them in your composition root before constructing either type.
- **Streaming reads deliver an authenticated prefix.** `AccessChunks`/`WriteTo` hand chunks to the consumer as each one authenticates (the `secretstream` model); if a later chunk fails the tag, earlier chunks have already been seen — the failure itself can never be silent, and the single-shot `CopyTo` instead zeroes everything it wrote.

## Demo

A runnable end-to-end demo lives in [`TopSecret.Demo`](TopSecret.Demo):

```
dotnet run --project TopSecret.Demo
```

The same scenarios also run **fully client-side in the browser**: [`TopSecret.Demo.Wasm`](TopSecret.Demo.Wasm) wraps the shared `DemoApp` (in [`TopSecret.Demo.Core`](TopSecret.Demo.Core)) in an [xterm.js](https://github.com/xtermjs/xterm.js) terminal on .NET WebAssembly and is deployed to GitHub Pages by [`pages.yml`](.github/workflows/pages.yml) on every push to master. In the browser the demo uses the library's `net10.0-browser` build (BouncyCastle AES-GCM); the Argon2id scenario is skipped there — see the `browser-wasm` caveats.

Both hosts finish by **running a representative NUnit slice live, in-process** ([`DemoTests`](TopSecret.Demo.Core/DemoTests.cs) via [`DemoTestRunner`](TopSecret.Demo.Core/DemoTestRunner.cs)) and reporting per-test PASS/SKIP/FAIL. Tests that aren't valid on the host self-skip (`Assert.Ignore`) — e.g. the hardware-backed tier where no TPM/Secure Enclave/Keystore is present — so the demo shows exactly which behaviours verify where it runs. (The exhaustive suites — tamper matrices, wire-format pinning, rotation, TPM — run in CI, not the demo.)

The demo exercises every public-facing pattern:

- Each constructor shape — `string`, `ReadOnlySpan<char>`, and `AppendChar` build-up followed by `MakeReadOnly`.
- The `ReadOnlySpan<char>` overload of `Access`, with an in-callback SHA-256 over the UTF-8 plaintext (illustrative only — never store a SHA-256 of a password as a credential verifier; use Argon2id).
- The `CopyTo(Span<char>)` sink against a `stackalloc` buffer.
- The `WriteUtf8To(Stream)` sink against a `MemoryStream`, with the same pattern that would feed a `NetworkStream` / `SslStream` / `FileStream` in production.
- Constant-time `Equals` for matching and mismatching inputs.
- Argon2id hash + verify with OWASP-aligned defaults, including the per-credential salt and the round-trip timing.
- The logging-safe `ToString()` — `ProtectedString[length=N]`, never the plaintext.
- The interop recipes from [Interop with string-only APIs](#interop-with-string-only-apis): custom `HttpContent` driving `WriteUtf8To`, and a `DelegatingHandler` that materializes a Bearer token inside `Access` for one send and lets the string die with the request. Both run against an in-process `HttpMessageHandler` so the demo is fully offline.

It also opts into `KeyAtRestProtection.HardwareBackedPreferred` at startup so the hardware-backed availability probe runs on the host — on Apple Silicon, Windows-with-TPM, or Android-on-device this picks up the secure element; on other hosts it falls back silently down the [tier order](#key-at-rest-wrapping-opt-in-tiered).

## API surface

| Member | Purpose |
| --- | --- |
| `ProtectedString()` | Empty instance, build with `AppendChar`. |
| `ProtectedString(string)` | Convenience wrap around a literal/configured string. See caveat below. |
| `ProtectedString(ReadOnlySpan<char>)` | Wrap a copy of the given characters. |
| `ProtectedString(char[], bool clearSource = false)` | Wrap a `char[]`, optionally zeroing the source. |
| `Length` / `IsReadOnly` / `IsDisposed` | Inspection. |
| `AppendChar(char)` | Append one char (not allowed if read-only). Writes to a pinned, locked, dump-excluded plaintext **build buffer** with geometric growth — **O(amortized 1) per call**. The buffer is committed to AES-GCM ciphertext on the next `MakeReadOnly()` (or `Dispose()` / process-key rotation), so a `new ProtectedString(); foreach AppendChar; MakeReadOnly()` build pays a single encryption regardless of secret length — particularly important under hardware-backed wrapping where a per-call encrypt would round-trip to the TPM / Secure Element on every character. **Trade-off:** while in build mode (between the first `AppendChar` after construction and `MakeReadOnly`), the plaintext lives in pinned/locked memory rather than encrypted. Call `MakeReadOnly()` as soon as the secret is fully assembled. |
| `MakeReadOnly()` | Commit the build buffer (if any) to ciphertext and disallow further mutation. |
| `Access(ReadOnlySpanAction<char>)` / `Access<T>(ReadOnlySpanFunc<char, T>)` | Run a callback against the plaintext as a `ReadOnlySpan<char>`. The span is a `ref struct` — the C# compiler refuses to let it be captured by a closure, stored in a field, returned from the lambda, or crossed by an `await`. **Recommended.** |
| `Access(Action<char[]>)` / `Access<T>(Func<char[], T>)` | **Obsolete** — kept for callers that genuinely need a `char[]` (e.g. an external API that takes one). The buffer is zeroed on return; do not retain the reference. The `ReadOnlySpan<char>` overloads are strictly safer. |
| `CopyTo(Span<char> destination)` | Copy the plaintext into a caller-owned buffer (e.g. `stackalloc char[N]`); returns the number of chars written (`Length`). The library does not own the destination — the caller is responsible for wiping or letting it fall out of scope. |
| `WriteUtf8To(Stream destination)` | Encode the plaintext as UTF-8 and write straight to a stream — no intermediate managed `string` materialises. The intermediate UTF-8 bytes pass through a pinned, locked, wiped-on-exit buffer. |
| `Copy()` | Independent, writable copy. |
| `Equals(ProtectedString)` | Constant-time comparison. (`Equals(object?)` is a one-line override that defers to this; same behavior.) |
| `GetHashCode()` | Length-only hash. Plaintext intentionally does not contribute, so a dictionary-bucket lookup never reveals anything about the secret through its hash function. |
| `ToString()` | Returns `ProtectedString[length=N]` (or `ProtectedString[disposed]`) — never the plaintext, so accidental logging is safe. |
| `ComputeArgon2idHash(salt, iterations, memoryKb, parallelism, hashLengthBytes)` | Compute an Argon2id hash of the plaintext. OWASP-aligned defaults (`t=3`, `m=19 MiB`, `p=1`, 32-byte output). Not supported on the single-threaded browser runtime — throws `PlatformNotSupportedException` there (see [`browser-wasm` support](#browser-wasm-support)). |
| `VerifyArgon2idHash(expectedHash, salt, iterations, memoryKb, parallelism)` | Constant-time verification against a previously stored hash. Same browser caveat as `ComputeArgon2idHash`. |
| `Dispose()` | Zero the ciphertext, nonce, tag, and any in-flight build buffer. |
| `static HardwareBackedAvailability` | Probe whether a hardware-backed master-key protector is available on this host. See [Key-at-rest wrapping](#key-at-rest-wrapping-opt-in-tiered). |
| `static RotateProcessKey()` | Re-encrypt every live instance under a fresh master AES key. Requires `ProcessKeyRotationPolicy != Disabled`. See [Process-key rotation](#process-key-rotation-opt-in). |

> **Caveat — `ProtectedString(string)`.** `string` cannot be reliably erased from memory — see [How safe is `new string(plain)`...](#11-how-safe-is-new-stringplain-inside-access) for the full explanation. Prefer `ReadOnlySpan<char>`, a `char[]` you control, or `AppendChar`.

## Replacing `SecureString`

### At a glance

| Concern | `SecureString` | `ProtectedString` |
| --- | --- | --- |
| **Encryption at rest** | Windows only (DPAPI `CryptProtectMemory`). **No encryption on Linux/macOS/mobile** — bytes are plaintext in unmanaged memory. | AES-GCM on every supported platform. |
| **Encryption strength** | DPAPI `SAME_PROCESS` — reversible in-process ([public PoC](https://blog.slowerzs.net/posts/cryptdecryptmemory/)). | AES-GCM-256 with per-instance AAD binding (details in [Security model](#security-model)); opt-in [hardware-backed key wrap](#key-at-rest-wrapping-opt-in-tiered) (SEP / Keystore / TPM) for real passive-dump resistance. |
| **Where bytes live** | Unmanaged memory. | Pinned object heap, with `VirtualLock` / `mlock`. |
| **Swap protection** | None — pages can be written to disk. | `VirtualLock` / `mlock` on every sensitive buffer; configurable failure policy. |
| **Wipe on dispose** | `SecureZeroMemory`. | `CryptographicOperations.ZeroMemory`, plus a finalizer for the forget-to-dispose case. |
| **Build char-by-char** | `AppendChar`. | `AppendChar` writes to a pinned, locked build buffer (geometric growth, single encryption on `MakeReadOnly()`) — see [API surface](#api-surface). |
| **Brief plaintext access** | `Marshal.SecureStringToGlobalAllocUnicode` + manual zero/free — easy to forget the wipe. | `Access(ReadOnlySpanAction<char>)` — the span is a `ref struct` the compiler refuses to let escape (no capture, no field, no return, no `await`); buffer wiped on return. The legacy `Action<char[]>` shape is still available, marked obsolete. |
| **Constant-time equality** | None. | `CryptographicOperations.FixedTimeEquals` for plaintext compare and Argon2id verify. |
| **Tamper detection** | None. | Per-instance 64-bit id bound as AEAD associated data — cross-instance ciphertext swap fails the GCM tag check. |
| **Credential KDF** | Out of scope. | Argon2id with OWASP-aligned defaults. |
| **Hardware-backed key wrap** | None. | Opt-in: Apple SEP, Android Keystore, Windows TPM, Linux TPM. |
| **Process-key rotation** | None. | Opt-in periodic or on-demand. |
| **In-process attacker** | No defence. | No defence (and says so explicitly). |
| **Vendor stance** | Officially deprecated for new code (`learn.microsoft.com`, `dotnet/runtime#30612`, DE0001). | Active. |

### On Windows

Windows is the only platform where `SecureString` actually encrypts, so it's also the only platform where the comparison is interesting beyond "one of these works, the other doesn't."

**The steelman for `SecureString`.** Its strongest defense is provenance: it is part of the framework, two decades in production, with Microsoft's own audit history. A familiar, well-bounded primitive can prove safer than a newer, theoretically stronger one that has not endured comparable adversarial scrutiny.

**Why `ProtectedString` still wins.** The cryptographic gap is in the table — AES-GCM-256 over the contents on every platform, with the master-key wrap on Windows under a per-protector random key (no fixed system-wide key for an attacker to reproduce, unlike `CryptProtectMemory`'s in-process-reversible construction). The argument that *isn't* in the table closes the question: Microsoft itself ships a "don't use this for new code" page, which neutralises the "trust the mature thing" defence. And TPM wrap (via [`TopSecret.ProtectedString.WindowsTpm`](TopSecret.ProtectedString.WindowsTpm)) puts the wrap key in the secure element instead of process memory — the only mechanism in either library that meaningfully raises the bar against an in-process attacker on Windows. `SecureString` has no equivalent.

**When `SecureString` is still the right pick.** Legacy code where it's woven into a Win32 interop boundary that expects it (`PSCredential`, `RunAs`, ADSI / WMI), the surface is stable, and the migration cost isn't justified by the threat model. For new code: `ProtectedString`, even on Windows, even before turning on TPM wrap.

### Migration mapping

The API was deliberately shaped to mirror `SecureString`. Most call sites map 1:1:

| `SecureString` | `ProtectedString` |
| --- | --- |
| `new SecureString()` | `new ProtectedString()` |
| `AppendChar(c)` | `AppendChar(c)` |
| `MakeReadOnly()` | `MakeReadOnly()` |
| `Length` / `IsReadOnly` | `Length` / `IsReadOnly` |
| `Marshal.SecureStringToGlobalAllocUnicode` + `ZeroFreeGlobalAllocUnicode` | `Access(plain => /* use plain */)` |
| `Dispose()` | `Dispose()` |

The one shape change is plaintext access: `ProtectedString` does not hand out a pointer the caller is expected to free. Callers pass a lambda and the buffer is zeroed automatically on return. That removes the most common `SecureString` leak — forgetting to call `ZeroFreeGlobalAllocUnicode`.

## Compared to `GuardedString`

The API was deliberately shaped after Evolveum's [`GuardedString`](#inspiration) — same problem, two decades apart, implementation choices have diverged in ways worth being explicit about.

### At a glance

| Concern | `GuardedString` (Java) | `ProtectedString` (.NET) |
| --- | --- | --- |
| **Encryption** | Pluggable `Encryptor` abstraction. The default is symmetric and **unauthenticated** — the API exposes no tag or AAD. | **AES-GCM-256** authenticated encryption — random nonce, tag, per-instance AAD (see [Security model](#security-model)). |
| **Key scope** | Static process-wide `Encryptor` from `EncryptorFactory.newRandomEncryptor()`. Random per JVM. | Static process-wide 32-byte master, lazily initialised. Random per process. |
| **Where bytes live** | Plain `byte[] encryptedBytes` on the Java heap — relocatable by the GC, no `mlock`. | Pinned object heap, with `VirtualLock` / `mlock` and a configurable [failure policy](#memory-locking-policy). |
| **Cross-instance binding** | None — ciphertext from one instance can be swapped onto another and decrypts cleanly. | Per-instance 64-bit id passed as AEAD associated data; tag check fails on cross-instance swap. |
| **Plaintext access** | `access(Accessor)` — single shape, void-returning callback. Buffer zeroed on return via `SecurityUtil.clear`. | `Access(ReadOnlySpanAction<char>)` plus `Access<T>(ReadOnlySpanFunc<char, T>)`; the span is a `ref struct` the compiler refuses to let escape. Buffer wiped on return. Sinks (`CopyTo(Span<char>)`, `WriteUtf8To(Stream)`) plus a [build-time analyzer](#build-time-analyzer-tps001--tps002) catch the common copy patterns. |
| **Equality** | Compares **stored Base64-SHA-1 hashes** of the plaintext — fast, but the hash sits in memory next to the ciphertext, and `String.equals` is not constant-time. SHA-1 is broken for collision resistance. | `CryptographicOperations.FixedTimeEquals` over freshly decrypted plaintext, with deadlock-free lock ordering (see [Security model](#what-this-library-does)). |
| **`hashCode`** | `base64SHA1Hash.hashCode()` — derived from the *content*. The SHA-1 of the secret is held in process memory. | `_length` only — never derived from plaintext, so dictionary buckets cannot reveal anything about the secret. |
| **Credential KDF** | `verifyBase64SHA1Hash(String)` — single-round SHA-1, no salt, no work factor. Useful as a probabilistic equality check; **not** safe as a password verifier. | `ComputeArgon2idHash` / `VerifyArgon2idHash` with OWASP-aligned defaults (see [API surface](#api-surface)) and constant-time verify. |
| **Serialisation** | Supported — ciphertext travels under a *known default key*; the docs explicitly defer real confidentiality to TLS. | Not serialisable. No "known default key" footgun. |
| **Wipe on dispose** | `dispose()` clears via `SecurityUtil.clear`. No finalizer fallback (Java finalizers are deprecated / unreliable). | `Dispose()` zeros ciphertext / nonce / tag, plus a finalizer fallback for the forget-to-dispose case. |
| **Hardware-backed key wrap** | None. | Opt-in: Apple SEP, Android Keystore, Windows TPM, Linux TPM. |
| **Process-key rotation** | None. | Opt-in periodic or on-demand; live instances are re-encrypted under the new master. |

### Where the gap matters

- **Authenticated encryption.** `GuardedString`'s `Encryptor` interface predates AEAD being a default expectation. Without a tag, an attacker who can flip bits in `encryptedBytes` can mutate the plaintext under decryption without detection; without AAD, ciphertext is freely transplantable across instances. `ProtectedString` has both.
- **Memory residency.** `byte[]` on the Java heap is fair game for the GC to relocate (and therefore *copy*) at any collection. Even if the original is wiped, the copy may not be. `ProtectedString` allocates onto the pinned object heap so the GC never relocates the encrypted state, then locks it so the OS will not page it to disk. That is the single biggest reason `ProtectedString` makes `SecureString`-like claims plausibly true — and `GuardedString` does not attempt this layer at all.
- **Equality, hashing, and verifiers leak less.** `GuardedString` keeps a Base64-SHA-1 hash *of the secret* in every instance's memory (an extra leak surface, compared non-constant-time), and `verifyBase64SHA1Hash` is a single unsalted SHA-1 round with no work factor — never safe as a stored password verifier. `ProtectedString` does the more expensive thing (decrypt, fixed-time compare), stores no plaintext-derived material, and ships Argon2id with OWASP-aligned defaults for the verifier job.

### Where they overlap

The callback-based access pattern (`Accessor` ↔ `Access`), the `appendChar` / `makeReadOnly` / `copy` / `dispose` shape, and the honest threat model (see [Threat model](#threat-model)) are deliberately identical. A `GuardedString`-trained reviewer recognises every method. The generic `Access<T>` overload is the only API-shape change, and it is an ergonomic addition rather than a different design.

### The one place `GuardedString` is more featureful

It serialises. That fits ConnId's wire-protocol use case — passing credentials between connector layers — and `ProtectedString` has no equivalent because it targets a different problem: protecting a secret in *this* process for the duration of *this* process. If you need to ship a secret across a network boundary, `ProtectedString` deliberately leaves that to TLS plus an out-of-band key, which is the same place `GuardedString`'s docs send you anyway since its serialisation key is a "known default."

## Security model

### Threat model

This is a best-effort defence against **accidental** memory disclosure (heap dumps, swap-to-disk, log scraping). It is *not* a sandbox, and it is *not* a defence against an attacker that already has read access to the running process. The two lists below exist to keep that boundary explicit.

### What this library does

- **AES-GCM authenticated encryption.** 12-byte random nonce per encryption, 16-byte tag, with the per-instance 64-bit id passed as AEAD associated data. If `_ciphertext` / `_nonce` / `_tag` are swapped between instances (memory corruption, deliberate tampering), the GCM tag check fails rather than decrypting to the wrong plaintext. Implementation: in-box `System.Security.Cryptography.AesGcm` on every TFM where `AesGcm.IsSupported` is `true`; BouncyCastle's `GcmBlockCipher` on `net10.0-browser` (where the in-box throws `PlatformNotSupportedException`). The two implementations are wire-format identical — see [`browser-wasm` support](#browser-wasm-support) and the cross-implementation tests in `AesGcmShimWireFormatTests`.
- **Pinned, non-relocating storage.** The 32-byte process master key is allocated via `GC.AllocateArray<byte>(32, pinned: true)` on the [pinned object heap](https://learn.microsoft.com/dotnet/standard/garbage-collection/large-object-heap#poh) — the GC never relocates (and therefore never copies) it. The encrypted state (`_ciphertext`, `_nonce`, `_tag`) is pinned the same way. The empty-value case allocates a zero-length pinned ciphertext rather than reusing the shared `Array.Empty<byte>()` singleton, so the "all encrypted state is POH-resident" invariant has no exception.
- **JIT-resistant wipes.** Plaintext buffers used inside `Access`, `AppendChar` (build buffer included), `Copy`, `CopyTo`, `WriteUtf8To`, and the Argon2id hash path are pinned and wiped with `CryptographicOperations.ZeroMemory` on the way out — the JIT is forbidden from optimizing those wipes away, unlike `Array.Clear`.
- **Build-mode buffer for `AppendChar`.** See the [API surface](#api-surface) entry for the geometric-growth / single-encryption-on-`MakeReadOnly` shape and the trade-off (plaintext lives in pinned/locked memory during build).
- **Memory locking.** Every pinned secret buffer is `VirtualLock`/`mlock`'d — see [Memory-locking policy](#memory-locking-policy).
- **Constant-time compare with deadlock-free lock ordering.** `CryptographicOperations.FixedTimeEquals` for plaintext equality and Argon2id verification. Concurrent `a.Equals(b)` / `b.Equals(a)` calls take the two instance locks in order of monotonic 64-bit ids (`Interlocked.Increment`) — deadlock-free, and unlike a `RuntimeHelpers.GetHashCode`-based ordering it has no 32-bit collision risk.
- **`Dispose` + finalizer.** `Dispose` zeros ciphertext / nonce / tag and any in-flight build buffer; a finalizer covers the forget-to-dispose case.
- **Logging-safe `ToString()`.** Returns `ProtectedString[length=N]`, never the plaintext.
- **Build-time analyzer (TPS001 / TPS002).** Flags plaintext copied or captured out of `Access` callbacks at compile time. Defence-in-depth, not a substitute for the structural protection the `ReadOnlySpan` overload provides — triggers, suppression, and packaging in [Build-time analyzer](#build-time-analyzer-tps001--tps002).

### What this library does **not** do (and why)

- **No protection against an attacker reading the live process.** Anything with `PROCESS_VM_READ`, `ptrace`, `WriteProcessMemory`, or root / `/proc/<pid>/mem` access — including a malicious assembly loaded into the same process — can read the AES key and the plaintext during the `Access(...)` window. Hardware-backed wrapping (Apple SEP, Android Keystore, Windows TPM via the optional subpackage) pushes the *wrapping* key out of process memory, but the unwrapped 32-byte master must materialise in heap memory for every AES-GCM op (and for the duration of `UnwrappedKeyCacheTtl` when caching is enabled). The threat being defended is a *cold* heap dump, not a debugger or in-process attacker.
- **`string` input or `new string(plain)` inside `Access` ends the protection.** See [How safe is `new string(plain)`...](#11-how-safe-is-new-stringplain-inside-access) for the heap-residency, GC-window, and BCL-copy details. The library closes the window between construction and use; closing it during use is the caller's job, and TPS001 catches the obvious slip-ups.

### Key-at-rest wrapping (opt-in, tiered)

By default the per-process AES master key sits plaintext in pinned, locked, dump-excluded memory for the lifetime of the process. Set `ProtectedStringOptions.KeyAtRestProtection` to wrap that master with progressively stronger primitives.

The headline decision is **fail-closed vs fall-back**: `HardwareBackedRequired` fails closed — `PlatformNotSupportedException` at the first construction on a host with no hardware-backed provider, deliberately ignoring `MemoryLockingFailureBehavior`, because silently downgrading a hard security request defeats the point — while `HardwareBackedPreferred` falls back silently (hardware → obscurity → none). Details in [Failure behaviour](#failure-behaviour).

> **All `ProtectedStringOptions` are read once at first construction.** Set them in your composition root before any `ProtectedString` is constructed — see [Hot-reload semantics](#hot-reload-semantics) for the per-key matrix and [`RotateProcessKey()`](#process-key-rotation-opt-in) for runtime protector swap.

The option has four values:

| Value | What happens | Per-op cost |
| --- | --- | --- |
| `None` *(default)* | No wrapping. Master sits in pinned/locked memory. | None |
| `Obscurity` | Software wrap only — AES-GCM-256 under a per-protector random key on Windows; HKDF stream-XOR everywhere else. Defeats casual scrapers but both wrap key and ciphertext live in the process heap — an attacker who can dump the process and knows the layout still wins. For real passive-dump resistance, use the hardware-backed tier. | ~µs |
| `HardwareBackedRequired` | Hardware-resident wrap key only — **fails closed** with `PlatformNotSupportedException` at the first `ProtectedString` construction if no hardware-backed provider is available on this host (see above). | ~ms — varies by provider, see [Performance](#hardware-backed-tier) |
| `HardwareBackedPreferred` | Best effort: try hardware → fall back to obscurity → fall back to no-op silently. The recommended setting when you want whatever protection the platform offers without hard failures. | Whatever the active tier costs |

Use `ProtectedString.HardwareBackedAvailability` in your composition root to branch deliberately. On Apple hosts the probe is destructive on first call (generates and discards a SEP-resident EC key) but cached for the process lifetime — see [Apple SEP availability](#apple-sep-availability) for which hosts have a Secure Enclave at all. On other platforms the probe inspects the registered providers without touching the secure element.

#### Per-platform wrapping primitives

| Platform | Hardware tier (built-in) | Hardware tier (optional package) | Obscurity tier |
| --- | --- | --- | --- |
| macOS / iOS / Mac Catalyst | Apple Secure Enclave EC P-256 + ECIES-AES-GCM | — | HKDF stream-XOR |
| Android (API 23+) | `AndroidKeyStore`-resident AES-GCM-256 via JNI (TEE; **not** StrongBox), on the `net10.0-android` TFM | — | HKDF stream-XOR |
| Windows | — | **TPM 2.0 via NCrypt** + Microsoft Platform Crypto Provider (RSA-2048 OAEP-SHA256), shipped in [`TopSecret.ProtectedString.WindowsTpm`](TopSecret.ProtectedString.WindowsTpm). Auto-registers via `[ModuleInitializer]`. | AES-GCM-256 with a per-protector random wrap key. |
| Linux | — | **TPM 2.0 via Microsoft TSS.MSR** (RSA-2048 OAEP-SHA256 against `/dev/tpmrm0`), shipped in [`TopSecret.ProtectedString.LinuxTpm`](TopSecret.ProtectedString.LinuxTpm). Auto-registers via `[ModuleInitializer]`. | HKDF stream-XOR |
| Browser WebAssembly | — | — (no SEP / Keystore / TPM in the WASM sandbox) | HKDF stream-XOR. AES-GCM itself uses BouncyCastle on this TFM since `System.Security.Cryptography.AesGcm.IsSupported` is `false` — see [`browser-wasm` support](#browser-wasm-support). |

##### Apple SEP availability

The Apple built-in ships in the main package, but the Secure Enclave itself is present only on Apple Silicon (M1+), T2 Macs (most 2018–2020), and T1 Macs (2016–2017 Touch Bar MBP, slower). It is **absent** on pre-T1 Intel Macs and the x86_64 iOS Simulator — SEP-bound key generation returns `NULL` there. Under `HardwareBackedRequired`, those hosts get a clean `PlatformNotSupportedException`; under `HardwareBackedPreferred` they fall through to obscurity.

##### Windows TPM (optional package)

Reference [`TopSecret.ProtectedString.WindowsTpm`](TopSecret.ProtectedString.WindowsTpm) when you want TPM-backed wrapping on Windows:

```
dotnet add package TopSecret.ProtectedString
dotnet add package TopSecret.ProtectedString.WindowsTpm
```

The package's `[ModuleInitializer]` calls `KeyAtRestProtectorFactory.RegisterHardwareBacked(...)` at assembly load, wiring the TPM provider in before the first `ProtectedString` construction. On non-Windows hosts the package is a no-op.

> **Composition-root timing.** The `[ModuleInitializer]` fires before your first `ProtectedString` construction in normal hosts — no extra wiring needed. For dynamic assembly load, plugin hosts, static-initializer construction, or Native AOT / trimming where module initializers may be elided, call `WindowsTpmRegistration.Register()` first thing in your composition root to guarantee registration order. The library emits a one-shot `Trace.TraceWarning` if `HardwareBackedRequired` / `HardwareBackedPreferred` is set on a Windows host with no registered provider — see [Diagnostics](#diagnostics).

##### Linux TPM (optional package)

Reference [`TopSecret.ProtectedString.LinuxTpm`](TopSecret.ProtectedString.LinuxTpm) when you want TPM-backed wrapping on Linux:

```
dotnet add package TopSecret.ProtectedString
dotnet add package TopSecret.ProtectedString.LinuxTpm
```

The package's `[ModuleInitializer]` calls `KeyAtRestProtectorFactory.RegisterHardwareBacked(...)` at assembly load. On non-Linux hosts the package is a no-op. Implementation: opens `/dev/tpmrm0` (kernel TPM 2.0 resource manager) via Microsoft's TSS.MSR (`Microsoft.TSS` NuGet), creates an ephemeral RSA-2048 keypair under the Owner hierarchy, and uses RSA-OAEP-SHA256 wrap — the same scheme the Windows TPM subpackage uses, just spoken over raw TPM 2.0 commands instead of NCrypt.

> **Permissions.** Reading `/dev/tpmrm0` typically requires membership in the `tss` group on Debian/Ubuntu or the `tpm` group on Fedora/RHEL. If the process can't open the device, `IsAvailable()` returns `false`, `TryCreate(...)` returns `null`, and (under `HardwareBackedRequired`) the factory throws `PlatformNotSupportedException`. The same composition-root timing caveats as the Windows TPM package apply — see above.

> **Container caveat.** Containers don't see the host TPM unless `/dev/tpmrm0` is explicitly mounted in (e.g. `--device /dev/tpmrm0` for Docker). Most cloud Linux VMs and serverless runtimes don't expose a TPM at all — the package self-skips on those hosts.

Hardware-backed wrapping pays a per-`UnwrapKey` round-trip on every `Access` / `Equals` / `AppendChar` / `Copy`. `ProtectedStringOptions.UnwrappedKeyCacheTtl` opts in to a short-lived cache that amortizes that cost — see [Performance: hardware-backed tier](#hardware-backed-tier) for per-provider round-trip numbers and the cache trade-off.

```csharp
ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.HardwareBackedPreferred;
ProtectedStringOptions.UnwrappedKeyCacheTtl = TimeSpan.FromMilliseconds(250);
```

#### Failure behaviour

`HardwareBackedRequired` fails closed as described at the top of this section — unconditionally, ignoring `MemoryLockingFailureBehavior`. Every other hardening primitive (memory locking, HKDF construction failures) routes through `ProtectedStringOptions.MemoryLockingFailureBehavior` — see [Memory-locking policy](#memory-locking-policy) for the enum values.

```csharp
using TopSecret;

// Recommended for most apps — take whatever protection the platform offers,
// don't fail on platforms that don't have hardware-backed wrapping.
ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.HardwareBackedPreferred;

using var ps = new ProtectedString("hunter2".AsSpan());
```

Or from `appsettings.json` — see [Configuration binding from `appsettings.json`](#configuration-binding-from-appsettingsjson) for the full surface (all five options, hot-reload semantics, the optional `TopSecret.ProtectedString.Configuration` companion package, and the rationale for the static-properties design).

### Diagnostics

The library emits one-shot `Trace.TraceWarning` calls for misconfigurations that would otherwise be silent. **You will only see them if a `TraceListener` is attached.** .NET's default trace configuration discards `Trace.TraceWarning` output; ASP.NET Core / generic-host apps don't attach a listener by default. Wire one up in your composition root:

```csharp
System.Diagnostics.Trace.Listeners.Add(new System.Diagnostics.ConsoleTraceListener());
```

Most warnings fire at most once per process, gated by an `Interlocked.CompareExchange`. The **partial rotation failure** warning is the exception — it fires once per failed `RotateProcessKey()` call so ongoing migration breakage stays visible.

| Warning | Trigger | What to do |
| --- | --- | --- |
| **No hardware-backed provider** | `KeyAtRestProtection` is `HardwareBackedRequired` / `HardwareBackedPreferred` on a platform with no built-in (Windows, Linux) and an empty external-provider registry, at first `ProtectedString` construction | Reference `TopSecret.ProtectedString.WindowsTpm` / `TopSecret.ProtectedString.LinuxTpm`, or call `KeyAtRestProtectorFactory.RegisterHardwareBacked(...)` from your composition root |
| **Late mutation of read-once option** | `KeyAtRestProtection`, `UnwrappedKeyCacheTtl`, or `ProcessKeyRotationInterval` is set after the first `ProtectedString` has been constructed (the change is a silent no-op) | Set the option in your composition root, before any construction; or call `ProtectedString.RotateProcessKey()` to swap protectors at runtime |
| **TPM transient-slot rotation** | `ProcessKeyRotationPolicy` is `Periodic` and a registered hardware-backed provider declared itself `transientSlotConstrained` (Windows TPM and Linux TPM both do) — long-running services rotating frequently can exhaust TPM transient slots (commodity TPMs hold ≤3) | Reduce `ProcessKeyRotationInterval`, switch to `OnDemand`, or accept the cost trade-off and ensure rotation cadence is well below your TPM's GC of orphaned transient keys |
| **Memory locking failure** | `VirtualLock` / `mlock` failed and `MemoryLockingFailureBehavior` is `LogWarning` (the default) | See [Memory-locking policy](#memory-locking-policy) — set the policy to `Throw` if paging-to-disk is in your threat model |
| **Partial rotation failure** *(per-call, not one-shot)* | One or more live `ProtectedString` instances threw during their per-instance migration inside `RotateProcessKey()`. The unmigrated instances still reference the previous master and would be lost in a "rotate then dispose old key" workflow | Inspect the trace message for the failed-instance count; investigate why the per-instance protector's `UnwrapKey` is failing (TPM unavailable mid-rotation, custom protector throwing, etc.). Re-running `RotateProcessKey()` after the cause is fixed retries the migration |

### Build-time analyzer (TPS001 / TPS002)

The NuGet ships a Roslyn analyzer (`TopSecret.ProtectedString.Analyzers.dll`, packaged at `analyzers/dotnet/cs/`) that flags the most common patterns where the plaintext made available inside a `ProtectedString.Access(...)` callback is copied or captured in a way that defeats the wipe-on-return guarantee.

Two diagnostics ship:

| ID | Severity | Triggers on |
| --- | --- | --- |
| **TPS001** | Warning | Plaintext copied into a managed `string` inside an `Access` callback — `new string(plain)`, `plain.ToString()`, `string.Concat(..., plain, ...)`, etc. Once the bytes have been hashed into a `string`, the runtime may intern, deduplicate, or copy them across GC cycles in ways nothing in user code can erase. |
| **TPS002** | Warning | The `Action<char[]>` overload's parameter is assigned to a captured local, field, or property — i.e., the `char[]` reference outlives the callback. The library zeroes the array on return, so the retained reference observes a buffer of zeros at best. The `ReadOnlySpan<char>` overload makes this structurally impossible. |

The diagnostics are warnings, not errors — the C# language cannot prevent intentional copying, and there are legitimate cases (passing the plaintext to an external API that demands a `string`). If you need to suppress one deliberately, do it locally with a justification:

```csharp
#pragma warning disable TPS001 // FIDO2 client API requires a string here.
ps.Access(plain => fido.AuthenticateWithUserVerification(new string(plain)));
#pragma warning restore TPS001
```

Disable globally in your csproj only if you have no callers that ought to be flagged:

```xml
<NoWarn>$(NoWarn);TPS001;TPS002</NoWarn>
```

The detection rules themselves are pinned by `TopSecret.ProtectedString.Analyzers.Tests`, which hosts the analyzer in-memory against a corpus of expected-violation snippets (TPS001 / TPS002 must fire) and expected-clean snippets (no diagnostic). That suite runs on every CI leg, so a regression that silently disables a detection rule fails the build instead of landing unobserved.

### Process-key rotation (opt-in)

The per-process AES master key is generated once per process by default. To bound the blast radius of a *historical* memory disclosure (an old core file, a crash dump captured at time T, an old swap backup), you can opt into periodic or on-demand rotation:

```csharp
using TopSecret;

ProtectedStringOptions.ProcessKeyRotationPolicy = ProcessKeyRotation.Periodic;
ProtectedStringOptions.ProcessKeyRotationInterval = TimeSpan.FromHours(1);

// Construct ProtectedStrings as usual. Each one is registered into a
// weak-reference registry and re-encrypted under a fresh master every hour.
using var ps = new ProtectedString("hunter2".AsSpan());

// Or rotate manually whenever you want:
ProtectedString.RotateProcessKey();
```

Three policy values:

| Policy | Behavior | Per-construction cost |
| --- | --- | --- |
| `Disabled` *(default)* | No registry, `RotateProcessKey()` throws. | None |
| `OnDemand` | Registry maintained; rotate by calling `RotateProcessKey()`. | Brief shared-lock acquisition |
| `Periodic` | Like `OnDemand` plus a background timer that fires `RotateProcessKey()` at `ProcessKeyRotationInterval`. | Brief shared-lock acquisition |

What rotation does:

1. Generates a fresh 32-byte master AES key, wraps it under the configured `KeyAtRestProtection`, and atomically swaps it in as the global protector.
2. Snapshots the registry (pruning dead weak refs).
3. For each live instance, takes the per-instance lock, decrypts under the old master, re-encrypts under the new one, and updates the instance's protector reference.

Concurrent operations on instances *not* currently being migrated proceed unblocked. Concurrent `RotateProcessKey()` calls are deduplicated — if a rotation is already in flight, the second call returns immediately.

> **Threat-model honesty.** Rotation only bounds *historical* exposure — ciphertext captured under a key that has since rotated cannot be recovered without that old key, and the old key has been zeroed. See [Threat model](#threat-model) for what rotation does not cover.

> **`ProcessKeyRotationPolicy` is read once at first construction** (see [Key-at-rest wrapping](#key-at-rest-wrapping-opt-in-tiered)). Instances created while the policy was `Disabled` are not in the registry and will not be migrated by later rotations — switching the policy at runtime affects future instances only.

### Memory-locking policy

`ProtectedString` calls `VirtualLock` / `mlock` on every sensitive buffer. Locking can fail — the platform may not expose the primitive at all, or the process may be at `RLIMIT_MEMLOCK` / working-set capacity. The static option `ProtectedStringOptions.MemoryLockingFailureBehavior` decides what happens when that occurs:

| Value | What it does |
| --- | --- |
| `LogWarning` *(default)* | Emit one `Trace.TraceWarning` per process, then proceed without locking. |
| `Throw` | Raise `PlatformNotSupportedException` from the constructor / mutation that needed to lock. |
| `Ignore` | Silently proceed. |

Set it directly:

```csharp
using TopSecret;

ProtectedStringOptions.MemoryLockingFailureBehavior = MemoryLockingFailureBehavior.Throw;
```

Or bind it from `appsettings.json` the same way as `KeyAtRestProtection` above — `ProtectedStringOptions` has no dependency on `Microsoft.Extensions.Configuration`, so the `Enum.TryParse` pattern is the same for every option.

> **`RLIMIT_MEMLOCK` budget on libc targets.** Linux unprivileged processes default to ≈64 KiB locked memory; iOS is stricter. Pinned buffers on the POH often share pages so practical capacity is higher than per-buffer counting suggests; set the policy to `Throw` if you need to fail loudly when the budget is hit.

## Performance

This section gives **algorithmic** cost per operation and the **indicative** wall-clock numbers that follow from it. Concrete numbers are order-of-magnitude estimates on a modern AES-NI desktop CPU; treat them as "the right shape" rather than benchmark output. If a hot path matters for your app, measure on your hardware.

### Default tier (no hardware-backed wrap)

The master key sits in pinned, locked, dump-excluded memory. Per-op cost is dominated by AES-GCM, which is hardware-accelerated on every modern x86 / ARM CPU.

| Operation | Cost shape | Indicative wall-clock |
| --- | --- | --- |
| `new ProtectedString(span)` | One AES-GCM encrypt over `span.Length` bytes + pinned-buffer alloc | Sub-µs for credential-sized secrets (≤ 256 chars) |
| `Access(...)` | One AES-GCM decrypt + your callback + JIT-resistant wipe | Sub-µs decrypt for credential-sized secrets; total dominated by your callback |
| `CopyTo(Span<char>)` | One AES-GCM decrypt + `Span.CopyTo` | Sub-µs for credential-sized secrets |
| `WriteUtf8To(Stream)` | One AES-GCM decrypt + UTF-8 transcode + `Stream.Write` | Bottleneck is almost always the stream, not the crypto |
| `Equals(other)` | Two AES-GCM decrypts + `FixedTimeEquals` | ≈ 2× `Access` decrypt; constant-time over the longer length |
| `AppendChar(c)` | O(amortized 1) — write into the pinned build buffer | ns per call; geometric growth |
| `MakeReadOnly()` | One AES-GCM encrypt over the assembled plaintext | Sub-µs for credential-sized secrets |
| `Dispose()` | `CryptographicOperations.ZeroMemory` over ciphertext / nonce / tag | ns |

**Why `Equals` decrypts both sides instead of comparing hashes.** Storing a hash of the secret next to the ciphertext is a leak surface (see [Compared to `GuardedString`](#where-the-gap-matters)). `ProtectedString` decrypts under each instance's per-instance AAD and `FixedTimeEquals`'s the plaintext. The cost is two AES-GCM decrypts; the gain is no plaintext-derived material between calls. Hot login paths see this every credential check — for those, prefer `ComputeArgon2idHash` + `VerifyArgon2idHash` against a stored hash.

### Hardware-backed tier

Each `Access`, `Equals`, `AppendChar`, and `Copy` round-trips through `UnwrapKey` once per call. The round-trip dominates the operation cost on a hot path:

| Provider | Per-op round-trip |
| --- | --- |
| Apple Secure Enclave (M1+, T2 Macs) | ≈ 3 ms |
| Intel PTT / AMD fTPM (firmware TPM) | ≈ 1–3 ms |
| Discrete TPM 2.0 (Windows / Linux) | ≈ 5–15 ms |
| Android Keystore TEE | ≈ 50–500 ms (varies widely by device) |

For a per-request credential validation that goes through `Equals` or `Access`, the per-call wrap latency adds linearly; character-by-character builds pay it only once thanks to the `AppendChar` build buffer (see [API surface](#api-surface)).

`ProtectedStringOptions.UnwrappedKeyCacheTtl` opts in to a short-lived cache that holds the unwrapped master in pinned, locked, dump-excluded memory for at most the configured TTL — cuts per-op cost back to the default tier within the cache window. The trade-off is real: caching widens the window in which the unwrapped master sits in process memory beyond the in-flight `Access(...)` window the library already accepts. Default is `TimeSpan.Zero` (off) because there is no universally safe value.

### Argon2id (credential KDF)

Argon2id is **intentionally slow** — that is its job as a password KDF. At the OWASP-aligned defaults (see [API surface](#api-surface) for the parameters), expect tens to low hundreds of milliseconds per hash on commodity hardware. Tune via the explicit-parameter overload only if you understand the trade-off between attacker-cost and your own login-path latency.

The API is deliberately **synchronous-only**. An async shape (`ComputeArgon2idHashAsync`, awaiting the KDF instead of blocking) was prototyped — it is the only shape that could run on the single-threaded browser runtime — and then **rejected after an adversarial review**: the sync method holds the per-instance lock for the whole KDF, and releasing that lock across an `await` demonstrably regresses three security invariants (overlapping KDF-lifetime pinned scratch copies under page-granular, non-refcounted `VirtualLock`/`mlock`; the loss of "`Dispose` returned ⇒ no library-held plaintext copy exists"; and a stale-verify linearization race). Restoring those invariants requires a per-instance async gate plus deadlock guards — more concurrency machinery than a security-critical type should carry for one platform's benefit. Consequence: Argon2id **throws `PlatformNotSupportedException` on `net10.0-browser`** ([details](#browser-wasm-support)); hash credentials server-side in browser apps.

### Memory footprint

| State | Per-instance cost |
| --- | --- |
| `_ciphertext` | `Length` bytes, pinned on the POH |
| `_nonce` | 12 bytes, pinned |
| `_tag` | 16 bytes, pinned |
| Per-instance lock + 64-bit id | ≈ a few dozen bytes |
| Build buffer (only between first `AppendChar` and `MakeReadOnly`) | Geometric growth, capacity ≥ `Length`, pinned |

The 32-byte process master key plus its protector live once per process, regardless of how many `ProtectedString`s you allocate. Memory locking has a per-process budget on libc targets — see [Memory-locking policy](#memory-locking-policy) for the budget number and the failure-behaviour knob.

## Build & test

```
dotnet build
dotnet test
dotnet run --project TopSecret.Demo
```

The main library targets `net10.0;net10.0-android;net10.0-ios;net10.0-macos;net10.0-maccatalyst;net10.0-browser`. Tests run on [NUnit 4](https://nunit.org/) against the `net10.0` build:

- **`TopSecret.ProtectedString.Tests`** — the cross-platform suite covering the public API, build mode, both `Access` overloads, sinks, rotation, memory locking, AES-GCM wire-format compatibility between the in-box `AesGcm` and BouncyCastle (the `net10.0-browser` shim's primitives), and an API-table drift guard that asserts every public member of `ProtectedString` is mentioned in the README's `## API surface` section.
- **`TopSecret.ProtectedBlob.Tests`** — wire-format pinning (`WireFormatPinningTests` freezes the [wire format](#wire-format)), the tamper matrix (reorder / truncate / transplant / bit-flip), `FromStream` and chunk-boundary coverage, and an API-table drift guard against the README's ProtectedBlob API-surface table.
- **`TopSecret.ProtectedString.Analyzers.Tests`** — hosts `EscapingPlaintextAnalyzer` against in-memory C# snippets and asserts on the diagnostics it emits. Both expected violations (TPS001 / TPS002 must fire) and expected-clean code (no diagnostic) are exercised. Without this leg, analyzer regressions are invisible: a broken detection rule "just works" until a user writes the missed pattern.
- **`TopSecret.ProtectedString.WindowsTpm.Tests`** — Windows-only smoke suite (self-skips on non-Windows hosts and on Windows hosts without a TPM).
- **`TopSecret.ProtectedString.LinuxTpm.Tests`** — Linux smoke suite (self-skips on non-Linux hosts; on the Linux CI leg it runs against a `swtpm` software TPM 2.0 simulator for end-to-end coverage of the TSS.MSR call shape).

The SDK floor is **.NET 10 SDK 10.0.200** (`global.json` enforces it with `rollForward: latestFeature`, so any 10.0.2xx-or-newer SDK satisfies it). The 10.0.200 floor exists because the analyzer references `Microsoft.CodeAnalysis.CSharp` 5.3.0, and that requires the host compiler to be 5.3+ — which only ships in SDK 10.0.200+. A contributor on an older SDK gets a clean "SDK 10.0.200 not found" error at restore time instead of a cryptic CS9057 mid-build. See [Maintainer notes — version pins worth knowing](#maintainer-notes--version-pins-worth-knowing) for the full rationale. Building the platform TFMs requires the corresponding workloads (`dotnet workload install android ios macos maccatalyst wasm-tools`).

### CI matrix and runner availability

GitHub-hosted runners exist for **Windows, Linux, and macOS only** — not for iOS, Android, or browser WebAssembly. So three workflows split the build coverage along that line:

| Workflow | Trigger | Builds | Why |
| --- | --- | --- | --- |
| `ci.yml` | push / pull_request | `net10.0` on all three OSes; `net10.0-macos` and `net10.0-maccatalyst` on the macOS leg | These TFMs target platforms with native runners (Windows / Linux / macOS), so the CI compile-check is matched by the same OS we'd run tests on. The macOS leg is pinned to `macos-14` for stable Apple-Silicon SEP availability. Tests run, AOT publish dry-runs on Linux, TPM smoke suites on Windows and Linux. |
| `build-platform-tfms.yml` | manual (`workflow_dispatch`) | `net10.0-ios` (macOS), `net10.0-android` (Linux), `net10.0-browser` (Linux) | These TFMs target platforms with no GitHub-hosted runner. Building them is cross-compilation only — no test value beyond the compile-check — so they live behind a manual trigger to keep per-PR pipeline cost down. |
| `release.yml` | scheduled / `workflow_dispatch` | every TFM (`net10.0;net10.0-android;net10.0-ios;net10.0-macos;net10.0-maccatalyst;net10.0-browser`) on `macos-14` | Release-time build runs natively on the only runner that has every Apple SDK + the wasm-tools + android workloads. The published NuGet contains all six platform-specific binaries; running on `macos-14` is the path that produces them all. Also auto-promotes `AnalyzerReleases.Unshipped.md` rules into `Shipped.md` under the new version's heading before the build, so RS2007 doesn't fail the analyzer build. |

The `ci.yml` Linux leg additionally runs an AOT publish dry-run with warnings escalated to errors (catches IL2026 / IL2050 / IL3050 / transitive trim warnings before they ship), and the Linux TPM smoke tests run against a `swtpm` software TPM 2.0 simulator for end-to-end coverage of the TSS.MSR call shape.

### Release & publishing flow

`release.yml` produces five NuGet packages plus their `.snupkg` symbol packages:

| Package | Contents |
| --- | --- |
| `TopSecret.ProtectedString` | Cross-platform main library (six TFM-specific assemblies under `lib/`) plus the `EscapingPlaintextAnalyzer` Roslyn analyzer at `analyzers/dotnet/cs/`. |
| `TopSecret.ProtectedString.WindowsTpm` | Optional Windows TPM 2.0 wrapping subpackage. |
| `TopSecret.ProtectedString.LinuxTpm` | Optional Linux TPM 2.0 wrapping subpackage. |
| `TopSecret.ProtectedString.Configuration` | Optional `appsettings.json` binder — a single extension method (`BindProtectedStringOptions`) that wraps the `Enum.TryParse` / `TimeSpan.TryParse` boilerplate. Takes a single dependency on `Microsoft.Extensions.Configuration.Abstractions` so the main package stays dependency-minimal. |
| `TopSecret.ProtectedBlob` | Large-secret-blob sibling — chunked AES-GCM-256 envelope for multi-MB byte blobs, key wrapped under the shared process master (see [ProtectedBlob](#protectedblob-large-secret-blobs)). Bundles the same analyzer at `analyzers/dotnet/cs/`. |

Two packaging details worth knowing: all five packages share **one NuGet `README.md`** ([`docs/nuget/README.md`](docs/nuget/README.md) — pure markdown sized for the nuget.org landing page, since nuget.org strips raw HTML), while this root README stays the GitHub-only landing page. Icons are per-package — `assets/string/`, `assets/blob/`, and `assets/rest/` (see [Icon](#icon)).

Each release also redeploys the [live browser demo](https://alpaq92.github.io/TopSecret.ProtectedString/) via [`pages.yml`](.github/workflows/pages.yml).

The release-time pipeline:

1. **Decide whether to release.** Compare `HEAD` against the latest `v*.*.*` tag; skip if no new commits.
2. **Compute the next version.** `[major]` in the merge commit subject or `BREAKING CHANGE` in the body bumps major; a Dependabot NuGet merge bumps minor; everything else bumps patch.
3. **Promote analyzer rules to `Shipped.md`.** Move every entry from `AnalyzerReleases.Unshipped.md` into `AnalyzerReleases.Shipped.md` under a fresh `## Release vX.Y.Z` heading. Modifies files only — the commit lands in step 5.
4. **Generate `CHANGELOG.md` entry.** Extract commits since the previous tag (filtered: no merge commits, no `chore(release):` self-noise), format as a markdown section, prepend to `CHANGELOG.md` at the `<!-- AUTO-INSERT-RELEASES-BELOW -->` marker, write the same body to `release_notes.txt` for the pack step. Modifies files only.
5. **Commit & push the release-time file updates.** Single `chore(release): vX.Y.Z — promote analyzer rules + update CHANGELOG` commit covering steps 3 and 4, pushed to the workflow's branch. Without the push the tag we'll create later would point at a commit not on master, and the next release would re-promote the same rules and re-write the same changelog entry. Idempotent: a re-run on the same version with already-promoted rules is a no-op.
6. **Install workloads.** All five (`android ios macos maccatalyst wasm-tools`) — `macos-14` is the only runner where every install succeeds.
7. **Restore + build + test.** Standard `dotnet restore` / `dotnet build` / `dotnet test` against the whole solution.
8. **Pack.** `dotnet pack TopSecret.ProtectedString.sln` emits the five `.nupkg`s + `.snupkg`s into `./nupkg`. `Directory.Build.props` at the repo root reads `release_notes.txt` (written in step 4) and stamps its content into each `.nuspec`'s `<releaseNotes>` element with newlines preserved — so the changelog appears on each package's nuget.org landing page as a proper bullet list, not as `%0A`-encoded literal text.
9. **Verify package contents.** Lists every entry inside each `.nupkg` to the CI log. Catches mis-packs early — a TFM dropping out, the analyzer DLL not landing at `analyzers/dotnet/cs/`, an icon path getting renamed in the csproj.
10. **(Optional) Sign packages.** Commented-out scaffold step ready to enable once a code-signing certificate is procured. Adds an Author signature to each `.nupkg` before push; NuGet.org's Repository signature applies on top.
11. **Verify NuGet credentials.** Fail with a clear message if the `NUGET_API_KEY` secret is empty or unset, before sending an empty header that NuGet.org would 401 on.
12. **Push to NuGet.org.** Glob over `./nupkg/*.nupkg`; `dotnet nuget push` auto-detects each `.snupkg` symbol package alongside the matching `.nupkg` and uploads both. `--skip-duplicate` makes the step retry-safe if a partial push has to be resumed.
13. **Tag and create GitHub Release.** Push `vX.Y.Z`; attach all `.nupkg` + `.snupkg` files to the GitHub Release page; populate the release-notes body from `release_notes.txt` so the GitHub Release page, `CHANGELOG.md`, and each package's `<releaseNotes>` all show the same text generated from one source.

> **Migrating to NuGet.org trusted publishing (OIDC).** NuGet.org launched federated identity for GitHub Actions in 2024 — push without a long-lived API key, using a short-lived token GitHub mints for each workflow run. Setup: configure a trusted-publisher policy on the package's NuGet.org settings page, add `permissions: id-token: write` to the workflow, fetch a federated token, and replace `--api-key ${{ secrets.NUGET_API_KEY }}` with the token. The current setup retains the API-key path for backward compatibility with existing repo secrets; the comment on the push step in `release.yml` calls out the migration steps for whenever the maintainer wants to rotate.

### Mobile support (`net10.0-ios` / `net10.0-android`)

**Current shape: build-verified, end-to-end device testing pending.**

What is verified:

- The `net10.0-ios`, `net10.0-android`, `net10.0-macos`, and `net10.0-maccatalyst` TFMs **compile** on a real Apple toolchain — `release.yml` runs on `macos-14` (Apple Silicon) with the `ios`, `macos`, `maccatalyst`, `android`, and `wasm-tools` workloads installed. A manual `build-platform-tfms.yml` run does the same compile-check on demand.
- `<IsAotCompatible>true</IsAotCompatible>` and `<IsTrimmable>true</IsTrimmable>` are set on every TFM **except `net10.0-browser`** (BouncyCastle is not yet trim/AOT clean — see [`browser-wasm` support](#browser-wasm-support)), so the Roslyn AOT analyzers (IL2026 / IL2050 / IL3050 / etc.) fire at build time and catch reflection-without-preserved-metadata, dynamic-code, and trim-unsafe patterns on the iOS/Android paths. CI also runs `dotnet publish -p:PublishAot=true` against the Demo on `linux-x64`, exercising the IL→native compilation path on every PR — partial coverage of what the iOS/Android AOT compilers would do.
- The Apple Secure Enclave probe (`AppleSecKeyProtector.IsActuallyAvailable`) and the `AndroidKeystoreProtector` JNI shim are unit-tested against the cross-platform fixture; the SEP probe self-skips on hosts without a Secure Enclave (see [Apple SEP availability](#apple-sep-availability)).

What is **not** yet verified:

- **No end-to-end run on a real iOS or Android device in CI.** GitHub-hosted runners don't exist for these platforms — see [CI matrix and runner availability](#ci-matrix-and-runner-availability). Native AOT behaviour, finalizer semantics on Mono/iOS, real Secure Enclave round-trips, and Android Keystore TEE behaviour are all inferred from the cross-platform suite + analyzer warnings, not from continuous observation on hardware. Mitigated, not closed: before tagging a major or security-relevant release, the maintainer runs a [one-off manual check on a borrowed/owned device](CONTRIBUTING.md#before-a-major-or-security-relevant-release-a-manual-device-check) — cheap and non-scaling, but it catches gross breakage a desktop-only suite can't.
- **The security claims in [Security model](#security-model) — pinned wipes, JIT-resistant zeroing, finalizer behavior — should be re-audited on real iOS / Android hardware before relying on this library in a mobile production app.** Specifically: Mono's GC (used on iOS) has different pinning semantics than CoreCLR's POH; `CryptographicOperations.ZeroMemory` is documented to be JIT-resistant on CoreCLR but the Mono guarantee is less explicit; finalizers on iOS have run-order quirks under Mono.

If you're shipping to mobile in production, run this library's test suite (and ideally a fuzz harness over `AppendChar` / `Access`) on real hardware via a device-farm CI step (AWS Device Farm, Firebase Test Lab, or BrowserStack App Automate) before relying on the in-process secrecy claims — the manual pre-release check above is a maintainer-side spot-check, not a substitute for your own continuous validation. Issues observed there are a known coverage gap; reports and patches welcome.

### `browser-wasm` support

`net10.0-browser` is supported via a conditional dependency on [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography), which provides a pure-managed AES-GCM-256 implementation (`GcmBlockCipher`
+ `AesEngine`) for the platform where `System.Security.Cryptography.AesGcm.IsSupported` is `false` and `new AesGcm(...)` throws `PlatformNotSupportedException`. BouncyCastle is referenced **only** for the `net10.0-browser` TFM — consumers on every other platform pay no size cost.

The wire format agrees with the in-box `AesGcm` exactly, so the [Security model](#security-model) holds on browser as on every other platform. The cross-platform test suite includes `AesGcmShimWireFormatTests`, which encrypts under the in-box `AesGcm` and decrypts under BouncyCastle (and vice versa), asserts both implementations produce byte-identical ciphertext and tag for the same key/nonce/AAD/plaintext, and exercises wrong-AAD / tampered-ciphertext rejection on the BC side. The shim's BC path is a thin marshal between `ReadOnlySpan` and BC's byte-array API, so wire-format equivalence plus the rest of the cross-platform suite (which exercises the `AesGcm`-on-`net10.0` path end-to-end) covers the browser path's correctness without needing a wasm test runner.

Caveats specific to the browser path:

- **Argon2id is not supported in the browser — deliberately.** Konscious (the managed Argon2 underneath) has no truly synchronous path: its sync `GetBytes` is `Task.Run(...).Result`, which cannot complete on the single-threaded WASM runtime — `.Result` blocks the only thread, and the queued lane work needs that very thread ([Konscious #22](https://github.com/kmaragon/Konscious.Security.Cryptography/issues/22)). The library fails fast and honestly: `ComputeArgon2idHash` / `VerifyArgon2idHash` **throw `PlatformNotSupportedException` on `net10.0-browser`**, and the live demo's Argon2id step reports itself unsupported there. An awaited async wrapper (which *would* complete on one thread) was prototyped and adversarially reviewed, then **rejected**: releasing the instance lock across the KDF `await` regresses the sync path's security invariants — overlapped hashes multiply long-lived pinned plaintext scratch copies (page-granular `mlock`/`VirtualLock` is not refcounted and the `RLIMIT_MEMLOCK` budget is small), `Dispose` stops being a barrier proving no library-held plaintext remains, and verify/mutate interleavings can accept a stale credential — and the gate-and-guard machinery needed to restore them adds more concurrency surface to a security-critical type than one platform's KDF is worth. Browser guidance: verify credentials **server-side** (where they should be verified anyway); the alternatives were also evaluated and rejected — Isopoh (CC0 license), Soenneker (wraps the same Konscious), NSec (native libsodium, no `browser-wasm` RID). Revisit if .NET's multithreaded WASM lands or a permissively-licensed, browser-safe managed Argon2 appears.
- **Memory locking is a no-op — no browser API or WASI proposal offers an `mlock` equivalent, and libsodium hits the identical wall.** `mlock` / `VirtualLock` aren't reachable from inside the WebAssembly sandbox — browsers deliberately expose no API letting page code influence OS paging (a real capability search turned up nothing: no JS API, no WASI `mlock`/`madvise` proposal), so `MemoryLocker` degrades to "best effort" (its existing `try { ... } catch { return false; }` probe path). This isn't a gap unique to this library: libsodium's own [`sodium_mlock`](https://github.com/jedisct1/libsodium/blob/master/src/libsodium/sodium/utils.c) returns `-1`/`ENOSYS` on the identical unsupported-platform case — fail-closed and let the caller/policy decide, exactly what `MemoryLocker` already does. The threat model on browser is "don't let secrets escape the WASM module" rather than "don't let secrets be paged out." One honest precision, though: that is not quite "there is no swap to leak to" — a browser tab's WASM linear memory is ordinary OS-owned process memory, and on a desktop OS under real memory pressure it *can* still be paged to disk like any other process's pages; WASM gets no exemption. What actually protects you is narrower than "impossible": foreground tabs are heavily deprioritized for eviction by both OS heuristics and the browser's own tab-discard logic, and this library's plaintext buffers typically live only microseconds inside an `Access` callback. The honest claim is "no mechanism to request or verify non-pageable memory, and a live foreground tab's working set is rarely swapped in practice" — not a hard guarantee.
- **`<IsAotCompatible>` is suspended on `net10.0-browser` only.** BouncyCastle is not yet trim/AOT clean. The wasm runtime AOT-compiles to native WebAssembly via the `wasm-tools` workload independently of the IL-level trimmer, so this does not affect the user-visible AOT story on browser.
- **Hardware-backed wrap is unavailable.** No SEP, no Keystore, no TPM on the browser. `KeyAtRestProtection.HardwareBackedRequired` throws on construction; `HardwareBackedPreferred` falls through to the obscurity tier (HKDF stream-XOR), then to the no-op tier — same as any other platform without a hardware-backed provider registered.
- **BouncyCastle holds three of its own non-zeroable copies, shrunk-but-not-eliminated by forcing an early collection.** The shim allocates pinned `byte[]` for the key, nonce, AAD, and plaintext / ciphertext buffers and zeros each one in a `finally` block. But (verified against BC's own source, not just inferred) `KeyParameter`'s constructor *copies* the key bytes rather than holding our array by reference, and `AesEngine` / `GcmBlockCipher` separately derive the expanded AES round-key schedule and the GHASH subkey into their own fields — three independent copies, none reachable or wipeable through any public BC API. Since `mlock` isn't an option here at all (see above), the shim's only remaining lever is object lifetime: it drops every reference to the BC objects and forces a Gen0 `GC.Collect` immediately after wiping its own buffers, so those three copies become unreachable — and their memory eligible for reuse — as soon as possible, rather than whenever the runtime next happens to collect on its own. This is a real trade: it costs a blocking collection on every AES-GCM call and it does **not** zero the underlying bytes (the CLR doesn't clear reclaimed memory), so a raw memory scan could still recover them until the space is overwritten by a later allocation — it only narrows the window during which they're reachable from a live object graph. The residue lives in the WASM linear memory (not paged to disk, sandboxed from other origins), so it does not leak across origins or to disk; if your threat model is stricter than that, do not rely on the browser-wasm TFM.

## Configuration binding from `appsettings.json`

Every static property on `ProtectedStringOptions` can be set from a `Microsoft.Extensions.Configuration` source. Two paths:

### Option 1 — the companion package (one line, recommended)

```
dotnet add package TopSecret.ProtectedString
dotnet add package TopSecret.ProtectedString.Configuration
```

```csharp
using TopSecret;

// In your composition root, before the first ProtectedString is constructed:
configuration.BindProtectedStringOptions();
```

By default the binder reads the `TopSecret:ProtectedString` section. Pass an explicit section if your layout differs:

```csharp
ProtectedStringConfigurationExtensions.BindProtectedStringOptions(
    configuration.GetSection("Crypto:Options"));
```

The companion package takes a single dependency (`Microsoft.Extensions.Configuration.Abstractions`) — the main `TopSecret.ProtectedString` package stays dependency-minimal so consumers who don't want `appsettings.json` integration pay nothing.

### Option 2 — manual binding (zero extra dependency)

If you'd rather not take the companion package, paste an `Enum.TryParse` / `TimeSpan.TryParse` block into your composition root — one `if` per option, written against `ProtectedStringOptions.*`:

```csharp
if (Enum.TryParse<KeyAtRestProtection>(
        configuration["TopSecret:ProtectedString:KeyAtRestProtection"],
        ignoreCase: true, out var protection))
{
    ProtectedStringOptions.KeyAtRestProtection = protection;
}
// ... repeat for UnwrappedKeyCacheTtl, MemoryLockingFailureBehavior,
//     ProcessKeyRotationPolicy, ProcessKeyRotationInterval.
```

Both paths use skip-on-missing, **warn-on-malformed** semantics — a typo in `appsettings.json` keeps the property's current value and emits a one-shot [`Trace.TraceWarning`](#diagnostics) (companion package only; the manual block is silent unless you add the warning yourself). The companion package is exactly this code, packaged.

### Hot-reload semantics

`IConfiguration` providers can fire reload tokens (e.g. `appsettings.json` edits at runtime). Whether a re-bind takes effect depends on which key changed:

| Key | When the new value takes effect |
| --- | --- |
| `ProcessKeyRotationPolicy` | Next `ProtectedString` construction. Pre-existing instances aren't retroactively enrolled in the rotation registry — switching from `Disabled` to `OnDemand` only affects instances created after the re-bind. |
| `MemoryLockingFailureBehavior` | Next memory-locking attempt that fails. The policy is consulted on every fault, so live processes pick up changes without a restart. |
| `KeyAtRestProtection` | **Never on a live process** — read once at the lazy initialisation of the process protector. Call [`ProtectedString.RotateProcessKey()`](#process-key-rotation-opt-in) to swap protectors at runtime under the new option values. |
| `UnwrappedKeyCacheTtl` | **Never on a live process** — same lazy-init point as `KeyAtRestProtection`. |
| `ProcessKeyRotationInterval` | **Never on a live process** if the periodic timer has already started; takes effect on first `ProcessKeyRotationPolicy = Periodic` construction if not. |

The library emits a one-shot [`Trace.TraceWarning`](#diagnostics) the first time a read-once option is mutated late — but only if a `TraceListener` is attached. **Practical guidance:** bind once in your composition root *before* any `ProtectedString` is constructed and treat the read-once keys as static configuration; reserve hot-reload for `ProcessKeyRotationPolicy` and `MemoryLockingFailureBehavior` if you want runtime adjustability.

### Why static, not `IOptions<T>`?

`ProtectedStringOptions` is a static class because the AES master key it gates is **process-wide by design**: every `ProtectedString` in the process shares the same master, and `RotateProcessKey()` rotates that single master globally. A scope-aware options pattern would imply per-scope cryptographic state, which the library deliberately does not support. For genuine per-tenant secret isolation, run separate processes (or separate `AppDomain`s on legacy .NET Framework). The companion package's `BindProtectedStringOptions` is therefore explicit that it sets process-wide statics, rather than masquerading as a scope-friendly options binding.

## FAQ

#### 1. When is `ProtectedString` the right tool, and why should I use it?

When you have a credential — a password, token, API key, or signing key — that has to **live across** an `await`, a request, or a process-wide cache. Anything sized like a credential, held longer than a single synchronous span.

It encrypts the value at rest in process memory on every supported platform (including non-Windows, where `SecureString` does not), `mlock`s the buffers so the OS won't page them to disk, wipes on `Dispose`, survives [process-key rotation](#process-key-rotation-opt-in) without invalidating live instances, and ships a [build-time analyzer](#build-time-analyzer-tps001--tps002) that fails the build when plaintext escapes into a managed `string`. See [Security model](#security-model) for the full picture.

#### 2. When ProtectedString is the wrong tool

`ProtectedString` is sized for credentials — passwords, tokens, API keys, signing keys. Two cases where it is not the right pick:

- **Bulk data (multi-MB blobs).** Every `Access` decrypts the whole buffer; per-op cost scales linearly with length, and large secrets may exceed the locked-memory budget (see [Memory-locking policy](#memory-locking-policy)). This is exactly what [`TopSecret.ProtectedBlob`](#protectedblob-large-secret-blobs) ships for — chunked AES-GCM over unpinned ciphertext, with the per-blob key wrapped under the same process master. Reach for it instead of hand-rolling a streaming envelope.
- **Per-request scope.** The encryption / decryption cost is small but not zero. If a secret is constructed and consumed once per request and never crosses an await/threadpool boundary, a `Span<char>` on the request's local stack is simpler. Reach for `ProtectedString` when the secret has to **live across** an await, a request, or a process-wide cache.

#### 3. Can I serialize a `ProtectedString`?

No, by design. Send the plaintext under TLS to a fresh `ProtectedString` on the other side instead — see [Compared to `GuardedString`](#compared-to-guardedstring) for why the "known default key" approach is a footgun this library avoids.

#### 4. Can I store a `ProtectedString` as a DI singleton?

Yes — that's the intended shape for long-lived secrets like API tokens. The encrypted state lives for the lifetime of the instance, operations are thread-safe (per-instance lock), and [process-key rotation](#process-key-rotation-opt-in) re-encrypts every live instance under a fresh master without invalidating the singleton. Don't register it as `Transient` for a long-lived secret — you'd allocate one per resolution and leave the previous instances to the finalizer.

#### 5. What happens if I `await` inside `Access`?

The `ReadOnlySpan<char>` overload makes it a **compile error** — the ref-struct cannot cross `await`, so the wipe-on-return window can't be widened across a suspension point. If you need async work with the plaintext, transform it inside the callback (HMAC, encrypt, stream write) and let the async code work with the derived bytes.

#### 6. Do I need to call `Dispose` if I use `using`?

`using var ps = new ProtectedString(...)` already calls `Dispose` at scope exit, which zeros the ciphertext, nonce, tag, and any in-flight build buffer. The `using` form is the recommended shape for short-lived instances. For long-lived singletons (a stored API key that lives for the process lifetime), the finalizer covers the case where the host shuts down without an explicit `Dispose` — but explicit `Dispose` from `IHostApplicationLifetime.ApplicationStopping` or your DI container's disposal callback is preferred, because finalizer timing is non-deterministic.

#### 7. Can I share a `ProtectedString` across threads?

Yes. Every operation takes a per-instance lock and is safe under concurrent calls. `Equals` between two instances acquires both locks in monotonic-id order, so concurrent `a.Equals(b)` and `b.Equals(a)` cannot deadlock. If you want an independent writable copy (e.g. so two threads can mutate separate secrets without contending on one lock), use `Copy()`.

#### 8. Why does `GetHashCode` return only the length?

Because a content-derived hash leaks bits about the secret — see [Compared to `GuardedString`](#where-the-gap-matters) for the full argument. Trade-off: a `Dictionary<ProtectedString, T>` will bucket-collide on length, so use a separate `Guid` / `string` key for hot-path lookups.

#### 9. What happens if I require hardware-backed (TPM) protection on a platform that doesn't support it?

This is configurable today via [`KeyAtRestProtection`](#key-at-rest-wrapping-opt-in-tiered):

- **`HardwareBackedRequired` fails closed** — the first `ProtectedString` construction throws `PlatformNotSupportedException`, deliberately ignoring `MemoryLockingFailureBehavior`: silently downgrading a hard security request would defeat the point of requesting it.
- **`HardwareBackedPreferred` falls back** — hardware → obscurity → none, silently apart from the one-shot [trace warning](#diagnostics).

To branch deliberately instead of failing or silently degrading, probe `ProtectedString.HardwareBackedAvailability` in your composition root and pick the policy (or a different secret store) per host.

#### 10. How do I read a password from the console without it touching a `string`?

Use `Console.ReadKey(intercept: true)` in a loop and `AppendChar`:

```csharp
using var pw = new ProtectedString();
while (true)
{
    var k = Console.ReadKey(intercept: true);
    if (k.Key == ConsoleKey.Enter) break;
    if (k.Key == ConsoleKey.Backspace) continue; // or pop a char if you track length
    pw.AppendChar(k.KeyChar);
}
pw.MakeReadOnly();
```

The `KeyChar` is a `char`, not a `string`, so no managed-string copy ever materialises. Don't use `Console.ReadLine()` — it returns a `string`, and you've lost.

#### 11. How safe is `new string(plain)` inside `Access`?

Materializing a `string` inside `Access` is the **best** the library can do at a string-only boundary, but strictly weaker than the streaming sinks (`WriteUtf8To`, `CopyTo`). What you give up:

- **The `string` lives on the regular managed heap** — not in pinned/locked/dump-excluded memory. The GC may relocate (and therefore *copy*) the backing buffer during compaction, leaving a bit-for-bit copy of the secret in the old location until that region is overwritten. Pinned-buffer guarantees end the moment you call `new string(plain)`.
- **You cannot wipe a `string` reliably.** `string` is immutable as far as the runtime contract goes. Even with `unsafe` + `MemoryMarshal.AsMemory<char>(s)`, the JIT may have folded reads, the BCL may have cached derived values (header parsing, hash codes), and a string that was ever interned cannot be wiped at all.
- **The window is "until the next GC of its generation."** Gen0 is frequent under load but not immediate; under `<ServerGarbageCollection>true</ServerGarbageCollection>` and a quiet process, an out-of-scope string can sit on the heap for seconds.
- **The BCL may copy further.** `AuthenticationHeaderValue`, `HttpHeaders.TryAddWithoutValidation`, and the HTTP/2 / HTTP/3 encoders all serialise headers into their own buffers — those copies are out of your reach.

What you do get by keeping the string narrow: the `ProtectedString` itself stays encrypted at rest between uses, the `string` is unreachable as soon as the surrounding scope exits, and a heap dump captured *between* operations sees only ciphertext.

#### 12. My analyzer is firing TPS001 / TPS002. How do I tell what's wrong?

The most common cause is `new string(plain)` or `plain.ToString()` inside an `Access` callback — the resulting `string` is on the heap, unwipeable, and visible to a heap dump. Replace it with a `Span<char>` sink (`CopyTo`, `WriteUtf8To`) or transform the data inside the callback. See [Build-time analyzer](#build-time-analyzer-tps001--tps002) for the full trigger list and unavoidable-boundary suppressions.

## Development

This library was built with an audit-driven workflow assisted by an AI pair programmer. Every security claim in [Security model](#security-model) was cross-checked against the primary sources cataloged in [References](#references) — RFC 9106, the OWASP Password Storage Cheat Sheet, the relevant `dotnet/runtime` issue threads, and the original Stack Overflow discussion that named the class — and the implementation was iterated against that bibliography rather than from memory. The AI's role was to surface citations, challenge invariants, and keep the README honest about what the library cannot do; design decisions and the code itself were authored and reviewed by hand.

### Maintainer notes — version pins worth knowing

- **`Microsoft.CodeAnalysis.CSharp` in the analyzer project is pinned to a Roslyn version that requires a matching SDK floor.** An analyzer that references a *newer* Roslyn than the host compiler fails to load with `CS9057` ("analyzer references compiler version X newer than running version Y"), breaking every consumer's build. Current pin: **5.3.0**, which requires the host compiler to be 5.3.x or newer — that ships in **.NET SDK 10.0.200+**. The repo's `global.json` is set to `"version": "10.0.200"` with `rollForward: latestFeature`, so a contributor on SDK 10.0.1xx gets a clear "SDK 10.0.200 not found" error at restore time instead of a cryptic CS9057 mid-build. Consumers of the published NuGet must also be on SDK 10.0.200+ for the analyzer to load. Bumping the Roslyn pin past 5.3.x requires a corresponding SDK-floor bump and a major-version release of this package (consumer-breaking change). **Enforced by `.github/dependabot.yml`**, which ignores `version-update:semver-minor` and `version-update:semver-major` bumps for that package — patch bumps inside the pinned major.minor still propose PRs.
- **Analyzer release-tracking files** (`AnalyzerReleases.Shipped.md`, `AnalyzerReleases.Unshipped.md`) are auto-promoted by `release.yml`. The runbook is in `AnalyzerReleases.Unshipped.md`'s header comment. Never hand-edit `Shipped.md` after a release lands; only add new rules to `Unshipped.md`.
- **`coverlet.msbuild` requires re-building** (no `--no-build`) because instrumentation runs at build time. CI's coverage step is ordered last on the Linux leg specifically so the instrumented binaries don't affect downstream test steps. If you reorder, keep it last.

## Inspiration

- The API and overall design are inspired by Evolveum's [`GuardedString`](https://github.com/Evolveum/openicf/blob/master/framework/java/connector-framework/src/main/java/org/identityconnectors/common/security/GuardedString.java) from the OpenICF / ConnId connector framework — in particular the encrypted-at-rest buffer, the callback-based access pattern, and the `appendChar` / `makeReadOnly` shape. This project is an independent reimplementation in C#; no code was copied. The original is licensed under CDDL. See [Compared to `GuardedString`](#compared-to-guardedstring) for a side-by-side of where the implementations agree and where they diverge.

- The Stack Overflow thread [*How to protect strings without `SecureString`?*](https://stackoverflow.com/questions/55590869/how-to-protect-strings-without-securestring) shaped the design directly:
  - **Ian Boyd's answer** splits `SecureString`'s job into two pillars (`SecureZeroMemory`-style wiping + `CryptProtectData`-style encryption at rest) and his comment proposes a class that *"stores the string in unmanaged memory"* and *"encrypts it with `CryptProtectMemory`"*, naming it `ProtectedString`. This project takes that proposal cross-platform: pinned managed memory (POH) instead of unmanaged, and `AesGcm` instead of `CryptProtectMemory`.
  - **Dai's answer** points out the safe-input pattern — read the secret one keystroke at a time directly into the secure container — which is what `AppendChar` is for here.
  - **Patrick Hofman**, **nvoigt**, and **Panagiotis Kanavos** make the honest counter-points (homebrew vs Microsoft, certs over credentials, "all bets are off" at the moment of use). Those quotes are cited inline where they bear on specific design choices — see [Interop with string-only APIs](#interop-with-string-only-apis) and [What this library does **not** do](#what-this-library-does-not-do-and-why).

## References

References used while auditing this implementation. Everything beyond *"this encrypts at rest in process memory"* in the [Security model](#security-model) section is grounded in one of these.

### `SecureString` deprecation context

- [Microsoft Learn — `System.Security.SecureString`](https://learn.microsoft.com/en-us/dotnet/fundamentals/runtime-libraries/system-security-securestring) — the official "don't use this for new code" page.
- [dotnet/runtime #30612 — Obsolete the `SecureString` type](https://github.com/dotnet/runtime/issues/30612) — the canonical issue, with the .NET team's reasoning.
- [.NET platform-compat DE0001 — `SecureString` shouldn't be used](https://github.com/dotnet/platform-compat/blob/master/docs/DE0001.md) — the formal deprecation analyser entry.
- [The Security Vault — *Breaking C# `SecureString`*](https://thesecurityvault.com/breaking_c_sharp_securestring/) — practical demonstration of why `SecureString` doesn't keep secrets out of memory dumps.

### Pinned memory, secret zeroing, and POH allocation

- [Geralt — *Secure memory in .NET*](https://www.geralt.xyz/secure-memory) — the reference write-up for the `GC.AllocateArray<>(pinned: true)` + `CryptographicOperations.ZeroMemory` pattern this library uses.
- [dotnet/runtime #48697 — *Can `Array.Clear()` be used to zero out sensitive byte arrays?*](https://github.com/dotnet/runtime/discussions/48697) — runtime-team discussion that establishes why `Array.Clear` is *not* a guaranteed wipe and `CryptographicOperations.ZeroMemory` is.
- [dotnet/runtime #27146 — *A new GC API for large array allocation*](https://github.com/dotnet/runtime/issues/27146) — design discussion behind `GC.AllocateArray<>(pinned: true)` and the pinned object heap.
- [`GC.AllocateArray<T>(Int32, Boolean)` — Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.gc.allocatearray) — reference docs.

### Memory locking (`mlock`) on unsupported platforms

- [libsodium — `sodium_mlock` / `sodium_munlock` (`src/libsodium/sodium/utils.c`)](https://github.com/jedisct1/libsodium/blob/master/src/libsodium/sodium/utils.c) — the most mature, widely-audited library with this exact primitive hits the identical wall on a platform with neither `mlock` nor `VirtualLock` (Emscripten/WASM included): it returns `-1` / `ENOSYS` rather than silently no-opping into "success." `MemoryLocker.TryLock` returning `false` on `net10.0-browser` is the same fail-closed shape, not an improvised shortcut — see [`browser-wasm` support](#browser-wasm-support).
- [WebAssembly/WASI](https://github.com/WebAssembly/WASI) — the WebAssembly System Interface (for non-browser WASM hosts) has no `mlock`/`madvise`-equivalent proposal; moot for `net10.0-browser` anyway, since that TFM runs inside an actual browser JS engine, not a WASI host.

### AES-GCM, its strengths, and its sharp edges

- [Scott Brady — *Authenticated Encryption in .NET with AES-GCM*](https://www.scottbrady.io/c-sharp/aes-gcm-dotnet) — practical guide to using `AesGcm` correctly in .NET.
- [Soatok — *Why AES-GCM Sucks*](https://soatok.blog/2020/05/13/why-aes-gcm-sucks/) — honest critique of AES-GCM's failure modes (cache-timing on non-AES-NI hardware, nonce-reuse fragility).
- [AquilaX — *Cryptographic Implementation Vulnerabilities (AES-GCM nonce reuse, timing)*](https://aquilax.ai/blog/cryptographic-implementation-vulnerabilities) — concrete failure cases to avoid.
- [NIST CSRC — *Practical Challenges with AES-GCM*](https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/Practical%20Challenges%20with%20AES-GCM.pdf) — academic perspective on AES-GCM limits.

### Password hashing (Argon2id)

- [Password Hashing Competition](https://www.password-hashing.net/) — the open competition (2013–2015) that selected Argon2 as the recommended password-hashing algorithm.
- [`p-h-c/phc-winner-argon2`](https://github.com/p-h-c/phc-winner-argon2) — the reference C implementation maintained by the Argon2 designers.
- [RFC 9106 — *Argon2 Memory-Hard Function for Password Hashing*](https://datatracker.ietf.org/doc/html/rfc9106) — the algorithm specification.
- [OWASP — *Password Storage Cheat Sheet*](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — current recommended Argon2id parameters (the source of this library's defaults).
- [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography) — the .NET Argon2id implementation this library depends on.

## Repository layout

```
TopSecret.ProtectedString/                       # main cross-platform library (NuGet)
TopSecret.ProtectedString.Analyzers/             # Roslyn analyzer (TPS001 / TPS002), packed into the main NuGet
TopSecret.ProtectedString.Configuration/         # optional appsettings.json binder subpackage (NuGet)
TopSecret.ProtectedString.WindowsTpm/            # optional Windows TPM 2.0 subpackage (NuGet)
TopSecret.ProtectedString.LinuxTpm/              # optional Linux TPM 2.0 subpackage (NuGet)
TopSecret.ProtectedBlob/                         # large-secret-blob sibling package — chunked AEAD (NuGet)
TopSecret.ProtectedBlob.Tests/                   # NUnit tests: wire-format pinning, tamper matrix, API drift guard
TopSecret.ProtectedString.Tests/                 # NUnit 4 cross-platform tests + API-table drift guard
TopSecret.ProtectedString.Analyzers.Tests/       # NUnit 4 analyzer detection-rule tests (hosts the analyzer in-memory)
TopSecret.ProtectedString.Configuration.Tests/   # NUnit 4 configuration-binding tests
TopSecret.ProtectedString.WindowsTpm.Tests/      # NUnit 4 Windows-only smoke tests
TopSecret.ProtectedString.LinuxTpm.Tests/        # NUnit 4 Linux-only smoke tests
TopSecret.Demo.Core/                             # shared demo scenarios + DemoTests + the in-process NUnit runner (net10.0 library)
TopSecret.Demo/                                  # runnable console demo host (the .slnLaunch sets this as the default startup project)
TopSecret.Demo.Wasm/                             # browser demo host: Demo.Core in xterm.js on .NET WebAssembly, deployed to GitHub Pages per push (not in the .sln — needs wasm-tools)
docs/nuget/                                      # the single shared NuGet README packed into all five packages
TopSecret.ProtectedString.sln
TopSecret.ProtectedString.slnLaunch              # committed VS launch profile pinning the Demo project
Directory.Build.props                            # release-time PackageReleaseNotes injection (reads release_notes.txt when the file exists)
CHANGELOG.md                                     # auto-generated from commit log by the release workflow
assets/string/                                   # icon assets for TopSecret.ProtectedString (icon.svg / icon.png)
assets/blob/                                     # icon assets for TopSecret.ProtectedBlob
assets/rest/                                     # icon assets shared by the .WindowsTpm / .LinuxTpm / .Configuration satellites
```

The two front-line packages pack the focused `README.md` sitting in their own project folders; the satellite packages pack this root README — see [Release & publishing flow](#release--publishing-flow).

## Icon

All three package icons (`icon.svg` / `icon.png` per assets folder) share the same composition: the [`shield`](https://pictogrammers.com/library/mdi/icon/shield/) glyph from [Material Design Icons](https://pictogrammers.com/library/mdi/) (the Pictogrammers community fork) with the [`alpha-t`](https://pictogrammers.com/library/mdi/icon/alpha-t/) glyph from the same library overlaid as the "T" — both licensed under the [Apache License 2.0](https://github.com/Templarian/MaterialDesign/blob/master/LICENSE). In each icon the "T" carries a white→soft-tint gradient running top-left to bottom-right, matching the shield's light direction so the letter reads with the same sense of depth as the background.

What differs per package is the palette, each borrowed from the [Jellyfin project](https://commons.wikimedia.org/wiki/Category:Jellyfin)'s icon family:

| Assets | Used by | Shield gradient | "T" tint |
| --- | --- | --- | --- |
| `assets/string/` | `TopSecret.ProtectedString` (main package) | Purple→blue (`#AA5CC3` → `#00A4DC`) — Jellyfin's main icon colours. | `#FFFFFF` → `#BFD9E8` |
| `assets/blob/` | `TopSecret.ProtectedBlob` | Red→gold (`#F2364D` → `#FDC92F`) — from Jellyfin's dev icon ([`Jellyfin_-_icon-solid-dev.svg` on Wikimedia Commons](https://commons.wikimedia.org/wiki/Category:Jellyfin#/media/File:Jellyfin_-_icon-solid-dev.svg), CC BY-SA 4.0, © the Jellyfin contributors). | `#FFFFFF` → `#F0DFB0` |
| `assets/rest/` | The `.WindowsTpm` / `.LinuxTpm` / `.Configuration` satellite packages | Green→slate (`#41B883` → `#34495E`) — from Jellyfin's vue icon ([`Jellyfin_-_icon-solid-vue.svg` on Wikimedia Commons](https://commons.wikimedia.org/wiki/Category:Jellyfin#/media/File:Jellyfin_-_icon-solid-vue.svg), CC BY-SA 4.0, © the Jellyfin contributors). | `#FFFFFF` → `#C3D4CC` |

The Jellyfin colours are used only as a palette reference; this project is not affiliated with or endorsed by Jellyfin.

## License

[MIT](LICENSE). Third-party material this project incorporates, builds on, or cites is catalogued in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
