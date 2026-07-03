# TopSecret.ProtectedBlob

Multi-megabyte secret **byte** blobs, encrypted at rest in process memory — the bulk-data companion to [`TopSecret.ProtectedString`](https://www.nuget.org/packages/TopSecret.ProtectedString).

```
dotnet add package TopSecret.ProtectedBlob
```

## Why a separate type?

`ProtectedString` is sized for credentials: every access decrypts the whole value, and its buffers are pinned and `mlock`ed — per-process locked-memory budgets make that the wrong shape for bulk data. `ProtectedBlob` inverts the layout: the bulk **ciphertext lives in ordinary memory** (ciphertext leaks nothing if paged or dumped), and only the ~60-byte wrapped key envelope and a one-chunk read scratch get the pinned+locked+wiped treatment. Blob size stops mattering to your `RLIMIT_MEMLOCK` budget.

## Quick start

```csharp
using TopSecret;

// Wrap bytes (encrypted chunk-by-chunk straight from your span)…
using var blob = new ProtectedBlob(modelWeights.AsSpan());

// …or stream unknown-length input: plaintext residency never exceeds two chunks.
using var fromStream = ProtectedBlob.FromStream(uploadStream);

// Read sequentially, one decrypted chunk at a time (ref-struct span, wiped after).
blob.AccessChunks(chunk => hasher.AppendData(chunk));

// Chunk-granular random access, whole-blob copy, or streaming out.
var n = blob.AccessChunk(0, chunk => chunk.Length);
blob.CopyTo(destinationBuffer);
blob.WriteTo(destinationStream);
```

## What you get

- **AES-GCM-256 in 64 KiB chunks** (configurable 4 KiB–1 MiB via constructor or `ProtectedBlobOptions.DefaultChunkSize`).
- **Fail-closed integrity** (libsodium `secretstream` pattern): bit flips, chunk reordering, truncation, and cross-blob chunk transplants all throw `CryptographicException` — never wrong plaintext. An empty blob is still one authenticated chunk.
- **One key posture with `ProtectedString`**: each blob's random 256-bit key is wrapped under the same process master, so the hardware-backed tiers (TPM / Secure Enclave / Keystore via `ProtectedStringOptions.KeyAtRestProtection`) cover blobs automatically — and any number of blobs consume a single hardware key slot.
- **One key unwrap per pass**: streaming 200 MB through `WriteTo` costs one hardware round-trip, not thousands.
- **Write-once by design** — no mutation API, no whole-blob plaintext exposure; `Dispose` zeroes the key envelope and all frames, with a finalizer backstop.

## Threat model, honestly

Defends against **accidental** disclosure (heap dumps, swap, GC copies of bulk plaintext) and detects ciphertext tampering. It is not a defence against an attacker who can read the live process. Note: blobs do not currently participate in process-key rotation — dispose blobs to end their exposure. Full details, wire-format documentation, performance notes, and a live browser demo: [repository README](https://github.com/Alpaq92/TopSecret.ProtectedString#readme).

## License

[MIT](https://github.com/Alpaq92/TopSecret.ProtectedString/blob/master/LICENSE).
