using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace TopSecret.Demo;

/// <summary>
/// The demo scenarios, shared verbatim between the console host
/// (<c>TopSecret.Demo</c>) and the browser host (<c>TopSecret.Demo.Wasm</c>,
/// which routes <see cref="Console.Out"/> into an xterm.js terminal).
/// </summary>
public static class DemoApp
{
    public static async Task RunAsync()
    {
        var runStopwatch = Stopwatch.StartNew();
        long allocatedAtStart = GC.GetTotalAllocatedBytes();
        Console.WriteLine("TopSecret.ProtectedString Demo");
        Console.WriteLine("==================================");
        Console.WriteLine();

        // 0. Configure key-at-rest wrapping in your composition root, before the
        //    first ProtectedString is constructed. HardwareBackedPreferred takes
        //    whatever protection the platform offers (Apple SEP / Android Keystore /
        //    Windows TPM via the optional TopSecret.ProtectedString.WindowsTpm package),
        //    falling back to Obscurity, then None, without throwing on platforms
        //    that don't have any. Use HardwareBackedRequired only when you want
        //    construction to throw on a host without a hardware-backed provider.
        ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.HardwareBackedPreferred;

        Console.WriteLine($"  Hardware-backed availability: {ProtectedString.HardwareBackedAvailability}");
        Console.WriteLine($"  Configured key-at-rest tier:  {ProtectedStringOptions.KeyAtRestProtection}");
        Console.WriteLine($"  Obscurity wrap (if reached):  {(OperatingSystem.IsWindows() ? "AES-GCM-256 with per-protector random wrap key" : "HKDF stream-XOR")}");
        Console.WriteLine();

        // 1. Wrap an existing string.
        //    (See README for the caveat — string is immutable, so the original lives on
        //    in the GC heap until collected. Prefer (2) or (3) when you can.)
        using var fromString = new ProtectedString("hunter2");
        Print("from string ctor:", fromString);

        // 2. Wrap a span. The span content is copied into the encrypted buffer.
        using var fromSpan = new ProtectedString("correct horse battery staple".AsSpan());
        Print("from span ctor:", fromSpan);

        // 3. Build incrementally, then lock down.
        using var built = new ProtectedString();
        foreach (var c in "p4ssw0rd!")
        {
            built.AppendChar(c);
        }
        built.MakeReadOnly();
        Print("built incrementally:", built);

        // 4. Use the value briefly. The ReadOnlySpan<char> passed to the callback
        //    is a ref struct — the C# compiler refuses to let it escape the lambda
        //    (no capture by closure, no storage in a field, no return, no await).
        //    The plaintext buffer is wiped the moment the callback returns.
        fromString.Access(plain =>
        {
            Span<byte> utf8 = stackalloc byte[Encoding.UTF8.GetMaxByteCount(plain.Length)];
            int written = Encoding.UTF8.GetBytes(plain, utf8);
            Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
            SHA256.HashData(utf8[..written], hash);
            var hashHex = Convert.ToHexString(hash);
            Console.WriteLine($"  inside Access(): SHA-256 hex = {hashHex[..32]}...  ");
            Console.WriteLine("    (note: this hash is for change-detection only — never store");
            Console.WriteLine("     a SHA-256 of a password as a credential verifier.)");
        });

        // 5. CopyTo — copy the plaintext into a caller-owned stackalloc
        //    buffer, then operate on it without going through the Access(...)
        //    callback shape. The destination span is yours; you're responsible
        //    for letting it fall out of scope (a stackalloc dies with the
        //    method frame, so this pattern is naturally bounded).
        Console.WriteLine();
        RunCopyToScenario(fromString);

        // 6. WriteUtf8To — stream the plaintext as UTF-8 bytes straight into a
        //    sink. The intermediate UTF-8 staging buffer is pinned, locked,
        //    and wiped on exit; nothing materialises as a managed `string`.
        //    Useful for "send the secret over a network / pipe / file" without
        //    a managed-string detour.
        using var ms = new MemoryStream();
        int written = fromString.WriteUtf8To(ms);
        // Fingerprint, not contents — printing even a few plaintext bytes
        // would contradict the "never log the body" discipline this demo
        // preaches.
        var sinkFingerprint = SHA256.HashData(ms.GetBuffer().AsSpan(0, written));
        Console.WriteLine($"  WriteUtf8To(MemoryStream): wrote {written} bytes; SHA-256 fingerprint = {Convert.ToHexString(sinkFingerprint.AsSpan(0, 8))}…");
        //    In a real app the sink would be a NetworkStream / SslStream /
        //    FileStream rather than a MemoryStream — using a MemoryStream here
        //    only because a console demo can't open a network socket. The
        //    library does what it can up to Stream.Write; what the stream
        //    then does with the bytes is the caller's responsibility.

        // 7. Constant-time equality.
        using var a = new ProtectedString("topsecret");
        using var b = new ProtectedString("topsecret");
        using var c2 = new ProtectedString("topSecret");
        Console.WriteLine();
        Console.WriteLine($"  a.Equals(b) (same value)      = {a.Equals(b)}");
        Console.WriteLine($"  a.Equals(c) (different value) = {a.Equals(c2)}");

        // 8. Credential verification — Argon2id with OWASP-aligned defaults.
        //    Skipped in the browser: the managed Argon2 implementation
        //    (Konscious) coordinates its lanes with blocking thread joins,
        //    which the single-threaded WASM runtime cannot perform
        //    (PlatformNotSupportedException: "Cannot wait on monitors").
        Console.WriteLine();
        if (OperatingSystem.IsBrowser())
        {
            Console.WriteLine("  Argon2id credential verification: skipped in the browser — the managed");
            Console.WriteLine("  Argon2 implementation blocks on worker threads, which the single-threaded");
            Console.WriteLine("  WASM runtime does not support. Run the console demo for this scenario.");
        }
        else
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            var sw = Stopwatch.StartNew();
            var stored = fromString.ComputeArgon2idHash(salt);
            sw.Stop();
            Console.WriteLine($"  Argon2id hash ({sw.ElapsedMilliseconds} ms, OWASP defaults: t=3, m=19 MiB, p=1)");

            using var rightAttempt = new ProtectedString("hunter2");
            using var wrongAttempt = new ProtectedString("Hunter2");
            Console.WriteLine($"    rightAttempt.VerifyArgon2idHash(stored) = {rightAttempt.VerifyArgon2idHash(stored, salt)}");
            Console.WriteLine($"    wrongAttempt.VerifyArgon2idHash(stored) = {wrongAttempt.VerifyArgon2idHash(stored, salt)}");
        }

        // 9. ToString never leaks the protected value, so accidental logging is safe.
        Console.WriteLine();
        Console.WriteLine($"  ToString safety: {fromString}");

        // 10. Interop with string-only APIs — HttpClient request body via custom
        //     HttpContent. WriteUtf8To streams the plaintext straight into the
        //     request stream; no managed `string` materialises in this process.
        //     The demo runs against an in-process HttpMessageHandler so it does
        //     not require network access.
        Console.WriteLine();
        Console.WriteLine("  Interop demos (offline, against an in-process HttpMessageHandler):");

        using (var inProcessHandler = new EchoHandler())
        using (var http = new HttpClient(inProcessHandler))
        {
            using var bodyReq = new HttpRequestMessage(HttpMethod.Post, "https://example.invalid/echo")
            {
                Content = new ProtectedStringContent(fromString),
            };
            using var bodyResp = await http.SendAsync(bodyReq);
            // ReadAsByteArrayAsync, deliberately: the byte count is the true
            // UTF-8 length, and the echoed secret never materialises as a
            // managed string in this process.
            var bodyEcho = await bodyResp.Content.ReadAsByteArrayAsync();
            Console.WriteLine($"    POST body via WriteUtf8To: server saw {bodyEcho.Length} UTF-8 bytes (echoed length only — never log the body)");
        }

        // 11. Interop with string-only APIs — Bearer token via DelegatingHandler.
        //     The string materialises inside SendAsync (under #pragma TPS001)
        //     and dies with the request. The ProtectedString stays encrypted at
        //     rest between sends.
        using (var inner = new EchoHandler())
        using (var bearerHandler = new ProtectedBearerHandler(fromString) { InnerHandler = inner })
        using (var http = new HttpClient(bearerHandler))
        {
            using var hdrReq = new HttpRequestMessage(HttpMethod.Get, "https://example.invalid/whoami");
            using var hdrResp = await http.SendAsync(hdrReq);
            var hdrEcho = hdrResp.Headers.GetValues("X-Echo-Authorization").First();
            // The echoed header reveals the scheme but we only print its shape, not the token bytes.
            Console.WriteLine($"    DelegatingHandler bearer: server saw scheme=\"{hdrEcho.Split(' ')[0]}\", token length={hdrEcho.Length - "Bearer ".Length}");
        }

        // 12. ProtectedBlob — the bulk-data sibling (TopSecret.ProtectedBlob
        //     package). Multi-MB secrets live as chunked AES-GCM-256 ciphertext in
        //     ordinary memory; the per-blob key is wrapped under the same process
        //     master configured in step 0, so the hardware-backed tier (when
        //     available) covers blobs too. Reads decrypt one chunk at a time.
        Console.WriteLine();
        Console.WriteLine("  ProtectedBlob (bulk secrets):");

        var payload = RandomNumberGenerator.GetBytes(2_000_000); // e.g. a sealed asset / model shard
        var payloadHashHex = Convert.ToHexString(SHA256.HashData(payload));
        using (var blob = new ProtectedBlob(payload, clearSource: true))
        {
            bool sourceZeroed = payload.AsSpan().IndexOfAnyExcept((byte)0) < 0;
            Console.WriteLine($"    wrapped {blob.Length:N0} bytes as {blob.ChunkCount} × {blob.ChunkSize / 1024} KiB chunks; source array zeroed: {sourceZeroed}");
            Console.WriteLine($"    ToString safety: {blob}");

            // Sequential streaming read — one chunk of plaintext at a time, one
            // key unwrap for the whole pass.
            using var incremental = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            blob.AccessChunks(chunk => incremental.AppendData(chunk));
            var roundTripHex = Convert.ToHexString(incremental.GetHashAndReset());
            Console.WriteLine($"    AccessChunks SHA-256 round-trip matches original: {roundTripHex == payloadHashHex}");

            // Chunk-granular random access.
            int firstChunkLength = blob.AccessChunk(0, chunk => chunk.Length);
            Console.WriteLine($"    AccessChunk(0) plaintext length: {firstChunkLength:N0} bytes");

            // WriteTo (the blob-shaped sibling of WriteUtf8To) streams the
            // plaintext out; FromStream re-wraps unknown-length input as it
            // streams — plaintext residency never exceeds two chunks.
            using var restored = new MemoryStream();
            blob.WriteTo(restored);
            Console.WriteLine($"    WriteTo(MemoryStream): wrote {restored.Length:N0} bytes");
            restored.Position = 0;
            using (var fromStream = ProtectedBlob.FromStream(restored))
            {
                Console.WriteLine($"    FromStream round-trip: {fromStream.Length:N0} bytes in {fromStream.ChunkCount} chunks");
            }
        }

        // 13. Run the library's tests live, in-process, via NUnit's
        //     programmatic runner (NUnitTestAssemblyRunner). Tests not valid
        //     in this environment self-skip (Argon2 on WASM, the hardware
        //     tier without a secure element), so the demo shows which
        //     behaviours actually verify on the host it runs on.
        Console.WriteLine();
        Console.WriteLine("  Live test run (representative slice; full suites run in CI):");
        DemoTestRunner.Run("    ");

        // 14. Run metrics — printed by the demo itself so the console and
        //     browser hosts report through the same channel.
        runStopwatch.Stop();

        // Allocated THIS run (delta), not process-lifetime cumulative — the
        // latter only ever grows across repeated runs. Then force a full
        // collection so the live-heap figure reflects what survives, and so a
        // "Run again" starts from a flushed heap rather than accumulating the
        // previous run's garbage.
        long allocatedThisRun = GC.GetTotalAllocatedBytes() - allocatedAtStart;
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        long liveHeap = GC.GetTotalMemory(forceFullCollection: false);

        Console.WriteLine();
        Console.WriteLine("  Run metrics:");
        Console.WriteLine($"    total time:            {runStopwatch.ElapsedMilliseconds:N0} ms");
        Console.WriteLine($"    allocated this run:    {allocatedThisRun / (1024.0 * 1024.0):F1} MiB");
        Console.WriteLine($"    live heap after GC:    {liveHeap / (1024.0 * 1024.0):F1} MiB");
        if (!OperatingSystem.IsBrowser())
        {
            try
            {
                using var process = Process.GetCurrentProcess();
                Console.WriteLine($"    peak working set:      {process.PeakWorkingSet64 / (1024.0 * 1024.0):F1} MiB");
            }
            catch (PlatformNotSupportedException)
            {
                // Some platforms don't expose peak working set — skip quietly.
            }
        }
    }

    private static void RunCopyToScenario(ProtectedString source)
    {
        // stackalloc must live in a non-async frame — a Span<char> cannot
        // cross the awaits in RunAsync, which is why this scenario sits in
        // its own method.
        Span<char> scratch = stackalloc char[source.Length];
        int copied = source.CopyTo(scratch);
        //    Compute a non-cryptographic character checksum inline as a debug
        //    signature. Note we never `new string(scratch)` — the same Access
        //    caveat about copies escaping the callback applies here.
        int charSum = 0;
        foreach (var ch in scratch[..copied]) charSum += ch;
        Console.WriteLine($"  CopyTo() into stackalloc: copied {copied} chars, charSum={charSum} (debug signature only)");
    }

    private static void Print(string label, ProtectedString ps)
    {
        // Notice we never print the plaintext directly — Access(...) is required.
        Console.WriteLine($"  {label,-22} length={ps.Length,3}  readonly={ps.IsReadOnly}  ToString=\"{ps}\"");
    }
}

// === Interop demo plumbing ===

// Streams the ProtectedString plaintext as UTF-8 directly into the request body.
// No managed `string` ever materialises — the bytes go from the decrypted,
// pinned, wipe-on-exit buffer straight into HttpClient's request stream.
internal sealed class ProtectedStringContent : HttpContent
{
    private readonly ProtectedString _ps;

    public ProtectedStringContent(ProtectedString ps, string mediaType = "text/plain")
    {
        _ps = ps;
        Headers.ContentType = new MediaTypeHeaderValue(mediaType) { CharSet = "utf-8" };
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
    {
        _ps.WriteUtf8To(stream);
        return Task.CompletedTask;
    }

    protected override bool TryComputeLength(out long length) { length = -1; return false; }
}

// Materialises a Bearer token string inside Access for one send and lets it
// fall out of scope when the request completes. Never assign the result to
// HttpClient.DefaultRequestHeaders.Authorization — that would pin the string
// for the lifetime of the client.
internal sealed class ProtectedBearerHandler : DelegatingHandler
{
    private readonly ProtectedString _token;

    public ProtectedBearerHandler(ProtectedString token) => _token = token;

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        _token.Access(plain =>
        {
#pragma warning disable TPS001 // HttpClient header API requires string
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", new string(plain));
#pragma warning restore TPS001
        });
        return base.SendAsync(request, cancellationToken);
    }
}

// In-process handler so the demo runs offline. Echoes the request body back
// in the response body (length only is printed by the caller) and the
// Authorization header back as X-Echo-Authorization.
internal sealed class EchoHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var resp = new HttpResponseMessage(HttpStatusCode.OK);
        if (request.Content is not null)
        {
            var bytes = await request.Content.ReadAsByteArrayAsync(cancellationToken);
            resp.Content = new ByteArrayContent(bytes);
        }
        if (request.Headers.Authorization is { } auth)
        {
            resp.Headers.TryAddWithoutValidation(
                "X-Echo-Authorization", $"{auth.Scheme} {auth.Parameter}");
        }
        return resp;
    }
}
