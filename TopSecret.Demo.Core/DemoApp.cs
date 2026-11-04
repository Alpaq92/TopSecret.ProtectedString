using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace TopSecret.Demo;

public static class DemoApp
{
    public static async Task RunAsync()
    {
        var runStopwatch = Stopwatch.StartNew();
        long allocatedAtStart = GC.GetTotalAllocatedBytes();
        Console.WriteLine("TopSecret.ProtectedString Demo");
        Console.WriteLine("==================================");
        Console.WriteLine();

        ProtectedStringOptions.KeyAtRestProtection = KeyAtRestProtection.HardwareBackedPreferred;

        Console.WriteLine($"  Hardware-backed availability: {ProtectedString.HardwareBackedAvailability}");
        Console.WriteLine($"  Configured key-at-rest tier:  {ProtectedStringOptions.KeyAtRestProtection}");
        Console.WriteLine("  Obscurity wrap (if reached):  AES-GCM-256 with per-protector random wrap key (HKDF stream-XOR fallback)");
        Console.WriteLine();

        string secretValue = DemoInputs.RandomSecret();
        using var fromString = new ProtectedString(secretValue);
        Print("from string ctor:", fromString);

        // 2. Wrap a span. The span content is copied into the encrypted buffer.
        using var fromSpan = new ProtectedString(DemoInputs.RandomSecret().AsSpan());
        Print("from span ctor:", fromSpan);

        // 3. Build incrementally, then lock down.
        using var built = new ProtectedString();
        foreach (var c in DemoInputs.RandomSecret())
        {
            built.AppendChar(c);
        }
        built.MakeReadOnly();
        Print("built incrementally:", built);

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

        Console.WriteLine();
        RunCopyToScenario(fromString);

        using var ms = new MemoryStream();
        int written = fromString.WriteUtf8To(ms);
        var sinkFingerprint = SHA256.HashData(ms.GetBuffer().AsSpan(0, written));
        Console.WriteLine($"  WriteUtf8To(MemoryStream): wrote {written} bytes; SHA-256 fingerprint = {Convert.ToHexString(sinkFingerprint.AsSpan(0, 8))}…");

        string equalValue = DemoInputs.RandomSecret();
        using var a = new ProtectedString(equalValue);
        using var b = new ProtectedString(equalValue);
        using var c2 = new ProtectedString(DemoInputs.MutateOneChar(equalValue));
        Console.WriteLine();
        Console.WriteLine($"  a.Equals(b) (same value)      = {a.Equals(b)}");
        Console.WriteLine($"  a.Equals(c) (different value) = {a.Equals(c2)}");

        Console.WriteLine();
        var salt = RandomNumberGenerator.GetBytes(16);
        var sw = Stopwatch.StartNew();
        var stored = fromString.ComputeArgon2idHash(salt);
        sw.Stop();
        Console.WriteLine($"  Argon2id hash ({sw.ElapsedMilliseconds} ms, OWASP defaults: t=3, m=19 MiB, p=1)");

        using var rightAttempt = new ProtectedString(secretValue);
        using var wrongAttempt = new ProtectedString(DemoInputs.MutateOneChar(secretValue));
        Console.WriteLine($"    rightAttempt.VerifyArgon2idHash(stored) = {rightAttempt.VerifyArgon2idHash(stored, salt)}");
        Console.WriteLine($"    wrongAttempt.VerifyArgon2idHash(stored) = {wrongAttempt.VerifyArgon2idHash(stored, salt)}");

        // 9. ToString never leaks the protected value, so accidental logging is safe.
        Console.WriteLine();
        Console.WriteLine($"  ToString safety: {fromString}");

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
            var bodyEcho = await bodyResp.Content.ReadAsByteArrayAsync();
            Console.WriteLine($"    POST body via WriteUtf8To: server saw {bodyEcho.Length} UTF-8 bytes (echoed length only — never log the body)");
        }

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

        Console.WriteLine();
        Console.WriteLine("  ProtectedBlob (bulk secrets):");

        // ~2 MB of fresh random bytes, size jittered per run (e.g. a sealed
        // asset / model shard) — so the chunk count varies between runs too.
        var payload = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(1_800_000, 2_200_001));
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

            using var restored = new MemoryStream();
            blob.WriteTo(restored);
            Console.WriteLine($"    WriteTo(MemoryStream): wrote {restored.Length:N0} bytes");
            restored.Position = 0;
            using (var fromStream = ProtectedBlob.FromStream(restored))
            {
                Console.WriteLine($"    FromStream round-trip: {fromStream.Length:N0} bytes in {fromStream.ChunkCount} chunks");
            }
        }

        Console.WriteLine();
        Console.WriteLine("  Live test run (representative slice; full suites run in CI):");
        await DemoTestRunner.RunAsync("    ");

        // 14. Run metrics — printed by the demo itself so the console and
        //     browser hosts report through the same channel.
        runStopwatch.Stop();

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
        Span<char> scratch = stackalloc char[source.Length];
        int copied = source.CopyTo(scratch);
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
