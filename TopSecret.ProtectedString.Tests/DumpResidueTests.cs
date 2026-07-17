using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

/// <summary>
/// The authoritative "no residue after dispose" check: construct a secret with
/// a high-entropy marker, dispose it, force a GC, then write a full-memory
/// crash dump of this process and assert the marker's plaintext is <b>absent</b>
/// from the dump file — while a plain managed <see cref="string"/> control with
/// a different marker <b>is</b> found, proving the dump and the scanner work.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ExplicitAttribute"/> and Windows-gated: it runs only when
/// selected by name and only where a dump primitive is present
/// (<c>MiniDumpWriteDump</c> from <c>dbghelp.dll</c>). The Linux/macOS
/// equivalent (<c>createdump</c> / <c>gcore</c>) is a separate external tool;
/// a CI leg that has one can add a sibling.
/// </para>
/// <para>
/// <b>Why the marker never pollutes the dump.</b> The secret is derived from a
/// small integer seed into a <see cref="char"/>[] that is wiped immediately,
/// and the value only ever enters a <see cref="ProtectedString"/> (encrypted at
/// rest, wiped on dispose) — it is never a managed <see cref="string"/>. The
/// scan needle is re-derived from the seed <i>after</i> the dump snapshot is
/// taken, so it is not present in memory at dump time.
/// </para>
/// </remarks>
[TestFixture]
[Explicit("writes a full-memory self-dump; run on demand where a dump primitive exists")]
public class DumpResidueTests
{
    private const int MiniDumpWithFullMemory = 0x00000002;
    private const int SecretSeed = 0x5EC0DE;
    private const int ControlSeed = 0x0C047401;
    private const int MarkerChars = 64; // 128 bytes of UTF-16 — no coincidental match

    [Test]
    public void Disposed_secret_is_absent_from_a_full_memory_dump()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("MiniDumpWriteDump is Windows-only; add a createdump/gcore sibling on other hosts.");
            return;
        }

        // 1. Materialize the secret ONLY inside a ProtectedString, from a wiped
        //    derivation buffer — never as a managed string.
        var secretChars = DeriveMarker(SecretSeed);
        var ps = new ProtectedString();
        ps.AppendChars(secretChars);
        ps.MakeReadOnly();
        ps.Access(_ => { }); // touch it, then let it go
        ps.Dispose();
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(secretChars.AsSpan()));

        // 2. Positive control: a plain managed string kept alive must survive
        //    into the dump so we know the scan can find what is really there.
        string control = new string(DeriveMarker(ControlSeed));

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var dumpPath = Path.Combine(Path.GetTempPath(), $"tsps-residue-{Guid.NewGuid():N}.dmp");
        try
        {
            WriteSelfDump(dumpPath);

            // 3. Derive the needles AFTER the snapshot so they are not in the
            //    dumped memory themselves.
            byte[] secretNeedle = MarkerBytes(SecretSeed);
            byte[] controlNeedle = MarkerBytes(ControlSeed);

            Assert.That(FileContains(dumpPath, controlNeedle), Is.True,
                "positive control: a live managed string's bytes must appear in the dump — " +
                "otherwise the scan or the dump is not capturing the heap and the test proves nothing");
            Assert.That(FileContains(dumpPath, secretNeedle), Is.False,
                "the disposed ProtectedString's plaintext must NOT appear anywhere in the full-memory dump");

            GC.KeepAlive(control);
        }
        finally
        {
            try { File.Delete(dumpPath); } catch { /* best effort */ }
        }
    }

    private static char[] DeriveMarker(int seed)
    {
        var rng = new Random(seed);
        var chars = new char[MarkerChars];
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < chars.Length; i++) chars[i] = alphabet[rng.Next(alphabet.Length)];
        return chars;
    }

    private static byte[] MarkerBytes(int seed)
    {
        var chars = DeriveMarker(seed);
        return Encoding.Unicode.GetBytes(chars); // UTF-16LE, matching ProtectedString's in-memory layout
    }

    private static void WriteSelfDump(string path)
    {
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        var process = Process.GetCurrentProcess();
        bool ok = MiniDumpWriteDump(
            process.Handle, (uint)process.Id, fs.SafeFileHandle,
            MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (!ok)
        {
            throw new InvalidOperationException(
                $"MiniDumpWriteDump failed (Win32 error {Marshal.GetLastPInvokeError()}).");
        }
    }

    private static bool FileContains(string path, byte[] needle)
    {
        // Streaming search with an overlap window so a match spanning two reads
        // is not missed.
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        int overlap = needle.Length - 1;
        var buffer = new byte[1 << 20];
        int carried = 0;
        int read;
        while ((read = fs.Read(buffer, carried, buffer.Length - carried)) > 0)
        {
            int available = carried + read;
            if (buffer.AsSpan(0, available).IndexOf(needle) >= 0) return true;
            if (available > overlap)
            {
                buffer.AsSpan(available - overlap, overlap).CopyTo(buffer);
                carried = overlap;
            }
            else
            {
                carried = available;
            }
        }
        return false;
    }

    [DllImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess, uint processId, SafeHandle hFile, int dumpType,
        IntPtr exceptionParam, IntPtr userStreamParam, IntPtr callbackParam);
}
