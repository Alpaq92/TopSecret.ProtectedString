using System.Diagnostics;
using System.Security.Cryptography;
using TopSecret.Cryptography;

namespace TopSecret;

/// <summary>
/// The Argon2id parameters produced by <see cref="Argon2Calibrator.Tune"/>,
/// ready to pass to <see cref="ProtectedString.ComputeArgon2idHash"/> /
/// <see cref="ProtectedString.VerifyArgon2idHash"/>.
/// </summary>
/// <param name="Iterations">Time cost (Argon2 <c>t</c>).</param>
/// <param name="MemoryKb">Memory cost in KiB (Argon2 <c>m</c>).</param>
/// <param name="Parallelism">Lane count (Argon2 <c>p</c>).</param>
/// <param name="Measured">
/// The latency actually measured on this host for a single hash at these
/// parameters. Compare against your target to see how close the calibration
/// landed (it may fall short only when the memory cap or the OWASP floors bind).
/// </param>
public readonly record struct Argon2idCalibration(
    int Iterations, int MemoryKb, int Parallelism, TimeSpan Measured);

/// <summary>
/// Benchmarks the host to pick Argon2id parameters that hit a target
/// per-hash latency. OWASP's guidance is "tune for your hardware"; almost
/// nobody does, so the credential-hashing feature otherwise ships with static
/// defaults that are too slow on some hosts and too weak on others.
/// </summary>
/// <remarks>
/// <para>
/// This is a <b>startup / ops helper</b>, not a hot-path API — it runs several
/// real Argon2id hashes and takes on the order of the target latency times a
/// small constant. Run it once at deploy time on the target hardware and cache
/// the result; results from a dev box do not transfer to a differently-specced
/// production host.
/// </para>
/// <para>
/// The search never returns parameters below OWASP's interactive-login floors
/// (<see cref="ProtectedString.DefaultArgon2idIterations"/> /
/// <see cref="ProtectedString.DefaultArgon2idMemoryKb"/>): if even the floor is
/// already slower than the target on this host, the floor is returned and
/// <see cref="Argon2idCalibration.Measured"/> reports the (larger) real cost.
/// </para>
/// </remarks>
public static class Argon2Calibrator
{
    /// <summary>1 GiB — a sane default ceiling on the memory the search will request.</summary>
    public const int DefaultMaxMemoryKb = 1024 * 1024;

    /// <summary>
    /// Finds Argon2id parameters whose measured single-hash latency is close to
    /// <paramref name="target"/> on this host, holding parallelism fixed and
    /// scaling memory (then iterations, if the memory cap binds).
    /// </summary>
    /// <param name="target">Desired per-hash latency. Typical interactive-login targets are 250–500 ms.</param>
    /// <param name="parallelism">
    /// Argon2 lane count to calibrate at. Defaults to
    /// <see cref="ProtectedString.DefaultArgon2idParallelism"/> (1), which works
    /// on every runtime including single-threaded browser-wasm. Raise it to
    /// match available cores if your verify path is multi-threaded.
    /// </param>
    /// <param name="maxMemoryKb">
    /// Upper bound on the memory cost the search will request. Defaults to
    /// <see cref="DefaultMaxMemoryKb"/> (1 GiB).
    /// </param>
    /// <param name="tolerance">
    /// Fractional band around <paramref name="target"/> treated as "close
    /// enough" (default 0.15 = ±15%), bounding how many probe hashes run.
    /// </param>
    public static Argon2idCalibration Tune(
        TimeSpan target,
        int parallelism = ProtectedString.DefaultArgon2idParallelism,
        int maxMemoryKb = DefaultMaxMemoryKb,
        double tolerance = 0.15)
    {
        if (target <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(target), target, "Target latency must be positive.");
        if (parallelism < 1)
            throw new ArgumentOutOfRangeException(nameof(parallelism), parallelism, "Parallelism must be at least 1.");
        if (maxMemoryKb < ProtectedString.DefaultArgon2idMemoryKb)
            throw new ArgumentOutOfRangeException(nameof(maxMemoryKb), maxMemoryKb,
                $"Max memory must be at least the OWASP floor ({ProtectedString.DefaultArgon2idMemoryKb} KiB).");
        if (tolerance is <= 0 or >= 1)
            throw new ArgumentOutOfRangeException(nameof(tolerance), tolerance, "Tolerance must be in (0, 1).");

        double targetMs = target.TotalMilliseconds;
        double lowerMs = targetMs * (1 - tolerance);

        int t = ProtectedString.DefaultArgon2idIterations;
        int m = ProtectedString.DefaultArgon2idMemoryKb;
        double measuredMs = Measure(t, m, parallelism);

        // Already at or over target at the floor — cannot go lower than OWASP.
        if (measuredMs >= lowerMs)
        {
            return new Argon2idCalibration(t, m, parallelism, TimeSpan.FromMilliseconds(measuredMs));
        }

        // Argon2 cost is ~linear in memory: scale proportionally, re-measure,
        // a bounded number of times. Each pass corrects for non-linearity.
        for (int pass = 0; pass < 6 && measuredMs < lowerMs; pass++)
        {
            double factor = targetMs / measuredMs; // > 1
            long scaled = (long)(m * factor);
            bool capped = scaled >= maxMemoryKb;
            m = capped ? maxMemoryKb : (int)Math.Max(m + 1, scaled);
            measuredMs = Measure(t, m, parallelism);
            if (capped) break;
        }

        // Memory capped but still short — buy the rest with iterations
        // (also ~linear), bounded so a hostile target cannot loop forever.
        while (m >= maxMemoryKb && measuredMs < lowerMs && t < 100)
        {
            t++;
            measuredMs = Measure(t, m, parallelism);
        }

        return new Argon2idCalibration(t, m, parallelism, TimeSpan.FromMilliseconds(measuredMs));
    }

    private static double Measure(int iterations, int memoryKb, int parallelism)
    {
        // Fixed dummy inputs — calibration times the KDF, it does not hash a
        // real secret. A single timed run; Argon2id is deterministic in cost.
        byte[] password = new byte[16];
        RandomNumberGenerator.Fill(password);
        byte[] salt = new byte[16];
        RandomNumberGenerator.Fill(salt);

        var sw = Stopwatch.StartNew();
        using (var argon = new Argon2id(password)
               {
                   Salt = salt,
                   Iterations = iterations,
                   MemorySize = memoryKb,
                   DegreeOfParallelism = parallelism,
               })
        {
            byte[] hash = argon.GetBytes(ProtectedString.DefaultArgon2idHashLength);
            CryptographicOperations.ZeroMemory(hash);
        }
        sw.Stop();

        CryptographicOperations.ZeroMemory(password);
        return sw.Elapsed.TotalMilliseconds;
    }
}
