using System.Diagnostics;
using System.Security.Cryptography;
using TopSecret.Cryptography;

namespace TopSecret;

public readonly record struct Argon2idCalibration(
    int Iterations, int MemoryKb, int Parallelism, TimeSpan Measured);

public static class Argon2Calibrator
{
    public const int DefaultMaxMemoryKb = 1024 * 1024;

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
