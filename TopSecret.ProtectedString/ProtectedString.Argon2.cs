using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TopSecret.Cryptography;

namespace TopSecret;

/// <summary>Argon2id password hashing and verification over the plaintext.</summary>
public sealed partial class ProtectedString
{
    /// <summary>
    /// Computes an Argon2id hash of the UTF-8 encoded plaintext using the
    /// supplied <paramref name="salt"/> and parameters. Suitable for storing
    /// password verifiers; <see cref="VerifyArgon2idHash(byte[], byte[], int, int, int)"/> is the matching
    /// constant-time verifier.
    /// </summary>
    /// <param name="salt">
    /// A unique, per-secret random salt of at least 8 bytes. <see cref="RandomNumberGenerator.GetBytes(int)"/>
    /// with a length of 16 is a sane default. The same salt must be supplied to
    /// <see cref="VerifyArgon2idHash(byte[], byte[], int, int, int)"/> for the comparison to succeed.
    /// </param>
    /// <param name="iterations">Time cost. OWASP recommends ≥3 for interactive logins; defaults to <see cref="DefaultArgon2idIterations"/>.</param>
    /// <param name="memoryKb">Memory cost in KiB. OWASP recommends ≥19 456 (≈19 MiB) for interactive logins; defaults to <see cref="DefaultArgon2idMemoryKb"/>.</param>
    /// <param name="parallelism">Number of lanes. Defaults to <see cref="DefaultArgon2idParallelism"/>.</param>
    /// <param name="hashLengthBytes">Output length in bytes. Defaults to <see cref="DefaultArgon2idHashLength"/> (32, i.e. 256 bits).</param>
    /// <remarks>
    /// The plaintext is decrypted into a pinned buffer for the duration of the
    /// hash computation and wiped on the way out. Argon2id is intentionally
    /// slow — picking parameters too low defeats the point, picking them too
    /// high stalls your authentication path. Tune for your hardware.
    /// Works on the single-threaded browser (WASM) runtime at the default
    /// <paramref name="parallelism"/> = 1 (see <see cref="DefaultArgon2idParallelism"/>);
    /// raising <paramref name="parallelism"/> above 1 there throws
    /// <see cref="PlatformNotSupportedException"/> — see the README's
    /// browser-wasm section for why that ceiling is permanent, not a bug.
    /// See the <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html">OWASP
    /// Password Storage Cheat Sheet</a> for current guidance.
    /// </remarks>
    public byte[] ComputeArgon2idHash(
        byte[] salt,
        int iterations = DefaultArgon2idIterations,
        int memoryKb = DefaultArgon2idMemoryKb,
        int parallelism = DefaultArgon2idParallelism,
        int hashLengthBytes = DefaultArgon2idHashLength)
    {
        ArgumentNullException.ThrowIfNull(salt);
        if (salt.Length < 8) throw new ArgumentException("Salt must be at least 8 bytes.", nameof(salt));
        if (iterations < 1) throw new ArgumentOutOfRangeException(nameof(iterations));
        if (memoryKb < 8) throw new ArgumentOutOfRangeException(nameof(memoryKb));
        if (parallelism < 1) throw new ArgumentOutOfRangeException(nameof(parallelism));
        if (hashLengthBytes < 16) throw new ArgumentOutOfRangeException(nameof(hashLengthBytes));

        // The whole KDF runs under _sync ON PURPOSE — see the README's
        // "Argon2id ... synchronous-only" rationale: releasing the lock for
        // the derivation would let Dispose return while this method still
        // holds a pinned plaintext copy, and opens a stale-verify race. What
        // does NOT need to span the derivation is the pooled plaintext lease:
        // the UTF-8 bytes are copied into a dedicated pinned array first and
        // the lease is returned before the hundreds-of-ms KDF starts, so a
        // hash in flight pins one private buffer, not a shared pool chunk.
        // Dedicated array (not pooled scratch): Argon2id's constructor
        // requires a real byte[] and the reference crosses into the external
        // KDF implementation.
        lock (_sync)
        {
            ThrowIfDisposed();

            byte[] bytes;
            LockedScratchPool.Lease? lease = null;
            try
            {
                ReadOnlySpan<char> plain = RentPlaintextLocked(out lease);
                bytes = AllocatePinnedBytes(Encoding.UTF8.GetByteCount(plain), excludeFromDumps: true);
                try
                {
                    Encoding.UTF8.GetBytes(plain, bytes);
                }
                catch
                {
                    ZeroBytes(bytes);
                    throw;
                }
            }
            finally
            {
                lease?.Return();
            }

            try
            {
                using var argon = new Argon2id(bytes)
                {
                    Salt = salt,
                    Iterations = iterations,
                    MemorySize = memoryKb,
                    DegreeOfParallelism = parallelism,
                };
                return argon.GetBytes(hashLengthBytes);
            }
            finally
            {
                ZeroBytes(bytes);
            }
        }
    }

    /// <summary>
    /// <see cref="ComputeArgon2idHash(byte[], int, int, int, int)"/> with the
    /// cost parameters taken from an <see cref="Argon2idCalibration"/>
    /// produced by <see cref="Argon2Calibrator.Tune"/>, so a calibration
    /// measured at startup feeds the hash directly instead of being copied
    /// field by field.
    /// </summary>
    public byte[] ComputeArgon2idHash(
        byte[] salt,
        Argon2idCalibration calibration,
        int hashLengthBytes = DefaultArgon2idHashLength) =>
        ComputeArgon2idHash(salt, calibration.Iterations, calibration.MemoryKb, calibration.Parallelism, hashLengthBytes);

    /// <summary>
    /// Constant-time comparison of an Argon2id hash of this instance (computed
    /// with <paramref name="salt"/> and the supplied parameters) against
    /// <paramref name="expectedHash"/>. The parameters must match the ones used
    /// when <paramref name="expectedHash"/> was originally produced.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> when the hashes match. <see langword="false"/>
    /// when they differ, and also when <paramref name="expectedHash"/> is
    /// shorter than the 16-byte minimum this type ever produces — a stored
    /// verifier that short cannot have come from
    /// <see cref="ComputeArgon2idHash(byte[], int, int, int, int)"/>, so it
    /// is treated as a non-match rather than an argument error.
    /// </returns>
    public bool VerifyArgon2idHash(
        byte[] expectedHash,
        byte[] salt,
        int iterations = DefaultArgon2idIterations,
        int memoryKb = DefaultArgon2idMemoryKb,
        int parallelism = DefaultArgon2idParallelism)
    {
        ArgumentNullException.ThrowIfNull(expectedHash);
        if (expectedHash.Length < 16) return false;
        var actual = ComputeArgon2idHash(salt, iterations, memoryKb, parallelism, expectedHash.Length);
        try
        {
            return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    /// <summary>
    /// <see cref="VerifyArgon2idHash(byte[], byte[], int, int, int)"/> with the
    /// cost parameters taken from an <see cref="Argon2idCalibration"/>. The
    /// calibration must be the one the verifier was produced with.
    /// </summary>
    public bool VerifyArgon2idHash(byte[] expectedHash, byte[] salt, Argon2idCalibration calibration) =>
        VerifyArgon2idHash(expectedHash, salt, calibration.Iterations, calibration.MemoryKb, calibration.Parallelism);
}
