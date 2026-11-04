using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TopSecret.Cryptography;

namespace TopSecret;

public sealed partial class ProtectedString
{
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

    public byte[] ComputeArgon2idHash(
        byte[] salt,
        Argon2idCalibration calibration,
        int hashLengthBytes = DefaultArgon2idHashLength) =>
        ComputeArgon2idHash(salt, calibration.Iterations, calibration.MemoryKb, calibration.Parallelism, hashLengthBytes);

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

    public bool VerifyArgon2idHash(byte[] expectedHash, byte[] salt, Argon2idCalibration calibration) =>
        VerifyArgon2idHash(expectedHash, salt, calibration.Iterations, calibration.MemoryKb, calibration.Parallelism);
}
