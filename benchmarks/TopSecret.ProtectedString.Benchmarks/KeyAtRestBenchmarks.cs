using BenchmarkDotNet.Attributes;
using TopSecret;

namespace TopSecret.Benchmarks;

[MemoryDiagnoser]
public class KeyAtRestBenchmarks
{
    [Params(
        KeyAtRestProtection.None,
        KeyAtRestProtection.Obscurity,
        KeyAtRestProtection.GuardedPage)]
    public KeyAtRestProtection Tier;

    private ProtectedString _ps = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Pin the tier before the first construction lazily initializes the
        // process protector.
        ProtectedStringOptions.KeyAtRestProtection = Tier;
        _ps = new ProtectedString("correct horse battery staple".AsSpan());
    }

    [Benchmark]
    public int Access() => _ps.Access(static span => span.Length);

    [GlobalCleanup]
    public void Cleanup() => _ps.Dispose();
}
