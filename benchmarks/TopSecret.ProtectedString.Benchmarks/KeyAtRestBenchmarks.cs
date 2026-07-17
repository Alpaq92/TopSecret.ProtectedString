using BenchmarkDotNet.Attributes;
using TopSecret;

namespace TopSecret.Benchmarks;

/// <summary>
/// Quantifies the per-operation cost of each software key-at-rest tier — in
/// particular the delta the 2.4 default flip (<c>None</c> → <c>Obscurity</c>)
/// adds per master unwrap, and where <c>GuardedPage</c> sits.
/// </summary>
/// <remarks>
/// <see cref="ProtectedStringOptions.KeyAtRestProtection"/> is read once at the
/// first construction, so each tier must run in its own process — which is
/// exactly how BenchmarkDotNet isolates each <see cref="ParamsAttribute"/> case.
/// <c>Access</c> re-unwraps the master every call (no TTL cache), so this is the
/// full per-op tier cost, not an amortized one.
/// </remarks>
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
