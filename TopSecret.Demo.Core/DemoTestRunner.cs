using System.Reflection;
using NUnit.Framework;

namespace TopSecret.Demo;

/// <summary>
/// Runs the demo's NUnit tests from C# code, in-process — the idea behind the
/// Stack Overflow question "How to run NUnit tests from C# code".
/// </summary>
/// <remarks>
/// NUnit's own <c>NUnitTestAssemblyRunner</c> executes tests on a worker
/// thread, which throws <see cref="System.Threading.ThreadStateException"/>
/// on the single-threaded WASM runtime. So this is a minimal runner that
/// discovers <c>[Test]</c> methods by reflection and invokes them on the
/// calling thread (awaiting <see cref="Task"/>-returning async tests rather
/// than fire-and-forgetting them, which would report false PASSes),
/// classifying the outcome from NUnit's own result
/// exceptions — <see cref="IgnoreException"/> (from <c>Assert.Ignore</c>) and
/// <see cref="InconclusiveException"/> become SKIP, <see cref="SuccessException"/>
/// (from <c>Assert.Pass</c>) and a clean return are PASS, and
/// <see cref="AssertionException"/> or any other exception is FAIL. This runs
/// identically in the console and the browser; tests that aren't valid on the
/// host call <c>Assert.Ignore</c> and surface as SKIP, which is how the demo
/// "recognises tests valid in the current environment".
/// </remarks>
public static class DemoTestRunner
{
    public static async Task RunAsync(string indent = "")
    {
        int passed = 0, skipped = 0, failed = 0;
        var start = System.Diagnostics.Stopwatch.StartNew();

        foreach (var fixture in DiscoverFixtures())
        {
            object? instance;
            try
            {
                // Null-forgiving: CreateInstance only returns null for
                // Nullable<T>, which a [TestFixture] class can never be.
                instance = Activator.CreateInstance(fixture)!;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{indent}[FAIL] {fixture.Name} (could not construct fixture)");
                Console.WriteLine($"{indent}       {Unwrap(ex).Message}");
                failed++;
                continue;
            }

            foreach (var test in fixture.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                         .Where(m => m.GetCustomAttribute<TestAttribute>() is not null)
                         .OrderBy(m => m.Name))
            {
                switch (await RunOneAsync(instance, test, indent))
                {
                    case Outcome.Pass: passed++; break;
                    case Outcome.Skip: skipped++; break;
                    default: failed++; break;
                }
            }

            (instance as IDisposable)?.Dispose();
        }

        start.Stop();
        Console.WriteLine(
            $"{indent}{passed} passed, {skipped} skipped, {failed} failed  " +
            $"({start.Elapsed.TotalSeconds:F2}s)");
    }

    private enum Outcome { Pass, Skip, Fail }

    private static async Task<Outcome> RunOneAsync(object instance, MethodInfo test, string indent)
    {
        try
        {
            // Await async Task tests instead of fire-and-forgetting them —
            // never block on the Task (a .Wait()/.Result here would deadlock
            // the single-threaded WASM runtime, the very bug this runner
            // exists to avoid).
            if (test.Invoke(instance, null) is Task task) await task;
            Report(indent, "PASS", test.Name);
            return Outcome.Pass;
        }
        catch (Exception ex)
        {
            var inner = Unwrap(ex);
            switch (inner)
            {
                case SuccessException:
                    Report(indent, "PASS", test.Name);
                    return Outcome.Pass;
                case IgnoreException:
                case InconclusiveException:
                    Report(indent, "SKIP", test.Name, inner.Message);
                    return Outcome.Skip;
                default:
                    Report(indent, "FAIL", test.Name, inner.Message);
                    return Outcome.Fail;
            }
        }
    }

    private static void Report(string indent, string mark, string name, string? message = null)
    {
        Console.WriteLine($"{indent}[{mark}] {name}");
        if (!string.IsNullOrWhiteSpace(message))
        {
            Console.WriteLine($"{indent}       {message.Trim().Split('\n')[0]}");
        }
    }

    private static Exception Unwrap(Exception ex) =>
        ex is TargetInvocationException { InnerException: { } inner } ? inner : ex;

    private static IEnumerable<Type> DiscoverFixtures() =>
        Assembly.GetExecutingAssembly()
            .GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false }
                        && t.GetCustomAttribute<TestFixtureAttribute>() is not null)
            .OrderBy(t => t.Name);
}
