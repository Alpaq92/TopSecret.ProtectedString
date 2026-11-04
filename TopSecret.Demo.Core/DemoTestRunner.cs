using System.Reflection;
using NUnit.Framework;

namespace TopSecret.Demo;

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
