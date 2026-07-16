using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using TopSecret.Analyzers;

namespace TopSecret.Analyzers.Tests;

/// <summary>
/// Hosts <see cref="EscapingPlaintextAnalyzer"/> against in-memory C#
/// snippets and asserts on the diagnostics it emits. Guards against
/// silent regressions in the analyzer's detection rules — analyzer
/// bugs (especially false negatives) are invisible in normal CI: the
/// analyzer "just works" until a user writes the missed pattern.
/// </summary>
/// <remarks>
/// Each test compiles a snippet with a stable reference set (the same
/// runtime <c>TRUSTED_PLATFORM_ASSEMBLIES</c> the test process loaded
/// itself from, plus the real <c>TopSecret.ProtectedString</c> assembly),
/// runs the analyzer via <see cref="Compilation.WithAnalyzers"/>, and
/// asserts on the resulting <see cref="Diagnostic"/> set. This is the
/// minimum viable testing surface — no codefix, no document workspace,
/// no cross-version compatibility concerns with the
/// <c>Microsoft.CodeAnalysis.Testing</c> harness packages.
/// </remarks>
[TestFixture]
public class EscapingPlaintextAnalyzerTests
{
    /// <summary>
    /// Reference assemblies for the test compilation: every DLL the test
    /// host is itself loading, plus the main <c>TopSecret.ProtectedString</c>
    /// library. Computed once per process — building the same set on every
    /// test would be wasteful and serialises GC pressure on the analyzer
    /// host.
    /// </summary>
    private static readonly Lazy<ImmutableArray<MetadataReference>> s_references = new(() =>
    {
        var trusted = (string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")
            ?? throw new InvalidOperationException(
                "TRUSTED_PLATFORM_ASSEMBLIES is not set — running outside a .NET host?");

        var refs = trusted
            .Split(Path.PathSeparator)
            .Where(p => !string.IsNullOrWhiteSpace(p) && File.Exists(p))
            .Select(p => (MetadataReference)MetadataReference.CreateFromFile(p))
            .ToList();

        // The analyzer matches by FQN `TopSecret.ProtectedString`; the
        // metadata reference must be present for that lookup to resolve.
        refs.Add(MetadataReference.CreateFromFile(
            typeof(global::TopSecret.ProtectedString).Assembly.Location));

        return refs.ToImmutableArray();
    });

    /// <summary>
    /// Compiles <paramref name="source"/> in-memory, runs
    /// <see cref="EscapingPlaintextAnalyzer"/> against it, and returns the
    /// diagnostics it emitted (plus any compiler errors, so a typo in the
    /// snippet surfaces loudly instead of silently producing a clean run).
    /// </summary>
    private static async Task<ImmutableArray<Diagnostic>> RunAsync(string source)
    {
        var syntaxTree = CSharpSyntaxTree.ParseText(
            source,
            new CSharpParseOptions(LanguageVersion.Latest));

        var compilation = CSharpCompilation.Create(
            assemblyName: "AnalyzerSnippetUnderTest",
            syntaxTrees: new[] { syntaxTree },
            references: s_references.Value,
            options: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        // Surface compile errors loudly. A snippet that fails to compile
        // would otherwise produce zero analyzer diagnostics and a passing
        // negative-case test for the wrong reason.
        var compileErrors = compilation.GetDiagnostics()
            .Where(d => d.Severity == DiagnosticSeverity.Error)
            .ToList();
        if (compileErrors.Count > 0)
        {
            Assert.Fail(
                "Test snippet failed to compile:\n" +
                string.Join("\n", compileErrors.Select(d => d.ToString())));
        }

        var withAnalyzers = compilation.WithAnalyzers(
            ImmutableArray.Create<DiagnosticAnalyzer>(new EscapingPlaintextAnalyzer()));
        return await withAnalyzers.GetAnalyzerDiagnosticsAsync();
    }

    /// <summary>
    /// Asserts <paramref name="diagnostics"/> contains exactly the IDs in
    /// <paramref name="expectedIds"/>, in any order. A mismatch dumps the
    /// full diagnostic list so the failure message is useful.
    /// </summary>
    private static void AssertDiagnosticIds(
        ImmutableArray<Diagnostic> diagnostics,
        params string[] expectedIds)
    {
        var actualIds = diagnostics.Select(d => d.Id).OrderBy(s => s).ToArray();
        var expected = expectedIds.OrderBy(s => s).ToArray();
        Assert.That(actualIds, Is.EqualTo(expected),
            $"Expected diagnostics [{string.Join(",", expected)}] but got " +
            $"[{string.Join(",", actualIds)}]. Full diagnostics:\n" +
            string.Join("\n", diagnostics.Select(d => d.ToString())));
    }

    // ---- TPS001: plaintext copied into a managed string -----------------

    [Test]
    public async Task TPS001_fires_on_new_string_inside_Access_lambda()
    {
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        var leak = new string(plain);
                        System.GC.KeepAlive(leak);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_ToString_inside_Access_lambda()
    {
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        var leak = plain.ToString();
                        System.GC.KeepAlive(leak);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_StringBuilder_Append_inside_Access_lambda()
    {
        // The analyzer flags any method call on System.String or
        // System.Text.StringBuilder that receives the plaintext parameter
        // — `sb.Append(plain)` parks the chars in StringBuilder's
        // internal buffer, which lives past the callback.
        var d = await RunAsync("""
            using System.Text;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    var sb = new StringBuilder();
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        sb.Append(plain);
                    });
            #pragma warning restore CS0618
                    System.GC.KeepAlive(sb);
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_new_string_inside_ReadOnlySpan_Access_lambda()
    {
        // The ReadOnlySpan overload structurally prevents capture, but a
        // caller can still copy the contents into a managed string. The
        // analyzer must catch that — TPS001 flags the *copy*, not the
        // capture.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var leak = new string(plain);
                        System.GC.KeepAlive(leak);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_Func_overload_with_new_string()
    {
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                string M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    return ps.Access((char[] plain) => new string(plain));
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    // ---- TPS002: char[] reference escapes via assignment ----------------

    [Test]
    public async Task TPS002_fires_on_assignment_to_captured_local()
    {
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    char[]? leaked = null;
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        leaked = plain;
                    });
            #pragma warning restore CS0618
                    System.GC.KeepAlive(leaked);
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS002");
    }

    [Test]
    public async Task TPS002_fires_on_assignment_to_field()
    {
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                private char[]? _leaked;
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        _leaked = plain;
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS002");
    }

    [Test]
    public async Task TPS002_fires_on_assignment_to_property()
    {
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                public char[]? Leaked { get; set; }
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        Leaked = plain;
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS002");
    }

    // ---- Negative cases: must NOT fire ----------------------------------

    [Test]
    public async Task No_diagnostic_when_using_plain_inline_with_no_copy()
    {
        // Using the parameter inline (e.g., reading its length, encoding
        // it to a stack buffer) is exactly the safe pattern the library
        // documents.
        var d = await RunAsync("""
            using System;
            using System.Text;
            using TopSecret;
            class C
            {
                int M(ProtectedString ps)
                {
                    return ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        Span<byte> utf8 = stackalloc byte[Encoding.UTF8.GetMaxByteCount(plain.Length)];
                        return Encoding.UTF8.GetBytes(plain, utf8);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    [Test]
    public async Task No_TPS002_when_local_is_declared_inside_lambda()
    {
        // A local declared inside the lambda dies with the frame.
        // Assigning the parameter to it is fine — the analyzer must
        // distinguish inside-the-lambda locals from captured locals.
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                int M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    return ps.Access((char[] plain) =>
                    {
                        var local = plain;
                        return local.Length;
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    [Test]
    public async Task No_diagnostic_when_new_string_is_outside_an_Access_lambda()
    {
        // The analyzer is scoped to ProtectedString.Access(...) callbacks.
        // A `new string(...)` elsewhere in the program — including with
        // a parameter named `plain` — must not trigger.
        var d = await RunAsync("""
            class C
            {
                string M()
                {
                    char[] plain = new[] { 'h', 'i' };
                    return new string(plain);
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    [Test]
    public async Task No_diagnostic_for_Access_on_unrelated_type_named_Access()
    {
        // The analyzer matches the containing type by FQN
        // (`TopSecret.ProtectedString`). A method also named `Access` on a
        // different type must not produce diagnostics.
        var d = await RunAsync("""
            using System;
            class Other
            {
                public void Access(Action<char[]> handler) => handler(System.Array.Empty<char>());
            }
            class C
            {
                void M(Other other)
                {
                    other.Access(plain =>
                    {
                        var s = new string(plain);
                        var t = plain.ToString();
                        char[]? leaked = plain;
                        System.GC.KeepAlive(s);
                        System.GC.KeepAlive(t);
                        System.GC.KeepAlive(leaked);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    // ---- Local functions inside Access lambdas -------------------------

    [Test]
    public async Task TPS001_fires_inside_local_function_nested_in_Access_lambda()
    {
        // The local function's body executes synchronously inside the
        // Access window — a leak there is the same kind of leak as a
        // direct lambda-body leak, and the analyzer must catch it.
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] outer) =>
                    {
                        void inner(char[] more)
                        {
                            var leak = new string(more);
                            System.GC.KeepAlive(leak);
                        }
                        inner(outer);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS002_fires_inside_local_function_nested_in_Access_lambda()
    {
        // Field assignment inside a nested local function still escapes.
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                private char[]? _leaked;
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] outer) =>
                    {
                        void inner(char[] more)
                        {
                            _leaked = more;
                        }
                        inner(outer);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS002");
    }

    [Test]
    public async Task No_diagnostic_for_local_function_outside_any_Access_call()
    {
        // A local function defined outside any Access lambda — even one
        // with a char[] parameter that copies it to a string — must not
        // be flagged. Without semantic linking back from `ps.Access(Inner)`
        // call sites to this local function, we cannot prove the chars
        // are plaintext from a ProtectedString. Documented as a known
        // limitation.
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                string M(ProtectedString ps)
                {
                    string Inner(char[] more) => new string(more);
            #pragma warning disable CS0618
                    return ps.Access((char[] outer) => Inner(outer));
            #pragma warning restore CS0618
                }
            }
            """);
        // The `new string(more)` inside Inner is NOT flagged (we don't
        // chase symbol references). The `Inner(outer)` call passes the
        // outer plaintext to a method, but that's not a stringification
        // pattern the analyzer recognises either. This test pins the
        // documented limitation: a local function decoupled from its
        // call site is out of scope.
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    // ---- TPS001: Encoding.GetString over the plaintext ------------------

    [Test]
    public async Task TPS001_fires_on_Encoding_GetString_over_span_param()
    {
        // Encoding.GetString decodes the plaintext bytes straight into a
        // managed string — the same escape class as new string(plain).
        // The analyzer must see through MemoryMarshal.AsBytes, which is
        // just a reinterpreted span over the same memory.
        var d = await RunAsync("""
            using System;
            using System.Runtime.InteropServices;
            using System.Text;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var leak = Encoding.Unicode.GetString(MemoryMarshal.AsBytes(plain));
                        System.GC.KeepAlive(leak);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_Encoding_GetString_over_array_param_via_AsSpan()
    {
        // Same sink through the char[] overload, wrapped twice:
        // plain.AsSpan() then MemoryMarshal.AsBytes(...). Both wrappers
        // are spans over the original plaintext, so the copy-to-string
        // still leaks it.
        var d = await RunAsync("""
            using System;
            using System.Runtime.InteropServices;
            using System.Text;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        var leak = Encoding.Unicode.GetString(MemoryMarshal.AsBytes(plain.AsSpan()));
                        System.GC.KeepAlive(leak);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task No_TPS001_when_Encoding_GetString_decodes_unrelated_buffer()
    {
        // Decoding some other buffer inside the Access window is a
        // legitimate operation — only the plaintext parameter (or a span
        // over it) as an argument is flagged.
        var d = await RunAsync("""
            using System;
            using System.Text;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    var greeting = new byte[] { 104, 105 };
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var s = Encoding.UTF8.GetString(greeting);
                        System.GC.KeepAlive(s);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    // ---- TPS001: string.Create with the plaintext as state --------------

    [Test]
    public async Task TPS001_fires_on_string_Create_with_plaintext_state()
    {
        // string.Create is a static method on System.String receiving the
        // plaintext by value as its state argument — the entire point of
        // the call is to bake that state into a managed string.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                string M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    return ps.Access((char[] plain) =>
                        string.Create(plain.Length, plain, (span, state) => state.CopyTo(span)));
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_string_Create_with_span_plaintext_state()
    {
        // The ReadOnlySpan overload can flow into string.Create too —
        // string.Create<TState> allows ref struct state on modern TFMs.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var leak = string.Create(plain.Length, plain, (span, state) => state.CopyTo(span));
                        System.GC.KeepAlive(leak);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task No_TPS001_when_string_Create_state_is_not_plaintext()
    {
        // string.Create with unrelated state inside an Access callback is
        // a legitimate sink — only the plaintext parameter as an argument
        // is flagged.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var s = string.Create(3, 'x', (span, ch) => span.Fill(ch));
                        System.GC.KeepAlive(s);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    // ---- TPS003: plaintext copied into a fresh heap array ---------------

    [Test]
    public async Task TPS003_fires_on_ToArray_of_array_param()
    {
        // Enumerable.ToArray over the char[] parameter — a heap copy the
        // library never zeroes.
        var d = await RunAsync("""
            using System.Linq;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        var copy = plain.ToArray();
                        System.GC.KeepAlive(copy);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS003");
    }

    [Test]
    public async Task TPS003_fires_on_ToArray_of_span_param()
    {
        // ReadOnlySpan<char>.ToArray() — the span itself cannot escape,
        // but the copy it produces is an ordinary array that can.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var copy = plain.ToArray();
                        System.GC.KeepAlive(copy);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS003");
    }

    [Test]
    public async Task No_TPS003_when_ToArray_is_on_unrelated_collection()
    {
        // ToArray over some other collection inside the Access window
        // does not touch the plaintext — must not fire.
        var d = await RunAsync("""
            using System;
            using System.Collections.Generic;
            using System.Linq;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var digits = new List<int> { 1, 2, 3 };
                        var copy = digits.ToArray();
                        System.GC.KeepAlive(copy);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    [Test]
    public async Task No_TPS001_when_string_constructor_takes_char_only()
    {
        // `new string('x', 5)` is the (char, int) ctor — not a copy of the
        // plaintext. Must not fire even when nominally inside an Access
        // callback.
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        var s = new string('x', 5);
                        System.GC.KeepAlive(s);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }
}
