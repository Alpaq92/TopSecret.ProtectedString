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
    // ---- Span-aware string sinks (new string / Concat / Append) ----------

    [Test]
    public async Task TPS001_fires_on_new_string_over_AsSpan_slice_of_array_param()
    {
        // `new string(plain.AsSpan(0, 4))` copies the same bytes as
        // `new string(plain)` — the span wrapper must not hide the sink.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        var leak = new string(plain.AsSpan(0, 4));
                        System.GC.KeepAlive(leak);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_string_Concat_with_span_over_array_param()
    {
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        var leak = string.Concat(plain.AsSpan(), "x");
                        System.GC.KeepAlive(leak);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_StringBuilder_Append_of_span_over_array_param()
    {
        var d = await RunAsync("""
            using System;
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
                        sb.Append(plain.AsSpan());
                    });
            #pragma warning restore CS0618
                    System.GC.KeepAlive(sb);
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_StringBuilder_Append_of_span_param()
    {
        var d = await RunAsync("""
            using System;
            using System.Text;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    var sb = new StringBuilder();
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        sb.Append(plain);
                    });
                    System.GC.KeepAlive(sb);
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    // ---- TPS001: slices, ranges, interpolation, Convert -----------------

    [Test]
    public async Task TPS001_fires_on_Slice_ToString_of_span_param()
    {
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var leak = plain.Slice(1).ToString();
                        System.GC.KeepAlive(leak);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_range_index_ToString_of_span_param()
    {
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var leak = plain[..2].ToString();
                        System.GC.KeepAlive(leak);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS003_fires_on_Slice_ToArray_of_span_param()
    {
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var copy = plain.Slice(1, 2).ToArray();
                        System.GC.KeepAlive(copy);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS003");
    }

    [Test]
    public async Task TPS001_fires_on_string_interpolation_of_span_param()
    {
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var leak = $"pw={plain}";
                        System.GC.KeepAlive(leak);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_string_interpolation_of_range_slice_of_span_param()
    {
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var leak = $"prefix={plain[..3]}";
                        System.GC.KeepAlive(leak);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS001_fires_on_string_interpolation_of_array_param()
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
                        var leak = $"{plain}";
                        System.GC.KeepAlive(leak);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task No_TPS001_when_interpolation_uses_plain_Length()
    {
        // Interpolating a scalar derived from the plaintext (its length)
        // does not copy the secret — must stay clean.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var s = $"length={plain.Length}";
                        System.GC.KeepAlive(s);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    [Test]
    public async Task TPS001_fires_on_Convert_ToBase64String_over_plaintext_bytes()
    {
        // Base64 is a reversible textual encoding — the resulting string
        // *is* the secret, just spelled differently.
        var d = await RunAsync("""
            using System;
            using System.Runtime.InteropServices;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var leak = Convert.ToBase64String(MemoryMarshal.AsBytes(plain));
                        System.GC.KeepAlive(leak);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task No_TPS001_when_Convert_ToBase64String_encodes_unrelated_buffer()
    {
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    var salt = new byte[] { 1, 2, 3 };
                    ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var s = Convert.ToBase64String(salt);
                        System.GC.KeepAlive(s);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    // ---- TPS003: Encoding.GetBytes and array range copies ---------------

    [Test]
    public async Task TPS003_fires_on_Encoding_GetBytes_returning_array_from_array_param()
    {
        // Encoding.GetBytes(char[]) returns a fresh byte[] holding the
        // encoded secret — a heap copy the library never zeroes.
        var d = await RunAsync("""
            using System.Text;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        var copy = Encoding.UTF8.GetBytes(plain);
                        System.GC.KeepAlive(copy);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS003");
    }

    [Test]
    public async Task No_TPS003_when_Encoding_GetBytes_writes_into_caller_buffer()
    {
        // The (chars, index, count, bytes, byteIndex) overload writes
        // into a caller-supplied buffer and returns int — no new copy
        // the analyzer should complain about.
        var d = await RunAsync("""
            using System.Text;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        var dest = new byte[Encoding.UTF8.GetMaxByteCount(plain.Length)];
                        int n = Encoding.UTF8.GetBytes(plain, 0, plain.Length, dest, 0);
                        System.GC.KeepAlive(n);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    [Test]
    public async Task TPS003_fires_on_range_index_of_array_param()
    {
        // `plain[..n]` on a char[] compiles to RuntimeHelpers.GetSubArray
        // — a fresh heap array holding a copy of the secret.
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        var copy = plain[..2];
                        System.GC.KeepAlive(copy);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS003");
    }

    [Test]
    public async Task No_TPS003_when_range_index_is_on_span_param()
    {
        // Re-slicing a span is a view, not a copy.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                int M(ProtectedString ps)
                {
                    return ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        var head = plain[..2];
                        return head.Length;
                    });
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    // ---- TPS002: returning / storing the array parameter ----------------

    [Test]
    public async Task TPS002_fires_when_expression_bodied_Func_lambda_returns_array_param()
    {
        // `ps.Access(p => p)` hands the caller the very array the library
        // zeroes on return.
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                char[] M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    return ps.Access((char[] p) => p);
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS002");
    }

    [Test]
    public async Task TPS002_fires_when_block_bodied_Func_lambda_returns_array_param()
    {
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                char[] M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    return ps.Access((char[] p) =>
                    {
                        return p;
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS002");
    }

    [Test]
    public async Task No_TPS002_when_Func_lambda_returns_scalar_derived_from_array_param()
    {
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                int M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    return ps.Access((char[] p) => p.Length);
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    [Test]
    public async Task No_TPS002_when_nested_local_function_returns_array_param_inside_Access()
    {
        // A return from a nested local function stays inside the Access
        // window — the array never leaves the callback.
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                int M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    return ps.Access((char[] p) =>
                    {
                        char[] Same(char[] x) { return x; }
                        return Same(p).Length;
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    [Test]
    public async Task TPS002_fires_on_List_Add_of_array_param()
    {
        // Storing the array in a collection that outlives the callback
        // retains the reference exactly like `field = plain` does.
        var d = await RunAsync("""
            using System.Collections.Generic;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    var list = new List<char[]>();
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        list.Add(plain);
                    });
            #pragma warning restore CS0618
                    System.GC.KeepAlive(list);
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS002");
    }

    [Test]
    public async Task TPS002_fires_on_array_slot_store_of_array_param()
    {
        var d = await RunAsync("""
            using TopSecret;
            class C
            {
                private readonly char[]?[] _slots = new char[]?[1];
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        _slots[0] = plain;
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS002");
    }

    [Test]
    public async Task No_TPS002_when_List_Add_stores_unrelated_value()
    {
        var d = await RunAsync("""
            using System.Collections.Generic;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    var lengths = new List<int>();
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        lengths.Add(plain.Length);
                    });
            #pragma warning restore CS0618
                    System.GC.KeepAlive(lengths);
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    // ---- Lambda wrapped in a cast / parentheses -------------------------

    [Test]
    public async Task TPS001_fires_when_lambda_is_cast_to_delegate_type()
    {
        // `ps.Access((ReadOnlySpanAction<char>)(p => ...))` is still a
        // lambda passed to Access — the cast must not hide it.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    ps.Access((ReadOnlySpanAction<char>)(p =>
                    {
                        var leak = new string(p);
                        System.GC.KeepAlive(leak);
                    }));
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS001");
    }

    [Test]
    public async Task TPS002_fires_when_parenthesised_lambda_captures_array_param()
    {
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                private char[]? _leaked;
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access(((Action<char[]>)((plain) =>
                    {
                        _leaked = plain;
                    })));
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS002");
    }

    // ---- Nested lambdas: resolve captures against the Access lambda -----

    [Test]
    public async Task No_TPS002_when_local_declared_in_Access_lambda_is_assigned_in_nested_lambda()
    {
        // The local lives in the Access lambda's frame; assigning it from
        // a nested lambda does not make it outlive the callback.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        char[]? local = null;
                        Action assign = () => { local = plain; };
                        assign();
                        System.GC.KeepAlive(local);
                    });
            #pragma warning restore CS0618
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    [Test]
    public async Task TPS002_fires_when_captured_local_is_assigned_in_nested_lambda()
    {
        // Same shape, but the local is declared outside Access — the
        // nesting must not hide the escape.
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                void M(ProtectedString ps)
                {
                    char[]? leaked = null;
            #pragma warning disable CS0618
                    ps.Access((char[] plain) =>
                    {
                        Action assign = () => { leaked = plain; };
                        assign();
                    });
            #pragma warning restore CS0618
                    System.GC.KeepAlive(leaked);
                }
            }
            """);
        AssertDiagnosticIds(d, "TPS002");
    }

    // ---- Negative controls: legitimate in-place operations --------------

    [Test]
    public async Task No_diagnostic_for_IndexOf_and_FixedTimeEquals_over_span_param()
    {
        var d = await RunAsync("""
            using System;
            using System.Runtime.InteropServices;
            using System.Security.Cryptography;
            using TopSecret;
            class C
            {
                bool M(ProtectedString ps, byte[] expected)
                {
                    return ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        int at = plain.IndexOf(':');
                        bool same = CryptographicOperations.FixedTimeEquals(MemoryMarshal.AsBytes(plain), expected);
                        return at >= 0 && same && plain.Length > 0;
                    });
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }

    [Test]
    public async Task No_diagnostic_for_CopyTo_into_stack_buffer_and_ProtectedString_ctor()
    {
        var d = await RunAsync("""
            using System;
            using TopSecret;
            class C
            {
                ProtectedString M(ProtectedString ps)
                {
                    return ps.Access((ReadOnlySpan<char> plain) =>
                    {
                        Span<char> destination = stackalloc char[plain.Length];
                        plain.CopyTo(destination);
                        plain[..2].CopyTo(destination);
                        return new ProtectedString(plain);
                    });
                }
            }
            """);
        AssertDiagnosticIds(d /* no expected diagnostics */);
    }
}
