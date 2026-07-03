using System.Runtime.InteropServices.JavaScript;
using System.Text;
using TopSecret.Demo;

namespace TopSecret.DemoWasm;

/// <summary>
/// Browser entry point: routes <see cref="Console.Out"/> into the xterm.js
/// terminal rendered by <c>main.js</c>, then runs the same
/// <see cref="DemoApp"/> the console demo runs. <see cref="RunDemo"/> is
/// exported to JS so the page's "Run again" button can re-run the scenarios
/// without reloading the runtime.
/// </summary>
public static partial class Program
{
    public static async Task Main()
    {
        Console.SetOut(new TerminalWriter());
        await RunDemo();
    }

    [JSExport]
    internal static async Task RunDemo()
    {
        Console.WriteLine("TopSecret demo - running fully client-side in your browser (.NET WebAssembly).");
        Console.WriteLine("Nothing you see here leaves this page; there is no server.");
        Console.WriteLine();

        try
        {
            await DemoApp.RunAsync();
            Console.WriteLine();
            Console.WriteLine("Demo complete - press \x1b[1mRun again\x1b[0m to repeat.");
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.WriteLine($"Demo failed: {ex.GetType().Name}: {ex.Message}");
            throw;
        }
        finally
        {
            // Push any trailing not-yet-newline-terminated text to the terminal.
            Console.Out.Flush();
        }
    }

    [JSImport("term.write", "main.js")]
    internal static partial void TerminalWrite(string text);

    /// <summary>
    /// A <see cref="TextWriter"/> that forwards to xterm.js. The writer
    /// emits plain <c>\n</c>; xterm.js performs the <c>\n</c> → <c>\r\n</c>
    /// translation (<c>convertEol: true</c> in <c>main.js</c>). JS interop
    /// is batched per flushed segment, not per character.
    /// </summary>
    private sealed class TerminalWriter : TextWriter
    {
        private readonly StringBuilder _buffer = new();

        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(char value)
        {
            _buffer.Append(value);
            if (value == '\n') Flush();
        }

        public override void Write(string? value)
        {
            if (string.IsNullOrEmpty(value)) return;
            _buffer.Append(value);
            if (value.Contains('\n')) Flush();
        }

        public override void Flush()
        {
            if (_buffer.Length == 0) return;
            TerminalWrite(_buffer.ToString());
            _buffer.Clear();
        }
    }
}
