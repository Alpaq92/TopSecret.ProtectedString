using System.Runtime.InteropServices.JavaScript;
using System.Text;
using TopSecret.Demo;

namespace TopSecret.DemoWasm;

public static partial class Program
{
    private static bool s_outputWired;

    public static void Main() { }

    [JSExport]
    internal static async Task RunDemo()
    {
        if (!s_outputWired)
        {
            Console.SetOut(new TerminalWriter());
            s_outputWired = true;
        }

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

    [JSImport("term.enqueue", "main.js")]
    internal static partial void EnqueueLine(string line);

    private sealed class TerminalWriter : TextWriter
    {
        private readonly StringBuilder _line = new();

        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(char value)
        {
            if (value == '\n')
            {
                EnqueueLine(_line.ToString());
                _line.Clear();
            }
            else if (value != '\r')
            {
                _line.Append(value);
            }
        }

        public override void Write(string? value)
        {
            if (string.IsNullOrEmpty(value)) return;
            foreach (var c in value) Write(c);
        }

        public override void Flush()
        {
            if (_line.Length == 0) return;
            EnqueueLine(_line.ToString());
            _line.Clear();
        }
    }
}
