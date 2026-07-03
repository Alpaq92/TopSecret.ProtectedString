using System.Diagnostics;
using System.Reflection;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

/// <summary>
/// Reflection helpers used only by tests that need to peek at private state
/// (e.g., to verify nonce uniqueness across instances or POH residency), or
/// to invoke members that production code is locked out of via
/// <c>[Obsolete(error: true)]</c>.
/// </summary>
internal static class TestAccessors
{
    private static readonly FieldInfo s_ciphertext = Field("_ciphertext");
    private static readonly FieldInfo s_nonce = Field("_nonce");
    private static readonly FieldInfo s_tag = Field("_tag");

    // The runtime does not enforce ObsoleteAttribute, so reflection bypasses
    // the [Obsolete(error: true)] compile-time block on
    // ResetRegistrationsForTests. nameof() is a compile-time string
    // extraction that does not count as a "use" of the obsolete member, so
    // the symbol is refactor-safe — a rename in the main package breaks this
    // line at build time instead of producing a silent runtime null.
    private static readonly MethodInfo s_resetRegistrations =
        typeof(global::TopSecret.KeyAtRestProtectorFactory).GetMethod(
            nameof(global::TopSecret.KeyAtRestProtectorFactory.ResetRegistrationsForTests),
            BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException(
            $"{nameof(global::TopSecret.KeyAtRestProtectorFactory)}." +
            $"{nameof(global::TopSecret.KeyAtRestProtectorFactory.ResetRegistrationsForTests)} " +
            "not found via reflection");

    private static FieldInfo Field(string name) =>
        typeof(global::TopSecret.ProtectedString)
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException($"Field {name} not found");

    public static byte[] GetCiphertext(global::TopSecret.ProtectedString ps)
    {
        var ct = (byte[]?)s_ciphertext.GetValue(ps);
        return ct is null ? Array.Empty<byte>() : (byte[])ct.Clone();
    }

    public static byte[]? GetCiphertextRaw(global::TopSecret.ProtectedString ps) =>
        (byte[]?)s_ciphertext.GetValue(ps);

    public static byte[]? GetNonceRaw(global::TopSecret.ProtectedString ps) =>
        (byte[]?)s_nonce.GetValue(ps);

    public static byte[]? GetTagRaw(global::TopSecret.ProtectedString ps) =>
        (byte[]?)s_tag.GetValue(ps);

    /// <summary>
    /// Invokes the test-only registry-reset hook on
    /// <c>KeyAtRestProtectorFactory</c>. The hook itself is marked
    /// <c>[Obsolete(error: true)]</c> to make every source-level call from
    /// production code a CS0619 build failure; this reflection wrapper is the
    /// single sanctioned bypass for the test fixture that legitimately needs
    /// to clear and re-populate the registry between tests.
    /// </summary>
    public static void ResetFactoryRegistrations() =>
        s_resetRegistrations.Invoke(null, null);

    /// <summary>
    /// Test-only: replaces the per-instance protector reference on
    /// <paramref name="ps"/> with <paramref name="protector"/>.
    /// </summary>
    public static void SetInstanceProtector(global::TopSecret.ProtectedString ps, KeyAtRestProtector protector)
    {
        var field = typeof(global::TopSecret.ProtectedString)
            .GetField("_instanceProtector", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("_instanceProtector field not found");
        field.SetValue(ps, protector);
    }

    private static readonly FieldInfo s_keyProtectorField =
        typeof(global::TopSecret.ProtectedString)
            .GetField("s_keyProtector", BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("s_keyProtector field not found");

    /// <summary>
    /// Test-only: returns the current process-wide protector (lazily
    /// initialised on first <c>ProtectedString</c> construction; may be
    /// <see langword="null"/> if no instance has yet been built).
    /// </summary>
    public static KeyAtRestProtector? GetProcessKeyProtector() =>
        (KeyAtRestProtector?)s_keyProtectorField.GetValue(null);

    /// <summary>
    /// Test-only: replaces the process-wide protector. Necessary together
    /// with <see cref="SetInstanceProtector"/> when driving the
    /// rotation-failed branch — the rotation-internal migration only
    /// touches instances whose <c>_instanceProtector</c> is reference-equal
    /// to the global <c>s_keyProtector</c> at rotation start.
    /// </summary>
    public static void SetProcessKeyProtector(KeyAtRestProtector? protector) =>
        s_keyProtectorField.SetValue(null, protector);
}

/// <summary>
/// Test-only protector whose <see cref="UnwrapKey"/> always throws. Used
/// to drive the rotation-failed branch of
/// <c>ProtectedString.RotateInternal</c> deterministically.
/// </summary>
internal sealed class AlwaysThrowingProtector : KeyAtRestProtector
{
    public override KeyAccessor UnwrapKey() =>
        throw new InvalidOperationException("simulated protector failure");
}

/// <summary>
/// Captures every <c>Write</c> / <c>WriteLine</c> the trace pipeline pushes
/// at this listener so a test can assert on the formatted message content.
/// </summary>
internal sealed class CapturingTraceListener : TraceListener
{
    public List<string> Messages { get; } = new();

    public override void Write(string? message)
    {
        if (!string.IsNullOrEmpty(message)) Messages.Add(message);
    }

    public override void WriteLine(string? message)
    {
        if (!string.IsNullOrEmpty(message)) Messages.Add(message);
    }
}
