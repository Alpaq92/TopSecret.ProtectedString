using System.Diagnostics;
using System.Reflection;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

internal static class TestAccessors
{
    private static readonly FieldInfo s_ciphertext = Field("_ciphertext");
    private static readonly FieldInfo s_nonce = Field("_nonce");
    private static readonly FieldInfo s_tag = Field("_tag");

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

    public static void ResetFactoryRegistrations() =>
        s_resetRegistrations.Invoke(null, null);

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

    public static KeyAtRestProtector? GetProcessKeyProtector() =>
        (KeyAtRestProtector?)s_keyProtectorField.GetValue(null);

    public static void SetProcessKeyProtector(KeyAtRestProtector? protector) =>
        s_keyProtectorField.SetValue(null, protector);
}

internal sealed class AlwaysThrowingProtector : KeyAtRestProtector
{
    public override KeyAccessor UnwrapKey() =>
        throw new InvalidOperationException("simulated protector failure");
}

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
