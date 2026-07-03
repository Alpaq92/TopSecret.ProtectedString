namespace TopSecret;

/// <summary>
/// Process-wide configuration for <see cref="ProtectedBlob"/> — the
/// blob-shaped sibling of <see cref="ProtectedStringOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Scope.</b> Only blob-specific knobs live here. The security posture —
/// <see cref="ProtectedStringOptions.KeyAtRestProtection"/>,
/// <see cref="ProtectedStringOptions.UnwrappedKeyCacheTtl"/>, and
/// <see cref="ProtectedStringOptions.MemoryLockingFailureBehavior"/> — is
/// deliberately shared with <see cref="ProtectedString"/> through
/// <see cref="ProtectedStringOptions"/>, because both types wrap their keys
/// under the same process-wide master protector: one process, one posture.
/// </para>
/// <para>
/// <b>Read semantics.</b> Unlike the read-once keys on
/// <see cref="ProtectedStringOptions"/>, <see cref="DefaultChunkSize"/> is
/// read at <i>each</i> <see cref="ProtectedBlob"/> construction that does
/// not pass an explicit <c>chunkSize</c>, and is captured per instance for
/// that blob's lifetime. Changing it at runtime affects future blobs only —
/// no re-encryption, no warning machinery needed.
/// </para>
/// <para>
/// <b>Binding from configuration.</b> The optional
/// <c>TopSecret.ProtectedString.Configuration</c> package deliberately does
/// not reference this package (string-only consumers should not pull in the
/// blob assembly), so bind this option manually in your composition root:
/// </para>
/// <code>
/// if (int.TryParse(configuration["TopSecret:ProtectedBlob:DefaultChunkSize"], out var chunkSize))
/// {
///     ProtectedBlobOptions.DefaultChunkSize = chunkSize;
/// }
/// </code>
/// </remarks>
public static class ProtectedBlobOptions
{
    private static int s_defaultChunkSize = ProtectedBlob.DefaultChunkSize;

    /// <summary>
    /// The chunk size used by <see cref="ProtectedBlob"/> constructors and
    /// <see cref="ProtectedBlob.FromStream(Stream)"/> when no explicit
    /// <c>chunkSize</c> is passed. Defaults to
    /// <see cref="ProtectedBlob.DefaultChunkSize"/> (64 KiB); must be
    /// between <see cref="ProtectedBlob.MinChunkSize"/> and
    /// <see cref="ProtectedBlob.MaxChunkSize"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is out of range.</exception>
    public static int DefaultChunkSize
    {
        get => s_defaultChunkSize;
        set
        {
            ProtectedBlob.ValidateChunkSize(value, nameof(value));
            s_defaultChunkSize = value;
        }
    }
}
