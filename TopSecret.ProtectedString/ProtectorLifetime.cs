namespace TopSecret;

/// <summary>
/// Reference-counts the holders of each <see cref="KeyAtRestProtector"/> —
/// every <see cref="ProtectedString"/> and <c>TopSecret.ProtectedBlob</c>
/// instance takes a reference on the protector it snapshots at construction —
/// so a protector superseded by <see cref="ProtectedString.RotateProcessKey"/>
/// can be disposed (master zeroed, lock released, TPM / Secure Element
/// transient slot flushed) deterministically when the last holder lets go,
/// instead of whenever the GC happens to finalize it.
/// </summary>
/// <remarks>
/// The current (non-superseded) protector is never disposed regardless of
/// count. Disposal requires both: the protector was marked superseded by a
/// rotation, and its holder count reached zero. The two dispose call sites
/// (<see cref="Release"/> and <see cref="MarkSuperseded"/>) can race each
/// other benignly — every protector's <c>Dispose</c> is idempotent. The
/// snapshot/AddRef vs. swap/MarkSuperseded race is closed by full fences on
/// both sides: <see cref="AddRef"/>'s Interlocked increment pairs with the
/// full-fence count read in <see cref="MarkSuperseded"/>, so either the
/// snapshotting thread's re-validation observes the swap, or the rotation
/// observes the new reference (see
/// <c>ProtectedString.SnapshotProtectorWithRef</c>).
/// </remarks>
internal static class ProtectorLifetime
{
    /// <summary>Records a new holder. Interlocked — safe from any thread, including finalizers.</summary>
    public static void AddRef(KeyAtRestProtector protector) =>
        Interlocked.Increment(ref protector.LifetimeHolderCount);

    /// <summary>
    /// Releases a holder reference taken by <see cref="AddRef"/>; disposes
    /// the protector when it was the last reference to a superseded one.
    /// </summary>
    public static void Release(KeyAtRestProtector protector)
    {
        if (Interlocked.Decrement(ref protector.LifetimeHolderCount) == 0 &&
            protector.LifetimeSuperseded)
        {
            (protector as IDisposable)?.Dispose();
        }
    }

    /// <summary>
    /// Marks <paramref name="protector"/> as rotated out; disposes it on the
    /// spot when no holder references remain. The count read is a full-fence
    /// Interlocked op so it pairs with the fence in <see cref="AddRef"/>.
    /// </summary>
    public static void MarkSuperseded(KeyAtRestProtector protector)
    {
        protector.LifetimeSuperseded = true;
        if (Interlocked.CompareExchange(ref protector.LifetimeHolderCount, 0, 0) == 0)
        {
            (protector as IDisposable)?.Dispose();
        }
    }
}
