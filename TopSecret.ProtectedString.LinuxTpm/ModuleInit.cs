using System.Runtime.CompilerServices;
using TopSecret;

namespace TopSecret.LinuxTpm;

/// <summary>
/// Auto-registers <see cref="LinuxTpmProtector"/> with the main package's
/// <see cref="KeyAtRestProtectorFactory"/> at assembly load. Consumers do
/// not call this directly — referencing
/// <c>TopSecret.ProtectedString.LinuxTpm</c> from any project that also
/// references <c>TopSecret.ProtectedString</c> is enough.
/// </summary>
/// <remarks>
/// <para>
/// On non-Linux hosts the module initializer still runs, but
/// <see cref="LinuxTpmProtector.IsAvailable"/> returns <see langword="false"/>
/// and <see cref="LinuxTpmProtector.TryCreate"/> returns
/// <see langword="null"/>, so the registration is a no-op in practice. This
/// keeps the package safely referenceable from cross-platform projects.
/// </para>
/// <para>
/// Module initializers run exactly once per assembly load, before any
/// caller-visible member of this assembly is touched. The registration
/// therefore lands before the first <see cref="ProtectedString"/>
/// construction <i>provided</i> the consumer references this assembly
/// strongly enough that the runtime loads it eagerly. If the consumer
/// relies on lazy / dynamic loading, register manually via
/// <see cref="LinuxTpmRegistration.Register"/> in their composition root.
/// </para>
/// </remarks>
internal static class ModuleInit
{
    // CA2255: ModuleInitializer is normally for app code, not libraries. We
    // use it deliberately here as the no-config wiring contract documented
    // in the package description; consumers who need explicit ordering can
    // call LinuxTpmRegistration.Register() instead.
#pragma warning disable CA2255
    [ModuleInitializer]
#pragma warning restore CA2255
    public static void Initialize()
    {
        LinuxTpmRegistration.Register();
    }
}

/// <summary>
/// Public registration entry-point. Call <see cref="Register"/> manually
/// from your composition root if you cannot rely on
/// <see cref="ModuleInit"/> firing in time (e.g. dynamic assembly loading).
/// </summary>
public static class LinuxTpmRegistration
{
    private static int s_registered;

    /// <summary>
    /// Registers <see cref="LinuxTpmProtector"/> with
    /// <see cref="KeyAtRestProtectorFactory"/>. Idempotent — repeated calls
    /// are no-ops. Safe to call from any platform; the factory delegate
    /// returns <see langword="null"/> on non-Linux hosts.
    /// </summary>
    public static void Register()
    {
        if (Interlocked.CompareExchange(ref s_registered, 1, 0) != 0) return;

        KeyAtRestProtectorFactory.RegisterHardwareBacked(
            factory: LinuxTpmProtector.TryCreate,
            availabilityProbe: LinuxTpmProtector.IsAvailable,
            // TPM 2.0 keeps generated keys in transient slots (≤3 on
            // commodity TPMs). Periodic process-key rotation orphans the
            // old protectors; without this flag the main package can't
            // tell the operator that they're about to hit TPM_RC_RESOURCES.
            transientSlotConstrained: true);
    }
}
