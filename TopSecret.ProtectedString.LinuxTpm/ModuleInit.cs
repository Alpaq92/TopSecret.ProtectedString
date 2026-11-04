using System.Runtime.CompilerServices;
using TopSecret;

namespace TopSecret.LinuxTpm;

internal static class ModuleInit
{
#pragma warning disable CA2255
    [ModuleInitializer]
#pragma warning restore CA2255
    public static void Initialize()
    {
        LinuxTpmRegistration.Register();
    }
}

public static class LinuxTpmRegistration
{
    private static int s_registered;

    public static void Register() =>
        HardwareProviderRegistration.RegisterOnce(
            ref s_registered,
            factory: LinuxTpmProtector.TryCreate,
            probe: LinuxTpmProtector.IsAvailable,
            transientSlotConstrained: true);
}
