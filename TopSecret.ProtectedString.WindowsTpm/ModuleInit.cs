using System.Runtime.CompilerServices;
using TopSecret;

namespace TopSecret.WindowsTpm;

internal static class ModuleInit
{
#pragma warning disable CA2255
    [ModuleInitializer]
#pragma warning restore CA2255
    public static void Initialize()
    {
        WindowsTpmRegistration.Register();
    }
}

public static class WindowsTpmRegistration
{
    private static int s_registered;

    public static void Register() =>
        HardwareProviderRegistration.RegisterOnce(
            ref s_registered,
            factory: WindowsTpmProtector.TryCreate,
            probe: WindowsTpmProtector.IsAvailable,
            transientSlotConstrained: true);
}
