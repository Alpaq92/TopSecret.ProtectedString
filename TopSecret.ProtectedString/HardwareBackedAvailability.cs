namespace TopSecret;

/// <summary>
/// Whether a hardware-backed master-key protector is available on this host.
/// Returned by <see cref="ProtectedString.HardwareBackedAvailability"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is a non-destructive probe: it reports whether at least one provider
/// (built-in or registered through
/// <see cref="KeyAtRestProtectorFactory.RegisterHardwareBacked"/>) <i>claims</i>
/// it can construct on the current host. It does <b>not</b> actually
/// initialise the secure element — that happens lazily on the first
/// <see cref="ProtectedString"/> construction.
/// </para>
/// <para>
/// On Apple platforms the probe is destructive but cached: the first call
/// generates and immediately discards a SEP-resident EC key to determine
/// whether the Secure Enclave is actually present, then caches the result
/// for the lifetime of the process. iOS Simulator on x86_64 and pre-T1
/// Intel Macs ship the built-in but lack the SEP, and report
/// <see cref="NoProviderForThisPlatform"/>. Subsequent calls are a single
/// volatile read.
/// </para>
/// </remarks>
// REVIEW (skipped from SECURITY-REVIEW.md #4B):
// A third enum value `MayFailAtRuntime` was considered, to model the
// "we ship a built-in but can't promise it'll succeed without a destructive
// probe" case without paying for the probe. It was rejected because it
// breaks the binary contract of this enum and pushes the decision back to
// the consumer. The Apple destructive probe (#4A, implemented) gives a
// definite answer behind the existing two-value API.
public enum HardwareBackedAvailability
{
    /// <summary>
    /// At least one hardware-backed provider claims to be available on this
    /// host. Apple platforms always report this; Android (on the
    /// <c>net10.0-android</c> TFM) always reports this; Windows and Linux
    /// report this only when an external provider has been registered (e.g.
    /// the <c>TopSecret.ProtectedString.WindowsTpm</c> or
    /// <c>TopSecret.ProtectedString.LinuxTpm</c> NuGets for TPM 2.0).
    /// </summary>
    Available,

    /// <summary>
    /// No hardware-backed provider is available on this host. Construction
    /// under <see cref="KeyAtRestProtection.HardwareBackedRequired"/> would
    /// throw; <see cref="KeyAtRestProtection.HardwareBackedPreferred"/>
    /// would fall back to <see cref="KeyAtRestProtection.Obscurity"/>.
    /// </summary>
    NoProviderForThisPlatform,
}
