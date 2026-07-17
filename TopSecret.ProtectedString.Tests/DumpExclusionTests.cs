using System.Runtime.InteropServices;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

[TestFixture]
public class DumpExclusionTests
{
    [Test]
    public void IsSupported_matches_platform_capability()
    {
        // Windows 10+ (WerRegisterExcludedMemoryBlock) and Linux (madvise
        // MADV_DONTDUMP, kernel 3.4+) — both of which cover every CI leg that
        // runs this TFM — must report support. Other platforms report false
        // and the primitives degrade to no-ops.
        if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux())
        {
            Assert.That(DumpExclusion.IsSupported, Is.True);
        }
        else
        {
            Assert.That(DumpExclusion.IsSupported, Is.False);
        }
    }

    [Test]
    public void WipeOnFork_support_matches_platform_and_range_calls_are_safe()
    {
        // MADV_WIPEONFORK is Linux/Android (4.14+) only; every other host —
        // including Windows, where the CI leg for this TFM runs — reports
        // unsupported and the range call is a no-op that still returns true.
        if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ||
            OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
        {
            Assert.That(DumpExclusion.IsWipeOnForkSupported, Is.False);
        }

        var page = GC.AllocateArray<byte>(Environment.SystemPageSize, pinned: true);
        var addr = Marshal.UnsafeAddrOfPinnedArrayElement(page, 0);
        // On an unsupported host this is a silent no-op returning true; on
        // Linux it applies MADV_WIPEONFORK and returns the syscall result.
        Assert.DoesNotThrow(() => DumpExclusion.TryWipeOnForkRange(addr, page.Length));
        if (!DumpExclusion.IsWipeOnForkSupported)
        {
            Assert.That(DumpExclusion.TryWipeOnForkRange(addr, page.Length), Is.True,
                "unsupported hosts treat wipe-on-fork as a no-op success");
        }
    }

    [Test]
    public void TryExclude_then_TryInclude_round_trips_on_pinned_buffer()
    {
        var buffer = GC.AllocateArray<byte>(64, pinned: true);

        // True on supported platforms (the primitive succeeded) AND on
        // not-applicable ones (the caller cannot act on a capability the OS
        // does not offer, so absence is not reported as failure).
        Assert.That(DumpExclusion.TryExclude(buffer), Is.True);
        Assert.DoesNotThrow(() => DumpExclusion.TryInclude(buffer));
    }

    [Test]
    public void Empty_buffer_is_a_no_op_success()
    {
        var empty = Array.Empty<byte>();
        Assert.That(DumpExclusion.TryExclude(empty), Is.True);
        Assert.DoesNotThrow(() => DumpExclusion.TryInclude(empty));
    }

    [Test]
    public void Sensitive_allocation_and_wipe_survive_the_dump_exclusion_path()
    {
        // End-to-end through the real choke points: AllocatePinnedBytes with
        // excludeFromDumps wires TryExclude; ZeroBytes → TryUnlock wires the
        // automatic TryInclude. Default policy is LogWarning, so any platform
        // shortfall degrades to a trace warning rather than a throw.
        var sensitive = ProtectedString.AllocatePinnedBytes(128, excludeFromDumps: true);
        Assert.That(sensitive.Length, Is.EqualTo(128));
        Assert.DoesNotThrow(() => ProtectedString.ZeroBytes(sensitive));

        // And the full type still round-trips with exclusion active on its
        // internal plaintext scratch.
        using var ps = new ProtectedString("dump-excluded".AsSpan());
        ps.Access(plain => Assert.That(plain.Length, Is.EqualTo(13)));
    }
}
