using System.Runtime.InteropServices;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

[TestFixture]
public class DumpExclusionTests
{
    [Test]
    public void IsSupported_matches_platform_capability()
    {
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
        var sensitive = ProtectedString.AllocatePinnedBytes(128, excludeFromDumps: true);
        Assert.That(sensitive.Length, Is.EqualTo(128));
        Assert.DoesNotThrow(() => ProtectedString.ZeroBytes(sensitive));

        // And the full type still round-trips with exclusion active on its
        // internal plaintext scratch.
        using var ps = new ProtectedString("dump-excluded".AsSpan());
        ps.Access(plain => Assert.That(plain.Length, Is.EqualTo(13)));
    }
}
