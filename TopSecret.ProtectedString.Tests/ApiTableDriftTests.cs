using System.IO;
using System.Reflection;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

/// <summary>
/// Asserts the README's API surface table stays in sync with the actual
/// public surface of <see cref="global::TopSecret.ProtectedString"/>. This
/// is the kind of drift that the maintainer hits whenever they refactor
/// the implementation without remembering that the README documents the
/// same surface in three different tables (API surface, SecureString
/// comparison, GuardedString comparison).
/// </summary>
/// <remarks>
/// <para>
/// Direction of the check: every public member declared on
/// <see cref="ProtectedString"/> must appear at least once inside the
/// README's "## API surface" section. The match is a backticked-name
/// substring test (e.g., <c>`AppendChar`</c> or <c>`AppendChar(char)`</c>)
/// — strict enough to catch additions/removals, lax enough not to fail
/// on legitimate phrasing changes inside a row.
/// </para>
/// <para>
/// What this does <i>not</i> catch:
/// </para>
/// <list type="bullet">
///   <item>Stale prose elsewhere in the README — a row that says
///   "AppendChar (O(n²) on hardware-backed wraps)" passes this check
///   because the substring <c>`AppendChar`</c> is present even though
///   the rest of the cell is wrong. Catching that requires generating
///   the table from xmldoc and diffing — out of scope here.</item>
///   <item>Overload-level drift. The check is by member name, so adding
///   a fifth <c>Access</c> overload doesn't trip it as long as
///   <c>`Access`</c> already appears.</item>
/// </list>
/// <para>
/// Both gaps are documented intentional limits — this test is a
/// "did you forget to update the README at all" guard, not a
/// "is the README perfectly accurate" guard.
/// </para>
/// </remarks>
[TestFixture]
public class ApiTableDriftTests
{
    [Test]
    public void Api_surface_section_in_README_mentions_every_public_member()
    {
        var readme = LoadReadme();
        var apiSection = ExtractSection(readme, "## API surface");

        var missing = EnumerateDocumentablePublicMemberNames()
            .Where(name => !MentionsMember(apiSection, name))
            .OrderBy(s => s)
            .ToList();

        Assert.That(missing, Is.Empty,
            "The README's '## API surface' section is missing entries for the following " +
            "public members of TopSecret.ProtectedString. Either add a row to the API table " +
            "or, if the member is intentionally omitted from the public docs, exclude it " +
            "from EnumerateDocumentablePublicMemberNames in this test:\n  " +
            string.Join("\n  ", missing));
    }

    // ---- Enum-table drift guards ---------------------------------------
    // Each public enum the library exposes has a documented table in the
    // README. Adding / renaming / removing an enum value without updating
    // the corresponding table is the same class of drift as adding a
    // public method without updating the API surface — these tests catch
    // it the same way.

    [Test]
    public void KeyAtRestProtection_enum_values_are_all_in_README()
    {
        AssertReadmeMentionsAllEnumValues<KeyAtRestProtection>(
            sectionStartHeading: "### Key-at-rest wrapping (opt-in, tiered)");
    }

    [Test]
    public void ProcessKeyRotation_enum_values_are_all_in_README()
    {
        AssertReadmeMentionsAllEnumValues<ProcessKeyRotation>(
            sectionStartHeading: "### Process-key rotation (opt-in)");
    }

    [Test]
    public void MemoryLockingFailureBehavior_enum_values_are_all_in_README()
    {
        AssertReadmeMentionsAllEnumValues<MemoryLockingFailureBehavior>(
            sectionStartHeading: "### Memory-locking policy");
    }

    /// <summary>
    /// Extracts the README section bounded by <paramref name="sectionStartHeading"/>
    /// (inclusive) and the next heading at the same level, then asserts
    /// every value of <typeparamref name="TEnum"/> appears as an
    /// identifier inside that section.
    /// </summary>
    private static void AssertReadmeMentionsAllEnumValues<TEnum>(string sectionStartHeading)
        where TEnum : struct, Enum
    {
        var readme = LoadReadme();
        var section = ExtractSection(readme, sectionStartHeading);

        var enumValues = Enum.GetNames(typeof(TEnum));
        var missing = enumValues
            .Where(v => !MentionsMember(section, v))
            .OrderBy(s => s)
            .ToList();

        Assert.That(missing, Is.Empty,
            $"The README's '{sectionStartHeading}' section is missing mentions for these " +
            $"{typeof(TEnum).Name} values: {string.Join(", ", missing)}.\n" +
            $"Either add a row / mention to the section, or — if the value is intentionally " +
            $"omitted from the public docs — exclude it from this test by name.");
    }

    /// <summary>
    /// Returns the distinct names of every public member on
    /// <see cref="ProtectedString"/> that the README is expected to
    /// document — public constructors (canonicalised to the type name),
    /// public instance + static methods, and public instance + static
    /// properties. Filters out compiler-generated accessors, inherited
    /// <see cref="object"/> overrides, and operator overloads.
    /// </summary>
    private static IEnumerable<string> EnumerateDocumentablePublicMemberNames()
    {
        const BindingFlags flags =
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (var member in typeof(ProtectedString).GetMembers(flags))
        {
            switch (member)
            {
                case ConstructorInfo:
                    // The README writes constructors as `ProtectedString()`
                    // / `ProtectedString(string)` etc. Canonicalise to the
                    // type name.
                    names.Add(nameof(ProtectedString));
                    break;

                case MethodInfo method when ShouldDocument(method):
                    names.Add(method.Name);
                    break;

                case PropertyInfo property:
                    names.Add(property.Name);
                    break;

                // Fields, events, nested types, etc. are not part of the
                // documented API surface.
            }
        }

        return names;
    }

    private static bool ShouldDocument(MethodInfo method)
    {
        // Property accessors (get_X, set_X) are documented via the
        // PropertyInfo entry, not the MethodInfo entry.
        if (method.IsSpecialName) return false;

        // Inherited object overrides (Equals(object), GetHashCode, ToString)
        // are intentionally on the API surface, BUT object.Equals(object?)
        // overrides report DeclaringType == typeof(ProtectedString); we
        // include them. The DeclaredOnly binding flag already filters out
        // un-overridden inherited methods.
        return true;
    }

    /// <summary>
    /// Returns the substring of <paramref name="readme"/> bounded by
    /// <paramref name="startHeading"/> (inclusive) and the next heading
    /// at the same depth or shallower. Used so the "is this name
    /// mentioned" tests are scoped to the relevant section only, not
    /// the entire 1000-line README.
    /// </summary>
    /// <param name="startHeading">
    /// A literal heading line — e.g. <c>"## API surface"</c> or
    /// <c>"### Memory-locking policy"</c>. The depth is inferred from
    /// the leading <c>#</c>s and the search for the next boundary stops
    /// at any heading of equal or shallower depth.
    /// </param>
    private static string ExtractSection(string readme, string startHeading)
    {
        int start = readme.IndexOf(startHeading, StringComparison.Ordinal);
        Assert.That(start, Is.GreaterThanOrEqualTo(0),
            $"README is missing the '{startHeading}' heading — did the section get renamed?");

        int hashCount = 0;
        while (hashCount < startHeading.Length && startHeading[hashCount] == '#') hashCount++;

        // Walk forward looking for the next line that starts with at most
        // `hashCount` '#'s followed by a space — a heading at equal or
        // shallower depth. That's the right end-of-section boundary
        // because deeper headings (e.g. `####` inside a `###` section)
        // are still part of the same section.
        int afterStart = start + startHeading.Length;
        int cursor = afterStart;
        while (cursor < readme.Length)
        {
            int nl = readme.IndexOf('\n', cursor);
            if (nl < 0) { cursor = readme.Length; break; }
            int lineStart = nl + 1;
            // Count leading hashes on the next line.
            int h = 0;
            while (lineStart + h < readme.Length && readme[lineStart + h] == '#') h++;
            // Heading at this depth or shallower? Stop here.
            if (h > 0 && h <= hashCount && lineStart + h < readme.Length && readme[lineStart + h] == ' ')
            {
                return readme.Substring(start, lineStart - start);
            }
            cursor = lineStart;
        }
        return readme.Substring(start);
    }

    private static bool MentionsMember(string section, string memberName)
    {
        // Word-boundary search inside the section. A match requires the
        // member name to be flanked by non-identifier characters on both
        // sides — so `AppendChar`, `static HardwareBackedAvailability`,
        // `Equals(ProtectedString)`, and `Access<T>(ReadOnlySpanFunc...)`
        // all match cleanly, while a hypothetical `AppendCharBuilder`
        // does not. The match is intentionally not anchored to backticks
        // so qualifiers like `static ` between the backtick and the name
        // do not defeat the check — backticks are not the only character
        // the README puts in front of a member name.
        int idx = 0;
        while ((idx = section.IndexOf(memberName, idx, StringComparison.Ordinal)) >= 0)
        {
            bool leftIsBoundary = idx == 0 || !IsIdentifierChar(section[idx - 1]);
            int afterEnd = idx + memberName.Length;
            bool rightIsBoundary = afterEnd == section.Length || !IsIdentifierChar(section[afterEnd]);
            if (leftIsBoundary && rightIsBoundary) return true;
            idx = afterEnd;
        }
        return false;
    }

    private static bool IsIdentifierChar(char c) =>
        char.IsLetterOrDigit(c) || c == '_';

    /// <summary>
    /// Locates <c>README.md</c> at the repo root, walking up from the
    /// test assembly's location. Tests run from
    /// <c>bin/{Configuration}/net10.0/</c> under the test project, so
    /// the repo root is four directories up — but we walk by looking for
    /// the file rather than counting, so the test stays correct under
    /// alternative output layouts.
    /// </summary>
    private static string LoadReadme()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "README.md");
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }
        }

        Assert.Fail(
            $"Could not locate README.md walking up from {AppContext.BaseDirectory}. " +
            "If the test layout has changed, update LoadReadme.");
        return string.Empty; // unreachable
    }
}
