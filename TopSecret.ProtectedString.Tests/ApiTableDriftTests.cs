using System.IO;
using System.Reflection;
using TopSecret;

namespace TopSecret.ProtectedStringTests;

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

        return true;
    }

    private static string ExtractSection(string readme, string startHeading)
    {
        int start = readme.IndexOf(startHeading, StringComparison.Ordinal);
        Assert.That(start, Is.GreaterThanOrEqualTo(0),
            $"README is missing the '{startHeading}' heading — did the section get renamed?");

        int hashCount = 0;
        while (hashCount < startHeading.Length && startHeading[hashCount] == '#') hashCount++;

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
