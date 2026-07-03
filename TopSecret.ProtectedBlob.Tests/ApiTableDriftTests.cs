using System.Reflection;
using TopSecret;

namespace TopSecret.ProtectedBlobTests;

/// <summary>
/// Asserts the README's "### ProtectedBlob API surface" section stays in
/// sync with the actual public surface of <see cref="ProtectedBlob"/> —
/// the sibling of the core suite's <c>ApiTableDriftTests</c>, with the
/// helpers duplicated because the repo deliberately has no shared
/// test-utility project.
/// </summary>
[TestFixture]
public class ApiTableDriftTests
{
    private const string SectionHeading = "### ProtectedBlob API surface";

    [Test]
    public void ProtectedBlob_api_section_in_README_mentions_every_public_member()
    {
        var readme = LoadReadme();
        var apiSection = ExtractSection(readme, SectionHeading);

        var missing = EnumerateDocumentablePublicMemberNames()
            .Where(name => !MentionsMember(apiSection, name))
            .OrderBy(s => s)
            .ToList();

        Assert.That(missing, Is.Empty,
            $"The README's '{SectionHeading}' section is missing entries for the following " +
            "public members of TopSecret.ProtectedBlob. Either add a row to the API table " +
            "or, if the member is intentionally omitted from the public docs, exclude it " +
            "from EnumerateDocumentablePublicMemberNames in this test:\n  " +
            string.Join("\n  ", missing));
    }

    private static IEnumerable<string> EnumerateDocumentablePublicMemberNames()
    {
        const BindingFlags flags =
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (var member in typeof(ProtectedBlob).GetMembers(flags))
        {
            switch (member)
            {
                case ConstructorInfo:
                    names.Add(nameof(ProtectedBlob));
                    break;

                case MethodInfo method when !method.IsSpecialName:
                    names.Add(method.Name);
                    break;

                case PropertyInfo property:
                    names.Add(property.Name);
                    break;

                case FieldInfo field when field.IsPublic:
                    // Public constants (DefaultChunkSize / MinChunkSize /
                    // MaxChunkSize) are part of the documented surface.
                    names.Add(field.Name);
                    break;
            }
        }

        return names;
    }

    private static string ExtractSection(string readme, string startHeading)
    {
        int start = readme.IndexOf(startHeading, StringComparison.Ordinal);
        Assert.That(start, Is.GreaterThanOrEqualTo(0),
            $"README is missing the '{startHeading}' heading — did the section get renamed?");

        int hashCount = 0;
        while (hashCount < startHeading.Length && startHeading[hashCount] == '#') hashCount++;

        int cursor = start + startHeading.Length;
        while (cursor < readme.Length)
        {
            int nl = readme.IndexOf('\n', cursor);
            if (nl < 0) break;
            int lineStart = nl + 1;
            int h = 0;
            while (lineStart + h < readme.Length && readme[lineStart + h] == '#') h++;
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
