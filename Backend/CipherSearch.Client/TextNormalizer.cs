using System.Text.RegularExpressions;

namespace CipherSearch.Client;

public static partial class TextNormalizer
{
    private static readonly HashSet<string> StopWords = [
        "a", "an", "the", "and", "or", "but", "is", "are", "was", "were", "be", "been",
        "to", "of", "in", "on", "at", "for", "with", "from", "by", "as", "it", "this",
        "that", "these", "those", "i", "you", "he", "she", "we", "they", "me", "my",
        "your", "our", "their", "not", "do", "does", "did", "have", "has", "had"];

    public static string[] Tokenize(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        // Python lower() expands U+0130 to i + combining dot.
        var lower = text.Replace("\u0130", "i\u0307").ToLowerInvariant();
        return Words().Matches(lower).Select(m => m.Value)
            .Where(w => w.Length > 1 && !StopWords.Contains(w)).ToArray();
    }

    public static string Query(string text)
    {
        var tokens = Tokenize(text);
        if (tokens.Length != 1) throw new ArgumentException("Exactly one searchable keyword is required.");
        return tokens[0];
    }

    [GeneratedRegex("[a-z]+", RegexOptions.CultureInvariant)]
    private static partial Regex Words();
}
