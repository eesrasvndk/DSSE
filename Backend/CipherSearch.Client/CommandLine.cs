namespace CipherSearch.Client;

internal static class CommandLine
{
    public static string Option(string[] args, string name, string fallback) => OptionOrNull(args, name) ?? fallback;

    public static string? OptionOrNull(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index < 0 ? null : args.ElementAtOrDefault(index + 1) ?? throw new ArgumentException($"Missing {name} value.");
    }
}
