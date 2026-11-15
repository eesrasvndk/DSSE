using Microsoft.Extensions.Configuration;

// Local development settings shared by the two hosts; no credentials are written to logs.
internal static class LocalSettings
{
    public static void Load(ConfigurationManager configuration, string contentRoot)
    {
        var root = new DirectoryInfo(contentRoot);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, ".env"))) root = root.Parent;
        if (root is null) throw new InvalidOperationException("Project .env not found.");
        var settings = File.ReadLines(Path.Combine(root.FullName, ".env"))
            .Where(l => l.Contains('=') && !l.TrimStart().StartsWith('#'))
            .Select(l => l.Split('=', 2)).ToDictionary(p => p[0].Trim(), p => p[1].Trim().Trim('"', '\''));
        string Q(string value) => "\"" + value.Replace("\"", "\"\"") + "\"";
        configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Postgres"] = $"Host=127.0.0.1;Port=5432;Database={Q(settings["POSTGRES_DB"])};Username={Q(settings["POSTGRES_USER"])};Password={Q(settings["POSTGRES_PASSWORD"])};Search Path=dsse",
            ["Minio:Endpoint"] = "127.0.0.1:9000",
            ["Minio:AccessKey"] = settings["MINIO_ROOT_USER"],
            ["Minio:SecretKey"] = settings["MINIO_ROOT_PASSWORD"],
            ["Minio:Bucket"] = "dsse-documents",
            ["Leakage:Path"] = Path.Combine(root.FullName, "tmp/server-leakage.jsonl"),
            ["VaultRoot"] = Path.Combine(root.FullName, "tmp/web-vaults")
        });
    }
}
