using CipherSearch.Client;
using CipherSearch.Contracts;

namespace CipherSearch.Web;

public sealed record DocumentInput(Guid DocumentId, long Revision, string Name, string Text);
public sealed record DocumentRow(Guid DocumentId, long Revision, string Name);
public sealed record SearchInput(string Keyword, bool Verify = true, bool Inspect = false);
public sealed record DeleteInput(long Revision);

public sealed class Workspace(IConfiguration configuration, IWebHostEnvironment environment) : IDisposable
{
    private readonly SemaphoreSlim gate = new(1);
    private readonly Dictionary<string, Session> sessions = new();
    private sealed record Session(string Path, LocalVault Vault, HttpClient Http, DocumentClient Client);

    public async Task<T> Run<T>(string scheme, Func<DocumentClient, LocalVault, string, Task<T>> action,
        Func<DocumentClient, LocalVault, Task>? initializeEmptyKamara = null)
    {
        if (scheme is not (SchemeIds.NaiveHmac or SchemeIds.Mitra or SchemeIds.Kamara))
            throw new ArgumentException("This search method is unavailable.");
        await gate.WaitAsync();
        try
        {
            if (!sessions.TryGetValue(scheme, out var session))
            {
                var root = configuration["VaultRoot"] ?? Path.Combine(environment.ContentRootPath, "../../tmp/web-vaults");
                var path = Path.GetFullPath(Path.Combine(root, scheme));
                var vault = new LocalVault(path, !Directory.Exists(path));
                if (scheme == SchemeIds.Kamara && vault.Exists("active-enron-collection"))
                {
                    vault.Dispose();
                    path = Path.Combine(path, "enron-collection");
                    vault = new LocalVault(path, false);
                }
                var http = new HttpClient { BaseAddress = new Uri(configuration["ServerUrl"] ?? "http://127.0.0.1:5180/"), Timeout = TimeSpan.FromMinutes(5) };
                try
                {
                    var scope = ReadScope(vault, scheme);
                    session = new(path, vault, http, new DocumentClient(http, scope, vault));
                    if (scheme == SchemeIds.Kamara && initializeEmptyKamara is not null && !vault.Exists("scope"))
                        await initializeEmptyKamara(session.Client, vault);
                    else
                        await session.Client.Initialize();
                    sessions.Add(scheme, session);
                }
                catch { http.Dispose(); vault.Dispose(); throw; }
            }
            await session.Client.Recover();
            if (scheme == SchemeIds.Kamara && initializeEmptyKamara is not null &&
                !Directory.EnumerateFiles(session.Path, "doc-*.state").Any() &&
                (await session.Client.Status()).Epoch == 0)
            {
                // Keep the old generation intact; a failed setup is resumed at the same path.
                var nextPath = Path.Combine(session.Path, "enron-collection");
                var nextVault = new LocalVault(nextPath, !Directory.Exists(nextPath));
                var nextHttp = new HttpClient { BaseAddress = session.Http.BaseAddress, Timeout = session.Http.Timeout };
                try
                {
                    var nextScope = ReadScope(nextVault, scheme);
                    var nextClient = new DocumentClient(nextHttp, nextScope, nextVault);
                    if (nextVault.Exists("scope")) await nextClient.Initialize();
                    else await initializeEmptyKamara(nextClient, nextVault);
                    session.Vault.Save("active-enron-collection", true);
                    session.Http.Dispose();
                    session.Vault.Dispose();
                    session = new(nextPath, nextVault, nextHttp, nextClient);
                    sessions[scheme] = session;
                }
                catch { nextHttp.Dispose(); nextVault.Dispose(); throw; }
            }
            return await action(session.Client, session.Vault, session.Path);
        }
        finally { gate.Release(); }
    }

    private static IndexScope ReadScope(LocalVault vault, string scheme) =>
        DocumentClient.ReadSavedScope(vault) ?? new IndexScope(Guid.NewGuid(), scheme, Guid.NewGuid(), 1);

    public static LocalDocument Get(LocalVault vault, Guid id)
    {
        if (id == Guid.Empty || !vault.Exists($"doc-{id:N}")) throw new KeyNotFoundException();
        var doc = vault.Load<LocalDocument>($"doc-{id:N}");
        return doc.Deleted ? throw new KeyNotFoundException() : doc;
    }

    public static DocumentRow Row(LocalVault vault, LocalDocument doc) => new(doc.DocumentId, doc.Revision,
        vault.Exists($"name-{doc.DocumentId:N}") ? vault.Load<string>($"name-{doc.DocumentId:N}") : doc.DocumentId.ToString());

    public static DocumentRow[] List(LocalVault vault, string path) => Directory.EnumerateFiles(path, "doc-*.state")
        .Select(file => vault.Load<LocalDocument>(Path.GetFileNameWithoutExtension(file)))
        .Where(doc => !doc.Deleted).Select(doc => Row(vault, doc)).OrderBy(doc => doc.Name).ToArray();

    public static void Validate(DocumentInput input)
    {
        if (input.DocumentId == Guid.Empty || string.IsNullOrWhiteSpace(input.Name) || input.Name.Length > 180)
            throw new ArgumentException("Enter a valid document ID and a name between 1 and 180 characters.");
        if (string.IsNullOrWhiteSpace(input.Text) || System.Text.Encoding.UTF8.GetByteCount(input.Text) > 256 * 1024)
            throw new ArgumentException("Enter nonempty UTF-8 text up to 256 KB.");
    }

    public void Dispose()
    {
        foreach (var s in sessions.Values) { s.Http.Dispose(); s.Vault.Dispose(); }
        gate.Dispose();
    }
}
