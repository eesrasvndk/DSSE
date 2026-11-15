using System.Net;
using System.Security.Cryptography;
using System.Text;
using CipherSearch.Contracts;
using CipherSearch.Web;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:5190");
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 2 * 1024 * 1024);
builder.Services.AddSingleton<Workspace>();
var app = builder.Build();
app.Use(async (ctx, next) =>
{
    if (ctx.Connection.RemoteIpAddress is not { } ip || !IPAddress.IsLoopback(ip) ||
        ctx.Request.Host.Host is not ("127.0.0.1" or "localhost"))
    { ctx.Response.StatusCode = 403; return; }
    ctx.Response.Headers["Cache-Control"] = "no-store";
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    if (ctx.Request.Path.StartsWithSegments("/api"))
    {
        var origin = ctx.Request.Headers.Origin.ToString();
        if (ctx.Request.Headers["X-CipherSearch"] != "local-client" ||
            (origin.Length > 0 && origin != $"{ctx.Request.Scheme}://{ctx.Request.Host}" &&
                origin is not ("http://localhost:5173" or "http://127.0.0.1:5173")))
        { ctx.Response.StatusCode = 403; return; }
    }
    try { await next(ctx); }
    catch (Exception ex) when (!ctx.Response.HasStarted)
    {
        var (status, message) = ex switch
        {
            CipherSearch.SearchSchemes.Kamara.KamaraCapacityException => (422,
                "This Kamara collection is full. Create a new collection with a larger capacity to add more documents."),
            ArgumentException => (400, ex.Message),
            BadHttpRequestException => (400, "The request format or size is invalid."),
            KeyNotFoundException => (404, "Document not found. Refresh the collection and try again."),
            InvalidOperationException => (409, "The collection state changed. Refresh and try again."),
            _ => (503, "The storage service is unavailable. Check the server, PostgreSQL, and MinIO, then refresh.")
        };
        ctx.Response.StatusCode = status;
        await ctx.Response.WriteAsJsonAsync(new { message });
    }
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapGet("/api/overview", async (Workspace w) =>
{
    string[] schemes = [SchemeIds.NaiveHmac, SchemeIds.Kamara, SchemeIds.Mitra];
    var items = new List<object>();
    foreach (var scheme in schemes)
    {
        try
        {
            items.Add(await w.Run(scheme, async (client, vault, path) =>
            {
                var files = Directory.EnumerateFiles(path, "doc-*.state")
                    .Select(f => vault.Load<CipherSearch.Client.LocalDocument>(Path.GetFileNameWithoutExtension(f))).ToArray();
                var live = files.Where(d => !d.Deleted).ToArray();
                var deletedCount = files.Count(d => d.Deleted);
                var uniqueKeywords = live.SelectMany(d => d.Keywords).Distinct(StringComparer.Ordinal).Count();
                var totalPostings = live.Sum(d => d.Keywords.Length);
                var status = await client.Status();
                return (object)new
                {
                    scheme,
                    available = true,
                    documentCount = live.Length,
                    deletedCount,
                    uniqueKeywords,
                    totalPostings,
                    status,
                    requestBytes = client.RequestBytes,
                    responseBytes = client.ResponseBytes
                };
            }));
        }
        catch
        {
            items.Add(new { scheme, available = false, documentCount = 0, deletedCount = 0, uniqueKeywords = 0, totalPostings = 0, status = (object?)null, requestBytes = 0L, responseBytes = 0L });
        }
    }
    return new { schemes = items };
});
app.MapPost("/api/seed-demo-all", async (Workspace w) =>
{
    var file = Path.GetFullPath(Path.Combine(app.Environment.ContentRootPath, "../../DataSet/processed/enron_1000.jsonl"));
    var documents = File.ReadLines(file).Take(25).Select(line =>
    {
        using var json = System.Text.Json.JsonDocument.Parse(line);
        var number = json.RootElement.GetProperty("documentId").GetInt32();
        var id = new Guid(SHA256.HashData(Encoding.UTF8.GetBytes($"dsse-enron-{number}"))[..16]);
        return (Id: id, Text: json.RootElement.GetProperty("text").GetString()!, Name: $"Enron {number:D4}");
    }).ToArray();
    var targetIds = documents.Select(d => d.Id).ToHashSet();
    string[] schemes = [SchemeIds.NaiveHmac, SchemeIds.Kamara, SchemeIds.Mitra];
    var results = new List<object>();
    foreach (var scheme in schemes)
    {
        var imported = 0;
        await w.Run(scheme, async (client, vault, path) =>
        {
            foreach (var liveDoc in Workspace.List(vault, path))
            {
                if (!targetIds.Contains(liveDoc.DocumentId))
                    await client.Mutate(MutationKind.Delete, liveDoc.DocumentId, null);
            }
            foreach (var document in documents)
            {
                var docKey = $"doc-{document.Id:N}";
                if (vault.Exists(docKey))
                {
                    var local = vault.Load<CipherSearch.Client.LocalDocument>(docKey);
                    if (!local.Deleted) continue;
                }
                vault.Save($"name-{document.Id:N}", document.Name);
                await client.Mutate(MutationKind.Add, document.Id, document.Text);
                imported++;
            }
            return new { imported };
        });
        results.Add(new { scheme, imported });
    }
    return new { count = documents.Length, results };
});
app.MapGet("/api/server-leakage", () =>
{
    var leakageFile = Path.GetFullPath(Path.Combine(app.Environment.ContentRootPath, "../../tmp/server-leakage.jsonl"));
    if (!File.Exists(leakageFile)) return Results.Ok(new { events = Array.Empty<object>() });
    var lines = File.ReadLines(leakageFile).Reverse().Take(45).ToArray();
    var events = new List<object>();
    foreach (var line in lines)
    {
        if (string.IsNullOrWhiteSpace(line)) continue;
        try
        {
            var ev = Wire.Decode<LeakageEvent>(Encoding.UTF8.GetBytes(line));
            events.Add(new
            {
                ev.EventId,
                ev.TimestampUtc,
                schemeId = ev.Scope.SchemeId,
                generationId = ev.Scope.GenerationId,
                ev.OperationId,
                ev.Operation,
                ev.Epoch,
                ev.RequestBytes,
                ev.ResponseBytes,
                ev.ElapsedMicroseconds,
                tokenCount = ev.ObservedTokensBase64.Count,
                addressCount = ev.ObservedAddressesBase64.Count,
                observedDocumentCount = ev.ObservedDocumentIds.Count,
                ev.ReturnedEntryCount,
                tokenSamples = ev.ObservedTokensBase64.Take(6).Select(Convert.ToHexString).ToArray(),
                addressSamples = ev.ObservedAddressesBase64.Take(6).Select(Convert.ToHexString).ToArray(),
                documentIdSamples = ev.ObservedDocumentIds.Take(6).ToArray()
            });
        }
        catch { /* Ignore malformed lines */ }
    }
    return Results.Ok(new { events });
});
app.MapGet("/api/{scheme}/documents", (string scheme, Workspace w) =>
    w.Run(scheme, async (client, vault, path) => new { documents = Workspace.List(vault, path), status = await client.Status() }));
app.MapPost("/api/{scheme}/import-enron", async (string scheme, Workspace w) =>
{
    var file = Path.GetFullPath(Path.Combine(app.Environment.ContentRootPath, "../../DataSet/processed/enron_1000.jsonl"));
    var documents = File.ReadLines(file).Select(line =>
    {
        using var json = System.Text.Json.JsonDocument.Parse(line);
        var number = json.RootElement.GetProperty("documentId").GetInt32();
        var id = new Guid(SHA256.HashData(Encoding.UTF8.GetBytes($"dsse-enron-{number}"))[..16]);
        return (Id: id, Text: json.RootElement.GetProperty("text").GetString()!, Name: $"Enron {number:D4}");
    }).ToArray();
    var imported = 0;
    return await w.Run(scheme, async (client, vault, _) =>
    {
        foreach (var document in documents)
        {
            if (vault.Exists($"doc-{document.Id:N}")) continue; // Preserve edited and deleted records on repeat import.
            vault.Save($"name-{document.Id:N}", document.Name);
            await client.Mutate(MutationKind.Add, document.Id, document.Text);
            imported++;
        }
        return new { imported };
    }, scheme != SchemeIds.Kamara ? null : async (client, vault) =>
    {
        foreach (var document in documents) vault.Save($"name-{document.Id:N}", document.Name);
        await client.InitializeKamaraCollection(documents.Select(d => (d.Id, d.Text)).ToArray(), 131_072, 16_384);
        imported = documents.Length;
    });
});
app.MapGet("/api/{scheme}/documents/{id:guid}", (string scheme, Guid id, Workspace w) =>
    w.Run(scheme, async (client, vault, _) =>
    {
        var doc = Workspace.Get(vault, id);
        return new { document = Workspace.Row(vault, doc), text = await client.Read(new(id, doc.Revision)) };
    }));
app.MapPost("/api/{scheme}/search", (string scheme, SearchInput input, Workspace w) =>
    w.Run(scheme, async (client, vault, _) =>
    {
        var keyword = NormalizeQuery(input.Keyword);
        var searchId = Guid.NewGuid();
        var timer = System.Diagnostics.Stopwatch.StartNew();
        var matches = await client.Search(keyword, searchId: searchId);
        var elapsedMs = timer.Elapsed.TotalMilliseconds;
        SearchObservation? observation = null;
        if (input.Inspect)
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                observation = await client.ObserveSearch(searchId, timeout.Token);
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or System.Text.Json.JsonException)
            { /* An unavailable diagnostic should not hide a successful search. */ }
        }
        object? oracle = null;
        if (input.Verify)
        {
            var (expected, _) = await PlaintextReference(client, Workspace.List(vault, _), keyword, false);
            oracle = new { passed = expected.SetEquals(matches.Select(m => m.DocumentId)), expectedCount = expected.Count };
        }
        return new { documents = matches.Select(m => Workspace.Row(vault, Workspace.Get(vault, m.DocumentId))).ToArray(), elapsedMs,
            oracle, searchId, observation };
    }));
app.MapPost("/api/verification", async (SearchInput input, Workspace w) =>
{
    var keyword = NormalizeQuery(input.Keyword);
    string[] schemes = [SchemeIds.NaiveHmac, SchemeIds.Kamara, SchemeIds.Mitra];
    var outcomes = new List<VerificationOutcome>();
    foreach (var scheme in schemes)
    {
        try
        {
            outcomes.Add(await w.Run(scheme, async (client, vault, path) =>
            {
                var docList = Workspace.List(vault, path);
                var (expected, fingerprint) = await PlaintextReference(client, docList, keyword, true);
                var searchId = Guid.NewGuid();
                var timer = System.Diagnostics.Stopwatch.StartNew();
                var matches = await client.Search(keyword, searchId: searchId);
                var elapsedMs = timer.Elapsed.TotalMilliseconds;
                SearchObservation? observation = null;
                try
                {
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    observation = await client.ObserveSearch(searchId, timeout.Token);
                }
                catch { /* Ignore diagnostic failure */ }
                var status = await client.Status();
                var matchedDocs = matches.Select(m => Workspace.Row(vault, Workspace.Get(vault, m.DocumentId))).ToArray();
                return new VerificationOutcome(scheme, fingerprint, expected.Order().ToArray(),
                    matches.Select(m => m.DocumentId).Order().ToArray(), elapsedMs, docList.Length,
                    status.IndexBytes, status.IndexEntries, status.Epoch, observation, matchedDocs);
            }));
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or
            IOException or CryptographicException or KeyNotFoundException or OperationCanceledException)
        {
            outcomes.Add(new(scheme, null, null, null, 0, 0, 0, 0, 0, null, []));
        }
    }
    var sameDataset = outcomes.All(o => o.Fingerprint is not null) &&
        outcomes.Select(o => o.Fingerprint).Distinct().Count() == 1;
    return new
    {
        keyword,
        sameDataset,
        rows = outcomes.Select(o => new
        {
            o.Scheme, o.Expected, o.Actual,
            o.ElapsedMs, o.DocumentCount, o.IndexBytes, o.IndexEntries, o.Epoch, o.Observation, o.MatchedDocuments,
            status = o.Fingerprint is null ? "Unavailable" : !sameDataset ? "Not comparable" :
                o.Expected!.Length == o.Actual!.Length && o.Expected.SequenceEqual(o.Actual) ? "PASS" : "FAIL"
        })
    };
});
app.MapPost("/api/{scheme}/documents", (string scheme, DocumentInput input, Workspace w) =>
    w.Run(scheme, async (client, vault, _) =>
    {
        Workspace.Validate(input);
        if (input.Revision != 0) throw new ArgumentException("A new document must start at revision zero.");
        if (vault.Exists($"doc-{input.DocumentId:N}")) throw new InvalidOperationException();
        vault.Save($"name-{input.DocumentId:N}", input.Name.Trim());
        await client.Mutate(MutationKind.Add, input.DocumentId, input.Text);
        return Workspace.Row(vault, Workspace.Get(vault, input.DocumentId));
    }));
app.MapPut("/api/{scheme}/documents/{id:guid}", (string scheme, Guid id, DocumentInput input, Workspace w) =>
    w.Run(scheme, async (client, vault, _) =>
    {
        Workspace.Validate(input);
        if (input.DocumentId != id || Workspace.Get(vault, id).Revision != input.Revision) throw new InvalidOperationException();
        await client.Mutate(MutationKind.Update, id, input.Text);
        vault.Save($"name-{id:N}", input.Name.Trim());
        return Workspace.Row(vault, Workspace.Get(vault, id));
    }));
app.MapDelete("/api/{scheme}/documents/{id:guid}", (string scheme, Guid id, [Microsoft.AspNetCore.Mvc.FromBody] DeleteInput input, Workspace w) =>
    w.Run(scheme, async (client, vault, _) =>
    {
        if (Workspace.Get(vault, id).Revision != input.Revision) throw new InvalidOperationException();
        await client.Mutate(MutationKind.Delete, id, null);
        return new { deleted = true };
    }));
app.MapFallbackToFile("index.html");
app.Run();

static string NormalizeQuery(string keyword)
{
    if (string.IsNullOrWhiteSpace(keyword) || keyword.Length > 200)
        throw new ArgumentException("Enter a single keyword.");
    return CipherSearch.Client.TextNormalizer.Query(keyword);
}

static async Task<(HashSet<Guid> Expected, string? Fingerprint)> PlaintextReference(
    CipherSearch.Client.DocumentClient client, DocumentRow[] rows, string keyword, bool fingerprint)
{
    var expected = new HashSet<Guid>();
    using var hash = fingerprint ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256) : null;
    foreach (var row in rows.OrderBy(r => r.DocumentId))
    {
        var text = await client.Read(new(row.DocumentId, row.Revision));
        if (CipherSearch.Client.TextNormalizer.Tokenize(text).Contains(keyword)) expected.Add(row.DocumentId);
        if (hash is not null)
        {
            hash.AppendData(row.DocumentId.ToByteArray());
            hash.AppendData(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        }
    }
    return (expected, hash is null ? null : Convert.ToHexString(hash.GetHashAndReset()));
}

sealed record VerificationOutcome(
    string Scheme, string? Fingerprint, Guid[]? Expected, Guid[]? Actual,
    double ElapsedMs, int DocumentCount, long IndexBytes, int IndexEntries,
    long Epoch, SearchObservation? Observation, DocumentRow[] MatchedDocuments);

