using System.Net;
using System.Runtime.Versioning;
using CipherSearch.Client;
using CipherSearch.Contracts;
using CipherSearch.SearchSchemes.Mitra;
using Xunit.Abstractions;

namespace CipherSearch.Tests;

// Measures what an honest-but-curious server observes on the Mitra write path.
// Characterizes application leakage; padding and rollback-resistant storage are outside interim scope.
[SupportedOSPlatform("windows")]
public sealed class MitraLeakageTests(ITestOutputHelper output)
{
    private const string Six = "alpha beta gamma delta epsilon zeta";

    [Fact]
    public async Task CollectApplicationLeakageEvidence()
    {
        var destination = Environment.GetEnvironmentVariable("CIPHERSEARCH_AUDIT_OUT");
        if (string.IsNullOrEmpty(destination)) return;
        var ids = Enumerable.Range(0, 16).Select(_ => Guid.NewGuid()).ToArray();
        var words = Enumerable.Range(0, 16).Select(i => "audit" + (char)('a' + i)).ToArray();
        using var run = await Run(async client =>
        {
            for (var i = 0; i < 16; i++) await client.Mutate(MutationKind.Add, ids[i], words[i]);
            for (var i = 0; i < 8; i++) await client.Mutate(MutationKind.Delete, ids[i], null);
            for (var i = 0; i < 16; i++)
                Assert.Equal(i < 8 ? 0 : 1, (await client.Search(words[i])).Count);
        });
        Directory.CreateDirectory(destination);
        File.WriteAllBytes(Path.Combine(destination, "application-server-events.json"), Wire.Encode(run.Server.Events));
        File.WriteAllBytes(Path.Combine(destination, "application-ground-truth.json"), Wire.Encode(new {
            scenario = "16 isolated adds, delete first 8 before any search, query in insertion order",
            ids, words, deleted = Enumerable.Range(0, 8).ToArray(),
            // Controlled schedule has exactly one successful blob per add, no retries.
            expectedBlobsInQueryOrder = run.Server.Blobs.Select(b => b.BlobId).ToArray()
        }));
    }

    [Fact]
    public async Task IndexWriteSizeRevealsNumberOfChangedKeywordPairs()
    {
        using var run = await Run(async client =>
        {
            var id = Guid.NewGuid();
            await client.Mutate(MutationKind.Add, id, Six);
            await client.Mutate(MutationKind.Update, id, "alpha beta");
            await client.Mutate(MutationKind.Delete, id, null);
        });
        var sizes = run.Server.Writes.Select(w => w.Addresses.Length).ToArray();
        output.WriteLine("add/update/delete index entries observed: " + string.Join(", ", sizes));
        Assert.Equal(new[] { 6, 4, 2 }, sizes);
    }

    [Fact]
    public async Task DeleteHasNoBlobUploadAndIsDistinguishableInThisSchedule()
    {
        using var run = await Run(async client =>
        {
            var id = Guid.NewGuid();
            await client.Mutate(MutationKind.Add, id, Six);
            await client.Mutate(MutationKind.Delete, id, null);
        });
        var kinds = run.Server.Events.Select(e => e.Kind).Where(k => k is "blob" or "write").ToArray();
        output.WriteLine("write-path sequence: " + string.Join(" -> ", kinds));
        Assert.Equal(new[] { "blob", "write", "write" }, kinds);
    }

    [Fact]
    public async Task UnpaddedCiphertextRevealsUtf8DocumentLength()
    {
        using var run = await Run(async client =>
        {
            await client.Mutate(MutationKind.Add, Guid.NewGuid(), "alpha");
            await client.Mutate(MutationKind.Add, Guid.NewGuid(), string.Join(' ', Enumerable.Repeat("beta", 400)));
        });
        var lengths = run.Server.Blobs.Select(b => b.CiphertextLength).ToArray();
        output.WriteLine("blob ciphertext lengths observed: " + string.Join(", ", lengths));
        Assert.Equal(new[] { 5, 1999 }, lengths);
    }

    [Fact]
    public async Task StateRollbackIsRejectedButRepeatedAddressesHaveAlreadyReachedServer()
    {
        var directory = TempDirectory();
        var scope = NewScope();
        using var server = new ObservingServer(scope);
        using var http = new HttpClient(server) { BaseAddress = new Uri("http://localhost/") };
        try
        {
            using var vault = new LocalVault(directory, true);
            var client = new DocumentClient(http, scope, vault);
            await client.Initialize();
            await client.Mutate(MutationKind.Add, Guid.NewGuid(), "alpha beta");
            var snapshot = File.ReadAllBytes(Path.Combine(directory, "mitra.state"));
            await client.Mutate(MutationKind.Add, Guid.NewGuid(), "alpha beta");
            File.WriteAllBytes(Path.Combine(directory, "mitra.state"), snapshot);
            await Assert.ThrowsAnyAsync<Exception>(() => client.Mutate(MutationKind.Add, Guid.NewGuid(), "alpha beta"));
        }
        finally { Directory.Delete(directory, true); }
        var seen = server.Writes.SelectMany(w => w.Addresses).ToArray();
        output.WriteLine($"addresses received: {seen.Length}, distinct: {seen.Distinct().Count()}");
        Assert.Equal(6, seen.Length);
        Assert.Equal(4, seen.Distinct().Count());
    }

    [Fact]
    public async Task WriteBodiesCarryNoDocumentIdentityKindOrRevision()
    {
        var id = Guid.NewGuid();
        using var run = await Run(async client =>
        {
            await client.Mutate(MutationKind.Add, id, Six);
            await client.Mutate(MutationKind.Update, id, "alpha");
            await client.Mutate(MutationKind.Delete, id, null);
        });
        Assert.NotEmpty(run.Server.Events);
        foreach (var e in run.Server.Events.Where(e => e.Kind is "write" or "blob"))
        {
            Assert.DoesNotContain(id.ToString(), e.Body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("documentId", e.Body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("revision", e.Body, StringComparison.OrdinalIgnoreCase);
            // The constant "mitra.mutate" message label is allowed; operation values are not.
            foreach (var operation in new[] { "\"add\"", "\"update\"", "\"delete\"" })
                Assert.DoesNotContain(operation, e.Body, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task EachRevisionUsesAFreshUnlinkableBlobId()
    {
        var id = Guid.NewGuid();
        using var run = await Run(async client =>
        {
            await client.Mutate(MutationKind.Add, id, Six);
            await client.Mutate(MutationKind.Update, id, "alpha");
            await client.Mutate(MutationKind.Update, id, "beta");
        });
        var ids = run.Server.Blobs.Select(b => b.BlobId).ToArray();
        Assert.Equal(3, ids.Length);
        Assert.Equal(ids.Length, ids.Distinct().Count());
        Assert.DoesNotContain(id, ids);
    }

    [Fact]
    public async Task LargeDocumentUsesOneUnpaddedBatchAndStaysSearchable()
    {
        var words = string.Join(' ', Enumerable.Range(0, 300).Select(i => "w" + new string((char)('a' + i % 26), 1 + i / 26)));
        using var run = await Run(async client =>
        {
            await client.Mutate(MutationKind.Add, Guid.NewGuid(), words);
            Assert.Single(await client.Search("w" + new string('c', 3)));
        });
        Assert.Single(run.Server.Writes);
        Assert.Equal(299, run.Server.Writes[0].Addresses.Length); // "we" is a stop word.
        var kinds = run.Server.Events.Select(e => e.Kind).Where(k => k is "blob" or "write").ToArray();
        Assert.Equal(["blob", "write"], kinds);
    }

    private static IndexScope NewScope() => new(Guid.NewGuid(), SchemeIds.Mitra, Guid.NewGuid(), 1);
    private static string TempDirectory() =>
        Path.Combine(Path.GetTempPath(), "ciphersearch-mitra-leak-" + Guid.NewGuid().ToString("N"));

    private static async Task<Session> Run(Func<DocumentClient, Task> body)
    {
        var scope = NewScope();
        var directory = TempDirectory();
        var server = new ObservingServer(scope);
        var http = new HttpClient(server) { BaseAddress = new Uri("http://localhost/") };
        try
        {
            using var vault = new LocalVault(directory, true);
            var client = new DocumentClient(http, scope, vault);
            await client.Initialize();
            await body(client);
        }
        catch { http.Dispose(); server.Dispose(); throw; }
        finally { Directory.Delete(directory, true); }
        return new(server, http);
    }

    private sealed record Session(ObservingServer Server, HttpClient Http) : IDisposable
    {
        public void Dispose() { Http.Dispose(); Server.Dispose(); }
    }

    private sealed record Event(string Kind, string Body);
    private sealed record WriteView(string[] Addresses);
    private sealed record BlobView(Guid BlobId, int CiphertextLength);

    private sealed class ObservingServer(IndexScope scope) : HttpMessageHandler
    {
        private readonly MitraServerScheme scheme = new();
        private readonly TestIndex store = new(scope);
        private readonly Dictionary<Guid, EncryptedEnvelope> blobs = [];
        private readonly HashSet<Guid> receipts = [];
        public List<Event> Events { get; } = [];
        public List<WriteView> Writes { get; } = [];
        public List<BlobView> Blobs { get; } = [];
        private long epoch;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var bytes = await request.Content!.ReadAsByteArrayAsync(ct);
            var path = request.RequestUri!.AbsolutePath;
            var body = System.Text.Encoding.UTF8.GetString(bytes);
            object result;
            switch (path)
            {
                case "/api/v1/indexes" or "/api/v1/indexes/epoch":
                    result = new InitializeResponse(scope, epoch);
                    break;
                case "/api/v1/searches":
                    Events.Add(new("search", body));
                    result = await scheme.SearchAsync(Wire.Decode<SearchRequest>(bytes), store, ct);
                    break;
                case "/api/v1/opaque-blobs":
                {
                    Events.Add(new("blob", body));
                    var blob = Wire.Decode<OpaqueBlobWrite>(bytes);
                    Blobs.Add(new(blob.BlobId, blob.Content.Ciphertext.Length));
                    blobs[blob.BlobId] = blob.Content;
                    result = new OpaqueBlobReceipt(blob.BlobId);
                    break;
                }
                case "/api/v1/opaque-blobs/read":
                    Events.Add(new("blob-read", body));
                    result = blobs[Wire.Decode<OpaqueBlobRead>(bytes).BlobId];
                    break;
                default:
                {
                    Assert.Equal("/api/v1/private-index-writes", path);
                    Events.Add(new("write", body));
                    var write = Wire.Decode<PrivateIndexWrite>(bytes);
                    var entries = Wire.Read<IndexEntry[]>(write.Entries, "mitra.mutate");
                    Writes.Add(new(entries.Select(e => Convert.ToHexString(e.Address)).ToArray()));
                    if (receipts.Add(write.OperationId))
                    {
                        await scheme.ApplyMutationAsync(scope, write.Entries, store, ct);
                        epoch++;
                    }
                    result = new PrivateIndexReceipt(write.OperationId);
                    break;
                }
            }
            return new(HttpStatusCode.OK) { Content = new ByteArrayContent(Wire.Encode(result)) };
        }
    }
}
