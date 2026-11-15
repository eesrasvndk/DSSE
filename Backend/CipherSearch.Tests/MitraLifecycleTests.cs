using System.Net;
using System.Runtime.Versioning;
using CipherSearch.Client;
using CipherSearch.Contracts;
using CipherSearch.SearchSchemes.Mitra;

namespace CipherSearch.Tests;

[SupportedOSPlatform("windows")]
public sealed class MitraLifecycleTests
{
    [Fact]
    public async Task CountersSurviveLostResponseRestartUpdateDeleteAndReadd()
    {
        var scope = new IndexScope(Guid.NewGuid(), SchemeIds.Mitra, Guid.NewGuid(), 1);
        var directory = Path.Combine(Path.GetTempPath(), "ciphersearch-mitra-" + Guid.NewGuid().ToString("N"));
        using var handler = new MemoryServer(scope);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://localhost/") };
        var first = Guid.NewGuid(); var second = Guid.NewGuid();
        using (var vault = new LocalVault(directory, true))
        {
            var client = new DocumentClient(http, scope, vault);
            await client.Initialize();
            await client.Mutate(MutationKind.Add, first, "alpha beta");
            handler.LoseNextResponse = true;
            await Assert.ThrowsAsync<HttpRequestException>(() => client.Mutate(MutationKind.Add, second, "alpha"));
        }
        using (var vault = new LocalVault(directory))
        {
            var client = new DocumentClient(http, scope, vault);
            await client.Initialize(); // Recovers identical operation and pending counters.
            Assert.Equal(2, (await client.Search("alpha")).Count);
            Assert.Equal(2, handler.Epoch);
            await client.Mutate(MutationKind.Update, first, "alpha beta");
            Assert.Equal(2, (await client.Search("beta")).Single().Revision);
            Assert.Equal("alpha beta", await client.Read((await client.Search("beta")).Single()));
            await client.Mutate(MutationKind.Update, first, "gamma");
            Assert.Equal(second, Assert.Single(await client.Search("alpha")).DocumentId);
            Assert.Empty(await client.Search("beta"));
            await client.Mutate(MutationKind.Delete, second, null);
            Assert.Empty(await client.Search("alpha"));
            await client.Mutate(MutationKind.Add, second, "alpha");
            Assert.Equal(3, Assert.Single(await client.Search("alpha")).Revision);
            Assert.Equal(first, Assert.Single(await client.Search("gamma")).DocumentId);
            Assert.Empty(await client.Search("absent"));
        }
        using (var vault = new LocalVault(directory))
        {
            var client = new DocumentClient(http, scope, vault);
            await client.Initialize();
            Assert.Equal("alpha", await client.Read(Assert.Single(await client.Search("alpha"))));
        }
        Assert.All(handler.Observations, observation =>
        {
            Assert.DoesNotContain(first.ToString(), observation.Body);
            Assert.DoesNotContain(second.ToString(), observation.Body);
            Assert.DoesNotContain("/delete", observation.Path);
        });
        var writes = handler.Observations.Where(o => o.Path == "/api/v1/private-index-writes").ToArray();
        Assert.NotEmpty(writes);
        foreach (var write in writes)
        {
            using var json = System.Text.Json.JsonDocument.Parse(write.Body);
            Assert.Equal(new[] { "entries", "operationId", "scope", "version" },
                json.RootElement.EnumerateObject().Select(p => p.Name).Order().ToArray());
            Assert.DoesNotContain("blobId", write.Body);
            Assert.DoesNotContain("revision", write.Body);
        }
        // Separation alone still exposes temporal adjacency to the same observer.
        Assert.Contains(Enumerable.Range(0, handler.Observations.Count - 1), i =>
            handler.Observations[i].Path == "/api/v1/opaque-blobs" &&
            handler.Observations[i + 1].Path == "/api/v1/private-index-writes");
        File.Move(Path.Combine(directory, "mitra.state"), Path.Combine(directory, "mitra.saved"));
        using (var vault = new LocalVault(directory))
            await Assert.ThrowsAsync<InvalidOperationException>(() => new DocumentClient(http, scope, vault).Initialize());
    }

    private sealed class MemoryServer(IndexScope scope) : HttpMessageHandler
    {
        private readonly MitraServerScheme scheme = new();
        private readonly TestIndex store = new(scope);
        private readonly Dictionary<Guid, PrivateIndexReceipt> receipts = [];
        private readonly Dictionary<Guid, EncryptedEnvelope> blobs = [];
        public List<(string Path, string Body)> Observations { get; } = [];
        public bool LoseNextResponse { get; set; }
        public long Epoch { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var bytes = await request.Content!.ReadAsByteArrayAsync(ct);
            Observations.Add((request.RequestUri!.AbsolutePath, System.Text.Encoding.UTF8.GetString(bytes)));
            object result;
            if (request.RequestUri!.AbsolutePath is "/api/v1/indexes" or "/api/v1/indexes/epoch")
                result = new InitializeResponse(scope, Epoch);
            else if (request.RequestUri.AbsolutePath == "/api/v1/searches")
                result = await scheme.SearchAsync(Wire.Decode<SearchRequest>(bytes), store, ct);
            else if (request.RequestUri.AbsolutePath == "/api/v1/opaque-blobs")
            {
                var blob = Wire.Decode<OpaqueBlobWrite>(bytes);
                blobs[blob.BlobId] = blob.Content;
                result = new OpaqueBlobReceipt(blob.BlobId);
            }
            else if (request.RequestUri.AbsolutePath == "/api/v1/opaque-blobs/read")
                result = blobs[Wire.Decode<OpaqueBlobRead>(bytes).BlobId];
            else
            {
                Assert.Equal("/api/v1/private-index-writes", request.RequestUri.AbsolutePath);
                var mutation = Wire.Decode<PrivateIndexWrite>(bytes);
                if (!receipts.TryGetValue(mutation.OperationId, out var receipt))
                {
                    var ack = await scheme.ApplyMutationAsync(scope, mutation.Entries, store, ct);
                    receipt = new(mutation.OperationId);
                    receipts.Add(mutation.OperationId, receipt);
                    Epoch++;
                }
                result = receipt;
                if (LoseNextResponse) { LoseNextResponse = false; throw new HttpRequestException("Lost acknowledgment."); }
            }
            return new(HttpStatusCode.OK) { Content = new ByteArrayContent(Wire.Encode(result)) };
        }
    }
}
