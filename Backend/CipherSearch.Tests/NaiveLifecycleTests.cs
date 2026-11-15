using System.Net;
using System.Runtime.Versioning;
using CipherSearch.Client;
using CipherSearch.Contracts;
using CipherSearch.SearchSchemes.Naive;

namespace CipherSearch.Tests;

[SupportedOSPlatform("windows")]
public sealed class NaiveLifecycleTests
{
    [Fact]
    public async Task SharedPostingListsSurviveLostReceiptRestartUpdateAndDelete()
    {
        var scope = new IndexScope(Guid.NewGuid(), SchemeIds.NaiveHmac, Guid.NewGuid(), 1);
        var directory = Path.Combine(Path.GetTempPath(), "ciphersearch-naive-" + Guid.NewGuid().ToString("N"));
        using var server = new MemoryServer(scope);
        using var http = new HttpClient(server) { BaseAddress = new Uri("http://localhost/") };
        var first = Guid.NewGuid(); var second = Guid.NewGuid();
        using (var vault = new LocalVault(directory, true))
        {
            var client = new DocumentClient(http, scope, vault);
            await client.Initialize();
            await client.Mutate(MutationKind.Add, first, "meeting project");
            server.LoseNextResponse = true;
            await Assert.ThrowsAsync<HttpRequestException>(() => client.Mutate(MutationKind.Add, second, "meeting salary"));
        }
        using (var vault = new LocalVault(directory))
        {
            var client = new DocumentClient(http, scope, vault);
            await client.Initialize();
            Assert.Equal(2, (await client.Search("meeting")).Count);
            Assert.Equal(2, server.Epoch);
            await client.Mutate(MutationKind.Update, first, "meeting updated");
            Assert.Empty(await client.Search("project"));
            Assert.Equal("meeting updated", await client.Read((await client.Search("updated")).Single()));
            await client.Mutate(MutationKind.Delete, second, null);
            Assert.Equal(first, Assert.Single(await client.Search("meeting")).DocumentId);
        }
        using (var vault = new LocalVault(directory))
        {
            var client = new DocumentClient(http, scope, vault);
            await client.Initialize();
            await client.Mutate(MutationKind.Delete, first, null);
            Assert.Empty(await client.Search("meeting"));
            Assert.Empty(server.Store.Rows);
            await client.Mutate(MutationKind.Add, first, "meeting");
            Assert.Equal(4, Assert.Single(await client.Search("meeting")).Revision);
        }
        File.Move(Path.Combine(directory, "naive.state"), Path.Combine(directory, "naive.saved"));
        using (var vault = new LocalVault(directory))
            await Assert.ThrowsAsync<InvalidOperationException>(() => new DocumentClient(http, scope, vault).Initialize());
    }

    private sealed class MemoryServer(IndexScope scope) : HttpMessageHandler
    {
        private readonly NaiveServerScheme scheme = new();
        public TestIndex Store { get; } = new(scope);
        private readonly Dictionary<Guid, MutationResponse> receipts = [];
        private readonly Dictionary<Guid, EncryptedDocument> documents = [];
        public bool LoseNextResponse { get; set; }
        public long Epoch { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var bytes = await request.Content!.ReadAsByteArrayAsync(ct);
            object result;
            if (request.RequestUri!.AbsolutePath is "/api/v1/indexes" or "/api/v1/indexes/epoch")
                result = new InitializeResponse(scope, Epoch);
            else if (request.RequestUri.AbsolutePath == "/api/v1/searches")
                result = await scheme.SearchAsync(Wire.Decode<SearchRequest>(bytes), Store, ct);
            else if (request.RequestUri.AbsolutePath == "/api/v1/documents/read")
                result = documents[Wire.Decode<GetEncryptedDocumentRequest>(bytes).DocumentId];
            else
            {
                var mutation = Wire.Decode<MutationRequest>(bytes);
                if (!receipts.TryGetValue(mutation.OperationId, out var receipt))
                {
                    var ack = await scheme.ApplyMutationAsync(scope, mutation.IndexMutation, Store, ct);
                    if (mutation.Replacement is not null) documents[mutation.DocumentId] = mutation.Replacement;
                    else documents.Remove(mutation.DocumentId);
                    receipt = new(mutation.OperationId, mutation.ExpectedRevision + 1, ack);
                    receipts.Add(mutation.OperationId, receipt);
                    Epoch++;
                }
                result = receipt;
                if (LoseNextResponse) { LoseNextResponse = false; throw new HttpRequestException("Lost receipt."); }
            }
            return new(HttpStatusCode.OK) { Content = new ByteArrayContent(Wire.Encode(result)) };
        }
    }
}
