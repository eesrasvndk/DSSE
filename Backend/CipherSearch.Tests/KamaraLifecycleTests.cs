using System.Net;
using System.Runtime.Versioning;
using CipherSearch.Client;
using CipherSearch.Contracts;
using CipherSearch.SearchSchemes.Kamara;

namespace CipherSearch.Tests;

[SupportedOSPlatform("windows")]
public sealed class KamaraLifecycleTests
{
    [Fact]
    public async Task InitialCollectionIsSearchableAfterLostSetupReceiptWithoutIndividualAdds()
    {
        var scope = new IndexScope(Guid.NewGuid(), SchemeIds.Kamara, Guid.NewGuid(), 1);
        var directory = Path.Combine(Path.GetTempPath(), "dsse-kamara-" + Guid.NewGuid().ToString("N"));
        using var server = new MemoryServer(scope) { LoseSetupResponse = true };
        using var http = new HttpClient(server) { BaseAddress = new Uri("http://localhost/") };
        var first = Guid.NewGuid(); var second = Guid.NewGuid();
        using (var vault = new LocalVault(directory, true))
            await Assert.ThrowsAsync<HttpRequestException>(() => new DocumentClient(http, scope, vault)
                .InitializeKamaraCollection([(first, "meeting project"), (second, "meeting salary")], 16, 4));
        using (var vault = new LocalVault(directory))
        {
            var client = new DocumentClient(http, scope, vault);
            await client.Initialize();
            var matches = await client.Search("meeting");
            Assert.Equal(2, matches.Count);
            Assert.Equal("meeting project", await client.Read(matches.Single(m => m.DocumentId == first)));
            Assert.Equal("meeting salary", await client.Read(matches.Single(m => m.DocumentId == second)));
            Assert.Equal(0, server.MutationCount);
            await client.Mutate(MutationKind.Delete, first, null);
            Assert.Equal(second, Assert.Single(await client.Search("meeting")).DocumentId);
        }
    }

    [Fact]
    public async Task SetupAndMutationsSurviveLostReceiptsRestartAndDecryptDocuments()
    {
        var scope = new IndexScope(Guid.NewGuid(), SchemeIds.Kamara, Guid.NewGuid(), 1);
        var directory = Path.Combine(Path.GetTempPath(), "dsse-kamara-" + Guid.NewGuid().ToString("N"));
        using var server = new MemoryServer(scope) { LoseSetupResponse = true };
        using var http = new HttpClient(server) { BaseAddress = new Uri("http://localhost/") };
        var first = Guid.NewGuid(); var second = Guid.NewGuid();
        using (var vault = new LocalVault(directory, true))
            await Assert.ThrowsAsync<HttpRequestException>(() => new DocumentClient(http, scope, vault, 16).Initialize());
        using (var vault = new LocalVault(directory))
        {
            var client = new DocumentClient(http, scope, vault, 16);
            await client.Initialize();
            await client.Mutate(MutationKind.Add, first, "meeting project");
            server.LoseMutationResponse = true;
            await Assert.ThrowsAsync<HttpRequestException>(() => client.Mutate(MutationKind.Add, second, "meeting salary"));
        }
        using (var vault = new LocalVault(directory))
        {
            var client = new DocumentClient(http, scope, vault, 16);
            await client.Initialize();
            Assert.Equal(2, server.Epoch);
            Assert.Equal(2, (await client.Search("meeting")).Count);
            server.LoseMutationResponse = true;
            await Assert.ThrowsAsync<HttpRequestException>(() => client.Mutate(MutationKind.Update, first, "meeting updated"));
        }
        using (var vault = new LocalVault(directory))
        {
            var client = new DocumentClient(http, scope, vault, 16);
            await client.Initialize();
            Assert.Equal(3, server.Epoch);
            Assert.Empty(await client.Search("project"));
            var match = Assert.Single(await client.Search("updated"));
            Assert.Equal(2, match.Revision);
            Assert.Equal("meeting updated", await client.Read(match));
            await client.Mutate(MutationKind.Delete, first, null);
            await client.Mutate(MutationKind.Delete, second, null);
            Assert.Empty(await client.Search("meeting"));
            await client.Mutate(MutationKind.Add, first, "meeting");
            Assert.Equal(4, Assert.Single(await client.Search("meeting")).Revision);
        }
        File.Move(Path.Combine(directory, "kamara.state"), Path.Combine(directory, "kamara.saved"));
        using (var vault = new LocalVault(directory))
            await Assert.ThrowsAsync<InvalidOperationException>(() => new DocumentClient(http, scope, vault, 16).Initialize());
    }

    private sealed class MemoryServer(IndexScope scope) : HttpMessageHandler
    {
        private readonly KamaraServerScheme scheme = new();
        private readonly TestIndex store = new(scope);
        private readonly Dictionary<Guid, MutationResponse> receipts = [];
        private readonly Dictionary<Guid, EncryptedDocument> documents = [];
        internal bool LoseSetupResponse, LoseMutationResponse;
        internal long Epoch;
        internal int MutationCount => receipts.Count;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var bytes = await request.Content!.ReadAsByteArrayAsync(ct);
            object result;
            var path = request.RequestUri!.AbsolutePath;
            if (path == "/api/v1/indexes")
            {
                var init = Wire.Decode<InitializeRequest>(bytes);
                if (init.Setup is not null) await scheme.ApplyMutationAsync(scope, init.Setup, store, ct);
                if (init.Documents is not null)
                {
                    foreach (var document in init.Documents) documents[document.DocumentId] = document;
                    Epoch = init.Documents.Length;
                }
                if (LoseSetupResponse) { LoseSetupResponse = false; throw new HttpRequestException("Lost setup receipt."); }
                result = new InitializeResponse(scope, Epoch);
            }
            else if (path == "/api/v1/indexes/epoch") result = new InitializeResponse(scope, Epoch);
            else if (path == "/api/v1/searches") result = await scheme.SearchAsync(Wire.Decode<SearchRequest>(bytes), store, ct);
            else if (path == "/api/v1/documents/read") result = documents[Wire.Decode<GetEncryptedDocumentRequest>(bytes).DocumentId];
            else
            {
                var mutation = Wire.Decode<MutationRequest>(bytes);
                if (!receipts.TryGetValue(mutation.OperationId, out var receipt))
                {
                    var ack = await scheme.ApplyMutationAsync(scope, mutation.IndexMutation, store, ct);
                    if (mutation.Replacement is not null) documents[mutation.DocumentId] = mutation.Replacement;
                    else documents.Remove(mutation.DocumentId);
                    receipt = new(mutation.OperationId, mutation.ExpectedRevision + 1, ack);
                    receipts.Add(mutation.OperationId, receipt); Epoch++;
                }
                result = receipt;
                if (LoseMutationResponse) { LoseMutationResponse = false; throw new HttpRequestException("Lost mutation receipt."); }
            }
            return new(HttpStatusCode.OK) { Content = new ByteArrayContent(Wire.Encode(result)) };
        }
    }
}
