using CipherSearch.Contracts;
using CipherSearch.SearchSchemes.Kamara;
using CipherSearch.Server;
using CipherSearch.Server.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Minio;
using Npgsql;

namespace CipherSearch.Tests;

public sealed class KamaraStorageTests
{
    [IntegrationTheory]
    [Trait("Category", "Integration")]
    [InlineData(1)]
    public async Task PostgreSqlRollsBackDeleteAddAndMinioFailureThenReplaysExactlyOnce(int version)
    {
        var settings = File.ReadAllLines(Environment.GetEnvironmentVariable("CIPHERSEARCH_ENV_FILE")
            ?? throw new InvalidOperationException("Environment file missing."))
            .Where(l => l.Contains('=') && !l.TrimStart().StartsWith('#')).Select(l => l.Split('=', 2))
            .ToDictionary(p => p[0].Trim(), p => p[1].Trim().Trim('"', '\''));
        await using var source = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder
        {
            Host = "127.0.0.1", Port = 5432, Database = settings["POSTGRES_DB"], Username = settings["POSTGRES_USER"],
            Password = settings["POSTGRES_PASSWORD"], SearchPath = "dsse"
        }.ConnectionString);
        var db = new RuntimeDatabase(source); await db.Initialize();
        using var minio = new MinioClient().WithEndpoint("127.0.0.1:9000")
            .WithCredentials(settings["MINIO_ROOT_USER"], settings["MINIO_ROOT_PASSWORD"]).Build();
        var objects = new MinioDocumentStore(minio, "dsse-documents"); await objects.Initialize();
        var fault = new FaultingObjects(objects);
        var engine = new SearchEngine(db, fault, new LeakageLog(new ConfigurationBuilder().Build(), NullLogger<LeakageLog>.Instance),
            NullLogger<SearchEngine>.Instance);
        using var keys = new TestKeys();
        var scope = new IndexScope(Guid.NewGuid(), SchemeIds.Kamara, Guid.NewGuid(), 1);
        var client = new KamaraClientScheme();
        var setup = await client.PrepareSetupAsync(scope, [], 8, 8, keys);
        var init = new InitializeRequest(version, Guid.NewGuid(), scope, setup.Message);
        Assert.Equal(0, (await db.Create(init, default)).Epoch);
        Assert.Equal(0, (await db.Create(init, default)).Epoch);
        var original = new TrustedDocument(Guid.NewGuid(), 1, ["alpha", "shared"]);
        var add = await client.PrepareMutationAsync(scope, MutationKind.Add, null, original, setup.PendingState, keys);
        var addRequest = Request(MutationKind.Add, original, 0, add.Message);
        var receipt = await engine.Mutate(addRequest, default);
        Assert.Equal(Wire.Encode(receipt), Wire.Encode(await engine.Mutate(addRequest, default)));
        var before = await Snapshot();
        var revised = original with { Revision = 2, Keywords = ["beta", "shared", "gamma"] };
        var update = await client.PrepareMutationAsync(scope, MutationKind.Update, original, revised, add.PendingState, keys);
        var updateRequest = Request(MutationKind.Update, revised, 1, update.Message);
        fault.FailNext = true;
        await Assert.ThrowsAsync<IOException>(() => engine.Mutate(updateRequest, default));
        Assert.Equal(before, await Snapshot());
        Assert.Equal(1, (await engine.Epoch(scope, default)).Epoch);
        await Expect("alpha", add.PendingState, [original.DocumentId]);
        await Expect("beta", add.PendingState, []);
        await engine.Cleanup(scope, default);
        Assert.Equal(1, (await engine.Read(new(scope, original.DocumentId, 1), default)).Revision);
        receipt = await engine.Mutate(updateRequest, default);
        Assert.Equal(Wire.Encode(receipt), Wire.Encode(await engine.Mutate(updateRequest, default)));
        await Expect("alpha", update.PendingState, []);
        await Expect("beta", update.PendingState, [original.DocumentId]);
        Assert.Equal(2, (await engine.Epoch(scope, default)).Epoch);
        // Setup replay must not rewind a mutated generation.
        before = await Snapshot();
        Assert.Equal(2, (await db.Create(init, default)).Epoch);
        Assert.Equal(before, await Snapshot());
        // Same-scope writers are serialized; different operation IDs cannot both
        // replace revision 2. One commits, one observes a revision conflict.
        var final = revised with { Revision = 3, Keywords = ["final"] };
        var last = await client.PrepareMutationAsync(scope, MutationKind.Update, revised, final, update.PendingState, keys);
        var req1 = Request(MutationKind.Update, final, 2, last.Message);
        var req2 = req1 with { OperationId = Guid.NewGuid() };
        var outcomes = await Task.WhenAll(Attempt(req1), Attempt(req2));
        Assert.Single(outcomes.Where(ok => ok));
        Assert.Equal(3, (await engine.Epoch(scope, default)).Epoch);
        await Expect("final", last.PendingState, [original.DocumentId]);
        var del = await client.PrepareMutationAsync(scope, MutationKind.Delete, final, null, last.PendingState, keys);
        await engine.Mutate(Request(MutationKind.Delete, final, 3, del.Message), default);
        await Expect("final", del.PendingState, []);
        Assert.Equal(18, (await engine.Status(scope, default)).IndexEntries); // 2 arrays + free head + metadata.

        MutationRequest Request(MutationKind kind, TrustedDocument d, long expected, ProtocolMessage message) =>
            new(1, Guid.NewGuid(), scope, kind, d.DocumentId, expected,
                kind == MutationKind.Delete ? null : new(d.DocumentId, d.Revision, new(1, 1, new byte[12], [1], new byte[16])), message);
        async Task<bool> Attempt(MutationRequest r)
        {
            try { await engine.Mutate(r, default); return true; }
            catch (InvalidOperationException) { return false; }
        }
        async Task Expect(string word, ClientState state, Guid[] expected)
        {
            var query = await client.BeginSearchAsync(scope, word, state, keys);
            var epoch = (await engine.Epoch(scope, default)).Epoch;
            var response = await engine.Search(new(1, Guid.NewGuid(), scope, epoch, 0, query.NextMessage!), default);
            Assert.Equal(expected, (await client.ContinueSearchAsync(scope, response, query.PendingState, keys)).CompletedDocumentIds);
        }
        async Task<string> Snapshot()
        {
            await using var cmd = source.CreateCommand("SELECT address,value FROM cs_entries WHERE generation_id=$1 ORDER BY address");
            cmd.Parameters.AddWithValue(scope.GenerationId);
            await using var reader = await cmd.ExecuteReaderAsync();
            var rows = new List<IndexEntry>();
            while (await reader.ReadAsync()) rows.Add(new(reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1)));
            return Convert.ToBase64String(Wire.Encode(rows));
        }
    }

    private sealed class FaultingObjects(IEncryptedDocumentStore inner) : IEncryptedDocumentStore
    {
        internal bool FailNext;
        public async ValueTask PutAsync(IndexScope scope, EncryptedDocument document, CancellationToken cancellationToken = default)
        {
            await inner.PutAsync(scope, document, cancellationToken);
            if (FailNext) { FailNext = false; throw new IOException("Injected failure after upload, before index commit."); }
        }
        public ValueTask<EncryptedDocument> GetAsync(GetEncryptedDocumentRequest request, CancellationToken cancellationToken = default) => inner.GetAsync(request, cancellationToken);
        public ValueTask DeleteAsync(GetEncryptedDocumentRequest request, CancellationToken cancellationToken = default) => inner.DeleteAsync(request, cancellationToken);
    }
}
