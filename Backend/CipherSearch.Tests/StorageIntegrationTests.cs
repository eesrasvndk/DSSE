using System.Security.Cryptography;
using CipherSearch.Contracts;
using CipherSearch.Cryptography;
using CipherSearch.SearchSchemes.Naive;
using CipherSearch.SearchSchemes.Mitra;
using CipherSearch.Server;
using CipherSearch.Server.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Minio;
using Npgsql;

namespace CipherSearch.Tests;

public sealed class IntegrationTheoryAttribute : TheoryAttribute
{
    public IntegrationTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("CIPHERSEARCH_INTEGRATION") != "1")
            Skip = "Set CIPHERSEARCH_INTEGRATION=1 and CIPHERSEARCH_ENV_FILE to run against PostgreSQL/MinIO.";
    }
}

public sealed class StorageIntegrationTests
{
    [IntegrationTheory]
    [Trait("Category", "Integration")]
    [InlineData(false)]
    public async Task RealStorageReplayScopeRollbackAndCleanup(bool mitra = false)
    {
        var path = Environment.GetEnvironmentVariable("CIPHERSEARCH_ENV_FILE")
            ?? throw new InvalidOperationException("Environment file path missing.");
        var settings = File.ReadAllLines(path).Where(l => l.Contains('=') && !l.TrimStart().StartsWith('#'))
            .Select(l => l.Split('=', 2)).ToDictionary(p => p[0].Trim(), p => p[1].Trim().Trim('"', '\''));
        var connection = new NpgsqlConnectionStringBuilder
        {
            Host = "127.0.0.1", Port = 5432, Database = settings["POSTGRES_DB"],
            Username = settings["POSTGRES_USER"], Password = settings["POSTGRES_PASSWORD"], SearchPath = "dsse"
        };
        await using var source = NpgsqlDataSource.Create(connection.ConnectionString);
        var db = new RuntimeDatabase(source);
        await db.Initialize();
        using var minio = new MinioClient().WithEndpoint("127.0.0.1:9000")
            .WithCredentials(settings["MINIO_ROOT_USER"], settings["MINIO_ROOT_PASSWORD"]).Build();
        var actualObjects = new MinioDocumentStore(minio, "dsse-documents");
        await actualObjects.Initialize();
        var faulting = new FaultingObjects(actualObjects);
        var log = new LeakageLog(new ConfigurationBuilder().Build(), NullLogger<LeakageLog>.Instance);
        var engine = new SearchEngine(db, faulting, log, NullLogger<SearchEngine>.Instance);
        using var keys = new TestKeys();
        IClientSearchScheme client = mitra ? new MitraClientScheme() : new NaiveClientScheme(keys);
        var scope = new IndexScope(Guid.NewGuid(), client.SchemeId, Guid.NewGuid(), 1);
        var init = new InitializeRequest(1, Guid.NewGuid(), scope);
        Assert.Equal(0, (await db.Create(init, default)).Epoch);
        Assert.Equal(0, (await db.Create(init, default)).Epoch);
        await Assert.ThrowsAsync<InvalidOperationException>(() => db.Create(init with { Scope = scope with { KeyVersion = 2 } }, default));
        var id = Guid.NewGuid();
        var state = await client.InitializeAsync(scope, keys);
        var first = new TrustedDocument(id, 1, ["alpha", "beta"]);
        var add = await Prepare(MutationKind.Add, null, first, state);
        var receipt = await engine.Mutate(add.Request, default);
        state = add.State;
        Assert.Equal(Wire.Encode(receipt), Wire.Encode(await engine.Mutate(add.Request, default)));
        Assert.Equal(1, (await engine.Epoch(scope, default)).Epoch);
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.Mutate(add.Request with { ExpectedRevision = 5 }, default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.Mutate(add.Request with { OperationId = Guid.NewGuid() }, default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.Epoch(scope with { DatasetId = Guid.NewGuid() }, default));
        var query = await client.BeginSearchAsync(scope, "alpha", state, keys);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            engine.Search(new(1, Guid.NewGuid(), scope, 0, 0, query.NextMessage!), default));
        var second = new TrustedDocument(id, 2, ["gamma"]);
        var update = await Prepare(MutationKind.Update, first, second, add.State);
        faulting.FailAfterUpload = true;
        await Assert.ThrowsAsync<IOException>(() => engine.Mutate(update.Request, default));
        Assert.Equal(1, (await engine.Epoch(scope, default)).Epoch);
        await Expect("alpha", [id], 1);
        await Expect("gamma", [], 1);
        Assert.Equal(2, (await actualObjects.GetAsync(new(scope, id, 2))).Revision);
        await engine.Cleanup(scope, default);
        await Assert.ThrowsAnyAsync<Exception>(async () => await actualObjects.GetAsync(new(scope, id, 2)));
        Assert.Equal(1, (await engine.Read(new(scope, id, 1), default)).Revision);
        await engine.Mutate(update.Request, default);
        state = update.State;
        await Expect("alpha", [], 2);
        await Expect("gamma", [id], 2);
        await Assert.ThrowsAsync<KeyNotFoundException>(() => engine.Read(new(scope, id, 1), default));
        await using (var intent = source.CreateCommand("INSERT INTO cs_upload_intents VALUES($1,$2,2)"))
        {
            intent.Parameters.AddWithValue(scope.GenerationId); intent.Parameters.AddWithValue(id);
            await intent.ExecuteNonQueryAsync();
        }
        await engine.Cleanup(scope, default);
        Assert.Equal(2, (await engine.Read(new(scope, id, 2), default)).Revision);
        var deletion = await Prepare(MutationKind.Delete, second, null, update.State);
        await engine.Mutate(deletion.Request, default);
        state = deletion.State;
        Assert.Equal(mitra ? 6 : 0, (await engine.Status(scope, default)).IndexEntries);
        await Assert.ThrowsAsync<KeyNotFoundException>(() => engine.Read(new(scope, id, 2), default));
        var third = new TrustedDocument(id, 4, []);
        var readd = await Prepare(MutationKind.Add, null, third, deletion.State, 3);
        await engine.Mutate(readd.Request, default);
        await Expect("gamma", [], 4);
        Assert.Equal(4, (await engine.Read(new(scope, id, 4), default)).Revision);
        var final = await Prepare(MutationKind.Delete, third, null, readd.State);
        await engine.Mutate(final.Request, default);
        Assert.Equal(mitra ? 6 : 0, (await engine.Status(scope, default)).IndexEntries);

        async Task<(MutationRequest Request, ClientState State)> Prepare(MutationKind kind,
            TrustedDocument? previous, TrustedDocument? replacement, ClientState local, long? expected = null)
        {
            var prepared = await client.PrepareMutationAsync(scope, kind, previous, replacement, local, keys);
            EncryptedDocument? encrypted = null;
            if (replacement is not null)
            {
                var key = await keys.DeriveKeyAsync(scope, KeyPurposes.Document);
                try
                {
                    encrypted = new(id, replacement.Revision, new AesGcmCipher().Encrypt(
                        "test document"u8, key, 1, keys.Reserve(scope, KeyPurposes.Document),
                        AssociatedData.Document(scope, id, replacement.Revision)));
                }
                finally { CryptographicOperations.ZeroMemory(key); }
            }
            return (new(1, Guid.NewGuid(), scope, kind, id, expected ?? previous?.Revision ?? 0, encrypted, prepared.Message),
                prepared.PendingState);
        }

        async Task Expect(string word, Guid[] expected, long epoch)
        {
            var start = await client.BeginSearchAsync(scope, word, state, keys);
            var response = await engine.Search(new(1, Guid.NewGuid(), scope, epoch, 0, start.NextMessage!), default);
            var result = await client.ContinueSearchAsync(scope, response, start.PendingState, keys);
            Assert.True(expected.ToHashSet().SetEquals(result.CompletedDocumentIds!));
        }
    }

    [IntegrationTheory]
    [Trait("Category", "Integration")]
    [InlineData(1)]
    public async Task PrivateIndexReplayAndOpaqueBlobStorage(int version)
    {
        var path = Environment.GetEnvironmentVariable("CIPHERSEARCH_ENV_FILE")
            ?? throw new InvalidOperationException("Environment file path missing.");
        var settings = File.ReadAllLines(path).Where(l => l.Contains('=') && !l.TrimStart().StartsWith('#'))
            .Select(l => l.Split('=', 2)).ToDictionary(p => p[0].Trim(), p => p[1].Trim().Trim('"', '\''));
        var connection = new NpgsqlConnectionStringBuilder
        {
            Host = "127.0.0.1", Port = 5432, Database = settings["POSTGRES_DB"],
            Username = settings["POSTGRES_USER"], Password = settings["POSTGRES_PASSWORD"], SearchPath = "dsse"
        };
        await using var source = NpgsqlDataSource.Create(connection.ConnectionString);
        var db = new RuntimeDatabase(source);
        await db.Initialize();
        using var minio = new MinioClient().WithEndpoint("127.0.0.1:9000")
            .WithCredentials(settings["MINIO_ROOT_USER"], settings["MINIO_ROOT_PASSWORD"]).Build();
        var actualObjects = new MinioDocumentStore(minio, "dsse-documents");
        await actualObjects.Initialize();

        var engine = new PrivateIndexEngine(db, actualObjects);
        using var keys = new TestKeys();
        var client = new MitraClientScheme();
        var scope = new IndexScope(Guid.NewGuid(), SchemeIds.Mitra, Guid.NewGuid(), 1);
        await db.Create(new(version, Guid.NewGuid(), scope), default);
        var state = await client.InitializeAsync(scope, keys);
        var doc = new TrustedDocument(Guid.NewGuid(), 1, ["alpha"]);
        var add = await client.PrepareMutationAsync(scope, MutationKind.Add, null, doc, state, keys);
        var write = new PrivateIndexWrite(1, Guid.NewGuid(), scope, add.Message);
        Assert.Equal(await engine.Write(write, default), await engine.Write(write, default));
        var conflict = write with { Entries = Wire.Message("mitra.mutate", Array.Empty<IndexEntry>()) };
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.Write(conflict, default));
        await using (var count = source.CreateCommand("SELECT count(*) FROM cs_documents WHERE generation_id=$1"))
        {
            count.Parameters.AddWithValue(scope.GenerationId);
            Assert.Equal(0L, (long)(await count.ExecuteScalarAsync())!);
        }
        var blob = new OpaqueBlobWrite(scope, Guid.NewGuid(), new(1, 1, new byte[12], [1, 2, 3], new byte[16]));
        Assert.Equal(await engine.Put(blob, default), await engine.Put(blob, default));
        Assert.Equal(blob.Content.Ciphertext, (await engine.Read(new(scope, blob.BlobId), default)).Ciphertext);
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.Put(blob with { Content = blob.Content with { Ciphertext = [4] } }, default));
        var del = await client.PrepareMutationAsync(scope, MutationKind.Delete, doc, null, add.PendingState, keys);
        await engine.Write(new(1, Guid.NewGuid(), scope, del.Message), default);
        var log = new LeakageLog(new ConfigurationBuilder().Build(), NullLogger<LeakageLog>.Instance);
        var search = new SearchEngine(db, actualObjects, log, NullLogger<SearchEngine>.Instance);
        var begin = await client.BeginSearchAsync(scope, "alpha", del.PendingState, keys);
        var response = await search.Search(new(1, Guid.NewGuid(), scope, 2, 0, begin.NextMessage!), default);
        Assert.Empty((await client.ContinueSearchAsync(scope, response, begin.PendingState, keys)).CompletedDocumentIds!);
        Assert.Equal(2, (await search.Status(scope, default)).IndexEntries);
        Assert.Equal(blob.Content.Ciphertext, (await engine.Read(new(scope, blob.BlobId), default)).Ciphertext);
        await Assert.ThrowsAsync<ArgumentException>(() => search.Mutate(new(1, Guid.NewGuid(), scope, MutationKind.Add, doc.DocumentId, 0, null, add.Message), default));
    }

    private sealed class FaultingObjects(IEncryptedDocumentStore inner) : IEncryptedDocumentStore
    {
        public bool FailAfterUpload { get; set; }
        public async ValueTask PutAsync(IndexScope scope, EncryptedDocument document, CancellationToken cancellationToken = default)
        {
            await inner.PutAsync(scope, document, cancellationToken);
            if (FailAfterUpload)
            {
                FailAfterUpload = false;
                throw new IOException("Injected failure after MinIO upload, before PostgreSQL commit.");
            }
        }
        public ValueTask<EncryptedDocument> GetAsync(GetEncryptedDocumentRequest request, CancellationToken cancellationToken = default) =>
            inner.GetAsync(request, cancellationToken);
        public ValueTask DeleteAsync(GetEncryptedDocumentRequest request, CancellationToken cancellationToken = default) =>
            inner.DeleteAsync(request, cancellationToken);
    }
}
