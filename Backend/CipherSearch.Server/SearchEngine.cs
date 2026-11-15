using System.Security.Cryptography;
using System.Diagnostics;
using CipherSearch.Contracts;
using CipherSearch.SearchSchemes.Naive;
using CipherSearch.SearchSchemes.Mitra;
using CipherSearch.SearchSchemes.Kamara;
using CipherSearch.Server.Storage;
using Npgsql;

namespace CipherSearch.Server;

public sealed class SearchEngine(RuntimeDatabase db, IEncryptedDocumentStore objects, LeakageLog leakage, ILogger<SearchEngine> logger)
{
    public async Task<InitializeResponse> Epoch(IndexScope scope, CancellationToken ct)
    {
        await using var conn = await db.Source.OpenConnectionAsync(ct);
        await using var txn = await conn.BeginTransactionAsync(ct);
        return new(scope, await RuntimeDatabase.Lock(conn, txn, scope, ct));
    }

    private static IServerSearchScheme Scheme(IndexScope scope) => scope.SchemeId switch
    {
        SchemeIds.NaiveHmac => new NaiveServerScheme(),
        SchemeIds.Mitra => new MitraServerScheme(),
        SchemeIds.Kamara => new KamaraServerScheme(),
        _ => throw new ArgumentException("Unsupported scheme.")
    };

    public async Task<RuntimeStatus> Status(IndexScope scope, CancellationToken ct)
    {
        await using var conn = await db.Source.OpenConnectionAsync(ct);
        await using var txn = await conn.BeginTransactionAsync(ct);
        var epoch = await RuntimeDatabase.Lock(conn, txn, scope, ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT count(*)::integer,coalesce(sum(octet_length(address)+octet_length(value)),0)::bigint FROM cs_entries WHERE generation_id=$1", conn, txn);
        cmd.Parameters.AddWithValue(scope.GenerationId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        await r.ReadAsync(ct);
        return new(scope, epoch, r.GetInt64(1), r.GetInt32(0));
    }

    public async Task<MutationResponse> Mutate(MutationRequest request, CancellationToken ct)
    {
        if (request.Scope.SchemeId == SchemeIds.Mitra)
            throw new ArgumentException("Mitra requires private index writes, not document mutations.");
        var timer = Stopwatch.StartNew();
        if (request.Version != 1 || request.OperationId == Guid.Empty || request.DocumentId == Guid.Empty
            || !Enum.IsDefined(request.Kind) || request.ExpectedRevision < 0)
            throw new ArgumentException("Invalid mutation.");
        await using var conn = await db.Source.OpenConnectionAsync(ct);
        await using var txn = await conn.BeginTransactionAsync(ct);
        var priorEpoch = await RuntimeDatabase.Lock(conn, txn, request.Scope, ct);
        var hash = SHA256.HashData(Wire.Encode(request));
        await using (var receipt = new NpgsqlCommand(
            "SELECT request_hash,response FROM cs_operations WHERE generation_id=$1 AND operation_id=$2", conn, txn))
        {
            receipt.Parameters.AddWithValue(request.Scope.GenerationId); receipt.Parameters.AddWithValue(request.OperationId);
            await using var r = await receipt.ExecuteReaderAsync(ct);
            if (await r.ReadAsync(ct))
            {
                if (!CryptographicOperations.FixedTimeEquals(hash, r.GetFieldValue<byte[]>(0)))
                    throw new InvalidOperationException("Operation ID reused with different content.");
                return Wire.Decode<MutationResponse>(r.GetFieldValue<byte[]>(1));
            }
        }
        var previous = await RuntimeDatabase.ReadDocument(conn, txn, request.Scope, request.DocumentId, ct);
        if (request.ExpectedRevision != (previous?.Revision ?? 0)
            || (request.Kind == MutationKind.Add ? previous is { Deleted: false } : previous is null or { Deleted: true }))
            throw new InvalidOperationException("Document revision conflict.");
        var revision = checked(request.ExpectedRevision + 1);
        if (request.Kind == MutationKind.Delete)
        {
            if (request.Replacement is not null) throw new ArgumentException("Deletion has a replacement.");
        }
        else
        {
            var replacement = request.Replacement ?? throw new ArgumentException("Missing encrypted document.");
            if (replacement.DocumentId != request.DocumentId || replacement.Revision != revision
                || replacement.Content.Version != 1 || replacement.Content.KeyVersion != request.Scope.KeyVersion
                || replacement.Content.Nonce.Length != 12 || replacement.Content.Tag.Length != 16)
                throw new ArgumentException("Invalid encrypted document.");
        }
        var session = new PostgresIndexSession(conn, txn, request.Scope);
        if (request.Scope.SchemeId == SchemeIds.Kamara)
        {
            var change = Wire.Read<KamaraMutation>(request.IndexMutation, "kamara.mutate");
            if ((change.Delete is not null) != (request.Kind != MutationKind.Add)
                || (change.Add is not null) != (request.Kind != MutationKind.Delete)
                || (change.Delete is not null && change.Delete.DocumentId != request.DocumentId))
                throw new ArgumentException("Kamara mutation does not match the document operation.");
        }
        var ack = await Scheme(request.Scope).ApplyMutationAsync(request.Scope, request.IndexMutation, session, ct);
        if (request.Replacement is not null)
        {
            // Independent commit survives a crash between object upload and index commit.
            await using var intent = db.Source.CreateCommand("INSERT INTO cs_upload_intents VALUES($1,$2,$3) ON CONFLICT DO NOTHING");
            intent.Parameters.AddWithValue(request.Scope.GenerationId); intent.Parameters.AddWithValue(request.DocumentId);
            intent.Parameters.AddWithValue(revision); await intent.ExecuteNonQueryAsync(ct);
            await objects.PutAsync(request.Scope, request.Replacement, ct);
        }
        await session.Flush(ct);
        var response = new MutationResponse(request.OperationId, revision, ack);
        await using var batch = new NpgsqlBatch(conn, txn);
        var metadata = new NpgsqlBatchCommand("""
            INSERT INTO cs_documents VALUES($1,$2,$3,$4) ON CONFLICT(generation_id,document_id)
            DO UPDATE SET revision=EXCLUDED.revision,deleted=EXCLUDED.deleted
            """);
        metadata.Parameters.AddWithValue(request.Scope.GenerationId); metadata.Parameters.AddWithValue(request.DocumentId);
        metadata.Parameters.AddWithValue(revision); metadata.Parameters.AddWithValue(request.Kind == MutationKind.Delete);
        batch.BatchCommands.Add(metadata);
        var record = new NpgsqlBatchCommand("INSERT INTO cs_operations VALUES($1,$2,$3,$4)");
        record.Parameters.AddWithValue(request.Scope.GenerationId); record.Parameters.AddWithValue(request.OperationId);
        record.Parameters.AddWithValue(hash); record.Parameters.AddWithValue(Wire.Encode(response));
        batch.BatchCommands.Add(record);
        var epoch = new NpgsqlBatchCommand("UPDATE cs_generations SET epoch=epoch+1 WHERE generation_id=$1");
        epoch.Parameters.AddWithValue(request.Scope.GenerationId); batch.BatchCommands.Add(epoch);
        var finishUpload = new NpgsqlBatchCommand("DELETE FROM cs_upload_intents WHERE generation_id=$1 AND document_id=$2 AND revision=$3");
        finishUpload.Parameters.AddWithValue(request.Scope.GenerationId); finishUpload.Parameters.AddWithValue(request.DocumentId);
        finishUpload.Parameters.AddWithValue(revision); batch.BatchCommands.Add(finishUpload);
        if (previous is { Deleted: false })
        {
            var cleanup = new NpgsqlBatchCommand("INSERT INTO cs_object_cleanup VALUES($1,$2,$3) ON CONFLICT DO NOTHING");
            cleanup.Parameters.AddWithValue(request.Scope.GenerationId); cleanup.Parameters.AddWithValue(request.DocumentId);
            cleanup.Parameters.AddWithValue(previous.Revision); batch.BatchCommands.Add(cleanup);
        }
        await batch.ExecuteNonQueryAsync(ct);
        await txn.CommitAsync(ct);
        try { await Cleanup(request.Scope, ct); }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { logger.LogWarning("Object cleanup pending for generation {Generation}", request.Scope.GenerationId); }
        timer.Stop();
        await leakage.Record(request.Scope, request.OperationId, request.Kind.ToString().ToLowerInvariant(),
            priorEpoch + 1, Wire.Encode(request).Length, Wire.Encode(response).Length, timer.ElapsedTicks * 1_000_000 / Stopwatch.Frequency,
            [], session.ObservedAddresses, [request.DocumentId], 0);
        return response;
    }

    public async Task Cleanup(IndexScope scope, CancellationToken ct)
    {
        await using var conn = await db.Source.OpenConnectionAsync(ct);
        await using var txn = await conn.BeginTransactionAsync(ct);
        await RuntimeDatabase.Lock(conn, txn, scope, ct);
        var pending = new List<GetEncryptedDocumentRequest>();
        await using (var cmd = new NpgsqlCommand("""
            SELECT document_id,revision FROM cs_object_cleanup WHERE generation_id=$1
            UNION SELECT document_id,revision FROM cs_upload_intents WHERE generation_id=$1
            """, conn, txn))
        {
            cmd.Parameters.AddWithValue(scope.GenerationId);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct)) pending.Add(new(scope, r.GetGuid(0), r.GetInt64(1)));
        }
        foreach (var item in pending)
        {
            var live = await RuntimeDatabase.ReadDocument(conn, txn, scope, item.DocumentId, ct);
            if (live is { Deleted: false } && live.Revision == item.Revision) continue;
            await objects.DeleteAsync(item, ct);
        }
        await using var clear = new NpgsqlBatch(conn, txn);
        foreach (var table in new[] { "cs_object_cleanup", "cs_upload_intents" })
        {
            var command = new NpgsqlBatchCommand($"DELETE FROM {table} WHERE generation_id=$1");
            command.Parameters.AddWithValue(scope.GenerationId);
            clear.BatchCommands.Add(command);
        }
        await clear.ExecuteNonQueryAsync(ct);
        await txn.CommitAsync(ct);
    }

    public async Task<SearchResponse> Search(SearchRequest request, CancellationToken ct)
    {
        var timer = Stopwatch.StartNew();
        if (request.Version != 1 || request.Round != 0 || request.SearchId == Guid.Empty)
            throw new ArgumentException("Invalid search.");
        await using var conn = await db.Source.OpenConnectionAsync(ct);
        await using var txn = await conn.BeginTransactionAsync(ct);
        var epoch = await RuntimeDatabase.Lock(conn, txn, request.Scope, ct);
        if (epoch != request.ExpectedEpoch) throw new InvalidOperationException("Epoch conflict.");
        var session = new PostgresIndexSession(conn, txn, request.Scope);
        var response = await Scheme(request.Scope).SearchAsync(request, session, ct);
        byte[][] tokens;
        Guid[] documentIds;
        int count;
        if (request.Scope.SchemeId == SchemeIds.NaiveHmac)
        {
            tokens = [Wire.Read<NaiveSearchPayload>(request.Message, "naive.search").Token];
            documentIds = [];
            count = Wire.Read<NaiveSearchResult>(response.Message, "naive.results").Entries.Count;
        }
        else if (request.Scope.SchemeId == SchemeIds.Mitra)
        {
            tokens = Wire.Read<MitraSearch>(request.Message, "mitra.search").Addresses;
            documentIds = [];
            count = Wire.Read<MitraResults>(response.Message, "mitra.results").Entries.Count;
        }
        else if (request.Scope.SchemeId == SchemeIds.Kamara)
        {
            var token = Wire.Read<KamaraSearchToken>(request.Message, "kamara.search");
            tokens = [token.F, token.G, token.P];
            documentIds = Wire.Read<KamaraResults>(response.Message, "kamara.results").DocumentIds;
            count = documentIds.Length;
        }
        else throw new ArgumentException("Unsupported scheme.");
        timer.Stop();
        await leakage.Record(request.Scope, request.SearchId, "search", epoch,
            Wire.Encode(request).Length, Wire.Encode(response).Length, timer.ElapsedTicks * 1_000_000 / Stopwatch.Frequency,
            tokens, session.ObservedAddresses, documentIds, count);
        return response;
    }

    public async Task<EncryptedDocument> Read(GetEncryptedDocumentRequest request, CancellationToken ct)
    {
        if (request.Scope.SchemeId == SchemeIds.Mitra) throw new ArgumentException("Use opaque blob reads.");
        await using var conn = await db.Source.OpenConnectionAsync(ct);
        await using var txn = await conn.BeginTransactionAsync(ct);
        await RuntimeDatabase.Lock(conn, txn, request.Scope, ct);
        var metadata = await RuntimeDatabase.ReadDocument(conn, txn, request.Scope, request.DocumentId, ct);
        if (metadata is null or { Deleted: true } || metadata.Revision != request.Revision)
            throw new KeyNotFoundException("Document revision unavailable.");
        return await objects.GetAsync(request, ct);
    }
}
