using System.Security.Cryptography;
using CipherSearch.Contracts;
using CipherSearch.SearchSchemes.Kamara;
using Npgsql;

namespace CipherSearch.Server.Storage;

public sealed class RuntimeDatabase(NpgsqlDataSource source)
{
    public NpgsqlDataSource Source => source;
    public async Task Initialize(CancellationToken ct = default)
    {
        await using var stream = typeof(RuntimeDatabase).Assembly.GetManifestResourceStream(
            "CipherSearch.Server.Storage.schema.sql") ?? throw new InvalidOperationException("Schema resource missing.");
        using var reader = new StreamReader(stream);
        await using var cmd = source.CreateCommand(await reader.ReadToEndAsync(ct));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public static void Validate(IndexScope scope)
    {
        if (scope.DatasetId == Guid.Empty || scope.GenerationId == Guid.Empty || scope.KeyVersion <= 0
            || scope.SchemeId is not (SchemeIds.NaiveHmac or SchemeIds.Mitra or SchemeIds.Kamara))
            throw new ArgumentException("Invalid scope.");
    }

    public async Task<InitializeResponse> Create(InitializeRequest request, CancellationToken ct,
        IEncryptedDocumentStore? objects = null)
    {
        Validate(request.Scope);
        if (request.Setup is not null && request.Scope.SchemeId != SchemeIds.Kamara)
            throw new ArgumentException("Setup snapshot is only supported for Kamara.");
        if (request.Version != 1 || request.OperationId == Guid.Empty) throw new ArgumentException("Invalid initialization.");
        var documents = request.Documents;
        if (documents is not null && (request.Setup is null || objects is null || documents.Length == 0 ||
            documents.Select(d => d.DocumentId).Distinct().Count() != documents.Length ||
            documents.Any(d => d.DocumentId == Guid.Empty || d.Revision != 1 ||
                d.Content.Version != 1 || d.Content.KeyVersion != request.Scope.KeyVersion ||
                d.Content.Nonce.Length != 12 || d.Content.Tag.Length != 16)))
            throw new ArgumentException("Invalid initial encrypted collection.");
        await using var conn = await source.OpenConnectionAsync(ct);
        await using var txn = await conn.BeginTransactionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO cs_generations VALUES($1,$2,$3,$4,0) ON CONFLICT DO NOTHING", conn, txn);
        cmd.Parameters.AddWithValue(request.Scope.GenerationId);
        cmd.Parameters.AddWithValue(request.Scope.DatasetId);
        cmd.Parameters.AddWithValue(request.Scope.SchemeId);
        cmd.Parameters.AddWithValue(request.Scope.KeyVersion);
        var created = await cmd.ExecuteNonQueryAsync(ct);
        var epoch = await Lock(conn, txn, request.Scope, ct);
        byte[]? setupHash = null;
        if (documents is not null)
        {
            setupHash = SHA256.HashData(Wire.Encode(request));
            if (created == 0)
            {
                await using var receipt = new NpgsqlCommand(
                    "SELECT request_hash FROM cs_operations WHERE generation_id=$1 AND operation_id=$2", conn, txn);
                receipt.Parameters.AddWithValue(request.Scope.GenerationId);
                receipt.Parameters.AddWithValue(request.OperationId);
                if (await receipt.ExecuteScalarAsync(ct) is not byte[] prior ||
                    !CryptographicOperations.FixedTimeEquals(prior, setupHash))
                    throw new InvalidOperationException("Initial collection requires a fresh generation.");
                return new(request.Scope, epoch);
            }
        }
        if (request.Scope.SchemeId == SchemeIds.Kamara)
        {
            if (request.Setup is null && created != 0)
                throw new ArgumentException("Kamara requires a trusted setup snapshot.");
            if (request.Setup is not null)
            {
                if (request.Setup.Kind != "kamara.setup") throw new ArgumentException("Expected Kamara setup.");
                var session = new PostgresIndexSession(conn, txn, request.Scope);
                await new KamaraServerScheme().ApplyMutationAsync(request.Scope, request.Setup, session, ct);
                await session.Flush(ct);
            }
        }
        if (documents is not null)
        {
            // The generation remains invisible until the index and document metadata commit.
            // A retry writes the same ciphertext to the same object keys.
            await using var batch = new NpgsqlBatch(conn, txn);
            foreach (var document in documents)
            {
                await objects!.PutAsync(request.Scope, document, ct);
                var row = new NpgsqlBatchCommand("INSERT INTO cs_documents VALUES($1,$2,1,false)");
                row.Parameters.AddWithValue(request.Scope.GenerationId);
                row.Parameters.AddWithValue(document.DocumentId);
                batch.BatchCommands.Add(row);
            }
            epoch = documents.Length;
            var update = new NpgsqlBatchCommand("UPDATE cs_generations SET epoch=$2 WHERE generation_id=$1");
            update.Parameters.AddWithValue(request.Scope.GenerationId);
            update.Parameters.AddWithValue(epoch);
            batch.BatchCommands.Add(update);
            var receipt = new NpgsqlBatchCommand("INSERT INTO cs_operations VALUES($1,$2,$3,$4)");
            receipt.Parameters.AddWithValue(request.Scope.GenerationId);
            receipt.Parameters.AddWithValue(request.OperationId);
            receipt.Parameters.AddWithValue(setupHash!);
            receipt.Parameters.AddWithValue(Wire.Encode(new InitializeResponse(request.Scope, epoch)));
            batch.BatchCommands.Add(receipt);
            await batch.ExecuteNonQueryAsync(ct);
        }
        await txn.CommitAsync(ct);
        return new(request.Scope, epoch);
    }

    public static async Task<long> Lock(NpgsqlConnection conn, NpgsqlTransaction txn, IndexScope scope, CancellationToken ct)
    {
        Validate(scope);
        await using var cmd = new NpgsqlCommand(
            "SELECT dataset_id,scheme_id,key_version,epoch FROM cs_generations WHERE generation_id=$1 FOR UPDATE", conn, txn);
        cmd.Parameters.AddWithValue(scope.GenerationId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) throw new KeyNotFoundException("Generation missing.");
        if (r.GetGuid(0) != scope.DatasetId || r.GetString(1) != scope.SchemeId || r.GetInt32(2) != scope.KeyVersion)
            throw new InvalidOperationException("Scope conflict.");
        return r.GetInt64(3);
    }

    public static async Task<StoredDocument?> ReadDocument(NpgsqlConnection conn, NpgsqlTransaction txn,
        IndexScope scope, Guid id, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(
            "SELECT revision,deleted FROM cs_documents WHERE generation_id=$1 AND document_id=$2", conn, txn);
        cmd.Parameters.AddWithValue(scope.GenerationId); cmd.Parameters.AddWithValue(id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? new(id, r.GetInt64(0), r.GetBoolean(1)) : null;
    }
}
