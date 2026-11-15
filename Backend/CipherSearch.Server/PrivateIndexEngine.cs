using System.Security.Cryptography;
using CipherSearch.Contracts;
using CipherSearch.SearchSchemes.Mitra;
using CipherSearch.Server.Storage;
using Npgsql;

namespace CipherSearch.Server;

// Separates explicit identities; does NOT conceal timing, batching or blob traffic.
public sealed class PrivateIndexEngine(RuntimeDatabase db, IEncryptedDocumentStore objects, LeakageLog? leakage = null)
{
    private static void Validate(IndexScope scope)
    {
        RuntimeDatabase.Validate(scope);
        if (scope.SchemeId != SchemeIds.Mitra) throw new ArgumentException("Mitra scope required.");
    }

    public async Task<PrivateIndexReceipt> Write(PrivateIndexWrite request, CancellationToken ct)
    {
        Validate(request.Scope);
        if (request.Version != 1 || request.OperationId == Guid.Empty) throw new ArgumentException("Invalid write.");
        await using var conn = await db.Source.OpenConnectionAsync(ct);
        await using var txn = await conn.BeginTransactionAsync(ct);
        await RuntimeDatabase.Lock(conn, txn, request.Scope, ct);
        var hash = SHA256.HashData(Wire.Encode(request));
        await using (var cmd = new NpgsqlCommand("SELECT request_hash,response FROM cs_operations WHERE generation_id=$1 AND operation_id=$2", conn, txn))
        {
            cmd.Parameters.AddWithValue(request.Scope.GenerationId); cmd.Parameters.AddWithValue(request.OperationId);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                if (!CryptographicOperations.FixedTimeEquals(hash, reader.GetFieldValue<byte[]>(0)))
                    throw new InvalidOperationException("Operation ID reused.");
                return Wire.Decode<PrivateIndexReceipt>(reader.GetFieldValue<byte[]>(1));
            }
        }
        var store = new PostgresIndexSession(conn, txn, request.Scope);
        await new MitraServerScheme().ApplyMutationAsync(request.Scope, request.Entries, store, ct);
        await store.Flush(ct);
        var response = new PrivateIndexReceipt(request.OperationId);
        await using var receipt = new NpgsqlCommand("INSERT INTO cs_operations VALUES($1,$2,$3,$4)", conn, txn);
        receipt.Parameters.AddWithValue(request.Scope.GenerationId); receipt.Parameters.AddWithValue(request.OperationId);
        receipt.Parameters.AddWithValue(hash); receipt.Parameters.AddWithValue(Wire.Encode(response));
        await receipt.ExecuteNonQueryAsync(ct);
        await using var epoch = new NpgsqlCommand("UPDATE cs_generations SET epoch=epoch+1 WHERE generation_id=$1 RETURNING epoch", conn, txn);
        epoch.Parameters.AddWithValue(request.Scope.GenerationId);
        var committedEpoch = (long)(await epoch.ExecuteScalarAsync(ct))!;
        await txn.CommitAsync(ct);
        if (leakage is not null)
            await leakage.Record(request.Scope, request.OperationId, "index-write", committedEpoch,
                Wire.Encode(request).Length, Wire.Encode(response).Length, 0, [],
                Wire.Read<IndexEntry[]>(request.Entries, "mitra.mutate").Select(e => e.Address).ToArray(), [], 0);
        return response;
    }

    public async Task<OpaqueBlobReceipt> Put(OpaqueBlobWrite request, CancellationToken ct)
    {
        Validate(request.Scope);
        if (request.BlobId == Guid.Empty || request.Content.Version != 1 || request.Content.KeyVersion != request.Scope.KeyVersion
            || request.Content.Nonce.Length != 12 || request.Content.Tag.Length != 16)
            throw new ArgumentException("Invalid blob.");
        await using var conn = await db.Source.OpenConnectionAsync(ct);
        await using var txn = await conn.BeginTransactionAsync(ct);
        await RuntimeDatabase.Lock(conn, txn, request.Scope, ct);
        var hash = SHA256.HashData(Wire.Encode(request.Content));
        await using var existing = new NpgsqlCommand("SELECT content_hash FROM cs_opaque_blobs WHERE generation_id=$1 AND blob_id=$2", conn, txn);
        existing.Parameters.AddWithValue(request.Scope.GenerationId); existing.Parameters.AddWithValue(request.BlobId);
        if (await existing.ExecuteScalarAsync(ct) is byte[] prior && !CryptographicOperations.FixedTimeEquals(prior, hash))
            throw new InvalidOperationException("Blob IDs are immutable.");
        // Retry repairs a write interrupted before receipt commit, using identical ciphertext.
        await objects.PutAsync(request.Scope, new(request.BlobId, 1, request.Content), ct);
        await using var record = new NpgsqlCommand("INSERT INTO cs_opaque_blobs VALUES($1,$2,$3) ON CONFLICT DO NOTHING", conn, txn);
        record.Parameters.AddWithValue(request.Scope.GenerationId); record.Parameters.AddWithValue(request.BlobId); record.Parameters.AddWithValue(hash);
        await record.ExecuteNonQueryAsync(ct); await txn.CommitAsync(ct);
        if (leakage is not null)
            await leakage.Record(request.Scope, request.BlobId, "blob-put", 0,
                Wire.Encode(request).Length, Wire.Encode(new OpaqueBlobReceipt(request.BlobId)).Length,
                0, [], [], [request.BlobId], 1);
        return new(request.BlobId);
    }

    public async Task<EncryptedEnvelope> Read(OpaqueBlobRead request, CancellationToken ct)
    {
        Validate(request.Scope);
        await using var conn = await db.Source.OpenConnectionAsync(ct);
        await using var txn = await conn.BeginTransactionAsync(ct);
        await RuntimeDatabase.Lock(conn, txn, request.Scope, ct);
        await using var exists = new NpgsqlCommand("SELECT 1 FROM cs_opaque_blobs WHERE generation_id=$1 AND blob_id=$2", conn, txn);
        exists.Parameters.AddWithValue(request.Scope.GenerationId); exists.Parameters.AddWithValue(request.BlobId);
        if (await exists.ExecuteScalarAsync(ct) is null) throw new KeyNotFoundException("Blob unavailable.");
        var content = (await objects.GetAsync(new(request.Scope, request.BlobId, 1), ct)).Content;
        if (leakage is not null)
            await leakage.Record(request.Scope, Guid.NewGuid(), "blob-read", 0,
                Wire.Encode(request).Length, Wire.Encode(content).Length, 0, [], [], [request.BlobId], 1);
        return content;
    }
}
