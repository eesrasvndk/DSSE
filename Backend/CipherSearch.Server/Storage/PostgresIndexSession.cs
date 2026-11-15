using CipherSearch.Contracts;
using Npgsql;

namespace CipherSearch.Server.Storage;

public sealed class PostgresIndexSession(NpgsqlConnection connection, NpgsqlTransaction transaction,
    IndexScope boundScope) : IIndexStore
{
    private readonly Dictionary<string, IndexEntry?> changes = [];
    private readonly Dictionary<string, IndexEntry?> reads = [];
    public byte[][] ObservedAddresses => changes.Keys.Concat(reads.Keys).Distinct().Select(Convert.FromHexString).ToArray();

    private void Check(IndexScope scope)
    {
        if (scope != boundScope) throw new ArgumentException("Index scope mismatch.");
    }

    public async ValueTask<IReadOnlyList<IndexEntry>> GetAsync(IndexScope scope,
        IReadOnlyList<byte[]> addresses, CancellationToken cancellationToken = default)
    {
        Check(scope);
        var result = new List<IndexEntry>();
        foreach (var address in addresses)
        {
            var hex = Convert.ToHexString(address);
            if (!changes.TryGetValue(hex, out var entry) && !reads.TryGetValue(hex, out entry))
            {
                await using var cmd = new NpgsqlCommand(
                    "SELECT value FROM cs_entries WHERE generation_id=$1 AND address=$2", connection, transaction);
                cmd.Parameters.AddWithValue(scope.GenerationId);
                cmd.Parameters.AddWithValue(address);
                var value = await cmd.ExecuteScalarAsync(cancellationToken) as byte[];
                entry = value is null ? null : new(address, value);
                reads[hex] = entry;
            }
            if (entry is not null) result.Add(new(entry.Address.ToArray(), entry.Value.ToArray()));
        }
        return result;
    }

    public async ValueTask<IReadOnlyList<IndexEntry>> FindByPrefixAsync(IndexScope scope,
        byte[] prefix, CancellationToken cancellationToken = default)
    {
        Check(scope);
        if (prefix.Length != 32) throw new ArgumentException("Unsupported prefix length.");
        await using var cmd = new NpgsqlCommand(
            "SELECT address,value FROM cs_entries WHERE generation_id=$1 AND substring(address from 1 for 32)=$2",
            connection, transaction);
        cmd.Parameters.AddWithValue(scope.GenerationId);
        cmd.Parameters.AddWithValue(prefix);
        var rows = new Dictionary<string, IndexEntry>();
        await using (var reader = await cmd.ExecuteReaderAsync(cancellationToken))
            while (await reader.ReadAsync(cancellationToken))
            {
                var entry = new IndexEntry(reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1));
                rows[Convert.ToHexString(entry.Address)] = entry;
                reads[Convert.ToHexString(entry.Address)] = entry;
            }
        foreach (var (hex, entry) in changes)
        {
            if (entry is null) rows.Remove(hex);
            else if (entry.Address.AsSpan().StartsWith(prefix)) rows[hex] = entry;
        }
        return rows.Values.ToArray();
    }

    public ValueTask PutAsync(IndexScope scope, IReadOnlyList<IndexEntry> entries,
        CancellationToken cancellationToken = default)
    {
        Check(scope);
        foreach (var entry in entries)
        {
            if (entry.Address.Length is < 1 or > 128 || entry.Value.Length > 1024 * 1024)
                throw new ArgumentException("Invalid index entry.");
            changes[Convert.ToHexString(entry.Address)] = new(entry.Address.ToArray(), entry.Value.ToArray());
        }
        return ValueTask.CompletedTask;
    }

    public ValueTask DeleteAsync(IndexScope scope, IReadOnlyList<byte[]> addresses,
        CancellationToken cancellationToken = default)
    {
        Check(scope);
        foreach (var address in addresses) changes[Convert.ToHexString(address)] = null;
        return ValueTask.CompletedTask;
    }

    public async Task Flush(CancellationToken ct)
    {
        if (changes.Count == 0) return;
        await using var batch = new NpgsqlBatch(connection, transaction);
        foreach (var (hex, entry) in changes)
        {
            var cmd = new NpgsqlBatchCommand(entry is null
                ? "DELETE FROM cs_entries WHERE generation_id=$1 AND address=$2"
                : "INSERT INTO cs_entries VALUES ($1,$2,$3) ON CONFLICT (generation_id,address) DO UPDATE SET value=EXCLUDED.value");
            cmd.Parameters.AddWithValue(boundScope.GenerationId);
            cmd.Parameters.AddWithValue(Convert.FromHexString(hex));
            if (entry is not null) cmd.Parameters.AddWithValue(entry.Value);
            batch.BatchCommands.Add(cmd);
        }
        await batch.ExecuteNonQueryAsync(ct);
    }
}
