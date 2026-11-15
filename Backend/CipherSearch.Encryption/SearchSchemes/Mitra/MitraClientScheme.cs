using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CipherSearch.Contracts;
using CipherSearch.Cryptography;

namespace CipherSearch.SearchSchemes.Mitra;

public sealed record MitraState(Dictionary<string, long> Counters, Dictionary<Guid, long> Revisions);
public sealed record MitraSearch(byte[][] Addresses);
public sealed record MitraResults(IReadOnlyList<IndexEntry> Entries);
public sealed record MitraPending(string Word, long Count, Dictionary<Guid, long> Revisions);

// CCS 2018, Algorithms 1–3. Entries are append-only, including deletions.
public sealed class MitraClientScheme : IClientSearchScheme
{
    public string SchemeId => SchemeIds.Mitra;
    public ValueTask<ClientState> InitializeAsync(IndexScope scope, IClientKeyProvider keys, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new ClientState(1, Wire.Encode(new MitraState([], []))));

    private static byte[] Prf(byte[] key, string word, long counter, byte domain)
    {
        var text = Encoding.UTF8.GetBytes(word);
        var input = new byte[checked(4 + text.Length + 9)];
        BinaryPrimitives.WriteInt32BigEndian(input, text.Length);
        text.CopyTo(input, 4);
        BinaryPrimitives.WriteInt64BigEndian(input.AsSpan(4 + text.Length), counter);
        input[^1] = domain;
        return HMACSHA256.HashData(key, input);
    }

    public async ValueTask<PreparedMutation> PrepareMutationAsync(IndexScope scope, MutationKind kind,
        TrustedDocument? previous, TrustedDocument? replacement, ClientState state, IClientKeyProvider keys,
        CancellationToken cancellationToken = default)
    {
        var local = Wire.Decode<MitraState>(state.Payload);
        var entries = new List<IndexEntry>();
        var key = await keys.DeriveKeyAsync(scope, KeyPurposes.IndexValue, cancellationToken);
        try
        {
            var oldWords = (previous?.Keywords ?? []).ToHashSet(StringComparer.Ordinal);
            var newWords = (replacement?.Keywords ?? []).ToHashSet(StringComparer.Ordinal);
            Append(previous, oldWords.Except(newWords), 0);
            Append(replacement, newWords.Except(oldWords), 1);
            if (previous is not null) local.Revisions.Remove(previous.DocumentId);
            if (replacement is not null) local.Revisions[replacement.DocumentId] = replacement.Revision;
            return new(Wire.Message("mitra.mutate", entries), new(1, Wire.Encode(local)));
        }
        finally { CryptographicOperations.ZeroMemory(key); }

        void Append(TrustedDocument? doc, IEnumerable<string> words, byte operation)
        {
            if (doc is null) return;
            foreach (var word in words)
            {
                var count = checked(local.Counters.GetValueOrDefault(word) + 1);
                local.Counters[word] = count;
                var plain = new byte[17]; // Stable document UUID followed by add/delete.
                doc.DocumentId.TryWriteBytes(plain);
                plain[16] = operation;
                var mask = Prf(key, word, count, 1);
                for (var i = 0; i < plain.Length; i++) plain[i] ^= mask[i];
                CryptographicOperations.ZeroMemory(mask);
                entries.Add(new(Prf(key, word, count, 0), plain));
            }
        }
    }

    public async ValueTask<ClientSearchStep> BeginSearchAsync(IndexScope scope, string normalizedKeyword,
        ClientState state, IClientKeyProvider keys, CancellationToken cancellationToken = default)
    {
        var local = Wire.Decode<MitraState>(state.Payload);
        var count = local.Counters.GetValueOrDefault(normalizedKeyword);
        var addresses = new byte[checked((int)count)][];
        var key = await keys.DeriveKeyAsync(scope, KeyPurposes.IndexValue, cancellationToken);
        try
        {
            for (var i = 0; i < addresses.Length; i++) addresses[i] = Prf(key, normalizedKeyword, i + 1L, 0);
            return new(Wire.Message("mitra.search", new MitraSearch(addresses)),
                new(1, Wire.Encode(new MitraPending(normalizedKeyword, count, local.Revisions))), null);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public async ValueTask<ClientSearchStep> ContinueSearchAsync(IndexScope scope, SearchResponse response,
        ClientState pendingState, IClientKeyProvider keys, CancellationToken cancellationToken = default)
    {
        var pending = Wire.Decode<MitraPending>(pendingState.Payload);
        var entries = Wire.Read<MitraResults>(response.Message, "mitra.results").Entries;
        if (entries.Count != pending.Count) throw new InvalidOperationException("Missing Mitra history entries.");
        var byAddress = entries.ToDictionary(e => Convert.ToHexString(e.Address));
        var live = new HashSet<Guid>();
        var key = await keys.DeriveKeyAsync(scope, KeyPurposes.IndexValue, cancellationToken);
        try
        {
            for (long i = 1; i <= pending.Count; i++)
            {
                var address = Prf(key, pending.Word, i, 0);
                if (!byAddress.TryGetValue(Convert.ToHexString(address), out var entry) || entry.Value.Length != 17)
                    throw new InvalidOperationException("Invalid Mitra history.");
                var plain = entry.Value.ToArray();
                var mask = Prf(key, pending.Word, i, 1);
                for (var j = 0; j < plain.Length; j++) plain[j] ^= mask[j];
                var match = new Guid(plain.AsSpan(0, 16));
                var operation = plain[16];
                CryptographicOperations.ZeroMemory(mask);
                CryptographicOperations.ZeroMemory(plain);
                if (match == Guid.Empty || operation > 1) throw new InvalidOperationException("Invalid Mitra entry.");
                if (operation == 1) live.Add(match);
                else live.Remove(match);
            }
            var matches = live.ToDictionary(id => id, id =>
                pending.Revisions.TryGetValue(id, out var revision) && revision > 0
                    ? new DocumentMatch(id, revision)
                    : throw new InvalidOperationException("Unknown live Mitra document."));
            return new(null, new(1, Wire.Encode(new SchemeState(matches, []))), matches.Keys.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
