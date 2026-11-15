using System.Security.Cryptography;
using CipherSearch.Contracts;
using CipherSearch.Cryptography;

namespace CipherSearch.SearchSchemes.Naive;

public sealed record NaiveState(Dictionary<string, Dictionary<Guid, DocumentMatch>> Postings);

public sealed class NaiveClientScheme(INonceSource nonces) : IClientSearchScheme
{
    public string SchemeId => SchemeIds.NaiveHmac;
    public ValueTask<ClientState> InitializeAsync(IndexScope scope, IClientKeyProvider keys, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new ClientState(1, Wire.Encode(new NaiveState([]))));

    public async ValueTask<PreparedMutation> PrepareMutationAsync(IndexScope scope, MutationKind kind,
        TrustedDocument? previous, TrustedDocument? replacement, ClientState state, IClientKeyProvider keys,
        CancellationToken cancellationToken = default)
    {
        var local = Wire.Decode<NaiveState>(state.Payload);
        var removed = new List<byte[]>();
        var entries = new List<IndexEntry>();
        var oldWords = (previous?.Keywords ?? []).ToHashSet(StringComparer.Ordinal);
        var newWords = (replacement?.Keywords ?? []).ToHashSet(StringComparer.Ordinal);
        var tokenKey = await keys.DeriveKeyAsync(scope, KeyPurposes.SearchToken, cancellationToken);
        var valueKey = await keys.DeriveKeyAsync(scope, KeyPurposes.IndexValue, cancellationToken);
        try
        {
            foreach (var word in oldWords.Union(newWords))
            {
                if (!local.Postings.TryGetValue(word, out var list))
                    local.Postings[word] = list = [];
                if (previous is not null && oldWords.Contains(word)) list.Remove(previous.DocumentId);
                if (replacement is not null && newWords.Contains(word))
                    list[replacement.DocumentId] = new(replacement.DocumentId, replacement.Revision);
                var token = HmacTokenGenerator.Generate(tokenKey, word);
                if (list.Count == 0)
                {
                    removed.Add(token);
                    local.Postings.Remove(word);
                    continue;
                }
                var plain = Wire.Encode(list.Values.OrderBy(m => m.DocumentId).ToArray());
                try
                {
                    var envelope = new AesGcmCipher().Encrypt(plain, valueKey, scope.KeyVersion,
                        nonces.Reserve(scope, KeyPurposes.IndexValue), AssociatedData.IndexValue(scope, token));
                    entries.Add(new(token, Wire.Encode(envelope)));
                }
                finally { CryptographicOperations.ZeroMemory(plain); }
            }
        }
        finally { CryptographicOperations.ZeroMemory(tokenKey); CryptographicOperations.ZeroMemory(valueKey); }
        return new(Wire.Message("naive.mutate", new NaiveIndexMutation(removed, entries)), new(1, Wire.Encode(local)));
    }

    public async ValueTask<ClientSearchStep> BeginSearchAsync(IndexScope scope, string normalizedKeyword,
        ClientState state, IClientKeyProvider keys, CancellationToken cancellationToken = default)
    {
        var key = await keys.DeriveKeyAsync(scope, KeyPurposes.SearchToken, cancellationToken);
        try
        {
            var token = HmacTokenGenerator.Generate(key, normalizedKeyword);
            return new(Wire.Message("naive.search", new NaiveSearchPayload(token)),
                new(1, Wire.Encode(new NaivePendingSearch(token))), null);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public async ValueTask<ClientSearchStep> ContinueSearchAsync(IndexScope scope, SearchResponse response,
        ClientState pendingState, IClientKeyProvider keys, CancellationToken cancellationToken = default)
    {
        var result = Wire.Read<NaiveSearchResult>(response.Message, "naive.results");
        var token = Wire.Decode<NaivePendingSearch>(pendingState.Payload).Token;
        if (token is not { Length: 32 }) throw new ArgumentException("Missing pending search token.");
        if (result.Entries.Count > 1) throw new CryptographicException("Expected one posting list.");
        var matches = new Dictionary<Guid, DocumentMatch>();
        var key = await keys.DeriveKeyAsync(scope, KeyPurposes.IndexValue, cancellationToken);
        try
        {
            foreach (var entry in result.Entries)
            {
                if (entry.Address.Length != 32 || !entry.Address.AsSpan().SequenceEqual(token))
                    throw new CryptographicException("Result belongs to another query.");
                var plain = new AesGcmCipher().Decrypt(Wire.Decode<EncryptedEnvelope>(entry.Value), key,
                    scope.KeyVersion, AssociatedData.IndexValue(scope, entry.Address));
                try
                {
                    foreach (var match in Wire.Decode<DocumentMatch[]>(plain))
                        if (match.Revision <= 0 || !matches.TryAdd(match.DocumentId, match))
                            throw new InvalidOperationException("Invalid or duplicate search result.");
                }
                finally { CryptographicOperations.ZeroMemory(plain); }
            }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        return new(null, new(1, Wire.Encode(new SchemeState(matches, []))), matches.Keys.ToArray());
    }
}
