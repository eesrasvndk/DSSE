using System.Security.Cryptography;
using CipherSearch.Contracts;
using CipherSearch.Cryptography;
using CipherSearch.SearchSchemes.Naive;
using CipherSearch.SearchSchemes.Mitra;

namespace CipherSearch.Tests;

public sealed class SearchSchemeTests
{
    [Theory]
    [InlineData(false, 1)]
    [InlineData(false, 17)]
    [InlineData(false, 42)]
    [InlineData(true, 1)]
    [InlineData(true, 17)]
    [InlineData(true, 42)]
    public async Task RandomMutationsMatchIndependentDocumentSets(bool mitra, int seed)
    {
        using var keys = new TestKeys();
        IClientSearchScheme client = mitra ? new MitraClientScheme() : new NaiveClientScheme(keys);
        IServerSearchScheme server = mitra ? new MitraServerScheme() : new NaiveServerScheme();
        var scope = new IndexScope(Guid.NewGuid(), client.SchemeId, Guid.NewGuid(), 1);
        var store = new TestIndex(scope);
        var state = await client.InitializeAsync(scope, keys);
        var documents = new Dictionary<Guid, TrustedDocument>();
        string[] words = ["alpha", "beta", "gamma", "delta", "epsilon", "absent"];
        var random = new Random(seed);
        for (var step = 0; step < 150; step++)
        {
            var kind = documents.Count == 0 ? MutationKind.Add : (MutationKind)random.Next(3);
            var previous = kind == MutationKind.Add ? null : documents.Values.ElementAt(random.Next(documents.Count));
            var next = kind == MutationKind.Delete ? null : new TrustedDocument(
                previous?.DocumentId ?? Guid.NewGuid(), (previous?.Revision ?? 0) + 1,
                Enumerable.Range(0, random.Next(7)).Select(_ => words[random.Next(words.Length - 1)]).ToArray());
            var prepared = await client.PrepareMutationAsync(scope, kind, previous, next, state, keys);
            await server.ApplyMutationAsync(scope, prepared.Message, store);
            state = prepared.PendingState;
            if (previous is not null) documents.Remove(previous.DocumentId);
            if (next is not null) documents[next.DocumentId] = next;
            foreach (var word in words)
            {
                var start = await client.BeginSearchAsync(scope, word, state, keys);
                var response = await server.SearchAsync(new(1, Guid.NewGuid(), scope, step, 0, start.NextMessage!), store);
                var finish = await client.ContinueSearchAsync(scope, response, start.PendingState, keys);
                var expected = documents.Values.Where(d => d.Keywords.Contains(word)).Select(d => d.DocumentId).ToHashSet();
                Assert.True(expected.SetEquals(finish.CompletedDocumentIds!), $"seed={seed}, step={step}, query={word}");
                var matches = Wire.Decode<SchemeState>(finish.PendingState.Payload).Matches;
                Assert.All(matches.Values, m => Assert.Equal(documents[m.DocumentId].Revision, m.Revision));
            }
        }
        foreach (var doc in documents.Values)
        {
            var prepared = await client.PrepareMutationAsync(scope, MutationKind.Delete, doc, null, state, keys);
            await server.ApplyMutationAsync(scope, prepared.Message, store);
            state = prepared.PendingState;
        }
        if (mitra) Assert.NotEmpty(store.Rows); // Deletions append history, never erase it.
        else Assert.Empty(store.Rows);
    }

    [Fact]
    public async Task NaiveRejectsTamperedIndexValue()
    {
        using var keys = new TestKeys();
        var client = new NaiveClientScheme(keys);
        var scope = new IndexScope(Guid.NewGuid(), client.SchemeId, Guid.NewGuid(), 1);
        var state = await client.InitializeAsync(scope, keys);
        var mutation = await client.PrepareMutationAsync(scope, MutationKind.Add, null, new(Guid.NewGuid(), 1, ["alpha"]), state, keys);
        var entry = Wire.Read<NaiveIndexMutation>(mutation.Message, "naive.mutate").PutEntries[0];
        var envelope = Wire.Decode<EncryptedEnvelope>(entry.Value);
        envelope.Tag[0] ^= 1;
        var response = new SearchResponse(Guid.NewGuid(), 0, 0, true,
            Wire.Message("naive.results", new NaiveSearchResult([entry with { Value = Wire.Encode(envelope) }])));
        var pending = await client.BeginSearchAsync(scope, "alpha", state, keys);
        await Assert.ThrowsAsync<CryptographicException>(async () => await client.ContinueSearchAsync(scope, response, pending.PendingState, keys));
    }

    [Fact]
    public async Task NaiveRejectsValidEncryptedEntryFromAnotherQuery()
    {
        using var keys = new TestKeys();
        var client = new NaiveClientScheme(keys);
        var scope = new IndexScope(Guid.NewGuid(), client.SchemeId, Guid.NewGuid(), 1);
        var state = await client.InitializeAsync(scope, keys);
        var mutation = await client.PrepareMutationAsync(scope, MutationKind.Add, null, new(Guid.NewGuid(), 1, ["alpha"]), state, keys);
        var entry = Wire.Read<NaiveIndexMutation>(mutation.Message, "naive.mutate").PutEntries[0];
        var pending = await client.BeginSearchAsync(scope, "beta", state, keys);
        var response = new SearchResponse(Guid.NewGuid(), 0, 0, true, Wire.Message("naive.results", new NaiveSearchResult([entry])));
        await Assert.ThrowsAsync<CryptographicException>(async () => await client.ContinueSearchAsync(scope, response, pending.PendingState, keys));
    }
}

internal sealed class TestKeys : IClientKeyProvider, INonceSource, IDisposable
{
    private readonly byte[] master = RandomNumberGenerator.GetBytes(32);
    public ValueTask<byte[]> DeriveKeyAsync(IndexScope scope, string purpose, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(KeyDerivation.Derive(master, scope, purpose));
    public byte[] Reserve(IndexScope scope, string purpose) => RandomNumberGenerator.GetBytes(12);
    public void Dispose() => CryptographicOperations.ZeroMemory(master);
}

internal sealed class TestIndex(IndexScope bound) : IIndexStore
{
    public Dictionary<string, IndexEntry> Rows { get; } = [];
    private void Check(IndexScope scope) { if (scope != bound) throw new ArgumentException("Scope mismatch."); }
    public ValueTask<IReadOnlyList<IndexEntry>> GetAsync(IndexScope scope, IReadOnlyList<byte[]> addresses, CancellationToken cancellationToken = default)
    {
        Check(scope);
        return ValueTask.FromResult<IReadOnlyList<IndexEntry>>(addresses.Select(a => Rows.GetValueOrDefault(Convert.ToHexString(a)))
            .OfType<IndexEntry>().Select(e => new IndexEntry(e.Address.ToArray(), e.Value.ToArray())).ToArray());
    }
    public ValueTask<IReadOnlyList<IndexEntry>> FindByPrefixAsync(IndexScope scope, byte[] prefix, CancellationToken cancellationToken = default)
    {
        Check(scope);
        return ValueTask.FromResult<IReadOnlyList<IndexEntry>>(Rows.Values.Where(e => e.Address.AsSpan().StartsWith(prefix)).ToArray());
    }
    public ValueTask PutAsync(IndexScope scope, IReadOnlyList<IndexEntry> entries, CancellationToken cancellationToken = default)
    {
        Check(scope);
        foreach (var entry in entries) Rows[Convert.ToHexString(entry.Address)] = new(entry.Address.ToArray(), entry.Value.ToArray());
        return ValueTask.CompletedTask;
    }
    public ValueTask DeleteAsync(IndexScope scope, IReadOnlyList<byte[]> addresses, CancellationToken cancellationToken = default)
    {
        Check(scope);
        foreach (var address in addresses) Rows.Remove(Convert.ToHexString(address));
        return ValueTask.CompletedTask;
    }
}
