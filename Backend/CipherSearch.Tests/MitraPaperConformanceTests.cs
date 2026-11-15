using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CipherSearch.Contracts;
using CipherSearch.SearchSchemes.Mitra;

namespace CipherSearch.Tests;

// CCS 2018 Algorithms 1–3 conformance checks, NOT a computational security proof.
public sealed class MitraPaperConformanceTests
{
    [Fact]
    public async Task UpdateMatchesIndependentPrfVectorAndKeepsOperationInsideMask()
    {
        using var keys = new FixedKeys();
        var client = new MitraClientScheme();
        var scope = Scope();
        var state = await client.InitializeAsync(scope, keys);
        var doc = new TrustedDocument(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"), 7, ["meeting"]);
        foreach (var deleting in new[] { false, true })
        {
            var prepared = await client.PrepareMutationAsync(scope,
                deleting ? MutationKind.Delete : MutationKind.Add,
                deleting ? doc : null, deleting ? null : doc, state, keys);
            var entry = Assert.Single(Wire.Read<IndexEntry[]>(prepared.Message, "mitra.mutate"));
            var counter = deleting ? 2L : 1L;
            Assert.Equal(ReferencePrf(keys.Key, "meeting", counter, 0), entry.Address);
            var clear = new byte[17];
            doc.DocumentId.ToByteArray().CopyTo(clear, 0);
            clear[16] = deleting ? (byte)0 : (byte)1;
            var mask = ReferencePrf(keys.Key, "meeting", counter, 1);
            Assert.Equal(clear.Select((b, i) => (byte)(b ^ mask[i])).ToArray(), entry.Value);
            Assert.Equal(32, entry.Address.Length);
            Assert.Equal(17, entry.Value.Length);
            state = prepared.PendingState;
        }
    }

    [Fact]
    public async Task OldSearchDoesNotContainLaterUpdateAddresses()
    {
        using var keys = new TestKeys();
        var client = new MitraClientScheme(); var scope = Scope();
        var state = await client.InitializeAsync(scope, keys);
        var doc = new TrustedDocument(Guid.NewGuid(), 1, ["meeting"]);
        var add = await client.PrepareMutationAsync(scope, MutationKind.Add, null, doc, state, keys);
        var old = await client.BeginSearchAsync(scope, "meeting", add.PendingState, keys);
        var delete = await client.PrepareMutationAsync(scope, MutationKind.Delete, doc, null, add.PendingState, keys);
        var oldAddresses = Wire.Read<MitraSearch>(old.NextMessage!, "mitra.search").Addresses;
        var deletion = Assert.Single(Wire.Read<IndexEntry[]>(delete.Message, "mitra.mutate"));
        Assert.DoesNotContain(oldAddresses, a => a.SequenceEqual(deletion.Address));
        var fresh = await client.BeginSearchAsync(scope, "meeting", delete.PendingState, keys);
        var all = Wire.Read<MitraSearch>(fresh.NextMessage!, "mitra.search").Addresses;
        Assert.Equal(2, all.Length); // Updates(w) is intentionally disclosed at the next search.
        Assert.Contains(all, a => a.SequenceEqual(deletion.Address));
    }

    [Fact]
    public async Task DeletedIdentityIsFilteredOnlyAtClientWhileServerReturnsEntireHistory()
    {
        using var keys = new TestKeys();
        var client = new MitraClientScheme(); var server = new MitraServerScheme();
        var scope = Scope(); var store = new TestIndex(scope);
        var state = await client.InitializeAsync(scope, keys);
        var deleted = new TrustedDocument(Guid.NewGuid(), 1, ["meeting"]);
        var live = new TrustedDocument(Guid.NewGuid(), 1, ["meeting"]);
        foreach (var operation in new[] {
            (MutationKind.Add, (TrustedDocument?)null, deleted),
            (MutationKind.Add, (TrustedDocument?)null, live),
            (MutationKind.Delete, (TrustedDocument?)deleted, (TrustedDocument?)null) })
        {
            var p = await client.PrepareMutationAsync(scope, operation.Item1, operation.Item2, operation.Item3, state, keys);
            await server.ApplyMutationAsync(scope, p.Message, store); state = p.PendingState;
        }
        var query = await client.BeginSearchAsync(scope, "meeting", state, keys);
        // Search message carries only addresses; no per-keyword decryption key is supplied.
        using var json = System.Text.Json.JsonDocument.Parse(query.NextMessage!.Payload);
        Assert.Equal("addresses", Assert.Single(json.RootElement.EnumerateObject()).Name);
        var response = await server.SearchAsync(new(1, Guid.NewGuid(), scope, 0, 0, query.NextMessage), store);
        var history = Wire.Read<MitraResults>(response.Message, "mitra.results");
        Assert.Equal(3, history.Entries.Count);
        Assert.Equal(3, store.Rows.Count);
        // A transport may reorder the opaque entries without changing local filtering.
        var reordered = response with { Message = Wire.Message("mitra.results", new MitraResults(history.Entries.Reverse().ToArray())) };
        var finished = await client.ContinueSearchAsync(scope, reordered, query.PendingState, keys);
        Assert.Equal(live.DocumentId, Assert.Single(finished.CompletedDocumentIds!));
    }

    private static IndexScope Scope() => new(Guid.NewGuid(), SchemeIds.Mitra, Guid.NewGuid(), 1);
    private static byte[] ReferencePrf(byte[] key, string word, long counter, byte domain)
    {
        // Independently serialize the documented adaptation of G(w, counter || domain).
        using var stream = new MemoryStream();
        var bytes = Encoding.UTF8.GetBytes(word);
        var length = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        var number = new byte[8]; BinaryPrimitives.WriteInt64BigEndian(number, counter);
        stream.Write(length); stream.Write(bytes); stream.Write(number); stream.WriteByte(domain);
        return HMACSHA256.HashData(key, stream.ToArray());
    }
    private sealed class FixedKeys : IClientKeyProvider, IDisposable
    {
        public byte[] Key { get; } = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        public ValueTask<byte[]> DeriveKeyAsync(IndexScope scope, string purpose, CancellationToken cancellationToken = default) => ValueTask.FromResult(Key.ToArray());
        public void Dispose() => CryptographicOperations.ZeroMemory(Key);
    }
}
