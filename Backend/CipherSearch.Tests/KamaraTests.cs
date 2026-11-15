using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CipherSearch.Contracts;
using CipherSearch.Cryptography;
using CipherSearch.SearchSchemes.Kamara;

namespace CipherSearch.Tests;

public sealed class KamaraTests
{
    private static TrustedDocument Doc(int id, params string[] words) => new(new Guid(id, 0, 0, new byte[8]), 1, words);

    [Fact]
    public async Task CiphertextSizedSetupUsesPaperByteBoundAndRejectsMismatchedFiles()
    {
        using var keys = new TestKeys();
        var client = new KamaraClientScheme();
        var scope = new IndexScope(Guid.NewGuid(), SchemeIds.Kamara, Guid.NewGuid(), 1);
        var doc = Doc(1, "alpha");
        var ciphertext = new EncryptedDocument(doc.DocumentId, 1, new(1, 1, new byte[12], new byte[64], new byte[16]));
        var setup = await client.PrepareSetupAsync(scope, [doc], [ciphertext], 4, keys);
        Assert.Equal(Wire.Encode(ciphertext).Length + 4, Wire.Read<KamaraSetup>(setup.Message, "kamara.setup").Capacity);
        await Assert.ThrowsAsync<ArgumentException>(async () => await client.PrepareSetupAsync(scope, [doc],
            [ciphertext with { DocumentId = Guid.NewGuid() }], 4, keys));
    }

    [Fact]
    public async Task SetupBuildsPaddedDualListsAndSearchesThePaperExample()
    {
        using var h = new Harness();
        await h.Setup([Doc(1, "w1"), Doc(2, "w1", "w2", "w3"), Doc(3, "w1", "w3")], 32, 5);
        await h.Verify();
        Assert.Equal(3, (await h.Search("w1")).Length);
        Assert.Equal(new[] { Doc(2).DocumentId }, await h.Search("w2"));
        Assert.Empty(await h.Search("absent"));
        Assert.Equal(32, h.Store.Rows.Values.Count(e => e.Address[1] == 1));
        Assert.Equal(32, h.Store.Rows.Values.Count(e => e.Address[1] == 2));
        Assert.Equal(5, h.FreePairs().Count);
        Assert.Equal(21, h.Padding.Count / 2); // 32 - six live pairs - five free pairs.
        var before = h.Snapshot();
        await h.Server.ApplyMutationAsync(h.Scope, h.SetupMessage!, h.Store);
        Assert.Equal(before, h.Snapshot());
        var other = await h.Client.PrepareSetupAsync(h.Scope, [], 32, 32, h.Keys);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await h.Server.ApplyMutationAsync(h.Scope, other.Message, h.Store));
        Assert.Equal(before, h.Snapshot());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task DeletesFirstMiddleAndLastNodesAndReusesReleasedDuals(int removed)
    {
        using var h = new Harness();
        await h.Setup([Doc(1, "shared", "one"), Doc(2, "shared", "two"), Doc(3, "shared", "three")], 12, 0);
        await h.Verify();
        await h.Mutate(MutationKind.Delete, h.Documents[Doc(removed).DocumentId], null);
        var released = h.FreePairs();
        Assert.Equal(2, released.Count);
        await h.Verify();
        await h.Mutate(MutationKind.Add, null, Doc(4, "shared", "new"));
        Assert.Empty(h.FreePairs());
        await h.Verify(); // With z=0 all inserted cells must be the released cells.
        foreach (var document in h.Documents.Values.ToArray())
            await h.Mutate(MutationKind.Delete, document, null);
        await h.Verify();
        Assert.Empty(await h.Search("shared"));
        Assert.DoesNotContain(h.Store.Rows.Values, e => e.Address[1] == 3 && e.Address.Length == 34);
        Assert.DoesNotContain(h.Store.Rows.Values, e => e.Address[1] == 4);
    }

    [Fact]
    public async Task EmptyDocumentsAndDuplicateWordsDoNotAllocateExtraNodes()
    {
        using var h = new Harness();
        await h.Setup([], 8, 8);
        await h.Mutate(MutationKind.Add, null, Doc(1));
        Assert.Equal(8, h.FreePairs().Count);
        await h.Mutate(MutationKind.Add, null, Doc(2, "a", "a", "b", "a"));
        Assert.Equal(6, h.FreePairs().Count);
        await h.Verify();
        await h.Mutate(MutationKind.Delete, h.Documents[Doc(1).DocumentId], null);
        await h.Mutate(MutationKind.Delete, h.Documents[Doc(2).DocumentId], null);
        Assert.Equal(8, h.FreePairs().Count);
        await h.Verify();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(17)]
    [InlineData(42)]
    public async Task MixedOperationsMatchPlaintextOracleAndEveryPointerInvariant(int seed)
    {
        using var h = new Harness();
        await h.Setup([], 256, 256);
        var rng = new Random(seed); var nextId = 1;
        string[] words = ["alpha", "beta", "gamma", "delta", "epsilon"];
        for (var step = 0; step < 120; step++)
        {
            var kind = h.Documents.Count == 0 ? MutationKind.Add : (MutationKind)rng.Next(3);
            var old = kind == MutationKind.Add ? null : h.Documents.Values.ElementAt(rng.Next(h.Documents.Count));
            var replacement = kind == MutationKind.Delete ? null : new TrustedDocument(old?.DocumentId ?? Doc(nextId++).DocumentId,
                (old?.Revision ?? 0) + 1, Enumerable.Range(0, rng.Next(7)).Select(_ => words[rng.Next(words.Length)]).ToArray());
            await h.Mutate(kind, old, replacement);
            await h.Verify();
            foreach (var word in words.Append("absent"))
                Assert.True(h.Documents.Values.Where(d => d.Keywords.Contains(word)).Select(d => d.DocumentId).ToHashSet()
                    .SetEquals(await h.Search(word)), $"seed={seed}, step={step}, word={word}");
        }
    }

    [Fact]
    public async Task ExhaustionAndFailureBetweenDeleteAndAddLeaveOriginalIndexIntact()
    {
        using var h = new Harness();
        await h.Setup([Doc(1, "old")], 2, 0);
        var old = h.Documents.Values.Single();
        var before = h.Snapshot();
        var tooLarge = old with { Revision = 2, Keywords = ["new", "other"] };
        var update = await h.Client.PrepareMutationAsync(h.Scope, MutationKind.Update, old, tooLarge, h.State!, h.Keys);
        await Assert.ThrowsAsync<KamaraCapacityException>(async () => await h.Server.ApplyMutationAsync(h.Scope, update.Message, h.Store));
        Assert.Equal(before, h.Snapshot());
        Assert.Equal(new[] { old.DocumentId }, await h.Search("old"));
        Assert.Empty(await h.Search("new"));
        // Failure after Delete has executed in the overlay, before Add can run.
        var parsed = Wire.Read<KamaraMutation>(update.Message, "kamara.mutate");
        parsed.Add!.Words[0].G[0] ^= 1;
        var malformed = parsed with { Add = parsed.Add with { G = [] } };
        await Assert.ThrowsAsync<ArgumentException>(async () => await h.Server.ApplyMutationAsync(h.Scope,
            Wire.Message("kamara.mutate", malformed), h.Store));
        Assert.Equal(before, h.Snapshot());
        await h.Mutate(MutationKind.Update, old, old with { Revision = 2, Keywords = ["new"] });
        Assert.Empty(await h.Search("old"));
        Assert.Single(await h.Search("new"));
        await h.Verify();
    }

    [Fact]
    public async Task TokensAreSeparatedDeterministicWhereRequiredAndFreshlyMaskedOnAdd()
    {
        using var h = new Harness();
        await h.Setup([], 8, 8);
        var d = Doc(1, "secret-word");
        var add1 = await h.Client.PrepareMutationAsync(h.Scope, MutationKind.Add, null, d, h.State!, h.Keys);
        var add2 = await h.Client.PrepareMutationAsync(h.Scope, MutationKind.Add, null, d, h.State!, h.Keys);
        var a = Wire.Read<KamaraMutation>(add1.Message, "kamara.mutate").Add!;
        var b = Wire.Read<KamaraMutation>(add2.Message, "kamara.mutate").Add!;
        Assert.Equal(a.F, b.F); Assert.Equal(a.G, b.G);
        Assert.NotEqual(a.Words[0].SearchNode, b.Words[0].SearchNode);
        Assert.NotEqual(a.Words[0].DeletionNode, b.Words[0].DeletionNode);
        var q = await h.Token("secret-word");
        Assert.Equal(q.F, (await h.Token("secret-word")).F);
        Assert.NotEqual(q.F, q.P); Assert.NotEqual(q.F, a.F);
        Assert.Equal(d.DocumentId, new Guid(Open(a.Words[0].SearchNode, q.P, false).AsSpan(0, 16)));
        await h.Mutate(MutationKind.Add, null, d);
        var del = Wire.Read<KamaraMutation>((await h.Client.PrepareMutationAsync(h.Scope, MutationKind.Delete, d, null, h.State!, h.Keys)).Message, "kamara.mutate").Delete!;
        Assert.Equal(q.F, Open(a.Words[0].DeletionNode, del.P, true)[24..]);
        var encoded = Encoding.UTF8.GetString(Wire.Encode(a));
        Assert.DoesNotContain("secret-word", encoded);
        foreach (var purpose in new[] { KeyPurposes.Document, KeyPurposes.IndexValue, KeyPurposes.SearchToken, KeyPurposes.ClientState })
        {
            var key = await h.Keys.DeriveKeyAsync(h.Scope, purpose);
            Assert.DoesNotContain(Convert.ToBase64String(key), encoded);
            Assert.All(h.Store.Rows.Values, e => Assert.False(e.Value.AsSpan().IndexOf(key) >= 0));
        }
        Assert.Empty(typeof(KamaraServerScheme).GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic));
        var another = h.Scope with { GenerationId = Guid.NewGuid() };
        var state = await h.Client.InitializeAsync(another, h.Keys);
        var different = Wire.Read<KamaraSearchToken>((await h.Client.BeginSearchAsync(another, "secret-word", state, h.Keys)).NextMessage!, "kamara.search");
        Assert.NotEqual(q.F, different.F); Assert.NotEqual(q.G, different.G); Assert.NotEqual(q.P, different.P);
        await Assert.ThrowsAsync<ArgumentException>(async () => await h.Client.BeginSearchAsync(another, "secret-word", h.State!, h.Keys));
    }

    [Fact]
    public async Task DuplicateMissingCancelledAndMalformedOperationsDoNotWrite()
    {
        using var h = new Harness();
        await h.Setup([], 8, 8);
        var add = await h.Mutate(MutationKind.Add, null, Doc(1, "x"));
        var before = h.Snapshot();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await h.Server.ApplyMutationAsync(h.Scope, add.Message, h.Store));
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await h.Server.ApplyMutationAsync(h.Scope, add.Message, h.Store, cancel.Token));
        Assert.Equal(before, h.Snapshot());
        var del = await h.Mutate(MutationKind.Delete, h.Documents.Values.Single(), null);
        before = h.Snapshot();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await h.Server.ApplyMutationAsync(h.Scope, del.Message, h.Store));
        Assert.Equal(before, h.Snapshot());
        var wrong = new KamaraSearchToken([], new byte[8], new byte[32]);
        await Assert.ThrowsAsync<ArgumentException>(async () => await h.Server.SearchAsync(new(1, Guid.NewGuid(), h.Scope, 0, 0,
            Wire.Message("kamara.search", wrong)), h.Store));
    }

    [Fact]
    public async Task RepeatedDeleteReaddDoesNotRetainPointersIntoRecycledLists()
    {
        using var h = new Harness();
        await h.Setup([], 4, 4);
        for (var i = 1; i <= 60; i++)
        {
            await h.Mutate(MutationKind.Add, null, Doc(i, "shared", "other"));
            await h.Verify();
            await h.Mutate(MutationKind.Delete, h.Documents.Values.Single(), null);
            await h.Verify();
            Assert.Equal(4, h.FreePairs().Count);
        }
    }

    // Independent binary inspection of gamma, not production traversal helpers.
    private static int Int(byte[] bytes, int offset = 0) => BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset, 4));
    private static byte[] Address(byte type, int index)
    {
        var a = new byte[6]; a[0] = 0x4b; a[1] = type;
        BinaryPrimitives.WriteInt32LittleEndian(a.AsSpan(2), index); return a;
    }
    private static byte[] Address(byte type, byte[] token) => [0x4b, type, .. token];
    private static byte[] Unmask(byte[] bytes, byte[] mask) => bytes.Zip(mask, (a, b) => (byte)(a ^ b)).ToArray();
    private static byte[] Open(byte[] bytes, byte[] key, bool deletion)
    {
        var length = deletion ? 56 : 20;
        Assert.Equal(length + 32, bytes.Length);
        var mask = new byte[length];
        HKDF.Expand(HashAlgorithmName.SHA256, key, mask,
            [.. Encoding.ASCII.GetBytes(deletion ? "KPR/H2" : "KPR/H1"), 0, .. bytes[length..]]);
        return Unmask(bytes[..length], mask);
    }

    private sealed class Harness : IDisposable
    {
        internal readonly TestKeys Keys = new();
        internal readonly KamaraClientScheme Client = new();
        internal readonly KamaraServerScheme Server = new();
        internal readonly IndexScope Scope = new(Guid.NewGuid(), SchemeIds.Kamara, Guid.NewGuid(), 1);
        internal readonly TestIndex Store;
        internal ClientState? State;
        internal ProtocolMessage? SetupMessage;
        internal readonly Dictionary<Guid, TrustedDocument> Documents = [];
        internal readonly Dictionary<string, byte[]> Padding = [];
        private int capacity, allocated;
        internal Harness() => Store = new(Scope);
        internal async Task Setup(TrustedDocument[] docs, int size, int free)
        {
            capacity = size; allocated = free + docs.Sum(d => d.Keywords.Distinct().Count());
            var setup = await Client.PrepareSetupAsync(Scope, docs, size, free, Keys);
            SetupMessage = setup.Message;
            await Server.ApplyMutationAsync(Scope, setup.Message, Store);
            State = setup.PendingState;
            foreach (var d in docs) Documents.Add(d.DocumentId, d);
            var live = await LiveNodes(); var available = FreePairs();
            var s = live.Values.Select(n => Int(n.Plain, 12)).Concat(available.Select(p => p.S)).ToHashSet();
            var ad = live.Keys.Concat(available.Select(p => p.D)).ToHashSet();
            foreach (var e in Store.Rows.Values.Where(e => e.Address[1] is 1 or 2))
                if (!(e.Address[1] == 1 ? s : ad).Contains(Int(e.Address, 2))) Padding.Add(Convert.ToHexString(e.Address), e.Value.ToArray());
        }
        internal byte[] Get(byte[] a) => Store.Rows[Convert.ToHexString(a)].Value;
        internal string Snapshot() => Convert.ToBase64String(Wire.Encode(Store.Rows.OrderBy(p => p.Key).ToArray()));
        internal async Task<PreparedMutation> Mutate(MutationKind kind, TrustedDocument? old, TrustedDocument? replacement)
        {
            var prepared = await Client.PrepareMutationAsync(Scope, kind, old, replacement, State!, Keys);
            await Server.ApplyMutationAsync(Scope, prepared.Message, Store); State = prepared.PendingState;
            if (old is not null) Documents.Remove(old.DocumentId);
            if (replacement is not null) Documents.Add(replacement.DocumentId, replacement);
            return prepared;
        }
        internal async Task<KamaraSearchToken> Token(string word) => Wire.Read<KamaraSearchToken>(
            (await Client.BeginSearchAsync(Scope, word, State!, Keys)).NextMessage!, "kamara.search");
        internal async Task<Guid[]> Search(string word)
        {
            var started = await Client.BeginSearchAsync(Scope, word, State!, Keys);
            var response = await Server.SearchAsync(new(1, Guid.NewGuid(), Scope, 0, 0, started.NextMessage!), Store);
            var done = await Client.ContinueSearchAsync(Scope, response, started.PendingState, Keys);
            Assert.All(Wire.Decode<SchemeState>(done.PendingState.Payload).Matches.Values,
                m => Assert.Equal(Documents[m.DocumentId].Revision, m.Revision));
            return done.CompletedDocumentIds!.ToArray();
        }
        internal List<(int S, int D)> FreePairs()
        {
            var result = new List<(int S, int D)>(); var p = Int(Get([0x4b, 3, 0x66, 0x72, 0x65, 0x65]));
            while (p != 0)
            {
                Assert.InRange(p, 1, capacity); Assert.DoesNotContain(result, pair => pair.S == p);
                var cell = Get(Address(1, p)); var d = Int(cell, 20);
                Assert.InRange(d, 1, capacity); Assert.DoesNotContain(result, pair => pair.D == d);
                result.Add((p, d)); p = Int(cell, 16);
            }
            return result;
        }
        private async Task<Dictionary<int, (TrustedDocument File, string Word, byte[] Plain)>> LiveNodes()
        {
            var nodes = new Dictionary<int, (TrustedDocument, string, byte[])>();
            foreach (var file in Documents.Values)
            {
                var prepared = await Client.PrepareMutationAsync(Scope, MutationKind.Delete, file, null, State!, Keys);
                var token = Wire.Read<KamaraMutation>(prepared.Message, "kamara.mutate").Delete!;
                var p = Int(Unmask(Get(Address(4, token.F)), token.G));
                foreach (var word in file.Keywords.Distinct())
                {
                    Assert.InRange(p, 1, capacity); Assert.False(nodes.ContainsKey(p));
                    var plain = Open(Get(Address(2, p)), token.P, true);
                    nodes.Add(p, (file, word, plain)); p = Int(plain);
                }
                Assert.Equal(0, p);
            }
            return nodes;
        }
        internal async Task Verify()
        {
            var live = await LiveNodes(); var free = FreePairs();
            Assert.Equal(allocated, live.Count + free.Count);
            Assert.Equal(live.Count, live.Values.Select(n => Int(n.Plain, 12)).Distinct().Count());
            Assert.Equal(live.Count + free.Count, live.Keys.Concat(free.Select(p => p.D)).Distinct().Count());
            Assert.Equal(live.Count + free.Count, live.Values.Select(n => Int(n.Plain, 12)).Concat(free.Select(p => p.S)).Distinct().Count());
            foreach (var (d, node) in live)
            {
                var p = node.Plain; var q = await Token(node.Word);
                Assert.Equal(q.F, p[24..]);
                var s = Int(p, 12); Assert.InRange(s, 1, capacity);
                var search = Open(Get(Address(1, s)), q.P, false);
                Assert.Equal(node.File.DocumentId, new Guid(search.AsSpan(0, 16)));
                Assert.Equal(Int(p, 20), Int(search, 16));
                foreach (var (dualOffset, searchOffset, backDualOffset, backSearchOffset) in new[] { (4, 16, 8, 20), (8, 20, 4, 16) })
                {
                    var neighbor = Int(p, dualOffset);
                    if (neighbor == 0) Assert.Equal(0, Int(p, searchOffset));
                    else
                    {
                        var other = live[neighbor]; Assert.Equal(node.Word, other.Word);
                        Assert.Equal(Int(other.Plain, 12), Int(p, searchOffset));
                        Assert.Equal(d, Int(other.Plain, backDualOffset)); Assert.Equal(s, Int(other.Plain, backSearchOffset));
                    }
                }
                if (Int(p, 4) == 0)
                {
                    var head = Unmask(Get(Address(3, q.F)), q.G);
                    Assert.Equal(s, Int(head)); Assert.Equal(d, Int(head, 4));
                }
            }
            foreach (var (key, bytes) in Padding) Assert.Equal(bytes, Store.Rows[key].Value);
            foreach (var word in Documents.Values.SelectMany(d => d.Keywords).Distinct())
                Assert.True(Documents.Values.Where(d => d.Keywords.Contains(word)).Select(d => d.DocumentId).ToHashSet().SetEquals(await Search(word)));
        }
        public void Dispose() => Keys.Dispose();
    }
}
