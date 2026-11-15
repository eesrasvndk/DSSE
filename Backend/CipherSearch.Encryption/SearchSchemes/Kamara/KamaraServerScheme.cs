using System.Security.Cryptography;
using CipherSearch.Contracts;
using static CipherSearch.SearchSchemes.Kamara.KamaraEncoding;

namespace CipherSearch.SearchSchemes.Kamara;

/// <summary>
/// Untrusted KPR server: no keys, keywords, client state or plaintext posting lists.
/// All list relations are decoded from authorized nodes or changed by XOR deltas.
/// The host MUST serialize a generation and atomically commit its IIndexStore
/// transaction. The overlay also prevents algorithm/capacity/cancellation failures
/// from writing any partial Delete+Add. A storage failure during Flush still needs
/// host rollback. Replay protection belongs to the host's OperationId receipt.
/// </summary>
public sealed class KamaraServerScheme : IServerSearchScheme
{
    public string SchemeId => SchemeIds.Kamara;

    public async ValueTask<ProtocolMessage> ApplyMutationAsync(IndexScope scope, ProtocolMessage mutation,
        IIndexStore store, CancellationToken cancellationToken = default)
    {
        Scope(scope);
        var tx = new Overlay(scope, store, cancellationToken);
        if (mutation.Kind == "kamara.setup")
            await Setup(tx, Wire.Read<KamaraSetup>(mutation, "kamara.setup"));
        else
        {
            await tx.Initialize();
            var change = Wire.Read<KamaraMutation>(mutation, "kamara.mutate");
            if (change.Delete is null && change.Add is null) throw new ArgumentException("Empty mutation.");
            if (change.Delete is not null) await Delete(tx, change.Delete);
            if (change.Add is not null) await Add(tx, change.Add);
        }
        await tx.Flush();
        return Wire.Message("kamara.ack", true);
    }

    private static async Task Setup(Overlay tx, KamaraSetup setup)
    {
        Capacity(setup.Capacity);
        var digest = SHA256.HashData(Wire.Encode(setup));
        var prior = await tx.Get(Metadata);
        if (prior is not null)
        {
            Length(prior, 36);
            if (Read(prior) != setup.Capacity || !CryptographicOperations.FixedTimeEquals(prior.AsSpan(4), digest))
                throw new InvalidOperationException("Cannot replace a live Kamara generation.");
            return; // Exact setup replay is safe even after later mutations.
        }
        tx.Limit = setup.Capacity;
        var seen = new HashSet<string>();
        var sCount = 0; var dCount = 0; var freeFound = false;
        foreach (var entry in setup.Entries)
        {
            var a = entry.Address;
            if (!seen.Add(Convert.ToHexString(a)) || a.Length < 2 || a[0] != 0x4b)
                throw new ArgumentException("Invalid/duplicate setup address.");
            if (a.SequenceEqual(Free)) { Length(entry.Value, 8); freeFound = true; }
            else if (a[1] is As or Ad)
            {
                Length(a, 6); tx.Pointer(Read(a, 2), false);
                Length(entry.Value, a[1] == As ? SearchSize : DeletionSize);
                if (a[1] == As) sCount++; else dCount++;
            }
            else if (a[1] is Ts or Td)
            {
                Length(a, 34); Length(entry.Value, a[1] == Ts ? 8 : 4);
            }
            else throw new ArgumentException("Invalid setup structure.");
            tx.Put(a, entry.Value);
        }
        if (!freeFound || sCount != setup.Capacity || dCount != setup.Capacity)
            throw new ArgumentException("Incomplete padded arrays.");
        var head = await tx.Required(Free, 8);
        if (Read(head, 4) != 0) throw new ArgumentException("Invalid free head.");
        var p = Read(head); var visited = new HashSet<int>(); var duals = new HashSet<int>();
        while (p != 0)
        {
            tx.Pointer(p, false);
            if (!visited.Add(p)) throw new ArgumentException("Free-list cycle.");
            var cell = await tx.Required(Address(As, p), SearchSize);
            var d = Read(cell, 20); tx.Pointer(d, false);
            if (!duals.Add(d)) throw new ArgumentException("Repeated free dual.");
            p = Read(cell, 16);
        }
        tx.Put(Metadata, [.. Ints(setup.Capacity), .. digest]);
    }

    private static async Task Add(Overlay tx, KamaraAddToken token)
    {
        Length(token.F, 32); Length(token.G, 4);
        var table = Address(Td, token.F);
        // Figure 2 Add.1 says "not in Td"; that would reject every new file.
        // Correct duplicate guard: reject iff already in Td.
        if (await tx.Get(table) is not null) throw new InvalidOperationException("Document already indexed.");
        if (token.Words is null || token.Words.Length > tx.Limit) throw new ArgumentException("Invalid add token.");
        var seenWords = new HashSet<string>();
        foreach (var word in token.Words)
        {
            Length(word.F, 32); Length(word.G, 8);
            Length(word.SearchNode, SearchSize); Length(word.DeletionNode, DeletionSize);
            if (!seenWords.Add(Convert.ToHexString(word.F))) throw new ArgumentException("Duplicate keyword token.");
        }
        // Reserve paired cells by traversing only the necessary prefix of Lfree.
        var pairs = new (int S, int D)[token.Words.Length];
        var free = Read(await tx.Required(Free, 8));
        var usedS = new HashSet<int>(); var usedD = new HashSet<int>();
        for (var i = 0; i < pairs.Length; i++)
        {
            if (free == 0) throw new KamaraCapacityException();
            tx.Pointer(free, false);
            var cell = await tx.Required(Address(As, free), SearchSize);
            var dual = Read(cell, 20); tx.Pointer(dual, false);
            if (!usedS.Add(free) || !usedD.Add(dual)) throw new InvalidOperationException("Corrupt free list.");
            pairs[i] = (free, dual); free = Read(cell, 16); tx.Pointer(free);
        }
        tx.Put(Free, Ints(free, 0));
        for (var i = 0; i < token.Words.Length; i++)
        {
            var word = token.Words[i]; var (s, d) = pairs[i];
            var address = Address(Ts, word.F);
            var old = await tx.Get(address);
            var head = old is null ? new byte[8] : Xor(old, word.G);
            var s1 = Read(head); var d1 = Read(head, 4);
            tx.Pointer(s1); tx.Pointer(d1);
            if ((s1 == 0) != (d1 == 0)) throw new InvalidOperationException("Invalid list head.");
            var node = word.SearchNode.ToArray(); Patch(node, 16, s1);
            tx.Put(Address(As, s), node); // Add.2(d)
            tx.Put(address, Xor(Ints(s, d), word.G)); // Add.2(e)
            if (d1 != 0)
            {
                var oldDual = await tx.Required(Address(Ad, d1), DeletionSize);
                Patch(oldDual, 4, d); Patch(oldDual, 16, s); // Add.2(f)
                tx.Put(Address(Ad, d1), oldDual);
            }
            var newDual = word.DeletionNode.ToArray();
            // Enc defines a forward Lf and Td points to its first node. Add.2(g,h)
            // mix predecessor/first conventions. Link to the NEXT allocated dual
            // and keep Td at the first, preserving Enc and keyword appearance order.
            Patch(newDual, 0, i + 1 < pairs.Length ? pairs[i + 1].D : 0);
            Patch(newDual, 8, d1); Patch(newDual, 12, s); Patch(newDual, 20, s1);
            // AddToken already masks F(w) in field 7: XORing it a second time as
            // printed in Add.2(g) would erase mu and make deletion-head repair impossible.
            tx.Put(Address(Ad, d), newDual);
        }
        tx.Put(table, Xor(Ints(pairs.Length == 0 ? 0 : pairs[0].D), token.G));
    }

    private static async Task Delete(Overlay tx, KamaraDeleteToken token)
    {
        Length(token.F, 32); Length(token.G, 4); Length(token.P, 32);
        if (token.DocumentId == Guid.Empty) throw new ArgumentException("Invalid deletion identity.");
        var table = Address(Td, token.F);
        var head = await tx.Get(table) ?? throw new InvalidOperationException("Document not indexed.");
        var current = Read(Xor(head, token.G));
        var visited = new HashSet<int>();
        while (current != 0)
        {
            tx.Pointer(current, false);
            if (!visited.Add(current)) throw new InvalidOperationException("Deletion-list cycle.");
            var plain = Open(await tx.Required(Address(Ad, current), DeletionSize), token.P, true);
            var nextFile = Read(plain); var prevDual = Read(plain, 4); var nextDual = Read(plain, 8);
            var self = Read(plain, 12); var prev = Read(plain, 16); var next = Read(plain, 20);
            foreach (var p in new[] { nextFile, prevDual, nextDual, prev, next }) tx.Pointer(p);
            tx.Pointer(self, false);
            if ((prev == 0) != (prevDual == 0) || (next == 0) != (nextDual == 0))
                throw new InvalidOperationException("Inconsistent dual pointers.");
            if (prev != 0)
            {
                var previous = await tx.Required(Address(As, prev), SearchSize);
                Patch(previous, 16, self ^ next); tx.Put(Address(As, prev), previous);
                var dual = await tx.Required(Address(Ad, prevDual), DeletionSize);
                Patch(dual, 8, current ^ nextDual); Patch(dual, 20, self ^ next);
                tx.Put(Address(Ad, prevDual), dual); // Del.3(f)
            }
            else
            {
                // Figure 3 omits the boundary case. Ts[mu] encrypts (self,current).
                // XOR old/new heads repairs it WITHOUT revealing G(w) or P(w).
                var address = Address(Ts, plain[24..56]);
                var entry = await tx.Required(address, 8);
                if (next == 0) tx.Remove(address);
                else { Patch(entry, 0, self ^ next); Patch(entry, 4, current ^ nextDual); tx.Put(address, entry); }
            }
            if (next != 0)
            {
                var dual = await tx.Required(Address(Ad, nextDual), DeletionSize);
                Patch(dual, 4, current ^ prevDual); Patch(dual, 16, self ^ prev);
                tx.Put(Address(Ad, nextDual), dual); // Del.3(g)
            }
            var free = Read(await tx.Required(Free, 8)); tx.Pointer(free);
            var released = RandomNumberGenerator.GetBytes(SearchSize);
            released.AsSpan(0, 16).Clear(); Write(released, 16, free); Write(released, 20, current);
            tx.Put(Address(As, self), released);
            tx.Put(Address(Ad, current), RandomNumberGenerator.GetBytes(DeletionSize));
            tx.Put(Free, Ints(self, 0)); // Del.3(b-e): return BOTH cells through Lfree.
            current = nextFile;
        }
        tx.Remove(table);
        // Ciphertext removal (Del.4) is performed by the existing document host.
    }

    public async ValueTask<SearchResponse> SearchAsync(SearchRequest request, IIndexStore store,
        CancellationToken cancellationToken = default)
    {
        Scope(request.Scope);
        if (request.Version != 1 || request.Round != 0) throw new ArgumentException("Invalid search request.");
        var token = Wire.Read<KamaraSearchToken>(request.Message, "kamara.search");
        Length(token.F, 32); Length(token.G, 8); Length(token.P, 32);
        var tx = new Overlay(request.Scope, store, cancellationToken);
        await tx.Initialize();
        var value = await tx.Get(Address(Ts, token.F));
        var ids = new List<Guid>();
        if (value is not null)
        {
            var p = Read(Xor(value, token.G));
            var visited = new HashSet<int>();
            while (p != 0)
            {
                tx.Pointer(p, false);
                if (!visited.Add(p)) throw new InvalidOperationException("Search-list cycle.");
                var plain = Open(await tx.Required(Address(As, p), SearchSize), token.P, false);
                ids.Add(new Guid(plain.AsSpan(0, 16))); p = Read(plain, 16);
            }
        }
        return new(request.SearchId, request.ExpectedEpoch, 0, true, Wire.Message("kamara.results", new KamaraResults(ids.ToArray())));
    }

    private sealed class Overlay(IndexScope scope, IIndexStore store, CancellationToken ct)
    {
        private readonly Dictionary<string, IndexEntry?> changes = [];
        internal int Limit { get; set; }
        internal async Task Initialize()
        {
            var meta = await Required(Metadata, 36); Limit = Read(meta); Capacity(Limit);
        }
        internal void Pointer(int p, bool allowEnd = true)
        {
            if (p < (allowEnd ? 0 : 1) || p > Limit) throw new InvalidOperationException("Pointer outside Kamara array.");
        }
        internal async Task<byte[]?> Get(byte[] address)
        {
            ct.ThrowIfCancellationRequested();
            if (changes.TryGetValue(Convert.ToHexString(address), out var value)) return value?.Value.ToArray();
            var entries = await store.GetAsync(scope, [address], ct);
            return entries.SingleOrDefault()?.Value.ToArray();
        }
        internal async Task<byte[]> Required(byte[] address, int size)
        {
            var bytes = await Get(address) ?? throw new InvalidOperationException("Missing Kamara cell/setup.");
            Length(bytes, size); return bytes;
        }
        internal void Put(byte[] address, byte[] value) => changes[Convert.ToHexString(address)] = new(address.ToArray(), value.ToArray());
        internal void Remove(byte[] address) => changes[Convert.ToHexString(address)] = null;
        internal async Task Flush()
        {
            ct.ThrowIfCancellationRequested();
            var puts = changes.Values.OfType<IndexEntry>().ToArray();
            var deletes = changes.Where(p => p.Value is null).Select(p => Convert.FromHexString(p.Key)).ToArray();
            if (puts.Length != 0) await store.PutAsync(scope, puts, ct);
            if (deletes.Length != 0) await store.DeleteAsync(scope, deletes, ct);
        }
    }
}
