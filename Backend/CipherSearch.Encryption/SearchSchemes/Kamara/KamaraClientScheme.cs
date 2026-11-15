using System.Security.Cryptography;
using CipherSearch.Contracts;
using static CipherSearch.SearchSchemes.Kamara.KamaraEncoding;

namespace CipherSearch.SearchSchemes.Kamara;

/// <summary>Trusted KPR client. File encryption/Dec use the existing AES-GCM document layer.</summary>
public sealed class KamaraClientScheme : IClientSearchScheme
{
    public string SchemeId => SchemeIds.Kamara;
    public async ValueTask<ClientState> InitializeAsync(IndexScope scope, IClientKeyProvider keys, CancellationToken cancellationToken = default)
    {
        using var material = await KamaraKeys.Create(scope, keys, cancellationToken);
        return State(new(scope, []));
    }

    private static ClientState State(KamaraState state) => new(1, Wire.Encode(state));
    private static KamaraState ReadState(IndexScope scope, ClientState state)
    {
        Scope(scope);
        if (state.Version != 1) throw new ArgumentException("Unsupported client state.");
        var parsed = Wire.Decode<KamaraState>(state.Payload);
        if (parsed.Scope != scope) throw new ArgumentException("Client state scope mismatch.");
        return parsed;
    }

    private sealed record Node(TrustedDocument File, string Word, int S, int D);

    /// <summary>Enc.1's literal |c|/8+z allocation, using the wire ciphertext byte length.</summary>
    public ValueTask<PreparedMutation> PrepareSetupAsync(IndexScope scope, IReadOnlyList<TrustedDocument> documents,
        IReadOnlyList<EncryptedDocument> ciphertexts, int initialFreeSlots, IClientKeyProvider keys,
        CancellationToken cancellationToken = default)
    {
        if (documents.Count != ciphertexts.Count || documents.Where((d, i) =>
            d.DocumentId != ciphertexts[i].DocumentId || d.Revision != ciphertexts[i].Revision).Any())
            throw new ArgumentException("Ciphertexts must correspond to the indexed files in order.");
        var bytes = ciphertexts.Sum(c => (long)Wire.Encode(c).Length);
        return PrepareSetupAsync(scope, documents, checked((int)(bytes + initialFreeSlots)), initialFreeSlots, keys, cancellationToken);
    }

    /// <summary>
    /// Enc, Figure 2: construct the complete index on the trusted side. capacity is
    /// a PUBLIC padded bound (the paper uses |c|/8+z); initialFreeSlots is z. A caller
    /// with ciphertext lengths should choose that bound, never infer it from the
    /// number of distinct file/word pairs. Remaining cells stay random. This
    /// explicit setup extension avoids leaking an initial collection as Add tokens.
    /// Publish the snapshot once into a fresh generation and commit PendingState
    /// only after the host's transaction succeeds.
    /// </summary>
    public async ValueTask<PreparedMutation> PrepareSetupAsync(IndexScope scope,
        IReadOnlyList<TrustedDocument> documents, int capacity, int initialFreeSlots,
        IClientKeyProvider keys, CancellationToken cancellationToken = default)
    {
        Capacity(capacity);
        if (initialFreeSlots < 0 || initialFreeSlots > capacity) throw new ArgumentOutOfRangeException(nameof(initialFreeSlots));
        if (documents.Select(d => d.DocumentId).Distinct().Count() != documents.Count)
            throw new ArgumentException("Duplicate document identity.");
        using var material = await KamaraKeys.Create(scope, keys, cancellationToken);
        var searchPositions = Enumerable.Range(1, capacity).ToArray();
        var deletionPositions = Enumerable.Range(1, capacity).ToArray();
        RandomNumberGenerator.Shuffle(searchPositions.AsSpan());
        RandomNumberGenerator.Shuffle(deletionPositions.AsSpan());
        var search = new byte[capacity][];
        var deletion = new byte[capacity][];
        for (var i = 0; i < capacity; i++)
        {
            search[i] = RandomNumberGenerator.GetBytes(SearchSize);
            deletion[i] = RandomNumberGenerator.GetBytes(DeletionSize);
        }
        // These plaintext maps exist only during trusted Enc, never in gamma.
        var wordLists = new Dictionary<string, List<Node>>(StringComparer.Ordinal);
        var fileLists = new List<Node>[documents.Count];
        var used = 0;
        for (var i = 0; i < documents.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var descriptor = File(documents[i]); CryptographicOperations.ZeroMemory(descriptor);
            fileLists[i] = [];
            foreach (var word in documents[i].Keywords.Distinct(StringComparer.Ordinal))
            {
                if (used >= capacity - initialFreeSlots) throw new InvalidOperationException("Padded capacity is too small.");
                var node = new Node(documents[i], word, searchPositions[used], deletionPositions[used]);
                used++;
                fileLists[i].Add(node);
                if (!wordLists.TryGetValue(word, out var list)) wordLists[word] = list = [];
                list.Add(node);
            }
        }
        var entries = new List<IndexEntry>();
        var neighbors = new Dictionary<int, (Node? Prev, Node? Next)>();
        foreach (var (word, list) in wordLists)
        {
            var input = Word(word);
            var p = material.P(input);
            try
            {
                for (var i = 0; i < list.Count; i++)
                {
                    var next = i + 1 < list.Count ? list[i + 1] : null;
                    neighbors[list[i].D] = (i == 0 ? null : list[i - 1], next);
                    search[list[i].S - 1] = Seal([.. list[i].File.DocumentId.ToByteArray(), .. Ints(next?.S ?? 0)], p, false);
                }
                entries.Add(new(Address(Ts, material.F(input)), Xor(Ints(list[0].S, list[0].D), material.G(input, 8))));
            }
            finally { CryptographicOperations.ZeroMemory(p); }
        }
        for (var i = 0; i < documents.Count; i++)
        {
            var input = File(documents[i]);
            var p = material.P(input);
            try
            {
                var list = fileLists[i];
                for (var j = 0; j < list.Count; j++)
                {
                    var node = list[j]; var (prev, next) = neighbors[node.D];
                    deletion[node.D - 1] = Seal([.. Ints(j + 1 < list.Count ? list[j + 1].D : 0,
                        prev?.D ?? 0, next?.D ?? 0, node.S, prev?.S ?? 0, next?.S ?? 0),
                        .. material.F(Word(node.Word))], p, true);
                }
                entries.Add(new(Address(Td, material.F(input)), Xor(Ints(list.Count == 0 ? 0 : list[0].D), material.G(input, 4))));
            }
            finally { CryptographicOperations.ZeroMemory(p); CryptographicOperations.ZeroMemory(input); }
        }
        var free = 0;
        for (var i = used; i < used + initialFreeSlots; i++)
        {
            var s = searchPositions[i];
            search[s - 1].AsSpan(0, 16).Clear();
            Write(search[s - 1], 16, free);
            Write(search[s - 1], 20, deletionPositions[i]);
            free = s;
        }
        entries.Add(new(Free, Ints(free, 0)));
        for (var i = 1; i <= capacity; i++)
        {
            entries.Add(new(Address(As, i), search[i - 1]));
            entries.Add(new(Address(Ad, i), deletion[i - 1]));
        }
        return new(Wire.Message("kamara.setup", new KamaraSetup(capacity, entries.ToArray())),
            State(new(scope, documents.ToDictionary(d => d.DocumentId, d => d.Revision))));
    }

    public async ValueTask<PreparedMutation> PrepareMutationAsync(IndexScope scope, MutationKind kind,
        TrustedDocument? previous, TrustedDocument? replacement, ClientState state, IClientKeyProvider keys,
        CancellationToken cancellationToken = default)
    {
        var local = ReadState(scope, state);
        if (!Enum.IsDefined(kind) || (kind == MutationKind.Add ? previous is not null || replacement is null
            : kind == MutationKind.Delete ? previous is null || replacement is not null : previous is null || replacement is null))
            throw new ArgumentException("Invalid mutation shape.");
        if (previous is not null && (!local.Revisions.TryGetValue(previous.DocumentId, out var revision) || revision != previous.Revision))
            throw new InvalidOperationException("Stale document descriptor.");
        if (replacement is not null && (kind == MutationKind.Add ? local.Revisions.ContainsKey(replacement.DocumentId)
            : replacement.DocumentId != previous!.DocumentId || replacement.Revision != checked(previous.Revision + 1)))
            throw new InvalidOperationException("Document identity/revision conflict.");
        using var material = await KamaraKeys.Create(scope, keys, cancellationToken);
        KamaraDeleteToken? delete = null;
        KamaraAddToken? add = null;
        if (previous is not null)
        {
            var input = File(previous);
            try { delete = new(material.F(input), material.G(input, 4), material.P(input), previous.DocumentId); }
            finally { CryptographicOperations.ZeroMemory(input); }
            local.Revisions.Remove(previous.DocumentId);
        }
        if (replacement is not null)
        {
            var input = File(replacement);
            var pFile = material.P(input);
            try
            {
                var words = new List<KamaraAddWord>();
                foreach (var word in replacement.Keywords.Distinct(StringComparer.Ordinal))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var w = Word(word); var f = material.F(w); var pWord = material.P(w);
                    try
                    {
                        words.Add(new(f, material.G(w, 8),
                            Seal([.. replacement.DocumentId.ToByteArray(), .. Ints(0)], pWord, false),
                            Seal([.. new byte[24], .. f], pFile, true)));
                    }
                    finally { CryptographicOperations.ZeroMemory(pWord); }
                }
                add = new(material.F(input), material.G(input, 4), words.ToArray());
            }
            finally { CryptographicOperations.ZeroMemory(input); CryptographicOperations.ZeroMemory(pFile); }
            local.Revisions.Add(replacement.DocumentId, replacement.Revision);
        }
        return new(Wire.Message("kamara.mutate", new KamaraMutation(delete, add)), State(local));
    }

    public async ValueTask<ClientSearchStep> BeginSearchAsync(IndexScope scope, string normalizedKeyword, ClientState state,
        IClientKeyProvider keys, CancellationToken cancellationToken = default)
    {
        ReadState(scope, state);
        using var material = await KamaraKeys.Create(scope, keys, cancellationToken);
        var input = Word(normalizedKeyword);
        return new(Wire.Message("kamara.search", new KamaraSearchToken(material.F(input), material.G(input, 8), material.P(input))), state, null);
    }
    public ValueTask<ClientSearchStep> ContinueSearchAsync(IndexScope scope, SearchResponse response, ClientState pendingState,
        IClientKeyProvider keys, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var local = ReadState(scope, pendingState);
        if (!response.IsFinal || response.Round != 0) throw new ArgumentException("Unexpected search round.");
        var ids = Wire.Read<KamaraResults>(response.Message, "kamara.results").DocumentIds;
        if (ids.Distinct().Count() != ids.Length || ids.Any(id => !local.Revisions.ContainsKey(id)))
            throw new InvalidOperationException("Invalid/stale search identifiers.");
        // This checks local revisions, not completeness/authenticity: KPR's XOR
        // index is intentionally malleable and assumes an honest-but-curious server.
        var matches = ids.ToDictionary(id => id, id => new DocumentMatch(id, local.Revisions[id]));
        return ValueTask.FromResult(new ClientSearchStep(null, new(1, Wire.Encode(new SchemeState(matches, []))), ids));
    }
}
