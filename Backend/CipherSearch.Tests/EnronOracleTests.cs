using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CipherSearch.Client;
using CipherSearch.Contracts;
using CipherSearch.SearchSchemes.Naive;
using CipherSearch.SearchSchemes.Mitra;
using CipherSearch.SearchSchemes.Kamara;

namespace CipherSearch.Tests;

public sealed class EnronTheoryAttribute : TheoryAttribute
{
    public EnronTheoryAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CIPHERSEARCH_ORACLE_ROOT")))
            Skip = "Set CIPHERSEARCH_ORACLE_ROOT and CIPHERSEARCH_ORACLE_OUT to run the Enron oracle.";
    }
}

public sealed class EnronOracleTests
{
    [EnronTheory]
    [InlineData(1)]
    [InlineData(17)]
    [InlineData(42)]
    public async Task SameEnronWorkloadMatchesPlaintext(int seed)
    {
        var root = Environment.GetEnvironmentVariable("CIPHERSEARCH_ORACLE_ROOT");
        if (string.IsNullOrWhiteSpace(root)) throw new InvalidOperationException("Oracle root missing.");
        var output = Environment.GetEnvironmentVariable("CIPHERSEARCH_ORACLE_OUT")
            ?? throw new InvalidOperationException("Oracle output directory missing.");
        Directory.CreateDirectory(output);
        var corpusPath = Path.Combine(root, "DataSet/processed/enron_1000.jsonl");
        var corpus = File.ReadLines(corpusPath).Select(line => {
            using var json = JsonDocument.Parse(line);
            return TextNormalizer.Tokenize(json.RootElement.GetProperty("text").GetString()!).Distinct().ToArray();
        }).ToArray();
        Assert.Equal(1000, corpus.Length);
        var vocabulary = corpus.SelectMany(w => w).GroupBy(w => w)
            .OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).Select(g => g.Key).ToArray();
        const string absent = "zzciphersearchoracleabsentzz";
        Assert.DoesNotContain(absent, vocabulary);
        // Rank-stratified queries include frequent and rare words, plus an absent keyword.
        var fixedQueries = Enumerable.Range(0, 128).Select(i => vocabulary[i * (vocabulary.Length - 1) / 127])
            .Append(absent).Distinct().ToArray();
        var expected = Enumerable.Range(0, 1000).ToDictionary(i => Id(i), i => new TrustedDocument(Id(i), 1, corpus[i]));
        var revisions = expected.ToDictionary(x => x.Key, x => x.Value.Revision);
        var workload = new List<object>(); var measurements = new List<object>();
        var random = new Random(seed);
        var schemes = new[] { SchemeIds.NaiveHmac, SchemeIds.Kamara, SchemeIds.Mitra };
        // Conservative capacity for initial pairs and all 60 mutations, even if
        // each added a maximum-size document without freeing any previous cells.
        var required = corpus.Sum(words => words.Length) + 60 * corpus.Max(words => words.Length);
        var capacity = checked(((required + 16_383) / 16_384) * 16_384);
        var harnesses = new List<Harness>();
        try
        {
            foreach (var scheme in schemes) harnesses.Add(await Harness.Create(scheme, capacity, expected.Values.ToArray()));
            foreach (var doc in expected.Values)
                foreach (var h in harnesses.Where(h => h.Scheme != SchemeIds.Kamara))
                    await h.Mutate(MutationKind.Add, null, doc);
            await Verify("initial", fixedQueries);
            var lastDeleted = Guid.Empty;
            for (var step = 0; step < 60; step++)
            {
                // Ten cycles cover additions, replacement, deletion, re-add, empty document and unchanged content.
                var scenario = step % 6;
                var id = scenario == 0 ? Id(1000 + step) : scenario == 3 ? lastDeleted
                    : expected.Keys.Order().ElementAt(random.Next(expected.Count));
                var previous = expected.GetValueOrDefault(id);
                var kind = scenario is 0 or 3 ? MutationKind.Add : scenario == 2 ? MutationKind.Delete : MutationKind.Update;
                var source = random.Next(corpus.Length);
                var words = scenario == 4 ? Array.Empty<string>() : scenario == 5 ? previous!.Keywords.ToArray() : corpus[source];
                var revision = revisions.GetValueOrDefault(id) + 1;
                var next = kind == MutationKind.Delete ? null : new TrustedDocument(id, revision, words);
                var queries = (previous?.Keywords ?? []).Concat(next?.Keywords ?? [])
                    .Concat(fixedQueries.Take(8)).Append(absent).Distinct().Order(StringComparer.Ordinal).ToArray();
                workload.Add(new { step, scenario, kind = kind.ToString(), documentId = id, revision,
                    sourceDocument = kind == MutationKind.Delete || scenario is 4 or 5 ? (int?)null : source,
                    keywords = next?.Keywords, queries });
                foreach (var h in harnesses) await h.Mutate(kind, previous, next);
                if (next is null) { expected.Remove(id); lastDeleted = id; }
                else expected[id] = next;
                revisions[id] = revision;
                await Verify($"mutation-{step}", queries);
            }
            await Verify("final", fixedQueries);
            // Persist only after assertions pass. Missing artifacts must never count as success.
            await File.WriteAllBytesAsync(Path.Combine(output, $"workload-{seed}.json"), Wire.Encode(new {
                seed, corpusSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(corpusPath))),
                initialDocuments = 1000, fixedQueries, operations = workload }));
            await File.WriteAllBytesAsync(Path.Combine(output, $"oracle-{seed}.json"), Wire.Encode(new {
                seed, status = "passed", finalLiveDocuments = expected.Count, comparisons = measurements }));
        }
        finally { foreach (var h in harnesses) h.Dispose(); }

        async Task Verify(string phase, string[] queries)
        {
            foreach (var word in queries)
            {
                // Independent direct plaintext scan: no tokens or encrypted scheme state.
                var oracle = expected.Values.Where(d => d.Keywords.Contains(word))
                    .ToDictionary(d => d.DocumentId, d => d.Revision);
                foreach (var h in harnesses)
                {
                    var actual = await h.Search(word);
                    Assert.True(oracle.Count == actual.Count && oracle.All(p => actual.TryGetValue(p.Key, out var revision) && revision == p.Value),
                        $"scheme={h.Scheme}, seed={seed}, phase={phase}, word={word}");
                    measurements.Add(new { phase, word, scheme = h.Scheme, expected = oracle.Count, actual = actual.Count,
                        resultSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(";", actual.OrderBy(p => p.Key).Select(p => $"{p.Key}:{p.Value}"))))) });
                }
            }
        }
    }
    private static Guid Id(int id) => new(SHA256.HashData(Encoding.UTF8.GetBytes($"enron-oracle-document-{id}"))[..16]);
    private sealed class Harness : IDisposable
    {
        private readonly TestKeys keys = new();
        private readonly IClientSearchScheme client;
        private readonly IServerSearchScheme server;
        private readonly IndexScope scope;
        private readonly TestIndex store;
        private ClientState state = null!;
        public string Scheme => scope.SchemeId;
        private Harness(string scheme)
        {
            client = scheme switch { SchemeIds.NaiveHmac => new NaiveClientScheme(keys), SchemeIds.Kamara => new KamaraClientScheme(), _ => new MitraClientScheme() };
            server = scheme switch { SchemeIds.NaiveHmac => new NaiveServerScheme(), SchemeIds.Kamara => new KamaraServerScheme(), _ => new MitraServerScheme() };
            scope = new(Guid.NewGuid(), scheme, Guid.NewGuid(), 1); store = new(scope);
        }
        public static async Task<Harness> Create(string scheme, int capacity, TrustedDocument[] initial)
        {
            var h = new Harness(scheme);
            if (h.client is KamaraClientScheme kamara)
            {
                var setup = await kamara.PrepareSetupAsync(h.scope, initial, capacity,
                    capacity - initial.Sum(d => d.Keywords.Count), h.keys);
                await h.server.ApplyMutationAsync(h.scope, setup.Message, h.store);
                h.state = setup.PendingState;
            }
            else h.state = await h.client.InitializeAsync(h.scope, h.keys);
            return h;
        }
        public async Task Mutate(MutationKind kind, TrustedDocument? previous, TrustedDocument? next)
        {
            var p = await client.PrepareMutationAsync(scope, kind, previous, next, state, keys);
            await server.ApplyMutationAsync(scope, p.Message, store);
            state = p.PendingState;
        }
        public async Task<Dictionary<Guid, long>> Search(string word)
        {
            var start = await client.BeginSearchAsync(scope, word, state, keys);
            var response = await server.SearchAsync(new(1, Guid.NewGuid(), scope, 0, 0, start.NextMessage!), store);
            var finish = await client.ContinueSearchAsync(scope, response, start.PendingState, keys);
            return Wire.Decode<SchemeState>(finish.PendingState.Payload).Matches.ToDictionary(p => p.Key, p => p.Value.Revision);
        }
        public void Dispose() => keys.Dispose();
    }
}
