using System.Security.Cryptography;
using System.Text.Json;
using CipherSearch.Contracts;

namespace CipherSearch.Client;

public sealed record BenchmarkQuery(string Word, string Class, int DocumentFrequency);

/// <summary>Everything a run needs before any service is called: data, queries, workload, Kamara sizing.</summary>
public sealed record BenchmarkSetup(WorkloadDocument[] Documents, Dictionary<string, string> InputHashes,
    BenchmarkQuery[] Queries, string[] CheckWords, WorkloadPlan Workload, string WorkloadKind,
    long InitialPairs, long KamaraFreeSlots, long RequiredKamaraCapacity)
{
    public string[] QueryWords => Queries.Select(q => q.Word).ToArray();
}

/// <summary>
/// Prepares the benchmark without PostgreSQL, MinIO or DPAPI, so the same code backs the
/// `plan` pre-flight command (any platform) and the `benchmark`/`smoke` runs (Windows).
/// </summary>
public static class BenchmarkPlanner
{
    public const string DefaultData = "DataSet/processed/enron_1000.jsonl";
    // Query classes are result-count buckets (document frequency at build time). They are a
    // protocol choice and are written into results.json.
    public const int RareMaxDocumentFrequency = 5;
    public const int FrequentMinDocumentFrequency = 51;
    public const string AbsentPrefix = "ciphersearchabsentkeyword";
    // Extra free Kamara cells on top of the exact peak need of the planned workload.
    public const int KamaraFreeMargin = 64;
    public const int KamaraBlock = 16_384;
    public const int KamaraMaxCapacity = 1_000_000;
    // Estimated JSON bytes per Kamara capacity cell pair: an As entry (~106 B) plus an Ad entry
    // (~154 B), base64-wrapped once more inside ProtocolMessage.Payload (x4/3). Excludes the
    // Ts/Td entries and encrypted documents. An estimate, not a measurement.
    public const int EstimatedSetupBytesPerCell = 347;
    public const long DefaultSetupLimitBytes = 64L * 1024 * 1024;

    private sealed record SourceDocument(int DocumentId, string Text);
    private sealed record ProcessedDocument(int DocumentId, string[] Tokens);
    private static readonly string[] SmokeWords = ["alpha", "beta", "gamma", "delta", "epsilon", "absent"];

    public static Guid Id(int number)
    {
        var bytes = new byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(12), number);
        return new Guid(bytes);
    }

    public static (WorkloadDocument[] Documents, Dictionary<string, string> Hashes) LoadDocuments(string dataPath)
    {
        var processed = Path.ChangeExtension(dataPath, null) + "_processed.jsonl";
        var expected = File.ReadLines(processed).Select(line => JsonSerializer.Deserialize<ProcessedDocument>(line, Wire.Json)!)
            .ToDictionary(d => d.DocumentId);
        var documents = new List<WorkloadDocument>();
        foreach (var line in File.ReadLines(dataPath))
        {
            var document = JsonSerializer.Deserialize<SourceDocument>(line, Wire.Json)!;
            var words = expected[document.DocumentId].Tokens;
            if (!TextNormalizer.Tokenize(document.Text).SequenceEqual(words))
                throw new InvalidOperationException($"Python/C# normalization differs for document {document.DocumentId}.");
            documents.Add(new(Id(document.DocumentId), document.Text, words.Distinct().ToArray()));
        }
        var hashes = new Dictionary<string, string>();
        foreach (var file in new[] { dataPath, processed })
        {
            using var stream = File.OpenRead(file);
            hashes[Path.GetFileName(file)] = Convert.ToHexString(SHA256.HashData(stream));
        }
        return (documents.ToArray(), hashes);
    }

    public static BenchmarkSetup Prepare(bool smoke, string dataPath, int queriesPerClass, int mutationCount,
        Action<string>? log = null)
    {
        if (queriesPerClass is < 1 or > 1000) throw new ArgumentException("Queries per class must be 1..1000.");
        if (mutationCount < 3 || mutationCount % 3 != 0 || mutationCount > 100_000)
            throw new ArgumentException("Mutations must be a positive multiple of 3 (equal add, update and delete counts).");
        WorkloadDocument[] documents;
        Dictionary<string, string> hashes = [];
        if (smoke)
        {
            string[][] tokens = [
                ["alpha", "beta"], ["alpha", "gamma"], ["alpha", "beta", "delta"],
                ["beta"], [], ["gamma", "delta"], ["epsilon"], ["alpha", "epsilon"]
            ];
            documents = tokens.Select((t, i) => new WorkloadDocument(Id(i + 1), string.Join(" ", t), t)).ToArray();
        }
        else (documents, hashes) = LoadDocuments(dataPath);

        var frequency = documents.SelectMany(d => d.Words).GroupBy(w => w)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);
        var queries = new List<BenchmarkQuery>();
        if (smoke)
        {
            foreach (var word in SmokeWords)
                queries.Add(new(word, word == "absent" ? "absent" : "smoke", frequency.GetValueOrDefault(word)));
        }
        else
        {
            var ordered = frequency.OrderBy(p => p.Value).ThenBy(p => p.Key, StringComparer.Ordinal).ToArray();
            var classes = new (string Name, Func<int, bool> Includes)[]
            {
                ("rare", df => df <= RareMaxDocumentFrequency),
                ("medium", df => df > RareMaxDocumentFrequency && df < FrequentMinDocumentFrequency),
                ("frequent", df => df >= FrequentMinDocumentFrequency)
            };
            foreach (var (name, includes) in classes)
            {
                var members = ordered.Where(p => includes(p.Value)).ToArray();
                var picked = Spread(members, queriesPerClass);
                foreach (var pair in picked) queries.Add(new(pair.Key, name, pair.Value));
                log?.Invoke($"Query class {name}: {members.Length} words available, {picked.Length} selected");
            }
            for (var i = 0; i < Math.Min(queriesPerClass, 5); i++)
            {
                var word = AbsentPrefix + (char)('a' + i);
                if (frequency.ContainsKey(word)) throw new InvalidOperationException("An absent query word occurs in the data.");
                queries.Add(new(word, "absent", 0));
            }
            if (queries.Count == 0) throw new InvalidOperationException("No benchmark queries could be selected.");
        }
        // One representative per class (and the first absent word) for the cheap check after each mutation.
        var checkWords = queries.GroupBy(q => q.Class).Select(g => g.First().Word).ToArray();

        // The whole add/update/delete sequence is planned first: every scheme replays the same
        // operations, and Kamara's free cells are sized from the exact peak need.
        var pool = documents.OrderBy(d => d.Id).ToArray();
        Func<int, Random, (string Text, string[] Words)> content;
        if (smoke)
            content = (step, _) =>
            {
                string[] words = [SmokeWords[step % SmokeWords.Length], "changed", "alpha"];
                return (string.Join(" ", words), words.Distinct().ToArray());
            };
        else
            content = (_, random) =>
            {
                var document = pool[random.Next(pool.Length)];
                return (document.Text, document.Words);
            };
        var workload = WorkloadPlanner.Plan(documents, mutationCount, 2026, step => Id(1000000 + step), content);
        var initialPairs = documents.Sum(d => (long)d.Words.Length);
        var freeSlots = workload.PeakExtraPairs + KamaraFreeMargin;
        return new(documents, hashes, queries.ToArray(), checkWords, workload, smoke ? "synthetic" : "enron-documents",
            initialPairs, freeSlots, initialPairs + freeSlots);
    }

    /// <summary>Public Kamara capacity: the need rounded up to a block, so the exact pair count is not published.</summary>
    public static int KamaraCapacityFor(long requiredCapacity)
    {
        if (requiredCapacity > KamaraMaxCapacity)
            throw new ArgumentException($"Kamara requires at least {requiredCapacity} slots including the workload reserve; the protocol limit is {KamaraMaxCapacity}.");
        return (int)Math.Min(KamaraMaxCapacity, (requiredCapacity + KamaraBlock - 1) / KamaraBlock * KamaraBlock);
    }

    // count evenly spaced members (by frequency rank); all of them when fewer exist.
    private static KeyValuePair<string, int>[] Spread(KeyValuePair<string, int>[] members, int count)
    {
        if (members.Length <= count) return members;
        if (count == 1) return [members[members.Length / 2]];
        return Enumerable.Range(0, count)
            .Select(i => members[(int)((long)i * (members.Length - 1) / (count - 1))]).ToArray();
    }

    /// <summary>`plan` command: pre-flight summary and plan.json without touching any service.</summary>
    public static void Run(string[] args)
    {
        var data = Path.GetFullPath(CommandLine.Option(args, "--data", DefaultData));
        var queriesPerClass = int.Parse(CommandLine.Option(args, "--queries-per-class", "20"));
        var mutations = int.Parse(CommandLine.Option(args, "--mutations", "300"));
        var output = Path.GetFullPath(CommandLine.Option(args, "--output", $"tmp/experiments/plan-{DateTime.UtcNow:yyyyMMdd-HHmmss}"));
        Directory.CreateDirectory(output);
        var setup = Prepare(false, data, queriesPerClass, mutations, Console.WriteLine);
        Console.WriteLine($"Documents: {setup.Documents.Length}, initial word-document pairs: {setup.InitialPairs}");
        var kinds = setup.Workload.Steps.GroupBy(s => s.Kind).OrderBy(g => g.Key).Select(g => $"{g.Key.ToString().ToLowerInvariant()}={g.Count()}");
        Console.WriteLine($"Workload: {setup.Workload.Steps.Length} mutations ({string.Join(", ", kinds)}), peak extra pairs {setup.Workload.PeakExtraPairs}");
        int? capacity = null;
        long? estimatedBytes = null;
        try
        {
            capacity = KamaraCapacityFor(setup.RequiredKamaraCapacity);
            estimatedBytes = (long)capacity.Value * EstimatedSetupBytesPerCell;
            var limitNote = estimatedBytes > DefaultSetupLimitBytes
                ? $"exceeds the default {DefaultSetupLimitBytes / 1048576} MiB limit: start the server with -MaxSetupRequestBytes (Start-Server.ps1) or Kamara__MaxSetupRequestBytes"
                : $"fits the default {DefaultSetupLimitBytes / 1048576} MiB limit";
            Console.WriteLine($"Kamara: free slots {setup.KamaraFreeSlots}, required {setup.RequiredKamaraCapacity}, capacity {capacity}; estimated setup request ~{estimatedBytes / 1048576.0:F0} MiB (an estimate) {limitNote}");
        }
        catch (ArgumentException ex) { Console.WriteLine($"Kamara: {ex.Message}"); }
        File.WriteAllBytes(Path.Combine(output, "plan.json"), Wire.Encode(new
        {
            documents = setup.Documents.Length, inputHashes = setup.InputHashes, initialPairs = setup.InitialPairs,
            queriesPerClass, queries = setup.Queries,
            queryClassThresholds = new { rareMaxDocumentFrequency = RareMaxDocumentFrequency, frequentMinDocumentFrequency = FrequentMinDocumentFrequency },
            mutations, workloadPeakExtraPairs = setup.Workload.PeakExtraPairs,
            kamaraFreeSlots = setup.KamaraFreeSlots, kamaraRequiredCapacity = setup.RequiredKamaraCapacity,
            kamaraCapacity = capacity, estimatedKamaraSetupBytes = estimatedBytes
        }));
        Console.WriteLine($"PLAN: {Path.Combine(output, "plan.json")}");
    }
}
