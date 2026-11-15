using System.Text.Json;
using CipherSearch.Client;
using CipherSearch.Contracts;

namespace CipherSearch.Tests;

// Benchmark preparation without services: a small synthetic corpus stands in for Enron.
public sealed class BenchmarkPlannerTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "planner-" + Guid.NewGuid().ToString("N"));
    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, true); }

    // Word j (a letters-only token, never a stop word) is in document i when i is a multiple of j+1,
    // so word 0 is in every document and document frequencies fall off like 1/(j+1).
    private static string Word(int j) => "zq" + string.Concat(j.ToString().Select(c => (char)('a' + (c - '0'))));

    private string WriteDataset(int documents, Func<int, string[], string[]>? processedTokens = null)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "corpus.jsonl");
        var data = new List<string>();
        var processed = new List<string>();
        for (var i = 1; i <= documents; i++)
        {
            var words = Enumerable.Range(0, 100).Where(j => i % (j + 1) == 0).Select(Word).ToArray();
            data.Add(JsonSerializer.Serialize(new { documentId = i, text = string.Join(' ', words) }));
            processed.Add(JsonSerializer.Serialize(new { documentId = i, tokens = processedTokens?.Invoke(i, words) ?? words }));
        }
        File.WriteAllLines(path, data);
        File.WriteAllLines(Path.Combine(directory, "corpus_processed.jsonl"), processed);
        return path;
    }

    [Fact]
    public void QueriesAreClassifiedByDocumentFrequency()
    {
        var setup = BenchmarkPlanner.Prepare(false, WriteDataset(300), queriesPerClass: 20, mutationCount: 30);
        var frequency = setup.Documents.SelectMany(d => d.Words).GroupBy(w => w).ToDictionary(g => g.Key, g => g.Count());
        var byClass = setup.Queries.GroupBy(q => q.Class).ToDictionary(g => g.Key, g => g.ToArray());
        Assert.Equal(["absent", "frequent", "medium", "rare"], byClass.Keys.Order());
        Assert.Equal(20, byClass["rare"].Length);
        Assert.Equal(20, byClass["medium"].Length);
        Assert.Equal(5, byClass["frequent"].Length);   // only five words qualify, so all are taken
        Assert.Equal(5, byClass["absent"].Length);
        Assert.All(byClass["rare"], q => Assert.InRange(q.DocumentFrequency, 1, 5));
        Assert.All(byClass["medium"], q => Assert.InRange(q.DocumentFrequency, 6, 50));
        Assert.All(byClass["frequent"], q => Assert.True(q.DocumentFrequency >= 51));
        Assert.All(byClass["absent"], q => { Assert.Equal(0, q.DocumentFrequency); Assert.False(frequency.ContainsKey(q.Word)); });
        Assert.All(setup.Queries.Where(q => q.Class != "absent"), q => Assert.Equal(frequency[q.Word], q.DocumentFrequency));
        Assert.Equal(setup.Queries.Length, setup.QueryWords.Distinct().Count());
        Assert.Equal(4, setup.CheckWords.Length);
    }

    [Fact]
    public void FewerQueriesPerClassSpreadAcrossTheFrequencyRange()
    {
        var setup = BenchmarkPlanner.Prepare(false, WriteDataset(300), queriesPerClass: 3, mutationCount: 30);
        var rare = setup.Queries.Where(q => q.Class == "rare").ToArray();
        Assert.Equal(3, rare.Length);
        Assert.True(rare[0].DocumentFrequency <= rare[^1].DocumentFrequency);
        Assert.Equal(3, setup.Queries.Count(q => q.Class == "absent"));
        Assert.Single(BenchmarkPlanner.Prepare(false, WriteDataset(300), 1, 30).Queries, q => q.Class == "rare");
    }

    [Fact]
    public void PreparationIsDeterministic()
    {
        var path = WriteDataset(300);
        var a = BenchmarkPlanner.Prepare(false, path, 20, 30);
        var b = BenchmarkPlanner.Prepare(false, path, 20, 30);
        Assert.Equal(a.Queries, b.Queries);
        Assert.Equal(a.Workload.Steps.Select(s => (s.Kind, s.Id, s.Text)), b.Workload.Steps.Select(s => (s.Kind, s.Id, s.Text)));
        Assert.Equal(a.InputHashes, b.InputHashes);
        Assert.Equal(2, a.InputHashes.Count);
    }

    [Fact]
    public void KamaraFreeSlotsFollowTheWorkloadPeak()
    {
        var setup = BenchmarkPlanner.Prepare(false, WriteDataset(300), 20, 300);
        Assert.Equal(setup.Documents.Sum(d => (long)d.Words.Length), setup.InitialPairs);
        Assert.Equal(setup.Workload.PeakExtraPairs + BenchmarkPlanner.KamaraFreeMargin, setup.KamaraFreeSlots);
        Assert.Equal(setup.InitialPairs + setup.KamaraFreeSlots, setup.RequiredKamaraCapacity);
        Assert.Equal(100, setup.Workload.Steps.Count(s => s.Kind == MutationKind.Delete));
        Assert.Equal("enron-documents", setup.WorkloadKind);
    }

    [Theory]
    [InlineData(1, 16_384)]
    [InlineData(16_384, 16_384)]
    [InlineData(16_385, 32_768)]
    [InlineData(61_885, 65_536)]
    [InlineData(999_999, 1_000_000)]
    [InlineData(1_000_000, 1_000_000)]
    public void KamaraCapacityRoundsUpToWholeBlocks(long required, int expected) =>
        Assert.Equal(expected, BenchmarkPlanner.KamaraCapacityFor(required));

    [Fact]
    public void KamaraCapacityRefusesTheProtocolLimit() =>
        Assert.Throws<ArgumentException>(() => BenchmarkPlanner.KamaraCapacityFor(1_000_001));

    [Theory]
    [InlineData(0, 30)]
    [InlineData(1001, 30)]
    [InlineData(20, 4)]
    [InlineData(20, 0)]
    public void InvalidSamplingOptionsAreRejected(int queriesPerClass, int mutations) =>
        Assert.Throws<ArgumentException>(() => BenchmarkPlanner.Prepare(false, WriteDataset(300), queriesPerClass, mutations));

    [Fact]
    public void SmokePreparationNeedsNoData()
    {
        var setup = BenchmarkPlanner.Prepare(true, "missing.jsonl", 20, 45);
        Assert.Equal(8, setup.Documents.Length);
        Assert.Equal(6, setup.Queries.Length);
        Assert.Equal("synthetic", setup.WorkloadKind);
        Assert.Equal(45, setup.Workload.Steps.Length);
    }

    [Fact]
    public void NormalizationMismatchIsDetected()
    {
        var path = WriteDataset(20, (i, words) => i == 7 ? words.Append("extra").ToArray() : words);
        var error = Assert.Throws<InvalidOperationException>(() => BenchmarkPlanner.LoadDocuments(path));
        Assert.Contains("document 7", error.Message);
    }

    [Fact]
    public void PlanCommandWritesAPlanFile()
    {
        var path = WriteDataset(300);
        var output = Path.Combine(directory, "out");
        BenchmarkPlanner.Run(["plan", "--data", path, "--output", output, "--mutations", "30", "--queries-per-class", "4"]);
        using var plan = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(output, "plan.json")));
        Assert.Equal(300, plan.RootElement.GetProperty("documents").GetInt32());
        Assert.Equal(4 * 3 + 4, plan.RootElement.GetProperty("queries").GetArrayLength());
        Assert.Equal(16_384, plan.RootElement.GetProperty("kamaraCapacity").GetInt32() % 16_384 == 0 ? 16_384 : 0);
        Assert.True(plan.RootElement.GetProperty("estimatedKamaraSetupBytes").GetInt64() > 0);
    }
}
