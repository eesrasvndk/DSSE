using CipherSearch.Client;
using CipherSearch.Contracts;
using CipherSearch.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace CipherSearch.Tests;

// Platform-neutral checks for the benchmark tooling (workload planning, result analysis,
// leakage-log switch). None of them needs DPAPI, PostgreSQL or MinIO.
public sealed class BenchmarkToolingTests
{
    private static Guid DocId(int n) => Guid.Parse($"00000000-0000-0000-0000-{n:D12}");
    private static WorkloadDocument Doc(int n, int words)
    {
        var list = Enumerable.Range(0, words).Select(i => $"w{n}x{i}").ToArray();
        return new(DocId(n), string.Join(' ', list), list);
    }
    private static WorkloadDocument[] Initial(int documents, int words) =>
        Enumerable.Range(1, documents).Select(n => Doc(n, words)).ToArray();
    private static WorkloadPlan Plan(int seed, int mutations = 30, int documents = 10, int words = 4) =>
        WorkloadPlanner.Plan(Initial(documents, words), mutations, seed, step => DocId(1_000_000 + step),
            (step, random) => { var d = Doc(5_000 + random.Next(100), 2 + random.Next(6)); return (d.Text, d.Words); });

    [Fact]
    public void WorkloadCyclesAddUpdateDeleteOnLiveDocuments()
    {
        var plan = Plan(7);
        var live = Initial(10, 4).Select(d => d.Id).ToHashSet();
        foreach (var step in plan.Steps)
        {
            Assert.Equal((MutationKind)(step.Step % 3), step.Kind);
            if (step.Kind == MutationKind.Add)
            {
                Assert.True(live.Add(step.Id), "an added document must be new");
                Assert.Empty(step.PreviousWords);
                Assert.NotEmpty(step.Words);
            }
            else
            {
                Assert.Contains(step.Id, live);
                Assert.NotEmpty(step.PreviousWords);
                if (step.Kind == MutationKind.Delete) { live.Remove(step.Id); Assert.Null(step.Text); Assert.Empty(step.Words); }
                else Assert.NotNull(step.Text);
            }
        }
        Assert.Equal(10, plan.Steps.Count(s => s.Kind == MutationKind.Add));
        Assert.Equal(10, plan.Steps.Count(s => s.Kind == MutationKind.Update));
        Assert.Equal(10, plan.Steps.Count(s => s.Kind == MutationKind.Delete));
    }

    [Fact]
    public void WorkloadIsDeterministicPerSeed()
    {
        static object[] Shape(WorkloadPlan p) => p.Steps.Select(s => (object)(s.Kind, s.Id, s.Text)).ToArray();
        Assert.Equal(Shape(Plan(11)), Shape(Plan(11)));
        Assert.NotEqual(Shape(Plan(11)), Shape(Plan(12)));
    }

    [Fact]
    public void WorkloadPeakMatchesAReplayOfTheSteps()
    {
        var plan = Plan(3, mutations: 60);
        var pairs = plan.InitialPairs;
        var peak = pairs;
        foreach (var step in plan.Steps)
        {
            pairs += step.Words.Length - step.PreviousWords.Length;
            peak = Math.Max(peak, pairs);
        }
        Assert.Equal(40, plan.InitialPairs);
        Assert.Equal(peak, plan.PeakPairs);
        Assert.Equal(Math.Max(0, peak - plan.InitialPairs), plan.PeakExtraPairs);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(-3)]
    public void WorkloadRejectsUnbalancedMutationCounts(int mutations) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Plan(1, mutations));

    [Fact]
    public void MedianAndPercentileUseDocumentedDefinitions()
    {
        Assert.Equal(25, Analyzer.Median([10, 20, 30, 40]));
        Assert.Equal(30, Analyzer.Median([10, 20, 30, 40, 50]));
        Assert.True(double.IsNaN(Analyzer.Median([])));
        var hundred = Enumerable.Range(1, 100).Select(i => (double)i).ToArray();
        Assert.Equal(95, Analyzer.Percentile(hundred, 0.95));
        Assert.Equal(19, Analyzer.Percentile(hundred.Take(20).ToArray(), 0.95));
        Assert.Equal(40, Analyzer.Percentile([10, 20, 30, 40], 0.95));
        Assert.Equal(7, Analyzer.Percentile([7], 0.95));
    }

    private static object[] SearchRows(string scheme, params double[] milliseconds) =>
        milliseconds.Select((ms, i) => (object)new
        {
            scheme, run = 1 + i / 2, operation = "search", query = "word", queryClass = "rare",
            itemCount = 3, previousItemCount = 0, milliseconds = ms, requestBytes = 100L, responseBytes = 200L
        }).ToArray();

    private static object Summary(string scheme, long index) => new
    {
        scope = new { schemeId = scheme }, run = 1, indexBytes = index, indexEntries = 10, clientStateBytes = 50L,
        algorithmStateBytes = 20L, finalIndexBytes = index * 2, finalIndexEntries = 20, finalClientStateBytes = 60L,
        finalAlgorithmStateBytes = 30L, encryptedDocumentBytes = 400L
    };

    [Fact]
    public void AnalyzerReportsMediansP95AndMitraRatios()
    {
        var json = Wire.Encode(new
        {
            schemaVersion = 3, command = "benchmark", queriesPerClass = 1, mutations = 3, workload = "enron-documents",
            runsCompleted = 2, runtime = ".NET 8", os = "test", processorCount = 4, totalMemoryBytes = 8_589_934_592L,
            measurements = SearchRows(SchemeIds.NaiveHmac, 10, 20, 30, 40)
                .Concat(SearchRows(SchemeIds.Kamara, 5, 5, 5, 5)).Concat(SearchRows(SchemeIds.Mitra, 20, 40, 60, 80)).ToArray(),
            summaries = new[] { Summary(SchemeIds.NaiveHmac, 100), Summary(SchemeIds.Kamara, 50), Summary(SchemeIds.Mitra, 200) }
        });
        var (markdown, csv) = Analyzer.Analyze(json);
        Assert.Contains("| search | rare | Naive HMAC | 4 | 25.00 | 40.00 | 10.00 | 40.00 | 15.00–35.00 |", markdown);
        Assert.Contains("| search | rare | Mitra | 4 | 50.00 | 80.00 |", markdown);
        Assert.Contains("| search | rare | Naive HMAC | 2.00× | +100.0% | 2.00× | +100.0% |", markdown);
        Assert.Contains("| search | rare | Kamara | 10.00× | +900.0% | 16.00× | +1500.0% |", markdown);
        Assert.Contains("| İndeks, build sonrası (bayt, mantıksal) | 100 | 50 | 200 |", markdown);
        Assert.Contains("search,rare,mitra-v2,4,50,80,20,80,30,70,100,200", csv);
    }

    [Fact]
    public void AnalyzerRejectsAnOtherSchema() =>
        Assert.Throws<InvalidDataException>(() => Analyzer.Analyze(Wire.Encode(new { schemaVersion = 2, measurements = Array.Empty<object>() })));

    [Theory]
    [InlineData(null, true)]
    [InlineData("true", true)]
    [InlineData("false", false)]
    public async Task LeakageLogHonorsTheEnabledSwitch(string? enabled, bool expectFile)
    {
        var directory = Path.Combine(Path.GetTempPath(), "leakage-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "events.jsonl");
        try
        {
            var settings = new Dictionary<string, string?> { ["Leakage:Path"] = path, ["Leakage:Enabled"] = enabled };
            var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
            var log = new LeakageLog(config, NullLogger<LeakageLog>.Instance);
            var scope = new IndexScope(Guid.NewGuid(), SchemeIds.Mitra, Guid.NewGuid(), 1);
            await log.Record(scope, Guid.NewGuid(), "search", 1, 10, 10, 5, [], [], [], 0);
            Assert.Equal(expectFile, File.Exists(path));
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }
}
