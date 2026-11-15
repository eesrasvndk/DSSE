using System.Diagnostics;
using System.Runtime.Versioning;
using CipherSearch.Client;
using CipherSearch.Contracts;

// Planning and summarizing need no vault, so they also run where DPAPI is unavailable.
if (args.FirstOrDefault() == "analyze") { Analyzer.Run(args); return; }
if (args.FirstOrDefault() == "plan") { BenchmarkPlanner.Run(args); return; }
if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The local vault requires Windows DPAPI.");
await ExperimentRunner.Run(args);

[SupportedOSPlatform("windows")]
internal static class ExperimentRunner
{
    internal sealed record OracleDocument(Guid Id, string Text, string[] Words);
    // ItemCount: search = result count; build/setup/ingest = documents; add/update/delete =
    // keywords of the new content (of the removed document for delete). PreviousItemCount:
    // keywords of the replaced document for update, otherwise 0.
    internal sealed record Measurement(string Scheme, int Run, string Operation, string Query, string QueryClass,
        int ItemCount, int PreviousItemCount, double Milliseconds, long RequestBytes, long ResponseBytes);
    // IndexBytes/IndexEntries/ClientStateBytes/AlgorithmStateBytes: right after build.
    // Final*: after the mutation sequence. ClientStateBytes is the whole vault directory;
    // AlgorithmStateBytes is only the scheme's own state file.
    internal sealed record RunSummary(IndexScope Scope, int Run, int Documents, long IndexBytes,
        int IndexEntries, long ClientStateBytes, long AlgorithmStateBytes, long FinalIndexBytes,
        int FinalIndexEntries, long FinalClientStateBytes, long FinalAlgorithmStateBytes,
        long EncryptedDocumentBytes, string VaultDirectory);
    internal sealed record ResumeRecord(IndexScope Scope, string VaultDirectory, OracleDocument[] Documents, string[] Queries);

    public static async Task Run(string[] args)
    {
        var command = args.FirstOrDefault() ?? "smoke";
        string Option(string name, string fallback) => CommandLine.Option(args, name, fallback);
        var url = Option("--url", "http://127.0.0.1:5180/");
        var output = Path.GetFullPath(Option("--output", $"tmp/experiments/{DateTime.UtcNow:yyyyMMdd-HHmmss}"));
        Directory.CreateDirectory(output);
        if (command == "verify")
        {
            var records = Wire.Decode<ResumeRecord[]>(File.ReadAllBytes(Path.Combine(output, "resume.json")));
            foreach (var record in records)
            {
                using var vault = new LocalVault(record.VaultDirectory);
                using var http = new HttpClient { BaseAddress = new Uri(url), Timeout = TimeSpan.FromMinutes(5) };
                var client = new DocumentClient(http, record.Scope, vault);
                await client.Initialize();
                foreach (var query in record.Queries) await Verify(client, record.Documents.ToDictionary(d => d.Id), query, true);
                Console.WriteLine($"RESTART PASS {record.Scope.SchemeId} generation={record.Scope.GenerationId}");
            }
            return;
        }
        if (command is not ("smoke" or "benchmark" or "validate-dataset"))
            throw new ArgumentException("Use smoke, benchmark, verify, validate-dataset, plan or analyze.");
        var data = Path.GetFullPath(Option("--data", BenchmarkPlanner.DefaultData));
        if (command == "validate-dataset")
        {
            var (documents, hashes) = BenchmarkPlanner.LoadDocuments(data);
            File.WriteAllBytes(Path.Combine(output, "normalization.json"), Wire.Encode(new { documents = documents.Length, inputHashes = hashes, passed = true }));
            Console.WriteLine($"NORMALIZATION PASS: {documents.Length} documents equal Python token sequences.");
            return;
        }
        var smoke = command == "smoke";
        var runs = int.Parse(Option("--runs", smoke ? "1" : "5"));
        if (runs is < 1 or > 100) throw new ArgumentException("Runs must be 1..100.");
        var queriesPerClass = int.Parse(Option("--queries-per-class", "20"));
        var mutationCount = int.Parse(Option("--mutations", smoke ? "45" : "300"));
        var note = Option("--note", "");
        var setup = BenchmarkPlanner.Prepare(smoke, data, queriesPerClass, mutationCount, Console.WriteLine);
        var source = setup.Documents.ToDictionary(d => d.Id, d => new OracleDocument(d.Id, d.Text, d.Words));
        var querySpecs = setup.Queries;
        var queryWords = setup.QueryWords;
        var plan = setup.Workload;

        var measurements = new List<Measurement>();
        var summaries = new List<RunSummary>();
        var resumes = new List<ResumeRecord>();
        var dataset = Guid.NewGuid();
        var schemes = Option("--schemes", $"{SchemeIds.NaiveHmac},{SchemeIds.Mitra}")
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (schemes.Length == 0 || schemes.Distinct().Count() != schemes.Length ||
            schemes.Any(s => s is not (SchemeIds.NaiveHmac or SchemeIds.Mitra or SchemeIds.Kamara)))
            throw new ArgumentException("Invalid --schemes list.");
        var kamaraFreeSlots = setup.KamaraFreeSlots;
        var kamaraCapacity = 16_384;
        if (schemes.Contains(SchemeIds.Kamara))
        {
            kamaraCapacity = BenchmarkPlanner.KamaraCapacityFor(setup.RequiredKamaraCapacity);
            Console.WriteLine($"Kamara capacity={kamaraCapacity}, initialPairs={setup.InitialPairs}, freeSlots={kamaraFreeSlots} (workload peak {plan.PeakExtraPairs} + margin {BenchmarkPlanner.KamaraFreeMargin})");
        }
        var repetitions = smoke ? 1 : 5;
        for (var run = 1; run <= runs; run++)
        foreach (var scheme in schemes.Skip((run - 1) % schemes.Length).Concat(schemes.Take((run - 1) % schemes.Length)))
        {
            var scope = new IndexScope(dataset, scheme, Guid.NewGuid(), 1);
            var vaultDir = Path.Combine(output, $"vault-{run}-{scheme}");
            using var vault = new LocalVault(vaultDir, true);
            using var handler = new LostResponseHandler();
            using var http = new HttpClient(handler) { BaseAddress = new Uri(url), Timeout = TimeSpan.FromMinutes(5) };
            var client = new DocumentClient(http, scope, vault, kamaraCapacity);
            var oracle = new Dictionary<Guid, OracleDocument>(source);
            Console.WriteLine($"START run={run} scheme={scheme} documents={source.Count}");
            await Measure("build", "", "", source.Count, 0, async () =>
            {
                if (scheme == SchemeIds.Kamara)
                {
                    await Measure("setup", "", "", source.Count, 0, () => client.InitializeKamaraCollection(
                        source.Values.Select(d => (d.Id, d.Text)).ToArray(), kamaraCapacity, checked((int)kamaraFreeSlots)));
                    return;
                }
                await Measure("setup", "", "", 0, 0, () => client.Initialize());
                await Measure("ingest", "", "", source.Count, 0, async () =>
                {
                    foreach (var doc in source.Values)
                        await client.Mutate(MutationKind.Add, doc.Id, doc.Text);
                });
            });
            var status = await client.Status();
            var stateBytes = VaultBytes(vaultDir);
            var algorithmBytes = AlgorithmStateBytes(vaultDir, scheme);
            long encryptedBytes = 0;
            foreach (var doc in source.Values)
            {
                // Serialized envelope length depends on UTF-8 length, not plaintext contents.
                encryptedBytes += Wire.Encode(new EncryptedDocument(doc.Id, 1, new(1, 1,
                    new byte[12], new byte[System.Text.Encoding.UTF8.GetByteCount(doc.Text)], new byte[16]))).Length;
            }
            foreach (var query in querySpecs)
            {
                // The unmeasured check also serves as this query's warm-up.
                await Verify(client, oracle, query.Word, false);
                var expected = oracle.Values.Where(d => d.Words.Contains(query.Word)).Select(d => d.Id).ToHashSet();
                for (var repetition = 0; repetition < repetitions; repetition++)
                    await MeasureSearch(query, expected, false);
                await MeasureSearch(query, expected, true);
            }
            foreach (var step in plan.Steps)
            {
                var kind = step.Kind;
                if (smoke && step.Step == 0) handler.DropNextMutationResponse = true;
                await Measure(kind.ToString().ToLowerInvariant(), "", "",
                    kind == MutationKind.Delete ? step.PreviousWords.Length : step.Words.Length,
                    kind == MutationKind.Update ? step.PreviousWords.Length : 0, async () =>
                {
                    try { await client.Mutate(kind, step.Id, step.Text); }
                    catch (HttpRequestException) when (smoke && step.Step == 0)
                    {
                        await client.Recover();
                        var recovered = await client.Status();
                        if (recovered.Epoch != source.Count + 1) throw new InvalidOperationException("Replay changed epoch.");
                    }
                });
                if (kind == MutationKind.Delete) oracle.Remove(step.Id);
                else oracle[step.Id] = new(step.Id, step.Text!, step.Words);
                // Unmeasured correctness check. Smoke checks every query; the benchmark checks one
                // word per class plus the words of the changed document (the oracle tests cover the rest).
                var verifyWords = smoke ? queryWords.Append("changed").Distinct()
                    : setup.CheckWords.Concat(step.PreviousWords.Take(4)).Concat(step.Words.Take(4)).Distinct();
                foreach (var word in verifyWords) await Verify(client, oracle, word, smoke);
            }
            foreach (var word in smoke ? queryWords.Append("changed").Distinct() : queryWords)
                await Verify(client, oracle, word, false);
            var finalStatus = await client.Status();
            summaries.Add(new(scope, run, source.Count, status.IndexBytes, status.IndexEntries, stateBytes, algorithmBytes,
                finalStatus.IndexBytes, finalStatus.IndexEntries, VaultBytes(vaultDir),
                AlgorithmStateBytes(vaultDir, scheme), encryptedBytes, vaultDir));
            resumes.Add(new(scope, vaultDir, oracle.Values.ToArray(), smoke ? queryWords.Append("changed").Distinct().ToArray() : queryWords));
            File.WriteAllBytes(Path.Combine(output, "resume.json"), Wire.Encode(resumes));
            File.WriteAllBytes(Path.Combine(output, "results.json"), Wire.Encode(new
            {
                schemaVersion = 3, command, inputHashes = setup.InputHashes, seed = 2026, note,
                queries = querySpecs, queriesPerClass,
                queryClassThresholds = new
                {
                    rareMaxDocumentFrequency = BenchmarkPlanner.RareMaxDocumentFrequency,
                    frequentMinDocumentFrequency = BenchmarkPlanner.FrequentMinDocumentFrequency
                },
                mutations = mutationCount, workload = setup.WorkloadKind,
                workloadInitialPairs = plan.InitialPairs, workloadPeakPairs = plan.PeakPairs,
                runsCompleted = summaries.Count,
                kamaraCapacity = schemes.Contains(SchemeIds.Kamara) ? (int?)kamaraCapacity : null,
                kamaraFreeSlots = schemes.Contains(SchemeIds.Kamara) ? (long?)kamaraFreeSlots : null,
                runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                processArchitecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
                processorIdentifier = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER"),
                totalMemoryBytes = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes,
                processorCount = Environment.ProcessorCount, summaries, measurements
            }));
            Console.WriteLine($"PASS run={run} scheme={scheme} indexBytes={status.IndexBytes} clientBytes={stateBytes}");

            async Task Measure(string operation, string query, string queryClass, int items, int previousItems, Func<Task> action)
            {
                var requestStart = client.RequestBytes; var responseStart = client.ResponseBytes;
                var timer = Stopwatch.StartNew();
                await action();
                timer.Stop();
                measurements.Add(new(scheme, run, operation, query, queryClass, items, previousItems,
                    timer.Elapsed.TotalMilliseconds, client.RequestBytes - requestStart, client.ResponseBytes - responseStart));
            }

            async Task MeasureSearch(BenchmarkQuery query, HashSet<Guid> expected, bool decrypt)
            {
                IReadOnlyList<DocumentMatch> matches = [];
                var plaintexts = decrypt ? new List<string>(expected.Count) : null;
                // Time the client operation only; the plaintext oracle is checked afterward.
                await Measure(decrypt ? "search-and-decrypt" : "search", query.Word, query.Class, expected.Count, 0, async () =>
                {
                    matches = await client.Search(query.Word);
                    if (decrypt)
                        foreach (var match in matches)
                            plaintexts!.Add(await client.Read(match));
                });
                VerifyMatches(matches, expected, query.Word);
                if (decrypt)
                    for (var i = 0; i < matches.Count; i++)
                        if (plaintexts![i] != oracle[matches[i].DocumentId].Text)
                            throw new InvalidOperationException("Decrypted document differs from original.");
            }
        }
        Console.WriteLine($"ALL PASS: {Path.Combine(output, "results.json")}");
    }

    private static long VaultBytes(string directory) =>
        Directory.EnumerateFiles(directory).Sum(f => new FileInfo(f).Length);

    private static long AlgorithmStateBytes(string directory, string scheme)
    {
        var name = scheme switch { SchemeIds.NaiveHmac => "naive", SchemeIds.Mitra => "mitra", _ => "kamara" };
        var path = Path.Combine(directory, name + ".state");
        return File.Exists(path) ? new FileInfo(path).Length : 0;
    }

    private static async Task Verify(DocumentClient client, Dictionary<Guid, OracleDocument> oracle, string query, bool decrypt)
    {
        var matches = await client.Search(query);
        var expected = oracle.Values.Where(d => d.Words.Contains(query)).Select(d => d.Id).ToHashSet();
        VerifyMatches(matches, expected, query);
        if (decrypt)
            foreach (var match in matches)
                if (await client.Read(match) != oracle[match.DocumentId].Text)
                    throw new InvalidOperationException("Decrypted document differs from original.");
    }

    private static void VerifyMatches(IReadOnlyList<DocumentMatch> matches, HashSet<Guid> expected, string query)
    {
        if (matches.Count != expected.Count || !expected.SetEquals(matches.Select(m => m.DocumentId)))
            throw new InvalidOperationException($"Oracle mismatch for query {query}.");
    }

    private sealed class LostResponseHandler : DelegatingHandler
    {
        public bool DropNextMutationResponse { get; set; }
        public LostResponseHandler() : base(new HttpClientHandler()) { }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var response = await base.SendAsync(request, ct);
            if (DropNextMutationResponse && request.RequestUri!.AbsolutePath is "/api/v1/documents" or "/api/v1/private-index-writes" && response.IsSuccessStatusCode)
            {
                DropNextMutationResponse = false;
                response.Dispose();
                throw new HttpRequestException("Simulated lost acknowledgment after server commit.");
            }
            return response;
        }
    }
}
