using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using CipherSearch.Client;
using CipherSearch.Contracts;

if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The local vault requires Windows DPAPI.");
await ExperimentRunner.Run(args);

[SupportedOSPlatform("windows")]
internal static class ExperimentRunner
{
    internal sealed record SourceDocument(int DocumentId, string Text);
    internal sealed record ProcessedDocument(int DocumentId, string[] Tokens);
    internal sealed record OracleDocument(Guid Id, string Text, string[] Words);
    internal sealed record Measurement(string Scheme, int Run, string Operation, string QueryClass,
        int ResultCount, double Milliseconds, long RequestBytes, long ResponseBytes);
    internal sealed record RunSummary(IndexScope Scope, int Run, int Documents, long IndexBytes,
        int IndexEntries, long ClientStateBytes, long EncryptedDocumentBytes, string VaultDirectory);
    internal sealed record ResumeRecord(IndexScope Scope, string VaultDirectory, OracleDocument[] Documents, string[] Queries);

    public static async Task Run(string[] args)
    {
        var command = args.FirstOrDefault() ?? "smoke";
        string Option(string name, string fallback)
        {
            var index = Array.IndexOf(args, name);
            return index < 0 ? fallback : args.ElementAtOrDefault(index + 1) ?? throw new ArgumentException($"Missing {name} value.");
        }
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
            throw new ArgumentException("Use smoke, benchmark, verify or validate-dataset.");
        var smoke = command == "smoke";
        var runs = int.Parse(Option("--runs", smoke ? "1" : "5"));
        if (runs is < 1 or > 100) throw new ArgumentException("Runs must be 1..100.");
        var source = new Dictionary<Guid, OracleDocument>();
        var inputHashes = new Dictionary<string, string>();
        if (smoke)
        {
            string[][] tokens = [
                ["alpha", "beta"], ["alpha", "gamma"], ["alpha", "beta", "delta"],
                ["beta"], [], ["gamma", "delta"], ["epsilon"], ["alpha", "epsilon"]
            ];
            for (var i = 0; i < tokens.Length; i++)
            {
                var text = string.Join(" ", tokens[i]);
                source.Add(Id(i + 1), new(Id(i + 1), text, tokens[i]));
            }
        }
        else
        {
            var data = Path.GetFullPath(Option("--data", "DataSet/processed/enron_1000.jsonl"));
            var processed = Path.ChangeExtension(data, null) + "_processed.jsonl";
            var expected = File.ReadLines(processed).Select(line => JsonSerializer.Deserialize<ProcessedDocument>(line, Wire.Json)!)
                .ToDictionary(d => d.DocumentId);
            foreach (var line in File.ReadLines(data))
            {
                var document = JsonSerializer.Deserialize<SourceDocument>(line, Wire.Json)!;
                var words = expected[document.DocumentId].Tokens;
                if (!TextNormalizer.Tokenize(document.Text).SequenceEqual(words))
                    throw new InvalidOperationException($"Python/C# normalization differs for document {document.DocumentId}.");
                source.Add(Id(document.DocumentId), new(Id(document.DocumentId), document.Text, words.Distinct().ToArray()));
            }
            foreach (var file in new[] { data, processed })
            {
                using var stream = File.OpenRead(file);
                inputHashes[Path.GetFileName(file)] = Convert.ToHexString(SHA256.HashData(stream));
            }
        }
        if (command == "validate-dataset")
        {
            File.WriteAllBytes(Path.Combine(output, "normalization.json"), Wire.Encode(new { documents = source.Count, inputHashes, passed = true }));
            Console.WriteLine($"NORMALIZATION PASS: {source.Count} documents equal Python token sequences.");
            return;
        }
        var frequencies = source.Values.SelectMany(d => d.Words.Distinct()).GroupBy(w => w)
            .OrderBy(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).ToArray();
        var queries = smoke ? new[] { "alpha", "beta", "gamma", "delta", "epsilon", "absent" }
            : new[] { frequencies[0].Key, frequencies[frequencies.Length / 2].Key,
                frequencies[(int)(frequencies.Length * .9)].Key, frequencies[^1].Key, "ciphersearchabsentkeyword" }.Distinct().ToArray();
        var measurements = new List<Measurement>();
        var summaries = new List<RunSummary>();
        var resumes = new List<ResumeRecord>();
        var dataset = Guid.NewGuid();
        var schemes = Option("--schemes", $"{SchemeIds.NaiveHmac},{SchemeIds.Mitra}")
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (schemes.Length == 0 || schemes.Distinct().Count() != schemes.Length ||
            schemes.Any(s => s is not (SchemeIds.NaiveHmac or SchemeIds.Mitra or SchemeIds.Kamara)))
            throw new ArgumentException("Invalid --schemes list.");
        var mutationCount = smoke ? 45 : 15;
        var initialPairs = source.Values.Sum(d => (long)d.Words.Length);
        // Each workload mutation introduces at most three pairs. Round the public
        // capacity up in blocks rather than publishing the exact initial pair count.
        var requiredCapacity = initialPairs + mutationCount * 3L;
        var kamaraCapacity = 16_384;
        if (schemes.Contains(SchemeIds.Kamara))
        {
            if (requiredCapacity > 1_000_000)
                throw new ArgumentException($"Kamara requires at least {requiredCapacity} slots including mutation reserve; the protocol limit is 1000000.");
            kamaraCapacity = (int)Math.Min(1_000_000, ((requiredCapacity + 16_383) / 16_384) * 16_384);
            Console.WriteLine($"Kamara capacity={kamaraCapacity}, initialPairs={initialPairs}, mutationReserve={mutationCount * 3}");
        }
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
            await Measure("build", "", source.Count, async () =>
            {
                if (scheme == SchemeIds.Kamara)
                {
                    await Measure("setup", "", source.Count, () => client.InitializeKamaraCollection(
                        source.Values.Select(d => (d.Id, d.Text)).ToArray(), kamaraCapacity, mutationCount * 3));
                    return;
                }
                await Measure("setup", "", 0, () => client.Initialize());
                await Measure("ingest", "", source.Count, async () =>
                {
                    foreach (var doc in source.Values)
                        await client.Mutate(MutationKind.Add, doc.Id, doc.Text);
                });
            });
            var status = await client.Status();
            var stateBytes = Directory.EnumerateFiles(vaultDir).Sum(f => new FileInfo(f).Length);
            long encryptedBytes = 0;
            foreach (var doc in source.Values)
            {
                // Serialized envelope length depends on UTF-8 length, not plaintext contents.
                encryptedBytes += Wire.Encode(new EncryptedDocument(doc.Id, 1, new(1, 1,
                    new byte[12], new byte[System.Text.Encoding.UTF8.GetByteCount(doc.Text)], new byte[16]))).Length;
            }
            summaries.Add(new(scope, run, source.Count, status.IndexBytes, status.IndexEntries, stateBytes, encryptedBytes, vaultDir));
            foreach (var query in queries)
            {
                await Verify(client, oracle, query, false);
                var expected = oracle.Values.Where(d => d.Words.Contains(query)).Select(d => d.Id).ToHashSet();
                for (var repetition = 0; repetition < (smoke ? 1 : 5); repetition++)
                    await MeasureSearch(query, expected, false);
                await MeasureSearch(query, expected, true);
            }
            var random = new Random(2026);
            for (var step = 0; step < mutationCount; step++)
            {
                var kind = (MutationKind)(step % 3);
                var id = kind == MutationKind.Add ? Id(1000000 + step) : oracle.Keys.OrderBy(x => x).ElementAt(random.Next(oracle.Count));
                string[] words = [queries[step % queries.Length], "changed", "alpha"];
                var text = string.Join(" ", words);
                if (smoke && step == 0) handler.DropNextMutationResponse = true;
                await Measure(kind.ToString().ToLowerInvariant(), "", 0, async () =>
                {
                    try { await client.Mutate(kind, id, kind == MutationKind.Delete ? null : text); }
                    catch (HttpRequestException) when (smoke && step == 0)
                    {
                        await client.Recover();
                        var recovered = await client.Status();
                        if (recovered.Epoch != source.Count + 1) throw new InvalidOperationException("Replay changed epoch.");
                    }
                });
                if (kind == MutationKind.Delete) oracle.Remove(id);
                else oracle[id] = new(id, text, words.Distinct().ToArray());
                foreach (var query in queries.Append("changed").Distinct())
                    await Verify(client, oracle, query, smoke);
            }
            resumes.Add(new(scope, vaultDir, oracle.Values.ToArray(), queries.Append("changed").Distinct().ToArray()));
            File.WriteAllBytes(Path.Combine(output, "resume.json"), Wire.Encode(resumes));
            File.WriteAllBytes(Path.Combine(output, "results.json"), Wire.Encode(new
            {
                schemaVersion = 2, command, inputHashes, seed = 2026, queries, runsCompleted = summaries.Count,
                kamaraCapacity = schemes.Contains(SchemeIds.Kamara) ? (int?)kamaraCapacity : null,
                runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                processorCount = Environment.ProcessorCount, summaries, measurements
            }));
            Console.WriteLine($"PASS run={run} scheme={scheme} indexBytes={status.IndexBytes} clientBytes={stateBytes}");

            async Task Measure(string operation, string query, int resultCount, Func<Task> action)
            {
                var requestStart = client.RequestBytes; var responseStart = client.ResponseBytes;
                var timer = Stopwatch.StartNew();
                await action();
                timer.Stop();
                measurements.Add(new(scheme, run, operation, query, resultCount, timer.Elapsed.TotalMilliseconds,
                    client.RequestBytes - requestStart, client.ResponseBytes - responseStart));
            }

            async Task MeasureSearch(string query, HashSet<Guid> expected, bool decrypt)
            {
                IReadOnlyList<DocumentMatch> matches = [];
                var plaintexts = decrypt ? new List<string>(expected.Count) : null;
                // Time the client operation only; the plaintext oracle is checked afterward.
                await Measure(decrypt ? "search-and-decrypt" : "search", query, expected.Count, async () =>
                {
                    matches = await client.Search(query);
                    if (decrypt)
                        foreach (var match in matches)
                            plaintexts!.Add(await client.Read(match));
                });
                VerifyMatches(matches, expected, query);
                if (decrypt)
                    for (var i = 0; i < matches.Count; i++)
                        if (plaintexts![i] != oracle[matches[i].DocumentId].Text)
                            throw new InvalidOperationException("Decrypted document differs from original.");
            }
        }
        Console.WriteLine($"ALL PASS: {Path.Combine(output, "results.json")}");
    }

    private static Guid Id(int number)
    {
        var bytes = new byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(12), number);
        return new Guid(bytes);
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
