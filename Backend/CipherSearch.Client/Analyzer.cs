using System.Globalization;
using System.Text;
using System.Text.Json;
using CipherSearch.Contracts;

namespace CipherSearch.Client;

/// <summary>
/// Summarizes a benchmark results.json (schema 3): median and p95 per scheme, operation and
/// query class, Mitra-versus-baseline ratios, run-to-run spread, index/client sizes and traffic.
/// It only reads JSON, so it runs on any platform.
/// </summary>
public static class Analyzer
{
    private sealed record Row(string Scheme, int Run, string Operation, string Query, string QueryClass,
        int ItemCount, int PreviousItemCount, double Milliseconds, long RequestBytes, long ResponseBytes);
    private sealed record ScopeInfo(string SchemeId);
    private sealed record SummaryRow(ScopeInfo Scope, int Run, long IndexBytes, int IndexEntries, long ClientStateBytes,
        long AlgorithmStateBytes, long FinalIndexBytes, int FinalIndexEntries, long FinalClientStateBytes,
        long FinalAlgorithmStateBytes, long EncryptedDocumentBytes);
    private sealed record Input(int SchemaVersion, string? Command, string? Note, int QueriesPerClass, int Mutations,
        string? Workload, long? KamaraCapacity, long? KamaraFreeSlots, string? Runtime, string? Os,
        string? ProcessorIdentifier, long TotalMemoryBytes, int ProcessorCount, int RunsCompleted,
        Row[] Measurements, SummaryRow[] Summaries);
    private sealed record Stat(int N, double Median, double P95, double Min, double Max,
        double RunMedianMin, double RunMedianMax, double MedianRequestBytes, double MedianResponseBytes);

    private static readonly string[] Operations =
        ["build", "setup", "ingest", "search", "search-and-decrypt", "add", "update", "delete"];
    private static readonly string[] Classes = ["", "smoke", "rare", "medium", "frequent", "absent"];
    private static readonly string[] SchemeOrder = [SchemeIds.NaiveHmac, SchemeIds.Kamara, SchemeIds.Mitra];

    public static void Run(string[] args)
    {
        var input = CommandLine.OptionOrNull(args, "--input");
        var directory = CommandLine.OptionOrNull(args, "--output");
        var path = input ?? (directory is null ? throw new ArgumentException("Use --input <results.json> or --output <directory>.")
            : Path.Combine(directory, "results.json"));
        path = Path.GetFullPath(path);
        var (markdown, csv) = Analyze(File.ReadAllBytes(path));
        var target = Path.GetDirectoryName(path)!;
        File.WriteAllText(Path.Combine(target, "summary.md"), markdown, new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(target, "summary.csv"), csv, new UTF8Encoding(false));
        Console.WriteLine($"SUMMARY: {Path.Combine(target, "summary.md")}");
    }

    public static (string Markdown, string Csv) Analyze(byte[] resultsJson)
    {
        var input = JsonSerializer.Deserialize<Input>(resultsJson, Wire.Json) ?? throw new InvalidDataException("Empty results.");
        if (input.SchemaVersion != 3)
            throw new InvalidDataException($"Unsupported results schema {input.SchemaVersion}; expected 3.");
        var rows = input.Measurements ?? [];
        var summaries = input.Summaries ?? [];
        var schemes = SchemeOrder.Where(s => rows.Any(r => r.Scheme == s) || summaries.Any(x => x.Scope.SchemeId == s)).ToArray();

        var stats = new Dictionary<(string Operation, string Class, string Scheme), Stat>();
        foreach (var group in rows.GroupBy(r => (r.Operation, r.QueryClass, r.Scheme)))
            stats[group.Key] = Compute(group);
        var keys = stats.Keys.Select(k => (k.Operation, k.Class)).Distinct()
            .OrderBy(k => Rank(Operations, k.Operation)).ThenBy(k => Rank(Classes, k.Class)).ToArray();

        var md = new StringBuilder();
        var csv = new StringBuilder("operation,queryClass,scheme,n,medianMs,p95Ms,minMs,maxMs,runMedianMinMs,runMedianMaxMs,medianRequestBytes,medianResponseBytes\n");
        md.AppendLine("# Benchmark özeti");
        md.AppendLine();
        md.AppendLine($"- Komut: `{input.Command}`, tamamlanan koşu: {input.RunsCompleted}, sorgu sayısı sınıf başına: {input.QueriesPerClass}, mutasyon: {input.Mutations}, iş yükü: {input.Workload}");
        if (input.KamaraCapacity is not null)
            md.AppendLine($"- Kamara kapasitesi: {input.KamaraCapacity}, serbest hücre: {input.KamaraFreeSlots}");
        md.AppendLine($"- Ortam: {input.Runtime}; {input.Os}; {input.ProcessorIdentifier}; {input.ProcessorCount} mantıksal işlemci; RAM {(input.TotalMemoryBytes / 1073741824.0).ToString("F1", CultureInfo.InvariantCulture)} GiB");
        if (!string.IsNullOrWhiteSpace(input.Note)) md.AppendLine($"- Not: {input.Note}");
        md.AppendLine("- Medyan: çift örnek sayısında ortadaki iki değerin ortalaması. p95: en yakın sıra (ceil(0.95·n)). n < 20 ise p95 neredeyse maksimumdur; n sütununa bakın.");
        md.AppendLine("- \"Koşu medyanı aralığı\": her koşunun kendi medyanının en küçük ve en büyük değeri (tekrarlar arası değişkenlik).");
        md.AppendLine();
        md.AppendLine("## Gecikme (ms) ve trafik (bayt)");
        md.AppendLine();
        md.AppendLine("| İşlem | Sınıf | Yöntem | n | Medyan | p95 | Min | Maks | Koşu medyanı aralığı | İstek B (medyan) | Yanıt B (medyan) |");
        md.AppendLine("|---|---|---|---:|---:|---:|---:|---:|---|---:|---:|");
        foreach (var (operation, cls) in keys)
            foreach (var scheme in schemes)
            {
                if (!stats.TryGetValue((operation, cls, scheme), out var s)) continue;
                md.AppendLine($"| {operation} | {cls} | {Name(scheme)} | {s.N} | {F(s.Median)} | {F(s.P95)} | {F(s.Min)} | {F(s.Max)} | {F(s.RunMedianMin)}–{F(s.RunMedianMax)} | {F(s.MedianRequestBytes, 0)} | {F(s.MedianResponseBytes, 0)} |");
                csv.AppendLine(string.Join(',', operation, cls, scheme, s.N, C(s.Median), C(s.P95), C(s.Min), C(s.Max),
                    C(s.RunMedianMin), C(s.RunMedianMax), C(s.MedianRequestBytes), C(s.MedianResponseBytes)));
            }
        md.AppendLine();
        md.AppendLine("`setup` ve `ingest` satırları yöntemler arasında eşdeğer değildir: Kamara toplu kurulur (`setup` tüm yüklemeyi kapsar), Naive ve Mitra sıralı eklenir. Yöntemler arası kıyas için `build` kullanılır.");

        if (schemes.Contains(SchemeIds.Mitra) && schemes.Length > 1)
        {
            md.AppendLine();
            md.AppendLine("## Mitra oranı (Mitra / karşılaştırılan yöntem)");
            md.AppendLine();
            md.AppendLine("Oran = Mitra / yöntem; ek maliyet (%) = (oran − 1) × 100. Oran > 1 Mitra'nın daha yavaş olduğu anlamına gelir.");
            md.AppendLine();
            md.AppendLine("| İşlem | Sınıf | Karşılaştırılan | Medyan oranı | Medyan ek maliyet | p95 oranı | p95 ek maliyet |");
            md.AppendLine("|---|---|---|---:|---:|---:|---:|");
            foreach (var (operation, cls) in keys)
            {
                if (!stats.TryGetValue((operation, cls, SchemeIds.Mitra), out var mitra)) continue;
                foreach (var other in schemes.Where(s => s != SchemeIds.Mitra))
                {
                    if (!stats.TryGetValue((operation, cls, other), out var baseline)) continue;
                    md.AppendLine($"| {operation} | {cls} | {Name(other)} | {Ratio(mitra.Median, baseline.Median)} | {Extra(mitra.Median, baseline.Median)} | {Ratio(mitra.P95, baseline.P95)} | {Extra(mitra.P95, baseline.P95)} |");
                }
            }
        }

        if (summaries.Length > 0)
        {
            var metrics = new (string Name, Func<SummaryRow, double> Value)[]
            {
                ("İndeks, build sonrası (bayt, mantıksal)", x => x.IndexBytes),
                ("İndeks girdisi, build sonrası", x => x.IndexEntries),
                ("İndeks, mutasyonlar sonrası (bayt, mantıksal)", x => x.FinalIndexBytes),
                ("İndeks girdisi, mutasyonlar sonrası", x => x.FinalIndexEntries),
                ("İstemci vault dizini, build sonrası (bayt)", x => x.ClientStateBytes),
                ("İstemci vault dizini, mutasyonlar sonrası (bayt)", x => x.FinalClientStateBytes),
                ("Algoritma durum dosyası, build sonrası (bayt)", x => x.AlgorithmStateBytes),
                ("Algoritma durum dosyası, mutasyonlar sonrası (bayt)", x => x.FinalAlgorithmStateBytes),
                ("Şifreli belge zarfı (bayt, hesaplanmış)", x => x.EncryptedDocumentBytes)
            };
            md.AppendLine();
            md.AppendLine("## Boyutlar (koşular arası medyan)");
            md.AppendLine();
            md.AppendLine("Mantıksal indeks boyutu PostgreSQL'deki adres + değer bayt toplamıdır; fiziksel disk alanı değildir. Vault dizini algoritma durumuna ek olarak yerel belge kayıtlarını ve anahtar/nonce dosyalarını içerir. Şifreli belge zarfı ölçülmüş MinIO tüketimi değil, hesaplanmış boyuttur.");
            md.AppendLine();
            md.AppendLine("| Ölçüt | " + string.Join(" | ", schemes.Select(Name)) + " |");
            md.AppendLine("|---|" + string.Concat(schemes.Select(_ => "---:|")));
            foreach (var (name, value) in metrics)
                md.AppendLine($"| {name} | " + string.Join(" | ", schemes.Select(s => F(MedianOf(summaries.Where(x => x.Scope.SchemeId == s).Select(value)), 0))) + " |");
            if (schemes.Contains(SchemeIds.Mitra) && schemes.Length > 1)
            {
                md.AppendLine();
                md.AppendLine("| Ölçüt (Mitra / yöntem oranı) | " + string.Join(" | ", schemes.Where(s => s != SchemeIds.Mitra).Select(Name)) + " |");
                md.AppendLine("|---|" + string.Concat(schemes.Where(s => s != SchemeIds.Mitra).Select(_ => "---:|")));
                foreach (var (name, value) in metrics)
                {
                    var mitra = MedianOf(summaries.Where(x => x.Scope.SchemeId == SchemeIds.Mitra).Select(value));
                    md.AppendLine($"| {name} | " + string.Join(" | ", schemes.Where(s => s != SchemeIds.Mitra)
                        .Select(s => Ratio(mitra, MedianOf(summaries.Where(x => x.Scope.SchemeId == s).Select(value))))) + " |");
                }
            }
        }
        return (md.ToString(), csv.ToString());
    }

    private static Stat Compute(IEnumerable<Row> group)
    {
        var rows = group.ToArray();
        var times = rows.Select(r => r.Milliseconds).Order().ToArray();
        var perRun = rows.GroupBy(r => r.Run).Select(g => Median(g.Select(r => r.Milliseconds).Order().ToArray())).Order().ToArray();
        return new(times.Length, Median(times), Percentile(times, 0.95), times[0], times[^1], perRun[0], perRun[^1],
            Median(rows.Select(r => (double)r.RequestBytes).Order().ToArray()),
            Median(rows.Select(r => (double)r.ResponseBytes).Order().ToArray()));
    }

    /// <summary>Median of an ascending list; the mean of the two middle values for an even count.</summary>
    public static double Median(IReadOnlyList<double> sorted)
    {
        var n = sorted.Count;
        if (n == 0) return double.NaN;
        return n % 2 == 1 ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
    }

    /// <summary>Nearest-rank percentile of an ascending list: the value at rank ceil(p·n).</summary>
    public static double Percentile(IReadOnlyList<double> sorted, double p)
    {
        var n = sorted.Count;
        if (n == 0) return double.NaN;
        var rank = (int)Math.Ceiling(p * n - 1e-9);
        return sorted[Math.Clamp(rank, 1, n) - 1];
    }

    private static double MedianOf(IEnumerable<double> values) => Median(values.Order().ToArray());
    private static int Rank(string[] order, string value) { var i = Array.IndexOf(order, value); return i < 0 ? order.Length : i; }
    private static string Name(string scheme) => scheme switch
    {
        SchemeIds.NaiveHmac => "Naive HMAC",
        SchemeIds.Kamara => "Kamara",
        SchemeIds.Mitra => "Mitra",
        _ => scheme
    };
    private static string F(double value, int digits = 2) =>
        double.IsNaN(value) ? "-" : value.ToString("F" + digits, CultureInfo.InvariantCulture);
    private static string C(double value) => value.ToString("R", CultureInfo.InvariantCulture);
    private static string Ratio(double mitra, double other) =>
        double.IsNaN(mitra) || double.IsNaN(other) || other == 0 ? "-" : (mitra / other).ToString("F2", CultureInfo.InvariantCulture) + "×";
    private static string Extra(double mitra, double other) =>
        double.IsNaN(mitra) || double.IsNaN(other) || other == 0 ? "-" : ((mitra / other - 1) * 100).ToString("+0.0;-0.0;0.0", CultureInfo.InvariantCulture) + "%";
}
