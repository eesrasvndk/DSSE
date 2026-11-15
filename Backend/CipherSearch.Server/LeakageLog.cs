using CipherSearch.Contracts;

namespace CipherSearch.Server;

public sealed class LeakageLog(IConfiguration configuration, ILogger<LeakageLog> logger, IHostEnvironment? environment = null)
{
    private readonly SemaphoreSlim gate = new(1);
    private readonly Queue<(Guid GenerationId, SearchObservation Observation)> recentSearches = new();
    private long sequence;

    public SearchObservation? FindSearch(Guid generationId, Guid searchId)
    {
        lock (recentSearches)
            return recentSearches.FirstOrDefault(e => e.GenerationId == generationId &&
                e.Observation.SearchId == searchId).Observation;
    }

    public async Task Record(IndexScope scope, Guid operationId, string operation, long epoch,
        long requestBytes, long responseBytes, long microseconds, byte[][] tokens,
        byte[][] addresses, Guid[] documentIds, int resultCount)
    {
        if (operation == "search" && environment?.IsDevelopment() == true)
        {
            var observation = new SearchObservation(operationId, scope.SchemeId, epoch, tokens.Length, addresses.Length,
                documentIds.Length, resultCount, tokens.Take(8).Select(Convert.ToHexString).ToArray(),
                addresses.Take(8).Select(Convert.ToHexString).ToArray(), documentIds.Take(8).ToArray());
            lock (recentSearches)
            {
                recentSearches.Enqueue((scope.GenerationId, observation));
                if (recentSearches.Count > 32) recentSearches.Dequeue();
            }
        }
        var path = configuration["Leakage:Path"];
        if (string.IsNullOrWhiteSpace(path)) return;
        var entry = new LeakageEvent(1, scope.GenerationId, Interlocked.Increment(ref sequence),
            DateTimeOffset.UtcNow, scope, operationId, operation, 0, epoch, requestBytes, responseBytes,
            microseconds, tokens, addresses, documentIds, resultCount, 200);
        await gate.WaitAsync();
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            await File.AppendAllTextAsync(path, System.Text.Encoding.UTF8.GetString(Wire.Encode(entry)) + "\n");
        }
        catch (IOException) { logger.LogWarning("Leakage event could not be persisted."); }
        finally { gate.Release(); }
    }
}
