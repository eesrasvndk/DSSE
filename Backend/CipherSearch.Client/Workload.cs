using CipherSearch.Contracts;

namespace CipherSearch.Client;

/// <summary>A trusted-side source document: normalized distinct keywords of Text.</summary>
public sealed record WorkloadDocument(Guid Id, string Text, string[] Words);

/// <summary>
/// One planned mutation. Words are the distinct keywords of the new content (empty for
/// a delete); PreviousWords are those of the document being replaced or removed.
/// </summary>
public sealed record WorkloadStep(int Step, MutationKind Kind, Guid Id, string? Text,
    string[] Words, string[] PreviousWords);

public sealed record WorkloadPlan(WorkloadStep[] Steps, long InitialPairs, long PeakPairs)
{
    /// <summary>
    /// Word-document cells a Kamara index must hold beyond its initial pairs. Deletes
    /// return cells to the free list, so this is the peak live-pair count over the
    /// whole sequence, not the sum of all additions.
    /// </summary>
    public long PeakExtraPairs => Math.Max(0, PeakPairs - InitialPairs);
}

/// <summary>
/// Deterministic add/update/delete sequence shared by every scheme: the same seed and
/// content provider give the same operations, so differences come from the scheme alone.
/// </summary>
public static class WorkloadPlanner
{
    public static WorkloadPlan Plan(IReadOnlyCollection<WorkloadDocument> initial, int mutationCount, int seed,
        Func<int, Guid> newId, Func<int, Random, (string Text, string[] Words)> content)
    {
        if (mutationCount < 3 || mutationCount % 3 != 0)
            throw new ArgumentOutOfRangeException(nameof(mutationCount),
                "Use a positive multiple of 3 so add, update and delete are balanced.");
        var live = initial.ToDictionary(d => d.Id, d => d.Words);
        var pairs = live.Values.Sum(words => (long)words.Length);
        var initialPairs = pairs;
        var peak = pairs;
        var random = new Random(seed);
        var steps = new WorkloadStep[mutationCount];
        for (var step = 0; step < mutationCount; step++)
        {
            var kind = (MutationKind)(step % 3);
            if (kind == MutationKind.Add)
            {
                var id = newId(step);
                var (text, words) = content(step, random);
                if (!live.TryAdd(id, words))
                    throw new InvalidOperationException("Planned document identity already exists.");
                pairs += words.Length;
                steps[step] = new(step, kind, id, text, words, []);
            }
            else
            {
                if (live.Count == 0) throw new InvalidOperationException("No document left to change.");
                var id = live.Keys.Order().ElementAt(random.Next(live.Count));
                var previous = live[id];
                if (kind == MutationKind.Delete)
                {
                    live.Remove(id);
                    pairs -= previous.Length;
                    steps[step] = new(step, kind, id, null, [], previous);
                }
                else
                {
                    var (text, words) = content(step, random);
                    live[id] = words;
                    pairs += words.Length - previous.Length;
                    steps[step] = new(step, kind, id, text, words, previous);
                }
            }
            peak = Math.Max(peak, pairs);
        }
        return new(steps, initialPairs, peak);
    }
}
