using CipherSearch.Contracts;

namespace CipherSearch.SearchSchemes.Mitra;

public sealed class MitraServerScheme : IServerSearchScheme
{
    public string SchemeId => SchemeIds.Mitra;
    public async ValueTask<ProtocolMessage> ApplyMutationAsync(IndexScope scope, ProtocolMessage mutation,
        IIndexStore store, CancellationToken cancellationToken = default)
    {
        var entries = Wire.Read<IndexEntry[]>(mutation, "mitra.mutate");
        if (entries.Any(e => e.Address.Length != 32 || e.Value.Length != 17)
            || entries.Select(e => Convert.ToHexString(e.Address)).Distinct().Count() != entries.Length)
            throw new ArgumentException("Invalid Mitra mutation.");
        if ((await store.GetAsync(scope, entries.Select(e => e.Address).ToArray(), cancellationToken)).Count != 0)
            throw new InvalidOperationException("Mitra address reuse; restore the correct client state.");
        await store.PutAsync(scope, entries, cancellationToken);
        return Wire.Message("mitra.ack", true);
    }

    public async ValueTask<SearchResponse> SearchAsync(SearchRequest request, IIndexStore store,
        CancellationToken cancellationToken = default)
    {
        var query = Wire.Read<MitraSearch>(request.Message, "mitra.search");
        if (query.Addresses.Any(a => a.Length != 32)) throw new ArgumentException("Invalid Mitra address.");
        var entries = await store.GetAsync(request.Scope, query.Addresses, cancellationToken);
        return new(request.SearchId, request.ExpectedEpoch, 0, true, Wire.Message("mitra.results", new MitraResults(entries)));
    }
}
