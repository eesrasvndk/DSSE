using CipherSearch.Contracts;

namespace CipherSearch.SearchSchemes.Naive;

public sealed class NaiveServerScheme : IServerSearchScheme
{
    public string SchemeId => SchemeIds.NaiveHmac;
    public async ValueTask<ProtocolMessage> ApplyMutationAsync(IndexScope scope, ProtocolMessage mutation,
        IIndexStore store, CancellationToken cancellationToken = default)
    {
        var change = Wire.Read<NaiveIndexMutation>(mutation, "naive.mutate");
        if (change.RemoveAddresses.Any(a => a.Length != 32) || change.PutEntries.Any(e => e.Address.Length != 32))
            throw new ArgumentException("Invalid naive address.");
        await store.DeleteAsync(scope, change.RemoveAddresses, cancellationToken);
        await store.PutAsync(scope, change.PutEntries, cancellationToken);
        return Wire.Message("naive.ack", true);
    }

    public async ValueTask<SearchResponse> SearchAsync(SearchRequest request, IIndexStore store,
        CancellationToken cancellationToken = default)
    {
        var query = Wire.Read<NaiveSearchPayload>(request.Message, "naive.search");
        if (query.Token.Length != 32) throw new ArgumentException("Invalid token.");
        var entries = await store.GetAsync(request.Scope, [query.Token], cancellationToken);
        return new(request.SearchId, request.ExpectedEpoch, 0, true, Wire.Message("naive.results", new NaiveSearchResult(entries)));
    }
}
