using CipherSearch.Contracts;
using CipherSearch.Cryptography;
using CipherSearch.SearchSchemes.Naive;
using CipherSearch.SearchSchemes.Mitra;

namespace CipherSearch.Tests;

public sealed class ExecutionMethodsTests
{
    [Fact]
    public async Task NaiveRewritesOneCompleteListAtTheSameTokenWithFreshNonce()
    {
        using var keys = new TestKeys();
        var client = new NaiveClientScheme(keys);
        var scope = new IndexScope(Guid.NewGuid(), client.SchemeId, Guid.NewGuid(), 1);
        var state = await client.InitializeAsync(scope, keys);
        var first = new TrustedDocument(Guid.NewGuid(), 1, ["meeting", "meeting"]);
        var second = new TrustedDocument(Guid.NewGuid(), 1, ["meeting"]);
        var add1 = await client.PrepareMutationAsync(scope, MutationKind.Add, null, first, state, keys);
        var add2 = await client.PrepareMutationAsync(scope, MutationKind.Add, null, second, add1.PendingState, keys);
        var entry1 = Assert.Single(Wire.Read<NaiveIndexMutation>(add1.Message, "naive.mutate").PutEntries);
        var entry2 = Assert.Single(Wire.Read<NaiveIndexMutation>(add2.Message, "naive.mutate").PutEntries);
        var tokenKey = await keys.DeriveKeyAsync(scope, KeyPurposes.SearchToken);
        Assert.Equal(HmacTokenGenerator.Generate(tokenKey, "meeting"), entry1.Address);
        Assert.Equal(entry1.Address, entry2.Address);
        var value1 = Wire.Decode<EncryptedEnvelope>(entry1.Value);
        var value2 = Wire.Decode<EncryptedEnvelope>(entry2.Value);
        Assert.NotEqual(value1.Nonce, value2.Nonce);
        var valueKey = await keys.DeriveKeyAsync(scope, KeyPurposes.IndexValue);
        var clear = new AesGcmCipher().Decrypt(value2, valueKey, 1, AssociatedData.IndexValue(scope, entry2.Address));
        Assert.True(new[] { first.DocumentId, second.DocumentId }.ToHashSet().SetEquals(
            Wire.Decode<DocumentMatch[]>(clear).Select(m => m.DocumentId)));
        var server = new NaiveServerScheme();
        var store = new TestIndex(scope);
        await server.ApplyMutationAsync(scope, add1.Message, store);
        await server.ApplyMutationAsync(scope, add2.Message, store);
        Assert.Single(store.Rows);
        var deleted = await client.PrepareMutationAsync(scope, MutationKind.Delete, first, null, add2.PendingState, keys);
        await server.ApplyMutationAsync(scope, deleted.Message, store);
        var query = await client.BeginSearchAsync(scope, "meeting", deleted.PendingState, keys);
        var response = await server.SearchAsync(new(1, Guid.NewGuid(), scope, 0, 0, query.NextMessage!), store);
        var result = await client.ContinueSearchAsync(scope, response, query.PendingState, keys);
        Assert.Equal(second.DocumentId, Assert.Single(result.CompletedDocumentIds!));
    }

    [Fact]
    public async Task MitraUpdatesOnlyKeywordDifferenceAndKeepsCurrentRevision()
    {
        using var keys = new TestKeys();
        var client = new MitraClientScheme();
        var server = new MitraServerScheme();
        var scope = new IndexScope(Guid.NewGuid(), client.SchemeId, Guid.NewGuid(), 1);
        var store = new TestIndex(scope);
        var first = new TrustedDocument(Guid.NewGuid(), 1, ["meeting", "project"]);
        var second = first with { Revision = 2, Keywords = ["meeting", "salary"] };
        var state = await client.InitializeAsync(scope, keys);
        var add = await client.PrepareMutationAsync(scope, MutationKind.Add, null, first, state, keys);
        await server.ApplyMutationAsync(scope, add.Message, store);
        var update = await client.PrepareMutationAsync(scope, MutationKind.Update, first, second, add.PendingState, keys);
        Assert.Equal(2, Wire.Read<IndexEntry[]>(update.Message, "mitra.mutate").Length);
        var counters = Wire.Decode<MitraState>(update.PendingState.Payload).Counters;
        Assert.Equal(1, counters["meeting"]);
        Assert.Equal(2, counters["project"]);
        Assert.Equal(1, counters["salary"]);
        await server.ApplyMutationAsync(scope, update.Message, store);
        var unchanged = await client.PrepareMutationAsync(scope, MutationKind.Update, second,
            second with { Revision = 3 }, update.PendingState, keys);
        Assert.Empty(Wire.Read<IndexEntry[]>(unchanged.Message, "mitra.mutate"));
        await server.ApplyMutationAsync(scope, unchanged.Message, store);
        var query = await client.BeginSearchAsync(scope, "meeting", unchanged.PendingState, keys);
        var response = await server.SearchAsync(new(1, Guid.NewGuid(), scope, 0, 0, query.NextMessage!), store);
        var result = await client.ContinueSearchAsync(scope, response, query.PendingState, keys);
        Assert.Equal(3, Assert.Single(Wire.Decode<SchemeState>(result.PendingState.Payload).Matches.Values).Revision);
    }

    [Theory]
    [InlineData("basic-dynamic-v1")]
    [InlineData("naive-hmac-v1")]
    [InlineData("mitra-v1")]
    public void RemovedAndLegacySchemesCannotDeriveKeys(string scheme) =>
        Assert.Throws<ArgumentException>(() => KeyDerivation.Derive(new byte[32],
            new(Guid.NewGuid(), scheme, Guid.NewGuid(), 1), KeyPurposes.Document));
}
