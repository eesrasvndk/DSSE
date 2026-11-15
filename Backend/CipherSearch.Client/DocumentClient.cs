using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using CipherSearch.Contracts;
using CipherSearch.Cryptography;
using CipherSearch.SearchSchemes.Naive;
using CipherSearch.SearchSchemes.Mitra;
using CipherSearch.SearchSchemes.Kamara;

namespace CipherSearch.Client;

public sealed record LocalDocument(Guid DocumentId, long Revision, bool Deleted,
    string[] Keywords, ClientState SchemeState, Guid? BlobId = null);
public sealed record PendingOperation(MutationRequest? Request, LocalDocument? Next, ClientState? GlobalState = null);

public sealed record PrivateJournal(PrivatePending? Operation);
public sealed record PrivatePending(PrivateIndexWrite Write, LocalDocument Next, ClientState State, OpaqueBlobWrite? Blob);
internal sealed record KamaraCollectionSetup(InitializeRequest Request, ClientState State, LocalDocument[] Documents);
internal sealed record KamaraSetupJournal(KamaraCollectionSetup? Pending);

[SupportedOSPlatform("windows")]
public sealed class DocumentClient(HttpClient http, IndexScope scope, LocalVault vault, int kamaraCapacity = 16_384)
{
    private readonly IClientSearchScheme scheme = scope.SchemeId switch
    {
        SchemeIds.NaiveHmac => new NaiveClientScheme(vault),
        SchemeIds.Mitra => new MitraClientScheme(),
        SchemeIds.Kamara => new KamaraClientScheme(),
        _ => throw new ArgumentException("Unsupported scheme.")
    };
    private readonly SemaphoreSlim gate = new(1);
    public long RequestBytes { get; private set; }
    public long ResponseBytes { get; private set; }

    public static IndexScope? ReadSavedScope(LocalVault vault) => vault.Exists("scope")
        ? vault.Load<IndexScope>("scope")
        : vault.Exists("kamara-collection") ? vault.Load<KamaraSetupJournal>("kamara-collection").Pending?.Request.Scope : null;

    public async Task Initialize(CancellationToken ct = default)
    {
        if (await RecoverKamaraSetup(ct)) return;
        if (vault.Exists("scope") && vault.Load<IndexScope>("scope") != scope)
            throw new InvalidOperationException("Vault belongs to another scope.");
        var existing = vault.Exists("scope");
        if (scope.SchemeId == SchemeIds.Kamara && !vault.Exists("kamara"))
        {
            if (existing) throw new InvalidOperationException("Missing Kamara state; create a fresh generation.");
            if (!vault.Exists("kamara-setup"))
                vault.Save("kamara-setup", await ((KamaraClientScheme)scheme).PrepareSetupAsync(
                    scope, [], kamaraCapacity, kamaraCapacity, vault, ct));
            vault.Save("kamara", vault.Load<PreparedMutation>("kamara-setup").PendingState);
        }
        if (scope.SchemeId == SchemeIds.NaiveHmac && !vault.Exists("naive"))
        {
            if (existing) throw new InvalidOperationException("Missing Naive posting lists; create a fresh generation.");
            vault.Save("naive", await scheme.InitializeAsync(scope, vault, ct));
        }
        if (scope.SchemeId == SchemeIds.Mitra && !vault.Exists("mitra"))
        {
            if (existing) throw new InvalidOperationException("Missing Mitra counters; refusing to reuse addresses.");
            vault.Save("mitra", await scheme.InitializeAsync(scope, vault, ct));
        }
        if (scope.SchemeId == SchemeIds.Mitra)
        {
            if (existing && !vault.Exists("mitra-wire-v2"))
                throw new InvalidOperationException("Legacy Mitra vault: create a fresh generation; past leakage cannot be undone.");
            vault.Save("mitra-wire-v2", true);
        }
        vault.Save("scope", scope);
        var setup = scope.SchemeId == SchemeIds.Kamara && !vault.Exists("kamara-setup-committed")
            ? vault.Load<PreparedMutation>("kamara-setup").Message : null;
        await Send<InitializeResponse>(HttpMethod.Post, "api/v1/indexes", new InitializeRequest(1, Guid.NewGuid(), scope, setup), ct);
        if (scope.SchemeId == SchemeIds.Kamara) vault.Save("kamara-setup-committed", true);
        await Recover(ct);
    }

    public async Task InitializeKamaraCollection(IReadOnlyList<(Guid Id, string Text)> documents,
        int capacity, int freeSlots, CancellationToken ct = default)
    {
        if (scheme is not KamaraClientScheme kamara || documents.Count == 0)
            throw new ArgumentException("A nonempty Kamara initial collection is required.");
        if (await RecoverKamaraSetup(ct)) return;
        if (vault.Exists("scope") || vault.Exists("kamara-setup") || vault.Exists("kamara"))
            throw new InvalidOperationException("Initial collection requires a fresh vault.");
        var trusted = documents.Select(d => new TrustedDocument(d.Id, 1,
            TextNormalizer.Tokenize(d.Text).Distinct(StringComparer.Ordinal).ToArray())).ToArray();
        if (trusted.Sum(d => (long)d.Keywords.Count) + freeSlots > capacity)
            throw new ArgumentException("Kamara setup capacity cannot hold the initial collection and free slots.");
        var prepared = await kamara.PrepareSetupAsync(scope, trusted, capacity, freeSlots, vault, ct);
        var encrypted = new EncryptedDocument[documents.Count];
        var local = new LocalDocument[documents.Count];
        for (var i = 0; i < documents.Count; i++)
        {
            var doc = documents[i];
            encrypted[i] = await EncryptDocument(doc.Id, 1, doc.Text, ct);
            local[i] = new(doc.Id, 1, false, trusted[i].Keywords.ToArray(), new(1, []));
        }
        var request = new InitializeRequest(1, Guid.NewGuid(), scope, prepared.Message, encrypted);
        vault.Save("kamara-collection", new KamaraSetupJournal(new(request, prepared.PendingState, local)));
        await RecoverKamaraSetup(ct);
    }

    private async Task<bool> RecoverKamaraSetup(CancellationToken ct)
    {
        if (scheme is not KamaraClientScheme || !vault.Exists("kamara-collection")) return false;
        var pending = vault.Load<KamaraSetupJournal>("kamara-collection").Pending;
        if (pending is null) return false;
        if (pending.Request.Scope != scope) throw new InvalidOperationException("Kamara setup scope mismatch.");
        var response = await Send<InitializeResponse>(HttpMethod.Post, "api/v1/indexes", pending.Request, ct);
        if (response.Scope != scope || response.Epoch != pending.Documents.Length)
            throw new InvalidOperationException("Unexpected initial collection receipt.");
        foreach (var doc in pending.Documents) vault.Save($"doc-{doc.DocumentId:N}", doc);
        vault.Save("kamara", pending.State);
        vault.Save("scope", scope);
        vault.Save("kamara-setup-committed", true);
        vault.Save("kamara-collection", new KamaraSetupJournal(null));
        return true;
    }

    public Task<RuntimeStatus> Status(CancellationToken ct = default) =>
        Send<RuntimeStatus>(HttpMethod.Post, "api/v1/indexes/status", scope, ct);

    public async Task Recover(CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try { await RecoverCore(ct); }
        finally { gate.Release(); }
    }

    private async Task RecoverCore(CancellationToken ct)
    {
        if (scope.SchemeId == SchemeIds.Mitra)
        {
            if (!vault.Exists("private-pending")) return;
            var operation = vault.Load<PrivateJournal>("private-pending").Operation;
            if (operation is null) return;
            if (operation.Blob is not null)
            {
                var stored = await Send<OpaqueBlobReceipt>(HttpMethod.Post, "api/v1/opaque-blobs", operation.Blob, ct);
                if (stored.BlobId != operation.Blob.BlobId) throw new InvalidOperationException("Unexpected blob receipt.");
            }
            var receipt = await Send<PrivateIndexReceipt>(HttpMethod.Post, "api/v1/private-index-writes", operation.Write, ct);
            if (receipt.OperationId != operation.Write.OperationId) throw new InvalidOperationException("Unexpected index receipt.");
            vault.Save($"doc-{operation.Next.DocumentId:N}", operation.Next);
            vault.Save("mitra", operation.State);
            vault.Save("private-pending", new PrivateJournal(null));
            return;
        }
        if (!vault.Exists("pending")) return;
        var pending = vault.Load<PendingOperation>("pending");
        if (pending.Request is null) return;
        var request = pending.Request;
        var (method, path) = request.Kind switch
        {
            MutationKind.Add => (HttpMethod.Post, "api/v1/documents"),
            MutationKind.Update => (HttpMethod.Put, $"api/v1/documents/{request.DocumentId}"),
            _ => (HttpMethod.Post, $"api/v1/documents/{request.DocumentId}/delete")
        };
        MutationResponse response;
        try { response = await Send<MutationResponse>(method, path, request, ct); }
        catch (HttpRequestException ex) when (scope.SchemeId == SchemeIds.Kamara &&
            ex.StatusCode == System.Net.HttpStatusCode.UnprocessableEntity)
        {
            // The server rejected this operation before committing index changes.
            vault.Save("pending", new PendingOperation(null, null));
            throw new KamaraCapacityException();
        }
        if (response.OperationId != request.OperationId || response.CommittedRevision != request.ExpectedRevision + 1)
            throw new InvalidOperationException("Unexpected mutation response.");
        vault.Save($"doc-{request.DocumentId:N}", pending.Next ?? throw new InvalidOperationException("Pending state missing."));
        if (pending.GlobalState is not null) vault.Save(scope.SchemeId == SchemeIds.Kamara ? "kamara" : "naive", pending.GlobalState);
        vault.Save("pending", new PendingOperation(null, null));
    }

    public async Task Mutate(MutationKind kind, Guid id, string? text, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            await RecoverCore(ct);
            var name = $"doc-{id:N}";
            var previous = vault.Exists(name) ? vault.Load<LocalDocument>(name) : null;
            if (kind == MutationKind.Add ? previous is { Deleted: false } : previous is null or { Deleted: true })
                throw new InvalidOperationException("Local document state conflict.");
            var revision = checked((previous?.Revision ?? 0) + 1);
            var words = kind == MutationKind.Delete ? [] : TextNormalizer.Tokenize(text ?? throw new ArgumentNullException(nameof(text)))
                .Distinct(StringComparer.Ordinal).ToArray();
            EncryptedDocument? replacement = null;
            if (kind != MutationKind.Delete)
                replacement = await EncryptDocument(id, revision, text!, ct);
            var state = scope.SchemeId == SchemeIds.Mitra ? vault.Load<ClientState>("mitra")
                : vault.Load<ClientState>(scope.SchemeId == SchemeIds.Kamara ? "kamara" : "naive");
            var prepared = await scheme.PrepareMutationAsync(scope, kind,
                previous is { Deleted: false } ? new(id, previous.Revision, previous.Keywords) : null,
                kind == MutationKind.Delete ? null : new(id, revision, words), state, vault, ct);
            var request = new MutationRequest(1, Guid.NewGuid(), scope, kind, id, previous?.Revision ?? 0, replacement, prepared.Message);
            var mitra = scope.SchemeId == SchemeIds.Mitra;
            var next = new LocalDocument(id, revision, kind == MutationKind.Delete, words,
                new ClientState(1, Wire.Encode(new SchemeState([], []))));
            if (mitra)
            {
                var blobId = replacement is null ? (Guid?)null : Guid.NewGuid();
                next = next with { BlobId = blobId };
                var blob = replacement is null ? null : new OpaqueBlobWrite(scope, blobId!.Value, replacement.Content);
                vault.Save("private-pending", new PrivateJournal(new PrivatePending(
                    new(1, Guid.NewGuid(), scope, prepared.Message), next, prepared.PendingState, blob)));
                await RecoverCore(ct);
                return;
            }
            // Commit the complete posting-list state only after the mutation receipt; replay is idempotent.
            vault.Save("pending", new PendingOperation(request, next, prepared.PendingState));
            await RecoverCore(ct);
        }
        finally { gate.Release(); }
    }

    private async Task<EncryptedDocument> EncryptDocument(Guid id, long revision, string text, CancellationToken ct)
    {
        var key = await vault.DeriveKeyAsync(scope, KeyPurposes.Document, ct);
        var plain = Encoding.UTF8.GetBytes(text);
        try
        {
            return new(id, revision, new AesGcmCipher().Encrypt(plain, key, scope.KeyVersion,
                vault.Reserve(scope, KeyPurposes.Document), AssociatedData.Document(scope, id, revision)));
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(plain); }
    }

    public async Task<IReadOnlyList<DocumentMatch>> Search(string keyword, CancellationToken ct = default, Guid? searchId = null)
    {
        await gate.WaitAsync(ct);
        try
        {
            await RecoverCore(ct);
            var state = scope.SchemeId == SchemeIds.Mitra ? vault.Load<ClientState>("mitra")
                : vault.Load<ClientState>(scope.SchemeId == SchemeIds.Kamara ? "kamara" : "naive");
            var started = await scheme.BeginSearchAsync(scope, TextNormalizer.Query(keyword), state, vault, ct);
            var status = await Send<InitializeResponse>(HttpMethod.Post, "api/v1/indexes/epoch", scope, ct);
            var id = searchId ?? Guid.NewGuid();
            var response = await Send<SearchResponse>(HttpMethod.Post, "api/v1/searches",
                new SearchRequest(1, id, scope, status.Epoch, 0, started.NextMessage!), ct);
            if (response.SearchId != id || response.Epoch != status.Epoch || response.Round != 0 || !response.IsFinal)
                throw new InvalidOperationException("Unexpected search response.");
            var completed = await scheme.ContinueSearchAsync(scope, response, started.PendingState, vault, ct);
            var matches = Wire.Decode<SchemeState>(completed.PendingState.Payload).Matches.Values.ToArray();
            foreach (var match in matches)
            {
                var local = vault.Load<LocalDocument>($"doc-{match.DocumentId:N}");
                if (local.Deleted || local.Revision != match.Revision) throw new InvalidOperationException("Stale search result.");
            }
            return matches;
        }
        finally { gate.Release(); }
    }

    public async Task<SearchObservation?> ObserveSearch(Guid searchId, CancellationToken ct = default)
    {
        using var response = await http.GetAsync($"api/v1/diagnostics/searches/{scope.GenerationId}/{searchId}", ct);
        if (!response.IsSuccessStatusCode) return null;
        var observation = Wire.Decode<SearchObservation>(await response.Content.ReadAsByteArrayAsync(ct));
        return observation.SearchId == searchId && observation.SchemeId == scope.SchemeId ? observation : null;
    }

    public async Task<string> Read(DocumentMatch match, CancellationToken ct = default)
    {
        EncryptedDocument document;
        if (scope.SchemeId == SchemeIds.Mitra)
        {
            var local = vault.Load<LocalDocument>($"doc-{match.DocumentId:N}");
            if (local.Deleted || local.Revision != match.Revision || local.BlobId is null)
                throw new InvalidOperationException("Document is not current.");
            var content = await Send<EncryptedEnvelope>(HttpMethod.Post, "api/v1/opaque-blobs/read",
                new OpaqueBlobRead(scope, local.BlobId.Value), ct);
            document = new(match.DocumentId, match.Revision, content);
        }
        else document = await Send<EncryptedDocument>(HttpMethod.Post, "api/v1/documents/read",
            new GetEncryptedDocumentRequest(scope, match.DocumentId, match.Revision), ct);
        if (document.DocumentId != match.DocumentId || document.Revision != match.Revision)
            throw new InvalidOperationException("Document context mismatch.");
        var key = await vault.DeriveKeyAsync(scope, KeyPurposes.Document, ct);
        byte[]? plaintext = null;
        try
        {
            plaintext = new AesGcmCipher().Decrypt(document.Content, key, scope.KeyVersion,
                AssociatedData.Document(scope, match.DocumentId, match.Revision));
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private async Task<T> Send<T>(HttpMethod method, string path, object payload, CancellationToken ct)
    {
        var bytes = Wire.Encode(payload);
        using var request = new HttpRequestMessage(method, path) { Content = new ByteArrayContent(bytes) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        RequestBytes += bytes.Length;
        using var response = await http.SendAsync(request, ct);
        var result = await response.Content.ReadAsByteArrayAsync(ct);
        ResponseBytes += result.Length;
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"CipherSearch returned HTTP {(int)response.StatusCode}: {Encoding.UTF8.GetString(result)}",
                null, response.StatusCode);
        return Wire.Decode<T>(result);
    }
}
