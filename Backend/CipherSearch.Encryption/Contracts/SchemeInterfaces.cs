namespace CipherSearch.Contracts;

/// <summary>
/// TRUSTED ONLY. Never serialize this model into an untrusted server request.
/// Tokens are unique normalized keywords, not cryptographic tokens.
/// </summary>
public sealed record TrustedDocument(
    Guid DocumentId, long Revision, IReadOnlyList<string> Keywords);

/// <summary>Opaque local state. Persist encrypted on the trusted side.</summary>
public sealed record ClientState(int Version, byte[] Payload);

/// <summary>
/// Keys belong exclusively to the trusted process. Implementations must redact logs
/// and dispose/clear temporary key buffers; this interface is not a wire DTO.
/// </summary>
public interface IClientKeyProvider
{
    ValueTask<byte[]> DeriveKeyAsync(
        IndexScope scope, string purpose, CancellationToken cancellationToken = default);
}

public sealed record PreparedMutation(
    ProtocolMessage Message, ClientState PendingState);

public sealed record ClientSearchStep(
    ProtocolMessage? NextMessage, ClientState PendingState,
    IReadOnlyList<Guid>? CompletedDocumentIds);

/// <summary>
/// TRUSTED ONLY. No implementation of this interface may be registered in Server.
/// Persist pending state and OperationId before sending; commit after acknowledgment.
/// </summary>
public interface IClientSearchScheme
{
    string SchemeId { get; }

    ValueTask<ClientState> InitializeAsync(
        IndexScope scope, IClientKeyProvider keys,
        CancellationToken cancellationToken = default);

    ValueTask<PreparedMutation> PrepareMutationAsync(
        IndexScope scope, MutationKind kind,
        TrustedDocument? previous, TrustedDocument? replacement,
        ClientState state, IClientKeyProvider keys,
        CancellationToken cancellationToken = default);

    ValueTask<ClientSearchStep> BeginSearchAsync(
        IndexScope scope, string normalizedKeyword, ClientState state,
        IClientKeyProvider keys, CancellationToken cancellationToken = default);

    ValueTask<ClientSearchStep> ContinueSearchAsync(
        IndexScope scope, SearchResponse response, ClientState pendingState,
        IClientKeyProvider keys, CancellationToken cancellationToken = default);
}

/// <summary>
/// UNTRUSTED SIDE. Receives opaque messages only. The host provides transaction,
/// revision, epoch, replay and serialization checks described in the API design.
/// </summary>
public interface IServerSearchScheme
{
    string SchemeId { get; }

    ValueTask<ProtocolMessage> ApplyMutationAsync(
        IndexScope scope, ProtocolMessage mutation, IIndexStore store,
        CancellationToken cancellationToken = default);

    ValueTask<SearchResponse> SearchAsync(
        SearchRequest request, IIndexStore store,
        CancellationToken cancellationToken = default);
}

/// <summary>One transaction-scoped, scope-isolated server storage session.</summary>
public interface IIndexStore
{
    ValueTask<IReadOnlyList<IndexEntry>> FindByPrefixAsync(
        IndexScope scope, byte[] prefix, CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<IndexEntry>> GetAsync(
        IndexScope scope, IReadOnlyList<byte[]> addresses,
        CancellationToken cancellationToken = default);

    ValueTask PutAsync(
        IndexScope scope, IReadOnlyList<IndexEntry> entries,
        CancellationToken cancellationToken = default);

    ValueTask DeleteAsync(
        IndexScope scope, IReadOnlyList<byte[]> addresses,
        CancellationToken cancellationToken = default);
}

public interface IEncryptedDocumentStore
{
    ValueTask PutAsync(
        IndexScope scope, EncryptedDocument document,
        CancellationToken cancellationToken = default);

    ValueTask<EncryptedDocument> GetAsync(
        GetEncryptedDocumentRequest request,
        CancellationToken cancellationToken = default);

    ValueTask DeleteAsync(
        GetEncryptedDocumentRequest request,
        CancellationToken cancellationToken = default);
}
