namespace CipherSearch.Contracts;

/// <summary>Stable protocol identifiers; they are not security guarantees.</summary>
public static class SchemeIds
{
    public const string NaiveHmac = "naive-hmac-v2";
    public const string Mitra = "mitra-v2";
    public const string Kamara = "kamara-2012-v1";
}

/// <summary>A server-visible, isolated index generation with one immutable key version.</summary>
public sealed record IndexScope(
    Guid DatasetId, string SchemeId, Guid GenerationId, int KeyVersion);

/// <summary>Binary properties are base64 in the JSON transport.</summary>
public sealed record EncryptedEnvelope(
    int Version, int KeyVersion, byte[] Nonce, byte[] Ciphertext, byte[] Tag);

public sealed record EncryptedDocument(
    Guid DocumentId, long Revision, EncryptedEnvelope Content);

/// <summary>
/// Naive values contain serialized EncryptedEnvelope bytes. Other schemes may use
/// a different opaque encoding; the server must not attempt to decrypt it.
/// </summary>
public sealed record IndexEntry(byte[] Address, byte[] Value);

public sealed record ProtocolMessage(string Kind, int Version, byte[] Payload);

public enum MutationKind { Add, Update, Delete }

/// <summary>Compare-and-swap revision: zero for a new document.</summary>
public sealed record MutationRequest(
    int Version, Guid OperationId, IndexScope Scope, MutationKind Kind,
    Guid DocumentId, long ExpectedRevision,
    EncryptedDocument? Replacement, ProtocolMessage IndexMutation);

public sealed record MutationResponse(
    Guid OperationId, long CommittedRevision, ProtocolMessage SchemeResponse);

// No document identity, revision, operation kind or blob reference in index writes.
public sealed record PrivateIndexWrite(int Version, Guid OperationId, IndexScope Scope, ProtocolMessage Entries);
public sealed record PrivateIndexReceipt(Guid OperationId);
public sealed record OpaqueBlobWrite(IndexScope Scope, Guid BlobId, EncryptedEnvelope Content);
public sealed record OpaqueBlobRead(IndexScope Scope, Guid BlobId);
public sealed record OpaqueBlobReceipt(Guid BlobId);

public sealed record SearchRequest(
    int Version, Guid SearchId, IndexScope Scope, long ExpectedEpoch,
    int Round, ProtocolMessage Message);

public sealed record SearchResponse(
    Guid SearchId, long Epoch, int Round, bool IsFinal,
    ProtocolMessage Message);

public sealed record InitializeRequest(
    int Version, Guid OperationId, IndexScope Scope, ProtocolMessage? Setup = null,
    EncryptedDocument[]? Documents = null);

public sealed record InitializeResponse(IndexScope Scope, long Epoch);

public sealed record ImportRequest(
    int Version, Guid OperationId, IndexScope Scope,
    IReadOnlyList<MutationRequest> Documents);

/// <summary>Exactly one of Result or Error must be present.</summary>
public sealed record ImportItemResponse(
    Guid OperationId, MutationResponse? Result, ApiError? Error);

public sealed record ImportResponse(
    Guid OperationId, IReadOnlyList<ImportItemResponse> Items);

public sealed record GetEncryptedDocumentRequest(
    IndexScope Scope, Guid DocumentId, long Revision);

public sealed record ApiError(string Code, string Message, Guid CorrelationId);

// Baseline payloads. These do not constrain the future schemes' wire formats.
public sealed record NaiveSearchPayload(byte[] Token);
public sealed record NaiveSearchResult(IReadOnlyList<IndexEntry> Entries);
public sealed record NaiveIndexMutation(
    IReadOnlyList<byte[]> RemoveAddresses, IReadOnlyList<IndexEntry> PutEntries);

/// <summary>Server observations only; ground truth belongs in a separate trusted artifact.</summary>
public sealed record LeakageEvent(
    int SchemaVersion, Guid RunId, long EventId, DateTimeOffset TimestampUtc,
    IndexScope Scope, Guid OperationId, string Operation, int Round, long Epoch,
    long RequestBytes, long ResponseBytes, long ElapsedMicroseconds,
    IReadOnlyList<byte[]> ObservedTokensBase64,
    IReadOnlyList<byte[]> ObservedAddressesBase64,
    IReadOnlyList<Guid> ObservedDocumentIds,
    int ReturnedEntryCount, int StatusCode);

public sealed record SearchObservation(Guid SearchId, string SchemeId, long Epoch,
    int TokenCount, int AddressCount, int ObservedDocumentCount, int ReturnedEntryCount,
    string[] TokenSamples, string[] AddressSamples, Guid[] DocumentIdSamples);
