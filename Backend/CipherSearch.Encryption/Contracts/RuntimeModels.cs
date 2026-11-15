using System.Text.Json;
using System.Text.Json.Serialization;

namespace CipherSearch.Contracts;

public static class Wire
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };
    public static byte[] Encode<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Json);
    public static T Decode<T>(byte[] value) =>
        JsonSerializer.Deserialize<T>(value, Json) ?? throw new ArgumentException("Empty payload.");
    public static ProtocolMessage Message<T>(string kind, T value) => new(kind, 1, Encode(value));
    public static T Read<T>(ProtocolMessage message, string kind)
    {
        if (message.Version != 1 || message.Kind != kind) throw new ArgumentException("Unsupported message.");
        return Decode<T>(message.Payload);
    }
}

public interface INonceSource
{
    byte[] Reserve(IndexScope scope, string purpose);
}

public sealed record DocumentMatch(Guid DocumentId, long Revision);
public sealed record NaivePendingSearch(byte[] Token);
public sealed record SchemeState(Dictionary<Guid, DocumentMatch> Matches,
    Dictionary<Guid, byte[][]> Addresses);
public sealed record StoredDocument(Guid DocumentId, long Revision, bool Deleted);
public sealed record RuntimeStatus(IndexScope Scope, long Epoch, long IndexBytes, int IndexEntries);
