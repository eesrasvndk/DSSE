using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using CipherSearch.Contracts;

namespace CipherSearch.Cryptography;

public static class AssociatedData
{
    public static byte[] Document(IndexScope scope, Guid documentId, long revision)
    {
        if (documentId == Guid.Empty || revision < 1)
            throw new ArgumentException("Invalid document identity or revision.");
        return Encode("CipherSearch/document/v1", scope,
            documentId.ToString("D"), revision.ToString(CultureInfo.InvariantCulture));
    }

    public static byte[] IndexValue(IndexScope scope, ReadOnlySpan<byte> address)
    {
        if (address.IsEmpty)
            throw new ArgumentException("An index address is required.", nameof(address));
        return Encode("CipherSearch/index/v1", scope, Convert.ToHexString(address).ToLowerInvariant());
    }

    public static byte[] ClientState(IndexScope scope, long revision)
    {
        if (revision < 1)
            throw new ArgumentOutOfRangeException(nameof(revision));
        return Encode("CipherSearch/state/v1", scope, revision.ToString(CultureInfo.InvariantCulture));
    }

    private static byte[] Encode(string domain, IndexScope scope, params string[] suffix)
    {
        KeyDerivation.ValidateScope(scope);
        string[] fields = [domain, scope.DatasetId.ToString("D"), scope.SchemeId,
            scope.GenerationId.ToString("D"), scope.KeyVersion.ToString(CultureInfo.InvariantCulture),
            .. suffix];
        using var output = new MemoryStream();
        Span<byte> length = stackalloc byte[4];
        foreach (var field in fields)
        {
            var bytes = Encoding.UTF8.GetBytes(field);
            BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
            output.Write(length);
            output.Write(bytes);
        }
        return output.ToArray();
    }
}
