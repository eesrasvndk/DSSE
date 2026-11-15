using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using CipherSearch.Contracts;

namespace CipherSearch.Cryptography;

public static class KeyPurposes
{
    public const string Document = "document";
    public const string IndexValue = "index-value";
    public const string SearchToken = "search-token";
    public const string ClientState = "client-state";
}

public static class KeyDerivation
{
    public static byte[] Derive(ReadOnlySpan<byte> masterKey, IndexScope scope, string purpose)
    {
        if (masterKey.Length != 32)
            throw new ArgumentException("A 32-byte master key is required.", nameof(masterKey));
        ValidateScope(scope);
        if (purpose is not (KeyPurposes.Document or KeyPurposes.IndexValue
            or KeyPurposes.SearchToken or KeyPurposes.ClientState))
            throw new ArgumentException("Unknown key purpose.", nameof(purpose));

        var info = $"CipherSearch/v1|{scope.DatasetId:D}|{scope.SchemeId}|{scope.GenerationId:D}|"
            + $"{scope.KeyVersion.ToString(CultureInfo.InvariantCulture)}|{purpose}";
        var output = new byte[32];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, output,
            Encoding.UTF8.GetBytes("CipherSearch/HKDF/v1"), Encoding.UTF8.GetBytes(info));
        return output;
    }

    internal static void ValidateScope(IndexScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (scope.DatasetId == Guid.Empty || scope.GenerationId == Guid.Empty || scope.KeyVersion < 1)
            throw new ArgumentException("Invalid index scope.", nameof(scope));
        if (scope.SchemeId is not (SchemeIds.NaiveHmac or SchemeIds.Mitra or SchemeIds.Kamara))
            throw new ArgumentException("Unknown scheme.", nameof(scope));
    }
}
