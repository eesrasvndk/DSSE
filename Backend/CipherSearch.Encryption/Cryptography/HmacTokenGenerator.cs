using System.Security.Cryptography;
using System.Text;

namespace CipherSearch.Cryptography;

public static class HmacTokenGenerator
{
    public static byte[] Generate(ReadOnlySpan<byte> key, string normalizedKeyword)
    {
        if (key.Length != 32)
            throw new ArgumentException("A 32-byte token key is required.", nameof(key));
        ArgumentNullException.ThrowIfNull(normalizedKeyword);
        if (normalizedKeyword.Length < 2 || normalizedKeyword.Any(c => c is < 'a' or > 'z'))
            throw new ArgumentException("Expected one normalized lowercase keyword.", nameof(normalizedKeyword));
        return HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(normalizedKeyword));
    }
}
