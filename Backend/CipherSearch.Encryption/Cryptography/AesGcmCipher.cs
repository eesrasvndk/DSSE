using System.Security.Cryptography;
using CipherSearch.Contracts;

namespace CipherSearch.Cryptography;

public sealed class AesGcmCipher
{
    public EncryptedEnvelope Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key,
        int keyVersion, ReadOnlySpan<byte> reservedNonce, ReadOnlySpan<byte> associatedData)
    {
        ValidateKey(key);
        if (keyVersion < 1)
            throw new ArgumentOutOfRangeException(nameof(keyVersion));
        if (reservedNonce.Length != 12)
            throw new ArgumentException("A reserved 12-byte nonce is required.", nameof(reservedNonce));
        if (associatedData.IsEmpty)
            throw new ArgumentException("Associated data is required.", nameof(associatedData));

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(reservedNonce, plaintext, ciphertext, tag, associatedData);
        return new EncryptedEnvelope(1, keyVersion, reservedNonce.ToArray(), ciphertext, tag);
    }

    public byte[] Decrypt(EncryptedEnvelope envelope, ReadOnlySpan<byte> key,
        int expectedKeyVersion, ReadOnlySpan<byte> associatedData)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ValidateKey(key);
        if (expectedKeyVersion < 1 || envelope.Version != 1
            || envelope.KeyVersion != expectedKeyVersion
            || envelope.Nonce is not { Length: 12 } || envelope.Tag is not { Length: 16 }
            || envelope.Ciphertext is null || associatedData.IsEmpty)
            throw new CryptographicException("Invalid encrypted envelope.");

        var plaintext = new byte[envelope.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, associatedData);
            return plaintext;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("Encrypted content authentication failed.");
        }
    }

    private static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
            throw new ArgumentException("AES-256 requires a 32-byte key.", nameof(key));
    }
}
