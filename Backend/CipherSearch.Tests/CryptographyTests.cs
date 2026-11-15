using System.Security.Cryptography;
using System.Text;
using CipherSearch.Contracts;
using CipherSearch.Cryptography;

namespace CipherSearch.Tests;

public class CryptographyTests
{
    private static readonly IndexScope Scope = new(
        Guid.Parse("10101010-1010-1010-1010-101010101010"),
        SchemeIds.NaiveHmac, Guid.Parse("20202020-2020-2020-2020-202020202020"), 1);
    private static readonly Guid DocumentId = Guid.Parse("30303030-3030-3030-3030-303030303030");

    [Theory]
    [InlineData("")]
    [InlineData("Meeting tomorrow.")]
    [InlineData("Türkçe içerik: şifreleme 🔒")]
    public void DocumentRoundTrip(string text)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes(text);
        var aad = AssociatedData.Document(Scope, DocumentId, 1);
        var cipher = new AesGcmCipher();
        var envelope = cipher.Encrypt(plaintext, key, 1, RandomNumberGenerator.GetBytes(12), aad);

        Assert.Equal(plaintext, cipher.Decrypt(envelope, key, 1, aad));
        Assert.Equal(12, envelope.Nonce.Length);
        Assert.Equal(16, envelope.Tag.Length);
    }

    [Theory]
    [InlineData("ciphertext")]
    [InlineData("tag")]
    [InlineData("nonce")]
    [InlineData("key")]
    [InlineData("document")]
    [InlineData("revision")]
    [InlineData("scope")]
    public void TamperingOrDifferentContextIsRejected(string change)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var aad = AssociatedData.Document(Scope, DocumentId, 1);
        var cipher = new AesGcmCipher();
        var envelope = cipher.Encrypt("content"u8, key, 1, RandomNumberGenerator.GetBytes(12), aad);
        switch (change)
        {
            case "ciphertext": envelope.Ciphertext[0] ^= 1; break;
            case "tag": envelope.Tag[0] ^= 1; break;
            case "nonce": envelope.Nonce[0] ^= 1; break;
            case "key": key[0] ^= 1; break;
            case "document": aad = AssociatedData.Document(Scope, Guid.NewGuid(), 1); break;
            case "revision": aad = AssociatedData.Document(Scope, DocumentId, 2); break;
            case "scope": aad = AssociatedData.Document(Scope with { DatasetId = Guid.NewGuid() }, DocumentId, 1); break;
        }
        Assert.Throws<CryptographicException>(() => cipher.Decrypt(envelope, key, 1, aad));
    }

    [Fact]
    public void Aes256MatchesKnownGcmVector()
    {
        var cipher = new AesGcmCipher();
        var key = Convert.FromHexString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        var nonce = Convert.FromHexString("cafebabefacedbaddecaf888");
        var aad = Convert.FromHexString("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        var plaintext = Convert.FromHexString(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        var envelope = cipher.Encrypt(plaintext, key, 1, nonce, aad);
        Assert.Equal(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            Convert.ToHexString(envelope.Ciphertext).ToLowerInvariant());
        Assert.Equal("76fc6ece0f4e1768cddf8853bb2d551b",
            Convert.ToHexString(envelope.Tag).ToLowerInvariant());
    }

    [Fact]
    public void KeyDerivationSeparatesPurposesAndScopes()
    {
        var master = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var document = KeyDerivation.Derive(master, Scope, KeyPurposes.Document);
        Assert.Equal(document, KeyDerivation.Derive(master, Scope, KeyPurposes.Document));
        foreach (var purpose in new[] { KeyPurposes.IndexValue, KeyPurposes.SearchToken, KeyPurposes.ClientState })
            Assert.False(document.SequenceEqual(KeyDerivation.Derive(master, Scope, purpose)));
        foreach (var other in new[] {
            Scope with { DatasetId = Guid.NewGuid() },
            Scope with { GenerationId = Guid.NewGuid() },
            Scope with { KeyVersion = 2 },
            Scope with { SchemeId = SchemeIds.Mitra } })
            Assert.False(document.SequenceEqual(KeyDerivation.Derive(master, other, KeyPurposes.Document)));
    }

    [Fact]
    public void HkdfMatchesIndependentExtractAndExpand()
    {
        var master = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var salt = Encoding.UTF8.GetBytes("CipherSearch/HKDF/v1");
        var info = Encoding.UTF8.GetBytes(
            "CipherSearch/v1|10101010-1010-1010-1010-101010101010|naive-hmac-v2|" +
            "20202020-2020-2020-2020-202020202020|1|document");
        var prk = HMACSHA256.HashData(salt, master);
        byte[] expandInput = [.. info, 1];
        var expected = HMACSHA256.HashData(prk, expandInput);
        Assert.Equal(expected, KeyDerivation.Derive(master, Scope, KeyPurposes.Document));
    }

    [Fact]
    public void TokenMatchesHmacAndChangesWithKeyOrKeyword()
    {
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var token = HmacTokenGenerator.Generate(key, "meeting");
        Assert.Equal(HMACSHA256.HashData(key, "meeting"u8), token);
        Assert.Equal(token, HmacTokenGenerator.Generate(key, "meeting"));
        Assert.False(token.SequenceEqual(HmacTokenGenerator.Generate(key, "project")));
        key[0] ^= 1;
        Assert.False(token.SequenceEqual(HmacTokenGenerator.Generate(key, "meeting")));
    }

    [Theory]
    [InlineData("")]
    [InlineData("Meeting")]
    [InlineData("two words")]
    [InlineData("123")]
    [InlineData("a")]
    public void TokenRejectsUnnormalizedInput(string keyword) =>
        Assert.Throws<ArgumentException>(() => HmacTokenGenerator.Generate(new byte[32], keyword));

    [Fact]
    public void EnvelopeValidationRejectsUnknownVersionsAndMalformedFields()
    {
        var cipher = new AesGcmCipher();
        var key = new byte[32];
        var aad = AssociatedData.Document(Scope, DocumentId, 1);
        var envelope = cipher.Encrypt("test"u8, key, 1, new byte[12], aad);
        foreach (var invalid in new[] {
            envelope with { Version = 2 }, envelope with { KeyVersion = 2 },
            envelope with { Nonce = new byte[11] }, envelope with { Tag = new byte[15] } })
            Assert.Throws<CryptographicException>(() => cipher.Decrypt(invalid, key, 1, aad));
        Assert.Throws<ArgumentException>(() => cipher.Encrypt("test"u8, new byte[16], 1, new byte[12], aad));
        Assert.Throws<ArgumentException>(() => KeyDerivation.Derive(key, Scope, "unknown"));
        Assert.Throws<ArgumentException>(() => KeyDerivation.Derive(key, Scope with { GenerationId = Guid.Empty }, KeyPurposes.Document));
    }
}
