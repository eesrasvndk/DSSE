using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CipherSearch.Contracts;
using CipherSearch.Cryptography;

namespace CipherSearch.SearchSchemes.Kamara;

// KPR, CCS 2012, Figures 2-3. Only these opaque DTOs cross the trust boundary.
public sealed record KamaraSearchToken(byte[] F, byte[] G, byte[] P);
public sealed record KamaraAddWord(byte[] F, byte[] G, byte[] SearchNode, byte[] DeletionNode);
public sealed record KamaraAddToken(byte[] F, byte[] G, KamaraAddWord[] Words);
public sealed record KamaraDeleteToken(byte[] F, byte[] G, byte[] P, Guid DocumentId);
// Update is an application-level Delete + Add, never a fourth paper protocol.
public sealed record KamaraMutation(KamaraDeleteToken? Delete, KamaraAddToken? Add);
public sealed record KamaraSetup(int Capacity, IndexEntry[] Entries);
public sealed record KamaraResults(Guid[] DocumentIds);
public sealed class KamaraCapacityException() : InvalidOperationException("Kamara free list exhausted; create a larger generation.");
// TRUSTED ONLY: revision lookup is application metadata, not a posting list.
public sealed record KamaraState(IndexScope Scope, Dictionary<Guid, long> Revisions);

/// <summary>
/// Fixed-width engineering encoding: k=256, Guid IDs=16 bytes, uint32 little-endian
/// addresses in [1,capacity], END=0. As=(id,next) XOR H1 || r (52 bytes);
/// Ad=(nextFile,prevDual,nextDual,selfSearch,prevSearch,nextSearch,F(w)) XOR H2 || r'
/// (88 bytes). Free As cells use (zero ID,nextFree,dualFree) and random padding.
/// Random-oracle instantiation follows section 6.1's HMAC approach; HKDF-Expand
/// supplies distinct H1/H2 domains and arbitrary output lengths, without repeating
/// a 32-byte mask. This is a concrete instantiation, not a random-oracle proof.
/// </summary>
internal static class KamaraEncoding
{
    internal const int SearchPlain = 20, DeletionPlain = 56;
    internal const int SearchSize = 52, DeletionSize = 88;
    internal const byte As = 1, Ad = 2, Ts = 3, Td = 4;
    internal static readonly byte[] Metadata = [0x4b, 0];
    internal static readonly byte[] Free = [0x4b, Ts, 0x66, 0x72, 0x65, 0x65];
    internal static byte[] Address(byte kind, int index) => [0x4b, kind, .. Ints(index)];
    internal static byte[] Address(byte kind, byte[] token) => [0x4b, kind, .. token];
    internal static int Read(byte[] bytes, int offset = 0) => BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset, 4));
    internal static void Write(byte[] bytes, int offset, int value) => BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset, 4), value);
    internal static byte[] Ints(params int[] values)
    {
        var bytes = new byte[values.Length * 4];
        for (var i = 0; i < values.Length; i++) Write(bytes, i * 4, values[i]);
        return bytes;
    }
    internal static byte[] Xor(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) throw new ArgumentException("Mask length mismatch.");
        var result = a.ToArray();
        for (var i = 0; i < result.Length; i++) result[i] ^= b[i];
        return result;
    }
    internal static void Patch(byte[] node, int offset, int delta)
    {
        Write(node, offset, Read(node, offset) ^ delta);
    }
    internal static byte[] Expand(byte[] key, string domain, byte[] input, int length)
    {
        var output = new byte[length];
        HKDF.Expand(HashAlgorithmName.SHA256, key, output, [.. Encoding.ASCII.GetBytes(domain), 0, .. input]);
        return output;
    }
    internal static byte[] Seal(byte[] plain, byte[] p, bool deletion)
    {
        var r = RandomNumberGenerator.GetBytes(32);
        return [.. Xor(plain, Expand(p, deletion ? "KPR/H2" : "KPR/H1", r, plain.Length)), .. r];
    }
    internal static byte[] Open(byte[] node, byte[] p, bool deletion)
    {
        var size = deletion ? DeletionPlain : SearchPlain;
        Length(node, size + 32);
        return Xor(node[..size], Expand(p, deletion ? "KPR/H2" : "KPR/H1", node[size..], size));
    }
    internal static void Length(byte[]? bytes, int size)
    {
        if (bytes is null || bytes.Length != size) throw new ArgumentException("Invalid Kamara field length.");
    }
    internal static void Scope(IndexScope scope)
    {
        KeyDerivation.ValidateScope(scope);
        if (scope.SchemeId != SchemeIds.Kamara) throw new ArgumentException("Kamara scope required.");
    }
    internal static void Capacity(int capacity)
    {
        if (capacity < 1 || capacity > 1_000_000) throw new ArgumentOutOfRangeException(nameof(capacity));
    }
    internal static byte[] Word(string word)
    {
        ArgumentException.ThrowIfNullOrEmpty(word);
        return [1, .. new UTF8Encoding(false, true).GetBytes(word)];
    }
    // The indexed file f is a canonical descriptor, permitted by section 3 and
    // footnote 6: identity, revision and the ordered keyword sequence. It is NOT
    // merely id(f). Length-prefix encoding and a type tag separate words/files.
    internal static byte[] File(TrustedDocument file)
    {
        if (file.DocumentId == Guid.Empty || file.Revision < 1 || file.Keywords is null)
            throw new ArgumentException("Invalid document descriptor.");
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, new UTF8Encoding(false, true));
        writer.Write((byte)2); writer.Write(file.DocumentId.ToByteArray());
        writer.Write(file.Revision); writer.Write(file.Keywords.Count);
        foreach (var word in file.Keywords)
        {
            var bytes = Word(word)[1..]; writer.Write(bytes.Length); writer.Write(bytes);
        }
        return stream.ToArray();
    }
}

// TRUSTED ONLY. Gen uses the existing RNG-backed master-key provider and separate
// HKDF domains to realize K1,K2,K3; K4 is the existing scope's Document key.
// No master/subkey is included in a token or persisted in server storage.
internal sealed class KamaraKeys : IDisposable
{
    private readonly byte[] k1, k2, k3;
    private KamaraKeys(byte[] seed)
    {
        k1 = KamaraEncoding.Expand(seed, "KPR/K1", [], 32);
        k2 = KamaraEncoding.Expand(seed, "KPR/K2", [], 32);
        k3 = KamaraEncoding.Expand(seed, "KPR/K3", [], 32);
    }
    internal static async ValueTask<KamaraKeys> Create(IndexScope scope, IClientKeyProvider keys, CancellationToken ct)
    {
        KamaraEncoding.Scope(scope);
        var seed = await keys.DeriveKeyAsync(scope, KeyPurposes.IndexValue, ct);
        try { KamaraEncoding.Length(seed, 32); return new(seed); }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }
    internal byte[] F(byte[] input) => HMACSHA256.HashData(k1, input);
    internal byte[] G(byte[] input, int length) => KamaraEncoding.Expand(k2, "KPR/G", input, length);
    internal byte[] P(byte[] input) => HMACSHA256.HashData(k3, input);
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(k1); CryptographicOperations.ZeroMemory(k2); CryptographicOperations.ZeroMemory(k3);
    }
}
