using System.Security.Cryptography;
using System.Runtime.Versioning;
using CipherSearch.Contracts;
using CipherSearch.Cryptography;

namespace CipherSearch.Client;

[SupportedOSPlatform("windows")]
public sealed class LocalVault : IClientKeyProvider, INonceSource, IDisposable
{
    private readonly string directory;
    private readonly byte[] master;
    private readonly FileStream lease;

    public LocalVault(string directory, bool create = false)
    {
        this.directory = Path.GetFullPath(directory);
        if (!Directory.Exists(directory) && !create) throw new DirectoryNotFoundException("Vault missing.");
        if (create && Directory.Exists(directory) && Directory.EnumerateFileSystemEntries(directory).Any())
            throw new IOException("Refusing to initialize a nonempty vault directory.");
        Directory.CreateDirectory(directory);
        lease = new FileStream(Path.Combine(directory, "vault.lock"), FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        try
        {
            var path = Path.Combine(directory, "master.dpapi");
            if (create)
            {
                if (File.Exists(path)) throw new IOException("Vault already initialized.");
                master = RandomNumberGenerator.GetBytes(32);
                WriteAtomic(path, ProtectedData.Protect(master, null, DataProtectionScope.CurrentUser));
                WriteAtomic(Path.Combine(directory, "nonce.dpapi"),
                    ProtectedData.Protect(RandomNumberGenerator.GetBytes(12), null, DataProtectionScope.CurrentUser));
            }
            else master = ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser);
            if (master.Length != 32) throw new CryptographicException("Invalid master key.");
        }
        catch { lease.Dispose(); throw; }
    }

    public ValueTask<byte[]> DeriveKeyAsync(IndexScope scope, string purpose, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(disposed, this);
        return ValueTask.FromResult(KeyDerivation.Derive(master, scope, purpose));
    }

    public byte[] Reserve(IndexScope scope, string purpose)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        lock (lease)
        {
            if (nonceRemaining == 0)
            {
                var path = Path.Combine(directory, "nonce.dpapi");
                var next = ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser);
                if (next.Length != 12) throw new CryptographicException("Invalid nonce state.");
                var highWater = next.ToArray();
                for (var i = 0; i < 1024; i++) Increment(highWater);
                WriteAtomic(path, ProtectedData.Protect(highWater, null, DataProtectionScope.CurrentUser));
                nonceNext = next;
                nonceRemaining = 1024;
            }
            var reserved = nonceNext.ToArray();
            Increment(nonceNext);
            nonceRemaining--;
            return reserved;
        }
    }

    private byte[] nonceNext = [];
    private int nonceRemaining;
    private static void Increment(byte[] counter)
    {
        var i = counter.Length - 1;
        while (i >= 0 && ++counter[i] == 0) i--;
        if (i < 0) throw new CryptographicException("Nonce space exhausted.");
    }

    public void Save<T>(string name, T value)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var bytes = Wire.Encode(value);
        try { WriteAtomic(StatePath(name), ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public T Load<T>(string name)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var bytes = ProtectedData.Unprotect(File.ReadAllBytes(StatePath(name)), null, DataProtectionScope.CurrentUser);
        try { return Wire.Decode<T>(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public bool Exists(string name) => File.Exists(StatePath(name));
    private string StatePath(string name)
    {
        if (name.Length == 0 || name.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
            throw new ArgumentException("Invalid state name.");
        return Path.Combine(directory, name + ".state");
    }
    private static void WriteAtomic(string path, byte[] bytes)
    {
        var temp = path + ".new";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(bytes);
            stream.Flush(true);
        }
        for (var attempt = 0; ; attempt++)
        {
            try { File.Move(temp, path, true); return; }
            catch (IOException ex) when (attempt < 7 && (ex.HResult & 0xffff) is 32 or 33)
            { Thread.Sleep(Math.Min(25 << attempt, 500)); }
            catch (UnauthorizedAccessException ex) when (attempt < 7 && (ex.HResult & 0xffff) == 5)
            { Thread.Sleep(Math.Min(25 << attempt, 500)); }
        }
    }
    private bool disposed;
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        CryptographicOperations.ZeroMemory(master);
        lease.Dispose();
    }
}
