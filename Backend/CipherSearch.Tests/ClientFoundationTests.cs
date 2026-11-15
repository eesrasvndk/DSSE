using CipherSearch.Client;
using CipherSearch.Contracts;
using CipherSearch.Cryptography;

namespace CipherSearch.Tests;

public sealed class ClientFoundationTests
{
    [Fact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task VaultRetriesTemporaryRenameLockWithoutReplacingOldStateEarly()
    {
        if (!OperatingSystem.IsWindows()) return;
        var directory = Path.Combine(Path.GetTempPath(), "ciphersearch-rename-" + Guid.NewGuid().ToString("N"));
        using var vault = new LocalVault(directory, true);
        vault.Save("example", 1);
        using var locked = new FileStream(Path.Combine(directory, "example.state"),
            FileMode.Open, FileAccess.Read, FileShare.Read);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var saving = Task.Run(() => { started.SetResult(); vault.Save("example", 2); });
        await started.Task;
        await Task.Delay(100);
        Assert.Equal(1, vault.Load<int>("example"));
        locked.Dispose();
        await saving;
        Assert.Equal(2, vault.Load<int>("example"));
    }

    [Theory]
    [InlineData("The QUICK fox, fox! 123", "quick fox fox")]
    [InlineData("İSTANBUL Straße CAFÉ", "stanbul stra caf")]
    [InlineData("a I x and", "")]
    [InlineData("foo-bar email@example.com", "foo bar email example com")]
    public void NormalizationMatchesPythonRules(string input, string expected) =>
        Assert.Equal(expected, string.Join(" ", TextNormalizer.Tokenize(input)));

    [Theory]
    [InlineData("the")]
    [InlineData("energy market")]
    [InlineData("")]
    public void RejectsNonSingleKeywordQueries(string query) =>
        Assert.Throws<ArgumentException>(() => TextNormalizer.Query(query));

    [Fact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task VaultRestartsWithoutRepeatingReservedNoncesOrChangingKeys()
    {
        if (!OperatingSystem.IsWindows()) return;
        var directory = Path.Combine(Path.GetTempPath(), "ciphersearch-test-" + Guid.NewGuid().ToString("N"));
        var scope = new IndexScope(Guid.NewGuid(), SchemeIds.NaiveHmac, Guid.NewGuid(), 1);
        byte[] key;
        var nonces = new HashSet<string>();
        using (var vault = new LocalVault(directory, true))
        {
            key = await vault.DeriveKeyAsync(scope, KeyPurposes.Document);
            for (var i = 0; i < 1100; i++) Assert.True(nonces.Add(Convert.ToHexString(vault.Reserve(scope, KeyPurposes.Document))));
            vault.Save("example", scope);
            Assert.Throws<IOException>(() => new LocalVault(directory));
        }
        using (var vault = new LocalVault(directory))
        {
            Assert.Equal(key, await vault.DeriveKeyAsync(scope, KeyPurposes.Document));
            Assert.Equal(scope, vault.Load<IndexScope>("example"));
            for (var i = 0; i < 1100; i++) Assert.True(nonces.Add(Convert.ToHexString(vault.Reserve(scope, KeyPurposes.Document))));
        }
        File.Move(Path.Combine(directory, "nonce.dpapi"), Path.Combine(directory, "nonce.saved"));
        using (var vault = new LocalVault(directory))
            Assert.Throws<FileNotFoundException>(() => vault.Reserve(scope, KeyPurposes.Document));
        File.Move(Path.Combine(directory, "master.dpapi"), Path.Combine(directory, "master.saved"));
        Assert.Throws<FileNotFoundException>(() => new LocalVault(directory));
    }
}
