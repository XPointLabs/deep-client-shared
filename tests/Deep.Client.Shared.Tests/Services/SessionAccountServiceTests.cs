using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class SessionAccountServiceTests
{
    private const string ValidRecoveryPhrase = "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade";

    [Fact]
    public async Task LoginWithSameRecoveryPhrase_IsDeterministic()
    {
        var runtimeA = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var runtimeB = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));

        var accountA = await runtimeA.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");
        var accountB = await runtimeB.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");

        Assert.Equal(accountA.SessionId, accountB.SessionId);
        Assert.StartsWith("05", accountA.SessionId.Value);
    }

    [Fact]
    public async Task LoginDerivesStandardSessionIdFromCurve25519PublicKey()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));

        var account = await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");

        var expectedSessionId = DeriveExpectedStandardSessionId(ValidRecoveryPhrase);

        Assert.Equal(expectedSessionId, account.SessionId.Value);
    }

    [Fact]
    public async Task LoginWithSessionIdString_IsRejected()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var sessionIdLikeInput = "05" + new string('a', 64);

        var ex = await Assert.ThrowsAsync<ArgumentException>(() => runtime.Accounts.LoginAsync(sessionIdLikeInput, "Alice"));

        Assert.Contains("Recovery by Session ID is disabled", ex.Message);
    }

    [Fact]
    public async Task LoginWithoutDisplayNameAndWithoutProfileLookup_Throws()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));

        var ex = await Assert.ThrowsAsync<ArgumentException>(() => runtime.Accounts.LoginAsync(ValidRecoveryPhrase));

        Assert.Contains("Unable to recover profile display name from network", ex.Message);
    }

    [Fact]
    public async Task LoginWithoutDisplayName_UsesRecoveredProfileName_WhenLookupSucceeds()
    {
        var store = new InMemorySessionStore();
        var lookup = new FakeRecoveryProfileLookup("Recovered Alice");
        var service = new SessionAccountService(store, store, new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")), lookup);

        var account = await service.LoginAsync(ValidRecoveryPhrase);

        Assert.Equal("Recovered Alice", account.DisplayName);
        Assert.True(account.IsRestoredAccount);
    }

    [Fact]
    public async Task SignOut_ClearsActiveAccountAndRecoveryPhrase()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));

        await runtime.Accounts.RegisterAsync("Alice");
        await runtime.Accounts.SignOutAsync();

        var account = await runtime.Accounts.GetActiveAccountAsync();
        var phrase = await runtime.Accounts.GetRecoveryPhraseAsync();

        Assert.Null(account);
        Assert.Null(phrase);
    }

    [Fact]
    public async Task UpdateDisplayName_PersistsActiveAccountAndSelfContact()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var account = await runtime.Accounts.RegisterAsync("Alice");

        var updated = await runtime.Accounts.UpdateDisplayNameAsync("QA Alice");
        var active = await runtime.Accounts.GetActiveAccountAsync();
        var selfContact = await ((IContactRepository)runtime.Store).GetAsync(account.SessionId);

        Assert.Equal("QA Alice", updated.DisplayName);
        Assert.Equal("QA Alice", active?.DisplayName);
        Assert.Equal("QA Alice", selfContact?.DisplayName);
    }

    private sealed class FakeRecoveryProfileLookup(string? displayName) : IRecoveryProfileLookup
    {
        public Task<string?> TryGetDisplayNameAsync(Deep.Client.Shared.Domain.SessionId sessionId, CancellationToken cancellationToken = default) =>
            Task.FromResult(displayName);
    }

    private static string DeriveExpectedStandardSessionId(string recoveryPhrase)
    {
        var normalized = string.Join(' ', recoveryPhrase
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(word => word.ToLowerInvariant()));
        var mnemonicBytes = Encoding.UTF8.GetBytes(normalized.Normalize(NormalizationForm.FormKD));
        var salt = Encoding.UTF8.GetBytes("mnemonic");
        var seed = Rfc2898DeriveBytes.Pbkdf2(
            mnemonicBytes,
            salt,
            2048,
            HashAlgorithmName.SHA512,
            32);

        var ed25519KeyPair = PublicKeyAuth.GenerateKeyPair(seed);
        var x25519PublicKey = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519KeyPair.PublicKey);
        return $"05{Convert.ToHexString(x25519PublicKey).ToLowerInvariant()}";
    }
}
