using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.State;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class SessionAccountServiceTests
{
    private const string ValidRecoveryPhrase = "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed";

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
    public async Task Login_RejectsTwelveWordPhrase()
    {
        var runtime = ClientRuntime.CreateStubbed();

        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => runtime.Accounts.LoginAsync(
                "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade",
                "Alice"));

        Assert.Contains("must contain 13 words", exception.Message, StringComparison.Ordinal);
        Assert.Null(await runtime.Accounts.GetRecoveryPhraseAsync());
    }

    [Fact]
    public async Task Login_NormalizesUnicodeWhitespaceInModernThirteenWordPhrase()
    {
        var registeredRuntime = ClientRuntime.CreateStubbed();
        var registered = await registeredRuntime.Accounts.RegisterAsync("Alice");
        var phrase = await registeredRuntime.Accounts.GetRecoveryPhraseAsync();
        var restoredRuntime = ClientRuntime.CreateStubbed();

        var restored = await restoredRuntime.Accounts.LoginAsync(
            WithMixedUnicodeWhitespace(phrase!.ToUpperInvariant()),
            "Alice");

        Assert.Equal(registered.SessionId, restored.SessionId);
        Assert.Equal(phrase, await restoredRuntime.Accounts.GetRecoveryPhraseAsync());
    }

    [Fact]
    public async Task Register_GeneratesSessionCompatible128BitPhraseWithChecksum()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-07-11T00:00:00Z")));

        var registered = await runtime.Accounts.RegisterAsync("Alice");
        var phrase = await runtime.Accounts.GetRecoveryPhraseAsync();
        var words = phrase!.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var restoredRuntime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-07-11T00:00:00Z")));
        var restored = await restoredRuntime.Accounts.LoginAsync(phrase, "Alice");

        Assert.Equal(13, words.Length);
        Assert.Equal(128, 16 * 8);
        Assert.Equal(registered.SessionId, restored.SessionId);
    }

    [Fact]
    public void RecoveryPhraseEncoding_MatchesOriginalSessionMnemonicVector()
    {
        var encoder = typeof(SessionAccountService).GetMethod(
            "EncodeRecoveryEntropy",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

        var phrase = Assert.IsType<string>(encoder!.Invoke(null, [Enumerable.Range(0, 16).Select(static value => (byte)value).ToArray()]));

        Assert.Equal(
            "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed",
            phrase);
    }

    [Fact]
    public void LegacyTwelveWordPhraseCannotCreateIdentityMaterial()
    {
        const string legacy =
            "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade";

        Assert.False(SessionAccountService.IsCanonicalRecoveryPhrase(legacy));
        Assert.Throws<ArgumentException>(() => new SessionIdentityProvider(legacy));
    }

    [Fact]
    public async Task Login_RejectsModernPhraseWithInvalidChecksum()
    {
        var runtime = ClientRuntime.CreateStubbed();
        await runtime.Accounts.RegisterAsync("Alice");
        var phrase = await runtime.Accounts.GetRecoveryPhraseAsync();
        var words = phrase!.Split(' ');
        words[^1] = string.Equals(words[^1], "abbey", StringComparison.Ordinal) ? "abducts" : "abbey";

        var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
            ClientRuntime.CreateStubbed().Accounts.LoginAsync(string.Join(' ', words), "Alice"));

        Assert.Contains("checksum", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Register_RecoveryPhraseStorageFailureNeverPublishesActiveAccount(bool throwAfterWrite)
    {
        var store = new InMemorySessionStore();
        var settings = new FaultInjectingSettingsRepository(store);
        settings.FailNextSet(SessionAccountService.ActiveRecoveryPhraseKey, throwAfterWrite);
        var service = new SessionAccountService(
            settings,
            store,
            store,
            new FrozenClock(DateTimeOffset.Parse("2026-07-11T00:00:00Z")));

        await Assert.ThrowsAsync<InjectedSettingsFaultException>(() => service.RegisterAsync("Alice"));

        Assert.Null(await store.GetAsync<Deep.Client.Shared.Domain.SessionAccount>(SessionAccountService.ActiveAccountKey));
        Assert.Null(await store.GetAsync<string>(SessionAccountService.ActiveRecoveryPhraseKey));
        Assert.Empty(await ToListAsync(((IContactRepository)store).ListAsync()));
    }

    [Fact]
    public async Task Register_AccountCommitFailureRestoresPreviousAccountAndSelfContact()
    {
        var store = new InMemorySessionStore();
        var settings = new FaultInjectingSettingsRepository(store);
        var service = new SessionAccountService(
            settings,
            store,
            store,
            new FrozenClock(DateTimeOffset.Parse("2026-07-11T00:00:00Z")));
        var previousAccount = await service.RegisterAsync("Alice");
        var previousPhrase = await service.GetRecoveryPhraseAsync();
        var previousSelfContact = await ((IContactRepository)store).GetAsync(previousAccount.SessionId);
        settings.FailNextSet(SessionAccountService.ActiveAccountKey, throwAfterWrite: true);

        await Assert.ThrowsAsync<InjectedSettingsFaultException>(() => service.LoginAsync(previousPhrase!, "Bob"));

        Assert.Equal(previousAccount, await service.GetActiveAccountAsync());
        Assert.Equal(previousPhrase, await service.GetRecoveryPhraseAsync());
        Assert.Equal(previousSelfContact, await ((IContactRepository)store).GetAsync(previousAccount.SessionId));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Register_AccountCommitFailureDeletesNewSelfContact(bool throwAfterWrite)
    {
        var store = new InMemorySessionStore();
        var settings = new FaultInjectingSettingsRepository(store);
        settings.FailNextSet(SessionAccountService.ActiveAccountKey, throwAfterWrite);
        var service = new SessionAccountService(
            settings,
            store,
            store,
            new FrozenClock(DateTimeOffset.Parse("2026-07-11T00:00:00Z")));

        await Assert.ThrowsAsync<InjectedSettingsFaultException>(() => service.RegisterAsync("Alice"));

        Assert.Null(await service.GetActiveAccountAsync());
        Assert.Null(await service.GetRecoveryPhraseAsync());
        Assert.Empty(await ToListAsync(((IContactRepository)store).ListAsync()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("corrupt recovery phrase")]
    public async Task Register_DifferentPersistedAccountRequiresPurgeWhenRecoveryPhraseIsUnavailable(
        string? previousPhrase)
    {
        var store = new InMemorySessionStore();
        var unrecoverable = new Deep.Client.Shared.Domain.SessionAccount(
            Deep.Client.Shared.Domain.SessionId.CreateNew(),
            "Broken",
            DateTimeOffset.Parse("2026-07-11T00:00:00Z"));
        await store.SetAsync(SessionAccountService.ActiveAccountKey, unrecoverable);
        if (previousPhrase is not null)
        {
            await store.SetAsync(SessionAccountService.ActiveRecoveryPhraseKey, previousPhrase);
        }

        var previousSelfContact = Contact.Self(
            unrecoverable.SessionId,
            unrecoverable.DisplayName,
            unrecoverable.RegisteredAt);
        await store.UpsertAsync(previousSelfContact);
        var service = new SessionAccountService(
            store,
            store,
            store,
            new FrozenClock(DateTimeOffset.Parse("2026-07-11T00:00:00Z")));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.RegisterAsync("Alice"));

        Assert.Contains("Sign out", exception.Message, StringComparison.Ordinal);
        Assert.Equal(unrecoverable, await service.GetActiveAccountAsync());
        Assert.Equal(previousPhrase, await service.GetRecoveryPhraseAsync());
        Assert.Equal(previousSelfContact, await ((IContactRepository)store).GetAsync(unrecoverable.SessionId));
        Assert.Single(await ToListAsync(((IContactRepository)store).ListAsync()));
    }

    [Fact]
    public void IdentityMaterialDisposeZeroizesAllKeyBuffers()
    {
        var materialType = typeof(SessionAccountService).Assembly.GetType(
            "Deep.Client.Shared.Services.SessionIdentityMaterial");
        Assert.NotNull(materialType);

        // The type is internal; keep this test at the security boundary without widening its API.
        var factory = materialType!.GetMethod("FromRecoveryPhrase", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public);
        Assert.NotNull(factory);
        var material = factory!.Invoke(null, [ValidRecoveryPhrase])
            ?? throw new InvalidOperationException("Identity material factory returned null.");

        var buffers = new[]
        {
            (byte[])materialType.GetProperty("Ed25519PublicKey")!.GetValue(material)!,
            (byte[])materialType.GetProperty("Ed25519PrivateKey")!.GetValue(material)!,
            (byte[])materialType.GetProperty("X25519PublicKey")!.GetValue(material)!,
            (byte[])materialType.GetProperty("X25519PrivateKey")!.GetValue(material)!
        };

        Assert.Contains(buffers.SelectMany(static value => value), static value => value != 0);
        ((IDisposable)material).Dispose();

        Assert.All(buffers.SelectMany(static value => value), static value => Assert.Equal(0, value));
        Assert.Throws<System.Reflection.TargetInvocationException>(() => materialType.GetProperty("Ed25519PrivateKey")!.GetValue(material));
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
    public async Task RegisteringDifferentAccountRequiresExplicitSignOutAndPreservesCurrentState()
    {
        using var runtime = ClientRuntime.CreateStubbed(
            clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var firstAccount = await runtime.Accounts.RegisterAsync("Alice");
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(SessionId.CreateNew(), "Bob");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => runtime.Accounts.RegisterAsync("Second account"));

        Assert.Contains("Sign out", exception.Message, StringComparison.Ordinal);
        Assert.Equal(firstAccount, await runtime.Accounts.GetActiveAccountAsync());
        Assert.Equal(conversation, await ((IConversationRepository)runtime.Store).GetAsync(conversation.Id));
    }

    [Fact]
    public async Task SignOut_ClearsActiveAccountAndRecoveryPhrase()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));

        await runtime.Accounts.RegisterAsync("Alice");
        Assert.NotNull(await runtime.Accounts.GetActiveAccountAsync());

        await runtime.Accounts.SignOutAsync();

        var account = await runtime.Accounts.GetActiveAccountAsync();
        var phrase = await runtime.Accounts.GetRecoveryPhraseAsync();

        Assert.Null(account);
        Assert.Null(phrase);
    }

    [Fact]
    public async Task SignOut_PurgeFailureLeavesTheActiveAccountAvailableForRetry()
    {
        var store = new InMemorySessionStore();
        var service = new SessionAccountService(
            store,
            store,
            new ThrowingAccountDataPurger(),
            new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var account = await service.RegisterAsync("Alice");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.SignOutAsync());

        Assert.Contains("purge failed", exception.Message, StringComparison.Ordinal);
        Assert.Equal(account, await service.GetActiveAccountAsync());
        Assert.NotNull(await service.GetRecoveryPhraseAsync());
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

    private sealed class ThrowingAccountDataPurger : IAccountDataPurger
    {
        public Task PurgeAccountDataAsync(CancellationToken cancellationToken = default) =>
            Task.FromException(new InvalidOperationException("Account data purge failed."));
    }

    private sealed class FaultInjectingSettingsRepository(ISettingsRepository inner) : ISettingsRepository
    {
        private string? failedKey;
        private bool throwAfterWrite;
        private int shouldFail;

        public void FailNextSet(string key, bool throwAfterWrite)
        {
            failedKey = key;
            this.throwAfterWrite = throwAfterWrite;
            Volatile.Write(ref shouldFail, 1);
        }

        public async Task SetAsync<T>(string key, T value, CancellationToken cancellationToken = default)
        {
            var fail = string.Equals(key, failedKey, StringComparison.Ordinal)
                && Interlocked.Exchange(ref shouldFail, 0) != 0;
            if (fail && !throwAfterWrite)
            {
                throw new InjectedSettingsFaultException($"Injected write failure for '{key}'.");
            }

            await inner.SetAsync(key, value, cancellationToken);
            if (fail)
            {
                throw new InjectedSettingsFaultException($"Injected post-write failure for '{key}'.");
            }
        }

        public Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default) =>
            inner.GetAsync<T>(key, cancellationToken);

        public Task DeleteAsync(string key, CancellationToken cancellationToken = default) =>
            inner.DeleteAsync(key, cancellationToken);
    }

    private sealed class InjectedSettingsFaultException(string message) : Exception(message);

    private static async Task<IReadOnlyList<T>> ToListAsync<T>(IAsyncEnumerable<T> source)
    {
        var items = new List<T>();
        await foreach (var item in source)
        {
            items.Add(item);
        }

        return items;
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

    private static string WithMixedUnicodeWhitespace(string phrase)
    {
        string[] separators = ["\r\n", "\n", "\t", "\u00a0", " \t "];
        var words = phrase.Split(' ');
        return $"\t{string.Join(string.Empty, words.Select(
            (word, index) => index == words.Length - 1
                ? word
                : word + separators[index % separators.Length]))}\u00a0";
    }
}
