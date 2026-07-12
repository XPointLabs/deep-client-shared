using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using System.Buffers.Binary;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace Deep.Client.Shared.Services;

internal interface IAccountGenerationLifecycle
{
    Task StopAsync(SessionId account, CancellationToken cancellationToken = default);

    void Resume(SessionId account);
}

public sealed class SessionAccountService
{
    private readonly ISettingsRepository settings;
    private readonly IContactRepository contacts;
    private readonly IAccountDataPurger accountDataPurger;
    private readonly IClock clock;
    private readonly IRecoveryProfileLookup? recoveryProfileLookup;
    private readonly SemaphoreSlim activeAccountGate = new(1, 1);
    private IAccountGenerationLifecycle? accountGenerationLifecycle;
    private SessionAccount? activeAccountCache;
    private SessionId? resumedLifecycleAccount;
    private bool activeAccountCacheLoaded;

    internal event Action? AccountStateChanged;

    public const string ActiveAccountKey = LocalSettingsKeys.ActiveAccount;
    public const string ActiveRecoveryPhraseKey = LocalSettingsKeys.ActiveRecoveryPhrase;
    public static readonly TimeSpan RecoveryProfileLookupTimeout = TimeSpan.FromSeconds(12);

    private const int RecoveryEntropySize = 16;
    private const int RecoveryDataWordCount = 12;
    private const int RecoveryPhraseWordCount = RecoveryDataWordCount + 1;
    private const int RecoveryWordPrefixLength = 3;
    private const int SessionRecoveryWordCount = 1626;
    private const string RecoveryWordListResource = "Deep.Client.Shared.Resources.Mnemonic.english.txt";

    public SessionAccountService(
        ISettingsRepository settings,
        IContactRepository contacts,
        IAccountDataPurger accountDataPurger,
        IClock clock,
        IRecoveryProfileLookup? recoveryProfileLookup = null)
    {
        this.settings = settings;
        this.contacts = contacts;
        this.accountDataPurger = accountDataPurger;
        this.clock = clock;
        this.recoveryProfileLookup = recoveryProfileLookup;
    }

    public SessionAccountService(
        ISettingsRepository settings,
        IContactRepository contacts,
        IClock clock,
        IRecoveryProfileLookup? recoveryProfileLookup = null)
        : this(
            settings,
            contacts,
            settings as IAccountDataPurger
                ?? throw new ArgumentException("The account settings store must support account data purge.", nameof(settings)),
            clock,
            recoveryProfileLookup)
    {
    }

    private static readonly string[] LegacyRecoveryWordList =
    [
        "amber", "anchor", "april", "arrow", "atom", "aurora", "autumn", "badge",
        "bamboo", "beacon", "berry", "blade", "blossom", "breeze", "bridge", "cactus",
        "candle", "canyon", "caper", "carbon", "cedar", "chisel", "cliff", "cloud",
        "cobalt", "comet", "coral", "crown", "dawn", "delta", "desert", "ember",
        "falcon", "fern", "fjord", "frost", "glacier", "harbor", "hazel", "horizon",
        "island", "juniper", "keystone", "lagoon", "lantern", "lilac", "lotus", "marble",
        "meadow", "meteor", "midnight", "mist", "nectar", "north", "oasis", "onyx",
        "orchid", "pebble", "phoenix", "pine", "quartz", "river", "sable", "saffron",
        "sage", "scarlet", "sierra", "signal", "silver", "spruce", "summit", "sunset",
        "tempest", "thistle", "timber", "topaz", "valley", "velvet", "violet", "willow"
    ];

    private static readonly string[] RecoveryWordList = LoadRecoveryWordList();
    private static readonly IReadOnlyDictionary<string, int> RecoveryWordIndexes = RecoveryWordList
        .Select(static (word, index) => new KeyValuePair<string, int>(word, index))
        .ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal);

    internal void RegisterAccountGenerationLifecycle(IAccountGenerationLifecycle lifecycle)
    {
        ArgumentNullException.ThrowIfNull(lifecycle);
        var existing = Interlocked.CompareExchange(ref accountGenerationLifecycle, lifecycle, null);
        if (existing is not null && !ReferenceEquals(existing, lifecycle))
        {
            throw new InvalidOperationException("An account generation lifecycle is already registered.");
        }

        if (activeAccountCacheLoaded && activeAccountCache is { } activeAccount)
        {
            ResumeLifecycleIfNeeded(activeAccount.SessionId);
        }
    }

    public async Task<SessionAccount> RegisterAsync(string displayName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        var recoveryPhrase = GenerateRecoveryPhrase();
        var account = new SessionAccount(DeriveSessionIdFromRecoveryPhrase(recoveryPhrase), displayName.Trim(), clock.UtcNow);
        await ActivateAccountAsync(account, recoveryPhrase, cancellationToken).ConfigureAwait(false);
        return account;
    }

    public async Task<SessionAccount> LoginAsync(string recoveryPhrase, string? displayName = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(recoveryPhrase);

        if (LooksLikeSessionId(recoveryPhrase))
        {
            throw new ArgumentException(
                "Recovery by Session ID is disabled. Enter the account recovery phrase instead.",
                nameof(recoveryPhrase));
        }

        var normalizedPhrase = NormalizeRecoveryPhrase(recoveryPhrase);
        ValidateRecoveryPhrase(normalizedPhrase);
        var sessionId = DeriveSessionIdFromRecoveryPhrase(normalizedPhrase);

        var recoveredDisplayName = await TryRecoverDisplayNameAsync(sessionId, cancellationToken).ConfigureAwait(false);
        var resolvedDisplayName = !string.IsNullOrWhiteSpace(recoveredDisplayName)
            ? recoveredDisplayName
            : displayName?.Trim();

        if (string.IsNullOrWhiteSpace(resolvedDisplayName))
        {
            throw new ArgumentException(
                "Unable to recover profile display name from network. Enter display name to finish restore.",
                nameof(displayName));
        }

        var account = new SessionAccount(sessionId, resolvedDisplayName, clock.UtcNow, IsRestoredAccount: true);
        await ActivateAccountAsync(account, normalizedPhrase, cancellationToken).ConfigureAwait(false);
        return account;
    }

    public async Task<SessionAccount?> GetActiveAccountAsync(CancellationToken cancellationToken = default)
    {
        await activeAccountGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (activeAccountCacheLoaded)
            {
                if (activeAccountCache is { } cachedAccount)
                {
                    ResumeLifecycleIfNeeded(cachedAccount.SessionId);
                }

                return activeAccountCache;
            }

            activeAccountCache = await settings.GetAsync<SessionAccount>(ActiveAccountKey, cancellationToken).ConfigureAwait(false);
            activeAccountCacheLoaded = true;
            if (activeAccountCache is { } loadedAccount)
            {
                ResumeLifecycleIfNeeded(loadedAccount.SessionId);
            }

            return activeAccountCache;
        }
        finally
        {
            activeAccountGate.Release();
        }
    }

    public Task<string?> GetRecoveryPhraseAsync(CancellationToken cancellationToken = default) =>
        settings.GetAsync<string>(ActiveRecoveryPhraseKey, cancellationToken);

    public async Task<SessionAccount> UpdateDisplayNameAsync(string displayName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        var account = await GetActiveAccountAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Sign in before updating profile.");

        var updated = account with { DisplayName = displayName.Trim() };
        await PersistAccountAsync(updated, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    public async Task SignOutAsync(CancellationToken cancellationToken = default)
    {
        await activeAccountGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var account = activeAccountCacheLoaded
                ? activeAccountCache
                : await settings.GetAsync<SessionAccount>(ActiveAccountKey, cancellationToken).ConfigureAwait(false);
            var lifecycle = Volatile.Read(ref accountGenerationLifecycle);

            try
            {
                if (account is not null && lifecycle is not null)
                {
                    await lifecycle.StopAsync(account.SessionId, cancellationToken).ConfigureAwait(false);
                }

                await accountDataPurger.PurgeAccountDataAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                if (account is not null && lifecycle is not null)
                {
                    lifecycle.Resume(account.SessionId);
                    resumedLifecycleAccount = account.SessionId;
                }

                throw;
            }

            activeAccountCache = null;
            activeAccountCacheLoaded = true;
            resumedLifecycleAccount = null;
        }
        finally
        {
            activeAccountGate.Release();
        }

        NotifyAccountStateChanged();
    }

    private async Task PersistAccountAsync(SessionAccount account, CancellationToken cancellationToken)
    {
        await activeAccountGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await settings.SetAsync(ActiveAccountKey, account, cancellationToken).ConfigureAwait(false);
            await contacts.UpsertAsync(Contact.Self(account.SessionId, account.DisplayName, clock.UtcNow), cancellationToken).ConfigureAwait(false);
            activeAccountCache = account;
            activeAccountCacheLoaded = true;
        }
        finally
        {
            activeAccountGate.Release();
        }
    }

    private async Task ActivateAccountAsync(
        SessionAccount account,
        string recoveryPhrase,
        CancellationToken cancellationToken)
    {
        await activeAccountGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var previousAccount = await settings
                .GetAsync<SessionAccount>(ActiveAccountKey, cancellationToken)
                .ConfigureAwait(false);
            var previousPhrase = await settings
                .GetAsync<string>(ActiveRecoveryPhraseKey, cancellationToken)
                .ConfigureAwait(false);
            var previousSelfContact = await contacts
                .GetAsync(account.SessionId, cancellationToken)
                .ConfigureAwait(false);

            if (previousAccount is not null && previousAccount.SessionId != account.SessionId)
            {
                throw new InvalidOperationException(
                    "Sign out from the active Deep account before activating a different account.");
            }

            try
            {
                // A recoverable credential must be durable before the account is made active.
                await settings
                    .SetAsync(ActiveRecoveryPhraseKey, recoveryPhrase, cancellationToken)
                    .ConfigureAwait(false);
                await contacts
                    .UpsertAsync(Contact.Self(account.SessionId, account.DisplayName, clock.UtcNow), cancellationToken)
                    .ConfigureAwait(false);
                await settings.SetAsync(ActiveAccountKey, account, cancellationToken).ConfigureAwait(false);

                activeAccountCache = account;
                activeAccountCacheLoaded = true;
                ResumeLifecycleIfNeeded(account.SessionId);
            }
            catch (Exception activationException)
            {
                activeAccountCache = null;
                activeAccountCacheLoaded = false;

                var rollbackException = await TryRestoreActivationStateAsync(
                    previousAccount,
                    previousPhrase,
                    account.SessionId,
                    previousSelfContact).ConfigureAwait(false);
                if (rollbackException is not null)
                {
                    throw new InvalidOperationException(
                        "Account activation failed and its previous state could not be restored completely.",
                        new AggregateException(activationException, rollbackException));
                }

                activeAccountCache = previousAccount;
                activeAccountCacheLoaded = true;

                ExceptionDispatchInfo.Capture(activationException).Throw();
                throw;
            }
        }
        finally
        {
            activeAccountGate.Release();
        }

        NotifyAccountStateChanged();
    }

    private void ResumeLifecycleIfNeeded(SessionId account)
    {
        if (resumedLifecycleAccount == account)
        {
            return;
        }

        Volatile.Read(ref accountGenerationLifecycle)?.Resume(account);
        resumedLifecycleAccount = account;
    }

    private void NotifyAccountStateChanged()
    {
        foreach (var handler in AccountStateChanged?.GetInvocationList().Cast<Action>() ?? [])
        {
            try
            {
                handler();
            }
            catch
            {
                // Account persistence is already committed; lifecycle cleanup is best-effort.
            }
        }
    }

    private async Task<Exception?> TryRestoreActivationStateAsync(
        SessionAccount? previousAccount,
        string? previousPhrase,
        SessionId activatedAccountId,
        Contact? previousSelfContact)
    {
        var failures = new List<Exception>();

        try
        {
            if (previousPhrase is null)
            {
                await settings.DeleteAsync(ActiveRecoveryPhraseKey, CancellationToken.None).ConfigureAwait(false);
            }
            else
            {
                await settings
                    .SetAsync(ActiveRecoveryPhraseKey, previousPhrase, CancellationToken.None)
                    .ConfigureAwait(false);
            }
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        try
        {
            if (previousSelfContact is null)
            {
                await contacts.DeleteAsync(activatedAccountId, CancellationToken.None).ConfigureAwait(false);
            }
            else
            {
                await contacts.UpsertAsync(previousSelfContact, CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        try
        {
            if (previousAccount is null || failures.Count != 0)
            {
                await settings.DeleteAsync(ActiveAccountKey, CancellationToken.None).ConfigureAwait(false);
            }
            else
            {
                await settings
                    .SetAsync(ActiveAccountKey, previousAccount, CancellationToken.None)
                    .ConfigureAwait(false);
            }
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        return failures.Count switch
        {
            0 => null,
            1 => failures[0],
            _ => new AggregateException(failures)
        };
    }

    private async Task<string?> TryRecoverDisplayNameAsync(SessionId sessionId, CancellationToken cancellationToken)
    {
        if (recoveryProfileLookup is null)
        {
            return null;
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(RecoveryProfileLookupTimeout);

        try
        {
            return await recoveryProfileLookup.TryGetDisplayNameAsync(sessionId, timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static string GenerateRecoveryPhrase()
    {
        var entropy = RandomNumberGenerator.GetBytes(RecoveryEntropySize);
        try
        {
            return EncodeRecoveryEntropy(entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    private static string EncodeRecoveryEntropy(byte[] entropy)
    {
        ArgumentNullException.ThrowIfNull(entropy);
        if (entropy.Length != RecoveryEntropySize)
        {
            throw new ArgumentException($"Recovery entropy must contain exactly {RecoveryEntropySize} bytes.", nameof(entropy));
        }

        var words = new List<string>(RecoveryPhraseWordCount);
        var wordCount = (uint)RecoveryWordList.Length;
        for (var offset = 0; offset < entropy.Length; offset += sizeof(uint))
        {
            var value = BinaryPrimitives.ReadUInt32LittleEndian(entropy.AsSpan(offset, sizeof(uint)));
            var first = value % wordCount;
            var second = ((value / wordCount) + first) % wordCount;
            var third = (((value / wordCount) / wordCount) + second) % wordCount;
            words.Add(RecoveryWordList[first]);
            words.Add(RecoveryWordList[second]);
            words.Add(RecoveryWordList[third]);
        }

        words.Add(words[GetChecksumWordIndex(words)]);
        return string.Join(' ', words);
    }

    private static int GetChecksumWordIndex(IReadOnlyList<string> words)
    {
        var prefixes = new StringBuilder(words.Count * RecoveryWordPrefixLength);
        foreach (var word in words)
        {
            prefixes.Append(word, 0, RecoveryWordPrefixLength);
        }

        var bytes = Encoding.UTF8.GetBytes(prefixes.ToString());
        try
        {
            return (int)(ComputeCrc32(bytes) % (uint)words.Count);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> value)
    {
        var crc = uint.MaxValue;
        foreach (var item in value)
        {
            crc ^= item;
            for (var bit = 0; bit < 8; bit++)
            {
                var mask = 0u - (crc & 1u);
                crc = (crc >> 1) ^ (0xedb88320u & mask);
            }
        }

        return ~crc;
    }

    private static SessionId DeriveSessionIdFromRecoveryPhrase(string recoveryPhrase)
    {
        using var identity = SessionIdentityMaterial.FromRecoveryPhrase(recoveryPhrase);
        return identity.SessionId;
    }

    private static bool LooksLikeSessionId(string candidate)
    {
        var normalized = candidate.Trim().ToLowerInvariant();
        return normalized.Length == 66 && normalized.All(Uri.IsHexDigit);
    }

    private static string NormalizeRecoveryPhrase(string phrase) =>
        SessionIdentityMaterial.NormalizeRecoveryPhrase(phrase);

    private static void ValidateRecoveryPhrase(string normalizedPhrase)
    {
        var words = normalizedPhrase.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 12)
        {
            if (words.Any(word => !LegacyRecoveryWordList.Contains(word, StringComparer.Ordinal)))
            {
                throw new ArgumentException("Recovery phrase contains invalid legacy words.", nameof(normalizedPhrase));
            }

            return;
        }

        if (words.Length != RecoveryPhraseWordCount)
        {
            throw new ArgumentException(
                $"Recovery phrase must contain {RecoveryPhraseWordCount} words, or 12 words for a legacy Deep account.",
                nameof(normalizedPhrase));
        }

        if (words.Any(word => !RecoveryWordIndexes.ContainsKey(word)))
        {
            throw new ArgumentException("Recovery phrase contains invalid words.", nameof(normalizedPhrase));
        }

        var wordCount = (ulong)RecoveryWordList.Length;
        for (var offset = 0; offset < RecoveryDataWordCount; offset += 3)
        {
            var first = (ulong)RecoveryWordIndexes[words[offset]];
            var second = (ulong)RecoveryWordIndexes[words[offset + 1]];
            var third = (ulong)RecoveryWordIndexes[words[offset + 2]];
            var decoded = first
                + wordCount * ((wordCount - first + second) % wordCount)
                + wordCount * wordCount * ((wordCount - second + third) % wordCount);
            if (decoded > uint.MaxValue || decoded % wordCount != first)
            {
                throw new ArgumentException("Recovery phrase contains an invalid word sequence.", nameof(normalizedPhrase));
            }
        }

        var dataWords = words.AsSpan(0, RecoveryDataWordCount).ToArray();
        var expectedChecksum = dataWords[GetChecksumWordIndex(dataWords)];
        if (!string.Equals(words[^1], expectedChecksum, StringComparison.Ordinal))
        {
            throw new ArgumentException("Recovery phrase checksum is invalid.", nameof(normalizedPhrase));
        }
    }

    private static string[] LoadRecoveryWordList()
    {
        using var stream = typeof(SessionAccountService).Assembly.GetManifestResourceStream(RecoveryWordListResource)
            ?? throw new InvalidOperationException($"Embedded recovery word list '{RecoveryWordListResource}' was not found.");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var words = reader
            .ReadToEnd()
            .Split([',', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(static word => word.ToLowerInvariant())
            .ToArray();

        if (words.Length != SessionRecoveryWordCount
            || words.Distinct(StringComparer.Ordinal).Count() != words.Length
            || words.Any(static word => word.Length < RecoveryWordPrefixLength)
            || words
                .Select(static word => word[..RecoveryWordPrefixLength])
                .Distinct(StringComparer.Ordinal)
                .Count() != words.Length)
        {
            throw new InvalidOperationException("The embedded recovery word list is malformed.");
        }

        return words;
    }
}
