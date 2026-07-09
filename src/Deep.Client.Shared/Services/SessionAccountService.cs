using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace Deep.Client.Shared.Services;

public sealed class SessionAccountService
{
    private readonly ISettingsRepository settings;
    private readonly IContactRepository contacts;
    private readonly IClock clock;
    private readonly IRecoveryProfileLookup? recoveryProfileLookup;
    private readonly SemaphoreSlim activeAccountGate = new(1, 1);
    private SessionAccount? activeAccountCache;
    private bool activeAccountCacheLoaded;

    public const string ActiveAccountKey = LocalSettingsKeys.ActiveAccount;
    public const string ActiveRecoveryPhraseKey = LocalSettingsKeys.ActiveRecoveryPhrase;
    public static readonly TimeSpan RecoveryProfileLookupTimeout = TimeSpan.FromSeconds(12);

    public SessionAccountService(
        ISettingsRepository settings,
        IContactRepository contacts,
        IClock clock,
        IRecoveryProfileLookup? recoveryProfileLookup = null)
    {
        this.settings = settings;
        this.contacts = contacts;
        this.clock = clock;
        this.recoveryProfileLookup = recoveryProfileLookup;
    }

    private static readonly string[] RecoveryWordList =
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

    public async Task<SessionAccount> RegisterAsync(string displayName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        var recoveryPhrase = GenerateRecoveryPhrase();
        var account = new SessionAccount(DeriveSessionIdFromRecoveryPhrase(recoveryPhrase), displayName.Trim(), clock.UtcNow);
        await PersistAccountAsync(account, cancellationToken).ConfigureAwait(false);
        await settings.SetAsync(ActiveRecoveryPhraseKey, recoveryPhrase, cancellationToken).ConfigureAwait(false);
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
        await PersistAccountAsync(account, cancellationToken).ConfigureAwait(false);
        await settings.SetAsync(ActiveRecoveryPhraseKey, normalizedPhrase, cancellationToken).ConfigureAwait(false);
        return account;
    }

    public async Task<SessionAccount?> GetActiveAccountAsync(CancellationToken cancellationToken = default)
    {
        await activeAccountGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (activeAccountCacheLoaded)
            {
                return activeAccountCache;
            }

            activeAccountCache = await settings.GetAsync<SessionAccount>(ActiveAccountKey, cancellationToken).ConfigureAwait(false);
            activeAccountCacheLoaded = true;
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
            await settings.DeleteAsync(ActiveAccountKey, cancellationToken).ConfigureAwait(false);
            activeAccountCache = null;
            activeAccountCacheLoaded = true;
            await settings.DeleteAsync(ActiveRecoveryPhraseKey, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            activeAccountGate.Release();
        }
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
        var words = new string[12];
        for (var index = 0; index < words.Length; index++)
        {
            var randomIndex = RandomNumberGenerator.GetInt32(RecoveryWordList.Length);
            words[index] = RecoveryWordList[randomIndex];
        }

        return string.Join(' ', words);
    }

    private static SessionId DeriveSessionIdFromRecoveryPhrase(string recoveryPhrase)
        => SessionIdentityMaterial.FromRecoveryPhrase(recoveryPhrase).SessionId;

    private static bool LooksLikeSessionId(string candidate)
    {
        var normalized = candidate.Trim().ToLowerInvariant();
        return normalized.Length == 66 && normalized.All(Uri.IsHexDigit);
    }

    private static string NormalizeRecoveryPhrase(string phrase) =>
        string.Join(' ', phrase
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(word => word.ToLowerInvariant()));

    private static void ValidateRecoveryPhrase(string normalizedPhrase)
    {
        var words = normalizedPhrase.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length != 12)
        {
            throw new ArgumentException("Recovery phrase must contain exactly 12 words.", nameof(normalizedPhrase));
        }

        if (words.Any(word => !RecoveryWordList.Contains(word, StringComparer.Ordinal)))
        {
            throw new ArgumentException("Recovery phrase contains invalid words.", nameof(normalizedPhrase));
        }
    }
}
