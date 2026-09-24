using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Network-free DID2 account entry point for a single private device store.
/// It never reads or migrates the incompatible STORE-V1 namespace.
/// </summary>
public sealed class DeepIdV2AccountService
{
    private readonly ProtectedDeepIdV2AccountOwner owner;
    private readonly IClock clock;
    private readonly Func<IDeepMlDsa65VerifierLease> verifierFactory;

    public DeepIdV2AccountService(IDeepSecureStorage storage,
        string privateDirectory, ReadOnlySpan<byte> networkId,
        ushort deploymentProfileId, IClock clock,
        Func<IDeepMlDsa65VerifierLease> verifierFactory)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateDirectory);
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.verifierFactory = verifierFactory ??
            throw new ArgumentNullException(nameof(verifierFactory));
        var directory = Path.GetFullPath(privateDirectory);
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException(
                "The DID2 account requires an existing private directory.");
        owner = new ProtectedDeepIdV2AccountOwner(storage,
            new DeepIdV2AccountFileLease(Path.Combine(directory,
                "deep-store-v2-account.lock")),
            Path.Combine(directory, "deep-store-v2-account.dsv2"),
            networkId, deploymentProfileId);
    }

    public async Task<DeepIdV2AccountSnapshot?> GetCurrentAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        using var current = await owner.ReadCurrentAsync(TrustedUnixSeconds(),
            verifier, cancellationToken).ConfigureAwait(false);
        return current is null ? null : Snapshot(current);
    }

    public async Task<DeepIdV2AccountSnapshot> CreateAsync(
        string displayName, CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        using var current = await owner.CreateFreshAsync(displayName,
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
        return Snapshot(current);
    }

    /// <summary>
    /// Opens the account-owned, SQLCipher-backed DID2 directory floor. The
    /// caller supplies the separately pinned signed empty V2 head; no V1
    /// directory state is read or migrated.
    /// </summary>
    public async Task<IDeepIdV2DirectoryProtectedLkgStore>
        OpenDirectoryLkgStoreAsync(
            VerifiedXPointNetworkAuthority authority,
            ReadOnlyMemory<byte> exactGenesisAdh1,
            ReadOnlyMemory<byte> protectedGenesisCoreHash,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        using var verifier = OpenVerifier();
        return await owner.OpenDirectoryLkgStoreAsync(TrustedUnixSeconds(),
            verifier, authority, exactGenesisAdh1,
            protectedGenesisCoreHash, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Caller owns and must dispose the returned phrase. Null means the user
    /// permanently deleted this device's retained phrase.
    /// </summary>
    public async Task<VerifiedDeepRecoveryPhrase?> ReadRetainedRecoveryPhraseAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadRetainedRecoveryPhraseAsync(
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task DeleteRetainedRecoveryPhraseAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        await owner.DeleteRetainedRecoveryPhraseAsync(TrustedUnixSeconds(),
            verifier, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Explicit destructive reset, never an automatic repair path.</summary>
    public Task ResetExplicitlyAsync(CancellationToken cancellationToken = default) =>
        owner.ResetExplicitlyAsync(cancellationToken).AsTask();

    private IDeepMlDsa65VerifierLease OpenVerifier() =>
        verifierFactory() ?? throw new InvalidOperationException(
            "The DID2 verifier factory returned no verifier lease.");

    private ulong TrustedUnixSeconds()
    {
        var seconds = clock.UtcNow.ToUnixTimeSeconds();
        if (seconds < 0)
            throw new InvalidOperationException(
                "The DID2 account clock precedes the Unix epoch.");
        return checked((ulong)seconds);
    }

    private static DeepIdV2AccountSnapshot Snapshot(
        VerifiedDeepIdV2CurrentAccount current) =>
        new(current.DisplayName, current.AccountId.Span,
            current.PermanentId);
}

public sealed class DeepIdV2AccountSnapshot
{
    private readonly byte[] accountId;

    internal DeepIdV2AccountSnapshot(string displayName,
        ReadOnlySpan<byte> accountId, DeepPermanentIdV2 permanentId)
    {
        DisplayName = displayName;
        this.accountId = accountId.ToArray();
        PermanentId = permanentId;
    }

    public string DisplayName { get; }
    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public DeepPermanentIdV2 PermanentId { get; }
}
