using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public enum MailboxCredentialScopeKind
{
    Self = 1,
    Peer = 2,
    Group = 3
}

public enum MailboxCredentialRole
{
    Retrieve = 1,
    Deposit = 2
}

public sealed class MailboxCredentialSelector
{
    private static ReadOnlySpan<byte> Domain => "deep.mailbox.credential-scope.v2"u8;
    private readonly byte[] subjectId;
    private readonly byte[] issuerContext;
    private readonly byte[]? groupMembershipCommitment;
    private readonly byte[] scopeId;

    public MailboxCredentialSelector(
        OutboxAccountScope accountScope,
        MailboxCredentialScopeKind kind,
        ReadOnlySpan<byte> subjectId,
        ReadOnlySpan<byte> issuerContext,
        ReadOnlySpan<byte> groupMembershipCommitment = default)
    {
        AccountScope = accountScope ?? throw new ArgumentNullException(nameof(accountScope));
        if (!Enum.IsDefined(kind) ||
            subjectId.Length != 32 ||
            subjectId.IndexOfAnyExcept((byte)0) < 0 ||
            issuerContext.Length != 32 ||
            issuerContext.IndexOfAnyExcept((byte)0) < 0 ||
            (kind == MailboxCredentialScopeKind.Group) !=
            (groupMembershipCommitment.Length == 32) ||
            !groupMembershipCommitment.IsEmpty &&
            groupMembershipCommitment.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("Mailbox credential selector is invalid.");
        }

        Kind = kind;
        this.subjectId = subjectId.ToArray();
        this.issuerContext = issuerContext.ToArray();
        this.groupMembershipCommitment = groupMembershipCommitment.IsEmpty
            ? null
            : groupMembershipCommitment.ToArray();
        scopeId = SHA256.HashData([
            .. Domain,
            .. accountScope.Value,
            (byte)kind,
            .. subjectId,
            .. issuerContext,
            .. (groupMembershipCommitment.IsEmpty
                ? ReadOnlySpan<byte>.Empty
                : groupMembershipCommitment)
        ]);
    }

    public OutboxAccountScope AccountScope { get; }
    public MailboxCredentialScopeKind Kind { get; }
    public ReadOnlyMemory<byte> SubjectId => subjectId.ToArray();
    public ReadOnlyMemory<byte> IssuerContext => issuerContext.ToArray();
    public ReadOnlyMemory<byte> GroupMembershipCommitment =>
        groupMembershipCommitment?.ToArray() ?? ReadOnlyMemory<byte>.Empty;
    public ReadOnlyMemory<byte> ScopeId => scopeId.ToArray();
    public override string ToString() => "[opaque-mailbox-credential-selector]";
}

public sealed class VerifiedOfficialMailboxAuthority
{
    private static ReadOnlySpan<byte> FingerprintDomain =>
        "deep.mailbox.authenticated-authority-policy.v2"u8;
    private readonly byte[] networkId;
    private readonly byte[] policyFingerprint;
    private readonly Func<bool> entitlement;
    private readonly IReadOnlyList<MailboxCapabilityIssuerAuthority>
        trustedIssuers;
    private readonly MailboxRuntimePolicyCoordinator policyCoordinator;

    internal VerifiedOfficialMailboxAuthority(
        ReadOnlyMemory<byte> networkId,
        ulong minimumGeneration,
        IReadOnlyList<MailboxCapabilityIssuerAuthority> trustedIssuers,
        bool requiresManagedEntitlement,
        Func<bool> entitlement,
        IFreshMailboxCapabilityRevocationSource revocations,
        TimeProvider timeProvider)
        : this(networkId, minimumGeneration, trustedIssuers,
            requiresManagedEntitlement, entitlement, revocations, timeProvider,
            MailboxRuntimePolicyCoordinator.Detached())
    {
    }

    internal VerifiedOfficialMailboxAuthority(
        ReadOnlyMemory<byte> networkId,
        ulong minimumGeneration,
        IReadOnlyList<MailboxCapabilityIssuerAuthority> trustedIssuers,
        bool requiresManagedEntitlement,
        Func<bool> entitlement,
        IFreshMailboxCapabilityRevocationSource revocations,
        TimeProvider timeProvider,
        MailboxRuntimePolicyCoordinator policyCoordinator)
    {
        ArgumentNullException.ThrowIfNull(trustedIssuers);
        networkId = networkId.ToArray();
        this.networkId = networkId.ToArray();
        MinimumGeneration = minimumGeneration;
        this.trustedIssuers = Array.AsReadOnly(trustedIssuers
            .Select(CloneIssuer)
            .OrderBy(static issuer => (byte)issuer.Domain)
            .ThenBy(static issuer => Convert.ToHexString(
                issuer.PublicKey.Span), StringComparer.Ordinal)
            .ToArray());
        RequiresManagedEntitlement = requiresManagedEntitlement;
        this.entitlement = entitlement ?? throw new ArgumentNullException(
            nameof(entitlement));
        Revocations = revocations ?? throw new ArgumentNullException(
            nameof(revocations));
        TimeProvider = timeProvider ?? throw new ArgumentNullException(
            nameof(timeProvider));
        this.policyCoordinator = policyCoordinator ?? throw new ArgumentNullException(
            nameof(policyCoordinator));
        Validate();
        policyFingerprint = ComputePolicyFingerprint(
            this.networkId, MinimumGeneration, RequiresManagedEntitlement,
            this.trustedIssuers);
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong MinimumGeneration { get; }
    public IReadOnlyList<MailboxCapabilityIssuerAuthority> TrustedIssuers =>
        Array.AsReadOnly(trustedIssuers.Select(CloneIssuer).ToArray());
    public bool RequiresManagedEntitlement { get; }
    public bool IsEntitled => !RequiresManagedEntitlement || entitlement();
    public IFreshMailboxCapabilityRevocationSource Revocations { get; }
    public TimeProvider TimeProvider { get; }
    public ReadOnlyMemory<byte> PolicyFingerprint =>
        policyFingerprint.ToArray();

    public ulong NowUnixSeconds => checked(
        (ulong)TimeProvider.GetUtcNow().ToUnixTimeSeconds());

    public void Validate()
    {
        Revocations.ValidateFreshness();
        if (!IsEntitled ||
            networkId.Length != 16 ||
            networkId.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            MinimumGeneration == 0 ||
            trustedIssuers is not { Count: > 0 and <= 8 } ||
            NowUnixSeconds == 0)
        {
            throw new InvalidOperationException(
                "Authenticated mailbox authority or managed entitlement is unavailable.");
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var issuer in trustedIssuers)
        {
            if (issuer.PublicKey.Length != 32 ||
                issuer.PublicKey.Span.IndexOfAnyExcept((byte)0) < 0 ||
                issuer.Domain is not (
                    MailboxCapabilityDomain.Deposit or
                    MailboxCapabilityDomain.Retrieve) ||
                issuer.AllowedLifecycle is not (
                    MailboxCapabilityLifecycle.Active or
                    MailboxCapabilityLifecycle.Overlap) ||
                issuer.MinimumGeneration == 0 ||
                issuer.MinimumGeneration > issuer.MaximumGeneration ||
                issuer.ValidFromUnixSeconds >= issuer.ValidUntilUnixSeconds ||
                !unique.Add($"{(byte)issuer.Domain}:" +
                    Convert.ToHexString(issuer.PublicKey.Span)))
            {
                throw new InvalidOperationException(
                    "Authenticated mailbox issuer authority is invalid.");
            }
        }
    }

    internal ValueTask<IAsyncDisposable>
        AcquireDispatchPolicyAsync(CancellationToken cancellationToken = default) =>
        policyCoordinator.AcquireDispatchAsync(cancellationToken);

    public void ReloadCommittedPolicy() => Revocations.ValidateFreshness();

    internal bool UsesSharedPolicyCoordinator(
        string canonicalStateIdentity,
        ReadOnlySpan<byte> stableAuthorityId) =>
        policyCoordinator.Matches(canonicalStateIdentity, stableAuthorityId);

    internal MailboxCapabilityIssuerAuthority ResolveIssuer(
        MailboxAuthenticatedGrant grant) => trustedIssuers.FirstOrDefault(
            issuer => issuer.Domain == grant.Domain &&
                ScopedMailboxCredentialValidator.Fixed(
                    issuer.PublicKey.Span,
                    grant.IssuerPublicKey.Span)) ??
            throw new InvalidDataException(
                "Scoped mailbox grant issuer is not trusted for its domain.");

    private static MailboxCapabilityIssuerAuthority CloneIssuer(
        MailboxCapabilityIssuerAuthority issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        return issuer with { PublicKey = issuer.PublicKey.ToArray() };
    }

    private static byte[] ComputePolicyFingerprint(
        ReadOnlySpan<byte> network,
        ulong minimumGeneration,
        bool requiresManagedEntitlement,
        IReadOnlyList<MailboxCapabilityIssuerAuthority> issuers)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(FingerprintDomain);
        hash.AppendData(network);
        hash.AppendData([requiresManagedEntitlement ? (byte)1 : (byte)0]);
        Span<byte> encoded = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
            encoded, minimumGeneration);
        hash.AppendData(encoded);
        hash.AppendData([(byte)issuers.Count]);
        foreach (var issuer in issuers)
        {
            hash.AppendData([(byte)issuer.Domain, (byte)issuer.AllowedLifecycle]);
            hash.AppendData(issuer.PublicKey.Span);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
                encoded, issuer.MinimumGeneration);
            hash.AppendData(encoded);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
                encoded, issuer.MaximumGeneration);
            hash.AppendData(encoded);
        }
        return hash.GetHashAndReset();
    }
}

public sealed record ScopedMailboxCredentialGeneration(
    MailboxCredentialSelector Selector,
    ReadOnlyMemory<byte> Generation,
    ReadOnlyMemory<byte> HolderPublicKey,
    ReadOnlyMemory<byte> MailboxId,
    MailboxCredentialEpoch Current,
    MailboxCredentialEpoch Next,
    MailboxCredentialGrantSet? Retrieve,
    MailboxCredentialGrantSet? Deposit,
    MailboxCredentialReplicaPair CurrentReplicas,
    MailboxCredentialReplicaPair NextReplicas)
{
    public MailboxCredentialReplicaPair ReplicasFor(ulong epoch) =>
        epoch == Current.Epoch
            ? CurrentReplicas
            : epoch == Next.Epoch
                ? NextReplicas
                : throw new ArgumentOutOfRangeException(
                    nameof(epoch),
                    "Replica pins are unavailable for the requested credential epoch.");
}

public sealed record ScopedMailboxBatchTarget(
    MailboxCredentialSelector Selector,
    MailboxAuthenticatedRequestBinding Binding);

public sealed record ScopedMailboxBatchSelector(
    MailboxCredentialSelector Selector,
    MessageId WireMessageId,
    MailboxAuthenticatedOperation Operation);

/// <summary>Opaque route material resolved only from a verified scoped credential.</summary>
public sealed record ScopedMailboxResolvedRoute(
    ulong Epoch,
    ulong ExpiresAtUnixSeconds,
    BlindedMailboxId MailboxId,
    BlindedPlacementId PlacementId,
    ReadOnlyMemory<byte> PlacementCommitment,
    ReadOnlyMemory<byte> MembershipCommitment,
    MailboxCredentialReplicaPair Replicas);

public sealed record ScopedMailboxPrepareBatchRequest(
    OutboxAccountScope AccountScope,
    ReadOnlyMemory<byte> ParentOperationId,
    ReadOnlyMemory<byte> SemanticOperationId,
    IReadOnlyList<ScopedMailboxBatchSelector> Selectors,
    IReadOnlyList<ScopedMailboxBatchTarget> Targets,
    DateTimeOffset CreatedAt);

public sealed record ScopedMailboxResumeBatchRequest(
    OutboxAccountScope AccountScope,
    ReadOnlyMemory<byte> ParentOperationId,
    ReadOnlyMemory<byte> SemanticOperationId,
    IReadOnlyList<ScopedMailboxBatchSelector> Selectors);

internal sealed record MailboxBundleRuntimeCheckpoint(
    int SchemaVersion,
    string Lane,
    string Platform,
    string Ownership,
    ulong CurrentEpoch,
    string PairGeneration);

internal sealed record MailboxRevocationRuntimeCheckpoint(
    int SchemaVersion,
    ulong GeneratedAtUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    string SnapshotSha256,
    string[] RevokedKeys);

internal sealed record MailboxRuntimeSnapshotCheckpoint(
    string BundleKey,
    MailboxBundleRuntimeCheckpoint Bundle,
    string RevocationKey,
    MailboxRevocationRuntimeCheckpoint Revocation);

internal sealed record ProductionMailboxRuntimePublicationJournal(
    int SchemaVersion,
    ulong TargetTrustRevision,
    string TargetTrustStateSha256,
    ulong CurrentEpoch,
    string PairGeneration,
    string SignedBundleSha256,
    string SignedBundleBase64,
    ulong VerificationExpiresAtUnixSeconds,
    ulong RefreshAfterUnixSeconds,
    ulong VerifiedAtUnixSeconds,
    string RouteCertificateSha256,
    string RouteAdvertisementSha256,
    string RouteDomainSha256,
    ulong RouteAdvertisementSequence);

public sealed class ScopedMailboxPreparedBatch
{
    internal ScopedMailboxPreparedBatch(
        ReadOnlyMemory<byte> parentOperationId,
        IReadOnlyList<MailboxAuthenticatedRequestFrame> frames)
    {
        ParentOperationId = parentOperationId.ToArray();
        Frames = Array.AsReadOnly(frames.ToArray());
    }

    public ReadOnlyMemory<byte> ParentOperationId { get; }
    public IReadOnlyList<MailboxAuthenticatedRequestFrame> Frames { get; }
}

public interface IScopedMailboxCredentialRepository
{
    /// <summary>
    /// Installs an exact self/peer/group credential snapshot atomically.  A retry
    /// is accepted only when every persisted credential byte is identical.
    /// Scope-specific generations, mailbox IDs, grants, and grant serials may
    /// never be shared by distinct scopes. Stable XNode replica identity keys
    /// may serve several independently scoped placements.
    /// </summary>
    Task InstallScopedCredentialBatchAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default);

    Task InstallScopedCredentialAsync(
        ScopedMailboxCredentialGeneration generation,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically rotates an existing batch from E/E+1 to E+1/E+2. The persisted E+1
    /// epoch and all of its grants must be byte-identical to the incoming current epoch.
    /// </summary>
    Task RotateScopedCredentialBatchAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default);

    Task SwitchScopedCredentialEpochAsync(
        MailboxCredentialSelector selector,
        ulong epoch,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default);

    Task<ScopedMailboxResolvedRoute> ReadScopedMailboxRouteAsync(
        MailboxCredentialSelector selector,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revalidates the exact active grant and route for one operation at the
    /// dispatch boundary.  A prepared frame is not authority to bypass a
    /// later expiry, entitlement change, issuer mismatch, or revocation.
    /// </summary>
    Task<ScopedMailboxResolvedRoute> RevalidateScopedMailboxDispatchAsync(
        MailboxCredentialSelector selector,
        MailboxAuthenticatedOperation operation,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default);

    Task<ScopedMailboxPreparedBatch> PrepareScopedMailboxBatchAsync(
        ScopedMailboxPrepareBatchRequest request,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resumes an already committed logical fan-out without requiring the caller to recreate
    /// randomized ciphertext. A null result means that no batch exists; any persisted conflict,
    /// stale authority, or corruption fails closed.
    /// </summary>
    Task<ScopedMailboxPreparedBatch?> TryResumeScopedMailboxBatchAsync(
        ScopedMailboxResumeBatchRequest request,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default);
}

public sealed partial class SqliteSessionStore : IScopedMailboxCredentialRepository
{
    private const int MaximumProductionPublicationPayloadChars =
        ProductionMailboxLocalOwnerJournalCodec.MaximumBase64Length + 4_096;
    public const int MaximumScopedMailboxBatchTargets = 2048;
    public const long MaximumScopedMailboxBatchRequestBytes =
        128L * 1024 * 1024;
    public async Task InstallScopedCredentialAsync(
        ScopedMailboxCredentialGeneration generation,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
        => await InstallScopedCredentialBatchAsync([generation], authority, cancellationToken)
            .ConfigureAwait(false);

    public async Task InstallScopedCredentialBatchAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ValidateInstallBatch(generations, authority);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            InstallCore(connection, transaction, generations, authority, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    public async Task RotateScopedCredentialBatchAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ValidateInstallBatch(generations, authority);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            RotateCore(connection, transaction, generations, authority, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    internal async Task ApplyScopedMailboxRuntimeSnapshotAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        MailboxRuntimeSnapshotCheckpoint checkpoint,
        MailboxRuntimeCommitActivation? committedActivation = null,
        CancellationToken cancellationToken = default)
        => await ApplyScopedMailboxRuntimeSnapshotCoreAsync(
            generations,
            authority,
            checkpoint,
            publicationJournalKey: null,
            activeBundleKey: null,
            publicationJournal: null,
            committedActivation,
            allowDevelopmentPairRebind: false,
            cancellationToken).ConfigureAwait(false);

    internal async Task ApplyDevelopmentMailboxRuntimeSnapshotAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        MailboxRuntimeSnapshotCheckpoint checkpoint,
        MailboxRuntimeCommitActivation? committedActivation = null,
        CancellationToken cancellationToken = default)
        => await ApplyScopedMailboxRuntimeSnapshotCoreAsync(
            generations,
            authority,
            checkpoint,
            publicationJournalKey: null,
            activeBundleKey: null,
            publicationJournal: null,
            committedActivation,
            allowDevelopmentPairRebind: true,
            cancellationToken).ConfigureAwait(false);

    internal async Task StageProductionMailboxRuntimePublicationAsync(
        string journalKey,
        ProductionMailboxRuntimePublicationJournal journal,
        CancellationToken cancellationToken = default)
        => await StageProductionMailboxRuntimePublicationAsync(
            journalKey, activeBundleKey: null, journal, cancellationToken)
            .ConfigureAwait(false);

    internal async Task StageProductionMailboxRuntimePublicationAsync(
        string journalKey,
        string? activeBundleKey,
        ProductionMailboxRuntimePublicationJournal journal,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(journalKey);
        if (activeBundleKey is not null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(activeBundleKey);
            if (string.Equals(journalKey, activeBundleKey, StringComparison.Ordinal))
                throw new ArgumentException(
                    "Production publication journal and active-bundle keys must differ.");
        }
        ValidateProductionPublicationJournal(journal);
        var payload = System.Text.Json.JsonSerializer.Serialize(
            journal, SerializerOptions);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            var prior = ReadProductionPublicationWithPayload(
                connection, transaction, journalKey);
            if (activeBundleKey is not null)
            {
                var active = ReadProductionPublicationWithPayload(
                    connection, transaction, activeBundleKey).Value;
                if (active is not null)
                {
                    ValidateProductionPublicationJournal(active);
                    ValidateProductionPublicationForward(active, journal);
                }
            }
            if (prior.Value is not null)
            {
                ValidateProductionPublicationJournal(prior.Value);
                if (prior.Value != journal)
                    throw new InvalidOperationException(
                        "A different production mailbox publication is already pending.");
            }
            else
            {
                CompareExchangeSetting(connection, transaction, journalKey, null, payload);
            }
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    internal async Task<ProductionMailboxRuntimePublicationJournal?>
        ReadProductionMailboxRuntimePublicationAsync(
            string key,
            CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            var value = ReadProductionPublicationWithPayload(connection, null, key).Value;
            if (value is not null) ValidateProductionPublicationJournal(value);
            return value;
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    internal async Task<bool> IsProductionMailboxRuntimePublicationCompleteAsync(
        MailboxRuntimeSnapshotCheckpoint checkpoint,
        string journalKey,
        string activeBundleKey,
        ProductionMailboxRuntimePublicationJournal journal,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(journalKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(activeBundleKey);
        ValidateProductionPublicationJournal(journal);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            var pending = ReadProductionPublicationWithPayload(
                connection, transaction, journalKey).Value;
            var active = ReadProductionPublicationWithPayload(
                connection, transaction, activeBundleKey);
            var bundle = ReadSettingWithPayload<MailboxBundleRuntimeCheckpoint>(
                connection, transaction, checkpoint.BundleKey);
            var revocation = ReadSettingWithPayload<MailboxRevocationRuntimeCheckpoint>(
                connection, transaction, checkpoint.RevocationKey);
            if (active.Value is not null) ValidateProductionPublicationJournal(active.Value);
            if (bundle.Value is not null) ValidateBundleCheckpoint(null, bundle.Value);
            if (revocation.Value is not null)
                ValidateRevocationCheckpoint(null, revocation.Value);
            transaction.Commit();
            return pending is null &&
                string.Equals(active.Payload,
                    System.Text.Json.JsonSerializer.Serialize(journal, SerializerOptions),
                    StringComparison.Ordinal) &&
                string.Equals(bundle.Payload,
                    System.Text.Json.JsonSerializer.Serialize(
                        checkpoint.Bundle, SerializerOptions),
                    StringComparison.Ordinal) &&
                string.Equals(revocation.Payload,
                    System.Text.Json.JsonSerializer.Serialize(
                        checkpoint.Revocation, SerializerOptions),
                    StringComparison.Ordinal);
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    internal async Task CompleteProductionMailboxRuntimePublicationAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        MailboxRuntimeSnapshotCheckpoint checkpoint,
        string journalKey,
        string activeBundleKey,
        ProductionMailboxRuntimePublicationJournal journal,
        MailboxRuntimeCommitActivation? committedActivation = null,
        CancellationToken cancellationToken = default)
        => await ApplyScopedMailboxRuntimeSnapshotCoreAsync(
            generations,
            authority,
            checkpoint,
            journalKey,
            activeBundleKey,
            journal,
            committedActivation,
            allowDevelopmentPairRebind: false,
            cancellationToken).ConfigureAwait(false);

    private async Task ApplyScopedMailboxRuntimeSnapshotCoreAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        MailboxRuntimeSnapshotCheckpoint checkpoint,
        string? publicationJournalKey,
        string? activeBundleKey,
        ProductionMailboxRuntimePublicationJournal? publicationJournal,
        MailboxRuntimeCommitActivation? committedActivation,
        bool allowDevelopmentPairRebind,
        CancellationToken cancellationToken)
    {
        ValidateInstallBatch(generations, authority);
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(checkpoint.BundleKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(checkpoint.RevocationKey);
        ValidateBundleCheckpoint(null, checkpoint.Bundle);
        ValidateRevocationCheckpoint(null, checkpoint.Revocation);
        if ((publicationJournalKey is null) != (publicationJournal is null) ||
            (activeBundleKey is null) != (publicationJournal is null))
            throw new ArgumentException(
                "Production publication journal, active-bundle key, and value must be supplied together.");
        if (publicationJournal is not null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(publicationJournalKey);
            ArgumentException.ThrowIfNullOrWhiteSpace(activeBundleKey);
            if (string.Equals(publicationJournalKey, activeBundleKey,
                    StringComparison.Ordinal))
                throw new ArgumentException(
                    "Production publication journal and active-bundle keys must differ.");
            ValidateProductionPublicationJournal(publicationJournal);
            if (publicationJournal.CurrentEpoch != checkpoint.Bundle.CurrentEpoch ||
                !string.Equals(publicationJournal.PairGeneration,
                    checkpoint.Bundle.PairGeneration, StringComparison.Ordinal))
                throw new InvalidDataException(
                    "Production publication journal differs from its runtime snapshot.");
        }
        var bundlePayload = System.Text.Json.JsonSerializer.Serialize(
            checkpoint.Bundle, SerializerOptions);
        var revocationPayload = System.Text.Json.JsonSerializer.Serialize(
            checkpoint.Revocation, SerializerOptions);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            var priorBundleRow = ReadSettingWithPayload<MailboxBundleRuntimeCheckpoint>(
                connection, transaction, checkpoint.BundleKey);
            var priorRevocationRow = ReadSettingWithPayload<MailboxRevocationRuntimeCheckpoint>(
                connection, transaction, checkpoint.RevocationKey);
            string? publicationPayload = null;
            (ProductionMailboxRuntimePublicationJournal? Value, string? Payload)
                activeBundleRow = default;
            if (publicationJournal is not null)
            {
                var pending = ReadProductionPublicationWithPayload(
                    connection, transaction, publicationJournalKey!);
                if (pending.Value is null || pending.Value != publicationJournal)
                    throw new InvalidOperationException(
                        "Production mailbox publication journal is unavailable or changed.");
                publicationPayload = pending.Payload;
                activeBundleRow =
                    ReadProductionPublicationWithPayload(
                        connection, transaction, activeBundleKey!);
                if (activeBundleRow.Value is not null)
                {
                    ValidateProductionPublicationJournal(activeBundleRow.Value);
                    ValidateProductionPublicationForward(
                        activeBundleRow.Value, publicationJournal);
                }
            }
            var priorBundle = priorBundleRow.Value;
            var priorRevocation = priorRevocationRow.Value;
            if (priorBundle is not null) ValidateBundleCheckpoint(null, priorBundle);
            if (priorRevocation is not null) ValidateRevocationCheckpoint(null, priorRevocation);
            ValidateBundleCheckpoint(
                priorBundle,
                checkpoint.Bundle,
                allowDevelopmentPairRebind);
            ValidateRevocationCheckpoint(priorRevocation, checkpoint.Revocation);
            var rotate = priorBundle is not null &&
                checkpoint.Bundle.CurrentEpoch > priorBundle.CurrentEpoch;
            if (rotate)
                RotateCore(connection, transaction, generations, authority, cancellationToken);
            else
                InstallCore(connection, transaction, generations, authority, cancellationToken);
            CompareExchangeSetting(connection, transaction, checkpoint.BundleKey,
                priorBundleRow.Payload, bundlePayload);
            CompareExchangeSetting(connection, transaction, checkpoint.RevocationKey,
                priorRevocationRow.Payload, revocationPayload);
            if (publicationJournal is not null)
            {
                CompareExchangeSetting(connection, transaction, activeBundleKey!,
                    activeBundleRow.Payload, publicationPayload!);
                DeleteSettingCompareExchange(
                    connection, transaction, publicationJournalKey!, publicationPayload!);
            }
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            committedActivation?.ActivateCommittedNoThrow();
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    internal MailboxRevocationRuntimeCheckpoint ReadMailboxRevocationCheckpoint(
        string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        using var connection = OpenConnection();
        var checkpoint = ReadSettingWithPayload<MailboxRevocationRuntimeCheckpoint>(
            connection, null, key).Value ?? throw new InvalidOperationException(
            "Committed mailbox revocation authority is unavailable.");
        ValidateRevocationCheckpoint(null, checkpoint);
        return checkpoint;
    }

    private static (T? Value, string? Payload) ReadSettingWithPayload<T>(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string key)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT payload_json FROM settings WHERE key=$key;";
        command.Parameters.AddWithValue("$key", key);
        var payload = command.ExecuteScalar() as string;
        if (payload is null) return (default, null);
        try
        {
            return (System.Text.Json.JsonSerializer.Deserialize<T>(payload, SerializerOptions)
                ?? throw new InvalidDataException(
                    "Mailbox runtime checkpoint is invalid JSON."), payload);
        }
        catch (System.Text.Json.JsonException exception)
        {
            throw new InvalidDataException(
                "Mailbox runtime checkpoint is invalid JSON.", exception);
        }
    }

    private static (ProductionMailboxRuntimePublicationJournal? Value, string? Payload)
        ReadProductionPublicationWithPayload(
            SqliteConnection connection,
            SqliteTransaction? transaction,
            string key)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT length(payload_json),payload_json FROM settings WHERE key=$key;";
        command.Parameters.AddWithValue("$key", key);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return (null, null);
        var length = reader.GetInt64(0);
        if (length is <= 0 or > MaximumProductionPublicationPayloadChars)
            throw new InvalidDataException(
                "Production mailbox publication payload exceeds its strict bound.");
        var payload = reader.GetString(1);
        if (payload.Length != length)
            throw new InvalidDataException(
                "Production mailbox publication payload length is inconsistent.");
        try
        {
            var value = System.Text.Json.JsonSerializer
                .Deserialize<ProductionMailboxRuntimePublicationJournal>(
                    payload, SerializerOptions)
                ?? throw new InvalidDataException(
                    "Production mailbox publication payload is invalid JSON.");
            var canonical = System.Text.Json.JsonSerializer.Serialize(
                value, SerializerOptions);
            if (!string.Equals(payload, canonical, StringComparison.Ordinal))
                throw new InvalidDataException(
                    "Production mailbox publication payload is not canonical JSON.");
            return (value, payload);
        }
        catch (System.Text.Json.JsonException exception)
        {
            throw new InvalidDataException(
                "Production mailbox publication payload is invalid JSON.", exception);
        }
    }

    private static void CompareExchangeSetting(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string key,
        string? priorPayload,
        string payload)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = priorPayload is null
            ? "INSERT OR IGNORE INTO settings(key,payload_json) VALUES($key,$payload);"
            : "UPDATE settings SET payload_json=$payload WHERE key=$key AND payload_json=$prior;";
        command.Parameters.AddWithValue("$key", key);
        command.Parameters.AddWithValue("$payload", payload);
        if (priorPayload is not null)
            command.Parameters.AddWithValue("$prior", priorPayload);
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException(
                "Mailbox runtime checkpoint compare-and-swap failed.");
    }

    private static void DeleteSettingCompareExchange(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string key,
        string priorPayload)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "DELETE FROM settings WHERE key=$key AND payload_json=$prior;";
        command.Parameters.AddWithValue("$key", key);
        command.Parameters.AddWithValue("$prior", priorPayload);
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException(
                "Production mailbox publication journal compare-and-delete failed.");
    }

    private static void ValidateProductionPublicationJournal(
        ProductionMailboxRuntimePublicationJournal? journal)
    {
        if (journal is null || journal.SchemaVersion != 2 ||
            journal.TargetTrustRevision == 0 || journal.CurrentEpoch == 0 ||
            journal.RefreshAfterUnixSeconds == 0 ||
            journal.RefreshAfterUnixSeconds >= journal.VerificationExpiresAtUnixSeconds ||
            journal.VerifiedAtUnixSeconds == 0 ||
            journal.VerifiedAtUnixSeconds > journal.VerificationExpiresAtUnixSeconds ||
            !IsLowerHex(journal.TargetTrustStateSha256, 64) ||
            !IsLowerHex(journal.PairGeneration, 64) ||
            !IsLowerHex(journal.SignedBundleSha256, 64) ||
            !IsLowerHex(journal.RouteCertificateSha256, 64) ||
            !IsLowerHex(journal.RouteAdvertisementSha256, 64) ||
            !IsLowerHex(journal.RouteDomainSha256, 64) ||
            journal.RouteAdvertisementSequence == 0 ||
            string.IsNullOrEmpty(journal.SignedBundleBase64) ||
            journal.SignedBundleBase64.Length >
                ProductionMailboxLocalOwnerJournalCodec.MaximumBase64Length)
            throw new InvalidDataException(
                "Production mailbox publication journal is invalid.");
        byte[] encoded;
        try
        {
            encoded = Convert.FromBase64String(journal.SignedBundleBase64);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Production mailbox publication journal bundle is not canonical base64.",
                exception);
        }
        try
        {
            if (encoded.Length is <= 0 or >
                    ProductionMailboxLocalOwnerJournalCodec.MaximumEncodedLength ||
                !string.Equals(
                    Convert.ToBase64String(encoded),
                    journal.SignedBundleBase64,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    Convert.ToHexStringLower(SHA256.HashData(encoded)),
                    journal.SignedBundleSha256,
                    StringComparison.Ordinal))
                throw new InvalidDataException(
                    "Production mailbox publication journal bundle hash is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static void ValidateProductionPublicationForward(
        ProductionMailboxRuntimePublicationJournal prior,
        ProductionMailboxRuntimePublicationJournal current)
    {
        if (current.TargetTrustRevision < prior.TargetTrustRevision ||
            current.CurrentEpoch < prior.CurrentEpoch ||
            !string.Equals(current.RouteDomainSha256,
                prior.RouteDomainSha256, StringComparison.Ordinal) ||
            current.RouteAdvertisementSequence < prior.RouteAdvertisementSequence ||
            current.RouteAdvertisementSequence == prior.RouteAdvertisementSequence &&
                !string.Equals(current.RouteAdvertisementSha256,
                    prior.RouteAdvertisementSha256, StringComparison.Ordinal) ||
            current.TargetTrustRevision == prior.TargetTrustRevision && current != prior)
            throw new InvalidDataException(
                "Production active public bundle is not an exact replay or forward rotation.");
    }

    private static void ValidateBundleCheckpoint(
        MailboxBundleRuntimeCheckpoint? prior,
        MailboxBundleRuntimeCheckpoint current,
        bool allowDevelopmentPairRebind = false)
    {
        if (current.SchemaVersion != 1 || current.CurrentEpoch == 0 ||
            string.IsNullOrWhiteSpace(current.Lane) ||
            string.IsNullOrWhiteSpace(current.Platform) ||
            string.IsNullOrWhiteSpace(current.Ownership) ||
            !IsLowerHex(current.PairGeneration, 64) ||
            current.Lane is not ("android-windows-pair" or
                "production-local-owner") ||
            current.Platform is not ("android" or "windows") ||
            current.Ownership is not ("UserManaged" or "OfficialManaged"))
            throw new InvalidDataException("Mailbox bundle checkpoint is invalid.");
        if (prior is null) return;
        var authenticatedDevelopmentPairRebind =
            allowDevelopmentPairRebind &&
            prior.SchemaVersion == current.SchemaVersion &&
            string.Equals(prior.Lane, "android-windows-pair", StringComparison.Ordinal) &&
            string.Equals(current.Lane, "android-windows-pair", StringComparison.Ordinal) &&
            string.Equals(prior.Platform, current.Platform, StringComparison.Ordinal) &&
            string.Equals(prior.Ownership, "UserManaged", StringComparison.Ordinal) &&
            string.Equals(current.Ownership, "UserManaged", StringComparison.Ordinal) &&
            prior.CurrentEpoch == current.CurrentEpoch &&
            !string.Equals(prior.PairGeneration,
                current.PairGeneration, StringComparison.Ordinal);
        if (prior.SchemaVersion != current.SchemaVersion ||
            !string.Equals(prior.Lane, current.Lane, StringComparison.Ordinal) ||
            !string.Equals(prior.Platform, current.Platform, StringComparison.Ordinal) ||
            !string.Equals(prior.Ownership, current.Ownership, StringComparison.Ordinal) ||
            current.CurrentEpoch < prior.CurrentEpoch ||
            current.CurrentEpoch - prior.CurrentEpoch > 1 ||
            current.CurrentEpoch == prior.CurrentEpoch && prior != current &&
                !authenticatedDevelopmentPairRebind)
            throw new InvalidDataException(
                "Mailbox bundle checkpoint is not an exact replay or forward rotation.");
    }

    private static void ValidateRevocationCheckpoint(
        MailboxRevocationRuntimeCheckpoint? prior,
        MailboxRevocationRuntimeCheckpoint current)
    {
        if (current.SchemaVersion != 1 ||
            current.GeneratedAtUnixSeconds >= current.ExpiresAtUnixSeconds ||
            !IsLowerHex(current.SnapshotSha256, 64) || current.RevokedKeys is null ||
            current.RevokedKeys.Length > 100_000 ||
            !current.RevokedKeys.SequenceEqual(
                current.RevokedKeys.OrderBy(static key => key, StringComparer.Ordinal),
                StringComparer.Ordinal) ||
            current.RevokedKeys.Any(static key => !IsCanonicalRevocationKey(key)) ||
            current.RevokedKeys.Distinct(StringComparer.Ordinal).Count() !=
                current.RevokedKeys.Length)
            throw new InvalidDataException("Mailbox revocation checkpoint is invalid.");
        if (prior is null) return;
        var exact = prior.SchemaVersion == current.SchemaVersion &&
            prior.GeneratedAtUnixSeconds == current.GeneratedAtUnixSeconds &&
            prior.ExpiresAtUnixSeconds == current.ExpiresAtUnixSeconds &&
            string.Equals(prior.SnapshotSha256, current.SnapshotSha256,
                StringComparison.Ordinal) &&
            prior.RevokedKeys.SequenceEqual(current.RevokedKeys,
                StringComparer.Ordinal);
        if (current.GeneratedAtUnixSeconds < prior.GeneratedAtUnixSeconds ||
            current.GeneratedAtUnixSeconds == prior.GeneratedAtUnixSeconds && !exact)
            throw new InvalidDataException(
                "Mailbox revocation checkpoint is not an exact replay or monotonic replacement.");
    }

    private static bool IsLowerHex(string? value, int length) =>
        value is { Length: > 0 } && value.Length == length &&
        value.All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsCanonicalRevocationKey(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 256) return false;
        var parts = value.Split(':');
        return parts.Length == 6 && IsUpperHex(parts[0], 64) &&
            IsUpperHex(parts[1], 32) && parts[2] is ("1" or "2") &&
            ulong.TryParse(parts[3], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var generation) &&
            generation > 0 &&
            ulong.TryParse(parts[4], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var epoch) &&
            epoch > 0 && IsUpperHex(parts[5], 64);
    }

    private static bool IsUpperHex(string value, int length) =>
        value.Length == length &&
        value.All(static c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static void InstallCore(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken)
    {
        foreach (var generation in generations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (CredentialExists(connection, transaction, generation))
            {
                EnsureExactInstalledCredential(connection, transaction, generation, authority);
                continue;
            }
            EnsureNoCrossScopeMaterialReuse(connection, transaction, generation);
            var selector = generation.Selector;
            using (var insert = connection.CreateCommand())
            {
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO mailbox_credential_scopes(
                        scope_id,account_scope,scope_kind,subject_id,issuer_context,network_id,
                        authority_policy_digest,holder_key,generation,active_epoch,
                        group_membership_commitment)
                    VALUES($scope,$account,$kind,$subject,$issuer,$network,$authorityPolicy,
                           $holder,$generation,$epoch,$membership);
                    """;
                insert.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
                insert.Parameters.Add("$account", SqliteType.Blob).Value = selector.AccountScope.ToArray();
                insert.Parameters.AddWithValue("$kind", (int)selector.Kind);
                insert.Parameters.Add("$subject", SqliteType.Blob).Value = selector.SubjectId.ToArray();
                insert.Parameters.Add("$issuer", SqliteType.Blob).Value = selector.IssuerContext.ToArray();
                insert.Parameters.Add("$network", SqliteType.Blob).Value = authority.NetworkId.ToArray();
                insert.Parameters.Add("$authorityPolicy", SqliteType.Blob).Value = authority.PolicyFingerprint.ToArray();
                insert.Parameters.Add("$holder", SqliteType.Blob).Value = generation.HolderPublicKey.ToArray();
                insert.Parameters.Add("$generation", SqliteType.Blob).Value = generation.Generation.ToArray();
                insert.Parameters.Add("$epoch", SqliteType.Blob).Value = MailboxU64(
                    ScopedMailboxCredentialValidator.ActiveEpochForInstall(
                        generation, authority));
                insert.Parameters.Add("$membership", SqliteType.Blob).Value =
                    selector.GroupMembershipCommitment.IsEmpty
                        ? DBNull.Value : selector.GroupMembershipCommitment.ToArray();
                insert.ExecuteNonQuery();
            }
            InsertEpoch(connection, transaction, generation, generation.Current);
            InsertEpoch(connection, transaction, generation, generation.Next);
            InsertGrants(connection, transaction, generation, generation.Current.Epoch);
            InsertGrants(connection, transaction, generation, generation.Next.Epoch);
        }
    }

    private static void RotateCore(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken)
    {
        foreach (var generation in generations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!CredentialExists(connection, transaction, generation))
                throw new InvalidOperationException(
                    "Mailbox credential rotation requires an installed scope.");
            if (IsExactInstalledGeneration(connection, transaction, generation, authority))
            {
                EnsureExactInstalledCredential(connection, transaction, generation, authority);
                continue;
            }
            EnsureNoCrossScopeMaterialReuse(connection, transaction, generation);
            EnsureExactRotationOverlap(connection, transaction, generation, authority);
            EnsureNoSameScopeRotationReuse(connection, transaction, generation);
            using (var deleteReplay = connection.CreateCommand())
            {
                deleteReplay.Transaction = transaction;
                deleteReplay.CommandText = "DELETE FROM mailbox_replay_counters WHERE scope_id=$scope AND epoch<>$overlap;";
                deleteReplay.Parameters.Add("$scope", SqliteType.Blob).Value = generation.Selector.ScopeId.ToArray();
                deleteReplay.Parameters.Add("$overlap", SqliteType.Blob).Value = MailboxU64(generation.Current.Epoch);
                deleteReplay.ExecuteNonQuery();
            }
            using (var deleteOld = connection.CreateCommand())
            {
                deleteOld.Transaction = transaction;
                deleteOld.CommandText = "DELETE FROM mailbox_credential_epochs WHERE scope_id=$scope AND epoch<>$overlap;";
                deleteOld.Parameters.Add("$scope", SqliteType.Blob).Value = generation.Selector.ScopeId.ToArray();
                deleteOld.Parameters.Add("$overlap", SqliteType.Blob).Value = MailboxU64(generation.Current.Epoch);
                if (deleteOld.ExecuteNonQuery() != 1)
                    throw new InvalidDataException("Mailbox credential rotation expected exactly one retired epoch.");
            }
            InsertEpoch(connection, transaction, generation, generation.Next);
            InsertGrants(connection, transaction, generation, generation.Next.Epoch);
            using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE mailbox_credential_scopes
                SET generation=$generation,active_epoch=$active,
                    authority_policy_digest=$authorityPolicy
                WHERE scope_id=$scope;
                """;
            update.Parameters.Add("$generation", SqliteType.Blob).Value = generation.Generation.ToArray();
            update.Parameters.Add("$active", SqliteType.Blob).Value = MailboxU64(
                ScopedMailboxCredentialValidator.ActiveEpochForInstall(
                    generation, authority));
            update.Parameters.Add("$authorityPolicy", SqliteType.Blob).Value = authority.PolicyFingerprint.ToArray();
            update.Parameters.Add("$scope", SqliteType.Blob).Value = generation.Selector.ScopeId.ToArray();
            if (update.ExecuteNonQuery() != 1)
                throw new InvalidOperationException("Mailbox credential rotation lost its exact scope.");
        }
    }

    public async Task SwitchScopedCredentialEpochAsync(
        MailboxCredentialSelector selector,
        ulong epoch,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selector);
        authority.Validate();
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            using var read = connection.CreateCommand();
            read.Transaction = transaction;
            read.CommandText = """
                SELECT s.account_scope,s.network_id,s.authority_policy_digest,
                       s.group_membership_commitment,s.active_epoch,
                       e.not_before,e.expires_at
                FROM mailbox_credential_scopes s
                JOIN mailbox_credential_epochs e ON e.scope_id=s.scope_id
                WHERE s.scope_id=$scope AND e.epoch=$epoch;
                """;
            read.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
            read.Parameters.Add("$epoch", SqliteType.Blob).Value = MailboxU64(epoch);
            using var reader = read.ExecuteReader();
            if (!reader.Read())
            {
                throw new InvalidOperationException("Mailbox credential scope is missing.");
            }
            if (!Fixed((byte[])reader.GetValue(0), selector.AccountScope.Value) ||
                !Fixed((byte[])reader.GetValue(1), authority.NetworkId.Span) ||
                !Fixed((byte[])reader.GetValue(2),
                    authority.PolicyFingerprint.Span) ||
                selector.Kind == MailboxCredentialScopeKind.Group &&
                (reader.IsDBNull(3) || !Fixed((byte[])reader.GetValue(3),
                    selector.GroupMembershipCommitment.Span)))
            {
                throw new InvalidOperationException(
                    "Scoped mailbox credential authority is stale or mismatched.");
            }
            var active = MailboxReadU64((byte[])reader.GetValue(4));
            var notBefore = MailboxReadU64((byte[])reader.GetValue(5));
            var expires = MailboxReadU64((byte[])reader.GetValue(6));
            if (active == ulong.MaxValue || epoch != active + 1 ||
                authority.NowUnixSeconds < notBefore ||
                authority.NowUnixSeconds > expires)
            {
                throw new InvalidOperationException("Mailbox epoch handoff is not authorized.");
            }
            reader.Dispose();
            using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE mailbox_credential_scopes SET active_epoch=$epoch
                WHERE scope_id=$scope AND active_epoch=$active;
                """;
            update.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
            update.Parameters.Add("$epoch", SqliteType.Blob).Value = MailboxU64(epoch);
            update.Parameters.Add("$active", SqliteType.Blob).Value = MailboxU64(active);
            if (update.ExecuteNonQuery() != 1)
            {
                throw new InvalidOperationException("Mailbox epoch changed concurrently.");
            }
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    public async Task<ScopedMailboxResolvedRoute> ReadScopedMailboxRouteAsync(
        MailboxCredentialSelector selector,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selector);
        authority.Validate();
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            var now = authority.NowUnixSeconds;
            var route = ReadScopedRouteRow(
                connection,
                transaction,
                selector,
                authority,
                epoch: null);
            if (now > route.ExpiresAtUnixSeconds)
            {
                if (route.Epoch == ulong.MaxValue)
                {
                    throw new InvalidOperationException(
                        "Exact scoped mailbox route is unavailable.");
                }
                var nextEpoch = checked(route.Epoch + 1);
                var next = ReadScopedRouteRow(
                    connection,
                    transaction,
                    selector,
                    authority,
                    nextEpoch);
                if (now < next.NotBeforeUnixSeconds ||
                    now > next.ExpiresAtUnixSeconds)
                {
                    throw new InvalidOperationException(
                        "Exact scoped mailbox route is unavailable.");
                }

                using var update = connection.CreateCommand();
                update.Transaction = transaction;
                update.CommandText = """
                    UPDATE mailbox_credential_scopes SET active_epoch=$next
                    WHERE scope_id=$scope AND active_epoch=$active;
                    """;
                update.Parameters.Add("$scope", SqliteType.Blob).Value =
                    selector.ScopeId.ToArray();
                update.Parameters.Add("$next", SqliteType.Blob).Value =
                    MailboxU64(nextEpoch);
                update.Parameters.Add("$active", SqliteType.Blob).Value =
                    MailboxU64(route.Epoch);
                if (update.ExecuteNonQuery() != 1)
                {
                    throw new InvalidOperationException(
                        "Mailbox epoch changed concurrently.");
                }
                route = next;
            }
            else if (now < route.NotBeforeUnixSeconds)
            {
                throw new InvalidOperationException(
                    "Exact scoped mailbox route is unavailable.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return route.ToResolved();
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    private static ScopedMailboxRouteRow ReadScopedRouteRow(
        SqliteConnection connection,
        SqliteTransaction transaction,
        MailboxCredentialSelector selector,
        VerifiedOfficialMailboxAuthority authority,
        ulong? epoch)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = epoch is null
            ? """
                SELECT s.account_scope,s.network_id,s.authority_policy_digest,
                       s.group_membership_commitment,e.epoch,
                       e.not_before,e.expires_at,e.mailbox_id,e.placement_id,
                       e.placement_commitment,e.membership_commitment,
                       e.first_replica_id,e.first_replica_key,
                       e.second_replica_id,e.second_replica_key
                FROM mailbox_credential_scopes s
                JOIN mailbox_credential_epochs e
                  ON e.scope_id=s.scope_id AND e.epoch=s.active_epoch
                WHERE s.scope_id=$scope;
                """
            : """
                SELECT s.account_scope,s.network_id,s.authority_policy_digest,
                       s.group_membership_commitment,e.epoch,
                       e.not_before,e.expires_at,e.mailbox_id,e.placement_id,
                       e.placement_commitment,e.membership_commitment,
                       e.first_replica_id,e.first_replica_key,
                       e.second_replica_id,e.second_replica_key
                FROM mailbox_credential_scopes s
                JOIN mailbox_credential_epochs e ON e.scope_id=s.scope_id
                WHERE s.scope_id=$scope AND e.epoch=$epoch;
                """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value =
            selector.ScopeId.ToArray();
        if (epoch is not null)
        {
            command.Parameters.Add("$epoch", SqliteType.Blob).Value =
                MailboxU64(epoch.Value);
        }
        using var reader = command.ExecuteReader();
        if (!reader.Read() ||
            !Fixed((byte[])reader.GetValue(0), selector.AccountScope.Value) ||
            !Fixed((byte[])reader.GetValue(1), authority.NetworkId.Span) ||
            !Fixed((byte[])reader.GetValue(2), authority.PolicyFingerprint.Span) ||
            selector.Kind == MailboxCredentialScopeKind.Group &&
            (reader.IsDBNull(3) || !Fixed((byte[])reader.GetValue(3),
                selector.GroupMembershipCommitment.Span)))
        {
            throw new InvalidOperationException(
                "Exact scoped mailbox route is unavailable.");
        }
        return new ScopedMailboxRouteRow(
            MailboxReadU64((byte[])reader.GetValue(4)),
            MailboxReadU64((byte[])reader.GetValue(5)),
            MailboxReadU64((byte[])reader.GetValue(6)),
            (byte[])reader.GetValue(7),
            (byte[])reader.GetValue(8),
            (byte[])reader.GetValue(9),
            (byte[])reader.GetValue(10),
            (byte[])reader.GetValue(11),
            (byte[])reader.GetValue(12),
            (byte[])reader.GetValue(13),
            (byte[])reader.GetValue(14));
    }

    private sealed record ScopedMailboxRouteRow(
        ulong Epoch,
        ulong NotBeforeUnixSeconds,
        ulong ExpiresAtUnixSeconds,
        byte[] MailboxId,
        byte[] PlacementId,
        byte[] PlacementCommitment,
        byte[] MembershipCommitment,
        byte[] FirstReplicaId,
        byte[] FirstReplicaKey,
        byte[] SecondReplicaId,
        byte[] SecondReplicaKey)
    {
        internal ScopedMailboxResolvedRoute ToResolved() => new(
            Epoch,
            ExpiresAtUnixSeconds,
            new BlindedMailboxId(MailboxId),
            new BlindedPlacementId(PlacementId),
            PlacementCommitment,
            MembershipCommitment,
            new MailboxCredentialReplicaPair(
                FirstReplicaId,
                FirstReplicaKey,
                SecondReplicaId,
                SecondReplicaKey));
    }

    public async Task<ScopedMailboxResolvedRoute> RevalidateScopedMailboxDispatchAsync(
        MailboxCredentialSelector selector,
        MailboxAuthenticatedOperation operation,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selector);
        authority.Validate();
        var role = operation == MailboxAuthenticatedOperation.Store
            ? MailboxCredentialRole.Deposit
            : operation is MailboxAuthenticatedOperation.Retrieve or
                MailboxAuthenticatedOperation.Ack
                ? MailboxCredentialRole.Retrieve
                : throw new ArgumentOutOfRangeException(nameof(operation));
        if (selector.Kind == MailboxCredentialScopeKind.Peer &&
            role != MailboxCredentialRole.Deposit)
        {
            throw new InvalidOperationException(
                "Peer mailbox scopes are deposit-only.");
        }

        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            var resolved = ResolveActiveGrant(
                connection,
                transaction,
                selector,
                role,
                authority,
                binding: null,
                allocateCounter: false);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return resolved.Route;
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    public async Task<ScopedMailboxPreparedBatch> PrepareScopedMailboxBatchAsync(
        ScopedMailboxPrepareBatchRequest request,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ValidateBatch(request, signer, authority);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            var semanticOwnerExists = ValidateSemanticBatchOwnership(
                connection, transaction,
                request.AccountScope.Value,
                request.SemanticOperationId.Span,
                request.ParentOperationId.Span);
            var planDigest = ComputePlanDigest(request);
            var resumed = ReadPreparedBatch(
                connection, transaction,
                new ScopedMailboxResumeBatchRequest(
                    request.AccountScope, request.ParentOperationId,
                    request.SemanticOperationId, request.Selectors),
                planDigest);
            if (resumed is not null)
            {
                for (var ordinal = 0; ordinal < request.Selectors.Count; ordinal++)
                {
                    var logical = request.Selectors[ordinal];
                    var decoded = MailboxAuthenticatedClientRequestCodec.Decode(
                        resumed.Frames[ordinal].GetCanonicalMau2Copy());
                    var target = new ScopedMailboxBatchTarget(
                        logical.Selector, decoded.Binding);
                    var resolved = ResolveForPrepare(
                        connection, transaction, target, signer, authority,
                        allocateCounter: false);
                    ValidateResumedFrame(
                        resumed.Frames[ordinal], target, resolved, signer);
                }
                transaction.Commit();
                return resumed;
            }
            if (semanticOwnerExists)
                throw new InvalidDataException(
                    "Mailbox semantic batch owner lost its prepared batch.");

            var frames = new List<MailboxAuthenticatedRequestFrame>(
                request.Targets.Count);
            using (var batch = connection.CreateCommand())
            {
                batch.Transaction = transaction;
                batch.CommandText = """
                    INSERT INTO mailbox_prepared_batches(
                        account_scope,parent_operation_id,semantic_operation_id,
                        plan_digest,target_count,created_at)
                    VALUES($account,$parent,$semantic,$digest,$count,$created);
                    """;
                batch.Parameters.Add("$account", SqliteType.Blob).Value =
                    request.AccountScope.ToArray();
                batch.Parameters.Add("$parent", SqliteType.Blob).Value =
                    request.ParentOperationId.ToArray();
                batch.Parameters.Add("$semantic", SqliteType.Blob).Value =
                    request.SemanticOperationId.ToArray();
                batch.Parameters.Add("$digest", SqliteType.Blob).Value = planDigest;
                batch.Parameters.AddWithValue("$count", request.Targets.Count);
                batch.Parameters.AddWithValue(
                    "$created", request.CreatedAt.ToUnixTimeMilliseconds());
                batch.ExecuteNonQuery();
            }

            for (var ordinal = 0; ordinal < request.Targets.Count; ordinal++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var target = request.Targets[ordinal];
                var resolved = ResolveForPrepare(
                    connection, transaction, target, signer, authority,
                    allocateCounter: true);
                var frame = SignResolved(target.Binding, signer, resolved);
                var canonical = frame.GetCanonicalMau2Copy();
                var logicalId = OutboxLogicalId.FromBytes(
                    target.Binding.OperationId.Span);
                var prepared = TransportOutboxPreparedItem.Create(
                    request.AccountScope,
                    logicalId,
                    OutboxDedupMaterial.FromBytes(
                        target.Binding.RequestDigest.Span),
                    canonical,
                    request.CreatedAt,
                    DateTimeOffset.FromUnixTimeSeconds(
                        checked((long)resolved.Grant.ExpiresAtUnixSeconds)),
                    request.CreatedAt);
                var candidate = TransportOutboxStateMachine.Prepared(prepared);
                if (ReadTransportOutboxItem(
                        connection, transaction, request.AccountScope.Value,
                        logicalId.Value) is not null)
                {
                    throw new InvalidOperationException(
                        "Mailbox target operation conflicts with durable outbox state.");
                }
                if (!HasScopedBatchOutboxCapacity(
                        connection, transaction, request.AccountScope.Value,
                        canonical.Length))
                {
                    throw new InvalidOperationException(
                        "Mailbox prepared batch exceeds durable outbox capacity.");
                }
                InsertTransportOutboxItem(connection, transaction, candidate);
                InsertPreparedTarget(
                    connection, transaction, request, target, resolved.Counter,
                    ordinal);
                frames.Add(frame);
            }

            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            try
            {
                commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch
            {
                throw new TransportOutboxCommitOutcomeUnknownException();
            }
            return new ScopedMailboxPreparedBatch(
                request.ParentOperationId, frames);
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    public async Task<ScopedMailboxPreparedBatch?> TryResumeScopedMailboxBatchAsync(
        ScopedMailboxResumeBatchRequest request,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        authority.Validate();
        ScopedMailboxCredentialValidator.ValidateResumeBatch(request, signer);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            var semanticOwnerExists = ValidateSemanticBatchOwnership(
                connection, transaction,
                request.AccountScope.Value,
                request.SemanticOperationId.Span,
                request.ParentOperationId.Span);
            var resumed = ReadPreparedBatch(
                connection,
                transaction,
                request,
                ScopedMailboxCredentialValidator.ComputePlanDigest(request));
            if (resumed is null)
            {
                if (semanticOwnerExists)
                    throw new InvalidDataException(
                        "Mailbox semantic batch owner lost its prepared batch.");
                transaction.Commit();
                return null;
            }

            for (var ordinal = 0; ordinal < request.Selectors.Count; ordinal++)
            {
                var logical = request.Selectors[ordinal];
                var frame = resumed.Frames[ordinal];
                var decoded = MailboxAuthenticatedClientRequestCodec.Decode(
                    frame.GetCanonicalMau2Copy());
                if (decoded.Binding.Operation != logical.Operation)
                {
                    throw new InvalidDataException(
                        "Mailbox prepared batch operation catalog is corrupt.");
                }
                var target = new ScopedMailboxBatchTarget(
                    logical.Selector, decoded.Binding);
                var resolved = ResolveForPrepare(
                    connection, transaction, target, signer, authority,
                    allocateCounter: false);
                ValidateResumedFrame(frame, target, resolved, signer);
            }
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return resumed;
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    internal sealed record ResolvedGrant(
        MailboxCredentialSelector Selector,
        MailboxAuthenticatedGrant Grant,
        ulong Counter,
        byte[] HolderKey,
        ScopedMailboxResolvedRoute Route);

    private static ResolvedGrant ResolveForPrepare(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxBatchTarget target,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority,
        bool allocateCounter)
    {
        var role = target.Binding.Operation == MailboxAuthenticatedOperation.Store
            ? MailboxCredentialRole.Deposit
            : MailboxCredentialRole.Retrieve;
        if (target.Selector.Kind == MailboxCredentialScopeKind.Peer &&
            role != MailboxCredentialRole.Deposit)
        {
            throw new InvalidOperationException("Peer mailbox scopes are deposit-only.");
        }

        return ResolveActiveGrant(
            connection,
            transaction,
            target.Selector,
            role,
            authority,
            target.Binding,
            allocateCounter);
    }

    private static ResolvedGrant ResolveActiveGrant(
        SqliteConnection connection,
        SqliteTransaction transaction,
        MailboxCredentialSelector selector,
        MailboxCredentialRole role,
        VerifiedOfficialMailboxAuthority authority,
        MailboxAuthenticatedRequestBinding? binding,
        bool allocateCounter)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT s.account_scope,s.network_id,s.authority_policy_digest,s.holder_key,
                   s.active_epoch,s.group_membership_commitment,
                   e.not_before,e.expires_at,e.mailbox_id,e.placement_id,
                   e.placement_commitment,e.membership_commitment,
                   e.first_replica_id,e.first_replica_key,
                   e.second_replica_id,e.second_replica_key,
                   g.grant_digest,g.canonical_grant
            FROM mailbox_credential_scopes s
            JOIN mailbox_credential_epochs e
              ON e.scope_id=s.scope_id AND e.epoch=s.active_epoch
            JOIN mailbox_credential_grants g
              ON g.scope_id=s.scope_id AND g.epoch=s.active_epoch AND g.role=$role
            WHERE s.scope_id=$scope;
        """;
        command.Parameters.AddWithValue("$role", (int)role);
        command.Parameters.Add("$scope", SqliteType.Blob).Value =
            selector.ScopeId.ToArray();
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            throw new InvalidOperationException(
                "Exact scoped mailbox credential is unavailable.");
        }
        var activeEpoch = MailboxReadU64((byte[])reader.GetValue(4));
        var notBefore = MailboxReadU64((byte[])reader.GetValue(6));
        var expires = MailboxReadU64((byte[])reader.GetValue(7));
        var mailbox = (byte[])reader.GetValue(8);
        var placement = (byte[])reader.GetValue(9);
        var placementCommitment = (byte[])reader.GetValue(10);
        var membershipCommitment = (byte[])reader.GetValue(11);
        if (!Fixed((byte[])reader.GetValue(0), selector.AccountScope.Value) ||
            !Fixed((byte[])reader.GetValue(1), authority.NetworkId.Span) ||
            !Fixed((byte[])reader.GetValue(2), authority.PolicyFingerprint.Span) ||
            authority.NowUnixSeconds < notBefore ||
            authority.NowUnixSeconds > expires ||
            selector.Kind == MailboxCredentialScopeKind.Group &&
            (reader.IsDBNull(5) ||
             !Fixed((byte[])reader.GetValue(5),
                 selector.GroupMembershipCommitment.Span)) ||
            !Fixed(
                placementCommitment,
                MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(placement))))
        {
            throw new InvalidOperationException(
                "Scoped mailbox credential authority is stale or mismatched.");
        }
        if (binding is not null)
        {
            ValidateBindingRoute(binding, activeEpoch, mailbox, placement);
        }

        var holder = (byte[])reader.GetValue(3);
        var grantDigest = (byte[])reader.GetValue(16);
        var grantBytes = (byte[])reader.GetValue(17);
        var grant = ScopedMailboxCredentialValidator.ValidateCanonicalGrant(
            grantBytes,
            role,
            activeEpoch,
            notBefore,
            expires,
            placementCommitment,
            membershipCommitment,
            holder,
            authority,
            rejectRevoked: true);
        var replicas = new MailboxCredentialReplicaPair(
            (byte[])reader.GetValue(12),
            (byte[])reader.GetValue(13),
            (byte[])reader.GetValue(14),
            (byte[])reader.GetValue(15));
        reader.Dispose();
        var counter = allocateCounter
            ? AllocateCounter(connection, transaction, selector.ScopeId.Span,
                activeEpoch, grantDigest)
            : 0;
        return new ResolvedGrant(
            selector,
            grant,
            counter,
            holder,
            new ScopedMailboxResolvedRoute(
                activeEpoch,
                expires,
                new BlindedMailboxId(mailbox),
                new BlindedPlacementId(placement),
                placementCommitment,
                membershipCommitment,
                replicas));
    }

    private static ulong AllocateCounter(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlySpan<byte> scope,
        ulong epoch,
        byte[] grantDigest)
    {
        using var read = connection.CreateCommand();
        read.Transaction = transaction;
        read.CommandText = """
            SELECT next_counter FROM mailbox_replay_counters
            WHERE scope_id=$scope AND epoch=$epoch AND grant_digest=$digest;
            """;
        read.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
        read.Parameters.Add("$epoch", SqliteType.Blob).Value = MailboxU64(epoch);
        read.Parameters.Add("$digest", SqliteType.Blob).Value = grantDigest;
        var stored = read.ExecuteScalar() as byte[];
        var counter = stored is null ? 1UL : MailboxReadU64(stored);
        if (counter == 0 || counter == ulong.MaxValue)
        {
            throw new InvalidOperationException("Mailbox replay counter is exhausted.");
        }
        using var upsert = connection.CreateCommand();
        upsert.Transaction = transaction;
        upsert.CommandText = """
            INSERT INTO mailbox_replay_counters(scope_id,epoch,grant_digest,next_counter)
            VALUES($scope,$epoch,$digest,$next)
            ON CONFLICT(scope_id,epoch,grant_digest)
            DO UPDATE SET next_counter=excluded.next_counter;
            """;
        upsert.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
        upsert.Parameters.Add("$epoch", SqliteType.Blob).Value = MailboxU64(epoch);
        upsert.Parameters.Add("$digest", SqliteType.Blob).Value = grantDigest;
        upsert.Parameters.Add("$next", SqliteType.Blob).Value =
            MailboxU64(counter + 1);
        upsert.ExecuteNonQuery();
        return counter;
    }

    internal static MailboxAuthenticatedRequestFrame SignResolved(
        MailboxAuthenticatedRequestBinding binding,
        IMailboxOperationSigner signer,
        ResolvedGrant resolved) =>
        ScopedMailboxCredentialValidator.Sign(
            binding,
            signer,
            resolved.Grant,
            resolved.Counter,
            resolved.HolderKey);

    private static void ValidateResumedFrame(
        MailboxAuthenticatedRequestFrame frame,
        ScopedMailboxBatchTarget target,
        ResolvedGrant resolved,
        IMailboxOperationSigner signer)
    {
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(
            frame.GetCanonicalMau2Copy());
        var persistedGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(
            decoded.Presentation.Grant);
        var currentGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(
            resolved.Grant);
        var signerKey = signer.GetEd25519PublicKey();
        try
        {
            if (decoded.Binding.Operation != target.Binding.Operation ||
                decoded.Presentation.Operation != target.Binding.Operation ||
                !Fixed(decoded.Binding.OperationId.Span,
                    target.Binding.OperationId.Span) ||
                !Fixed(decoded.Binding.RequestDigest.Span,
                    target.Binding.RequestDigest.Span) ||
                !Fixed(decoded.Binding.CanonicalRequest.Span,
                    target.Binding.CanonicalRequest.Span) ||
                !Fixed(persistedGrant, currentGrant) ||
                !Fixed(signerKey, resolved.HolderKey) ||
                !new SodiumMailboxCapabilityCrypto().VerifyHolder(
                    resolved.HolderKey,
                    MailboxAuthenticatedCapabilityCodec
                        .GetPresentationSigningBytes(decoded.Presentation),
                    decoded.Presentation.HolderSignature.Span))
            {
                throw new InvalidDataException(
                    "Mailbox prepared batch frame is stale or corrupt.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signerKey);
        }
    }

    private static void ValidateBindingRoute(
        MailboxAuthenticatedRequestBinding binding,
        ulong epoch,
        ReadOnlySpan<byte> mailbox,
        ReadOnlySpan<byte> placement) =>
        ScopedMailboxCredentialValidator.ValidateBindingRoute(
            binding, epoch, mailbox, placement);

    private static void ValidateGeneration(
        ScopedMailboxCredentialGeneration value,
        VerifiedOfficialMailboxAuthority authority,
        ISet<string> serials) =>
        ScopedMailboxCredentialValidator.ValidateGeneration(
            value, authority, serials);

    private static void ValidateInstallBatch(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(generations);
        authority.Validate();
        if (generations.Count is < 1 or > MaximumScopedMailboxBatchTargets)
        {
            throw new ArgumentException("Scoped mailbox credential import is invalid.", nameof(generations));
        }

        var scopes = new HashSet<string>(StringComparer.Ordinal);
        var material = new HashSet<string>(StringComparer.Ordinal);
        var serials = new HashSet<string>(StringComparer.Ordinal);
        foreach (var generation in generations)
        {
            ValidateGeneration(generation, authority, serials);
            if (!scopes.Add(Convert.ToHexString(generation.Selector.ScopeId.Span)))
            {
                throw new InvalidDataException("Scoped mailbox import repeats a scope.");
            }

            foreach (var value in ImportUniqueMaterial(generation))
            {
                if (!material.Add(Convert.ToHexString(value.Span)))
                {
                    throw new InvalidDataException(
                        "Scoped mailbox import reuses credential material across scopes.");
                }
            }
        }
    }

    private static IEnumerable<ReadOnlyMemory<byte>> ImportUniqueMaterial(
        ScopedMailboxCredentialGeneration generation)
    {
        // Holder keys and replica pins are deliberately not unique: one account
        // and one placement pair can legitimately serve several scopes.  The
        // credential material itself must never be re-bound.
        yield return generation.Generation;
        yield return generation.MailboxId;
        if (generation.Retrieve is { } retrieve)
        {
            yield return retrieve.CurrentGrant;
            yield return retrieve.NextGrant;
        }
        if (generation.Deposit is { } deposit)
        {
            yield return deposit.CurrentGrant;
            yield return deposit.NextGrant;
        }
    }

    private static IEnumerable<ReadOnlyMemory<byte>> ImportGrants(
        ScopedMailboxCredentialGeneration generation)
    {
        if (generation.Retrieve is { } retrieve)
        {
            yield return retrieve.CurrentGrant;
            yield return retrieve.NextGrant;
        }
        if (generation.Deposit is { } deposit)
        {
            yield return deposit.CurrentGrant;
            yield return deposit.NextGrant;
        }
    }

    private static bool CredentialExists(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxCredentialGeneration generation)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT 1 FROM mailbox_credential_scopes WHERE scope_id=$scope;";
        command.Parameters.Add("$scope", SqliteType.Blob).Value =
            generation.Selector.ScopeId.ToArray();
        return command.ExecuteScalar() is not null;
    }

    private static bool IsExactInstalledGeneration(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxCredentialGeneration generation,
        VerifiedOfficialMailboxAuthority authority)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT generation,authority_policy_digest
            FROM mailbox_credential_scopes WHERE scope_id=$scope;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value =
            generation.Selector.ScopeId.ToArray();
        using var reader = command.ExecuteReader();
        return reader.Read() &&
            Fixed((byte[])reader.GetValue(0), generation.Generation.Span) &&
            Fixed((byte[])reader.GetValue(1), authority.PolicyFingerprint.Span);
    }

    private static void EnsureExactRotationOverlap(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxCredentialGeneration value,
        VerifiedOfficialMailboxAuthority authority)
    {
        var selector = value.Selector;
        using (var scope = connection.CreateCommand())
        {
            scope.Transaction = transaction;
            scope.CommandText = """
                SELECT account_scope,scope_kind,subject_id,issuer_context,network_id,
                       holder_key,generation,active_epoch,group_membership_commitment
                FROM mailbox_credential_scopes WHERE scope_id=$scope;
                """;
            scope.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
            using var reader = scope.ExecuteReader();
            if (!reader.Read() ||
                !Fixed((byte[])reader.GetValue(0), selector.AccountScope.Value) ||
                reader.GetInt32(1) != (int)selector.Kind ||
                !Fixed((byte[])reader.GetValue(2), selector.SubjectId.Span) ||
                !Fixed((byte[])reader.GetValue(3), selector.IssuerContext.Span) ||
                !Fixed((byte[])reader.GetValue(4), authority.NetworkId.Span) ||
                !Fixed((byte[])reader.GetValue(5), value.HolderPublicKey.Span) ||
                Fixed((byte[])reader.GetValue(6), value.Generation.Span) ||
                MailboxReadU64((byte[])reader.GetValue(7)) > value.Current.Epoch ||
                (selector.GroupMembershipCommitment.IsEmpty
                    ? !reader.IsDBNull(8)
                    : reader.IsDBNull(8) || !Fixed((byte[])reader.GetValue(8),
                        selector.GroupMembershipCommitment.Span)))
            {
                throw new InvalidOperationException(
                    "Mailbox credential rotation changed its stable scope or did not advance.");
            }
        }

        using (var epoch = connection.CreateCommand())
        {
            epoch.Transaction = transaction;
            epoch.CommandText = """
                SELECT not_before,expires_at,mailbox_id,placement_id,placement_commitment,
                       membership_commitment,first_replica_id,first_replica_key,
                       second_replica_id,second_replica_key
                FROM mailbox_credential_epochs WHERE scope_id=$scope AND epoch=$epoch;
                """;
            epoch.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
            epoch.Parameters.Add("$epoch", SqliteType.Blob).Value =
                MailboxU64(value.Current.Epoch);
            using var reader = epoch.ExecuteReader();
            if (!reader.Read() ||
                MailboxReadU64((byte[])reader.GetValue(0)) != value.Current.NotBeforeUnixSeconds ||
                MailboxReadU64((byte[])reader.GetValue(1)) != value.Current.ExpiresAtUnixSeconds ||
                !Fixed((byte[])reader.GetValue(2), value.MailboxId.Span) ||
                !Fixed((byte[])reader.GetValue(3), value.Current.PlacementId.Span) ||
                !Fixed((byte[])reader.GetValue(4), value.Current.PlacementCommitment.Span) ||
                !Fixed((byte[])reader.GetValue(5), value.Current.MembershipCommitment.Span) ||
                !Fixed((byte[])reader.GetValue(6), value.CurrentReplicas.FirstId.Span) ||
                !Fixed((byte[])reader.GetValue(7), value.CurrentReplicas.FirstSigningKey.Span) ||
                !Fixed((byte[])reader.GetValue(8), value.CurrentReplicas.SecondId.Span) ||
                !Fixed((byte[])reader.GetValue(9), value.CurrentReplicas.SecondSigningKey.Span))
            {
                throw new InvalidOperationException(
                    "Mailbox rotation E+1 is not byte-identical to the installed overlap.");
            }
        }

        EnsureGrant(MailboxCredentialRole.Retrieve, value.Retrieve);
        EnsureGrant(MailboxCredentialRole.Deposit, value.Deposit);
        void EnsureGrant(MailboxCredentialRole role, MailboxCredentialGrantSet? set)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                SELECT canonical_grant FROM mailbox_credential_grants
                WHERE scope_id=$scope AND epoch=$epoch AND role=$role;
                """;
            command.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
            command.Parameters.Add("$epoch", SqliteType.Blob).Value =
                MailboxU64(value.Current.Epoch);
            command.Parameters.AddWithValue("$role", (int)role);
            var stored = command.ExecuteScalar() as byte[];
            var expected = set?.CurrentGrant.ToArray();
            if ((stored is null) != (expected is null) ||
                stored is not null && !Fixed(stored, expected!))
            {
                throw new InvalidOperationException(
                    "Mailbox rotation grants do not exactly preserve E+1.");
            }
        }
    }

    private static void EnsureNoSameScopeRotationReuse(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxCredentialGeneration generation)
    {
        using (var epoch = connection.CreateCommand())
        {
            epoch.Transaction = transaction;
            epoch.CommandText = """
                SELECT 1 FROM mailbox_credential_epochs
                WHERE scope_id=$scope AND epoch<>$overlap AND
                      (placement_id=$placement OR membership_commitment=$membership)
                LIMIT 1;
                """;
            epoch.Parameters.Add("$scope", SqliteType.Blob).Value =
                generation.Selector.ScopeId.ToArray();
            epoch.Parameters.Add("$overlap", SqliteType.Blob).Value =
                MailboxU64(generation.Current.Epoch);
            epoch.Parameters.Add("$placement", SqliteType.Blob).Value =
                generation.Next.PlacementId.ToArray();
            epoch.Parameters.Add("$membership", SqliteType.Blob).Value =
                generation.Next.MembershipCommitment.ToArray();
            if (epoch.ExecuteScalar() is not null)
                throw new InvalidDataException(
                    "Mailbox rotation reuses retired E material for E+2.");
        }
        foreach (var grant in new[]
        {
            generation.Retrieve?.NextGrant,
            generation.Deposit?.NextGrant
        }.Where(static item => item.HasValue).Select(static item => item!.Value))
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                SELECT 1 FROM mailbox_credential_grants
                WHERE scope_id=$scope AND epoch<>$overlap AND canonical_grant=$grant
                LIMIT 1;
                """;
            command.Parameters.Add("$scope", SqliteType.Blob).Value =
                generation.Selector.ScopeId.ToArray();
            command.Parameters.Add("$overlap", SqliteType.Blob).Value =
                MailboxU64(generation.Current.Epoch);
            command.Parameters.Add("$grant", SqliteType.Blob).Value = grant.ToArray();
            if (command.ExecuteScalar() is not null)
                throw new InvalidDataException(
                    "Mailbox rotation reuses a retired grant for E+2.");
        }
    }

    private static void EnsureNoCrossScopeMaterialReuse(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxCredentialGeneration generation)
    {
        foreach (var value in ImportUniqueMaterial(generation))
        {
            using var scope = connection.CreateCommand();
            scope.Transaction = transaction;
            scope.CommandText = """
                SELECT 1 FROM mailbox_credential_scopes
                WHERE scope_id <> $scope AND generation=$material
                UNION ALL
                SELECT 1 FROM mailbox_credential_epochs
                WHERE scope_id <> $scope AND mailbox_id=$material
                UNION ALL
                SELECT 1 FROM mailbox_credential_grants
                WHERE scope_id <> $scope AND canonical_grant=$material
                LIMIT 1;
                """;
            scope.Parameters.Add("$scope", SqliteType.Blob).Value =
                generation.Selector.ScopeId.ToArray();
            scope.Parameters.Add("$material", SqliteType.Blob).Value = value.ToArray();
            if (scope.ExecuteScalar() is not null)
            {
                throw new InvalidDataException(
                    "Scoped mailbox credential material is already bound to another scope.");
            }
        }


        foreach (var encoded in ImportGrants(generation))
        {
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                encoded.Span);
            using var serial = connection.CreateCommand();
            serial.Transaction = transaction;
            serial.CommandText = """
                SELECT 1
                FROM mailbox_credential_grants g
                WHERE g.scope_id <> $scope
                  AND g.issuer_key=$issuerKey
                  AND g.serial=$serial
                LIMIT 1;
                """;
            serial.Parameters.Add("$scope", SqliteType.Blob).Value =
                generation.Selector.ScopeId.ToArray();
            serial.Parameters.Add("$issuerKey", SqliteType.Blob).Value =
                grant.IssuerPublicKey.ToArray();
            serial.Parameters.Add("$serial", SqliteType.Blob).Value =
                grant.Serial.ToArray();
            if (serial.ExecuteScalar() is not null)
            {
                throw new InvalidDataException(
                    "Scoped mailbox grant serial is already bound to another scope.");
            }
        }
    }

    private static void EnsureExactInstalledCredential(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxCredentialGeneration value,
        VerifiedOfficialMailboxAuthority authority)
    {
        var selector = value.Selector;
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT account_scope,scope_kind,subject_id,issuer_context,network_id,
                       authority_policy_digest,holder_key,generation,active_epoch,
                       group_membership_commitment
                FROM mailbox_credential_scopes WHERE scope_id=$scope;
                """;
            command.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
            using var reader = command.ExecuteReader();
            if (!reader.Read())
            {
                throw new InvalidOperationException(
                    "Mailbox credential import conflicts with the exact persisted scope.");
            }
            var activeEpoch = MailboxReadU64((byte[])reader.GetValue(8));
            if (!Fixed((byte[])reader.GetValue(0), selector.AccountScope.Value) ||
                reader.GetInt32(1) != (int)selector.Kind ||
                !Fixed((byte[])reader.GetValue(2), selector.SubjectId.Span) ||
                !Fixed((byte[])reader.GetValue(3), selector.IssuerContext.Span) ||
                !Fixed((byte[])reader.GetValue(4), authority.NetworkId.Span) ||
                !Fixed((byte[])reader.GetValue(5), authority.PolicyFingerprint.Span) ||
                !Fixed((byte[])reader.GetValue(6), value.HolderPublicKey.Span) ||
                !Fixed((byte[])reader.GetValue(7), value.Generation.Span) ||
                (activeEpoch != value.Current.Epoch &&
                 activeEpoch != value.Next.Epoch) ||
                (selector.GroupMembershipCommitment.IsEmpty
                    ? !reader.IsDBNull(9)
                    : reader.IsDBNull(9) || !Fixed((byte[])reader.GetValue(9),
                        selector.GroupMembershipCommitment.Span)))
            {
                throw new InvalidOperationException(
                    "Mailbox credential import conflicts with the exact persisted scope.");
            }
            if (reader.Read())
            {
                throw new InvalidDataException("Mailbox credential scope is duplicated.");
            }
        }

        EnsureExactEpoch(value.Current);
        EnsureExactEpoch(value.Next);
        EnsureExactGrant(value.Current.Epoch, MailboxCredentialRole.Retrieve, value.Retrieve);
        EnsureExactGrant(value.Current.Epoch, MailboxCredentialRole.Deposit, value.Deposit);
        EnsureExactGrant(value.Next.Epoch, MailboxCredentialRole.Retrieve, value.Retrieve);
        EnsureExactGrant(value.Next.Epoch, MailboxCredentialRole.Deposit, value.Deposit);

        void EnsureExactEpoch(MailboxCredentialEpoch epoch)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                SELECT not_before,expires_at,mailbox_id,placement_id,placement_commitment,
                       membership_commitment,first_replica_id,first_replica_key,
                       second_replica_id,second_replica_key
                FROM mailbox_credential_epochs WHERE scope_id=$scope AND epoch=$epoch;
                """;
            command.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
            command.Parameters.Add("$epoch", SqliteType.Blob).Value = MailboxU64(epoch.Epoch);
            using var reader = command.ExecuteReader();
            var replicas = value.ReplicasFor(epoch.Epoch);
            if (!reader.Read() ||
                MailboxReadU64((byte[])reader.GetValue(0)) != epoch.NotBeforeUnixSeconds ||
                MailboxReadU64((byte[])reader.GetValue(1)) != epoch.ExpiresAtUnixSeconds ||
                !Fixed((byte[])reader.GetValue(2), value.MailboxId.Span) ||
                !Fixed((byte[])reader.GetValue(3), epoch.PlacementId.Span) ||
                !Fixed((byte[])reader.GetValue(4), epoch.PlacementCommitment.Span) ||
                !Fixed((byte[])reader.GetValue(5), epoch.MembershipCommitment.Span) ||
                !Fixed((byte[])reader.GetValue(6), replicas.FirstId.Span) ||
                !Fixed((byte[])reader.GetValue(7), replicas.FirstSigningKey.Span) ||
                !Fixed((byte[])reader.GetValue(8), replicas.SecondId.Span) ||
                !Fixed((byte[])reader.GetValue(9), replicas.SecondSigningKey.Span))
            {
                throw new InvalidOperationException(
                    "Mailbox credential import epoch conflicts with persisted material.");
            }
            if (reader.Read())
            {
                throw new InvalidDataException("Mailbox credential epoch is duplicated.");
            }
        }

        void EnsureExactGrant(
            ulong epoch,
            MailboxCredentialRole role,
            MailboxCredentialGrantSet? grantSet)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                SELECT canonical_grant FROM mailbox_credential_grants
                WHERE scope_id=$scope AND epoch=$epoch AND role=$role;
                """;
            command.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
            command.Parameters.Add("$epoch", SqliteType.Blob).Value = MailboxU64(epoch);
            command.Parameters.AddWithValue("$role", (int)role);
            var stored = command.ExecuteScalar() as byte[];
            var expected = grantSet is null ? null :
                (epoch == value.Current.Epoch ? grantSet.CurrentGrant : grantSet.NextGrant).ToArray();
            if ((stored is null) != (expected is null) ||
                stored is not null && !Fixed(stored, expected!))
            {
                throw new InvalidOperationException(
                    "Mailbox credential import grant conflicts with persisted material.");
            }
        }
    }

    private static void ValidateBatch(
        ScopedMailboxPrepareBatchRequest request,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority)
    {
        authority.Validate();
        ScopedMailboxCredentialValidator.ValidateBatch(request, signer);
    }

    private static byte[] ComputePlanDigest(
        ScopedMailboxPrepareBatchRequest request) =>
        ScopedMailboxCredentialValidator.ComputePlanDigest(request);

    private static void InsertEpoch(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxCredentialGeneration generation,
        MailboxCredentialEpoch epoch)
    {
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO mailbox_credential_epochs(
                scope_id,epoch,not_before,expires_at,mailbox_id,placement_id,
                placement_commitment,membership_commitment,first_replica_id,
                first_replica_key,second_replica_id,second_replica_key)
            VALUES($scope,$epoch,$notBefore,$expires,$mailbox,$placement,
                   $placementCommitment,$membership,$firstId,$firstKey,
                   $secondId,$secondKey);
            """;
        insert.Parameters.Add("$scope", SqliteType.Blob).Value =
            generation.Selector.ScopeId.ToArray();
        insert.Parameters.Add("$epoch", SqliteType.Blob).Value =
            MailboxU64(epoch.Epoch);
        insert.Parameters.Add("$notBefore", SqliteType.Blob).Value =
            MailboxU64(epoch.NotBeforeUnixSeconds);
        insert.Parameters.Add("$expires", SqliteType.Blob).Value =
            MailboxU64(epoch.ExpiresAtUnixSeconds);
        insert.Parameters.Add("$mailbox", SqliteType.Blob).Value =
            generation.MailboxId.ToArray();
        insert.Parameters.Add("$placement", SqliteType.Blob).Value =
            epoch.PlacementId.ToArray();
        insert.Parameters.Add("$placementCommitment", SqliteType.Blob).Value =
            epoch.PlacementCommitment.ToArray();
        insert.Parameters.Add("$membership", SqliteType.Blob).Value =
            epoch.MembershipCommitment.ToArray();
        var replicas = generation.ReplicasFor(epoch.Epoch);
        insert.Parameters.Add("$firstId", SqliteType.Blob).Value =
            replicas.FirstId.ToArray();
        insert.Parameters.Add("$firstKey", SqliteType.Blob).Value =
            replicas.FirstSigningKey.ToArray();
        insert.Parameters.Add("$secondId", SqliteType.Blob).Value =
            replicas.SecondId.ToArray();
        insert.Parameters.Add("$secondKey", SqliteType.Blob).Value =
            replicas.SecondSigningKey.ToArray();
        insert.ExecuteNonQuery();
    }

    private static void InsertGrants(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxCredentialGeneration generation,
        ulong epoch)
    {
        Insert(MailboxCredentialRole.Retrieve, generation.Retrieve);
        Insert(MailboxCredentialRole.Deposit, generation.Deposit);

        void Insert(MailboxCredentialRole role, MailboxCredentialGrantSet? set)
        {
            if (set is null)
            {
                return;
            }
            var encoded = epoch == generation.Current.Epoch
                ? set.CurrentGrant.ToArray()
                : set.NextGrant.ToArray();
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(encoded);
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO mailbox_credential_grants(
                    scope_id,epoch,role,issuer_context,grant_digest,issuer_key,
                    serial,canonical_grant)
                VALUES($scope,$epoch,$role,$issuer,$digest,$issuerKey,$serial,$grant);
                """;
            insert.Parameters.Add("$scope", SqliteType.Blob).Value =
                generation.Selector.ScopeId.ToArray();
            insert.Parameters.Add("$epoch", SqliteType.Blob).Value =
                MailboxU64(epoch);
            insert.Parameters.AddWithValue("$role", (int)role);
            insert.Parameters.Add("$issuer", SqliteType.Blob).Value =
                generation.Selector.IssuerContext.ToArray();
            insert.Parameters.Add("$digest", SqliteType.Blob).Value =
                SHA256.HashData(encoded);
            insert.Parameters.Add("$issuerKey", SqliteType.Blob).Value =
                grant.IssuerPublicKey.ToArray();
            insert.Parameters.Add("$serial", SqliteType.Blob).Value =
                grant.Serial.ToArray();
            insert.Parameters.Add("$grant", SqliteType.Blob).Value = encoded;
            insert.ExecuteNonQuery();
        }
    }

    private static void InsertPreparedTarget(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxPrepareBatchRequest request,
        ScopedMailboxBatchTarget target,
        ulong counter,
        int ordinal)
    {
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO mailbox_prepared_batch_targets(
                account_scope,parent_operation_id,target_ordinal,
                target_operation_id,scope_id,request_digest,replay_counter)
            VALUES($account,$parent,$ordinal,$operation,$scope,$digest,$counter);
            """;
        insert.Parameters.Add("$account", SqliteType.Blob).Value =
            request.AccountScope.ToArray();
        insert.Parameters.Add("$parent", SqliteType.Blob).Value =
            request.ParentOperationId.ToArray();
        insert.Parameters.AddWithValue("$ordinal", ordinal);
        insert.Parameters.Add("$operation", SqliteType.Blob).Value =
            target.Binding.OperationId.ToArray();
        insert.Parameters.Add("$scope", SqliteType.Blob).Value =
            target.Selector.ScopeId.ToArray();
        insert.Parameters.Add("$digest", SqliteType.Blob).Value =
            target.Binding.RequestDigest.ToArray();
        insert.Parameters.Add("$counter", SqliteType.Blob).Value =
            MailboxU64(counter);
        insert.ExecuteNonQuery();
    }

    private static bool HasScopedBatchOutboxCapacity(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlySpan<byte> accountScope,
        int additionalBytes)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT count(*), COALESCE(sum(length(ciphertext_bundle)), 0)
            FROM transport_outbox_items WHERE account_scope=$scope;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value =
            accountScope.ToArray();
        using var reader = command.ExecuteReader();
        _ = reader.Read();
        var count = reader.GetInt64(0);
        var bytes = reader.GetInt64(1);
        return count < 4096 &&
            bytes <= 256L * 1024 * 1024 - additionalBytes;
    }

    private static bool ValidateSemanticBatchOwnership(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlySpan<byte> accountScope,
        ReadOnlySpan<byte> semanticOperationId,
        ReadOnlySpan<byte> parentOperationId)
    {
        using (var semantic = connection.CreateCommand())
        {
            semantic.Transaction = transaction;
            semantic.CommandText = """
                SELECT parent_operation_id FROM mailbox_prepared_batches
                WHERE account_scope=$account AND semantic_operation_id=$semantic;
                """;
            semantic.Parameters.Add("$account", SqliteType.Blob).Value =
                accountScope.ToArray();
            semantic.Parameters.Add("$semantic", SqliteType.Blob).Value =
                semanticOperationId.ToArray();
            var ownedParent = semantic.ExecuteScalar() as byte[];
            if (ownedParent is not null)
            {
                if (!Fixed(ownedParent, parentOperationId))
                    throw new InvalidOperationException(
                        "Mailbox semantic operation conflicts with its durable fan-out.");
                return true;
            }
        }

        using var parent = connection.CreateCommand();
        parent.Transaction = transaction;
        parent.CommandText = """
            SELECT semantic_operation_id FROM mailbox_prepared_batches
            WHERE account_scope=$account AND parent_operation_id=$parent;
            """;
        parent.Parameters.Add("$account", SqliteType.Blob).Value = accountScope.ToArray();
        parent.Parameters.Add("$parent", SqliteType.Blob).Value = parentOperationId.ToArray();
        var ownedSemantic = parent.ExecuteScalar() as byte[];
        if (ownedSemantic is not null && !Fixed(ownedSemantic, semanticOperationId))
            throw new InvalidOperationException(
                "Mailbox logical fan-out belongs to another semantic operation.");
        return ownedSemantic is not null;
    }

    private static ScopedMailboxPreparedBatch? ReadPreparedBatch(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxResumeBatchRequest request,
        byte[] planDigest)
    {
        using var read = connection.CreateCommand();
        read.Transaction = transaction;
        read.CommandText = """
            SELECT semantic_operation_id,plan_digest,target_count
            FROM mailbox_prepared_batches
            WHERE account_scope=$account AND parent_operation_id=$parent;
            """;
        read.Parameters.Add("$account", SqliteType.Blob).Value =
            request.AccountScope.ToArray();
        read.Parameters.Add("$parent", SqliteType.Blob).Value =
            request.ParentOperationId.ToArray();
        using var reader = read.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }
        if (!Fixed((byte[])reader.GetValue(0), request.SemanticOperationId.Span) ||
            !Fixed((byte[])reader.GetValue(1), planDigest) ||
            reader.GetInt32(2) != request.Selectors.Count)
        {
            throw new InvalidOperationException(
                "Mailbox batch operation conflicts with durable preparation.");
        }
        reader.Dispose();

        var catalog = new List<(
            int Ordinal,
            byte[] OperationId,
            byte[] ScopeId,
            byte[] RequestDigest,
            ulong Counter)>(request.Selectors.Count);
        using (var targets = connection.CreateCommand())
        {
            targets.Transaction = transaction;
            targets.CommandText = """
                SELECT target_ordinal,target_operation_id,scope_id,
                       request_digest,replay_counter
                FROM mailbox_prepared_batch_targets
                WHERE account_scope=$account AND parent_operation_id=$parent
                ORDER BY target_ordinal;
                """;
            targets.Parameters.Add("$account", SqliteType.Blob).Value =
                request.AccountScope.ToArray();
            targets.Parameters.Add("$parent", SqliteType.Blob).Value =
                request.ParentOperationId.ToArray();
            using var targetReader = targets.ExecuteReader();
            while (targetReader.Read())
            {
                catalog.Add((
                    targetReader.GetInt32(0),
                    (byte[])targetReader.GetValue(1),
                    (byte[])targetReader.GetValue(2),
                    (byte[])targetReader.GetValue(3),
                    MailboxReadU64((byte[])targetReader.GetValue(4))));
            }
        }
        if (catalog.Count != request.Selectors.Count)
        {
            throw new InvalidDataException(
                "Mailbox prepared batch target catalog is incomplete.");
        }

        var frames = new List<MailboxAuthenticatedRequestFrame>(
            request.Selectors.Count);
        for (var ordinal = 0; ordinal < request.Selectors.Count; ordinal++)
        {
            var target = request.Selectors[ordinal];
            var persisted = catalog[ordinal];
            if (persisted.Ordinal != ordinal ||
                persisted.Counter == 0 ||
                !Fixed(persisted.ScopeId, target.Selector.ScopeId.Span))
            {
                throw new InvalidDataException(
                    "Mailbox prepared batch target catalog is corrupt.");
            }
            var stored = ReadTransportOutboxItem(
                connection, transaction, request.AccountScope.Value,
                persisted.OperationId)
                ?? throw new InvalidDataException(
                    "Mailbox prepared batch lost an outbox target.");
            var canonical = stored.CiphertextBundle;
            var decoded =
                MailboxAuthenticatedClientRequestCodec.Decode(canonical);
            if (decoded.Binding.Operation != target.Operation ||
                decoded.Presentation.Operation != target.Operation ||
                decoded.Presentation.ReplayCounter != persisted.Counter ||
                !Fixed(decoded.Binding.OperationId.Span,
                    persisted.OperationId) ||
                !Fixed(decoded.Binding.RequestDigest.Span,
                    persisted.RequestDigest) ||
                !Fixed(decoded.Presentation.OperationId.Span,
                    persisted.OperationId) ||
                !Fixed(decoded.Presentation.RequestDigest.Span,
                    persisted.RequestDigest))
            {
                throw new InvalidDataException(
                    "Mailbox prepared batch target is corrupt.");
            }
            frames.Add(new MailboxAuthenticatedRequestFrame(
                decoded.Binding.Operation, canonical));
        }
        return new ScopedMailboxPreparedBatch(
            request.ParentOperationId, frames);
    }

    private static byte[] MailboxU64(ulong value)
    {
        var encoded = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
            encoded, value);
        return encoded;
    }

    private static ulong MailboxReadU64(ReadOnlySpan<byte> value)
    {
        if (value.Length != 8)
        {
            throw new InvalidDataException("Mailbox UInt64 state is invalid.");
        }
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(value);
    }
}
