using System.Security.Cryptography;
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
        "deep.mailbox.authenticated-authority-policy.v1"u8;
    private readonly byte[] networkId;
    private readonly byte[] policyFingerprint;
    private readonly Func<bool> entitlement;
    private readonly IReadOnlyList<MailboxCapabilityIssuerAuthority>
        trustedIssuers;

    public VerifiedOfficialMailboxAuthority(
        ReadOnlyMemory<byte> networkId,
        ulong minimumGeneration,
        IReadOnlyList<MailboxCapabilityIssuerAuthority> trustedIssuers,
        bool requiresManagedEntitlement,
        Func<bool> entitlement,
        IMailboxCapabilityRevocationSource revocations,
        TimeProvider timeProvider)
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
        Validate();
        policyFingerprint = ComputePolicyFingerprint(
            this.networkId, MinimumGeneration, this.trustedIssuers);
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong MinimumGeneration { get; }
    public IReadOnlyList<MailboxCapabilityIssuerAuthority> TrustedIssuers =>
        Array.AsReadOnly(trustedIssuers.Select(CloneIssuer).ToArray());
    public bool RequiresManagedEntitlement { get; }
    public bool IsEntitled => !RequiresManagedEntitlement || entitlement();
    public IMailboxCapabilityRevocationSource Revocations { get; }
    public TimeProvider TimeProvider { get; }
    public ReadOnlyMemory<byte> PolicyFingerprint =>
        policyFingerprint.ToArray();

    public ulong NowUnixSeconds => checked(
        (ulong)TimeProvider.GetUtcNow().ToUnixTimeSeconds());

    public void Validate()
    {
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
        IReadOnlyList<MailboxCapabilityIssuerAuthority> issuers)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(FingerprintDomain);
        hash.AppendData(network);
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
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
                encoded, issuer.ValidFromUnixSeconds);
            hash.AppendData(encoded);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
                encoded, issuer.ValidUntilUnixSeconds);
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
    MailboxCredentialReplicaPair Replicas);

public sealed record ScopedMailboxBatchTarget(
    MailboxCredentialSelector Selector,
    MailboxAuthenticatedRequestBinding Binding);

/// <summary>Opaque route material resolved only from a verified scoped credential.</summary>
public sealed record ScopedMailboxResolvedRoute(
    ulong Epoch,
    BlindedMailboxId MailboxId,
    BlindedPlacementId PlacementId,
    ReadOnlyMemory<byte> PlacementCommitment,
    ReadOnlyMemory<byte> MembershipCommitment,
    MailboxCredentialReplicaPair Replicas);

public sealed record ScopedMailboxPrepareBatchRequest(
    OutboxAccountScope AccountScope,
    ReadOnlyMemory<byte> ParentOperationId,
    IReadOnlyList<ScopedMailboxBatchTarget> Targets,
    DateTimeOffset CreatedAt);

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
}

public sealed partial class SqliteSessionStore : IScopedMailboxCredentialRepository
{
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
                        scope_id, account_scope, scope_kind, subject_id,
                        issuer_context, network_id, authority_policy_digest, holder_key,
                        generation, active_epoch, group_membership_commitment)
                    VALUES($scope,$account,$kind,$subject,$issuer,$network,$authorityPolicy,
                           $holder,$generation,$epoch,$membership);
                    """;
                    insert.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
                    insert.Parameters.Add("$account", SqliteType.Blob).Value = selector.AccountScope.ToArray();
                    insert.Parameters.AddWithValue("$kind", (int)selector.Kind);
                    insert.Parameters.Add("$subject", SqliteType.Blob).Value = selector.SubjectId.ToArray();
                    insert.Parameters.Add("$issuer", SqliteType.Blob).Value = selector.IssuerContext.ToArray();
                    insert.Parameters.Add("$network", SqliteType.Blob).Value = authority.NetworkId.ToArray();
                    insert.Parameters.Add("$authorityPolicy", SqliteType.Blob).Value =
                        authority.PolicyFingerprint.ToArray();
                    insert.Parameters.Add("$holder", SqliteType.Blob).Value = generation.HolderPublicKey.ToArray();
                    insert.Parameters.Add("$generation", SqliteType.Blob).Value = generation.Generation.ToArray();
                    insert.Parameters.Add("$epoch", SqliteType.Blob).Value = MailboxU64(generation.Current.Epoch);
                    insert.Parameters.Add("$membership", SqliteType.Blob).Value =
                        selector.GroupMembershipCommitment.IsEmpty
                            ? DBNull.Value
                            : selector.GroupMembershipCommitment.ToArray();
                    insert.ExecuteNonQuery();
                }

                InsertEpoch(connection, transaction, generation, generation.Current);
                InsertEpoch(connection, transaction, generation, generation.Next);
                InsertGrants(connection, transaction, generation, generation.Current.Epoch);
                InsertGrants(connection, transaction, generation, generation.Next.Epoch);
            }
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
        }
        finally
        {
            _databaseGate.Release();
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
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT s.account_scope,s.network_id,s.authority_policy_digest,
                       s.group_membership_commitment,s.active_epoch,
                       e.not_before,e.expires_at,e.mailbox_id,e.placement_id,
                       e.placement_commitment,e.membership_commitment,
                       e.first_replica_id,e.first_replica_key,
                       e.second_replica_id,e.second_replica_key
                FROM mailbox_credential_scopes s
                JOIN mailbox_credential_epochs e
                  ON e.scope_id=s.scope_id AND e.epoch=s.active_epoch
                WHERE s.scope_id=$scope;
                """;
            command.Parameters.Add("$scope", SqliteType.Blob).Value =
                selector.ScopeId.ToArray();
            using var reader = command.ExecuteReader();
            if (!reader.Read() ||
                !Fixed((byte[])reader.GetValue(0), selector.AccountScope.Value) ||
                !Fixed((byte[])reader.GetValue(1), authority.NetworkId.Span) ||
                !Fixed((byte[])reader.GetValue(2), authority.PolicyFingerprint.Span) ||
                authority.NowUnixSeconds < MailboxReadU64((byte[])reader.GetValue(5)) ||
                authority.NowUnixSeconds > MailboxReadU64((byte[])reader.GetValue(6)) ||
                selector.Kind == MailboxCredentialScopeKind.Group &&
                (reader.IsDBNull(3) || !Fixed((byte[])reader.GetValue(3),
                    selector.GroupMembershipCommitment.Span)))
            {
                throw new InvalidOperationException(
                    "Exact scoped mailbox route is unavailable.");
            }
            return new ScopedMailboxResolvedRoute(
                MailboxReadU64((byte[])reader.GetValue(4)),
                new BlindedMailboxId((byte[])reader.GetValue(7)),
                new BlindedPlacementId((byte[])reader.GetValue(8)),
                (byte[])reader.GetValue(9),
                (byte[])reader.GetValue(10),
                new MailboxCredentialReplicaPair(
                    (byte[])reader.GetValue(11), (byte[])reader.GetValue(12),
                    (byte[])reader.GetValue(13), (byte[])reader.GetValue(14)));
        }
        finally
        {
            _databaseGate.Release();
        }
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
            var planDigest = ComputePlanDigest(request);
            var resumed = ReadPreparedBatch(
                connection, transaction, request, planDigest);
            if (resumed is not null)
            {
                for (var ordinal = 0; ordinal < request.Targets.Count; ordinal++)
                {
                    var target = request.Targets[ordinal];
                    var resolved = ResolveForPrepare(
                        connection, transaction, target, signer, authority,
                        allocateCounter: false);
                    ValidateResumedFrame(
                        resumed.Frames[ordinal], target, resolved, signer);
                }
                transaction.Commit();
                return resumed;
            }

            var frames = new List<MailboxAuthenticatedRequestFrame>(
                request.Targets.Count);
            using (var batch = connection.CreateCommand())
            {
                batch.Transaction = transaction;
                batch.CommandText = """
                    INSERT INTO mailbox_prepared_batches(
                        account_scope,parent_operation_id,plan_digest,target_count,created_at)
                    VALUES($account,$parent,$digest,$count,$created);
                    """;
                batch.Parameters.Add("$account", SqliteType.Blob).Value =
                    request.AccountScope.ToArray();
                batch.Parameters.Add("$parent", SqliteType.Blob).Value =
                    request.ParentOperationId.ToArray();
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
            if (!reader.Read() ||
                MailboxReadU64((byte[])reader.GetValue(0)) != epoch.NotBeforeUnixSeconds ||
                MailboxReadU64((byte[])reader.GetValue(1)) != epoch.ExpiresAtUnixSeconds ||
                !Fixed((byte[])reader.GetValue(2), value.MailboxId.Span) ||
                !Fixed((byte[])reader.GetValue(3), epoch.PlacementId.Span) ||
                !Fixed((byte[])reader.GetValue(4), epoch.PlacementCommitment.Span) ||
                !Fixed((byte[])reader.GetValue(5), epoch.MembershipCommitment.Span) ||
                !Fixed((byte[])reader.GetValue(6), value.Replicas.FirstId.Span) ||
                !Fixed((byte[])reader.GetValue(7), value.Replicas.FirstSigningKey.Span) ||
                !Fixed((byte[])reader.GetValue(8), value.Replicas.SecondId.Span) ||
                !Fixed((byte[])reader.GetValue(9), value.Replicas.SecondSigningKey.Span))
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
        insert.Parameters.Add("$firstId", SqliteType.Blob).Value =
            generation.Replicas.FirstId.ToArray();
        insert.Parameters.Add("$firstKey", SqliteType.Blob).Value =
            generation.Replicas.FirstSigningKey.ToArray();
        insert.Parameters.Add("$secondId", SqliteType.Blob).Value =
            generation.Replicas.SecondId.ToArray();
        insert.Parameters.Add("$secondKey", SqliteType.Blob).Value =
            generation.Replicas.SecondSigningKey.ToArray();
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

    private static ScopedMailboxPreparedBatch? ReadPreparedBatch(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxPrepareBatchRequest request,
        byte[] planDigest)
    {
        using var read = connection.CreateCommand();
        read.Transaction = transaction;
        read.CommandText = """
            SELECT plan_digest,target_count,created_at FROM mailbox_prepared_batches
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
        if (!Fixed((byte[])reader.GetValue(0), planDigest) ||
            reader.GetInt32(1) != request.Targets.Count ||
            reader.GetInt64(2) != request.CreatedAt.ToUnixTimeMilliseconds())
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
            ulong Counter)>(request.Targets.Count);
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
        if (catalog.Count != request.Targets.Count)
        {
            throw new InvalidDataException(
                "Mailbox prepared batch target catalog is incomplete.");
        }

        var frames = new List<MailboxAuthenticatedRequestFrame>(
            request.Targets.Count);
        for (var ordinal = 0; ordinal < request.Targets.Count; ordinal++)
        {
            var target = request.Targets[ordinal];
            var persisted = catalog[ordinal];
            if (persisted.Ordinal != ordinal ||
                persisted.Counter == 0 ||
                !Fixed(persisted.OperationId, target.Binding.OperationId.Span) ||
                !Fixed(persisted.ScopeId, target.Selector.ScopeId.Span) ||
                !Fixed(persisted.RequestDigest, target.Binding.RequestDigest.Span))
            {
                throw new InvalidDataException(
                    "Mailbox prepared batch target catalog is corrupt.");
            }
            var stored = ReadTransportOutboxItem(
                connection, transaction, request.AccountScope.Value,
                target.Binding.OperationId.Span)
                ?? throw new InvalidDataException(
                    "Mailbox prepared batch lost an outbox target.");
            var canonical = stored.CiphertextBundle;
            var decoded =
                MailboxAuthenticatedClientRequestCodec.Decode(canonical);
            if (decoded.Binding.Operation != target.Binding.Operation ||
                decoded.Presentation.Operation != target.Binding.Operation ||
                decoded.Presentation.ReplayCounter != persisted.Counter ||
                !Fixed(decoded.Binding.OperationId.Span,
                    target.Binding.OperationId.Span) ||
                !Fixed(decoded.Binding.RequestDigest.Span,
                    target.Binding.RequestDigest.Span) ||
                !Fixed(decoded.Binding.CanonicalRequest.Span,
                    target.Binding.CanonicalRequest.Span) ||
                !Fixed(decoded.Presentation.OperationId.Span,
                    target.Binding.OperationId.Span) ||
                !Fixed(decoded.Presentation.RequestDigest.Span,
                    target.Binding.RequestDigest.Span))
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
