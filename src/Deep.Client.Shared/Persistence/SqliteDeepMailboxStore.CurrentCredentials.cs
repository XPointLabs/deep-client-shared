#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

/// <summary>
/// Durable clean-break current-epoch mailbox credentials. ContactV1 XMC1 does
/// not issue a speculative next grant, so rollover is an authenticated replace
/// after a fresh acquisition rather than a fabricated current/next bundle.
/// </summary>
public sealed partial class SqliteDeepMailboxStore
{
    public Task InstallScopedCredentialAsync(
        ScopedMailboxCredentialGeneration generation,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default) =>
        throw PairCredentialsUnavailable();

    public Task InstallScopedCredentialBatchAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default) =>
        throw PairCredentialsUnavailable();

    public Task RotateScopedCredentialBatchAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default) =>
        throw PairCredentialsUnavailable();

    public Task SwitchScopedCredentialEpochAsync(
        MailboxCredentialSelector selector,
        ulong epoch,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default) =>
        throw PairCredentialsUnavailable();

    public async Task InstallCurrentScopedCredentialAsync(
        ScopedCurrentMailboxCredential credential,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ValidateCurrentCredential(credential, authority);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: false);
            var existing = ReadCurrentIdentity(
                connection, transaction, credential.Selector.ScopeId.Span);
            if (existing is not null)
            {
                if (existing.Value.Epoch > credential.Current.Epoch)
                    throw new InvalidOperationException(
                        "A current mailbox credential cannot roll back its epoch.");
                if (existing.Value.Epoch == credential.Current.Epoch)
                {
                    EnsureExactCurrentCredential(
                        connection, transaction, credential, authority);
                    await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                    return;
                }
                DeleteCurrentCredential(
                    connection, transaction, credential.Selector.ScopeId.Span);
            }

            InsertCurrentCredential(
                connection, transaction, credential, authority);
            cancellationToken.ThrowIfCancellationRequested();
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
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
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: false);
            var resolved = ResolveCurrent(
                connection, transaction, selector, role: null,
                authority, binding: null, allocateCounter: false);
            cancellationToken.ThrowIfCancellationRequested();
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return resolved.Route;
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
        var role = ScopedMailboxCredentialValidator.RoleFor(operation);
        ScopedMailboxCredentialValidator.EnsureRoleAllowed(selector, role);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: false);
            var resolved = ResolveCurrent(
                connection, transaction, selector, role,
                authority, binding: null, allocateCounter: false);
            cancellationToken.ThrowIfCancellationRequested();
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
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
        authority.Validate();
        ScopedMailboxCredentialValidator.ValidateBatch(request, signer);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: false);
            var semanticOwnerExists = ValidateSemanticBatchOwnershipCurrent(
                connection, transaction, request.AccountScope.Value,
                request.SemanticOperationId.Span, request.ParentOperationId.Span);
            var planDigest = ScopedMailboxCredentialValidator.ComputePlanDigest(request);
            var resume = new ScopedMailboxResumeBatchRequest(
                request.AccountScope, request.ParentOperationId,
                request.SemanticOperationId, request.Selectors);
            var resumed = ReadPreparedBatchCurrent(
                connection, transaction, resume, planDigest);
            if (resumed is not null)
            {
                ValidateResumedFrames(
                    connection, transaction, resumed, request.Targets,
                    signer, authority);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return resumed;
            }
            if (semanticOwnerExists)
                throw new InvalidDataException(
                    "Mailbox semantic batch owner lost its prepared batch.");

            using (var insert = connection.CreateCommand())
            {
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO mailbox_prepared_batches(
                        account_scope,parent_operation_id,semantic_operation_id,
                        plan_digest,target_count,created_at)
                    VALUES($account,$parent,$semantic,$digest,$count,$created);
                    """;
                insert.Parameters.Add("$account", SqliteType.Blob).Value =
                    request.AccountScope.ToArray();
                insert.Parameters.Add("$parent", SqliteType.Blob).Value =
                    request.ParentOperationId.ToArray();
                insert.Parameters.Add("$semantic", SqliteType.Blob).Value =
                    request.SemanticOperationId.ToArray();
                insert.Parameters.Add("$digest", SqliteType.Blob).Value = planDigest;
                insert.Parameters.AddWithValue("$count", request.Targets.Count);
                insert.Parameters.AddWithValue(
                    "$created", request.CreatedAt.ToUnixTimeMilliseconds());
                insert.ExecuteNonQuery();
            }

            var frames = new List<MailboxAuthenticatedRequestFrame>(request.Targets.Count);
            for (var ordinal = 0; ordinal < request.Targets.Count; ordinal++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var target = request.Targets[ordinal];
                var role = ScopedMailboxCredentialValidator.RoleFor(
                    target.Binding.Operation);
                ScopedMailboxCredentialValidator.EnsureRoleAllowed(
                    target.Selector, role);
                var resolved = ResolveCurrent(
                    connection, transaction, target.Selector, role,
                    authority, target.Binding, allocateCounter: true);
                var frame = ScopedMailboxCredentialValidator.Sign(
                    target.Binding, signer, resolved.Grant!,
                    resolved.Counter, resolved.HolderKey);
                var canonical = frame.GetCanonicalMau2Copy();
                var logicalId = OutboxLogicalId.FromBytes(
                    target.Binding.OperationId.Span);
                var prepared = TransportOutboxPreparedItem.Create(
                    request.AccountScope,
                    logicalId,
                    OutboxDedupMaterial.FromBytes(target.Binding.RequestDigest.Span),
                    canonical,
                    request.CreatedAt,
                    DateTimeOffset.FromUnixTimeSeconds(
                        checked((long)resolved.Grant!.ExpiresAtUnixSeconds)),
                    request.CreatedAt);
                if (ReadTransportOutboxItem(
                        connection, transaction, request.AccountScope.Value,
                        logicalId.Value) is not null)
                    throw new InvalidOperationException(
                        "Mailbox target operation conflicts with durable outbox state.");
                if (!HasCurrentOutboxCapacity(
                        connection, transaction, request.AccountScope.Value,
                        canonical.Length))
                    throw new InvalidOperationException(
                        "Mailbox prepared batch exceeds durable outbox capacity.");
                InsertTransportOutboxItem(
                    connection, transaction,
                    TransportOutboxStateMachine.Prepared(prepared));
                InsertPreparedTargetCurrent(
                    connection, transaction, request, target,
                    resolved.Counter, ordinal);
                frames.Add(frame);
            }

            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            cancellationToken.ThrowIfCancellationRequested();
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch
            {
                throw new TransportOutboxCommitOutcomeUnknownException();
            }
            return new ScopedMailboxPreparedBatch(request.ParentOperationId, frames);
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
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: false);
            var semanticOwnerExists = ValidateSemanticBatchOwnershipCurrent(
                connection, transaction, request.AccountScope.Value,
                request.SemanticOperationId.Span, request.ParentOperationId.Span);
            var resumed = ReadPreparedBatchCurrent(
                connection, transaction, request,
                ScopedMailboxCredentialValidator.ComputePlanDigest(request));
            if (resumed is null)
            {
                if (semanticOwnerExists)
                    throw new InvalidDataException(
                        "Mailbox semantic batch owner lost its prepared batch.");
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return null;
            }
            var targets = resumed.Frames.Select((frame, index) =>
            {
                var decoded = MailboxAuthenticatedClientRequestCodec.Decode(
                    frame.GetCanonicalMau2Copy());
                if (decoded.Binding.Operation != request.Selectors[index].Operation)
                    throw new InvalidDataException(
                        "Mailbox prepared batch operation catalog is corrupt.");
                return new ScopedMailboxBatchTarget(
                    request.Selectors[index].Selector, decoded.Binding);
            }).ToArray();
            ValidateResumedFrames(
                connection, transaction, resumed, targets, signer, authority);
            cancellationToken.ThrowIfCancellationRequested();
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return resumed;
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    private static NotSupportedException PairCredentialsUnavailable() => new(
        "The clean mailbox store accepts only exact current XMG1/XMC1 credentials.");

    private static void ValidateCurrentCredential(
        ScopedCurrentMailboxCredential value,
        VerifiedOfficialMailboxAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(value.Selector);
        ArgumentNullException.ThrowIfNull(value.Current);
        ArgumentNullException.ThrowIfNull(value.Grants);
        ArgumentNullException.ThrowIfNull(value.Replicas);
        authority.Validate();
        if (!NonzeroCurrent(value.Generation.Span, 32) ||
            !NonzeroCurrent(value.HolderPublicKey.Span, 32) ||
            !NonzeroCurrent(value.MailboxId.Span, 32) ||
            authority.NowUnixSeconds < value.Current.NotBeforeUnixSeconds ||
            authority.NowUnixSeconds > value.Current.ExpiresAtUnixSeconds ||
            !FixedCurrent(
                value.Current.PlacementCommitment.Span,
                MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(value.Current.PlacementId.Span))))
            throw new InvalidDataException(
                "The current scoped mailbox credential is invalid.");

        var retrieve = value.Grants.RetrieveGrant;
        var deposit = value.Grants.DepositGrant;
        if (value.Selector.Kind == MailboxCredentialScopeKind.Self && retrieve.IsEmpty ||
            value.Selector.Kind == MailboxCredentialScopeKind.Peer && deposit.IsEmpty ||
            value.Selector.Kind == MailboxCredentialScopeKind.Group && deposit.IsEmpty)
            throw new InvalidDataException(
                "The current mailbox grant role does not match its scope.");
        if (!retrieve.IsEmpty)
            _ = ScopedMailboxCredentialValidator.ValidateCanonicalGrant(
                retrieve.Span, MailboxCredentialRole.Retrieve,
                value.Current.Epoch, value.Current.NotBeforeUnixSeconds,
                value.Current.ExpiresAtUnixSeconds,
                value.Current.PlacementCommitment.Span,
                value.Current.MembershipCommitment.Span,
                value.HolderPublicKey.Span, authority, rejectRevoked: true);
        if (!deposit.IsEmpty)
            _ = ScopedMailboxCredentialValidator.ValidateCanonicalGrant(
                deposit.Span, MailboxCredentialRole.Deposit,
                value.Current.Epoch, value.Current.NotBeforeUnixSeconds,
                value.Current.ExpiresAtUnixSeconds,
                value.Current.PlacementCommitment.Span,
                value.Current.MembershipCommitment.Span,
                value.HolderPublicKey.Span, authority, rejectRevoked: true);
    }

    private static (ulong Epoch, byte[] Generation)? ReadCurrentIdentity(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlySpan<byte> scope)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT active_epoch,generation FROM mailbox_credential_scopes WHERE scope_id=$scope;";
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? (ReadU64Current((byte[])reader.GetValue(0)),
                (byte[])reader.GetValue(1))
            : null;
    }

    private static void DeleteCurrentCredential(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlySpan<byte> scope)
    {
        using (var replay = connection.CreateCommand())
        {
            replay.Transaction = transaction;
            replay.CommandText =
                "DELETE FROM mailbox_replay_counters WHERE scope_id=$scope;";
            replay.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
            replay.ExecuteNonQuery();
        }
        using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText =
            "DELETE FROM mailbox_credential_scopes WHERE scope_id=$scope;";
        delete.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
        if (delete.ExecuteNonQuery() != 1)
            throw new InvalidOperationException(
                "The current mailbox credential changed concurrently.");
    }

    private static void InsertCurrentCredential(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedCurrentMailboxCredential value,
        VerifiedOfficialMailboxAuthority authority)
    {
        var selector = value.Selector;
        using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO mailbox_credential_scopes(
                    scope_id,account_scope,scope_kind,subject_id,issuer_context,
                    network_id,authority_policy_digest,holder_key,generation,
                    active_epoch,group_membership_commitment)
                VALUES($scope,$account,$kind,$subject,$issuer,$network,$policy,
                       $holder,$generation,$epoch,$membership);
                """;
            insert.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
            insert.Parameters.Add("$account", SqliteType.Blob).Value = selector.AccountScope.ToArray();
            insert.Parameters.AddWithValue("$kind", (int)selector.Kind);
            insert.Parameters.Add("$subject", SqliteType.Blob).Value = selector.SubjectId.ToArray();
            insert.Parameters.Add("$issuer", SqliteType.Blob).Value = selector.IssuerContext.ToArray();
            insert.Parameters.Add("$network", SqliteType.Blob).Value = authority.NetworkId.ToArray();
            insert.Parameters.Add("$policy", SqliteType.Blob).Value = authority.PolicyFingerprint.ToArray();
            insert.Parameters.Add("$holder", SqliteType.Blob).Value = value.HolderPublicKey.ToArray();
            insert.Parameters.Add("$generation", SqliteType.Blob).Value = value.Generation.ToArray();
            insert.Parameters.Add("$epoch", SqliteType.Blob).Value = U64Current(value.Current.Epoch);
            insert.Parameters.Add("$membership", SqliteType.Blob).Value =
                selector.GroupMembershipCommitment.IsEmpty
                    ? DBNull.Value
                    : selector.GroupMembershipCommitment.ToArray();
            insert.ExecuteNonQuery();
        }
        InsertCurrentEpoch(connection, transaction, value);
        if (!value.Grants.RetrieveGrant.IsEmpty)
            InsertCurrentGrant(
                connection, transaction, value,
                MailboxCredentialRole.Retrieve,
                value.Grants.RetrieveGrant.Span);
        if (!value.Grants.DepositGrant.IsEmpty)
            InsertCurrentGrant(
                connection, transaction, value,
                MailboxCredentialRole.Deposit,
                value.Grants.DepositGrant.Span);
    }

    private static void InsertCurrentEpoch(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedCurrentMailboxCredential value)
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
        insert.Parameters.Add("$scope", SqliteType.Blob).Value = value.Selector.ScopeId.ToArray();
        insert.Parameters.Add("$epoch", SqliteType.Blob).Value = U64Current(value.Current.Epoch);
        insert.Parameters.Add("$notBefore", SqliteType.Blob).Value = U64Current(value.Current.NotBeforeUnixSeconds);
        insert.Parameters.Add("$expires", SqliteType.Blob).Value = U64Current(value.Current.ExpiresAtUnixSeconds);
        insert.Parameters.Add("$mailbox", SqliteType.Blob).Value = value.MailboxId.ToArray();
        insert.Parameters.Add("$placement", SqliteType.Blob).Value = value.Current.PlacementId.ToArray();
        insert.Parameters.Add("$placementCommitment", SqliteType.Blob).Value = value.Current.PlacementCommitment.ToArray();
        insert.Parameters.Add("$membership", SqliteType.Blob).Value = value.Current.MembershipCommitment.ToArray();
        insert.Parameters.Add("$firstId", SqliteType.Blob).Value = value.Replicas.FirstId.ToArray();
        insert.Parameters.Add("$firstKey", SqliteType.Blob).Value = value.Replicas.FirstSigningKey.ToArray();
        insert.Parameters.Add("$secondId", SqliteType.Blob).Value = value.Replicas.SecondId.ToArray();
        insert.Parameters.Add("$secondKey", SqliteType.Blob).Value = value.Replicas.SecondSigningKey.ToArray();
        insert.ExecuteNonQuery();
    }

    private static void InsertCurrentGrant(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedCurrentMailboxCredential value,
        MailboxCredentialRole role,
        ReadOnlySpan<byte> encoded)
    {
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(encoded);
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO mailbox_credential_grants(
                scope_id,epoch,role,issuer_context,grant_digest,issuer_key,
                serial,canonical_grant)
            VALUES($scope,$epoch,$role,$issuer,$digest,$issuerKey,$serial,$grant);
            """;
        insert.Parameters.Add("$scope", SqliteType.Blob).Value = value.Selector.ScopeId.ToArray();
        insert.Parameters.Add("$epoch", SqliteType.Blob).Value = U64Current(value.Current.Epoch);
        insert.Parameters.AddWithValue("$role", (int)role);
        insert.Parameters.Add("$issuer", SqliteType.Blob).Value = value.Selector.IssuerContext.ToArray();
        insert.Parameters.Add("$digest", SqliteType.Blob).Value = SHA256.HashData(encoded);
        insert.Parameters.Add("$issuerKey", SqliteType.Blob).Value = grant.IssuerPublicKey.ToArray();
        insert.Parameters.Add("$serial", SqliteType.Blob).Value = grant.Serial.ToArray();
        insert.Parameters.Add("$grant", SqliteType.Blob).Value = encoded.ToArray();
        insert.ExecuteNonQuery();
    }

    private static void EnsureExactCurrentCredential(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedCurrentMailboxCredential value,
        VerifiedOfficialMailboxAuthority authority)
    {
        var resolvedRole = value.Grants.DepositGrant.IsEmpty
            ? MailboxCredentialRole.Retrieve
            : MailboxCredentialRole.Deposit;
        var resolved = ResolveCurrentStatic(
            connection, transaction, value.Selector, resolvedRole,
            authority, binding: null, allocateCounter: false);
        var expectedGrant = resolvedRole == MailboxCredentialRole.Deposit
            ? value.Grants.DepositGrant.Span
            : value.Grants.RetrieveGrant.Span;
        var actualGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(resolved.Grant!);
        try
        {
            if (!FixedCurrent(resolved.HolderKey, value.HolderPublicKey.Span) ||
                !FixedCurrent(actualGrant, expectedGrant) ||
                !FixedCurrent(resolved.Route.MailboxId.Bytes.Span, value.MailboxId.Span) ||
                !FixedCurrent(resolved.Route.PlacementId.Bytes.Span, value.Current.PlacementId.Span) ||
                !FixedCurrent(resolved.Route.MembershipCommitment.Span, value.Current.MembershipCommitment.Span) ||
                !FixedCurrent(value.Generation.Span,
                    ReadCurrentIdentity(connection, transaction, value.Selector.ScopeId.Span)!.Value.Generation))
                throw new InvalidOperationException(
                    "The current mailbox credential retry conflicts with persisted material.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualGrant);
        }
    }

    private sealed record CurrentResolvedGrant(
        MailboxAuthenticatedGrant? Grant,
        ulong Counter,
        byte[] HolderKey,
        ScopedMailboxResolvedRoute Route);

    private CurrentResolvedGrant ResolveCurrent(
        SqliteConnection connection,
        SqliteTransaction transaction,
        MailboxCredentialSelector selector,
        MailboxCredentialRole? role,
        VerifiedOfficialMailboxAuthority authority,
        MailboxAuthenticatedRequestBinding? binding,
        bool allocateCounter) => ResolveCurrentStatic(
            connection, transaction, selector, role, authority,
            binding, allocateCounter);

    private static CurrentResolvedGrant ResolveCurrentStatic(
        SqliteConnection connection,
        SqliteTransaction transaction,
        MailboxCredentialSelector selector,
        MailboxCredentialRole? role,
        VerifiedOfficialMailboxAuthority authority,
        MailboxAuthenticatedRequestBinding? binding,
        bool allocateCounter)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = role is null ? """
            SELECT s.account_scope,s.network_id,s.authority_policy_digest,s.holder_key,
                   s.active_epoch,s.group_membership_commitment,e.not_before,e.expires_at,
                   e.mailbox_id,e.placement_id,e.placement_commitment,e.membership_commitment,
                   e.first_replica_id,e.first_replica_key,e.second_replica_id,e.second_replica_key,
                   NULL,NULL
            FROM mailbox_credential_scopes s
            JOIN mailbox_credential_epochs e
              ON e.scope_id=s.scope_id AND e.epoch=s.active_epoch
            WHERE s.scope_id=$scope;
            """ : """
            SELECT s.account_scope,s.network_id,s.authority_policy_digest,s.holder_key,
                   s.active_epoch,s.group_membership_commitment,e.not_before,e.expires_at,
                   e.mailbox_id,e.placement_id,e.placement_commitment,e.membership_commitment,
                   e.first_replica_id,e.first_replica_key,e.second_replica_id,e.second_replica_key,
                   g.grant_digest,g.canonical_grant
            FROM mailbox_credential_scopes s
            JOIN mailbox_credential_epochs e
              ON e.scope_id=s.scope_id AND e.epoch=s.active_epoch
            JOIN mailbox_credential_grants g
              ON g.scope_id=s.scope_id AND g.epoch=s.active_epoch AND g.role=$role
            WHERE s.scope_id=$scope;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value = selector.ScopeId.ToArray();
        if (role is not null)
            command.Parameters.AddWithValue("$role", (int)role.Value);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            throw new InvalidOperationException(
                "Exact current scoped mailbox credential is unavailable.");
        var epoch = ReadU64Current((byte[])reader.GetValue(4));
        var notBefore = ReadU64Current((byte[])reader.GetValue(6));
        var expires = ReadU64Current((byte[])reader.GetValue(7));
        var mailbox = (byte[])reader.GetValue(8);
        var placement = (byte[])reader.GetValue(9);
        var placementCommitment = (byte[])reader.GetValue(10);
        var membership = (byte[])reader.GetValue(11);
        if (!FixedCurrent((byte[])reader.GetValue(0), selector.AccountScope.Value) ||
            !FixedCurrent((byte[])reader.GetValue(1), authority.NetworkId.Span) ||
            !FixedCurrent((byte[])reader.GetValue(2), authority.PolicyFingerprint.Span) ||
            authority.NowUnixSeconds < notBefore || authority.NowUnixSeconds > expires ||
            selector.Kind == MailboxCredentialScopeKind.Group &&
                (reader.IsDBNull(5) ||
                 !FixedCurrent((byte[])reader.GetValue(5), selector.GroupMembershipCommitment.Span)) ||
            !FixedCurrent(
                placementCommitment,
                MailboxPlacementCommitment.Compute(new BlindedPlacementId(placement))))
            throw new InvalidOperationException(
                "Current scoped mailbox credential authority is stale or mismatched.");
        if (binding is not null)
            ScopedMailboxCredentialValidator.ValidateBindingRoute(
                binding, epoch, mailbox, placement);
        var holder = (byte[])reader.GetValue(3);
        MailboxAuthenticatedGrant? grant = null;
        byte[]? grantDigest = null;
        if (role is not null)
        {
            grantDigest = (byte[])reader.GetValue(16);
            grant = ScopedMailboxCredentialValidator.ValidateCanonicalGrant(
                (byte[])reader.GetValue(17), role.Value, epoch, notBefore,
                expires, placementCommitment, membership, holder,
                authority, rejectRevoked: true);
        }
        var replicas = new MailboxCredentialReplicaPair(
            (byte[])reader.GetValue(12), (byte[])reader.GetValue(13),
            (byte[])reader.GetValue(14), (byte[])reader.GetValue(15));
        reader.Dispose();
        var counter = allocateCounter
            ? AllocateCounterCurrent(
                connection, transaction, selector.ScopeId.Span,
                epoch, grantDigest!)
            : 0;
        return new CurrentResolvedGrant(
            grant, counter, holder,
            new ScopedMailboxResolvedRoute(
                epoch, expires, new BlindedMailboxId(mailbox),
                new BlindedPlacementId(placement), placementCommitment,
                membership, replicas));
    }

    private static ulong AllocateCounterCurrent(
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
        read.Parameters.Add("$epoch", SqliteType.Blob).Value = U64Current(epoch);
        read.Parameters.Add("$digest", SqliteType.Blob).Value = grantDigest;
        var stored = read.ExecuteScalar() as byte[];
        var counter = stored is null ? 1UL : ReadU64Current(stored);
        if (counter == 0 || counter == ulong.MaxValue)
            throw new InvalidOperationException("Mailbox replay counter is exhausted.");
        using var upsert = connection.CreateCommand();
        upsert.Transaction = transaction;
        upsert.CommandText = """
            INSERT INTO mailbox_replay_counters(scope_id,epoch,grant_digest,next_counter)
            VALUES($scope,$epoch,$digest,$next)
            ON CONFLICT(scope_id,epoch,grant_digest)
            DO UPDATE SET next_counter=excluded.next_counter;
            """;
        upsert.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
        upsert.Parameters.Add("$epoch", SqliteType.Blob).Value = U64Current(epoch);
        upsert.Parameters.Add("$digest", SqliteType.Blob).Value = grantDigest;
        upsert.Parameters.Add("$next", SqliteType.Blob).Value = U64Current(counter + 1);
        upsert.ExecuteNonQuery();
        return counter;
    }

    private static void ValidateResumedFrames(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScopedMailboxPreparedBatch resumed,
        IReadOnlyList<ScopedMailboxBatchTarget> targets,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority)
    {
        for (var ordinal = 0; ordinal < targets.Count; ordinal++)
        {
            var target = targets[ordinal];
            var role = ScopedMailboxCredentialValidator.RoleFor(
                target.Binding.Operation);
            var resolved = ResolveCurrentStatic(
                connection, transaction, target.Selector, role,
                authority, target.Binding, allocateCounter: false);
            var frame = resumed.Frames[ordinal];
            var decoded = MailboxAuthenticatedClientRequestCodec.Decode(
                frame.GetCanonicalMau2Copy());
            var persistedGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(
                decoded.Presentation.Grant);
            var currentGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(
                resolved.Grant!);
            var signerKey = signer.GetEd25519PublicKey();
            try
            {
                if (decoded.Binding.Operation != target.Binding.Operation ||
                    decoded.Presentation.Operation != target.Binding.Operation ||
                    !FixedCurrent(decoded.Binding.OperationId.Span, target.Binding.OperationId.Span) ||
                    !FixedCurrent(decoded.Binding.RequestDigest.Span, target.Binding.RequestDigest.Span) ||
                    !FixedCurrent(decoded.Binding.CanonicalRequest.Span, target.Binding.CanonicalRequest.Span) ||
                    !FixedCurrent(persistedGrant, currentGrant) ||
                    !FixedCurrent(signerKey, resolved.HolderKey) ||
                    !new SodiumMailboxCapabilityCrypto().VerifyHolder(
                        resolved.HolderKey,
                        MailboxAuthenticatedCapabilityCodec
                            .GetPresentationSigningBytes(decoded.Presentation),
                        decoded.Presentation.HolderSignature.Span))
                    throw new InvalidDataException(
                        "Mailbox prepared batch frame is stale or corrupt.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(persistedGrant);
                CryptographicOperations.ZeroMemory(currentGrant);
                CryptographicOperations.ZeroMemory(signerKey);
            }
        }
    }

    private static void InsertPreparedTargetCurrent(
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
        insert.Parameters.Add("$account", SqliteType.Blob).Value = request.AccountScope.ToArray();
        insert.Parameters.Add("$parent", SqliteType.Blob).Value = request.ParentOperationId.ToArray();
        insert.Parameters.AddWithValue("$ordinal", ordinal);
        insert.Parameters.Add("$operation", SqliteType.Blob).Value = target.Binding.OperationId.ToArray();
        insert.Parameters.Add("$scope", SqliteType.Blob).Value = target.Selector.ScopeId.ToArray();
        insert.Parameters.Add("$digest", SqliteType.Blob).Value = target.Binding.RequestDigest.ToArray();
        insert.Parameters.Add("$counter", SqliteType.Blob).Value = U64Current(counter);
        insert.ExecuteNonQuery();
    }

    private static bool HasCurrentOutboxCapacity(
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
        command.Parameters.Add("$scope", SqliteType.Blob).Value = accountScope.ToArray();
        using var reader = command.ExecuteReader();
        _ = reader.Read();
        return reader.GetInt64(0) < 4096 &&
            reader.GetInt64(1) <= 256L * 1024 * 1024 - additionalBytes;
    }

    private static bool ValidateSemanticBatchOwnershipCurrent(
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
            semantic.Parameters.Add("$account", SqliteType.Blob).Value = accountScope.ToArray();
            semantic.Parameters.Add("$semantic", SqliteType.Blob).Value = semanticOperationId.ToArray();
            var ownedParent = semantic.ExecuteScalar() as byte[];
            if (ownedParent is not null)
            {
                if (!FixedCurrent(ownedParent, parentOperationId))
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
        if (ownedSemantic is not null &&
            !FixedCurrent(ownedSemantic, semanticOperationId))
            throw new InvalidOperationException(
                "Mailbox logical fan-out belongs to another semantic operation.");
        return ownedSemantic is not null;
    }

    private static ScopedMailboxPreparedBatch? ReadPreparedBatchCurrent(
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
        read.Parameters.Add("$account", SqliteType.Blob).Value = request.AccountScope.ToArray();
        read.Parameters.Add("$parent", SqliteType.Blob).Value = request.ParentOperationId.ToArray();
        using var reader = read.ExecuteReader();
        if (!reader.Read()) return null;
        if (!FixedCurrent((byte[])reader.GetValue(0), request.SemanticOperationId.Span) ||
            !FixedCurrent((byte[])reader.GetValue(1), planDigest) ||
            reader.GetInt32(2) != request.Selectors.Count)
            throw new InvalidOperationException(
                "Mailbox batch operation conflicts with durable preparation.");
        reader.Dispose();

        var catalog = new List<(int Ordinal, byte[] OperationId, byte[] ScopeId,
            byte[] RequestDigest, ulong Counter)>(request.Selectors.Count);
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
            targets.Parameters.Add("$account", SqliteType.Blob).Value = request.AccountScope.ToArray();
            targets.Parameters.Add("$parent", SqliteType.Blob).Value = request.ParentOperationId.ToArray();
            using var targetReader = targets.ExecuteReader();
            while (targetReader.Read())
                catalog.Add((
                    targetReader.GetInt32(0),
                    (byte[])targetReader.GetValue(1),
                    (byte[])targetReader.GetValue(2),
                    (byte[])targetReader.GetValue(3),
                    ReadU64Current((byte[])targetReader.GetValue(4))));
        }
        if (catalog.Count != request.Selectors.Count)
            throw new InvalidDataException(
                "Mailbox prepared batch target catalog is incomplete.");
        var frames = new List<MailboxAuthenticatedRequestFrame>(catalog.Count);
        for (var ordinal = 0; ordinal < catalog.Count; ordinal++)
        {
            var target = request.Selectors[ordinal];
            var persisted = catalog[ordinal];
            if (persisted.Ordinal != ordinal || persisted.Counter == 0 ||
                !FixedCurrent(persisted.ScopeId, target.Selector.ScopeId.Span))
                throw new InvalidDataException(
                    "Mailbox prepared batch target catalog is corrupt.");
            var stored = ReadTransportOutboxItem(
                connection, transaction, request.AccountScope.Value,
                persisted.OperationId) ?? throw new InvalidDataException(
                    "Mailbox prepared batch lost an outbox target.");
            var canonical = stored.CiphertextBundle;
            var decoded = MailboxAuthenticatedClientRequestCodec.Decode(canonical);
            if (decoded.Binding.Operation != target.Operation ||
                decoded.Presentation.Operation != target.Operation ||
                decoded.Presentation.ReplayCounter != persisted.Counter ||
                !FixedCurrent(decoded.Binding.OperationId.Span, persisted.OperationId) ||
                !FixedCurrent(decoded.Binding.RequestDigest.Span, persisted.RequestDigest) ||
                !FixedCurrent(decoded.Presentation.OperationId.Span, persisted.OperationId) ||
                !FixedCurrent(decoded.Presentation.RequestDigest.Span, persisted.RequestDigest))
                throw new InvalidDataException(
                    "Mailbox prepared batch target is corrupt.");
            frames.Add(new MailboxAuthenticatedRequestFrame(
                decoded.Binding.Operation, canonical));
        }
        return new ScopedMailboxPreparedBatch(request.ParentOperationId, frames);
    }

    private static bool NonzeroCurrent(ReadOnlySpan<byte> value, int length) =>
        value.Length == length && value.IndexOfAnyExcept((byte)0) >= 0;

    private static bool FixedCurrent(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static byte[] U64Current(ulong value)
    {
        var encoded = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        return encoded;
    }

    private static ulong ReadU64Current(ReadOnlySpan<byte> value)
    {
        if (value.Length != 8)
            throw new InvalidDataException("Mailbox UInt64 state is invalid.");
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(value);
    }
}
#endif
