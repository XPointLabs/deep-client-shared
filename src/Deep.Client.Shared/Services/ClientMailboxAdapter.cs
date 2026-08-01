using System.Security.Cryptography;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

public interface IClientMailboxBinaryIngress
{
    Task<ReadOnlyMemory<byte>> StoreAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default);

    Task<ReadOnlyMemory<byte>> RetrieveAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default);

    Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default);
}

public sealed class ClientMailboxPinnedRoute
{
    private readonly byte[] membershipCommitment;
    private readonly byte[] firstReplicaId;
    private readonly byte[] firstReplicaKey;
    private readonly byte[] secondReplicaId;
    private readonly byte[] secondReplicaKey;

    public ClientMailboxPinnedRoute(
        BlindedPlacementId placementId,
        ReadOnlySpan<byte> membershipCommitment,
        ReadOnlySpan<byte> firstReplicaId,
        ReadOnlySpan<byte> firstReplicaKey,
        ReadOnlySpan<byte> secondReplicaId,
        ReadOnlySpan<byte> secondReplicaKey)
    {
        ArgumentNullException.ThrowIfNull(placementId);
        ValidateNonzero(membershipCommitment, 32, nameof(membershipCommitment));
        ValidateNonzero(firstReplicaId, 32, nameof(firstReplicaId));
        ValidateNonzero(firstReplicaKey, 32, nameof(firstReplicaKey));
        ValidateNonzero(secondReplicaId, 32, nameof(secondReplicaId));
        ValidateNonzero(secondReplicaKey, 32, nameof(secondReplicaKey));
        if (CryptographicOperations.FixedTimeEquals(firstReplicaId, secondReplicaId))
        {
            throw new ArgumentException("Pinned mailbox replicas must be distinct.");
        }
        if (CryptographicOperations.FixedTimeEquals(firstReplicaKey, secondReplicaKey))
        {
            throw new ArgumentException(
                "Pinned mailbox replica signing keys must be distinct.");
        }

        PlacementId = placementId;
        this.membershipCommitment = membershipCommitment.ToArray();
        this.firstReplicaId = firstReplicaId.ToArray();
        this.firstReplicaKey = firstReplicaKey.ToArray();
        this.secondReplicaId = secondReplicaId.ToArray();
        this.secondReplicaKey = secondReplicaKey.ToArray();
    }

    public BlindedPlacementId PlacementId { get; }
    public byte[] GetMembershipCommitmentCopy() => membershipCommitment.ToArray();
    public byte[] GetPlacementCommitmentCopy() =>
        MailboxPlacementCommitment.Compute(PlacementId);

    internal ReadOnlySpan<byte> MembershipCommitment => membershipCommitment;

    internal bool TryGetKey(
        ReadOnlySpan<byte> replicaId,
        out ReadOnlyMemory<byte> key)
    {
        if (CryptographicOperations.FixedTimeEquals(replicaId, firstReplicaId))
        {
            key = firstReplicaKey;
            return true;
        }

        if (CryptographicOperations.FixedTimeEquals(replicaId, secondReplicaId))
        {
            key = secondReplicaKey;
            return true;
        }

        key = default;
        return false;
    }

    internal bool IsExactReplicaPair(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        TryGetKey(left, out _) &&
        TryGetKey(right, out _) &&
        !CryptographicOperations.FixedTimeEquals(left, right);

    private static void ValidateNonzero(
        ReadOnlySpan<byte> value,
        int length,
        string parameter)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("Pinned mailbox route material is invalid.", parameter);
        }
    }
}

public sealed class ClientMailboxActivation
{
    private readonly byte[] issuerContext;

    public ClientMailboxActivation(
        bool enabled,
        ReadOnlySpan<byte> issuerContext,
        bool ingressConfigured)
    {
        Enabled = enabled;
        this.issuerContext = issuerContext.ToArray();
        IngressConfigured = ingressConfigured;
    }

    public bool Enabled { get; }
    public bool IngressConfigured { get; }
    public bool HasIssuerContext =>
        issuerContext.Length == 32 &&
        issuerContext.AsSpan().IndexOfAnyExcept((byte)0) >= 0;

    internal ClientMailboxScope ScopeFor(BlindedMailboxId mailboxId, ulong epoch) =>
        ClientMailboxScope.Derive(issuerContext, mailboxId, epoch);

    internal ClientMailboxJournalScope JournalScope =>
        ClientMailboxJournalScope.Derive(issuerContext);

    internal ReadOnlyMemory<byte> IssuerContext => issuerContext.ToArray();

    public override string ToString() =>
        $"ClientMailboxActivation {{ Enabled = {Enabled}, " +
        $"IssuerContext = {(HasIssuerContext ? "[configured]" : "[missing]")}, " +
        $"Ingress = {(IngressConfigured ? "[configured]" : "[missing]")} }}";
}

public sealed record ClientMailboxStoreResult(
    ulong? Cursor,
    MailboxReplicaDisposition? Disposition);

public sealed record ClientMailboxRetrieveResult(
    ulong AfterCursor,
    bool HasMore,
    ReadOnlyMemory<byte> ContinuationToken,
    IReadOnlyList<MailboxRetrievedEnvelope> NewItems);

public sealed record ClientMailboxAckResult(
    bool Idempotent,
    int DurableTombstones);

public sealed class ClientMailboxRetryLeaseException : IOException
{
    public ClientMailboxRetryLeaseException(DateTimeOffset retryNotBefore)
        : base("Mailbox operation is already leased for an in-flight or outcome-unknown attempt.")
    {
        RetryNotBefore = retryNotBefore;
    }

    public DateTimeOffset RetryNotBefore { get; }
}

public sealed class ClientMailboxReceiptExpectation
{
    public required ulong Epoch { get; init; }
    public required ReadOnlyMemory<byte> OperationId { get; init; }
    public required BlindedMailboxId MailboxId { get; init; }
    public required ClientMailboxPinnedRoute Route { get; init; }
    public required ReadOnlyMemory<byte> EnvelopeDigest { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required IReadOnlySet<MailboxReplicaDisposition> AllowedDispositions { get; init; }
    public ulong? Cursor { get; init; }
}

public interface IClientMailboxReceiptVerifier
{
    MailboxReplicaReceiptV2 VerifyAccepted(
        ReadOnlySpan<byte> encodedMrr2,
        ClientMailboxReceiptExpectation expectation);

    VerifiedMailboxDurableQuorumV3 VerifyDurable(
        ReadOnlySpan<byte> encodedMqr3,
        ClientMailboxReceiptExpectation expectation);
}

public sealed class PinnedClientMailboxReceiptVerifier(
    IMailboxPeerReplicationCrypto crypto) : IClientMailboxReceiptVerifier
{
    public MailboxReplicaReceiptV2 VerifyAccepted(
        ReadOnlySpan<byte> encodedMrr2,
        ClientMailboxReceiptExpectation expectation)
    {
        ArgumentNullException.ThrowIfNull(expectation);
        var receipt = MailboxReceiptV2Codec.DecodeReplica(encodedMrr2);
        VerifyReplica(receipt, expectation, MailboxReceiptStatus.Accepted);
        return receipt;
    }

    public VerifiedMailboxDurableQuorumV3 VerifyDurable(
        ReadOnlySpan<byte> encodedMqr3,
        ClientMailboxReceiptExpectation expectation)
    {
        ArgumentNullException.ThrowIfNull(expectation);
        var receipt = MailboxReceiptV3Codec.DecodeDurableQuorum(encodedMqr3);
        if (!expectation.Route.IsExactReplicaPair(
                receipt.FirstReplica.ReplicaId.Span,
                receipt.SecondReplica.ReplicaId.Span))
        {
            throw InvalidReceipt(
                "MQR3 does not contain the exact two pinned placement replicas.");
        }

        VerifyReplica(receipt.FirstReplica, expectation, MailboxReceiptStatus.Durable);
        VerifyReplica(receipt.SecondReplica, expectation, MailboxReceiptStatus.Durable);
        if (!SameStatement(receipt.FirstReplica, receipt.SecondReplica))
        {
            throw InvalidReceipt("MQR3 replica statements equivocate.");
        }

        if (!expectation.Route.TryGetKey(receipt.CoordinatorId.Span, out var coordinatorKey) ||
            !crypto.Verify(
                coordinatorKey.Span,
                MailboxReceiptV3Codec.GetQuorumSigningBytes(receipt),
                receipt.Signature.Span))
        {
            throw InvalidReceipt("MQR3 coordinator signature is invalid.");
        }

        return new VerifiedMailboxDurableQuorumV3(
            receipt.FirstReplica.Cursor,
            receipt.FirstReplica.Disposition,
            [receipt.FirstReplica, receipt.SecondReplica],
            receipt);
    }

    private void VerifyReplica(
        MailboxReplicaReceiptV2 receipt,
        ClientMailboxReceiptExpectation expectation,
        MailboxReceiptStatus expectedStatus)
    {
        var placementCommitment = expectation.Route.GetPlacementCommitmentCopy();
        if (!expectation.Route.TryGetKey(receipt.ReplicaId.Span, out var key) ||
            receipt.Status != expectedStatus ||
            !expectation.AllowedDispositions.Contains(receipt.Disposition) ||
            receipt.Epoch != expectation.Epoch ||
            (expectation.Cursor is { } cursor && receipt.Cursor != cursor) ||
            receipt.ExpiresAtUnixSeconds != expectation.ExpiresAtUnixSeconds ||
            !FixedEquals(receipt.OperationId.Span, expectation.OperationId.Span) ||
            !FixedEquals(receipt.BlindedMailboxId.Span, expectation.MailboxId.Bytes.Span) ||
            !FixedEquals(receipt.PlacementCommitment.Span, placementCommitment) ||
            !FixedEquals(
                receipt.MembershipCommitment.Span,
                expectation.Route.MembershipCommitment) ||
            !FixedEquals(receipt.EnvelopeDigest.Span, expectation.EnvelopeDigest.Span) ||
            !crypto.Verify(
                key.Span,
                MailboxReceiptV2Codec.GetReplicaSigningBytes(receipt),
                receipt.Signature.Span))
        {
            throw InvalidReceipt("MRR2 does not match the pinned mailbox operation.");
        }
    }

    private static bool SameStatement(
        MailboxReplicaReceiptV2 left,
        MailboxReplicaReceiptV2 right) =>
        left.Status == right.Status &&
        left.Disposition == right.Disposition &&
        left.Epoch == right.Epoch &&
        left.Cursor == right.Cursor &&
        left.ExpiresAtUnixSeconds == right.ExpiresAtUnixSeconds &&
        FixedEquals(left.OperationId.Span, right.OperationId.Span) &&
        FixedEquals(left.BlindedMailboxId.Span, right.BlindedMailboxId.Span) &&
        FixedEquals(left.PlacementCommitment.Span, right.PlacementCommitment.Span) &&
        FixedEquals(left.MembershipCommitment.Span, right.MembershipCommitment.Span) &&
        FixedEquals(left.EnvelopeDigest.Span, right.EnvelopeDigest.Span);

    private static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static MailboxReceiptException InvalidReceipt(string message) =>
        new(MailboxReceiptError.UnexpectedStatement, message);
}

public sealed class ClientMailboxAdapter
{
    private static readonly IReadOnlySet<MailboxReplicaDisposition> StoreDispositions =
        new HashSet<MailboxReplicaDisposition>
        {
            MailboxReplicaDisposition.Stored,
            MailboxReplicaDisposition.Duplicate
        };
    private static readonly IReadOnlySet<MailboxReplicaDisposition> TombstoneDisposition =
        new HashSet<MailboxReplicaDisposition>
        {
            MailboxReplicaDisposition.Tombstone
        };

    private readonly ClientMailboxActivation activation;
    private readonly IClientMailboxBinaryIngress ingress;
    private readonly ITransportOutboxRepository outbox;
    private readonly IClientMailboxStateRepository state;
    private readonly IClientMailboxReceiptVerifier receipts;
    private readonly MailboxAuthenticatedRequestFactory requests;
    private readonly IMailboxClientDecodePolicyProvider decodePolicies;
    private readonly TimeProvider timeProvider;

    internal ClientMailboxAdapter(
        ClientFeatureFlags flags,
        ClientMailboxActivation activation,
        IClientMailboxBinaryIngress ingress,
        SqliteSessionStore localStore,
        IClientMailboxReceiptVerifier receipts,
        MailboxAuthenticatedRequestFactory requests,
        IMailboxClientDecodePolicyProvider decodePolicies,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(flags);
        this.activation = activation ?? throw new ArgumentNullException(nameof(activation));
        this.ingress = ingress ?? throw new ArgumentNullException(nameof(ingress));
        ArgumentNullException.ThrowIfNull(localStore);
        this.outbox = localStore;
        this.state = localStore;
        this.receipts = receipts ?? throw new ArgumentNullException(nameof(receipts));
        this.requests = requests ?? throw new ArgumentNullException(nameof(requests));
        this.decodePolicies = decodePolicies ?? throw new ArgumentNullException(nameof(decodePolicies));
        this.timeProvider = timeProvider ?? TimeProvider.System;
        if (!flags.ClientMailboxAdapterEnabled ||
            !activation.Enabled ||
            !activation.HasIssuerContext ||
            !activation.IngressConfigured)
        {
            throw new InvalidOperationException(
                "Client mailbox adapter requires its disabled-by-default flag, issuer, placement and ingress.");
        }
        if (!requests.Uses(localStore))
        {
            throw new InvalidOperationException(
                "Native mailbox preparation must share the SQLite local-state transaction.");
        }
    }

    public async Task<ClientMailboxStoreResult> StoreAsync(
        OutboxAccountScope outboxScope,
        IMailboxOperationSigner signer,
        MailboxCredentialSelector selector,
        MailboxEncryptedEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outboxScope);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(envelope);
        var logicalId = OutboxLogicalId.FromBytes(envelope.OperationId.Span);
        await using var operationLease =
            await ClientMailboxOperationSingleFlight.EnterAsync(
                outboxScope,
                logicalId,
                cancellationToken).ConfigureAwait(false);
        var prepared = await PrepareOrResumeAsync(
            outboxScope,
            MailboxAuthenticatedOperation.Store,
            () => requests.CreateStoreAsync(
                outboxScope,
                selector,
                signer,
                envelope,
                cancellationToken),
            cancellationToken).ConfigureAwait(false);
        EnsureSignerMatches(prepared, signer);
        return await DispatchStoreAsync(
            outboxScope,
            selector,
            prepared,
            cancellationToken).ConfigureAwait(false);
    }

    internal async Task<ClientMailboxStoreResult> DispatchPreparedStoreAsync(
        OutboxAccountScope outboxScope,
        MailboxCredentialSelector selector,
        MailboxAuthenticatedRequestFrame prepared,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outboxScope);
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(prepared);
        return await DispatchStoreAsync(
            outboxScope, selector, prepared, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ClientMailboxRetrieveResult> RetrieveAsync(
        OutboxAccountScope outboxScope,
        IMailboxOperationSigner signer,
        MailboxCredentialSelector selector,
        ReadOnlyMemory<byte> operationId,
        ushort maximumItems,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outboxScope);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(selector);
        var logicalId = OutboxLogicalId.FromBytes(operationId.Span);
        await using var operationLease =
            await ClientMailboxOperationSingleFlight.EnterAsync(
                outboxScope,
                logicalId,
                cancellationToken).ConfigureAwait(false);
        var route = await requests.ReadRouteAsync(selector, cancellationToken)
            .ConfigureAwait(false);
        var scope = activation.ScopeFor(route.MailboxId, route.Epoch);
        await ReconcileExpiredAsync(scope, cancellationToken).ConfigureAwait(false);
        var traversal = await state.ReadTraversalAsync(scope, cancellationToken)
            .ConfigureAwait(false);
        var prepared = await PrepareOrResumeAsync(
            outboxScope,
            MailboxAuthenticatedOperation.Retrieve,
            () => requests.CreateRetrieveAsync(
                outboxScope,
                selector,
                signer,
                operationId,
                traversal.AfterCursor,
                maximumItems,
                traversal.ContinuationToken.ToArray(),
                cancellationToken),
            cancellationToken).ConfigureAwait(false);
        EnsureSignerMatches(prepared, signer);
        return await DispatchRetrieveAsync(
            outboxScope,
            selector,
            prepared,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<ClientMailboxAckResult> AcknowledgeAsync(
        OutboxAccountScope outboxScope,
        IMailboxOperationSigner signer,
        MailboxCredentialSelector selector,
        ReadOnlyMemory<byte> operationId,
        bool isFinalPage,
        ReadOnlyMemory<byte> continuationToken,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outboxScope);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(acknowledgements);
        var logicalId = OutboxLogicalId.FromBytes(operationId.Span);
        await using var operationLease =
            await ClientMailboxOperationSingleFlight.EnterAsync(
                outboxScope,
                logicalId,
                cancellationToken).ConfigureAwait(false);
        var prepared = await PrepareOrResumeAsync(
            outboxScope,
            MailboxAuthenticatedOperation.Ack,
            () => requests.CreateAckAsync(
                outboxScope,
                selector,
                signer,
                operationId,
                isFinalPage,
                continuationToken,
                acknowledgements,
                cancellationToken),
            cancellationToken).ConfigureAwait(false);
        EnsureSignerMatches(prepared, signer);
        return await DispatchAcknowledgeAsync(
            outboxScope,
            selector,
            prepared,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<ClientMailboxStoreResult> DispatchStoreAsync(
        OutboxAccountScope outboxScope,
        MailboxCredentialSelector selector,
        MailboxAuthenticatedRequestFrame authenticatedRequest,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outboxScope);
        ArgumentNullException.ThrowIfNull(authenticatedRequest);
        var encoded = authenticatedRequest.GetCanonicalMau2Copy();
        var request = DecodeRequest(
            authenticatedRequest,
            MailboxAuthenticatedOperation.Store);
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(
            request.Binding.CanonicalRequest.Span);
        var logicalId = OutboxLogicalId.FromBytes(
            request.Binding.OperationId.Span);
        var dedup = OutboxDedupMaterial.FromBytes(
            request.Binding.RequestDigest.Span);
        var snapshot = await ReadExactOutboxAsync(
            outboxScope,
            logicalId,
            dedup,
            encoded,
            cancellationToken).ConfigureAwait(false);
        if (snapshot.State == TransportOutboxState.Accepted)
        {
            await using var recoveredPolicyLease =
                await requests.AcquireDispatchPolicyAsync(cancellationToken)
                    .ConfigureAwait(false);
            requests.ReloadCommittedPolicy();
            var recoveredRoute = await ResolveDispatchRouteAsync(
                selector, envelope.Epoch, envelope.MailboxId, envelope.PlacementId,
                MailboxAuthenticatedOperation.Store,
                cancellationToken).ConfigureAwait(false);
            var accepted = snapshot.Attempts.Single(
                static attempt =>
                    attempt.State == TransportOutboxAttemptState.Accepted);
            var evidence = accepted.GetEvidenceCopy();
            var persistedDurable = await VerifyAndJournalDurableAsync(
                evidence,
                StoreExpectation(envelope, recoveredRoute),
                cancellationToken).ConfigureAwait(false);
            await PromoteAcceptedAsync(
                outboxScope,
                logicalId,
                snapshot,
                accepted,
                evidence,
                cancellationToken).ConfigureAwait(false);
            return new ClientMailboxStoreResult(
                persistedDurable.Cursor,
                persistedDurable.Disposition);
        }
        if (snapshot.State == TransportOutboxState.Durable)
        {
            await using var recoveredPolicyLease =
                await requests.AcquireDispatchPolicyAsync(cancellationToken)
                    .ConfigureAwait(false);
            requests.ReloadCommittedPolicy();
            var recoveredRoute = await ResolveDispatchRouteAsync(
                selector, envelope.Epoch, envelope.MailboxId, envelope.PlacementId,
                MailboxAuthenticatedOperation.Store,
                cancellationToken).ConfigureAwait(false);
            var evidence = snapshot.Attempts
                .Single(static attempt =>
                    attempt.State == TransportOutboxAttemptState.Durable)
                .GetEvidenceCopy();
            var persistedDurable = await VerifyAndJournalDurableAsync(
                evidence,
                StoreExpectation(envelope, recoveredRoute),
                cancellationToken).ConfigureAwait(false);
            return new ClientMailboxStoreResult(
                persistedDurable.Cursor,
                persistedDurable.Disposition);
        }

        await using var policyLease =
            await requests.AcquireDispatchPolicyAsync(cancellationToken)
                .ConfigureAwait(false);
        requests.ReloadCommittedPolicy();
        var route = await ResolveDispatchRouteAsync(
            selector, envelope.Epoch, envelope.MailboxId, envelope.PlacementId,
            MailboxAuthenticatedOperation.Store,
            cancellationToken).ConfigureAwait(false);
        var attempt = await BeginAttemptAsync(
            outboxScope,
            logicalId,
            snapshot,
            MailboxAuthenticatedOperation.Store,
            cancellationToken).ConfigureAwait(false);

        var response = await ingress.StoreAsync(encoded, cancellationToken)
            .ConfigureAwait(false);
        // Once ingress returned, caller cancellation must not skip the committed-policy
        // fence or the exact route/grant revalidation for the received response.
        requests.ReloadCommittedPolicy();
        route = await ResolveDispatchRouteAsync(
            selector, envelope.Epoch, envelope.MailboxId, envelope.PlacementId,
            MailboxAuthenticatedOperation.Store,
            CancellationToken.None).ConfigureAwait(false);
        var expectation = StoreExpectation(envelope, route);
        var durable = await VerifyAndJournalDurableAsync(
            response,
            expectation,
            cancellationToken).ConfigureAwait(false);
        snapshot = await ReadFoundAsync(outboxScope, logicalId, cancellationToken)
            .ConfigureAwait(false);
        var outcomeAt = timeProvider.GetUtcNow();
        await ApplyAsync(
            TransportOutboxTransition.Accepted(
                outboxScope,
                logicalId,
                snapshot.Revision,
                attempt,
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.AdapterAccepted,
                outcomeAt,
                RetryAt(
                    outcomeAt,
                    snapshot.ExpiresAt,
                    MailboxAuthenticatedOperation.Store),
                response.Span),
            cancellationToken).ConfigureAwait(false);
        snapshot = await ReadFoundAsync(outboxScope, logicalId, cancellationToken)
            .ConfigureAwait(false);
        await ApplyAsync(
            TransportOutboxTransition.Durable(
                outboxScope,
                logicalId,
                snapshot.Revision,
                attempt,
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.AdapterConfirmedDurable,
                outcomeAt,
                response.Span),
            cancellationToken).ConfigureAwait(false);
        return new ClientMailboxStoreResult(
            durable.Cursor,
            durable.Disposition);
    }

    public async Task<ClientMailboxTraversal> ReadTraversalAsync(
        MailboxCredentialSelector selector,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selector);
        var route = await requests.ReadRouteAsync(selector, cancellationToken)
            .ConfigureAwait(false);
        var scope = activation.ScopeFor(route.MailboxId, route.Epoch);
        await ReconcileExpiredAsync(scope, cancellationToken).ConfigureAwait(false);
        return await state.ReadTraversalAsync(scope, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<MailboxRetrievedEnvelope>> ReadDurableInboxAsync(
        MailboxCredentialSelector selector,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selector);
        var route = await requests.ReadRouteAsync(selector, cancellationToken)
            .ConfigureAwait(false);
        var scope = activation.ScopeFor(route.MailboxId, route.Epoch);
        await ReconcileExpiredAsync(scope, cancellationToken).ConfigureAwait(false);
        return await state.ReadDurableInboxAsync(scope, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<ClientMailboxRetrieveResult> DispatchRetrieveAsync(
        OutboxAccountScope outboxScope,
        MailboxCredentialSelector selector,
        MailboxAuthenticatedRequestFrame authenticatedRequest,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticatedRequest);
        var canonicalMau2 = authenticatedRequest.GetCanonicalMau2Copy();
        var authenticated = DecodeRequest(
            authenticatedRequest,
            MailboxAuthenticatedOperation.Retrieve);
        var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
            authenticated.Binding.CanonicalRequest.Span);
        var logicalId = OutboxLogicalId.FromBytes(request.OperationId.Span);
        var dedup = OutboxDedupMaterial.FromBytes(
            authenticated.Binding.RequestDigest.Span);
        var outboxSnapshot = await ReadExactOutboxAsync(
            outboxScope,
            logicalId,
            dedup,
            canonicalMau2,
            cancellationToken).ConfigureAwait(false);
        var scope = activation.ScopeFor(request.MailboxId, request.Epoch);
        await ReconcileExpiredAsync(scope, cancellationToken).ConfigureAwait(false);
        if (outboxSnapshot.State is
            TransportOutboxState.Accepted or
            TransportOutboxState.Durable)
        {
            await using var recoveredPolicyLease =
                await requests.AcquireDispatchPolicyAsync(cancellationToken)
                    .ConfigureAwait(false);
            requests.ReloadCommittedPolicy();
            _ = await ResolveDispatchRouteAsync(
                selector, request.Epoch, request.MailboxId, request.PlacementId,
                MailboxAuthenticatedOperation.Retrieve,
                cancellationToken).ConfigureAwait(false);
            var completedAttempt = outboxSnapshot.Attempts.Single(
                attempt => attempt.State ==
                    (outboxSnapshot.State == TransportOutboxState.Accepted
                        ? TransportOutboxAttemptState.Accepted
                        : TransportOutboxAttemptState.Durable));
            var evidence = completedAttempt.GetEvidenceCopy();
            var summary =
                ClientMailboxRetrieveOutcomeSummary.DecodeAndValidate(
                    evidence,
                    request);
            if (outboxSnapshot.State == TransportOutboxState.Accepted)
            {
                await PromoteAcceptedAsync(
                    outboxScope,
                    logicalId,
                    outboxSnapshot,
                    completedAttempt,
                    evidence,
                    cancellationToken).ConfigureAwait(false);
            }

            return new ClientMailboxRetrieveResult(
                summary.ResultAfterCursor,
                summary.HasMore,
                summary.ContinuationToken,
                []);
        }
        var traversal = await state.ReadTraversalAsync(scope, cancellationToken)
            .ConfigureAwait(false);
        if (outboxSnapshot.State == TransportOutboxState.Prepared &&
            (request.AfterCursor != traversal.AfterCursor ||
             !FixedEquals(
                 request.ContinuationToken.Span,
                 traversal.ContinuationToken)))
        {
            throw new InvalidOperationException(
                "MBR2 cursor/token does not match durable mailbox traversal.");
        }

        await using var policyLease =
            await requests.AcquireDispatchPolicyAsync(cancellationToken)
                .ConfigureAwait(false);
        requests.ReloadCommittedPolicy();
        var route = await ResolveDispatchRouteAsync(
            selector, request.Epoch, request.MailboxId, request.PlacementId,
            MailboxAuthenticatedOperation.Retrieve,
            cancellationToken).ConfigureAwait(false);
        var attempt = await BeginAttemptAsync(
            outboxScope,
            logicalId,
            outboxSnapshot,
            MailboxAuthenticatedOperation.Retrieve,
            cancellationToken).ConfigureAwait(false);
        var response = await ingress.RetrieveAsync(
            canonicalMau2,
            cancellationToken).ConfigureAwait(false);
        requests.ReloadCommittedPolicy();
        route = await ResolveDispatchRouteAsync(
            selector, request.Epoch, request.MailboxId, request.PlacementId,
            MailboxAuthenticatedOperation.Retrieve,
            CancellationToken.None).ConfigureAwait(false);
        var page = MailboxClientCodec.DecodeRetrievePage(
            response.Span, decodePolicies.GetCurrent());
        if (page.Epoch != request.Epoch ||
            !FixedEquals(page.OperationId.Span, request.OperationId.Span) ||
            page.Items.Any(item =>
                !FixedEquals(item.Envelope.MailboxId.Bytes.Span, request.MailboxId.Bytes.Span) ||
                !FixedEquals(item.Envelope.PlacementId.Bytes.Span, request.PlacementId.Bytes.Span)))
        {
            throw new InvalidDataException(
                "MRP1 does not match the exact authenticated MBR2 operation.");
        }

        ClientMailboxReceiveCommitResult committed;
        if (await IsRetrieveOutcomeAlreadyCommittedAsync(
                scope,
                traversal,
                page,
                cancellationToken).ConfigureAwait(false))
        {
            committed = new ClientMailboxReceiveCommitResult(
                traversal,
                page.Items);
        }
        else
        {
            if (request.AfterCursor != traversal.AfterCursor ||
                !FixedEquals(
                    request.ContinuationToken.Span,
                    traversal.ContinuationToken))
            {
                throw new InvalidOperationException(
                    "Persisted MBR2 no longer matches mailbox traversal and its outcome is absent.");
            }

            committed = await state.CommitRetrievePageAsync(
                scope,
                traversal,
                page,
                cancellationToken)
                .ConfigureAwait(false);
        }
        var summaryEvidence = ClientMailboxRetrieveOutcomeSummary.Encode(
            request,
            page,
            response.Span);
        await RecordOutcomeAsync(
            outboxScope,
            logicalId,
            attempt,
            summaryEvidence,
            MailboxAuthenticatedOperation.Retrieve,
            cancellationToken).ConfigureAwait(false);
        return new ClientMailboxRetrieveResult(
            committed.Traversal.AfterCursor,
            page.HasMore,
            committed.Traversal.GetContinuationTokenCopy(),
            committed.DurableInbox);
    }

    private async Task<ClientMailboxAckResult> DispatchAcknowledgeAsync(
        OutboxAccountScope outboxScope,
        MailboxCredentialSelector selector,
        MailboxAuthenticatedRequestFrame authenticatedRequest,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticatedRequest);
        var canonicalMau2 = authenticatedRequest.GetCanonicalMau2Copy();
        var authenticated = DecodeRequest(
            authenticatedRequest,
            MailboxAuthenticatedOperation.Ack);
        var request = MailboxAuthenticatedRequestTranscript.DecodeAckBody(
            authenticated.Binding.CanonicalRequest.Span);
        var logicalId = OutboxLogicalId.FromBytes(request.OperationId.Span);
        var dedup = OutboxDedupMaterial.FromBytes(
            authenticated.Binding.RequestDigest.Span);
        var outboxSnapshot = await ReadExactOutboxAsync(
            outboxScope,
            logicalId,
            dedup,
            canonicalMau2,
            cancellationToken).ConfigureAwait(false);
        var scope = activation.ScopeFor(request.MailboxId, request.Epoch);
        await ReconcileExpiredAsync(scope, cancellationToken).ConfigureAwait(false);
        if (outboxSnapshot.State is
            TransportOutboxState.Accepted or
            TransportOutboxState.Durable)
        {
            await using var recoveredPolicyLease =
                await requests.AcquireDispatchPolicyAsync(cancellationToken)
                    .ConfigureAwait(false);
            requests.ReloadCommittedPolicy();
            _ = await ResolveDispatchRouteAsync(
                selector, request.Epoch, request.MailboxId, request.PlacementId,
                MailboxAuthenticatedOperation.Ack,
                cancellationToken).ConfigureAwait(false);
            if (outboxSnapshot.State == TransportOutboxState.Accepted)
            {
                var accepted = outboxSnapshot.Attempts.Single(
                    static attempt =>
                        attempt.State == TransportOutboxAttemptState.Accepted);
                await PromoteAcceptedAsync(
                    outboxScope,
                    logicalId,
                    outboxSnapshot,
                    accepted,
                    accepted.GetEvidenceCopy(),
                    cancellationToken).ConfigureAwait(false);
            }

            return new ClientMailboxAckResult(
                true,
                request.Acknowledgements.Count);
        }
        var traversal = await state.ReadTraversalAsync(scope, cancellationToken)
            .ConfigureAwait(false);
        var lastAcknowledgement = request.Acknowledgements[^1];
        if (request.IsFinalPage
                ? traversal.AfterCursor != 0 ||
                  !request.ContinuationToken.IsEmpty
                : traversal.AfterCursor != lastAcknowledgement.Cursor ||
                  !FixedEquals(
                      traversal.ContinuationToken,
                      request.ContinuationToken.Span))
        {
            throw new InvalidOperationException(
                "MBA2 does not match the durable page continuation authority.");
        }
        var pending = await state.CheckAcknowledgementsAsync(
            scope,
            request.Acknowledgements,
            cancellationToken).ConfigureAwait(false);
        if (pending is not (
                ClientMailboxAckState.Pending or
                ClientMailboxAckState.AlreadyCommitted))
        {
            throw new InvalidOperationException(
                "MBA2 is not the next ordered persistent acknowledgement prefix.");
        }
        var expectations = await state.ReadAckExpectationsAsync(
            scope,
            request.Acknowledgements,
            cancellationToken).ConfigureAwait(false);
        await using var policyLease =
            await requests.AcquireDispatchPolicyAsync(cancellationToken)
                .ConfigureAwait(false);
        requests.ReloadCommittedPolicy();
        var route = await ResolveDispatchRouteAsync(
            selector, request.Epoch, request.MailboxId, request.PlacementId,
            MailboxAuthenticatedOperation.Ack,
            cancellationToken).ConfigureAwait(false);
        if (pending == ClientMailboxAckState.AlreadyCommitted)
        {
            var localAttempt = await BeginAttemptAsync(
                outboxScope,
                logicalId,
                outboxSnapshot,
                MailboxAuthenticatedOperation.Ack,
                cancellationToken).ConfigureAwait(false);
            var recoveredResponse = await ingress.AcknowledgeAsync(
                canonicalMau2,
                cancellationToken).ConfigureAwait(false);
            requests.ReloadCommittedPolicy();
            route = await ResolveDispatchRouteAsync(
                selector, request.Epoch, request.MailboxId, request.PlacementId,
                MailboxAuthenticatedOperation.Ack,
                CancellationToken.None).ConfigureAwait(false);
            var recoveredAggregate = MailboxAggregateAckCodec.DecodeMqr3(
                recoveredResponse.Span);
            if (recoveredAggregate.Epoch != request.Epoch ||
                !FixedEquals(
                    recoveredAggregate.OperationId.Span,
                    request.OperationId.Span) ||
                recoveredAggregate.TombstoneQuorums.Count !=
                    request.Acknowledgements.Count)
            {
                throw new InvalidDataException(
                    "Recovered MAR1 does not match the exact authenticated MBA2 operation.");
            }
            for (var index = 0;
                 index < request.Acknowledgements.Count;
                 index++)
            {
                var acknowledgement = request.Acknowledgements[index];
                _ = await VerifyAndJournalDurableAsync(
                    recoveredAggregate.TombstoneQuorums[index],
                    new ClientMailboxReceiptExpectation
                    {
                        Epoch = request.Epoch,
                        OperationId = request.OperationId.ToArray(),
                        MailboxId = request.MailboxId,
                        Route = route,
                        EnvelopeDigest =
                            acknowledgement.EnvelopeDigest.ToArray(),
                        ExpiresAtUnixSeconds =
                            expectations[index].ExpiresAtUnixSeconds,
                        AllowedDispositions = TombstoneDisposition,
                        Cursor = acknowledgement.Cursor
                    },
                    cancellationToken).ConfigureAwait(false);
            }
            await RecordOutcomeAsync(
                outboxScope,
                logicalId,
                localAttempt,
                CanonicalOutcomeEvidence(recoveredResponse.Span),
                MailboxAuthenticatedOperation.Ack,
                cancellationToken).ConfigureAwait(false);
            return new ClientMailboxAckResult(true, request.Acknowledgements.Count);
        }

        var attempt = await BeginAttemptAsync(
            outboxScope,
            logicalId,
            outboxSnapshot,
            MailboxAuthenticatedOperation.Ack,
            cancellationToken).ConfigureAwait(false);
        var response = await ingress.AcknowledgeAsync(
            canonicalMau2,
            cancellationToken).ConfigureAwait(false);
        requests.ReloadCommittedPolicy();
        route = await ResolveDispatchRouteAsync(
            selector, request.Epoch, request.MailboxId, request.PlacementId,
            MailboxAuthenticatedOperation.Ack,
            CancellationToken.None).ConfigureAwait(false);
        var aggregate = MailboxAggregateAckCodec.DecodeMqr3(response.Span);
        if (aggregate.Epoch != request.Epoch ||
            !FixedEquals(aggregate.OperationId.Span, request.OperationId.Span) ||
            aggregate.TombstoneQuorums.Count != request.Acknowledgements.Count)
        {
            throw new InvalidDataException("MAR1 does not match the exact authenticated MBA2 operation.");
        }

        for (var index = 0; index < request.Acknowledgements.Count; index++)
        {
            var acknowledgement = request.Acknowledgements[index];
            _ = await VerifyAndJournalDurableAsync(
                aggregate.TombstoneQuorums[index],
                new ClientMailboxReceiptExpectation
                {
                    Epoch = request.Epoch,
                    OperationId = request.OperationId.ToArray(),
                    MailboxId = request.MailboxId,
                    Route = route,
                    EnvelopeDigest = acknowledgement.EnvelopeDigest.ToArray(),
                    ExpiresAtUnixSeconds =
                        expectations[index].ExpiresAtUnixSeconds,
                    AllowedDispositions = TombstoneDisposition,
                    Cursor = acknowledgement.Cursor
                },
                cancellationToken).ConfigureAwait(false);
        }

        var committed = await state.CommitAcknowledgementsAsync(
            scope,
            request.Acknowledgements,
            cancellationToken).ConfigureAwait(false);
        if (committed is not (
                ClientMailboxAckState.Pending or
                ClientMailboxAckState.AlreadyCommitted))
        {
            throw new IOException("Mailbox acknowledgement state changed concurrently.");
        }
        await RecordOutcomeAsync(
            outboxScope,
            logicalId,
            attempt,
            CanonicalOutcomeEvidence(response.Span),
            MailboxAuthenticatedOperation.Ack,
            cancellationToken).ConfigureAwait(false);

        return new ClientMailboxAckResult(
            committed == ClientMailboxAckState.AlreadyCommitted,
            request.Acknowledgements.Count);
    }

    private ClientMailboxReceiptExpectation StoreExpectation(
        MailboxEncryptedEnvelope envelope,
        ClientMailboxPinnedRoute route) => new()
        {
            Epoch = envelope.Epoch,
            OperationId = envelope.OperationId.ToArray(),
            MailboxId = envelope.MailboxId,
            Route = route,
            EnvelopeDigest = envelope.DeduplicationDigest.ToArray(),
            ExpiresAtUnixSeconds = envelope.ExpiresAtUnixSeconds,
            AllowedDispositions = StoreDispositions
        };

    private async Task<bool> IsRetrieveOutcomeAlreadyCommittedAsync(
        ClientMailboxScope scope,
        ClientMailboxTraversal traversal,
        MailboxRetrievePage page,
        CancellationToken cancellationToken)
    {
        var expectedCursor = page.HasMore ? page.NextCursor : 0UL;
        var expectedToken = page.HasMore
            ? page.ContinuationToken.Span
            : ReadOnlySpan<byte>.Empty;
        if (traversal.AfterCursor != expectedCursor ||
            !FixedEquals(
                traversal.ContinuationToken,
                expectedToken))
        {
            return false;
        }

        if (page.Items.Count == 0)
        {
            return true;
        }

        var durable = await state.ReadDurableInboxAsync(
            scope,
            cancellationToken).ConfigureAwait(false);
        foreach (var item in page.Items)
        {
            var persisted = durable.SingleOrDefault(
                candidate => candidate.Cursor == item.Cursor);
            if (persisted is null ||
                !FixedEquals(
                    MailboxClientCodec.EncodeEncryptedEnvelope(
                        persisted.Envelope),
                    MailboxClientCodec.EncodeEncryptedEnvelope(
                        item.Envelope)))
            {
                return false;
            }
        }

        return true;
    }

    private async Task<VerifiedMailboxDurableQuorumV3>
        VerifyAndJournalDurableAsync(
            ReadOnlyMemory<byte> encodedMqr3,
            ClientMailboxReceiptExpectation expectation,
            CancellationToken cancellationToken)
    {
        var verified = receipts.VerifyDurable(encodedMqr3.Span, expectation);
        var receipt = verified.CoordinatorReceipt;
        var statementDigest = SHA256.HashData(
            MailboxReceiptV3Codec.GetQuorumSigningBytes(receipt));
        var nowUnixSeconds = checked(
            (ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
        var result = await state.RecordCoordinatorStatementAsync(
            activation.JournalScope,
            expectation.Route.GetMembershipCommitmentCopy(),
            expectation.Epoch,
            receipt.CoordinatorId,
            receipt.CoordinatorSequence,
            statementDigest,
            expectation.ExpiresAtUnixSeconds,
            nowUnixSeconds,
            cancellationToken).ConfigureAwait(false);
        if (result == ClientMailboxCoordinatorRecordResult.Equivocation)
        {
            throw new MailboxReceiptException(
                MailboxReceiptError.UnexpectedStatement,
                "MQR3 coordinator sequence equivocation detected.");
        }
        if (result == ClientMailboxCoordinatorRecordResult.CapacityExceeded)
        {
            throw new InvalidOperationException(
                "Mailbox coordinator journal capacity is exhausted.");
        }

        return verified;
    }

    private Task<ClientMailboxExpiryReconciliationResult> ReconcileExpiredAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken) =>
        state.ReconcileExpiredAsync(
            scope,
            checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds()),
            cancellationToken);

    private async Task<ClientMailboxPinnedRoute> ResolveDispatchRouteAsync(
        MailboxCredentialSelector selector,
        ulong epoch,
        BlindedMailboxId mailboxId,
        BlindedPlacementId placementId,
        MailboxAuthenticatedOperation operation,
        CancellationToken cancellationToken)
    {
        var resolved = await requests.RevalidateDispatchAsync(
                selector, operation, cancellationToken)
            .ConfigureAwait(false);
        if (resolved.Epoch != epoch ||
            !FixedEquals(resolved.MailboxId.Bytes.Span, mailboxId.Bytes.Span) ||
            !FixedEquals(resolved.PlacementId.Bytes.Span, placementId.Bytes.Span))
        {
            throw new InvalidOperationException(
                "Mailbox operation no longer matches the selected scoped route.");
        }

        return new ClientMailboxPinnedRoute(
            resolved.PlacementId,
            resolved.MembershipCommitment.Span,
            resolved.Replicas.FirstId.Span,
            resolved.Replicas.FirstSigningKey.Span,
            resolved.Replicas.SecondId.Span,
            resolved.Replicas.SecondSigningKey.Span);
    }

    private async Task<TransportOutboxItemSnapshot> ReadExactOutboxAsync(
        OutboxAccountScope scope,
        OutboxLogicalId logicalId,
        OutboxDedupMaterial dedup,
        ReadOnlyMemory<byte> encoded,
        CancellationToken cancellationToken)
    {
        var snapshot = await ReadFoundAsync(scope, logicalId, cancellationToken)
            .ConfigureAwait(false);
        if (!FixedEquals(snapshot.DedupMaterial.ToArray(), dedup.ToArray()) ||
            !FixedEquals(snapshot.GetCiphertextBundleCopy(), encoded.Span) ||
            snapshot.State is TransportOutboxState.Delivered or
                TransportOutboxState.Expired)
        {
            throw new InvalidOperationException(
                "Mailbox operation id conflicts with persistent outbox state.");
        }
        var successfulAttempts = snapshot.Attempts.Count(
            static attempt =>
                attempt.State is
                    TransportOutboxAttemptState.Accepted or
                    TransportOutboxAttemptState.Durable);
        var expectedSuccessfulAttempts = snapshot.State is
            TransportOutboxState.Accepted or
            TransportOutboxState.Durable
                ? 1
                : 0;
        if (successfulAttempts != expectedSuccessfulAttempts)
        {
            throw new TransportOutboxCorruptException();
        }

        return snapshot;
    }

    private async Task<TransportOutboxItemSnapshot> ReadFoundAsync(
        OutboxAccountScope scope,
        OutboxLogicalId logicalId,
        CancellationToken cancellationToken)
    {
        var read = await outbox.ReadTransportOutboxAsync(
            scope,
            logicalId,
            cancellationToken).ConfigureAwait(false);
        return read is { Result: TransportOutboxReadResult.Found, Item: not null }
            ? read.Item
            : throw new IOException("Mailbox outbox state is missing or corrupt.");
    }

    private async Task ApplyAsync(
        TransportOutboxTransition transition,
        CancellationToken cancellationToken)
    {
        var result = await outbox.ApplyTransportOutboxTransitionAsync(
            transition,
            cancellationToken).ConfigureAwait(false);
        if (result is not (
                TransportOutboxCommitResult.Applied or
                TransportOutboxCommitResult.Idempotent))
        {
            throw new IOException("Mailbox outbox transition was not committed.");
        }
    }

    private async Task<MailboxAuthenticatedRequestFrame> PrepareOrResumeAsync(
        OutboxAccountScope outboxScope,
        MailboxAuthenticatedOperation expectedOperation,
        Func<Task<MailboxAuthenticatedRequestFrame>> create,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(create);
        var frame = await create().ConfigureAwait(false);
        var canonical = frame.GetCanonicalMau2Copy();
        var decoded = DecodeRequest(frame, expectedOperation);
        if (decoded.Binding.Operation != expectedOperation)
        {
            throw new InvalidOperationException(
                "Scoped mailbox preparation returned the wrong operation.");
        }
        return frame;
    }

    private static MailboxAuthenticatedRequestFrame RecoverFrame(
        TransportOutboxItemSnapshot snapshot,
        MailboxAuthenticatedRequestBinding expectedBinding)
    {
        if (snapshot.State is
            TransportOutboxState.Delivered or
            TransportOutboxState.Expired)
        {
            throw new InvalidOperationException(
                "Mailbox operation conflicts with terminal outbox state.");
        }

        var canonical = snapshot.GetCiphertextBundleCopy();
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(canonical);
        EnsureExactBinding(decoded.Binding, expectedBinding);
        return new MailboxAuthenticatedRequestFrame(
            decoded.Binding.Operation,
            canonical);
    }

    private static void EnsureExactBinding(
        MailboxAuthenticatedRequestBinding actual,
        MailboxAuthenticatedRequestBinding expected)
    {
        if (actual.Operation != expected.Operation ||
            !FixedEquals(actual.OperationId.Span, expected.OperationId.Span) ||
            !FixedEquals(actual.RequestDigest.Span, expected.RequestDigest.Span) ||
            !FixedEquals(
                actual.CanonicalRequest.Span,
                expected.CanonicalRequest.Span))
        {
            throw new InvalidOperationException(
                "Mailbox operation id conflicts with the durable MAU2 request.");
        }
    }

    private async Task<OutboxAttemptId> BeginAttemptAsync(
        OutboxAccountScope outboxScope,
        OutboxLogicalId logicalId,
        TransportOutboxItemSnapshot snapshot,
        MailboxAuthenticatedOperation operation,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        if (now < snapshot.NotBefore)
        {
            throw new ClientMailboxRetryLeaseException(snapshot.NotBefore);
        }
        if (now >= snapshot.ExpiresAt)
        {
            throw new InvalidOperationException("Mailbox operation expired.");
        }
        var attempt = CreateAttemptId();
        await ApplyAsync(
            TransportOutboxTransition.Attempted(
                outboxScope,
                logicalId,
                snapshot.Revision,
                attempt,
                OutboxTransitionSource.Adapter,
                snapshot.State == TransportOutboxState.Prepared
                    ? OutboxTransitionReason.DispatchStarted
                    : OutboxTransitionReason.RetryScheduled,
                now,
                RetryAt(now, snapshot.ExpiresAt, operation)),
            cancellationToken).ConfigureAwait(false);
        return attempt;
    }

    private async Task RecordOutcomeAsync(
        OutboxAccountScope outboxScope,
        OutboxLogicalId logicalId,
        OutboxAttemptId attempt,
        ReadOnlyMemory<byte> evidence,
        MailboxAuthenticatedOperation operation,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var snapshot = await ReadFoundAsync(
            outboxScope,
            logicalId,
            cancellationToken).ConfigureAwait(false);
        await ApplyAsync(
            TransportOutboxTransition.Accepted(
                outboxScope,
                logicalId,
                snapshot.Revision,
                attempt,
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.AdapterAccepted,
                now,
                RetryAt(now, snapshot.ExpiresAt, operation),
                evidence.Span),
            cancellationToken).ConfigureAwait(false);
        snapshot = await ReadFoundAsync(
            outboxScope,
            logicalId,
            cancellationToken).ConfigureAwait(false);
        await ApplyAsync(
            TransportOutboxTransition.Durable(
                outboxScope,
                logicalId,
                snapshot.Revision,
                attempt,
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.AdapterConfirmedDurable,
                now,
                evidence.Span),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task PromoteAcceptedAsync(
        OutboxAccountScope outboxScope,
        OutboxLogicalId logicalId,
        TransportOutboxItemSnapshot snapshot,
        TransportOutboxAttemptSnapshot accepted,
        ReadOnlyMemory<byte> evidence,
        CancellationToken cancellationToken)
    {
        await ApplyAsync(
            TransportOutboxTransition.Durable(
                outboxScope,
                logicalId,
                snapshot.Revision,
                accepted.AttemptId,
                OutboxTransitionSource.Recovery,
                OutboxTransitionReason.CrashReconciled,
                timeProvider.GetUtcNow(),
                evidence.Span),
            cancellationToken).ConfigureAwait(false);
    }

    private static byte[] CanonicalOutcomeEvidence(
        ReadOnlySpan<byte> canonicalOutcome)
    {
        if (canonicalOutcome.IsEmpty)
        {
            throw new InvalidDataException(
                "Mailbox canonical outcome is empty.");
        }

        var evidence = new byte[40];
        "MCO1"u8.CopyTo(evidence);
        SHA256.HashData(canonicalOutcome).CopyTo(evidence, 8);
        return evidence;
    }

    private static OutboxAttemptId CreateAttemptId()
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var bytes = RandomNumberGenerator.GetBytes(
                TransportOutboxLimits.AttemptIdBytes);
            if (bytes.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
            {
                return OutboxAttemptId.FromBytes(bytes);
            }
        }

        throw new CryptographicException("Mailbox attempt id generation failed.");
    }

    private static DateTimeOffset RetryAt(
        DateTimeOffset now,
        DateTimeOffset expiresAt,
        MailboxAuthenticatedOperation operation)
    {
        var contract = operation switch
        {
            MailboxAuthenticatedOperation.Store =>
                MailboxWireHttpContract.Store,
            MailboxAuthenticatedOperation.Retrieve =>
                MailboxWireHttpContract.Retrieve,
            MailboxAuthenticatedOperation.Ack =>
                MailboxWireHttpContract.Acknowledge,
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
        var candidate = now.AddSeconds(
            checked(contract.RequestTimeoutSeconds + 5));
        if (candidate >= expiresAt)
        {
            throw new InvalidOperationException(
                "Mailbox operation has no valid retry window.");
        }

        return candidate;
    }

    private static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static MailboxAuthenticatedClientRequest DecodeRequest(
        MailboxAuthenticatedRequestFrame frame,
        MailboxAuthenticatedOperation expectedOperation)
    {
        if (frame.Operation != expectedOperation)
        {
            throw new ArgumentException(
                "Authenticated mailbox request operation does not match the adapter entry point.",
                nameof(frame));
        }

        var canonical = frame.GetCanonicalMau2Copy();
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(canonical);
        if (decoded.Binding.Operation != expectedOperation ||
            decoded.Presentation.Operation != expectedOperation)
        {
            throw new InvalidDataException(
                "MAU2 operation does not match the adapter entry point.");
        }

        return decoded;
    }

    private static void EnsureSignerMatches(
        MailboxAuthenticatedRequestFrame frame,
        IMailboxOperationSigner signer)
    {
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(
            frame.GetCanonicalMau2Copy());
        var publicKey = signer.GetEd25519PublicKey();
        try
        {
            if (!FixedEquals(
                    publicKey,
                    decoded.Presentation.Grant.HolderPublicKey.Span))
            {
                throw new InvalidOperationException(
                    "Mailbox recovery signer does not match the persisted MAU2 holder.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }
}
