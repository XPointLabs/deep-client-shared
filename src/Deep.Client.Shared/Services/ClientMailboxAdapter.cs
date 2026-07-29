using System.Security.Cryptography;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

public enum ClientMailboxIngressState
{
    Accepted = 1,
    Durable = 2
}

public sealed record ClientMailboxStoreIngressResult(
    ClientMailboxIngressState State,
    ReadOnlyMemory<byte> CanonicalReceipt);

public interface IClientMailboxBinaryIngress
{
    Task<ClientMailboxStoreIngressResult> StoreAsync(
        ReadOnlyMemory<byte> canonicalMst1,
        CancellationToken cancellationToken = default);

    Task<ReadOnlyMemory<byte>> RetrieveAsync(
        ReadOnlyMemory<byte> canonicalMrt1,
        CancellationToken cancellationToken = default);

    Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
        ReadOnlyMemory<byte> canonicalMak1,
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
        ClientMailboxPinnedRoute? route,
        bool ingressConfigured,
        bool allowLegacyMirrorOverlap = false,
        ulong legacyMirrorExpiresAtUnixSeconds = 0)
    {
        Enabled = enabled;
        this.issuerContext = issuerContext.ToArray();
        Route = route;
        IngressConfigured = ingressConfigured;
        AllowLegacyMirrorOverlap = allowLegacyMirrorOverlap;
        LegacyMirrorExpiresAtUnixSeconds = legacyMirrorExpiresAtUnixSeconds;
    }

    public bool Enabled { get; }
    public ClientMailboxPinnedRoute? Route { get; }
    public bool IngressConfigured { get; }
    public bool AllowLegacyMirrorOverlap { get; }
    public ulong LegacyMirrorExpiresAtUnixSeconds { get; }
    public bool HasIssuerContext =>
        issuerContext.Length == 32 &&
        issuerContext.AsSpan().IndexOfAnyExcept((byte)0) >= 0;

    internal ClientMailboxScope ScopeFor(BlindedMailboxId mailboxId, ulong epoch) =>
        ClientMailboxScope.Derive(issuerContext, mailboxId, epoch);

    internal ClientMailboxJournalScope JournalScope =>
        ClientMailboxJournalScope.Derive(issuerContext);

    public override string ToString() =>
        $"ClientMailboxActivation {{ Enabled = {Enabled}, " +
        $"IssuerContext = {(HasIssuerContext ? "[configured]" : "[missing]")}, " +
        $"Route = {(Route is null ? "[missing]" : "[configured]")}, " +
        $"Ingress = {(IngressConfigured ? "[configured]" : "[missing]")} }}";
}

public sealed record ClientMailboxStoreResult(
    ClientMailboxIngressState State,
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
    private readonly MailboxClientDecodePolicy decodePolicy;
    private readonly TimeProvider timeProvider;

    public ClientMailboxAdapter(
        ClientFeatureFlags flags,
        ClientMailboxActivation activation,
        IClientMailboxBinaryIngress ingress,
        ITransportOutboxRepository outbox,
        IClientMailboxStateRepository state,
        IClientMailboxReceiptVerifier receipts,
        MailboxClientDecodePolicy decodePolicy,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(flags);
        this.activation = activation ?? throw new ArgumentNullException(nameof(activation));
        this.ingress = ingress ?? throw new ArgumentNullException(nameof(ingress));
        this.outbox = outbox ?? throw new ArgumentNullException(nameof(outbox));
        this.state = state ?? throw new ArgumentNullException(nameof(state));
        this.receipts = receipts ?? throw new ArgumentNullException(nameof(receipts));
        this.decodePolicy = decodePolicy ?? throw new ArgumentNullException(nameof(decodePolicy));
        this.timeProvider = timeProvider ?? TimeProvider.System;
        if (!flags.ClientMailboxAdapterEnabled ||
            !activation.Enabled ||
            !activation.HasIssuerContext ||
            activation.Route is null ||
            !activation.IngressConfigured)
        {
            throw new InvalidOperationException(
                "Client mailbox adapter requires its disabled-by-default flag, issuer, placement and ingress.");
        }
    }

    public async Task<ClientMailboxStoreResult> StoreAsync(
        OutboxAccountScope outboxScope,
        MailboxStoreRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outboxScope);
        ArgumentNullException.ThrowIfNull(request);
        EnsureVersion(request.MixedVersion);
        EnsurePlacement(request.Envelope.PlacementId);
        var encoded = MailboxClientCodec.EncodeStore(request);
        var logicalId = OutboxLogicalId.FromBytes(request.OperationId.Span);
        var dedup = OutboxDedupMaterial.FromBytes(
            request.Envelope.DeduplicationDigest.Span);
        var createdAt = DateTimeOffset.FromUnixTimeSeconds(
            checked((long)request.Envelope.CreatedAtUnixSeconds));
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(
            checked((long)request.Envelope.ExpiresAtUnixSeconds));
        var prepared = TransportOutboxPreparedItem.Create(
            outboxScope,
            logicalId,
            dedup,
            encoded,
            createdAt,
            expiresAt,
            createdAt);
        var prepare = await outbox.PrepareTransportOutboxAsync(prepared, cancellationToken)
            .ConfigureAwait(false);
        if (prepare is not (
                TransportOutboxCommitResult.Applied or
                TransportOutboxCommitResult.Idempotent or
                TransportOutboxCommitResult.Conflict))
        {
            throw new IOException("Mailbox outbox preparation failed.");
        }

        var snapshot = await ReadExactOutboxAsync(
            outboxScope,
            logicalId,
            dedup,
            encoded,
            cancellationToken).ConfigureAwait(false);
        if (snapshot.State == TransportOutboxState.Durable)
        {
            var evidence = snapshot.Attempts
                .Single(static attempt =>
                    attempt.State == TransportOutboxAttemptState.Durable)
                .GetEvidenceCopy();
            var persistedDurable = await VerifyAndJournalDurableAsync(
                evidence,
                StoreExpectation(request),
                cancellationToken).ConfigureAwait(false);
            return new ClientMailboxStoreResult(
                ClientMailboxIngressState.Durable,
                persistedDurable.Cursor,
                persistedDurable.Disposition);
        }

        var now = timeProvider.GetUtcNow();
        if (now >= expiresAt)
        {
            throw new InvalidOperationException("Mailbox store operation expired.");
        }

        var attempt = CreateAttemptId();
        await ApplyAsync(
            TransportOutboxTransition.Attempted(
                outboxScope,
                logicalId,
                snapshot.Revision,
                attempt,
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.DispatchStarted,
                now,
                RetryAt(now, expiresAt)),
            cancellationToken).ConfigureAwait(false);

        var response = await ingress.StoreAsync(encoded, cancellationToken)
            .ConfigureAwait(false);
        var expectation = StoreExpectation(request);
        if (response.State == ClientMailboxIngressState.Accepted)
        {
            var accepted = receipts.VerifyAccepted(
                response.CanonicalReceipt.Span,
                expectation);
            snapshot = await ReadFoundAsync(outboxScope, logicalId, cancellationToken)
                .ConfigureAwait(false);
            await ApplyAsync(
                TransportOutboxTransition.Accepted(
                    outboxScope,
                    logicalId,
                    snapshot.Revision,
                    attempt,
                    OutboxTransitionSource.Adapter,
                    OutboxTransitionReason.AdapterAccepted,
                    now,
                    RetryAt(now, expiresAt),
                    response.CanonicalReceipt.Span),
                cancellationToken).ConfigureAwait(false);
            return new ClientMailboxStoreResult(
                ClientMailboxIngressState.Accepted,
                accepted.Cursor,
                accepted.Disposition);
        }

        if (response.State != ClientMailboxIngressState.Durable)
        {
            throw new InvalidDataException("Mailbox ingress returned an unknown state.");
        }

        var durable = await VerifyAndJournalDurableAsync(
            response.CanonicalReceipt,
            expectation,
            cancellationToken).ConfigureAwait(false);
        snapshot = await ReadFoundAsync(outboxScope, logicalId, cancellationToken)
            .ConfigureAwait(false);
        await ApplyAsync(
            TransportOutboxTransition.Accepted(
                outboxScope,
                logicalId,
                snapshot.Revision,
                attempt,
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.AdapterAccepted,
                now,
                RetryAt(now, expiresAt),
                response.CanonicalReceipt.Span),
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
                now,
                response.CanonicalReceipt.Span),
            cancellationToken).ConfigureAwait(false);
        return new ClientMailboxStoreResult(
            ClientMailboxIngressState.Durable,
            durable.Cursor,
            durable.Disposition);
    }

    public async Task<ClientMailboxTraversal> ReadTraversalAsync(
        BlindedMailboxId mailboxId,
        ulong epoch,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mailboxId);
        var scope = activation.ScopeFor(mailboxId, epoch);
        await ReconcileExpiredAsync(scope, cancellationToken).ConfigureAwait(false);
        return await state.ReadTraversalAsync(scope, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<MailboxRetrievedEnvelope>> ReadDurableInboxAsync(
        BlindedMailboxId mailboxId,
        ulong epoch,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mailboxId);
        var scope = activation.ScopeFor(mailboxId, epoch);
        await ReconcileExpiredAsync(scope, cancellationToken).ConfigureAwait(false);
        return await state.ReadDurableInboxAsync(scope, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ClientMailboxRetrieveResult> RetrieveAsync(
        MailboxRetrieveRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        EnsureVersion(request.MixedVersion);
        EnsurePlacement(request.PlacementId);
        var scope = activation.ScopeFor(request.MailboxId, request.Epoch);
        await ReconcileExpiredAsync(scope, cancellationToken).ConfigureAwait(false);
        var traversal = await state.ReadTraversalAsync(scope, cancellationToken)
            .ConfigureAwait(false);
        if (request.AfterCursor != traversal.AfterCursor ||
            !FixedEquals(
                request.ContinuationToken.Span,
                traversal.ContinuationToken))
        {
            throw new InvalidOperationException(
                "MRT1 cursor/token does not match durable mailbox traversal.");
        }

        var response = await ingress.RetrieveAsync(
            MailboxClientCodec.EncodeRetrieve(request),
            cancellationToken).ConfigureAwait(false);
        var page = MailboxClientCodec.DecodeRetrievePage(response.Span, decodePolicy);
        if (page.Epoch != request.Epoch ||
            !FixedEquals(page.OperationId.Span, request.OperationId.Span) ||
            page.Items.Any(item =>
                !FixedEquals(item.Envelope.MailboxId.Bytes.Span, request.MailboxId.Bytes.Span) ||
                !FixedEquals(item.Envelope.PlacementId.Bytes.Span, request.PlacementId.Bytes.Span)))
        {
            throw new InvalidDataException(
                "MRP1 does not match the exact MRT1 mailbox operation.");
        }

        var committed = await state.CommitRetrievePageAsync(
            scope,
            traversal,
            page,
            cancellationToken)
            .ConfigureAwait(false);
        return new ClientMailboxRetrieveResult(
            committed.Traversal.AfterCursor,
            page.HasMore,
            committed.Traversal.GetContinuationTokenCopy(),
            committed.DurableInbox);
    }

    public async Task<ClientMailboxAckResult> AcknowledgeAsync(
        MailboxAckRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        EnsureVersion(request.MixedVersion);
        EnsurePlacement(request.PlacementId);
        var canonicalAck = MailboxClientCodec.EncodeAck(request);
        var scope = activation.ScopeFor(request.MailboxId, request.Epoch);
        await ReconcileExpiredAsync(scope, cancellationToken).ConfigureAwait(false);
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
                "MAK1 does not match the durable page continuation authority.");
        }
        var pending = await state.CheckAcknowledgementsAsync(
            scope,
            request.Acknowledgements,
            cancellationToken).ConfigureAwait(false);
        if (pending == ClientMailboxAckState.AlreadyCommitted)
        {
            return new ClientMailboxAckResult(true, request.Acknowledgements.Count);
        }
        if (pending != ClientMailboxAckState.Pending)
        {
            throw new InvalidOperationException(
                "MAK1 is not the next ordered persistent acknowledgement prefix.");
        }
        var expectations = await state.ReadAckExpectationsAsync(
            scope,
            request.Acknowledgements,
            cancellationToken).ConfigureAwait(false);

        var response = await ingress.AcknowledgeAsync(
            canonicalAck,
            cancellationToken).ConfigureAwait(false);
        var aggregate = MailboxAggregateAckCodec.DecodeMqr3(response.Span);
        if (aggregate.Epoch != request.Epoch ||
            !FixedEquals(aggregate.OperationId.Span, request.OperationId.Span) ||
            aggregate.TombstoneQuorums.Count != request.Acknowledgements.Count)
        {
            throw new InvalidDataException("MAR1 does not match the exact MAK1 operation.");
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
                    Route = activation.Route!,
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

        return new ClientMailboxAckResult(
            committed == ClientMailboxAckState.AlreadyCommitted,
            request.Acknowledgements.Count);
    }

    private ClientMailboxReceiptExpectation StoreExpectation(
        MailboxStoreRequest request) => new()
        {
            Epoch = request.Epoch,
            OperationId = request.OperationId.ToArray(),
            MailboxId = request.Envelope.MailboxId,
            Route = activation.Route!,
            EnvelopeDigest = request.Envelope.DeduplicationDigest.ToArray(),
            ExpiresAtUnixSeconds = request.Envelope.ExpiresAtUnixSeconds,
            AllowedDispositions = StoreDispositions
        };

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

    private void EnsureVersion(MailboxMixedVersionMarker marker)
    {
        if (marker == MailboxMixedVersionMarker.LegacyMirrorOverlap &&
            (!activation.AllowLegacyMirrorOverlap ||
             !decodePolicy.AllowLegacyMirrorOverlap ||
             activation.LegacyMirrorExpiresAtUnixSeconds == 0 ||
             checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds()) >
                activation.LegacyMirrorExpiresAtUnixSeconds))
        {
            throw new MailboxClientException(
                MailboxClientError.DowngradeRejected,
                "Legacy mailbox mirror overlap was not explicitly activated.");
        }
    }

    private void EnsurePlacement(BlindedPlacementId placementId)
    {
        if (!FixedEquals(
                placementId.Bytes.Span,
                activation.Route!.PlacementId.Bytes.Span))
        {
            throw new InvalidOperationException(
                "Mailbox operation does not match the pinned placement.");
        }
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
        DateTimeOffset expiresAt)
    {
        var candidate = now.AddSeconds(1);
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
}
