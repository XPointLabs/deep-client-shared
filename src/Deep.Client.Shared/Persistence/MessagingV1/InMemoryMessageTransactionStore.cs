using System.Security.Cryptography;
using Deep.Client.Shared.Domain.MessagingV1;

namespace Deep.Client.Shared.Persistence.MessagingV1;

internal sealed class InMemoryMessageStoreBacking
{
    internal InMemoryMessageStoreBacking(MessageStoreScope scope) =>
        Scope = new(scope.LocalAccountId, scope.DatabaseGeneration, scope.StoreInstanceId);

    internal MessageStoreScope Scope { get; }
    internal SemaphoreSlim Gate { get; } = new(1, 1);
    internal Dictionary<string, InMemoryStoredClaim> Claims { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, LogicalOutboxSnapshot> Outboxes { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, string> Operations { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, MessageTombstone> Tombstones { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, InboxEventSnapshot> Inbox { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, PendingMessageReceipt> Receipts { get; } = new(StringComparer.Ordinal);
    internal HashSet<string> CompletedReceipts { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, InMemoryRatchetState> Ratchets { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, string> Attempts { get; } = new(StringComparer.Ordinal);
    internal byte[]? EvidenceAuthorityFingerprint { get; set; }
}

internal sealed record InMemoryStoredClaim(MessageEventHash32 EventHash, bool ForkLatched,
    HashSet<string> Devices, MessageEventHash32? ForkEvidence);
internal sealed record InMemoryRatchetState(RatchetStateHash32 BeforeHash,
    RatchetStateHash32 AfterHash, byte[] SealedState, DateTimeOffset AppliedAt);

internal sealed class InMemoryMessageTransactionStore : IMessageTransactionStore, IAsyncDisposable
{
    private readonly MessageStoreAuthorityBinding authorityBinding;
    private readonly InMemoryMessageStoreBacking backing;
    private SemaphoreSlim gate => backing.Gate;
    private Dictionary<string, InMemoryStoredClaim> claims => backing.Claims;
    private Dictionary<string, LogicalOutboxSnapshot> outboxes => backing.Outboxes;
    private Dictionary<string, string> operations => backing.Operations;
    private Dictionary<string, MessageTombstone> tombstones => backing.Tombstones;
    private Dictionary<string, InboxEventSnapshot> inbox => backing.Inbox;
    private Dictionary<string, PendingMessageReceipt> receipts => backing.Receipts;
    private HashSet<string> completedReceipts => backing.CompletedReceipts;
    private Dictionary<string, InMemoryRatchetState> ratchets => backing.Ratchets;
    private Dictionary<string, string> attempts => backing.Attempts;
    private readonly IMessageStoreFailpoint? failpoint;
    private readonly TaskCompletionSource<bool> disposalCompletion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private int disposed;

    internal InMemoryMessageTransactionStore(
        MessageStoreScope scope,
        Msg01VerifiedSessionAuthority evidenceAuthority,
        IMessageStoreFailpoint? failpoint = null)
        : this(new InMemoryMessageStoreBacking(scope), evidenceAuthority, failpoint)
    {
    }

    internal InMemoryMessageTransactionStore(
        InMemoryMessageStoreBacking backing,
        Msg01VerifiedSessionAuthority evidenceAuthority,
        IMessageStoreFailpoint? failpoint = null)
    {
        ArgumentNullException.ThrowIfNull(backing);
        ArgumentNullException.ThrowIfNull(evidenceAuthority);
        var authorityFingerprint = evidenceAuthority.Fingerprint.ToArray();
        lock (backing)
        {
            if (backing.EvidenceAuthorityFingerprint is null)
                backing.EvidenceAuthorityFingerprint = authorityFingerprint.ToArray();
            else if (!CryptographicOperations.FixedTimeEquals(
                         backing.EvidenceAuthorityFingerprint, authorityFingerprint))
                throw new CryptographicException(
                    "The MSG-01 backing is bound to another verified session authority.");
        }
        CryptographicOperations.ZeroMemory(authorityFingerprint);
        authorityBinding = new MessageStoreAuthorityBinding(evidenceAuthority);
        this.backing = backing;
        this.failpoint = failpoint;
        Scope = new(backing.Scope.LocalAccountId, backing.Scope.DatabaseGeneration,
            backing.Scope.StoreInstanceId);
    }

    public MessageStoreScope Scope { get; }
    internal InMemoryMessageStoreBacking Backing => backing;

    public IMessageVerifiedTransportHandoff ClaimVerifiedTransportHandoff() =>
        authorityBinding.ClaimHandoff();
    public IMessageGroupDispatchSafetyHandoff ClaimGroupDispatchSafetyHandoff() =>
        authorityBinding.ClaimGroupSafetyHandoff();

    public async ValueTask<SemanticClaimResult> ClaimSemanticAsync(
        SemanticClaimCandidate claim,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claim);
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return ClaimSemanticUnderGate(claim);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<BeginMessageResult> BeginOutboundAsync(
        MessageMutationId32 operationId,
        SemanticClaimCandidate claim,
        LogicalOutboxSeed seed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operationId);
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(seed);
        ValidateOutboundBinding(claim, seed);
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var claimStorageKey = ClaimStorageKey(claim.Key);
            var outboxKey = OutboxStorageKey(seed.ClaimKey);
            var operationKey = Key(operationId);
            var fingerprint = BeginFingerprint(claim, seed);

            if (claims.TryGetValue(claimStorageKey, out var storedClaim))
            {
                if (storedClaim.ForkLatched)
                {
                    return new(SemanticClaimResult.ForkLatched, MessageCommitResult.ForkLatched, null);
                }

                if (!storedClaim.EventHash.Equals(claim.EventHash))
                {
                    claims[claimStorageKey] = storedClaim with { ForkLatched = true, ForkEvidence = claim.EventHash };
                    return new(SemanticClaimResult.ForkLatched, MessageCommitResult.ForkLatched, null);
                }
            }

            if (operations.TryGetValue(operationKey, out var previous))
            {
                return previous == fingerprint && outboxes.TryGetValue(outboxKey, out var replayed)
                    ? new(SemanticClaimResult.ExactDuplicate, MessageCommitResult.Idempotent, Clone(replayed))
                    : new(SemanticClaimResult.ExactDuplicate, MessageCommitResult.Conflict, null);
            }

            if (outboxes.TryGetValue(outboxKey, out var existing))
            {
                return SameSeed(existing, seed)
                    ? new(SemanticClaimResult.ExactDuplicate, MessageCommitResult.Idempotent, Clone(existing))
                    : new(SemanticClaimResult.ExactDuplicate, MessageCommitResult.Conflict, null);
            }

            var queued = LogicalOutboxStateMachine.Queued(seed);
            failpoint?.Hit("begin.before-commit");
            if (storedClaim is null)
            {
                claims.Add(claimStorageKey, new(MessageEventHash32.FromBytes(claim.EventHash.Span), false,
                    new(StringComparer.Ordinal){Key(claim.AuthorDeviceId)}, null));
            }
            else storedClaim.Devices.Add(Key(claim.AuthorDeviceId));
            outboxes.Add(outboxKey, queued);
            operations.Add(operationKey, fingerprint);
            failpoint?.Hit("begin.after-commit-before-return");
            return new(storedClaim is null ? SemanticClaimResult.First : SemanticClaimResult.ExactDuplicate,
                MessageCommitResult.Applied, Clone(queued));
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<ApplyMessageResult> ApplyAsync(
        PreparedMessageMutation plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ThrowIfDisposed();
        plan.DemandTrustedAuthorityIfRequired(authorityBinding);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!plan.Scope.Equals(Scope))
            {
                return new(MessageCommitResult.Conflict, null, null);
            }
            var outboxKey = OutboxStorageKey(plan.ClaimKey);
            if (!outboxes.TryGetValue(outboxKey, out var current))
            {
                return new(MessageCommitResult.Missing, null, null);
            }

            if (!claims.TryGetValue(ClaimStorageKey(current.ClaimKey), out var claim))
            {
                return new(MessageCommitResult.Conflict, Clone(current), null);
            }

            if (claim.ForkLatched)
            {
                return new(MessageCommitResult.ForkLatched, Clone(current), null);
            }

            var operationKey = Key(plan.OperationId);
            var fingerprint = PlanFingerprint(plan);
            if (operations.TryGetValue(operationKey, out var previous))
            {
                return previous == fingerprint
                    ? new(MessageCommitResult.Idempotent, Clone(current), tombstones.GetValueOrDefault(outboxKey))
                    : new(MessageCommitResult.Conflict, Clone(current), null);
            }

            if (plan.ExpectedRevision != current.Revision)
            {
                return new(MessageCommitResult.StaleRevision, Clone(current), null);
            }

            foreach (var attempt in plan.Attempts)
            {
                if (attempts.ContainsKey(Key(attempt.AttemptId)))
                    return new(MessageCommitResult.Conflict, Clone(current), null);
            }

            LogicalOutboxSnapshot candidate;
            try
            {
                candidate = LogicalOutboxStateMachine.Apply(current, plan);
            }
            catch (InvalidOperationException exception) when (exception is not MessageRevisionExhaustedException)
            {
                return new(MessageCommitResult.Conflict, Clone(current), null);
            }

            failpoint?.Hit("apply.before-commit");
            outboxes[outboxKey] = candidate;
            operations.Add(operationKey, fingerprint);
            foreach (var attempt in plan.Attempts)
                attempts.Add(Key(attempt.AttemptId), AttemptFingerprint(candidate.ClaimKey, attempt));
            MessageTombstone? tombstone = null;
            if (candidate.State is LogicalOutboxState.Expired
                or LogicalOutboxState.Cancelled
                or LogicalOutboxState.TerminalRejected)
            {
                tombstone = new(candidate, tombstones.TryGetValue(outboxKey, out var existingTombstone)
                    ? existingTombstone.RetainedAt : plan.OccurredAt);
                tombstones[outboxKey] = tombstone;
            }

            failpoint?.Hit("apply.after-commit-before-return");
            return new(MessageCommitResult.Applied, Clone(candidate), tombstone);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<LogicalOutboxSnapshot?> ReadAsync(
        SemanticClaimKey claimKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claimKey);
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return outboxes.TryGetValue(OutboxStorageKey(claimKey), out var item)
                ? Clone(item)
                : null;
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<InboxEventSnapshot?> ReadInboxAsync(
        SemanticClaimKey claimKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claimKey); ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return inbox.TryGetValue(ClaimStorageKey(claimKey), out var item)
                ? Clone(item) : null;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<MessageRatchetSnapshot?> ReadRatchetAsync(
        RatchetSessionId32 sessionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sessionId); ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return ratchets.TryGetValue(Key(sessionId), out var state)
                ? new MessageRatchetSnapshot(sessionId, state.BeforeHash, state.AfterHash,
                    state.SealedState, state.AppliedAt) : null;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<InboxEventSnapshot?> MaterializeInboundAsync(InboxMaterializationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); ThrowIfDisposed();
        request.DemandIssuedBy(authorityBinding);
        if (request.CanonicalEvent.Length is 0 or > MessagingV1Limits.MaxCanonicalEventBytes
            || request.AuthenticatedReceipt.Length is 0 or > MessagingV1Limits.MaxAuthenticatedEvidenceBytes)
            throw new ArgumentOutOfRangeException(nameof(request));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if(!request.Scope.Equals(Scope)) throw new InvalidOperationException("MSG-01 inbound capability has the wrong store scope.");
            var operationKey = Key(request.OperationId);
            var operationFingerprint = InboundFingerprint(request);
            var replayedOperation = operations.TryGetValue(operationKey, out var priorOperation);
            if (replayedOperation && !string.Equals(priorOperation, operationFingerprint, StringComparison.Ordinal))
                throw new CryptographicException(
                    "MSG-01 authenticated evidence replay identity was reused for changed inbound context.");
            if (replayedOperation && !inbox.ContainsKey(ClaimStorageKey(request.Claim.Key)))
                throw new InvalidOperationException(
                    "MSG-01 inbound replay ledger is inconsistent with the materialized event.");
            var key = ClaimStorageKey(request.Claim.Key);
            var ratchetKey=Key(request.SessionId);
            var ratchet=PrepareRatchetTransition(request,ratchetKey);
            if (inbox.TryGetValue(key, out var exact))
            {
                if (!exact.EventHash.Equals(request.Claim.EventHash))
                {
                    ClaimSemanticUnderGate(request.Claim); throw new InvalidOperationException("MSG-01 semantic fork is latched.");
                }
                if(receipts.TryGetValue(Key(request.ReceiptId),out var duplicateReceipt)
                    && (!duplicateReceipt.ClaimKey.Equals(request.Claim.Key)
                        || !duplicateReceipt.EvidenceHash.Equals(request.EvidenceHash)
                        || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                            duplicateReceipt.AuthenticatedReceipt,
                            request.AuthenticatedReceipt.Span)))
                    throw new InvalidOperationException("MSG-01 receipt id is already bound to different evidence.");
                var devices=exact.ObservedAuthorDevices.Append(request.Claim.AuthorDeviceId).Distinct().ToArray();
                var updated=new InboxEventSnapshot(Scope,exact.ClaimKey,exact.EventHash,exact.CanonicalEvent,
                    exact.MaterializedAt,exact.ReceiptId,devices);
                var duplicatePending = new PendingMessageReceipt(request.ReceiptId, request.Claim.Key,
                    request.EvidenceHash, request.AuthenticatedReceipt.Span, request.OccurredAt, null);
                failpoint?.Hit("inbox-duplicate.before-commit");
                inbox[key]=updated;
                receipts.TryAdd(Key(request.ReceiptId), duplicatePending);
                ClaimSemanticUnderGate(request.Claim);
                if(ratchet is not null) ratchets[ratchetKey]=ratchet;
                if (!replayedOperation) operations.Add(operationKey, operationFingerprint);
                failpoint?.Hit("inbox-duplicate.after-commit-before-return");
                return Clone(updated);
            }
            if(receipts.TryGetValue(Key(request.ReceiptId),out var priorReceipt)
                && (!priorReceipt.ClaimKey.Equals(request.Claim.Key)
                    || !priorReceipt.EvidenceHash.Equals(request.EvidenceHash)
                    || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                        priorReceipt.AuthenticatedReceipt,
                        request.AuthenticatedReceipt.Span)))
                throw new InvalidOperationException("MSG-01 receipt id is already bound to different evidence.");
            var item = new InboxEventSnapshot(Scope, request.Claim.Key, request.Claim.EventHash,
                request.CanonicalEvent.Span, request.OccurredAt, request.ReceiptId, [request.Claim.AuthorDeviceId]);
            var pending = new PendingMessageReceipt(request.ReceiptId, request.Claim.Key,
                request.EvidenceHash, request.AuthenticatedReceipt.Span, request.OccurredAt, null);
            failpoint?.Hit("inbox.before-commit");
            var claimResult=ClaimSemanticUnderGate(request.Claim);
            if(claimResult==SemanticClaimResult.ForkLatched) throw new InvalidOperationException("MSG-01 semantic fork is latched.");
            inbox.Add(key, item);
            receipts[Key(request.ReceiptId)] = pending;
            if(ratchet is not null) ratchets[ratchetKey]=ratchet;
            if (!replayedOperation) operations.Add(operationKey, operationFingerprint);
            failpoint?.Hit("inbox.after-commit-before-return");
            return Clone(item);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<IReadOnlyList<MessageStoreRecoveryItem>> ClaimRecoveryAsync(MessageRecoveryOwnerId16 owner, DateTimeOffset now, int maxItems, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(owner); if (maxItems is < 1 or > MessagingV1Limits.MaxRecoveryBatch) throw new ArgumentOutOfRangeException(nameof(maxItems)); ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { ThrowIfDisposed(); now=LogicalOutboxSeed.Canonical(now); var until=now+MessagingV1Limits.MaxRecoveryLease;
            var selected=outboxes.Where(x => x.Value.State is LogicalOutboxState.Queued or LogicalOutboxState.FanoutPrepared or LogicalOutboxState.Sending or LogicalOutboxState.PartiallyAccepted or LogicalOutboxState.OutcomeUnknown)
                .Where(x=>x.Value.RecoveryLease is null||x.Value.RecoveryLease.ExpiresAt<=now||x.Value.RecoveryLease.OwnerId.Equals(owner))
                .OrderBy(x=>x.Value.CreatedAt)
                .ThenBy(x=>x.Value.ClaimKey.AuthorAccountId)
                .ThenBy(x=>x.Value.ClaimKey.ConversationId)
                .ThenBy(x=>x.Value.ClaimKey.SemanticMessageId)
                .Take(maxItems).ToArray();
            var result=new List<MessageStoreRecoveryItem>(); foreach(var pair in selected){var x=pair.Value; var leased=new LogicalOutboxSnapshot(x.StoreScope,x.ClaimKey,x.AuthorDeviceId,x.EventHash,x.CanonicalPayload,x.CreatedAt,x.ExpiresAt,x.State,x.Revision,x.Targets,new(owner,until),x.PayloadKind); outboxes[pair.Key]=leased; result.Add(new(Clone(leased),[]));} return result; }
        finally { gate.Release(); }
    }

    public async ValueTask<IReadOnlyList<PendingMessageReceipt>> ClaimPendingReceiptsAsync(MessageRecoveryOwnerId16 owner, DateTimeOffset now, int maxItems, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(owner); if (maxItems is < 1 or > MessagingV1Limits.MaxRecoveryBatch) throw new ArgumentOutOfRangeException(nameof(maxItems)); ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { ThrowIfDisposed(); now=LogicalOutboxSeed.Canonical(now); var until=now+MessagingV1Limits.MaxRecoveryLease;
            var selected=receipts.Where(x=>x.Value.Lease is null||x.Value.Lease.ExpiresAt<=now||x.Value.Lease.OwnerId.Equals(owner))
                .OrderBy(x=>x.Value.CreatedAt)
                .ThenBy(x=>x.Value.ReceiptId)
                .Take(maxItems).ToArray();
            var result=new List<PendingMessageReceipt>(); foreach(var pair in selected){var x=pair.Value; var leased=new PendingMessageReceipt(x.ReceiptId,x.ClaimKey,x.EvidenceHash,x.AuthenticatedReceipt,x.CreatedAt,new(owner,until));receipts[pair.Key]=leased;result.Add(Clone(leased));} return result; }
        finally { gate.Release(); }
    }

    public async ValueTask<PendingMessageReceipt?> ClaimPendingReceiptAsync(
        MessageReceiptId32 receiptId, MessageRecoveryOwnerId16 owner,
        DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receiptId); ArgumentNullException.ThrowIfNull(owner);
        ThrowIfDisposed(); now=LogicalOutboxSeed.Canonical(now);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var key=Key(receiptId);
            if(!receipts.TryGetValue(key,out var receipt)) return null;
            if(receipt.Lease is not null && receipt.Lease.ExpiresAt>now
                && !receipt.Lease.OwnerId.Equals(owner)) return null;
            var leased=new PendingMessageReceipt(receipt.ReceiptId,receipt.ClaimKey,
                receipt.EvidenceHash,receipt.AuthenticatedReceipt,receipt.CreatedAt,
                new(owner,now+MessagingV1Limits.MaxRecoveryLease));
            receipts[key]=leased; return Clone(leased);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<MessageCommitResult> CompletePendingReceiptAsync(
        MessageReceiptId32 receiptId, MessageRecoveryOwnerId16 owner,
        DateTimeOffset completedAt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receiptId); ArgumentNullException.ThrowIfNull(owner);
        _ = LogicalOutboxSeed.Canonical(completedAt); ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var key=Key(receiptId);
            if(!receipts.TryGetValue(key,out var receipt))
                return completedReceipts.Contains(key)
                    ? MessageCommitResult.Idempotent : MessageCommitResult.Missing;
            if(receipt.Lease is null || !receipt.Lease.OwnerId.Equals(owner)
                || receipt.Lease.ExpiresAt < LogicalOutboxSeed.Canonical(completedAt))
                return MessageCommitResult.Conflict;
            failpoint?.Hit("receipt-complete.before-commit");
            receipts.Remove(key); completedReceipts.Add(key);
            failpoint?.Hit("receipt-complete.after-commit-before-return");
            return MessageCommitResult.Applied;
        }
        finally { gate.Release(); }
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0)
        {
            return new(disposalCompletion.Task);
        }

        return new(DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        try
        {
            authorityBinding.Dispose();
            await gate.WaitAsync().ConfigureAwait(false);
            try
            {
                // Durable in-memory backing intentionally survives an instance close/reopen.
            }
            finally
            {
                gate.Release();
            }
            disposalCompletion.TrySetResult(true);
        }
        catch (Exception exception)
        {
            disposalCompletion.TrySetException(exception);
            throw;
        }
    }

    private SemanticClaimResult ClaimSemanticUnderGate(SemanticClaimCandidate claim)
    {
        var key = ClaimStorageKey(claim.Key);
        if (!claims.TryGetValue(key, out var stored))
        {
            claims.Add(key, new(MessageEventHash32.FromBytes(claim.EventHash.Span), false,
                new(StringComparer.Ordinal){Key(claim.AuthorDeviceId)}, null));
            return SemanticClaimResult.First;
        }

        if (stored.ForkLatched)
        {
            return SemanticClaimResult.ForkLatched;
        }

        if (stored.EventHash.Equals(claim.EventHash))
        {
            stored.Devices.Add(Key(claim.AuthorDeviceId));
            return SemanticClaimResult.ExactDuplicate;
        }

        claims[key] = stored with { ForkLatched = true, ForkEvidence = claim.EventHash };
        return SemanticClaimResult.ForkLatched;
    }

    private void ValidateOutboundBinding(SemanticClaimCandidate claim, LogicalOutboxSeed seed)
    {
        if (!seed.StoreScope.Equals(Scope)
            || !claim.Key.Equals(seed.ClaimKey)
            || !claim.AuthorDeviceId.Equals(seed.AuthorDeviceId)
            || !claim.EventHash.Equals(seed.EventHash)
            || !claim.AuthorAccountId.Equals(seed.LocalAccountId))
        {
            throw new ArgumentException("Outbound claim and logical outbox seed are not exactly bound.");
        }
    }

    private static bool SameSeed(LogicalOutboxSnapshot snapshot, LogicalOutboxSeed seed) =>
        snapshot.StoreScope.Equals(seed.StoreScope)
        && snapshot.ClaimKey.Equals(seed.ClaimKey)
        && snapshot.AuthorDeviceId.Equals(seed.AuthorDeviceId)
        && snapshot.EventHash.Equals(seed.EventHash)
        && snapshot.PayloadKind == seed.PayloadKind
        && CryptographicOperations.FixedTimeEquals(snapshot.CanonicalPayload, seed.CanonicalPayload)
        && snapshot.CreatedAt == seed.CreatedAt
        && snapshot.ExpiresAt == seed.ExpiresAt;

    private static LogicalOutboxSnapshot Clone(LogicalOutboxSnapshot snapshot) => new(
        snapshot.StoreScope, snapshot.ClaimKey, snapshot.AuthorDeviceId, snapshot.EventHash,
        snapshot.CanonicalPayload, snapshot.CreatedAt, snapshot.ExpiresAt, snapshot.State,
        snapshot.Revision, snapshot.Targets, snapshot.RecoveryLease, snapshot.PayloadKind);

    private static InboxEventSnapshot Clone(InboxEventSnapshot snapshot) => new(
        snapshot.StoreScope, snapshot.ClaimKey, snapshot.EventHash,
        snapshot.CanonicalEvent, snapshot.MaterializedAt, snapshot.ReceiptId,
        snapshot.ObservedAuthorDevices);

    private static PendingMessageReceipt Clone(PendingMessageReceipt receipt) => new(
        receipt.ReceiptId, receipt.ClaimKey, receipt.EvidenceHash,
        receipt.AuthenticatedReceipt, receipt.CreatedAt, receipt.Lease);

    private InMemoryRatchetState? PrepareRatchetTransition(
        InboxMaterializationRequest request, string ratchetKey)
    {
        if(ratchets.TryGetValue(ratchetKey,out var prior))
        {
            if(prior.AfterHash.Equals(request.AfterHash))
            {
                if(!prior.BeforeHash.Equals(request.BeforeHash)
                    || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                        prior.SealedState,request.SealedRatchetState.Span))
                    throw new InvalidOperationException(
                        "MSG-01 exact ratchet replay has changed bytes.");
                return null;
            }
            if(!prior.AfterHash.Equals(request.BeforeHash))
                throw new InvalidOperationException(
                    "MSG-01 ratchet predecessor does not match.");
        }
        return new InMemoryRatchetState(request.BeforeHash,request.AfterHash,
            request.SealedRatchetState.ToArray(),request.OccurredAt);
    }

    private static string ClaimStorageKey(SemanticClaimKey key) => string.Concat(
        Key(key.AuthorAccountId), Key(key.ConversationId), Key(key.SemanticMessageId));

    private static string OutboxStorageKey(SemanticClaimKey claimKey) => ClaimStorageKey(claimKey);

    private static string BeginFingerprint(SemanticClaimCandidate claim, LogicalOutboxSeed seed) => string.Concat(
        "B", ScopeKey(seed.StoreScope), ClaimStorageKey(claim.Key), Key(claim.AuthorDeviceId), Key(claim.EventHash), ((int)seed.PayloadKind).ToString("X2"), Convert.ToHexString(SHA256.HashData(seed.CanonicalPayload)),
        seed.CreatedAt.ToUnixTimeMilliseconds().ToString("X16"),
        seed.ExpiresAt.ToUnixTimeMilliseconds().ToString("X16"));

    private static string PlanFingerprint(PreparedMessageMutation plan) => string.Concat(
        "M", ScopeKey(plan.Scope), ClaimStorageKey(plan.ClaimKey), ((int)plan.Kind).ToString("X2"),
        plan.ExpectedRevision.ToString("X16"), plan.OccurredAt.ToUnixTimeMilliseconds().ToString("X16"),
        plan.Target is null ? "" : Key(plan.Target.AccountId)+Key(plan.Target.DeviceId),
        plan.AttemptId is null ? "" : Key(plan.AttemptId),
        string.Concat(plan.Fanout.Select(static x => Key(x.Target.AccountId)+Key(x.Target.DeviceId)+Key(x.DirectoryHeadHash)+Key(x.OperationId)+Key(x.BindingHash))),
        string.Concat(plan.Attempts.Select(static x => AttemptFingerprint(null,x))),
        plan.Outcome is null ? string.Empty : Key(plan.Outcome.AttemptId)+Key(plan.Outcome.EvidenceHash)+((int)plan.Outcome.Kind).ToString("X2")+Key(plan.Outcome.TargetOperationId)+Key(plan.Outcome.BindingHash)+Replay(plan.Outcome.ReplayCounter,plan.Outcome.ReplayNonce.Span),
        plan.Uncertainty is null ? string.Empty : Key(plan.Uncertainty.AttemptId)+Key(plan.Uncertainty.EvidenceHash)+Key(plan.Uncertainty.TargetOperationId)+Key(plan.Uncertainty.BindingHash)+Replay(plan.Uncertainty.ReplayCounter,plan.Uncertainty.ReplayNonce.Span),
        plan.Reconciliation is null ? string.Empty : Key(plan.Reconciliation.Target.AccountId)+Key(plan.Reconciliation.Target.DeviceId)+Key(plan.Reconciliation.AttemptId)+((int)plan.Reconciliation.Kind).ToString("X2")+Key(plan.Reconciliation.TargetOperationId)+Key(plan.Reconciliation.BindingHash)+Key(plan.Reconciliation.EvidenceHash)+Replay(plan.Reconciliation.ReplayCounter,plan.Reconciliation.ReplayNonce.Span),
        plan.LateReceipt is null ? string.Empty : Key(plan.LateReceipt.AcceptedAttemptId)+Key(plan.LateReceipt.ReceiptId)+Key(plan.LateReceipt.EvidenceHash)+Key(plan.LateReceipt.TargetOperationId)+Key(plan.LateReceipt.BindingHash)+Replay(plan.LateReceipt.ReplayCounter,plan.LateReceipt.ReplayNonce.Span),
        plan.GroupDispatchBlock is null ? string.Empty : GroupBlockFingerprint(plan.GroupDispatchBlock));

    private static string GroupBlockFingerprint(VerifiedLocalGroupDispatchBlock block) => string.Concat(
        Key(block.ClaimKey.AuthorDeviceId!), Key(block.EventHash), Key(block.Target.AccountId), Key(block.Target.DeviceId),
        Key(block.DirectoryHeadHash), Key(block.TargetOperationId), Key(block.BindingHash), Key(block.AttemptId),
        Key(block.RequestHash), Key(block.RatchetBeforeHash), Key(block.RatchetTransitionHash),
        Convert.ToHexString(block.GroupId.Span), block.OutboxRevision.ToString("X16"),
        (block.GroupHeadRevision ?? 0).ToString("X16"), ((int)block.Disposition).ToString("X2"),
        Convert.ToHexString(SHA256.HashData(block.ExactDgm1.Span)),
        Convert.ToHexString(block.GroupHeadFingerprint.Span));

    private static string AttemptFingerprint(SemanticClaimKey? key, TargetAttemptPlan attempt) => string.Concat(
        key is null ? "" : ClaimStorageKey(key), Key(attempt.Target.AccountId), Key(attempt.Target.DeviceId),
        Key(attempt.AttemptId), Key(attempt.RequestHash), Key(attempt.RatchetTransitionHash),
        Key(attempt.RatchetBeforeHash), Key(attempt.DirectoryHeadHash), Key(attempt.OperationId), Key(attempt.BindingHash),
        Convert.ToHexString(SHA256.HashData(attempt.Ciphertext.Span)));

    private static string InboundFingerprint(InboxMaterializationRequest request) => string.Concat(
        "I", ScopeKey(request.Scope), ClaimStorageKey(request.Claim.Key),
        Key(request.Claim.AuthorDeviceId), Key(request.Claim.EventHash),
        Key(request.SessionId), Key(request.BeforeHash), Key(request.AfterHash),
        Convert.ToHexString(SHA256.HashData(request.CanonicalEvent.Span)),
        Convert.ToHexString(SHA256.HashData(request.SealedRatchetState.Span)),
        Key(request.ReceiptId), Key(request.EvidenceHash),
        Convert.ToHexString(SHA256.HashData(request.AuthenticatedReceipt.Span)),
        request.ReplayCounter.ToString("X16"), Convert.ToHexString(request.ReplayNonce.Span));

    private static string Key(MessagingBinaryValue value) => Convert.ToHexString(value.Span);

    private static string Replay(ulong counter, ReadOnlySpan<byte> nonce) =>
        string.Concat(counter.ToString("X16"), Convert.ToHexString(nonce));

    private static string ScopeKey(MessageStoreScope scope) => string.Concat(
        Key(scope.LocalAccountId), scope.DatabaseGeneration.ToString("X16"), Key(scope.StoreInstanceId));

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

}
