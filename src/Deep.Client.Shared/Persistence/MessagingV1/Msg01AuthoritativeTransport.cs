using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.GroupV1;

namespace Deep.Client.Shared.Persistence.MessagingV1;

internal sealed class Msg01DeliveryPendingException(LogicalOutboxState state)
    : IOException($"MSG-01 delivery remains durably queued in state '{state}'.")
{
    internal LogicalOutboxState State { get; } = state;
}

internal sealed record Msg01GroupFirstDispatchBlock(
    RecipientDeviceTarget Target,
    GroupMessageFirstDispatchDisposition Disposition);

internal sealed record Msg01GroupDispatchResult(
    LogicalOutboxSnapshot Snapshot,
    IReadOnlyList<Msg01GroupFirstDispatchBlock> Blocks);

internal sealed class Msg01AuthoritativeTransport :
    ISessionMessageTransport, IGroupSyncTransport, IGroupMailboxRouteSyncTransport,
    IKnownGroupInboxReceiver, IGroupInboxMaintenance, IDurableInboxAcknowledger,
    IMailboxAckCorrelationProjectionSource, IDisposable, IAsyncDisposable
{
    private static readonly TimeSpan RecoveryPeriod = TimeSpan.FromSeconds(15);
    private readonly ISessionMessageTransport inbound;
    private readonly IGroupSyncTransport groups;
    private readonly IGroupMailboxRouteSyncTransport routes;
    private readonly IMsg01AuthenticatedEvidenceSource session;
    private readonly GroupMessageDispatchSafetyService? groupDispatchSafety;
    private readonly MessagingV1RuntimeOwner owner;
    private readonly IClock clock;
    private readonly IDisposable? ownedTransport;
    private readonly IAsyncDisposable? asyncOwnedTransport;
    private readonly CancellationTokenSource shutdown = new();
    private readonly SemaphoreSlim recoveryGate = new(1, 1);
    private readonly SemaphoreSlim deliveryGate = new(1, 1);
    private readonly SemaphoreSlim sessionMutationGate = new(1, 1);
    private readonly object lifecycleGate = new();
    private readonly TaskCompletionSource<bool> disposalCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource<bool> drained = CompletedDrain();
    private Task? recoveryTask;
    private SessionId? activeAccount;
    private int activeOperations;
    private bool accepting = true;
    private int disposed;

    internal Msg01AuthoritativeTransport(
        ISessionMessageTransport verifiedSessionTransport,
        IGroupSyncTransport? groupTransport,
        IMsg01AuthenticatedEvidenceSource session,
        MessagingV1RuntimeOwner owner,
        IClock clock,
        bool ownsTransport,
        GroupMessageDispatchSafetyService? groupDispatchSafety = null)
    {
        inbound = verifiedSessionTransport ?? throw new ArgumentNullException(nameof(verifiedSessionTransport));
        groups = groupTransport ?? verifiedSessionTransport as IGroupSyncTransport ?? new DisabledGroupSyncTransport();
        routes = verifiedSessionTransport as IGroupMailboxRouteSyncTransport ?? new DisabledGroupMailboxRouteSyncTransport();
        this.session = session ?? throw new ArgumentNullException(nameof(session));
        this.groupDispatchSafety = groupDispatchSafety;
        this.owner = owner ?? throw new ArgumentNullException(nameof(owner));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        if (ownsTransport)
        {
            asyncOwnedTransport = verifiedSessionTransport as IAsyncDisposable;
            ownedTransport = asyncOwnedTransport is null
                ? verifiedSessionTransport as IDisposable
                    ?? throw new ArgumentException("An owned MSG-01 transport must be disposable.", nameof(verifiedSessionTransport))
                : null;
        }
    }

    internal async Task PrepareDirectAsync(
        OutboundMessageEnvelope envelope,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        using var operation = Enter(cancellationToken);
        await deliveryGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            await PrepareDurableOutboundAsync(
                MessagePayloadKind.DirectMessage,
                envelope.Sender,
                ConversationId.ForOneToOne(envelope.Recipient).Value,
                (envelope.Id ?? throw new InvalidOperationException(
                    "MSG-01 requires a stable message id.")).Value,
                envelope.CreatedAt,
                envelope.ExpiresAt,
                Canonical(envelope),
                [envelope.Recipient],
                operation.Token).ConfigureAwait(false);
        }
        finally
        {
            deliveryGate.Release();
        }
    }

    internal async Task PrepareGroupAsync(
        OutboundGroupMessageEnvelope envelope,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        using var operation = Enter(cancellationToken);
        await deliveryGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            var recipients = (envelope.NotifyRecipients ?? [])
                .Where(recipient => recipient != envelope.Sender)
                .Distinct()
                .ToArray();
            await PrepareDurableOutboundAsync(
                MessagePayloadKind.GroupMessage,
                envelope.Sender,
                envelope.GroupId.Value,
                envelope.Id.Value,
                envelope.CreatedAt,
                envelope.ExpiresAt,
                CanonicalGroupMessage(envelope.Id, envelope.GroupId, envelope.Sender,
                    envelope.Body, envelope.Attachments, envelope.CreatedAt,
                    envelope.ExpiresAt, envelope.ReplyTo, envelope.Reaction),
                recipients,
                operation.Token).ConfigureAwait(false);
        }
        finally
        {
            deliveryGate.Release();
        }
    }

    public async Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        using var operation = Enter(cancellationToken);
        await deliveryGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            EnsureRecoveryStarted(envelope.Sender);
            var canonical = Canonical(envelope);
            var dispatch = await PrepareOutboundAsync(MessagePayloadKind.DirectMessage, envelope.Sender,
                ConversationId.ForOneToOne(envelope.Recipient).Value,
                (envelope.Id ?? throw new InvalidOperationException("MSG-01 requires a stable message id.")).Value,
                envelope.CreatedAt, envelope.ExpiresAt, canonical, [envelope.Recipient], operation.Token).ConfigureAwait(false);
            EnsureCallerVisibleOutcome(
                (await DispatchToStableAsync(dispatch, operation.Token).ConfigureAwait(false)).Snapshot);
        }
        finally
        {
            deliveryGate.Release();
        }
    }

    public async Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default)
    {
        using var operation = Enter(cancellationToken);
        EnsureRecoveryStarted(recipient);
        var envelopes = await inbound.ReceiveAsync(recipient, operation.Token).ConfigureAwait(false);
        foreach (var envelope in envelopes)
            await MaterializeInboundAsync(recipient, envelope.Sender,
                ConversationId.ForOneToOne(envelope.Sender == recipient ? envelope.Recipient : envelope.Sender).Value,
                envelope.Id.Value, envelope.ServerHash, Canonical(envelope), operation.Token).ConfigureAwait(false);
        return envelopes;
    }

    public async Task PublishGroupStateAsync(Group group, DateTimeOffset updatedAt,
        IEnumerable<SessionId>? recipients = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(group);
        using var operation = Enter(cancellationToken);
        var local = await session.GetLocalAccountAsync(operation.Token).ConfigureAwait(false);
        await deliveryGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            EnsureRecoveryStarted(local);
            var targetAccounts = (recipients ?? group.Members.Select(static member => member.SessionId))
                .Where(recipient => recipient != local).Distinct().ToArray();
            var canonical = Canonical(new GroupStatePayload(group, updatedAt));
            var dispatch = await PrepareOutboundAsync(MessagePayloadKind.GroupState, local, group.Id.Value,
                $"group-state:{group.Revision}", updatedAt, null, canonical, targetAccounts, operation.Token).ConfigureAwait(false);
            EnsureCallerVisibleOutcome(
                (await DispatchToStableAsync(dispatch, operation.Token).ConfigureAwait(false)).Snapshot);
        }
        finally
        {
            deliveryGate.Release();
        }
    }

    public async Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(SessionId member, CancellationToken cancellationToken = default)
    {
        using var operation = Enter(cancellationToken);
        EnsureRecoveryStarted(member);
        var envelopes = await groups.ReceiveGroupStatesAsync(member, operation.Token).ConfigureAwait(false);
        foreach (var envelope in envelopes)
            await MaterializeInboundAsync(member, envelope.Sender, envelope.Group.Id.Value,
                $"group-state:{envelope.Group.Revision}", envelope.ServerHash,
                Canonical(new GroupStatePayload(envelope.Group, envelope.UpdatedAt)), operation.Token).ConfigureAwait(false);
        return envelopes;
    }

    public async Task SendGroupMessageAsync(OutboundGroupMessageEnvelope envelope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        using var operation = Enter(cancellationToken);
        await deliveryGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            EnsureRecoveryStarted(envelope.Sender);
            var recipients = (envelope.NotifyRecipients ?? []).Where(recipient => recipient != envelope.Sender).Distinct().ToArray();
            var dispatch = await PrepareOutboundAsync(MessagePayloadKind.GroupMessage, envelope.Sender,
                envelope.GroupId.Value, envelope.Id.Value, envelope.CreatedAt, envelope.ExpiresAt,
                CanonicalGroupMessage(envelope.Id, envelope.GroupId, envelope.Sender, envelope.Body,
                    envelope.Attachments, envelope.CreatedAt, envelope.ExpiresAt, envelope.ReplyTo,
                    envelope.Reaction), recipients, operation.Token).ConfigureAwait(false);
            EnsureCallerVisibleOutcome(
                (await DispatchToStableAsync(dispatch, operation.Token).ConfigureAwait(false)).Snapshot);
        }
        finally
        {
            deliveryGate.Release();
        }
    }

    public async Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(ConversationId groupId, CancellationToken cancellationToken = default)
    {
        using var operation = Enter(cancellationToken);
        var account = await session.GetLocalAccountAsync(operation.Token).ConfigureAwait(false);
        EnsureRecoveryStarted(account);
        var envelopes = await groups.ReceiveGroupMessagesAsync(groupId, operation.Token).ConfigureAwait(false);
        await MaterializeGroupBatchAsync(account, envelopes, operation.Token).ConfigureAwait(false);
        return envelopes;
    }

    public async Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveKnownGroupMessagesAsync(
        SessionId account, IReadOnlyCollection<ConversationId> groupIds, CancellationToken cancellationToken = default)
    {
        using var operation = Enter(cancellationToken);
        EnsureRecoveryStarted(account);
        var receiver = groups as IKnownGroupInboxReceiver
            ?? throw new InvalidOperationException("The verified MSG-01 session has no bounded known-group receiver.");
        var envelopes = await receiver.ReceiveKnownGroupMessagesAsync(account, groupIds, operation.Token).ConfigureAwait(false);
        await MaterializeGroupBatchAsync(account, envelopes, operation.Token).ConfigureAwait(false);
        return envelopes;
    }

    public async Task<int> DiscardUnknownGroupMessagesAsync(SessionId account,
        IReadOnlyCollection<ConversationId> knownGroupIds, CancellationToken cancellationToken = default)
    {
        using var operation = Enter(cancellationToken);
        return groups is IGroupInboxMaintenance maintenance
            ? await maintenance.DiscardUnknownGroupMessagesAsync(account, knownGroupIds, operation.Token).ConfigureAwait(false)
            : 0;
    }

    public async Task PublishGroupMailboxRoutesAsync(GroupMailboxRouteBundle bundle, DateTimeOffset updatedAt,
        IEnumerable<SessionId> recipients, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        using var operation = Enter(cancellationToken);
        var local = await session.GetLocalAccountAsync(operation.Token).ConfigureAwait(false);
        await deliveryGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            EnsureRecoveryStarted(local);
            var targetAccounts = recipients.Where(recipient => recipient != local).Distinct().ToArray();
            var canonical = Canonical(new GroupRoutesPayload(bundle, updatedAt));
            var dispatch = await PrepareOutboundAsync(MessagePayloadKind.GroupMailboxRoutes, local,
                bundle.GroupId.Value, $"group-routes:{bundle.GroupRevision}", updatedAt, null,
                canonical, targetAccounts, operation.Token).ConfigureAwait(false);
            EnsureCallerVisibleOutcome(
                (await DispatchToStableAsync(dispatch, operation.Token).ConfigureAwait(false)).Snapshot);
        }
        finally
        {
            deliveryGate.Release();
        }
    }

    public async Task<IReadOnlyList<InboundGroupMailboxRouteEnvelope>> ReceiveGroupMailboxRoutesAsync(SessionId member, CancellationToken cancellationToken = default)
    {
        using var operation = Enter(cancellationToken);
        EnsureRecoveryStarted(member);
        var envelopes = await routes.ReceiveGroupMailboxRoutesAsync(member, operation.Token).ConfigureAwait(false);
        foreach (var envelope in envelopes)
            await MaterializeInboundAsync(member, envelope.Sender, envelope.Bundle.GroupId.Value,
                $"group-routes:{envelope.Bundle.GroupRevision}", envelope.ServerHash,
                Canonical(new GroupRoutesPayload(envelope.Bundle, envelope.IssuedAt)), operation.Token).ConfigureAwait(false);
        return envelopes;
    }

    public async Task AcknowledgeInboxItemAsync(SessionId account, string serverHash, CancellationToken cancellationToken = default)
    {
        using var operation = Enter(cancellationToken);
        var composition = owner.TryGetActiveForAccount(account);
        if (composition is null) return;
        var receiptId = MessageReceiptId32.FromBytes(Hash("receipt", serverHash));
        var recoveryOwner = RecoveryOwner(account);
        var now = CanonicalTime(clock.UtcNow);
        var receipt = await composition.Store.ClaimPendingReceiptAsync(receiptId, recoveryOwner, now, operation.Token).ConfigureAwait(false);
        if (receipt is null) return;
        await session.AcknowledgeReceiptAsync(receipt.AuthenticatedReceipt, operation.Token).ConfigureAwait(false);
        var result = await composition.Store.CompletePendingReceiptAsync(receiptId, recoveryOwner,
            CanonicalTime(clock.UtcNow), operation.Token).ConfigureAwait(false);
        if (result is not (MessageCommitResult.Applied or MessageCommitResult.Idempotent))
            throw new InvalidOperationException("MSG-01 could not commit the durable ACK intent.");
    }

    Task<MailboxAckCorrelationProjection?> IMailboxAckCorrelationProjectionSource.ProjectMailboxAckCorrelationAsync(
        SessionId account, string serverHash, CancellationToken cancellationToken) =>
        ProjectMailboxAckCorrelationOwnedAsync(account, serverHash, cancellationToken);

    internal async Task<int> RecoverNowAsync(
        SessionId account, CancellationToken cancellationToken)
    {
        using var operation = Enter(cancellationToken);
        EnsureRecoveryStarted(account);
        return await RecoverOnceAsync(account, operation.Token).ConfigureAwait(false);
    }

    internal async ValueTask<Msg01GroupDispatchResult> DispatchDurableGroupAsync(
        SharedMessagingV1Composition composition,
        LogicalOutboxSnapshot head,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(composition);
        ArgumentNullException.ThrowIfNull(head);
        using var operation = Enter(cancellationToken);
        await deliveryGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            if (head.PayloadKind != MessagePayloadKind.GroupMessage || !IsCanonicalDgm1(head))
            {
                throw new InvalidDataException(
                    "The GROUP-CLIENT-01 dispatch entry point accepts only exact DGM1 outboxes.");
            }

            var prepared = await EnsureFanoutAndAttemptsAsync(
                composition, head, null, prepareAttempts: true, operation.Token)
                .ConfigureAwait(false);
            var dispatched = await DispatchToStableAsync(
                new(composition, prepared.Head, prepared.FreshAttemptIds), operation.Token)
                .ConfigureAwait(false);
            return new(dispatched.Snapshot, dispatched.GroupBlocks);
        }
        finally
        {
            deliveryGate.Release();
        }
    }

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    public async ValueTask DisposeAsync()
    {
        Task drain;
        Task? worker;
        lock (lifecycleGate)
        {
            if (accepting)
            {
                accepting = false;
                shutdown.Cancel();
                if (activeOperations == 0) drained.TrySetResult(true);
            }
            drain = drained.Task;
            worker = recoveryTask;
        }
        if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0)
        {
            await disposalCompletion.Task.ConfigureAwait(false);
            return;
        }
        try
        {
            await drain.ConfigureAwait(false);
            if (worker is not null)
            {
                try { await worker.ConfigureAwait(false); }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
            await owner.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            disposalCompletion.TrySetException(exception);
            throw;
        }
        finally
        {
            try
            {
                if (asyncOwnedTransport is not null) await asyncOwnedTransport.DisposeAsync().ConfigureAwait(false);
                else ownedTransport?.Dispose();
            }
            finally
            {
                sessionMutationGate.Dispose(); deliveryGate.Dispose(); recoveryGate.Dispose(); shutdown.Dispose();
                disposalCompletion.TrySetResult(true);
            }
        }
    }

    private async Task<PreparedDispatch> PrepareOutboundAsync(MessagePayloadKind kind, SessionId localAccount,
        string conversation, string semanticMessage, DateTimeOffset createdAt, DateTimeOffset? expiresAt,
        byte[] canonical, IReadOnlyList<SessionId> recipients, CancellationToken cancellationToken)
    {
        var begun = await BeginOutboundHeadAsync(kind, localAccount, conversation,
            semanticMessage, createdAt, expiresAt, canonical, cancellationToken).ConfigureAwait(false);
        var prepared = await EnsureFanoutAndAttemptsAsync(
            begun.Composition, begun.Head, recipients, prepareAttempts: true,
            cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        return new(begun.Composition, prepared.Head, prepared.FreshAttemptIds);
    }

    private async Task PrepareDurableOutboundAsync(MessagePayloadKind kind, SessionId localAccount,
        string conversation, string semanticMessage, DateTimeOffset createdAt, DateTimeOffset? expiresAt,
        byte[] canonical, IReadOnlyList<SessionId> recipients, CancellationToken cancellationToken)
    {
        var begun = await BeginOutboundHeadAsync(kind, localAccount, conversation,
            semanticMessage, createdAt, expiresAt, canonical, cancellationToken).ConfigureAwait(false);
        _ = await EnsureFanoutAndAttemptsAsync(
            begun.Composition, begun.Head, recipients, prepareAttempts: false,
            cancellationToken: cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<OutboundHead> BeginOutboundHeadAsync(MessagePayloadKind kind,
        SessionId localAccount, string conversation, string semanticMessage,
        DateTimeOffset createdAt, DateTimeOffset? expiresAt, byte[] canonical,
        CancellationToken cancellationToken)
    {
        var composition = owner.OpenForAccount(localAccount);
        var store = composition.Store;
        var authorDevice = MessagingDeviceId32.FromBytes(Hash("device", localAccount.Value));
        var conversationId = ConversationId32.FromBytes(Hash("conversation", conversation));
        var semanticId = SemanticMessageId32.FromBytes(Hash("semantic", semanticMessage));
        var eventHash = MessageEventHash32.FromBytes(SHA256.HashData(canonical));
        createdAt = CanonicalTime(createdAt);
        var boundedExpiry = CanonicalTime(expiresAt ?? createdAt.AddDays(7));
        if (boundedExpiry <= createdAt || boundedExpiry - createdAt > MessagingV1Limits.MaxEventLifetime)
            boundedExpiry = createdAt.AddDays(7);
        var seed = LogicalOutboxSeed.CreateOutbound(store.Scope, authorDevice, conversationId, semanticId,
            eventHash, canonical, createdAt, boundedExpiry, kind);
        var claim = new SemanticClaimCandidate(store.Scope.LocalAccountId, authorDevice, conversationId, semanticId, eventHash);
        var begin = await store.BeginOutboundAsync(MessageMutationId32.FromBytes(Hash("begin", Convert.ToHexString(eventHash.ToArray()))),
            claim, seed, cancellationToken).ConfigureAwait(false);
        var head = begin.Snapshot ?? await store.ReadAsync(seed.ClaimKey, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("MSG-01 outbound head is unavailable.");
        return new(composition, head);
    }

    private async Task<PreparedAttempts> EnsureFanoutAndAttemptsAsync(SharedMessagingV1Composition composition,
        LogicalOutboxSnapshot head, IReadOnlyList<SessionId>? initialRecipients,
        bool prepareAttempts, CancellationToken cancellationToken)
    {
        await sessionMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Another foreground operation or recovery pass may have advanced
            // this logical head while the caller waited for the ratchet gate.
            head = await composition.Store.ReadAsync(head.ClaimKey, cancellationToken)
                .ConfigureAwait(false) ?? throw new InvalidOperationException(
                    "MSG-01 outbound head disappeared before attempt preparation.");
            if (head.State is LogicalOutboxState.Accepted or
                LogicalOutboxState.RecipientMaterialized or
                LogicalOutboxState.Expired or
                LogicalOutboxState.Cancelled or
                LogicalOutboxState.TerminalRejected)
                return new(head, new HashSet<TransportAttemptId16>());

            var plans = new List<TargetAttemptPlan>();
            if (head.State == LogicalOutboxState.Queued)
            {
                var recipients = (initialRecipients
                        ?? RecipientsFromPayload(head.PayloadKind, head.CanonicalPayload))
                    .Where(recipient => !Target(recipient).AccountId.Equals(head.LocalAccountId))
                    .Distinct()
                    .ToArray();
                if (recipients.Length == 0)
                    throw new InvalidOperationException("MSG-01 requires at least one recipient target.");
                var fanout = new List<FanoutTargetSeed>();
                foreach (var recipient in recipients)
                {
                    var target = Target(recipient);
                    var operationId = MessageTargetOperationId32.FromBytes(Hash("target-operation", ClaimText(head.ClaimKey) + "\0" + recipient.Value));
                    var bindingHash = MessageBindingHash32.FromBytes(Hash("binding", Convert.ToHexString(head.EventHash.ToArray()) + "\0" + recipient.Value));
                    var directoryHead = await session.ResolveFanoutTargetAsync(
                        new Msg01ResolveFanoutTargetRequest(head.PayloadKind, head.StoreScope,
                            head.ClaimKey, target, operationId, bindingHash),
                        cancellationToken).ConfigureAwait(false);
                    fanout.Add(new FanoutTargetSeed(target, directoryHead, operationId, bindingHash));
                }
                head = (await composition.Store.ApplyAsync(PreparedMessageMutation.PrepareFanout(head,
                    MessageMutationId32.FromBytes(Hash("fanout", ClaimText(head.ClaimKey))), fanout, SafeNow(head)),
                    cancellationToken).ConfigureAwait(false)).Snapshot
                    ?? throw new InvalidOperationException("MSG-01 fanout preparation failed.");
            }
            if (!prepareAttempts)
                return new(head, new HashSet<TransportAttemptId16>());
            if (head.State is LogicalOutboxState.FanoutPrepared or LogicalOutboxState.PartiallyAccepted)
            {
                foreach (var target in head.Targets.Where(target => target.State == LogicalTargetState.Pending
                             && target.ActiveAttemptId is null
                             && plans.All(plan => !plan.Target.Equals(target.Target))))
                {
                    var attemptId = TransportAttemptId16.FromBytes(RandomNumberGenerator.GetBytes(16));
                    var prepared = await session.PrepareAttemptAsync(new Msg01PrepareAttemptRequest(head.PayloadKind,
                        head.StoreScope, head.ClaimKey, target.Target, attemptId, target.OperationId!, target.BindingHash!,
                        head.CanonicalPayload), cancellationToken).ConfigureAwait(false);
                    if (!prepared.DirectoryHeadHash.Equals(target.DirectoryHeadHash))
                        throw new CryptographicException("Verified directory head changed after durable fanout binding.");
                    plans.Add(new TargetAttemptPlan(target.Target, attemptId, prepared.RequestHash,
                        prepared.RatchetBeforeHash, prepared.RatchetAfterHash, prepared.DirectoryHeadHash,
                        target.OperationId!, target.BindingHash!, prepared.Ciphertext.Span));
                }
                if (plans.Count > 0)
                {
                    var operationBytes = plans.SelectMany(static plan => plan.AttemptId.ToArray()).ToArray();
                    head = (await composition.Store.ApplyAsync(PreparedMessageMutation.StartSending(head,
                        MessageMutationId32.FromBytes(SHA256.HashData(operationBytes)), plans, SafeNow(head)),
                        cancellationToken).ConfigureAwait(false)).Snapshot
                        ?? throw new InvalidOperationException("MSG-01 prepared attempts were not committed.");
                }
            }
            return new(head, plans.Select(static plan => plan.AttemptId).ToHashSet());
        }
        finally
        {
            sessionMutationGate.Release();
        }
    }

    private async Task<DispatchPassResult> DispatchToStableAsync(PreparedDispatch dispatch,
        CancellationToken cancellationToken)
    {
        var head = dispatch.Head;
        if (head.State is LogicalOutboxState.Accepted or LogicalOutboxState.RecipientMaterialized)
            return new(head, []);
        var groupBlocks = new List<Msg01GroupFirstDispatchBlock>();
        var targets = head.Targets.Where(static target => target.ActiveAttemptId is not null)
            .Select(static target => target.Target).ToArray();
        foreach (var targetIdentity in targets)
        {
            var target = head.Targets.SingleOrDefault(item => item.Target.Equals(targetIdentity));
            if (target?.ActiveAttemptId is null) continue;
            var request = new Msg01DispatchEvidenceRequest(head.PayloadKind, head, target);
            var fresh = dispatch.FreshAttemptIds.Contains(target.ActiveAttemptId);
            Msg01AuthenticatedDispatchResult result;
            if (target.LastAttemptId is null && IsCanonicalDgm1(head))
            {
                var firstDispatch = await DispatchFirstGroupAttemptAsync(
                    dispatch.Composition, head, target, request, fresh, cancellationToken)
                    .ConfigureAwait(false);
                if (firstDispatch.Result is null)
                {
                    head = firstDispatch.BlockedSnapshot
                        ?? throw new InvalidDataException(
                            "The GroupV1 safety block was not committed durably.");
                    groupBlocks.Add(new(
                        new RecipientDeviceTarget(target.Target.AccountId, target.Target.DeviceId),
                        firstDispatch.Disposition));
                    continue;
                }
                result = firstDispatch.Result;
            }
            else
            {
                // Retries after one authenticated resolution deliberately do
                // not hold the GroupV1 head lease. A recovered never-resolved
                // first attempt is reauthorized above before reconciliation.
                result = fresh
                    ? await session.DispatchPreparedAsync(request, cancellationToken).ConfigureAwait(false)
                    : await session.ReconcilePreparedAsync(request, cancellationToken).ConfigureAwait(false);
            }
            var purpose = result.OutcomeUnknown
                ? MessageEvidencePurpose.AttemptUncertainty
                : fresh ? MessageEvidencePurpose.TargetOutcome
                    : MessageEvidencePurpose.AttemptReconciliation;
            var context = Context(purpose, head, target, result.Outcome, result.ReplayCounter, result.ReplayNonce.Span);
            PreparedMessageMutation mutation;
            if (result.OutcomeUnknown)
            {
                var uncertainty = dispatch.Composition.VerifiedTransport.VerifyAttemptUncertainty(context, result.AuthenticatedEvidence.Span);
                mutation = PreparedMessageMutation.MarkOutcomeUnknown(head, uncertainty, SafeNow(head));
            }
            else if (!fresh)
            {
                var reconciliation = dispatch.Composition.VerifiedTransport.VerifyReconciliation(
                    context, result.AuthenticatedEvidence.Span);
                mutation = PreparedMessageMutation.ReconcileOutcomeUnknown(
                    head, reconciliation, SafeNow(head));
            }
            else
            {
                var outcome = dispatch.Composition.VerifiedTransport.VerifyTargetOutcome(context, result.AuthenticatedEvidence.Span);
                mutation = PreparedMessageMutation.FromVerifiedOutcome(head, outcome, SafeNow(head));
            }
            head = (await dispatch.Composition.Store.ApplyAsync(mutation, cancellationToken).ConfigureAwait(false)).Snapshot
                ?? throw new InvalidOperationException("MSG-01 authenticated target result was not committed.");
        }
        return new(head, groupBlocks);
    }

    private async ValueTask<FirstGroupAttemptResult> DispatchFirstGroupAttemptAsync(
        SharedMessagingV1Composition composition,
        LogicalOutboxSnapshot head,
        LogicalTargetSnapshot target,
        Msg01DispatchEvidenceRequest request,
        bool fresh,
        CancellationToken cancellationToken)
    {
        var safety = groupDispatchSafety ?? throw new InvalidOperationException(
            GroupMessageDispatchSafetyCompositionStatus.Blocker);
        Msg01AuthenticatedDispatchResult? authenticated = null;
        LogicalOutboxSnapshot? blockedSnapshot = null;
        var decision = await safety.DispatchFirstAsync(
            head,
            target,
            composition.Store,
            composition.GroupDispatchSafety,
            SafeNow(head),
            async (context, callbackToken) =>
            {
                DemandExactFirstDispatchContext(context, request, head);
                authenticated = fresh
                    ? await session.DispatchPreparedAsync(request, callbackToken).ConfigureAwait(false)
                    : await session.ReconcilePreparedAsync(request, callbackToken).ConfigureAwait(false);
            },
            cancellationToken).ConfigureAwait(false);
        blockedSnapshot = decision.BlockedSnapshot;

        return decision.Disposition switch
        {
            GroupMessageFirstDispatchDisposition.Dispatched when authenticated is not null =>
                new(decision.Disposition, authenticated, null),
            GroupMessageFirstDispatchDisposition.GroupNotFound or
            GroupMessageFirstDispatchDisposition.StaleGroupState or
            GroupMessageFirstDispatchDisposition.ForkLatched or
            GroupMessageFirstDispatchDisposition.TargetRemoved when blockedSnapshot is not null =>
                new(decision.Disposition, null, blockedSnapshot),
            GroupMessageFirstDispatchDisposition.GroupNotFound or
            GroupMessageFirstDispatchDisposition.StaleGroupState or
            GroupMessageFirstDispatchDisposition.ForkLatched or
            GroupMessageFirstDispatchDisposition.TargetRemoved =>
                throw new InvalidDataException(
                    "The GroupV1 safety boundary returned a block without durable state."),
            GroupMessageFirstDispatchDisposition.Dispatched =>
                throw new InvalidDataException(
                    "The GroupV1 first-dispatch boundary completed without a transport result."),
            GroupMessageFirstDispatchDisposition.NoTarget or
            GroupMessageFirstDispatchDisposition.NotFirstDispatch =>
                throw new InvalidDataException(
                    "The durable DGM1 first-attempt snapshot changed before authorization."),
            _ => throw new InvalidDataException("Unknown GroupV1 first-dispatch disposition."),
        };
    }

    private static void DemandExactFirstDispatchContext(
        GroupMessageFirstDispatchContext context,
        Msg01DispatchEvidenceRequest request,
        LogicalOutboxSnapshot head)
    {
        var canonical = context.CanonicalDgm1.ToArray();
        var ciphertext = context.Ciphertext.ToArray();
        var requestCiphertext = request.Ciphertext.ToArray();
        var headCanonical = head.CanonicalPayload;
        try
        {
            if (!context.StoreScope.Equals(request.Scope)
                || !context.ClaimKey.Equals(request.ClaimKey)
                || context.ClaimKey.AuthorDeviceId is null
                || request.ClaimKey.AuthorDeviceId is null
                || !context.ClaimKey.AuthorDeviceId.Equals(request.ClaimKey.AuthorDeviceId)
                || !context.EventHash.Equals(request.EnvelopeHash)
                || !context.Target.Equals(request.Target)
                || !context.DirectoryHeadHash.Equals(
                    head.Targets.Single(candidate => candidate.Target.Equals(request.Target))
                        .DirectoryHeadHash)
                || !context.OperationId.Equals(request.OperationId)
                || !context.BindingHash.Equals(request.BindingHash)
                || !context.AttemptId.Equals(request.AttemptId)
                || !context.RequestHash.Equals(request.RequestHash)
                || !context.RatchetBeforeHash.Equals(request.RatchetBeforeHash)
                || !context.RatchetTransitionHash.Equals(request.RatchetAfterHash)
                || context.OutboxRevision != head.Revision
                || !canonical.AsSpan().SequenceEqual(headCanonical)
                || !ciphertext.AsSpan().SequenceEqual(requestCiphertext))
            {
                throw new InvalidDataException(
                    "The GroupV1 lease context is not the exact durable MSG-01 attempt.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(requestCiphertext);
            CryptographicOperations.ZeroMemory(headCanonical);
        }
    }

    private static bool IsCanonicalDgm1(LogicalOutboxSnapshot head)
    {
        if (head.PayloadKind != MessagePayloadKind.GroupMessage)
            return false;
        var canonical = head.CanonicalPayload;
        try
        {
            return canonical.Length >= 4 && canonical.AsSpan(0, 4).SequenceEqual("DGM1"u8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    private async Task<int> RecoverOnceAsync(SessionId account, CancellationToken cancellationToken)
    {
        await recoveryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var deliveryEntered = false;
        try
        {
            // Foreground prepare+dispatch and recovery reconciliation are one
            // ownership lane. Recovery must never reconcile an attempt while
            // its original dispatch is still in flight.
            await deliveryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            deliveryEntered = true;
            var composition = owner.OpenForAccount(account);
            var now = CanonicalTime(clock.UtcNow);
            var recoveryOwner = RecoveryOwner(account);
            var items = await composition.Store.ClaimRecoveryAsync(recoveryOwner, now,
                MessagingV1Limits.MaxRecoveryBatch, cancellationToken).ConfigureAwait(false);
            foreach (var item in items)
            {
                try
                {
                    var head = item.Snapshot;
                    // A persisted active attempt may have reached ingress before the
                    // process died, even when the local OutcomeUnknown mutation did
                    // not commit. Reconcile it first; never blindly redispatch it.
                    if (head.Targets.Any(static target => target.ActiveAttemptId is not null))
                    {
                        head = (await DispatchToStableAsync(
                            new(composition, head, new HashSet<TransportAttemptId16>()), cancellationToken)
                            .ConfigureAwait(false)).Snapshot;
                    }

                    if (head.Targets.Any(static target => target.ActiveAttemptId is not null))
                        continue;

                    if (head.State is not (LogicalOutboxState.Accepted
                        or LogicalOutboxState.RecipientMaterialized
                        or LogicalOutboxState.Expired
                        or LogicalOutboxState.Cancelled
                        or LogicalOutboxState.TerminalRejected))
                    {
                        // Authenticated NotAccepted reconciliation clears the old
                        // attempt. Only then may recovery allocate and dispatch a
                        // fresh attempt for that target.
                        var prepared = await EnsureFanoutAndAttemptsAsync(
                            composition, head, null, prepareAttempts: true,
                            cancellationToken: cancellationToken).ConfigureAwait(false);
                        _ = await DispatchToStableAsync(
                            new(composition, prepared.Head, prepared.FreshAttemptIds), cancellationToken)
                            .ConfigureAwait(false);
                    }
                }
                catch (Exception exception) when (exception is not OperationCanceledException) { }
            }
            var receipts = await composition.Store.ClaimPendingReceiptsAsync(recoveryOwner, now,
                MessagingV1Limits.MaxRecoveryBatch, cancellationToken).ConfigureAwait(false);
            foreach (var receipt in receipts)
            {
                try
                {
                    await session.AcknowledgeReceiptAsync(receipt.AuthenticatedReceipt, cancellationToken).ConfigureAwait(false);
                    await composition.Store.CompletePendingReceiptAsync(receipt.ReceiptId, recoveryOwner,
                        CanonicalTime(clock.UtcNow), cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is not OperationCanceledException) { }
            }
            return items.Count + receipts.Count;
        }
        finally
        {
            if (deliveryEntered) deliveryGate.Release();
            recoveryGate.Release();
        }
    }

    private void EnsureRecoveryStarted(SessionId account)
    {
        lock (lifecycleGate)
        {
            if (!accepting) throw new ObjectDisposedException(nameof(Msg01AuthoritativeTransport));
            if (activeAccount is not null && activeAccount.Value.Value != account.Value)
                throw new InvalidOperationException("MSG-01 recovery is already bound to another account.");
            activeAccount = account;
            recoveryTask ??= Task.Run(() => RecoveryLoopAsync(account, shutdown.Token));
        }
    }

    private async Task RecoveryLoopAsync(SessionId account, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(RecoveryPeriod);
        do
        {
            try { _ = await RecoverOnceAsync(account, cancellationToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
        }
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
    }

    private async Task MaterializeGroupBatchAsync(SessionId account,
        IReadOnlyList<InboundGroupMessageEnvelope> envelopes, CancellationToken cancellationToken)
    {
        foreach (var envelope in envelopes)
            await MaterializeInboundAsync(account, envelope.Sender, envelope.GroupId.Value, envelope.Id.Value,
                envelope.ServerHash, Canonical(envelope), cancellationToken).ConfigureAwait(false);
    }

    private async Task<MailboxAckCorrelationProjection?> ProjectMailboxAckCorrelationOwnedAsync(
        SessionId account, string serverHash, CancellationToken cancellationToken)
    {
        using var operation = Enter(cancellationToken);
        return inbound is IMailboxAckCorrelationProjectionSource source
            ? await source.ProjectMailboxAckCorrelationAsync(
                account, serverHash, operation.Token).ConfigureAwait(false)
            : null;
    }

    private async Task MaterializeInboundAsync(SessionId localAccount, SessionId author, string conversation,
        string semanticMessage, string serverHash, byte[] canonical, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(author.Value)) throw new CryptographicException("MSG-01 inbound author is missing.");
        var composition = owner.OpenForAccount(localAccount);
        var store = composition.Store;
        var claim = new SemanticClaimCandidate(MessagingAccountId32.FromBytes(Hash("account", author.Value)),
            MessagingDeviceId32.FromBytes(Hash("device", author.Value)),
            ConversationId32.FromBytes(Hash("conversation", conversation)),
            SemanticMessageId32.FromBytes(Hash("semantic", semanticMessage)),
            MessageEventHash32.FromBytes(SHA256.HashData(canonical)));
        await sessionMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Re-check under the ratchet gate. Concurrent receives of the same
            // exact envelope must never ask the crypto session to advance twice.
            var existing = await store.ReadInboxAsync(claim.Key, cancellationToken).ConfigureAwait(false);
            if (existing is not null && existing.EventHash.Equals(claim.EventHash)) return;
            var receiptId = MessageReceiptId32.FromBytes(Hash("receipt", serverHash));
            var authenticated = await session.GetInboundResultAsync(
                new Msg01InboundEvidenceRequest(store.Scope, claim, receiptId, canonical), cancellationToken).ConfigureAwait(false);
            var context = new MessageCapabilityTrustedContext(MessageEvidencePurpose.InboundMaterialization,
                store.Scope, claim.Key, receiptId: receiptId, requestHash: SHA256.HashData(canonical),
                envelopeHash: claim.EventHash.ToArray(), ratchetBeforeHash: authenticated.BeforeHash.ToArray(),
                ratchetAfterHash: authenticated.AfterHash.ToArray(), replayCounter: authenticated.ReplayCounter,
                replayNonce: authenticated.ReplayNonce.ToArray(), ratchetSessionId: authenticated.SessionId);
            var request = composition.VerifiedTransport.VerifyInbound(context, claim, canonical,
                authenticated.SessionId, authenticated.BeforeHash, authenticated.AfterHash,
                authenticated.SealedRatchetState.Span, CanonicalTime(clock.UtcNow), authenticated.AuthenticatedEvidence.Span);
            _ = await store.MaterializeInboundAsync(request, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException("MSG-01 inbound materialization did not commit.");
        }
        finally
        {
            sessionMutationGate.Release();
        }
    }

    private static MessageCapabilityTrustedContext Context(MessageEvidencePurpose purpose,
        LogicalOutboxSnapshot head, LogicalTargetSnapshot target, VerifiedTargetOutcomeKind? outcome,
        ulong replayCounter, ReadOnlySpan<byte> replayNonce) => new(purpose, head.StoreScope, head.ClaimKey,
            target.Target, target.ActiveAttemptId!, outcome, targetOperationId: target.OperationId,
            bindingHash: target.BindingHash, requestHash: target.RequestHash!.ToArray(),
            envelopeHash: head.EventHash.ToArray(), ratchetBeforeHash: target.RatchetBeforeHash!.ToArray(),
            ratchetAfterHash: target.RatchetTransitionHash!.ToArray(), replayCounter: replayCounter,
            replayNonce: replayNonce.ToArray());

    private static IReadOnlyList<SessionId> RecipientsFromPayload(MessagePayloadKind kind, byte[] payload) => kind switch
    {
        MessagePayloadKind.DirectMessage => [Deserialize<DirectPayload>(payload).Recipient],
        MessagePayloadKind.GroupMessage => throw new InvalidDataException(
            "A queued group message without durable fanout targets cannot be recovered."),
        MessagePayloadKind.GroupState => Deserialize<GroupStatePayload>(payload).Group.Members
            .Select(static member => member.SessionId).ToArray(),
        MessagePayloadKind.GroupMailboxRoutes => Deserialize<GroupRoutesPayload>(payload).Bundle.Invitations
            .Select(static invitation => invitation.Member).ToArray(),
        _ => throw new InvalidDataException("Unknown durable MSG-01 payload kind.")
    };

    private static T Deserialize<T>(byte[] payload) => JsonSerializer.Deserialize<T>(payload)
        ?? throw new InvalidDataException("Durable MSG-01 canonical payload is malformed.");

    private static byte[] Canonical(OutboundMessageEnvelope envelope) => Canonical(new DirectPayload(
        envelope.Id ?? throw new InvalidOperationException("MSG-01 requires a stable message id."),
        envelope.Sender, envelope.Recipient, envelope.Body, envelope.Attachments,
        envelope.CreatedAt, envelope.ExpiresAt, envelope.ReplyTo, envelope.Reaction));
    private static byte[] Canonical(InboundMessageEnvelope envelope) => Canonical(new DirectPayload(
        envelope.Id, envelope.Sender, envelope.Recipient, envelope.Body, envelope.Attachments,
        envelope.CreatedAt, envelope.ExpiresAt, envelope.ReplyTo, envelope.Reaction));
    private static byte[] Canonical(InboundGroupMessageEnvelope envelope) => CanonicalGroupMessage(
        envelope.Id, envelope.GroupId, envelope.Sender, envelope.Body, envelope.Attachments,
        envelope.CreatedAt, envelope.ExpiresAt, envelope.ReplyTo, envelope.Reaction);
    private static byte[] CanonicalGroupMessage(MessageId id, ConversationId groupId, SessionId sender,
        string body, IReadOnlyList<AttachmentMetadata> attachments, DateTimeOffset createdAt,
        DateTimeOffset? expiresAt, MessageReply? replyTo, MessageReactionUpdate? reaction) =>
        Canonical(new GroupMessagePayload(id, groupId, sender, body, attachments, createdAt,
            expiresAt, replyTo, reaction));
    private static RecipientDeviceTarget Target(SessionId recipient) => new(
        MessagingAccountId32.FromBytes(Hash("account", recipient.Value)),
        MessagingDeviceId32.FromBytes(Hash("device", recipient.Value)));
    private static MessageRecoveryOwnerId16 RecoveryOwner(SessionId account) =>
        MessageRecoveryOwnerId16.FromBytes(Hash("recovery-owner", account.Value)[..16]);

    private static byte[] Canonical<T>(T value)
    {
        var canonical = JsonSerializer.SerializeToUtf8Bytes(value);
        if (canonical.Length is 0 or > MessagingV1Limits.MaxCanonicalEventBytes)
            throw new InvalidOperationException("The MSG-01 canonical payload exceeds its bound.");
        return canonical;
    }

    private static string ClaimText(SemanticClaimKey key) => string.Concat(
        Convert.ToHexString(key.AuthorAccountId.ToArray()), Convert.ToHexString(key.ConversationId.ToArray()),
        Convert.ToHexString(key.SemanticMessageId.ToArray()));
    private static byte[] Hash(string domain, string value)
    {
        var bytes = Encoding.UTF8.GetBytes($"Deep/MSG-01/{domain}/v1\0{value}");
        try { return SHA256.HashData(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static DateTimeOffset CanonicalTime(DateTimeOffset value) =>
        DateTimeOffset.FromUnixTimeMilliseconds(value.ToUnixTimeMilliseconds());
    private DateTimeOffset SafeNow(LogicalOutboxSnapshot head) =>
        CanonicalTime(clock.UtcNow < head.CreatedAt ? head.CreatedAt : clock.UtcNow);

    private OperationLease Enter(CancellationToken callerToken)
    {
        lock (lifecycleGate)
        {
            if (!accepting) throw new ObjectDisposedException(nameof(Msg01AuthoritativeTransport));
            if (activeOperations++ == 0) drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        return new(this, CancellationTokenSource.CreateLinkedTokenSource(callerToken, shutdown.Token));
    }
    private void Exit()
    {
        lock (lifecycleGate) if (--activeOperations == 0) drained.TrySetResult(true);
    }
    private static TaskCompletionSource<bool> CompletedDrain()
    {
        var source = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.SetResult(true);
        return source;
    }
    private sealed class OperationLease(Msg01AuthoritativeTransport owner, CancellationTokenSource cancellation) : IDisposable
    {
        private int disposed;
        internal CancellationToken Token => cancellation.Token;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            cancellation.Dispose(); owner.Exit();
        }
    }
    private static void EnsureCallerVisibleOutcome(LogicalOutboxSnapshot head)
    {
        if (head.State is LogicalOutboxState.Accepted or LogicalOutboxState.RecipientMaterialized)
            return;
        if (head.State is LogicalOutboxState.Queued or LogicalOutboxState.FanoutPrepared
            or LogicalOutboxState.Sending or LogicalOutboxState.PartiallyAccepted
            or LogicalOutboxState.OutcomeUnknown)
            throw new Msg01DeliveryPendingException(head.State);
        throw new InvalidOperationException($"MSG-01 delivery reached terminal state '{head.State}'.");
    }

    private sealed record PreparedAttempts(
        LogicalOutboxSnapshot Head,
        IReadOnlySet<TransportAttemptId16> FreshAttemptIds);
    private sealed record OutboundHead(
        SharedMessagingV1Composition Composition,
        LogicalOutboxSnapshot Head);
    private sealed record PreparedDispatch(
        SharedMessagingV1Composition Composition,
        LogicalOutboxSnapshot Head,
        IReadOnlySet<TransportAttemptId16> FreshAttemptIds);
    private sealed record DispatchPassResult(
        LogicalOutboxSnapshot Snapshot,
        IReadOnlyList<Msg01GroupFirstDispatchBlock> GroupBlocks);
    private sealed record FirstGroupAttemptResult(
        GroupMessageFirstDispatchDisposition Disposition,
        Msg01AuthenticatedDispatchResult? Result,
        LogicalOutboxSnapshot? BlockedSnapshot);
    private sealed record DirectPayload(MessageId Id, SessionId Sender, SessionId Recipient, string Body,
        IReadOnlyList<AttachmentMetadata> Attachments, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt,
        MessageReply? ReplyTo, MessageReactionUpdate? Reaction);
    private sealed record GroupMessagePayload(MessageId Id, ConversationId GroupId, SessionId Sender, string Body,
        IReadOnlyList<AttachmentMetadata> Attachments, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt,
        MessageReply? ReplyTo, MessageReactionUpdate? Reaction);
    private sealed record GroupStatePayload(Group Group, DateTimeOffset UpdatedAt);
    private sealed record GroupRoutesPayload(GroupMailboxRouteBundle Bundle, DateTimeOffset UpdatedAt);
}
