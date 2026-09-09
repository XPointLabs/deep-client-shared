using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Client.Shared.Tests.MessagingV1;

internal static class MessagingV1Fixture
{
    private static readonly byte[] EvidenceSeed = Bytes(32, 0x7e51);
    internal static byte[] EvidencePublicKey
    {
        get
        {
            using var pair = PublicKeyAuth.GenerateKeyPair(EvidenceSeed);
            return pair.PublicKey.ToArray();
        }
    }

    internal static Msg01VerifiedSessionAuthority CreateEvidenceAuthority() =>
        Msg01VerifiedSessionAuthority.CreateTestEd25519(EvidencePublicKey);

    internal static byte[] Authenticate(
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> canonicalEvidence)
    {
        var transcript = CapabilityChecks.AuthenticationTranscript(context, canonicalEvidence);
        try
        {
            using var pair = PublicKeyAuth.GenerateKeyPair(EvidenceSeed);
            var signature = PublicKeyAuth.SignDetached(transcript, pair.PrivateKey);
            var result = new byte[canonicalEvidence.Length + signature.Length];
            canonicalEvidence.CopyTo(result);
            signature.CopyTo(result, canonicalEvidence.Length);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcript);
        }
    }
    public static readonly DateTimeOffset CreatedAt =
        DateTimeOffset.FromUnixTimeMilliseconds(1_900_000_000_000);

    public static byte[] Bytes(int length, int marker)
    {
        var value = new byte[length];
        BitConverter.TryWriteBytes(value, marker);
        value[^1] = 0xa5;
        return value;
    }

    public static MessagingAccountId32 Account(int marker = 1) =>
        MessagingAccountId32.FromBytes(Bytes(32, marker));

    public static MessagingDeviceId32 Device(int marker = 2) =>
        MessagingDeviceId32.FromBytes(Bytes(32, marker));

    public static ConversationId32 Conversation(int marker = 3) =>
        ConversationId32.FromBytes(Bytes(32, marker));

    public static SemanticMessageId32 Semantic(int marker = 4) =>
        SemanticMessageId32.FromBytes(Bytes(32, marker));

    public static byte[] Payload(int marker = 5) => Bytes(128, marker);

    public static MessageEventHash32 EventHash(int marker = 5) =>
        MessageEventHash32.FromBytes(SHA256.HashData(Payload(marker)));

    public static MessageMutationId32 Operation(int marker) =>
        MessageMutationId32.FromBytes(Bytes(32, marker));

    public static TransportAttemptId16 Attempt(int marker = 1) =>
        TransportAttemptId16.FromBytes(Bytes(16, marker));

    public static RecipientDeviceTarget Target(int account = 10, int device = 11) =>
        new(Account(account), Device(device));

    public static MessageStoreScope Scope(int account = 1, ulong generation = 1, int instance = 900) =>
        new(Account(account), generation, MessageStoreInstanceId32.FromBytes(Bytes(32, instance)));

    public static LogicalOutboxSeed Seed(
        int semantic = 4,
        int eventHash = 5,
        int authorDevice = 2,
        DateTimeOffset? expiresAt = null,
        MessageStoreScope? scope = null) =>
        LogicalOutboxSeed.CreateOutbound(
            scope ?? Scope(), Device(authorDevice), Conversation(), Semantic(semantic), EventHash(eventHash),
            Payload(eventHash), CreatedAt, expiresAt ?? CreatedAt.AddDays(7));

    public static SemanticClaimCandidate Claim(
        int authorAccount = 1,
        int authorDevice = 2,
        int conversation = 3,
        int semantic = 4,
        int eventHash = 5) =>
        new(Account(authorAccount), Device(authorDevice), Conversation(conversation),
            Semantic(semantic), EventHash(eventHash));

    public static DirectoryHeadHash32 Directory(int marker = 6) => DirectoryHeadHash32.FromBytes(Bytes(32, marker));
    public static MessageTargetOperationId32 TargetOperation(int marker = 7) => MessageTargetOperationId32.FromBytes(Bytes(32, marker));
    public static MessageBindingHash32 Binding(int marker = 8) => MessageBindingHash32.FromBytes(Bytes(32, marker));
    public static TransportRequestHash32 Request(int marker = 9) => TransportRequestHash32.FromBytes(Bytes(32, marker));
    public static RatchetTransitionHash32 Transition(int marker = 10) => RatchetTransitionHash32.FromBytes(Bytes(32, marker));
    public static MessageEvidenceHash32 Evidence(int marker = 11) => MessageEvidenceHash32.FromBytes(Bytes(32, marker));
    public static MessageReceiptId32 Receipt(int marker = 12) => MessageReceiptId32.FromBytes(Bytes(32, marker));
    public static RatchetSessionId32 RatchetSession(int marker = 13) => RatchetSessionId32.FromBytes(Bytes(32, marker));
    public static RatchetStateHash32 RatchetHash(int marker = 14) => RatchetStateHash32.FromBytes(Bytes(32, marker));
    public static MessageRecoveryOwnerId16 RecoveryOwner(int marker = 15) => MessageRecoveryOwnerId16.FromBytes(Bytes(16, marker));
    public static FanoutTargetSeed Fanout(RecipientDeviceTarget target, int marker = 1) => new(target, Directory(marker + 100), TargetOperation(marker + 200), Binding(marker + 300));
    public static TargetAttemptPlan AttemptPlan(LogicalOutboxSnapshot head, RecipientDeviceTarget target, TransportAttemptId16 attempt, int marker = 1)
    {
        var t = head.Targets.Single(x => x.Target.Equals(target));
        return new(target, attempt, Request(marker + 400), RatchetHash(marker + 450), Transition(marker + 500), t.DirectoryHeadHash, t.OperationId!, t.BindingHash!, Bytes(256, marker + 600));
    }

    public static async Task<LogicalOutboxSnapshot> BeginAsync(
        InMemoryMessageTransactionStore store,
        LogicalOutboxSeed? seed = null,
        int operation = 1)
    {
        seed ??= Seed();
        var result = await store.BeginOutboundAsync(
            Operation(operation),
            new(seed.AuthorAccountId, seed.AuthorDeviceId, seed.ConversationId,
                seed.SemanticMessageId, seed.EventHash),
            seed,
            CancellationToken.None);
        Assert.Equal(MessageCommitResult.Applied, result.CommitResult);
        return Assert.IsType<LogicalOutboxSnapshot>(result.Snapshot);
    }

    public static VerifiedTransportTargetOutcome Outcome(
        IMessageVerifiedTransportHandoff capabilities,
        LogicalOutboxSnapshot head,
        RecipientDeviceTarget target,
        TransportAttemptId16 attempt,
        VerifiedTargetOutcomeKind outcome)
    {
        var bytes=Bytes(32,(int)outcome+600);
        var context = TargetContext(MessageEvidencePurpose.TargetOutcome, head, target, attempt, outcome);
        return capabilities.VerifyTargetOutcome(
            context, Authenticate(context, bytes));
    }

    public static VerifiedTransportAttemptUncertainty Uncertainty(
        IMessageVerifiedTransportHandoff capabilities,
        LogicalOutboxSnapshot head,
        RecipientDeviceTarget target, TransportAttemptId16 attempt)
    {
        var bytes=Bytes(32,700);
        var context = TargetContext(MessageEvidencePurpose.AttemptUncertainty, head, target, attempt);
        return capabilities.VerifyAttemptUncertainty(
            context, Authenticate(context, bytes));
    }
    public static VerifiedTransportAttemptUncertainty Uncertainty(IMessageVerifiedTransportHandoff capabilities, LogicalOutboxSnapshot head, TransportAttemptId16 attempt) =>
        Uncertainty(capabilities, head, head.Targets.Single(x => x.ActiveAttemptId?.Equals(attempt) == true).Target, attempt);

    public static VerifiedTransportAttemptReconciliation Reconciliation(
        IMessageVerifiedTransportHandoff capabilities,
        LogicalOutboxSnapshot head,
        TransportAttemptId16 attempt,
        VerifiedTargetOutcomeKind outcome = VerifiedTargetOutcomeKind.NotAccepted)
    {
        var bytes=Bytes(32,701);
        var stored = head.Targets.Single(item => item.ActiveAttemptId?.Equals(attempt) == true);
        var context = new MessageCapabilityTrustedContext(
            MessageEvidencePurpose.AttemptReconciliation, head.StoreScope, head.ClaimKey,
            stored.Target, attempt, outcome, targetOperationId: stored.OperationId,
            bindingHash: stored.BindingHash,
            requestHash: stored.RequestHash!.ToArray(), envelopeHash: head.EventHash.ToArray(),
            ratchetBeforeHash: stored.RatchetBeforeHash!.ToArray(),
            ratchetAfterHash: stored.RatchetTransitionHash!.ToArray(),
            replayCounter: head.Revision + 1, replayNonce: Bytes(32, 713));
        return capabilities.VerifyReconciliation(
            context, Authenticate(context, bytes));
    }

    public static VerifiedLateMaterializationReceipt LateReceipt(
        IMessageVerifiedTransportHandoff capabilities,
        LogicalOutboxSnapshot head,
        RecipientDeviceTarget target,
        TransportAttemptId16 acceptedAttempt)
    {
        var bytes=Bytes(32,703);
        var context = TargetContext(MessageEvidencePurpose.LateMaterialization, head, target, acceptedAttempt,
            VerifiedTargetOutcomeKind.Materialized, Receipt(702));
        return capabilities.VerifyLateReceipt(
            context, Authenticate(context, bytes));
    }

    public static InboxMaterializationRequest Inbound(
        IMessageVerifiedTransportHandoff capabilities,
        MessageStoreScope scope,
        int authorDevice = 80,
        int semantic = 81,
        int canonicalMarker = 82,
        int session = 83,
        RatchetStateHash32? beforeHash = null,
        int sealedStateMarker = 84,
        int receipt = 85,
        int authorAccount = 79,
        DateTimeOffset? occurredAt = null)
    {
        var canonical = Bytes(128, canonicalMarker);
        var sealedState = Bytes(96, sealedStateMarker);
        var receiptBytes = Bytes(96, receipt + 10_000);
        var claim = new SemanticClaimCandidate(Account(authorAccount), Device(authorDevice),
            Conversation(), Semantic(semantic),
            MessageEventHash32.FromBytes(SHA256.HashData(canonical)));
        var before = beforeHash ?? RatchetHash(session + 1);
        var after = RatchetStateHash32.FromBytes(SHA256.HashData(sealedState));
        var context = new MessageCapabilityTrustedContext(MessageEvidencePurpose.InboundMaterialization,
            scope, claim.Key, receiptId: Receipt(receipt),
            requestHash: SHA256.HashData(canonical), envelopeHash: claim.EventHash.ToArray(),
            ratchetBeforeHash: before.ToArray(), ratchetAfterHash: after.ToArray(),
            replayCounter: checked((ulong)receipt + 1), replayNonce: Bytes(32, receipt + 20_000),
            ratchetSessionId: RatchetSession(session));
        return capabilities.VerifyInbound(context, claim, canonical, RatchetSession(session),
            before, after,
            sealedState, occurredAt ?? CreatedAt.AddMilliseconds(receipt),
            Authenticate(context, receiptBytes));
    }

    internal static MessageCapabilityTrustedContext TargetContext(MessageEvidencePurpose purpose,
        LogicalOutboxSnapshot head, RecipientDeviceTarget target, TransportAttemptId16 attempt,
        VerifiedTargetOutcomeKind? outcome = null, MessageReceiptId32? receipt = null)
    {
        var stored = head.Targets.Single(item => item.Target.Equals(target));
        return new MessageCapabilityTrustedContext(purpose, head.StoreScope, head.ClaimKey, target, attempt,
            outcome, receipt, stored.OperationId, stored.BindingHash,
            requestHash: stored.RequestHash?.ToArray() ?? Request(901).ToArray(),
            envelopeHash: head.EventHash.ToArray(),
            ratchetBeforeHash: stored.RatchetBeforeHash?.ToArray() ?? RatchetHash(903).ToArray(),
            ratchetAfterHash: stored.RatchetTransitionHash?.ToArray() ?? Transition(902).ToArray(),
            replayCounter: head.Revision + 1,
            replayNonce: SHA256.HashData(attempt.ToArray()));
    }
}

internal sealed class TestVerifiedMsg01Transport :
    IDirectP2pSessionMessageTransport, IAuthenticatedInboxTransport,
    IMsg01AuthenticatedEvidenceSource, IDisposable
{
    private readonly Msg01VerifiedSessionAuthority evidenceAuthority =
        MessagingV1Fixture.CreateEvidenceAuthority();
    private long replay;
    private SessionId local = SessionId.CreateNew();
    private int disposeCount;
    internal int DisposeCount => Volatile.Read(ref disposeCount);
    public Msg01VerifiedSessionAuthority EvidenceAuthority => evidenceAuthority;
    public ValueTask<SessionId> GetLocalAccountAsync(CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); return ValueTask.FromResult(local); }
    public ValueTask<DirectoryHeadHash32> ResolveFanoutTargetAsync(
        Msg01ResolveFanoutTargetRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(MessagingV1Fixture.Directory(1900));
    }
    public ValueTask<Msg01PreparedTransportAttempt> PrepareAttemptAsync(
        Msg01PrepareAttemptRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.Kind == MessagePayloadKind.DirectMessage)
            local = System.Text.Json.JsonSerializer.Deserialize<DirectFixturePayload>(request.CanonicalPayload.Span)!.Sender;
        return ValueTask.FromResult(new Msg01PreparedTransportAttempt(
            MessagingV1Fixture.Directory(1900), MessagingV1Fixture.RatchetHash(1901),
            MessagingV1Fixture.Transition(1902), request.CanonicalPayload.Span));
    }
    public ValueTask<Msg01AuthenticatedDispatchResult> DispatchPreparedAsync(
        Msg01DispatchEvidenceRequest request, CancellationToken cancellationToken) =>
        ValueTask.FromResult(Result(request, MessageEvidencePurpose.TargetOutcome, cancellationToken));
    public ValueTask<Msg01AuthenticatedDispatchResult> ReconcilePreparedAsync(
        Msg01DispatchEvidenceRequest request, CancellationToken cancellationToken) =>
        ValueTask.FromResult(Result(request, MessageEvidencePurpose.AttemptReconciliation, cancellationToken));
    public ValueTask<Msg01AuthenticatedInboundResult> GetInboundResultAsync(
        Msg01InboundEvidenceRequest request, CancellationToken cancellationToken) =>
        ValueTask.FromException<Msg01AuthenticatedInboundResult>(new InvalidOperationException("No inbound test envelope."));
    public ValueTask AcknowledgeReceiptAsync(ReadOnlyMemory<byte> authenticatedReceipt, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); return ValueTask.CompletedTask; }
    public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
    { cancellationToken.ThrowIfCancellationRequested(); return Task.CompletedTask; }
    public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default)
    { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]); }
    public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
        SessionIdentityProvider identity, CancellationToken cancellationToken = default) => ReceiveAsync(identity.SessionId, cancellationToken);
    public void Dispose() => Interlocked.Increment(ref disposeCount);

    private Msg01AuthenticatedDispatchResult Result(Msg01DispatchEvidenceRequest request,
        MessageEvidencePurpose purpose, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var counter = checked((ulong)Interlocked.Increment(ref replay));
        var nonce = MessagingV1Fixture.Bytes(32, checked((int)counter + 2000));
        var context = new MessageCapabilityTrustedContext(purpose,
            request.Scope, request.ClaimKey, request.Target, request.AttemptId,
            VerifiedTargetOutcomeKind.Accepted, targetOperationId: request.OperationId,
            bindingHash: request.BindingHash, requestHash: request.RequestHash.ToArray(),
            envelopeHash: request.EnvelopeHash.ToArray(), ratchetBeforeHash: request.RatchetBeforeHash.ToArray(),
            ratchetAfterHash: request.RatchetAfterHash.ToArray(), replayCounter: counter, replayNonce: nonce);
        return new(VerifiedTargetOutcomeKind.Accepted, false, counter, nonce,
            MessagingV1Fixture.Authenticate(context, SHA256.HashData(request.Ciphertext.Span)));
    }

    private sealed record DirectFixturePayload(MessageId Id, SessionId Sender, SessionId Recipient,
        string Body, IReadOnlyList<AttachmentMetadata> Attachments, DateTimeOffset CreatedAt,
        DateTimeOffset? ExpiresAt, MessageReply? ReplyTo, MessageReactionUpdate? Reaction);
}
