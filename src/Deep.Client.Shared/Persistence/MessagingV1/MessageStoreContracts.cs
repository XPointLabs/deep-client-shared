using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Protocol.GroupV1;
#if DEEP_TEST_INTERNALS
using Sodium;
#endif

namespace Deep.Client.Shared.Persistence.MessagingV1;

// MSG-01 is deliberately transport-neutral.  Only an authenticated transport
// adapter may mint these objects; persistence never accepts a bare outcome.
internal enum VerifiedTargetOutcomeKind { Accepted = 1, Materialized = 2, Expired = 3, Revoked = 4, TerminalRejected = 5, NotAccepted = 6 }
internal enum MessageMutationKind { PrepareFanout = 1, StartSending = 2, TargetOutcome = 3, MarkOutcomeUnknown = 4, ReconcileOutcomeUnknown = 5, Cancel = 6, Expire = 7, LateMaterializationReceipt = 8, LocalGroupDispatchBlock = 9 }
internal enum SemanticClaimResult { First = 1, ExactDuplicate = 2, ForkLatched = 3 }
internal enum MessageCommitResult { Applied = 1, Idempotent = 2, StaleRevision = 3, Conflict = 4, Missing = 5, ForkLatched = 6 }
internal enum MessageEvidencePurpose { TargetOutcome = 1, AttemptUncertainty = 2, AttemptReconciliation = 3, LateMaterialization = 4, InboundMaterialization = 5 }

internal sealed class MessageCapabilityEvidence
{
    private readonly byte[] evidence;
    private readonly byte[] replayNonce;
    internal MessageCapabilityEvidence(MessageEvidencePurpose purpose, MessageStoreScope scope,
        SemanticClaimKey key, RecipientDeviceTarget? target, TransportAttemptId16? attemptId,
        VerifiedTargetOutcomeKind? outcomeKind, MessageReceiptId32? receiptId,
        MessageEvidenceHash32 evidenceHash, ReadOnlySpan<byte> evidence,
        MessageTargetOperationId32? targetOperationId = null, MessageBindingHash32? bindingHash = null,
        ulong replayCounter = 0, ReadOnlySpan<byte> replayNonce = default)
    {
        if (replayCounter == 0 || replayNonce.Length != 32
            || replayNonce.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("MSG-01 replay identity is incomplete.");
        Purpose = purpose; Scope = LogicalOutboxSnapshot.Copy(scope);
        ClaimKey = new(key.AuthorAccountId, key.ConversationId, key.SemanticMessageId);
        Target = target is null ? null : new(target.AccountId, target.DeviceId);
        AttemptId = attemptId is null ? null : TransportAttemptId16.FromBytes(attemptId.Span);
        OutcomeKind = outcomeKind;
        ReceiptId = receiptId is null ? null : MessageReceiptId32.FromBytes(receiptId.Span);
        TargetOperationId = targetOperationId is null ? null : MessageTargetOperationId32.FromBytes(targetOperationId.Span);
        BindingHash = bindingHash is null ? null : MessageBindingHash32.FromBytes(bindingHash.Span);
        ReplayCounter = replayCounter;
        this.replayNonce = replayNonce.ToArray();
        EvidenceHash = MessageEvidenceHash32.FromBytes(evidenceHash.Span); this.evidence = evidence.ToArray();
    }
    internal MessageEvidencePurpose Purpose { get; }
    internal MessageStoreScope Scope { get; }
    internal SemanticClaimKey ClaimKey { get; }
    internal RecipientDeviceTarget? Target { get; }
    internal TransportAttemptId16? AttemptId { get; }
    internal VerifiedTargetOutcomeKind? OutcomeKind { get; }
    internal MessageReceiptId32? ReceiptId { get; }
    internal MessageTargetOperationId32? TargetOperationId { get; }
    internal MessageBindingHash32? BindingHash { get; }
    internal ulong ReplayCounter { get; }
    internal ReadOnlyMemory<byte> ReplayNonce => replayNonce.ToArray();
    internal MessageEvidenceHash32 EvidenceHash { get; }
    internal ReadOnlyMemory<byte> Evidence => evidence.ToArray();
}

// Capability evidence is a local, authenticated hand-off between the reviewed
// transport/ratchet adapter and MSG-01 persistence.  It is deliberately not an
// injectable predicate: accepting an arbitrary unconditional callback turns
// an untrusted transport result into a durable state mutation.
internal sealed class MessageCapabilityTrustedContext
{
    private readonly byte[] requestHash;
    private readonly byte[] envelopeHash;
    private readonly byte[] ratchetBeforeHash;
    private readonly byte[] ratchetAfterHash;
    private readonly byte[] replayNonce;

    internal MessageCapabilityTrustedContext(
        MessageEvidencePurpose purpose, MessageStoreScope scope, SemanticClaimKey claimKey,
        RecipientDeviceTarget? target = null, TransportAttemptId16? attemptId = null,
        VerifiedTargetOutcomeKind? outcomeKind = null, MessageReceiptId32? receiptId = null,
        MessageTargetOperationId32? targetOperationId = null, MessageBindingHash32? bindingHash = null,
        byte[]? requestHash = null, byte[]? envelopeHash = null,
        byte[]? ratchetBeforeHash = null, byte[]? ratchetAfterHash = null,
        ulong replayCounter = 0, byte[]? replayNonce = null,
        RatchetSessionId32? ratchetSessionId = null)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(claimKey);
        Purpose = purpose; Scope = LogicalOutboxSnapshot.Copy(scope);
        ClaimKey = new(claimKey.AuthorAccountId, claimKey.ConversationId, claimKey.SemanticMessageId);
        Target = target is null ? null : new(target.AccountId, target.DeviceId);
        AttemptId = attemptId is null ? null : TransportAttemptId16.FromBytes(attemptId.Span);
        OutcomeKind = outcomeKind;
        ReceiptId = receiptId is null ? null : MessageReceiptId32.FromBytes(receiptId.Span);
        TargetOperationId = targetOperationId is null ? null : MessageTargetOperationId32.FromBytes(targetOperationId.Span);
        BindingHash = bindingHash is null ? null : MessageBindingHash32.FromBytes(bindingHash.Span);
        this.requestHash = Exact32(requestHash, nameof(requestHash));
        this.envelopeHash = Exact32(envelopeHash, nameof(envelopeHash));
        this.ratchetBeforeHash = Exact32(ratchetBeforeHash, nameof(ratchetBeforeHash));
        this.ratchetAfterHash = Exact32(ratchetAfterHash, nameof(ratchetAfterHash));
        if (replayCounter == 0) throw new ArgumentOutOfRangeException(nameof(replayCounter));
        ReplayCounter = replayCounter;
        this.replayNonce = Exact32(replayNonce, nameof(replayNonce));
        RatchetSessionId = ratchetSessionId is null
            ? null : RatchetSessionId32.FromBytes(ratchetSessionId.Span);
        if (!HasCanonicalShape()) throw new ArgumentException("MSG-01 capability context has an invalid purpose binding.", nameof(purpose));
    }

    internal MessageEvidencePurpose Purpose { get; }
    internal MessageStoreScope Scope { get; }
    internal SemanticClaimKey ClaimKey { get; }
    internal RecipientDeviceTarget? Target { get; }
    internal TransportAttemptId16? AttemptId { get; }
    internal VerifiedTargetOutcomeKind? OutcomeKind { get; }
    internal MessageReceiptId32? ReceiptId { get; }
    internal MessageTargetOperationId32? TargetOperationId { get; }
    internal MessageBindingHash32? BindingHash { get; }
    internal ReadOnlyMemory<byte> RequestHash => requestHash.ToArray();
    internal ReadOnlyMemory<byte> EnvelopeHash => envelopeHash.ToArray();
    internal ReadOnlyMemory<byte> RatchetBeforeHash => ratchetBeforeHash.ToArray();
    internal ReadOnlyMemory<byte> RatchetAfterHash => ratchetAfterHash.ToArray();
    internal ulong ReplayCounter { get; }
    internal ReadOnlyMemory<byte> ReplayNonce => replayNonce.ToArray();
    internal RatchetSessionId32? RatchetSessionId { get; }

    internal MessageCapabilityEvidence Evidence(MessageEvidenceHash32 evidenceHash, ReadOnlySpan<byte> evidence) =>
        new(Purpose, Scope, ClaimKey, Target, AttemptId, OutcomeKind, ReceiptId, evidenceHash, evidence,
            TargetOperationId, BindingHash, ReplayCounter, ReplayNonce.Span);

    private bool HasCanonicalShape() => Purpose switch
    {
        MessageEvidencePurpose.TargetOutcome => Target is not null && AttemptId is not null
            && OutcomeKind is not null && ReceiptId is null && TargetOperationId is not null && BindingHash is not null
            && RatchetSessionId is null,
        MessageEvidencePurpose.AttemptUncertainty => Target is not null && AttemptId is not null
            && OutcomeKind is null && ReceiptId is null && TargetOperationId is not null && BindingHash is not null
            && RatchetSessionId is null,
        MessageEvidencePurpose.AttemptReconciliation => Target is not null && AttemptId is not null
            && OutcomeKind is not null && ReceiptId is null && TargetOperationId is not null && BindingHash is not null
            && RatchetSessionId is null,
        MessageEvidencePurpose.LateMaterialization => Target is not null && AttemptId is not null
            && OutcomeKind == VerifiedTargetOutcomeKind.Materialized && ReceiptId is not null
            && TargetOperationId is not null && BindingHash is not null && RatchetSessionId is null,
        MessageEvidencePurpose.InboundMaterialization => Target is null && AttemptId is null
            && OutcomeKind is null && ReceiptId is not null && TargetOperationId is null && BindingHash is null
            && RatchetSessionId is not null,
        _ => false
    };

    private static byte[] Exact32(byte[]? value, string name)
    {
        if (value is null || value.Length != 32 || value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("MSG-01 exact evidence binding must be a nonzero 32-byte value.", name);
        return value.ToArray();
    }
}

internal interface IMessageVerifiedTransportHandoff
{
    VerifiedTransportTargetOutcome VerifyTargetOutcome(
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> authenticatedEvidence);
    VerifiedTransportAttemptUncertainty VerifyAttemptUncertainty(
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> authenticatedEvidence);
    VerifiedTransportAttemptReconciliation VerifyReconciliation(
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> authenticatedEvidence);
    VerifiedLateMaterializationReceipt VerifyLateReceipt(
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> authenticatedEvidence);
    InboxMaterializationRequest VerifyInbound(
        MessageCapabilityTrustedContext context,
        SemanticClaimCandidate claim,
        ReadOnlySpan<byte> canonicalEvent,
        RatchetSessionId32 sessionId,
        RatchetStateHash32 beforeHash,
        RatchetStateHash32 afterHash,
        ReadOnlySpan<byte> sealedRatchetState,
        DateTimeOffset occurredAt,
        ReadOnlySpan<byte> authenticatedEvidence);
}

/// <summary>
/// Store-owned handoff consumed only by the GroupV1 first-dispatch safety
/// boundary. It can mint a local block capability only while the exact
/// database-wide group-head lease remains active.
/// </summary>
internal interface IMessageGroupDispatchSafetyHandoff
{
    VerifiedLocalGroupDispatchBlock MintLocalBlock(
        GroupHeadReadLease headLease,
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot target,
        GroupMessageFirstDispatchDisposition disposition,
        DateTimeOffset occurredAt);
}

// Implemented only by a transport/session verifier which can return evidence
// signed by the authority key pinned into the MSG-01 store. A completed Task or
// successful SendAsync call is deliberately not evidence.
internal sealed class Msg01PrepareAttemptRequest
{
    private readonly byte[] canonicalPayload;
    internal Msg01PrepareAttemptRequest(
        MessagePayloadKind kind, MessageStoreScope scope, SemanticClaimKey claimKey,
        RecipientDeviceTarget target, TransportAttemptId16 attemptId,
        MessageTargetOperationId32 operationId, MessageBindingHash32 bindingHash,
        ReadOnlySpan<byte> canonicalPayload)
    {
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        if (canonicalPayload.Length is < 1 or > MessagingV1Limits.MaxCanonicalEventBytes)
            throw new ArgumentOutOfRangeException(nameof(canonicalPayload));
        Kind = kind;
        Scope = LogicalOutboxSnapshot.Copy(scope);
        ClaimKey = new(claimKey.AuthorAccountId, claimKey.AuthorDeviceId!, claimKey.ConversationId, claimKey.SemanticMessageId);
        Target = new(target.AccountId, target.DeviceId);
        AttemptId = TransportAttemptId16.FromBytes(attemptId.Span);
        OperationId = MessageTargetOperationId32.FromBytes(operationId.Span);
        BindingHash = MessageBindingHash32.FromBytes(bindingHash.Span);
        this.canonicalPayload = canonicalPayload.ToArray();
    }
    internal MessagePayloadKind Kind { get; }
    internal MessageStoreScope Scope { get; }
    internal SemanticClaimKey ClaimKey { get; }
    internal RecipientDeviceTarget Target { get; }
    internal TransportAttemptId16 AttemptId { get; }
    internal MessageTargetOperationId32 OperationId { get; }
    internal MessageBindingHash32 BindingHash { get; }
    internal ReadOnlyMemory<byte> CanonicalPayload => canonicalPayload.ToArray();
}

/// <summary>
/// Exact directory-resolution input used before MSG-01 commits immutable fanout.
/// It carries no authority and cannot promote a transport result into an outcome.
/// </summary>
internal sealed class Msg01ResolveFanoutTargetRequest
{
    internal Msg01ResolveFanoutTargetRequest(
        MessagePayloadKind kind,
        MessageStoreScope scope,
        SemanticClaimKey claimKey,
        RecipientDeviceTarget target,
        MessageTargetOperationId32 operationId,
        MessageBindingHash32 bindingHash)
    {
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        Kind = kind;
        Scope = LogicalOutboxSnapshot.Copy(scope);
        ClaimKey = new(claimKey.AuthorAccountId, claimKey.AuthorDeviceId!,
            claimKey.ConversationId, claimKey.SemanticMessageId);
        Target = new(target.AccountId, target.DeviceId);
        OperationId = MessageTargetOperationId32.FromBytes(operationId.Span);
        BindingHash = MessageBindingHash32.FromBytes(bindingHash.Span);
    }

    internal MessagePayloadKind Kind { get; }
    internal MessageStoreScope Scope { get; }
    internal SemanticClaimKey ClaimKey { get; }
    internal RecipientDeviceTarget Target { get; }
    internal MessageTargetOperationId32 OperationId { get; }
    internal MessageBindingHash32 BindingHash { get; }
}

internal sealed class Msg01PreparedTransportAttempt
{
    private readonly byte[] ciphertext;
    internal Msg01PreparedTransportAttempt(
        DirectoryHeadHash32 directoryHeadHash, RatchetStateHash32 ratchetBeforeHash,
        RatchetTransitionHash32 ratchetAfterHash, ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length is < 1 or > MessagingV1Limits.MaxCiphertextBytes)
            throw new ArgumentOutOfRangeException(nameof(ciphertext));
        DirectoryHeadHash = DirectoryHeadHash32.FromBytes(directoryHeadHash.Span);
        RatchetBeforeHash = RatchetStateHash32.FromBytes(ratchetBeforeHash.Span);
        RatchetAfterHash = RatchetTransitionHash32.FromBytes(ratchetAfterHash.Span);
        this.ciphertext = ciphertext.ToArray();
        RequestHash = TransportRequestHash32.FromBytes(SHA256.HashData(this.ciphertext));
    }
    internal DirectoryHeadHash32 DirectoryHeadHash { get; }
    internal TransportRequestHash32 RequestHash { get; }
    internal RatchetStateHash32 RatchetBeforeHash { get; }
    internal RatchetTransitionHash32 RatchetAfterHash { get; }
    internal ReadOnlyMemory<byte> Ciphertext => ciphertext.ToArray();
}

internal sealed class Msg01DispatchEvidenceRequest
{
    private readonly byte[] ciphertext;
    internal Msg01DispatchEvidenceRequest(
        MessagePayloadKind kind, LogicalOutboxSnapshot head, LogicalTargetSnapshot target)
    {
        if (target.ActiveAttemptId is null || target.RequestHash is null
            || target.RatchetBeforeHash is null || target.RatchetTransitionHash is null
            || target.Ciphertext is null || target.OperationId is null || target.BindingHash is null)
            throw new ArgumentException("MSG-01 dispatch request is incomplete.", nameof(target));
        Kind = kind;
        Scope = LogicalOutboxSnapshot.Copy(head.StoreScope);
        ClaimKey = new(head.ClaimKey.AuthorAccountId, head.ClaimKey.AuthorDeviceId!, head.ClaimKey.ConversationId, head.ClaimKey.SemanticMessageId);
        Target = new(target.Target.AccountId, target.Target.DeviceId);
        AttemptId = TransportAttemptId16.FromBytes(target.ActiveAttemptId.Span);
        RequestHash = TransportRequestHash32.FromBytes(target.RequestHash.Span);
        EnvelopeHash = MessageEventHash32.FromBytes(head.EventHash.Span);
        RatchetBeforeHash = RatchetStateHash32.FromBytes(target.RatchetBeforeHash.Span);
        RatchetAfterHash = RatchetTransitionHash32.FromBytes(target.RatchetTransitionHash.Span);
        OperationId = MessageTargetOperationId32.FromBytes(target.OperationId.Span);
        BindingHash = MessageBindingHash32.FromBytes(target.BindingHash.Span);
        ciphertext = target.Ciphertext;
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(ciphertext), RequestHash.Span))
            throw new CryptographicException("MSG-01 durable ciphertext does not match its request hash.");
    }
    internal MessagePayloadKind Kind { get; }
    internal MessageStoreScope Scope { get; }
    internal SemanticClaimKey ClaimKey { get; }
    internal RecipientDeviceTarget Target { get; }
    internal TransportAttemptId16 AttemptId { get; }
    internal TransportRequestHash32 RequestHash { get; }
    internal MessageEventHash32 EnvelopeHash { get; }
    internal RatchetStateHash32 RatchetBeforeHash { get; }
    internal RatchetTransitionHash32 RatchetAfterHash { get; }
    internal MessageTargetOperationId32 OperationId { get; }
    internal MessageBindingHash32 BindingHash { get; }
    internal ReadOnlyMemory<byte> Ciphertext => ciphertext.ToArray();
}

internal sealed class Msg01AuthenticatedDispatchResult
{
    private readonly byte[] replayNonce;
    private readonly byte[] authenticatedEvidence;
    internal Msg01AuthenticatedDispatchResult(
        VerifiedTargetOutcomeKind? outcome, bool outcomeUnknown, ulong replayCounter,
        ReadOnlySpan<byte> replayNonce, ReadOnlySpan<byte> authenticatedEvidence)
    {
        if ((outcome is null) == !outcomeUnknown || replayCounter == 0
            || replayNonce.Length != 32 || replayNonce.IndexOfAnyExcept((byte)0) < 0
            || authenticatedEvidence.IsEmpty)
            throw new ArgumentException("Authenticated dispatch result is incomplete.");
        Outcome = outcome;
        OutcomeUnknown = outcomeUnknown;
        ReplayCounter = replayCounter;
        this.replayNonce = replayNonce.ToArray();
        this.authenticatedEvidence = authenticatedEvidence.ToArray();
    }
    internal VerifiedTargetOutcomeKind? Outcome { get; }
    internal bool OutcomeUnknown { get; }
    internal ulong ReplayCounter { get; }
    internal ReadOnlyMemory<byte> ReplayNonce => replayNonce.ToArray();
    internal ReadOnlyMemory<byte> AuthenticatedEvidence => authenticatedEvidence.ToArray();
}

internal interface IMsg01AuthenticatedEvidenceSource
{
    Msg01VerifiedSessionAuthority EvidenceAuthority { get; }

    ValueTask<Deep.Client.Shared.Domain.SessionId> GetLocalAccountAsync(
        CancellationToken cancellationToken);

    ValueTask<DirectoryHeadHash32> ResolveFanoutTargetAsync(
        Msg01ResolveFanoutTargetRequest request,
        CancellationToken cancellationToken);

    ValueTask<Msg01PreparedTransportAttempt> PrepareAttemptAsync(
        Msg01PrepareAttemptRequest request,
        CancellationToken cancellationToken);

    ValueTask<Msg01AuthenticatedDispatchResult> DispatchPreparedAsync(
        Msg01DispatchEvidenceRequest request,
        CancellationToken cancellationToken);

    ValueTask<Msg01AuthenticatedDispatchResult> ReconcilePreparedAsync(
        Msg01DispatchEvidenceRequest request,
        CancellationToken cancellationToken);

    ValueTask<Msg01AuthenticatedInboundResult> GetInboundResultAsync(
        Msg01InboundEvidenceRequest request,
        CancellationToken cancellationToken);

    ValueTask AcknowledgeReceiptAsync(
        ReadOnlyMemory<byte> authenticatedReceipt,
        CancellationToken cancellationToken);
}

internal sealed class Msg01InboundEvidenceRequest
{
    private readonly byte[] canonicalEnvelope;
    internal Msg01InboundEvidenceRequest(
        MessageStoreScope scope,
        SemanticClaimCandidate claim,
        MessageReceiptId32 receiptId,
        ReadOnlySpan<byte> canonicalEnvelope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(receiptId);
        if (canonicalEnvelope.IsEmpty) throw new ArgumentException("Canonical envelope is empty.");
        Scope = LogicalOutboxSnapshot.Copy(scope);
        Claim = claim;
        ReceiptId = MessageReceiptId32.FromBytes(receiptId.Span);
        this.canonicalEnvelope = canonicalEnvelope.ToArray();
    }
    internal MessageStoreScope Scope { get; }
    internal SemanticClaimCandidate Claim { get; }
    internal MessageReceiptId32 ReceiptId { get; }
    internal ReadOnlyMemory<byte> CanonicalEnvelope => canonicalEnvelope.ToArray();
}

internal sealed class Msg01AuthenticatedInboundResult
{
    private readonly byte[] sealedRatchetState;
    private readonly byte[] authenticatedEvidence;

    internal Msg01AuthenticatedInboundResult(
        RatchetSessionId32 sessionId,
        RatchetStateHash32 beforeHash,
        RatchetStateHash32 afterHash,
        ReadOnlySpan<byte> sealedRatchetState,
        ulong replayCounter,
        ReadOnlySpan<byte> replayNonce,
        ReadOnlySpan<byte> authenticatedEvidence)
    {
        ArgumentNullException.ThrowIfNull(sessionId);
        ArgumentNullException.ThrowIfNull(beforeHash);
        ArgumentNullException.ThrowIfNull(afterHash);
        if (sealedRatchetState.IsEmpty || authenticatedEvidence.IsEmpty
            || replayCounter == 0 || replayNonce.Length != 32
            || replayNonce.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Authenticated inbound evidence is incomplete.");
        SessionId = RatchetSessionId32.FromBytes(sessionId.Span);
        BeforeHash = RatchetStateHash32.FromBytes(beforeHash.Span);
        AfterHash = RatchetStateHash32.FromBytes(afterHash.Span);
        this.sealedRatchetState = sealedRatchetState.ToArray();
        ReplayCounter = replayCounter;
        ReplayNonce = replayNonce.ToArray();
        this.authenticatedEvidence = authenticatedEvidence.ToArray();
    }

    internal RatchetSessionId32 SessionId { get; }
    internal RatchetStateHash32 BeforeHash { get; }
    internal RatchetStateHash32 AfterHash { get; }
    internal ReadOnlyMemory<byte> SealedRatchetState => sealedRatchetState.ToArray();
    internal ulong ReplayCounter { get; }
    internal ReadOnlyMemory<byte> ReplayNonce { get; }
    internal ReadOnlyMemory<byte> AuthenticatedEvidence => authenticatedEvidence.ToArray();
}

/// <summary>
/// Non-exportable identity of the protocol/session verifier which is allowed to
/// promote exact external evidence into MSG-01 capabilities. Release builds do
/// not expose a constructor or a caller-key factory. A future production source
/// must live in this assembly and be rooted directly in the reviewed DPE2 and
/// transport-receipt verifier.
/// </summary>
internal sealed class Msg01VerifiedSessionAuthority
{
    private delegate bool EvidenceAuthenticator(
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> authenticatedEvidence);

    private sealed class AuthorityState(
        ReadOnlySpan<byte> fingerprint,
        EvidenceAuthenticator authenticator)
    {
        internal byte[] Fingerprint { get; } = fingerprint.ToArray();
        internal EvidenceAuthenticator Authenticator { get; } = authenticator;
    }

    private static readonly ConditionalWeakTable<Msg01VerifiedSessionAuthority, AuthorityState> States = new();

    private Msg01VerifiedSessionAuthority()
    {
    }

    internal ReadOnlyMemory<byte> Fingerprint => RequireState().Fingerprint.ToArray();

    internal void VerifyAuthenticated(
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> authenticatedEvidence)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (authenticatedEvidence.IsEmpty
            || authenticatedEvidence.Length > MessagingV1Limits.MaxAuthenticatedEvidenceBytes)
            throw new ArgumentOutOfRangeException(nameof(authenticatedEvidence));
        if (!RequireState().Authenticator(context, authenticatedEvidence))
            throw new CryptographicException(
                "MSG-01 rejected evidence not authenticated by its verified session authority.");
    }

#if DEEP_TEST_INTERNALS
    internal static Msg01VerifiedSessionAuthority CreateTestEd25519(
        ReadOnlySpan<byte> verificationKey)
    {
        if (verificationKey.Length != 32 || verificationKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero test verification key is required.", nameof(verificationKey));
        var ownedKey = verificationKey.ToArray();
        var authority = new Msg01VerifiedSessionAuthority();
        var fingerprintInput = new byte["Deep/MSG-01/test-authority/v1\0"u8.Length + ownedKey.Length];
        "Deep/MSG-01/test-authority/v1\0"u8.CopyTo(fingerprintInput);
        ownedKey.CopyTo(fingerprintInput.AsSpan("Deep/MSG-01/test-authority/v1\0"u8.Length));
        var fingerprint = SHA256.HashData(fingerprintInput);
        CryptographicOperations.ZeroMemory(fingerprintInput);
        States.Add(authority, new AuthorityState(fingerprint, (context, evidence) =>
        {
            const int signatureLength = 64;
            if (evidence.Length <= signatureLength) return false;
            var transcript = CapabilityChecks.AuthenticationTranscript(
                context, evidence[..^signatureLength]);
            try
            {
                return PublicKeyAuth.VerifyDetached(
                    evidence[^signatureLength..].ToArray(), transcript, ownedKey);
            }
            catch (Exception exception) when (exception is CryptographicException or ArgumentException)
            {
                return false;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(transcript);
            }
        }));
        CryptographicOperations.ZeroMemory(fingerprint);
        return authority;
    }
#endif

    private AuthorityState RequireState()
    {
        if (!States.TryGetValue(this, out var state))
            throw new CryptographicException(
                "MSG-01 rejected an uninitialized or reflection-created session authority.");
        return state;
    }
}

internal sealed class MessageStoreAuthorityBinding : IDisposable
{
    private readonly Msg01VerifiedSessionAuthority authority;
    private int verifiedTransportClaimed;
    private int groupSafetyClaimed;
    private int disposed;

    internal MessageStoreAuthorityBinding(Msg01VerifiedSessionAuthority authority)
    {
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        _ = authority.Fingerprint;
    }

    internal IMessageVerifiedTransportHandoff ClaimHandoff()
    {
        ThrowIfDisposed();
        if (Interlocked.CompareExchange(ref verifiedTransportClaimed, 1, 0) != 0)
        {
            throw new InvalidOperationException(
                "The MSG-01 verified transport handoff is already owned by a runtime composition.");
        }

        return new StoreBoundVerifiedTransportHandoff(this);
    }

    internal IMessageGroupDispatchSafetyHandoff ClaimGroupSafetyHandoff()
    {
        ThrowIfDisposed();
        if (Interlocked.CompareExchange(ref groupSafetyClaimed, 1, 0) != 0)
        {
            throw new InvalidOperationException(
                "The MSG-01 GroupV1 safety handoff is already owned by a runtime composition.");
        }

        return new StoreBoundGroupDispatchSafetyHandoff(this);
    }

    internal void DemandTrustedIssuer(MessageStoreAuthorityBinding? candidate)
    {
        ThrowIfDisposed();
        if (!ReferenceEquals(this, candidate))
        {
            throw new CryptographicException(
                "MSG-01 rejected a capability issued for a foreign store trust root.");
        }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref disposed, 1);
    }

    private void VerifyShape(
        MessageCapabilityTrustedContext context,
        MessageEvidencePurpose expectedPurpose,
        ReadOnlySpan<byte> authenticatedEvidence)
    {
        ArgumentNullException.ThrowIfNull(context);
        ThrowIfDisposed();
        if (context.Purpose != expectedPurpose)
        {
            throw new CryptographicException("MSG-01 capability purpose is not trusted.");
        }
        if (authenticatedEvidence.IsEmpty
            || authenticatedEvidence.Length > MessagingV1Limits.MaxAuthenticatedEvidenceBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(authenticatedEvidence));
        }
    }

    private void VerifyAuthenticated(
        MessageCapabilityTrustedContext context,
        MessageEvidencePurpose expectedPurpose,
        ReadOnlySpan<byte> authenticatedEvidence)
    {
        VerifyShape(context, expectedPurpose, authenticatedEvidence);
        authority.VerifyAuthenticated(context, authenticatedEvidence);
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

    private sealed class StoreBoundVerifiedTransportHandoff(MessageStoreAuthorityBinding owner)
        : IMessageVerifiedTransportHandoff
    {
        public VerifiedTransportTargetOutcome VerifyTargetOutcome(
            MessageCapabilityTrustedContext context,
            ReadOnlySpan<byte> authenticatedEvidence)
        {
            owner.VerifyAuthenticated(context, MessageEvidencePurpose.TargetOutcome, authenticatedEvidence);
            return new FactoryTargetOutcome(owner, context, authenticatedEvidence);
        }

        public VerifiedTransportAttemptUncertainty VerifyAttemptUncertainty(
            MessageCapabilityTrustedContext context,
            ReadOnlySpan<byte> authenticatedEvidence)
        {
            owner.VerifyAuthenticated(context, MessageEvidencePurpose.AttemptUncertainty, authenticatedEvidence);
            return new FactoryAttemptUncertainty(owner, context, authenticatedEvidence);
        }

        public VerifiedTransportAttemptReconciliation VerifyReconciliation(
            MessageCapabilityTrustedContext context,
            ReadOnlySpan<byte> authenticatedEvidence)
        {
            owner.VerifyAuthenticated(context, MessageEvidencePurpose.AttemptReconciliation, authenticatedEvidence);
            return new FactoryAttemptReconciliation(owner, context, authenticatedEvidence);
        }

        public VerifiedLateMaterializationReceipt VerifyLateReceipt(
            MessageCapabilityTrustedContext context,
            ReadOnlySpan<byte> authenticatedEvidence)
        {
            owner.VerifyAuthenticated(context, MessageEvidencePurpose.LateMaterialization, authenticatedEvidence);
            return new FactoryLateMaterializationReceipt(owner, context, authenticatedEvidence);
        }

        public InboxMaterializationRequest VerifyInbound(
            MessageCapabilityTrustedContext context,
            SemanticClaimCandidate claim,
            ReadOnlySpan<byte> canonicalEvent,
            RatchetSessionId32 sessionId,
            RatchetStateHash32 beforeHash,
            RatchetStateHash32 afterHash,
            ReadOnlySpan<byte> sealedRatchetState,
            DateTimeOffset occurredAt,
            ReadOnlySpan<byte> authenticatedEvidence)
        {
            ArgumentNullException.ThrowIfNull(claim);
            ArgumentNullException.ThrowIfNull(sessionId);
            ArgumentNullException.ThrowIfNull(beforeHash);
            ArgumentNullException.ThrowIfNull(afterHash);
            owner.VerifyAuthenticated(context, MessageEvidencePurpose.InboundMaterialization, authenticatedEvidence);
            if (!context.ClaimKey.Equals(claim.Key)
                || context.RatchetSessionId is null
                || !context.RatchetSessionId.Equals(sessionId)
                || canonicalEvent.Length is 0 or > MessagingV1Limits.MaxCanonicalEventBytes
                || sealedRatchetState.Length is 0 or > MessagingV1Limits.MaxSealedRatchetStateBytes
                || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(canonicalEvent), claim.EventHash.Span)
                || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(sealedRatchetState), afterHash.Span))
            {
                throw new CryptographicException("MSG-01 inbound event/ratchet binding failed.");
            }

            return new FactoryInboxMaterializationRequest(
                owner, context.Scope, claim, canonicalEvent, sessionId, beforeHash, afterHash,
                sealedRatchetState, context.ReceiptId!, Hash(authenticatedEvidence),
                authenticatedEvidence, context.ReplayCounter, context.ReplayNonce.Span, occurredAt);
        }

        private static MessageEvidenceHash32 Hash(ReadOnlySpan<byte> value) =>
            MessageEvidenceHash32.FromBytes(SHA256.HashData(value));
    }

    private sealed class StoreBoundGroupDispatchSafetyHandoff(MessageStoreAuthorityBinding owner)
        : IMessageGroupDispatchSafetyHandoff
    {
        public VerifiedLocalGroupDispatchBlock MintLocalBlock(
            GroupHeadReadLease headLease,
            LogicalOutboxSnapshot outbox,
            LogicalTargetSnapshot target,
            GroupMessageFirstDispatchDisposition disposition,
            DateTimeOffset occurredAt)
        {
            owner.ThrowIfDisposed();
            _ = headLease.DemandActiveHead();
            return new FactoryLocalGroupDispatchBlock(
                owner, headLease, outbox, target, disposition, occurredAt);
        }
    }

    private sealed class FactoryTargetOutcome(
        MessageStoreAuthorityBinding issuer,
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> authenticatedEvidence)
        : VerifiedTransportTargetOutcome(issuer, context, authenticatedEvidence);

    private sealed class FactoryAttemptUncertainty(
        MessageStoreAuthorityBinding issuer,
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> authenticatedEvidence)
        : VerifiedTransportAttemptUncertainty(issuer, context, authenticatedEvidence);

    private sealed class FactoryAttemptReconciliation(
        MessageStoreAuthorityBinding issuer,
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> authenticatedEvidence)
        : VerifiedTransportAttemptReconciliation(issuer, context, authenticatedEvidence);

    private sealed class FactoryLateMaterializationReceipt(
        MessageStoreAuthorityBinding issuer,
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> authenticatedEvidence)
        : VerifiedLateMaterializationReceipt(issuer, context, authenticatedEvidence);

    private sealed class FactoryInboxMaterializationRequest(
        MessageStoreAuthorityBinding issuer,
        MessageStoreScope scope,
        SemanticClaimCandidate claim,
        ReadOnlySpan<byte> canonicalEvent,
        RatchetSessionId32 sessionId,
        RatchetStateHash32 beforeHash,
        RatchetStateHash32 afterHash,
        ReadOnlySpan<byte> sealedRatchetState,
        MessageReceiptId32 receiptId,
        MessageEvidenceHash32 evidenceHash,
        ReadOnlySpan<byte> authenticatedReceipt,
        ulong replayCounter,
        ReadOnlySpan<byte> replayNonce,
        DateTimeOffset occurredAt)
        : InboxMaterializationRequest(
            issuer, scope, claim, canonicalEvent, sessionId, beforeHash, afterHash,
            sealedRatchetState, receiptId, evidenceHash, authenticatedReceipt,
            replayCounter, replayNonce, occurredAt);

    private sealed class FactoryLocalGroupDispatchBlock(
        MessageStoreAuthorityBinding issuer,
        GroupHeadReadLease headLease,
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot target,
        GroupMessageFirstDispatchDisposition disposition,
        DateTimeOffset occurredAt)
        : VerifiedLocalGroupDispatchBlock(
            issuer, headLease, outbox, target, disposition, occurredAt);
}

internal sealed class SemanticClaimCandidate
{
    internal SemanticClaimCandidate(MessagingAccountId32 authorAccountId, MessagingDeviceId32 authorDeviceId,
        ConversationId32 conversationId, SemanticMessageId32 semanticMessageId, MessageEventHash32 eventHash)
    {
        ArgumentNullException.ThrowIfNull(authorAccountId); ArgumentNullException.ThrowIfNull(authorDeviceId);
        ArgumentNullException.ThrowIfNull(conversationId); ArgumentNullException.ThrowIfNull(semanticMessageId); ArgumentNullException.ThrowIfNull(eventHash);
        AuthorAccountId = MessagingAccountId32.FromBytes(authorAccountId.Span);
        AuthorDeviceId = MessagingDeviceId32.FromBytes(authorDeviceId.Span);
        Key = new(AuthorAccountId, conversationId, semanticMessageId);
        EventHash = MessageEventHash32.FromBytes(eventHash.Span);
    }
    internal MessagingAccountId32 AuthorAccountId { get; }
    internal MessagingDeviceId32 AuthorDeviceId { get; }
    internal SemanticClaimKey Key { get; }
    internal MessageEventHash32 EventHash { get; }
}

internal sealed class TargetAttemptPlan
{
    private readonly byte[] ciphertext;
    internal TargetAttemptPlan(RecipientDeviceTarget target, TransportAttemptId16 attemptId,
        TransportRequestHash32 requestHash, RatchetStateHash32 ratchetBeforeHash,
        RatchetTransitionHash32 transitionHash, DirectoryHeadHash32 directoryHeadHash,
        MessageTargetOperationId32 operationId, MessageBindingHash32 bindingHash,
        ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(target); ArgumentNullException.ThrowIfNull(attemptId); ArgumentNullException.ThrowIfNull(requestHash); ArgumentNullException.ThrowIfNull(ratchetBeforeHash); ArgumentNullException.ThrowIfNull(transitionHash); ArgumentNullException.ThrowIfNull(directoryHeadHash); ArgumentNullException.ThrowIfNull(operationId); ArgumentNullException.ThrowIfNull(bindingHash);
        Target = new(target.AccountId, target.DeviceId); AttemptId = TransportAttemptId16.FromBytes(attemptId.Span);
        RequestHash = TransportRequestHash32.FromBytes(requestHash.Span); RatchetBeforeHash = RatchetStateHash32.FromBytes(ratchetBeforeHash.Span); RatchetTransitionHash = RatchetTransitionHash32.FromBytes(transitionHash.Span);
        DirectoryHeadHash = DirectoryHeadHash32.FromBytes(directoryHeadHash.Span); OperationId=MessageTargetOperationId32.FromBytes(operationId.Span); BindingHash=MessageBindingHash32.FromBytes(bindingHash.Span);
        if (ciphertext.Length is < 1 or > MessagingV1Limits.MaxCiphertextBytes)
            throw new ArgumentOutOfRangeException(nameof(ciphertext));
        this.ciphertext = ciphertext.ToArray();
    }
    internal RecipientDeviceTarget Target { get; }
    internal TransportAttemptId16 AttemptId { get; }
    internal TransportRequestHash32 RequestHash { get; }
    internal RatchetStateHash32 RatchetBeforeHash { get; }
    internal RatchetTransitionHash32 RatchetTransitionHash { get; }
    internal DirectoryHeadHash32 DirectoryHeadHash { get; }
    internal MessageTargetOperationId32 OperationId { get; }
    internal MessageBindingHash32 BindingHash { get; }
    internal ReadOnlyMemory<byte> Ciphertext => ciphertext.ToArray();
}

internal abstract class VerifiedTransportTargetOutcome
{
    private readonly byte[] evidence;
    private readonly byte[] replayNonce;
    private readonly MessageStoreAuthorityBinding? issuer;
    private protected VerifiedTransportTargetOutcome(
        MessageStoreAuthorityBinding issuer,
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> sealedEvidence)
    {
        this.issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        Scope = LogicalOutboxSnapshot.Copy(context.Scope); ClaimKey = new(context.ClaimKey.AuthorAccountId, context.ClaimKey.ConversationId, context.ClaimKey.SemanticMessageId);
        Target = new(context.Target!.AccountId, context.Target.DeviceId); AttemptId = TransportAttemptId16.FromBytes(context.AttemptId!.Span); Kind = context.OutcomeKind!.Value;
        TargetOperationId = MessageTargetOperationId32.FromBytes(context.TargetOperationId!.Span); BindingHash = MessageBindingHash32.FromBytes(context.BindingHash!.Span);
        ReplayCounter = context.ReplayCounter; replayNonce = context.ReplayNonce.ToArray();
        EvidenceHash = MessageEvidenceHash32.FromBytes(SHA256.HashData(sealedEvidence)); evidence = sealedEvidence.ToArray();
    }
    internal MessageStoreScope Scope { get; } internal SemanticClaimKey ClaimKey { get; } internal RecipientDeviceTarget Target { get; }
    internal TransportAttemptId16 AttemptId { get; } internal VerifiedTargetOutcomeKind Kind { get; }
    internal MessageTargetOperationId32 TargetOperationId { get; } internal MessageBindingHash32 BindingHash { get; }
    internal ulong ReplayCounter { get; } internal ReadOnlyMemory<byte> ReplayNonce => replayNonce.ToArray();
    internal MessageEvidenceHash32 EvidenceHash { get; } internal ReadOnlyMemory<byte> Evidence => evidence.ToArray();
    internal MessageMutationId32 OperationId => CapabilityChecks.OperationId(new(
        MessageEvidencePurpose.TargetOutcome, Scope, ClaimKey, Target, AttemptId, Kind, null, EvidenceHash, Evidence.Span,
        TargetOperationId, BindingHash, ReplayCounter, ReplayNonce.Span));
    internal void DemandIssuedBy(MessageStoreAuthorityBinding expectedIssuer) =>
        expectedIssuer.DemandTrustedIssuer(issuer);
    internal void DemandFactoryIssued()
    {
        if (issuer is null) throw new CryptographicException("MSG-01 rejected an uninitialized capability.");
    }
}
internal abstract class VerifiedTransportAttemptUncertainty
{
    private readonly byte[] evidence;
    private readonly byte[] replayNonce;
    private readonly MessageStoreAuthorityBinding? issuer;
    private protected VerifiedTransportAttemptUncertainty(MessageStoreAuthorityBinding issuer, MessageCapabilityTrustedContext context, ReadOnlySpan<byte> sealedEvidence)
    { this.issuer=issuer??throw new ArgumentNullException(nameof(issuer)); Scope=LogicalOutboxSnapshot.Copy(context.Scope); ClaimKey=new(context.ClaimKey.AuthorAccountId,context.ClaimKey.ConversationId,context.ClaimKey.SemanticMessageId); Target=new(context.Target!.AccountId,context.Target.DeviceId); AttemptId=TransportAttemptId16.FromBytes(context.AttemptId!.Span); TargetOperationId=MessageTargetOperationId32.FromBytes(context.TargetOperationId!.Span); BindingHash=MessageBindingHash32.FromBytes(context.BindingHash!.Span); ReplayCounter=context.ReplayCounter; replayNonce=context.ReplayNonce.ToArray(); EvidenceHash=MessageEvidenceHash32.FromBytes(SHA256.HashData(sealedEvidence)); evidence=sealedEvidence.ToArray(); }
    internal MessageStoreScope Scope { get; } internal SemanticClaimKey ClaimKey { get; } internal RecipientDeviceTarget Target { get; } internal TransportAttemptId16 AttemptId { get; } internal MessageEvidenceHash32 EvidenceHash { get; } internal ReadOnlyMemory<byte> Evidence => evidence.ToArray();
    internal MessageTargetOperationId32 TargetOperationId { get; } internal MessageBindingHash32 BindingHash { get; }
    internal ulong ReplayCounter { get; } internal ReadOnlyMemory<byte> ReplayNonce => replayNonce.ToArray();
    internal MessageMutationId32 OperationId => CapabilityChecks.OperationId(new(
        MessageEvidencePurpose.AttemptUncertainty, Scope, ClaimKey, Target, AttemptId, null, null, EvidenceHash, Evidence.Span,
        TargetOperationId, BindingHash, ReplayCounter, ReplayNonce.Span));
    internal void DemandIssuedBy(MessageStoreAuthorityBinding expectedIssuer) =>
        expectedIssuer.DemandTrustedIssuer(issuer);
    internal void DemandFactoryIssued()
    {
        if (issuer is null) throw new CryptographicException("MSG-01 rejected an uninitialized capability.");
    }
}
internal abstract class VerifiedTransportAttemptReconciliation
{
    private readonly byte[] evidence;
    private readonly byte[] replayNonce;
    private readonly MessageStoreAuthorityBinding? issuer;
    private protected VerifiedTransportAttemptReconciliation(MessageStoreAuthorityBinding issuer, MessageCapabilityTrustedContext context, ReadOnlySpan<byte> sealedEvidence)
    { this.issuer=issuer??throw new ArgumentNullException(nameof(issuer)); Scope=LogicalOutboxSnapshot.Copy(context.Scope); ClaimKey=new(context.ClaimKey.AuthorAccountId,context.ClaimKey.ConversationId,context.ClaimKey.SemanticMessageId); Target=new(context.Target!.AccountId,context.Target.DeviceId); AttemptId=TransportAttemptId16.FromBytes(context.AttemptId!.Span); Kind=context.OutcomeKind!.Value; TargetOperationId=MessageTargetOperationId32.FromBytes(context.TargetOperationId!.Span); BindingHash=MessageBindingHash32.FromBytes(context.BindingHash!.Span); ReplayCounter=context.ReplayCounter; replayNonce=context.ReplayNonce.ToArray(); EvidenceHash=MessageEvidenceHash32.FromBytes(SHA256.HashData(sealedEvidence)); evidence=sealedEvidence.ToArray(); }
    internal MessageStoreScope Scope { get; } internal SemanticClaimKey ClaimKey { get; }
    internal RecipientDeviceTarget Target { get; } internal TransportAttemptId16 AttemptId { get; }
    internal VerifiedTargetOutcomeKind Kind { get; } internal MessageTargetOperationId32 TargetOperationId { get; }
    internal MessageBindingHash32 BindingHash { get; } internal ulong ReplayCounter { get; }
    internal ReadOnlyMemory<byte> ReplayNonce => replayNonce.ToArray(); internal MessageEvidenceHash32 EvidenceHash { get; }
    internal ReadOnlyMemory<byte> Evidence => evidence.ToArray();
    internal MessageMutationId32 OperationId => CapabilityChecks.OperationId(new(
        MessageEvidencePurpose.AttemptReconciliation, Scope, ClaimKey, Target, AttemptId, Kind, null,
        EvidenceHash, Evidence.Span, TargetOperationId, BindingHash, ReplayCounter, ReplayNonce.Span));
    internal void DemandIssuedBy(MessageStoreAuthorityBinding expectedIssuer) =>
        expectedIssuer.DemandTrustedIssuer(issuer);
    internal void DemandFactoryIssued()
    {
        if (issuer is null) throw new CryptographicException("MSG-01 rejected an uninitialized capability.");
    }
}
internal abstract class VerifiedLateMaterializationReceipt
{
    private readonly byte[] evidence;
    private readonly byte[] replayNonce;
    private readonly MessageStoreAuthorityBinding? issuer;
    private protected VerifiedLateMaterializationReceipt(MessageStoreAuthorityBinding issuer, MessageCapabilityTrustedContext context, ReadOnlySpan<byte> sealedEvidence)
    { this.issuer=issuer??throw new ArgumentNullException(nameof(issuer)); Scope=LogicalOutboxSnapshot.Copy(context.Scope); ClaimKey=new(context.ClaimKey.AuthorAccountId,context.ClaimKey.ConversationId,context.ClaimKey.SemanticMessageId); Target=new(context.Target!.AccountId,context.Target.DeviceId); AcceptedAttemptId=TransportAttemptId16.FromBytes(context.AttemptId!.Span); ReceiptId=MessageReceiptId32.FromBytes(context.ReceiptId!.Span); TargetOperationId=MessageTargetOperationId32.FromBytes(context.TargetOperationId!.Span); BindingHash=MessageBindingHash32.FromBytes(context.BindingHash!.Span); ReplayCounter=context.ReplayCounter; replayNonce=context.ReplayNonce.ToArray(); EvidenceHash=MessageEvidenceHash32.FromBytes(SHA256.HashData(sealedEvidence)); evidence=sealedEvidence.ToArray(); }
    internal MessageStoreScope Scope { get; } internal SemanticClaimKey ClaimKey { get; } internal RecipientDeviceTarget Target { get; } internal TransportAttemptId16 AcceptedAttemptId { get; } internal MessageReceiptId32 ReceiptId { get; } internal MessageEvidenceHash32 EvidenceHash { get; } internal ReadOnlyMemory<byte> Evidence => evidence.ToArray();
    internal MessageTargetOperationId32 TargetOperationId { get; } internal MessageBindingHash32 BindingHash { get; }
    internal ulong ReplayCounter { get; } internal ReadOnlyMemory<byte> ReplayNonce => replayNonce.ToArray();
    internal MessageMutationId32 OperationId => CapabilityChecks.OperationId(new(
        MessageEvidencePurpose.LateMaterialization, Scope, ClaimKey, Target, AcceptedAttemptId,
        VerifiedTargetOutcomeKind.Materialized, ReceiptId, EvidenceHash, Evidence.Span, TargetOperationId, BindingHash,
        ReplayCounter, ReplayNonce.Span));
    internal void DemandIssuedBy(MessageStoreAuthorityBinding expectedIssuer) =>
        expectedIssuer.DemandTrustedIssuer(issuer);
    internal void DemandFactoryIssued()
    {
        if (issuer is null) throw new CryptographicException("MSG-01 rejected an uninitialized capability.");
    }
}

internal static class CapabilityChecks
{
    internal static byte[] AuthenticationTranscript(
        MessageCapabilityTrustedContext context,
        ReadOnlySpan<byte> canonicalEvidence)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (canonicalEvidence.IsEmpty)
        {
            throw new ArgumentException("Canonical authenticated evidence is empty.", nameof(canonicalEvidence));
        }
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        hash.AppendData("Deep/MSG-01/external-evidence/v1\0"u8);
        AppendContext(hash, context);
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
            length, checked((uint)canonicalEvidence.Length));
        hash.AppendData(length);
        hash.AppendData(canonicalEvidence);
        return hash.GetHashAndReset();
    }

    internal static MessageMutationId32 OperationId(MessageCapabilityEvidence evidence)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        // The durable operation key is deliberately only the authority replay
        // identity inside one store scope. Reusing a counter/nonce for changed
        // context therefore collides with the prior operation and is rejected
        // by the exact mutation fingerprint, including after restart.
        hash.AppendData("Deep/MSG-01/evidence-replay/v1\0"u8);
        hash.AppendData(evidence.Scope.LocalAccountId.ToArray());
        Span<byte> generation = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
            generation, evidence.Scope.DatabaseGeneration);
        hash.AppendData(generation);
        hash.AppendData(evidence.Scope.StoreInstanceId.ToArray());
        Span<byte> replayCounter = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
            replayCounter, evidence.ReplayCounter);
        hash.AppendData(replayCounter);
        hash.AppendData(evidence.ReplayNonce.Span);
        return MessageMutationId32.FromBytes(hash.GetHashAndReset());
    }

    internal static void AppendContext(IncrementalHash hash, MessageCapabilityTrustedContext context)
    {
        hash.AppendData([(byte)context.Purpose]);
        hash.AppendData(context.Scope.LocalAccountId.ToArray());
        Span<byte> generation = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(generation, context.Scope.DatabaseGeneration);
        hash.AppendData(generation);
        hash.AppendData(context.Scope.StoreInstanceId.ToArray());
        hash.AppendData(context.ClaimKey.AuthorAccountId.ToArray());
        hash.AppendData(context.ClaimKey.ConversationId.ToArray());
        hash.AppendData(context.ClaimKey.SemanticMessageId.ToArray());
        if (context.Target is not null) { hash.AppendData(context.Target.AccountId.ToArray()); hash.AppendData(context.Target.DeviceId.ToArray()); }
        if (context.AttemptId is not null) hash.AppendData(context.AttemptId.ToArray());
        if (context.OutcomeKind is not null) hash.AppendData([(byte)context.OutcomeKind.Value]);
        if (context.ReceiptId is not null) hash.AppendData(context.ReceiptId.ToArray());
        if (context.TargetOperationId is not null) hash.AppendData(context.TargetOperationId.ToArray());
        if (context.BindingHash is not null) hash.AppendData(context.BindingHash.ToArray());
        hash.AppendData(context.RequestHash.Span);
        hash.AppendData(context.EnvelopeHash.Span);
        hash.AppendData(context.RatchetBeforeHash.Span);
        hash.AppendData(context.RatchetAfterHash.Span);
        if (context.RatchetSessionId is not null)
            hash.AppendData(context.RatchetSessionId.ToArray());
        Span<byte> replayCounter = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
            replayCounter, context.ReplayCounter);
        hash.AppendData(replayCounter);
        hash.AppendData(context.ReplayNonce.Span);
    }

}

/// <summary>
/// Non-forgeable, store-bound proof that the GroupV1 safety boundary rejected
/// one exact first durable DGM1 attempt while holding the exact group-head
/// lease. It is local authority, not a transport receipt.
/// </summary>
internal abstract class VerifiedLocalGroupDispatchBlock
{
    private readonly MessageStoreAuthorityBinding? issuer;
    private readonly byte[] exactDgm1;
    private readonly byte[] groupHeadFingerprint;

    private protected VerifiedLocalGroupDispatchBlock(
        MessageStoreAuthorityBinding issuer,
        GroupHeadReadLease headLease,
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot target,
        GroupMessageFirstDispatchDisposition disposition,
        DateTimeOffset occurredAt)
    {
        this.issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        ArgumentNullException.ThrowIfNull(headLease);
        ArgumentNullException.ThrowIfNull(outbox);
        ArgumentNullException.ThrowIfNull(target);
        if (disposition is not (GroupMessageFirstDispatchDisposition.GroupNotFound
            or GroupMessageFirstDispatchDisposition.StaleGroupState
            or GroupMessageFirstDispatchDisposition.ForkLatched
            or GroupMessageFirstDispatchDisposition.TargetRemoved))
            throw new ArgumentOutOfRangeException(nameof(disposition));
        if (outbox.PayloadKind != MessagePayloadKind.GroupMessage
            || outbox.ClaimKey.AuthorDeviceId is null
            || outbox.Revision == 0
            || target.ActiveAttemptId is null
            || target.UnresolvedAttemptId is null
            || !target.ActiveAttemptId.Equals(target.UnresolvedAttemptId)
            || target.LastAttemptId is not null
            || target.OutcomeUnknown
            || target.OperationId is null
            || target.BindingHash is null
            || target.RequestHash is null
            || target.RatchetBeforeHash is null
            || target.RatchetTransitionHash is null)
            throw new InvalidDataException("The local GroupV1 block is not bound to an exact first attempt.");

        exactDgm1 = outbox.CanonicalPayload;
        if (exactDgm1.Length is < 1 or > MessagingV1Limits.MaxCanonicalEventBytes)
            throw new InvalidDataException("The local GroupV1 block DGM1 exceeds its bound.");
        var message = GroupCodec.Decode("DGM1", exactDgm1) as GroupApplicationMessageRecord
            ?? throw new InvalidDataException("The local GroupV1 block payload is not exact DGM1.");
        if (!message.CanonicalBytes.Span.SequenceEqual(exactDgm1)
            || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(exactDgm1), outbox.EventHash.Span)
            || !message.Field(2).Span.SequenceEqual(outbox.ConversationId.Span))
            throw new InvalidDataException("The local GroupV1 block DGM1 binding is invalid.");

        var leasedHead = headLease.DemandActiveHead();
        if (disposition == GroupMessageFirstDispatchDisposition.GroupNotFound)
        {
            if (leasedHead is not null)
                throw new InvalidDataException("GroupNotFound requires an empty exact group-head lease.");
            GroupHeadRevision = null;
            groupHeadFingerprint = new byte[32];
        }
        else
        {
            if (leasedHead is null
                || !leasedHead.GroupId.Span.SequenceEqual(message.Field(2).Span)
                || !leasedHead.NetworkId.Span.SequenceEqual(message.Field(1).Span))
                throw new InvalidDataException("The local GroupV1 block lease does not bind the DGM1 group.");
            if (disposition == GroupMessageFirstDispatchDisposition.ForkLatched
                && !leasedHead.ForkLatched)
                throw new InvalidDataException("ForkLatched requires a fork-latched exact group head.");
            GroupHeadRevision = leasedHead.Revision;
            groupHeadFingerprint = ComputeGroupHeadFingerprint(leasedHead);
        }

        Scope = LogicalOutboxSnapshot.Copy(outbox.StoreScope);
        ClaimKey = new SemanticClaimKey(
            outbox.AuthorAccountId, outbox.AuthorDeviceId,
            outbox.ConversationId, outbox.SemanticMessageId);
        EventHash = MessageEventHash32.FromBytes(outbox.EventHash.Span);
        Target = new RecipientDeviceTarget(target.Target.AccountId, target.Target.DeviceId);
        DirectoryHeadHash = DirectoryHeadHash32.FromBytes(target.DirectoryHeadHash.Span);
        TargetOperationId = MessageTargetOperationId32.FromBytes(target.OperationId.Span);
        BindingHash = MessageBindingHash32.FromBytes(target.BindingHash.Span);
        AttemptId = TransportAttemptId16.FromBytes(target.ActiveAttemptId.Span);
        RequestHash = TransportRequestHash32.FromBytes(target.RequestHash.Span);
        RatchetBeforeHash = RatchetStateHash32.FromBytes(target.RatchetBeforeHash.Span);
        RatchetTransitionHash = RatchetTransitionHash32.FromBytes(target.RatchetTransitionHash.Span);
        GroupId = GroupId32.FromBytes(message.Field(2).Span);
        OutboxRevision = outbox.Revision;
        Disposition = disposition;
        OccurredAt = LogicalOutboxSeed.Canonical(occurredAt);
        if (OccurredAt < outbox.CreatedAt)
            throw new ArgumentOutOfRangeException(nameof(occurredAt));
        OperationId = ComputeOperationId();
    }

    internal MessageStoreScope Scope { get; }
    internal SemanticClaimKey ClaimKey { get; }
    internal MessageEventHash32 EventHash { get; }
    internal RecipientDeviceTarget Target { get; }
    internal DirectoryHeadHash32 DirectoryHeadHash { get; }
    internal MessageTargetOperationId32 TargetOperationId { get; }
    internal MessageBindingHash32 BindingHash { get; }
    internal TransportAttemptId16 AttemptId { get; }
    internal TransportRequestHash32 RequestHash { get; }
    internal RatchetStateHash32 RatchetBeforeHash { get; }
    internal RatchetTransitionHash32 RatchetTransitionHash { get; }
    internal GroupId32 GroupId { get; }
    internal ulong OutboxRevision { get; }
    internal ulong? GroupHeadRevision { get; }
    internal GroupMessageFirstDispatchDisposition Disposition { get; }
    internal DateTimeOffset OccurredAt { get; }
    internal MessageMutationId32 OperationId { get; }
    internal ReadOnlyMemory<byte> ExactDgm1 => exactDgm1.ToArray();
    internal ReadOnlyMemory<byte> GroupHeadFingerprint => groupHeadFingerprint.ToArray();

    internal void DemandIssuedBy(MessageStoreAuthorityBinding expectedIssuer) =>
        expectedIssuer.DemandTrustedIssuer(issuer);

    internal void DemandFactoryIssued()
    {
        if (issuer is null)
            throw new CryptographicException("MSG-01 rejected an uninitialized local GroupV1 capability.");
    }

    private MessageMutationId32 ComputeOperationId()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/MSG-01/local-group-dispatch-block/v1\0"u8);
        hash.AppendData(Scope.LocalAccountId.Span);
        AppendU64(hash, Scope.DatabaseGeneration);
        hash.AppendData(Scope.StoreInstanceId.Span);
        hash.AppendData(ClaimKey.AuthorAccountId.Span);
        hash.AppendData(ClaimKey.AuthorDeviceId!.Span);
        hash.AppendData(ClaimKey.ConversationId.Span);
        hash.AppendData(ClaimKey.SemanticMessageId.Span);
        hash.AppendData(EventHash.Span);
        hash.AppendData(Target.AccountId.Span);
        hash.AppendData(Target.DeviceId.Span);
        hash.AppendData(DirectoryHeadHash.Span);
        hash.AppendData(TargetOperationId.Span);
        hash.AppendData(BindingHash.Span);
        hash.AppendData(AttemptId.Span);
        hash.AppendData(RequestHash.Span);
        hash.AppendData(RatchetBeforeHash.Span);
        hash.AppendData(RatchetTransitionHash.Span);
        hash.AppendData(GroupId.Span);
        AppendU64(hash, OutboxRevision);
        AppendU64(hash, GroupHeadRevision ?? 0);
        hash.AppendData([(byte)Disposition]);
        AppendU64(hash, checked((ulong)OccurredAt.ToUnixTimeMilliseconds()));
        hash.AppendData(SHA256.HashData(exactDgm1));
        hash.AppendData(groupHeadFingerprint);
        return MessageMutationId32.FromBytes(hash.GetHashAndReset());
    }

    private static byte[] ComputeGroupHeadFingerprint(GroupHeadSnapshot head)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/MSG-01/group-head-lease/v1\0"u8);
        hash.AppendData(head.NetworkId.Span);
        hash.AppendData(head.GroupId.Span);
        AppendU64(hash, head.Epoch);
        AppendU64(hash, head.Revision);
        hash.AppendData(head.CommitHash.Span);
        hash.AppendData(head.PackageHash.Span);
        hash.AppendData(head.PredecessorHash.Span);
        hash.AppendData(SHA256.HashData(head.ExactCanonicalCommit.Span));
        hash.AppendData(SHA256.HashData(head.ExactCanonicalPackage.Span));
        hash.AppendData(head.ExactVerifiedGcp1Sha256.Span);
        hash.AppendData([head.ForkLatched ? (byte)1 : (byte)0]);
        return hash.GetHashAndReset();
    }

    private static void AppendU64(IncrementalHash hash, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        hash.AppendData(bytes);
    }
}

internal sealed class PreparedMessageMutation
{
    private PreparedMessageMutation(MessageMutationKind kind, LogicalOutboxSnapshot head, MessageMutationId32 operationId, DateTimeOffset occurredAt, IEnumerable<FanoutTargetSeed>? fanout=null, IEnumerable<TargetAttemptPlan>? attempts=null, VerifiedTransportTargetOutcome? outcome=null, VerifiedTransportAttemptUncertainty? uncertainty=null, VerifiedTransportAttemptReconciliation? reconciliation=null, VerifiedLateMaterializationReceipt? lateReceipt=null, VerifiedLocalGroupDispatchBlock? groupDispatchBlock=null)
    { Kind=kind; Scope=LogicalOutboxSnapshot.Copy(head.StoreScope); ClaimKey=head.ClaimKey.AuthorDeviceId is null ? new(head.ClaimKey.AuthorAccountId,head.ClaimKey.ConversationId,head.ClaimKey.SemanticMessageId) : new(head.ClaimKey.AuthorAccountId,head.ClaimKey.AuthorDeviceId,head.ClaimKey.ConversationId,head.ClaimKey.SemanticMessageId); ExpectedRevision=head.Revision; OperationId=MessageMutationId32.FromBytes(operationId.Span); OccurredAt=LogicalOutboxSeed.Canonical(occurredAt); Fanout=(fanout??[]).Select(x=>new FanoutTargetSeed(x.Target,x.DirectoryHeadHash,x.OperationId,x.BindingHash)).OrderBy(x=>x.Target).ToArray(); Attempts=(attempts??[]).Select(x=>new TargetAttemptPlan(x.Target,x.AttemptId,x.RequestHash,x.RatchetBeforeHash,x.RatchetTransitionHash,x.DirectoryHeadHash,x.OperationId,x.BindingHash,x.Ciphertext.Span)).OrderBy(x=>x.Target).ToArray(); Outcome=outcome; Uncertainty=uncertainty; Reconciliation=reconciliation; LateReceipt=lateReceipt; GroupDispatchBlock=groupDispatchBlock; }
    internal MessageMutationKind Kind { get; } internal MessageStoreScope Scope { get; } internal SemanticClaimKey ClaimKey { get; } internal ulong ExpectedRevision { get; } internal MessageMutationId32 OperationId { get; } internal DateTimeOffset OccurredAt { get; }
    internal IReadOnlyList<FanoutTargetSeed> Fanout { get; } internal IReadOnlyList<TargetAttemptPlan> Attempts { get; } internal VerifiedTransportTargetOutcome? Outcome { get; } internal VerifiedTransportAttemptUncertainty? Uncertainty { get; } internal VerifiedTransportAttemptReconciliation? Reconciliation { get; } internal VerifiedLateMaterializationReceipt? LateReceipt { get; } internal VerifiedLocalGroupDispatchBlock? GroupDispatchBlock { get; }
    internal RecipientDeviceTarget? Target => Outcome?.Target ?? Uncertainty?.Target ?? Reconciliation?.Target ?? LateReceipt?.Target ?? GroupDispatchBlock?.Target ?? (Attempts.Count == 1 ? Attempts[0].Target : null);
    internal TransportAttemptId16? AttemptId => Outcome?.AttemptId ?? Uncertainty?.AttemptId ?? Reconciliation?.AttemptId ?? LateReceipt?.AcceptedAttemptId ?? GroupDispatchBlock?.AttemptId ?? (Attempts.Count == 1 ? Attempts[0].AttemptId : null);
    internal static PreparedMessageMutation PrepareFanout(LogicalOutboxSnapshot h, MessageMutationId32 o, IEnumerable<FanoutTargetSeed> f, DateTimeOffset at)
    { Head(h);var a=f?.ToArray()??throw new ArgumentNullException(nameof(f));if(a.Length is <1 or > MessagingV1Limits.MaxFanoutTargets||a.Select(x=>x.Target).Distinct().Count()!=a.Length)throw new ArgumentOutOfRangeException(nameof(f));if(h.State!=LogicalOutboxState.Queued||h.Targets.Count!=0)throw new InvalidOperationException("Fanout can only be prepared from Queued.");return new(MessageMutationKind.PrepareFanout,h,o,at,fanout:a); }
    internal static PreparedMessageMutation StartSending(LogicalOutboxSnapshot h, MessageMutationId32 o, IEnumerable<TargetAttemptPlan> a, DateTimeOffset at)
    { Head(h);var x=a?.ToArray()??throw new ArgumentNullException(nameof(a));if(x.Length is <1 or > MessagingV1Limits.MaxFanoutTargets||x.Select(v=>v.Target).Distinct().Count()!=x.Length||x.Select(v=>v.AttemptId).Distinct().Count()!=x.Length||x.Select(v=>v.OperationId).Distinct().Count()!=x.Length||x.Select(v=>v.BindingHash).Distinct().Count()!=x.Length)throw new ArgumentOutOfRangeException(nameof(a));if(h.State is not(LogicalOutboxState.FanoutPrepared or LogicalOutboxState.Sending or LogicalOutboxState.PartiallyAccepted))throw new InvalidOperationException("Dispatch is not allowed from this state.");return new(MessageMutationKind.StartSending,h,o,at,attempts:x); }
    internal static PreparedMessageMutation FromVerifiedOutcome(LogicalOutboxSnapshot h, VerifiedTransportTargetOutcome x, DateTimeOffset at)
    { Head(h);ArgumentNullException.ThrowIfNull(x);x.DemandFactoryIssued();if(!x.Scope.Equals(h.StoreScope)||!x.ClaimKey.Equals(h.ClaimKey)||!h.Targets.Any(t=>!t.OutcomeUnknown&&MatchesActiveAttempt(t,x.Target,x.AttemptId,x.TargetOperationId,x.BindingHash)))throw new InvalidOperationException("Outcome is not bound to a fresh active target attempt.");return new(MessageMutationKind.TargetOutcome,h,x.OperationId,at,outcome:x); }
    internal static PreparedMessageMutation MarkOutcomeUnknown(LogicalOutboxSnapshot h, VerifiedTransportAttemptUncertainty x, DateTimeOffset at)
    { Head(h);ArgumentNullException.ThrowIfNull(x);x.DemandFactoryIssued();if(!x.Scope.Equals(h.StoreScope)||!x.ClaimKey.Equals(h.ClaimKey)||!h.Targets.Any(t=>MatchesActiveAttempt(t,x.Target,x.AttemptId,x.TargetOperationId,x.BindingHash)))throw new InvalidOperationException("Uncertainty is not bound to an active target attempt.");return new(MessageMutationKind.MarkOutcomeUnknown,h,x.OperationId,at,uncertainty:x); }
    internal static PreparedMessageMutation ReconcileOutcomeUnknown(LogicalOutboxSnapshot h, VerifiedTransportAttemptReconciliation x, DateTimeOffset at)
    { Head(h);ArgumentNullException.ThrowIfNull(x);x.DemandFactoryIssued();if(h.State is not(LogicalOutboxState.Sending or LogicalOutboxState.PartiallyAccepted or LogicalOutboxState.OutcomeUnknown)||!x.Scope.Equals(h.StoreScope)||!x.ClaimKey.Equals(h.ClaimKey)||!h.Targets.Any(t=>MatchesActiveAttempt(t,x.Target,x.AttemptId,x.TargetOperationId,x.BindingHash)))throw new InvalidOperationException("Reconciliation is not bound to this unresolved target attempt.");return new(MessageMutationKind.ReconcileOutcomeUnknown,h,x.OperationId,at,reconciliation:x); }
    internal static PreparedMessageMutation ApplyLateReceipt(LogicalOutboxSnapshot h, VerifiedLateMaterializationReceipt x, DateTimeOffset at)
    { Head(h);ArgumentNullException.ThrowIfNull(x);x.DemandFactoryIssued();if(!x.Scope.Equals(h.StoreScope)||!x.ClaimKey.Equals(h.ClaimKey)||!h.Targets.Any(t=>t.Target.Equals(x.Target)&&t.State==LogicalTargetState.Accepted&&t.LastAttemptId?.Equals(x.AcceptedAttemptId)==true&&t.OperationId?.Equals(x.TargetOperationId)==true&&t.BindingHash?.Equals(x.BindingHash)==true))throw new InvalidOperationException("Receipt is not bound to an accepted target attempt.");return new(MessageMutationKind.LateMaterializationReceipt,h,x.OperationId,at,lateReceipt:x); }
    internal static PreparedMessageMutation FromLocalGroupDispatchBlock(
        LogicalOutboxSnapshot h,
        VerifiedLocalGroupDispatchBlock block)
    {
        Head(h);
        ArgumentNullException.ThrowIfNull(block);
        block.DemandFactoryIssued();
        var canonical = h.CanonicalPayload;
        var exact = block.ExactDgm1.ToArray();
        try
        {
            if (!block.Scope.Equals(h.StoreScope)
                || !block.ClaimKey.Equals(h.ClaimKey)
                || block.ClaimKey.AuthorDeviceId is null
                || h.ClaimKey.AuthorDeviceId is null
                || !block.ClaimKey.AuthorDeviceId.Equals(h.ClaimKey.AuthorDeviceId)
                || !block.EventHash.Equals(h.EventHash)
                || block.OutboxRevision != h.Revision
                || h.PayloadKind != MessagePayloadKind.GroupMessage
                || !canonical.AsSpan().SequenceEqual(exact)
                || !h.Targets.Any(target => ExactBlockedAttempt(target, block)))
                throw new InvalidOperationException(
                    "The local GroupV1 block is not bound to the exact active DGM1 attempt.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
            CryptographicOperations.ZeroMemory(exact);
        }
        return new PreparedMessageMutation(
            MessageMutationKind.LocalGroupDispatchBlock,
            h,
            block.OperationId,
            block.OccurredAt,
            groupDispatchBlock: block);
    }
    internal static PreparedMessageMutation Cancel(LogicalOutboxSnapshot h, MessageMutationId32 o, DateTimeOffset at){Head(h);return new(MessageMutationKind.Cancel,h,o,at);}
    internal static PreparedMessageMutation Expire(LogicalOutboxSnapshot h, MessageMutationId32 o, DateTimeOffset at){Head(h);return new(MessageMutationKind.Expire,h,o,at);}
    private static void Head(LogicalOutboxSnapshot h){ArgumentNullException.ThrowIfNull(h);if(h.Revision==ulong.MaxValue)throw new MessageRevisionExhaustedException();}
    private static bool MatchesActiveAttempt(LogicalTargetSnapshot target, RecipientDeviceTarget expectedTarget,
        TransportAttemptId16 expectedAttempt, MessageTargetOperationId32 expectedOperation,
        MessageBindingHash32 expectedBinding) => target.Target.Equals(expectedTarget)
        && target.ActiveAttemptId?.Equals(expectedAttempt) == true
        && target.OperationId?.Equals(expectedOperation) == true
        && target.BindingHash?.Equals(expectedBinding) == true;

    private static bool ExactBlockedAttempt(
        LogicalTargetSnapshot target,
        VerifiedLocalGroupDispatchBlock block)
    {
        var ciphertext = target.Ciphertext;
        try
        {
            return target.Target.Equals(block.Target)
                && target.DirectoryHeadHash.Equals(block.DirectoryHeadHash)
                && target.State == LogicalTargetState.Pending
                && target.ActiveAttemptId?.Equals(block.AttemptId) == true
                && target.UnresolvedAttemptId?.Equals(block.AttemptId) == true
                && target.LastAttemptId is null
                && !target.OutcomeUnknown
                && target.OperationId?.Equals(block.TargetOperationId) == true
                && target.BindingHash?.Equals(block.BindingHash) == true
                && target.RequestHash?.Equals(block.RequestHash) == true
                && target.RatchetBeforeHash?.Equals(block.RatchetBeforeHash) == true
                && target.RatchetTransitionHash?.Equals(block.RatchetTransitionHash) == true
                && ciphertext is not null
                && CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(ciphertext), block.RequestHash.Span);
        }
        finally
        {
            if (ciphertext is not null)
                CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    internal void DemandTrustedAuthorityIfRequired(MessageStoreAuthorityBinding expectedIssuer)
    {
        switch (Kind)
        {
            case MessageMutationKind.TargetOutcome:
                Outcome!.DemandIssuedBy(expectedIssuer);
                break;
            case MessageMutationKind.MarkOutcomeUnknown:
                Uncertainty!.DemandIssuedBy(expectedIssuer);
                break;
            case MessageMutationKind.ReconcileOutcomeUnknown:
                Reconciliation!.DemandIssuedBy(expectedIssuer);
                break;
            case MessageMutationKind.LateMaterializationReceipt:
                LateReceipt!.DemandIssuedBy(expectedIssuer);
                break;
            case MessageMutationKind.LocalGroupDispatchBlock:
                GroupDispatchBlock!.DemandIssuedBy(expectedIssuer);
                break;
        }
    }
}

internal static class MessageOutcomeCompositionStatus
{
    internal const string Blocker = "Resolved by the authenticated capability verifier boundary.";
}

internal sealed record BeginMessageResult(SemanticClaimResult ClaimResult, MessageCommitResult CommitResult, LogicalOutboxSnapshot? Snapshot);
internal sealed record ApplyMessageResult(MessageCommitResult CommitResult, LogicalOutboxSnapshot? Snapshot, MessageTombstone? Tombstone);
internal sealed class MessageRatchetSnapshot
{
    private readonly byte[] sealedState;
    internal MessageRatchetSnapshot(RatchetSessionId32 sessionId,
        RatchetStateHash32 beforeHash, RatchetStateHash32 afterHash,
        ReadOnlySpan<byte> sealedState, DateTimeOffset appliedAt)
    {
        SessionId = RatchetSessionId32.FromBytes(sessionId.Span);
        BeforeHash = RatchetStateHash32.FromBytes(beforeHash.Span);
        AfterHash = RatchetStateHash32.FromBytes(afterHash.Span);
        this.sealedState = sealedState.ToArray();
        AppliedAt = LogicalOutboxSeed.Canonical(appliedAt);
    }
    internal RatchetSessionId32 SessionId { get; }
    internal RatchetStateHash32 BeforeHash { get; }
    internal RatchetStateHash32 AfterHash { get; }
    internal byte[] SealedState => sealedState.ToArray();
    internal DateTimeOffset AppliedAt { get; }
}
internal abstract class InboxMaterializationRequest
{
    private readonly MessageStoreAuthorityBinding? issuer;
    private readonly byte[] canonicalEvent;
    private readonly byte[] sealedRatchetState;
    private readonly byte[] authenticatedReceipt;
    private readonly byte[] replayNonce;
    private protected InboxMaterializationRequest(MessageStoreAuthorityBinding issuer, MessageStoreScope scope, SemanticClaimCandidate claim, ReadOnlySpan<byte> canonicalEvent,
        RatchetSessionId32 sessionId, RatchetStateHash32 beforeHash, RatchetStateHash32 afterHash,
        ReadOnlySpan<byte> sealedRatchetState, MessageReceiptId32 receiptId,
        MessageEvidenceHash32 evidenceHash, ReadOnlySpan<byte> authenticatedReceipt,
        ulong replayCounter, ReadOnlySpan<byte> replayNonce, DateTimeOffset occurredAt)
    { this.issuer=issuer??throw new ArgumentNullException(nameof(issuer)); Scope=LogicalOutboxSnapshot.Copy(scope); Claim=claim; this.canonicalEvent=canonicalEvent.ToArray(); SessionId=sessionId; BeforeHash=beforeHash; AfterHash=afterHash; this.sealedRatchetState=sealedRatchetState.ToArray(); ReceiptId=receiptId; EvidenceHash=evidenceHash; this.authenticatedReceipt=authenticatedReceipt.ToArray(); ReplayCounter=replayCounter; this.replayNonce=replayNonce.ToArray(); OccurredAt=LogicalOutboxSeed.Canonical(occurredAt); }
    internal MessageStoreScope Scope { get; }
    internal SemanticClaimCandidate Claim { get; } internal ReadOnlyMemory<byte> CanonicalEvent => canonicalEvent.ToArray();
    internal RatchetSessionId32 SessionId { get; } internal RatchetStateHash32 BeforeHash { get; }
    internal RatchetStateHash32 AfterHash { get; } internal ReadOnlyMemory<byte> SealedRatchetState => sealedRatchetState.ToArray();
    internal MessageReceiptId32 ReceiptId { get; } internal MessageEvidenceHash32 EvidenceHash { get; }
    internal ReadOnlyMemory<byte> AuthenticatedReceipt => authenticatedReceipt.ToArray(); internal DateTimeOffset OccurredAt { get; }
    internal ulong ReplayCounter { get; }
    internal ReadOnlyMemory<byte> ReplayNonce => replayNonce.ToArray();
    internal MessageMutationId32 OperationId => CapabilityChecks.OperationId(new(
        MessageEvidencePurpose.InboundMaterialization, Scope, Claim.Key, null, null, null,
        ReceiptId, EvidenceHash, AuthenticatedReceipt.Span, replayCounter: ReplayCounter,
        replayNonce: ReplayNonce.Span));
    internal void DemandIssuedBy(MessageStoreAuthorityBinding expectedIssuer) =>
        expectedIssuer.DemandTrustedIssuer(issuer);
}
internal sealed record MessageStoreRecoveryItem(LogicalOutboxSnapshot Snapshot, IReadOnlyList<PendingMessageReceipt> Receipts);
internal interface IMessageStoreFailpoint { void Hit(string window); }
internal interface IMessageTransactionStore : IAsyncDisposable
{
    MessageStoreScope Scope { get; }
    IMessageVerifiedTransportHandoff ClaimVerifiedTransportHandoff();
    IMessageGroupDispatchSafetyHandoff ClaimGroupDispatchSafetyHandoff();
    ValueTask<SemanticClaimResult> ClaimSemanticAsync(SemanticClaimCandidate claim, CancellationToken cancellationToken);
    ValueTask<BeginMessageResult> BeginOutboundAsync(MessageMutationId32 operationId, SemanticClaimCandidate claim, LogicalOutboxSeed seed, CancellationToken cancellationToken);
    ValueTask<ApplyMessageResult> ApplyAsync(PreparedMessageMutation plan, CancellationToken cancellationToken);
    ValueTask<LogicalOutboxSnapshot?> ReadAsync(SemanticClaimKey claimKey, CancellationToken cancellationToken);
    ValueTask<InboxEventSnapshot?> ReadInboxAsync(SemanticClaimKey claimKey, CancellationToken cancellationToken);
    ValueTask<MessageRatchetSnapshot?> ReadRatchetAsync(RatchetSessionId32 sessionId, CancellationToken cancellationToken);
    ValueTask<InboxEventSnapshot?> MaterializeInboundAsync(InboxMaterializationRequest request, CancellationToken cancellationToken);
    ValueTask<IReadOnlyList<MessageStoreRecoveryItem>> ClaimRecoveryAsync(MessageRecoveryOwnerId16 owner, DateTimeOffset now, int maxItems, CancellationToken cancellationToken);
    ValueTask<IReadOnlyList<PendingMessageReceipt>> ClaimPendingReceiptsAsync(MessageRecoveryOwnerId16 owner, DateTimeOffset now, int maxItems, CancellationToken cancellationToken);
    ValueTask<PendingMessageReceipt?> ClaimPendingReceiptAsync(MessageReceiptId32 receiptId,
        MessageRecoveryOwnerId16 owner, DateTimeOffset now, CancellationToken cancellationToken);
    ValueTask<MessageCommitResult> CompletePendingReceiptAsync(MessageReceiptId32 receiptId,
        MessageRecoveryOwnerId16 owner, DateTimeOffset completedAt, CancellationToken cancellationToken);
}
