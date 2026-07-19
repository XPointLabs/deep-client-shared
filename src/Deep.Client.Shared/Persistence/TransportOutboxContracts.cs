using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

public static class TransportOutboxLimits
{
    public const int LogicalIdBytes = 16;
    public const int AccountScopeBytes = 32;
    public const int AttemptIdBytes = 16;
    public const int DedupMaterialBytes = 32;
    public const int MaxCiphertextBundleBytes = 1024 * 1024;
    public const int MaxEvidenceBytes = 4096;
    public const int MaxAttemptsPerItem = 16;
    public const int MaxListCount = 256;
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromDays(365);
}

internal static class TransportOutboxTime
{
    public static DateTimeOffset Canonical(DateTimeOffset value) =>
        DateTimeOffset.FromUnixTimeMilliseconds(value.ToUnixTimeMilliseconds());

    public static DateTimeOffset? Canonical(DateTimeOffset? value) =>
        value is null ? null : Canonical(value.Value);

    public static bool IsCanonical(DateTimeOffset value) => value == Canonical(value);
}

public abstract class OutboxOpaqueValue : IEquatable<OutboxOpaqueValue>
{
    private readonly byte[] value;
    private readonly string redactedName;

    private protected OutboxOpaqueValue(ReadOnlySpan<byte> value, int requiredLength, string redactedName)
    {
        if (value.Length != requiredLength)
        {
            throw new ArgumentException("Opaque outbox value has an invalid length.", nameof(value));
        }
        if (value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("Opaque outbox value must not be all zero.", nameof(value));
        }

        this.value = value.ToArray();
        this.redactedName = redactedName;
    }

    public byte[] ToArray() => value.ToArray();

    internal ReadOnlySpan<byte> Value => value;

    public bool Equals(OutboxOpaqueValue? other) =>
        other is not null
        && other.GetType() == GetType()
        && CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) => Equals(obj as OutboxOpaqueValue);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(GetType());
        hash.AddBytes(value);
        return hash.ToHashCode();
    }

    public override string ToString() => $"[opaque-{redactedName}]";
}

public sealed class OutboxLogicalId : OutboxOpaqueValue
{
    private OutboxLogicalId(ReadOnlySpan<byte> value)
        : base(value, TransportOutboxLimits.LogicalIdBytes, "outbox-logical-id")
    {
    }

    public static OutboxLogicalId FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class OutboxAccountScope : OutboxOpaqueValue
{
    private OutboxAccountScope(ReadOnlySpan<byte> value)
        : base(value, TransportOutboxLimits.AccountScopeBytes, "outbox-account-scope")
    {
    }

    public static OutboxAccountScope FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class OutboxAttemptId : OutboxOpaqueValue
{
    private OutboxAttemptId(ReadOnlySpan<byte> value)
        : base(value, TransportOutboxLimits.AttemptIdBytes, "outbox-attempt-id")
    {
    }

    public static OutboxAttemptId FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class OutboxDedupMaterial : OutboxOpaqueValue
{
    private OutboxDedupMaterial(ReadOnlySpan<byte> value)
        : base(value, TransportOutboxLimits.DedupMaterialBytes, "outbox-dedup-material")
    {
    }

    public static OutboxDedupMaterial FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public enum TransportOutboxState
{
    Prepared = 1,
    Attempted = 2,
    Accepted = 3,
    Durable = 4,
    Delivered = 5,
    Expired = 6
}

public enum TransportOutboxAttemptState
{
    Attempted = 1,
    Accepted = 2,
    Durable = 3
}

public enum OutboxTransitionSource
{
    LocalQueue = 1,
    Adapter = 2,
    Recovery = 3,
    RecipientDevice = 4,
    ExpiryScheduler = 5
}

public enum OutboxTransitionReason
{
    Prepared = 1,
    DispatchStarted = 2,
    AdapterAccepted = 3,
    AdapterConfirmedDurable = 4,
    RecipientAcknowledged = 5,
    RetryScheduled = 6,
    LifetimeElapsed = 7,
    CrashReconciled = 8
}

public enum TransportOutboxCommitResult
{
    Applied,
    Idempotent,
    Conflict,
    Corrupt
}

public enum TransportOutboxReadResult
{
    Missing,
    Found,
    Corrupt
}

public sealed class TransportOutboxCorruptException : IOException
{
    public TransportOutboxCorruptException()
        : base("Persisted transport outbox state is corrupt.")
    {
    }
}

public sealed class TransportOutboxCommitOutcomeUnknownException : IOException
{
    public TransportOutboxCommitOutcomeUnknownException()
        : base("The transport outbox commit outcome is unknown; read and reconcile before retrying.")
    {
    }
}

public sealed class TransportOutboxPreparedItem
{
    private readonly byte[] ciphertextBundle;

    private TransportOutboxPreparedItem(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        OutboxDedupMaterial dedupMaterial,
        byte[] ciphertextBundle,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        DateTimeOffset notBefore)
    {
        AccountScope = OutboxAccountScope.FromBytes(accountScope.Value);
        LogicalId = OutboxLogicalId.FromBytes(logicalId.Value);
        DedupMaterial = OutboxDedupMaterial.FromBytes(dedupMaterial.Value);
        this.ciphertextBundle = ciphertextBundle;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
        NotBefore = notBefore;
    }

    public OutboxAccountScope AccountScope { get; }

    public OutboxLogicalId LogicalId { get; }

    public OutboxDedupMaterial DedupMaterial { get; }

    public DateTimeOffset CreatedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public DateTimeOffset NotBefore { get; }

    public byte[] GetCiphertextBundleCopy() => ciphertextBundle.ToArray();

    internal ReadOnlySpan<byte> CiphertextBundle => ciphertextBundle;

    public static TransportOutboxPreparedItem Create(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        OutboxDedupMaterial dedupMaterial,
        ReadOnlySpan<byte> ciphertextBundle,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        DateTimeOffset notBefore)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(logicalId);
        ArgumentNullException.ThrowIfNull(dedupMaterial);
        if (ciphertextBundle.IsEmpty
            || ciphertextBundle.Length > TransportOutboxLimits.MaxCiphertextBundleBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertextBundle));
        }

        createdAt = TransportOutboxTime.Canonical(createdAt);
        expiresAt = TransportOutboxTime.Canonical(expiresAt);
        notBefore = TransportOutboxTime.Canonical(notBefore);
        ValidateTimeline(createdAt, expiresAt, notBefore);
        return new(
            accountScope,
            logicalId,
            dedupMaterial,
            ciphertextBundle.ToArray(),
            createdAt,
            expiresAt,
            notBefore);
    }

    internal static void ValidateTimeline(
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        DateTimeOffset notBefore)
    {
        if (createdAt <= DateTimeOffset.UnixEpoch
            || expiresAt <= createdAt
            || expiresAt - createdAt > TransportOutboxLimits.MaxLifetime
            || notBefore < createdAt
            || notBefore > expiresAt)
        {
            throw new ArgumentOutOfRangeException(nameof(expiresAt), "Outbox timeline is invalid.");
        }
    }
}

public sealed class RecipientDeviceAcknowledgement
{
    private readonly byte[] evidence;

    private RecipientDeviceAcknowledgement(
        OutboxLogicalId logicalId,
        OutboxDedupMaterial dedupMaterial,
        byte[] evidence,
        DateTimeOffset acknowledgedAt)
    {
        LogicalId = OutboxLogicalId.FromBytes(logicalId.Value);
        DedupMaterial = OutboxDedupMaterial.FromBytes(dedupMaterial.Value);
        this.evidence = evidence;
        AcknowledgedAt = acknowledgedAt;
    }

    public OutboxLogicalId LogicalId { get; }

    public OutboxDedupMaterial DedupMaterial { get; }

    public DateTimeOffset AcknowledgedAt { get; }

    public byte[] GetEvidenceCopy() => evidence.ToArray();

    internal ReadOnlySpan<byte> Evidence => evidence;

    public static RecipientDeviceAcknowledgement Create(
        OutboxLogicalId logicalId,
        OutboxDedupMaterial dedupMaterial,
        ReadOnlySpan<byte> evidence,
        DateTimeOffset acknowledgedAt)
    {
        ArgumentNullException.ThrowIfNull(logicalId);
        ArgumentNullException.ThrowIfNull(dedupMaterial);
        ValidateEvidence(evidence);
        acknowledgedAt = TransportOutboxTime.Canonical(acknowledgedAt);
        ValidateOccurredAt(acknowledgedAt);
        return new(logicalId, dedupMaterial, evidence.ToArray(), acknowledgedAt);
    }

    internal static void ValidateEvidence(ReadOnlySpan<byte> evidence)
    {
        if (evidence.IsEmpty || evidence.Length > TransportOutboxLimits.MaxEvidenceBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(evidence));
        }
    }

    internal static void ValidateOccurredAt(DateTimeOffset occurredAt)
    {
        if (occurredAt <= DateTimeOffset.UnixEpoch)
        {
            throw new ArgumentOutOfRangeException(nameof(occurredAt));
        }
    }
}

public sealed class TransportOutboxTransition
{
    private readonly byte[] evidence;

    private TransportOutboxTransition(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        ulong expectedRevision,
        TransportOutboxState targetState,
        OutboxAttemptId? attemptId,
        OutboxTransitionSource source,
        OutboxTransitionReason reason,
        DateTimeOffset occurredAt,
        DateTimeOffset? retryNotBefore,
        byte[] evidence,
        RecipientDeviceAcknowledgement? acknowledgement)
    {
        AccountScope = OutboxAccountScope.FromBytes(accountScope.Value);
        LogicalId = OutboxLogicalId.FromBytes(logicalId.Value);
        ExpectedRevision = expectedRevision;
        TargetState = targetState;
        AttemptId = attemptId is null ? null : OutboxAttemptId.FromBytes(attemptId.Value);
        Source = source;
        Reason = reason;
        OccurredAt = occurredAt;
        RetryNotBefore = retryNotBefore;
        this.evidence = evidence;
        Acknowledgement = acknowledgement is null
            ? null
            : RecipientDeviceAcknowledgement.Create(
                acknowledgement.LogicalId,
                acknowledgement.DedupMaterial,
                acknowledgement.Evidence,
                acknowledgement.AcknowledgedAt);
    }

    public OutboxAccountScope AccountScope { get; }

    public OutboxLogicalId LogicalId { get; }

    public ulong ExpectedRevision { get; }

    public TransportOutboxState TargetState { get; }

    public OutboxAttemptId? AttemptId { get; }

    public OutboxTransitionSource Source { get; }

    public OutboxTransitionReason Reason { get; }

    public DateTimeOffset OccurredAt { get; }

    public DateTimeOffset? RetryNotBefore { get; }

    public RecipientDeviceAcknowledgement? Acknowledgement { get; }

    public byte[] GetEvidenceCopy() => evidence.ToArray();

    internal ReadOnlySpan<byte> Evidence => evidence;

    public static TransportOutboxTransition Attempted(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        ulong expectedRevision,
        OutboxAttemptId attemptId,
        OutboxTransitionSource source,
        OutboxTransitionReason reason,
        DateTimeOffset occurredAt,
        DateTimeOffset retryNotBefore) =>
        CreateAttempt(
            accountScope,
            logicalId,
            expectedRevision,
            TransportOutboxState.Attempted,
            attemptId,
            source,
            reason,
            occurredAt,
            retryNotBefore,
            []);

    public static TransportOutboxTransition Accepted(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        ulong expectedRevision,
        OutboxAttemptId attemptId,
        OutboxTransitionSource source,
        OutboxTransitionReason reason,
        DateTimeOffset occurredAt,
        DateTimeOffset retryNotBefore,
        ReadOnlySpan<byte> evidence) =>
        CreateAttempt(
            accountScope,
            logicalId,
            expectedRevision,
            TransportOutboxState.Accepted,
            attemptId,
            source,
            reason,
            occurredAt,
            retryNotBefore,
            evidence);

    public static TransportOutboxTransition Durable(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        ulong expectedRevision,
        OutboxAttemptId attemptId,
        OutboxTransitionSource source,
        OutboxTransitionReason reason,
        DateTimeOffset occurredAt,
        ReadOnlySpan<byte> evidence) =>
        CreateAttempt(
            accountScope,
            logicalId,
            expectedRevision,
            TransportOutboxState.Durable,
            attemptId,
            source,
            reason,
            occurredAt,
            retryNotBefore: null,
            evidence);

    public static TransportOutboxTransition Delivered(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        ulong expectedRevision,
        RecipientDeviceAcknowledgement acknowledgement,
        OutboxTransitionReason reason,
        DateTimeOffset occurredAt)
    {
        ArgumentNullException.ThrowIfNull(acknowledgement);
        occurredAt = TransportOutboxTime.Canonical(occurredAt);
        ValidateCommon(accountScope, logicalId, expectedRevision, OutboxTransitionSource.RecipientDevice, reason, occurredAt);
        if (reason != OutboxTransitionReason.RecipientAcknowledged)
        {
            throw new ArgumentException("Delivered requires the recipient acknowledgement reason.", nameof(reason));
        }

        return new(
            accountScope,
            logicalId,
            expectedRevision,
            TransportOutboxState.Delivered,
            attemptId: null,
            OutboxTransitionSource.RecipientDevice,
            reason,
            occurredAt,
            retryNotBefore: null,
            [],
            acknowledgement);
    }

    public static TransportOutboxTransition Expired(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        ulong expectedRevision,
        DateTimeOffset occurredAt)
    {
        occurredAt = TransportOutboxTime.Canonical(occurredAt);
        ValidateCommon(
            accountScope,
            logicalId,
            expectedRevision,
            OutboxTransitionSource.ExpiryScheduler,
            OutboxTransitionReason.LifetimeElapsed,
            occurredAt);
        return new(
            accountScope,
            logicalId,
            expectedRevision,
            TransportOutboxState.Expired,
            attemptId: null,
            OutboxTransitionSource.ExpiryScheduler,
            OutboxTransitionReason.LifetimeElapsed,
            occurredAt,
            retryNotBefore: null,
            [],
            acknowledgement: null);
    }

    private static TransportOutboxTransition CreateAttempt(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        ulong expectedRevision,
        TransportOutboxState targetState,
        OutboxAttemptId attemptId,
        OutboxTransitionSource source,
        OutboxTransitionReason reason,
        DateTimeOffset occurredAt,
        DateTimeOffset? retryNotBefore,
        ReadOnlySpan<byte> evidence)
    {
        ArgumentNullException.ThrowIfNull(attemptId);
        ValidateCommon(accountScope, logicalId, expectedRevision, source, reason, occurredAt);
        if (source is not (OutboxTransitionSource.Adapter or OutboxTransitionSource.Recovery))
        {
            throw new ArgumentException("Attempt transitions require an adapter or recovery source.", nameof(source));
        }
        var reasonIsLegal = targetState switch
        {
            TransportOutboxState.Attempted =>
                reason is OutboxTransitionReason.DispatchStarted
                    or OutboxTransitionReason.RetryScheduled
                    or OutboxTransitionReason.CrashReconciled,
            TransportOutboxState.Accepted =>
                reason is OutboxTransitionReason.AdapterAccepted
                    or OutboxTransitionReason.CrashReconciled,
            TransportOutboxState.Durable =>
                reason is OutboxTransitionReason.AdapterConfirmedDurable
                    or OutboxTransitionReason.CrashReconciled,
            _ => false
        };
        if (!reasonIsLegal
            || source == OutboxTransitionSource.Recovery
                && reason != OutboxTransitionReason.CrashReconciled
            || source == OutboxTransitionSource.Adapter
                && reason == OutboxTransitionReason.CrashReconciled)
        {
            throw new ArgumentException("Attempt transition reason does not match its state and source.", nameof(reason));
        }

        if (targetState is TransportOutboxState.Accepted or TransportOutboxState.Durable)
        {
            RecipientDeviceAcknowledgement.ValidateEvidence(evidence);
        }
        else if (!evidence.IsEmpty)
        {
            throw new ArgumentException("Attempt-start evidence must be empty.", nameof(evidence));
        }

        occurredAt = TransportOutboxTime.Canonical(occurredAt);
        retryNotBefore = TransportOutboxTime.Canonical(retryNotBefore);
        if (retryNotBefore is not null && retryNotBefore < occurredAt)
        {
            throw new ArgumentOutOfRangeException(nameof(retryNotBefore));
        }

        return new(
            accountScope,
            logicalId,
            expectedRevision,
            targetState,
            attemptId,
            source,
            reason,
            occurredAt,
            retryNotBefore,
            evidence.ToArray(),
            acknowledgement: null);
    }

    private static void ValidateCommon(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        ulong expectedRevision,
        OutboxTransitionSource source,
        OutboxTransitionReason reason,
        DateTimeOffset occurredAt)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(logicalId);
        if (expectedRevision == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedRevision));
        }

        if (!Enum.IsDefined(source) || !Enum.IsDefined(reason))
        {
            throw new ArgumentOutOfRangeException(nameof(source));
        }

        RecipientDeviceAcknowledgement.ValidateOccurredAt(
            TransportOutboxTime.Canonical(occurredAt));
    }
}

public sealed class TransportOutboxAttemptSnapshot
{
    private readonly byte[] evidence;

    internal TransportOutboxAttemptSnapshot(
        OutboxAttemptId attemptId,
        TransportOutboxAttemptState state,
        OutboxTransitionSource source,
        OutboxTransitionReason reason,
        DateTimeOffset occurredAt,
        byte[] evidence)
    {
        AttemptId = OutboxAttemptId.FromBytes(attemptId.Value);
        State = state;
        Source = source;
        Reason = reason;
        OccurredAt = occurredAt;
        this.evidence = evidence.ToArray();
    }

    public OutboxAttemptId AttemptId { get; }
    public TransportOutboxAttemptState State { get; }
    public OutboxTransitionSource Source { get; }
    public OutboxTransitionReason Reason { get; }
    public DateTimeOffset OccurredAt { get; }
    public byte[] GetEvidenceCopy() => evidence.ToArray();
    internal ReadOnlySpan<byte> Evidence => evidence;
}

public sealed class TransportOutboxItemSnapshot
{
    private readonly byte[] ciphertextBundle;
    private readonly byte[]? acknowledgementEvidence;
    private readonly IReadOnlyList<TransportOutboxAttemptSnapshot> attempts;

    internal TransportOutboxItemSnapshot(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        OutboxDedupMaterial dedupMaterial,
        byte[] ciphertextBundle,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        DateTimeOffset notBefore,
        TransportOutboxState state,
        ulong revision,
        OutboxTransitionSource source,
        OutboxTransitionReason reason,
        DateTimeOffset transitionedAt,
        IReadOnlyList<TransportOutboxAttemptSnapshot> attempts,
        byte[]? acknowledgementEvidence)
    {
        AccountScope = OutboxAccountScope.FromBytes(accountScope.Value);
        LogicalId = OutboxLogicalId.FromBytes(logicalId.Value);
        DedupMaterial = OutboxDedupMaterial.FromBytes(dedupMaterial.Value);
        this.ciphertextBundle = ciphertextBundle.ToArray();
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
        NotBefore = notBefore;
        State = state;
        Revision = revision;
        Source = source;
        Reason = reason;
        TransitionedAt = transitionedAt;
        this.attempts = Array.AsReadOnly(attempts
            .Select(static attempt => new TransportOutboxAttemptSnapshot(
                attempt.AttemptId,
                attempt.State,
                attempt.Source,
                attempt.Reason,
                attempt.OccurredAt,
                attempt.Evidence.ToArray()))
            .ToArray());
        this.acknowledgementEvidence = acknowledgementEvidence?.ToArray();
    }

    public OutboxAccountScope AccountScope { get; }
    public OutboxLogicalId LogicalId { get; }
    public OutboxDedupMaterial DedupMaterial { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public DateTimeOffset NotBefore { get; }
    public TransportOutboxState State { get; }
    public ulong Revision { get; }
    public OutboxTransitionSource Source { get; }
    public OutboxTransitionReason Reason { get; }
    public DateTimeOffset TransitionedAt { get; }
    public IReadOnlyList<TransportOutboxAttemptSnapshot> Attempts => attempts;
    public byte[] GetCiphertextBundleCopy() => ciphertextBundle.ToArray();
    public byte[]? GetAcknowledgementEvidenceCopy() => acknowledgementEvidence?.ToArray();
    internal ReadOnlySpan<byte> CiphertextBundle => ciphertextBundle;
    internal ReadOnlySpan<byte> AcknowledgementEvidence => acknowledgementEvidence;
}

public sealed record TransportOutboxReadSnapshot(
    TransportOutboxReadResult Result,
    TransportOutboxItemSnapshot? Item);

public interface ITransportOutboxRepository
{
    Task<TransportOutboxCommitResult> PrepareTransportOutboxAsync(
        TransportOutboxPreparedItem item,
        CancellationToken cancellationToken = default);

    Task<TransportOutboxReadSnapshot> ReadTransportOutboxAsync(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        CancellationToken cancellationToken = default);

    Task<TransportOutboxCommitResult> ApplyTransportOutboxTransitionAsync(
        OutboxAccountScope accountScope,
        TransportOutboxTransition transition,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<TransportOutboxItemSnapshot>> ListReadyTransportOutboxAsync(
        OutboxAccountScope accountScope,
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken = default);

    Task<int> ExpireDueTransportOutboxAsync(
        OutboxAccountScope accountScope,
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken = default);

    Task PurgeTransportOutboxScopeAsync(
        OutboxAccountScope accountScope,
        CancellationToken cancellationToken = default);
}

public static class TransportOutboxRepositoryExtensions
{
    public static Task<TransportOutboxCommitResult> ApplyTransportOutboxTransitionAsync(
        this ITransportOutboxRepository repository,
        TransportOutboxTransition transition,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(transition);
        return repository.ApplyTransportOutboxTransitionAsync(
            transition.AccountScope,
            transition,
            cancellationToken);
    }
}

internal enum TransportOutboxCommitFaultPoint
{
    BeforeDurableCommit,
    AfterDurableCommit
}
