using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

public enum TransportOutboxAdapterDisposition
{
    Accepted = 1,
    Durable = 2
}

public sealed class TransportOutboxDispatchRequest
{
    private readonly byte[] ciphertextBundle;
    private readonly byte[] dedupMaterial;

    internal TransportOutboxDispatchRequest(
        OutboxLogicalId logicalId,
        OutboxAttemptId attemptId,
        OutboxDedupMaterial dedupMaterial,
        ReadOnlySpan<byte> ciphertextBundle,
        DateTimeOffset expiresAt)
    {
        LogicalId = OutboxLogicalId.FromBytes(logicalId.ToArray());
        AttemptId = OutboxAttemptId.FromBytes(attemptId.ToArray());
        this.dedupMaterial = dedupMaterial.ToArray();
        this.ciphertextBundle = ciphertextBundle.ToArray();
        ExpiresAt = expiresAt;
    }

    public OutboxLogicalId LogicalId { get; }

    public OutboxAttemptId AttemptId { get; }

    public DateTimeOffset ExpiresAt { get; }

    public byte[] GetDedupMaterialCopy() => dedupMaterial.ToArray();

    public byte[] GetCiphertextBundleCopy() => ciphertextBundle.ToArray();
}

public sealed class TransportOutboxAdapterReceipt
{
    private readonly byte[] acceptedEvidence;
    private readonly byte[]? durableEvidence;

    private TransportOutboxAdapterReceipt(
        TransportOutboxAdapterDisposition disposition,
        ReadOnlySpan<byte> acceptedEvidence,
        ReadOnlySpan<byte> durableEvidence)
    {
        ValidateEvidence(acceptedEvidence, nameof(acceptedEvidence));
        if (disposition == TransportOutboxAdapterDisposition.Durable)
        {
            ValidateEvidence(durableEvidence, nameof(durableEvidence));
        }
        else if (!durableEvidence.IsEmpty)
        {
            throw new ArgumentException(
                "Accepted-only receipts cannot contain durable evidence.",
                nameof(durableEvidence));
        }

        Disposition = disposition;
        this.acceptedEvidence = acceptedEvidence.ToArray();
        this.durableEvidence = disposition == TransportOutboxAdapterDisposition.Durable
            ? durableEvidence.ToArray()
            : null;
    }

    public TransportOutboxAdapterDisposition Disposition { get; }

    public byte[] GetAcceptedEvidenceCopy() => acceptedEvidence.ToArray();

    public byte[]? GetDurableEvidenceCopy() => durableEvidence?.ToArray();

    public static TransportOutboxAdapterReceipt Accepted(ReadOnlySpan<byte> evidence) =>
        new(TransportOutboxAdapterDisposition.Accepted, evidence, []);

    public static TransportOutboxAdapterReceipt Durable(
        ReadOnlySpan<byte> acceptedEvidence,
        ReadOnlySpan<byte> durableEvidence) =>
        new(TransportOutboxAdapterDisposition.Durable, acceptedEvidence, durableEvidence);

    private static void ValidateEvidence(ReadOnlySpan<byte> evidence, string parameterName)
    {
        if (evidence.IsEmpty || evidence.Length > TransportOutboxLimits.MaxEvidenceBytes)
        {
            throw new ArgumentOutOfRangeException(parameterName);
        }
    }
}

public interface ITransportOutboxAdapter
{
    Task<TransportOutboxAdapterReceipt> DispatchAsync(
        TransportOutboxDispatchRequest request,
        CancellationToken cancellationToken = default);
}

public interface IBoundedTransportOutboxAdapter : ITransportOutboxAdapter
{
    TimeSpan MaximumDispatchDuration { get; }
}

/// <summary>
/// Platform-owned supervisor for a transport adapter running outside the client
/// process. Implementations must reserve from a bounded worker pool without
/// invoking adapter code, and each acquired execution must be independently
/// killable. An in-process task, thread, or cancellation token does not satisfy
/// this contract.
/// </summary>
public interface IExternalTransportOutboxExecutor
{
    TimeSpan MaximumDispatchDuration { get; }

    bool TryAcquire(out IExternalTransportOutboxExecution? execution);
}

/// <summary>
/// One exclusive external worker reservation. Dispatch must return only after
/// a receipt, a confirmed worker termination, or caller cancellation followed
/// by confirmed worker termination. It must never leave adapter work running
/// after this lease is disposed.
/// </summary>
public interface IExternalTransportOutboxExecution : IAsyncDisposable
{
    Task<TransportOutboxAdapterReceipt> DispatchAsync(
        TransportOutboxDispatchRequest request,
        TimeSpan hardTimeout,
        CancellationToken cancellationToken = default);
}

public sealed record TransportOutboxDispatchBatchResult(
    int ExpiredCount,
    int DurableCount,
    int AcceptedCount,
    int RetryScheduledCount,
    int ConflictCount,
    int ExhaustedCount,
    int OutcomeUnknownCount = 0,
    int CapacityDeferredCount = 0)
{
    public int AttemptedCount =>
        DurableCount + AcceptedCount + RetryScheduledCount + OutcomeUnknownCount + ConflictCount;
}

/// <summary>
/// Performs one caller-owned, bounded outbox pass. It never polls or starts a
/// background loop; mobile lifecycle code decides when a pass is worth a wakeup.
/// </summary>
public sealed class TransportOutboxDispatcher
{
    public static readonly TimeSpan DefaultRetryDelay = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan DefaultAttemptTimeout = TimeSpan.FromSeconds(15);

    private readonly ITransportOutboxRepository repository;
    private readonly IExternalTransportOutboxExecutor executor;
    private readonly IClock clock;
    private readonly TimeSpan retryDelay;
    private readonly TimeSpan attemptTimeout;
    private readonly SemaphoreSlim dispatchGate = new(1, 1);

    public TransportOutboxDispatcher(
        ITransportOutboxRepository repository,
        IExternalTransportOutboxExecutor executor,
        IClock clock,
        TimeSpan? retryDelay = null,
        TimeSpan? attemptTimeout = null)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
        this.executor = executor ?? throw new ArgumentNullException(nameof(executor));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.retryDelay = retryDelay ?? DefaultRetryDelay;
        this.attemptTimeout = attemptTimeout ?? DefaultAttemptTimeout;
        if (this.retryDelay < TimeSpan.Zero || this.retryDelay > TimeSpan.FromDays(1))
        {
            throw new ArgumentOutOfRangeException(nameof(retryDelay));
        }
        if (this.attemptTimeout <= TimeSpan.Zero || this.attemptTimeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(attemptTimeout));
        }
        if (this.executor.MaximumDispatchDuration <= TimeSpan.Zero
            || this.executor.MaximumDispatchDuration > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(
                nameof(executor),
                "The external executor maximum dispatch duration must be positive and no more than five minutes.");
        }
    }

    public Task<TransportOutboxCommitResult> PrepareAsync(
        TransportOutboxPreparedItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        return repository.PrepareTransportOutboxAsync(item, cancellationToken);
    }

    public Task<TransportOutboxReadSnapshot> ReadAsync(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(logicalId);
        return repository.ReadTransportOutboxAsync(accountScope, logicalId, cancellationToken);
    }

    public async Task<TransportOutboxDispatchBatchResult> DispatchReadyAsync(
        OutboxAccountScope accountScope,
        int limit = 32,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        if (limit is <= 0 or > TransportOutboxLimits.MaxListCount)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        await dispatchGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var batchNow = clock.UtcNow;
            var expired = await repository.ExpireDueTransportOutboxAsync(
                accountScope,
                batchNow,
                limit,
                cancellationToken).ConfigureAwait(false);
            var ready = await repository.ListReadyTransportOutboxAsync(
                accountScope,
                batchNow,
                limit,
                cancellationToken).ConfigureAwait(false);

            var durable = 0;
            var accepted = 0;
            var outcomeUnknown = 0;
            var conflicts = 0;
            var exhausted = 0;
            var capacityDeferred = 0;

            foreach (var item in ready)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var itemNow = clock.UtcNow;
                if (itemNow >= item.ExpiresAt)
                {
                    if (await ApplyOrReconcileExpiryAsync(
                            item,
                            item.Revision,
                            itemNow,
                            cancellationToken).ConfigureAwait(false))
                    {
                        expired++;
                    }
                    else
                    {
                        conflicts++;
                    }
                    continue;
                }

                if (item.Attempts.Count >= TransportOutboxLimits.MaxAttemptsPerItem)
                {
                    exhausted++;
                    continue;
                }

                if (!executor.TryAcquire(out var execution))
                {
                    capacityDeferred++;
                    continue;
                }
                if (execution is null)
                {
                    throw new InvalidOperationException(
                        "The external outbox executor reported a reservation without an execution lease.");
                }

                await using var ownedExecution = execution;
                var attemptId = CreateAttemptId();
                var retryNotBefore = RetryNotBefore(itemNow, item.ExpiresAt);
                var attempted = TransportOutboxTransition.Attempted(
                    item.AccountScope,
                    item.LogicalId,
                    item.Revision,
                    attemptId,
                    OutboxTransitionSource.Adapter,
                    item.State == TransportOutboxState.Prepared
                        ? OutboxTransitionReason.DispatchStarted
                        : OutboxTransitionReason.RetryScheduled,
                    itemNow,
                    retryNotBefore);
                if (!await ApplyOrReconcileAttemptAsync(
                        item,
                        attempted,
                        TransportOutboxAttemptState.Attempted,
                        cancellationToken).ConfigureAwait(false))
                {
                    conflicts++;
                    continue;
                }

                var request = new TransportOutboxDispatchRequest(
                    item.LogicalId,
                    attemptId,
                    item.DedupMaterial,
                    item.GetCiphertextBundleCopy(),
                    item.ExpiresAt);
                var dispatchAt = clock.UtcNow;
                if (dispatchAt >= item.ExpiresAt)
                {
                    if (await ApplyOrReconcileExpiryAsync(
                            item,
                            item.Revision + 1,
                            dispatchAt,
                            cancellationToken).ConfigureAwait(false))
                    {
                        expired++;
                    }
                    else
                    {
                        conflicts++;
                    }
                    continue;
                }

                TransportOutboxAdapterReceipt? receipt = null;
                var remainingTtl = item.ExpiresAt - dispatchAt;
                var dispatchWindow = Min(
                    remainingTtl,
                    attemptTimeout,
                    executor.MaximumDispatchDuration);
                try
                {
                    var dispatchTask = execution.DispatchAsync(
                        request,
                        dispatchWindow,
                        cancellationToken);
                    if (dispatchTask is null)
                    {
                        throw new InvalidOperationException(
                            "The external outbox execution returned no dispatch task.");
                    }

                    receipt = await dispatchTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch
                {
                    // The external executor has confirmed worker termination before surfacing
                    // failure. Adapter exception text may contain endpoints or identifiers and
                    // must not cross this boundary.
                    outcomeUnknown++;
                    continue;
                }

                if (receipt is null)
                {
                    outcomeUnknown++;
                    continue;
                }

                switch (await ApplyReceiptAsync(
                        item,
                        attemptId,
                        receipt,
                        cancellationToken).ConfigureAwait(false))
                {
                    case ReceiptApplyResult.Expired:
                        expired++;
                        break;
                    case ReceiptApplyResult.Accepted:
                        accepted++;
                        break;
                    case ReceiptApplyResult.Durable:
                        durable++;
                        break;
                    case ReceiptApplyResult.Conflict:
                        conflicts++;
                        break;
                }
            }

            return new(
                expired,
                durable,
                accepted,
                RetryScheduledCount: 0,
                conflicts,
                exhausted,
                outcomeUnknown,
                capacityDeferred);
        }
        finally
        {
            dispatchGate.Release();
        }
    }

    private async Task<ReceiptApplyResult> ApplyReceiptAsync(
        TransportOutboxItemSnapshot item,
        OutboxAttemptId attemptId,
        TransportOutboxAdapterReceipt receipt,
        CancellationToken cancellationToken)
    {
        var receiptAt = clock.UtcNow;
        if (receiptAt >= item.ExpiresAt)
        {
            return await ApplyOrReconcileExpiryAsync(
                    item,
                    expectedRevision: item.Revision + 1,
                    receiptAt,
                    cancellationToken).ConfigureAwait(false)
                ? ReceiptApplyResult.Expired
                : ReceiptApplyResult.Conflict;
        }

        var acceptedTransition = TransportOutboxTransition.Accepted(
            item.AccountScope,
            item.LogicalId,
            item.Revision + 1,
            attemptId,
            OutboxTransitionSource.Adapter,
            OutboxTransitionReason.AdapterAccepted,
            receiptAt,
            RetryNotBefore(receiptAt, item.ExpiresAt),
            receipt.GetAcceptedEvidenceCopy());
        if (!await ApplyOrReconcileAttemptAsync(
                item,
                acceptedTransition,
                TransportOutboxAttemptState.Accepted,
                cancellationToken).ConfigureAwait(false))
        {
            return ReceiptApplyResult.Conflict;
        }

        if (receipt.Disposition == TransportOutboxAdapterDisposition.Accepted)
        {
            return ReceiptApplyResult.Accepted;
        }

        var durableEvidence = receipt.GetDurableEvidenceCopy()
            ?? throw new InvalidOperationException("A durable receipt has no durable evidence.");
        var durableAt = clock.UtcNow;
        if (durableAt >= item.ExpiresAt)
        {
            return await ApplyOrReconcileExpiryAsync(
                    item,
                    expectedRevision: item.Revision + 2,
                    durableAt,
                    cancellationToken).ConfigureAwait(false)
                ? ReceiptApplyResult.Expired
                : ReceiptApplyResult.Conflict;
        }

        var durableTransition = TransportOutboxTransition.Durable(
            item.AccountScope,
            item.LogicalId,
            item.Revision + 2,
            attemptId,
            OutboxTransitionSource.Adapter,
            OutboxTransitionReason.AdapterConfirmedDurable,
            durableAt,
            durableEvidence);
        return await ApplyOrReconcileAttemptAsync(
                item,
                durableTransition,
                TransportOutboxAttemptState.Durable,
                cancellationToken).ConfigureAwait(false)
            ? ReceiptApplyResult.Durable
            : ReceiptApplyResult.Conflict;
    }

    private async Task<bool> ApplyOrReconcileAttemptAsync(
        TransportOutboxItemSnapshot original,
        TransportOutboxTransition transition,
        TransportOutboxAttemptState expectedAttemptState,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await repository.ApplyTransportOutboxTransitionAsync(
                original.AccountScope,
                transition,
                cancellationToken).ConfigureAwait(false);
            if (result == TransportOutboxCommitResult.Corrupt)
            {
                throw new TransportOutboxCorruptException();
            }
            return result is TransportOutboxCommitResult.Applied or TransportOutboxCommitResult.Idempotent;
        }
        catch (TransportOutboxCommitOutcomeUnknownException)
        {
            var read = await repository.ReadTransportOutboxAsync(
                original.AccountScope,
                original.LogicalId,
                cancellationToken).ConfigureAwait(false);
            if (read.Result == TransportOutboxReadResult.Corrupt)
            {
                throw new TransportOutboxCorruptException();
            }

            var attempt = read.Item?.Attempts.SingleOrDefault(candidate =>
                candidate.AttemptId.Equals(transition.AttemptId));
            return attempt is not null && attempt.State >= expectedAttemptState;
        }
    }

    private async Task<bool> ApplyOrReconcileExpiryAsync(
        TransportOutboxItemSnapshot original,
        ulong expectedRevision,
        DateTimeOffset occurredAt,
        CancellationToken cancellationToken)
    {
        var transition = TransportOutboxTransition.Expired(
            original.AccountScope,
            original.LogicalId,
            expectedRevision,
            occurredAt);
        try
        {
            var result = await repository.ApplyTransportOutboxTransitionAsync(
                original.AccountScope,
                transition,
                cancellationToken).ConfigureAwait(false);
            if (result == TransportOutboxCommitResult.Corrupt)
            {
                throw new TransportOutboxCorruptException();
            }
            return result is TransportOutboxCommitResult.Applied or TransportOutboxCommitResult.Idempotent;
        }
        catch (TransportOutboxCommitOutcomeUnknownException)
        {
            var read = await repository.ReadTransportOutboxAsync(
                original.AccountScope,
                original.LogicalId,
                cancellationToken).ConfigureAwait(false);
            if (read.Result == TransportOutboxReadResult.Corrupt)
            {
                throw new TransportOutboxCorruptException();
            }

            return read.Item?.State == TransportOutboxState.Expired;
        }
    }

    private DateTimeOffset RetryNotBefore(DateTimeOffset now, DateTimeOffset expiresAt)
    {
        var candidate = now.Add(retryDelay);
        var latest = expiresAt.AddMilliseconds(-1);
        return candidate <= latest ? candidate : now <= latest ? latest : now;
    }

    private static TimeSpan Min(TimeSpan first, TimeSpan second, TimeSpan third) =>
        first <= second
            ? first <= third ? first : third
            : second <= third ? second : third;

    private static OutboxAttemptId CreateAttemptId()
    {
        Span<byte> bytes = stackalloc byte[TransportOutboxLimits.AttemptIdBytes];
        do
        {
            RandomNumberGenerator.Fill(bytes);
        }
        while (bytes.IndexOfAnyExcept((byte)0) < 0);
        return OutboxAttemptId.FromBytes(bytes);
    }

    private enum ReceiptApplyResult
    {
        Expired,
        Accepted,
        Durable,
        Conflict
    }
}
