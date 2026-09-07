using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.MessagingCryptoV1;

/// <summary>
/// Production object-capability bridge between the protocol-owned exact DPE2
/// plan and the SQLCipher authority for one ratchet scope.
/// </summary>
internal sealed class ExactDpe2SqliteDurableTransactionAuthority(
    SqliteMessagingCryptoV1Store store) : IExactDpe2DurableTransactionAuthority
{
    private readonly SqliteMessagingCryptoV1Store store =
        store ?? throw new ArgumentNullException(nameof(store));

    public async ValueTask<ExactDpe2DurableCommitReceipt> CommitAsync(
        ExactDpe2DurablePersistencePlan plan,
        ExactDpe2DurableCommitCompletion completion,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(completion);
        cancellationToken.ThrowIfCancellationRequested();

        using var snapshot = ExactDpe2ProtocolPlanSnapshot.Capture(plan);
        var result = await store.CommitExactDpe2Async(snapshot, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        var disposition = result.Disposition switch
        {
            MessagingCryptoV1CommitDisposition.Committed =>
                ExactDpe2DurableCommitDisposition.Committed,
            MessagingCryptoV1CommitDisposition.ExactReplay =>
                ExactDpe2DurableCommitDisposition.ExactReplay,
            MessagingCryptoV1CommitDisposition.CasConflict =>
                ExactDpe2DurableCommitDisposition.CasConflict,
            MessagingCryptoV1CommitDisposition.ForkLatched or
            MessagingCryptoV1CommitDisposition.AlreadyForkLatched =>
                ExactDpe2DurableCommitDisposition.ForkLatched,
            MessagingCryptoV1CommitDisposition.RollbackLatched =>
                ExactDpe2DurableCommitDisposition.RollbackLatched,
            MessagingCryptoV1CommitDisposition.CapacityExceeded =>
                throw new InvalidOperationException(
                    "The ratchet journal reached its closed capacity; a verified rollover is required."),
            _ => throw new CryptographicException("The durable store returned an invalid DPE2 result."),
        };

        return completion.Complete(disposition);
    }
}

/// <summary>
/// Short-lived owned copy of a protocol plan. Every field is copied exactly
/// once from the public defensive-copy surface and zeroed after the store call.
/// </summary>
internal sealed class ExactDpe2ProtocolPlanSnapshot : IDisposable
{
    private readonly List<byte[]> owned = [];
    private int disposed;

    private ExactDpe2ProtocolPlanSnapshot(ExactDpe2DurablePersistencePlan plan)
    {
        try
        {
            Direction = plan.Direction switch
            {
                ExactDpe2DurableDirection.Send => MessagingCryptoV1Direction.Send,
                ExactDpe2DurableDirection.Receive => MessagingCryptoV1Direction.Receive,
                _ => throw new CryptographicException("Unknown exact DPE2 direction."),
            };
            PriorStateGeneration = plan.PriorStateGeneration;
            NextStateGeneration = plan.NextStateGeneration;
            CheckpointPriorGeneration = plan.CheckpointPriorGeneration;
            ExpectedJournalGeneration = plan.ExpectedJournalGeneration;
            HasStateMutation = plan.HasStateMutation;
            MessageKeyDeleted = plan.MessageKeyDeletedAfterAuthenticatedEnvelopeOperation;
            OperationId = Copy(plan.OperationId);
            ReplayToken = Copy(plan.ReplayToken);
            ExactHeaderHash = Copy(plan.ExactHeaderHash);
            ExactEnvelopeHash = Copy(plan.ExactEnvelopeHash);
            ExactEnvelope = Copy(plan.ExactEnvelope);
            JournalPredecessor = Copy(plan.JournalPredecessor);
            PriorTrs1 = Copy(plan.PriorTrs1);
            NextTrs1 = Copy(plan.NextTrs1);
            PriorStateCommitment = Copy(plan.PriorStateCommitment);
            NextStateCommitment = Copy(plan.NextStateCommitment);
            CheckpointPriorCommitment = Copy(plan.CheckpointPriorCommitment);
            DeletionManifestCommitment = Copy(plan.DeletionManifestCommitment);
            MessageKeyDeletionEvidence = Copy(plan.MessageKeyDeletionEvidence);
            ReplayEvidenceCommitment = Copy(plan.ReplayEvidenceCommitment);
            DeduplicationMutationCommitment = Copy(plan.DeduplicationMutationCommitment);
            PqFenceMutationCommitment = Copy(plan.PqFenceMutationCommitment);
            TerminalStateCommitment = Copy(plan.TerminalStateCommitment);
        }
        catch
        {
            foreach (var value in owned) CryptographicOperations.ZeroMemory(value);
            throw;
        }
    }

    internal MessagingCryptoV1Direction Direction { get; }
    internal ulong PriorStateGeneration { get; }
    internal ulong NextStateGeneration { get; }
    internal ulong CheckpointPriorGeneration { get; }
    internal ulong ExpectedJournalGeneration { get; }
    internal bool HasStateMutation { get; }
    internal bool MessageKeyDeleted { get; }
    internal byte[] OperationId { get; }
    internal byte[] ReplayToken { get; }
    internal byte[] ExactHeaderHash { get; }
    internal byte[] ExactEnvelopeHash { get; }
    internal byte[] ExactEnvelope { get; }
    internal byte[] JournalPredecessor { get; }
    internal byte[] PriorTrs1 { get; }
    internal byte[] NextTrs1 { get; }
    internal byte[] PriorStateCommitment { get; }
    internal byte[] NextStateCommitment { get; }
    internal byte[] CheckpointPriorCommitment { get; }
    internal byte[] DeletionManifestCommitment { get; }
    internal byte[] MessageKeyDeletionEvidence { get; }
    internal byte[] ReplayEvidenceCommitment { get; }
    internal byte[] DeduplicationMutationCommitment { get; }
    internal byte[] PqFenceMutationCommitment { get; }
    internal byte[] TerminalStateCommitment { get; }

    internal static ExactDpe2ProtocolPlanSnapshot Capture(
        ExactDpe2DurablePersistencePlan plan) => new(plan);

    internal bool IsClearedForTesting => owned.All(static value =>
        value.AsSpan().IndexOfAnyExcept((byte)0) < 0);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var value in owned) CryptographicOperations.ZeroMemory(value);
    }

    private byte[] Copy(ReadOnlyMemory<byte> source)
    {
        var result = source.ToArray();
        owned.Add(result);
        return result;
    }
}
