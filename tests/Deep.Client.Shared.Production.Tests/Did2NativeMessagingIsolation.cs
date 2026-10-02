using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Production.Tests;

/// <summary>Test-only crypto/storage diagnostic using real SQLCipher and an
/// in-memory protected-storage adapter, and real account-owned source retirement.
/// Uses account-owned catalog/SQL reopen; NOT shipping MSG/transport or
/// physical E2E evidence.</summary>
internal sealed class Did2NativeMessagingIsolation : IExactDpe2DurableTransactionAuthority, IDisposable
{
    private readonly OwnedInitialMessagingSeed seed;
    private readonly Did2MessagingSessionScope scope;
    private Did2MessagingFloor floor;
    private OwnedDid2MessagingStorage? ownedStorage;
    private Did2MessagingProtectedCheckpoint checkpoint => ownedStorage!.Checkpoint;
    private Did2MessagingSqlJournal sql => ownedStorage!.Sql;
    private Did2MessagingDurableCustody custody => ownedStorage!.Custody;
    private readonly Func<Task<OwnedDid2MessagingStorage>> reopen;
    private byte[] state, journal;
    private byte[] sendEventHash = [];
    private readonly byte[] retention;
    private ulong journalGeneration;
    private bool disposed;
    internal ulong Generation => Facts().Generation;

    internal Did2NativeMessagingIsolation(OwnedInitialMessagingSeed seed,
        OwnedDid2MessagingStorage ownedStorage, Func<Task<OwnedDid2MessagingStorage>> reopen,
        Func<Did2InitialStateTransfer, Task<Did2InitialKeyRetirementReceipt>> retire)
    {
        this.seed = seed;
        state = seed.ExactTrs.ToArray(); journal = seed.InitialBasisHash.ToArray();
        retention = SHA256.HashData(seed.Instance);
        scope = Did2MessagingSessionScope.FromSeed(seed);
        this.ownedStorage = ownedStorage; this.reopen = reopen;
        try
        {
        Assert.True(ownedStorage.Scope.Exact.SequenceEqual(scope.Exact));
        using var import = OwnedDid2MessagingMutation.Import(seed, Did2MessagingFloor.Empty(scope));
        Assert.True(import.NextTrs.SequenceEqual(state));
        using (var restored = OwnedDid2MessagingMutation.RecoverProtectedPending(scope, import.Successor, import.Exact.Span))
            Assert.True(restored.Exact.Span.SequenceEqual(import.Exact.Span));
        var awaiting = Persist(import);
        Assert.Equal((byte)0, awaiting.Status);
        var transfer = custody.VerifyInitialTransferAsync(default).GetAwaiter().GetResult();
        var receipt = retire(transfer).GetAwaiter().GetResult();
        floor = custody.ActivateRetiredAsync(receipt, default).GetAwaiter().GetResult();
        Assert.Equal((byte)1, floor.Status);
        Assert.Equal(floor.Exact.ToArray(), custody.ActivateRetiredAsync(receipt, default).GetAwaiter().GetResult().Exact.ToArray());
        using var active = custody.ReadActiveStateAsync(default).GetAwaiter().GetResult();
        Assert.Equal(state, active.Use(static bytes => bytes.ToArray()));
        journal = floor.Head.ToArray(); journalGeneration = floor.Ordinal;
        RestartStorage();
        }
        catch { Dispose(); throw; }
    }

    private Did2MessagingFloor Persist(OwnedDid2MessagingMutation mutation)
    {
        checkpoint.StageAsync(mutation.Predecessor, mutation.Successor, mutation.Exact, default).GetAwaiter().GetResult();
        // Import exercises restart after protected pending, before SQL.
        // Later mutations exercise restart after SQL, before protected cleanup.
        if (mutation.Kind != 1) sql.Append(mutation);
        var expected = mutation.Successor.Cleanup(scope).Stable(scope);
        RestartStorage();
        var stable = custody.ReconcileAsync(default).GetAwaiter().GetResult();
        Assert.Equal(expected.Exact.ToArray(), sql.VerifyTip().Exact.ToArray());
        Assert.Equal(expected.Exact.ToArray(), stable.Exact.ToArray());
        if (mutation.Kind is 1 or 2)
            Assert.Equal(stable.Exact.ToArray(), custody.CommitOwnedAsync(mutation, default).GetAwaiter().GetResult().Exact.ToArray());
        using var readback = sql.ReadVerifiedLatest(stable);
        Assert.Equal(stable.RatchetHash.ToArray(), readback.Use(bytes => SHA256.HashData(bytes)));
        return stable;
    }

    private void RestartStorage()
    {
        ownedStorage?.Dispose(); ownedStorage = null;
        ownedStorage = reopen().GetAwaiter().GetResult();
    }

    internal async Task<byte[]> Send(ParsedDmc2 message, byte[] operation)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        using var retained = sql.ReadVerifiedOperation(floor, operation);
        if (retained is not null)
        {
            if (retained.Direction != 1 || !Did2MessagingSessionScope.Fixed(retained.EventHash, SHA256.HashData(message.CanonicalBytes.Span)))
                throw new CryptographicException("Retained outbound operation has changed content/direction.");
            return retained.ExactEnvelope.ToArray();
        }
        sendEventHash = SHA256.HashData(message.CanonicalBytes.Span);
        try
        {
            using var prepared = ExactDpe2DurableTransactionProducer.PrepareSend(state, Context(false),
                message.CanonicalBytes.Span, seed.Initiation.NetworkId.Span, operation);
            using var success = await prepared.CommitAsync(this);
            return success.TakeExactEnvelope();
        }
        finally { CryptographicOperations.ZeroMemory(sendEventHash); sendEventHash = []; }
    }

    internal async Task<ExactDpe2ReceiveSuccessCapability> Receive(byte[] envelope)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var record = Dpe2Codec.Decode(envelope);
        using var retained = sql.ReadVerifiedOperation(floor, record.OperationId.Span);
        var replay = retained is not null;
        if (retained is not null && (retained.Direction != 2 || !retained.ExactEnvelope.SequenceEqual(envelope)))
            throw new CryptographicException("Isolated receive operation has changed bytes.");
        using var prepared = ExactDpe2DurableTransactionProducer.PrepareReceive(state, Context(replay), envelope);
        return await prepared.CommitAsync(this);
    }

    public ValueTask<ExactDpe2DurableCommitReceipt> CommitAsync(ExactDpe2DurablePersistencePlan plan,
        ExactDpe2DurableCommitCompletion completion, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this); cancellationToken.ThrowIfCancellationRequested();
        var prior = plan.PriorTrs1.ToArray(); var predecessor = plan.JournalPredecessor.ToArray();
        try
        {
            Assert.Equal(state, prior); Assert.Equal(journal, predecessor);
            Assert.Equal(journalGeneration, plan.ExpectedJournalGeneration);
            if (!plan.HasStateMutation)
            {
                Assert.Equal(ExactDpe2DurableDirection.Receive, plan.Direction);
                using var retained = sql.ReadVerifiedOperation(floor, plan.OperationId.Span);
                Assert.NotNull(retained); Assert.Equal(2, retained.Direction);
                Assert.Equal(retained.EnvelopeHash.ToArray(), plan.ExactEnvelopeHash.ToArray());
                return ValueTask.FromResult(completion.Complete(ExactDpe2DurableCommitDisposition.ExactReplay));
            }
            Assert.True(plan.MessageKeyDeletedAfterAuthenticatedEnvelopeOperation);
            Assert.Equal(Generation + 1, plan.NextStateGeneration);
            using var mutation = OwnedDid2MessagingMutation.Ratchet(scope, floor, plan,
                plan.Direction == ExactDpe2DurableDirection.Send ? sendEventHash : []);
            using (var recovery = OwnedDid2MessagingMutation.RecoverProtectedPending(scope, mutation.Successor, mutation.Exact.Span))
                Assert.True(recovery.Exact.Span.SequenceEqual(mutation.Exact.Span));
            floor = Persist(mutation);
            using var stored = sql.ReadVerifiedLatest(floor);
            var next = stored.Use(bytes => bytes.ToArray());
            var nextJournal = floor.Head.ToArray();
            var priorState = state;
            state = next; journal = nextJournal; journalGeneration = floor.Ordinal;
            CryptographicOperations.ZeroMemory(priorState);
            Assert.All(priorState, value => Assert.Equal((byte)0, value));
            return ValueTask.FromResult(completion.Complete(ExactDpe2DurableCommitDisposition.Committed));
        }
        finally { CryptographicOperations.ZeroMemory(prior); CryptographicOperations.ZeroMemory(predecessor); }
    }

    private MessagingCryptoV1Trs1Facts Facts() => MessagingCryptoV1Trs1.ValidateDeviceBinding(state,
        seed.Initiation.SessionId.Span,
        seed.IsInitiator ? seed.Initiation.InitiatorDeviceId.Span : seed.Initiation.ResponderDeviceId.Span,
        seed.IsInitiator ? seed.Initiation.InitiatorDeviceGeneration : seed.Initiation.ResponderDeviceGeneration);

    private ExactDpe2DurableTransitionContext Context(bool replay)
    {
        var facts = Facts();
        return new(facts.Generation, facts.StateCommitment, facts.Generation, facts.StateCommitment,
            journalGeneration, journal, retention,
            replay ? ExactDpe2ReceiveReplayDisposition.ExactReplay : ExactDpe2ReceiveReplayDisposition.Fresh);
    }

    public void Dispose()
    {
        if (disposed) return; disposed = true;
        CryptographicOperations.ZeroMemory(state); CryptographicOperations.ZeroMemory(journal);
        CryptographicOperations.ZeroMemory(retention);
        CryptographicOperations.ZeroMemory(sendEventHash);
        ownedStorage?.Dispose(); ownedStorage = null;
    }
}
