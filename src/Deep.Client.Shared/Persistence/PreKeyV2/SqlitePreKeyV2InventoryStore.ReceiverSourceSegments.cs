using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.PreKeyV2;

internal sealed partial class SqlitePreKeyV2InventoryStore
{
    internal sealed record SourceConsumption(string Slot, byte[] ExpectedHash, int[] Indices);
    internal sealed record SourceRecovery(byte[] StableCheckpoint, IReadOnlyList<SourceConsumption> Consumption);

    // A synchronous segment over the caller's fresh registration and protected
    // roots. Dispose this store and its secret snapshot before any provider.
    internal void VerifyMessagingSourceReadSegment(Did2MessagingSessionScope scope, bool requireRetired,
        ReadOnlyMemory<byte> checkpointExact, ProtectedInitialKeyRetirementJournal.State retirements,
        ReadOnlyMemory<byte> accountInstance)
    {
        gate.Wait();
        try
        {
            ThrowIfDisposed(); BindReceiverSource(accountInstance.Span, retirements);
            using var checkpoint = ResponderInitialSessionCheckpoint.Decode(checkpointExact.Span, receiverInstance!, account, network);
            if (checkpoint.Phase != 1) throw new IOException("Pending receiver work requires a separate recovery segment.");
            // Includes exact inventory signatures/binding, exhausted SQL
            // secrets and independent protected successor-secret destruction.
            ValidateStagedRows(restoreSecrets: true);
            using var tx = connection.BeginTransaction(deferred: true);
            using var ledger = ReadReceiverLedger(tx);
            RequireReceiverSourceTip(checkpoint, ledger);
            var session = scope.Session.ToArray();
            var source = ledger.Entries.SingleOrDefault(value => Fixed(value.Commit.SessionId.Span, session)) ??
                throw new CryptographicException("Mutable receiver source history is absent.");
            Did2MessagingSourceScope.RequireReceiver(scope, source.Commit);
            var entry = receiverRetirements!.Find(2, receiverInstance!, source.Sequence);
            Did2MessagingSourceScope.RequireRetirement(entry, scope, requireRetired, source.Commit.HasInitialState);
        }
        finally { gate.Release(); }
    }

    internal SourceRecovery RecoverMessagingSourceSegment(ReadOnlyMemory<byte> checkpointExact,
        ProtectedInitialKeyRetirementJournal.State retirements, ReadOnlyMemory<byte> accountInstance)
    {
        gate.Wait();
        try
        {
            ThrowIfDisposed(); BindReceiverSource(accountInstance.Span, retirements);
            using var checkpoint = ResponderInitialSessionCheckpoint.Decode(checkpointExact.Span, receiverInstance!, account, network);
            if (checkpoint.Phase != 2) throw new InvalidOperationException("Receiver recovery requires its exact pending checkpoint.");
            using var completed = DeepIdV2InitialContactSessionCommit.RestorePending(checkpoint.Payload);
            RequireReceiverScope(completed);
            using (var ledger = ReadReceiverLedger())
            {
                if (ledger.Sequence + 1 == checkpoint.Sequence && Fixed(ledger.Hash, checkpoint.Previous))
                    AppendReceiverTransaction(checkpoint, completed);
                else if (ledger.Sequence != checkpoint.Sequence || !Fixed(ledger.Hash, checkpoint.Hash) ||
                    !Fixed(ledger.Entries[^1].Commit.CanonicalSpan, completed.CanonicalSpan))
                    throw new CryptographicException("Pending receiver record has no exact recoverable predecessor or committed successor.");
            }
            using var verified = ReadReceiverLedger(); RequireReceiverSourceTip(checkpoint, verified);
            var consumption = ReadSourceConsumption(verified);
            return new(ResponderInitialSessionCheckpoint.Stable(receiverInstance!, account, network,
                checkpoint.Sequence, checkpoint.Hash), consumption);
        }
        finally { gate.Release(); }
    }

    private void BindReceiverSource(ReadOnlySpan<byte> instance, ProtectedInitialKeyRetirementJournal.State retirements)
    {
        if (instance.Length != 32 || instance.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact receiver instance is required.", nameof(instance));
        if (receiverInstance is not null && !Fixed(receiverInstance, instance))
            throw new CryptographicException("Receiver custody cannot change owner.");
        receiverInstance = instance.ToArray(); receiverRetirements = retirements;
    }

    private static void RequireReceiverSourceTip(ResponderInitialSessionCheckpoint.State checkpoint, Ledger ledger)
    {
        if (checkpoint.Sequence != ledger.Sequence || !Fixed(checkpoint.Hash, ledger.Hash))
            throw new CryptographicException("Receiver history is missing, rolled back or substituted.");
    }

    private List<SourceConsumption> ReadSourceConsumption(Ledger ledger)
    {
        var result = new List<SourceConsumption>();
        if (successorCustody is null) return result;
        var ownedMembers = OwnedPublicMembers();
        for (var ordinal = 0; ordinal < successorCustody.Entries.Count; ordinal++)
        {
            var entry = successorCustody.Entries[ordinal];
            var publication = successorPublicRecords[ordinal];
            var members = publication.OneTimeMembers.Append(publication.LastResortMember).ToArray();
            var erase = new List<int>();
            for (var index = 0; index < members.Length; index++)
            {
                var consumed = IsOwnedPreKeyExhausted(ledger, members[index], ownedMembers);
                var blob = entry.CopySealedSecret(index);
                try
                {
                    if (blob.Length == 0 && !consumed) throw new CryptographicException("A protected unconsumed prekey disappeared.");
                    if (blob.Length > 0 && consumed) erase.Add(index);
                }
                finally { CryptographicOperations.ZeroMemory(blob); }
            }
            if (erase.Count == 0) continue;
            var exact = entry.CopyExact();
            try { result.Add(new(ProtectedPreKeyInventoryChain.EntrySlot(entry.PublicationHash), SHA256.HashData(exact), erase.ToArray())); }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
        return result;
    }
}
