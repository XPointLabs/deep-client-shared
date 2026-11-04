using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV1;

public sealed partial class SqliteDeviceStateStore
{
    // Public custody coordinates only; no restored Initial/TRS leaves a
    // physical source segment or survives its next protected-storage callback.
    internal sealed record CancellationSource(ulong Ordinal, byte[] RecordHash,
        byte[] Basis, byte[] TrsHash, byte[] Session, bool Live);

    internal CancellationSource? InspectCancellationSourceSegment(ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> checkpointExact, ProtectedInitialKeyRetirementJournal.State retirements,
        ProtectedDid2ContactStartJournal.Entry draft)
    {
        using var operation = EnterOperation(); gate.Wait();
        try
        {
            ThrowIfDisposed(); initialSessionNetwork = network.ToArray(); initialRetirements = retirements;
            using var checkpoint = DeviceInitialSessionCheckpoint.Decode(checkpointExact.Span,
                storeInstanceId.Span, accountId.Span, initialSessionNetwork);
            if (checkpoint.Phase != 1) throw new IOException("Cancellation requires its exact stable source checkpoint.");
            using var tx = GetConnection().BeginTransaction(deferred: true);
            RequireInitialSourceTip(checkpoint, ReadInitialSessionTip(GetConnection(), tx));
            return ReadCancellationSource(GetConnection(), tx, draft);
        }
        finally { gate.Release(); }
    }

    internal void DeleteCancellationSourceSegment(ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> checkpointExact, ProtectedInitialKeyRetirementJournal.State retirements,
        ProtectedDid2ContactStartJournal.Entry draft, ProtectedInitialKeyRetirementJournal.Entry expected)
    {
        using var operation = EnterOperation(); gate.Wait();
        try
        {
            ThrowIfDisposed(); initialSessionNetwork = network.ToArray(); initialRetirements = retirements;
            using var checkpoint = DeviceInitialSessionCheckpoint.Decode(checkpointExact.Span,
                storeInstanceId.Span, accountId.Span, initialSessionNetwork);
            if (checkpoint.Phase != 1) throw new IOException("Cancellation cannot delete an unresolved source checkpoint.");
            using var tx = GetConnection().BeginTransaction(deferred: false);
            RequireInitialSourceTip(checkpoint, ReadInitialSessionTip(GetConnection(), tx));
            var source = ReadCancellationSource(GetConnection(), tx, draft);
            RequireCancellationSource(expected, draft, source);
            if (expected.Phase != 1) throw new CryptographicException("Stable cancellation cannot destroy resurrected keys.");
            if (source is not null)
            {
                using var delete = GetConnection().CreateCommand(); delete.Transaction = tx;
                delete.CommandText = "DELETE FROM device_initial_state WHERE sequence=$sequence;";
                delete.Parameters.AddWithValue("$sequence", checked((long)source.Ordinal));
                if (delete.ExecuteNonQuery() != (source.Live ? 1 : 0))
                    throw new CryptographicException("Initial cancellation deleted another key source.");
            }
            tx.Commit();
        }
        finally { gate.Release(); }
    }

    internal void RequireCancellationSource(ProtectedInitialKeyRetirementJournal.Entry expected,
        ProtectedDid2ContactStartJournal.Entry draft, CancellationSource? source)
    {
        if (expected.Role != 3 || !DeviceInitialSessionCheckpoint.Fixed(expected.SourceInstance, storeInstanceId.Span) ||
            !DeviceInitialSessionCheckpoint.Fixed(expected.Intent, draft.Intent) ||
            !DeviceInitialSessionCheckpoint.Fixed(expected.ScopeHash, draft.CancellationBinding) ||
            expected.Ordinal != (source?.Ordinal ?? 0) ||
            source is not null && (!DeviceInitialSessionCheckpoint.Fixed(expected.RecordHash, source.RecordHash) ||
                !DeviceInitialSessionCheckpoint.Fixed(expected.Basis, source.Basis) ||
                !DeviceInitialSessionCheckpoint.Fixed(expected.TrsHash, source.TrsHash)) ||
            expected.Phase == 2 && source?.Live == true)
            throw new CryptographicException("Initial cancellation changed its exact source or resurrected keys.");
    }

    private CancellationSource? ReadCancellationSource(SqliteConnection db, SqliteTransaction tx,
        ProtectedDid2ContactStartJournal.Entry draft)
    {
        using var source = ReadInitialSessionByIntent(db, tx, draft.Intent.ToArray());
        if (source is null) return null;
        if (!draft.PayloadRetired)
        {
            var conversation = source.RequireInitialConversation(draft.Init, draft.Hello);
            try
            {
                if (!DeviceInitialSessionCheckpoint.Fixed(conversation, draft.Conversation))
                    throw new CryptographicException("Cancelled source changed its original events.");
            }
            finally { CryptographicOperations.ZeroMemory(conversation); }
        }
        using var read = db.CreateCommand(); read.Transaction = tx;
        read.CommandText = "SELECT sequence,record_hash FROM device_initial_sessions WHERE logical_intent_id=$intent;";
        read.Parameters.AddWithValue("$intent", draft.Intent.ToArray()); using var row = read.ExecuteReader();
        if (!row.Read()) throw new CryptographicException("Cancelled Initial source disappeared.");
        var result = new CancellationSource(checked((ulong)row.GetInt64(0)), row.GetFieldValue<byte[]>(1),
            SHA256.HashData(source.CanonicalSpan), source.InitialStateHashSpan.ToArray(), source.SessionId.ToArray(), source.HasInitialState);
        if (row.Read()) throw new CryptographicException("Cancelled Initial source is not unique.");
        return result;
    }
}
