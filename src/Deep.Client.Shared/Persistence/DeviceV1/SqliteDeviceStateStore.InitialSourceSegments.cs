using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV1;

public sealed partial class SqliteDeviceStateStore
{
    // Registration and protected roots belong to the caller's actual read
    // group. This owner must be disposed before the next protected operation.
    internal static SqliteDeviceStateStore OpenMessagingSourceSegment(
        SqliteDeviceStateStoreOptions options, bool readOnlySource)
    {
        ArgumentNullException.ThrowIfNull(options);
        try { return new(options, readOnlySource); }
        finally { options.ClearSourceSegmentKey(); }
    }

    internal void VerifyMessagingSourceReadSegment(Did2MessagingSessionScope scope, bool requireRetired,
        ReadOnlyMemory<byte> checkpointExact, ProtectedInitialKeyRetirementJournal.State retirements)
    {
        using var operation = EnterOperation(); gate.Wait();
        try
        {
            ThrowIfDisposed();
            initialSessionNetwork = scope.Network.ToArray(); initialRetirements = retirements;
            using var checkpoint = DeviceInitialSessionCheckpoint.Decode(checkpointExact.Span,
                storeInstanceId.Span, accountId.Span, initialSessionNetwork);
            if (checkpoint.Phase != 1) throw new IOException("Pending sender work requires a separate recovery segment.");
            var db = GetConnection(); using var tx = db.BeginTransaction(deferred: true);
            RequireInitialSourceTip(checkpoint, ReadInitialSessionTip(db, tx));
            RequireMessagingSender(db, tx, scope, requireRetired);
        }
        finally { gate.Release(); }
    }

    // No protected storage or asynchronous callback is reachable here. The
    // returned public checkpoint proposal is published only after disposal.
    internal byte[] RecoverMessagingSourceSegment(ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> checkpointExact, ProtectedInitialKeyRetirementJournal.State retirements)
    {
        using var operation = EnterOperation(); gate.Wait();
        try
        {
            ThrowIfDisposed(); initialSessionNetwork = network.ToArray(); initialRetirements = retirements;
            using var checkpoint = DeviceInitialSessionCheckpoint.Decode(checkpointExact.Span,
                storeInstanceId.Span, accountId.Span, initialSessionNetwork);
            if (checkpoint.Phase != 2) throw new InvalidOperationException("Sender recovery requires its exact pending checkpoint.");
            using var completed = DeepIdV2InitialSessionCommit.RestorePending(checkpoint.Payload);
            RequireInitialSessionScope(completed);
            var db = GetConnection();
            using (var tx = db.BeginTransaction(deferred: false))
            {
                var tip = ReadInitialSessionTip(db, tx);
                if (tip.Sequence + 1 == checkpoint.Sequence && DeviceInitialSessionCheckpoint.Fixed(tip.Hash, checkpoint.Previous))
                {
                    if (ReadOperation(db, tx, DeviceOperationId32.FromBytes(completed.ClaimOperationId.Span)) is not null)
                        throw new CryptographicException("The protected pending agreement has a different durable burn.");
                    var directory = ReadProtectedDmd1(db, tx);
                    if (directory is null || !directory.ExactEquals(completed.Directory))
                        throw new CryptographicException("Pending recovery cannot overwrite a different current device directory.");
                    InsertCompletedInitialSession(db, tx, checkpoint, completed);
                }
                else RequireInitialSourceTip(checkpoint, tip);
                tx.Commit();
            }
            using (var tx = db.BeginTransaction(deferred: true))
                RequireInitialSourceTip(checkpoint, ReadInitialSessionTip(db, tx));
            return DeviceInitialSessionCheckpoint.Stable(storeInstanceId.Span, accountId.Span,
                initialSessionNetwork, checkpoint.Sequence, checkpoint.Hash);
        }
        finally { gate.Release(); }
    }

    private static void RequireInitialSourceTip(DeviceInitialSessionCheckpoint.State checkpoint, InitialSessionTip tip)
    {
        if (tip.Sequence != checkpoint.Sequence || !DeviceInitialSessionCheckpoint.Fixed(tip.Hash, checkpoint.Hash))
            throw new CryptographicException("The initial-session history is missing, rolled back or substituted.");
    }

    private void RequireMessagingSender(SqliteConnection db, SqliteTransaction tx,
        Did2MessagingSessionScope scope, bool requireRetired)
    {
        using var read = db.CreateCommand(); read.Transaction = tx;
        read.CommandText = "SELECT sequence,payload FROM device_initial_sessions ORDER BY sequence;";
        using var rows = read.ExecuteReader(); var found = false;
        while (rows.Read())
        {
            var payload = rows.GetFieldValue<byte[]>(1);
            try
            {
                using var source = DeepIdV2InitialSessionCommit.RestoreCustody(payload);
                if (!DeviceInitialSessionCheckpoint.Fixed(source.SessionId.Span, scope.Session)) continue;
                if (found) throw new CryptographicException("Mutable sender source is not unique.");
                found = true; Did2MessagingSourceScope.RequireSender(scope, source);
                var entry = initialRetirements!.Find(1, storeInstanceId.Span, checked((ulong)rows.GetInt64(0)));
                Did2MessagingSourceScope.RequireRetirement(entry, scope, requireRetired, live: entry is null || entry.Phase != 2);
            }
            finally { CryptographicOperations.ZeroMemory(payload); }
        }
        if (!found) throw new CryptographicException("Mutable sender source history is absent.");
    }
}
