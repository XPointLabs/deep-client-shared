using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    // Private native read composition, not a transferable authority. The owner
    // consumes/disposes it synchronously before its next await/callback and
    // independently reconciles protected custody again afterwards. One actual
    // SQL snapshot authenticates the COMPLETE history, not merely selected rows.
    internal HistoricalRouteRead OpenHistoricalRouteRead(Did2MessagingFloor protectedStable)
        => HistoricalRouteRead.Open(this, protectedStable);

    internal sealed class HistoricalRouteRead : IDisposable
    {
        private readonly Did2MessagingSqlJournal owner;
        private readonly Did2MessagingFloor floor;
        private readonly SqliteTransaction transaction;
        private bool disposed;

        private HistoricalRouteRead(Did2MessagingSqlJournal owner, Did2MessagingFloor floor, SqliteTransaction transaction)
        { this.owner = owner; this.floor = floor; this.transaction = transaction; }

        // Even another assembly-internal caller cannot supply an unchecked
        // transaction. Construction always performs the actual complete join.
        internal static HistoricalRouteRead Open(Did2MessagingSqlJournal owner, Did2MessagingFloor floor)
        {
            _ = Did2MessagingFloor.Decode(floor.Exact.Span, owner.scope);
            if (floor.Phase != 1 || floor.Status != 1)
                throw new InvalidDataException("Historical route read requires active stable native custody.");
            var transaction = owner.connection.BeginTransaction(deferred: true);
            try
            {
                RequireSame(floor, owner.VerifyTipInTransaction(transaction));
                return new(owner, floor, transaction);
            }
            catch { transaction.Dispose(); throw; }
        }

        private void RequireActive() => ObjectDisposedException.ThrowIf(disposed, this);

        internal (byte[] SessionInit, byte[] Hello) ReadInitialEvents()
        {
            RequireActive();
            using var command = owner.Command("SELECT length(session_init),session_init,length(hello),hello FROM initial_events WHERE singleton=1;", transaction);
            using var reader = command.ExecuteReader();
            if (!reader.Read() || reader.GetInt64(0) is < 1 or > 32768 || reader.GetInt64(2) is < 1 or > 32768)
                throw new InvalidDataException("Verified initial events are absent or exceed their bounded shape.");
            var initial = reader.GetFieldValue<byte[]>(1); byte[] hello = [];
            try
            {
                hello = reader.GetFieldValue<byte[]>(3);
                if (reader.Read()) throw new InvalidDataException("Duplicate initial event custody exists.");
                var result = (initial, hello); initial = []; hello = []; return result;
            }
            finally { CryptographicOperations.ZeroMemory(initial); CryptographicOperations.ZeroMemory(hello); }
        }

        internal OwnedDid2MessagingPersistedEvent? ReadOperation(ReadOnlySpan<byte> operation)
        {
            RequireActive();
            ProtectedDph2PreClaimJournal.RequireIntent(operation);
            using var command = owner.Command("SELECT direction,length(envelope),envelope,length(plaintext),plaintext,metadata,ordinal FROM events WHERE operation=$op;", transaction);
            command.Parameters.AddWithValue("$op", operation.ToArray());
            using var row = command.ExecuteReader();
            return owner.ReadSelectedOrdinaryEvent(floor, row);
        }

        internal OwnedDid2MessagingPersistedEvent? ReadReceiveForEvent(ReadOnlySpan<byte> eventHash)
        {
            RequireActive();
            ProtectedDph2PreClaimJournal.RequireIntent(eventHash);
            using var command = owner.Command("SELECT direction,length(envelope),envelope,length(plaintext),plaintext,metadata,ordinal FROM events WHERE direction=2 AND substr(metadata,301,32)=$hash ORDER BY ordinal LIMIT 1;", transaction);
            command.Parameters.AddWithValue("$hash", eventHash.ToArray());
            using var row = command.ExecuteReader();
            return owner.ReadSelectedOrdinaryEvent(floor, row);
        }

        // Retained history is lifetime-sized: keep ONE bounded native event at
        // a time rather than adding a new maximum route count or a lifetime
        // plaintext collection. Full framing/type/marker checks preceded this
        // filter in VerifyTipInTransaction; each selected row is checked again.
        // No await, callback or mutation is permitted while enumerating.
        internal IEnumerable<OwnedDid2MessagingPersistedEvent> ReadIncomingRouteControls(CancellationToken ct)
        {
            RequireActive(); ct.ThrowIfCancellationRequested();
            using var command = owner.Command("SELECT ordinal,operation,metadata,envelope,plaintext,typeof(operation),length(operation),typeof(metadata),length(metadata),typeof(envelope),length(envelope),typeof(plaintext),length(plaintext) FROM events WHERE direction=2 AND substr(metadata,$routeOffset,1) IN (X'01',X'02') ORDER BY ordinal;", transaction);
            command.Parameters.AddWithValue("$routeOffset", Did2RouteProcessingMetadata.Offset + 1);
            using var reader = command.ExecuteReader();
            ulong previous = 0;
            while (reader.Read())
            {
                RequireActive(); ct.ThrowIfCancellationRequested();
                var ordinal = reader.GetInt64(0);
                if (ordinal <= 0 || (ulong)ordinal <= previous || (ulong)ordinal > floor.Ordinal ||
                    reader.GetString(5) != "blob" || reader.GetInt64(6) != 32 ||
                    reader.GetString(7) != "blob" || reader.GetInt64(8) != Did2MessagingFloor.MetadataBytes ||
                    reader.GetString(9) != "blob" || reader.GetInt64(10) is < 1 or > 65536 ||
                    reader.GetString(11) != "blob" || reader.GetInt64(12) is < 1 or > 33082)
                    throw new InvalidDataException("Route history has a noncanonical native event shape.");
                var operation = reader.GetFieldValue<byte[]>(1); var metadata = reader.GetFieldValue<byte[]>(2);
                byte[] envelope = [], plaintext = [];
                OwnedDid2MessagingPersistedEvent? result = null;
                try
                {
                    envelope = reader.GetFieldValue<byte[]>(3); plaintext = reader.GetFieldValue<byte[]>(4);
                    owner.VerifyHistoricalEvent((ulong)ordinal, 2, operation, metadata, envelope, plaintext);
                    if (metadata[Did2RouteProcessingMetadata.Offset] is not (1 or 2))
                        throw new InvalidDataException("Route-only history selected a non-control native event.");
                    result = new(2, (ulong)ordinal, envelope, plaintext, metadata.AsSpan(300, 32),
                        metadata.AsSpan(Did2RouteProcessingMetadata.Offset, Did2RouteProcessingMetadata.Bytes));
                    envelope = []; plaintext = []; previous = (ulong)ordinal;
                    yield return result;
                }
                finally
                {
                    result?.Dispose();
                    CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(metadata);
                    CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(plaintext);
                }
            }
            RequireActive(); ct.ThrowIfCancellationRequested();
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true; transaction.Dispose();
        }
    }
}
