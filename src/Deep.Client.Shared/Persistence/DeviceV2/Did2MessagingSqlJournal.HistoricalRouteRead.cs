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
                owner.RequireSame(floor, owner.VerifyActiveTip(transaction, null, out _));
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
            using var selection = new ActiveSelection([operation.ToArray()]);
            owner.RequireSame(floor, owner.VerifyActiveTip(transaction, selection, out _));
            return owner.ReadCapturedOrdinaryEvent(selection[0], transaction);
        }

        internal OwnedDid2MessagingPersistedEvent? ReadReceiveForEvent(ReadOnlySpan<byte> eventHash)
        {
            RequireActive();
            ProtectedDph2PreClaimJournal.RequireIntent(eventHash);
            using var selection = new ActiveSelection([eventHash.ToArray()], eventHash: true);
            owner.RequireSame(floor, owner.VerifyActiveTip(transaction, selection, out _));
            return owner.ReadCapturedOrdinaryEvent(selection[0], transaction);
        }

        internal OwnedDid2MessagingPersistedEvent? ReadArchivedPeerHead()
        {
            RequireActive(); var reference = owner.ReadArchiveReducer(transaction).Reference(Did2MessagingArchiveReducer.ReferenceKind.PeerHead);
            if (reference.Kind != 2) return null;
            reference.RequireAtBasis(owner.WorkingBasis.Ordinal);
            using var tuple = owner.ReadArchivedTuple(reference, transaction);
            return owner.ReadCapturedOrdinaryEvent(tuple, transaction);
        }

        internal bool ReadArchivedPeerFault()
        {
            RequireActive(); var reference = owner.ReadArchiveReducer(transaction).Reference(Did2MessagingArchiveReducer.ReferenceKind.FirstFault);
            if (reference.IsAbsent) return false;
            reference.RequireAtBasis(owner.WorkingBasis.Ordinal);
            using var original = owner.ReadArchiveOriginal(reference, transaction);
            if (reference.Kind == 3)
            {
                var decision = Did2RouteHistoryDecision.Decode(original.Plaintext, owner.scope);
                if (decision.Subject != 2 || decision.Action != Did2RouteHistoryDecision.ActionKind.Conflict)
                    throw new CryptographicException("Selected historical fault lost its actual peer conflict decision.");
                return true;
            }
            var message = Deep.Protocol.ApplicationCore.ApplicationCoreCodec.DecodeDmc2(original.Plaintext);
            Did2RouteProcessingMetadata.RequireReceivedEvent(original.Metadata.AsSpan(608, 64), message);
            if (original.Metadata[608] != 2) throw new CryptographicException("Selected historical route fault changes its original outcome.");
            return true;
        }

        internal Deep.Protocol.ContactV1.ParsedContactRouteClosure? ReadQualifiedArchivedPeerRoute(
            ReadOnlySpan<byte> expected, ulong actualConsentOrdinal)
        {
            RequireActive(); var value = owner.ReadArchiveFact(Did2MessagingArchiveFamily.QualifiedPeerRoute, SHA256.HashData(expected), transaction);
            if (value is null)
            {
                var headers = owner.ReadJournal(out var actual, transaction); owner.RequireSame(floor, actual);
                for (var index = 0; index < headers.Count; index++)
                {
                    var metadata = headers[index]; if (metadata[5] != 6) continue;
                    var selected = owner.CaptureDecisionReference(checked(owner.WorkingBasis.Ordinal + (ulong)index + 1), metadata, transaction);
                    using var working = owner.ReadRouteHistoryDecision(selected, transaction);
                    if (working.Body.Subject != 2 || working.Body.Action != Did2RouteHistoryDecision.ActionKind.Promotion ||
                        !Fixed(working.Body.EndpointHash, SHA256.HashData(expected))) continue;
                    if (working.Body.Consent.Ordinal != actualConsentOrdinal) throw new CryptographicException("Working peer promotion changes its actual consent.");
                    var closure = owner.ReadQualifiedDecisionClosure(working, transaction);
                    if (!Fixed(closure.ExactBytes.Span, expected)) throw new CryptographicException("Working peer promotion changes its exact qualified endpoint.");
                    return closure;
                }
                return null;
            }
            var reference = Did2MessagingArchiveReference.Decode(value.AsSpan(0, 88), false); reference.RequireAtBasis(owner.WorkingBasis.Ordinal);
            if (reference.Kind == 3)
            {
                using var decision = owner.ReadRouteHistoryDecision(reference, transaction);
                if (decision.Body.Action != Did2RouteHistoryDecision.ActionKind.Promotion || decision.Body.Subject != 2 ||
                    decision.Body.Consent.Ordinal != actualConsentOrdinal || !Fixed(decision.Body.EndpointHash, SHA256.HashData(expected)) ||
                    !Fixed(decision.Body.L.Exact.Span, decision.Body.Selected.Exact.Span))
                    throw new CryptographicException("Historical qualified route lost its actual peer promotion/consent.");
                var qualifiedClosure = owner.ReadQualifiedDecisionClosure(decision, transaction);
                if (!Fixed(qualifiedClosure.ExactBytes.Span, expected)) throw new CryptographicException("Historical peer promotion changed its exact endpoint closure.");
                return qualifiedClosure;
            }
            byte[] exact;
            if (reference.Kind == 1)
            {
                var initial = owner.ReadArchiveInitialSource(transaction);
                try
                {
                    if (owner.scope.IsInitiator || !Fixed(SHA256.HashData(initial.Metadata), reference.MetadataHash)) throw new CryptographicException("Historical qualified Hello changes its original.");
                    exact = initial.Hello.ToArray();
                }
                finally { CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello); }
            }
            else
            {
                using var original = owner.ReadArchiveOriginal(reference, transaction);
                if (reference.Direction != 2) throw new CryptographicException("Historical qualified route has an outgoing witness.");
                exact = original.Plaintext.ToArray();
            }
            try
            {
                var message = Deep.Protocol.ApplicationCore.ApplicationCoreCodec.DecodeDmc2(exact);
                var consent = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(value.AsSpan(88));
                var predecessor = value.AsSpan(96, 32); var sequence = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(value.AsSpan(128));
                var closure = message.ParsedPayload switch
                {
                    Deep.Protocol.ApplicationCore.ContactHelloDmc2Payload hello when reference.Kind == 1 && consent == 0 && Did2MessagingSessionScope.Zero(predecessor) => hello.MailboxRoute.Route,
                    Deep.Protocol.ApplicationCore.ContactAcceptDmc2Payload accept when owner.scope.IsInitiator && consent == reference.Ordinal && consent == actualConsentOrdinal && Did2MessagingSessionScope.Zero(predecessor) => accept.MailboxRoute.Route,
                    Deep.Protocol.ApplicationCore.ContactRouteUpdateDmc2Payload update when consent == actualConsentOrdinal && consent != 0 && reference.Ordinal > consent && Fixed(predecessor, update.PredecessorRouteUpdateHash.Span) => Deep.Protocol.ContactV1.ContactRouteClosureCodec.Decode(update.ExactRouteClosure.Span),
                    _ => throw new CryptographicException("Historical archive qualification changes actual consent/predecessor/source kind.")
                };
                if (sequence != message.SenderClientSequence || !Fixed(expected, closure.ExactBytes.Span)) throw new CryptographicException("Historical archive qualification changes the exact closure/sequence.");
                return closure;
            }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }

        // Retained history is lifetime-sized: keep ONE bounded native event at
        // a time rather than adding a new maximum route count or a lifetime
        // plaintext collection. Full framing/type/marker checks preceded this
        // filter in VerifyTipInTransaction; each selected row is checked again.
        // No await, callback or mutation is permitted while enumerating.
        internal IEnumerable<OwnedDid2MessagingPersistedEvent> ReadIncomingRouteControls(CancellationToken ct)
        {
            RequireActive(); ct.ThrowIfCancellationRequested();
            using var command = owner.Command("SELECT ordinal,operation,metadata,envelope,plaintext,typeof(operation),length(operation),typeof(metadata),length(metadata),typeof(envelope),length(envelope),typeof(plaintext),length(plaintext) FROM events WHERE ordinal>$basis AND direction=2 AND substr(metadata,$routeOffset,1) IN (X'01',X'02') ORDER BY ordinal;", transaction);
            command.Parameters.AddWithValue("$basis", checked((long)owner.WorkingBasis.Ordinal));
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
