using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV1;

public sealed partial class SqliteDeviceStateStore
{
    private IDeepSecureStorage? initialSessionStorage;
    private byte[]? initialSessionNetwork;
    private ProtectedInitialKeyRetirementJournal.State? initialRetirements;
    private sealed record InitialSessionTip(ulong Sequence, byte[] Hash);

    internal async ValueTask OpenInitialSessionCustodyAsync(IDeepSecureStorage storage,
        ReadOnlyMemory<byte> network, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(storage);
        using var operation = EnterOperation();
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (initialSessionStorage is not null && (!ReferenceEquals(storage, initialSessionStorage) ||
                !DeviceInitialSessionCheckpoint.Fixed(network.Span, initialSessionNetwork)))
                throw new CryptographicException("Initial-session custody cannot change owner.");
            initialSessionStorage = storage; initialSessionNetwork = network.ToArray();
            await ReconcileInitialSessionsUnderGateAsync(ct).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    internal async ValueTask<bool> HasCompletedInitialSessionAsync(ReadOnlyMemory<byte> intent, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span);
        var lookupIntent = intent.ToArray();
        using var operation = EnterOperation(); await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); await ReconcileInitialSessionsUnderGateAsync(ct).ConfigureAwait(false);
            using var read = GetConnection().CreateCommand();
            read.CommandText = "SELECT 1 FROM device_initial_sessions WHERE logical_intent_id=$intent;";
            read.Parameters.AddWithValue("$intent", lookupIntent); return read.ExecuteScalar() is not null;
        }
        finally { gate.Release(); }
    }

    // Account-owned import reads the actual reconciled source, not a caller's
    // retained TRS. This grants neither dispatch nor contact acceptance.
    internal async ValueTask<DeepIdV2InitialSessionCommit> ReadMessagingSourceByIntentUnderLeaseAsync(
        ReadOnlyMemory<byte> intent, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span);
        var ownedIntent = intent.ToArray();
        using var operation = EnterOperation(); await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); await ReconcileInitialSessionsUnderGateAsync(ct).ConfigureAwait(false);
            var db = GetConnection(); using var tx = db.BeginTransaction(deferred: false);
            return ReadInitialSessionByIntent(db, tx, ownedIntent) ??
                throw new CryptographicException("Owned messaging import has no completed sender source.");
        }
        finally { gate.Release(); }
    }

    // Completed retry precedes any reopening of DR-0019 preclaim secrets.
    internal async ValueTask<DeepIdV2InitialSessionCommit?> FindCompletedInitialSessionAsync(
        ReadOnlyMemory<byte> intent, VerifiedDpk2Offering offering, Dmd1LineageState directory,
        LocalDeviceX25519AgreementAuthority authority, VerifiedXpc1V2PreKeyClaimReceipt claim,
        ReadOnlyMemory<byte> initial, ReadOnlyMemory<byte> first, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span);
        if (initial.IsEmpty || initial.Length > 32768 || first.Length > 32768)
            throw new InvalidDataException("Completed retry events exceed their closed local bounds.");
        var lookupIntent = intent.ToArray(); var exactInitial = initial.ToArray(); var exactFirst = first.ToArray();
        using var operation = EnterOperation(); var entered = false;
        DeepIdV2InitialSessionCommit? prior = null;
        try
        {
            await gate.WaitAsync(ct).ConfigureAwait(false); entered = true;
            ThrowIfDisposed(); await ReconcileInitialSessionsUnderGateAsync(ct).ConfigureAwait(false);
            var db = GetConnection(); using var tx = db.BeginTransaction(deferred: false);
            prior = ReadInitialSessionByIntent(db, tx, lookupIntent);
            if (prior is null) return null;
            var evidence = CurrentDmd1Evidence.FromVerified(directory);
            var device = LocalDeviceAgreementBinding.FromAuthority(authority);
            var fingerprint = ProtectedCurrentDmd1Validation.FingerprintAgreement(evidence, device,
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1, prior.ClaimOperationId.Span,
                offering.InitiatorAgreementPeerPublicKey.Span);
            if (ProtectedCurrentDmd1Validation.ValidateAuthorization(ReadSnapshot(db, tx), ReadProtectedDmd1(db, tx), evidence, device) !=
                ProtectedDeviceAgreementDisposition.Granted || prior.Fingerprint != fingerprint ||
                !DeviceInitialSessionCheckpoint.Fixed(prior.ClaimOperationId.Span, claim.OperationId.Span) ||
                !DeviceInitialSessionCheckpoint.Fixed(prior.ExactClaimReplayHash.Span, claim.ExactReplayHash.Span) ||
                !DeviceInitialSessionCheckpoint.Fixed(offering.ExactHash.Span, claim.ExactDpk2Hash.Span) ||
                !DeviceInitialSessionCheckpoint.Fixed(prior.EventHashSpan, DeviceInitialSessionCheckpoint.EventHash(exactInitial, exactFirst)))
                throw new CryptographicException("Completed initial-session retry substituted its exact owned inputs.");
            _ = prior.RequireInitialConversation(exactInitial, exactFirst);
            var result = prior; prior = null; return result;
        }
        finally
        {
            prior?.Dispose(); CryptographicOperations.ZeroMemory(exactInitial); CryptographicOperations.ZeroMemory(exactFirst);
            if (entered) gate.Release();
        }
    }

    // No general-purpose callback and no lease/preparation escape. The only
    // result is a stable, custody-authenticated complete initial session.
    internal async ValueTask<DeepIdV2InitialSessionCommit> CommitInitialSessionAsync(
        ReadOnlyMemory<byte> logicalIntent, InitiatorDph2PreKeyClaim started,
        VerifiedDpk2Offering offering, Dmd1LineageState directory,
        LocalDeviceX25519AgreementAuthority authority, VerifiedXpc1V2PreKeyClaimReceipt claim,
        VerifiedDeepIdV2DirectoryFreshness currentAccount, OnionTrustedTimeAuthority trustedTime,
        ReadOnlyMemory<byte> sessionInit, ReadOnlyMemory<byte> firstEvent,
        int maximumMessagesWithoutPqInjection, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent.Span);
        ArgumentNullException.ThrowIfNull(started); ArgumentNullException.ThrowIfNull(offering);
        ArgumentNullException.ThrowIfNull(claim); ArgumentNullException.ThrowIfNull(trustedTime);
        if (sessionInit.IsEmpty || sessionInit.Length > 32768 || firstEvent.Length > 32768)
            throw new InvalidDataException("The initial events exceed their closed local preparation bound.");
        var intent = logicalIntent.ToArray(); var initial = sessionInit.ToArray(); var first = firstEvent.ToArray();
        using var operationLease = EnterOperation();
        var entered = false;
        DeepIdV2InitialSessionCommit? completed = null;
        try
        {
            await gate.WaitAsync(ct).ConfigureAwait(false); entered = true; ThrowIfDisposed();
            await ReconcileInitialSessionsUnderGateAsync(ct).ConfigureAwait(false);
            var storage = RequireInitialSessionStorage(); var network = initialSessionNetwork!;
            var evidence = CurrentDmd1Evidence.FromVerified(directory);
            var device = LocalDeviceAgreementBinding.FromAuthority(authority);
            var operation = DeviceOperationId32.FromBytes(started.ClaimOperationId.Span);
            var peer = offering.InitiatorAgreementPeerPublicKey;
            var purpose = LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1;
            var fingerprint = ProtectedCurrentDmd1Validation.FingerprintAgreement(evidence, device, purpose,
                operation.Span, peer.Span);
            var eventHash = DeviceInitialSessionCheckpoint.EventHash(initial, first);
            if (!DeviceInitialSessionCheckpoint.Fixed(offering.ExactHash.Span, claim.ExactDpk2Hash.Span) ||
                !DeviceInitialSessionCheckpoint.Fixed(operation.Span, claim.OperationId.Span))
                throw new CryptographicException("The exact initial-session offering or operation differs from its claim.");

            var db = GetConnection();
            using var transaction = db.BeginTransaction(deferred: false);
            if (ProtectedCurrentDmd1Validation.ValidateAuthorization(ReadSnapshot(db, transaction),
                ReadProtectedDmd1(db, transaction), evidence, device) != ProtectedDeviceAgreementDisposition.Granted)
                throw new CryptographicException("The initial-session device directory is not the protected current authority.");
            var prior = ReadInitialSessionByIntent(db, transaction, intent);
            if (prior is not null)
            {
                if (prior.Fingerprint != fingerprint || !DeviceInitialSessionCheckpoint.Fixed(prior.EventHashSpan, eventHash) ||
                    !DeviceInitialSessionCheckpoint.Fixed(prior.ClaimOperationId.Span, operation.Span) ||
                    !DeviceInitialSessionCheckpoint.Fixed(prior.ExactClaimReplayHash.Span, claim.ExactReplayHash.Span))
                { prior.Dispose(); throw new CryptographicException("The durable initial-session intent was substituted."); }
                try { _ = prior.RequireInitialConversation(initial, first); }
                catch { prior.Dispose(); throw; }
                return prior; // Never consumes/reissues a spent lease or re-encrypts DPH2.
            }
            if (ReadOperation(db, transaction, operation) is not null)
                throw new CryptographicException("The device operation was already spent without this exact initial session.");
            using var checkpointOwner = await storage.ReadOwnedAsync(DeviceInitialSessionCheckpoint.Slot, ct)
                .ConfigureAwait(false) ?? throw new InvalidDataException("The initial-session checkpoint disappeared.");
            var previous = checkpointOwner.Use(static bytes => bytes.ToArray());
            byte[]? pending = null;
            try
            {
                using var stable = DeviceInitialSessionCheckpoint.Decode(previous, storeInstanceId.Span, accountId.Span, network);
                if (stable.Phase != 1) throw new CryptographicException("Initial-session custody is not stable.");
                // Transient authorization is private to this closed transaction.
                // No general issuer can receive it before durable completion.
                using var authorization = new ProtectedDeviceAgreementAuthorization(operation, evidence, device,
                    purpose, operation.Span, peer.Span);
                using var lease = ProtectedDeviceAgreementLeaseBridge.Redeem(authorization, directory, authority);
                using var prepared = new ManagedInitiatorInitialSessionFactory(maximumMessagesWithoutPqInjection)
                    .CompleteClaim(started, offering, lease);
                using var capability = await prepared.CompleteAsync(claim, currentAccount, trustedTime,
                    initial, first, ct).ConfigureAwait(false);
                completed = DeepIdV2InitialSessionCommit.Capture(capability, evidence, fingerprint,
                    claim.ExactReplayHash.Span, eventHash, intent, peer.Span);
                _ = completed.RequireInitialConversation(initial, first);
                RequireInitialSessionScope(completed);
                var pendingBody = completed.SerializePending();
                try { pending = DeviceInitialSessionCheckpoint.Pending(storeInstanceId.Span, accountId.Span, network,
                    stable, pendingBody); }
                finally { CryptographicOperations.ZeroMemory(pendingBody); }
                ct.ThrowIfCancellationRequested();
                if (!await storage.CompareExchangeAsync(DeviceInitialSessionCheckpoint.Slot, previous, pending, ct)
                        .ConfigureAwait(false))
                    throw new CryptographicException("Initial-session protected pending publication lost its exact predecessor.");
                DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.AfterInitialSessionPendingCheckpoint);
                // Pending is now authoritative; advisory cancellation cannot
                // abandon/recompute the completed claim. A stop is recovered.
                using var retained = DeviceInitialSessionCheckpoint.Decode(pending, storeInstanceId.Span, accountId.Span, network);
                InsertCompletedInitialSession(db, transaction, retained, completed);
                transaction.Commit();
                DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.AfterInitialSessionSqlCommit);
                await StabilizeInitialSessionCheckpointAsync(pending, retained, CancellationToken.None).ConfigureAwait(false);
                DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.AfterInitialSessionStableCheckpoint);
                var result = completed; completed = null; return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(previous);
                if (pending is not null) CryptographicOperations.ZeroMemory(pending);
            }
        }
        finally
        {
            completed?.Dispose(); CryptographicOperations.ZeroMemory(initial); CryptographicOperations.ZeroMemory(first);
            if (entered) gate.Release();
        }
    }

    internal async Task VerifyMessagingSourceUnderLeaseAsync(Did2MessagingSessionScope scope, bool requireRetired, CancellationToken ct)
    {
        using var operation = EnterOperation(); await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); await ReconcileInitialSessionsUnderGateAsync(ct).ConfigureAwait(false);
            var db = GetConnection(); using var tx = db.BeginTransaction(deferred: false);
            using var read = db.CreateCommand(); read.Transaction = tx;
            read.CommandText = "SELECT sequence,record_hash,payload FROM device_initial_sessions ORDER BY sequence;";
            using var rows = read.ExecuteReader(); var found = false;
            while (rows.Read())
            {
                var payload = rows.GetFieldValue<byte[]>(2);
                try
                {
                    using var source = DeepIdV2InitialSessionCommit.RestoreCustody(payload);
                    if (!Did2MessagingSessionScope.Fixed(source.SessionId.Span, scope.Session)) continue;
                    if (found) throw new CryptographicException("Mutable sender source is not unique.");
                    found = true; Did2MessagingSourceScope.RequireSender(scope, source);
                    var entry = initialRetirements!.Find(1, storeInstanceId.Span, checked((ulong)rows.GetInt64(0)));
                    // Reconcile already checked each source state and record hash
                    // against its independent retirement entry and full chain.
                    Did2MessagingSourceScope.RequireRetirement(entry, scope, requireRetired, live: entry is null || entry.Phase != 2);
                }
                finally { CryptographicOperations.ZeroMemory(payload); }
            }
            if (!found) throw new CryptographicException("Mutable sender source history is absent.");
        }
        finally { gate.Release(); }
    }

    internal async Task<Did2InitialKeyRetirementReceipt> RetireInitialKeysUnderLeaseAsync(Did2InitialStateTransfer transfer, CancellationToken ct)
    {
        using var operation = EnterOperation(); await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); await ReconcileInitialSessionsUnderGateAsync(ct).ConfigureAwait(false);
            var storage = RequireInitialSessionStorage(); var db = GetConnection();
            byte[] intent, hash; ulong ordinal;
            using (var read = db.CreateCommand())
            {
                read.CommandText = "SELECT logical_intent_id,sequence,record_hash FROM device_initial_sessions WHERE operation_id=$op;";
                read.Parameters.AddWithValue("$op", transfer.Operation.ToArray()); using var row = read.ExecuteReader();
                if (!row.Read()) throw new CryptographicException("Mutable transfer has no authenticated sender source.");
                intent = row.GetFieldValue<byte[]>(0); ordinal = checked((ulong)row.GetInt64(1)); hash = row.GetFieldValue<byte[]>(2);
            }
            bool live;
            using (var tx = db.BeginTransaction(deferred: false))
            using (var source = ReadInitialSessionByIntent(db, tx, intent) ?? throw new CryptographicException("Sender source disappeared."))
            { transfer.RequireSender(source); live = source.HasInitialState; }
            var preclaimHash = await SqliteDeepIdV2AccountGeneration.ReadPreclaimRetirementHashUnderLeaseAsync(storage, transfer, intent, ct).ConfigureAwait(false);
            var entry = await ProtectedInitialKeyRetirementJournal.StageUnderLeaseAsync(storage, transfer,
                storeInstanceId.ToArray(), ordinal, hash, intent, preclaimHash, ct).ConfigureAwait(false);
            // After pending publication the same deletion is recovered even if cancellation arrives.
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterPending);
            await SqliteDeepIdV2AccountGeneration.RetirePreclaimUnderLeaseAsync(storage, transfer, entry, CancellationToken.None).ConfigureAwait(false);
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterPreclaim);
            if (entry.Phase != 2)
            {
                using var tx = db.BeginTransaction(deferred: false);
                using var deletion = db.CreateCommand(); deletion.Transaction = tx;
                deletion.CommandText = "DELETE FROM device_initial_state WHERE sequence=$sequence;";
                deletion.Parameters.AddWithValue("$sequence", checked((long)ordinal));
                if (deletion.ExecuteNonQuery() != (live ? 1 : 0)) throw new CryptographicException("Sender deletion affected a different initial state.");
                tx.Commit();
            }
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterSourceDelete);
            // Independently re-open the authenticated chain with pending deletion permission.
            await ReconcileInitialSessionsUnderGateAsync(CancellationToken.None).ConfigureAwait(false);
            using (var tx = db.BeginTransaction(deferred: false))
            using (var source = ReadInitialSessionByIntent(db, tx, intent) ?? throw new CryptographicException("Sender metadata disappeared."))
                if (source.HasInitialState) throw new CryptographicException("Sender initial keys survived retirement.");
            await ProtectedInitialKeyRetirementJournal.CompleteUnderLeaseAsync(storage, transfer, entry, CancellationToken.None).ConfigureAwait(false);
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterStable);
            return await Did2InitialKeyRetirementReceipt.VerifyStableAsync(transfer, storage, entry, CancellationToken.None).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    private async ValueTask ReconcileInitialSessionsUnderGateAsync(CancellationToken ct)
    {
        if (initialSessionStorage is null) return; // Non-DID2 generic store has no such owner.
        var storage = RequireInitialSessionStorage(); var network = initialSessionNetwork!;
        initialRetirements = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, network, accountId.ToArray(), ct).ConfigureAwait(false);
        using var owner = await storage.ReadOwnedAsync(DeviceInitialSessionCheckpoint.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("The protected initial-session checkpoint is absent; explicit reset is required.");
        var exact = owner.Use(static bytes => bytes.ToArray());
        try
        {
            using var checkpoint = DeviceInitialSessionCheckpoint.Decode(exact, storeInstanceId.Span, accountId.Span, network);
            var db = GetConnection(); using var transaction = db.BeginTransaction(deferred: false);
            var tip = ReadInitialSessionTip(db, transaction);
            if (checkpoint.Phase == 1)
            {
                if (tip.Sequence != checkpoint.Sequence || !DeviceInitialSessionCheckpoint.Fixed(tip.Hash, checkpoint.Hash))
                    throw new CryptographicException("The stable initial-session history is missing, rolled back or substituted.");
                return;
            }
            using var completed = DeepIdV2InitialSessionCommit.RestorePending(checkpoint.Payload);
            RequireInitialSessionScope(completed);
            if (tip.Sequence + 1 == checkpoint.Sequence && DeviceInitialSessionCheckpoint.Fixed(tip.Hash, checkpoint.Previous))
            {
                if (ReadOperation(db, transaction, DeviceOperationId32.FromBytes(completed.ClaimOperationId.Span)) is not null)
                    throw new CryptographicException("The protected pending agreement has a different durable burn.");
                var protectedDirectory = ReadProtectedDmd1(db, transaction);
                if (protectedDirectory is null || !protectedDirectory.ExactEquals(completed.Directory))
                    throw new CryptographicException("Pending recovery cannot overwrite a different current device directory.");
                InsertCompletedInitialSession(db, transaction, checkpoint, completed);
                transaction.Commit();
            }
            else if (tip.Sequence != checkpoint.Sequence || !DeviceInitialSessionCheckpoint.Fixed(tip.Hash, checkpoint.Hash))
                throw new CryptographicException("The initial-session pending checkpoint has no exact SQL predecessor/result.");
            else transaction.Commit();
            await StabilizeInitialSessionCheckpointAsync(exact, checkpoint, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    private InitialSessionTip ReadInitialSessionTip(SqliteConnection db, SqliteTransaction transaction)
    {
        using (var integrity = db.CreateCommand())
        {
            integrity.Transaction = transaction; integrity.CommandText = "PRAGMA foreign_key_check;";
            using var rows = integrity.ExecuteReader();
            if (rows.Read()) throw new CryptographicException("Initial-state history contains an orphaned source row.");
        }
        using var command = db.CreateCommand(); command.Transaction = transaction;
        command.CommandText = """
            SELECT s.sequence,s.predecessor_hash,s.record_hash,length(s.payload),s.payload,s.operation_id,s.logical_intent_id,
                o.fingerprint,a.fingerprint,a.directory_generation,a.directory_hash,a.account_id,a.account_generation,
                a.device_id,a.device_generation,a.dpd1_hash,a.purpose,a.operation_binding,a.peer_public_key,
                length(k.exact_state),k.exact_state
            FROM device_initial_sessions AS s
            LEFT JOIN device_operation_dedup AS o ON o.operation_id=s.operation_id
            LEFT JOIN device_agreement_authorizations AS a ON a.operation_id=s.operation_id
            LEFT JOIN device_initial_state AS k ON k.sequence=s.sequence ORDER BY s.sequence;
            """;
        using var reader = command.ExecuteReader(); ulong ordinal = 0; byte[] tip = new byte[32];
        while (reader.Read())
        {
            if (++ordinal > DeviceInitialSessionCheckpoint.MaximumSessions || reader.GetInt64(0) != checked((long)ordinal) ||
                reader.GetInt64(3) is < DeepIdV2InitialSessionCommit.HeaderBytes or > DeepIdV2InitialSessionCommit.MaximumPayloadBytes)
                throw new InvalidDataException("The initial-session SQL history has an invalid cardinality or row size.");
            var previous = reader.GetFieldValue<byte[]>(1); var hash = reader.GetFieldValue<byte[]>(2);
            var payload = reader.GetFieldValue<byte[]>(4);
            var state = ReadInitialState(reader, 19, 20);
            try
            {
                if (!DeviceInitialSessionCheckpoint.Fixed(previous, tip) ||
                    !DeviceInitialSessionCheckpoint.Fixed(hash, DeviceInitialSessionCheckpoint.RecordHash(
                        storeInstanceId.Span, accountId.Span, initialSessionNetwork!, ordinal, previous, payload)))
                    throw new CryptographicException("The initial-session SQL history chain differs.");
                using var record = DeepIdV2InitialSessionCommit.RestoreCustody(payload, state); RequireInitialSessionScope(record);
                RequireRetirementBinding(ordinal, hash, record);
                if (!DeviceInitialSessionCheckpoint.Fixed(record.ClaimOperationId.Span, reader.GetFieldValue<byte[]>(5)) ||
                    !DeviceInitialSessionCheckpoint.Fixed(record.IntentSpan, reader.GetFieldValue<byte[]>(6)))
                    throw new CryptographicException("The initial-session SQL row identity differs from its authenticated payload.");
                if (reader.IsDBNull(7) || reader.IsDBNull(8) || reader.GetString(7) != record.Fingerprint ||
                    reader.GetString(8) != record.Fingerprint ||
                    ReadU64(reader.GetFieldValue<byte[]>(9)) != record.Directory.DirectoryGeneration ||
                    !DeviceInitialSessionCheckpoint.Fixed(reader.GetFieldValue<byte[]>(10), record.Directory.DirectoryHash.Span) ||
                    !DeviceInitialSessionCheckpoint.Fixed(reader.GetFieldValue<byte[]>(11), record.Directory.AccountId.Span) ||
                    ReadU64(reader.GetFieldValue<byte[]>(12)) != record.Directory.AccountGeneration ||
                    !DeviceInitialSessionCheckpoint.Fixed(reader.GetFieldValue<byte[]>(13), record.Device.DeviceId.Span) ||
                    ReadU64(reader.GetFieldValue<byte[]>(14)) != record.Device.DeviceGeneration ||
                    !DeviceInitialSessionCheckpoint.Fixed(reader.GetFieldValue<byte[]>(15), record.Device.ExactDpd1Hash.Span) ||
                    reader.GetInt32(16) != (int)LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1 ||
                    !DeviceInitialSessionCheckpoint.Fixed(reader.GetFieldValue<byte[]>(17), record.ClaimOperationId.Span) ||
                    !DeviceInitialSessionCheckpoint.Fixed(reader.GetFieldValue<byte[]>(18), record.AgreementPeerSpan))
                    throw new CryptographicException("The initial-session history differs from its exact durable agreement burn.");
                tip = hash;
            }
            finally { CryptographicOperations.ZeroMemory(payload); CryptographicOperations.ZeroMemory(state); }
        }
        initialRetirements!.RequireSourceTip(1, storeInstanceId.Span, ordinal);
        return new(ordinal, tip);
    }

    private DeepIdV2InitialSessionCommit? ReadInitialSessionByIntent(SqliteConnection db,
        SqliteTransaction transaction, byte[] intent)
    {
        using var read = db.CreateCommand(); read.Transaction = transaction;
        read.CommandText = "SELECT length(s.payload),s.payload,length(k.exact_state),k.exact_state,s.sequence,s.record_hash FROM device_initial_sessions s LEFT JOIN device_initial_state k ON k.sequence=s.sequence WHERE logical_intent_id=$intent;";
        read.Parameters.AddWithValue("$intent", intent); using var reader = read.ExecuteReader();
        if (!reader.Read()) return null;
        if (reader.GetInt64(0) is < DeepIdV2InitialSessionCommit.HeaderBytes or > DeepIdV2InitialSessionCommit.MaximumPayloadBytes)
            throw new InvalidDataException("The retained initial-session payload is oversized.");
        var payload = reader.GetFieldValue<byte[]>(1);
        var state = ReadInitialState(reader, 2, 3);
        DeepIdV2InitialSessionCommit? result = null;
        try
        {
            result = DeepIdV2InitialSessionCommit.RestoreCustody(payload, state);
            RequireRetirementBinding(checked((ulong)reader.GetInt64(4)), reader.GetFieldValue<byte[]>(5), result);
            var retained = result; result = null; return retained;
        }
        finally { result?.Dispose(); CryptographicOperations.ZeroMemory(payload); CryptographicOperations.ZeroMemory(state); }
    }

    private void InsertCompletedInitialSession(SqliteConnection db, SqliteTransaction transaction,
        DeviceInitialSessionCheckpoint.State checkpoint, DeepIdV2InitialSessionCommit completed)
    {
        RequireInitialSessionScope(completed);
        var operation = DeviceOperationId32.FromBytes(completed.ClaimOperationId.Span);
        InsertOperation(db, transaction, operation, completed.Fingerprint);
        InsertAgreementAuthorization(db, transaction, operation, completed.Fingerprint, completed.Directory,
            completed.Device, LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1, operation.Span, completed.AgreementPeerSpan);
        var owned = completed.CanonicalSpan.ToArray();
        var state = completed.ExactTrsSpan.ToArray();
        try
        {
            Insert(db, transaction, "INSERT INTO device_initial_sessions VALUES($operation,$intent,$sequence,$previous,$hash,$payload);",
                ("$operation", operation.ToArray()), ("$intent", completed.IntentSpan.ToArray()),
                ("$sequence", checked((long)checkpoint.Sequence)), ("$previous", checkpoint.Previous),
                ("$hash", checkpoint.Hash), ("$payload", owned));
            Insert(db, transaction, "INSERT INTO device_initial_state VALUES($sequence,$state);",
                ("$sequence", checked((long)checkpoint.Sequence)), ("$state", state));
        }
        finally { CryptographicOperations.ZeroMemory(owned); CryptographicOperations.ZeroMemory(state); }
    }

    private async ValueTask StabilizeInitialSessionCheckpointAsync(byte[] exactPending,
        DeviceInitialSessionCheckpoint.State pending, CancellationToken ct)
    {
        var stable = DeviceInitialSessionCheckpoint.Stable(storeInstanceId.Span, accountId.Span,
            initialSessionNetwork!, pending.Sequence, pending.Hash);
        if (!await RequireInitialSessionStorage().CompareExchangeAsync(DeviceInitialSessionCheckpoint.Slot,
                exactPending, stable, ct).ConfigureAwait(false))
            throw new CryptographicException("Initial-session stabilization lost its exact protected pending record.");
    }
    private static byte[] ReadInitialState(SqliteDataReader reader, int lengthColumn, int stateColumn)
    {
        if (reader.IsDBNull(lengthColumn)) return [];
        if (reader.GetInt64(lengthColumn) is < 1 or > DeepIdV2InitialSessionCommit.MaximumInitialTrsBytes)
            throw new InvalidDataException("Retained initial state exceeds its closed bound.");
        return reader.GetFieldValue<byte[]>(stateColumn);
    }
    private void RequireRetirementBinding(ulong ordinal, byte[] hash, DeepIdV2InitialSessionCommit record) =>
        (initialRetirements ?? throw new InvalidOperationException("Protected retirements were not verified.")).RequireSource(
            1, storeInstanceId.Span, ordinal, hash, record.CanonicalSpan, record.InitialStateHashSpan, record.IntentSpan, record.HasInitialState);

    private IDeepSecureStorage RequireInitialSessionStorage() => initialSessionStorage ??
        throw new InvalidOperationException("DID2 initial-session custody is not configured for this device store.");
    private void RequireInitialSessionScope(DeepIdV2InitialSessionCommit completed)
    {
        if (completed.Directory.AccountGeneration != accountGeneration ||
            !DeviceInitialSessionCheckpoint.Fixed(completed.Record.NetworkId.Span, initialSessionNetwork!) ||
            !DeviceInitialSessionCheckpoint.Fixed(completed.Record.InitiatorAccountId.Span, accountId.Span))
            throw new CryptographicException("The completed initial session belongs to another protected device/account store.");
    }
}
