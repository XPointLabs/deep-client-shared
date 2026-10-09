using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Dedicated DR-0027 SQL backend. Its caller owns the SQLCipher key,
/// connection and account lease, and must bracket Append with protected
/// pending/verified-SQL/cleanup/stable. No Protocol receipt, source retirement,
/// public messaging activation, materialization or ACK is granted here.</summary>
internal sealed partial class Did2MessagingSqlJournal(SqliteConnection connection, Did2MessagingSessionScope scope,
    Did2MessagingHistoryCheckpoint history)
{
    private readonly Did2MessagingHistoryCheckpoint historyRoot = history ?? throw new ArgumentNullException(nameof(history));
    internal const int ApplicationId = 0x444d5332, SchemaVersion = 3, MaximumEntries = 4096;
    private readonly SqliteConnection connection = connection ?? throw new ArgumentNullException(nameof(connection));
    private readonly Did2MessagingSessionScope scope = scope ?? throw new ArgumentNullException(nameof(scope));
    internal void RequireScope(Did2MessagingSessionScope expected)
    {
        if (!Fixed(scope.Exact, expected.Exact)) throw new CryptographicException("DID2 SQL scope differs from its owner.");
    }
    private static readonly (string Name, string Sql)[] Schema =
    [
        ("scope", "CREATE TABLE scope (singleton INTEGER PRIMARY KEY CHECK(singleton=1), exact_scope BLOB NOT NULL CHECK(length(exact_scope)=404));"),
        ("journal", "CREATE TABLE journal (ordinal INTEGER PRIMARY KEY CHECK(ordinal BETWEEN 1 AND 9223372036854775807), predecessor BLOB NOT NULL CHECK(length(predecessor)=32), head BLOB NOT NULL CHECK(length(head)=32), metadata BLOB NOT NULL CHECK(length(metadata)=608));"),
        ("ratchet", "CREATE TABLE ratchet (singleton INTEGER PRIMARY KEY CHECK(singleton=1), exact_state BLOB NOT NULL CHECK(length(exact_state) BETWEEN 1 AND 2097152));"),
        ("initial_events", "CREATE TABLE initial_events (singleton INTEGER PRIMARY KEY CHECK(singleton=1), envelope BLOB NOT NULL CHECK(length(envelope) BETWEEN 1 AND 65536), session_init BLOB NOT NULL CHECK(length(session_init) BETWEEN 1 AND 32768), hello BLOB NOT NULL CHECK(length(hello) BETWEEN 1 AND 32768), metadata BLOB NOT NULL CHECK(length(metadata)=608));"),
        ("events", "CREATE TABLE events (operation BLOB PRIMARY KEY CHECK(length(operation)=32), ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal BETWEEN 1 AND 9223372036854775807), direction INTEGER NOT NULL CHECK(direction IN (1,2)), envelope BLOB NOT NULL CHECK(length(envelope) BETWEEN 1 AND 65536), plaintext BLOB, metadata BLOB NOT NULL CHECK(length(metadata)=608), CHECK((direction=1 AND plaintext IS NULL) OR (direction=2 AND plaintext IS NOT NULL AND length(plaintext) BETWEEN 1 AND 33082)));"),
    ];

    internal void CreateRegisteredEmpty(Did2MessagingFloor registeredEmpty)
    {
        _ = Did2MessagingFloor.Decode(registeredEmpty.Exact.Span, scope);
        if (registeredEmpty.Phase != 1 || registeredEmpty.Ordinal != 0)
            throw new InvalidDataException("DID2 messaging SQL creation requires its registered empty floor.");
        RequireEmptyHistory();
        RequireCipherPolicy();
        using (var existing = connection.CreateCommand())
        {
            existing.CommandText = "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%';";
            if (Convert.ToInt64(existing.ExecuteScalar()) != 0) throw new InvalidDataException("DID2 messaging SQL is not empty; no migration is permitted.");
        }
        using var tx = connection.BeginTransaction();
        foreach (var (_, sql) in Schema) Execute(sql, tx);
        Execute($"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaVersion};", tx);
        using (var insert = Command("INSERT INTO scope VALUES(1,$scope);", tx))
        { insert.Parameters.AddWithValue("$scope", scope.Exact.ToArray()); insert.ExecuteNonQuery(); }
        tx.Commit();
        RequireSame(registeredEmpty, VerifyTip());
    }

    internal void InitializeOrVerifyRegisteredEmpty(Did2MessagingFloor registeredEmpty)
    {
        RequireSame(Did2MessagingFloor.Empty(scope), registeredEmpty);
        RequireEmptyHistory();
        RequireCipherPolicy();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%';";
        if (Convert.ToInt64(command.ExecuteScalar()) == 0 &&
            PragmaInteger("application_id") == 0 && PragmaInteger("user_version") == 0)
            CreateRegisteredEmpty(registeredEmpty);
        else RequireSame(registeredEmpty, VerifyTip());
    }

    internal Did2MessagingFloor VerifyTip()
    {
        RequireCipherPolicy(); ValidateSchema();
        VerifyHistoryPrefix();
        var headers = ReadJournal(out var tip);
        VerifyRows(headers, tip);
        return tip;
    }

    internal byte[] VerifyInitialImport(Did2MessagingFloor protectedStable)
    {
        RequireSame(protectedStable, VerifyTip());
        if (protectedStable.Phase != 1 || protectedStable.Status != 0 || protectedStable.Ordinal != 1 || protectedStable.RatchetGeneration != 1)
            throw new InvalidDataException("Mutable source transfer is not the unactivated first import.");
        var headers = ReadJournal(out _);
        if (headers.Count != 1 || headers[0][5] != 1) throw new CryptographicException("Mutable first import metadata differs.");
        return headers[0];
    }

    internal (byte[] SessionInit, byte[] Hello) ReadVerifiedActiveInitialEvents(Did2MessagingFloor protectedStable)
    {
        _ = Did2MessagingFloor.Decode(protectedStable.Exact.Span, scope);
        if (protectedStable.Phase != 1 || protectedStable.Status != 1)
            throw new InvalidDataException("Initial inbox handoff requires the retired active messaging floor.");
        RequireSame(protectedStable, VerifyTip());
        using var command = Command("SELECT length(session_init),session_init,length(hello),hello FROM initial_events WHERE singleton=1;");
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

    internal void Append(OwnedDid2MessagingMutation mutation)
    {
        ArgumentNullException.ThrowIfNull(mutation);
        if (!Fixed(scope.Exact, mutation.Scope.Exact) || mutation.Successor.Ordinal > long.MaxValue)
            throw new InvalidDataException("DID2 messaging mutation scope/capacity differs.");
        RequireCipherPolicy(); ValidateSchema();
        using var tx = connection.BeginTransaction();
        VerifyHistoryPrefix(tx);
        var priorHeaders = ReadJournal(out var prior, tx); VerifyRows(priorHeaders, prior, tx);
        if (priorHeaders.Count >= MaximumEntries)
            throw new InvalidOperationException("DID2 messaging working journal requires owned prefix checkpointing.");
        RequireSame(prior, mutation.Predecessor);
        using var blobs = new OwnedBindings();
        using (var journal = Command("INSERT INTO journal VALUES($ordinal,$previous,$head,$header);", tx))
        {
            journal.Parameters.AddWithValue("$ordinal", checked((long)mutation.Successor.Ordinal));
            blobs.Add(journal, "$previous", prior.Head); blobs.Add(journal, "$head", mutation.Successor.Head); blobs.Add(journal, "$header", mutation.Header);
            journal.ExecuteNonQuery();
        }
        if (mutation.Kind is 1 or 2)
        {
            Execute("DELETE FROM ratchet;", tx);
            using var state = Command("INSERT INTO ratchet VALUES(1,$state);", tx);
            blobs.Add(state, "$state", mutation.NextTrs); state.ExecuteNonQuery();
        }
        else if (mutation.Kind == 4) Execute("DELETE FROM ratchet;", tx);
        if (mutation.Kind == 1)
        {
            using var initial = Command("INSERT INTO initial_events VALUES(1,$envelope,$init,$hello,$metadata);", tx);
            blobs.Add(initial, "$envelope", mutation.Envelope); blobs.Add(initial, "$init", mutation.SessionInit); blobs.Add(initial, "$hello", mutation.ContactHello);
            blobs.Add(initial, "$metadata", mutation.Header);
            initial.ExecuteNonQuery();
        }
        else if (mutation.Kind == 2)
        {
            using var message = Command("INSERT INTO events VALUES($operation,$ordinal,$direction,$envelope,$plain,$metadata);", tx);
            blobs.Add(message, "$operation", mutation.Operation); message.Parameters.AddWithValue("$ordinal", checked((long)mutation.Successor.Ordinal));
            message.Parameters.AddWithValue("$direction", (int)mutation.Direction); blobs.Add(message, "$envelope", mutation.Envelope);
            if (mutation.Direction == 2) blobs.Add(message, "$plain", mutation.AuthenticatedDmc2);
            else message.Parameters.AddWithValue("$plain", DBNull.Value);
            blobs.Add(message, "$metadata", mutation.Header);
            message.ExecuteNonQuery();
        }
        var nextHeaders = ReadJournal(out var next, tx); VerifyRows(nextHeaders, next, tx);
        RequireSame(next, mutation.Successor.Cleanup(scope).Stable(scope));
        tx.Commit();
    }

    /// <summary>Reads only the current TRS, after SQL and an independently
    /// protected stable floor agree. A caller still needs current endpoint and
    /// retirement authority before preparing an ordinary operation.</summary>
    internal OwnedDeepSecret ReadVerifiedLatest(Did2MessagingFloor protectedStable)
    {
        _ = Did2MessagingFloor.Decode(protectedStable.Exact.Span, scope);
        if (protectedStable.Phase != 1 || protectedStable.Ordinal == 0 || protectedStable.Status == 2)
            throw new InvalidDataException("DID2 messaging floor has no releasable current ratchet.");
        RequireSame(protectedStable, VerifyTip());
        using var command = Command("SELECT exact_state FROM ratchet WHERE singleton=1;");
        var bytes = (byte[])(command.ExecuteScalar() ?? throw new InvalidDataException("DID2 live ratchet is absent."));
        try { return new(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    // Includes retained prefix history, not just the working journal. Fixed
    // memory enumeration; the held owner authenticates the tip before reading.
    internal IEnumerable<byte[]> ReadVerifiedOutgoingOperations(Did2MessagingFloor protectedStable, CancellationToken ct)
    {
        _ = Did2MessagingFloor.Decode(protectedStable.Exact.Span, scope);
        if (protectedStable.Phase != 1 || protectedStable.Status != 1)
            throw new InvalidDataException("Outgoing history requires an active stable messaging floor.");
        RequireSame(protectedStable, VerifyTip());
        using var command = Command("SELECT operation,typeof(operation),length(operation) FROM events WHERE direction=1 ORDER BY ordinal;");
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            ct.ThrowIfCancellationRequested();
            if (reader.GetString(1) != "blob" || reader.GetInt64(2) != 32)
                throw new InvalidDataException("An outgoing history selector has an invalid shape.");
            yield return reader.GetFieldValue<byte[]>(0);
        }
    }

    internal OwnedDid2MessagingPersistedEvent? ReadVerifiedOperation(Did2MessagingFloor protectedStable, ReadOnlySpan<byte> operation)
    {
        if (operation.Length != 32 || Did2MessagingSessionScope.Zero(operation)) throw new ArgumentException("An exact nonzero operation is required.");
        _ = Did2MessagingFloor.Decode(protectedStable.Exact.Span, scope);
        if (protectedStable.Phase != 1 || protectedStable.Status != 1)
            throw new InvalidDataException("Operation read-back requires an active stable messaging floor.");
        RequireSame(protectedStable, VerifyTip());
        using var command = Command("SELECT direction,length(envelope),envelope,length(plaintext),plaintext,metadata FROM events WHERE operation=$op;");
        command.Parameters.AddWithValue("$op", operation.ToArray()); using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        var direction = row.GetInt32(0);
        if (direction is not (1 or 2) || row.GetInt64(1) is < 1 or > 65536 ||
            direction == 1 && !row.IsDBNull(3) || direction == 2 && (row.IsDBNull(3) || row.GetInt64(3) is < 1 or > 33082))
            throw new InvalidDataException("Retained messaging operation has an invalid bounded shape.");
        var envelope = row.GetFieldValue<byte[]>(2); byte[] plaintext = []; OwnedDid2MessagingPersistedEvent? result = null;
        try
        {
            if (direction == 2) plaintext = row.GetFieldValue<byte[]>(4);
            var metadata = row.GetFieldValue<byte[]>(5);
            result = new(direction, envelope, plaintext, metadata.AsSpan(300, 32));
            envelope = []; plaintext = [];
            if (row.Read()) throw new InvalidDataException("Retained messaging operation is not unique.");
            var value = result; result = null; return value;
        }
        finally { result?.Dispose(); CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal OwnedDid2MessagingPersistedEvent? ReadVerifiedReceiveForEvent(Did2MessagingFloor protectedStable, ReadOnlySpan<byte> eventHash)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(eventHash);
        RequireSame(protectedStable, VerifyTip());
        using var command = Command("SELECT operation FROM events WHERE direction=2 AND substr(metadata,301,32)=$hash ORDER BY ordinal LIMIT 1;");
        command.Parameters.AddWithValue("$hash", eventHash.ToArray());
        var operation = command.ExecuteScalar() as byte[];
        if (operation is null) return null;
        try { return ReadVerifiedOperation(protectedStable, operation); }
        finally { CryptographicOperations.ZeroMemory(operation); }
    }

    // Store-derived snapshot only: neither an arbitrary retention hash nor a
    // caller replay flag can select Protocol's replay path.
    internal ExactDpe2DurableTransitionContext CreateVerifiedTransitionContext(
        Did2MessagingFloor protectedStable, ReadOnlySpan<byte> operation, ReadOnlySpan<byte> receivedEnvelope)
    {
        using var retained = ReadVerifiedOperation(protectedStable, operation);
        var replay = ExactDpe2ReceiveReplayDisposition.Fresh;
        if (retained is not null)
        {
            if (receivedEnvelope.IsEmpty || retained.Direction != 2 ||
                !Fixed(retained.ExactEnvelope, receivedEnvelope))
                throw new CryptographicException("DID2 retained operation does not authorize this exact receive replay.");
            replay = ExactDpe2ReceiveReplayDisposition.ExactReplay;
        }
        var headers = ReadJournal(out var tip);
        if (replay == ExactDpe2ReceiveReplayDisposition.Fresh && headers.Count >= MaximumEntries - 1)
            throw new InvalidOperationException("DID2 ordinary messaging requires verified journal checkpointing.");
        RequireSame(protectedStable, tip); VerifyRows(headers, tip);
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("Deep/STORE-V2/messaging-replay-retention"u8); digest.AppendData([0]);
        Span<byte> number = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(number, 1);
        digest.AppendData(number); digest.AppendData(scope.Hash); digest.AppendData(protectedStable.Exact.Span);
        digest.AppendData(historyRoot.Exact.Span);
        BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)headers.Count(h => h[5] == 2)));
        digest.AppendData(number);
        for (var index = 0; index < headers.Count; index++)
        {
            if (headers[index][5] != 2) continue;
            BinaryPrimitives.WriteUInt64BigEndian(number, checked(historyRoot.Basis.Ordinal + (ulong)index + 1));
            digest.AppendData(number); digest.AppendData(headers[index]);
        }
        return new(protectedStable.RatchetGeneration, protectedStable.RatchetCommitment,
            protectedStable.RatchetGeneration, protectedStable.RatchetCommitment,
            protectedStable.Ordinal, protectedStable.Head, digest.GetHashAndReset(), replay);
    }

    private List<byte[]> ReadJournal(out Did2MessagingFloor tip, SqliteTransaction? tx = null)
    {
        _ = Did2MessagingHistoryCheckpoint.Decode(historyRoot.Exact.Span, scope);
        tip = historyRoot.Basis; var result = new List<byte[]>();
        using var command = Command("SELECT ordinal,predecessor,head,metadata FROM journal ORDER BY ordinal;", tx);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var ordinal = reader.GetInt64(0); var previous = reader.GetFieldValue<byte[]>(1); var head = reader.GetFieldValue<byte[]>(2); var header = reader.GetFieldValue<byte[]>(3);
            if (result.Count >= MaximumEntries || ordinal != checked((long)tip.Ordinal + 1) || !Fixed(previous, tip.Head))
                throw new CryptographicException("DID2 SQL journal ordinal/predecessor differs.");
            var next = Did2MessagingFloor.FromJournalMetadata(scope, tip, header);
            if (!Fixed(head, next.Head)) throw new CryptographicException("DID2 SQL journal head differs.");
            result.Add(header); tip = next;
        }
        return result;
    }

    private void VerifyRows(List<byte[]> headers, Did2MessagingFloor tip, SqliteTransaction? tx = null)
    {
        using (var identity = Command("SELECT singleton,exact_scope FROM scope;", tx))
        using (var reader = identity.ExecuteReader())
        {
            if (!reader.Read() || reader.GetInt64(0) != 1 || !Fixed(reader.GetFieldValue<byte[]>(1), scope.Exact) || reader.Read())
                throw new CryptographicException("DID2 SQL identity scope differs.");
        }
        using (var latest = Command("SELECT singleton,exact_state FROM ratchet;", tx))
        using (var reader = latest.ExecuteReader())
        {
            if (tip.Ordinal == 0 || tip.Status == 2)
            { if (reader.Read()) throw new CryptographicException("DID2 empty/latched SQL retains live ratchet keys."); }
            else
            {
                if (!reader.Read() || reader.GetInt64(0) != 1) throw new InvalidDataException("DID2 SQL live ratchet is absent.");
                var bytes = reader.GetFieldValue<byte[]>(1);
                try
                {
                    var facts = MessagingCryptoV1Trs1.ValidateDeviceBinding(bytes, scope.Session, scope.LocalDevice, scope.LocalDeviceGeneration);
                    MessagingCryptoV1Trs1.RequireResponderContactBinding(bytes, scope.RemoteDevice, scope.RemoteDeviceGeneration);
                    MessagingCryptoV1Trs1.RequireLocalDirectoryBinding(bytes, scope.LocalDirectory); MessagingCryptoV1Trs1.RequireRemoteDirectoryBinding(bytes, scope.RemoteDirectory);
                    if (facts.Generation != tip.RatchetGeneration || !Fixed(facts.StateCommitment, tip.RatchetCommitment) || !Fixed(facts.ExactHash, tip.RatchetHash))
                        throw new CryptographicException("DID2 SQL latest ratchet differs from its journal tip.");
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
                if (reader.Read()) throw new InvalidDataException("DID2 SQL has duplicate current ratchets.");
            }
        }
        VerifyInitial(headers, tx);
        var count = 0;
        using var events = Command("SELECT operation,ordinal,direction,envelope,plaintext,metadata,length(envelope),length(plaintext),length(metadata) FROM events WHERE ordinal>$basis ORDER BY ordinal;", tx);
        events.Parameters.AddWithValue("$basis", checked((long)historyRoot.Basis.Ordinal));
        using var eventReader = events.ExecuteReader();
        while (eventReader.Read())
        {
            count++; var ordinal = eventReader.GetInt64(1); var direction = eventReader.GetInt32(2);
            if (ordinal <= checked((long)historyRoot.Basis.Ordinal) || (ulong)ordinal - historyRoot.Basis.Ordinal > (ulong)headers.Count ||
                eventReader.GetInt64(6) is < 1 or > 65536 || eventReader.GetInt64(8) != Did2MessagingFloor.MetadataBytes ||
                direction == 1 && !eventReader.IsDBNull(7) || direction == 2 && (eventReader.IsDBNull(7) || eventReader.GetInt64(7) is < 1 or > 33082))
                throw new InvalidDataException("DID2 SQL event journal reference/size differs.");
            var header = headers[checked((int)((ulong)ordinal - historyRoot.Basis.Ordinal - 1))];
            if (!Fixed(eventReader.GetFieldValue<byte[]>(5), header))
                throw new CryptographicException("DID2 SQL event metadata differs from its current journal.");
            var envelopeBytes = eventReader.GetFieldValue<byte[]>(3);
            var envelope = Dpe2Codec.Decode(envelopeBytes);
            if (header[5] != 2 || direction != header[6] || !Fixed(eventReader.GetFieldValue<byte[]>(0), header.AsSpan(268, 32)) ||
                !Fixed(envelope.OperationId.Span, header.AsSpan(268, 32)) || !Fixed(envelope.NetworkId.Span, scope.Network) ||
                !Fixed(envelope.SessionId.Span, scope.Session) || !Fixed(envelope.SenderDeviceId.Span, direction == 1 ? scope.LocalDevice : scope.RemoteDevice) ||
                !Fixed(envelope.RecipientDeviceId.Span, direction == 1 ? scope.RemoteDevice : scope.LocalDevice) ||
                !Fixed(MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(envelope), header.AsSpan(332, 32)) ||
                !Fixed(MessagingWireCryptographicInputs.ComputeDtr2HeaderHash(envelope.RatchetHeader), header.AsSpan(364, 32)))
                throw new CryptographicException("DID2 SQL event envelope differs from its exact journal.");
            if (direction == 1)
            { if (!eventReader.IsDBNull(4)) throw new InvalidDataException("DID2 SQL send retains unexpected plaintext."); }
            else
            {
                if (eventReader.IsDBNull(4)) throw new InvalidDataException("DID2 SQL receive lost its authenticated event.");
                var plaintext = eventReader.GetFieldValue<byte[]>(4);
                try
                {
                    var parsed = ApplicationCoreCodec.DecodeDmc2(plaintext);
                    if (!Fixed(SHA256.HashData(plaintext), header.AsSpan(300, 32)) || !Fixed(parsed.NetworkId.Span, scope.Network) ||
                        !Fixed(parsed.SenderAccountId.Span, scope.RemoteAccount) || !Fixed(parsed.SenderDeviceId.Span, scope.RemoteDevice))
                        throw new CryptographicException("DID2 SQL authenticated receive scope differs.");
                }
                finally { CryptographicOperations.ZeroMemory(plaintext); }
            }
        }
        if (count != headers.Count(static header => header[5] == 2)) throw new InvalidDataException("DID2 SQL lost a journal-bound event.");
    }
    private void VerifyInitial(List<byte[]> headers, SqliteTransaction? tx)
    {
        using var command = Command("SELECT singleton,envelope,session_init,hello,metadata,length(envelope),length(session_init),length(hello),length(metadata) FROM initial_events;", tx);
        using var reader = command.ExecuteReader();
        if (headers.Count == 0 && historyRoot.Basis.Ordinal == 0)
        { if (reader.Read()) throw new InvalidDataException("DID2 empty SQL retains initial events."); return; }
        if (!reader.Read() || reader.GetInt64(0) != 1 || reader.GetInt64(5) is < 1 or > 65536 ||
            reader.GetInt64(6) is < 1 or > 32768 || reader.GetInt64(7) is < 1 or > 32768 || reader.GetInt64(8) != Did2MessagingFloor.MetadataBytes)
            throw new InvalidDataException("DID2 SQL initial events are absent.");
        var header = reader.GetFieldValue<byte[]>(4);
        OwnedDid2MessagingMutation.ValidateMetadataTransition(header, scope, Did2MessagingFloor.Empty(scope));
        if (header[5] != 1 || (historyRoot.Basis.Ordinal == 0 ? !Fixed(header, headers[0]) :
            !Fixed(SHA256.HashData(header), historyRoot.InitialHeaderHash)))
            throw new CryptographicException("DID2 initial metadata differs from the protected journal/history basis.");
        var envelopeBytes = reader.GetFieldValue<byte[]>(1); var initBytes = reader.GetFieldValue<byte[]>(2); var helloBytes = reader.GetFieldValue<byte[]>(3);
        try
        {
            var envelope = Dph2Codec.Decode(envelopeBytes); var init = ApplicationCoreCodec.DecodeDmc2(initBytes); var hello = ApplicationCoreCodec.DecodeDmc2(helloBytes);
            if (!Fixed(SHA256.HashData(envelopeBytes), header.AsSpan(332, 32)) || !Fixed(DeviceInitialSessionCheckpoint.EventHash(initBytes, helloBytes), header.AsSpan(300, 32)) ||
                !Fixed(envelope.SessionId.Span, scope.Session) || !Fixed(envelope.NetworkId.Span, scope.Network) ||
                !Fixed(envelope.ClaimOperationId.Span, header.AsSpan(268, 32)) ||
                !Fixed(init.ConversationId.Span, scope.Conversation) || !Fixed(hello.ConversationId.Span, scope.Conversation) ||
                init.ParsedPayload is not SessionInitDmc2Payload || hello.ParsedPayload is not ContactHelloDmc2Payload contact ||
                !Fixed(contact.RelationshipId.Span, scope.Relationship))
                throw new CryptographicException("DID2 SQL initial events differ from authenticated import.");
        }
        finally { CryptographicOperations.ZeroMemory(initBytes); CryptographicOperations.ZeroMemory(helloBytes); }
        if (reader.Read()) throw new InvalidDataException("DID2 SQL has duplicate initial events.");
    }
    private void ValidateSchema()
    {
        if (PragmaInteger("application_id") != ApplicationId || PragmaInteger("user_version") != SchemaVersion)
            throw new InvalidDataException("DID2 messaging SQL generation differs; no old reader is permitted.");
        var expected = Schema.OrderBy(static row => row.Name, StringComparer.Ordinal).ToArray(); var index = 0;
        using var command = Command("SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name;");
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (index >= expected.Length || reader.GetString(0) != "table" || reader.GetString(1) != expected[index].Name ||
                reader.IsDBNull(2) || reader.GetString(2).TrimEnd(';') != expected[index].Sql.TrimEnd(';'))
                throw new InvalidDataException("DID2 messaging SQL schema has an unexpected object or definition.");
            index++;
        }
        if (index != expected.Length) throw new InvalidDataException("DID2 messaging SQL schema is incomplete.");
    }
    private void RequireCipherPolicy()
    {
        using var cipher = Command("PRAGMA cipher_version;");
        var version = Convert.ToString(cipher.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
        if (version is null || !version.StartsWith("4.", StringComparison.Ordinal) || PragmaInteger("secure_delete") != 1 ||
            PragmaInteger("synchronous") != 2 || PragmaInteger("foreign_keys") != 1)
            throw new InvalidDataException("DID2 messaging SQL requires exact SQLCipher durability/deletion policy.");
        using var journal = Command("PRAGMA journal_mode;");
        if (!string.Equals(Convert.ToString(journal.ExecuteScalar()), "delete", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("DID2 messaging SQL forbids WAL or plaintext compatibility.");
    }
    private long PragmaInteger(string name) { using var cmd = Command("PRAGMA " + name + ";"); return Convert.ToInt64(cmd.ExecuteScalar()); }
    private SqliteCommand Command(string sql, SqliteTransaction? tx = null) { var command = connection.CreateCommand(); command.Transaction = tx; command.CommandText = sql; return command; }
    private void Execute(string sql, SqliteTransaction tx) { using var command = Command(sql, tx); command.ExecuteNonQuery(); }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);
    private static void RequireSame(Did2MessagingFloor a, Did2MessagingFloor b)
    { if (!Fixed(a.Exact.Span, b.Exact.Span)) throw new CryptographicException("DID2 SQL and expected protected floor differ."); }
    private sealed class OwnedBindings : IDisposable
    {
        private readonly List<byte[]> buffers = [];
        internal void Add(SqliteCommand command, string parameter, ReadOnlySpan<byte> bytes)
        { var owned = bytes.ToArray(); buffers.Add(owned); command.Parameters.AddWithValue(parameter, owned); }
        public void Dispose() { foreach (var bytes in buffers) CryptographicOperations.ZeroMemory(bytes); }
    }
}
