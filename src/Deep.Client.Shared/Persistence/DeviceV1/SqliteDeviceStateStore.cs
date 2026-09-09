using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Deep.Client.Shared.Domain.DeviceV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV1;

public enum DeviceStateStoreOpenFailure
{ UnreadableOrWrongKey = 1, UnsupportedGeneration = 2, ScopeMismatch = 3, Corrupt = 4 }

public sealed class DeviceStateStoreOpenException : IOException
{
    internal DeviceStateStoreOpenException(DeviceStateStoreOpenFailure reason, string message, Exception? inner = null)
        : base(message, inner) => Reason = reason;
    public DeviceStateStoreOpenFailure Reason { get; }
}

public sealed class SqliteDeviceStateStoreOptions
{
    private readonly byte[] key;
    public SqliteDeviceStateStoreOptions(string statePath, ReadOnlySpan<byte> encryptionKey,
        DeviceAccountId32 accountId, ulong accountGeneration, ulong databaseGeneration,
        DeviceOperationId32 storeInstanceId, bool allowCreate = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath); ArgumentNullException.ThrowIfNull(accountId);
        ArgumentNullException.ThrowIfNull(storeInstanceId);
        if (encryptionKey.Length != 32 || encryptionKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte SQLCipher key is required.", nameof(encryptionKey));
        if (accountGeneration == 0 || databaseGeneration == 0) throw new ArgumentOutOfRangeException(nameof(accountGeneration));
        StatePath = Path.GetFullPath(statePath); key = encryptionKey.ToArray();
        AccountId = DeviceAccountId32.FromBytes(accountId.Span); AccountGeneration = accountGeneration;
        DatabaseGeneration = databaseGeneration; StoreInstanceId = DeviceOperationId32.FromBytes(storeInstanceId.Span);
        AllowCreate = allowCreate;
    }
    public string StatePath { get; }
    internal ReadOnlyMemory<byte> EncryptionKey => key.ToArray();
    public DeviceAccountId32 AccountId { get; }
    public ulong AccountGeneration { get; }
    public ulong DatabaseGeneration { get; }
    public DeviceOperationId32 StoreInstanceId { get; }
    public bool AllowCreate { get; }
}

public sealed partial class SqliteDeviceStateStore : IDeviceStateStore, IProtectedCurrentDmd1Store, IDisposable
{
    private const int ApplicationId = 0x44565331; // DVS1
    private const int SchemaGeneration = 3;
    // This is a sealed, clean-break schema.  It is deliberately kept as one canonical input for
    // creation and for the cryptographic sqlite_master contract checked on every open.
    private const string SchemaDdl = """
        CREATE TABLE device_store_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), database_generation BLOB NOT NULL CHECK(length(database_generation)=8), store_instance_id BLOB NOT NULL CHECK(length(store_instance_id)=32), account_id BLOB NOT NULL CHECK(length(account_id)=32), account_generation BLOB NOT NULL CHECK(length(account_generation)=8));
        CREATE TABLE device_heads(singleton INTEGER PRIMARY KEY CHECK(singleton=1), state_revision BLOB NOT NULL CHECK(length(state_revision)=8), fork_latched INTEGER NOT NULL CHECK(fork_latched IN (0,1)), directory_generation BLOB NOT NULL CHECK(length(directory_generation)=8), directory_hash BLOB NOT NULL CHECK(length(directory_hash)=32), predecessor_hash BLOB NOT NULL CHECK(length(predecessor_hash)=32), drs_revision BLOB NOT NULL CHECK(length(drs_revision)=8), drs_hash BLOB NOT NULL CHECK(length(drs_hash)=32));
        CREATE TABLE device_directory_entries(device_id BLOB PRIMARY KEY CHECK(length(device_id)=32), certificate_hash BLOB NOT NULL CHECK(length(certificate_hash)=32));
        CREATE TABLE device_revocation_floor(device_id BLOB PRIMARY KEY CHECK(length(device_id)=32), revoked_dpd_reference BLOB NOT NULL CHECK(length(revoked_dpd_reference)=38), prior_drs_revision BLOB NOT NULL CHECK(length(prior_drs_revision)=8), prior_drs_hash BLOB NOT NULL CHECK(length(prior_drs_hash)=32), successor_drs_revision BLOB NOT NULL CHECK(length(successor_drs_revision)=8), successor_drs_hash BLOB NOT NULL CHECK(length(successor_drs_hash)=32), saga_operation_id BLOB NOT NULL CHECK(length(saga_operation_id)=32));
        CREATE TABLE device_sagas(saga_operation_id BLOB PRIMARY KEY CHECK(length(saga_operation_id)=32), intent_json TEXT NOT NULL, phase INTEGER NOT NULL CHECK(phase BETWEEN 1 AND 10), remote_outcome INTEGER NOT NULL CHECK(remote_outcome BETWEEN 1 AND 3), pending_phase INTEGER NULL CHECK(pending_phase IS NULL OR pending_phase BETWEEN 1 AND 10), pending_external_operation_id BLOB NULL CHECK(pending_external_operation_id IS NULL OR length(pending_external_operation_id)=32), CHECK((phase=9 AND remote_outcome=3 AND pending_phase IS NOT NULL AND pending_external_operation_id IS NOT NULL) OR (phase!=9 AND remote_outcome!=3 AND pending_phase IS NULL AND pending_external_operation_id IS NULL)));
        CREATE TABLE device_history(ordinal INTEGER PRIMARY KEY CHECK(ordinal>=0), device_id BLOB NOT NULL CHECK(length(device_id)=32), recovery_mode INTEGER NOT NULL CHECK(recovery_mode BETWEEN 1 AND 3), recovery_outcome INTEGER NOT NULL CHECK(recovery_outcome BETWEEN 1 AND 4), history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 1 AND 3), source_device_id BLOB NULL CHECK(source_device_id IS NULL OR length(source_device_id)=32), backup_manifest_hash BLOB NULL CHECK(backup_manifest_hash IS NULL OR length(backup_manifest_hash)=32));
        CREATE TABLE device_repairs(logical_message_id BLOB NOT NULL CHECK(length(logical_message_id)=32), recipient_account_id BLOB NOT NULL CHECK(length(recipient_account_id)=32), recipient_account_generation BLOB NOT NULL CHECK(length(recipient_account_generation)=8), recipient_device_id BLOB NOT NULL CHECK(length(recipient_device_id)=32), attempts_used INTEGER NOT NULL CHECK(attempts_used BETWEEN 0 AND 2), status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 3), CHECK((status=1 AND attempts_used=1) OR (status=2 AND attempts_used BETWEEN 1 AND 2) OR (status=3 AND attempts_used=2)), PRIMARY KEY(logical_message_id,recipient_account_id,recipient_account_generation,recipient_device_id));
        CREATE TABLE device_operation_dedup(operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64 AND fingerprint NOT GLOB '*[^0-9A-F]*'));
        CREATE TABLE protected_current_dmd1(singleton INTEGER PRIMARY KEY CHECK(singleton=1), canonical_dmd1 BLOB NOT NULL CHECK(length(canonical_dmd1) BETWEEN 426 AND 1476), drs_revision BLOB NOT NULL CHECK(length(drs_revision)=8));
        CREATE TABLE device_agreement_authorizations(operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64 AND fingerprint NOT GLOB '*[^0-9A-F]*'), directory_generation BLOB NOT NULL CHECK(length(directory_generation)=8), directory_hash BLOB NOT NULL CHECK(length(directory_hash)=32), account_id BLOB NOT NULL CHECK(length(account_id)=32), account_generation BLOB NOT NULL CHECK(length(account_generation)=8), device_id BLOB NOT NULL CHECK(length(device_id)=32), device_generation BLOB NOT NULL CHECK(length(device_generation)=8), dpd1_hash BLOB NOT NULL CHECK(length(dpd1_hash)=32), purpose INTEGER NOT NULL CHECK(purpose BETWEEN 1 AND 2), operation_binding BLOB NOT NULL CHECK(length(operation_binding)=32), peer_public_key BLOB NOT NULL CHECK(length(peer_public_key)=32));
        CREATE INDEX device_sagas_phase ON device_sagas(phase);
        CREATE INDEX device_repairs_status ON device_repairs(status);
        """;
    private static readonly byte[] ExpectedSchemaFingerprint = HashSchemaObjects(ExpectedSchemaObjects());
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly object lifecycleGate = new();
    private readonly ManualResetEventSlim drained = new(initialState: true);
    private readonly byte[] key;
    private readonly string connectionString;
    private readonly string statePath;
    private readonly DeviceAccountId32 accountId;
    private readonly ulong accountGeneration;
    private readonly ulong databaseGeneration;
    private readonly DeviceOperationId32 storeInstanceId;
    private SqliteConnection? connection;
    private int disposed;
    private int operationsInFlight;

    static SqliteDeviceStateStore() => SQLitePCL.Batteries_V2.Init();

    public SqliteDeviceStateStore(SqliteDeviceStateStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var exists = File.Exists(options.StatePath);
        if (!exists && !options.AllowCreate) throw Failure(DeviceStateStoreOpenFailure.UnreadableOrWrongKey,
            "The current DeviceV1 database generation does not exist.");
        if (exists && new FileInfo(options.StatePath).Length == 0)
            throw Failure(DeviceStateStoreOpenFailure.Corrupt, "The DeviceV1 database is empty.");
        var parent = Path.GetDirectoryName(options.StatePath);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        key = options.EncryptionKey.ToArray(); statePath = options.StatePath; accountId = DeviceAccountId32.FromBytes(options.AccountId.Span);
        accountGeneration = options.AccountGeneration; databaseGeneration = options.DatabaseGeneration;
        storeInstanceId = DeviceOperationId32.FromBytes(options.StoreInstanceId.Span);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = options.StatePath, Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private, Pooling = false
        }.ToString();
        try
        {
            using (var opened = Open())
            {
                if (exists) Validate(opened); else Create(opened);
            }
            ValidateEncryptedMainDatabase(statePath);
            connection = Open();
            ValidateEncryptedSidecars(statePath, connection);
        }
        catch (DeviceStateStoreOpenException)
        {
            connection?.Dispose(); connection = null; CryptographicOperations.ZeroMemory(key); throw;
        }
        catch (Exception ex) when (ex is SqliteException or InvalidOperationException or FormatException)
        {
            connection?.Dispose(); connection = null; CryptographicOperations.ZeroMemory(key);
            throw Failure(DeviceStateStoreOpenFailure.UnreadableOrWrongKey,
                "DeviceV1 SQLCipher state cannot be opened with this key.", ex);
        }
    }

    internal string ConnectionString => connectionString;
    internal bool IsKeyZeroedForTesting => key.All(static value => value == 0);
    internal void ValidateEncryptedFilesForTesting()
    { ValidateEncryptedMainDatabase(statePath); ValidateEncryptedSidecars(statePath, GetConnection()); }

    public async ValueTask<DeviceStoreReadResult> ReadAsync(DeviceAccountId32 requestedAccountId,
        ulong requestedAccountGeneration, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestedAccountId);
        using var lease = EnterOperation();
        if (!InScope(requestedAccountId, requestedAccountGeneration)) return new DeviceStoreReadResult(null);
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false); entered = true;
            ThrowIfDisposed(); DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.AfterGateAcquired);
            var snapshot = ReadSnapshot(GetConnection(), null);
            if (snapshot is not null) ValidateSnapshotSemantics(snapshot);
            return new DeviceStoreReadResult(snapshot);
        }
        finally { if (entered) gate.Release(); }
    }

    public async ValueTask<DeviceCommitResult> CommitAsync(DeviceTransactionPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        using var lease = EnterOperation();
        if (!InScope(plan.AccountId, plan.AccountGeneration))
            return new DeviceCommitResult(DeviceCommitDisposition.Conflict, null);
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false); entered = true;
            ThrowIfDisposed(); DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.AfterGateAcquired);
            var db = GetConnection();
            await using var transaction = db.BeginTransaction(deferred: false);
            var fingerprint = plan.Fingerprint();
            var priorFingerprint = ReadOperation(db, transaction, plan.OperationId);
            if (priorFingerprint is not null)
            {
                var snapshot = ReadSnapshot(db, transaction);
                if (snapshot is not null) ValidateSnapshotSemantics(snapshot);
                transaction.Commit();
                return new DeviceCommitResult(FixedEquals(priorFingerprint, fingerprint)
                    ? DeviceCommitDisposition.Idempotent : DeviceCommitDisposition.Conflict, snapshot);
            }
            var current = ReadSnapshot(db, transaction);
            if (current is not null) ValidateSnapshotSemantics(current);
            var result = DeviceStateMachine.Apply(current, plan);
            if (result.Snapshot is not null) ValidateSnapshotSemantics(result.Snapshot);
            if (result.Snapshot is not null && result.Disposition is DeviceCommitDisposition.Applied
                or DeviceCommitDisposition.ForkLatched or DeviceCommitDisposition.Idempotent)
            {
                if (result.Disposition != DeviceCommitDisposition.Idempotent)
                    WriteSnapshot(db, transaction, current?.Revision, result.Snapshot);
                DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.BeforeDedupInsert);
                InsertOperation(db, transaction, plan.OperationId, fingerprint);
            }
            DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.BeforeCommit);
            transaction.Commit();
            return result;
        }
        catch (DeviceStateStoreInjectedCrashException) { throw; }
        catch (DeviceStateStoreOpenException) { throw; }
        catch (Exception ex) when (ex is SqliteException or InvalidOperationException or JsonException
            or FormatException or OverflowException)
        {
            throw Failure(DeviceStateStoreOpenFailure.Corrupt,
                "The atomic DeviceV1 state transaction failed.", ex);
        }
        finally { if (entered) gate.Release(); }
    }

    public void Dispose()
    {
        lock (lifecycleGate)
        {
            if (disposed != 0) return;
            Volatile.Write(ref disposed, 1);
            if (operationsInFlight == 0) drained.Set();
        }
        drained.Wait();
        connection?.Dispose(); connection = null; gate.Dispose(); CryptographicOperations.ZeroMemory(key);
    }

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(connectionString);
        try
        {
            db.Open(); var rc = SQLitePCL.raw.sqlite3_key(db.Handle, key);
            if (rc != SQLitePCL.raw.SQLITE_OK) throw new SqliteException("SQLCipher rejected the key.", rc);
            Execute(db, null, "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;");
            return db;
        }
        catch { db.Dispose(); throw; }
    }

    private void Create(SqliteConnection db)
    {
        Execute(db, null, $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        Execute(db, null, SchemaDdl);
        using var command = db.CreateCommand();
        command.CommandText = "INSERT INTO device_store_meta VALUES(1,$dg,$sid,$aid,$ag);";
        Add(command, "$dg", U64(databaseGeneration)); Add(command, "$sid", storeInstanceId.ToArray());
        Add(command, "$aid", accountId.ToArray()); Add(command, "$ag", U64(accountGeneration)); command.ExecuteNonQuery();
        ValidateSchema(db); ValidateCipher(db);
    }

    private void Validate(SqliteConnection db)
    {
        try
        {
            if (ScalarLong(db, "PRAGMA application_id;") != ApplicationId
                || ScalarLong(db, "PRAGMA user_version;") != SchemaGeneration)
                throw Failure(DeviceStateStoreOpenFailure.UnsupportedGeneration, "Unsupported DeviceV1 schema generation.");
            ValidateSchema(db);
            using var command = db.CreateCommand();
            command.CommandText = "SELECT database_generation,store_instance_id,account_id,account_generation FROM device_store_meta WHERE singleton=1;";
            using var reader = command.ExecuteReader();
            if (!reader.Read()) throw Failure(DeviceStateStoreOpenFailure.Corrupt, "DeviceV1 scope metadata is absent.");
            if (ReadU64((byte[])reader[0]) != databaseGeneration
                || !((byte[])reader[1]).AsSpan().SequenceEqual(storeInstanceId.Span)
                || !((byte[])reader[2]).AsSpan().SequenceEqual(accountId.Span)
                || ReadU64((byte[])reader[3]) != accountGeneration)
                throw Failure(DeviceStateStoreOpenFailure.ScopeMismatch, "DeviceV1 database belongs to another current generation.");
            ValidateCipher(db);
            ValidatePersistedPrimitiveSemantics(db);
            var snapshot = ReadSnapshot(db, null);
            if (snapshot is not null) ValidateSnapshotSemantics(snapshot);
            ValidateProtectedCurrentDmd1Semantics(db, snapshot);
        }
        catch (DeviceStateStoreOpenException) { throw; }
        catch (SqliteException ex) { throw Failure(DeviceStateStoreOpenFailure.UnreadableOrWrongKey,
            "DeviceV1 SQLCipher metadata cannot be read.", ex); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or
            InvalidDataException or FormatException or JsonException)
        { throw Failure(DeviceStateStoreOpenFailure.Corrupt, "DeviceV1 persisted state violates its sealed semantic contract.", ex); }
    }

    private static void ValidateCipher(SqliteConnection db)
    {
        var version = Convert.ToString(Scalar(db, "PRAGMA cipher_version;"), CultureInfo.InvariantCulture);
        if (string.IsNullOrWhiteSpace(version) || !version.StartsWith("4.", StringComparison.Ordinal))
            throw Failure(DeviceStateStoreOpenFailure.UnsupportedGeneration, "SQLCipher generation 4 is required.");
        using var command = db.CreateCommand(); command.CommandText = "PRAGMA cipher_integrity_check;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var result = reader.IsDBNull(0) ? string.Empty : Convert.ToString(reader.GetValue(0), CultureInfo.InvariantCulture);
            if (!string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase))
                throw Failure(DeviceStateStoreOpenFailure.Corrupt, "SQLCipher integrity verification failed.");
        }
    }

    private static void ValidateSchema(SqliteConnection db)
    {
        var actual = ReadSchemaObjects(db);
        var actualFingerprint = HashSchemaObjects(actual);
        if (!CryptographicOperations.FixedTimeEquals(ExpectedSchemaFingerprint, actualFingerprint))
            throw Failure(DeviceStateStoreOpenFailure.Corrupt,
                "DeviceV1 DDL, constraints, indexes, or schema fingerprint does not match the sealed contract.");
    }

    private static string[] ExpectedSchemaObjects()
    {
        var statements = SchemaDdl.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var result = new List<string>(statements.Length);
        foreach (var statement in statements)
        {
            var match = Regex.Match(statement,
                @"^CREATE\s+(TABLE|INDEX)\s+([a-z0-9_]+)(?:\s+ON\s+([a-z0-9_]+))?",
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (!match.Success) throw new InvalidOperationException("The sealed DeviceV1 schema declaration is malformed.");
            var type = match.Groups[1].Value.ToLowerInvariant(); var name = match.Groups[2].Value;
            var table = type == "table" ? name : match.Groups[3].Value;
            result.Add($"{type}|{name}|{table}|{NormalizeSql(statement)}");
        }
        return result.OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    }

    private static string[] ReadSchemaObjects(SqliteConnection db)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type,name;";
        using var reader = command.ExecuteReader(); var result = new List<string>();
        while (reader.Read())
        {
            if (reader.IsDBNull(3)) throw Failure(DeviceStateStoreOpenFailure.Corrupt, "DeviceV1 schema contains an unexpected implicit index.");
            result.Add($"{reader.GetString(0)}|{reader.GetString(1)}|{reader.GetString(2)}|{NormalizeSql(reader.GetString(3))}");
        }
        return result.OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    }

    private static byte[] HashSchemaObjects(IEnumerable<string> objects) => SHA256.HashData(Encoding.UTF8.GetBytes(
        string.Join('\n', objects)));
    private static string NormalizeSql(string sql) => Regex.Replace(sql.Trim().TrimEnd(';'), @"\s+", " ");

    private static void ValidateEncryptedMainDatabase(string path)
    {
        using var stream = OpenSharedRead(path);
        if (stream.Length < 16)
            throw Failure(DeviceStateStoreOpenFailure.Corrupt, "The encrypted DeviceV1 main database is truncated.");
        Span<byte> header = stackalloc byte[16];
        ReadExactHeader(stream, header, "The encrypted DeviceV1 main database is truncated.");
        if (header.SequenceEqual("SQLite format 3\0"u8))
            throw Failure(DeviceStateStoreOpenFailure.Corrupt,
                "DeviceV1 main state must never expose a plaintext SQLite header.");
    }

    private static void ValidateEncryptedSidecars(string path, SqliteConnection db)
    {
        var wal = path + "-wal";
        if (File.Exists(wal)) ValidateWalSidecar(wal, checked((int)ScalarLong(db, "PRAGMA page_size;")));
        var sharedMemory = path + "-shm";
        if (File.Exists(sharedMemory)) ValidateSharedMemorySidecar(sharedMemory);
    }

    private static void ValidateWalSidecar(string path, int pageSize)
    {
        using var stream = OpenSharedRead(path);
        // SQLite retains a zero-length WAL after a successful checkpoint/reopen.  A non-empty WAL
        // has a 32-byte WAL header followed by complete encrypted frames.
        if (stream.Length == 0) return;
        if (pageSize is < 512 or > 65536 || (pageSize & (pageSize - 1)) != 0)
            throw Failure(DeviceStateStoreOpenFailure.Corrupt, "The DeviceV1 SQLCipher page size is invalid.");
        if (stream.Length < 32 || (stream.Length - 32) % (pageSize + 24L) != 0)
            throw Failure(DeviceStateStoreOpenFailure.Corrupt, "The DeviceV1 SQLCipher WAL is truncated.");
        Span<byte> header = stackalloc byte[16];
        ReadExactHeader(stream, header, "The DeviceV1 SQLCipher WAL is truncated.");
        if (header.SequenceEqual("SQLite format 3\0"u8))
            throw Failure(DeviceStateStoreOpenFailure.Corrupt,
                "The DeviceV1 WAL must never contain a plaintext SQLite database header.");
    }

    private static void ValidateSharedMemorySidecar(string path)
    {
        using var stream = OpenSharedRead(path);
        // WAL-index shared memory contains synchronization/index metadata, not database pages.
        // SQLite allocates it in 32 KiB regions; zero is valid during creation/removal.
        if (stream.Length != 0 && (stream.Length < 32 * 1024 || stream.Length % (32 * 1024) != 0))
            throw Failure(DeviceStateStoreOpenFailure.Corrupt, "The DeviceV1 WAL shared-memory sidecar has an invalid size.");
    }

    private static FileStream OpenSharedRead(string path) => new(path, FileMode.Open, FileAccess.Read,
        FileShare.ReadWrite | FileShare.Delete);

    private static void ReadExactHeader(Stream stream, Span<byte> header, string failure)
    {
        var read = 0;
        while (read != header.Length)
        {
            var count = stream.Read(header[read..]);
            if (count == 0) throw Failure(DeviceStateStoreOpenFailure.Corrupt, failure);
            read += count;
        }
    }

    private static void ValidateSnapshotSemantics(DeviceAccountStateSnapshot snapshot)
    {
        if (snapshot.LocalRevocationFloor.Any(entry => snapshot.Directory.Head.Contains(entry.DeviceId)
                || entry.SuccessorDrsRevision != entry.PriorDrsRevision + 1))
            throw new InvalidOperationException("Invalid DeviceV1 local revocation floor.");
        if (snapshot.RevocationSagas.Count(static saga => !saga.IsTerminal) > 1
            || snapshot.RevocationSagas.Any(static saga => !Enum.IsDefined(saga.Phase)
                || !Enum.IsDefined(saga.RemoteOutcome)
                || (saga.Phase == DeviceRevocationPhase.ReconcileRequired) != (saga.PendingPhase is not null)
                || (saga.Phase == DeviceRevocationPhase.ReconcileRequired) != (saga.PendingExternalOperationId is not null)))
            throw new InvalidOperationException("Invalid DeviceV1 revocation saga semantics.");
        if (snapshot.HistoryDecisions.Any(static decision => !ValidHistoryDecision(decision)))
            throw new InvalidOperationException("Invalid DeviceV1 history semantics.");
        if (snapshot.Repairs.Any(static repair => !Enum.IsDefined(repair.Status)
                || repair.AttemptsUsed is < 0 or > 2
                || (repair.Status == DeviceRepairStatus.Active && repair.AttemptsUsed != 1)
                || (repair.Status == DeviceRepairStatus.Exhausted && repair.AttemptsUsed != 2)
                || (repair.Status == DeviceRepairStatus.Completed && repair.AttemptsUsed is < 1 or > 2)))
            throw new InvalidOperationException("Invalid DeviceV1 repair semantics.");
    }

    private static bool ValidHistoryDecision(DeviceHistoryDecisionSnapshot decision)
    {
        if (!Enum.IsDefined(decision.RecoveryMode) || !Enum.IsDefined(decision.RecoveryOutcome)
            || !Enum.IsDefined(decision.HistoryPolicy)
            || (decision.BackupManifestHash is not null && decision.BackupManifestHash.Value.Length != 32)) return false;
        return (decision.RecoveryMode, decision.RecoveryOutcome, decision.HistoryPolicy,
            decision.SourceDeviceId is not null, decision.BackupManifestHash is not null) switch
        {
            (DeviceRecoveryMode.ReturningProtectedDevice, DeviceRecoveryOutcome.ReturningDeviceLocalStateRequired,
                DeviceHistoryPolicy.NoHistory, false, false) => true,
            (DeviceRecoveryMode.PhraseCreatesNewDevice, DeviceRecoveryOutcome.NewDeviceWithoutHistory,
                DeviceHistoryPolicy.NoHistory, false, false) => true,
            (DeviceRecoveryMode.PhraseCreatesNewDevice, DeviceRecoveryOutcome.NewDeviceWithEncryptedBackup,
                DeviceHistoryPolicy.AuthenticatedEncryptedBackup, false, true) => true,
            (DeviceRecoveryMode.ExistingDeviceEnrollsNewDevice, DeviceRecoveryOutcome.NewDeviceWithoutHistory,
                DeviceHistoryPolicy.NoHistory, true, false) => true,
            (DeviceRecoveryMode.ExistingDeviceEnrollsNewDevice, DeviceRecoveryOutcome.NewDeviceWithEncryptedTransfer,
                DeviceHistoryPolicy.AuthenticatedEncryptedDeviceTransfer, true, false) => true,
            _ => false
        };
    }

    private static void ValidatePersistedPrimitiveSemantics(SqliteConnection db)
    {
        const string invalid = """
            SELECT
              (SELECT COUNT(*) FROM device_heads) > 1 OR
              EXISTS(SELECT 1 FROM device_heads WHERE fork_latched NOT IN (0,1)
                OR length(state_revision)!=8 OR length(directory_generation)!=8 OR length(drs_revision)!=8) OR
              EXISTS(SELECT 1 FROM device_sagas WHERE phase NOT BETWEEN 1 AND 10
                OR remote_outcome NOT BETWEEN 1 AND 3
                OR (phase=9 AND remote_outcome!=3) OR (phase!=9 AND remote_outcome=3)
                OR (phase=9) != (pending_phase IS NOT NULL AND pending_external_operation_id IS NOT NULL)) OR
              EXISTS(SELECT 1 FROM device_history WHERE recovery_mode NOT BETWEEN 1 AND 3
                OR recovery_outcome NOT BETWEEN 1 AND 4 OR history_policy NOT BETWEEN 1 AND 3) OR
              EXISTS(SELECT 1 FROM device_repairs WHERE attempts_used NOT BETWEEN 0 AND 2
                OR status NOT BETWEEN 1 AND 3
                OR (status=1 AND attempts_used!=1) OR (status=3 AND attempts_used!=2)) OR
              EXISTS(SELECT 1 FROM device_operation_dedup WHERE length(fingerprint)!=64
                OR fingerprint GLOB '*[^0-9A-F]*');
            """;
        if (ScalarLong(db, invalid) != 0)
            throw Failure(DeviceStateStoreOpenFailure.Corrupt, "DeviceV1 persisted enum or primitive invariants are invalid.");
    }

    private DeviceAccountStateSnapshot? ReadSnapshot(SqliteConnection db, SqliteTransaction? transaction)
    {
        using var command = db.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT state_revision,fork_latched,directory_generation,directory_hash,predecessor_hash,drs_revision,drs_hash FROM device_heads WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var revision = ReadU64((byte[])reader[0]); var fork = reader.GetInt32(1) != 0;
        var dmdGeneration = ReadU64((byte[])reader[2]); var dmdHash = (byte[])reader[3];
        var predecessor = (byte[])reader[4]; var drsRevision = ReadU64((byte[])reader[5]); var drsHash = (byte[])reader[6];
        reader.Close();
        var active = ReadActive(db, transaction);
        var facts = VerifiedDeviceDirectoryFacts.RestorePersisted(accountId, accountGeneration, dmdGeneration,
            DeviceDirectoryHash32.FromBytes(dmdHash), predecessor, drsRevision,
            DeviceRevocationHash32.FromBytes(drsHash), active);
        var floor = ReadFloor(db, transaction);
        var directory = DeviceDirectoryState.Restore(facts, fork, floor);
        return new DeviceAccountStateSnapshot(revision, directory, ReadSagas(db, transaction),
            ReadHistory(db, transaction), ReadRepairs(db, transaction));
    }

    private static VerifiedActiveDeviceFacts[] ReadActive(SqliteConnection db, SqliteTransaction? tx)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT device_id,certificate_hash FROM device_directory_entries ORDER BY device_id;";
        using var reader = command.ExecuteReader(); var result = new List<VerifiedActiveDeviceFacts>();
        while (reader.Read()) result.Add(new VerifiedActiveDeviceFacts(
            DeviceIdentifier32.FromBytes((byte[])reader[0]), DeviceCertificateHash32.FromBytes((byte[])reader[1])));
        return result.ToArray();
    }

    private DeviceLocalRevocationFloorEntry[] ReadFloor(SqliteConnection db, SqliteTransaction? tx)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT device_id,revoked_dpd_reference,prior_drs_revision,prior_drs_hash,successor_drs_revision,successor_drs_hash,saga_operation_id FROM device_revocation_floor ORDER BY device_id;";
        using var reader = command.ExecuteReader(); var result = new List<DeviceLocalRevocationFloorEntry>();
        while (reader.Read()) result.Add(new DeviceLocalRevocationFloorEntry(accountId, accountGeneration,
            DeviceIdentifier32.FromBytes((byte[])reader[0]), (byte[])reader[1], ReadU64((byte[])reader[2]),
            DeviceRevocationHash32.FromBytes((byte[])reader[3]), ReadU64((byte[])reader[4]),
            DeviceRevocationHash32.FromBytes((byte[])reader[5]), DeviceOperationId32.FromBytes((byte[])reader[6])));
        return result.ToArray();
    }

    private static DeviceRevocationSagaSnapshot[] ReadSagas(SqliteConnection db, SqliteTransaction? tx)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT saga_operation_id,intent_json,phase,remote_outcome,pending_phase,pending_external_operation_id FROM device_sagas ORDER BY saga_operation_id;";
        using var reader = command.ExecuteReader(); var result = new List<DeviceRevocationSagaSnapshot>();
        while (reader.Read())
        {
            var dto = JsonSerializer.Deserialize<IntentDto>(reader.GetString(1)) ?? throw new JsonException("Missing intent.");
            result.Add(new(DeviceOperationId32.FromBytes((byte[])reader[0]), FromDto(dto),
                (DeviceRevocationPhase)reader.GetInt32(2), (DeviceRemoteOutcome)reader.GetInt32(3),
                reader.IsDBNull(4) ? null : (DeviceRevocationPhase)reader.GetInt32(4),
                reader.IsDBNull(5) ? null : DeviceOperationId32.FromBytes((byte[])reader[5])));
        }
        return result.ToArray();
    }

    private DeviceHistoryDecisionSnapshot[] ReadHistory(SqliteConnection db, SqliteTransaction? tx)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT device_id,recovery_mode,recovery_outcome,history_policy,source_device_id,backup_manifest_hash FROM device_history ORDER BY ordinal;";
        using var reader = command.ExecuteReader(); var result = new List<DeviceHistoryDecisionSnapshot>();
        while (reader.Read()) result.Add(new(accountId, accountGeneration, DeviceIdentifier32.FromBytes((byte[])reader[0]),
            (DeviceRecoveryMode)reader.GetInt32(1), (DeviceRecoveryOutcome)reader.GetInt32(2),
            (DeviceHistoryPolicy)reader.GetInt32(3), reader.IsDBNull(4) ? null : DeviceIdentifier32.FromBytes((byte[])reader[4]),
            reader.IsDBNull(5) ? null : (byte[])reader[5]));
        return result.ToArray();
    }

    private DeviceRepairSnapshot[] ReadRepairs(SqliteConnection db, SqliteTransaction? tx)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT logical_message_id,recipient_account_id,recipient_account_generation,recipient_device_id,attempts_used,status FROM device_repairs;";
        using var reader = command.ExecuteReader(); var result = new List<DeviceRepairSnapshot>();
        while (reader.Read()) result.Add(new(new DeviceRepairKey(accountId, accountGeneration,
            LogicalMessageId32.FromBytes((byte[])reader[0]), DeviceAccountId32.FromBytes((byte[])reader[1]),
            ReadU64((byte[])reader[2]), DeviceIdentifier32.FromBytes((byte[])reader[3])),
            reader.GetInt32(4), (DeviceRepairStatus)reader.GetInt32(5)));
        return result.ToArray();
    }

    private static void WriteSnapshot(SqliteConnection db, SqliteTransaction tx, ulong? expectedRevision,
        DeviceAccountStateSnapshot snapshot)
    {
        if (expectedRevision is null)
        {
            using var insert = db.CreateCommand(); insert.Transaction = tx;
            insert.CommandText = "INSERT INTO device_heads VALUES(1,$r,$f,$dg,$dh,$p,$rr,$rh);";
            BindHead(insert, snapshot); if (insert.ExecuteNonQuery() != 1) throw new InvalidOperationException("Bootstrap CAS failed.");
        }
        else
        {
            using var update = db.CreateCommand(); update.Transaction = tx;
            update.CommandText = "UPDATE device_heads SET state_revision=$r,fork_latched=$f,directory_generation=$dg,directory_hash=$dh,predecessor_hash=$p,drs_revision=$rr,drs_hash=$rh WHERE singleton=1 AND state_revision=$expected;";
            BindHead(update, snapshot); Add(update, "$expected", U64(expectedRevision.Value));
            if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("DeviceV1 state CAS failed.");
        }
        DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.AfterHeadWritten);
        ReplaceChildren(db, tx, snapshot);
        DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.AfterChildReplacement);
    }

    private static void BindHead(SqliteCommand command, DeviceAccountStateSnapshot snapshot)
    {
        var head = snapshot.Directory.Head;
        Add(command, "$r", U64(snapshot.Revision)); Add(command, "$f", snapshot.Directory.ForkLatched ? 1 : 0);
        Add(command, "$dg", U64(head.DirectoryGeneration)); Add(command, "$dh", head.DirectoryHash.ToArray());
        Add(command, "$p", head.PredecessorHash.ToArray()); Add(command, "$rr", U64(head.RevocationRevision));
        Add(command, "$rh", head.RevocationHash.ToArray());
    }

    private static void ReplaceChildren(SqliteConnection db, SqliteTransaction tx,
        DeviceAccountStateSnapshot snapshot)
    {
        Execute(db, tx, "DELETE FROM device_directory_entries; DELETE FROM device_revocation_floor; DELETE FROM device_sagas; DELETE FROM device_history; DELETE FROM device_repairs;");
        foreach (var item in snapshot.Directory.Head.ActiveDevices)
            Insert(db, tx, "INSERT INTO device_directory_entries VALUES($a,$b);",
                ("$a", item.DeviceId.ToArray()), ("$b", item.CertificateHash.ToArray()));
        foreach (var item in snapshot.LocalRevocationFloor)
            Insert(db, tx, "INSERT INTO device_revocation_floor VALUES($a,$b,$c,$d,$e,$f,$g);",
                ("$a", item.DeviceId.ToArray()), ("$b", item.RevokedDpdReference.ToArray()),
                ("$c", U64(item.PriorDrsRevision)), ("$d", item.PriorDrsHash.ToArray()),
                ("$e", U64(item.SuccessorDrsRevision)), ("$f", item.SuccessorDrsHash.ToArray()),
                ("$g", item.SagaOperationId.ToArray()));
        foreach (var saga in snapshot.RevocationSagas)
            Insert(db, tx, "INSERT INTO device_sagas VALUES($a,$b,$c,$d,$e,$f);",
                ("$a", saga.OperationId.ToArray()), ("$b", JsonSerializer.Serialize(ToDto(saga.Intent))),
                ("$c", (int)saga.Phase), ("$d", (int)saga.RemoteOutcome),
                ("$e", saga.PendingPhase is null ? DBNull.Value : (int)saga.PendingPhase.Value),
                ("$f", saga.PendingExternalOperationId is null ? DBNull.Value : saga.PendingExternalOperationId.ToArray()));
        var ordinal = 0;
        foreach (var history in snapshot.HistoryDecisions)
            Insert(db, tx, "INSERT INTO device_history VALUES($o,$a,$b,$c,$d,$e,$f);",
                ("$o", ordinal++), ("$a", history.DeviceId.ToArray()), ("$b", (int)history.RecoveryMode),
                ("$c", (int)history.RecoveryOutcome), ("$d", (int)history.HistoryPolicy),
                ("$e", history.SourceDeviceId is null ? DBNull.Value : history.SourceDeviceId.ToArray()),
                ("$f", history.BackupManifestHash is null ? DBNull.Value : history.BackupManifestHash.Value.ToArray()));
        foreach (var repair in snapshot.Repairs)
            Insert(db, tx, "INSERT INTO device_repairs VALUES($a,$b,$c,$d,$e,$f);",
                ("$a", repair.Key.LogicalMessageId.ToArray()), ("$b", repair.Key.RecipientAccountId.ToArray()),
                ("$c", U64(repair.Key.RecipientAccountGeneration)), ("$d", repair.Key.RecipientDeviceId.ToArray()),
                ("$e", repair.AttemptsUsed), ("$f", (int)repair.Status));
    }

    private static string? ReadOperation(SqliteConnection db, SqliteTransaction tx, DeviceOperationId32 id)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT fingerprint FROM device_operation_dedup WHERE operation_id=$id;";
        Add(command, "$id", id.ToArray()); return command.ExecuteScalar() as string;
    }
    private static void InsertOperation(SqliteConnection db, SqliteTransaction tx, DeviceOperationId32 id, string fingerprint) =>
        Insert(db, tx, "INSERT INTO device_operation_dedup VALUES($a,$b);", ("$a", id.ToArray()), ("$b", fingerprint));

    private bool InScope(DeviceAccountId32 id, ulong generation) =>
        accountId.Equals(id) && accountGeneration == generation;
    private OperationLease EnterOperation()
    {
        lock (lifecycleGate)
        {
            ThrowIfDisposed();
            if (++operationsInFlight == 1) drained.Reset();
            return new OperationLease(this);
        }
    }
    private void ExitOperation()
    {
        lock (lifecycleGate)
        {
            if (--operationsInFlight < 0) throw new InvalidOperationException("DeviceV1 lifecycle lease underflow.");
            if (operationsInFlight == 0 && Volatile.Read(ref disposed) != 0) drained.Set();
        }
    }
    private SqliteConnection GetConnection() => connection ?? throw new ObjectDisposedException(nameof(SqliteDeviceStateStore));
    private void ThrowIfDisposed() { if (Volatile.Read(ref disposed) != 0) throw new ObjectDisposedException(nameof(SqliteDeviceStateStore)); }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static ulong ReadU64(byte[] value) => value.Length == 8 ? BinaryPrimitives.ReadUInt64BigEndian(value)
        : throw new FormatException("Expected an eight-byte unsigned integer.");
    private static object? Scalar(SqliteConnection db, string sql)
    { using var command = db.CreateCommand(); command.CommandText = sql; return command.ExecuteScalar(); }
    private static long ScalarLong(SqliteConnection db, string sql) => Convert.ToInt64(Scalar(db, sql), CultureInfo.InvariantCulture);
    private static void Execute(SqliteConnection db, SqliteTransaction? tx, string sql)
    { using var command = db.CreateCommand(); command.Transaction = tx; command.CommandText = sql; command.ExecuteNonQuery(); }
    private static void Insert(SqliteConnection db, SqliteTransaction tx, string sql,
        params (string Name, object Value)[] values)
    { using var command = db.CreateCommand(); command.Transaction = tx; command.CommandText = sql;
      foreach (var value in values) Add(command, value.Name, value.Value); command.ExecuteNonQuery(); }
    private static void Add(SqliteCommand command, string name, object value) => command.Parameters.AddWithValue(name, value);
    private static bool FixedEquals(string left, string right) => CryptographicOperations.FixedTimeEquals(
        Convert.FromHexString(left), Convert.FromHexString(right));
    private static DeviceStateStoreOpenException Failure(DeviceStateStoreOpenFailure reason, string message,
        Exception? inner = null) => new(reason, message, inner);

    private sealed class OperationLease : IDisposable
    {
        private SqliteDeviceStateStore? owner;
        internal OperationLease(SqliteDeviceStateStore owner) => this.owner = owner;
        public void Dispose() => Interlocked.Exchange(ref owner, null)?.ExitOperation();
    }

    private sealed record ActiveDto(string Device, string Certificate);
    private sealed record DirectoryDto(ulong Generation, string Hash, string Predecessor, ulong DrsRevision,
        string DrsHash, ActiveDto[] Active);
    private sealed record EnrollmentDto(ulong DrsRevision, string DrsHash, string Device, string Certificate);
    private sealed record RecoveryDto(int Mode, int Outcome, string Target, string? Source, int Policy, string? Backup);
    private sealed record RevocationDto(string Device, string Dpd, ulong PriorRevision, string PriorHash,
        ulong SuccessorRevision, string SuccessorHash, DirectoryDto Directory, string PriorAdc, string SuccessorAdc);
    private sealed record IntentDto(int Kind, string Account, ulong AccountGeneration, ulong ExpectedGeneration,
        string ExpectedHash, EnrollmentDto? Enrollment, RecoveryDto? Recovery, RevocationDto? Revocation,
        string[]? Operations, string[] Contacts, string[] Groups, ActiveDto[] Desired);

    private static IntentDto ToDto(DeviceMutationIntent intent) => new((int)intent.Kind,
        Convert.ToHexString(intent.AccountId.Span), intent.AccountGeneration, intent.ExpectedDirectoryGeneration,
        Convert.ToHexString(intent.ExpectedDirectoryHash.Span),
        intent.Enrollment is null ? null : new(intent.Enrollment.RevocationRevision,
            Convert.ToHexString(intent.Enrollment.RevocationHash.Span), Convert.ToHexString(intent.Enrollment.DeviceId.Span),
            Convert.ToHexString(intent.Enrollment.CertificateHash.Span)),
        intent.RecoveryIntent is null ? null : new((int)intent.RecoveryIntent.Mode, (int)intent.RecoveryIntent.Outcome,
            Convert.ToHexString(intent.RecoveryIntent.TargetDeviceId.Span),
            intent.RecoveryIntent.SourceDeviceId is null ? null : Convert.ToHexString(intent.RecoveryIntent.SourceDeviceId.Span),
            (int)intent.RecoveryIntent.HistoryPolicy, intent.RecoveryIntent.BackupManifestHash is null ? null
                : Convert.ToHexString(intent.RecoveryIntent.BackupManifestHash.Value.Span)),
        intent.Revocation is null ? null : new(Convert.ToHexString(intent.Revocation.RevokedDeviceId.Span),
            Convert.ToHexString(intent.Revocation.RevokedDpdReference.Span), intent.Revocation.PriorDrsRevision,
            Convert.ToHexString(intent.Revocation.PriorDrsHash.Span), intent.Revocation.SuccessorDrsRevision,
            Convert.ToHexString(intent.Revocation.SuccessorDrsHash.Span), DirectoryToDto(intent.Revocation.SuccessorDirectory),
            Convert.ToHexString(intent.Revocation.PriorAdcHash.Span), Convert.ToHexString(intent.Revocation.SuccessorAdcHash.Span)),
        intent.PlaneOperations is null ? null : new[] { intent.PlaneOperations.Prekeys, intent.PlaneOperations.Directory,
            intent.PlaneOperations.Capabilities, intent.PlaneOperations.Contacts, intent.PlaneOperations.Groups,
            intent.PlaneOperations.Completion }.Select(static x => Convert.ToHexString(x.Span)).ToArray(),
        intent.ContactWorklist.Select(static x => Convert.ToHexString(x.Span)).ToArray(),
        intent.GroupWorklist.Select(static x => Convert.ToHexString(x.Span)).ToArray(),
        intent.DesiredDevices.Select(static x => new ActiveDto(Convert.ToHexString(x.DeviceId.Span),
            Convert.ToHexString(x.CertificateHash.Span))).ToArray());

    private static DeviceMutationIntent FromDto(IntentDto dto)
    {
        var account = DeviceAccountId32.FromBytes(Convert.FromHexString(dto.Account));
        var enrollment = dto.Enrollment is null ? null : VerifiedEnrollmentDeviceFacts.RestorePersisted(account,
            dto.AccountGeneration, dto.Enrollment.DrsRevision, DeviceRevocationHash32.FromBytes(Convert.FromHexString(dto.Enrollment.DrsHash)),
            DeviceIdentifier32.FromBytes(Convert.FromHexString(dto.Enrollment.Device)),
            DeviceCertificateHash32.FromBytes(Convert.FromHexString(dto.Enrollment.Certificate)));
        var recovery = dto.Recovery is null ? null : DeviceRecoveryIntent.RestorePersisted(
            (DeviceRecoveryMode)dto.Recovery.Mode, (DeviceRecoveryOutcome)dto.Recovery.Outcome, account,
            dto.AccountGeneration, DeviceIdentifier32.FromBytes(Convert.FromHexString(dto.Recovery.Target)),
            dto.Recovery.Source is null ? null : DeviceIdentifier32.FromBytes(Convert.FromHexString(dto.Recovery.Source)),
            (DeviceHistoryPolicy)dto.Recovery.Policy, dto.Recovery.Backup is null ? null : Convert.FromHexString(dto.Recovery.Backup));
        DeviceRevocationCommitment? revocation = null;
        if (dto.Revocation is not null)
            revocation = DeviceRevocationCommitment.RestorePersisted(account, dto.AccountGeneration,
                DeviceIdentifier32.FromBytes(Convert.FromHexString(dto.Revocation.Device)),
                Convert.FromHexString(dto.Revocation.Dpd), dto.Revocation.PriorRevision,
                DeviceRevocationHash32.FromBytes(Convert.FromHexString(dto.Revocation.PriorHash)),
                dto.Revocation.SuccessorRevision, DeviceRevocationHash32.FromBytes(Convert.FromHexString(dto.Revocation.SuccessorHash)),
                DirectoryFromDto(account, dto.AccountGeneration, dto.Revocation.Directory),
                Convert.FromHexString(dto.Revocation.PriorAdc), Convert.FromHexString(dto.Revocation.SuccessorAdc));
        DeviceRevocationPlaneOperations? operations = null;
        if (dto.Operations is { Length: 6 } op) operations = new(op.Select(static x =>
            DeviceOperationId32.FromBytes(Convert.FromHexString(x))).ToArray()[0],
            DeviceOperationId32.FromBytes(Convert.FromHexString(op[1])),
            DeviceOperationId32.FromBytes(Convert.FromHexString(op[2])),
            DeviceOperationId32.FromBytes(Convert.FromHexString(op[3])),
            DeviceOperationId32.FromBytes(Convert.FromHexString(op[4])),
            DeviceOperationId32.FromBytes(Convert.FromHexString(op[5])));
        return DeviceMutationIntent.RestorePersisted((DeviceMutationKind)dto.Kind, account, dto.AccountGeneration,
            dto.ExpectedGeneration, DeviceDirectoryHash32.FromBytes(Convert.FromHexString(dto.ExpectedHash)),
            enrollment, revocation, recovery, operations,
            dto.Contacts.Select(static x => DeviceContactWorkItemId32.FromBytes(Convert.FromHexString(x))),
            dto.Groups.Select(static x => DeviceGroupWorkItemId32.FromBytes(Convert.FromHexString(x))),
            dto.Desired.Select(static x => new VerifiedActiveDeviceFacts(
                DeviceIdentifier32.FromBytes(Convert.FromHexString(x.Device)),
                DeviceCertificateHash32.FromBytes(Convert.FromHexString(x.Certificate)))));
    }

    private static DirectoryDto DirectoryToDto(VerifiedDeviceDirectoryFacts facts) => new(facts.DirectoryGeneration,
        Convert.ToHexString(facts.DirectoryHash.Span), Convert.ToHexString(facts.PredecessorHash.Span),
        facts.RevocationRevision, Convert.ToHexString(facts.RevocationHash.Span),
        facts.ActiveDevices.Select(static x => new ActiveDto(Convert.ToHexString(x.DeviceId.Span),
            Convert.ToHexString(x.CertificateHash.Span))).ToArray());
    private static VerifiedDeviceDirectoryFacts DirectoryFromDto(DeviceAccountId32 account, ulong generation,
        DirectoryDto dto) => VerifiedDeviceDirectoryFacts.RestorePersisted(account, generation, dto.Generation,
            DeviceDirectoryHash32.FromBytes(Convert.FromHexString(dto.Hash)), Convert.FromHexString(dto.Predecessor),
            dto.DrsRevision, DeviceRevocationHash32.FromBytes(Convert.FromHexString(dto.DrsHash)),
            dto.Active.Select(static x => new VerifiedActiveDeviceFacts(
                DeviceIdentifier32.FromBytes(Convert.FromHexString(x.Device)),
                DeviceCertificateHash32.FromBytes(Convert.FromHexString(x.Certificate)))));
}
