using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Deep.Client.Shared.Domain.AccountDirectoryV1;
using Deep.Protocol.AccountDirectoryV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.AccountDirectoryV1;

public enum AccountDirectoryStoreOpenFailure
{
    UnreadableOrWrongKey = 1,
    UnsupportedGeneration = 2,
    ScopeMismatch = 3,
    Corrupt = 4
}

public sealed class AccountDirectoryStoreOpenException : IOException
{
    internal AccountDirectoryStoreOpenException(AccountDirectoryStoreOpenFailure reason, string message, Exception? inner = null)
        : base(message, inner) => Reason = reason;
    public AccountDirectoryStoreOpenFailure Reason { get; }
}

public sealed class SqliteAccountDirectoryStateStoreOptions
{
    private readonly byte[] key;
    private readonly byte[] networkId;
    private readonly byte[] localAccountId;

    public SqliteAccountDirectoryStateStoreOptions(string statePath, ReadOnlySpan<byte> encryptionKey,
        ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> localAccountId, ulong localAccountGeneration,
        ulong databaseGeneration, AccountDirectoryStoreId32 storeInstanceId, bool allowCreate = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(storeInstanceId);
        if (encryptionKey.Length != 32 || encryptionKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte SQLCipher key is required.", nameof(encryptionKey));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Network ID must be 16 nonzero bytes.", nameof(networkId));
        if (localAccountId.Length != 32 || localAccountId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Local account ID must be 32 nonzero bytes.", nameof(localAccountId));
        if (localAccountGeneration == 0 || databaseGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(localAccountGeneration));
        StatePath = Path.GetFullPath(statePath); key = encryptionKey.ToArray(); this.networkId = networkId.ToArray();
        this.localAccountId = localAccountId.ToArray(); LocalAccountGeneration = localAccountGeneration;
        DatabaseGeneration = databaseGeneration; StoreInstanceId = AccountDirectoryStoreId32.FromBytes(storeInstanceId.Span);
        AllowCreate = allowCreate;
    }

    public string StatePath { get; }
    internal ReadOnlyMemory<byte> EncryptionKey => key.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> LocalAccountId => localAccountId.ToArray();
    public ulong LocalAccountGeneration { get; }
    public ulong DatabaseGeneration { get; }
    public AccountDirectoryStoreId32 StoreInstanceId { get; }
    public bool AllowCreate { get; }
}

public sealed class SqliteAccountDirectoryStateStore : IAccountDirectoryStateStore, IDisposable
{
    private const int ApplicationId = 0x41445331; // ADS1
    private const int SchemaGeneration = 1;
    private const string SchemaDdl = """
        CREATE TABLE account_directory_store_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), database_generation BLOB NOT NULL CHECK(length(database_generation)=8), store_instance_id BLOB NOT NULL CHECK(length(store_instance_id)=32), network_id BLOB NOT NULL CHECK(length(network_id)=16), local_account_id BLOB NOT NULL CHECK(length(local_account_id)=32), local_account_generation BLOB NOT NULL CHECK(length(local_account_generation)=8));
        CREATE TABLE account_directory_head(singleton INTEGER PRIMARY KEY CHECK(singleton=1), state_revision BLOB NOT NULL CHECK(length(state_revision)=8), fork_latched INTEGER NOT NULL CHECK(fork_latched IN (0,1)), exact_adh1 BLOB NULL, adh1_core_hash BLOB NULL CHECK(adh1_core_hash IS NULL OR length(adh1_core_hash)=32), log_generation BLOB NULL CHECK(log_generation IS NULL OR length(log_generation)=8), tree_size BLOB NULL CHECK(tree_size IS NULL OR length(tree_size)=8), CHECK((exact_adh1 IS NULL AND adh1_core_hash IS NULL AND log_generation IS NULL AND tree_size IS NULL) OR (length(exact_adh1)>0 AND adh1_core_hash IS NOT NULL AND log_generation IS NOT NULL AND tree_size IS NOT NULL)));
        CREATE TABLE account_directory_subjects(leaf_key BLOB PRIMARY KEY CHECK(length(leaf_key)=32), state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4), refresh_reason INTEGER NOT NULL CHECK(refresh_reason BETWEEN 0 AND 5), exact_adc1_reference BLOB NOT NULL CHECK(length(exact_adc1_reference) IN (0,38)), account_generation BLOB NOT NULL CHECK(length(account_generation)=8), directory_generation BLOB NOT NULL CHECK(length(directory_generation)=8), boot_id BLOB NOT NULL CHECK(length(boot_id)=16), verified_at_monotonic BLOB NOT NULL CHECK(length(verified_at_monotonic)=8), freshness_deadline_monotonic BLOB NOT NULL CHECK(length(freshness_deadline_monotonic)=8), authorization_id BLOB NULL CHECK(authorization_id IS NULL OR length(authorization_id)=32), device_id BLOB NULL CHECK(device_id IS NULL OR length(device_id)=32), CHECK((state=1 AND refresh_reason=0) OR (state=2 AND refresh_reason BETWEEN 1 AND 5) OR (state IN (3,4) AND refresh_reason=0)));
        """;
    private static readonly byte[] ExpectedSchemaFingerprint = HashSchemaObjects(ExpectedSchemaObjects());

    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly byte[] key;
    private readonly byte[] networkId;
    private readonly byte[] localAccountId;
    private readonly ulong localAccountGeneration;
    private readonly ulong databaseGeneration;
    private readonly AccountDirectoryStoreId32 storeInstanceId;
    private readonly string statePath;
    private readonly string connectionString;
    private SqliteConnection? connection;
    private int disposed;

    static SqliteAccountDirectoryStateStore() => SQLitePCL.Batteries_V2.Init();

    public SqliteAccountDirectoryStateStore(SqliteAccountDirectoryStateStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var exists = File.Exists(options.StatePath);
        if (!exists && !options.AllowCreate)
            throw Failure(AccountDirectoryStoreOpenFailure.UnreadableOrWrongKey, "The protected directory store does not exist.");
        if (exists && new FileInfo(options.StatePath).Length == 0)
            throw Failure(AccountDirectoryStoreOpenFailure.Corrupt, "The protected directory store is empty.");
        var parent = Path.GetDirectoryName(options.StatePath); if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        key = options.EncryptionKey.ToArray(); networkId = options.NetworkId.ToArray();
        localAccountId = options.LocalAccountId.ToArray(); localAccountGeneration = options.LocalAccountGeneration;
        databaseGeneration = options.DatabaseGeneration;
        storeInstanceId = AccountDirectoryStoreId32.FromBytes(options.StoreInstanceId.Span);
        statePath = options.StatePath;
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString();
        try
        {
            using (var opened = Open()) { if (exists) Validate(opened); else Create(opened); }
            ValidateEncryptedHeader(statePath);
            connection = Open();
        }
        catch (AccountDirectoryStoreOpenException) { CryptographicOperations.ZeroMemory(key); throw; }
        catch (Exception exception) when (exception is SqliteException or InvalidOperationException or FormatException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(AccountDirectoryStoreOpenFailure.UnreadableOrWrongKey,
                "The protected directory store cannot be opened with this key.", exception);
        }
    }

    internal string ConnectionString => connectionString;
    internal bool IsKeyZeroedForTesting => key.All(static value => value == 0);

    public async ValueTask<AccountDirectoryStateSnapshot?> ReadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { ThrowIfDisposed(); return AccountDirectoryStateCloner.Clone(ReadSnapshot(GetConnection(), null)); }
        catch (AccountDirectoryStoreOpenException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or ArgumentException)
        { throw Failure(AccountDirectoryStoreOpenFailure.Corrupt, "Protected directory state is corrupt.", exception); }
        finally { gate.Release(); }
    }

    public async ValueTask<AccountDirectoryStoreWriteResult> CompareExchangeAsync(ulong? expectedRevision,
        AccountDirectoryStateSnapshot replacement, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); ValidateSnapshotScope(replacement);
            var db = GetConnection();
            using var transaction = db.BeginTransaction(deferred: false);
            var current = ReadSnapshot(db, transaction);
            if (current?.Revision != expectedRevision)
                return new(AccountDirectoryStoreWriteDisposition.Conflict, AccountDirectoryStateCloner.Clone(current));
            var requiredRevision = expectedRevision is null ? 1UL : checked(expectedRevision.Value + 1);
            if (replacement.Revision != requiredRevision)
                throw new InvalidOperationException("Replacement revision must be the next CAS revision.");
            WriteSnapshot(db, transaction, expectedRevision, replacement);
            AccountDirectoryStateStoreTestHooks.Hit(AccountDirectoryStoreFailpoint.BeforeCommit);
            transaction.Commit();
            return new(AccountDirectoryStoreWriteDisposition.Applied, AccountDirectoryStateCloner.Clone(replacement));
        }
        catch (AccountDirectoryStoreInjectedCrashException) { throw; }
        catch (AccountDirectoryStoreOpenException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or ArgumentException
            or InvalidOperationException or OverflowException)
        { throw Failure(AccountDirectoryStoreOpenFailure.Corrupt, "Atomic protected directory update failed.", exception); }
        finally { gate.Release(); }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        gate.Wait();
        try { connection?.Dispose(); connection = null; CryptographicOperations.ZeroMemory(key); }
        finally { gate.Release(); }
    }

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(connectionString);
        try
        {
            db.Open();
            var result = SQLitePCL.raw.sqlite3_key(db.Handle, key);
            if (result != SQLitePCL.raw.SQLITE_OK) throw new SqliteException("SQLCipher rejected the key.", result);
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
        command.CommandText = "INSERT INTO account_directory_store_meta VALUES(1,$dg,$sid,$network,$account,$generation);";
        Add(command, "$dg", U64(databaseGeneration)); Add(command, "$sid", storeInstanceId.ToArray());
        Add(command, "$network", networkId); Add(command, "$account", localAccountId);
        Add(command, "$generation", U64(localAccountGeneration)); command.ExecuteNonQuery();
        Execute(db, null, "PRAGMA wal_checkpoint(FULL);"); Validate(db);
    }

    private void Validate(SqliteConnection db)
    {
        if (ScalarLong(db, "PRAGMA application_id;") != ApplicationId)
            throw Failure(AccountDirectoryStoreOpenFailure.Corrupt, "Unexpected protected directory application ID.");
        if (ScalarLong(db, "PRAGMA user_version;") != SchemaGeneration)
            throw Failure(AccountDirectoryStoreOpenFailure.UnsupportedGeneration, "Unsupported protected directory schema generation.");
        if (!string.Equals(Convert.ToString(Scalar(db, "PRAGMA quick_check;")), "ok", StringComparison.OrdinalIgnoreCase))
            throw Failure(AccountDirectoryStoreOpenFailure.Corrupt, "Protected directory integrity check failed.");
        ValidateCipher(db);
        var actualSchemaFingerprint = HashSchemaObjects(ReadSchemaObjects(db));
        if (!CryptographicOperations.FixedTimeEquals(ExpectedSchemaFingerprint, actualSchemaFingerprint))
            throw Failure(AccountDirectoryStoreOpenFailure.Corrupt,
                "Protected directory DDL or constraints differ from the sealed generation-1 contract.");
        using var command = db.CreateCommand();
        command.CommandText = "SELECT database_generation,store_instance_id,network_id,local_account_id,local_account_generation FROM account_directory_store_meta WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read() || !Fixed((byte[])reader[0], U64(databaseGeneration))
            || !Fixed((byte[])reader[1], storeInstanceId.Span) || !Fixed((byte[])reader[2], networkId)
            || !Fixed((byte[])reader[3], localAccountId) || !Fixed((byte[])reader[4], U64(localAccountGeneration))
            || reader.Read())
            throw Failure(AccountDirectoryStoreOpenFailure.ScopeMismatch, "Protected directory store scope differs from the requested account/network generation.");
        var snapshot = ReadSnapshot(db, null); if (snapshot is not null) ValidateSnapshotScope(snapshot);
    }

    private AccountDirectoryStateSnapshot? ReadSnapshot(SqliteConnection db, SqliteTransaction? transaction)
    {
        using var head = db.CreateCommand(); head.Transaction = transaction;
        head.CommandText = "SELECT state_revision,fork_latched,exact_adh1,adh1_core_hash,log_generation,tree_size FROM account_directory_head WHERE singleton=1;";
        using var reader = head.ExecuteReader(); if (!reader.Read()) return null;
        var revision = ReadU64((byte[])reader[0]); var fork = reader.GetInt32(1) == 1;
        AccountDirectoryProtectedLkgState? lkg = null;
        if (!reader.IsDBNull(2)) lkg = AccountDirectoryProtectedLkgState.RestorePersisted((byte[])reader[2],
            (byte[])reader[3], ReadU64((byte[])reader[4]), ReadU64((byte[])reader[5]));
        if (reader.Read()) throw new FormatException("Multiple protected directory heads exist.");
        reader.Close();
        var subjects = new List<AccountDirectorySubjectState>();
        using var command = db.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT leaf_key,state,refresh_reason,exact_adc1_reference,account_generation,directory_generation,boot_id,verified_at_monotonic,freshness_deadline_monotonic,authorization_id,device_id FROM account_directory_subjects ORDER BY leaf_key;";
        using var rows = command.ExecuteReader();
        while (rows.Read()) subjects.Add(new(AccountDirectoryLeafKey32.FromBytes((byte[])rows[0]),
            (AccountDirectoryClientState)rows.GetInt32(1), (AccountDirectoryRefreshReason)rows.GetInt32(2),
            (byte[])rows[3], ReadU64((byte[])rows[4]), ReadU64((byte[])rows[5]), (byte[])rows[6],
            ReadU64((byte[])rows[7]), ReadU64((byte[])rows[8]),
            rows.IsDBNull(9) ? null : AccountDirectoryAuthorizationId32.FromBytes((byte[])rows[9]),
            rows.IsDBNull(10) ? null : AccountDirectoryDeviceId32.FromBytes((byte[])rows[10])));
        return new AccountDirectoryStateSnapshot(revision, lkg, fork, subjects);
    }

    private void WriteSnapshot(SqliteConnection db, SqliteTransaction transaction, ulong? expectedRevision,
        AccountDirectoryStateSnapshot snapshot)
    {
        using (var head = db.CreateCommand())
        {
            head.Transaction = transaction;
            if (expectedRevision is null)
                head.CommandText = "INSERT INTO account_directory_head VALUES(1,$revision,$fork,$adh,$hash,$generation,$tree);";
            else
            {
                head.CommandText = "UPDATE account_directory_head SET state_revision=$revision,fork_latched=$fork,exact_adh1=$adh,adh1_core_hash=$hash,log_generation=$generation,tree_size=$tree WHERE singleton=1 AND state_revision=$expected;";
                Add(head, "$expected", U64(expectedRevision.Value));
            }
            Add(head, "$revision", U64(snapshot.Revision)); Add(head, "$fork", snapshot.ForkLatched ? 1 : 0);
            Add(head, "$adh", snapshot.ProtectedLkg is null ? DBNull.Value : snapshot.ProtectedLkg.ExactAdh1.ToArray());
            Add(head, "$hash", snapshot.ProtectedLkg is null ? DBNull.Value : snapshot.ProtectedLkg.CoreHash.ToArray());
            Add(head, "$generation", snapshot.ProtectedLkg is null ? DBNull.Value : U64(snapshot.ProtectedLkg.LogGeneration));
            Add(head, "$tree", snapshot.ProtectedLkg is null ? DBNull.Value : U64(snapshot.ProtectedLkg.TreeSize));
            if (head.ExecuteNonQuery() != 1) throw new InvalidOperationException("Protected directory CAS failed.");
        }
        AccountDirectoryStateStoreTestHooks.Hit(AccountDirectoryStoreFailpoint.AfterHeadWrite);
        Execute(db, transaction, "DELETE FROM account_directory_subjects;");
        foreach (var subject in snapshot.Subjects)
        {
            using var command = db.CreateCommand(); command.Transaction = transaction;
            command.CommandText = "INSERT INTO account_directory_subjects VALUES($leaf,$state,$reason,$adc,$ag,$dg,$boot,$sample,$deadline,$authorization,$device);";
            Add(command, "$leaf", subject.LeafKey.ToArray()); Add(command, "$state", (int)subject.State);
            Add(command, "$reason", (int)subject.RefreshReason); Add(command, "$adc", subject.ExactAdc1Reference.ToArray());
            Add(command, "$ag", U64(subject.AccountGeneration)); Add(command, "$dg", U64(subject.DirectoryGeneration));
            Add(command, "$boot", subject.BootId.ToArray()); Add(command, "$sample", U64(subject.VerifiedAtMonotonic));
            Add(command, "$deadline", U64(subject.FreshnessDeadlineMonotonic));
            Add(command, "$authorization", subject.AuthorizationId is null ? DBNull.Value : subject.AuthorizationId.ToArray());
            Add(command, "$device", subject.DeviceId is null ? DBNull.Value : subject.DeviceId.ToArray()); command.ExecuteNonQuery();
        }
        AccountDirectoryStateStoreTestHooks.Hit(AccountDirectoryStoreFailpoint.AfterSubjectReplacement);
    }

    private void ValidateSnapshotScope(AccountDirectoryStateSnapshot snapshot)
    {
        if (snapshot.ProtectedLkg is null) return;
        var head = AccountDirectoryAdh1Codec.Decode(snapshot.ProtectedLkg.ExactAdh1.Span);
        if (!Fixed(head.NetworkId.Span, networkId))
            throw Failure(AccountDirectoryStoreOpenFailure.ScopeMismatch, "Protected LKG belongs to another network.");
    }

    private static void ValidateEncryptedHeader(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var header = new byte[16]; if (stream.Read(header, 0, header.Length) != header.Length) throw new FormatException("Database header is truncated.");
        if (header.AsSpan().SequenceEqual("SQLite format 3\0"u8))
            throw Failure(AccountDirectoryStoreOpenFailure.Corrupt, "Protected directory database was written without SQLCipher.");
    }

    private SqliteConnection GetConnection() => connection ?? throw new ObjectDisposedException(nameof(SqliteAccountDirectoryStateStore));
    private void ThrowIfDisposed() { if (Volatile.Read(ref disposed) != 0) throw new ObjectDisposedException(nameof(SqliteAccountDirectoryStateStore)); }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static ulong ReadU64(byte[] value) => value.Length == 8 ? BinaryPrimitives.ReadUInt64BigEndian(value) : throw new FormatException("Expected u64be.");
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static object? Scalar(SqliteConnection db, string sql) { using var command = db.CreateCommand(); command.CommandText = sql; return command.ExecuteScalar(); }
    private static long ScalarLong(SqliteConnection db, string sql) => Convert.ToInt64(Scalar(db, sql), System.Globalization.CultureInfo.InvariantCulture);
    private static void ValidateCipher(SqliteConnection db)
    {
        var version = Convert.ToString(Scalar(db, "PRAGMA cipher_version;"), System.Globalization.CultureInfo.InvariantCulture);
        if (string.IsNullOrWhiteSpace(version) || !version.StartsWith("4.", StringComparison.Ordinal))
            throw Failure(AccountDirectoryStoreOpenFailure.UnsupportedGeneration, "SQLCipher generation 4 is required.");
        using var command = db.CreateCommand(); command.CommandText = "PRAGMA cipher_integrity_check;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var result = reader.IsDBNull(0) ? string.Empty : Convert.ToString(reader.GetValue(0), System.Globalization.CultureInfo.InvariantCulture);
            if (!string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase))
                throw Failure(AccountDirectoryStoreOpenFailure.Corrupt, "SQLCipher integrity verification failed.");
        }
    }
    private static string[] ExpectedSchemaObjects() => SchemaDdl
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(statement =>
        {
            var match = Regex.Match(statement, @"^CREATE\s+TABLE\s+([a-z_]+)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (!match.Success) throw new InvalidOperationException("Sealed directory schema declaration is malformed.");
            return $"table|{match.Groups[1].Value}|{match.Groups[1].Value}|{NormalizeSql(statement)}";
        }).OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    private static string[] ReadSchemaObjects(SqliteConnection db)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type,name;";
        using var reader = command.ExecuteReader(); var result = new List<string>();
        while (reader.Read())
        {
            if (reader.IsDBNull(3)) throw Failure(AccountDirectoryStoreOpenFailure.Corrupt, "Unexpected implicit schema object.");
            result.Add($"{reader.GetString(0)}|{reader.GetString(1)}|{reader.GetString(2)}|{NormalizeSql(reader.GetString(3))}");
        }
        return result.OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    }
    private static byte[] HashSchemaObjects(IEnumerable<string> values) => SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values)));
    private static string NormalizeSql(string sql) => Regex.Replace(sql.Trim().TrimEnd(';'), @"\s+", " ");
    private static void Execute(SqliteConnection db, SqliteTransaction? transaction, string sql) { using var command = db.CreateCommand(); command.Transaction = transaction; command.CommandText = sql; command.ExecuteNonQuery(); }
    private static void Add(SqliteCommand command, string name, object value) => command.Parameters.AddWithValue(name, value);
    private static AccountDirectoryStoreOpenException Failure(AccountDirectoryStoreOpenFailure reason, string message, Exception? inner = null) => new(reason, message, inner);
}
