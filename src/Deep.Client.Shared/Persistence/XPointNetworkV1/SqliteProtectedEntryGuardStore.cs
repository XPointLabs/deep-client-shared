using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.XPointNetworkV1;

public enum EntryGuardStoreOpenFailure
{
    UnreadableOrWrongKey = 1,
    UnsupportedGeneration = 2,
    ScopeMismatch = 3,
    Corrupt = 4,
}

public sealed class EntryGuardStoreOpenException : IOException
{
    internal EntryGuardStoreOpenException(
        EntryGuardStoreOpenFailure reason,
        string message,
        Exception? inner = null) : base(message, inner) => Reason = reason;
    public EntryGuardStoreOpenFailure Reason { get; }
}

public sealed class SqliteProtectedEntryGuardStoreOptions
{
    private readonly byte[] key, networkId, localAccountId, storeInstanceId;

    public SqliteProtectedEntryGuardStoreOptions(
        string statePath,
        ReadOnlySpan<byte> encryptionKey,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> localAccountId,
        ulong localAccountGeneration,
        ulong databaseGeneration,
        ReadOnlySpan<byte> storeInstanceId,
        bool allowCreate = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        Require(encryptionKey, 32, nameof(encryptionKey));
        Require(networkId, 16, nameof(networkId));
        Require(localAccountId, 32, nameof(localAccountId));
        Require(storeInstanceId, 32, nameof(storeInstanceId));
        if (localAccountGeneration == 0) throw new ArgumentOutOfRangeException(nameof(localAccountGeneration));
        if (databaseGeneration == 0) throw new ArgumentOutOfRangeException(nameof(databaseGeneration));
        StatePath = Path.GetFullPath(statePath);
        key = encryptionKey.ToArray();
        this.networkId = networkId.ToArray();
        this.localAccountId = localAccountId.ToArray();
        this.storeInstanceId = storeInstanceId.ToArray();
        LocalAccountGeneration = localAccountGeneration;
        DatabaseGeneration = databaseGeneration;
        AllowCreate = allowCreate;
    }

    public string StatePath { get; }
    internal ReadOnlyMemory<byte> EncryptionKey => key.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> LocalAccountId => localAccountId.ToArray();
    public ulong LocalAccountGeneration { get; }
    public ulong DatabaseGeneration { get; }
    public ReadOnlyMemory<byte> StoreInstanceId => storeInstanceId.ToArray();
    public bool AllowCreate { get; }

    private static void Require(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be a nonzero {length}-byte value.", name);
    }
}

/// <summary>SQLCipher-backed CAS store for client-local ROUTE-01 entry guards.</summary>
public sealed class SqliteProtectedEntryGuardStore : IProtectedEntryGuardStore, IDisposable
{
    private const int ApplicationId = 0x58475331; // XGS1
    private const int SchemaGeneration = 1;
    private const string Schema = """
        CREATE TABLE entry_guard_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),database_generation BLOB NOT NULL CHECK(length(database_generation)=8),store_instance_id BLOB NOT NULL CHECK(length(store_instance_id)=32),network_id BLOB NOT NULL CHECK(length(network_id)=16),local_account_id BLOB NOT NULL CHECK(length(local_account_id)=32),local_account_generation BLOB NOT NULL CHECK(length(local_account_generation)=8));
        CREATE TABLE entry_guard_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision BLOB NOT NULL CHECK(length(revision)=8),exact_xgs1 BLOB NOT NULL CHECK(length(exact_xgs1) BETWEEN 168 AND 232));
        """;
    private static readonly byte[] ExpectedSchemaFingerprint =
        HashSchemaObjects(ExpectedSchemaObjects());

    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly byte[] key, networkId, accountId, instanceId;
    private readonly ulong accountGeneration, databaseGeneration;
    private readonly string path, connectionString;
    private SqliteConnection? connection;
    private int disposed;

    static SqliteProtectedEntryGuardStore() => SQLitePCL.Batteries_V2.Init();

    public SqliteProtectedEntryGuardStore(SqliteProtectedEntryGuardStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var exists = File.Exists(options.StatePath);
        if (!exists && !options.AllowCreate)
            throw Failure(EntryGuardStoreOpenFailure.UnreadableOrWrongKey, "The protected entry-guard store does not exist.");
        if (exists && new FileInfo(options.StatePath).Length == 0)
            throw Failure(EntryGuardStoreOpenFailure.Corrupt, "The protected entry-guard store is empty.");
        key = options.EncryptionKey.ToArray();
        networkId = options.NetworkId.ToArray();
        accountId = options.LocalAccountId.ToArray();
        instanceId = options.StoreInstanceId.ToArray();
        accountGeneration = options.LocalAccountGeneration;
        databaseGeneration = options.DatabaseGeneration;
        path = options.StatePath;
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();
        try
        {
            if (exists) ValidateEncryptedHeader(path);
            else
            {
                var parent = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
            }
            using (var db = Open())
            {
                if (exists) Validate(db);
                else Create(db);
            }
            ValidateEncryptedHeader(path);
            connection = Open();
        }
        catch (EntryGuardStoreOpenException) { CryptographicOperations.ZeroMemory(key); throw; }
        catch (Exception exception) when (exception is SqliteException or InvalidOperationException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(EntryGuardStoreOpenFailure.UnreadableOrWrongKey,
                "The protected entry-guard store cannot be opened with this key.", exception);
        }
        catch (Exception exception) when (exception is FormatException or InvalidDataException or ArgumentException or CryptographicException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(EntryGuardStoreOpenFailure.Corrupt,
                "The protected entry-guard store contains invalid state.", exception);
        }
    }

    public async ValueTask<EntryGuardState?> ReadAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return Read(GetConnection(), null); }
        finally { gate.Release(); }
    }

    public async ValueTask<EntryGuardStoreWriteResult> CompareExchangeAsync(
        ulong? expectedRevision,
        EntryGuardState replacement,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(replacement);
        ValidateScope(replacement);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var transaction = GetConnection().BeginTransaction(System.Data.IsolationLevel.Serializable);
            var current = Read(GetConnection(), transaction);
            if (current?.Revision != expectedRevision)
            {
                transaction.Rollback();
                return new(EntryGuardStoreWriteDisposition.Conflict, current);
            }
            var required = expectedRevision is null ? 1UL : checked(expectedRevision.Value + 1);
            if (replacement.Revision != required)
                throw new InvalidOperationException("Replacement must use the next guard-state revision.");
            var exact = EntryGuardStateCodec.Encode(replacement);
            try
            {
                using var command = GetConnection().CreateCommand();
                command.Transaction = transaction;
                command.CommandText = expectedRevision is null
                    ? "INSERT INTO entry_guard_state VALUES(1,$revision,$state);"
                    : "UPDATE entry_guard_state SET revision=$revision,exact_xgs1=$state WHERE singleton=1 AND revision=$expected;";
                Add(command, "$revision", U64(replacement.Revision));
                Add(command, "$state", exact);
                if (expectedRevision is not null) Add(command, "$expected", U64(expectedRevision.Value));
                if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Protected entry-guard CAS failed.");
                transaction.Commit();
            }
            finally { CryptographicOperations.ZeroMemory(exact); }
            return new(EntryGuardStoreWriteDisposition.Applied, EntryGuardState.Copy(replacement));
        }
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
            Execute(db, null, "PRAGMA cipher_compatibility=4; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;");
            return db;
        }
        catch { db.Dispose(); throw; }
    }

    private void Create(SqliteConnection db)
    {
        Execute(db, null, $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        Execute(db, null, Schema);
        using var command = db.CreateCommand();
        command.CommandText = "INSERT INTO entry_guard_meta VALUES(1,$database,$instance,$network,$account,$generation);";
        Add(command, "$database", U64(databaseGeneration)); Add(command, "$instance", instanceId);
        Add(command, "$network", networkId); Add(command, "$account", accountId); Add(command, "$generation", U64(accountGeneration));
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Entry-guard metadata was not created.");
        Execute(db, null, "PRAGMA wal_checkpoint(FULL);");
        Validate(db);
    }

    private void Validate(SqliteConnection db)
    {
        if (ScalarLong(db, "PRAGMA application_id;") != ApplicationId)
            throw Failure(EntryGuardStoreOpenFailure.Corrupt, "Unexpected entry-guard application ID.");
        if (ScalarLong(db, "PRAGMA user_version;") != SchemaGeneration)
            throw Failure(EntryGuardStoreOpenFailure.UnsupportedGeneration, "Unsupported entry-guard schema generation.");
        ValidateCipher(db);
        var actualSchemaFingerprint = HashSchemaObjects(ReadSchemaObjects(db));
        if (!CryptographicOperations.FixedTimeEquals(
                ExpectedSchemaFingerprint,
                actualSchemaFingerprint))
            throw Failure(EntryGuardStoreOpenFailure.Corrupt,
                "Protected entry-guard DDL differs from the sealed generation-1 contract.");
        if (!string.Equals(Convert.ToString(Scalar(db, "PRAGMA quick_check;")), "ok", StringComparison.OrdinalIgnoreCase))
            throw Failure(EntryGuardStoreOpenFailure.Corrupt, "Entry-guard database integrity check failed.");
        using var command = db.CreateCommand();
        command.CommandText = "SELECT database_generation,store_instance_id,network_id,local_account_id,local_account_generation FROM entry_guard_meta WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read() || !Fixed((byte[])reader[0], U64(databaseGeneration)) ||
            !Fixed((byte[])reader[1], instanceId) || !Fixed((byte[])reader[2], networkId) ||
            !Fixed((byte[])reader[3], accountId) || !Fixed((byte[])reader[4], U64(accountGeneration)) || reader.Read())
            throw Failure(EntryGuardStoreOpenFailure.ScopeMismatch, "Entry-guard store scope differs from the requested account/network generation.");
        var state = Read(db, null);
        if (state is not null) ValidateScope(state);
    }

    private EntryGuardState? Read(SqliteConnection db, SqliteTransaction? transaction)
    {
        using var command = db.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT revision,exact_xgs1 FROM entry_guard_state WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var revision = ReadU64((byte[])reader[0]);
        var state = EntryGuardStateCodec.Decode((byte[])reader[1]);
        if (state.Revision != revision || reader.Read()) throw new FormatException("Entry-guard row revision/cardinality is invalid.");
        ValidateScope(state);
        return state;
    }

    private void ValidateScope(EntryGuardState state)
    {
        if (!Fixed(state.NetworkId.Span, networkId))
            throw Failure(EntryGuardStoreOpenFailure.ScopeMismatch, "Entry-guard state belongs to another network.");
    }

    private static void ValidateEncryptedHeader(string statePath)
    {
        using var stream = new FileStream(statePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        Span<byte> header = stackalloc byte[16];
        if (stream.Read(header) != header.Length) throw Failure(EntryGuardStoreOpenFailure.Corrupt, "Entry-guard database header is truncated.");
        if (header.SequenceEqual("SQLite format 3\0"u8)) throw Failure(EntryGuardStoreOpenFailure.Corrupt, "Entry-guard database is plaintext.");
    }

    private SqliteConnection GetConnection() => connection ?? throw new ObjectDisposedException(nameof(SqliteProtectedEntryGuardStore));
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static ulong ReadU64(byte[] value) => value.Length == 8 ? BinaryPrimitives.ReadUInt64BigEndian(value) : throw new FormatException("Expected u64be.");
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static void Add(SqliteCommand command, string name, object value) => command.Parameters.AddWithValue(name, value);
    private static void Execute(SqliteConnection db, SqliteTransaction? transaction, string sql) { using var command = db.CreateCommand(); command.Transaction = transaction; command.CommandText = sql; command.ExecuteNonQuery(); }
    private static object? Scalar(SqliteConnection db, string sql) { using var command = db.CreateCommand(); command.CommandText = sql; return command.ExecuteScalar(); }
    private static long ScalarLong(SqliteConnection db, string sql) => Convert.ToInt64(Scalar(db, sql));
    private static void ValidateCipher(SqliteConnection db)
    {
        var version = Convert.ToString(Scalar(db, "PRAGMA cipher_version;"),
            System.Globalization.CultureInfo.InvariantCulture);
        if (string.IsNullOrWhiteSpace(version) || !version.StartsWith("4.", StringComparison.Ordinal))
            throw Failure(EntryGuardStoreOpenFailure.UnsupportedGeneration,
                "SQLCipher generation 4 is required.");
        using var command = db.CreateCommand();
        command.CommandText = "PRAGMA cipher_integrity_check;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var result = reader.IsDBNull(0) ? string.Empty : Convert.ToString(
                reader.GetValue(0), System.Globalization.CultureInfo.InvariantCulture);
            if (!string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase))
                throw Failure(EntryGuardStoreOpenFailure.Corrupt,
                    "SQLCipher entry-guard integrity verification failed.");
        }
    }
    private static string[] ExpectedSchemaObjects() => Schema
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(statement =>
        {
            var match = Regex.Match(statement, @"^CREATE\s+TABLE\s+([a-z_]+)",
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (!match.Success)
                throw new InvalidOperationException("Sealed entry-guard schema declaration is malformed.");
            return $"table|{match.Groups[1].Value}|{match.Groups[1].Value}|{NormalizeSql(statement)}";
        })
        .OrderBy(static value => value, StringComparer.Ordinal)
        .ToArray();
    private static string[] ReadSchemaObjects(SqliteConnection db)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type,name;";
        using var reader = command.ExecuteReader();
        var result = new List<string>();
        while (reader.Read())
        {
            if (reader.IsDBNull(3))
                throw Failure(EntryGuardStoreOpenFailure.Corrupt,
                    "Unexpected implicit entry-guard schema object.");
            result.Add($"{reader.GetString(0)}|{reader.GetString(1)}|{reader.GetString(2)}|{NormalizeSql(reader.GetString(3))}");
        }
        return result.OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    }
    private static byte[] HashSchemaObjects(IEnumerable<string> values) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values)));
    private static string NormalizeSql(string sql) =>
        Regex.Replace(sql.Trim().TrimEnd(';'), @"\s+", " ");
    private static EntryGuardStoreOpenException Failure(EntryGuardStoreOpenFailure reason, string message, Exception? inner = null) => new(reason, message, inner);
}
