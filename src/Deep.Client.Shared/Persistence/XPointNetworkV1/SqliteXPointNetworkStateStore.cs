using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.XPointNetworkV1;

public enum XPointNetworkStoreOpenFailure
{
    UnreadableOrWrongKey = 1,
    UnsupportedGeneration = 2,
    ScopeMismatch = 3,
    Corrupt = 4,
}

public sealed class XPointNetworkStoreOpenException : IOException
{
    internal XPointNetworkStoreOpenException(
        XPointNetworkStoreOpenFailure reason,
        string message,
        Exception? inner = null) : base(message, inner) => Reason = reason;

    public XPointNetworkStoreOpenFailure Reason { get; }
}

public sealed class SqliteXPointNetworkStateStoreOptions
{
    private readonly byte[] encryptionKey;
    private readonly byte[] networkId;
    private readonly byte[] localAccountId;
    private readonly byte[] storeInstanceId;

    public SqliteXPointNetworkStateStoreOptions(
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
        RequireNonzero(encryptionKey, 32, nameof(encryptionKey));
        RequireNonzero(networkId, 16, nameof(networkId));
        RequireNonzero(localAccountId, 32, nameof(localAccountId));
        RequireNonzero(storeInstanceId, 32, nameof(storeInstanceId));
        if (localAccountGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(localAccountGeneration));
        if (databaseGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(databaseGeneration));

        StatePath = Path.GetFullPath(statePath);
        this.encryptionKey = encryptionKey.ToArray();
        this.networkId = networkId.ToArray();
        this.localAccountId = localAccountId.ToArray();
        this.storeInstanceId = storeInstanceId.ToArray();
        LocalAccountGeneration = localAccountGeneration;
        DatabaseGeneration = databaseGeneration;
        AllowCreate = allowCreate;
    }

    public string StatePath { get; }
    internal ReadOnlyMemory<byte> EncryptionKey => encryptionKey.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> LocalAccountId => localAccountId.ToArray();
    public ulong LocalAccountGeneration { get; }
    public ulong DatabaseGeneration { get; }
    public ReadOnlyMemory<byte> StoreInstanceId => storeInstanceId.ToArray();
    public bool AllowCreate { get; }

    private static void RequireNonzero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} nonzero bytes.", name);
    }
}

/// <summary>
/// SQLCipher generation-1 persistence for the authenticated XPoint network
/// rollback floor. The database is local protected state and never a trust source.
/// </summary>
public sealed class SqliteXPointNetworkStateStore : IXPointNetworkStateStore, IDisposable
{
    private const int ApplicationId = 0x584C5331; // XLS1
    private const int SchemaGeneration = 1;
    private const int ExactXlk1Bytes = 265;
    private const string SchemaDdl = """
        CREATE TABLE xpoint_network_store_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), database_generation BLOB NOT NULL CHECK(length(database_generation)=8), store_instance_id BLOB NOT NULL CHECK(length(store_instance_id)=32), network_id BLOB NOT NULL CHECK(length(network_id)=16), local_account_id BLOB NOT NULL CHECK(length(local_account_id)=32), local_account_generation BLOB NOT NULL CHECK(length(local_account_generation)=8));
        CREATE TABLE xpoint_network_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), state_revision BLOB NOT NULL CHECK(length(state_revision)=8), exact_xlk1 BLOB NOT NULL CHECK(length(exact_xlk1)=265), fork_latched INTEGER NOT NULL CHECK(fork_latched IN (0,1)));
        """;
    private static readonly byte[] ExpectedSchemaFingerprint =
        HashSchemaObjects(ExpectedSchemaObjects());

    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly byte[] key;
    private readonly byte[] networkId;
    private readonly byte[] localAccountId;
    private readonly byte[] storeInstanceId;
    private readonly ulong localAccountGeneration;
    private readonly ulong databaseGeneration;
    private readonly string statePath;
    private readonly string connectionString;
    private SqliteConnection? connection;
    private int disposed;

    static SqliteXPointNetworkStateStore() => SQLitePCL.Batteries_V2.Init();

    public SqliteXPointNetworkStateStore(SqliteXPointNetworkStateStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var exists = File.Exists(options.StatePath);
        if (!exists && !options.AllowCreate)
            throw Failure(
                XPointNetworkStoreOpenFailure.UnreadableOrWrongKey,
                "The protected XPoint network store does not exist.");
        if (exists && new FileInfo(options.StatePath).Length == 0)
            throw Failure(
                XPointNetworkStoreOpenFailure.Corrupt,
                "The protected XPoint network store is empty.");

        key = options.EncryptionKey.ToArray();
        networkId = options.NetworkId.ToArray();
        localAccountId = options.LocalAccountId.ToArray();
        storeInstanceId = options.StoreInstanceId.ToArray();
        localAccountGeneration = options.LocalAccountGeneration;
        databaseGeneration = options.DatabaseGeneration;
        statePath = options.StatePath;
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();

        try
        {
            if (exists)
                ValidateEncryptedHeader(statePath);
            else
            {
                var parent = Path.GetDirectoryName(statePath);
                if (!string.IsNullOrEmpty(parent))
                    Directory.CreateDirectory(parent);
            }

            using (var opened = Open())
            {
                if (exists)
                    Validate(opened);
                else
                    Create(opened);
            }

            ValidateEncryptedHeader(statePath);
            connection = Open();
        }
        catch (XPointNetworkStoreOpenException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        catch (Exception exception) when (
            exception is FormatException or ArgumentException or OverflowException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(
                XPointNetworkStoreOpenFailure.Corrupt,
                "The protected XPoint network store contains invalid state.",
                exception);
        }
        catch (Exception exception) when (
            exception is SqliteException or InvalidOperationException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(
                XPointNetworkStoreOpenFailure.UnreadableOrWrongKey,
                "The protected XPoint network store cannot be opened with this key.",
                exception);
        }
    }

    internal string ConnectionString => connectionString;
    internal bool IsKeyZeroedForTesting => key.All(static value => value == 0);

    public async ValueTask<XPointNetworkStateSnapshot?> ReadAsync(
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return XPointNetworkStateCloner.Clone(ReadSnapshot(GetConnection(), null));
        }
        catch (XPointNetworkStoreOpenException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SqliteException or FormatException or ArgumentException or OverflowException)
        {
            throw Failure(
                XPointNetworkStoreOpenFailure.Corrupt,
                "Protected XPoint network state is corrupt.",
                exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<XPointNetworkStoreWriteResult> CompareExchangeAsync(
        ulong? expectedRevision,
        XPointNetworkStateSnapshot replacement,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            ValidateSnapshotScope(replacement);
            var db = GetConnection();
            using var transaction = db.BeginTransaction(deferred: false);
            var current = ReadSnapshot(db, transaction);
            if (current?.Revision != expectedRevision)
                return new(
                    XPointNetworkStoreWriteDisposition.Conflict,
                    XPointNetworkStateCloner.Clone(current));

            var requiredRevision = expectedRevision is null
                ? 1UL
                : checked(expectedRevision.Value + 1);
            if (replacement.Revision != requiredRevision)
                throw new InvalidOperationException(
                    "Replacement revision must be the next XPoint network CAS revision.");
            if (current?.ForkLatched == true && !replacement.ForkLatched)
                throw new InvalidOperationException(
                    "A protected XPoint network fork latch cannot be cleared.");

            WriteSnapshot(db, transaction, expectedRevision, replacement);
            transaction.Commit();
            return new(
                XPointNetworkStoreWriteDisposition.Applied,
                XPointNetworkStateCloner.Clone(replacement));
        }
        catch (XPointNetworkStoreOpenException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SqliteException or FormatException or ArgumentException)
        {
            throw Failure(
                XPointNetworkStoreOpenFailure.Corrupt,
                "Atomic protected XPoint network update failed.",
                exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        gate.Wait();
        try
        {
            connection?.Dispose();
            connection = null;
            CryptographicOperations.ZeroMemory(key);
        }
        finally
        {
            gate.Release();
        }
    }

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(connectionString);
        try
        {
            db.Open();
            var result = SQLitePCL.raw.sqlite3_key(db.Handle, key);
            if (result != SQLitePCL.raw.SQLITE_OK)
                throw new SqliteException("SQLCipher rejected the key.", result);
            Execute(db, null,
                "PRAGMA cipher_compatibility=4; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;");
            return db;
        }
        catch
        {
            db.Dispose();
            throw;
        }
    }

    private void Create(SqliteConnection db)
    {
        Execute(db, null,
            $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        Execute(db, null, SchemaDdl);
        using var command = db.CreateCommand();
        command.CommandText =
            "INSERT INTO xpoint_network_store_meta VALUES(1,$database,$store,$network,$account,$account_generation);";
        Add(command, "$database", U64(databaseGeneration));
        Add(command, "$store", storeInstanceId);
        Add(command, "$network", networkId);
        Add(command, "$account", localAccountId);
        Add(command, "$account_generation", U64(localAccountGeneration));
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("Protected XPoint network metadata was not created.");
        Execute(db, null, "PRAGMA wal_checkpoint(FULL);");
        Validate(db);
    }

    private void Validate(SqliteConnection db)
    {
        if (ScalarLong(db, "PRAGMA application_id;") != ApplicationId)
            throw Failure(
                XPointNetworkStoreOpenFailure.Corrupt,
                "Unexpected protected XPoint network application ID.");
        if (ScalarLong(db, "PRAGMA user_version;") != SchemaGeneration)
            throw Failure(
                XPointNetworkStoreOpenFailure.UnsupportedGeneration,
                "Unsupported protected XPoint network schema generation.");
        if (!string.Equals(
                Convert.ToString(Scalar(db, "PRAGMA quick_check;")),
                "ok",
                StringComparison.OrdinalIgnoreCase))
            throw Failure(
                XPointNetworkStoreOpenFailure.Corrupt,
                "Protected XPoint network integrity check failed.");

        ValidateCipher(db);
        var actualSchemaFingerprint = HashSchemaObjects(ReadSchemaObjects(db));
        if (!CryptographicOperations.FixedTimeEquals(
                ExpectedSchemaFingerprint,
                actualSchemaFingerprint))
            throw Failure(
                XPointNetworkStoreOpenFailure.Corrupt,
                "Protected XPoint network DDL differs from the sealed generation-1 contract.");

        using var command = db.CreateCommand();
        command.CommandText =
            "SELECT database_generation,store_instance_id,network_id,local_account_id,local_account_generation FROM xpoint_network_store_meta WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read()
            || !Fixed((byte[])reader[0], U64(databaseGeneration))
            || !Fixed((byte[])reader[1], storeInstanceId)
            || !Fixed((byte[])reader[2], networkId)
            || !Fixed((byte[])reader[3], localAccountId)
            || !Fixed((byte[])reader[4], U64(localAccountGeneration))
            || reader.Read())
            throw Failure(
                XPointNetworkStoreOpenFailure.ScopeMismatch,
                "Protected XPoint network store scope differs from the requested account/network generation.");

        var snapshot = ReadSnapshot(db, null);
        if (snapshot is not null)
            ValidateSnapshotScope(snapshot);
    }

    private XPointNetworkStateSnapshot? ReadSnapshot(
        SqliteConnection db,
        SqliteTransaction? transaction)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT state_revision,exact_xlk1,fork_latched FROM xpoint_network_state WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return null;
        var revision = ReadU64((byte[])reader[0]);
        var exactXlk1 = (byte[])reader[1];
        if (exactXlk1.Length != ExactXlk1Bytes)
            throw new FormatException("Protected XPoint network XLK1 length is invalid.");
        var forkValue = reader.GetInt32(2);
        if (forkValue is not (0 or 1))
            throw new FormatException("Protected XPoint network fork latch is invalid.");
        var snapshot = new XPointNetworkStateSnapshot(
            revision,
            XPointNetworkProtectedLkgCodec.Decode(exactXlk1),
            forkValue == 1);
        if (reader.Read())
            throw new FormatException("Multiple protected XPoint network states exist.");
        return snapshot;
    }

    private static void WriteSnapshot(
        SqliteConnection db,
        SqliteTransaction transaction,
        ulong? expectedRevision,
        XPointNetworkStateSnapshot snapshot)
    {
        var exactXlk1 = XPointNetworkProtectedLkgCodec.Encode(snapshot.ProtectedLkg);
        try
        {
            using var command = db.CreateCommand();
            command.Transaction = transaction;
            if (expectedRevision is null)
            {
                command.CommandText =
                    "INSERT INTO xpoint_network_state VALUES(1,$revision,$xlk1,$fork);";
            }
            else
            {
                command.CommandText =
                    "UPDATE xpoint_network_state SET state_revision=$revision,exact_xlk1=$xlk1,fork_latched=$fork WHERE singleton=1 AND state_revision=$expected;";
                Add(command, "$expected", U64(expectedRevision.Value));
            }
            Add(command, "$revision", U64(snapshot.Revision));
            Add(command, "$xlk1", exactXlk1);
            Add(command, "$fork", snapshot.ForkLatched ? 1 : 0);
            if (command.ExecuteNonQuery() != 1)
                throw new InvalidOperationException("Protected XPoint network CAS failed.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactXlk1);
        }
    }

    private void ValidateSnapshotScope(XPointNetworkStateSnapshot snapshot)
    {
        if (!Fixed(snapshot.ProtectedLkg.NetworkId.Span, networkId))
            throw Failure(
                XPointNetworkStoreOpenFailure.ScopeMismatch,
                "Protected XPoint network LKG belongs to another network.");
    }

    private static void ValidateEncryptedHeader(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        var header = new byte[16];
        if (stream.Read(header, 0, header.Length) != header.Length)
            throw Failure(
                XPointNetworkStoreOpenFailure.Corrupt,
                "Protected XPoint network database header is truncated.");
        if (header.AsSpan().SequenceEqual("SQLite format 3\0"u8))
            throw Failure(
                XPointNetworkStoreOpenFailure.Corrupt,
                "Protected XPoint network database was written without SQLCipher.");
    }

    private SqliteConnection GetConnection() => connection
        ?? throw new ObjectDisposedException(nameof(SqliteXPointNetworkStateStore));

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
            throw new ObjectDisposedException(nameof(SqliteXPointNetworkStateStore));
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static ulong ReadU64(byte[] value) => value.Length == 8
        ? BinaryPrimitives.ReadUInt64BigEndian(value)
        : throw new FormatException("Expected exact u64be.");

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static object? Scalar(SqliteConnection db, string sql)
    {
        using var command = db.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static long ScalarLong(SqliteConnection db, string sql) =>
        Convert.ToInt64(Scalar(db, sql), System.Globalization.CultureInfo.InvariantCulture);

    private static void ValidateCipher(SqliteConnection db)
    {
        var version = Convert.ToString(
            Scalar(db, "PRAGMA cipher_version;"),
            System.Globalization.CultureInfo.InvariantCulture);
        if (string.IsNullOrWhiteSpace(version)
            || !version.StartsWith("4.", StringComparison.Ordinal))
            throw Failure(
                XPointNetworkStoreOpenFailure.UnsupportedGeneration,
                "SQLCipher generation 4 is required.");

        using var command = db.CreateCommand();
        command.CommandText = "PRAGMA cipher_integrity_check;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var result = reader.IsDBNull(0)
                ? string.Empty
                : Convert.ToString(
                    reader.GetValue(0),
                    System.Globalization.CultureInfo.InvariantCulture);
            if (!string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase))
                throw Failure(
                    XPointNetworkStoreOpenFailure.Corrupt,
                    "SQLCipher integrity verification failed.");
        }
    }

    private static string[] ExpectedSchemaObjects() => SchemaDdl
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(statement =>
        {
            var match = Regex.Match(
                statement,
                @"^CREATE\s+TABLE\s+([a-z_]+)",
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (!match.Success)
                throw new InvalidOperationException("Sealed XPoint network schema declaration is malformed.");
            return $"table|{match.Groups[1].Value}|{match.Groups[1].Value}|{NormalizeSql(statement)}";
        })
        .OrderBy(static value => value, StringComparer.Ordinal)
        .ToArray();

    private static string[] ReadSchemaObjects(SqliteConnection db)
    {
        using var command = db.CreateCommand();
        command.CommandText =
            "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type,name;";
        using var reader = command.ExecuteReader();
        var result = new List<string>();
        while (reader.Read())
        {
            if (reader.IsDBNull(3))
                throw Failure(
                    XPointNetworkStoreOpenFailure.Corrupt,
                    "Unexpected implicit XPoint network schema object.");
            result.Add(
                $"{reader.GetString(0)}|{reader.GetString(1)}|{reader.GetString(2)}|{NormalizeSql(reader.GetString(3))}");
        }
        return result.OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    }

    private static byte[] HashSchemaObjects(IEnumerable<string> values) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values)));

    private static string NormalizeSql(string sql) =>
        Regex.Replace(sql.Trim().TrimEnd(';'), @"\s+", " ");

    private static void Execute(
        SqliteConnection db,
        SqliteTransaction? transaction,
        string sql)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static void Add(SqliteCommand command, string name, object value) =>
        command.Parameters.AddWithValue(name, value);

    private static XPointNetworkStoreOpenException Failure(
        XPointNetworkStoreOpenFailure reason,
        string message,
        Exception? inner = null) => new(reason, message, inner);
}
