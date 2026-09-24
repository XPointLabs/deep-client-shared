using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// An isolated SQLCipher generation for a verified DID2 account. The caller
/// must hold the V2 account lease. This owns only the immutable local account
/// projection and empty durable roots; it is not yet the MAUI account store.
/// </summary>
internal static class SqliteDeepIdV2AccountGeneration
{
    private const string KeySlot = "deep.store.v2.sql-generation";
    private const int KeyRecordLength = 120;
    private const int ApplicationId = 0x44535632; // DSV2
    private const int SchemaVersion = 2;
    private const string AccountTable = "CREATE TABLE local_account (singleton INTEGER PRIMARY KEY CHECK(singleton=1), network_id BLOB NOT NULL CHECK(length(network_id)=16), account_id BLOB NOT NULL CHECK(length(account_id)=32), did2_hash BLOB NOT NULL CHECK(length(did2_hash)=32), dab2_hash BLOB NOT NULL CHECK(length(dab2_hash)=32), deep_id_text TEXT NOT NULL);";
    private const string DeviceTable = "CREATE TABLE local_device (singleton INTEGER PRIMARY KEY CHECK(singleton=1), device_id BLOB NOT NULL CHECK(length(device_id)=32), dpd1_hash BLOB NOT NULL CHECK(length(dpd1_hash)=32), dmd1_hash BLOB NOT NULL CHECK(length(dmd1_hash)=32));";
    private const string ProfileTable = "CREATE TABLE local_profile (singleton INTEGER PRIMARY KEY CHECK(singleton=1), display_name TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>=1));";
    private const string IdentityTable = "CREATE TABLE store_identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), database_instance_id BLOB NOT NULL CHECK(length(database_instance_id)=32), cipher_generation INTEGER NOT NULL CHECK(cipher_generation=2));";
    private const string LkgTable = "CREATE TABLE protected_lkg_root (root_kind INTEGER PRIMARY KEY, revision INTEGER NOT NULL, payload BLOB NOT NULL);";
    private const string OutboxTable = "CREATE TABLE outbox_root (root_kind INTEGER PRIMARY KEY, revision INTEGER NOT NULL, payload BLOB NOT NULL);";
    private const string InboxTable = "CREATE TABLE inbox_root (root_kind INTEGER PRIMARY KEY, revision INTEGER NOT NULL, payload BLOB NOT NULL);";
    private const string EventTable = "CREATE TABLE security_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at INTEGER NOT NULL, event_kind INTEGER NOT NULL, payload BLOB NOT NULL);";
    private static readonly (string Name, string Sql)[] Schema =
    [
        ("local_account", AccountTable), ("local_device", DeviceTable),
        ("local_profile", ProfileTable),
        ("store_identity", IdentityTable), ("protected_lkg_root", LkgTable),
        ("outbox_root", OutboxTable), ("inbox_root", InboxTable),
        ("security_events", EventTable)
    ];

    static SqliteDeepIdV2AccountGeneration() => SQLitePCL.Batteries_V2.Init();

    internal static void DeleteArtifactsAfterExplicitReset(string statePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        var path = Path.GetFullPath(statePath);
        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            throw new ArgumentException("An existing private V2 SQL directory is required.",
                nameof(statePath));
        foreach (var artifact in new[] { path, path + ".pending",
                     path + "-journal", path + "-wal", path + "-shm",
                     path + ".pending-journal", path + ".pending-wal",
                     path + ".pending-shm" })
            File.Delete(artifact);
    }

    internal static async Task EnsureAsync(string statePath,
        IDeepSecureStorage storage, ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> accountId, string displayName,
        VerifiedDeepIdV2LocalGenesis genesis, bool allowCreate,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(genesis);
        if (networkId.Length != 16 || accountId.Length != 32 ||
            networkId.Span.IndexOfAnyExcept((byte)0) < 0 ||
            accountId.Span.IndexOfAnyExcept((byte)0) < 0 ||
            !genesis.PublicEvidence.Binding.Identity.Account.Certificate.NetworkId
                .Span.SequenceEqual(networkId.Span) ||
            !genesis.PublicEvidence.Binding.Identity.Account.DeepAccountIdHash
                .Span.SequenceEqual(accountId.Span))
            throw new CryptographicException("The DID2 SQL projection has a different account scope.");
        if (Deep.Client.Shared.Domain.DeepDisplayName.Normalize(displayName,
                nameof(displayName)) != displayName)
            throw new ArgumentException("The DID2 SQL display name must be canonical.",
                nameof(displayName));

        var path = Path.GetFullPath(statePath);
        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            throw new ArgumentException("An existing private V2 SQL directory is required.",
                nameof(statePath));
        await using var bootstrapLock = await AcquireLockAsync(
            path + ".bootstrap.lock", cancellationToken).ConfigureAwait(false);
        var pendingPath = path + ".pending";
        using var published = await storage.ReadOwnedAsync(
            "deep.store.v2.current-account", cancellationToken)
            .ConfigureAwait(false);
        if (allowCreate && published is not null)
            throw new InvalidOperationException(
                "A DID2 SQL generation cannot be created after account publication.");
        if (!File.Exists(path) && (File.Exists(path + "-wal") ||
            File.Exists(path + "-shm")))
            throw new InvalidDataException("The DID2 SQL file family is incomplete.");

        using var existing = await storage.ReadOwnedAsync(KeySlot,
            cancellationToken).ConfigureAwait(false);
        if (existing is null && (File.Exists(path) || File.Exists(pendingPath)))
            throw new InvalidDataException("DID2 SQL exists without its protected key record.");
        if (existing is null && !allowCreate)
            throw new InvalidOperationException("DID2 SQL generation does not exist.");
        var record = existing is null
            ? NewRecord(networkId.Span, accountId.Span)
            : existing.Use(value => value.ToArray());
        try
        {
            ValidateRecord(record, networkId.Span, accountId.Span);
            if (existing is null)
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(KeySlot, record)],
                    cancellationToken).ConfigureAwait(false);
            var key = record.AsSpan(88, 32).ToArray();
            try
            {
                var instanceId = record.AsSpan(56, 32).ToArray();
                var binding = AccountBinding.From(genesis, accountId.Span,
                    networkId.Span, displayName, instanceId);
                if (!File.Exists(path))
                {
                    if (!allowCreate)
                        throw new InvalidOperationException(
                            "DID2 SQL is missing after current-account publication.");
                    if (File.Exists(pendingPath))
                    {
                        try { ValidateDatabase(pendingPath, key, binding); }
                        catch (Exception exception) when (exception is
                            InvalidDataException or SqliteException)
                        {
                            // No account index exists yet. The pending file is
                            // only an unpublished projection with empty roots;
                            // recreate it from the same protected key/identity.
                            DeletePendingArtifacts(pendingPath);
                        }
                    }
                    if (!File.Exists(pendingPath))
                    {
                        DeletePendingArtifacts(pendingPath);
                        CreateDatabase(pendingPath, key, binding);
                    }
                    ValidateDatabase(pendingPath, key, binding);
                    File.Move(pendingPath, path);
                }
                if (File.Exists(pendingPath))
                    throw new InvalidDataException(
                        "A stale DID2 SQL pending file exists beside the current database.");
                ValidateDatabase(path, key, binding);
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        }
        finally { CryptographicOperations.ZeroMemory(record); }
    }

    private static void DeletePendingArtifacts(string pendingPath)
    {
        foreach (var artifact in new[] { pendingPath, pendingPath + "-journal",
                     pendingPath + "-wal", pendingPath + "-shm" })
            File.Delete(artifact);
    }

    private static byte[] NewRecord(ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId)
    {
        var result = new byte[KeyRecordLength];
        "DSK2"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 2);
        networkId.CopyTo(result.AsSpan(8));
        accountId.CopyTo(result.AsSpan(24));
        RandomNumberGenerator.Fill(result.AsSpan(56, 64));
        return result;
    }

    private static void ValidateRecord(ReadOnlySpan<byte> record,
        ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> accountId)
    {
        if (record.Length != KeyRecordLength ||
            !record[..4].SequenceEqual("DSK2"u8) ||
            BinaryPrimitives.ReadUInt16BigEndian(record[4..]) != 2 ||
            record.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            !CryptographicOperations.FixedTimeEquals(record.Slice(8, 16), networkId) ||
            !CryptographicOperations.FixedTimeEquals(record.Slice(24, 32), accountId) ||
            record.Slice(56, 32).IndexOfAnyExcept((byte)0) < 0 ||
            record.Slice(88, 32).IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("The DID2 SQL key record is malformed or out of scope.");
    }

    private static async Task<FileStream> AcquireLockAsync(string path,
        CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(path, FileMode.OpenOrCreate,
                    FileAccess.ReadWrite, FileShare.None, 1,
                    FileOptions.Asynchronous);
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                await Task.Delay(50, cancellationToken).ConfigureAwait(false);
            }
            catch (IOException exception)
            {
                throw new TimeoutException("DID2 SQL bootstrap lease timed out.", exception);
            }
        }
    }

    private static void CreateDatabase(string path, ReadOnlySpan<byte> key,
        AccountBinding binding)
    {
        using var connection = OpenConnection(path, key, create: true);
        using var transaction = connection.BeginTransaction();
        foreach (var (_, sql) in Schema)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaVersion};";
            command.ExecuteNonQuery();
        }
        InsertBinding(connection, transaction, binding);
        transaction.Commit();
    }

    private static void InsertBinding(SqliteConnection connection,
        SqliteTransaction transaction, AccountBinding binding)
    {
        using var account = connection.CreateCommand();
        account.Transaction = transaction;
        account.CommandText = "INSERT INTO local_account VALUES(1,$network,$account,$did,$dab,$text);";
        account.Parameters.AddWithValue("$network", binding.NetworkId);
        account.Parameters.AddWithValue("$account", binding.AccountId);
        account.Parameters.AddWithValue("$did", binding.Did2Hash);
        account.Parameters.AddWithValue("$dab", binding.Dab2Hash);
        account.Parameters.AddWithValue("$text", binding.DeepIdText);
        account.ExecuteNonQuery();
        using var device = connection.CreateCommand();
        device.Transaction = transaction;
        device.CommandText = "INSERT INTO local_device VALUES(1,$id,$dpd,$dmd);";
        device.Parameters.AddWithValue("$id", binding.DeviceId);
        device.Parameters.AddWithValue("$dpd", binding.Dpd1Hash);
        device.Parameters.AddWithValue("$dmd", binding.Dmd1Hash);
        device.ExecuteNonQuery();
        using var profile = connection.CreateCommand();
        profile.Transaction = transaction;
        profile.CommandText = "INSERT INTO local_profile VALUES(1,$name,1);";
        profile.Parameters.AddWithValue("$name", binding.DisplayName);
        profile.ExecuteNonQuery();
        using var identity = connection.CreateCommand();
        identity.Transaction = transaction;
        identity.CommandText = "INSERT INTO store_identity VALUES(1,$instance,2);";
        identity.Parameters.AddWithValue("$instance", binding.InstanceId);
        identity.ExecuteNonQuery();
    }

    private static void ValidateDatabase(string path, ReadOnlySpan<byte> key,
        AccountBinding binding)
    {
        if (new FileInfo(path).Length == 0)
            throw new InvalidDataException("The DID2 SQL database is empty.");
        using var connection = OpenConnection(path, key, create: false);
        using (var cipher = connection.CreateCommand())
        {
            cipher.CommandText = "PRAGMA cipher_version;";
            var version = Convert.ToString(cipher.ExecuteScalar(),
                System.Globalization.CultureInfo.InvariantCulture);
            if (version is null || !version.StartsWith("4.", StringComparison.Ordinal))
                throw new InvalidDataException("SQLCipher 4 is required for DID2 state.");
        }
        using (var integrity = connection.CreateCommand())
        {
            integrity.CommandText = "PRAGMA cipher_integrity_check;";
            using var reader = integrity.ExecuteReader();
            if (reader.Read())
                throw new InvalidDataException("DID2 SQLCipher integrity failed.");
        }
        if (Pragma(connection, "application_id") != ApplicationId ||
            Pragma(connection, "user_version") != SchemaVersion)
            throw new InvalidDataException("The DID2 SQL generation is not exact.");
        var actual = new List<(string Name, string Sql)>();
        using (var schema = connection.CreateCommand())
        {
            schema.CommandText = "SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name;";
            using var reader = schema.ExecuteReader();
            while (reader.Read())
            {
                if (reader.GetString(0) != "table" || reader.IsDBNull(2))
                    throw new InvalidDataException(
                        "The DID2 SQL schema contains an unexpected object.");
                actual.Add((reader.GetString(1), reader.GetString(2)));
            }
        }
        var expected = Schema.OrderBy(static item => item.Name,
            StringComparer.Ordinal).ToArray();
        if (actual.Count != expected.Length ||
            actual.Where((item, index) =>
                item.Name != expected[index].Name ||
                item.Sql.TrimEnd(';') != expected[index].Sql.TrimEnd(';'))
                .Any())
            throw new InvalidDataException("The DID2 SQL schema differs from generation 2.");
        VerifyRow(connection, "local_account",
            "SELECT network_id,account_id,did2_hash,dab2_hash,deep_id_text FROM local_account WHERE singleton=1;",
            [binding.NetworkId, binding.AccountId, binding.Did2Hash,
             binding.Dab2Hash, binding.DeepIdText]);
        VerifyRow(connection, "local_device",
            "SELECT device_id,dpd1_hash,dmd1_hash FROM local_device WHERE singleton=1;",
            [binding.DeviceId, binding.Dpd1Hash, binding.Dmd1Hash]);
        VerifyRow(connection, "local_profile",
            "SELECT display_name,revision FROM local_profile WHERE singleton=1;",
            [binding.DisplayName, 1L]);
        VerifyRow(connection, "store_identity",
            "SELECT database_instance_id,cipher_generation FROM store_identity WHERE singleton=1;",
            [binding.InstanceId, 2L]);
    }

    private static void VerifyRow(SqliteConnection connection, string table,
        string sql, object[] expected)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            throw new InvalidDataException($"DID2 SQL {table} has no singleton row.");
        for (var index = 0; index < expected.Length; index++)
        {
            var matches = expected[index] switch
            {
                byte[] bytes => reader.GetFieldValue<byte[]>(index)
                    .AsSpan().SequenceEqual(bytes),
                string value => reader.GetString(index) == value,
                long value => reader.GetInt64(index) == value,
                _ => false
            };
            if (!matches)
                throw new InvalidDataException($"DID2 SQL {table} has a different scope.");
        }
        if (reader.Read())
            throw new InvalidDataException($"DID2 SQL {table} has multiple rows.");
    }

    private static int Pragma(SqliteConnection connection, string name)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA {name};";
        return Convert.ToInt32(command.ExecuteScalar(),
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private static SqliteConnection OpenConnection(string path,
        ReadOnlySpan<byte> key, bool create)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = create ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        };
        var connection = new SqliteConnection(builder.ToString());
        try
        {
            connection.Open();
            var ownedKey = key.ToArray();
            int result;
            try { result = SQLitePCL.raw.sqlite3_key(connection.Handle, ownedKey); }
            finally { CryptographicOperations.ZeroMemory(ownedKey); }
            if (result != SQLitePCL.raw.SQLITE_OK)
                throw new SqliteException("SQLCipher rejected the DID2 key.", result);
            using (var version = connection.CreateCommand())
            {
                version.CommandText = "PRAGMA cipher_version;";
                var cipherVersion = Convert.ToString(version.ExecuteScalar(),
                    System.Globalization.CultureInfo.InvariantCulture);
                if (cipherVersion is null ||
                    !cipherVersion.StartsWith("4.", StringComparison.Ordinal))
                    throw new InvalidDataException(
                        "SQLCipher 4 is required before DID2 database creation.");
            }
            using var configure = connection.CreateCommand();
            configure.CommandText = create
                ? "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA journal_mode=DELETE;"
                : "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";
            configure.ExecuteNonQuery();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private sealed record AccountBinding(byte[] NetworkId, byte[] AccountId,
        byte[] Did2Hash, byte[] Dab2Hash, string DisplayName,
        string DeepIdText, byte[] DeviceId, byte[] Dpd1Hash,
        byte[] Dmd1Hash, byte[] InstanceId)
    {
        internal static AccountBinding From(VerifiedDeepIdV2LocalGenesis genesis,
            ReadOnlySpan<byte> accountId, ReadOnlySpan<byte> networkId,
            string displayName, ReadOnlySpan<byte> instanceId)
        {
            var evidence = genesis.PublicEvidence;
            var device = evidence.Binding.Identity.ActiveDevices.Single();
            return new(networkId.ToArray(), accountId.ToArray(),
                evidence.Binding.DeepId.RecordHash.ToArray(),
                evidence.Binding.Record.RecordHash.ToArray(), displayName,
                evidence.Binding.DeepId.Text,
                device.Certificate.DeviceId.ToArray(),
                device.Certificate.CanonicalHash.ToArray(),
                evidence.Directory.Record.RecordHash.ToArray(),
                instanceId.ToArray());
        }
    }
}
