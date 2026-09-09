using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Deep.Client.Shared.Domain.ContactV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.ContactV1;

public enum ContactStateStoreOpenFailure
{
    UnreadableOrWrongKey = 1,
    UnsupportedGeneration = 2,
    ScopeMismatch = 3,
    Corrupt = 4,
}

public sealed class ContactStateStoreOpenException : IOException
{
    internal ContactStateStoreOpenException(
        ContactStateStoreOpenFailure reason,
        string message,
        Exception? inner = null)
        : base(message, inner) => Reason = reason;

    public ContactStateStoreOpenFailure Reason { get; }
}

public sealed class SqliteContactStateStoreOptions : IDisposable
{
    private readonly object keyGate = new();
    private readonly byte[] encryptionKey;
    private int disposed;

    public SqliteContactStateStoreOptions(
        string statePath,
        ReadOnlySpan<byte> encryptionKey,
        ContactStoreScope scope,
        bool allowCreate = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(scope);
        if (encryptionKey.Length != 32 || encryptionKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte SQLCipher key is required.", nameof(encryptionKey));

        StatePath = Path.GetFullPath(statePath);
        this.encryptionKey = encryptionKey.ToArray();
        Scope = scope;
        AllowCreate = allowCreate;
    }

    public string StatePath { get; }
    public ContactStoreScope Scope { get; }
    public bool AllowCreate { get; }

    internal bool EncryptionKeyIsZeroized
    {
        get { lock (keyGate) return encryptionKey.AsSpan().IndexOfAnyExcept((byte)0) < 0; }
    }

    internal void CopyEncryptionKeyTo(Span<byte> destination)
    {
        if (destination.Length != encryptionKey.Length)
            throw new ArgumentException("The SQLCipher key destination must be exactly 32 bytes.", nameof(destination));
        lock (keyGate)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            encryptionKey.CopyTo(destination);
        }
    }

    public void Dispose()
    {
        lock (keyGate)
        {
            if (disposed != 0) return;
            CryptographicOperations.ZeroMemory(encryptionKey);
            Volatile.Write(ref disposed, 1);
        }
    }
}

public sealed partial class SqliteContactStateStore : IContactStateStore, IContactResolveOperationStore, IDisposable
{
    private const int ApplicationId = 0x44435331; // DCS1
    private const int SchemaGeneration = 4;
    private const int MaximumPendingAddresses = 10_000;
    private const string SchemaDdl = """
        CREATE TABLE contact_store_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), account_id BLOB NOT NULL CHECK(length(account_id)=32), store_generation INTEGER NOT NULL CHECK(store_generation=2));
        CREATE TABLE pending_contact_addresses(kind INTEGER NOT NULL CHECK(kind IN (1,2)), canonical_bytes BLOB NOT NULL, network_id BLOB NOT NULL CHECK(length(network_id)=16), canonical_text TEXT NOT NULL, expires_at BLOB NULL CHECK(expires_at IS NULL OR length(expires_at)=8), imported_at_utc_ticks INTEGER NOT NULL CHECK(imported_at_utc_ticks>=0), PRIMARY KEY(kind,canonical_bytes), CHECK((kind=1 AND length(canonical_bytes)=76 AND length(canonical_text)=90 AND expires_at IS NULL) OR (kind=2 AND length(canonical_bytes)=225 AND length(canonical_text)=311 AND length(expires_at)=8)));
        CREATE INDEX pending_contact_addresses_order ON pending_contact_addresses(imported_at_utc_ticks,kind,canonical_bytes);
        CREATE TABLE contact_relationships(relationship_id BLOB PRIMARY KEY CHECK(length(relationship_id)=32), conversation_id BLOB NOT NULL UNIQUE CHECK(length(conversation_id)=32), remote_account_id BLOB NOT NULL CHECK(length(remote_account_id)=32), address_kind INTEGER NOT NULL CHECK(address_kind IN (1,2)), canonical_address BLOB NOT NULL, state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 13), revision BLOB NOT NULL CHECK(length(revision)=8), created_at_utc_ticks INTEGER NOT NULL CHECK(created_at_utc_ticks>=0), updated_at_utc_ticks INTEGER NOT NULL CHECK(updated_at_utc_ticks>=created_at_utc_ticks), did1_hash BLOB NOT NULL CHECK(length(did1_hash)=32), dab1_hash BLOB NOT NULL CHECK(length(dab1_hash)=32), dpa1_hash BLOB NOT NULL CHECK(length(dpa1_hash)=32), drs1_hash BLOB NOT NULL CHECK(length(drs1_hash)=32), dmd1_hash BLOB NOT NULL CHECK(length(dmd1_hash)=32), dca1_hash BLOB NOT NULL CHECK(length(dca1_hash)=32), dcb1_hash BLOB NOT NULL CHECK(length(dcb1_hash)=32), dcr1_hash BLOB NOT NULL CHECK(length(dcr1_hash)=32), adh1_hash BLOB NOT NULL CHECK(length(adh1_hash)=32), adp1_hash BLOB NOT NULL CHECK(length(adp1_hash)=32), reachability_descriptor_hash BLOB NOT NULL CHECK(length(reachability_descriptor_hash)=32), CHECK((address_kind=1 AND length(canonical_address)=76) OR (address_kind=2 AND length(canonical_address)=225)));
        CREATE INDEX contact_relationships_order ON contact_relationships(updated_at_utc_ticks,relationship_id);
        CREATE TABLE contact_verified_peer_packages(relationship_id BLOB PRIMARY KEY CHECK(length(relationship_id)=32), package_version INTEGER NOT NULL CHECK(package_version=1), package_hash BLOB NOT NULL CHECK(length(package_hash)=32), local_account_id BLOB NOT NULL CHECK(length(local_account_id)=32), remote_account_id BLOB NOT NULL CHECK(length(remote_account_id)=32), conversation_id BLOB NOT NULL CHECK(length(conversation_id)=32), network_id BLOB NOT NULL CHECK(length(network_id)=16), address_kind INTEGER NOT NULL CHECK(address_kind IN (1,2)), canonical_address BLOB NOT NULL, exact_xiq1 BLOB NOT NULL CHECK(length(exact_xiq1)>0 AND length(exact_xiq1)<=65535), exact_xis1 BLOB NOT NULL CHECK(length(exact_xis1)>0 AND length(exact_xis1)<=131072), exact_dcr1 BLOB NOT NULL CHECK(length(exact_dcr1)>0 AND length(exact_dcr1)<=65535), exact_dcb1 BLOB NOT NULL CHECK(length(exact_dcb1)>0 AND length(exact_dcb1)<=65535), exact_dmd1 BLOB NOT NULL CHECK(length(exact_dmd1)>0 AND length(exact_dmd1)<=65535), exact_route_closure BLOB NOT NULL CHECK(length(exact_route_closure)>0 AND length(exact_route_closure)<=65535), CHECK((address_kind=1 AND length(canonical_address)=76) OR (address_kind=2 AND length(canonical_address)=225)), FOREIGN KEY(relationship_id) REFERENCES contact_relationships(relationship_id) ON DELETE RESTRICT);
        CREATE INDEX contact_verified_peer_packages_conversation ON contact_verified_peer_packages(conversation_id);
        CREATE TABLE contact_verified_peer_devices(relationship_id BLOB NOT NULL CHECK(length(relationship_id)=32), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 15), device_id BLOB NOT NULL CHECK(length(device_id)=32), exact_dpd1 BLOB NOT NULL CHECK(length(exact_dpd1)=776), PRIMARY KEY(relationship_id,ordinal), UNIQUE(relationship_id,device_id), FOREIGN KEY(relationship_id) REFERENCES contact_verified_peer_packages(relationship_id) ON DELETE RESTRICT);
        CREATE TABLE contact_relationship_operations(operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32), fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), relationship_id BLOB NOT NULL CHECK(length(relationship_id)=32), committed_revision BLOB NOT NULL CHECK(length(committed_revision)=8), FOREIGN KEY(relationship_id) REFERENCES contact_relationships(relationship_id) ON DELETE RESTRICT);
        CREATE INDEX contact_relationship_operations_relationship ON contact_relationship_operations(relationship_id,committed_revision);
        CREATE TABLE contact_resolve_operations(operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32), request_hash BLOB NOT NULL CHECK(length(request_hash)=32), relationship_id BLOB NOT NULL CHECK(length(relationship_id)=32), address_kind INTEGER NOT NULL CHECK(address_kind IN (1,2)), canonical_address BLOB NOT NULL, exact_xiq1 BLOB NOT NULL CHECK(length(exact_xiq1)>0 AND length(exact_xiq1)<=65535), state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 6), dispatch_count BLOB NOT NULL CHECK(length(dispatch_count)=8), transport_attempt_count BLOB NOT NULL CHECK(length(transport_attempt_count)=8), last_disposition INTEGER NULL CHECK(last_disposition IS NULL OR last_disposition BETWEEN 1 AND 11), last_retry INTEGER NULL CHECK(last_retry IS NULL OR last_retry BETWEEN 0 AND 4), retry_after_seconds INTEGER NULL CHECK(retry_after_seconds IS NULL OR retry_after_seconds BETWEEN 0 AND 4294967295), required_view_hash BLOB NULL CHECK(required_view_hash IS NULL OR length(required_view_hash)=32), exact_xis1 BLOB NULL CHECK(exact_xis1 IS NULL OR (length(exact_xis1)>0 AND length(exact_xis1)<=131072)), updated_at_utc_ticks INTEGER NOT NULL CHECK(updated_at_utc_ticks>=0), CHECK((address_kind=1 AND length(canonical_address)=76) OR (address_kind=2 AND length(canonical_address)=225)), CHECK((last_disposition IS NULL AND last_retry IS NULL) OR (last_disposition IS NOT NULL AND last_retry IS NOT NULL)), FOREIGN KEY(address_kind,canonical_address) REFERENCES pending_contact_addresses(kind,canonical_bytes) ON DELETE RESTRICT);
        CREATE INDEX contact_resolve_operations_state ON contact_resolve_operations(state,updated_at_utc_ticks,operation_id);
        CREATE INDEX contact_resolve_operations_relationship ON contact_resolve_operations(relationship_id,operation_id);
        """;
    private static readonly byte[] ExpectedSchemaFingerprint = HashSchemaObjects(ExpectedSchemaObjects());

    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly object lifecycleGate = new();
    private readonly ManualResetEventSlim drained = new(initialState: true);
    private readonly byte[] encryptionKey;
    private readonly string statePath;
    private readonly string connectionString;
    private SqliteConnection? connection;
    private int disposed;
    private int operationsInFlight;

    static SqliteContactStateStore() => SQLitePCL.Batteries_V2.Init();

    public SqliteContactStateStore(SqliteContactStateStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Scope.StoreGeneration != ContactStoreScope.CurrentStoreGeneration)
        {
            throw Failure(ContactStateStoreOpenFailure.UnsupportedGeneration,
                "Only the current ContactV1 store generation can be opened.");
        }

        var exists = File.Exists(options.StatePath);
        if (!exists && !options.AllowCreate)
        {
            throw Failure(ContactStateStoreOpenFailure.UnreadableOrWrongKey,
                "The current ContactV1 database does not exist.");
        }
        if (exists && new FileInfo(options.StatePath).Length == 0)
            throw Failure(ContactStateStoreOpenFailure.Corrupt, "The ContactV1 database is empty.");

        var parent = Path.GetDirectoryName(options.StatePath);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

        Scope = options.Scope;
        statePath = options.StatePath;
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();
        encryptionKey = new byte[32];
        options.CopyEncryptionKeyTo(encryptionKey);

        try
        {
            using (var opened = Open())
            {
                if (exists) ValidateExisting(opened);
                else Create(opened);
            }
            ValidateEncryptedMainDatabase(statePath);
            connection = Open();
            ValidateEncryptedSidecars(statePath, connection);
        }
        catch (ContactStateStoreOpenException)
        {
            DisposeFailedOpen();
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or InvalidOperationException or FormatException)
        {
            DisposeFailedOpen();
            throw Failure(ContactStateStoreOpenFailure.UnreadableOrWrongKey,
                "ContactV1 SQLCipher state cannot be opened with this key.", exception);
        }
        catch
        {
            DisposeFailedOpen();
            throw;
        }
    }

    public ContactStoreScope Scope { get; }
    internal string ConnectionString => connectionString;
    internal bool EncryptionKeyIsZeroized => encryptionKey.AsSpan().IndexOfAnyExcept((byte)0) < 0;

    public async ValueTask<PendingContactAddressWriteResult> PutPendingAddressAsync(
        PendingContactAddress address,
        CancellationToken cancellationToken = default)
    {
        var candidate = ContactStatePersistenceValidation.CloneAndValidate(address);
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            var database = GetConnection();
            await using var transaction = database.BeginTransaction(deferred: false);
            var existing = ReadOne(database, transaction, candidate.Address.Kind,
                candidate.Address.CanonicalBytes.Span);
            if (existing is not null)
            {
                if (!existing.Address.Equals(candidate.Address))
                    throw new ArgumentException("The canonical address is already bound to another network.", nameof(address));
                transaction.Commit();
                return new PendingContactAddressWriteResult(
                    PendingContactAddressWriteDisposition.Idempotent,
                    existing);
            }

            if (Count(database, transaction) >= MaximumPendingAddresses)
            {
                transaction.Commit();
                return new PendingContactAddressWriteResult(
                    PendingContactAddressWriteDisposition.CapacityExceeded, null);
            }

            Insert(database, transaction, candidate);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return new PendingContactAddressWriteResult(
                PendingContactAddressWriteDisposition.Added,
                ContactStatePersistenceValidation.CloneAndValidate(candidate));
        }
        catch (ContactStateStoreOpenException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The ContactV1 pending-address transaction failed closed.", exception);
        }
        finally
        {
            if (entered) gate.Release();
        }
    }

    public async ValueTask<PendingContactAddress?> ReadPendingAddressAsync(
        ContactAddressKind kind,
        ReadOnlyMemory<byte> exactCanonicalAddress,
        CancellationToken cancellationToken = default)
    {
        ContactStatePersistenceValidation.ValidateLookup(kind, exactCanonicalAddress.Span);
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            var result = ReadOne(GetConnection(), null, kind, exactCanonicalAddress.Span);
            return result;
        }
        catch (ContactStateStoreOpenException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "Persisted ContactV1 state is invalid and must be reset.", exception);
        }
        finally
        {
            if (entered) gate.Release();
        }
    }

    public async ValueTask<IReadOnlyList<PendingContactAddress>> ReadPendingAddressesAsync(
        CancellationToken cancellationToken = default)
    {
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            return ReadAll(GetConnection(), null).ToArray();
        }
        catch (ContactStateStoreOpenException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "Persisted ContactV1 state is invalid and must be reset.", exception);
        }
        finally
        {
            if (entered) gate.Release();
        }
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
        connection?.Dispose();
        connection = null;
        gate.Dispose();
        CryptographicOperations.ZeroMemory(encryptionKey);
    }

    internal void ValidateEncryptedFilesForTesting()
    {
        ValidateEncryptedMainDatabase(statePath);
        ValidateEncryptedSidecars(statePath, GetConnection());
    }

    private SqliteConnection Open()
    {
        var database = new SqliteConnection(connectionString);
        try
        {
            database.Open();
            var result = SQLitePCL.raw.sqlite3_key(database.Handle, encryptionKey);
            if (result != SQLitePCL.raw.SQLITE_OK)
                throw new SqliteException("SQLCipher rejected the key.", result);
            Execute(database, null,
                "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;");
            return database;
        }
        catch
        {
            database.Dispose();
            throw;
        }
    }

    private void Create(SqliteConnection database)
    {
        Execute(database, null, $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        using var transaction = database.BeginTransaction(deferred: false);
        Execute(database, transaction, SchemaDdl);
        using (var command = database.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO contact_store_meta(singleton,account_id,store_generation) VALUES(1,$account,$generation);";
            command.Parameters.AddWithValue("$account", Scope.AccountId.Bytes.ToArray());
            command.Parameters.AddWithValue("$generation", Scope.StoreGeneration);
            command.ExecuteNonQuery();
        }
        transaction.Commit();
        ValidateSchema(database);
        ValidateCipher(database);
    }

    private void ValidateExisting(SqliteConnection database)
    {
        try
        {
            if (ScalarLong(database, "PRAGMA application_id;") != ApplicationId
                || ScalarLong(database, "PRAGMA user_version;") != SchemaGeneration)
            {
                throw Failure(ContactStateStoreOpenFailure.UnsupportedGeneration,
                    "Unsupported ContactV1 schema generation.");
            }
            ValidateSchema(database);
            using (var command = database.CreateCommand())
            {
                command.CommandText = "SELECT account_id,store_generation FROM contact_store_meta WHERE singleton=1;";
                using var reader = command.ExecuteReader();
                if (!reader.Read())
                    throw Failure(ContactStateStoreOpenFailure.Corrupt, "ContactV1 scope metadata is absent.");
                var account = (byte[])reader[0];
                var generation = reader.GetInt32(1);
                if (account.Length != 32 || generation <= 0)
                {
                    throw Failure(ContactStateStoreOpenFailure.Corrupt,
                        "ContactV1 scope metadata has an invalid canonical shape.");
                }
                if (!Scope.AccountId.Matches(account) || generation != Scope.StoreGeneration)
                {
                    throw Failure(ContactStateStoreOpenFailure.ScopeMismatch,
                        "The ContactV1 database belongs to another Deep account or store generation.");
                }
                if (reader.Read())
                    throw Failure(ContactStateStoreOpenFailure.Corrupt, "ContactV1 scope metadata is duplicated.");
            }
            ValidateCipher(database);
            var rows = ReadAll(database, null);
            if (rows.Count > MaximumPendingAddresses)
                throw Failure(ContactStateStoreOpenFailure.Corrupt, "ContactV1 pending-address capacity was exceeded.");
            ValidatePersistedRelationships(database);
            ValidatePersistedResolveOperations(database);
        }
        catch (ContactStateStoreOpenException)
        {
            throw;
        }
        catch (SqliteException exception)
        {
            throw Failure(ContactStateStoreOpenFailure.UnreadableOrWrongKey,
                "ContactV1 SQLCipher metadata cannot be read.", exception);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or FormatException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "ContactV1 persisted state violates its sealed semantic contract.", exception);
        }
    }

    private static void Insert(
        SqliteConnection database,
        SqliteTransaction transaction,
        PendingContactAddress pending)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO pending_contact_addresses(
              kind,canonical_bytes,network_id,canonical_text,expires_at,imported_at_utc_ticks)
            VALUES($kind,$canonical,$network,$text,$expiry,$imported);
            """;
        command.Parameters.AddWithValue("$kind", (int)pending.Address.Kind);
        command.Parameters.AddWithValue("$canonical", pending.Address.CanonicalBytes.ToArray());
        command.Parameters.AddWithValue("$network", pending.Address.NetworkId.ToArray());
        command.Parameters.AddWithValue("$text", pending.Address.CanonicalText);
        command.Parameters.AddWithValue("$expiry", pending.Address.ExpiresAtUnixSeconds is ulong expiry
            ? ContactStatePersistenceValidation.U64(expiry)
            : DBNull.Value);
        command.Parameters.AddWithValue("$imported", pending.ImportedAt.UtcTicks);
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("ContactV1 pending-address insert did not affect exactly one row.");
    }

    private static PendingContactAddress? ReadOne(
        SqliteConnection database,
        SqliteTransaction? transaction,
        ContactAddressKind kind,
        ReadOnlySpan<byte> canonical)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT kind,network_id,canonical_bytes,canonical_text,expires_at,imported_at_utc_ticks
            FROM pending_contact_addresses
            WHERE kind=$kind AND canonical_bytes=$canonical;
            """;
        command.Parameters.AddWithValue("$kind", (int)kind);
        command.Parameters.AddWithValue("$canonical", canonical.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var result = ReadRow(reader);
        if (reader.Read())
            throw Failure(ContactStateStoreOpenFailure.Corrupt, "Duplicate ContactV1 pending-address rows were found.");
        return result;
    }

    private static List<PendingContactAddress> ReadAll(
        SqliteConnection database,
        SqliteTransaction? transaction)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT kind,network_id,canonical_bytes,canonical_text,expires_at,imported_at_utc_ticks
            FROM pending_contact_addresses
            ORDER BY imported_at_utc_ticks,kind,canonical_bytes;
            """;
        using var reader = command.ExecuteReader();
        var result = new List<PendingContactAddress>();
        while (reader.Read())
        {
            if (result.Count == MaximumPendingAddresses)
                throw Failure(ContactStateStoreOpenFailure.Corrupt, "ContactV1 pending-address capacity was exceeded.");
            result.Add(ReadRow(reader));
        }
        return result;
    }

    private static PendingContactAddress ReadRow(SqliteDataReader reader)
    {
        var network = (byte[])reader[1];
        var canonical = (byte[])reader[2];
        var expiry = reader.IsDBNull(4) ? null : (byte[])reader[4];
        try
        {
            return ContactStatePersistenceValidation.Restore(
                reader.GetInt32(0), network, canonical, reader.GetString(3), expiry,
                reader.GetInt64(5));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(network);
            CryptographicOperations.ZeroMemory(canonical);
            if (expiry is not null) CryptographicOperations.ZeroMemory(expiry);
        }
    }

    private static long Count(SqliteConnection database, SqliteTransaction transaction)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COUNT(*) FROM pending_contact_addresses;";
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static void ValidateCipher(SqliteConnection database)
    {
        var version = Convert.ToString(Scalar(database, "PRAGMA cipher_version;"), CultureInfo.InvariantCulture);
        if (string.IsNullOrWhiteSpace(version) || !version.StartsWith("4.", StringComparison.Ordinal))
        {
            throw Failure(ContactStateStoreOpenFailure.UnsupportedGeneration,
                "SQLCipher generation 4 is required for ContactV1 state.");
        }
        using (var command = database.CreateCommand())
        {
            command.CommandText = "PRAGMA cipher_integrity_check;";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var result = reader.IsDBNull(0) ? string.Empty
                    : Convert.ToString(reader.GetValue(0), CultureInfo.InvariantCulture);
                if (!string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase))
                {
                    throw Failure(ContactStateStoreOpenFailure.Corrupt,
                        "ContactV1 SQLCipher integrity verification failed.");
                }
            }
        }
        if (!string.Equals(Convert.ToString(Scalar(database, "PRAGMA quick_check;"), CultureInfo.InvariantCulture),
                "ok", StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "ContactV1 SQLite structural verification failed.");
        }
    }

    private static void ValidateSchema(SqliteConnection database)
    {
        var actualFingerprint = HashSchemaObjects(ReadSchemaObjects(database));
        if (!CryptographicOperations.FixedTimeEquals(ExpectedSchemaFingerprint, actualFingerprint))
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "ContactV1 DDL, constraints, indexes, or schema fingerprint does not match the sealed contract.");
        }
    }

    private static string[] ExpectedSchemaObjects()
    {
        var statements = SchemaDdl.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var result = new List<string>(statements.Length);
        foreach (var statement in statements)
        {
            var match = Regex.Match(statement,
                @"^CREATE\s+(TABLE|INDEX)\s+([a-z_]+)(?:\s+ON\s+([a-z_]+))?",
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (!match.Success)
                throw new InvalidOperationException("The sealed ContactV1 schema declaration is malformed.");
            var type = match.Groups[1].Value.ToLowerInvariant();
            var name = match.Groups[2].Value;
            var table = type == "table" ? name : match.Groups[3].Value;
            result.Add($"{type}|{name}|{table}|{NormalizeSql(statement)}");
        }
        return result.OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    }

    private static string[] ReadSchemaObjects(SqliteConnection database)
    {
        using var command = database.CreateCommand();
        command.CommandText = """
            SELECT type,name,tbl_name,sql FROM sqlite_master
            WHERE type IN ('table','index','view','trigger') AND name NOT LIKE 'sqlite_%'
            ORDER BY type,name;
            """;
        using var reader = command.ExecuteReader();
        var result = new List<string>();
        while (reader.Read())
        {
            if (reader.IsDBNull(3))
                throw Failure(ContactStateStoreOpenFailure.Corrupt,
                    "ContactV1 schema contains an unexpected implicit index.");
            result.Add($"{reader.GetString(0)}|{reader.GetString(1)}|{reader.GetString(2)}|{NormalizeSql(reader.GetString(3))}");
        }
        return result.OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    }

    private static byte[] HashSchemaObjects(IEnumerable<string> objects) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', objects)));
    private static string NormalizeSql(string sql) =>
        Regex.Replace(sql.Trim().TrimEnd(';'), @"\s+", " ");

    private static void ValidateEncryptedMainDatabase(string path)
    {
        using var stream = OpenSharedRead(path);
        if (stream.Length < 16)
            throw Failure(ContactStateStoreOpenFailure.Corrupt, "The encrypted ContactV1 database is truncated.");
        Span<byte> header = stackalloc byte[16];
        ReadExactHeader(stream, header, "The encrypted ContactV1 database is truncated.");
        if (header.SequenceEqual("SQLite format 3\0"u8))
        {
            throw Failure(ContactStateStoreOpenFailure.UnreadableOrWrongKey,
                "ContactV1 refuses a plaintext SQLite database.");
        }
    }

    private static void ValidateEncryptedSidecars(string path, SqliteConnection database)
    {
        var wal = path + "-wal";
        if (File.Exists(wal)) ValidateWalSidecar(wal, checked((int)ScalarLong(database, "PRAGMA page_size;")));
        var sharedMemory = path + "-shm";
        if (File.Exists(sharedMemory)) ValidateSharedMemorySidecar(sharedMemory);
    }

    private static void ValidateWalSidecar(string path, int pageSize)
    {
        using var stream = OpenSharedRead(path);
        if (stream.Length == 0) return;
        if (pageSize is < 512 or > 65_536 || (pageSize & (pageSize - 1)) != 0
            || stream.Length < 32 || (stream.Length - 32) % (pageSize + 24L) != 0)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The ContactV1 SQLCipher WAL has an invalid shape.");
        }
        Span<byte> header = stackalloc byte[16];
        ReadExactHeader(stream, header, "The ContactV1 SQLCipher WAL is truncated.");
        if (header.SequenceEqual("SQLite format 3\0"u8))
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The ContactV1 WAL must never contain a plaintext SQLite database header.");
        }
    }

    private static void ValidateSharedMemorySidecar(string path)
    {
        using var stream = OpenSharedRead(path);
        if (stream.Length != 0 && (stream.Length < 32 * 1024 || stream.Length % (32 * 1024) != 0))
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The ContactV1 WAL shared-memory sidecar has an invalid size.");
        }
    }

    private static FileStream OpenSharedRead(string path) => new(
        path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

    private static void ReadExactHeader(Stream stream, Span<byte> header, string message)
    {
        var read = 0;
        while (read != header.Length)
        {
            var count = stream.Read(header[read..]);
            if (count == 0) throw Failure(ContactStateStoreOpenFailure.Corrupt, message);
            read += count;
        }
    }

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
            if (--operationsInFlight < 0)
                throw new InvalidOperationException("ContactV1 lifecycle lease underflow.");
            if (operationsInFlight == 0 && Volatile.Read(ref disposed) != 0) drained.Set();
        }
    }

    private void DisposeFailedOpen()
    {
        connection?.Dispose();
        connection = null;
        CryptographicOperations.ZeroMemory(encryptionKey);
    }

    private SqliteConnection GetConnection() => connection
        ?? throw new ObjectDisposedException(nameof(SqliteContactStateStore));
    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
            throw new ObjectDisposedException(nameof(SqliteContactStateStore));
    }

    private static object? Scalar(SqliteConnection database, string sql)
    {
        using var command = database.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }
    private static long ScalarLong(SqliteConnection database, string sql) =>
        Convert.ToInt64(Scalar(database, sql), CultureInfo.InvariantCulture);
    private static void Execute(SqliteConnection database, SqliteTransaction? transaction, string sql)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
    private static ContactStateStoreOpenException Failure(
        ContactStateStoreOpenFailure reason,
        string message,
        Exception? inner = null) => new(reason, message, inner);

    private sealed class OperationLease : IDisposable
    {
        private SqliteContactStateStore? owner;
        internal OperationLease(SqliteContactStateStore owner) => this.owner = owner;
        public void Dispose() => Interlocked.Exchange(ref owner, null)?.ExitOperation();
    }
}
