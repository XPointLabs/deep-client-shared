using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Protocol.ContactV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.ContactV1;

public sealed class SqliteContactAddressPublicationStoreOptions : IDisposable
{
    private readonly object gate = new();
    private readonly byte[] encryptionKey;
    private int disposed;

    public SqliteContactAddressPublicationStoreOptions(
        string statePath,
        ReadOnlySpan<byte> encryptionKey,
        ContactStoreScope scope,
        bool allowCreate = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(scope);
        if (encryptionKey.Length != 32 || encryptionKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte SQLCipher key is required.", nameof(encryptionKey));
        if (scope.StoreGeneration != ContactStoreScope.CurrentStoreGeneration)
            throw new ArgumentException("Only the current ContactV1 account scope is supported.", nameof(scope));

        StatePath = Path.GetFullPath(statePath);
        this.encryptionKey = encryptionKey.ToArray();
        Scope = scope;
        AllowCreate = allowCreate;
    }

    public string StatePath { get; }
    public ContactStoreScope Scope { get; }
    public bool AllowCreate { get; }

    internal void CopyEncryptionKeyTo(Span<byte> destination)
    {
        if (destination.Length != 32)
            throw new ArgumentException("The SQLCipher key destination must be 32 bytes.", nameof(destination));
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            encryptionKey.CopyTo(destination);
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed != 0) return;
            CryptographicOperations.ZeroMemory(encryptionKey);
            disposed = 1;
        }
    }
}

/// <summary>
/// Minimal SQLCipher journal kept separate from resolver/contact relationship state.
/// It contains only opaque exact XPU1/XPO1 bytes and account-scope metadata.
/// </summary>
public sealed class SqliteContactAddressPublicationStore : IContactAddressPublicationStore, IDisposable
{
    private const int ApplicationId = 0x44435031; // DCP1
    private const int SchemaGeneration = 1;
    private const int MaximumOperations = 10_000;
    private const string SchemaDdl = """
        CREATE TABLE publication_scope(singleton INTEGER PRIMARY KEY CHECK(singleton=1), account_id BLOB NOT NULL CHECK(length(account_id)=32), contact_store_generation INTEGER NOT NULL CHECK(contact_store_generation=2));
        CREATE TABLE address_publication_operations(operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32), request_hash BLOB NOT NULL CHECK(length(request_hash)=32), exact_xpu1 BLOB NOT NULL CHECK(length(exact_xpu1) BETWEEN 1 AND 69649), state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 3), attempt_count INTEGER NOT NULL CHECK(attempt_count>=1), last_status INTEGER NULL CHECK(last_status IS NULL OR last_status BETWEEN 1 AND 9), last_mutation_outcome INTEGER NULL CHECK(last_mutation_outcome IS NULL OR last_mutation_outcome BETWEEN 0 AND 2), last_server_time BLOB NULL CHECK(last_server_time IS NULL OR length(last_server_time)=8), retry_after INTEGER NULL CHECK(retry_after IS NULL OR retry_after BETWEEN 0 AND 4294967295), exact_xpo1 BLOB NULL CHECK(exact_xpo1 IS NULL OR length(exact_xpo1) BETWEEN 1 AND 131072), CHECK((last_status IS NULL AND last_mutation_outcome IS NULL AND last_server_time IS NULL AND retry_after IS NULL AND exact_xpo1 IS NULL) OR (last_status IS NOT NULL AND last_mutation_outcome IS NOT NULL AND last_server_time IS NOT NULL AND retry_after IS NOT NULL AND exact_xpo1 IS NOT NULL)));
        """;

    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly byte[] encryptionKey = new byte[32];
    private readonly string statePath;
    private readonly string connectionString;
    private int disposed;

    static SqliteContactAddressPublicationStore() => SQLitePCL.Batteries_V2.Init();

    public SqliteContactAddressPublicationStore(SqliteContactAddressPublicationStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Scope = options.Scope;
        statePath = options.StatePath;
        options.CopyEncryptionKeyTo(encryptionKey);
        var existed = File.Exists(statePath);
        if (!existed && !options.AllowCreate)
            throw new IOException("The ContactV1 publication journal does not exist.");
        if (existed && new FileInfo(statePath).Length == 0)
            throw new FormatException("The ContactV1 publication journal is empty.");

        var parent = Path.GetDirectoryName(statePath);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();

        try
        {
            using var database = Open();
            if (existed) ValidateExisting(database);
            else Create(database);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(encryptionKey);
            throw;
        }
    }

    public ContactStoreScope Scope { get; }

    public async ValueTask<ContactAddressPublicationStageResult> StageAttemptAsync(
        ReadOnlyMemory<byte> exactXpu1,
        CancellationToken cancellationToken = default)
    {
        var candidate = ContactAddressPublicationPersistenceValidation.NewPending(
            Scope, exactXpu1.Span, attemptCount: 1);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            using var database = Open();
            using var transaction = database.BeginTransaction(deferred: false);
            var current = Read(database, transaction, candidate.OperationIdSpan);
            if (current is not null)
            {
                if (!ContactAddressPublicationPersistenceValidation.ExactEquals(
                        current.ExactXpu1Span, candidate.ExactXpu1Span))
                {
                    throw new ContactAddressPublicationConflictException();
                }

                var next = current.State == ContactAddressPublicationState.Pending
                    ? current.WithAttemptCount(checked(current.AttemptCount + 1))
                    : current.Copy();
                if (next.AttemptCount > long.MaxValue)
                    throw new InvalidOperationException("The publication retry counter is exhausted.");
                if (next.AttemptCount != current.AttemptCount)
                    UpdateAttemptCount(database, transaction, next);
                transaction.Commit();
                return new ContactAddressPublicationStageResult(
                    ContactAddressPublicationStageDisposition.ExactReplay, next.Copy());
            }

            if (Count(database, transaction) >= MaximumOperations)
                throw new InvalidOperationException("The ContactV1 publication journal capacity is exhausted.");
            Insert(database, transaction, candidate);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return new ContactAddressPublicationStageResult(
                ContactAddressPublicationStageDisposition.Added, candidate.Copy());
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<ContactAddressPublicationSnapshot?> ReadAsync(
        ReadOnlyMemory<byte> operationId32,
        CancellationToken cancellationToken = default)
    {
        ContactAddressPublicationPersistenceValidation.ValidateOperationId(operationId32.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            using var database = Open();
            return Read(database, null, operationId32.Span)?.Copy();
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<ContactAddressPublicationSnapshot> RecordValidatedResultAsync(
        ReadOnlyMemory<byte> operationId32,
        ReadOnlyMemory<byte> expectedRequestHash32,
        ReadOnlyMemory<byte> exactXpo1,
        ContactAddressPublicationState state,
        CancellationToken cancellationToken = default)
    {
        ContactAddressPublicationPersistenceValidation.ValidateOperationId(operationId32.Span);
        if (expectedRequestHash32.Length != 32)
            throw new ArgumentException("The expected request hash must be 32 bytes.", nameof(expectedRequestHash32));

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            using var database = Open();
            using var transaction = database.BeginTransaction(deferred: false);
            var current = Read(database, transaction, operationId32.Span)
                ?? throw new InvalidOperationException("The publication must be staged before recording a result.");
            if (!CryptographicOperations.FixedTimeEquals(
                    current.RequestHashSpan, expectedRequestHash32.Span))
            {
                throw new ContactAddressPublicationConflictException();
            }

            var result = Xpo1Codec.Decode(exactXpo1.Span, current.ExactXpu1Span);
            if (ContactAddressPublicationPersistenceValidation.StateFor(result.Status) != state)
                throw new ArgumentException("The requested state does not match the exact XPO1 result.", nameof(state));
            var updated = ContactAddressPublicationPersistenceValidation.Validate(
                current.WithResult(state, result, exactXpo1.Span), Scope);
            UpdateResult(database, transaction, updated);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return updated.Copy();
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        gate.Wait();
        try
        {
            CryptographicOperations.ZeroMemory(encryptionKey);
        }
        finally
        {
            gate.Release();
            gate.Dispose();
        }
    }

    private SqliteConnection Open()
    {
        ThrowIfDisposed();
        var database = new SqliteConnection(connectionString);
        try
        {
            database.Open();
            var result = SQLitePCL.raw.sqlite3_key(database.Handle, encryptionKey);
            if (result != SQLitePCL.raw.SQLITE_OK)
                throw new SqliteException("SQLCipher rejected the publication-journal key.", result);
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
        Execute(database, null,
            $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        using var transaction = database.BeginTransaction(deferred: false);
        Execute(database, transaction, SchemaDdl);
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO publication_scope(singleton,account_id,contact_store_generation) VALUES(1,$account,$generation);";
        command.Parameters.AddWithValue("$account", Scope.AccountId.Bytes.ToArray());
        command.Parameters.AddWithValue("$generation", Scope.StoreGeneration);
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("The publication scope was not persisted atomically.");
        transaction.Commit();
        ValidateExisting(database);
    }

    private void ValidateExisting(SqliteConnection database)
    {
        if (ScalarLong(database, "PRAGMA application_id;") != ApplicationId
            || ScalarLong(database, "PRAGMA user_version;") != SchemaGeneration)
        {
            throw new FormatException("Unsupported ContactV1 publication-journal schema.");
        }

        var cipherVersion = Convert.ToString(Scalar(database, "PRAGMA cipher_version;"), CultureInfo.InvariantCulture);
        if (string.IsNullOrWhiteSpace(cipherVersion) || !cipherVersion.StartsWith("4.", StringComparison.Ordinal))
            throw new InvalidOperationException("SQLCipher generation 4 is required for publication state.");
        using (var command = database.CreateCommand())
        {
            command.CommandText = "PRAGMA cipher_integrity_check;";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var result = reader.IsDBNull(0)
                    ? string.Empty
                    : Convert.ToString(reader.GetValue(0), CultureInfo.InvariantCulture);
                if (!string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase))
                    throw new FormatException("The ContactV1 publication journal failed SQLCipher integrity validation.");
            }
        }
        if (!string.Equals(Convert.ToString(Scalar(database, "PRAGMA quick_check;"), CultureInfo.InvariantCulture),
                "ok", StringComparison.OrdinalIgnoreCase))
        {
            throw new FormatException("The ContactV1 publication journal failed SQLite integrity validation.");
        }

        using (var command = database.CreateCommand())
        {
            command.CommandText = "SELECT account_id,contact_store_generation FROM publication_scope WHERE singleton=1;";
            using var reader = command.ExecuteReader();
            if (!reader.Read()) throw new FormatException("The publication account scope is absent.");
            var accountId = (byte[])reader[0];
            try
            {
                if (!Scope.AccountId.Matches(accountId) || reader.GetInt32(1) != Scope.StoreGeneration)
                    throw new InvalidOperationException("The publication journal belongs to another Deep account scope.");
                if (reader.Read()) throw new FormatException("The publication account scope is duplicated.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(accountId);
            }
        }

        using (var command = database.CreateCommand())
        {
            command.CommandText = "SELECT sql FROM sqlite_master WHERE type='table' AND name IN ('publication_scope','address_publication_operations') ORDER BY name;";
            using var reader = command.ExecuteReader();
            var count = 0;
            while (reader.Read())
            {
                if (reader.IsDBNull(0) || string.IsNullOrWhiteSpace(reader.GetString(0)))
                    throw new FormatException("The publication-journal DDL is absent.");
                count++;
            }
            if (count != 2) throw new FormatException("The publication-journal schema is incomplete.");
        }

        if (Count(database, null) > MaximumOperations)
            throw new FormatException("The ContactV1 publication journal capacity was exceeded.");
        var operationIds = new List<byte[]>();
        using (var all = database.CreateCommand())
        {
            all.CommandText = "SELECT operation_id FROM address_publication_operations ORDER BY operation_id;";
            using var rows = all.ExecuteReader();
            while (rows.Read()) operationIds.Add((byte[])rows[0]);
        }
        foreach (var operationId in operationIds)
        {
            try
            {
                _ = Read(database, null, operationId)
                    ?? throw new FormatException("A persisted publication disappeared during validation.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(operationId);
            }
        }
    }

    private ContactAddressPublicationSnapshot? Read(
        SqliteConnection database,
        SqliteTransaction? transaction,
        ReadOnlySpan<byte> operationId)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT operation_id,request_hash,exact_xpu1,state,attempt_count,last_status,
                   last_mutation_outcome,last_server_time,retry_after,exact_xpo1
            FROM address_publication_operations WHERE operation_id=$operation;
            """;
        command.Parameters.AddWithValue("$operation", operationId.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var value = ReadRow(reader);
        if (reader.Read()) throw new FormatException("Duplicate publication operation rows were found.");
        return ContactAddressPublicationPersistenceValidation.Validate(value, Scope);
    }

    private ContactAddressPublicationSnapshot ReadRow(SqliteDataReader reader)
    {
        var operationId = (byte[])reader[0];
        var requestHash = (byte[])reader[1];
        var exactXpu1 = (byte[])reader[2];
        byte[]? serverTime = reader.IsDBNull(7) ? null : (byte[])reader[7];
        byte[]? exactXpo1 = reader.IsDBNull(9) ? null : (byte[])reader[9];
        try
        {
            if (reader.GetInt64(4) <= 0)
                throw new FormatException("The publication attempt count is invalid.");
            return new ContactAddressPublicationSnapshot(
                Scope,
                operationId,
                requestHash,
                exactXpu1,
                (ContactAddressPublicationState)reader.GetInt32(3),
                checked((ulong)reader.GetInt64(4)),
                reader.IsDBNull(5) ? null : (Xpo1Status)reader.GetInt32(5),
                reader.IsDBNull(6) ? null : (ContactServiceMutationOutcome)reader.GetInt32(6),
                serverTime is null ? null : BinaryPrimitives.ReadUInt64BigEndian(serverTime),
                reader.IsDBNull(8) ? null : checked((uint)reader.GetInt64(8)),
                exactXpo1 ?? []);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(operationId);
            CryptographicOperations.ZeroMemory(requestHash);
            CryptographicOperations.ZeroMemory(exactXpu1);
            if (serverTime is not null) CryptographicOperations.ZeroMemory(serverTime);
            if (exactXpo1 is not null) CryptographicOperations.ZeroMemory(exactXpo1);
        }
    }

    private static void Insert(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactAddressPublicationSnapshot value)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO address_publication_operations(
              operation_id,request_hash,exact_xpu1,state,attempt_count)
            VALUES($operation,$hash,$request,$state,$attempts);
            """;
        command.Parameters.AddWithValue("$operation", value.OperationIdSpan.ToArray());
        command.Parameters.AddWithValue("$hash", value.RequestHashSpan.ToArray());
        command.Parameters.AddWithValue("$request", value.ExactXpu1Span.ToArray());
        command.Parameters.AddWithValue("$state", (int)value.State);
        command.Parameters.AddWithValue("$attempts", checked((long)value.AttemptCount));
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("The publication operation was not staged atomically.");
    }

    private static void UpdateAttemptCount(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactAddressPublicationSnapshot value)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "UPDATE address_publication_operations SET attempt_count=$attempts WHERE operation_id=$operation AND request_hash=$hash;";
        command.Parameters.AddWithValue("$attempts", checked((long)value.AttemptCount));
        command.Parameters.AddWithValue("$operation", value.OperationIdSpan.ToArray());
        command.Parameters.AddWithValue("$hash", value.RequestHashSpan.ToArray());
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("The publication retry was not recorded atomically.");
    }

    private static void UpdateResult(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactAddressPublicationSnapshot value)
    {
        Span<byte> serverTime = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(serverTime,
            value.LastServerTimeUnixSeconds ?? throw new InvalidOperationException());
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE address_publication_operations
            SET state=$state,last_status=$status,last_mutation_outcome=$outcome,
                last_server_time=$server,retry_after=$retry,exact_xpo1=$result
            WHERE operation_id=$operation AND request_hash=$hash;
            """;
        command.Parameters.AddWithValue("$state", (int)value.State);
        command.Parameters.AddWithValue("$status", (int)(value.LastStatus ?? throw new InvalidOperationException()));
        command.Parameters.AddWithValue("$outcome", (int)(value.LastMutationOutcome ?? throw new InvalidOperationException()));
        command.Parameters.AddWithValue("$server", serverTime.ToArray());
        command.Parameters.AddWithValue("$retry", checked((long)(value.RetryAfterSeconds ?? throw new InvalidOperationException())));
        command.Parameters.AddWithValue("$result", value.ExactXpo1Span.ToArray());
        command.Parameters.AddWithValue("$operation", value.OperationIdSpan.ToArray());
        command.Parameters.AddWithValue("$hash", value.RequestHashSpan.ToArray());
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("The publication result was not recorded atomically.");
        CryptographicOperations.ZeroMemory(serverTime);
    }

    private static long Count(SqliteConnection database, SqliteTransaction? transaction)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COUNT(*) FROM address_publication_operations;";
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static void Execute(
        SqliteConnection database,
        SqliteTransaction? transaction,
        string sql)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static object? Scalar(SqliteConnection database, string sql)
    {
        using var command = database.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static long ScalarLong(SqliteConnection database, string sql) =>
        Convert.ToInt64(Scalar(database, sql), CultureInfo.InvariantCulture);

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(
        Volatile.Read(ref disposed) != 0, this);
}
