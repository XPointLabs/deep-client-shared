using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.ContactV1;

public sealed class SqliteXpk1ClaimJournalOptions : IDisposable
{
    private readonly byte[] key;
    private int disposed;

    public SqliteXpk1ClaimJournalOptions(
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
        key = encryptionKey.ToArray();
        Scope = scope;
        AllowCreate = allowCreate;
    }

    public string StatePath { get; }
    public ContactStoreScope Scope { get; }
    public bool AllowCreate { get; }

    internal void CopyKey(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        key.CopyTo(destination);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        CryptographicOperations.ZeroMemory(key);
    }
}

internal sealed class Xpk1ClaimJournalEntry
{
    internal Xpk1ClaimJournalEntry(
        Xpk1ClaimJournalDisposition disposition,
        Xpk1ClaimJournalState state,
        ulong revision)
    {
        Disposition = disposition;
        State = state ?? throw new ArgumentNullException(nameof(state));
        if (revision == 0) throw new ArgumentOutOfRangeException(nameof(revision));
        Revision = revision;
    }

    internal Xpk1ClaimJournalDisposition Disposition { get; }
    internal Xpk1ClaimJournalState State { get; }
    internal ulong Revision { get; }
    internal ReadOnlyMemory<byte> StoredResultWire => State.StoredResultWire;

    internal PreKeyV1DurableClaimOperation? TryCreateDispatchOperation() =>
        State.CanDispatchExactRequest
            ? new PreKeyV1DurableClaimOperation(
                State.ExactRequest.Span,
                State.OperationId.Span,
                Revision)
            : null;
}

/// <summary>
/// Account-scoped SQLCipher journal for one exact canonical XPK1 per operation ID.
/// Protocol owns every retry, fork and terminal-result transition; this store only
/// restores that immutable state and commits the resulting exact bytes atomically.
/// </summary>
public sealed class SqliteXpk1ClaimJournal : IDisposable
{
    private const int ApplicationId = 0x58434A31; // XCJ1
    private const int SchemaGeneration = 1;
    private const string Ddl = """
        CREATE TABLE xpk1_claim_journal_meta(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            account_id BLOB NOT NULL CHECK(length(account_id)=32),
            store_generation INTEGER NOT NULL CHECK(store_generation=2));
        CREATE TABLE xpk1_claim_operations(
            operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32),
            exact_xpk1 BLOB NOT NULL CHECK(length(exact_xpk1)>0 AND length(exact_xpk1)<=65945),
            exact_xpc1 BLOB NULL,
            successful_result INTEGER NOT NULL CHECK(successful_result IN (0,1)),
            fork_request BLOB NULL,
            revision BLOB NOT NULL CHECK(length(revision)=8),
            CHECK((exact_xpc1 IS NULL AND successful_result=0) OR exact_xpc1 IS NOT NULL),
            CHECK(fork_request IS NULL OR length(fork_request)>0));
        """;

    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly byte[] key = new byte[32];
    private readonly string statePath;
    private readonly string connectionString;
    private SqliteConnection? connection;
    private int disposed;

    static SqliteXpk1ClaimJournal() => SQLitePCL.Batteries_V2.Init();

    public SqliteXpk1ClaimJournal(SqliteXpk1ClaimJournalOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Scope.StoreGeneration != ContactStoreScope.CurrentStoreGeneration)
            throw Failure(ContactStateStoreOpenFailure.UnsupportedGeneration,
                "Only the current ContactV1 store generation can own an XPK1 journal.");

        Scope = new ContactStoreScope(options.Scope.AccountId, options.Scope.StoreGeneration);
        statePath = options.StatePath;
        options.CopyKey(key);
        var exists = File.Exists(statePath);
        if (!exists && !options.AllowCreate)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(ContactStateStoreOpenFailure.UnreadableOrWrongKey,
                "The current XPK1 claim journal does not exist.");
        }
        if (exists && new FileInfo(statePath).Length == 0)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The XPK1 claim journal is empty.");
        }

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
            using (var opened = Open())
            {
                if (exists) ValidateExisting(opened);
                else Create(opened);
            }
            ValidateEncryptedFile();
            connection = Open();
            ValidateRows(connection);
        }
        catch (ContactStateStoreOpenException)
        {
            FailedOpen();
            throw;
        }
        catch (Exception error) when (error is SqliteException or InvalidOperationException
            or ArgumentException or FormatException or CryptographicException or OverflowException)
        {
            FailedOpen();
            throw Failure(ContactStateStoreOpenFailure.UnreadableOrWrongKey,
                "The XPK1 SQLCipher journal cannot be opened.", error);
        }
        catch
        {
            FailedOpen();
            throw;
        }
    }

    public ContactStoreScope Scope { get; }

    internal async ValueTask<Xpk1ClaimJournalEntry> StageAsync(
        ReadOnlyMemory<byte> exactXpk1,
        VerifiedXpc1PreKeyClaimReceipt? retainedVerifiedReceipt = null,
        CancellationToken cancellationToken = default)
    {
        var candidate = Xpk1ClaimJournalState.Stage(exactXpk1.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var row = ReadRow(db, tx, candidate.OperationId.Span);
            if (row is null)
            {
                Insert(db, tx, candidate, 1);
                tx.Commit();
                return new Xpk1ClaimJournalEntry(
                    Xpk1ClaimJournalDisposition.Staged, candidate, 1);
            }

            var current = Restore(row, retainedVerifiedReceipt);
            var transition = current.ApplyRequest(exactXpk1.Span);
            var revision = row.Revision;
            if (transition.RequiresDurableWrite)
            {
                revision = checked(revision + 1);
                Update(db, tx, transition.NextState, exactXpk1.ToArray(), revision);
            }
            tx.Commit();
            return new Xpk1ClaimJournalEntry(
                transition.Disposition, transition.NextState, revision);
        }
        finally
        {
            gate.Release();
        }
    }

    internal ValueTask<Xpk1ClaimJournalEntry> RecordFailureAsync(
        PreKeyV1DurableClaimOperation operation,
        ReadOnlyMemory<byte> exactXpc1,
        CancellationToken cancellationToken = default) =>
        RecordAsync(operation, exactXpc1, null, cancellationToken);

    internal ValueTask<Xpk1ClaimJournalEntry> RecordVerifiedClaimAsync(
        PreKeyV1DurableClaimOperation operation,
        ReadOnlyMemory<byte> exactXpc1,
        VerifiedXpc1PreKeyClaimReceipt verifiedReceipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifiedReceipt);
        return RecordAsync(operation, exactXpc1, verifiedReceipt, cancellationToken);
    }

    private async ValueTask<Xpk1ClaimJournalEntry> RecordAsync(
        PreKeyV1DurableClaimOperation operation,
        ReadOnlyMemory<byte> exactXpc1,
        VerifiedXpc1PreKeyClaimReceipt? verifiedReceipt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var row = ReadRow(db, tx, operation.OperationIdSpan)
                ?? throw new InvalidOperationException("The exact XPK1 operation was not durably staged.");
            if (row.Revision != operation.JournalRevision ||
                !CryptographicOperations.FixedTimeEquals(row.ExactXpk1, operation.ExactXpk1Span))
                throw new CryptographicException("The XPK1 dispatch lease is stale or belongs to another exact request.");

            var current = Restore(row, verifiedReceipt);
            var result = Xpc1Codec.Decode(exactXpc1.Span, operation.ExactXpk1Span);
            var transition = verifiedReceipt is null
                ? current.RecordFailureResult(result)
                : current.RecordVerifiedClaimResult(result, verifiedReceipt);
            var revision = row.Revision;
            if (transition.RequiresDurableWrite)
            {
                revision = checked(revision + 1);
                Update(db, tx, transition.NextState, null, revision);
            }
            tx.Commit();
            return new Xpk1ClaimJournalEntry(
                transition.Disposition, transition.NextState, revision);
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose()
    {
        gate.Wait();
        try
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            connection?.Dispose();
            connection = null;
            CryptographicOperations.ZeroMemory(key);
        }
        finally
        {
            gate.Release();
        }
    }

    private static Xpk1ClaimJournalState Restore(
        Row row,
        VerifiedXpc1PreKeyClaimReceipt? retainedVerifiedReceipt)
    {
        Xpk1ClaimJournalState state;
        if (row.ExactXpc1 is null)
        {
            state = Xpk1ClaimJournalState.Stage(row.ExactXpk1);
        }
        else if (row.SuccessfulResult)
        {
            if (retainedVerifiedReceipt is null)
                throw new CryptographicException(
                    "A persisted successful XPC1 must be reverified before journal restoration.");
            state = Xpk1ClaimJournalState.RestoreVerifiedClaim(
                row.ExactXpk1, row.ExactXpc1, retainedVerifiedReceipt);
        }
        else
        {
            state = Xpk1ClaimJournalState.RestoreFailure(row.ExactXpk1, row.ExactXpc1);
        }

        if (row.ForkRequest is not null)
        {
            var fork = state.ApplyRequest(row.ForkRequest);
            if (fork.Disposition != Xpk1ClaimJournalDisposition.ForkLatched)
                throw new InvalidDataException("The persisted XPK1 fork latch is not reproducible.");
            state = fork.NextState;
        }
        return state;
    }

    private static Row? ReadRow(SqliteConnection db, SqliteTransaction? tx, ReadOnlySpan<byte> operationId)
    {
        using var query = db.CreateCommand();
        query.Transaction = tx;
        query.CommandText = """
            SELECT exact_xpk1,exact_xpc1,successful_result,fork_request,revision
            FROM xpk1_claim_operations WHERE operation_id=$operation;
            """;
        query.Parameters.AddWithValue("$operation", operationId.ToArray());
        using var reader = query.ExecuteReader();
        if (!reader.Read()) return null;
        return new Row(
            (byte[])reader[0],
            reader.IsDBNull(1) ? null : (byte[])reader[1],
            reader.GetBoolean(2),
            reader.IsDBNull(3) ? null : (byte[])reader[3],
            ReadU64((byte[])reader[4]));
    }

    private static void Insert(
        SqliteConnection db,
        SqliteTransaction tx,
        Xpk1ClaimJournalState state,
        ulong revision)
    {
        using var command = db.CreateCommand();
        command.Transaction = tx;
        command.CommandText = """
            INSERT INTO xpk1_claim_operations(
                operation_id,exact_xpk1,exact_xpc1,successful_result,fork_request,revision)
            VALUES($operation,$request,NULL,0,NULL,$revision);
            """;
        command.Parameters.AddWithValue("$operation", state.OperationId.ToArray());
        command.Parameters.AddWithValue("$request", state.ExactRequest.ToArray());
        command.Parameters.AddWithValue("$revision", U64(revision));
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("The XPK1 claim operation was not staged.");
    }

    private static void Update(
        SqliteConnection db,
        SqliteTransaction tx,
        Xpk1ClaimJournalState state,
        byte[]? forkCandidate,
        ulong revision)
    {
        var successful = state.StoredStatus is Xpc1Status.Claimed or Xpc1Status.Replay;
        using var command = db.CreateCommand();
        command.Transaction = tx;
        command.CommandText = """
            UPDATE xpk1_claim_operations
            SET exact_xpc1=$result,successful_result=$successful,
                fork_request=COALESCE(fork_request,$fork),revision=$revision
            WHERE operation_id=$operation;
            """;
        command.Parameters.AddWithValue("$result",
            state.HasStoredResult ? state.StoredResultWire.ToArray() : DBNull.Value);
        command.Parameters.AddWithValue("$successful", successful ? 1 : 0);
        command.Parameters.AddWithValue("$fork",
            state.IsForkLatched && forkCandidate is not null
                ? forkCandidate
                : DBNull.Value);
        command.Parameters.AddWithValue("$revision", U64(revision));
        command.Parameters.AddWithValue("$operation", state.OperationId.ToArray());
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("The XPK1 claim journal transition was not persisted.");
    }

    private void ValidateRows(SqliteConnection db)
    {
        using var query = db.CreateCommand();
        query.CommandText = """
            SELECT operation_id,exact_xpk1,exact_xpc1,successful_result,fork_request,revision
            FROM xpk1_claim_operations ORDER BY operation_id;
            """;
        using var reader = query.ExecuteReader();
        while (reader.Read())
        {
            var operation = (byte[])reader[0];
            var request = (byte[])reader[1];
            var parsed = Xpk1ClaimJournalState.Stage(request);
            if (!CryptographicOperations.FixedTimeEquals(operation, parsed.OperationId.Span))
                throw new InvalidDataException("A persisted XPK1 operation ID does not match its exact request.");
            var result = reader.IsDBNull(2) ? null : (byte[])reader[2];
            var successful = reader.GetBoolean(3);
            if (result is not null)
            {
                var decoded = Xpc1Codec.Decode(result, request);
                if (successful != (decoded.Status is Xpc1Status.Claimed or Xpc1Status.Replay))
                    throw new InvalidDataException("A persisted XPC1 success classification is inconsistent.");
                if (!successful) _ = Xpk1ClaimJournalState.RestoreFailure(request, result);
            }
            if (!reader.IsDBNull(4))
            {
                var fork = Xpk1Codec.Decode((byte[])reader[4]);
                if (!CryptographicOperations.FixedTimeEquals(operation, fork.OperationId.Span))
                    throw new InvalidDataException("A persisted XPK1 fork belongs to another operation.");
            }
            if (ReadU64((byte[])reader[5]) == 0)
                throw new InvalidDataException("A persisted XPK1 journal revision is zero.");
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
                throw new SqliteException("SQLCipher rejected the XPK1 journal key.", result);
            Execute(db, null,
                "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;");
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
        using var tx = db.BeginTransaction(deferred: false);
        Execute(db, tx, Ddl);
        using var insert = db.CreateCommand();
        insert.Transaction = tx;
        insert.CommandText = "INSERT INTO xpk1_claim_journal_meta VALUES(1,$account,$generation);";
        insert.Parameters.AddWithValue("$account", Scope.AccountId.Bytes.ToArray());
        insert.Parameters.AddWithValue("$generation", Scope.StoreGeneration);
        insert.ExecuteNonQuery();
        tx.Commit();
        ValidateCipher(db);
    }

    private void ValidateExisting(SqliteConnection db)
    {
        if (Scalar(db, "PRAGMA application_id;") != ApplicationId ||
            Scalar(db, "PRAGMA user_version;") != SchemaGeneration)
            throw Failure(ContactStateStoreOpenFailure.UnsupportedGeneration,
                "The XPK1 claim journal schema generation is unsupported.");
        ValidateCipher(db);
        using var query = db.CreateCommand();
        query.CommandText =
            "SELECT account_id,store_generation FROM xpk1_claim_journal_meta WHERE singleton=1;";
        using var reader = query.ExecuteReader();
        if (!reader.Read())
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The XPK1 claim journal scope metadata is absent.");
        var accountId = (byte[])reader[0];
        var storeGeneration = reader.GetInt32(1);
        if (reader.Read())
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The XPK1 claim journal scope metadata is duplicated.");
        if (!Scope.AccountId.Matches(accountId) || storeGeneration != Scope.StoreGeneration)
            throw Failure(ContactStateStoreOpenFailure.ScopeMismatch,
                "The XPK1 claim journal belongs to another Deep account.");
    }

    private void ValidateEncryptedFile()
    {
        var header = new byte[16];
        using var stream = new FileStream(statePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (stream.Read(header, 0, header.Length) != header.Length ||
            header.AsSpan().SequenceEqual("SQLite format 3\0"u8))
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The XPK1 claim journal is not SQLCipher-encrypted.");
    }

    private static void ValidateCipher(SqliteConnection db)
    {
        using var command = db.CreateCommand();
        command.CommandText = "PRAGMA cipher_version;";
        if (string.IsNullOrWhiteSpace(Convert.ToString(command.ExecuteScalar())))
            throw Failure(ContactStateStoreOpenFailure.UnreadableOrWrongKey,
                "SQLCipher is unavailable for the XPK1 claim journal.");
    }

    private static int Scalar(SqliteConnection db, string sql)
    {
        using var command = db.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private static void Execute(SqliteConnection db, SqliteTransaction? tx, string sql)
    {
        using var command = db.CreateCommand();
        command.Transaction = tx;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private SqliteConnection GetConnection() => connection
        ?? throw new ObjectDisposedException(nameof(SqliteXpk1ClaimJournal));

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

    private void FailedOpen()
    {
        connection?.Dispose();
        connection = null;
        CryptographicOperations.ZeroMemory(key);
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static ulong ReadU64(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 8) throw new FormatException("The XPK1 journal revision is not u64.");
        return BinaryPrimitives.ReadUInt64BigEndian(bytes);
    }

    private static ContactStateStoreOpenException Failure(
        ContactStateStoreOpenFailure reason,
        string message,
        Exception? inner = null) => new(reason, message, inner);

    private sealed record Row(
        byte[] ExactXpk1,
        byte[]? ExactXpc1,
        bool SuccessfulResult,
        byte[]? ForkRequest,
        ulong Revision);
}
