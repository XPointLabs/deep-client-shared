using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

/// <summary>
/// Clean-break SQLCipher owner for mailbox traversal and the authenticated
/// transport outbox. It has no Session tables, identifiers, readers, or
/// migration path. A schema mismatch requires an explicit local reset.
/// </summary>
public sealed partial class SqliteDeepMailboxStore :
    ITransportOutboxRepository,
    IScopedMailboxCredentialRepository,
    IDisposable
{
    private const int ApplicationId = 0x444D4231; // DMB1
    private const int SchemaVersion = 4;
    private readonly string _connectionString;
    private readonly byte[] encryptionKey;
    private readonly SemaphoreSlim _databaseGate = new(1, 1);
    private int _disposed;

    static SqliteDeepMailboxStore() => SQLitePCL.Batteries_V2.Init();

    public SqliteDeepMailboxStore(SqliteDeepMailboxStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.StatePath))
            throw new ArgumentException("State path is required.", nameof(options));
        if (options.EncryptionKey.Length != 32 ||
            options.EncryptionKey.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                "A nonzero 32-byte SQLCipher key is required.", nameof(options));

        var path = Path.GetFullPath(options.StatePath);
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        if (!File.Exists(path) &&
            (File.Exists(path + "-wal") || File.Exists(path + "-shm")))
            throw ResetRequired("Clean mailbox state is incomplete.");
        if (File.Exists(path) && new FileInfo(path).Length == 0)
            throw ResetRequired("Clean mailbox state is empty.");

        encryptionKey = options.EncryptionKey.ToArray();
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            ForeignKeys = true
        }.ToString();
        try
        {
            InitializeSchema();
        }
        catch
        {
            CryptographicOperations.ZeroMemory(encryptionKey);
            throw;
        }
    }

    private void InitializeSchema()
    {
        using var connection = new SqliteConnection(_connectionString);
        try
        {
            connection.Open();
            ApplyMailboxEncryptionKey(connection);
            Configure(connection);
            using var transaction = connection.BeginTransaction(deferred: false);
            var applicationId = ReadPragma(connection, transaction, "application_id");
            var version = ReadPragma(connection, transaction, "user_version");
            if (applicationId == 0 && version == 0)
            {
                CreateSchema(connection, transaction);
            }
            else if (applicationId != ApplicationId || version != SchemaVersion)
            {
                throw ResetRequired(
                    "Clean mailbox state belongs to another or unsupported generation.");
            }
            ValidateTransportOutboxSchema(connection, transaction);
            ValidateDirectInboxState(connection, transaction);
            transaction.Commit();
            ValidateCipher(connection);
        }
        catch (LocalStateResetRequiredException)
        {
            throw;
        }
        catch (SqliteException exception)
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.UnreadableOrWrongKey,
                "Clean mailbox state is unreadable or has the wrong key.",
                exception);
        }
    }

    private static void CreateSchema(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE client_mailbox_traversal (
                scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) = 32),
                after_cursor BLOB NOT NULL CHECK(length(after_cursor) = 8),
                continuation_token BLOB NOT NULL);
            CREATE TABLE client_mailbox_poll_clock (
                scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) = 32),
                generation BLOB NOT NULL CHECK(length(generation) = 8));
            CREATE TABLE client_mailbox_inbox (
                scope BLOB NOT NULL CHECK(length(scope) = 32),
                cursor BLOB NOT NULL CHECK(length(cursor) = 8),
                digest BLOB NOT NULL CHECK(length(digest) = 32),
                expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                canonical_envelope BLOB NOT NULL,
                acknowledged INTEGER NOT NULL CHECK(acknowledged IN (0, 1)),
                PRIMARY KEY(scope, cursor), UNIQUE(scope, digest));
            CREATE TABLE client_mailbox_expired_quarantine (
                scope BLOB NOT NULL CHECK(length(scope) = 32),
                cursor BLOB NOT NULL CHECK(length(cursor) = 8),
                digest BLOB NOT NULL CHECK(length(digest) = 32),
                expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                canonical_envelope BLOB NOT NULL,
                quarantined_at INTEGER NOT NULL,
                reason TEXT NOT NULL,
                PRIMARY KEY(scope, cursor, digest));
            CREATE TABLE client_mailbox_coordinator_journal (
                installation_scope BLOB NOT NULL CHECK(length(installation_scope) = 32),
                statement_key BLOB NOT NULL CHECK(length(statement_key) = 32),
                statement_digest BLOB NOT NULL CHECK(length(statement_digest) = 32),
                expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                PRIMARY KEY(installation_scope, statement_key));
            CREATE TABLE transport_outbox_items (
                account_scope BLOB NOT NULL, logical_id BLOB NOT NULL,
                dedup_material BLOB NOT NULL, ciphertext_bundle BLOB NOT NULL,
                created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                not_before INTEGER NOT NULL, state INTEGER NOT NULL,
                revision INTEGER NOT NULL, transition_source INTEGER NOT NULL,
                transition_reason INTEGER NOT NULL, transitioned_at INTEGER NOT NULL,
                last_transition_state INTEGER NOT NULL, last_attempt_id BLOB NULL,
                last_retry_not_before INTEGER NULL, acknowledgement_evidence BLOB NULL,
                acknowledged_at INTEGER NULL,
                PRIMARY KEY(account_scope, logical_id));
            CREATE TABLE transport_outbox_attempts (
                account_scope BLOB NOT NULL, logical_id BLOB NOT NULL,
                attempt_id BLOB NOT NULL, state INTEGER NOT NULL,
                transition_source INTEGER NOT NULL, transition_reason INTEGER NOT NULL,
                occurred_at INTEGER NOT NULL, evidence BLOB NOT NULL,
                PRIMARY KEY(account_scope, logical_id, attempt_id),
                FOREIGN KEY(account_scope, logical_id)
                    REFERENCES transport_outbox_items(account_scope, logical_id)
                    ON DELETE CASCADE);
            CREATE TABLE authenticated_dmc2_inbox_owner (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                local_account_id BLOB NOT NULL CHECK(length(local_account_id) = 32),
                local_account_generation BLOB NOT NULL CHECK(length(local_account_generation) = 8));
            CREATE TABLE authenticated_dmc2_inbox (
                conversation_id BLOB NOT NULL CHECK(length(conversation_id) = 32),
                logical_message_id BLOB NOT NULL CHECK(length(logical_message_id) = 32),
                author_device_id BLOB NOT NULL CHECK(length(author_device_id) = 32),
                author_account_id BLOB NOT NULL CHECK(length(author_account_id) = 32),
                content_kind INTEGER NOT NULL,
                exact_dmc2_hash BLOB NOT NULL CHECK(length(exact_dmc2_hash) = 32),
                exact_dmc2 BLOB NOT NULL CHECK(length(exact_dmc2) BETWEEN 282 AND 33082),
                materialized_at INTEGER NOT NULL CHECK(materialized_at > 0),
                PRIMARY KEY(conversation_id, logical_message_id, author_device_id));
            CREATE TABLE authenticated_dmc2_inbox_forks (
                conversation_id BLOB NOT NULL CHECK(length(conversation_id) = 32),
                logical_message_id BLOB NOT NULL CHECK(length(logical_message_id) = 32),
                author_device_id BLOB NOT NULL CHECK(length(author_device_id) = 32),
                incumbent_hash BLOB NOT NULL CHECK(length(incumbent_hash) = 32),
                conflicting_hash BLOB NOT NULL CHECK(length(conflicting_hash) = 32),
                PRIMARY KEY(conversation_id, logical_message_id, author_device_id),
                FOREIGN KEY(conversation_id, logical_message_id, author_device_id)
                    REFERENCES authenticated_dmc2_inbox(conversation_id, logical_message_id, author_device_id)
                    ON DELETE RESTRICT);
            CREATE TABLE direct_sender_sequences (
                conversation_id BLOB NOT NULL CHECK(length(conversation_id) = 32),
                author_device_id BLOB NOT NULL CHECK(length(author_device_id) = 32),
                next_sequence INTEGER NOT NULL CHECK(next_sequence >= 3),
                PRIMARY KEY(conversation_id, author_device_id));
            CREATE TABLE direct_text_outbox (
                conversation_id BLOB NOT NULL CHECK(length(conversation_id) = 32),
                logical_message_id BLOB NOT NULL CHECK(length(logical_message_id) = 32),
                author_device_id BLOB NOT NULL CHECK(length(author_device_id) = 32),
                recipient_account_id BLOB NOT NULL CHECK(length(recipient_account_id) = 32),
                recipient_device_id BLOB NOT NULL CHECK(length(recipient_device_id) = 32),
                sender_sequence INTEGER NOT NULL CHECK(sender_sequence >= 3),
                operation_id BLOB NOT NULL UNIQUE CHECK(length(operation_id) = 32),
                exact_dmc2_hash BLOB NOT NULL CHECK(length(exact_dmc2_hash) = 32),
                exact_dmc2 BLOB NOT NULL CHECK(length(exact_dmc2) BETWEEN 285 AND 16668),
                created_at INTEGER NOT NULL CHECK(created_at > 0),
                PRIMARY KEY(conversation_id, logical_message_id, author_device_id),
                UNIQUE(conversation_id, author_device_id, sender_sequence));
            CREATE TABLE mailbox_credential_scopes (
                scope_id BLOB NOT NULL PRIMARY KEY CHECK(length(scope_id) = 32),
                account_scope BLOB NOT NULL CHECK(length(account_scope) = 32),
                scope_kind INTEGER NOT NULL CHECK(scope_kind IN (1, 2, 3)),
                subject_id BLOB NOT NULL CHECK(length(subject_id) = 32),
                issuer_context BLOB NOT NULL CHECK(length(issuer_context) = 32),
                network_id BLOB NOT NULL CHECK(length(network_id) = 16),
                authority_policy_digest BLOB NOT NULL CHECK(length(authority_policy_digest) = 32),
                holder_key BLOB NOT NULL CHECK(length(holder_key) = 32),
                generation BLOB NOT NULL CHECK(length(generation) = 32),
                active_epoch BLOB NOT NULL CHECK(length(active_epoch) = 8),
                group_membership_commitment BLOB NULL
                    CHECK(group_membership_commitment IS NULL OR length(group_membership_commitment) = 32),
                UNIQUE(account_scope, scope_kind, subject_id, issuer_context));
            CREATE TABLE mailbox_credential_epochs (
                scope_id BLOB NOT NULL CHECK(length(scope_id) = 32),
                epoch BLOB NOT NULL CHECK(length(epoch) = 8),
                not_before BLOB NOT NULL CHECK(length(not_before) = 8),
                expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                mailbox_id BLOB NOT NULL CHECK(length(mailbox_id) = 32),
                placement_id BLOB NOT NULL CHECK(length(placement_id) = 32),
                placement_commitment BLOB NOT NULL CHECK(length(placement_commitment) = 32),
                membership_commitment BLOB NOT NULL CHECK(length(membership_commitment) = 32),
                first_replica_id BLOB NOT NULL CHECK(length(first_replica_id) = 32),
                first_replica_key BLOB NOT NULL CHECK(length(first_replica_key) = 32),
                second_replica_id BLOB NOT NULL CHECK(length(second_replica_id) = 32),
                second_replica_key BLOB NOT NULL CHECK(length(second_replica_key) = 32),
                PRIMARY KEY(scope_id, epoch),
                FOREIGN KEY(scope_id) REFERENCES mailbox_credential_scopes(scope_id) ON DELETE CASCADE);
            CREATE TABLE mailbox_credential_grants (
                scope_id BLOB NOT NULL CHECK(length(scope_id) = 32),
                epoch BLOB NOT NULL CHECK(length(epoch) = 8),
                role INTEGER NOT NULL CHECK(role IN (1, 2)),
                issuer_context BLOB NOT NULL CHECK(length(issuer_context) = 32),
                grant_digest BLOB NOT NULL CHECK(length(grant_digest) = 32),
                issuer_key BLOB NOT NULL CHECK(length(issuer_key) = 32),
                serial BLOB NOT NULL,
                canonical_grant BLOB NOT NULL,
                PRIMARY KEY(scope_id, epoch, role),
                UNIQUE(issuer_key, serial),
                FOREIGN KEY(scope_id, epoch)
                    REFERENCES mailbox_credential_epochs(scope_id, epoch) ON DELETE CASCADE);
            CREATE TABLE mailbox_replay_counters (
                scope_id BLOB NOT NULL CHECK(length(scope_id) = 32),
                epoch BLOB NOT NULL CHECK(length(epoch) = 8),
                grant_digest BLOB NOT NULL CHECK(length(grant_digest) = 32),
                next_counter BLOB NOT NULL CHECK(length(next_counter) = 8),
                PRIMARY KEY(scope_id, epoch, grant_digest));
            CREATE TABLE mailbox_prepared_batches (
                account_scope BLOB NOT NULL CHECK(length(account_scope) = 32),
                parent_operation_id BLOB NOT NULL CHECK(length(parent_operation_id) = 16),
                semantic_operation_id BLOB NOT NULL CHECK(length(semantic_operation_id) = 16),
                plan_digest BLOB NOT NULL CHECK(length(plan_digest) = 32),
                target_count INTEGER NOT NULL CHECK(target_count BETWEEN 1 AND 2048),
                created_at INTEGER NOT NULL,
                PRIMARY KEY(account_scope, parent_operation_id),
                UNIQUE(account_scope, semantic_operation_id));
            CREATE TABLE mailbox_prepared_batch_targets (
                account_scope BLOB NOT NULL CHECK(length(account_scope) = 32),
                parent_operation_id BLOB NOT NULL CHECK(length(parent_operation_id) = 16),
                target_ordinal INTEGER NOT NULL CHECK(target_ordinal BETWEEN 0 AND 2047),
                target_operation_id BLOB NOT NULL CHECK(length(target_operation_id) = 16),
                scope_id BLOB NOT NULL CHECK(length(scope_id) = 32),
                request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                replay_counter BLOB NOT NULL CHECK(length(replay_counter) = 8),
                PRIMARY KEY(account_scope, parent_operation_id, target_ordinal),
                UNIQUE(account_scope, target_operation_id),
                FOREIGN KEY(account_scope, parent_operation_id)
                    REFERENCES mailbox_prepared_batches(account_scope, parent_operation_id)
                    ON DELETE CASCADE);
            CREATE INDEX idx_client_mailbox_inbox_scope_expiry
                ON client_mailbox_inbox(scope, expires_at);
            CREATE INDEX idx_client_mailbox_inbox_expiry_scope
                ON client_mailbox_inbox(expires_at, scope);
            CREATE INDEX idx_client_mailbox_inbox_scope_ack_cursor
                ON client_mailbox_inbox(scope, acknowledged, cursor);
            CREATE INDEX idx_client_mailbox_quarantine_age
                ON client_mailbox_expired_quarantine(quarantined_at, expires_at, scope);
            CREATE INDEX idx_client_mailbox_journal_scope_expiry
                ON client_mailbox_coordinator_journal(installation_scope, expires_at);
            CREATE INDEX idx_transport_outbox_ready
                ON transport_outbox_items(account_scope, state, not_before, expires_at, created_at);
            CREATE INDEX idx_transport_outbox_expiry
                ON transport_outbox_items(account_scope, expires_at, state);
            """;
        command.ExecuteNonQuery();
        using var mark = connection.CreateCommand();
        mark.Transaction = transaction;
        mark.CommandText = $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaVersion};";
        mark.ExecuteNonQuery();
    }

    private async Task<TResult> WithReplayConnectionAsync<TResult>(
        Func<SqliteConnection, Task<TResult>> action,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            return await action(connection).ConfigureAwait(false);
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    private void ApplyMailboxEncryptionKey(SqliteConnection connection)
    {
        var result = SQLitePCL.raw.sqlite3_key(connection.Handle, encryptionKey);
        if (result != SQLitePCL.raw.SQLITE_OK)
            throw new SqliteException("SQLCipher rejected the mailbox key.", result);
    }

    private static void ValidateCipher(SqliteConnection connection)
    {
        using var version = connection.CreateCommand();
        version.CommandText = "PRAGMA cipher_version;";
        var value = Convert.ToString(version.ExecuteScalar(),
            System.Globalization.CultureInfo.InvariantCulture);
        if (string.IsNullOrWhiteSpace(value) || !value.StartsWith("4.", StringComparison.Ordinal))
            throw ResetRequired("SQLCipher generation 4 is required for mailbox state.");
        using var integrity = connection.CreateCommand();
        integrity.CommandText = "PRAGMA cipher_integrity_check;";
        using var reader = integrity.ExecuteReader();
        if (reader.Read()) throw ResetRequired("Mailbox SQLCipher integrity check failed.");
    }

    private static int ReadPragma(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string name)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA {name};";
        return Convert.ToInt32(command.ExecuteScalar(),
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private static void ValidateTransportOutboxSchema(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        foreach (var table in new[] {
                     "transport_outbox_items", "transport_outbox_attempts",
                     "authenticated_dmc2_inbox_owner", "authenticated_dmc2_inbox",
                     "authenticated_dmc2_inbox_forks", "direct_sender_sequences",
                     "direct_text_outbox", "mailbox_credential_scopes",
                     "mailbox_credential_epochs", "mailbox_credential_grants",
                     "mailbox_replay_counters", "mailbox_prepared_batches",
                     "mailbox_prepared_batch_targets" })
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=$name;";
            command.Parameters.AddWithValue("$name", table);
            if (Convert.ToInt32(command.ExecuteScalar(),
                    System.Globalization.CultureInfo.InvariantCulture) != 1)
                throw ResetRequired("Clean mailbox outbox schema is incomplete.");
        }
    }

    private static void ValidateDirectInboxState(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        using var count = connection.CreateCommand();
        count.Transaction = transaction;
        count.CommandText = "SELECT (SELECT count(*) FROM authenticated_dmc2_inbox_owner),(SELECT count(*) FROM authenticated_dmc2_inbox),(SELECT count(*) FROM authenticated_dmc2_inbox_forks),(SELECT count(*) FROM direct_text_outbox),(SELECT count(*) FROM direct_sender_sequences);";
        using (var reader = count.ExecuteReader())
        {
            if (!reader.Read()) throw ResetRequired("Clean direct inbox state is missing.");
            var ownerCount = reader.GetInt64(0);
            var eventCount = reader.GetInt64(1);
            var forkCount = reader.GetInt64(2);
            var outboundCount = reader.GetInt64(3);
            var senderCount = reader.GetInt64(4);
            if (ownerCount is < 0 or > 1 ||
                eventCount is < 0 or > 100_000 ||
                forkCount < 0 || forkCount > eventCount ||
                outboundCount is < 0 or > 100_000 ||
                senderCount is < 0 or > 100_000 ||
                ownerCount == 0 &&
                    (eventCount != 0 || outboundCount != 0 || senderCount != 0))
                throw ResetRequired("Clean direct inbox ownership or cardinality is invalid.");
        }
        using var foreignKeys = connection.CreateCommand();
        foreignKeys.Transaction = transaction;
        foreignKeys.CommandText = "PRAGMA foreign_key_check;";
        using var violation = foreignKeys.ExecuteReader();
        if (violation.Read())
            throw ResetRequired("Clean direct inbox foreign-key lineage is invalid.");
    }

    private static void EnableSqliteSecureDelete(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA secure_delete=ON;";
        command.ExecuteNonQuery();
    }

    private static LocalStateResetRequiredException ResetRequired(string message) =>
        new(LocalStateResetRequiredReason.InvalidCurrentSchema, message);

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new ObjectDisposedException(nameof(SqliteDeepMailboxStore));
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _databaseGate.Wait();
        try
        {
            CryptographicOperations.ZeroMemory(encryptionKey);
        }
        finally
        {
            _databaseGate.Release();
            _databaseGate.Dispose();
        }
    }
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class SqliteDeepMailboxStoreOptions : IDisposable
{
    private readonly byte[] encryptionKey;
    private int disposed;

    public SqliteDeepMailboxStoreOptions(
        string statePath,
        ReadOnlySpan<byte> encryptionKey)
    {
        StatePath = statePath;
        this.encryptionKey = encryptionKey.ToArray();
    }

    public string StatePath { get; }
    public ReadOnlyMemory<byte> EncryptionKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            return encryptionKey;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            CryptographicOperations.ZeroMemory(encryptionKey);
    }

    public override string ToString() =>
        $"{nameof(SqliteDeepMailboxStoreOptions)} {{ StatePath = " +
        $"{(string.IsNullOrWhiteSpace(StatePath) ? "[missing]" : "[configured]")}, " +
        "EncryptionKey = [redacted] }";
}
