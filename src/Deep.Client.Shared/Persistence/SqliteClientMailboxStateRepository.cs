using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

internal enum ClientMailboxMigrationFaultPoint
{
    AfterBackupBeforeRewrite
}

/// <summary>
/// SQLCipher-backed state containing only domain-separated scope hashes,
/// encrypted envelopes, cursor/token state, and receipt commitments.
/// </summary>
public sealed class SqliteClientMailboxStateRepository :
    IClientMailboxStateRepository,
    IDisposable
{
    private const int SchemaVersion = 2;
    private readonly string connectionString;
    private readonly Action<ClientMailboxMigrationFaultPoint>? migrationFault;
    private readonly Action<ClientMailboxCommitFaultPoint>? commitFault;
    private readonly SemaphoreSlim gate = new(1, 1);

    static SqliteClientMailboxStateRepository()
    {
        SQLitePCL.Batteries_V2.Init();
    }

    public SqliteClientMailboxStateRepository(SqliteSessionStoreOptions options)
        : this(options, migrationFault: null, commitFault: null)
    {
    }

    internal SqliteClientMailboxStateRepository(
        SqliteSessionStoreOptions options,
        Action<ClientMailboxMigrationFaultPoint>? migrationFault,
        Action<ClientMailboxCommitFaultPoint>? commitFault = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var encryptionKey = options.GetEncryptionKeyForStore();
        if (string.IsNullOrWhiteSpace(options.StatePath) ||
            string.IsNullOrWhiteSpace(encryptionKey))
        {
            throw new InvalidOperationException(
                "Client mailbox SQLite state requires the SQLCipher session-store key path.");
        }

        var directory = Path.GetDirectoryName(Path.GetFullPath(options.StatePath));
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = options.StatePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = false,
            Password = encryptionKey
        }.ToString();
        this.migrationFault = migrationFault;
        this.commitFault = commitFault;
        Initialize();
    }

    public Task<ClientMailboxTraversal> ReadTraversalAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken = default) =>
        ReadAsync(scope, ClientMailboxStateMachine.Traversal, cancellationToken);

    public Task<IReadOnlyList<MailboxRetrievedEnvelope>> ReadDurableInboxAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken = default) =>
        ReadAsync(
            scope,
            ClientMailboxStateMachine.DurableInbox,
            cancellationToken);

    public Task<ClientMailboxReceiveCommitResult> CommitRetrievePageAsync(
        ClientMailboxScope scope,
        ClientMailboxTraversal expectedTraversal,
        MailboxRetrievePage page,
        CancellationToken cancellationToken = default) =>
        MutateAsync(
            scope,
            state => ClientMailboxStateMachine.CommitPage(
                state,
                expectedTraversal,
                page),
            cancellationToken);

    public Task<ClientMailboxAckState> CheckAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        ReadAsync(
            scope,
            state => ClientMailboxStateMachine.Check(state, acknowledgements),
            cancellationToken);

    public Task<IReadOnlyList<ClientMailboxAckExpectation>> ReadAckExpectationsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        ReadAsync(
            scope,
            state => ClientMailboxStateMachine.AckExpectations(
                state,
                acknowledgements),
            cancellationToken);

    public Task<ClientMailboxAckState> CommitAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        MutateAsync(
            scope,
            state => ClientMailboxStateMachine.CommitAck(state, acknowledgements),
            cancellationToken);

    public Task<ClientMailboxCoordinatorRecordResult> RecordCoordinatorStatementAsync(
        ClientMailboxScope scope,
        ReadOnlyMemory<byte> membershipCommitment,
        ulong epoch,
        ReadOnlyMemory<byte> coordinatorId,
        ulong coordinatorSequence,
        ReadOnlyMemory<byte> statementDigest,
        ulong expiresAtUnixSeconds,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default) =>
        MutateAsync(
            scope,
            state => ClientMailboxStateMachine.RecordCoordinator(
                state,
                membershipCommitment.Span,
                epoch,
                coordinatorId.Span,
                coordinatorSequence,
                statementDigest.Span,
                expiresAtUnixSeconds,
                nowUnixSeconds),
            cancellationToken);

    internal void InsertRawStateForTests(
        ClientMailboxScope scope,
        ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(scope);
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO client_mailbox_state(scope, state_blob)
            VALUES($scope, $state)
            ON CONFLICT(scope) DO UPDATE SET state_blob = excluded.state_blob;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
        command.Parameters.Add("$state", SqliteType.Blob).Value = encoded.ToArray();
        command.ExecuteNonQuery();
    }

    internal int BackupCountForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM client_mailbox_migration_backup;";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal int QuarantineCountForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM client_mailbox_quarantine;";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    public void Dispose() => gate.Dispose();

    private void Initialize()
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                CREATE TABLE IF NOT EXISTS client_mailbox_meta (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    schema_version INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS client_mailbox_state (
                    scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) = 32),
                    state_blob BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS client_mailbox_migration_backup (
                    scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) = 32),
                    state_blob BLOB NOT NULL,
                    migrated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS client_mailbox_quarantine (
                    scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) = 32),
                    state_blob BLOB NOT NULL,
                    reason TEXT NOT NULL,
                    quarantined_at INTEGER NOT NULL
                );
                INSERT INTO client_mailbox_meta(id, schema_version)
                VALUES(1, 2)
                ON CONFLICT(id) DO NOTHING;
                """;
            command.ExecuteNonQuery();
        }

        using (var version = connection.CreateCommand())
        {
            version.Transaction = transaction;
            version.CommandText =
                "SELECT schema_version FROM client_mailbox_meta WHERE id = 1;";
            var found = Convert.ToInt32(version.ExecuteScalar());
            if (found is < 1 or > SchemaVersion)
            {
                throw new InvalidDataException(
                    "Client mailbox state schema version is unsupported.");
            }

            if (found < SchemaVersion)
            {
                version.CommandText =
                    "UPDATE client_mailbox_meta SET schema_version = 2 WHERE id = 1;";
                version.ExecuteNonQuery();
            }
        }

        var rows = new List<(byte[] Scope, byte[] State)>();
        using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT scope, state_blob FROM client_mailbox_state;";
            using var reader = select.ExecuteReader();
            while (reader.Read())
            {
                rows.Add((
                    reader.GetFieldValue<byte[]>(0),
                    reader.GetFieldValue<byte[]>(1)));
            }
        }

        var quarantined = false;
        foreach (var row in rows)
        {
            if (ClientMailboxStateCodec.IsVersionOne(row.State))
            {
                try
                {
                    var safe = ClientMailboxStateCodec
                        .MigrateVersionOneToSafeReplay(row.State);
                    InsertBackup(connection, transaction, row.Scope, row.State);
                    migrationFault?.Invoke(
                        ClientMailboxMigrationFaultPoint.AfterBackupBeforeRewrite);
                    WriteState(
                        connection,
                        transaction,
                        row.Scope,
                        ClientMailboxStateCodec.Encode(safe));
                }
                catch (InvalidDataException)
                {
                    Quarantine(connection, transaction, row.Scope, row.State);
                    quarantined = true;
                }

                continue;
            }

            try
            {
                _ = ClientMailboxStateCodec.Decode(row.State);
            }
            catch (InvalidDataException)
            {
                Quarantine(connection, transaction, row.Scope, row.State);
                quarantined = true;
            }
        }

        transaction.Commit();
        if (quarantined)
        {
            throw new InvalidDataException(
                "Corrupt client mailbox state was quarantined; retry starts a safe cursor-zero cycle.");
        }
    }

    private async Task<TResult> ReadAsync<TResult>(
        ClientMailboxScope scope,
        Func<ClientMailboxStoredState, TResult> read,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(read);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            var state = await LoadAsync(
                connection,
                transaction: null,
                scope,
                cancellationToken).ConfigureAwait(false);
            return read(state.Clone());
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<TResult> MutateAsync<TResult>(
        ClientMailboxScope scope,
        Func<ClientMailboxStoredState, TResult> mutation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(mutation);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction();
            var current = await LoadAsync(
                connection,
                transaction,
                scope,
                cancellationToken).ConfigureAwait(false);
            var candidate = current.Clone();
            var result = mutation(candidate);
            var encoded = ClientMailboxStateCodec.Encode(candidate);
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO client_mailbox_state(scope, state_blob)
                VALUES($scope, $state)
                ON CONFLICT(scope) DO UPDATE SET state_blob = excluded.state_blob;
                """;
            command.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
            command.Parameters.Add("$state", SqliteType.Blob).Value = encoded;
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return result;
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<ClientMailboxStoredState> LoadAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        ClientMailboxScope scope,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT state_blob FROM client_mailbox_state WHERE scope = $scope;";
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
        var value = await command.ExecuteScalarAsync(cancellationToken)
            .ConfigureAwait(false);
        return value is byte[] encoded
            ? ClientMailboxStateCodec.Decode(encoded)
            : new ClientMailboxStoredState();
    }

    private static void InsertBackup(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        byte[] state)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO client_mailbox_migration_backup(scope, state_blob, migrated_at)
            VALUES($scope, $state, $at)
            ON CONFLICT(scope) DO NOTHING;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
        command.Parameters.Add("$state", SqliteType.Blob).Value = state;
        command.Parameters.AddWithValue(
            "$at",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        command.ExecuteNonQuery();
    }

    private static void WriteState(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        byte[] state)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "UPDATE client_mailbox_state SET state_blob = $state WHERE scope = $scope;";
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
        command.Parameters.Add("$state", SqliteType.Blob).Value = state;
        command.ExecuteNonQuery();
    }

    private static void Quarantine(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        byte[] state)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO client_mailbox_quarantine(
                scope, state_blob, reason, quarantined_at)
            VALUES($scope, $state, 'invalid-canonical-state', $at)
            ON CONFLICT(scope) DO UPDATE SET
                state_blob = excluded.state_blob,
                reason = excluded.reason,
                quarantined_at = excluded.quarantined_at;
            DELETE FROM client_mailbox_state WHERE scope = $scope;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
        command.Parameters.Add("$state", SqliteType.Blob).Value = state;
        command.Parameters.AddWithValue(
            "$at",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        command.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        Configure(connection);
        return connection;
    }

    private async Task<SqliteConnection> OpenAsync(
        CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA busy_timeout=5000;
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            """;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }

    private static void Configure(SqliteConnection connection)
    {
        using var cipher = connection.CreateCommand();
        cipher.CommandText = "PRAGMA cipher_version;";
        if (string.IsNullOrWhiteSpace(cipher.ExecuteScalar()?.ToString()))
        {
            throw new InvalidOperationException(
                "SQLCipher support is unavailable for client mailbox state.");
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA busy_timeout=5000;
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            """;
        command.ExecuteNonQuery();
    }
}
