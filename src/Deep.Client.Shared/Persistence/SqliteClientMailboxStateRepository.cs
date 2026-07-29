using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

internal enum ClientMailboxMigrationFaultPoint
{
    AfterBackupBeforeRewrite,
    AfterCorruptEvidenceBeforeLegacyDelete
}

/// <summary>
/// SQLCipher-backed state containing only domain-separated scope hashes,
/// encrypted envelopes, cursor/token state, and receipt commitments.
/// </summary>
public sealed class SqliteClientMailboxStateRepository :
    IClientMailboxStateRepository,
    IDisposable
{
    private const int SchemaVersion = 5;
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
        ReadNormalizedAsync(
            scope,
            static (connection, transaction, value, token) =>
                ReadTraversalCoreAsync(connection, transaction, value, token),
            cancellationToken);

    public Task<IReadOnlyList<MailboxRetrievedEnvelope>> ReadDurableInboxAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken = default) =>
        ReadNormalizedAsync(
            scope,
            static async (connection, transaction, value, token) =>
                ClientMailboxStateMachine.DurableInbox(
                    await LoadNormalizedStateAsync(
                        connection, transaction, value, token)
                        .ConfigureAwait(false)),
            cancellationToken);

    public Task<ClientMailboxExpiryReconciliationResult> ReconcileExpiredAsync(
        ClientMailboxScope scope,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default) =>
        ReconcileExpiredNormalizedAsync(scope, nowUnixSeconds, cancellationToken);

    public Task<ClientMailboxReceiveCommitResult> CommitRetrievePageAsync(
        ClientMailboxScope scope,
        ClientMailboxTraversal expectedTraversal,
        MailboxRetrievePage page,
        CancellationToken cancellationToken = default) =>
        CommitPageNormalizedAsync(
            scope, expectedTraversal, page, cancellationToken);

    public Task<ClientMailboxAckState> CheckAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        ReadNormalizedAsync(
            scope,
            async (connection, transaction, value, token) =>
                ClientMailboxStateMachine.Check(
                    await LoadNormalizedStateAsync(
                        connection, transaction, value, token)
                        .ConfigureAwait(false),
                    acknowledgements),
            cancellationToken);

    public Task<IReadOnlyList<ClientMailboxAckExpectation>> ReadAckExpectationsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        ReadNormalizedAsync(
            scope,
            async (connection, transaction, value, token) =>
                ClientMailboxStateMachine.AckExpectations(
                    await LoadNormalizedStateAsync(
                        connection, transaction, value, token)
                        .ConfigureAwait(false),
                    acknowledgements),
            cancellationToken);

    public Task<ClientMailboxAckState> CommitAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        CommitAckNormalizedAsync(scope, acknowledgements, cancellationToken);

    public Task<ClientMailboxCoordinatorRecordResult> RecordCoordinatorStatementAsync(
        ClientMailboxJournalScope scope,
        ReadOnlyMemory<byte> membershipCommitment,
        ulong epoch,
        ReadOnlyMemory<byte> coordinatorId,
        ulong coordinatorSequence,
        ReadOnlyMemory<byte> statementDigest,
        ulong expiresAtUnixSeconds,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default) =>
        RecordCoordinatorNormalizedAsync(
            scope,
            membershipCommitment,
            epoch,
            coordinatorId,
            coordinatorSequence,
            statementDigest,
            expiresAtUnixSeconds,
            nowUnixSeconds,
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

    internal void InsertRawStatesForTests(
        IReadOnlyList<(ClientMailboxScope Scope, byte[] Encoded)> snapshots)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        foreach (var snapshot in snapshots)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO client_mailbox_state(scope, state_blob)
                VALUES($scope, $state)
                ON CONFLICT(scope) DO UPDATE SET state_blob = excluded.state_blob;
                """;
            command.Parameters.Add("$scope", SqliteType.Blob).Value =
                snapshot.Scope.ToArray();
            command.Parameters.Add("$state", SqliteType.Blob).Value =
                snapshot.Encoded;
            command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    internal void InsertOversizedRawStateForTests(
        ClientMailboxScope scope,
        long bytes)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (bytes <= ClientMailboxStateLimits.MaximumLegacyStateBlobBytes ||
            bytes > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(bytes));
        }

        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO client_mailbox_state(scope, state_blob)
            VALUES($scope, zeroblob($bytes))
            ON CONFLICT(scope) DO UPDATE SET state_blob = excluded.state_blob;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
        command.Parameters.AddWithValue("$bytes", bytes);
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
        command.CommandText = """
            SELECT
                COALESCE((SELECT corrupt_count
                    FROM client_mailbox_corrupt_aggregate WHERE id = 1), 0) +
                (SELECT count(*) FROM client_mailbox_quarantine);
            """;
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal long CorruptEvidenceStoredBytesForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                COALESCE((SELECT length(evidence_digest) + length(first_prefix) +
                    length(last_reason)
                    FROM client_mailbox_corrupt_aggregate WHERE id = 1), 0) +
                COALESCE((SELECT sum(length(state_blob))
                    FROM client_mailbox_quarantine), 0);
            """;
        return Convert.ToInt64(command.ExecuteScalar());
    }

    internal int InstallationTraversalCountForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM client_mailbox_traversal;";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal long InstallationTraversalTokenBytesForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COALESCE(sum(length(continuation_token)), 0)
            FROM client_mailbox_traversal;
            """;
        return Convert.ToInt64(command.ExecuteScalar());
    }

    internal int LegacyStateCountForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM client_mailbox_state;";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal int NormalizedInboxCountForTests(ClientMailboxScope scope)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT count(*) FROM client_mailbox_inbox WHERE scope = $scope;";
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal int ExpiredQuarantineCountForTests(ClientMailboxScope scope)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT count(*) FROM client_mailbox_expired_quarantine
            WHERE scope = $scope;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal int InstallationInboxCountForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM client_mailbox_inbox;";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal int InstallationExpiredQuarantineCountForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT count(*) FROM client_mailbox_expired_quarantine;";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal int CoordinatorJournalCountForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                (SELECT count(*) FROM client_mailbox_coordinator_journal) +
                (SELECT count(*) FROM client_mailbox_legacy_journal_guard_v2);
            """;
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal void SeedNormalizedStatesForTests(
        IReadOnlyList<(ClientMailboxScope Scope, byte[] Encoded)> snapshots)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        foreach (var snapshot in snapshots)
        {
            InsertNormalizedSnapshot(
                connection,
                transaction,
                snapshot.Scope.ToArray(),
                ClientMailboxStateCodec.Decode(snapshot.Encoded));
        }

        transaction.Commit();
    }

    internal void SeedCoordinatorJournalForTests(
        int count,
        ulong expiresAtUnixSeconds)
    {
        if (count < 0 || expiresAtUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        using (var clear = connection.CreateCommand())
        {
            clear.Transaction = transaction;
            clear.CommandText = """
                DELETE FROM client_mailbox_coordinator_journal;
                DELETE FROM client_mailbox_legacy_journal_guard;
                DELETE FROM client_mailbox_legacy_journal_guard_v2;
                """;
            clear.ExecuteNonQuery();
        }

        for (var index = 0; index < count; index++)
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO client_mailbox_coordinator_journal(
                    installation_scope, statement_key,
                    statement_digest, expires_at)
                VALUES($scope, $key, $digest, $expires);
                """;
            insert.Parameters.Add("$scope", SqliteType.Blob).Value =
                SHA256.HashData([
                    .. "test-installation-journal-scope"u8,
                    .. U64(checked((ulong)(index % 17) + 1))
                ]);
            insert.Parameters.Add("$key", SqliteType.Blob).Value =
                SHA256.HashData([
                    .. "test-coordinator-statement-key"u8,
                    .. U64(checked((ulong)index + 1))
                ]);
            insert.Parameters.Add("$digest", SqliteType.Blob).Value =
                SHA256.HashData([
                    .. "test-coordinator-statement-digest"u8,
                    .. U64(checked((ulong)index + 1))
                ]);
            insert.Parameters.Add("$expires", SqliteType.Blob).Value =
                U64(expiresAtUnixSeconds);
            insert.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    internal void AgeMigrationArtifactsForTests(long unixSeconds)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE client_mailbox_migration_backup SET migrated_at = $at;
            UPDATE client_mailbox_quarantine SET quarantined_at = $at;
            UPDATE client_mailbox_corrupt_aggregate SET updated_at = $at;
            UPDATE client_mailbox_migration_cutover SET verified_at = $at;
            """;
        command.Parameters.AddWithValue("$at", unixSeconds);
        command.ExecuteNonQuery();
    }

    internal int MigrationCutoverCountForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT count(*) FROM client_mailbox_migration_cutover;";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal void SimulateVersionThreeWithoutCutoverMarkerForTests()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE client_mailbox_meta SET schema_version = 3 WHERE id = 1;
            DELETE FROM client_mailbox_migration_cutover;
            """;
        command.ExecuteNonQuery();
    }

    public void Dispose() => gate.Dispose();

    private void Initialize()
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
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
                CREATE TABLE IF NOT EXISTS client_mailbox_migration_cutover (
                    scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) = 32),
                    verified_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS client_mailbox_quarantine (
                    scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) = 32),
                    state_blob BLOB NOT NULL,
                    reason TEXT NOT NULL,
                    quarantined_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS client_mailbox_corrupt_aggregate (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    corrupt_count INTEGER NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    evidence_digest BLOB NOT NULL
                        CHECK(length(evidence_digest) = 32),
                    first_prefix BLOB NOT NULL
                        CHECK(length(first_prefix) <= 256),
                    last_reason TEXT NOT NULL CHECK(length(last_reason) <= 64),
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS client_mailbox_traversal (
                    scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) = 32),
                    after_cursor BLOB NOT NULL CHECK(length(after_cursor) = 8),
                    continuation_token BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS client_mailbox_inbox (
                    scope BLOB NOT NULL CHECK(length(scope) = 32),
                    cursor BLOB NOT NULL CHECK(length(cursor) = 8),
                    digest BLOB NOT NULL CHECK(length(digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    canonical_envelope BLOB NOT NULL,
                    acknowledged INTEGER NOT NULL CHECK(acknowledged IN (0, 1)),
                    PRIMARY KEY(scope, cursor),
                    UNIQUE(scope, digest)
                );
                CREATE INDEX IF NOT EXISTS ix_client_mailbox_inbox_scope_expiry
                    ON client_mailbox_inbox(scope, expires_at);
                CREATE INDEX IF NOT EXISTS ix_client_mailbox_inbox_expiry_scope
                    ON client_mailbox_inbox(expires_at, scope);
                CREATE INDEX IF NOT EXISTS ix_client_mailbox_inbox_scope_ack_cursor
                    ON client_mailbox_inbox(scope, acknowledged, cursor);
                CREATE TABLE IF NOT EXISTS client_mailbox_expired_quarantine (
                    scope BLOB NOT NULL CHECK(length(scope) = 32),
                    cursor BLOB NOT NULL CHECK(length(cursor) = 8),
                    digest BLOB NOT NULL CHECK(length(digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    canonical_envelope BLOB NOT NULL,
                    quarantined_at INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    PRIMARY KEY(scope, cursor, digest)
                );
                CREATE INDEX IF NOT EXISTS ix_client_mailbox_quarantine_age
                    ON client_mailbox_expired_quarantine(
                        quarantined_at, expires_at, scope);
                CREATE TABLE IF NOT EXISTS client_mailbox_coordinator_journal (
                    installation_scope BLOB NOT NULL
                        CHECK(length(installation_scope) = 32),
                    statement_key BLOB NOT NULL CHECK(length(statement_key) = 32),
                    statement_digest BLOB NOT NULL
                        CHECK(length(statement_digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    PRIMARY KEY(installation_scope, statement_key)
                );
                CREATE INDEX IF NOT EXISTS ix_client_mailbox_journal_scope_expiry
                    ON client_mailbox_coordinator_journal(
                        installation_scope, expires_at);
                CREATE TABLE IF NOT EXISTS client_mailbox_legacy_journal_guard (
                    legacy_mailbox_scope BLOB NOT NULL
                        CHECK(length(legacy_mailbox_scope) = 32),
                    statement_key BLOB NOT NULL CHECK(length(statement_key) = 32),
                    statement_digest BLOB NOT NULL
                        CHECK(length(statement_digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    PRIMARY KEY(legacy_mailbox_scope, statement_key)
                );
                CREATE INDEX IF NOT EXISTS ix_client_mailbox_legacy_journal_key
                    ON client_mailbox_legacy_journal_guard(
                        statement_key, expires_at);
                CREATE TABLE IF NOT EXISTS client_mailbox_legacy_journal_guard_v2 (
                    statement_key BLOB PRIMARY KEY NOT NULL
                        CHECK(length(statement_key) = 32),
                    statement_digest BLOB NOT NULL
                        CHECK(length(statement_digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    conflict INTEGER NOT NULL CHECK(conflict IN (0, 1))
                );
                CREATE INDEX IF NOT EXISTS ix_client_mailbox_legacy_guard_v2_expiry
                    ON client_mailbox_legacy_journal_guard_v2(expires_at);
                INSERT INTO client_mailbox_meta(id, schema_version)
                VALUES(1, 5)
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
                    "UPDATE client_mailbox_meta SET schema_version = 5 WHERE id = 1;";
                version.ExecuteNonQuery();
            }
        }

        using (var backfill = connection.CreateCommand())
        {
            backfill.Transaction = transaction;
            backfill.CommandText = """
                INSERT INTO client_mailbox_migration_cutover(scope, verified_at)
                SELECT backup.scope, backup.migrated_at
                FROM client_mailbox_migration_backup AS backup
                WHERE NOT EXISTS (
                    SELECT 1 FROM client_mailbox_state AS legacy
                    WHERE legacy.scope = backup.scope)
                ON CONFLICT(scope) DO NOTHING;
                """;
            backfill.ExecuteNonQuery();
        }

        CompactExistingCorruptQuarantine(connection, transaction);
        UpgradeLegacyJournalGuards(connection, transaction);

        var quarantined = false;
        byte[]? previousScope = null;
        while (TryReadNextLegacyStateMetadata(
                   connection,
                   transaction,
                   previousScope,
                   out var scope,
                   out var stateBytes))
        {
            previousScope = scope;
            if (stateBytes < 0 ||
                stateBytes > ClientMailboxStateLimits.MaximumLegacyStateBlobBytes)
            {
                CompactLegacyStateFromDatabase(
                    connection,
                    transaction,
                    scope,
                    stateBytes,
                    "oversized-legacy-state");
                quarantined = true;
                continue;
            }

            var state = LoadBoundedLegacyState(
                connection, transaction, scope, stateBytes);
            ClientMailboxStoredState decoded;
            try
            {
                decoded = ClientMailboxStateCodec.IsVersionOne(state)
                    ? ClientMailboxStateCodec.MigrateVersionOneToSafeReplay(state)
                    : ClientMailboxStateCodec.Decode(state);
            }
            catch (Exception exception) when (IsQuarantinable(exception))
            {
                CompactCorruptState(
                    connection,
                    transaction,
                    scope,
                    state,
                    "invalid-canonical-state");
                migrationFault?.Invoke(
                    ClientMailboxMigrationFaultPoint
                        .AfterCorruptEvidenceBeforeLegacyDelete);
                DeleteLegacyState(connection, transaction, scope);
                quarantined = true;
                continue;
            }

            InsertBackup(connection, transaction, scope, state);
            migrationFault?.Invoke(
                ClientMailboxMigrationFaultPoint.AfterBackupBeforeRewrite);
            InsertNormalizedSnapshot(
                connection, transaction, scope, decoded);
            MarkVerifiedCutover(
                connection, transaction, scope);
            DeleteLegacyState(connection, transaction, scope);
        }

        GarbageCollectMigrationArtifacts(
            connection,
            transaction,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        EnforceInstallationMigrationBounds(connection, transaction);
        transaction.Commit();
        if (quarantined)
        {
            throw new InvalidDataException(
                "Corrupt client mailbox state was quarantined; retry starts a safe cursor-zero cycle.");
        }
    }

    private async Task<TResult> ReadNormalizedAsync<TResult>(
        ClientMailboxScope scope,
        Func<SqliteConnection, SqliteTransaction?, byte[], CancellationToken,
            Task<TResult>> read,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            return await read(
                connection, null, scope.ToArray(), cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<ClientMailboxReceiveCommitResult> CommitPageNormalizedAsync(
        ClientMailboxScope scope,
        ClientMailboxTraversal expected,
        MailboxRetrievePage page,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(page);
        _ = MailboxClientCodec.EncodeRetrievePage(page);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var transaction =
                connection.BeginTransaction(deferred: false);
            var scopeBytes = scope.ToArray();
            if (page.Items.Count > 0)
            {
                _ = await SweepInstallationExpiredAsync(
                    connection,
                    transaction,
                    page.Items.Max(static item =>
                        item.Envelope.CreatedAtUnixSeconds),
                    cancellationToken).ConfigureAwait(false);
            }

            var traversal = await ReadTraversalCoreAsync(
                connection, transaction, scopeBytes, cancellationToken)
                .ConfigureAwait(false);
            if (traversal.AfterCursor != expected.AfterCursor ||
                !CryptographicOperations.FixedTimeEquals(
                    traversal.ContinuationToken, expected.ContinuationToken))
            {
                throw new InvalidOperationException(
                    "Mailbox traversal changed before durable page commit.");
            }

            var committedPage =
                new List<MailboxRetrievedEnvelope>(page.Items.Count);
            foreach (var item in page.Items)
            {
                var envelope = MailboxClientCodec.EncodeEncryptedEnvelope(item.Envelope);
                var digest = item.Envelope.DeduplicationDigest.ToArray();
                await using var inspect = connection.CreateCommand();
                inspect.Transaction = transaction;
                inspect.CommandText = """
                    SELECT cursor, digest, expires_at, canonical_envelope, acknowledged
                    FROM client_mailbox_inbox
                    WHERE scope = $scope AND (cursor = $cursor OR digest = $digest);
                    """;
                inspect.Parameters.Add("$scope", SqliteType.Blob).Value = scopeBytes;
                inspect.Parameters.Add("$cursor", SqliteType.Blob).Value = U64(item.Cursor);
                inspect.Parameters.Add("$digest", SqliteType.Blob).Value = digest;
                await using var reader = await inspect.ExecuteReaderAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var matches =
                        Fixed(reader.GetFieldValue<byte[]>(0), U64(item.Cursor)) &&
                        Fixed(reader.GetFieldValue<byte[]>(1), digest) &&
                        ReadU64(reader.GetFieldValue<byte[]>(2)) ==
                            item.Envelope.ExpiresAtUnixSeconds &&
                        Fixed(reader.GetFieldValue<byte[]>(3), envelope);
                    var acknowledged = reader.GetInt32(4) == 1;
                    if (!matches ||
                        await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                    {
                        throw new InvalidDataException(
                            "Mailbox cursor/digest history conflicts with durable inbox.");
                    }

                    if (!acknowledged)
                    {
                        committedPage.Add(item);
                    }

                    continue;
                }

                if (expected.AfterCursor != 0 && item.Cursor <= expected.AfterCursor)
                {
                    throw new InvalidDataException(
                        "Continuation page rolled back below its authorized cursor.");
                }

                await using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO client_mailbox_inbox(
                        scope, cursor, digest, expires_at,
                        canonical_envelope, acknowledged)
                    VALUES($scope, $cursor, $digest, $expires, $envelope, 0);
                    """;
                insert.Parameters.Add("$scope", SqliteType.Blob).Value = scopeBytes;
                insert.Parameters.Add("$cursor", SqliteType.Blob).Value = U64(item.Cursor);
                insert.Parameters.Add("$digest", SqliteType.Blob).Value = digest;
                insert.Parameters.Add("$expires", SqliteType.Blob).Value =
                    U64(item.Envelope.ExpiresAtUnixSeconds);
                insert.Parameters.Add("$envelope", SqliteType.Blob).Value = envelope;
                await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                committedPage.Add(item);
            }

            var next = page.HasMore
                ? new ClientMailboxTraversal(page.NextCursor, page.ContinuationToken.Span)
                : new ClientMailboxTraversal(0, []);
            await WriteTraversalAsync(
                connection, transaction, scopeBytes, next, cancellationToken)
                .ConfigureAwait(false);
            await EnforceInboxCapacityAsync(
                connection, transaction, scopeBytes, cancellationToken)
                .ConfigureAwait(false);
            await EnforceInstallationInboxCapacityAsync(
                connection, transaction, cancellationToken)
                .ConfigureAwait(false);
            await EnforceInstallationScopeCapacityAsync(
                connection, transaction, cancellationToken)
                .ConfigureAwait(false);
            var durable = ClientMailboxStateMachine.PageInbox(committedPage);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return new(next, durable);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<ClientMailboxAckState> CommitAckNormalizedAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(acknowledgements);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var transaction =
                connection.BeginTransaction(deferred: false);
            var scopeBytes = scope.ToArray();
            var state = await LoadNormalizedStateAsync(
                connection, transaction, scopeBytes, cancellationToken)
                .ConfigureAwait(false);
            var result = ClientMailboxStateMachine.Check(state, acknowledgements);
            if (result == ClientMailboxAckState.Pending)
            {
                foreach (var acknowledgement in acknowledgements)
                {
                    await using var update = connection.CreateCommand();
                    update.Transaction = transaction;
                    update.CommandText = """
                        UPDATE client_mailbox_inbox SET acknowledged = 1
                        WHERE scope = $scope AND cursor = $cursor AND digest = $digest;
                        """;
                    update.Parameters.Add("$scope", SqliteType.Blob).Value = scopeBytes;
                    update.Parameters.Add("$cursor", SqliteType.Blob).Value =
                        U64(acknowledgement.Cursor);
                    update.Parameters.Add("$digest", SqliteType.Blob).Value =
                        acknowledgement.EnvelopeDigest.ToArray();
                    if (await update.ExecuteNonQueryAsync(cancellationToken)
                            .ConfigureAwait(false) != 1)
                    {
                        throw new IOException(
                            "Mailbox acknowledgement state changed concurrently.");
                    }
                }
            }

            await EnforceInstallationScopeCapacityAsync(
                connection, transaction, cancellationToken)
                .ConfigureAwait(false);
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

    private async Task<ClientMailboxExpiryReconciliationResult>
        ReconcileExpiredNormalizedAsync(
            ClientMailboxScope scope,
            ulong nowUnixSeconds,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (nowUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nowUnixSeconds));
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var transaction =
                connection.BeginTransaction(deferred: false);
            var result = await SweepInstallationExpiredAsync(
                connection,
                transaction,
                nowUnixSeconds,
                cancellationToken).ConfigureAwait(false);
            await EnforceInstallationScopeCapacityAsync(
                connection, transaction, cancellationToken)
                .ConfigureAwait(false);
            if (result.QuarantinedUnacknowledged == 0 &&
                result.RemovedAcknowledged == 0)
            {
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return result;
            }

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

    private async Task<ClientMailboxCoordinatorRecordResult>
        RecordCoordinatorNormalizedAsync(
            ClientMailboxJournalScope scope,
            ReadOnlyMemory<byte> membershipCommitment,
            ulong epoch,
            ReadOnlyMemory<byte> coordinatorId,
            ulong coordinatorSequence,
            ReadOnlyMemory<byte> statementDigest,
            ulong expiresAtUnixSeconds,
            ulong nowUnixSeconds,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        var probe = new ClientMailboxJournalState();
        _ = ClientMailboxStateMachine.RecordCoordinator(
            probe, membershipCommitment.Span, epoch, coordinatorId.Span,
            coordinatorSequence, statementDigest.Span, expiresAtUnixSeconds,
            nowUnixSeconds);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var transaction =
                connection.BeginTransaction(deferred: false);
            var scopeBytes = scope.ToArray();
            var statementKey = CoordinatorStatementKey(
                membershipCommitment.Span,
                epoch,
                coordinatorId.Span,
                coordinatorSequence);
            await using (var prune = connection.CreateCommand())
            {
                prune.Transaction = transaction;
                prune.CommandText = """
                    DELETE FROM client_mailbox_coordinator_journal
                    WHERE expires_at <= $now;
                    DELETE FROM client_mailbox_legacy_journal_guard_v2
                    WHERE expires_at <= $now;
                    """;
                prune.Parameters.Add("$now", SqliteType.Blob).Value = U64(nowUnixSeconds);
                await prune.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            await EnforceInstallationScopeCapacityAsync(
                connection, transaction, cancellationToken)
                .ConfigureAwait(false);

            await using (var legacy = connection.CreateCommand())
            {
                legacy.Transaction = transaction;
                legacy.CommandText = """
                    SELECT statement_digest, conflict
                    FROM client_mailbox_legacy_journal_guard_v2
                    WHERE statement_key = $key;
                    """;
                legacy.Parameters.Add("$key", SqliteType.Blob).Value = statementKey;
                await using var reader = await legacy.ExecuteReaderAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var conflict = reader.GetInt32(1) == 1;
                    if (conflict || !Fixed(
                            reader.GetFieldValue<byte[]>(0),
                            statementDigest.Span))
                    {
                        await reader.DisposeAsync().ConfigureAwait(false);
                        await transaction.CommitAsync(cancellationToken)
                            .ConfigureAwait(false);
                        return ClientMailboxCoordinatorRecordResult.Equivocation;
                    }

                    await reader.DisposeAsync().ConfigureAwait(false);
                    await transaction.CommitAsync(cancellationToken)
                        .ConfigureAwait(false);
                    return ClientMailboxCoordinatorRecordResult.Idempotent;
                }
            }

            await using (var find = connection.CreateCommand())
            {
                find.Transaction = transaction;
                find.CommandText = """
                    SELECT statement_digest
                    FROM client_mailbox_coordinator_journal
                    WHERE statement_key = $key;
                    """;
                find.Parameters.Add("$key", SqliteType.Blob).Value = statementKey;
                await using var reader = await find.ExecuteReaderAsync(cancellationToken)
                    .ConfigureAwait(false);
                var found = false;
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    found = true;
                    if (!Fixed(
                            reader.GetFieldValue<byte[]>(0),
                            statementDigest.Span))
                    {
                        await reader.DisposeAsync().ConfigureAwait(false);
                        await transaction.CommitAsync(cancellationToken)
                            .ConfigureAwait(false);
                        return ClientMailboxCoordinatorRecordResult.Equivocation;
                    }
                }

                if (found)
                {
                    await reader.DisposeAsync().ConfigureAwait(false);
                    await transaction.CommitAsync(cancellationToken)
                        .ConfigureAwait(false);
                    return ClientMailboxCoordinatorRecordResult.Idempotent;
                }
            }

            await using (var count = connection.CreateCommand())
            {
                count.Transaction = transaction;
                count.CommandText = """
                    SELECT
                        (SELECT count(*) FROM client_mailbox_coordinator_journal) +
                        (SELECT count(*) FROM client_mailbox_legacy_journal_guard_v2);
                    """;
                if (Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken)
                        .ConfigureAwait(false)) >=
                    ClientMailboxStateLimits.MaximumCoordinatorStatements)
                {
                    await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                    return ClientMailboxCoordinatorRecordResult.CapacityExceeded;
                }
            }

            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO client_mailbox_coordinator_journal(
                    installation_scope, statement_key, statement_digest, expires_at)
                VALUES($scope, $key, $digest, $expires);
                """;
            insert.Parameters.Add("$scope", SqliteType.Blob).Value = scopeBytes;
            insert.Parameters.Add("$key", SqliteType.Blob).Value = statementKey;
            insert.Parameters.Add("$digest", SqliteType.Blob).Value =
                statementDigest.ToArray();
            insert.Parameters.Add("$expires", SqliteType.Blob).Value =
                U64(expiresAtUnixSeconds);
            await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return ClientMailboxCoordinatorRecordResult.Applied;
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<ClientMailboxTraversal> ReadTraversalCoreAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        byte[] scope,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT after_cursor, continuation_token
            FROM client_mailbox_traversal WHERE scope = $scope;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? new ClientMailboxTraversal(
                ReadU64(reader.GetFieldValue<byte[]>(0)),
                reader.GetFieldValue<byte[]>(1))
            : new ClientMailboxTraversal(0, []);
    }

    private static async Task<ClientMailboxStoredState> LoadNormalizedStateAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        byte[] scope,
        CancellationToken cancellationToken)
    {
        var traversal = await ReadTraversalCoreAsync(
            connection, transaction, scope, cancellationToken)
            .ConfigureAwait(false);
        var state = new ClientMailboxStoredState
        {
            AfterCursor = traversal.AfterCursor,
            ContinuationToken = traversal.GetContinuationTokenCopy()
        };
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT cursor, digest, expires_at, canonical_envelope, acknowledged
            FROM client_mailbox_inbox WHERE scope = $scope ORDER BY cursor;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            state.Entries.Add(new ClientMailboxStoredEntry
            {
                Cursor = ReadU64(reader.GetFieldValue<byte[]>(0)),
                Digest = reader.GetFieldValue<byte[]>(1),
                ExpiresAtUnixSeconds = ReadU64(reader.GetFieldValue<byte[]>(2)),
                CanonicalEnvelope = reader.GetFieldValue<byte[]>(3),
                Acknowledged = reader.GetInt32(4) == 1
            });
        }

        ClientMailboxStateMachine.Validate(state);
        return state;
    }

    private static async Task WriteTraversalAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        ClientMailboxTraversal traversal,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO client_mailbox_traversal(
                scope, after_cursor, continuation_token)
            VALUES($scope, $cursor, $token)
            ON CONFLICT(scope) DO UPDATE SET
                after_cursor = excluded.after_cursor,
                continuation_token = excluded.continuation_token;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
        command.Parameters.Add("$cursor", SqliteType.Blob).Value =
            U64(traversal.AfterCursor);
        command.Parameters.Add("$token", SqliteType.Blob).Value =
            traversal.GetContinuationTokenCopy();
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnforceInboxCapacityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            await using var count = connection.CreateCommand();
            count.Transaction = transaction;
            count.CommandText = """
                SELECT count(*), COALESCE(sum(length(canonical_envelope)), 0)
                FROM client_mailbox_inbox WHERE scope = $scope;
                """;
            count.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
            await using var reader = await count.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            _ = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (reader.GetInt64(0) <= ClientMailboxStateLimits.MaximumInboxEntries &&
                reader.GetInt64(1) <= ClientMailboxStateLimits.MaximumInboxBytes)
            {
                return;
            }

            await reader.DisposeAsync().ConfigureAwait(false);
            await using var delete = connection.CreateCommand();
            delete.Transaction = transaction;
            delete.CommandText = """
                DELETE FROM client_mailbox_inbox
                WHERE scope = $scope AND cursor = (
                    SELECT cursor FROM client_mailbox_inbox
                    WHERE scope = $scope AND acknowledged = 1
                    ORDER BY cursor LIMIT 1);
                """;
            delete.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
            if (await delete.ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false) == 0)
            {
                throw new InvalidDataException(
                    "Unacknowledged mailbox inbox exceeded its persistent bound.");
            }
        }
    }

    private static async Task<ClientMailboxExpiryReconciliationResult>
        SweepInstallationExpiredAsync(
            SqliteConnection connection,
            SqliteTransaction transaction,
            ulong nowUnixSeconds,
            CancellationToken cancellationToken)
    {
        if (nowUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nowUnixSeconds));
        }

        var cutoff = nowUnixSeconds >
            ClientMailboxStateLimits.ExpiredQuarantineRetentionSeconds
            ? nowUnixSeconds -
              ClientMailboxStateLimits.ExpiredQuarantineRetentionSeconds
            : 0;
        await using (var age = connection.CreateCommand())
        {
            age.Transaction = transaction;
            age.CommandText = """
                DELETE FROM client_mailbox_expired_quarantine
                WHERE quarantined_at <= $cutoff;
                """;
            age.Parameters.AddWithValue(
                "$cutoff",
                checked((long)Math.Min(cutoff, (ulong)long.MaxValue)));
            await age.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        var expired = new List<(byte[] Scope, byte[] Cursor, byte[] Digest,
            byte[] Expires, byte[] Envelope, bool Acknowledged)>();
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT scope, cursor, digest, expires_at,
                    canonical_envelope, acknowledged
                FROM client_mailbox_inbox
                WHERE expires_at <= $now
                ORDER BY expires_at, scope, cursor;
                """;
            select.Parameters.Add("$now", SqliteType.Blob).Value = U64(nowUnixSeconds);
            await using var reader = await select.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                expired.Add((
                    reader.GetFieldValue<byte[]>(0),
                    reader.GetFieldValue<byte[]>(1),
                    reader.GetFieldValue<byte[]>(2),
                    reader.GetFieldValue<byte[]>(3),
                    reader.GetFieldValue<byte[]>(4),
                    reader.GetInt32(5) == 1));
            }
        }

        foreach (var item in expired.Where(static item => !item.Acknowledged))
        {
            await using var quarantine = connection.CreateCommand();
            quarantine.Transaction = transaction;
            quarantine.CommandText = """
                INSERT INTO client_mailbox_expired_quarantine(
                    scope, cursor, digest, expires_at, canonical_envelope,
                    quarantined_at, reason)
                VALUES($scope, $cursor, $digest, $expires, $envelope, $at,
                    'expired-unacknowledged-no-fabricated-ack')
                ON CONFLICT(scope, cursor, digest) DO NOTHING;
                """;
            quarantine.Parameters.Add("$scope", SqliteType.Blob).Value = item.Scope;
            quarantine.Parameters.Add("$cursor", SqliteType.Blob).Value = item.Cursor;
            quarantine.Parameters.Add("$digest", SqliteType.Blob).Value = item.Digest;
            quarantine.Parameters.Add("$expires", SqliteType.Blob).Value = item.Expires;
            quarantine.Parameters.Add("$envelope", SqliteType.Blob).Value = item.Envelope;
            quarantine.Parameters.AddWithValue("$at", checked((long)Math.Min(
                nowUnixSeconds, (ulong)long.MaxValue)));
            await quarantine.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false);
        }

        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText =
                "DELETE FROM client_mailbox_inbox WHERE expires_at <= $now;";
            delete.Parameters.Add("$now", SqliteType.Blob).Value = U64(nowUnixSeconds);
            await delete.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        foreach (var affectedScope in expired
                     .Where(static item => !item.Acknowledged)
                     .Select(static item => item.Scope)
                     .GroupBy(
                         static value => Convert.ToHexString(value),
                         StringComparer.Ordinal)
                     .Select(static group => group.First()))
        {
            await EnforceExpiredQuarantineScopeCapacityAsync(
                connection,
                transaction,
                affectedScope,
                cancellationToken).ConfigureAwait(false);
        }

        await EnforceInstallationExpiredQuarantineCapacityAsync(
            connection, transaction, cancellationToken).ConfigureAwait(false);
        await RemoveRetiredTraversalScopesAsync(
            connection, transaction, cancellationToken).ConfigureAwait(false);
        return new(
            expired.Count(static item => !item.Acknowledged),
            expired.Count(static item => item.Acknowledged));
    }

    private static async Task EnforceExpiredQuarantineScopeCapacityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            await using var count = connection.CreateCommand();
            count.Transaction = transaction;
            count.CommandText = """
                SELECT count(*), COALESCE(sum(length(canonical_envelope)), 0)
                FROM client_mailbox_expired_quarantine WHERE scope = $scope;
                """;
            count.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
            await using var reader = await count.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            _ = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (reader.GetInt64(0) <=
                    ClientMailboxStateLimits.MaximumExpiredQuarantineEntries &&
                reader.GetInt64(1) <=
                    ClientMailboxStateLimits.MaximumExpiredQuarantineBytes)
            {
                return;
            }

            await reader.DisposeAsync().ConfigureAwait(false);
            await using var delete = connection.CreateCommand();
            delete.Transaction = transaction;
            delete.CommandText = """
                DELETE FROM client_mailbox_expired_quarantine
                WHERE scope = $scope AND cursor = (
                    SELECT cursor FROM client_mailbox_expired_quarantine
                    WHERE scope = $scope
                    ORDER BY quarantined_at, expires_at, cursor, digest LIMIT 1)
                  AND digest = (
                    SELECT digest FROM client_mailbox_expired_quarantine
                    WHERE scope = $scope
                    ORDER BY quarantined_at, expires_at, cursor, digest LIMIT 1);
                """;
            delete.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
            if (await delete.ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false) != 1)
            {
                throw new IOException(
                    "Expired mailbox quarantine pruning made no progress.");
            }
        }
    }

    private static async Task EnforceInstallationExpiredQuarantineCapacityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            await using var count = connection.CreateCommand();
            count.Transaction = transaction;
            count.CommandText = """
                SELECT count(*), COALESCE(sum(length(canonical_envelope)), 0)
                FROM client_mailbox_expired_quarantine;
                """;
            await using var reader = await count.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            _ = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (reader.GetInt64(0) <=
                    ClientMailboxStateLimits
                        .MaximumInstallationExpiredQuarantineEntries &&
                reader.GetInt64(1) <=
                    ClientMailboxStateLimits
                        .MaximumInstallationExpiredQuarantineBytes)
            {
                return;
            }

            await reader.DisposeAsync().ConfigureAwait(false);
            await using var delete = connection.CreateCommand();
            delete.Transaction = transaction;
            delete.CommandText = """
                DELETE FROM client_mailbox_expired_quarantine
                WHERE (scope, cursor, digest) = (
                    SELECT scope, cursor, digest
                    FROM client_mailbox_expired_quarantine
                    ORDER BY quarantined_at, expires_at, scope, cursor, digest
                    LIMIT 1);
                """;
            if (await delete.ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false) != 1)
            {
                throw new IOException(
                    "Installation expired-quarantine pruning made no progress.");
            }
        }
    }

    private static async Task EnforceInstallationInboxCapacityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            await using var count = connection.CreateCommand();
            count.Transaction = transaction;
            count.CommandText = """
                SELECT count(*), COALESCE(sum(length(canonical_envelope)), 0)
                FROM client_mailbox_inbox;
                """;
            await using var reader = await count.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            _ = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (reader.GetInt64(0) <=
                    ClientMailboxStateLimits.MaximumInstallationInboxEntries &&
                reader.GetInt64(1) <=
                    ClientMailboxStateLimits.MaximumInstallationInboxBytes)
            {
                return;
            }

            await reader.DisposeAsync().ConfigureAwait(false);
            await using var delete = connection.CreateCommand();
            delete.Transaction = transaction;
            delete.CommandText = """
                DELETE FROM client_mailbox_inbox
                WHERE (scope, cursor) = (
                    SELECT inbox.scope, inbox.cursor
                    FROM client_mailbox_inbox AS inbox
                    LEFT JOIN client_mailbox_traversal AS traversal
                        ON traversal.scope = inbox.scope
                    WHERE inbox.acknowledged = 1
                    ORDER BY
                        CASE WHEN traversal.after_cursor = $zero THEN 0 ELSE 1 END,
                        inbox.expires_at,
                        inbox.scope,
                        inbox.cursor
                    LIMIT 1);
                """;
            delete.Parameters.Add("$zero", SqliteType.Blob).Value = U64(0);
            if (await delete.ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false) != 1)
            {
                throw new InvalidDataException(
                    "Installation-global unacknowledged mailbox inbox exceeded its persistent bound.");
            }
        }
    }

    private static async Task RemoveRetiredTraversalScopesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = """
            DELETE FROM client_mailbox_traversal
            WHERE after_cursor = $zero
              AND continuation_token = X''
              AND NOT EXISTS (
                  SELECT 1 FROM client_mailbox_inbox
                  WHERE client_mailbox_inbox.scope =
                      client_mailbox_traversal.scope)
              AND NOT EXISTS (
                  SELECT 1 FROM client_mailbox_expired_quarantine
                  WHERE client_mailbox_expired_quarantine.scope =
                      client_mailbox_traversal.scope);
            """;
        delete.Parameters.Add("$zero", SqliteType.Blob).Value = U64(0);
        await delete.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnforceInstallationScopeCapacityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await RemoveRetiredTraversalScopesAsync(
            connection, transaction, cancellationToken).ConfigureAwait(false);
        await using var bounds = connection.CreateCommand();
        bounds.Transaction = transaction;
        bounds.CommandText = """
            SELECT count(*), COALESCE(sum(length(continuation_token)), 0)
            FROM client_mailbox_traversal;
            """;
        await using var reader = await bounds.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        _ = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (reader.GetInt64(0) >
                ClientMailboxStateLimits.MaximumInstallationScopes ||
            reader.GetInt64(1) >
                ClientMailboxStateLimits.MaximumInstallationTraversalTokenBytes)
        {
            throw new InvalidDataException(
                "Installation-global mailbox traversal metadata exceeded its persistent bound.");
        }
    }

    private static void InsertNormalizedSnapshot(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        ClientMailboxStoredState state)
    {
        using (var traversal = connection.CreateCommand())
        {
            traversal.Transaction = transaction;
            traversal.CommandText = """
                INSERT INTO client_mailbox_traversal(
                    scope, after_cursor, continuation_token)
                VALUES($scope, $cursor, $token)
                ON CONFLICT(scope) DO UPDATE SET
                    after_cursor = excluded.after_cursor,
                    continuation_token = excluded.continuation_token;
                """;
            traversal.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
            traversal.Parameters.Add("$cursor", SqliteType.Blob).Value =
                U64(state.AfterCursor);
            traversal.Parameters.Add("$token", SqliteType.Blob).Value =
                state.ContinuationToken;
            traversal.ExecuteNonQuery();
        }

        foreach (var entry in state.Entries)
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO client_mailbox_inbox(
                    scope, cursor, digest, expires_at,
                    canonical_envelope, acknowledged)
                VALUES($scope, $cursor, $digest, $expires, $envelope, $ack)
                ON CONFLICT(scope, cursor) DO UPDATE SET
                    digest = excluded.digest,
                    expires_at = excluded.expires_at,
                    canonical_envelope = excluded.canonical_envelope,
                    acknowledged = excluded.acknowledged;
                """;
            insert.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
            insert.Parameters.Add("$cursor", SqliteType.Blob).Value =
                U64(entry.Cursor);
            insert.Parameters.Add("$digest", SqliteType.Blob).Value = entry.Digest;
            insert.Parameters.Add("$expires", SqliteType.Blob).Value =
                U64(entry.ExpiresAtUnixSeconds);
            insert.Parameters.Add("$envelope", SqliteType.Blob).Value =
                entry.CanonicalEnvelope;
            insert.Parameters.AddWithValue("$ack", entry.Acknowledged ? 1 : 0);
            insert.ExecuteNonQuery();
        }

        foreach (var statement in state.CoordinatorStatements)
        {
            UpsertLegacyJournalGuard(
                connection,
                transaction,
                CoordinatorStatementKey(
                    statement.MembershipCommitment,
                    statement.Epoch,
                    statement.CoordinatorId,
                    statement.CoordinatorSequence),
                statement.StatementDigest,
                U64(statement.ExpiresAtUnixSeconds));
        }
    }

    private static void UpsertLegacyJournalGuard(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] statementKey,
        byte[] statementDigest,
        byte[] expiresAt)
    {
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO client_mailbox_legacy_journal_guard_v2(
                statement_key, statement_digest, expires_at, conflict)
            VALUES(
                $key,
                $digest,
                CASE WHEN COALESCE((
                    SELECT max(expires_at)
                    FROM client_mailbox_coordinator_journal
                    WHERE statement_key = $key), X'') > $expires
                THEN (
                    SELECT max(expires_at)
                    FROM client_mailbox_coordinator_journal
                    WHERE statement_key = $key)
                ELSE $expires END,
                CASE WHEN EXISTS (
                    SELECT 1 FROM client_mailbox_coordinator_journal
                    WHERE statement_key = $key
                      AND statement_digest <> $digest)
                THEN 1 ELSE 0 END)
            ON CONFLICT(statement_key) DO UPDATE SET
                expires_at = CASE
                    WHEN client_mailbox_legacy_journal_guard_v2.expires_at <
                        excluded.expires_at
                    THEN excluded.expires_at
                    ELSE client_mailbox_legacy_journal_guard_v2.expires_at
                END,
                conflict = CASE
                    WHEN client_mailbox_legacy_journal_guard_v2.conflict = 1 OR
                         client_mailbox_legacy_journal_guard_v2.statement_digest <>
                            excluded.statement_digest OR
                         EXISTS (
                             SELECT 1 FROM client_mailbox_coordinator_journal
                             WHERE statement_key = excluded.statement_key
                               AND statement_digest <>
                                   excluded.statement_digest)
                    THEN 1
                    ELSE 0
                END;
            DELETE FROM client_mailbox_coordinator_journal
            WHERE statement_key = $key;
            """;
        insert.Parameters.Add("$key", SqliteType.Blob).Value = statementKey;
        insert.Parameters.Add("$digest", SqliteType.Blob).Value = statementDigest;
        insert.Parameters.Add("$expires", SqliteType.Blob).Value = expiresAt;
        insert.ExecuteNonQuery();
    }

    private static void UpgradeLegacyJournalGuards(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        var rows = new List<(byte[] Key, byte[] Digest, byte[] Expires)>();
        using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT statement_key, statement_digest, expires_at
                FROM client_mailbox_legacy_journal_guard
                ORDER BY statement_key, legacy_mailbox_scope;
                """;
            using var reader = select.ExecuteReader();
            while (reader.Read())
            {
                rows.Add((
                    reader.GetFieldValue<byte[]>(0),
                    reader.GetFieldValue<byte[]>(1),
                    reader.GetFieldValue<byte[]>(2)));
            }
        }

        foreach (var row in rows)
        {
            UpsertLegacyJournalGuard(
                connection, transaction, row.Key, row.Digest, row.Expires);
        }

        using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = "DELETE FROM client_mailbox_legacy_journal_guard;";
        delete.ExecuteNonQuery();
    }

    private static void DeleteLegacyState(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "DELETE FROM client_mailbox_state WHERE scope = $scope;";
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
        command.ExecuteNonQuery();
    }

    private static void MarkVerifiedCutover(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO client_mailbox_migration_cutover(scope, verified_at)
            VALUES($scope, $at)
            ON CONFLICT(scope) DO NOTHING;
            """;
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
        command.Parameters.AddWithValue(
            "$at",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        command.ExecuteNonQuery();
    }

    private static bool IsQuarantinable(Exception exception) =>
        exception is InvalidDataException or MailboxClientException or
            ArgumentOutOfRangeException or IndexOutOfRangeException or
            OverflowException;

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] CoordinatorStatementKey(
        ReadOnlySpan<byte> membershipCommitment,
        ulong epoch,
        ReadOnlySpan<byte> coordinatorId,
        ulong coordinatorSequence) =>
        SHA256.HashData([
            .. "deep.client.mailbox.coordinator-statement-key.v1"u8,
            .. membershipCommitment,
            .. U64(epoch),
            .. coordinatorId,
            .. U64(coordinatorSequence)
        ]);

    private static ulong ReadU64(ReadOnlySpan<byte> value)
    {
        if (value.Length != 8)
        {
            throw new InvalidDataException("Persisted UInt64 is invalid.");
        }

        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(value);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void EnforceInstallationMigrationBounds(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT
                (SELECT count(*) FROM client_mailbox_inbox),
                (SELECT COALESCE(sum(length(canonical_envelope)), 0)
                    FROM client_mailbox_inbox),
                (SELECT count(*) FROM client_mailbox_traversal),
                (SELECT COALESCE(sum(length(continuation_token)), 0)
                    FROM client_mailbox_traversal),
                (SELECT count(*) FROM client_mailbox_coordinator_journal) +
                (SELECT count(*) FROM client_mailbox_legacy_journal_guard_v2),
                (SELECT count(*) FROM client_mailbox_migration_cutover);
            """;
        using var reader = command.ExecuteReader();
        _ = reader.Read();
        if (reader.GetInt64(0) >
                ClientMailboxStateLimits.MaximumInstallationInboxEntries ||
            reader.GetInt64(1) >
                ClientMailboxStateLimits.MaximumInstallationInboxBytes ||
            reader.GetInt64(2) >
                ClientMailboxStateLimits.MaximumInstallationScopes ||
            reader.GetInt64(3) >
                ClientMailboxStateLimits
                    .MaximumInstallationTraversalTokenBytes ||
            reader.GetInt64(4) >
                ClientMailboxStateLimits.MaximumCoordinatorStatements ||
            reader.GetInt64(5) >
                ClientMailboxStateLimits.MaximumInstallationScopes)
        {
            throw new InvalidDataException(
                "Migrated installation-global mailbox bounds are exceeded; legacy recovery state was retained.");
        }
    }

    private static void GarbageCollectMigrationArtifacts(
        SqliteConnection connection,
        SqliteTransaction transaction,
        long nowUnixSeconds)
    {
        var cutoff = nowUnixSeconds -
            ClientMailboxStateLimits.MigrationArtifactRetentionSeconds;
        using (var collect = connection.CreateCommand())
        {
            collect.Transaction = transaction;
            collect.CommandText = """
                DELETE FROM client_mailbox_migration_backup
                WHERE migrated_at <= $cutoff
                  AND NOT EXISTS (
                      SELECT 1 FROM client_mailbox_state
                      WHERE client_mailbox_state.scope =
                          client_mailbox_migration_backup.scope)
                  AND EXISTS (
                      SELECT 1 FROM client_mailbox_migration_cutover
                      WHERE client_mailbox_migration_cutover.scope =
                          client_mailbox_migration_backup.scope);
                DELETE FROM client_mailbox_quarantine
                WHERE quarantined_at <= $cutoff;
                DELETE FROM client_mailbox_corrupt_aggregate
                WHERE updated_at <= $cutoff;
                DELETE FROM client_mailbox_migration_cutover
                WHERE verified_at <= $cutoff
                  AND NOT EXISTS (
                      SELECT 1 FROM client_mailbox_migration_backup
                      WHERE client_mailbox_migration_backup.scope =
                          client_mailbox_migration_cutover.scope)
                  AND NOT EXISTS (
                      SELECT 1 FROM client_mailbox_state
                      WHERE client_mailbox_state.scope =
                          client_mailbox_migration_cutover.scope);
                """;
            collect.Parameters.AddWithValue("$cutoff", cutoff);
            collect.ExecuteNonQuery();
        }

        using var bounds = connection.CreateCommand();
        bounds.Transaction = transaction;
        bounds.CommandText = """
            SELECT
                (SELECT count(*) FROM client_mailbox_migration_backup) +
                (SELECT count(*) FROM client_mailbox_quarantine),
                (SELECT COALESCE(sum(length(state_blob)), 0)
                    FROM client_mailbox_migration_backup) +
                (SELECT COALESCE(sum(length(state_blob)), 0)
                    FROM client_mailbox_quarantine);
            """;
        using var reader = bounds.ExecuteReader();
        _ = reader.Read();
        if (reader.GetInt64(0) >
                ClientMailboxStateLimits.MaximumMigrationArtifacts ||
            reader.GetInt64(1) >
                ClientMailboxStateLimits.MaximumMigrationArtifactBytes)
        {
            throw new InvalidDataException(
                "Mailbox migration recovery artifacts exceed installation bounds before minimum retention; cutover was rolled back.");
        }
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

    private static bool TryReadNextLegacyStateMetadata(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[]? previousScope,
        out byte[] scope,
        out long stateBytes)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = previousScope is null
            ? """
                SELECT scope, length(state_blob)
                FROM client_mailbox_state
                ORDER BY scope LIMIT 1;
                """
            : """
                SELECT scope, length(state_blob)
                FROM client_mailbox_state
                WHERE scope > $previous
                ORDER BY scope LIMIT 1;
                """;
        if (previousScope is not null)
        {
            command.Parameters.Add("$previous", SqliteType.Blob).Value =
                previousScope;
        }

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            scope = [];
            stateBytes = 0;
            return false;
        }

        scope = reader.GetFieldValue<byte[]>(0);
        stateBytes = reader.GetInt64(1);
        return true;
    }

    private static byte[] LoadBoundedLegacyState(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        long expectedBytes)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT state_blob FROM client_mailbox_state WHERE scope = $scope;";
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
        var state = command.ExecuteScalar() as byte[] ??
            throw new InvalidDataException(
                "Legacy mailbox state disappeared during migration.");
        if (state.LongLength != expectedBytes ||
            state.Length > ClientMailboxStateLimits.MaximumLegacyStateBlobBytes)
        {
            throw new InvalidDataException(
                "Legacy mailbox state changed or exceeded its bounded read.");
        }

        return state;
    }

    private void CompactLegacyStateFromDatabase(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        long expectedBytes,
        string reason)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT state_blob FROM client_mailbox_state WHERE scope = $scope;";
        command.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            throw new InvalidDataException(
                "Legacy mailbox state disappeared during migration.");
        }

        using var stream = reader.GetStream(0);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var prefix = new byte[ClientMailboxStateLimits.MaximumCorruptEvidencePrefixBytes];
        var buffer = new byte[64 * 1024];
        long total = 0;
        var prefixBytes = 0;
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) != 0)
        {
            hash.AppendData(buffer, 0, read);
            if (prefixBytes < prefix.Length)
            {
                var copy = Math.Min(read, prefix.Length - prefixBytes);
                buffer.AsSpan(0, copy).CopyTo(prefix.AsSpan(prefixBytes));
                prefixBytes += copy;
            }

            total = checked(total + read);
        }

        if (total != expectedBytes)
        {
            throw new InvalidDataException(
                "Legacy mailbox state changed during bounded streaming recovery.");
        }

        stream.Dispose();
        reader.Dispose();
        CompactCorruptEvidence(
            connection,
            transaction,
            scope,
            hash.GetHashAndReset(),
            total,
            prefix.AsSpan(0, prefixBytes),
            reason);
        migrationFault?.Invoke(
            ClientMailboxMigrationFaultPoint.AfterCorruptEvidenceBeforeLegacyDelete);
        DeleteLegacyState(connection, transaction, scope);
    }

    private static void CompactCorruptState(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        byte[] state,
        string reason) =>
        CompactCorruptEvidence(
            connection,
            transaction,
            scope,
            SHA256.HashData(state),
            state.LongLength,
            state.AsSpan(
                0,
                Math.Min(
                    state.Length,
                    ClientMailboxStateLimits.MaximumCorruptEvidencePrefixBytes)),
            reason);

    private static void CompactCorruptEvidence(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        byte[] blobDigest,
        long stateBytes,
        ReadOnlySpan<byte> prefix,
        string reason)
    {
        var priorDigest = new byte[32];
        var priorCount = 0L;
        var priorBytes = 0L;
        byte[]? firstPrefix = null;
        using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT corrupt_count, total_bytes, evidence_digest, first_prefix
                FROM client_mailbox_corrupt_aggregate WHERE id = 1;
                """;
            using var reader = select.ExecuteReader();
            if (reader.Read())
            {
                priorCount = reader.GetInt64(0);
                priorBytes = reader.GetInt64(1);
                priorDigest = reader.GetFieldValue<byte[]>(2);
                firstPrefix = reader.GetFieldValue<byte[]>(3);
            }
        }

        var evidenceDigest = SHA256.HashData([
            .. "deep.client.mailbox.corrupt-evidence.v1"u8,
            .. priorDigest,
            .. scope,
            .. blobDigest,
            .. U64(checked((ulong)stateBytes))
        ]);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO client_mailbox_corrupt_aggregate(
                id, corrupt_count, total_bytes, evidence_digest,
                first_prefix, last_reason, updated_at)
            VALUES(1, $count, $bytes, $digest, $prefix, $reason, $at)
            ON CONFLICT(id) DO UPDATE SET
                corrupt_count = excluded.corrupt_count,
                total_bytes = excluded.total_bytes,
                evidence_digest = excluded.evidence_digest,
                first_prefix = excluded.first_prefix,
                last_reason = excluded.last_reason,
                updated_at = excluded.updated_at;
            """;
        command.Parameters.AddWithValue("$count", checked(priorCount + 1));
        command.Parameters.AddWithValue("$bytes", checked(priorBytes + stateBytes));
        command.Parameters.Add("$digest", SqliteType.Blob).Value = evidenceDigest;
        command.Parameters.Add("$prefix", SqliteType.Blob).Value =
            firstPrefix ?? prefix.ToArray();
        command.Parameters.AddWithValue(
            "$reason",
            reason.Length <= 64 ? reason : "legacy-corrupt-state");
        command.Parameters.AddWithValue(
            "$at",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        command.ExecuteNonQuery();
    }

    private static void CompactExistingCorruptQuarantine(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        var rows = new List<(byte[] Scope, long StateBytes, string Reason)>();
        using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT scope, length(state_blob), reason
                FROM client_mailbox_quarantine ORDER BY scope;
                """;
            using var reader = select.ExecuteReader();
            while (reader.Read())
            {
                rows.Add((
                    reader.GetFieldValue<byte[]>(0),
                    reader.GetInt64(1),
                    reader.GetString(2)));
            }
        }

        foreach (var row in rows)
        {
            using var select = connection.CreateCommand();
            select.Transaction = transaction;
            select.CommandText = """
                SELECT state_blob FROM client_mailbox_quarantine
                WHERE scope = $scope;
                """;
            select.Parameters.Add("$scope", SqliteType.Blob).Value = row.Scope;
            using var reader = select.ExecuteReader();
            if (!reader.Read())
            {
                throw new InvalidDataException(
                    "Legacy corrupt evidence disappeared during compaction.");
            }

            using var stream = reader.GetStream(0);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var prefix =
                new byte[ClientMailboxStateLimits.MaximumCorruptEvidencePrefixBytes];
            var buffer = new byte[64 * 1024];
            long total = 0;
            var prefixBytes = 0;
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
                hash.AppendData(buffer, 0, read);
                if (prefixBytes < prefix.Length)
                {
                    var copy = Math.Min(read, prefix.Length - prefixBytes);
                    buffer.AsSpan(0, copy).CopyTo(prefix.AsSpan(prefixBytes));
                    prefixBytes += copy;
                }

                total = checked(total + read);
            }

            if (total != row.StateBytes)
            {
                throw new InvalidDataException(
                    "Legacy corrupt evidence changed during compaction.");
            }

            stream.Dispose();
            reader.Dispose();
            CompactCorruptEvidence(
                connection,
                transaction,
                row.Scope,
                hash.GetHashAndReset(),
                total,
                prefix.AsSpan(0, prefixBytes),
                row.Reason);
        }

        using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = "DELETE FROM client_mailbox_quarantine;";
        delete.ExecuteNonQuery();
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
            PRAGMA synchronous=FULL;
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
            PRAGMA synchronous=FULL;
            """;
        command.ExecuteNonQuery();
    }
}
