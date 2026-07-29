using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Client.Shared.Persistence;

/// <summary>
/// SQLCipher-backed state containing only domain-separated scope hashes,
/// encrypted envelopes, cursor/token state, and receipt commitments.
/// </summary>
public sealed class SqliteClientMailboxStateRepository :
    IClientMailboxStateRepository,
    IClientMailboxCredentialStateRepository,
    IDisposable
{
    private const int SchemaVersion = 7;
    private static readonly string[] CurrentTables =
    [
        "client_mailbox_meta",
        "client_mailbox_traversal",
        "client_mailbox_inbox",
        "client_mailbox_expired_quarantine",
        "client_mailbox_coordinator_journal",
        "client_mailbox_credentials",
        "client_mailbox_replay_counters"
    ];
    private static readonly IReadOnlyDictionary<string, string> CurrentTableDefinitions =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["client_mailbox_meta"] = """
                CREATE TABLE client_mailbox_meta (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    schema_version INTEGER NOT NULL
                )
                """,
            ["client_mailbox_traversal"] = """
                CREATE TABLE client_mailbox_traversal (
                    scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) = 32),
                    after_cursor BLOB NOT NULL CHECK(length(after_cursor) = 8),
                    continuation_token BLOB NOT NULL
                )
                """,
            ["client_mailbox_inbox"] = """
                CREATE TABLE client_mailbox_inbox (
                    scope BLOB NOT NULL CHECK(length(scope) = 32),
                    cursor BLOB NOT NULL CHECK(length(cursor) = 8),
                    digest BLOB NOT NULL CHECK(length(digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    canonical_envelope BLOB NOT NULL,
                    acknowledged INTEGER NOT NULL CHECK(acknowledged IN (0, 1)),
                    PRIMARY KEY(scope, cursor),
                    UNIQUE(scope, digest)
                )
                """,
            ["client_mailbox_expired_quarantine"] = """
                CREATE TABLE client_mailbox_expired_quarantine (
                    scope BLOB NOT NULL CHECK(length(scope) = 32),
                    cursor BLOB NOT NULL CHECK(length(cursor) = 8),
                    digest BLOB NOT NULL CHECK(length(digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    canonical_envelope BLOB NOT NULL,
                    quarantined_at INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    PRIMARY KEY(scope, cursor, digest)
                )
                """,
            ["client_mailbox_coordinator_journal"] = """
                CREATE TABLE client_mailbox_coordinator_journal (
                    installation_scope BLOB NOT NULL
                        CHECK(length(installation_scope) = 32),
                    statement_key BLOB NOT NULL CHECK(length(statement_key) = 32),
                    statement_digest BLOB NOT NULL
                        CHECK(length(statement_digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    PRIMARY KEY(installation_scope, statement_key)
                )
                """
            , ["client_mailbox_credentials"] = """
                CREATE TABLE client_mailbox_credentials (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    generation BLOB NOT NULL CHECK(length(generation) = 32),
                    active_epoch BLOB NOT NULL CHECK(length(active_epoch) = 8),
                    canonical_bundle BLOB NOT NULL CHECK(length(canonical_bundle) = 2216)
                )
                """
            , ["client_mailbox_replay_counters"] = """
                CREATE TABLE client_mailbox_replay_counters (
                    grant_key BLOB PRIMARY KEY NOT NULL CHECK(length(grant_key) = 32),
                    next_counter BLOB NOT NULL CHECK(length(next_counter) = 8)
                )
                """
        };
    private static readonly IReadOnlyDictionary<string, string[]> CurrentIndexes =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["ix_client_mailbox_inbox_scope_expiry"] = ["scope", "expires_at"],
            ["ix_client_mailbox_inbox_expiry_scope"] = ["expires_at", "scope"],
            ["ix_client_mailbox_inbox_scope_ack_cursor"] =
                ["scope", "acknowledged", "cursor"],
            ["ix_client_mailbox_quarantine_age"] =
                ["quarantined_at", "expires_at", "scope"],
            ["ix_client_mailbox_journal_scope_expiry"] =
                ["installation_scope", "expires_at"]
        };
    private static readonly IReadOnlyDictionary<string, string> CurrentIndexDefinitions =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["ix_client_mailbox_inbox_scope_expiry"] = """
                CREATE INDEX ix_client_mailbox_inbox_scope_expiry
                    ON client_mailbox_inbox(scope, expires_at)
                """,
            ["ix_client_mailbox_inbox_expiry_scope"] = """
                CREATE INDEX ix_client_mailbox_inbox_expiry_scope
                    ON client_mailbox_inbox(expires_at, scope)
                """,
            ["ix_client_mailbox_inbox_scope_ack_cursor"] = """
                CREATE INDEX ix_client_mailbox_inbox_scope_ack_cursor
                    ON client_mailbox_inbox(scope, acknowledged, cursor)
                """,
            ["ix_client_mailbox_quarantine_age"] = """
                CREATE INDEX ix_client_mailbox_quarantine_age
                    ON client_mailbox_expired_quarantine(
                        quarantined_at, expires_at, scope)
                """,
            ["ix_client_mailbox_journal_scope_expiry"] = """
                CREATE INDEX ix_client_mailbox_journal_scope_expiry
                    ON client_mailbox_coordinator_journal(
                        installation_scope, expires_at)
                """
        };
    private readonly string connectionString;
    private readonly Action<ClientMailboxCommitFaultPoint>? commitFault;
    private readonly SemaphoreSlim gate = new(1, 1);

    static SqliteClientMailboxStateRepository()
    {
        SQLitePCL.Batteries_V2.Init();
    }

    public SqliteClientMailboxStateRepository(SqliteSessionStoreOptions options)
        : this(options, commitFault: null)
    {
    }

    internal SqliteClientMailboxStateRepository(
        SqliteSessionStoreOptions options,
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
        this.commitFault = commitFault;
        PreflightExistingSchema(options.StatePath, encryptionKey);
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

    public async Task ImportCredentialGenerationAsync(
        MailboxCredentialGeneration generation,
        MailboxCredentialImportPolicy policy,
        CancellationToken cancellationToken = default)
    {
        var candidate = MailboxCredentialStateMachine.Import(generation, policy);
        var bundle = MailboxCredentialBinaryCodec.Encode(candidate.Generation);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = Open(); using var transaction = connection.BeginTransaction(deferred: false);
            using var read = connection.CreateCommand(); read.Transaction = transaction;
            read.CommandText = "SELECT canonical_bundle FROM client_mailbox_credentials WHERE id = 1;";
            var existing = read.ExecuteScalar() as byte[];
            if (existing is not null)
            {
                if (!CryptographicOperations.FixedTimeEquals(existing, bundle))
                    throw new InvalidOperationException("Mailbox credential generation changed unexpectedly.");
                transaction.Commit(); return;
            }
            using var insert = connection.CreateCommand(); insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO client_mailbox_credentials(id, generation, active_epoch, canonical_bundle) VALUES(1, $generation, $epoch, $bundle);";
            insert.Parameters.Add("$generation", SqliteType.Blob).Value = candidate.Generation.Generation.ToArray();
            insert.Parameters.Add("$epoch", SqliteType.Blob).Value = U64(candidate.ActiveEpoch);
            insert.Parameters.Add("$bundle", SqliteType.Blob).Value = bundle;
            insert.ExecuteNonQuery(); commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            transaction.Commit(); commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
        }
        finally { gate.Release(); }
    }

    public async Task<MailboxCredentialGeneration> ReadCredentialGenerationAsync(
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { using var connection = Open(); return ReadCredentials(connection, null).Generation.Clone(); }
        finally { gate.Release(); }
    }

    public async Task<ulong> ReadActiveCredentialEpochAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { using var connection = Open(); return ReadCredentials(connection, null).ActiveEpoch; }
        finally { gate.Release(); }
    }

    public async Task SwitchCredentialEpochAsync(ulong epoch, ulong nowUnixSeconds,
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = Open(); using var transaction = connection.BeginTransaction(deferred: false);
            var state = ReadCredentials(connection, transaction); MailboxCredentialStateMachine.Switch(state, epoch, nowUnixSeconds);
            using var update = connection.CreateCommand(); update.Transaction = transaction;
            update.CommandText = "UPDATE client_mailbox_credentials SET active_epoch = $epoch WHERE id = 1;";
            update.Parameters.Add("$epoch", SqliteType.Blob).Value = U64(state.ActiveEpoch);
            update.ExecuteNonQuery(); commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            transaction.Commit(); commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
        }
        finally { gate.Release(); }
    }

    public async Task<MailboxCredentialGrantLease> AllocateReplayCounterAsync(
        MailboxCredentialGrantKind kind, ulong nowUnixSeconds,
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = Open(); using var transaction = connection.BeginTransaction(deferred: false);
            var state = ReadCredentials(connection, transaction);
            var provisional = MailboxCredentialStateMachine.Allocate(state, kind, nowUnixSeconds);
            var key = SHA256.HashData(provisional.CanonicalGrant.Span);
            using var read = connection.CreateCommand(); read.Transaction = transaction;
            read.CommandText = "SELECT next_counter FROM client_mailbox_replay_counters WHERE grant_key = $key;";
            read.Parameters.Add("$key", SqliteType.Blob).Value = key;
            var stored = read.ExecuteScalar() as byte[];
            var counter = stored is null ? provisional.ReplayCounter : ReadU64(stored);
            if (counter == 0 || counter == ulong.MaxValue)
                throw new InvalidOperationException("Mailbox replay counter is exhausted.");
            var lease = new MailboxCredentialGrantLease(kind, provisional.Epoch, counter,
                provisional.CanonicalGrant.Span);
            using var upsert = connection.CreateCommand(); upsert.Transaction = transaction;
            upsert.CommandText = "INSERT INTO client_mailbox_replay_counters(grant_key, next_counter) VALUES($key, $counter) ON CONFLICT(grant_key) DO UPDATE SET next_counter = excluded.next_counter;";
            upsert.Parameters.Add("$key", SqliteType.Blob).Value = key;
            upsert.Parameters.Add("$counter", SqliteType.Blob).Value = U64(checked(counter + 1));
            upsert.ExecuteNonQuery(); commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            transaction.Commit(); commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return lease;
        }
        finally { gate.Release(); }
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
        command.CommandText = "SELECT count(*) FROM client_mailbox_coordinator_journal;";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    internal void SeedCurrentStatesForTests(
        IReadOnlyList<(ClientMailboxScope Scope, ClientMailboxStoredState State)> snapshots)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        foreach (var snapshot in snapshots)
        {
            InsertCurrentSnapshot(
                connection,
                transaction,
                snapshot.Scope.ToArray(),
                snapshot.State);
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

    public void Dispose() => gate.Dispose();

    private void Initialize()
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        EnsureCurrentSchemaOrFreshDatabase(connection, transaction);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                CREATE TABLE IF NOT EXISTS client_mailbox_meta (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    schema_version INTEGER NOT NULL
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
                CREATE TABLE IF NOT EXISTS client_mailbox_credentials (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    generation BLOB NOT NULL CHECK(length(generation) = 32),
                    active_epoch BLOB NOT NULL CHECK(length(active_epoch) = 8),
                    canonical_bundle BLOB NOT NULL CHECK(length(canonical_bundle) = 2216)
                );
                CREATE TABLE IF NOT EXISTS client_mailbox_replay_counters (
                    grant_key BLOB PRIMARY KEY NOT NULL CHECK(length(grant_key) = 32),
                    next_counter BLOB NOT NULL CHECK(length(next_counter) = 8)
                );
                INSERT INTO client_mailbox_meta(id, schema_version)
                VALUES(1, 7)
                ON CONFLICT(id) DO NOTHING;
                """;
            command.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    private static void PreflightExistingSchema(string statePath, string encryptionKey)
    {
        if (!File.Exists(statePath))
        {
            return;
        }

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            Password = encryptionKey
        }.ToString());
        connection.Open();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA query_only = ON;";
            command.ExecuteNonQuery();
        }
        EnsureCurrentSchemaOrFreshDatabase(connection, transaction: null);
    }

    private static void EnsureCurrentSchemaOrFreshDatabase(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        using var tables = connection.CreateCommand();
        tables.Transaction = transaction;
        tables.CommandText = """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name LIKE 'client_mailbox_%';
            """;
        using var reader = tables.ExecuteReader();
        var names = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read())
        {
            names.Add(reader.GetString(0));
        }
        reader.Dispose();

        if (!names.Contains("client_mailbox_meta"))
        {
            if (names.Count != 0)
            {
                throw ResetRequired();
            }

            return;
        }

        if (!names.SetEquals(CurrentTables))
        {
            throw ResetRequired();
        }

        using var version = connection.CreateCommand();
        version.Transaction = transaction;
        version.CommandText =
            "SELECT schema_version FROM client_mailbox_meta WHERE id = 1;";
        var rawVersion = version.ExecuteScalar();
        if (rawVersion is null || Convert.ToInt32(rawVersion) != SchemaVersion ||
            !HasExactColumns(
                connection,
                transaction,
                "client_mailbox_meta",
                [("id", "INTEGER", false, 1), ("schema_version", "INTEGER", true, 0)]) ||
            !HasExactColumns(
                connection,
                transaction,
                "client_mailbox_traversal",
                [
                    ("scope", "BLOB", true, 1),
                    ("after_cursor", "BLOB", true, 0),
                    ("continuation_token", "BLOB", true, 0)
                ]) ||
            !HasExactColumns(
                connection,
                transaction,
                "client_mailbox_inbox",
                [
                    ("scope", "BLOB", true, 1),
                    ("cursor", "BLOB", true, 2),
                    ("digest", "BLOB", true, 0),
                    ("expires_at", "BLOB", true, 0),
                    ("canonical_envelope", "BLOB", true, 0),
                    ("acknowledged", "INTEGER", true, 0)
                ]) ||
            !HasExactColumns(
                connection,
                transaction,
                "client_mailbox_expired_quarantine",
                [
                    ("scope", "BLOB", true, 1),
                    ("cursor", "BLOB", true, 2),
                    ("digest", "BLOB", true, 3),
                    ("expires_at", "BLOB", true, 0),
                    ("canonical_envelope", "BLOB", true, 0),
                    ("quarantined_at", "INTEGER", true, 0),
                    ("reason", "TEXT", true, 0)
                ]) ||
            !HasExactColumns(
                connection,
                transaction,
                "client_mailbox_coordinator_journal",
                [
                    ("installation_scope", "BLOB", true, 1),
                    ("statement_key", "BLOB", true, 2),
                    ("statement_digest", "BLOB", true, 0),
                    ("expires_at", "BLOB", true, 0)
                ]) ||
            !HasExactColumns(
                connection,
                transaction,
                "client_mailbox_credentials",
                [
                    ("id", "INTEGER", false, 1),
                    ("generation", "BLOB", true, 0),
                    ("active_epoch", "BLOB", true, 0),
                    ("canonical_bundle", "BLOB", true, 0)
                ]) ||
            !HasExactColumns(
                connection,
                transaction,
                "client_mailbox_replay_counters",
                [
                    ("grant_key", "BLOB", true, 1),
                    ("next_counter", "BLOB", true, 0)
                ]) ||
            !HasExactSchemaDefinitions(
                connection,
                transaction,
                "table",
                CurrentTableDefinitions) ||
            !HasExactIndexes(connection, transaction))
        {
            throw ResetRequired();
        }
    }

    private static bool HasExactColumns(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string table,
        IReadOnlyList<(string Name, string Type, bool NotNull, int PrimaryKeyOrder)>
            expected)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA table_info(\"{table}\");";
        using var reader = command.ExecuteReader();
        var offset = 0;
        while (reader.Read())
        {
            if (offset >= expected.Count)
            {
                return false;
            }

            var column = expected[offset++];
            if (!string.Equals(reader.GetString(1), column.Name, StringComparison.Ordinal) ||
                !string.Equals(reader.GetString(2), column.Type, StringComparison.Ordinal) ||
                reader.GetBoolean(3) != column.NotNull ||
                reader.GetInt32(5) != column.PrimaryKeyOrder)
            {
                return false;
            }
        }

        return offset == expected.Count;
    }

    private static bool HasExactIndexes(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        using var indexes = connection.CreateCommand();
        indexes.Transaction = transaction;
        indexes.CommandText = """
            SELECT name, sql FROM sqlite_master
            WHERE type = 'index' AND name LIKE 'ix_client_mailbox_%';
            """;
        using var reader = indexes.ExecuteReader();
        var names = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read())
        {
            var name = reader.GetString(0);
            if (!CurrentIndexDefinitions.TryGetValue(name, out var expectedSql) ||
                reader.IsDBNull(1) ||
                !string.Equals(
                    NormalizeSchemaSql(reader.GetString(1)),
                    NormalizeSchemaSql(expectedSql),
                    StringComparison.Ordinal))
            {
                return false;
            }

            names.Add(name);
        }
        reader.Dispose();

        if (!names.SetEquals(CurrentIndexes.Keys))
        {
            return false;
        }

        foreach (var (name, expectedColumns) in CurrentIndexes)
        {
            using var columns = connection.CreateCommand();
            columns.Transaction = transaction;
            columns.CommandText = $"PRAGMA index_info(\"{name}\");";
            using var columnReader = columns.ExecuteReader();
            var offset = 0;
            while (columnReader.Read())
            {
                if (offset >= expectedColumns.Length ||
                    !string.Equals(
                        columnReader.GetString(2),
                        expectedColumns[offset++],
                        StringComparison.Ordinal))
                {
                    return false;
                }
            }

            if (offset != expectedColumns.Length)
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasExactSchemaDefinitions(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string type,
        IReadOnlyDictionary<string, string> expected)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT name, sql FROM sqlite_master
            WHERE type = $type AND name LIKE 'client_mailbox_%';
            """;
        command.Parameters.AddWithValue("$type", type);
        using var reader = command.ExecuteReader();
        var found = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read())
        {
            var name = reader.GetString(0);
            if (!expected.TryGetValue(name, out var expectedSql) ||
                reader.IsDBNull(1) ||
                !string.Equals(
                    NormalizeSchemaSql(reader.GetString(1)),
                    NormalizeSchemaSql(expectedSql),
                    StringComparison.Ordinal))
            {
                return false;
            }

            found.Add(name);
        }

        return found.SetEquals(expected.Keys);
    }

    private static string NormalizeSchemaSql(string value)
    {
        var normalized = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            if (!char.IsWhiteSpace(character) && character != ';')
            {
                normalized.Append(char.ToUpperInvariant(character));
            }
        }

        return normalized
            .ToString()
            .Replace("IFNOTEXISTS", string.Empty, StringComparison.Ordinal);
    }

    private static InvalidDataException ResetRequired() =>
        new("Client mailbox state uses a pre-current or incompatible schema. Wipe/reset the local mailbox database before continuing.");

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
                    """;
                prune.Parameters.Add("$now", SqliteType.Blob).Value = U64(nowUnixSeconds);
                await prune.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            await EnforceInstallationScopeCapacityAsync(
                connection, transaction, cancellationToken)
                .ConfigureAwait(false);

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
                count.CommandText = "SELECT count(*) FROM client_mailbox_coordinator_journal;";
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

    private static MailboxCredentialStoredState ReadCredentials(
        SqliteConnection connection, SqliteTransaction? transaction)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT active_epoch, canonical_bundle FROM client_mailbox_credentials WHERE id = 1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.IsDBNull(0) || reader.IsDBNull(1))
            throw new InvalidOperationException("Mailbox credentials are not installed.");
        var active = ReadU64((byte[])reader.GetValue(0));
        var generation = MailboxCredentialBinaryCodec.Decode((byte[])reader.GetValue(1));
        if (active != generation.Current.Epoch && active != generation.Next.Epoch)
            throw new InvalidDataException("Mailbox credential state is invalid.");
        return new MailboxCredentialStoredState { Generation = generation, ActiveEpoch = active };
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static void InsertCurrentSnapshot(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] scope,
        ClientMailboxStoredState state)
    {
        ClientMailboxStateMachine.Validate(state);
        using (var traversal = connection.CreateCommand())
        {
            traversal.Transaction = transaction;
            traversal.CommandText = """
                INSERT INTO client_mailbox_traversal(scope, after_cursor, continuation_token)
                VALUES($scope, $cursor, $token);
                """;
            traversal.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
            traversal.Parameters.Add("$cursor", SqliteType.Blob).Value = U64(state.AfterCursor);
            traversal.Parameters.Add("$token", SqliteType.Blob).Value = state.ContinuationToken;
            traversal.ExecuteNonQuery();
        }

        foreach (var entry in state.Entries)
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO client_mailbox_inbox(
                    scope, cursor, digest, expires_at, canonical_envelope, acknowledged)
                VALUES($scope, $cursor, $digest, $expires, $envelope, $ack);
                """;
            insert.Parameters.Add("$scope", SqliteType.Blob).Value = scope;
            insert.Parameters.Add("$cursor", SqliteType.Blob).Value = U64(entry.Cursor);
            insert.Parameters.Add("$digest", SqliteType.Blob).Value = entry.Digest;
            insert.Parameters.Add("$expires", SqliteType.Blob).Value = U64(entry.ExpiresAtUnixSeconds);
            insert.Parameters.Add("$envelope", SqliteType.Blob).Value = entry.CanonicalEnvelope;
            insert.Parameters.AddWithValue("$ack", entry.Acknowledged ? 1 : 0);
            insert.ExecuteNonQuery();
        }
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
