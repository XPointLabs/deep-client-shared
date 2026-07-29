using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

/// <summary>
/// Stores only opaque scope hashes, cursors and envelope digests. No mailbox,
/// account or contact identifier is written to the database.
/// </summary>
public sealed class SqliteClientMailboxStateRepository :
    IClientMailboxStateRepository,
    IDisposable
{
    private const int SchemaVersion = 2;
    private readonly string connectionString;
    private readonly SemaphoreSlim gate = new(1, 1);

    public SqliteClientMailboxStateRepository(string statePath)
    {
        if (string.IsNullOrWhiteSpace(statePath))
        {
            throw new ArgumentException("A mailbox state path is required.", nameof(statePath));
        }

        var directory = Path.GetDirectoryName(Path.GetFullPath(statePath));
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = false
        }.ToString();
        Initialize();
    }

    public Task<ulong> ReadAfterCursorAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken = default) =>
        ReadAsync(scope, static state => state.AfterCursor, cancellationToken);

    public Task<ClientMailboxMergeResult> MergeRetrievePageAsync(
        ClientMailboxScope scope,
        MailboxRetrievePage page,
        CancellationToken cancellationToken = default) =>
        MutateAsync(
            scope,
            state => ClientMailboxStateMachine.Merge(state, page),
            cancellationToken);

    public Task<ClientMailboxAckState> CheckAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        ReadAsync(
            scope,
            state => ClientMailboxStateMachine.Check(state, acknowledgements),
            cancellationToken);

    public Task<ClientMailboxAckState> CommitAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        MutateAsync(
            scope,
            state => ClientMailboxStateMachine.Commit(state, acknowledgements),
            cancellationToken);

    internal void InsertVersionOneStateForTests(
        ClientMailboxScope scope,
        ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(scope);
        _ = ClientMailboxStateCodec.Decode(encoded);
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

    public void Dispose() => gate.Dispose();

    private void Initialize()
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
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
            INSERT INTO client_mailbox_meta(id, schema_version)
            VALUES(1, 2)
            ON CONFLICT(id) DO NOTHING;
            """;
        command.ExecuteNonQuery();

        using var version = connection.CreateCommand();
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
            using var migrate = connection.CreateCommand();
            migrate.Transaction = transaction;
            migrate.CommandText =
                "UPDATE client_mailbox_meta SET schema_version = 2 WHERE id = 1;";
            migrate.ExecuteNonQuery();
        }

        transaction.Commit();
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
            var state = await LoadAsync(connection, transaction: null, scope, cancellationToken)
                .ConfigureAwait(false);
            return read(state);
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
            var state = await LoadAsync(connection, transaction, scope, cancellationToken)
                .ConfigureAwait(false);
            var result = mutation(state);
            var encoded = ClientMailboxStateCodec.Encode(state);
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
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
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

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
        command.ExecuteNonQuery();
        return connection;
    }

    private async Task<SqliteConnection> OpenAsync(
        CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText =
            "PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;";
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }
}
