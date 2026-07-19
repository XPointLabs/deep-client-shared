using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteSessionStore
{
    private Action<AtomicBoundedSettingsFaultPoint>? atomicBoundedSettingsFaultInjector;

    public async Task<AtomicBoundedSettingReadOutcome> ReadAtomicBoundedSettingAsync(
        string key,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!AtomicBoundedSettingsEnvelope.IsValidKeyAndLimit(
                key,
                maximumValueUtf8Bytes))
        {
            return new(AtomicBoundedSettingReadResult.Oversized);
        }

        try
        {
            return await WithConnectionAsync(
                connection => ReadAtomicBoundedSettingOnConnectionAsync(
                    connection,
                    key,
                    maximumValueUtf8Bytes,
                    cancellationToken),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return new(AtomicBoundedSettingReadResult.DependencyFailure);
        }
    }

    public Task<AtomicBoundedSettingMutationResult> CreateAtomicBoundedSettingAsync(
        string key,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default) =>
        MutateAtomicBoundedSettingAsync(
            key,
            expectedRevision: null,
            utf8Json,
            maximumValueUtf8Bytes,
            delete: false,
            create: true,
            cancellationToken);

    public Task<AtomicBoundedSettingMutationResult> ReplaceAtomicBoundedSettingAsync(
        string key,
        AtomicBoundedSettingRevision expectedRevision,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedRevision);
        return MutateAtomicBoundedSettingAsync(
            key,
            expectedRevision,
            utf8Json,
            maximumValueUtf8Bytes,
            delete: false,
            create: false,
            cancellationToken);
    }

    public Task<AtomicBoundedSettingMutationResult> DeleteAtomicBoundedSettingAsync(
        string key,
        AtomicBoundedSettingRevision expectedRevision,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedRevision);
        return MutateAtomicBoundedSettingAsync(
            key,
            expectedRevision,
            utf8Json: default,
            maximumValueUtf8Bytes,
            delete: true,
            create: false,
            cancellationToken);
    }

    internal void SetAtomicBoundedSettingsFaultInjectorForTests(
        Action<AtomicBoundedSettingsFaultPoint>? faultInjector) =>
        atomicBoundedSettingsFaultInjector = faultInjector;

    private async Task<AtomicBoundedSettingMutationResult> MutateAtomicBoundedSettingAsync(
        string key,
        AtomicBoundedSettingRevision? expectedRevision,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes,
        bool delete,
        bool create,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        bool validInput;
        try
        {
            validInput = delete
                ? AtomicBoundedSettingsEnvelope.IsValidKeyAndLimit(
                    key,
                    maximumValueUtf8Bytes)
                : AtomicBoundedSettingsEnvelope.IsValidInput(
                    key,
                    utf8Json,
                    maximumValueUtf8Bytes);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return AtomicBoundedSettingMutationResult.DependencyFailure;
        }
        if (!validInput)
        {
            return AtomicBoundedSettingMutationResult.TooLarge;
        }

        string? replacement = null;
        try
        {
            if (!delete)
            {
                var input = utf8Json.ToArray();
                replacement = AtomicBoundedSettingsEnvelope.Create(
                    AtomicBoundedSettingsEnvelope.CreateRevision(),
                    input);
            }

            atomicBoundedSettingsFaultInjector?.Invoke(
                AtomicBoundedSettingsFaultPoint.BeforeCommit);
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return AtomicBoundedSettingMutationResult.DependencyFailure;
        }

        var committed = false;
        AtomicBoundedSettingMutationResult result;
        try
        {
            result = await WithConnectionAsync(async connection =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var transaction = connection.BeginTransaction(deferred: false);
                if (create)
                {
                    await using var createCommand = connection.CreateCommand();
                    createCommand.Transaction = transaction;
                    createCommand.CommandText = """
                        INSERT INTO settings(key, payload_json)
                        VALUES ($key, $payload)
                        ON CONFLICT(key) DO NOTHING;
                        """;
                    createCommand.Parameters.AddWithValue("$key", key);
                    createCommand.Parameters.AddWithValue("$payload", replacement!);
                    await createCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
                    var changed = await createCommand
                        .ExecuteNonQueryAsync(cancellationToken)
                        .ConfigureAwait(false);
                    if (changed == 1)
                    {
                        committed = true;
                        transaction.Commit();
                        return AtomicBoundedSettingMutationResult.Applied;
                    }

                    return AtomicBoundedSettingMutationResult.Conflict;
                }

                var stored = await ReadStoredEnvelopeOnConnectionAsync(
                    connection,
                    transaction,
                    key,
                    maximumValueUtf8Bytes,
                    cancellationToken).ConfigureAwait(false);
                if (stored.Result == AtomicBoundedSettingReadResult.Missing)
                {
                    return AtomicBoundedSettingMutationResult.Missing;
                }
                if (stored.Result == AtomicBoundedSettingReadResult.Oversized)
                {
                    return AtomicBoundedSettingMutationResult.TooLarge;
                }
                if (stored.Result != AtomicBoundedSettingReadResult.Found
                    || stored.Envelope is null
                    || expectedRevision is null)
                {
                    return AtomicBoundedSettingMutationResult.DependencyFailure;
                }
                if (!CryptographicOperations.FixedTimeEquals(
                        stored.Envelope.Revision,
                        expectedRevision.Value))
                {
                    return AtomicBoundedSettingMutationResult.Conflict;
                }

                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = delete
                    ? """
                        DELETE FROM settings
                        WHERE key = $key AND payload_json = $expectedPayload;
                        """
                    : """
                        UPDATE settings
                        SET payload_json = $payload
                        WHERE key = $key AND payload_json = $expectedPayload;
                        """;
                command.Parameters.AddWithValue("$key", key);
                command.Parameters.AddWithValue("$expectedPayload", stored.RawEnvelope!);
                if (!delete)
                {
                    command.Parameters.AddWithValue("$payload", replacement!);
                }
                await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
                var affected = await command
                    .ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (affected == 1)
                {
                    committed = true;
                    transaction.Commit();
                    return AtomicBoundedSettingMutationResult.Applied;
                }

                await using var exists = connection.CreateCommand();
                exists.Transaction = transaction;
                exists.CommandText = "SELECT 1 FROM settings WHERE key = $key LIMIT 1;";
                exists.Parameters.AddWithValue("$key", key);
                await exists.PrepareAsync(cancellationToken).ConfigureAwait(false);
                return await exists.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is null
                    ? AtomicBoundedSettingMutationResult.Missing
                    : AtomicBoundedSettingMutationResult.Conflict;
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (committed)
            {
                return AtomicBoundedSettingMutationResult.OutcomeUnknown;
            }
            throw;
        }
        catch
        {
            return committed
                ? AtomicBoundedSettingMutationResult.OutcomeUnknown
                : AtomicBoundedSettingMutationResult.DependencyFailure;
        }

        if (result != AtomicBoundedSettingMutationResult.Applied)
        {
            return result;
        }

        try
        {
            atomicBoundedSettingsFaultInjector?.Invoke(
                AtomicBoundedSettingsFaultPoint.AfterCommit);
        }
        catch
        {
            return AtomicBoundedSettingMutationResult.OutcomeUnknown;
        }

        return result;
    }

    private static async Task<AtomicBoundedSettingReadOutcome>
        ReadAtomicBoundedSettingOnConnectionAsync(
            SqliteConnection connection,
            string key,
            int maximumValueUtf8Bytes,
            CancellationToken cancellationToken)
    {
        using var transaction = connection.BeginTransaction(deferred: true);
        var stored = await ReadStoredEnvelopeOnConnectionAsync(
            connection,
            transaction,
            key,
            maximumValueUtf8Bytes,
            cancellationToken).ConfigureAwait(false);
        if (stored.Result != AtomicBoundedSettingReadResult.Found
            || stored.Envelope is null)
        {
            return new(stored.Result);
        }

        transaction.Commit();
        return new(
            AtomicBoundedSettingReadResult.Found,
            AtomicBoundedSettingRevision.FromBytes(stored.Envelope.Revision),
            stored.Envelope.Value);
    }

    private static async Task<SqliteStoredAtomicEnvelope> ReadStoredEnvelopeOnConnectionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string key,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken)
    {
        await using (var lengthCommand = connection.CreateCommand())
        {
            lengthCommand.Transaction = transaction;
            lengthCommand.CommandText = """
                SELECT length(CAST(payload_json AS BLOB))
                FROM settings
                WHERE key = $key;
                """;
            lengthCommand.Parameters.AddWithValue("$key", key);
            await lengthCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
            var rawLength = await lengthCommand
                .ExecuteScalarAsync(cancellationToken)
                .ConfigureAwait(false);
            if (rawLength is null or DBNull)
            {
                return SqliteStoredAtomicEnvelope.For(
                    AtomicBoundedSettingReadResult.Missing);
            }
            if (Convert.ToInt64(rawLength, System.Globalization.CultureInfo.InvariantCulture)
                > AtomicBoundedSettingsEnvelope.MaximumStoredUtf8Bytes(
                    maximumValueUtf8Bytes))
            {
                return SqliteStoredAtomicEnvelope.For(
                    AtomicBoundedSettingReadResult.Oversized);
            }
        }

        string storedEnvelope;
        await using (var valueCommand = connection.CreateCommand())
        {
            valueCommand.Transaction = transaction;
            valueCommand.CommandText = """
                SELECT payload_json
                FROM settings
                WHERE key = $key;
                """;
            valueCommand.Parameters.AddWithValue("$key", key);
            await valueCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
            storedEnvelope = (string?)await valueCommand
                .ExecuteScalarAsync(cancellationToken)
                .ConfigureAwait(false)
                ?? string.Empty;
        }

        var parsed = AtomicBoundedSettingsEnvelope.TryRead(
            storedEnvelope,
            maximumValueUtf8Bytes,
            out var envelope);
        return parsed switch
        {
            AtomicBoundedEnvelopeReadResult.Found when envelope is not null =>
                SqliteStoredAtomicEnvelope.Found(storedEnvelope, envelope),
            AtomicBoundedEnvelopeReadResult.Oversized =>
                SqliteStoredAtomicEnvelope.For(AtomicBoundedSettingReadResult.Oversized),
            _ => SqliteStoredAtomicEnvelope.For(
                AtomicBoundedSettingReadResult.DependencyFailure)
        };
    }

    private sealed class SqliteStoredAtomicEnvelope
    {
        private SqliteStoredAtomicEnvelope(
            AtomicBoundedSettingReadResult result,
            string? rawEnvelope = null,
            AtomicBoundedEnvelope? envelope = null)
        {
            Result = result;
            RawEnvelope = rawEnvelope;
            Envelope = envelope;
        }

        public AtomicBoundedSettingReadResult Result { get; }

        public string? RawEnvelope { get; }

        public AtomicBoundedEnvelope? Envelope { get; }

        public static SqliteStoredAtomicEnvelope For(
            AtomicBoundedSettingReadResult result) =>
            new(result);

        public static SqliteStoredAtomicEnvelope Found(
            string rawEnvelope,
            AtomicBoundedEnvelope envelope) =>
            new(AtomicBoundedSettingReadResult.Found, rawEnvelope, envelope);
    }
}
