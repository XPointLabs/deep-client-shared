using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteSessionStore
{
    private Action<TransportOutboxCommitFaultPoint>? _transportOutboxFaultInjector;

    internal SqliteSessionStore(
        SqliteSessionStoreOptions options,
        Action<TransportOutboxCommitFaultPoint> outboxFaultInjector)
        : this(options)
    {
        _transportOutboxFaultInjector =
            outboxFaultInjector ?? throw new ArgumentNullException(nameof(outboxFaultInjector));
    }

    public Task<TransportOutboxCommitResult> PrepareTransportOutboxAsync(
        TransportOutboxPreparedItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        var candidate = TransportOutboxStateMachine.Prepared(item);
        return WithReplayConnectionAsync(connection =>
        {
            using var transaction = connection.BeginTransaction();
            TransportOutboxStoredItem? existing;
            try
            {
                existing = ReadTransportOutboxItem(connection, transaction, item.LogicalId.Value);
            }
            catch (TransportOutboxCorruptException)
            {
                return Task.FromResult(TransportOutboxCommitResult.Corrupt);
            }

            if (existing is not null)
            {
                try
                {
                    return Task.FromResult(
                        TransportOutboxStateMachine.SamePrepared(existing, item)
                            ? TransportOutboxCommitResult.Idempotent
                            : TransportOutboxCommitResult.Conflict);
                }
                catch (TransportOutboxCorruptException)
                {
                    return Task.FromResult(TransportOutboxCommitResult.Corrupt);
                }
            }

            _transportOutboxFaultInjector?.Invoke(TransportOutboxCommitFaultPoint.BeforeDurableCommit);
            cancellationToken.ThrowIfCancellationRequested();
            InsertTransportOutboxItem(connection, transaction, candidate);
            transaction.Commit();
            ThrowIfSqliteOutboxOutcomeUnknown(cancellationToken);
            return Task.FromResult(TransportOutboxCommitResult.Applied);
        }, cancellationToken);
    }

    public Task<TransportOutboxReadSnapshot> ReadTransportOutboxAsync(
        OutboxLogicalId logicalId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(logicalId);
        return WithReplayConnectionAsync(connection =>
        {
            try
            {
                var item = ReadTransportOutboxItem(connection, transaction: null, logicalId.Value);
                return Task.FromResult(
                    item is null
                        ? new TransportOutboxReadSnapshot(TransportOutboxReadResult.Missing, null)
                        : new TransportOutboxReadSnapshot(
                            TransportOutboxReadResult.Found,
                            TransportOutboxStateMachine.Snapshot(item)));
            }
            catch (TransportOutboxCorruptException)
            {
                return Task.FromResult(
                    new TransportOutboxReadSnapshot(TransportOutboxReadResult.Corrupt, null));
            }
        }, cancellationToken);
    }

    public Task<TransportOutboxCommitResult> ApplyTransportOutboxTransitionAsync(
        TransportOutboxTransition transition,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transition);
        return WithReplayConnectionAsync(connection =>
        {
            using var transaction = connection.BeginTransaction();
            TransportOutboxStoredItem? existing;
            TransportOutboxStoredItem candidate;
            TransportOutboxCommitResult result;
            try
            {
                existing = ReadTransportOutboxItem(connection, transaction, transition.LogicalId.Value);
                if (existing is null)
                {
                    return Task.FromResult(TransportOutboxCommitResult.Conflict);
                }
                candidate = existing.Clone();
                result = TransportOutboxStateMachine.Apply(candidate, transition);
            }
            catch (TransportOutboxCorruptException)
            {
                return Task.FromResult(TransportOutboxCommitResult.Corrupt);
            }

            if (result != TransportOutboxCommitResult.Applied)
            {
                return Task.FromResult(result);
            }

            _transportOutboxFaultInjector?.Invoke(TransportOutboxCommitFaultPoint.BeforeDurableCommit);
            cancellationToken.ThrowIfCancellationRequested();
            ReplaceTransportOutboxItem(connection, transaction, candidate);
            transaction.Commit();
            ThrowIfSqliteOutboxOutcomeUnknown(cancellationToken);
            return Task.FromResult(TransportOutboxCommitResult.Applied);
        }, cancellationToken);
    }

    public Task<IReadOnlyList<TransportOutboxItemSnapshot>> ListReadyTransportOutboxAsync(
        OutboxAccountScope accountScope,
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ValidateSqliteOutboxList(accountScope, now, limit);
        return WithReplayConnectionAsync<IReadOnlyList<TransportOutboxItemSnapshot>>(connection =>
        {
            using var transaction = connection.BeginTransaction();
            var logicalIds = QueryOutboxLogicalIds(
                connection,
                transaction,
                """
                SELECT length(logical_id), logical_id
                FROM transport_outbox_items
                WHERE account_scope = $scope
                  AND state IN (1, 2, 3)
                  AND not_before <= $now
                  AND expires_at > $now
                ORDER BY not_before, created_at, logical_id
                LIMIT $limit;
                """,
                accountScope,
                now,
                limit);
            var items = new List<TransportOutboxItemSnapshot>(logicalIds.Count);
            foreach (var logicalId in logicalIds)
            {
                var item = ReadTransportOutboxItem(connection, transaction, logicalId)
                    ?? throw new TransportOutboxCorruptException();
                items.Add(TransportOutboxStateMachine.Snapshot(item));
            }
            transaction.Commit();
            return Task.FromResult<IReadOnlyList<TransportOutboxItemSnapshot>>(items);
        }, cancellationToken);
    }

    public Task<int> ExpireDueTransportOutboxAsync(
        OutboxAccountScope accountScope,
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ValidateSqliteOutboxList(accountScope, now, limit);
        return WithReplayConnectionAsync(connection =>
        {
            using var transaction = connection.BeginTransaction();
            var logicalIds = QueryOutboxLogicalIds(
                connection,
                transaction,
                """
                SELECT length(logical_id), logical_id
                FROM transport_outbox_items
                WHERE account_scope = $scope
                  AND state NOT IN (5, 6)
                  AND expires_at <= $now
                ORDER BY expires_at, logical_id
                LIMIT $limit;
                """,
                accountScope,
                now,
                limit);
            var replacements = new List<TransportOutboxStoredItem>(logicalIds.Count);
            foreach (var logicalId in logicalIds)
            {
                var item = ReadTransportOutboxItem(connection, transaction, logicalId)
                    ?? throw new TransportOutboxCorruptException();
                var candidate = item.Clone();
                if (TransportOutboxStateMachine.Apply(
                        candidate,
                        TransportOutboxTransition.Expired(
                            OutboxLogicalId.FromBytes(item.LogicalId),
                            item.Revision,
                            now))
                    != TransportOutboxCommitResult.Applied)
                {
                    throw new TransportOutboxCorruptException();
                }
                replacements.Add(candidate);
            }
            if (replacements.Count == 0)
            {
                return Task.FromResult(0);
            }

            _transportOutboxFaultInjector?.Invoke(TransportOutboxCommitFaultPoint.BeforeDurableCommit);
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var replacement in replacements)
            {
                ReplaceTransportOutboxItem(connection, transaction, replacement);
            }
            transaction.Commit();
            ThrowIfSqliteOutboxOutcomeUnknown(cancellationToken);
            return Task.FromResult(replacements.Count);
        }, cancellationToken);
    }

    public Task PurgeTransportOutboxScopeAsync(
        OutboxAccountScope accountScope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        return WithReplayConnectionAsync(connection =>
        {
            using var transaction = connection.BeginTransaction();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                "DELETE FROM transport_outbox_items WHERE account_scope = $scope;";
            command.Parameters.AddWithValue("$scope", accountScope.ToArray());
            command.ExecuteNonQuery();
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return Task.FromResult(0);
        }, cancellationToken);
    }

    private static TransportOutboxStoredItem? ReadTransportOutboxItem(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        ReadOnlySpan<byte> logicalId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT
                length(account_scope),
                length(logical_id),
                length(dedup_material),
                length(ciphertext_bundle),
                CASE WHEN acknowledgement_evidence IS NULL
                    THEN NULL ELSE length(acknowledgement_evidence) END,
                account_scope,
                logical_id,
                dedup_material,
                ciphertext_bundle,
                created_at,
                expires_at,
                not_before,
                state,
                revision,
                transition_source,
                transition_reason,
                transitioned_at,
                acknowledgement_evidence
            FROM transport_outbox_items
            WHERE logical_id = $logicalId;
            """;
        command.Parameters.AddWithValue("$logicalId", logicalId.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var accountScope = ReadProjectedOutboxBlob(
            reader,
            0,
            5,
            TransportOutboxLimits.AccountScopeBytes,
            TransportOutboxLimits.AccountScopeBytes);
        var storedLogicalId = ReadProjectedOutboxBlob(
            reader,
            1,
            6,
            TransportOutboxLimits.LogicalIdBytes,
            TransportOutboxLimits.LogicalIdBytes);
        var dedupMaterial = ReadProjectedOutboxBlob(
            reader,
            2,
            7,
            TransportOutboxLimits.DedupMaterialBytes,
            TransportOutboxLimits.DedupMaterialBytes);
        var ciphertextBundle = ReadProjectedOutboxBlob(
            reader,
            3,
            8,
            1,
            TransportOutboxLimits.MaxCiphertextBundleBytes);
        var acknowledgement = reader.IsDBNull(4)
            ? null
            : ReadProjectedOutboxBlob(
                reader,
                4,
                17,
                1,
                TransportOutboxLimits.MaxEvidenceBytes);
        var createdAt = ReadOutboxTimestamp(reader, 9);
        var expiresAt = ReadOutboxTimestamp(reader, 10);
        var notBefore = ReadOutboxTimestamp(reader, 11);
        var state = (TransportOutboxState)ReadBoundedOutboxInteger(reader, 12);
        var revisionValue = reader.GetInt64(13);
        if (revisionValue <= 0)
        {
            throw new TransportOutboxCorruptException();
        }
        var source = (OutboxTransitionSource)ReadBoundedOutboxInteger(reader, 14);
        var reason = (OutboxTransitionReason)ReadBoundedOutboxInteger(reader, 15);
        var transitionedAt = ReadOutboxTimestamp(reader, 16);
        reader.Close();

        var attempts = ReadTransportOutboxAttempts(
            connection,
            transaction,
            storedLogicalId);
        var item = new TransportOutboxStoredItem
        {
            AccountScope = accountScope,
            LogicalId = storedLogicalId,
            DedupMaterial = dedupMaterial,
            CiphertextBundle = ciphertextBundle,
            CreatedAt = createdAt,
            ExpiresAt = expiresAt,
            NotBefore = notBefore,
            State = state,
            Revision = checked((ulong)revisionValue),
            Source = source,
            Reason = reason,
            TransitionedAt = transitionedAt,
            Attempts = attempts,
            AcknowledgementEvidence = acknowledgement
        };
        TransportOutboxStateMachine.Validate(item);
        return item;
    }

    private static List<TransportOutboxStoredAttempt> ReadTransportOutboxAttempts(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        byte[] logicalId)
    {
        using (var count = connection.CreateCommand())
        {
            count.Transaction = transaction;
            count.CommandText =
                "SELECT COUNT(*) FROM transport_outbox_attempts WHERE logical_id = $logicalId;";
            count.Parameters.AddWithValue("$logicalId", logicalId);
            var value = Convert.ToInt64(count.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
            if (value is < 0 or > TransportOutboxLimits.MaxAttemptsPerItem)
            {
                throw new TransportOutboxCorruptException();
            }
        }

        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT
                length(attempt_id),
                length(evidence),
                attempt_id,
                state,
                transition_source,
                transition_reason,
                occurred_at,
                evidence
            FROM transport_outbox_attempts
            WHERE logical_id = $logicalId
            ORDER BY attempt_id;
            """;
        command.Parameters.AddWithValue("$logicalId", logicalId);
        using var reader = command.ExecuteReader();
        var attempts = new List<TransportOutboxStoredAttempt>();
        while (reader.Read())
        {
            var attemptId = ReadProjectedOutboxBlob(
                reader,
                0,
                2,
                TransportOutboxLimits.AttemptIdBytes,
                TransportOutboxLimits.AttemptIdBytes);
            var state = (TransportOutboxAttemptState)ReadBoundedOutboxInteger(reader, 3);
            var evidenceMinimum = state == TransportOutboxAttemptState.Attempted ? 0 : 1;
            var evidence = ReadProjectedOutboxBlob(
                reader,
                1,
                7,
                evidenceMinimum,
                TransportOutboxLimits.MaxEvidenceBytes);
            attempts.Add(new TransportOutboxStoredAttempt
            {
                AttemptId = attemptId,
                State = state,
                Source = (OutboxTransitionSource)ReadBoundedOutboxInteger(reader, 4),
                Reason = (OutboxTransitionReason)ReadBoundedOutboxInteger(reader, 5),
                OccurredAt = ReadOutboxTimestamp(reader, 6),
                Evidence = evidence
            });
        }
        return attempts;
    }

    private static void InsertTransportOutboxItem(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TransportOutboxStoredItem item)
    {
        TransportOutboxStateMachine.Validate(item);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO transport_outbox_items (
                account_scope, logical_id, dedup_material, ciphertext_bundle,
                created_at, expires_at, not_before, state, revision,
                transition_source, transition_reason, transitioned_at,
                acknowledgement_evidence)
            VALUES (
                $scope, $logicalId, $dedup, $ciphertext,
                $createdAt, $expiresAt, $notBefore, $state, $revision,
                $source, $reason, $transitionedAt, $acknowledgement);
            """;
        AddTransportOutboxItemParameters(command, item);
        if (command.ExecuteNonQuery() != 1)
        {
            throw new TransportOutboxCommitOutcomeUnknownException();
        }
    }

    private static void ReplaceTransportOutboxItem(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TransportOutboxStoredItem item)
    {
        TransportOutboxStateMachine.Validate(item);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                UPDATE transport_outbox_items
                SET account_scope = $scope,
                    dedup_material = $dedup,
                    ciphertext_bundle = $ciphertext,
                    created_at = $createdAt,
                    expires_at = $expiresAt,
                    not_before = $notBefore,
                    state = $state,
                    revision = $revision,
                    transition_source = $source,
                    transition_reason = $reason,
                    transitioned_at = $transitionedAt,
                    acknowledgement_evidence = $acknowledgement
                WHERE logical_id = $logicalId;
                """;
            AddTransportOutboxItemParameters(command, item);
            if (command.ExecuteNonQuery() != 1)
            {
                throw new TransportOutboxCommitOutcomeUnknownException();
            }
        }

        using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText =
                "DELETE FROM transport_outbox_attempts WHERE logical_id = $logicalId;";
            delete.Parameters.AddWithValue("$logicalId", item.LogicalId);
            delete.ExecuteNonQuery();
        }
        foreach (var attempt in item.Attempts)
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO transport_outbox_attempts (
                    logical_id, attempt_id, state, transition_source,
                    transition_reason, occurred_at, evidence)
                VALUES (
                    $logicalId, $attemptId, $state, $source,
                    $reason, $occurredAt, $evidence);
                """;
            insert.Parameters.AddWithValue("$logicalId", item.LogicalId);
            insert.Parameters.AddWithValue("$attemptId", attempt.AttemptId);
            insert.Parameters.AddWithValue("$state", (int)attempt.State);
            insert.Parameters.AddWithValue("$source", (int)attempt.Source);
            insert.Parameters.AddWithValue("$reason", (int)attempt.Reason);
            insert.Parameters.AddWithValue("$occurredAt", attempt.OccurredAt.ToUnixTimeMilliseconds());
            insert.Parameters.AddWithValue("$evidence", attempt.Evidence);
            insert.ExecuteNonQuery();
        }
    }

    private static void AddTransportOutboxItemParameters(
        SqliteCommand command,
        TransportOutboxStoredItem item)
    {
        command.Parameters.AddWithValue("$scope", item.AccountScope);
        command.Parameters.AddWithValue("$logicalId", item.LogicalId);
        command.Parameters.AddWithValue("$dedup", item.DedupMaterial);
        command.Parameters.AddWithValue("$ciphertext", item.CiphertextBundle);
        command.Parameters.AddWithValue("$createdAt", item.CreatedAt.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$expiresAt", item.ExpiresAt.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$notBefore", item.NotBefore.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$state", (int)item.State);
        command.Parameters.AddWithValue("$revision", checked((long)item.Revision));
        command.Parameters.AddWithValue("$source", (int)item.Source);
        command.Parameters.AddWithValue("$reason", (int)item.Reason);
        command.Parameters.AddWithValue("$transitionedAt", item.TransitionedAt.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue(
            "$acknowledgement",
            item.AcknowledgementEvidence is null ? DBNull.Value : item.AcknowledgementEvidence);
    }

    private static List<byte[]> QueryOutboxLogicalIds(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        OutboxAccountScope accountScope,
        DateTimeOffset now,
        int limit)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$scope", accountScope.ToArray());
        command.Parameters.AddWithValue("$now", now.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$limit", limit);
        using var reader = command.ExecuteReader();
        var result = new List<byte[]>(limit);
        while (reader.Read())
        {
            result.Add(ReadProjectedOutboxBlob(
                reader,
                0,
                1,
                TransportOutboxLimits.LogicalIdBytes,
                TransportOutboxLimits.LogicalIdBytes));
        }
        return result;
    }

    private static byte[] ReadProjectedOutboxBlob(
        SqliteDataReader reader,
        int lengthOrdinal,
        int blobOrdinal,
        int minimumBytes,
        int maximumBytes)
    {
        long projectedLength;
        try
        {
            projectedLength = reader.GetInt64(lengthOrdinal);
        }
        catch (Exception exception) when (exception is InvalidCastException or OverflowException)
        {
            throw new TransportOutboxCorruptException();
        }
        if (projectedLength < minimumBytes || projectedLength > maximumBytes)
        {
            throw new TransportOutboxCorruptException();
        }

        var actualLength = reader.GetBytes(blobOrdinal, 0, null, 0, 0);
        if (actualLength != projectedLength)
        {
            throw new TransportOutboxCorruptException();
        }
        var value = new byte[checked((int)projectedLength)];
        if (projectedLength > 0
            && reader.GetBytes(blobOrdinal, 0, value, 0, value.Length) != projectedLength)
        {
            throw new TransportOutboxCorruptException();
        }
        return value;
    }

    private static DateTimeOffset ReadOutboxTimestamp(SqliteDataReader reader, int ordinal)
    {
        try
        {
            return DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(ordinal));
        }
        catch (Exception exception) when (exception is ArgumentOutOfRangeException
                                          or InvalidCastException
                                          or OverflowException)
        {
            throw new TransportOutboxCorruptException();
        }
    }

    private static int ReadBoundedOutboxInteger(SqliteDataReader reader, int ordinal)
    {
        try
        {
            var value = reader.GetInt64(ordinal);
            return checked((int)value);
        }
        catch (Exception exception) when (exception is InvalidCastException or OverflowException)
        {
            throw new TransportOutboxCorruptException();
        }
    }

    private void ThrowIfSqliteOutboxOutcomeUnknown(CancellationToken cancellationToken)
    {
        try
        {
            _transportOutboxFaultInjector?.Invoke(TransportOutboxCommitFaultPoint.AfterDurableCommit);
        }
        catch (Exception exception) when (exception is not TransportOutboxCommitOutcomeUnknownException)
        {
            throw new TransportOutboxCommitOutcomeUnknownException();
        }

        if (cancellationToken.IsCancellationRequested)
        {
            throw new TransportOutboxCommitOutcomeUnknownException();
        }
    }

    private static void ValidateSqliteOutboxList(
        OutboxAccountScope accountScope,
        DateTimeOffset now,
        int limit)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        RecipientDeviceAcknowledgement.ValidateOccurredAt(now);
        if (limit is <= 0 or > TransportOutboxLimits.MaxListCount)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }
    }
}
