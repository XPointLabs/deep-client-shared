using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteSessionStore
{
    private readonly Action<TransportOutboxCommitFaultPoint>? _transportOutboxFaultInjector;

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
            using var transaction = connection.BeginTransaction(deferred: false);
            TransportOutboxStoredItem? existing;
            try
            {
                existing = ReadTransportOutboxItem(
                    connection,
                    transaction,
                    item.AccountScope.Value,
                    item.LogicalId.Value);
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

            var admission = ValidateSqliteOutboxAdmission(
                connection,
                transaction,
                candidate);
            if (admission is not null)
            {
                return Task.FromResult(admission.Value);
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
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(logicalId);
        return WithReplayConnectionAsync(connection =>
        {
            using var transaction = connection.BeginTransaction();
            try
            {
                var item = ReadTransportOutboxItem(
                    connection,
                    transaction,
                    accountScope.Value,
                    logicalId.Value);
                var result =
                    item is null
                        ? new TransportOutboxReadSnapshot(TransportOutboxReadResult.Missing, null)
                        : new TransportOutboxReadSnapshot(
                            TransportOutboxReadResult.Found,
                            TransportOutboxStateMachine.Snapshot(item));
                transaction.Commit();
                return Task.FromResult(result);
            }
            catch (TransportOutboxCorruptException)
            {
                return Task.FromResult(
                    new TransportOutboxReadSnapshot(TransportOutboxReadResult.Corrupt, null));
            }
        }, cancellationToken);
    }

    public Task<TransportOutboxCommitResult> ApplyTransportOutboxTransitionAsync(
        OutboxAccountScope accountScope,
        TransportOutboxTransition transition,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(transition);
        if (!accountScope.Value.SequenceEqual(transition.AccountScope.Value))
        {
            return Task.FromResult(TransportOutboxCommitResult.Conflict);
        }
        return WithReplayConnectionAsync(connection =>
        {
            using var transaction = connection.BeginTransaction(deferred: false);
            TransportOutboxStoredItem? existing;
            TransportOutboxStoredItem candidate;
            TransportOutboxCommitResult result;
            try
            {
                existing = ReadTransportOutboxItem(
                    connection,
                    transaction,
                    accountScope.Value,
                    transition.LogicalId.Value);
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
            UpdateTransportOutboxItem(
                connection,
                transaction,
                existing,
                candidate,
                transition);
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
                  AND NOT EXISTS (
                      SELECT 1
                      FROM transport_outbox_attempts AS attempt
                      WHERE attempt.account_scope = transport_outbox_items.account_scope
                        AND attempt.logical_id = transport_outbox_items.logical_id
                      LIMIT 1 OFFSET $maxAttemptOffset
                  )
                ORDER BY not_before, created_at, logical_id
                LIMIT $limit;
                """,
                accountScope,
                now,
                limit,
                bindMaxAttemptOffset: true);
            var items = new List<TransportOutboxItemSnapshot>(logicalIds.Count);
            foreach (var logicalId in logicalIds)
            {
                var item = ReadTransportOutboxItem(
                    connection,
                    transaction,
                    accountScope.Value,
                    logicalId)
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
            using var transaction = connection.BeginTransaction(deferred: false);
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
            var replacements = new List<(
                TransportOutboxStoredItem Existing,
                TransportOutboxStoredItem Candidate,
                TransportOutboxTransition Transition)>(logicalIds.Count);
            foreach (var logicalId in logicalIds)
            {
                var item = ReadTransportOutboxItem(
                    connection,
                    transaction,
                    accountScope.Value,
                    logicalId)
                    ?? throw new TransportOutboxCorruptException();
                var candidate = item.Clone();
                var transition = TransportOutboxTransition.Expired(
                    accountScope,
                    OutboxLogicalId.FromBytes(item.LogicalId),
                    item.Revision,
                    now);
                if (TransportOutboxStateMachine.Apply(candidate, transition)
                    != TransportOutboxCommitResult.Applied)
                {
                    throw new TransportOutboxCorruptException();
                }
                replacements.Add((item, candidate, transition));
            }
            if (replacements.Count == 0)
            {
                return Task.FromResult(0);
            }

            _transportOutboxFaultInjector?.Invoke(TransportOutboxCommitFaultPoint.BeforeDurableCommit);
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var replacement in replacements)
            {
                UpdateTransportOutboxItem(
                    connection,
                    transaction,
                    replacement.Existing,
                    replacement.Candidate,
                    replacement.Transition);
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
            EnableSqliteSecureDelete(connection);
            using var transaction = connection.BeginTransaction(deferred: false);
            ValidateTransportOutboxSchema(connection, transaction);
            var hasRecoveryTables =
                ValidateTransportOutboxRecoveryTablesIfPresent(connection, transaction);
            using (var active = connection.CreateCommand())
            {
                active.Transaction = transaction;
                active.CommandText = """
                    DELETE FROM transport_outbox_attempts
                    WHERE account_scope = $scope;
                    DELETE FROM transport_outbox_items
                    WHERE account_scope = $scope;
                    """;
                active.Parameters.AddWithValue("$scope", accountScope.ToArray());
                active.ExecuteNonQuery();
            }
            if (hasRecoveryTables)
            {
                using var recovery = connection.CreateCommand();
                recovery.Transaction = transaction;
                recovery.CommandText = """
                    DELETE FROM transport_outbox_attempts_v8_recovery
                    WHERE logical_id IN (
                        SELECT logical_id
                        FROM transport_outbox_items_v8_recovery
                        WHERE account_scope = $scope);
                    DELETE FROM transport_outbox_items_v8_recovery
                    WHERE account_scope = $scope;
                    """;
                recovery.Parameters.AddWithValue("$scope", accountScope.ToArray());
                recovery.ExecuteNonQuery();
            }
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            RunPostScopePurgeMaintenanceBestEffort(connection);
            return Task.FromResult(0);
        }, cancellationToken);
    }

    private static void RunPostScopePurgeMaintenanceBestEffort(SqliteConnection connection)
    {
        // Zero busy timeout bounds lock waiting. Logical deletion is already committed,
        // so a busy or unavailable truncate checkpoint is safe to retry later.
        try
        {
            using (var noWait = connection.CreateCommand())
            {
                noWait.CommandText = "PRAGMA busy_timeout=0;";
                noWait.ExecuteNonQuery();
            }

            using var checkpoint = connection.CreateCommand();
            checkpoint.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            using var result = checkpoint.ExecuteReader();
            if (result.Read())
            {
                _ = result.GetInt32(0); // Busy is expected when another reader owns a snapshot.
                _ = result.GetInt32(1);
                _ = result.GetInt32(2);
            }
        }
        catch
        {
            // Post-commit maintenance must not make callers infer that deletion rolled back.
        }
        finally
        {
            try
            {
                using var restoreTimeout = connection.CreateCommand();
                restoreTimeout.CommandText = "PRAGMA busy_timeout=5000;";
                restoreTimeout.ExecuteNonQuery();
            }
            catch
            {
                // The operation is complete and this short-lived connection can be discarded.
            }
        }
    }

    private static TransportOutboxStoredItem? ReadTransportOutboxItem(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        ReadOnlySpan<byte> accountScope,
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
                CASE WHEN last_attempt_id IS NULL
                    THEN NULL ELSE length(last_attempt_id) END,
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
                last_transition_state,
                last_attempt_id,
                last_retry_not_before,
                acknowledgement_evidence,
                acknowledged_at
            FROM transport_outbox_items
            WHERE account_scope = $scope AND logical_id = $logicalId;
            """;
        command.Parameters.AddWithValue("$scope", accountScope.ToArray());
        command.Parameters.AddWithValue("$logicalId", logicalId.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var storedAccountScope = ReadProjectedOutboxBlob(
            reader,
            0,
            6,
            TransportOutboxLimits.AccountScopeBytes,
            TransportOutboxLimits.AccountScopeBytes);
        var storedLogicalId = ReadProjectedOutboxBlob(
            reader,
            1,
            7,
            TransportOutboxLimits.LogicalIdBytes,
            TransportOutboxLimits.LogicalIdBytes);
        var dedupMaterial = ReadProjectedOutboxBlob(
            reader,
            2,
            8,
            TransportOutboxLimits.DedupMaterialBytes,
            TransportOutboxLimits.DedupMaterialBytes);
        var ciphertextBundle = ReadProjectedOutboxBlob(
            reader,
            3,
            9,
            1,
            TransportOutboxLimits.MaxCiphertextBundleBytes);
        var acknowledgement = reader.IsDBNull(4)
            ? null
            : ReadProjectedOutboxBlob(
                reader,
                4,
                21,
                1,
                TransportOutboxLimits.MaxEvidenceBytes);
        var lastAttemptId = reader.IsDBNull(5)
            ? null
            : ReadProjectedOutboxBlob(
                reader,
                5,
                19,
                TransportOutboxLimits.AttemptIdBytes,
                TransportOutboxLimits.AttemptIdBytes);
        var createdAt = ReadOutboxTimestamp(reader, 10);
        var expiresAt = ReadOutboxTimestamp(reader, 11);
        var notBefore = ReadOutboxTimestamp(reader, 12);
        var state = (TransportOutboxState)ReadBoundedOutboxInteger(reader, 13);
        var revisionValue = ReadOutboxInteger64(reader, 14);
        if (revisionValue <= 0)
        {
            throw new TransportOutboxCorruptException();
        }
        var source = (OutboxTransitionSource)ReadBoundedOutboxInteger(reader, 15);
        var reason = (OutboxTransitionReason)ReadBoundedOutboxInteger(reader, 16);
        var transitionedAt = ReadOutboxTimestamp(reader, 17);
        var lastTransitionState =
            (TransportOutboxState)ReadBoundedOutboxInteger(reader, 18);
        DateTimeOffset? lastRetryNotBefore = reader.IsDBNull(20)
            ? null
            : ReadOutboxTimestamp(reader, 20);
        DateTimeOffset? acknowledgedAt = reader.IsDBNull(22)
            ? null
            : ReadOutboxTimestamp(reader, 22);
        reader.Close();

        var attempts = ReadTransportOutboxAttempts(
            connection,
            transaction,
            storedAccountScope,
            storedLogicalId);
        var item = new TransportOutboxStoredItem
        {
            AccountScope = storedAccountScope,
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
            LastTransitionState = lastTransitionState,
            LastTransitionAttemptId = lastAttemptId,
            LastTransitionRetryNotBefore = lastRetryNotBefore,
            AcknowledgementEvidence = acknowledgement,
            AcknowledgedAt = acknowledgedAt
        };
        TransportOutboxStateMachine.Validate(item);
        return item;
    }

    private static List<TransportOutboxStoredAttempt> ReadTransportOutboxAttempts(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        byte[] accountScope,
        byte[] logicalId)
    {
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
            WHERE account_scope = $scope AND logical_id = $logicalId
            ORDER BY attempt_id
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$scope", accountScope);
        command.Parameters.AddWithValue("$logicalId", logicalId);
        command.Parameters.AddWithValue("$limit", TransportOutboxLimits.MaxAttemptsPerItem + 1);
        using var reader = command.ExecuteReader();
        var attempts = new List<TransportOutboxStoredAttempt>();
        while (reader.Read())
        {
            if (attempts.Count == TransportOutboxLimits.MaxAttemptsPerItem)
            {
                throw new TransportOutboxCorruptException();
            }
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
                last_transition_state, last_attempt_id, last_retry_not_before,
                acknowledgement_evidence, acknowledged_at)
            VALUES (
                $scope, $logicalId, $dedup, $ciphertext,
                $createdAt, $expiresAt, $notBefore, $state, $revision,
                $source, $reason, $transitionedAt,
                $lastTransitionState, $lastAttemptId, $lastRetryNotBefore,
                $acknowledgement, $acknowledgedAt);
            """;
        AddTransportOutboxItemParameters(command, item);
        if (command.ExecuteNonQuery() != 1)
        {
            throw new TransportOutboxCommitOutcomeUnknownException();
        }
    }

    private static void UpdateTransportOutboxItem(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TransportOutboxStoredItem existing,
        TransportOutboxStoredItem item,
        TransportOutboxTransition transition)
    {
        TransportOutboxStateMachine.Validate(item);
        if (transition.AttemptId is { } attemptId)
        {
            var attempt = item.Attempts.Single(candidate =>
                candidate.AttemptId.AsSpan().SequenceEqual(attemptId.Value));
            using var attemptCommand = connection.CreateCommand();
            attemptCommand.Transaction = transaction;
            if (transition.TargetState == TransportOutboxState.Attempted)
            {
                attemptCommand.CommandText = """
                    INSERT INTO transport_outbox_attempts (
                        account_scope, logical_id, attempt_id, state,
                        transition_source, transition_reason, occurred_at, evidence)
                    VALUES (
                        $scope, $logicalId, $attemptId, $state,
                        $source, $reason, $occurredAt, $evidence);
                    """;
            }
            else
            {
                attemptCommand.CommandText = """
                    UPDATE transport_outbox_attempts
                    SET state = $state,
                        transition_source = $source,
                        transition_reason = $reason,
                        occurred_at = $occurredAt,
                        evidence = $evidence
                    WHERE account_scope = $scope
                      AND logical_id = $logicalId
                      AND attempt_id = $attemptId
                      AND state = $previousState;
                    """;
                attemptCommand.Parameters.AddWithValue(
                    "$previousState",
                    (int)attempt.State - 1);
            }
            attemptCommand.Parameters.AddWithValue("$scope", item.AccountScope);
            attemptCommand.Parameters.AddWithValue("$logicalId", item.LogicalId);
            attemptCommand.Parameters.AddWithValue("$attemptId", attempt.AttemptId);
            attemptCommand.Parameters.AddWithValue("$state", (int)attempt.State);
            attemptCommand.Parameters.AddWithValue("$source", (int)attempt.Source);
            attemptCommand.Parameters.AddWithValue("$reason", (int)attempt.Reason);
            attemptCommand.Parameters.AddWithValue(
                "$occurredAt",
                attempt.OccurredAt.ToUnixTimeMilliseconds());
            attemptCommand.Parameters.AddWithValue("$evidence", attempt.Evidence);
            if (attemptCommand.ExecuteNonQuery() != 1)
            {
                throw new TransportOutboxCommitOutcomeUnknownException();
            }
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                UPDATE transport_outbox_items
                SET not_before = $notBefore,
                    state = $state,
                    revision = $revision,
                    transition_source = $source,
                    transition_reason = $reason,
                    transitioned_at = $transitionedAt,
                    last_transition_state = $lastTransitionState,
                    last_attempt_id = $lastAttemptId,
                    last_retry_not_before = $lastRetryNotBefore,
                    acknowledgement_evidence = $acknowledgement,
                    acknowledged_at = $acknowledgedAt
                WHERE account_scope = $scope
                  AND logical_id = $logicalId
                  AND revision = $expectedRevision;
                """;
            AddTransportOutboxItemParameters(command, item);
            command.Parameters.AddWithValue(
                "$expectedRevision",
                checked((long)existing.Revision));
            if (command.ExecuteNonQuery() != 1)
            {
                throw new TransportOutboxCommitOutcomeUnknownException();
            }
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
        command.Parameters.AddWithValue("$lastTransitionState", (int)item.LastTransitionState);
        command.Parameters.AddWithValue(
            "$lastAttemptId",
            item.LastTransitionAttemptId is null ? DBNull.Value : item.LastTransitionAttemptId);
        command.Parameters.AddWithValue(
            "$lastRetryNotBefore",
            item.LastTransitionRetryNotBefore is null
                ? DBNull.Value
                : item.LastTransitionRetryNotBefore.Value.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue(
            "$acknowledgement",
            item.AcknowledgementEvidence is null ? DBNull.Value : item.AcknowledgementEvidence);
        command.Parameters.AddWithValue(
            "$acknowledgedAt",
            item.AcknowledgedAt is null
                ? DBNull.Value
                : item.AcknowledgedAt.Value.ToUnixTimeMilliseconds());
    }

    private static List<byte[]> QueryOutboxLogicalIds(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        OutboxAccountScope accountScope,
        DateTimeOffset now,
        int limit,
        bool bindMaxAttemptOffset = false)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$scope", accountScope.ToArray());
        command.Parameters.AddWithValue("$now", now.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$limit", limit);
        if (bindMaxAttemptOffset)
        {
            command.Parameters.AddWithValue(
                "$maxAttemptOffset",
                TransportOutboxLimits.MaxAttemptsPerItem - 1);
        }
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
        catch (Exception exception) when (exception is InvalidCastException
                                          or FormatException
                                          or OverflowException)
        {
            throw new TransportOutboxCorruptException();
        }
        if (projectedLength < minimumBytes || projectedLength > maximumBytes)
        {
            throw new TransportOutboxCorruptException();
        }

        try
        {
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
        catch (Exception exception) when (exception is InvalidCastException
                                          or FormatException
                                          or OverflowException)
        {
            throw new TransportOutboxCorruptException();
        }
    }

    private static DateTimeOffset ReadOutboxTimestamp(SqliteDataReader reader, int ordinal)
    {
        try
        {
            return DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(ordinal));
        }
        catch (Exception exception) when (exception is ArgumentOutOfRangeException
                                          or InvalidCastException
                                          or FormatException
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
        catch (Exception exception) when (exception is InvalidCastException
                                          or FormatException
                                          or OverflowException)
        {
            throw new TransportOutboxCorruptException();
        }
    }

    private static TransportOutboxCommitResult? ValidateSqliteOutboxAdmission(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TransportOutboxStoredItem candidate)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT typeof(ciphertext_bundle), length(ciphertext_bundle)
            FROM transport_outbox_items
            WHERE account_scope = $scope
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$scope", candidate.AccountScope);
        command.Parameters.AddWithValue(
            "$limit",
            TransportOutboxLimits.MaxItemsPerScope + 1);
        using var reader = command.ExecuteReader();
        var count = 0;
        long logicalBytes = 0;
        while (reader.Read())
        {
            count++;
            if (count >= TransportOutboxLimits.MaxItemsPerScope)
            {
                return TransportOutboxCommitResult.CapacityExceeded;
            }

            long length;
            try
            {
                if (!string.Equals(reader.GetString(0), "blob", StringComparison.Ordinal))
                {
                    return TransportOutboxCommitResult.Corrupt;
                }
                length = reader.GetInt64(1);
            }
            catch (Exception exception) when (exception is InvalidCastException
                                              or FormatException
                                              or OverflowException)
            {
                return TransportOutboxCommitResult.Corrupt;
            }
            if (length is <= 0 or > TransportOutboxLimits.MaxCiphertextBundleBytes)
            {
                return TransportOutboxCommitResult.Corrupt;
            }

            logicalBytes += length;
            if (logicalBytes >
                TransportOutboxLimits.MaxLogicalCiphertextBytesPerScope -
                candidate.CiphertextBundle.Length)
            {
                return TransportOutboxCommitResult.CapacityExceeded;
            }
        }

        return candidate.CiphertextBundle.Length >
            TransportOutboxLimits.MaxLogicalCiphertextBytesPerScope - logicalBytes
                ? TransportOutboxCommitResult.CapacityExceeded
                : null;
    }

    private static long ReadOutboxInteger64(SqliteDataReader reader, int ordinal)
    {
        try
        {
            return reader.GetInt64(ordinal);
        }
        catch (Exception exception) when (exception is InvalidCastException
                                          or FormatException
                                          or OverflowException)
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
