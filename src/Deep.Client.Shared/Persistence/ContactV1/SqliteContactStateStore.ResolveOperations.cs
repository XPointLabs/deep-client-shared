using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.ContactV1;

public sealed partial class SqliteContactStateStore
{
    async ValueTask<ContactResolveOperationStageResult> IContactResolveOperationStore.StageResolveOperationAsync(
        ContactResolveOperationIntent intent,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(intent);
        var candidate = ContactResolveOperationPersistenceValidation.NewPrepared(
            Scope, intent, CanonicalTime(updatedAt));
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            var database = GetConnection();
            await using var transaction = database.BeginTransaction(deferred: false);
            var pending = ReadOne(database, transaction, candidate.PendingAddress.Address.Kind,
                candidate.PendingAddress.Address.CanonicalBytes.Span);
            if (pending is null
                || !pending.Address.Equals(candidate.PendingAddress.Address)
                || pending.ImportedAt != candidate.PendingAddress.ImportedAt)
                throw new ContactResolveOperationMissingAddressException();
            EnsureRelationshipBinding(database, transaction, candidate);

            var existing = ReadResolveOperation(database, transaction, candidate.OperationIdSpan);
            if (existing is not null)
            {
                transaction.Commit();
                if (!SameIntent(existing, candidate))
                    throw new ContactResolveOperationConflictException();
                return new ContactResolveOperationStageResult(
                    ContactResolveOperationStageDisposition.ExactReplay,
                    ContactResolveOperationPersistenceValidation.Validate(existing, Scope));
            }

            if (CountResolveOperations(database, transaction) >= ContactResolveOperationPersistenceValidation.MaximumOperations
                || CountResolveOperationsForRelationship(database, transaction, candidate.RelationshipIdSpan)
                    >= ContactResolveOperationPersistenceValidation.MaximumOperationsPerRelationship)
                throw new ContactResolveOperationCapacityException();

            InsertResolveOperation(database, transaction, candidate);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return new ContactResolveOperationStageResult(
                ContactResolveOperationStageDisposition.Added, candidate.Copy());
        }
        catch (ContactStateStoreOpenException) { throw; }
        catch (ContactResolveOperationConflictException) { throw; }
        catch (ContactResolveOperationCapacityException) { throw; }
        catch (ContactResolveOperationMissingAddressException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The ContactV1 resolve-operation stage failed closed.", exception);
        }
        finally { if (entered) gate.Release(); }
    }

    async ValueTask<ContactResolveOperationSnapshot?> IContactResolveOperationStore.ReadResolveOperationAsync(
        ReadOnlyMemory<byte> operationId32,
        CancellationToken cancellationToken)
    {
        ValidateOperationId(operationId32.Span);
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            var value = ReadResolveOperation(GetConnection(), null, operationId32.Span);
            return value is null ? null : ContactResolveOperationPersistenceValidation.Validate(value, Scope);
        }
        catch (ContactStateStoreOpenException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "Persisted ContactV1 resolve-operation state is invalid.", exception);
        }
        finally { if (entered) gate.Release(); }
    }

    async ValueTask<IReadOnlyList<ContactResolveOperationSnapshot>> IContactResolveOperationStore.ReadResolveOperationsAsync(
        CancellationToken cancellationToken)
    {
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            return ReadAllResolveOperations(GetConnection(), null)
                .Select(value => ContactResolveOperationPersistenceValidation.Validate(value, Scope))
                .ToArray();
        }
        catch (ContactStateStoreOpenException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "Persisted ContactV1 resolve-operation state is invalid.", exception);
        }
        finally { if (entered) gate.Release(); }
    }

    async ValueTask<ContactResolveOperationSnapshot> IContactResolveOperationStore.BeginResolveDispatchAsync(
        ReadOnlyMemory<byte> operationId32,
        ReadOnlyMemory<byte> expectedRequestHash32,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken)
    {
        ValidateOperationId(operationId32.Span);
        RequireHash(expectedRequestHash32.Span, nameof(expectedRequestHash32));
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            var database = GetConnection();
            await using var transaction = database.BeginTransaction(deferred: false);
            var current = ReadResolveOperation(database, transaction, operationId32.Span)
                ?? throw new KeyNotFoundException("The resolver operation does not exist in this account scope.");
            EnsureRequestHash(current, expectedRequestHash32.Span);
            if (current.State is not (ContactResolveOperationState.Prepared or ContactResolveOperationState.RetryPending))
                throw new ContactResolveOperationStateException("Only a prepared or retry-pending resolver operation can dispatch.");
            var updated = current.WithDispatch(CanonicalTime(updatedAt));
            UpdateResolveOperation(database, transaction, updated);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return updated.Copy();
        }
        catch (ContactStateStoreOpenException) { throw; }
        catch (ContactResolveOperationConflictException) { throw; }
        catch (ContactResolveOperationStateException) { throw; }
        catch (KeyNotFoundException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The ContactV1 resolve dispatch transition failed closed.", exception);
        }
        finally { if (entered) gate.Release(); }
    }

    async ValueTask<ContactResolveOperationSnapshot> IContactResolveOperationStore.RecordResolveOutcomeAsync(
        ReadOnlyMemory<byte> operationId32,
        ReadOnlyMemory<byte> expectedRequestHash32,
        ContactResolveOutcomeUpdate update,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken)
    {
        ValidateOperationId(operationId32.Span);
        RequireHash(expectedRequestHash32.Span, nameof(expectedRequestHash32));
        ArgumentNullException.ThrowIfNull(update);
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            var database = GetConnection();
            await using var transaction = database.BeginTransaction(deferred: false);
            var current = ReadResolveOperation(database, transaction, operationId32.Span)
                ?? throw new KeyNotFoundException("The resolver operation does not exist in this account scope.");
            EnsureRequestHash(current, expectedRequestHash32.Span);
            if (current.DispatchCount == 0)
                throw new ContactResolveOperationStateException("A resolver outcome cannot precede durable dispatch intent.");
            if (update.Disposition == ContactResolverDisposition.Verified
                && ReadRelationship(database, transaction, current.RelationshipId) is null)
                throw new ContactResolveOperationStateException("A verified resolver outcome has no idempotently linked relationship.");
            var updated = ContactResolveOperationPersistenceValidation.Validate(
                current.WithOutcome(update, CanonicalTime(updatedAt)), Scope);
            UpdateResolveOperation(database, transaction, updated);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return updated.Copy();
        }
        catch (ContactStateStoreOpenException) { throw; }
        catch (ContactResolveOperationConflictException) { throw; }
        catch (ContactResolveOperationStateException) { throw; }
        catch (KeyNotFoundException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The ContactV1 resolve outcome transition failed closed.", exception);
        }
        finally { if (entered) gate.Release(); }
    }

    private static void InsertResolveOperation(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactResolveOperationSnapshot value)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO contact_resolve_operations(
              operation_id,request_hash,relationship_id,address_kind,canonical_address,exact_xiq1,
              state,dispatch_count,transport_attempt_count,last_disposition,last_retry,
              retry_after_seconds,required_view_hash,exact_xis1,updated_at_utc_ticks)
            VALUES($operation,$request,$relationship,$kind,$address,$xiq,$state,$dispatch,$attempts,
              NULL,NULL,NULL,NULL,NULL,$updated);
            """;
        command.Parameters.AddWithValue("$operation", value.OperationId.ToArray());
        command.Parameters.AddWithValue("$request", value.RequestHash.ToArray());
        command.Parameters.AddWithValue("$relationship", value.RelationshipId.ToArray());
        command.Parameters.AddWithValue("$kind", (int)value.PendingAddress.Address.Kind);
        command.Parameters.AddWithValue("$address", value.PendingAddress.Address.CanonicalBytes.ToArray());
        command.Parameters.AddWithValue("$xiq", value.ExactXiq1.ToArray());
        command.Parameters.AddWithValue("$state", (int)value.State);
        command.Parameters.AddWithValue("$dispatch", ContactStatePersistenceValidation.U64(value.DispatchCount));
        command.Parameters.AddWithValue("$attempts", ContactStatePersistenceValidation.U64(value.TransportAttemptCount));
        command.Parameters.AddWithValue("$updated", value.UpdatedAt.UtcTicks);
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("ContactV1 resolve-operation insert did not affect exactly one row.");
    }

    private static void UpdateResolveOperation(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactResolveOperationSnapshot value)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE contact_resolve_operations SET
              state=$state,dispatch_count=$dispatch,transport_attempt_count=$attempts,
              last_disposition=$disposition,last_retry=$retry,retry_after_seconds=$retryAfter,
              required_view_hash=$requiredView,exact_xis1=$xis,updated_at_utc_ticks=$updated
            WHERE operation_id=$operation AND request_hash=$request;
            """;
        command.Parameters.AddWithValue("$state", (int)value.State);
        command.Parameters.AddWithValue("$dispatch", ContactStatePersistenceValidation.U64(value.DispatchCount));
        command.Parameters.AddWithValue("$attempts", ContactStatePersistenceValidation.U64(value.TransportAttemptCount));
        command.Parameters.AddWithValue("$disposition", value.LastDisposition is null ? DBNull.Value : (int)value.LastDisposition.Value);
        command.Parameters.AddWithValue("$retry", value.LastRetry is null ? DBNull.Value : (int)value.LastRetry.Value);
        command.Parameters.AddWithValue("$retryAfter", value.RetryAfterSeconds is null ? DBNull.Value : (long)value.RetryAfterSeconds.Value);
        command.Parameters.AddWithValue("$requiredView", value.RequiredViewHash.IsEmpty ? DBNull.Value : value.RequiredViewHash.ToArray());
        command.Parameters.AddWithValue("$xis", value.ExactXis1.IsEmpty ? DBNull.Value : value.ExactXis1.ToArray());
        command.Parameters.AddWithValue("$updated", value.UpdatedAt.UtcTicks);
        command.Parameters.AddWithValue("$operation", value.OperationId.ToArray());
        command.Parameters.AddWithValue("$request", value.RequestHash.ToArray());
        if (command.ExecuteNonQuery() != 1)
            throw new ContactResolveOperationConflictException();
    }

    private ContactResolveOperationSnapshot? ReadResolveOperation(
        SqliteConnection database,
        SqliteTransaction? transaction,
        ReadOnlySpan<byte> operationId32)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = ResolveOperationSelect + " WHERE operation_id=$operation;";
        command.Parameters.AddWithValue("$operation", operationId32.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var raw = ReadResolveOperationRawRow(reader);
        if (reader.Read()) throw new FormatException("Duplicate ContactV1 resolve operations were found.");
        reader.Close();
        return MaterializeResolveOperation(database, transaction, raw);
    }

    private List<ContactResolveOperationSnapshot> ReadAllResolveOperations(
        SqliteConnection database,
        SqliteTransaction? transaction)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = ResolveOperationSelect + " ORDER BY updated_at_utc_ticks,operation_id;";
        using var reader = command.ExecuteReader();
        var rows = new List<ResolveOperationRawRow>();
        while (reader.Read()) rows.Add(ReadResolveOperationRawRow(reader));
        reader.Close();
        return rows.Select(row => MaterializeResolveOperation(database, transaction, row)).ToList();
    }

    private static ResolveOperationRawRow ReadResolveOperationRawRow(SqliteDataReader reader) => new(
        (byte[])reader[0],
        (byte[])reader[1],
        (byte[])reader[2],
        (ContactAddressKind)reader.GetInt32(3),
        (byte[])reader[4],
        (byte[])reader[5],
        (ContactResolveOperationState)reader.GetInt32(6),
        ContactStatePersistenceValidation.ReadU64((byte[])reader[7]),
        ContactStatePersistenceValidation.ReadU64((byte[])reader[8]),
        reader.IsDBNull(9) ? null : (ContactResolverDisposition)reader.GetInt32(9),
        reader.IsDBNull(10) ? null : (ContactResolverRetryClassification)reader.GetInt32(10),
        reader.IsDBNull(11) ? null : checked((uint)reader.GetInt64(11)),
        reader.IsDBNull(12) ? null : (byte[])reader[12],
        reader.IsDBNull(13) ? null : (byte[])reader[13],
        reader.GetInt64(14));

    private ContactResolveOperationSnapshot MaterializeResolveOperation(
        SqliteConnection database,
        SqliteTransaction? transaction,
        ResolveOperationRawRow row)
    {
        var pending = ReadOne(database, transaction, row.AddressKind, row.CanonicalAddress)
            ?? throw new FormatException("A ContactV1 resolve operation lost its pending address.");
        return new ContactResolveOperationSnapshot(
            Scope, pending, row.OperationId, row.RequestHash, row.RelationshipId, row.ExactXiq1,
            row.State, row.DispatchCount, row.TransportAttemptCount, row.LastDisposition,
            row.LastRetry, row.RetryAfterSeconds, row.RequiredViewHash ?? [], row.ExactXis1 ?? [],
            Utc(row.UpdatedAtUtcTicks));
    }

    private static void EnsureRelationshipBinding(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactResolveOperationSnapshot candidate)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT address_kind,canonical_address FROM contact_resolve_operations
            WHERE relationship_id=$relationship LIMIT 1;
            """;
        command.Parameters.AddWithValue("$relationship", candidate.RelationshipId.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return;
        var kind = (ContactAddressKind)reader.GetInt32(0);
        var canonical = (byte[])reader[1];
        if (kind != candidate.PendingAddress.Address.Kind
            || !ContactResolveOperationPersistenceValidation.Exact(
                canonical, candidate.PendingAddress.Address.CanonicalBytes.Span))
            throw new ContactResolveOperationConflictException();
    }

    private void ValidatePersistedResolveOperations(SqliteConnection database)
    {
        var values = ReadAllResolveOperations(database, null);
        foreach (var value in values)
        {
            _ = ContactResolveOperationPersistenceValidation.Validate(value, Scope);
            if (value.State == ContactResolveOperationState.RelationshipLinked
                && ReadRelationship(database, null, value.RelationshipId) is null)
                throw new FormatException("A completed ContactV1 resolve operation lost its relationship.");
        }
        if (values.Count > ContactResolveOperationPersistenceValidation.MaximumOperations)
            throw new FormatException("The ContactV1 resolve-operation journal exceeded its bound.");
        foreach (var group in values.GroupBy(value => Convert.ToHexString(value.RelationshipIdSpan), StringComparer.Ordinal))
        {
            if (group.Count() > ContactResolveOperationPersistenceValidation.MaximumOperationsPerRelationship)
                throw new FormatException("A ContactV1 relationship exceeded its resolve-operation bound.");
            var first = group.First();
            if (group.Any(value => value.PendingAddress.Address.Kind != first.PendingAddress.Address.Kind
                    || !ContactResolveOperationPersistenceValidation.Exact(
                        value.PendingAddress.Address.CanonicalBytes.Span,
                        first.PendingAddress.Address.CanonicalBytes.Span)))
                throw new FormatException("One ContactV1 relationship ID is bound to multiple imported addresses.");
        }
    }

    private static bool SameIntent(
        ContactResolveOperationSnapshot left,
        ContactResolveOperationSnapshot right) =>
        ContactResolveOperationPersistenceValidation.Exact(left.RequestHashSpan, right.RequestHashSpan)
        && ContactResolveOperationPersistenceValidation.Exact(left.RelationshipIdSpan, right.RelationshipIdSpan)
        && left.PendingAddress.Address.Equals(right.PendingAddress.Address)
        && left.PendingAddress.ImportedAt == right.PendingAddress.ImportedAt
        && ContactResolveOperationPersistenceValidation.Exact(left.ExactXiq1Span, right.ExactXiq1Span);

    private static void EnsureRequestHash(ContactResolveOperationSnapshot value, ReadOnlySpan<byte> expected)
    {
        if (!ContactResolveOperationPersistenceValidation.Exact(value.RequestHashSpan, expected))
            throw new ContactResolveOperationConflictException();
    }

    private static void ValidateOperationId(ReadOnlySpan<byte> value)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte resolver operation ID is required.", nameof(value));
    }

    private static void RequireHash(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte resolver request hash is required.", name);
    }

    private static DateTimeOffset CanonicalTime(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        if (utc.Ticks < 0) throw new ArgumentOutOfRangeException(nameof(value));
        return utc;
    }

    private static long CountResolveOperations(SqliteConnection database, SqliteTransaction transaction)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COUNT(*) FROM contact_resolve_operations;";
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static long CountResolveOperationsForRelationship(
        SqliteConnection database,
        SqliteTransaction transaction,
        ReadOnlySpan<byte> relationshipId32)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COUNT(*) FROM contact_resolve_operations WHERE relationship_id=$relationship;";
        command.Parameters.AddWithValue("$relationship", relationshipId32.ToArray());
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private const string ResolveOperationSelect = """
        SELECT operation_id,request_hash,relationship_id,address_kind,canonical_address,exact_xiq1,
          state,dispatch_count,transport_attempt_count,last_disposition,last_retry,retry_after_seconds,
          required_view_hash,exact_xis1,updated_at_utc_ticks
        FROM contact_resolve_operations
        """;

    private sealed record ResolveOperationRawRow(
        byte[] OperationId,
        byte[] RequestHash,
        byte[] RelationshipId,
        ContactAddressKind AddressKind,
        byte[] CanonicalAddress,
        byte[] ExactXiq1,
        ContactResolveOperationState State,
        ulong DispatchCount,
        ulong TransportAttemptCount,
        ContactResolverDisposition? LastDisposition,
        ContactResolverRetryClassification? LastRetry,
        uint? RetryAfterSeconds,
        byte[]? RequiredViewHash,
        byte[]? ExactXis1,
        long UpdatedAtUtcTicks);
}
