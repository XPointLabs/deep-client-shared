using System.Globalization;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.ContactV1;

public sealed partial class SqliteContactStateStore
{
    public async ValueTask<ContactRelationshipSnapshot?> ReadRelationshipAsync(
        ContactRelationshipId32 relationshipId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(relationshipId);
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            return ReadRelationship(GetConnection(), null, relationshipId);
        }
        catch (ContactStateStoreOpenException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "Persisted ContactV1 relationship state is invalid and must be reset.", exception);
        }
        finally { if (entered) gate.Release(); }
    }

    public async ValueTask<IReadOnlyList<ContactRelationshipSnapshot>> ReadRelationshipsAsync(
        CancellationToken cancellationToken = default)
    {
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            return ReadAllRelationships(GetConnection(), null).Select(static value => value.Copy()).ToArray();
        }
        catch (ContactStateStoreOpenException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "Persisted ContactV1 relationship state is invalid and must be reset.", exception);
        }
        finally { if (entered) gate.Release(); }
    }

    public async ValueTask<ContactVerifiedPeerPackageEvidence?> ReadVerifiedPeerPackageAsync(
        ContactRelationshipId32 relationshipId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(relationshipId);
        using var operation = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            return ReadVerifiedPeerPackage(GetConnection(), null, relationshipId)?.Copy();
        }
        catch (ContactStateStoreOpenException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "Persisted ContactV1 verified-peer package is invalid and must be reset.", exception);
        }
        finally { if (entered) gate.Release(); }
    }

    public async ValueTask<ContactRelationshipCommitResult> CommitRelationshipAsync(
        ContactRelationshipMutationPlan mutation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mutation);
        if (!Scope.Equals(mutation.Scope))
            throw new ArgumentException("The contact mutation belongs to another exact account scope.", nameof(mutation));
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

            var replay = ReadOperation(database, transaction, mutation.OperationId);
            if (replay is not null)
            {
                var current = ReadRelationship(database, transaction, replay.RelationshipId)
                    ?? throw new FormatException("A ContactV1 replay journal entry lost its relationship head.");
                transaction.Commit();
                if (!CryptographicOperations.FixedTimeEquals(replay.Fingerprint, mutation.Fingerprint)
                    || !replay.RelationshipId.Equals(mutation.RelationshipId))
                {
                    return new(ContactRelationshipCommitDisposition.Conflict, current, null);
                }
                return new(ContactRelationshipCommitDisposition.Idempotent, current, replay.CommittedRevision);
            }

            ContactRelationshipCommitResult result;
            if (mutation.Kind == ContactRelationshipMutationKind.BundleVerified)
                result = CreateVerifiedBundle(database, transaction, mutation);
            else
                result = ApplyTransition(database, transaction, mutation);

            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return result with { Relationship = result.Relationship?.Copy() };
        }
        catch (ContactStateStoreOpenException) { throw; }
        catch (Exception exception) when (exception is SqliteException or FormatException or InvalidOperationException or ArgumentException)
        {
            throw Failure(ContactStateStoreOpenFailure.Corrupt,
                "The ContactV1 relationship transaction failed closed.", exception);
        }
        finally { if (entered) gate.Release(); }
    }

    private ContactRelationshipCommitResult CreateVerifiedBundle(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactRelationshipMutationPlan mutation)
    {
        var evidence = mutation.BundleEvidence!;
        var collision = ReadRelationship(database, transaction, mutation.RelationshipId);
        if (collision is not null)
            return new(ContactRelationshipCommitDisposition.Conflict, collision, null);
        if (CountRelationships(database, transaction) >= MaximumPendingAddresses)
            return new(ContactRelationshipCommitDisposition.CapacityExceeded, null, null);
        var pending = ReadOne(database, transaction, evidence.Address.Kind, evidence.Address.CanonicalBytes.Span);
        if (pending is null || !pending.Address.Equals(evidence.Address))
            return new(ContactRelationshipCommitDisposition.NotFound, null, null);
        if (mutation.OccurredAt < pending.ImportedAt)
            return new(ContactRelationshipCommitDisposition.InvalidTransition, null, null);

        var created = new ContactRelationshipSnapshot(evidence.RelationshipId, evidence.ConversationId,
            evidence.RemoteAccountId, evidence.Address.Kind, evidence.Address.CanonicalBytes.Span,
            ContactRelationshipState.BundleVerified, 1, mutation.OccurredAt, mutation.OccurredAt,
            evidence.ArtifactHashes);
        InsertRelationship(database, transaction, created);
        InsertVerifiedPeerPackage(database, transaction, mutation.RecoveryPackage!);
        InsertOperation(database, transaction, mutation, created.Revision);
        return new(ContactRelationshipCommitDisposition.Applied, created, created.Revision);
    }

    private static ContactRelationshipCommitResult ApplyTransition(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactRelationshipMutationPlan mutation)
    {
        var current = ReadRelationship(database, transaction, mutation.RelationshipId);
        if (current is null)
            return new(ContactRelationshipCommitDisposition.NotFound, null, null);
        var result = ContactRelationshipStateMachine.Apply(current, mutation);
        if (result.Disposition != ContactRelationshipCommitDisposition.Applied)
            return result;
        UpdateRelationship(database, transaction, result.Relationship!, mutation.ExpectedRevision!.Value);
        InsertOperation(database, transaction, mutation, result.Relationship!.Revision);
        return result;
    }

    private static void InsertRelationship(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactRelationshipSnapshot value)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO contact_relationships(
              relationship_id,conversation_id,remote_account_id,address_kind,canonical_address,
              state,revision,created_at_utc_ticks,updated_at_utc_ticks,
              did1_hash,dab1_hash,dpa1_hash,drs1_hash,dmd1_hash,dca1_hash,dcb1_hash,dcr1_hash,
              adh1_hash,adp1_hash,reachability_descriptor_hash)
            VALUES($relationship,$conversation,$remote,$kind,$canonical,$state,$revision,$created,$updated,
              $did1,$dab1,$dpa1,$drs1,$dmd1,$dca1,$dcb1,$dcr1,$adh1,$adp1,$reachability);
            """;
        BindRelationship(command, value);
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("ContactV1 relationship insert did not affect exactly one row.");
    }

    private static void UpdateRelationship(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactRelationshipSnapshot value,
        ulong expectedRevision)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE contact_relationships SET state=$state,revision=$revision,updated_at_utc_ticks=$updated
            WHERE relationship_id=$relationship AND revision=$expected;
            """;
        command.Parameters.AddWithValue("$state", (int)value.State);
        command.Parameters.AddWithValue("$revision", ContactStatePersistenceValidation.U64(value.Revision));
        command.Parameters.AddWithValue("$updated", value.UpdatedAt.UtcTicks);
        command.Parameters.AddWithValue("$relationship", value.RelationshipId.ToArray());
        command.Parameters.AddWithValue("$expected", ContactStatePersistenceValidation.U64(expectedRevision));
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("ContactV1 relationship CAS lost its locked current head.");
    }

    private static void BindRelationship(SqliteCommand command, ContactRelationshipSnapshot value)
    {
        command.Parameters.AddWithValue("$relationship", value.RelationshipId.ToArray());
        command.Parameters.AddWithValue("$conversation", value.ConversationId.ToArray());
        command.Parameters.AddWithValue("$remote", value.RemoteAccountId.ToArray());
        command.Parameters.AddWithValue("$kind", (int)value.AddressKind);
        command.Parameters.AddWithValue("$canonical", value.ExactCanonicalAddress.ToArray());
        command.Parameters.AddWithValue("$state", (int)value.State);
        command.Parameters.AddWithValue("$revision", ContactStatePersistenceValidation.U64(value.Revision));
        command.Parameters.AddWithValue("$created", value.CreatedAt.UtcTicks);
        command.Parameters.AddWithValue("$updated", value.UpdatedAt.UtcTicks);
        foreach (var (parameter, kind) in ArtifactColumns)
            command.Parameters.AddWithValue(parameter, value.ArtifactHashes[kind].ToArray());
    }

    private static void InsertOperation(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactRelationshipMutationPlan mutation,
        ulong committedRevision)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO contact_relationship_operations(operation_id,fingerprint,relationship_id,committed_revision)
            VALUES($operation,$fingerprint,$relationship,$revision);
            """;
        command.Parameters.AddWithValue("$operation", mutation.OperationId.ToArray());
        command.Parameters.AddWithValue("$fingerprint", mutation.Fingerprint.ToArray());
        command.Parameters.AddWithValue("$relationship", mutation.RelationshipId.ToArray());
        command.Parameters.AddWithValue("$revision", ContactStatePersistenceValidation.U64(committedRevision));
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("ContactV1 operation journal insert did not affect exactly one row.");
    }

    private static void InsertVerifiedPeerPackage(
        SqliteConnection database,
        SqliteTransaction transaction,
        ContactVerifiedPeerPackageEvidence package)
    {
        using (var command = database.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO contact_verified_peer_packages(
                  relationship_id,package_version,package_hash,local_account_id,remote_account_id,
                  conversation_id,network_id,address_kind,canonical_address,exact_xiq1,exact_xis1,
                  exact_dcr1,exact_dcb1,exact_dmd1,exact_route_closure)
                VALUES($relationship,$version,$hash,$local,$remote,$conversation,$network,$kind,
                  $address,$xiq1,$xis1,$dcr1,$dcb1,$dmd1,$route);
                """;
            command.Parameters.AddWithValue("$relationship", package.RelationshipId.ToArray());
            command.Parameters.AddWithValue("$version", package.Version);
            command.Parameters.AddWithValue("$hash", package.PackageHash.ToArray());
            command.Parameters.AddWithValue("$local", package.Scope.AccountId.Bytes.ToArray());
            command.Parameters.AddWithValue("$remote", package.RemoteAccountId.ToArray());
            command.Parameters.AddWithValue("$conversation", package.ConversationId.ToArray());
            command.Parameters.AddWithValue("$network", package.NetworkId.ToArray());
            command.Parameters.AddWithValue("$kind", (int)package.AddressKind);
            command.Parameters.AddWithValue("$address", package.ExactCanonicalAddress.ToArray());
            command.Parameters.AddWithValue("$xiq1", package.ExactXiq1.ToArray());
            command.Parameters.AddWithValue("$xis1", package.ExactXis1.ToArray());
            command.Parameters.AddWithValue("$dcr1", package.ExactDcr1.ToArray());
            command.Parameters.AddWithValue("$dcb1", package.ExactDcb1.ToArray());
            command.Parameters.AddWithValue("$dmd1", package.ExactDmd1.ToArray());
            command.Parameters.AddWithValue("$route", package.ExactRouteClosure.ToArray());
            if (command.ExecuteNonQuery() != 1)
                throw new InvalidOperationException("Verified-peer package insert did not affect exactly one row.");
        }

        var devices = package.Devices;
        for (var index = 0; index < devices.Count; index++)
        {
            using var command = database.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO contact_verified_peer_devices(relationship_id,ordinal,device_id,exact_dpd1)
                VALUES($relationship,$ordinal,$device,$dpd1);
                """;
            command.Parameters.AddWithValue("$relationship", package.RelationshipId.ToArray());
            command.Parameters.AddWithValue("$ordinal", index);
            command.Parameters.AddWithValue("$device", devices[index].DeviceId.ToArray());
            command.Parameters.AddWithValue("$dpd1", devices[index].ExactDpd1.ToArray());
            if (command.ExecuteNonQuery() != 1)
                throw new InvalidOperationException("Verified-peer device insert did not affect exactly one row.");
        }
    }

    private ContactVerifiedPeerPackageEvidence? ReadVerifiedPeerPackage(
        SqliteConnection database,
        SqliteTransaction? transaction,
        ContactRelationshipId32 relationshipId)
    {
        byte[] packageHash;
        byte[] localAccount;
        byte[] remoteAccount;
        byte[] conversation;
        byte[] network;
        byte[] address;
        byte[] xiq1;
        byte[] xis1;
        byte[] dcr1;
        byte[] dcb1;
        byte[] dmd1;
        byte[] route;
        int kind;
        using (var command = database.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT package_version,package_hash,local_account_id,remote_account_id,conversation_id,
                  network_id,address_kind,canonical_address,exact_xiq1,exact_xis1,exact_dcr1,
                  exact_dcb1,exact_dmd1,exact_route_closure
                FROM contact_verified_peer_packages WHERE relationship_id=$relationship;
                """;
            command.Parameters.AddWithValue("$relationship", relationshipId.ToArray());
            using var reader = command.ExecuteReader();
            if (!reader.Read()) return null;
            if (reader.GetInt32(0) != ContactVerifiedPeerPackageEvidence.CurrentVersion)
                throw new FormatException("Persisted verified-peer package version is unsupported.");
            packageHash = (byte[])reader[1];
            localAccount = (byte[])reader[2];
            remoteAccount = (byte[])reader[3];
            conversation = (byte[])reader[4];
            network = (byte[])reader[5];
            kind = reader.GetInt32(6);
            address = (byte[])reader[7];
            xiq1 = (byte[])reader[8];
            xis1 = (byte[])reader[9];
            dcr1 = (byte[])reader[10];
            dcb1 = (byte[])reader[11];
            dmd1 = (byte[])reader[12];
            route = (byte[])reader[13];
            if (reader.Read()) throw new FormatException("Duplicate verified-peer packages were found.");
        }
        if (!Scope.AccountId.Matches(localAccount))
            throw new FormatException("Persisted verified-peer package belongs to another local account.");

        var devices = new List<ContactVerifiedPeerDeviceEvidence>();
        using (var command = database.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT ordinal,device_id,exact_dpd1 FROM contact_verified_peer_devices
                WHERE relationship_id=$relationship ORDER BY ordinal;
                """;
            command.Parameters.AddWithValue("$relationship", relationshipId.ToArray());
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                if (reader.GetInt32(0) != devices.Count || devices.Count == ContactVerifiedPeerPackageEvidence.MaximumDevices)
                    throw new FormatException("Persisted verified-peer device ordering is invalid.");
                devices.Add(new ContactVerifiedPeerDeviceEvidence((byte[])reader[1], (byte[])reader[2]));
            }
        }

        return new ContactVerifiedPeerPackageEvidence(
            Scope,
            relationshipId,
            ContactConversationId32.FromBytes(conversation),
            ContactAccountId32.FromVerifiedBytes(remoteAccount),
            (ContactAddressKind)kind,
            network,
            address,
            xiq1,
            xis1,
            dcr1,
            dcb1,
            dmd1,
            devices,
            route,
            packageHash);
    }

    private static ContactOperationRow? ReadOperation(
        SqliteConnection database,
        SqliteTransaction? transaction,
        ContactMutationId32 operationId)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT fingerprint,relationship_id,committed_revision
            FROM contact_relationship_operations WHERE operation_id=$operation;
            """;
        command.Parameters.AddWithValue("$operation", operationId.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var fingerprint = (byte[])reader[0];
        if (fingerprint.Length != 32)
            throw new FormatException("Persisted ContactV1 operation fingerprint is invalid.");
        var result = new ContactOperationRow(fingerprint,
            ContactRelationshipId32.FromBytes((byte[])reader[1]),
            ContactStatePersistenceValidation.ReadU64((byte[])reader[2]));
        if (result.CommittedRevision == 0 || reader.Read())
            throw new FormatException("Persisted ContactV1 operation journal is invalid.");
        return result;
    }

    private static ContactRelationshipSnapshot? ReadRelationship(
        SqliteConnection database,
        SqliteTransaction? transaction,
        ContactRelationshipId32 relationshipId)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = RelationshipSelect + " WHERE relationship_id=$relationship;";
        command.Parameters.AddWithValue("$relationship", relationshipId.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var result = ReadRelationshipRow(reader);
        if (reader.Read()) throw new FormatException("Duplicate ContactV1 relationship rows were found.");
        return result;
    }

    private static List<ContactRelationshipSnapshot> ReadAllRelationships(
        SqliteConnection database,
        SqliteTransaction? transaction)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = RelationshipSelect + " ORDER BY updated_at_utc_ticks,relationship_id;";
        using var reader = command.ExecuteReader();
        var result = new List<ContactRelationshipSnapshot>();
        while (reader.Read())
        {
            if (result.Count == MaximumPendingAddresses)
                throw new FormatException("ContactV1 relationship capacity was exceeded.");
            result.Add(ReadRelationshipRow(reader));
        }
        return result;
    }

    private static ContactRelationshipSnapshot ReadRelationshipRow(SqliteDataReader reader)
    {
        var kind = (ContactAddressKind)reader.GetInt32(3);
        var canonical = (byte[])reader[4];
        ContactStatePersistenceValidation.ValidateLookup(kind, canonical);
        var hashes = Enumerable.Range(9, 11)
            .Select(index => ContactArtifactHash32.FromVerifiedBytes((byte[])reader[index]))
            .ToArray();
        return new(ContactRelationshipId32.FromBytes((byte[])reader[0]),
            ContactConversationId32.FromBytes((byte[])reader[1]),
            ContactAccountId32.FromVerifiedBytes((byte[])reader[2]), kind, canonical,
            (ContactRelationshipState)reader.GetInt32(5),
            ContactStatePersistenceValidation.ReadU64((byte[])reader[6]),
            Utc(reader.GetInt64(7)), Utc(reader.GetInt64(8)),
            new ContactVerifiedArtifactHashes(hashes));
    }

    private static DateTimeOffset Utc(long ticks)
    {
        if (ticks < 0 || ticks > DateTimeOffset.MaxValue.Ticks)
            throw new FormatException("Persisted ContactV1 UTC timestamp is invalid.");
        return new DateTimeOffset(ticks, TimeSpan.Zero);
    }

    private static long CountRelationships(SqliteConnection database, SqliteTransaction transaction)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COUNT(*) FROM contact_relationships;";
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private void ValidatePersistedRelationships(SqliteConnection database)
    {
        var rows = ReadAllRelationships(database, null);
        foreach (var row in rows)
        {
            var pending = ReadOne(database, null, row.AddressKind, row.ExactCanonicalAddress.Span)
                ?? throw new FormatException("A persisted ContactV1 relationship has no exact pending-address origin.");
            if (Scope.AccountId.Matches(row.RemoteAccountId.Span))
                throw new FormatException("A persisted ContactV1 relationship targets its local account.");
            var expected = ContactConversationId32.Derive(pending.Address.NetworkId.Span,
                row.RelationshipId, Scope.AccountId.Bytes.Span, row.RemoteAccountId.Span);
            if (!expected.Equals(row.ConversationId))
                throw new FormatException("A persisted ContactV1 conversation ID is not bound to its exact account scope.");
            var package = ReadVerifiedPeerPackage(database, null, row.RelationshipId)
                ?? throw new FormatException("A persisted ContactV1 relationship has no verified-peer package.");
            if (!package.ConversationId.Equals(row.ConversationId) ||
                !package.RemoteAccountId.Equals(row.RemoteAccountId) ||
                package.AddressKind != row.AddressKind ||
                !package.ExactCanonicalAddress.Span.SequenceEqual(row.ExactCanonicalAddress.Span))
                throw new FormatException("A persisted verified-peer package differs from its relationship head.");
        }

        using (var count = database.CreateCommand())
        {
            count.CommandText = "SELECT COUNT(*) FROM contact_verified_peer_packages;";
            if (Convert.ToInt64(count.ExecuteScalar(), CultureInfo.InvariantCulture) != rows.Count)
                throw new FormatException("Persisted verified-peer package cardinality is invalid.");
        }

        using var command = database.CreateCommand();
        command.CommandText = """
            SELECT operation_id,fingerprint,relationship_id,committed_revision
            FROM contact_relationship_operations ORDER BY operation_id;
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            _ = ContactMutationId32.FromBytes((byte[])reader[0]);
            var fingerprint = (byte[])reader[1];
            if (fingerprint.Length != 32)
                throw new FormatException("A persisted ContactV1 operation fingerprint is invalid.");
            var relationship = rows.SingleOrDefault(value => value.RelationshipId.Equals(
                ContactRelationshipId32.FromBytes((byte[])reader[2])))
                ?? throw new FormatException("A persisted ContactV1 operation has no relationship.");
            var committed = ContactStatePersistenceValidation.ReadU64((byte[])reader[3]);
            if (committed == 0 || committed > relationship.Revision)
                throw new FormatException("A persisted ContactV1 operation revision is invalid.");
        }
    }

    private const string RelationshipSelect = """
        SELECT relationship_id,conversation_id,remote_account_id,address_kind,canonical_address,
          state,revision,created_at_utc_ticks,updated_at_utc_ticks,
          did1_hash,dab1_hash,dpa1_hash,drs1_hash,dmd1_hash,dca1_hash,dcb1_hash,dcr1_hash,
          adh1_hash,adp1_hash,reachability_descriptor_hash
        FROM contact_relationships
        """;

    private static readonly (string Parameter, ContactVerifiedArtifactKind Kind)[] ArtifactColumns =
    [
        ("$did1", ContactVerifiedArtifactKind.Did1),
        ("$dab1", ContactVerifiedArtifactKind.Dab1),
        ("$dpa1", ContactVerifiedArtifactKind.Dpa1),
        ("$drs1", ContactVerifiedArtifactKind.Drs1),
        ("$dmd1", ContactVerifiedArtifactKind.Dmd1),
        ("$dca1", ContactVerifiedArtifactKind.Dca1),
        ("$dcb1", ContactVerifiedArtifactKind.Dcb1),
        ("$dcr1", ContactVerifiedArtifactKind.Dcr1),
        ("$adh1", ContactVerifiedArtifactKind.Adh1),
        ("$adp1", ContactVerifiedArtifactKind.Adp1),
        ("$reachability", ContactVerifiedArtifactKind.ReachabilityDescriptor),
    ];

    private sealed record ContactOperationRow(
        byte[] Fingerprint,
        ContactRelationshipId32 RelationshipId,
        ulong CommittedRevision);
}
