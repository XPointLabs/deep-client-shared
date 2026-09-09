using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.PreKeyV1;

internal sealed partial class SqlitePreKeyV1SecretOwner
{
    internal async ValueTask<PreKeyV1PublicationRequest?> ReadPublicationAsync(
        ulong inventoryEpoch,
        CancellationToken cancellationToken = default)
    {
        if (inventoryEpoch == 0) throw new ArgumentOutOfRangeException(nameof(inventoryEpoch));
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            using var command = GetConnection().CreateCommand();
            command.CommandText = "SELECT inventory_epoch,service_generation,operation_id,predecessor_xpi1_hash,current_dmd1_generation,current_dmd1_hash,xpi1_hash,exact_xpi1,exact_xpp1 FROM prekey_publications WHERE inventory_epoch=$epoch;";
            Add(command, "$epoch", U64(inventoryEpoch));
            using var reader = command.ExecuteReader();
            if (!reader.Read()) return null;
            var result = Publication(reader);
            if (reader.Read()) throw new FormatException("Duplicate pre-key publication epochs exist.");
            return result;
        }
        finally
        {
            if (entered) gate.Release();
        }
    }

    internal async ValueTask<PreKeyV1PublicationRequest?> ReadLatestPublicationAsync(
        CancellationToken cancellationToken = default)
    {
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            var db = GetConnection();
            using var transaction = db.BeginTransaction(deferred: true);
            return ReadLatestPublication(db, transaction);
        }
        finally
        {
            if (entered) gate.Release();
        }
    }

    internal async ValueTask<PreKeyV1InventoryStageResult> StageInventoryAsync(
        PreKeyV1PublicationRequest request,
        IReadOnlyList<PreKeyV1ProvisioningCapability> capabilities,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(capabilities);
        var publication = Xpp1Codec.Decode(request.ExactXpp1Span);
        if (capabilities.Count != publication.OneTimeDpk2Records.Count + 1)
            throw new ArgumentException("The inventory must transfer every XPP1 DPK2 secret exactly once.", nameof(capabilities));

        var payloads = new List<PreKeyV1ProvisioningCapability.Payload>(capabilities.Count);
        var candidateFingerprint = Hash("Deep/Client/PreKeyV1/publication/v1", request.ExactPublicationRequest);
        var entered = false;
        try
        {
            foreach (var capability in capabilities)
                payloads.Add((capability ?? throw new ArgumentException("The inventory contains a null secret capability.", nameof(capabilities))).Consume());
            ValidateTransferredInventory(request, publication, payloads);

            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            var db = GetConnection();
            using var transaction = db.BeginTransaction(deferred: false);
            if (IsForkLatched(db, transaction))
                return new(PreKeyV1InventoryStageDisposition.AlreadyForkLatched, null, true);

            var latest = ReadLatestPublication(db, transaction);
            var existing = ReadPublication(db, transaction, request.InventoryEpoch);
            if (existing is not null)
            {
                if (latest is not null && latest.InventoryEpoch == request.InventoryEpoch &&
                    Fixed(existing.ExactXpp1Span, request.ExactXpp1Span))
                    return new(PreKeyV1InventoryStageDisposition.ExactReplay, existing, false);
                var incumbent = Hash(
                    "Deep/Client/PreKeyV1/publication/v1",
                    (latest ?? existing).ExactPublicationRequest);
                try { LatchFork(db, transaction, 5, incumbent, candidateFingerprint, null, null); }
                finally { CryptographicOperations.ZeroMemory(incumbent); }
                return new(PreKeyV1InventoryStageDisposition.ForkLatched, null, true);
            }

            if (latest is not null &&
                (request.InventoryEpoch <= latest.InventoryEpoch ||
                 request.ServiceGeneration < latest.ServiceGeneration ||
                 request.CurrentDmd1Generation < latest.CurrentDmd1Generation ||
                 (request.CurrentDmd1Generation == latest.CurrentDmd1Generation &&
                  !Fixed(request.CurrentDmd1HashSpan, latest.CurrentDmd1HashSpan)) ||
                 !Fixed(request.PredecessorXpi1HashSpan, latest.Xpi1HashSpan)))
            {
                var incumbent = Hash("Deep/Client/PreKeyV1/publication/v1", latest.ExactPublicationRequest);
                try { LatchFork(db, transaction, 5, incumbent, candidateFingerprint, null, null); }
                finally { CryptographicOperations.ZeroMemory(incumbent); }
                return new(PreKeyV1InventoryStageDisposition.ForkLatched, null, true);
            }
            if (latest is null && request.PredecessorXpi1HashSpan.IndexOfAnyExcept((byte)0) >= 0)
                throw new CryptographicException("The first durable pre-key publication cannot name an unknown predecessor.");

            foreach (var payload in payloads)
            {
                var record = Dpk2Codec.Decode(payload.ExactDpk2);
                var exactHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record);
                var mlHash = SHA256.HashData(payload.SealedSecret);
                var fingerprint = FingerprintProvision(record, exactHash, mlHash);
                try
                {
                    using var collision = ReadProvisionCollision(db, transaction, record);
                    if (HasHistoricalClaim(db, transaction, exactHash, record) || collision is not null)
                        throw new CryptographicException("A generated DPK2 collides with durable pre-key history.");
                    InsertProvision(db, transaction, record, exactHash, payload);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(exactHash);
                    CryptographicOperations.ZeroMemory(mlHash);
                    CryptographicOperations.ZeroMemory(fingerprint);
                }
            }
            PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.AfterInventorySecretsBeforePublication);
            InsertPublication(db, transaction, request);
            PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.BeforeInventoryCommit);
            transaction.Commit();
            PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.AfterInventoryCommit);
            return new(PreKeyV1InventoryStageDisposition.Staged, request, false);
        }
        finally
        {
            foreach (var payload in payloads) payload.Dispose();
            foreach (var capability in capabilities) capability?.Dispose();
            CryptographicOperations.ZeroMemory(candidateFingerprint);
            if (entered) gate.Release();
        }
    }

    private void ValidateTransferredInventory(
        PreKeyV1PublicationRequest request,
        Xpp1Record publication,
        IReadOnlyList<PreKeyV1ProvisioningCapability.Payload> payloads)
    {
        if (!Fixed(publication.NetworkId.Span, scope.NetworkId) ||
            !Fixed(publication.Manifest.NetworkId.Span, scope.NetworkId) ||
            publication.Manifest.InventoryEpoch != request.InventoryEpoch ||
            publication.Manifest.ServiceGeneration != request.ServiceGeneration ||
            !Fixed(publication.Manifest.ResponderDeviceId.Span, scope.DeviceId) ||
            !Fixed(publication.Manifest.ResponderDpd1Reference.Span, scope.Dpd1Reference) ||
            !Fixed(publication.Manifest.CurrentDmd1Hash.Span, request.CurrentDmd1HashSpan))
            throw new CryptographicException("The XPI1/XPP1 publication is outside the exact pre-key owner scope.");
        var expected = publication.OneTimeDpk2Records
            .Select(static value => value.ToArray())
            .Append(publication.LastResortDpk2Record.ToArray())
            .ToArray();
        try
        {
            for (var index = 0; index < expected.Length; index++)
            {
                if (!Fixed(payloads[index].ExactDpk2, expected[index]))
                    throw new CryptographicException("The transferred private capability does not match the ordered XPP1 inventory.");
                var record = Dpk2Codec.Decode(payloads[index].ExactDpk2);
                if (record.InventoryEpoch != request.InventoryEpoch ||
                    record.PrekeyServiceGeneration != request.ServiceGeneration ||
                    record.DeviceDirectoryGeneration != request.CurrentDmd1Generation ||
                    !Fixed(record.DeviceDirectoryHeadHash.Span, request.CurrentDmd1HashSpan))
                    throw new CryptographicException("A transferred DPK2 is outside the exact current DMD1 inventory lineage.");
            }
        }
        finally
        {
            foreach (var exact in expected) CryptographicOperations.ZeroMemory(exact);
        }
    }

    private static void InsertPublication(SqliteConnection db, SqliteTransaction transaction, PreKeyV1PublicationRequest request)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO prekey_publications VALUES($epoch,$service,$operation,$predecessor,$dmdGeneration,$dmdHash,$xpiHash,$xppHash,$xpi,$xpp);";
        var xppHash = Hash("Deep/Client/PreKeyV1/exact-xpp1/v1", request.ExactPublicationRequest);
        try
        {
            Add(command, "$epoch", U64(request.InventoryEpoch));
            Add(command, "$service", U64(request.ServiceGeneration));
            Add(command, "$operation", request.OperationId.ToArray());
            Add(command, "$predecessor", request.PredecessorXpi1Hash.ToArray());
            Add(command, "$dmdGeneration", U64(request.CurrentDmd1Generation));
            Add(command, "$dmdHash", request.CurrentDmd1Hash.ToArray());
            Add(command, "$xpiHash", request.Xpi1Hash.ToArray());
            Add(command, "$xppHash", xppHash);
            Add(command, "$xpi", request.ExactXpi1.ToArray());
            Add(command, "$xpp", request.ExactPublicationRequest.ToArray());
            if (command.ExecuteNonQuery() != 1)
                throw new InvalidOperationException("The durable XPI1/XPP1 publication insert failed.");
        }
        finally { CryptographicOperations.ZeroMemory(xppHash); }
    }

    private static PreKeyV1PublicationRequest? ReadPublication(SqliteConnection db, SqliteTransaction transaction, ulong epoch)
    {
        using var command = db.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT inventory_epoch,service_generation,operation_id,predecessor_xpi1_hash,current_dmd1_generation,current_dmd1_hash,xpi1_hash,exact_xpi1,exact_xpp1 FROM prekey_publications WHERE inventory_epoch=$epoch;";
        Add(command, "$epoch", U64(epoch)); using var reader = command.ExecuteReader();
        return reader.Read() ? Publication(reader) : null;
    }

    private static PreKeyV1PublicationRequest? ReadLatestPublication(SqliteConnection db, SqliteTransaction transaction)
    {
        using var command = db.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT inventory_epoch,service_generation,operation_id,predecessor_xpi1_hash,current_dmd1_generation,current_dmd1_hash,xpi1_hash,exact_xpi1,exact_xpp1 FROM prekey_publications ORDER BY inventory_epoch DESC LIMIT 1;";
        using var reader = command.ExecuteReader(); return reader.Read() ? Publication(reader) : null;
    }

    private static PreKeyV1PublicationRequest Publication(SqliteDataReader reader) => new(
        BinaryPrimitives.ReadUInt64BigEndian((byte[])reader[0]),
        BinaryPrimitives.ReadUInt64BigEndian((byte[])reader[1]),
        (byte[])reader[2], (byte[])reader[3],
        BinaryPrimitives.ReadUInt64BigEndian((byte[])reader[4]),
        (byte[])reader[5], (byte[])reader[6], (byte[])reader[7], (byte[])reader[8]);

    private void ValidatePublicationRows(SqliteConnection db)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT inventory_epoch,service_generation,operation_id,predecessor_xpi1_hash,current_dmd1_generation,current_dmd1_hash,xpi1_hash,xpp1_hash,exact_xpi1,exact_xpp1 FROM prekey_publications ORDER BY inventory_epoch;";
        using var reader = command.ExecuteReader();
        ulong priorEpoch = 0, priorService = 0;
        byte[] priorXpiHash = new byte[32];
        try
        {
            while (reader.Read())
            {
                var request = new PreKeyV1PublicationRequest(
                    BinaryPrimitives.ReadUInt64BigEndian((byte[])reader[0]),
                    BinaryPrimitives.ReadUInt64BigEndian((byte[])reader[1]),
                    (byte[])reader[2], (byte[])reader[3],
                    BinaryPrimitives.ReadUInt64BigEndian((byte[])reader[4]),
                    (byte[])reader[5], (byte[])reader[6], (byte[])reader[8], (byte[])reader[9]);
                var xppHash = Hash("Deep/Client/PreKeyV1/exact-xpp1/v1", request.ExactPublicationRequest);
                try
                {
                    if (!Fixed(xppHash, (byte[])reader[7]) || request.InventoryEpoch <= priorEpoch ||
                        request.ServiceGeneration < priorService ||
                        (priorEpoch == 0
                            ? request.PredecessorXpi1HashSpan.IndexOfAnyExcept((byte)0) >= 0
                            : !Fixed(request.PredecessorXpi1HashSpan, priorXpiHash)))
                        throw new FormatException("Persisted pre-key publication lineage is corrupt.");
                    ValidatePersistedPublicationScope(request);
                }
                finally { CryptographicOperations.ZeroMemory(xppHash); }
                priorEpoch = request.InventoryEpoch;
                priorService = request.ServiceGeneration;
                CryptographicOperations.ZeroMemory(priorXpiHash);
                priorXpiHash = request.Xpi1Hash.ToArray();
            }
        }
        finally { CryptographicOperations.ZeroMemory(priorXpiHash); }
    }

    private void ValidatePersistedPublicationScope(PreKeyV1PublicationRequest request)
    {
        var publication = Xpp1Codec.Decode(request.ExactXpp1Span);
        if (!Fixed(publication.NetworkId.Span, scope.NetworkId) ||
            !Fixed(publication.Manifest.NetworkId.Span, scope.NetworkId) ||
            !Fixed(publication.Manifest.ResponderDeviceId.Span, scope.DeviceId) ||
            !Fixed(publication.Manifest.ResponderDpd1Reference.Span, scope.Dpd1Reference) ||
            publication.Manifest.InventoryEpoch != request.InventoryEpoch ||
            publication.Manifest.ServiceGeneration != request.ServiceGeneration ||
            !Fixed(publication.Manifest.CurrentDmd1Hash.Span, request.CurrentDmd1HashSpan))
            throw new FormatException("Persisted XPI1/XPP1 is outside the exact pre-key store scope.");

        foreach (var exactDpk2 in publication.OneTimeDpk2Records
                     .Append(publication.LastResortDpk2Record))
        {
            var record = Dpk2Codec.Decode(exactDpk2.Span);
            if (!RecordMatchesStoreScope(record) ||
                record.InventoryEpoch != request.InventoryEpoch ||
                record.PrekeyServiceGeneration != request.ServiceGeneration ||
                record.DeviceDirectoryGeneration != request.CurrentDmd1Generation ||
                !Fixed(record.DeviceDirectoryHeadHash.Span, request.CurrentDmd1HashSpan))
                throw new FormatException(
                    "Persisted XPP1 contains a DPK2 outside the exact account/device/DMD1 lineage.");
        }
    }
}
