using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;
using Sodium;

namespace Deep.Client.Shared.Persistence.PreKeyV2;

/// <summary>
/// First-generation DID2-only SQLCipher custody for a locally authored V2
/// inventory. It deliberately has no network publish or secret-release API.
/// The account owner must add a protected rollback floor before exposing any
/// staged XPP1 to transport.
/// </summary>
internal sealed class SqlitePreKeyV2InventoryStore : IAsyncDisposable
{
    private const int ApplicationId = 0x504B5632; // PKV2
    private const int SchemaVersion = 1;
    private const string CreateOwner = "CREATE TABLE owner(singleton INTEGER PRIMARY KEY CHECK(singleton=1),network_id BLOB NOT NULL CHECK(length(network_id)=16),account_id BLOB NOT NULL CHECK(length(account_id)=32),account_generation INTEGER NOT NULL CHECK(account_generation>0),device_id BLOB NOT NULL CHECK(length(device_id)=32),device_generation INTEGER NOT NULL CHECK(device_generation>0),dpd1_reference BLOB NOT NULL CHECK(length(dpd1_reference)=38),device_signing_key BLOB NOT NULL CHECK(length(device_signing_key)=32))";
    private const string CreateInventory = "CREATE TABLE inventory(singleton INTEGER PRIMARY KEY CHECK(singleton=1),epoch INTEGER NOT NULL CHECK(epoch BETWEEN 1 AND 14),exact_xpi1 BLOB NOT NULL CHECK(length(exact_xpi1)=560),exact_xpp1 BLOB NOT NULL CHECK(length(exact_xpp1) BETWEEN 67983 AND 8362607))";
    private const string CreateSecrets = "CREATE TABLE secrets(member_index INTEGER PRIMARY KEY CHECK(member_index BETWEEN 0 AND 4096),exact_dpk2_hash BLOB NOT NULL UNIQUE CHECK(length(exact_dpk2_hash)=32),exact_dpk2 BLOB NOT NULL CHECK(length(exact_dpk2) IN(1973,2037)),sealed_secret BLOB NOT NULL CHECK(length(sealed_secret) BETWEEN 386 AND 4481))";
    private readonly string path;
    private readonly byte[] network;
    private readonly byte[] account;
    private readonly byte[] device;
    private readonly byte[] dpd1;
    private readonly byte[] signer;
    private readonly ulong accountGeneration;
    private readonly ulong deviceGeneration;
    private readonly Dpk2PreKeyPersistenceProtector protector;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly SqliteConnection connection;
    private int disposed;

    static SqlitePreKeyV2InventoryStore() => SQLitePCL.Batteries_V2.Init();

    internal SqlitePreKeyV2InventoryStore(string statePath,
        ReadOnlySpan<byte> databaseKey32, ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> accountId32, ulong accountGeneration,
        ReadOnlySpan<byte> deviceId32, ulong deviceGeneration,
        ReadOnlySpan<byte> dpd1Reference38,
        ReadOnlySpan<byte> deviceSigningPublicKey32, bool allowCreate)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        Nonzero(databaseKey32, 32, nameof(databaseKey32));
        Nonzero(networkId16, 16, nameof(networkId16));
        Nonzero(accountId32, 32, nameof(accountId32));
        Nonzero(deviceId32, 32, nameof(deviceId32));
        Nonzero(deviceSigningPublicKey32, 32,
            nameof(deviceSigningPublicKey32));
        if (accountGeneration == 0 || deviceGeneration == 0 ||
            dpd1Reference38.Length != 38 ||
            !dpd1Reference38[..4].SequenceEqual("DPD1"u8))
            throw new ArgumentException("The DID2 pre-key scope is invalid.");
        path = Path.GetFullPath(statePath);
        network = networkId16.ToArray();
        account = accountId32.ToArray();
        device = deviceId32.ToArray();
        dpd1 = dpd1Reference38.ToArray();
        signer = deviceSigningPublicKey32.ToArray();
        this.accountGeneration = accountGeneration;
        this.deviceGeneration = deviceGeneration;
        var exists = File.Exists(path);
        if (!exists && !allowCreate)
            throw new InvalidDataException("The DID2 pre-key store is missing.");
        if (exists && new FileInfo(path).Length == 0)
            throw new InvalidDataException("The DID2 pre-key store is empty.");
        var sealKey = HMACSHA256.HashData(databaseKey32,
            "Deep/PreKeyV2/secret-seal"u8);
        try { protector = new Dpk2PreKeyPersistenceProtector(sealKey); }
        finally { CryptographicOperations.ZeroMemory(sealKey); }
        var parent = Path.GetDirectoryName(path);
        try
        {
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
            connection = Open(path, databaseKey32, create: !exists);
            if (exists) Validate();
            else Create();
        }
        catch
        {
            connection?.Dispose();
            protector.Dispose();
            throw;
        }
    }

    internal bool HasStagedInventory
    {
        get
        {
            ThrowIfDisposed();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM inventory;";
            return Convert.ToInt32(command.ExecuteScalar()) == 1;
        }
    }

    internal byte[]? ReadStagedPublicationHash()
    {
        ThrowIfDisposed();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT exact_xpp1 FROM inventory WHERE singleton=1;";
        var exact = command.ExecuteScalar() as byte[];
        return exact is null ? null : SHA256.HashData(exact);
    }

    internal byte[]? ReadStagedPublication()
    {
        ThrowIfDisposed();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT exact_xpp1 FROM inventory WHERE singleton=1;";
        var exact = command.ExecuteScalar() as byte[];
        return exact?.ToArray();
    }

    internal async Task StageInitialAsync(AuthoredDpk2InventoryV2 inventory,
        Func<CancellationToken, ValueTask>? beforeCommit = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        cancellationToken.ThrowIfCancellationRequested();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (HasStagedInventory)
                throw new CryptographicException(
                    "A DID2 pre-key inventory is already staged.");
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(
                inventory.ExactXpp1.Span);
            ValidateInventory(inventory, publication);
            var sealedSecrets = new List<byte[]>(
                inventory.OneTimeOfferings.Count + 1);
            try
            {
                foreach (var offering in inventory.OneTimeOfferings)
                    sealedSecrets.Add(Seal(offering));
                sealedSecrets.Add(Seal(inventory.LastResortOffering));
                using var transaction = connection.BeginTransaction(deferred: false);
                using (var insert = connection.CreateCommand())
                {
                    insert.Transaction = transaction;
                    insert.CommandText = "INSERT INTO inventory VALUES(1,$epoch,$xpi,$xpp);";
                    insert.Parameters.AddWithValue("$epoch", checked((long)
                        BinaryPrimitives.ReadUInt64BigEndian(
                            publication.Manifest.Field(7).Span)));
                    Add(insert, "$xpi", inventory.ExactXpi1.ToArray());
                    Add(insert, "$xpp", inventory.ExactXpp1.ToArray());
                    insert.ExecuteNonQuery();
                }
                for (var index = 0; index < sealedSecrets.Count; index++)
                {
                    var offering = index < inventory.OneTimeOfferings.Count
                        ? inventory.OneTimeOfferings[index]
                        : inventory.LastResortOffering;
                    using var insert = connection.CreateCommand();
                    insert.Transaction = transaction;
                    insert.CommandText = "INSERT INTO secrets VALUES($index,$hash,$exact,$sealed);";
                    insert.Parameters.AddWithValue("$index", index);
                    Add(insert, "$hash", offering.ExactDpk2Hash.ToArray());
                    Add(insert, "$exact", offering.ExactDpk2.ToArray());
                    Add(insert, "$sealed", sealedSecrets[index]);
                    insert.ExecuteNonQuery();
                }
                if (beforeCommit is not null)
                    await beforeCommit(cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                transaction.Commit();
            }
            finally
            {
                foreach (var sealedSecret in sealedSecrets)
                    CryptographicOperations.ZeroMemory(sealedSecret);
            }
        }
        finally { gate.Release(); }
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
        {
            connection.Dispose();
            protector.Dispose();
            gate.Dispose();
        }
        return ValueTask.CompletedTask;
    }

    private byte[] Seal(AuthoredDpk2Offering offering)
    {
        return offering.SealSecretForPersistence(protector,
            new Dpk2PreKeyPersistenceScope(network, account,
                accountGeneration, device, deviceGeneration, dpd1))
            .CanonicalBytes.ToArray();
    }

    private void ValidateInventory(AuthoredDpk2InventoryV2 inventory,
        ParsedXpp1V2 publication)
    {
        if (!publication.NetworkId.Span.SequenceEqual(network) ||
            !publication.Manifest.CanonicalBytes.Span.SequenceEqual(
                inventory.ExactXpi1.Span) ||
            !publication.Manifest.Field(3).Span.SequenceEqual(device) ||
            !publication.Manifest.Field(4).Span.SequenceEqual(dpd1) ||
            !PublicKeyAuth.VerifyDetached(
                publication.Manifest.Field(16).ToArray(),
                publication.Manifest.SignatureInput.ToArray(), signer) ||
            publication.OneTimeMembers.Count != inventory.OneTimeOfferings.Count)
            throw new CryptographicException(
                "The DID2 inventory is outside its exact local owner scope.");
        for (var index = 0; index <= publication.OneTimeMembers.Count; index++)
        {
            var member = index < publication.OneTimeMembers.Count
                ? publication.OneTimeMembers[index]
                : publication.LastResortMember;
            var offering = index < inventory.OneTimeOfferings.Count
                ? inventory.OneTimeOfferings[index]
                : inventory.LastResortOffering;
            if (!member.CanonicalBytes.Span.SequenceEqual(offering.ExactDpk2.Span) ||
                !member.ExactHash.Span.SequenceEqual(offering.ExactDpk2Hash.Span) ||
                !member.ResponderAccountId.Span.SequenceEqual(account) ||
                !member.ResponderDeviceId.Span.SequenceEqual(device) ||
                member.ResponderDeviceGeneration != deviceGeneration ||
                !member.ResponderDpd1Reference.Span.SequenceEqual(dpd1))
                throw new CryptographicException(
                    "The DID2 inventory contains a foreign pre-key capability.");
        }
    }

    private void Create()
    {
        using var transaction = connection.BeginTransaction(deferred: false);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaVersion}; {CreateOwner}; {CreateInventory}; {CreateSecrets};";
        command.ExecuteNonQuery();
        command.CommandText = "INSERT INTO owner VALUES(1,$network,$account,$accountGeneration,$device,$deviceGeneration,$dpd1,$signer);";
        Add(command, "$network", network);
        Add(command, "$account", account);
        command.Parameters.AddWithValue("$accountGeneration", (long)accountGeneration);
        Add(command, "$device", device);
        command.Parameters.AddWithValue("$deviceGeneration", (long)deviceGeneration);
        Add(command, "$dpd1", dpd1);
        Add(command, "$signer", signer);
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private void Validate()
    {
        using (var check = connection.CreateCommand())
        {
            check.CommandText = "PRAGMA cipher_integrity_check;";
            using var reader = check.ExecuteReader();
            if (reader.Read())
                throw new InvalidDataException("DID2 pre-key SQLCipher integrity failed.");
        }
        if (Pragma("application_id") != ApplicationId ||
            Pragma("user_version") != SchemaVersion)
            throw new InvalidDataException("The DID2 pre-key schema version is invalid.");
        using (var schema = connection.CreateCommand())
        {
            schema.CommandText = "SELECT name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name;";
            using var reader = schema.ExecuteReader();
            var expected = new[] { ("inventory", CreateInventory),
                ("owner", CreateOwner), ("secrets", CreateSecrets) };
            foreach (var item in expected)
                if (!reader.Read() || reader.GetString(0) != item.Item1 ||
                    reader.GetString(1) != item.Item2)
                    throw new InvalidDataException("The DID2 pre-key SQL schema differs.");
            if (reader.Read())
                throw new InvalidDataException("The DID2 pre-key SQL schema has extras.");
        }
        using (var owner = connection.CreateCommand())
        {
            owner.CommandText = "SELECT network_id,account_id,account_generation,device_id,device_generation,dpd1_reference,device_signing_key FROM owner;";
            using var reader = owner.ExecuteReader();
            if (!reader.Read() ||
                !reader.GetFieldValue<byte[]>(0).AsSpan().SequenceEqual(network) ||
                !reader.GetFieldValue<byte[]>(1).AsSpan().SequenceEqual(account) ||
                reader.GetInt64(2) != (long)accountGeneration ||
                !reader.GetFieldValue<byte[]>(3).AsSpan().SequenceEqual(device) ||
                reader.GetInt64(4) != (long)deviceGeneration ||
                !reader.GetFieldValue<byte[]>(5).AsSpan().SequenceEqual(dpd1) ||
                !reader.GetFieldValue<byte[]>(6).AsSpan().SequenceEqual(signer) ||
                reader.Read())
                throw new CryptographicException(
                    "The DID2 pre-key SQL owner scope changed.");
        }
        ValidateStagedRows();
    }

    private void ValidateStagedRows()
    {
        long epoch = 0;
        byte[]? exactXpi1 = null;
        byte[]? exactXpp1 = null;
        using (var inventory = connection.CreateCommand())
        {
            inventory.CommandText = "SELECT epoch,exact_xpi1,exact_xpp1 FROM inventory;";
            using var row = inventory.ExecuteReader();
            if (row.Read())
            {
                epoch = row.GetInt64(0);
                exactXpi1 = row.GetFieldValue<byte[]>(1);
                exactXpp1 = row.GetFieldValue<byte[]>(2);
                if (row.Read())
                    throw new InvalidDataException(
                        "Multiple DID2 pre-key inventories exist.");
            }
        }
        if (exactXpp1 is null)
        {
            using var count = connection.CreateCommand();
            count.CommandText = "SELECT COUNT(*) FROM secrets;";
            if (Convert.ToInt32(count.ExecuteScalar()) != 0)
                throw new InvalidDataException("DID2 pre-key secrets have no inventory.");
            return;
        }
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(exactXpp1);
        if (!publication.Manifest.CanonicalBytes.Span.SequenceEqual(exactXpi1) ||
            !publication.NetworkId.Span.SequenceEqual(network) ||
            !publication.Manifest.Field(3).Span.SequenceEqual(device) ||
            !publication.Manifest.Field(4).Span.SequenceEqual(dpd1) ||
            !PublicKeyAuth.VerifyDetached(publication.Manifest.Field(16).ToArray(),
                publication.Manifest.SignatureInput.ToArray(), signer) ||
            epoch != checked((long)BinaryPrimitives.ReadUInt64BigEndian(
                publication.Manifest.Field(7).Span)))
            throw new CryptographicException("The durable DID2 inventory is invalid.");
        using var secrets = connection.CreateCommand();
        secrets.CommandText = "SELECT member_index,exact_dpk2_hash,exact_dpk2,sealed_secret FROM secrets ORDER BY member_index;";
        using var reader = secrets.ExecuteReader();
        for (var index = 0; index <= publication.OneTimeMembers.Count; index++)
        {
            var member = index < publication.OneTimeMembers.Count
                ? publication.OneTimeMembers[index]
                : publication.LastResortMember;
            if (!reader.Read() || reader.GetInt32(0) != index ||
                !reader.GetFieldValue<byte[]>(1).AsSpan()
                    .SequenceEqual(member.ExactHash.Span) ||
                !reader.GetFieldValue<byte[]>(2).AsSpan()
                    .SequenceEqual(member.CanonicalBytes.Span) ||
                !member.ResponderAccountId.Span.SequenceEqual(account) ||
                !member.ResponderDeviceId.Span.SequenceEqual(device) ||
                member.ResponderDeviceGeneration != deviceGeneration ||
                !member.ResponderDpd1Reference.Span.SequenceEqual(dpd1))
                throw new CryptographicException(
                    "The durable DID2 pre-key member is invalid.");
            var blob = Dpk2PreKeyPersistenceBlob.Decode(
                reader.GetFieldValue<byte[]>(3));
            using var restored = protector.Restore(blob,
                member.CanonicalBytes, new Dpk2PreKeyPersistenceScope(
                    network, account, accountGeneration, device,
                    deviceGeneration, dpd1));
        }
        if (reader.Read())
            throw new InvalidDataException("The DID2 pre-key inventory has extra secrets.");
    }

    private int Pragma(string name)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA {name};";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private static SqliteConnection Open(string path, ReadOnlySpan<byte> key,
        bool create)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = create ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString());
        try
        {
            connection.Open();
            var ownedKey = key.ToArray();
            try
            {
                if (SQLitePCL.raw.sqlite3_key(connection.Handle, ownedKey) !=
                    SQLitePCL.raw.SQLITE_OK)
                    throw new CryptographicException("SQLCipher rejected the DID2 pre-key key.");
            }
            finally { CryptographicOperations.ZeroMemory(ownedKey); }
            using var version = connection.CreateCommand();
            version.CommandText = "PRAGMA cipher_version;";
            if (!Convert.ToString(version.ExecuteScalar())?.StartsWith("4.",
                    StringComparison.Ordinal) ?? true)
                throw new InvalidDataException("SQLCipher 4 is required.");
            using var configure = connection.CreateCommand();
            configure.CommandText = create
                ? "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA journal_mode=DELETE;"
                : "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";
            configure.ExecuteNonQuery();
            return connection;
        }
        catch { connection.Dispose(); throw; }
    }

    private static void Add(SqliteCommand command, string name, byte[] value) =>
        command.Parameters.Add(name, SqliteType.Blob).Value = value;

    private static void Nonzero(ReadOnlySpan<byte> value, int length,
        string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The DID2 pre-key scope is invalid.", name);
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
}
