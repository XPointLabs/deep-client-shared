using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal const string DeviceStateMarkerSlot =
        "deep.store.v2.device-state-installed";

    internal static string DeviceStatePath(string accountStatePath) =>
        Path.GetFullPath(accountStatePath) + ".devices.dvs1";

    internal static void DeleteDeviceStateAfterExplicitReset(
        string accountStatePath)
    {
        var path = DeviceStatePath(accountStatePath);
        foreach (var artifact in new[] { path, path + "-journal",
                     path + "-wal", path + "-shm" })
            File.Delete(artifact);
    }

    /// <summary>
    /// Opens an incompatible V2-scoped DeviceV1 protocol-state database. Its
    /// SQLCipher key is domain-separated from the protected DSV2 key. The
    /// protected marker is written before initial creation, so losing this
    /// database can never silently reset agreement-operation burns.
    /// Caller holds the process-independent DID2 account lease.
    /// </summary>
    internal static async ValueTask<SqliteDeviceStateStore>
        OpenCurrentDeviceStateStoreAsync(IDeepSecureStorage storage,
            string accountStatePath, VerifiedDeepIdV2CurrentAccount current,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(current);
        var accountPath = Path.GetFullPath(accountStatePath);
        var devicePath = DeviceStatePath(accountPath);
        var network = current.Verified.PublicEvidence.Binding.Identity.Account
            .Certificate.NetworkId;
        using var secret = await storage.ReadOwnedAsync(KeySlot,
            cancellationToken).ConfigureAwait(false) ??
            throw new InvalidDataException("The DID2 SQL key record is absent.");
        var record = secret.Use(static value => value.ToArray());
        byte[]? transcript = null;
        byte[]? deviceKey = null;
        byte[]? storeId = null;
        byte[]? marker = null;
        try
        {
            ValidateRecord(record, network.Span, current.AccountId.Span);
            var binding = AccountBinding.From(current.Verified,
                current.AccountId.Span, network.Span, current.DisplayName,
                current.PermanentId.CanonicalText, record.AsSpan(56, 32));
            ValidateDatabase(accountPath, record.AsSpan(88, 32), binding);

            ReadOnlySpan<byte> domain = "Deep/STORE-V2/device-state-key"u8;
            transcript = new byte[domain.Length + 16 + 32 + 32];
            domain.CopyTo(transcript);
            network.Span.CopyTo(transcript.AsSpan(domain.Length));
            current.AccountId.Span.CopyTo(
                transcript.AsSpan(domain.Length + 16));
            record.AsSpan(56, 32).CopyTo(
                transcript.AsSpan(domain.Length + 48));
            deviceKey = HMACSHA256.HashData(record.AsSpan(88, 32),
                transcript);
            storeId = SHA256.HashData(transcript);
            marker = SHA256.HashData(storeId.Concat(network.ToArray())
                .Concat(current.AccountId.ToArray()).ToArray());

            var familyExists = File.Exists(devicePath) ||
                File.Exists(devicePath + "-journal") ||
                File.Exists(devicePath + "-wal") ||
                File.Exists(devicePath + "-shm");
            using var installed = await storage.ReadOwnedAsync(
                DeviceStateMarkerSlot, cancellationToken)
                .ConfigureAwait(false);
            if (installed is null)
            {
                if (familyExists)
                    throw new InvalidDataException(
                        "DID2 device state exists without its protected marker.");
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(DeviceStateMarkerSlot, marker),
                     new DeepSecureStorageWrite(DeviceInitialSessionCheckpoint.Slot,
                         DeviceInitialSessionCheckpoint.Stable(storeId,
                             current.AccountId.Span, network.Span, 0, new byte[32]))],
                    cancellationToken).ConfigureAwait(false);
            }
            else if (!installed.Use(value => value.Length == marker.Length &&
                     CryptographicOperations.FixedTimeEquals(value, marker)))
                throw new CryptographicException(
                    "The DID2 device-state marker has a different scope.");
            else if (!File.Exists(devicePath))
                throw new InvalidDataException(
                    "The protected DID2 device-state database is missing.");

            var store = new SqliteDeviceStateStore(
                new SqliteDeviceStateStoreOptions(devicePath, deviceKey,
                    DeviceAccountId32.FromBytes(current.AccountId.Span),
                    current.Verified.PublicEvidence.Binding.Identity.Account
                        .Certificate.AccountGeneration,
                    databaseGeneration: 1,
                    DeviceOperationId32.FromBytes(storeId),
                    allowCreate: installed is null));
            try
            {
                await store.OpenInitialSessionCustodyAsync(storage, network,
                    cancellationToken).ConfigureAwait(false);
            return store;
            }
            catch { store.Dispose(); throw; }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(record);
            if (transcript is not null) CryptographicOperations.ZeroMemory(transcript);
            if (deviceKey is not null) CryptographicOperations.ZeroMemory(deviceKey);
            if (storeId is not null) CryptographicOperations.ZeroMemory(storeId);
            if (marker is not null) CryptographicOperations.ZeroMemory(marker);
        }
    }

    // Stored-plan readback only. No current account authority, source repair,
    // registration, creation, PRAGMA mutation or key retirement is performed.
    internal static async Task<byte[]> ReadExistingDeviceSourceProjectionUnderLeaseAsync(IDeepSecureStorage storage,
        string accountPath, ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        var path = DeviceStatePath(accountPath);
        RequireOrdinaryDirectory(Path.GetDirectoryName(path) ?? throw new InvalidDataException("An owned source directory is required."));
        RequireApplicationFileFamily(path);
        if (new[] { "-journal", "-wal", "-shm" }.Any(suffix => File.Exists(path + suffix)))
            throw new IOException("Unfinished device-source IO pins local cleanup.");
        using var installed = await storage.ReadOwnedAsync(DeviceStateMarkerSlot, ct).ConfigureAwait(false);
        using var checkpoint = await storage.ReadOwnedAsync(DeviceInitialSessionCheckpoint.Slot, ct).ConfigureAwait(false);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/mailbox-device-source-state"u8); hash.AppendData([0]);
        hash.AppendData(network.Span); hash.AppendData(account.Span); hash.AppendData(instance.Span);
        if (installed is null)
        {
            if (checkpoint is not null || File.Exists(path)) throw new InvalidDataException("Device source lost its protected marker.");
            hash.AppendData([0]); return hash.GetHashAndReset();
        }
        if (checkpoint is null || !File.Exists(path)) throw new InvalidDataException("Installed device source lost its existing custody.");
        using var secret = await ReadCompactionRegistrationUnderLeaseAsync(storage, network, account, ct).ConfigureAwait(false);
        var record = secret.Use(bytes => bytes.ToArray()); byte[] key = [], storeId = [], transcript = [];
        try
        {
            if (!Fixed(record.AsSpan(56, 32), instance.Span)) throw new CryptographicException("Device source changed its account instance.");
            var domain = "Deep/STORE-V2/device-state-key"u8;
            transcript = new byte[domain.Length + 80]; domain.CopyTo(transcript);
            record.AsSpan(8, 48).CopyTo(transcript.AsSpan(domain.Length)); record.AsSpan(56, 32).CopyTo(transcript.AsSpan(domain.Length + 48));
            key = HMACSHA256.HashData(record.AsSpan(88, 32), transcript); storeId = SHA256.HashData(transcript);
            var markerBytes = new byte[80]; storeId.CopyTo(markerBytes, 0); network.Span.CopyTo(markerBytes.AsSpan(32)); account.Span.CopyTo(markerBytes.AsSpan(48));
            if (!installed.Use(bytes => Fixed(bytes, SHA256.HashData(markerBytes)))) throw new CryptographicException("Device source marker is foreign.");
            using var state = checkpoint.Use(bytes => DeviceInitialSessionCheckpoint.Decode(bytes, storeId, account.Span, network.Span));
            if (state.Phase != 1) throw new IOException("Unfinished initial-session work pins local cleanup.");
            installed.Use(bytes => { hash.AppendData(bytes); return true; }); checkpoint.Use(bytes => { hash.AppendData(bytes); return true; });
            using var db = new Microsoft.Data.Sqlite.SqliteConnection(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
            { DataSource = path, Mode = Microsoft.Data.Sqlite.SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
            db.Open(); var code = SQLitePCL.raw.sqlite3_key(db.Handle, key);
            if (code != SQLitePCL.raw.SQLITE_OK) throw new CryptographicException("Device source key was rejected.");
            SqliteDeviceStateStore.RequireReadOnlyMailboxSource(db, storeId, account.Span);
            var projection = SqliteDeepMailboxStore.ReadCompleteLocalSqlProjection(db, storeId, ct);
            try { hash.AppendData(projection); }
            finally { CryptographicOperations.ZeroMemory(projection); }
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return hash.GetHashAndReset();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(record); CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(storeId); CryptographicOperations.ZeroMemory(transcript);
        }
    }
}
