using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    private const string DeviceStateMarkerSlot =
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
                    [new DeepSecureStorageWrite(DeviceStateMarkerSlot, marker)],
                    cancellationToken).ConfigureAwait(false);
            }
            else if (!installed.Use(value => value.Length == marker.Length &&
                     CryptographicOperations.FixedTimeEquals(value, marker)))
                throw new CryptographicException(
                    "The DID2 device-state marker has a different scope.");
            else if (!File.Exists(devicePath))
                throw new InvalidDataException(
                    "The protected DID2 device-state database is missing.");

            return new SqliteDeviceStateStore(
                new SqliteDeviceStateStoreOptions(devicePath, deviceKey,
                    DeviceAccountId32.FromBytes(current.AccountId.Span),
                    current.Verified.PublicEvidence.Binding.Identity.Account
                        .Certificate.AccountGeneration,
                    databaseGeneration: 1,
                    DeviceOperationId32.FromBytes(storeId),
                    allowCreate: installed is null));
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
}
