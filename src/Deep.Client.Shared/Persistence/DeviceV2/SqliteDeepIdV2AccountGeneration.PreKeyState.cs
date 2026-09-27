using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    private const string PreKeyInstallMarkerSlot =
        "deep.store.v2.prekey-installed";
    private const string PreKeyInventoryMarkerSlot =
        "deep.store.v2.prekey-inventory-tip";

    internal static string PreKeyStatePath(string accountStatePath) =>
        Path.GetFullPath(accountStatePath) + ".prekeys.pkv2";

    internal static void DeletePreKeyStateAfterExplicitReset(
        string accountStatePath)
    {
        var path = PreKeyStatePath(accountStatePath);
        foreach (var artifact in new[] { path, path + "-journal",
                     path + "-wal", path + "-shm" })
            File.Delete(artifact);
    }

    /// <summary>
    /// The caller holds the DID2 account lease. SQL commits every secret before
    /// the add-only protected tip is installed. No caller may dispatch XPP1
    /// until this method returns; an interrupted tip is completed from the
    /// verified full SQL transaction on reopen. Once the tip exists, SQL
    /// rollback is rejected. This does not itself authorize XPP1 dispatch.
    /// </summary>
    internal static async ValueTask StageInitialPreKeyInventoryAsync(
        IDeepSecureStorage storage, string accountStatePath,
        VerifiedDeepIdV2CurrentAccount current,
        AuthoredDpk2InventoryV2 inventory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        var opened = await OpenPreKeyStoreAsync(storage, accountStatePath,
            current, allowInitialize: true, cancellationToken)
            .ConfigureAwait(false);
        await using var store = opened.Store;
        try
        {
            var authoredHash = SHA256.HashData(inventory.ExactXpp1.Span);
            var stagedHash = store.ReadStagedPublicationHash();
            if (stagedHash is null)
            {
                await store.StageInitialAsync(inventory,
                    cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                stagedHash = store.ReadStagedPublicationHash();
                if (stagedHash is null ||
                    !CryptographicOperations.FixedTimeEquals(
                        stagedHash, authoredHash))
                    throw new CryptographicException(
                        "The durable DID2 pre-key inventory commit differs.");
                await WritePreKeyTipAsync(storage, opened.ScopeHash,
                    stagedHash, cancellationToken).ConfigureAwait(false);
            }
            else if (!CryptographicOperations.FixedTimeEquals(
                         stagedHash, authoredHash))
                throw new CryptographicException(
                    "A different DID2 pre-key inventory was already staged.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(opened.ScopeHash);
        }
    }

    internal static async ValueTask<bool> HasStagedPreKeyInventoryAsync(
        IDeepSecureStorage storage, string accountStatePath,
        VerifiedDeepIdV2CurrentAccount current,
        CancellationToken cancellationToken)
    {
        var path = PreKeyStatePath(accountStatePath);
        using var installed = await storage.ReadOwnedAsync(
            PreKeyInstallMarkerSlot, cancellationToken).ConfigureAwait(false);
        if (installed is null)
        {
            if (PreKeyFileFamilyExists(path))
                throw new InvalidDataException(
                    "DID2 pre-key state exists without its protected marker.");
            return false;
        }
        var opened = await OpenPreKeyStoreAsync(storage, accountStatePath,
            current, allowInitialize: false, cancellationToken)
            .ConfigureAwait(false);
        await using var store = opened.Store;
        try { return store.HasStagedInventory; }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }

    private static async ValueTask<(SqlitePreKeyV2InventoryStore Store,
        byte[] ScopeHash)> OpenPreKeyStoreAsync(IDeepSecureStorage storage,
        string accountStatePath, VerifiedDeepIdV2CurrentAccount current,
        bool allowInitialize, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(current);
        var accountPath = Path.GetFullPath(accountStatePath);
        var statePath = PreKeyStatePath(accountPath);
        var identity = current.Verified.PublicEvidence.Binding.Identity;
        var network = identity.Account.Certificate.NetworkId.ToArray();
        var account = current.AccountId.ToArray();
        if (identity.ActiveDevices.Count != 1 ||
            identity.ActiveDeviceRelatives.Count != 1)
            throw new CryptographicException(
                "The DID2 pre-key owner requires one verified local device.");
        var certificate = identity.ActiveDevices[0].Certificate;
        var dpd1 = new byte[38];
        "DPD1"u8.CopyTo(dpd1);
        BinaryPrimitives.WriteUInt16BigEndian(dpd1.AsSpan(4), 1);
        certificate.CanonicalHash.Span.CopyTo(dpd1.AsSpan(6));
        using var secret = await storage.ReadOwnedAsync(KeySlot,
            cancellationToken).ConfigureAwait(false) ??
            throw new InvalidDataException("The DID2 SQL key record is absent.");
        var record = secret.Use(static value => value.ToArray());
        byte[]? transcript = null;
        byte[]? key = null;
        byte[]? scopeHash = null;
        try
        {
            ValidateRecord(record, network, account);
            var binding = AccountBinding.From(current.Verified,
                account, network, current.DisplayName,
                current.PermanentId.CanonicalText, record.AsSpan(56, 32));
            ValidateDatabase(accountPath, record.AsSpan(88, 32), binding);
            ReadOnlySpan<byte> domain = "Deep/STORE-V2/prekey-state-key"u8;
            transcript = new byte[domain.Length + 16 + 32 + 8 + 32 + 8 +
                38 + 32];
            var offset = 0;
            domain.CopyTo(transcript.AsSpan(offset));
            offset += domain.Length;
            network.CopyTo(transcript, offset);
            offset += network.Length;
            account.CopyTo(transcript, offset);
            offset += account.Length;
            BinaryPrimitives.WriteUInt64BigEndian(
                transcript.AsSpan(offset),
                identity.Account.Certificate.AccountGeneration);
            offset += 8;
            certificate.DeviceId.Span.CopyTo(transcript.AsSpan(offset));
            offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(
                transcript.AsSpan(offset), certificate.DeviceGeneration);
            offset += 8;
            dpd1.CopyTo(transcript, offset);
            offset += dpd1.Length;
            record.AsSpan(56, 32).CopyTo(transcript.AsSpan(offset));
            key = HMACSHA256.HashData(record.AsSpan(88, 32), transcript);
            scopeHash = SHA256.HashData(transcript);

            var familyExists = PreKeyFileFamilyExists(statePath);
            using var installed = await storage.ReadOwnedAsync(
                PreKeyInstallMarkerSlot, cancellationToken)
                .ConfigureAwait(false);
            if (installed is null)
            {
                if (!allowInitialize || familyExists)
                    throw new InvalidDataException(
                        "DID2 pre-key state has no protected install marker.");
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(PreKeyInstallMarkerSlot,
                        scopeHash)], cancellationToken).ConfigureAwait(false);
            }
            else if (!installed.Use(value => value.Length == 32 &&
                     CryptographicOperations.FixedTimeEquals(value,
                         scopeHash)))
                throw new CryptographicException(
                    "The DID2 pre-key install marker has a different scope.");
            else if (!File.Exists(statePath))
            {
                using var tip = await storage.ReadOwnedAsync(
                    PreKeyInventoryMarkerSlot, cancellationToken)
                    .ConfigureAwait(false);
                if (tip is not null || familyExists)
                    throw new InvalidDataException(
                        "The protected DID2 pre-key database is missing after inventory staging.");
                // There is no publication tip and therefore no releasable
                // inventory. Recreate only the empty database after an
                // interrupted initial installation.
            }

            var store = new SqlitePreKeyV2InventoryStore(statePath, key,
                network, account,
                identity.Account.Certificate.AccountGeneration,
                certificate.DeviceId.Span, certificate.DeviceGeneration,
                dpd1, certificate.DeviceEd25519PublicKey.Span,
                allowCreate: !File.Exists(statePath));
            try
            {
                using var tip = await storage.ReadOwnedAsync(
                    PreKeyInventoryMarkerSlot, cancellationToken)
                    .ConfigureAwait(false);
                var stagedHash = store.ReadStagedPublicationHash();
                if (tip is null)
                {
                    if (stagedHash is not null)
                        await WritePreKeyTipAsync(storage, scopeHash,
                            stagedHash, cancellationToken)
                            .ConfigureAwait(false);
                }
                else if (stagedHash is null ||
                         !tip.Use(value => value.Length == 64 &&
                             CryptographicOperations.FixedTimeEquals(
                                 value[..32], scopeHash) &&
                             CryptographicOperations.FixedTimeEquals(
                                 value[32..], stagedHash)))
                    throw new CryptographicException(
                        "The protected DID2 pre-key inventory tip differs.");
                return (store, scopeHash);
            }
            catch
            {
                await store.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        catch
        {
            if (scopeHash is not null)
                CryptographicOperations.ZeroMemory(scopeHash);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(record);
            if (transcript is not null)
                CryptographicOperations.ZeroMemory(transcript);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
        }
    }

    private static bool PreKeyFileFamilyExists(string path) =>
        File.Exists(path) || File.Exists(path + "-journal") ||
        File.Exists(path + "-wal") || File.Exists(path + "-shm");

    private static async ValueTask WritePreKeyTipAsync(
        IDeepSecureStorage storage, ReadOnlyMemory<byte> scopeHash,
        ReadOnlyMemory<byte> publicationHash,
        CancellationToken cancellationToken)
    {
        if (scopeHash.Length != 32 || publicationHash.Length != 32)
            throw new CryptographicException(
                "The DID2 pre-key tip has an invalid scope or publication.");
        var marker = new byte[64];
        try
        {
            scopeHash.Span.CopyTo(marker);
            publicationHash.Span.CopyTo(marker.AsSpan(32));
            await storage.WriteBatchAsync(
                [new DeepSecureStorageWrite(PreKeyInventoryMarkerSlot,
                    marker)], cancellationToken).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(marker); }
    }
}
