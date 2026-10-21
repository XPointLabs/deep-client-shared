using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    private const string PreKeyInstallMarkerSlot =
        "deep.store.v2.prekey-installed";
    private const string PreKeyInventoryMarkerSlot =
        ProtectedPreKeyInventoryChain.TipSlot;
    private const string PreKeyCommitMarkerSlot =
        "deep.store.v2.prekey-commit-pair-v1";
    private const int PreKeyCommitMarkerLength = 64 +
        2 * DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength;

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
        AuthoredDeepIdV2PreKeyService service,
        AuthoredDpk2InventoryV2 inventory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(service);
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
                await store.StageInitialAsync(service, inventory,
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
                         stagedHash, authoredHash) ||
                     !store.ReadStagedService()!.AsSpan().SequenceEqual(
                         service.ExactXps1.Span))
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

    internal static async ValueTask<(byte[] ExactXpp1, byte[] ExactXps1)?> ReadStagedPreKeyPublicationAsync(
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
            return null;
        }
        var opened = await OpenPreKeyStoreAsync(storage, accountStatePath,
            current, allowInitialize: false, cancellationToken)
            .ConfigureAwait(false);
        await using var store = opened.Store;
        try
        {
            var exact = store.ReadStagedPublication();
            if (exact is null) return null;
            using var tip = await storage.ReadOwnedAsync(
                PreKeyInventoryMarkerSlot, cancellationToken)
                .ConfigureAwait(false) ?? throw new InvalidDataException(
                    "The DID2 pre-key publication has no protected tip.");
            var hash = SHA256.HashData(exact);
            if (!tip.Use(value => value.Length == 64 &&
                CryptographicOperations.FixedTimeEquals(value[..32],
                    opened.ScopeHash) &&
                CryptographicOperations.FixedTimeEquals(value[32..], hash)))
                throw new CryptographicException(
                    "The DID2 pre-key publication differs from its protected tip.");
            return (exact, store.ReadStagedService() ?? throw new
                InvalidDataException("The protected DID2 pre-key service is missing."));
        }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }

    /// <summary>Records only a pair already authenticated against the live
    /// placement by the publication transport. The protected add-only slot
    /// binds the pair to this exact account scope and durable XPP1.</summary>
    internal static async ValueTask RecordPreKeyCommitPairAsync(
        IDeepSecureStorage storage, string accountStatePath,
        VerifiedDeepIdV2CurrentAccount current,
        ReadOnlyMemory<byte> exactXpp1,
        ParsedXic1V2 first, ParsedXic1V2 second,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);
        var opened = await OpenPreKeyStoreAsync(storage, accountStatePath,
            current, allowInitialize: false, cancellationToken)
            .ConfigureAwait(false);
        await using var store = opened.Store;
        try
        {
            var publicationHash = SHA256.HashData(exactXpp1.Span);
            var stagedHash = store.ReadStagedPublicationHash();
            if (stagedHash is null ||
                !CryptographicOperations.FixedTimeEquals(
                    stagedHash, publicationHash))
                throw new CryptographicException(
                    "The DID2 receipt pair is outside the exact protected inventory.");
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(
                exactXpp1.Span);
            ValidatePreKeyCommitPair(publication, first, second);
            var pairSlot = PreKeyPairSlot(store, publicationHash);
            var marker = new byte[PreKeyCommitMarkerLength];
            try
            {
                opened.ScopeHash.CopyTo(marker, 0);
                publicationHash.CopyTo(marker, 32);
                first.CanonicalBytes.Span.CopyTo(marker.AsSpan(64));
                second.CanonicalBytes.Span.CopyTo(marker.AsSpan(64 +
                    DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength));
                using var existing = await storage.ReadOwnedAsync(
                    pairSlot, cancellationToken)
                    .ConfigureAwait(false);
                if (existing is null)
                    await storage.WriteBatchAsync(
                        [new DeepSecureStorageWrite(pairSlot,
                            marker)], cancellationToken).ConfigureAwait(false);
                else if (!existing.Use(value => value.Length == marker.Length &&
                         CryptographicOperations.FixedTimeEquals(value,
                             marker)))
                    throw new CryptographicException(
                        "A different DID2 pre-key commit pair is already protected.");
            }
            finally { CryptographicOperations.ZeroMemory(marker); }
        }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }

    internal static async ValueTask<(byte[] First, byte[] Second)?>
        ReadPreKeyCommitPairAsync(IDeepSecureStorage storage,
            string accountStatePath, VerifiedDeepIdV2CurrentAccount current,
            CancellationToken cancellationToken)
    {
        if (await ReadStagedPreKeyPublicationAsync(storage, accountStatePath,
                current, cancellationToken).ConfigureAwait(false) is null)
            return null;
        var opened = await OpenPreKeyStoreAsync(storage, accountStatePath,
            current, allowInitialize: false, cancellationToken)
            .ConfigureAwait(false);
        await using var store = opened.Store;
        try
        {
            var exactXpp1 = store.ReadStagedPublication() ?? throw new
                InvalidDataException("The committed DID2 inventory is missing.");
            using var protectedPair = await storage.ReadOwnedAsync(
                PreKeyPairSlot(store, SHA256.HashData(exactXpp1)), cancellationToken).ConfigureAwait(false);
            if (protectedPair is null) return null;
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(exactXpp1);
            return protectedPair.Use(value => DecodePreKeyCommitPairMarker(value, opened.ScopeHash, publication));
        }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }

    private static void ValidatePreKeyCommitPair(ParsedXpp1V2 publication,
        ParsedXic1V2 first, ParsedXic1V2 second)
    {
        foreach (var receipt in new[] { first, second })
            if (!receipt.Field(1).Span.SequenceEqual(publication.NetworkId.Span) ||
                !receipt.Field(2).Span.SequenceEqual(
                    publication.PublicationOperationId.Span) ||
                !receipt.Field(3).Span.SequenceEqual(
                    publication.Manifest.ExactHash.Span) ||
                !receipt.Field(4).Span.SequenceEqual(
                    publication.PlacementHash.Span) ||
                BinaryPrimitives.ReadUInt64BigEndian(receipt.Field(6).Span) <
                    BinaryPrimitives.ReadUInt64BigEndian(
                        publication.Manifest.Field(14).Span) ||
                BinaryPrimitives.ReadUInt64BigEndian(receipt.Field(6).Span) >=
                    BinaryPrimitives.ReadUInt64BigEndian(
                        publication.Manifest.Field(15).Span))
                throw new CryptographicException(
                    "The DID2 receipt differs from the protected publication.");
        if (first.Field(5).Span.SequenceEqual(second.Field(5).Span))
            throw new CryptographicException(
                "The DID2 commit pair repeats one replica.");
    }

    private static string PreKeyPairSlot(SqlitePreKeyV2InventoryStore store, ReadOnlySpan<byte> publicationHash)
    {
        var initialHash = store.ReadInitialPublicationHash() ?? throw new InvalidDataException("Initial prekey anchor is absent.");
        return CryptographicOperations.FixedTimeEquals(initialHash, publicationHash) ? PreKeyCommitMarkerSlot :
            ProtectedPreKeyInventoryChain.CommitSlot(publicationHash);
    }

    private static (byte[] First, byte[] Second) DecodePreKeyCommitPairMarker(ReadOnlySpan<byte> value,
        ReadOnlySpan<byte> scopeHash, ParsedXpp1V2 publication)
    {
        if (value.Length != PreKeyCommitMarkerLength || !CryptographicOperations.FixedTimeEquals(value[..32], scopeHash) ||
            !CryptographicOperations.FixedTimeEquals(value.Slice(32, 32), SHA256.HashData(publication.CanonicalBytes.Span)))
            throw new CryptographicException("The DID2 commit pair differs from its protected inventory.");
        var first = DeepIdV2PreKeyCommitReceiptCodec.Decode(value.Slice(64, DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength));
        var second = DeepIdV2PreKeyCommitReceiptCodec.Decode(value.Slice(64 + DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength));
        ValidatePreKeyCommitPair(publication, first, second);
        return (first.CanonicalBytes.ToArray(), second.CanonicalBytes.ToArray());
    }

    internal static async Task StageSuccessorPreKeyInventoryAsync(IDeepSecureStorage storage, string accountStatePath,
        VerifiedDeepIdV2CurrentAccount current, AuthoredDeepIdV2PreKeyService service,
        AuthoredDpk2InventoryV2 inventory, CancellationToken ct)
    {
        if (await ReadPreKeyCommitPairAsync(storage, accountStatePath, current, ct).ConfigureAwait(false) is null)
            throw new CryptographicException("An unresolved prekey publication cannot be replaced by another inventory.");
        var opened = await OpenPreKeyStoreAsync(storage, accountStatePath, current, allowInitialize: false, ct).ConfigureAwait(false);
        await using var store = opened.Store;
        try { await store.StageSuccessorAsync(storage, opened.ScopeHash, service, inventory, ct).ConfigureAwait(false); }
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

            using var heads = await storage.ReadOwnedBatchAsync(
                [PreKeyInventoryMarkerSlot, PreKeyCommitMarkerSlot], cancellationToken).ConfigureAwait(false);
            var capturedTip = heads[0];
            var initialCommittedHash = heads[1]?.Use(value =>
            {
                if (value.Length != PreKeyCommitMarkerLength || !CryptographicOperations.FixedTimeEquals(value[..32], scopeHash))
                    throw new CryptographicException("The initial prekey commit anchor has a different owner scope.");
                return value.Slice(32, 32).ToArray();
            });
            if (capturedTip is null && initialCommittedHash is not null)
                throw new CryptographicException("A committed prekey inventory lost its protected pointer.");
            ProtectedPreKeyInventoryChain.Snapshot? successors = null;
            if (capturedTip is not null && initialCommittedHash is not null &&
                !capturedTip.Use(value => value.Length == 64 && CryptographicOperations.FixedTimeEquals(value[..32], scopeHash) &&
                    CryptographicOperations.FixedTimeEquals(value[32..], initialCommittedHash)))
                successors = await ProtectedPreKeyInventoryChain.ReadAsync(storage, scopeHash,
                    initialCommittedHash, cancellationToken).ConfigureAwait(false);
            SqlitePreKeyV2InventoryStore store;
            try
            {
                store = new SqlitePreKeyV2InventoryStore(statePath, key, network, account,
                    identity.Account.Certificate.AccountGeneration, certificate.DeviceId.Span, certificate.DeviceGeneration,
                    dpd1, certificate.DeviceEd25519PublicKey.Span, allowCreate: !File.Exists(statePath), successorCustody: successors,
                    connectionKey: current.PreKeyConnectionKey);
            }
            catch { successors?.Dispose(); throw; }
            try
            {
                var stagedHash = store.ReadInitialPublicationHash();
                if (initialCommittedHash is not null && (stagedHash is null ||
                    !CryptographicOperations.FixedTimeEquals(initialCommittedHash, stagedHash)))
                    throw new CryptographicException("The initial SQL inventory differs from its protected commit anchor.");
                if (heads[1] is { } initialPair)
                    initialPair.Use(value => DecodePreKeyCommitPairMarker(value, scopeHash,
                        DeepIdV2PreKeyPublicationCodec.Decode(store.ReadInitialPublication()!)));
                if (successors is not null)
                {
                    var entries = successors.Entries;
                    for (var entryOffset = 0; entryOffset < entries.Count; entryOffset += 32)
                    {
                        var count = Math.Min(32, entries.Count - entryOffset);
                        using var pairs = await storage.ReadOwnedBatchAsync(entries.Skip(entryOffset).Take(count)
                            .Select(entry => ProtectedPreKeyInventoryChain.CommitSlot(entry.PublicationHash)).ToArray(), cancellationToken).ConfigureAwait(false);
                        for (var index = 0; index < count; index++)
                        {
                            var position = entryOffset + index;
                            if (pairs[index] is not { } pair)
                            {
                                if (position != entries.Count - 1)
                                    throw new InvalidDataException("A prekey predecessor lost its protected replica pair.");
                                continue; // Only the current inventory can still be pending.
                            }
                            pair.Use(value => DecodePreKeyCommitPairMarker(value, scopeHash,
                                DeepIdV2PreKeyPublicationCodec.Decode(entries[position].CopyPublication())));
                        }
                    }
                }
                if (capturedTip is null)
                {
                    if (stagedHash is not null)
                        await WritePreKeyTipAsync(storage, scopeHash,
                            stagedHash, cancellationToken)
                            .ConfigureAwait(false);
                }
                else if (successors is not null)
                {
                    if (!capturedTip.Use(value => CryptographicOperations.FixedTimeEquals(value, successors.Tip)))
                        throw new CryptographicException("Prekey custody changed while opening its SQL owner.");
                }
                else if (stagedHash is null ||
                         !capturedTip.Use(value => value.Length == 64 &&
                             CryptographicOperations.FixedTimeEquals(
                                 value[..32], scopeHash) &&
                             CryptographicOperations.FixedTimeEquals(
                                 value[32..], stagedHash)))
                    throw new CryptographicException(
                        "The protected DID2 pre-key inventory tip differs.");
                await store.ReconcileReceiverSessionsAsync(storage, record.AsMemory(56, 32), cancellationToken).ConfigureAwait(false);
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
