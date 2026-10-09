using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // A local readback digest only. The live producer independently owns
    // exclusion/dependency closure; a copied digest never grants deletion.
    private async Task<Did2CompactionPlan.RootReadback> ReadMailboxStoreStateUnderLeaseAsync(
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var selectorHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        selectorHash.AppendData("Deep/STORE-V2/mailbox-store-state-selector"u8); selectorHash.AppendData([0]);
        selectorHash.AppendData(networkId); selectorHash.AppendData(account.Span); selectorHash.AppendData(instance.Span);
        var selector = selectorHash.GetHashAndReset();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/mailbox-store-state"u8); hash.AppendData([0]); hash.AppendData(selector);
        using var registration = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(
            storage, networkId, account, ct).ConfigureAwait(false);
        if (!registration.Use(bytes => FixedRoute(bytes.Slice(56, 32), instance.Span)))
            throw new CryptographicException("Mailbox state readback changed its registered account instance.");
        registration.Use(bytes => { hash.AppendData(bytes); return true; });
        using (var publication = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Mailbox state lost protected publication/retained-route custody."))
        {
            using var decoded = publication.Use(bytes => ProtectedDid2ContactRouteJournal.Decode(bytes, networkId, account.Span, instance.Span));
            publication.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; });
        }
        var resolverDigest = await new ProtectedDeepIdV2ResolverCapabilityStore(storage, networkId, account.Span)
            .ReadCustodyDigestAsync(ct).ConfigureAwait(false);
        try { hash.AppendData(resolverDigest); }
        finally { CryptographicOperations.ZeroMemory(resolverDigest); }
        using (var contact = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Mailbox state lost contact-start custody."))
        {
            using var decoded = contact.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, networkId, account.Span, instance.Span));
            contact.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; });
        }
        using (var contact = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Mailbox state lost contact-accept custody."))
        {
            using var decoded = contact.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, networkId, account.Span, instance.Span));
            contact.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; });
        }
        using (var retirements = await storage.ReadOwnedAsync(ProtectedInitialKeyRetirementJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Mailbox state lost initial-key retirement custody."))
        {
            _ = retirements.Use(bytes => ProtectedInitialKeyRetirementJournal.Decode(bytes, networkId, account.Span, instance.Span));
            retirements.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; });
        }
        using (var preclaims = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Mailbox state lost preclaim custody."))
        {
            _ = preclaims.Use(bytes => ProtectedDph2PreClaimJournal.Decode(bytes, networkId, account.Span, instance.Span));
            preclaims.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; });
        }
        var sourceProjection = await SqliteDeepIdV2AccountGeneration.ReadExistingDeviceSourceProjectionUnderLeaseAsync(
            storage, sqlStatePath, networkId, account, instance, held, lease, ct).ConfigureAwait(false);
        try { hash.AppendData(sourceProjection); }
        finally { CryptographicOperations.ZeroMemory(sourceProjection); }
        var responderReadback = await SqliteDeepIdV2AccountGeneration.ReadExistingPreKeySourceReadbackUnderLeaseAsync(
            storage, sqlStatePath, networkId, account, instance, held, lease, ct).ConfigureAwait(false);
        try { hash.AppendData(responderReadback); }
        finally { CryptographicOperations.ZeroMemory(responderReadback); }
        using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, account.Span, instance.Span)
            .ReadAsync(ct).ConfigureAwait(false);
        hash.AppendData(catalog.Exact.Span);
        using (var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
            storage, sqlStatePath, networkId, account, instance, held, lease, ct).ConfigureAwait(false))
        {
            var projection = await application.ReadCompleteMailboxStateProjectionAsync(selector, ct).ConfigureAwait(false);
            try { hash.AppendData(projection); }
            finally { CryptographicOperations.ZeroMemory(projection); }
        }
        // Catalog bounds the number of databases. Each SQL verifier streams
        // bounded cells and authenticates the complete retained history/tip.
        for (var index = 0; index < catalog.Count; index++)
        {
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            if (catalog.Phase(index) != 2)
                throw new IOException("Uninitialized native messaging work pins mailbox retirement.");
            var scope = catalog.Scope(index);
            using var floorRaw = await storage.ReadOwnedAsync(scope.FloorSlot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Mailbox state readback lost its native floor.");
            var floor = floorRaw.Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
            if (floor.Phase != 1 || floor.Status == 2)
                throw new IOException("Pending or latched native work pins mailbox retirement.");
            var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
            using var peer = await storage.ReadOwnedAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope), ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Mailbox state readback lost its protected peer.");
            _ = peer.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope));
            using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(
                sqlStatePath, catalog, scope, held, lease);
            var sql = new Did2MessagingSqlJournal(connection, scope, history);
            if (!FixedRoute(sql.VerifyTip().Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Mailbox state readback differs from its protected native tip.");
            var projection = sql.ReadCompleteCompactionProjection();
            try
            {
                hash.AppendData(scope.Hash); hash.AppendData(floor.Exact.Span); hash.AppendData(history.Exact.Span);
                peer.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; });
                hash.AppendData(projection);
            }
            finally { CryptographicOperations.ZeroMemory(projection); }
        }
        using var finalCatalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, account.Span, instance.Span)
            .ReadAsync(ct).ConfigureAwait(false);
        if (!FixedRoute(catalog.Exact.Span, finalCatalog.Exact.Span))
            throw new CryptographicException("Mailbox state catalog changed during readback.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        return new(Did2CompactionPlan.RootKind.MailboxStoreState, selector, hash.GetHashAndReset());
    }
}
