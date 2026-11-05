using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private enum MailboxCustodyProfile { Complete, RetainedPath, ContactPayload, InitialPayload, StoppedAccept, StoppedInitial }
    // A local readback digest only. The live producer independently owns
    // exclusion/dependency closure; a copied digest never grants deletion.
    private async Task<Did2CompactionPlan.RootReadback> ReadMailboxStoreStateUnderLeaseAsync(
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, HeldDeepIdV2AccountLease held, CancellationToken ct)
        => await ReadMailboxCustodyUnderLeaseAsync(account, instance, held, MailboxCustodyProfile.Complete, ct).ConfigureAwait(false);

    // Publication and application SQL have their own exact before/after roots
    // in the joint retained-path profile. Every OTHER source/native dependency
    // remains independently guarded; Root12 keeps its original complete meaning.
    private async Task<Did2CompactionPlan.RootReadback> ReadMailboxLocalCustodyUnderLeaseAsync(
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, HeldDeepIdV2AccountLease held, CancellationToken ct)
        => await ReadMailboxCustodyUnderLeaseAsync(account, instance, held, MailboxCustodyProfile.RetainedPath, ct).ConfigureAwait(false);

    // Only this joint profile owns a separate exact ContactAccept successor.
    // Root12 keeps its complete meaning; every other source remains guarded.
    private async Task<Did2CompactionPlan.RootReadback> ReadMailboxContactCustodyUnderLeaseAsync(
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, HeldDeepIdV2AccountLease held, CancellationToken ct)
        => await ReadMailboxCustodyUnderLeaseAsync(account, instance, held, MailboxCustodyProfile.ContactPayload, ct).ConfigureAwait(false);
    private async Task<Did2CompactionPlan.RootReadback> ReadMailboxInitialCustodyUnderLeaseAsync(
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, HeldDeepIdV2AccountLease held, CancellationToken ct)
        => await ReadMailboxCustodyUnderLeaseAsync(account, instance, held, MailboxCustodyProfile.InitialPayload, ct).ConfigureAwait(false);
    private Task<Did2CompactionPlan.RootReadback> ReadStoppedControlCustodyUnderLeaseAsync(
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, HeldDeepIdV2AccountLease held, bool initial, CancellationToken ct)
        => ReadMailboxCustodyUnderLeaseAsync(account, instance, held, initial ? MailboxCustodyProfile.StoppedInitial : MailboxCustodyProfile.StoppedAccept, ct);

    private async Task<Did2CompactionPlan.RootReadback> ReadMailboxCustodyUnderLeaseAsync(
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, HeldDeepIdV2AccountLease held,
        MailboxCustodyProfile profile, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var jointPath = profile == MailboxCustodyProfile.RetainedPath;
        var stopped = profile is MailboxCustodyProfile.StoppedAccept or MailboxCustodyProfile.StoppedInitial;
        var contactPayload = profile is MailboxCustodyProfile.ContactPayload or MailboxCustodyProfile.StoppedAccept;
        var initialPayload = profile is MailboxCustodyProfile.InitialPayload or MailboxCustodyProfile.StoppedInitial;
        using var selectorHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        selectorHash.AppendData(stopped ? (initialPayload ? "Deep/STORE-V2/stopped-initial-custody-selector"u8 : "Deep/STORE-V2/stopped-accept-custody-selector"u8) :
            initialPayload ? "Deep/STORE-V2/mailbox-initial-custody-selector"u8 :
            contactPayload ? "Deep/STORE-V2/mailbox-contact-custody-selector"u8 :
            jointPath ? "Deep/STORE-V2/mailbox-local-custody-selector"u8 : "Deep/STORE-V2/mailbox-store-state-selector"u8); selectorHash.AppendData([0]);
        selectorHash.AppendData(networkId); selectorHash.AppendData(account.Span); selectorHash.AppendData(instance.Span);
        var selector = selectorHash.GetHashAndReset();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(stopped ? (initialPayload ? "Deep/STORE-V2/stopped-initial-custody"u8 : "Deep/STORE-V2/stopped-accept-custody"u8) :
            initialPayload ? "Deep/STORE-V2/mailbox-initial-custody"u8 :
            contactPayload ? "Deep/STORE-V2/mailbox-contact-custody"u8 :
            jointPath ? "Deep/STORE-V2/mailbox-local-custody"u8 : "Deep/STORE-V2/mailbox-store-state"u8); hash.AppendData([0]); hash.AppendData(selector);
        using var registration = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(
            storage, networkId, account, ct).ConfigureAwait(false);
        if (!registration.Use(bytes => FixedRoute(bytes.Slice(56, 32), instance.Span)))
            throw new CryptographicException("Mailbox state readback changed its registered account instance.");
        registration.Use(bytes => { hash.AppendData(bytes); return true; });
        var registrationHash = registration.Use(bytes => SHA256.HashData(bytes));
        registration.Dispose();
        if (!jointPath)
        using (var publication = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Mailbox state lost protected publication/retained-route custody."))
        {
            using var decoded = publication.Use(bytes => ProtectedDid2ContactRouteJournal.Decode(bytes, networkId, account.Span, instance.Span));
            await ProtectedDid2ContactRouteJournal.RequireArchiveCustodyAsync(storage, publication, networkId, account, instance, ct).ConfigureAwait(false);
            publication.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; });
        }
        var resolverDigest = await new ProtectedDeepIdV2ResolverCapabilityStore(storage, networkId, account.Span)
            .ReadCustodyDigestAsync(ct).ConfigureAwait(false);
        try { hash.AppendData(resolverDigest); }
        finally { CryptographicOperations.ZeroMemory(resolverDigest); }
        if (!initialPayload)
        using (var contact = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Mailbox state lost contact-start custody."))
        {
            using var decoded = contact.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, networkId, account.Span, instance.Span));
            contact.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; });
        }
        if (!contactPayload)
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
        byte[] catalogHash;
        Did2MessagingSessionScope[] scopes;
        using (var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, account.Span, instance.Span)
            .ReadAsync(ct).ConfigureAwait(false))
        {
            hash.AppendData(catalog.Exact.Span); catalogHash = SHA256.HashData(catalog.Exact.Span);
            scopes = new Did2MessagingSessionScope[catalog.Count];
            for (var index = 0; index < scopes.Length; index++)
            {
                if (catalog.Phase(index) != 2) throw new IOException("Uninitialized native messaging work pins mailbox retirement.");
                scopes[index] = Did2MessagingSessionScope.RestoreMetadata(catalog.Scope(index).Exact);
            }
        }
        var guards = new Dictionary<string, byte[]?>(StringComparer.Ordinal)
        {
            [SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot] = registrationHash,
            [ProtectedDid2MessagingSessionCatalog.Slot] = catalogHash,
            [ProtectedDid2MessagingArchiveEnrollment.Slot] = null
        };
        // Root2 already commits each retained entry hash. Validate mandatory
        // physical originals and guard those same objects throughout this
        // readback; no alternate root or new compaction digest is introduced.
        await GuardRetainedAcquisitionCustodyUnderLeaseAsync(account, instance, held, guards, ct).ConfigureAwait(false);
        if (!jointPath && !stopped)
        using (var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
            storage, sqlStatePath, networkId, account, instance, held, lease, ct).ConfigureAwait(false))
        {
            var projection = await application.ReadCompleteMailboxStateProjectionAsync(selector, ct).ConfigureAwait(false);
            try { hash.AppendData(projection); }
            finally { CryptographicOperations.ZeroMemory(projection); }
        }
        // Catalog bounds the number of databases. Each SQL verifier streams
        // bounded cells and authenticates the complete retained history/tip.
        foreach (var scope in scopes)
        {
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            string[] slots = [ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot,
                Did2MessagingHistoryCheckpoint.Slot(scope), Did2MessagingArchiveRoot.Slot(scope),
                ProtectedDid2MessagingPeerBootstrap.Slot(scope)];
            using var roots = await storage.ReadOwnedGuardedBatchAsync(slots, guards, ct).ConfigureAwait(false);
            using var catalog = (roots[0] ?? throw new InvalidDataException("Mailbox state readback lost its actual catalog.")).Use(bytes =>
                ProtectedDid2MessagingSessionCatalog.Decode(bytes, networkId, account.Span, instance.Span));
            var selected = catalog.FindExact(scope);
            if (selected < 0 || catalog.Phase(selected) != 2)
                throw new CryptographicException("Mailbox state readback changed its initialized native scope.");
            var floor = (roots[1] ?? throw new InvalidDataException("Mailbox state readback lost its native floor.")).Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
            if (floor.Phase != 1 || floor.Status == 2)
                throw new IOException("Pending or latched native work pins mailbox retirement.");
            var history = (roots[2] ?? throw new InvalidDataException("Mailbox state readback lost its native history.")).Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
            var archive = (roots[3] ?? throw new InvalidDataException("Mailbox state readback lost its native archive root.")).Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
            archive.RequireSource(history);
            var peer = roots[4] ?? throw new InvalidDataException("Mailbox state readback lost its protected peer.");
            _ = peer.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope));
            var peerHash = peer.Use(bytes => SHA256.HashData(bytes));
            roots.Dispose(); ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(
                sqlStatePath, catalog, scope, held, lease);
            var sql = new Did2MessagingSqlJournal(connection, scope, history); sql.BindArchiveRoot(archive);
            if (!FixedRoute(sql.VerifyTip().Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Mailbox state readback differs from its protected native tip.");
            var projection = sql.ReadCompleteCompactionProjection();
            try
            {
                hash.AppendData(scope.Hash); hash.AppendData(floor.Exact.Span); hash.AppendData(history.Exact.Span);
                hash.AppendData(archive.Exact.Span); hash.AppendData(peerHash);
                hash.AppendData(projection);
            }
            finally { CryptographicOperations.ZeroMemory(projection); }
        }
        using var finalOwners = await storage.ReadOwnedGuardedBatchAsync([], guards, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        return new(contactPayload || initialPayload ? Did2CompactionPlan.RootKind.MailboxContactCustody :
            jointPath ? Did2CompactionPlan.RootKind.MailboxLocalCustody : Did2CompactionPlan.RootKind.MailboxStoreState,
            selector, hash.GetHashAndReset());
    }
}
