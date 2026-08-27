using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Client.Shared.Services;

public sealed record ProductionMailboxReplicaBinding(
    ReadOnlyMemory<byte> ReplicaId,
    Uri HttpsEndpoint,
    ReadOnlyMemory<byte> CurrentSpkiSha256,
    ReadOnlyMemory<byte> NextSpkiSha256);

public sealed record ProductionMailboxSelectionBinding(
    ulong Epoch,
    ulong Generation,
    ReadOnlyMemory<byte> CanonicalSelection,
    IReadOnlyList<ProductionMailboxReplicaBinding> Replicas);

public sealed record ProductionMailboxGrantBinding(
    MailboxCapabilityDomain Domain,
    ulong Epoch,
    ulong Generation,
    ReadOnlyMemory<byte> CanonicalGrant);

public sealed record ProductionMailboxLocalOwnerBundle(
    ReadOnlyMemory<byte> HolderEd25519PublicKey,
    ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey,
    ReadOnlyMemory<byte> IdempotencyKey,
    ReadOnlyMemory<byte> BlindedMailboxId,
    ReadOnlyMemory<byte> BlindedPlacementId,
    ReadOnlyMemory<byte> SelectionInputCommitment,
    ProductionMailboxControlPlaneArtifacts ControlPlane,
    IReadOnlyList<ProductionMailboxSelectionBinding> Selections,
    IReadOnlyList<ProductionMailboxGrantBinding> Grants,
    ReadOnlyMemory<byte> CanonicalRouteCertificate,
    ReadOnlyMemory<byte> RouteCertificateSha256,
    ReadOnlyMemory<byte> CanonicalRouteAdvertisement,
    ReadOnlyMemory<byte> RouteAdvertisementSha256,
    ReadOnlyMemory<byte> CanonicalSelectionSuccessor,
    ReadOnlyMemory<byte> SelectionSuccessorSha256,
    ulong IssuedAtUnixSeconds,
    ulong ExpiresAtUnixSeconds);

public sealed record ProductionMailboxPeerDepositBundle(
    ReadOnlyMemory<byte> HolderEd25519PublicKey,
    ReadOnlyMemory<byte> RecipientEd25519PublicKey,
    ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey,
    ReadOnlyMemory<byte> IdempotencyKey,
    ReadOnlyMemory<byte> BlindedMailboxId,
    ReadOnlyMemory<byte> BlindedPlacementId,
    ReadOnlyMemory<byte> SelectionInputCommitment,
    ProductionMailboxControlPlaneArtifacts ControlPlane,
    IReadOnlyList<ProductionMailboxSelectionBinding> Selections,
    IReadOnlyList<ProductionMailboxGrantBinding> Grants,
    ReadOnlyMemory<byte> CanonicalRouteAdvertisement,
    ReadOnlyMemory<byte> RouteAdvertisementSha256,
    ulong IssuedAtUnixSeconds,
    ulong ExpiresAtUnixSeconds);

public sealed record ImportedProductionMailboxRuntimeMaterial(
    VerifiedOfficialMailboxAuthority Authority,
    ClientMailboxActivation Activation,
    IMailboxClientDecodePolicyProvider DecodePolicies,
    MailboxCredentialSelector SelfSelector,
    SessionId LocalSessionId,
    MailboxInfrastructureOwnership Ownership);

public sealed record ImportedProductionMailboxPeerDepositMaterial(
    VerifiedOfficialMailboxAuthority Authority,
    MailboxCredentialSelector PeerSelector,
    SessionId LocalSessionId,
    SessionId RecipientSessionId,
    MailboxInfrastructureOwnership Ownership);

public enum ProductionMailboxActiveBundleStatus
{
    Absent = 0,
    Valid = 1,
    RefreshRecommended = 2,
    Expired = 3,
    Corrupt = 4
}

public sealed record ProductionMailboxActiveBundleLoadResult(
    ProductionMailboxActiveBundleStatus Status,
    ImportedProductionMailboxRuntimeMaterial? Material,
    ProductionMailboxLocalOwnerPublicRoute? PublicRoute = null);

public sealed record ProductionMailboxLocalOwnerPublicRoute(
    ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey,
    ReadOnlyMemory<byte> CanonicalRouteAdvertisement,
    ulong ExpiresAtUnixSeconds);

/// <summary>
/// Imports exact Registry LocalOwner and PeerDeposit responses. PeerDeposit requires the caller
/// to supply the independently authenticated recipient Session ID and mailbox-owner key; PRA1 is
/// never treated as a public Session directory.
/// </summary>
public static class ProductionMailboxCredentialBundleImporter
{
    private static ReadOnlySpan<byte> AccountDomain =>
        "deep.mailbox.account-scope.v1"u8;
    private static ReadOnlySpan<byte> AuthorityDomain =>
        "deep.mailbox.stable-authority-id.v1"u8;
    private static ReadOnlySpan<byte> GenerationDomain =>
        "deep.mailbox.production-local-owner-generation.v1"u8;
    private static ReadOnlySpan<byte> PeerGenerationDomain =>
        "deep.mailbox.production-peer-deposit-generation.v1"u8;

    internal enum PublicationFaultPoint
    {
        AfterJournalCommit,
        AfterTrustCommit,
        AfterRuntimeCommit
    }

    public static async Task<ImportedProductionMailboxRuntimeMaterial> ImportLocalOwnerAsync(
        SqliteSessionStore store,
        MailboxHolderIdentity holder,
        ProductionMailboxLocalOwnerBundle bundle,
        ReadOnlyMemory<byte> expectedMailboxOwnerEd25519PublicKey,
        ProductionMailboxTrustAnchor buildAnchor,
        IProductionMailboxTrustStateStore trustStateStore,
        ProductionMailboxClientApprovalIdentity clientIdentity,
        MailboxInfrastructureOwnership ownership,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
        => await ImportLocalOwnerCoreAsync(
            store,
            holder,
            bundle,
            expectedMailboxOwnerEd25519PublicKey,
            buildAnchor,
            trustStateStore,
            clientIdentity,
            ownership,
            timeProvider,
            faultInjector: null,
            verifyOnly: false,
            persistedJournal: null,
            cancellationToken).ConfigureAwait(false);

    public static async Task<ImportedProductionMailboxPeerDepositMaterial>
        ImportPeerDepositAsync(
            SqliteSessionStore store,
            MailboxHolderIdentity holder,
            SessionId expectedRecipientSessionId,
            ReadOnlyMemory<byte> expectedRecipientMailboxOwnerEd25519PublicKey,
            ProductionMailboxPeerDepositBundle bundle,
            ProductionMailboxTrustAnchor buildAnchor,
            IProductionMailboxTrustStateStore trustStateStore,
            ProductionMailboxClientApprovalIdentity clientIdentity,
            MailboxInfrastructureOwnership ownership,
            TimeProvider? timeProvider = null,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(holder);
        ArgumentNullException.ThrowIfNull(bundle);
        ArgumentNullException.ThrowIfNull(buildAnchor);
        ArgumentNullException.ThrowIfNull(trustStateStore);
        ArgumentNullException.ThrowIfNull(clientIdentity);
        if (ownership != MailboxInfrastructureOwnership.OfficialManaged)
            throw new InvalidOperationException(
                "Registry PeerDeposit provisioning is official-managed only.");

        bundle = FreezePeerDepositBundle(bundle);
        clientIdentity = FreezeClientIdentity(clientIdentity);
        var expectedOwner = ExactNonzero(
            expectedRecipientMailboxOwnerEd25519PublicKey.Span, 32,
            "expected recipient owner key");
        var holderKey = ExactNonzero(
            bundle.HolderEd25519PublicKey.Span, 32, "holder key");
        var recipientKey = ExactNonzero(
            bundle.RecipientEd25519PublicKey.Span, 32, "recipient Session key");
        var ownerKey = ExactNonzero(
            bundle.MailboxOwnerEd25519PublicKey.Span, 32, "recipient owner key");
        var idempotency = ExactNonzero(
            bundle.IdempotencyKey.Span, 32, "idempotency key");
        var mailbox = ExactNonzero(
            bundle.BlindedMailboxId.Span, 32, "mailbox ID");
        var placement = ExactNonzero(
            bundle.BlindedPlacementId.Span, 32, "placement ID");
        var selectionCommitment = ExactNonzero(
            bundle.SelectionInputCommitment.Span, 32, "selection commitment");
        try
        {
            Require(Fixed(holderKey, holder.Ed25519PublicKey.Span),
                "Registry holder differs from the active Session holder.");
            Require(holder.SessionId == SessionIdFromEd25519(holderKey),
                "Registry holder does not map to the active Session ID.");
            var recipientSessionId = SessionIdFromEd25519(recipientKey);
            Require(recipientSessionId == expectedRecipientSessionId,
                "Registry recipient does not map to the authenticated contact Session ID.");
            Require(Fixed(ownerKey, expectedOwner),
                "Registry PeerDeposit changed the authenticated contact owner identity.");

            var clock = timeProvider ?? TimeProvider.System;
            var now = clock.GetUtcNow().ToUnixTimeSeconds();
            Require(now > 0,
                "Production mailbox verification time is outside its valid range.");
            var verifiedAt = checked((ulong)now);
            Require(bundle.IssuedAtUnixSeconds > 0 &&
                    bundle.IssuedAtUnixSeconds < bundle.ExpiresAtUnixSeconds &&
                    verifiedAt >= bundle.IssuedAtUnixSeconds &&
                    verifiedAt <= bundle.ExpiresAtUnixSeconds,
                "Registry PeerDeposit response is expired or has an invalid issuance window.");
            Require(bundle.Selections is { Count: 2 } && bundle.Grants is { Count: 2 },
                "Registry PeerDeposit requires exact current/next selections and grants.");

            var placementId = new BlindedPlacementId(placement);
            Require(Fixed(
                    ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(
                        placementId),
                    selectionCommitment),
                "Registry selection commitment does not match its placement.");
            var verified = await ProductionMailboxControlPlaneVerifier.VerifyAsync(
                bundle.ControlPlane,
                buildAnchor,
                trustStateStore,
                clientIdentity,
                ownership,
                placementId,
                placementId,
                clock,
                cancellationToken).ConfigureAwait(false);
            ValidateSelectionBinding(bundle.Selections[0], verified.CurrentSelection);
            ValidateSelectionBinding(bundle.Selections[1], verified.NextSelection);

            var authority = verified.Authority.Authority;
            var topology = verified.Topology.Snapshot;
            Require(Fixed(authority.NetworkId.Span, topology.NetworkId.Span),
                "Verified production control-plane network IDs differ.");
            Require(bundle.ExpiresAtUnixSeconds ==
                    topology.CurrentEpoch.NotAfterUnixSeconds,
                "Registry PeerDeposit expiry differs from its current epoch.");
            var route = VerifyPeerRouteClosure(
                bundle,
                verified,
                ownerKey,
                mailbox,
                placement,
                selectionCommitment,
                clientIdentity,
                verifiedAt);

            var grants = bundle.Grants.Select(DecodeGrant).ToArray();
            Require(grants.Length == 2 && grants.All(static value =>
                    value.Binding.Domain == MailboxCapabilityDomain.Deposit),
                "PeerDeposit accepts deposit grants only.");
            ValidateGrant(
                grants[0], MailboxCapabilityDomain.Deposit, holderKey, authority,
                topology.CurrentEpoch, placementId, "PeerDeposit");
            ValidateGrant(
                grants[1], MailboxCapabilityDomain.Deposit, holderKey, authority,
                topology.NextEpoch, placementId, "PeerDeposit");
            Require(!Fixed(grants[0].Grant.Serial.Span, grants[1].Grant.Serial.Span),
                "Current and next PeerDeposit grant serials must differ.");

            var issuer = authority.MailboxIssuerEd25519PublicKey.ToArray();
            var issuerAuthorities = IssuerAuthorities(issuer, topology);
            var account = OutboxAccountScope.FromBytes(
                DomainHash(AccountDomain, holderKey));
            var issuerContext = DomainHash(
                AuthorityDomain,
                new byte[] { (byte)ownership },
                authority.NetworkId,
                issuer);
            var selector = new MailboxCredentialSelector(
                account,
                MailboxCredentialScopeKind.Peer,
                recipientKey,
                issuerContext);
            var revoked = BuildRevocationKeys(
                verified.Revocations.Snapshot.RevokedGrantSerials,
                issuer,
                topology);
            var revocationReceipt = new MailboxRevocationRuntimeCheckpoint(
                1,
                verified.Revocations.Snapshot.IssuedAtUnixSeconds,
                verified.Revocations.Snapshot.ExpiresAtUnixSeconds,
                Convert.ToHexStringLower(
                    verified.Revocations.CanonicalSnapshotHash.Span),
                revoked);
            var revocationKey = "deep.mailbox.production-revocation.v1:" +
                Convert.ToHexStringLower(issuerContext);
            var revocationSource = new SqliteMailboxRevocationSource(
                store, revocationKey, revocationReceipt, clock);
            var coordinator = MailboxRuntimePolicyCoordinator.For(
                store.CanonicalStateIdentity, issuerContext);
            var runtimeAuthority = new VerifiedOfficialMailboxAuthority(
                authority.NetworkId,
                topology.CurrentEpoch.Generation,
                issuerAuthorities,
                requiresManagedEntitlement: true,
                static () => true,
                revocationSource,
                clock,
                coordinator);
            var generation = DomainHash(
                PeerGenerationDomain,
                verified.Authority.CanonicalAuthorityHash,
                verified.Topology.CanonicalTopologyHash,
                idempotency,
                holderKey,
                recipientKey,
                ownerKey,
                mailbox,
                route.CertificateHash,
                route.AdvertisementHash,
                route.RouteDomainHash,
                UInt64Bytes(route.Sequence),
                SHA256.HashData(grants[0].Binding.CanonicalGrant.Span),
                SHA256.HashData(grants[1].Binding.CanonicalGrant.Span));
            var credential = new ScopedMailboxCredentialGeneration(
                selector,
                generation,
                holderKey,
                mailbox,
                ToEpoch(topology.CurrentEpoch, placementId),
                ToEpoch(topology.NextEpoch, placementId),
                Retrieve: null,
                new MailboxCredentialGrantSet(
                    grants[0].Binding.CanonicalGrant.Span,
                    grants[1].Binding.CanonicalGrant.Span),
                ReplicaPair(verified.CurrentSelection),
                ReplicaPair(verified.NextSelection));

            await CommitTrustStateRecoveringAmbiguousOutcomeAsync(
                verified, trustStateStore, cancellationToken).ConfigureAwait(false);
            await store.InstallScopedCredentialAsync(
                credential, runtimeAuthority, CancellationToken.None).ConfigureAwait(false);
            return new ImportedProductionMailboxPeerDepositMaterial(
                runtimeAuthority,
                selector,
                holder.SessionId,
                recipientSessionId,
                ownership);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedOwner);
            CryptographicOperations.ZeroMemory(holderKey);
            CryptographicOperations.ZeroMemory(recipientKey);
            CryptographicOperations.ZeroMemory(ownerKey);
            CryptographicOperations.ZeroMemory(idempotency);
            CryptographicOperations.ZeroMemory(mailbox);
            CryptographicOperations.ZeroMemory(placement);
            CryptographicOperations.ZeroMemory(selectionCommitment);
        }
    }

    public static async Task<ImportedProductionMailboxRuntimeMaterial?>
        TryRecoverPendingLocalOwnerAsync(
            SqliteSessionStore store,
            MailboxHolderIdentity holder,
            ProductionMailboxTrustAnchor buildAnchor,
            IProductionMailboxTrustStateStore trustStateStore,
            ProductionMailboxClientApprovalIdentity clientIdentity,
            ReadOnlyMemory<byte> expectedMailboxOwnerEd25519PublicKey,
            MailboxInfrastructureOwnership ownership,
            TimeProvider? timeProvider = null,
            CancellationToken cancellationToken = default)
        => await TryImportPersistedLocalOwnerAsync(
            store,
            holder,
            PublicationJournalKey(holder),
            "Pending production mailbox publication journal bundle",
            buildAnchor,
            trustStateStore,
            clientIdentity,
            expectedMailboxOwnerEd25519PublicKey,
            ownership,
            timeProvider,
            cancellationToken).ConfigureAwait(false);

    public static async Task<ProductionMailboxActiveBundleLoadResult>
        LoadActiveLocalOwnerAsync(
            SqliteSessionStore store,
            MailboxHolderIdentity holder,
            ProductionMailboxTrustAnchor buildAnchor,
            IProductionMailboxTrustStateStore trustStateStore,
            ProductionMailboxClientApprovalIdentity clientIdentity,
            ReadOnlyMemory<byte> expectedMailboxOwnerEd25519PublicKey,
            MailboxInfrastructureOwnership ownership,
            TimeProvider? timeProvider = null,
            CancellationToken cancellationToken = default)
    {
        var clock = timeProvider ?? TimeProvider.System;
        (ProductionMailboxRuntimePublicationJournal Journal,
            ProductionMailboxLocalOwnerBundle Bundle)? active;
        try
        {
            active = await ReadPersistedLocalOwnerAsync(
                store,
                ActiveBundleKey(holder),
                "Active production mailbox public bundle",
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsPersistedCorruption(exception))
        {
            return new ProductionMailboxActiveBundleLoadResult(
                ProductionMailboxActiveBundleStatus.Corrupt, null);
        }
        if (active is null)
            return new ProductionMailboxActiveBundleLoadResult(
                ProductionMailboxActiveBundleStatus.Absent, null);
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        if (now <= 0) throw new InvalidOperationException(
            "Production mailbox active-bundle time is outside its valid range.");
        if (active.Value.Journal.RefreshAfterUnixSeconds == 0 ||
            active.Value.Journal.RefreshAfterUnixSeconds >=
                active.Value.Journal.VerificationExpiresAtUnixSeconds)
            return new ProductionMailboxActiveBundleLoadResult(
                ProductionMailboxActiveBundleStatus.Corrupt, null);
        if (active.Value.Journal.VerifiedAtUnixSeconds > checked((ulong)now))
            return new ProductionMailboxActiveBundleLoadResult(
                ProductionMailboxActiveBundleStatus.Corrupt, null);
        if (checked((ulong)now) > active.Value.Journal.VerificationExpiresAtUnixSeconds)
        {
            // Expiry metadata is stored in SQLite and is not an authentication boundary. Reverify
            // the exact signed closure at its issuance time without publishing it before allowing
            // an online refresh. A canonical-but-tampered expired row remains corrupt/fail-closed.
            try
            {
                _ = await ImportLocalOwnerCoreAsync(
                    store,
                    holder,
                    active.Value.Bundle,
                    expectedMailboxOwnerEd25519PublicKey,
                    buildAnchor,
                    trustStateStore,
                    clientIdentity,
                    ownership,
                    clock,
                    faultInjector: null,
                    verifyOnly: true,
                    persistedJournal: active.Value.Journal,
                    cancellationToken).ConfigureAwait(false);
                RequirePersistedExpiryMatchesSignedTopology(active.Value);
            }
            catch (Exception exception) when (IsPersistedCorruption(exception))
            {
                return new ProductionMailboxActiveBundleLoadResult(
                    ProductionMailboxActiveBundleStatus.Corrupt, null);
            }
            return new ProductionMailboxActiveBundleLoadResult(
                ProductionMailboxActiveBundleStatus.Expired, null);
        }
        ImportedProductionMailboxRuntimeMaterial material;
        try
        {
            material = await ImportPersistedLocalOwnerAsync(
                store,
                holder,
                active.Value.Journal,
                active.Value.Bundle,
                "Active production mailbox public bundle",
                buildAnchor,
                trustStateStore,
                clientIdentity,
                expectedMailboxOwnerEd25519PublicKey,
                ownership,
                clock,
                cancellationToken).ConfigureAwait(false);
            RequirePersistedExpiryMatchesSignedTopology(active.Value);
        }
        catch (Exception exception) when (IsPersistedCorruption(exception))
        {
            return new ProductionMailboxActiveBundleLoadResult(
                ProductionMailboxActiveBundleStatus.Corrupt, null);
        }
        return new ProductionMailboxActiveBundleLoadResult(
            checked((ulong)now) >= active.Value.Journal.RefreshAfterUnixSeconds
                ? ProductionMailboxActiveBundleStatus.RefreshRecommended
                : ProductionMailboxActiveBundleStatus.Valid,
            material,
            new ProductionMailboxLocalOwnerPublicRoute(
                active.Value.Bundle.MailboxOwnerEd25519PublicKey.ToArray(),
                active.Value.Bundle.CanonicalRouteAdvertisement.ToArray(),
                active.Value.Bundle.ExpiresAtUnixSeconds));
    }

    private static void RequirePersistedExpiryMatchesSignedTopology(
        (ProductionMailboxRuntimePublicationJournal Journal,
            ProductionMailboxLocalOwnerBundle Bundle) active)
    {
        var topology = ProductionMailboxTopologyCodec.Decode(
            active.Bundle.ControlPlane.CanonicalTopology.Span);
        var advertisement = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(
            active.Bundle.CanonicalRouteAdvertisement.Span);
        var hardExpiresAt = Math.Min(
            topology.ExpiresAtUnixSeconds,
            Math.Min(advertisement.Certificate.ExpiresAtUnixSeconds,
                advertisement.ExpiresAtUnixSeconds));
        if (active.Journal.VerificationExpiresAtUnixSeconds !=
                hardExpiresAt)
            throw new InvalidDataException(
                "Active production mailbox public bundle is corrupt.");
    }

    private static async Task<ImportedProductionMailboxRuntimeMaterial?>
        TryImportPersistedLocalOwnerAsync(
            SqliteSessionStore store,
            MailboxHolderIdentity holder,
            string persistedKey,
            string diagnosticName,
            ProductionMailboxTrustAnchor buildAnchor,
            IProductionMailboxTrustStateStore trustStateStore,
            ProductionMailboxClientApprovalIdentity clientIdentity,
            ReadOnlyMemory<byte> expectedMailboxOwnerEd25519PublicKey,
            MailboxInfrastructureOwnership ownership,
            TimeProvider? timeProvider,
            CancellationToken cancellationToken)
    {
        var persisted = await ReadPersistedLocalOwnerAsync(
            store, persistedKey, diagnosticName, cancellationToken).ConfigureAwait(false);
        if (persisted is null) return null;
        return await ImportPersistedLocalOwnerAsync(
            store,
            holder,
            persisted.Value.Journal,
            persisted.Value.Bundle,
            diagnosticName,
            buildAnchor,
            trustStateStore,
            clientIdentity,
            expectedMailboxOwnerEd25519PublicKey,
            ownership,
            timeProvider ?? TimeProvider.System,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<(ProductionMailboxRuntimePublicationJournal Journal,
        ProductionMailboxLocalOwnerBundle Bundle)?> ReadPersistedLocalOwnerAsync(
            SqliteSessionStore store,
            string persistedKey,
            string diagnosticName,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        ProductionMailboxRuntimePublicationJournal? journal;
        try
        {
            journal = await store
                .ReadProductionMailboxRuntimePublicationAsync(
                    persistedKey, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is System.Text.Json.JsonException or
            InvalidDataException or FormatException)
        {
            throw new InvalidDataException(
                diagnosticName + " is corrupt.", exception);
        }
        if (journal is null) return null;

        byte[] encoded;
        try
        {
            encoded = Convert.FromBase64String(journal.SignedBundleBase64);
        }
        catch (Exception exception) when (exception is FormatException or
            ArgumentNullException)
        {
            throw new InvalidDataException(
                diagnosticName + " is incomplete.", exception);
        }
        try
        {
            if (!string.Equals(
                    Convert.ToHexStringLower(SHA256.HashData(encoded)),
                    journal.SignedBundleSha256,
                    StringComparison.Ordinal))
                throw new InvalidDataException(
                    diagnosticName + " is corrupt.");
            ProductionMailboxLocalOwnerBundle bundle;
            try
            {
                bundle = ProductionMailboxLocalOwnerJournalCodec.Decode(encoded);
            }
            catch (InvalidDataException exception)
            {
                throw new InvalidDataException(
                    diagnosticName + " is corrupt.",
                    exception);
            }
            return (journal, bundle);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static async Task<ImportedProductionMailboxRuntimeMaterial>
        ImportPersistedLocalOwnerAsync(
            SqliteSessionStore store,
            MailboxHolderIdentity holder,
            ProductionMailboxRuntimePublicationJournal journal,
            ProductionMailboxLocalOwnerBundle bundle,
            string diagnosticName,
            ProductionMailboxTrustAnchor buildAnchor,
            IProductionMailboxTrustStateStore trustStateStore,
            ProductionMailboxClientApprovalIdentity clientIdentity,
            ReadOnlyMemory<byte> expectedMailboxOwnerEd25519PublicKey,
            MailboxInfrastructureOwnership ownership,
            TimeProvider timeProvider,
            CancellationToken cancellationToken)
    {
        if (expectedMailboxOwnerEd25519PublicKey.Length != 32 ||
            expectedMailboxOwnerEd25519PublicKey.Span.IndexOfAnyExcept((byte)0) < 0 ||
            bundle.MailboxOwnerEd25519PublicKey.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(
                bundle.MailboxOwnerEd25519PublicKey.Span,
                expectedMailboxOwnerEd25519PublicKey.Span))
            throw new InvalidDataException(
                diagnosticName + " changed the stable owner identity.");
        try
        {
            return await ImportLocalOwnerCoreAsync(
                store,
                holder,
                bundle,
                expectedMailboxOwnerEd25519PublicKey,
                buildAnchor,
                trustStateStore,
                clientIdentity,
                ownership,
                timeProvider,
                faultInjector: null,
                verifyOnly: false,
                persistedJournal: journal,
                cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidDataException exception)
        {
            throw new InvalidDataException(
                diagnosticName + " failed verification.",
                exception);
        }
    }

    internal static async Task<ImportedProductionMailboxRuntimeMaterial>
        ImportLocalOwnerWithFaultInjectionAsync(
            SqliteSessionStore store,
            MailboxHolderIdentity holder,
            ProductionMailboxLocalOwnerBundle bundle,
            ReadOnlyMemory<byte> expectedMailboxOwnerEd25519PublicKey,
            ProductionMailboxTrustAnchor buildAnchor,
            IProductionMailboxTrustStateStore trustStateStore,
            ProductionMailboxClientApprovalIdentity clientIdentity,
            MailboxInfrastructureOwnership ownership,
            Action<PublicationFaultPoint> faultInjector,
            TimeProvider? timeProvider = null,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(faultInjector);
        return await ImportLocalOwnerCoreAsync(
            store,
            holder,
            bundle,
            expectedMailboxOwnerEd25519PublicKey,
            buildAnchor,
            trustStateStore,
            clientIdentity,
            ownership,
            timeProvider,
            faultInjector,
            verifyOnly: false,
            persistedJournal: null,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<ImportedProductionMailboxRuntimeMaterial>
        ImportLocalOwnerCoreAsync(
            SqliteSessionStore store,
            MailboxHolderIdentity holder,
            ProductionMailboxLocalOwnerBundle bundle,
            ReadOnlyMemory<byte> expectedMailboxOwnerEd25519PublicKey,
            ProductionMailboxTrustAnchor buildAnchor,
            IProductionMailboxTrustStateStore trustStateStore,
            ProductionMailboxClientApprovalIdentity clientIdentity,
            MailboxInfrastructureOwnership ownership,
            TimeProvider? timeProvider,
            Action<PublicationFaultPoint>? faultInjector,
            bool verifyOnly,
            ProductionMailboxRuntimePublicationJournal? persistedJournal,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(holder);
        ArgumentNullException.ThrowIfNull(bundle);
        bundle = FreezeLocalOwnerBundle(bundle);
        var expectedOwner = ExactNonzero(
            expectedMailboxOwnerEd25519PublicKey.Span, 32, "expected owner key");
        if (!CryptographicOperations.FixedTimeEquals(
                bundle.MailboxOwnerEd25519PublicKey.Span, expectedOwner))
        {
            CryptographicOperations.ZeroMemory(expectedOwner);
            throw new InvalidDataException(
                "Production mailbox bundle changed the stable owner identity.");
        }
        ArgumentNullException.ThrowIfNull(buildAnchor);
        ArgumentNullException.ThrowIfNull(trustStateStore);
        ArgumentNullException.ThrowIfNull(clientIdentity);
        if (ownership != MailboxInfrastructureOwnership.OfficialManaged)
            throw new InvalidOperationException(
                "Registry LocalOwner provisioning is official-managed only.");

        clientIdentity = FreezeClientIdentity(clientIdentity);
        var clock = timeProvider ?? TimeProvider.System;
        var actualNow = clock.GetUtcNow().ToUnixTimeSeconds();
        Require(actualNow > 0,
            "Production mailbox verification time is outside its valid range.");
        var verifiedAt = persistedJournal?.VerifiedAtUnixSeconds ?? checked((ulong)actualNow);
        Require(verifiedAt > 0 && verifiedAt <= checked((ulong)actualNow),
            "Production mailbox persisted verification time is invalid.");
        var verificationClock = new FixedUnixTimeProvider(verifiedAt);
        var holderKey = ExactNonzero(bundle.HolderEd25519PublicKey.Span, 32, "holder key");
        var ownerKey = ExactNonzero(bundle.MailboxOwnerEd25519PublicKey.Span, 32, "owner key");
        var idempotency = ExactNonzero(bundle.IdempotencyKey.Span, 32, "idempotency key");
        var mailbox = ExactNonzero(bundle.BlindedMailboxId.Span, 32, "mailbox ID");
        var placement = ExactNonzero(bundle.BlindedPlacementId.Span, 32, "placement ID");
        var selectionCommitment = ExactNonzero(
            bundle.SelectionInputCommitment.Span, 32, "selection commitment");
        try
        {
            Require(Fixed(holderKey, holder.Ed25519PublicKey.Span),
                "Registry holder differs from the active Session holder.");
            Require(holder.SessionId == SessionIdFromEd25519(holderKey),
                "Registry holder does not map to the active Session ID.");
            Require(bundle.IssuedAtUnixSeconds > 0 &&
                    bundle.IssuedAtUnixSeconds < bundle.ExpiresAtUnixSeconds,
                "Registry issuance window is invalid.");
            Require(verifiedAt >= bundle.IssuedAtUnixSeconds &&
                    verifiedAt <= bundle.ExpiresAtUnixSeconds,
                "Registry LocalOwner response is expired.");
            Require(bundle.CanonicalSelectionSuccessor.IsEmpty &&
                    bundle.SelectionSuccessorSha256.IsEmpty,
                "Registry LocalOwner selection-successor activation is not supported yet.");

            var placementId = new BlindedPlacementId(placement);
            Require(Fixed(
                    ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(placementId),
                    selectionCommitment),
                "Registry selection commitment does not match its placement.");
            Require(bundle.Selections is { Count: 2 } && bundle.Grants is { Count: 2 },
                "Registry LocalOwner requires exact current/next selections and grants.");

            var verified = await ProductionMailboxControlPlaneVerifier.VerifyAsync(
                bundle.ControlPlane,
                buildAnchor,
                trustStateStore,
                clientIdentity,
                ownership,
                placementId,
                placementId,
                verificationClock,
                cancellationToken).ConfigureAwait(false);
            ValidateSelectionBinding(bundle.Selections[0], verified.CurrentSelection);
            ValidateSelectionBinding(bundle.Selections[1], verified.NextSelection);

            var authority = verified.Authority.Authority;
            var topology = verified.Topology.Snapshot;
            Require(Fixed(authority.NetworkId.Span, topology.NetworkId.Span),
                "Verified production control-plane network IDs differ.");
            Require(bundle.ExpiresAtUnixSeconds ==
                    topology.CurrentEpoch.NotAfterUnixSeconds,
                "Registry bundle expiry differs from its current epoch.");
            var route = VerifyRouteClosure(
                bundle,
                verified,
                holderKey,
                ownerKey,
                mailbox,
                placement,
                selectionCommitment,
                clientIdentity,
                verifiedAt,
                persistedJournal);
            var grants = bundle.Grants.Select(DecodeGrant).ToArray();
            Require(grants.Length == 2 &&
                    grants.All(static value =>
                        value.Binding.Domain == MailboxCapabilityDomain.Retrieve),
                "LocalOwner accepts retrieve grants only.");
            ValidateGrant(
                grants[0], MailboxCapabilityDomain.Retrieve, holderKey, authority,
                topology.CurrentEpoch, placementId, "LocalOwner");
            ValidateGrant(
                grants[1], MailboxCapabilityDomain.Retrieve, holderKey, authority,
                topology.NextEpoch, placementId, "LocalOwner");
            Require(!Fixed(grants[0].Grant.Serial.Span, grants[1].Grant.Serial.Span),
                "Current and next LocalOwner grant serials must differ.");

            var issuer = authority.MailboxIssuerEd25519PublicKey.ToArray();
            var issuerAuthorities = IssuerAuthorities(issuer, topology);
            var account = OutboxAccountScope.FromBytes(DomainHash(AccountDomain, holderKey));
            var issuerContext = DomainHash(
                AuthorityDomain,
                new byte[] { (byte)ownership },
                authority.NetworkId,
                issuer);
            var selector = new MailboxCredentialSelector(
                account, MailboxCredentialScopeKind.Self, holderKey, issuerContext);
            var revoked = BuildRevocationKeys(
                verified.Revocations.Snapshot.RevokedGrantSerials,
                issuer,
                topology);
            var revocationReceipt = new MailboxRevocationRuntimeCheckpoint(
                1,
                verified.Revocations.Snapshot.IssuedAtUnixSeconds,
                verified.Revocations.Snapshot.ExpiresAtUnixSeconds,
                Convert.ToHexStringLower(
                    verified.Revocations.CanonicalSnapshotHash.Span),
                revoked);
            var revocationKey = "deep.mailbox.production-revocation.v1:" +
                Convert.ToHexStringLower(issuerContext);
            var revocationSource = new SqliteMailboxRevocationSource(
                store, revocationKey, revocationReceipt, clock);
            var coordinator = MailboxRuntimePolicyCoordinator.For(
                store.CanonicalStateIdentity, issuerContext);
            var runtimeAuthority = new VerifiedOfficialMailboxAuthority(
                authority.NetworkId,
                topology.CurrentEpoch.Generation,
                issuerAuthorities,
                requiresManagedEntitlement: true,
                static () => true,
                revocationSource,
                clock,
                coordinator);
            var currentEpoch = ToEpoch(topology.CurrentEpoch, placementId);
            var nextEpoch = ToEpoch(topology.NextEpoch, placementId);
            var currentReplicas = ReplicaPair(verified.CurrentSelection);
            var nextReplicas = ReplicaPair(verified.NextSelection);
            var generation = DomainHash(
                GenerationDomain,
                verified.Authority.CanonicalAuthorityHash,
                verified.Topology.CanonicalTopologyHash,
                idempotency,
                mailbox,
                route.CertificateHash,
                route.AdvertisementHash,
                route.RouteDomainHash,
                UInt64Bytes(route.Sequence),
                UInt64Bytes(verifiedAt));
            var credential = new ScopedMailboxCredentialGeneration(
                selector,
                generation,
                holderKey,
                mailbox,
                currentEpoch,
                nextEpoch,
                new MailboxCredentialGrantSet(
                    grants[0].Binding.CanonicalGrant.Span,
                    grants[1].Binding.CanonicalGrant.Span),
                Deposit: null,
                currentReplicas,
                nextReplicas);
            var decodePolicies = new TimeProviderMailboxClientDecodePolicyProvider(
                new MailboxEpochWindow
                {
                    CurrentEpoch = topology.CurrentEpoch.Epoch,
                    NextEpoch = topology.NextEpoch.Epoch,
                    CurrentNotBeforeUnixSeconds = topology.CurrentEpoch.NotBeforeUnixSeconds,
                    NextNotBeforeUnixSeconds = topology.NextEpoch.NotBeforeUnixSeconds,
                    CurrentExpiresAtUnixSeconds = topology.CurrentEpoch.NotAfterUnixSeconds,
                    NextExpiresAtUnixSeconds = topology.NextEpoch.NotAfterUnixSeconds
                },
                new MailboxCapabilityDecodePolicy
                {
                    CurrentBucket = checked((uint)topology.CurrentEpoch.Epoch),
                    MinimumGeneration = topology.CurrentEpoch.Generation
                },
                clock);
            _ = decodePolicies.GetCurrent();
            var checkpoint = new MailboxRuntimeSnapshotCheckpoint(
                "deep.mailbox.production-local-owner.v1:" + holder.SessionId.Value,
                new MailboxBundleRuntimeCheckpoint(
                    1,
                    "production-local-owner",
                    clientIdentity.Platform.ToString().ToLowerInvariant(),
                    ownership.ToString(),
                    topology.CurrentEpoch.Epoch,
                    Convert.ToHexStringLower(generation)),
                revocationKey,
                revocationReceipt);
            if (verifyOnly)
                return new ImportedProductionMailboxRuntimeMaterial(
                    runtimeAuthority,
                    new ClientMailboxActivation(true, issuerContext, ingressConfigured: true),
                    decodePolicies,
                    selector,
                    holder.SessionId,
                    ownership);
            var encodedTrustState = ProductionMailboxTrustStateCodec.Encode(
                verified.StateToCommit);
            var encodedBundle = ProductionMailboxLocalOwnerJournalCodec.Encode(bundle);
            var verificationLifetime = checked(
                topology.ExpiresAtUnixSeconds - topology.IssuedAtUnixSeconds);
            var refreshLead = Math.Min(900UL, Math.Max(1UL, verificationLifetime / 4));
            var hardExpiresAt = Math.Min(
                topology.ExpiresAtUnixSeconds,
                Math.Min(route.CertificateExpiresAtUnixSeconds,
                    route.AdvertisementExpiresAtUnixSeconds));
            var refreshAfter = hardExpiresAt > refreshLead
                ? hardExpiresAt - refreshLead
                : hardExpiresAt;
            Require(refreshAfter > verifiedAt &&
                    refreshAfter < hardExpiresAt,
                "Registry route closure leaves no safe refresh interval.");
            var publicationJournal = new ProductionMailboxRuntimePublicationJournal(
                2,
                verified.StateToCommit.Revision,
                Convert.ToHexStringLower(SHA256.HashData(encodedTrustState)),
                topology.CurrentEpoch.Epoch,
                Convert.ToHexStringLower(generation),
                Convert.ToHexStringLower(SHA256.HashData(encodedBundle)),
                Convert.ToBase64String(encodedBundle),
                hardExpiresAt,
                refreshAfter,
                verifiedAt,
                Convert.ToHexStringLower(route.CertificateHash),
                Convert.ToHexStringLower(route.AdvertisementHash),
                Convert.ToHexStringLower(route.RouteDomainHash),
                route.Sequence);
            if (persistedJournal is not null && publicationJournal != persistedJournal)
                throw new InvalidDataException(
                    "Persisted production mailbox journal is not bound to its verified closure.");
            CryptographicOperations.ZeroMemory(encodedTrustState);
            CryptographicOperations.ZeroMemory(encodedBundle);
            var publicationJournalKey = PublicationJournalKey(holder);
            var activeBundleKey = ActiveBundleKey(holder);
            await using var publication = await coordinator.AcquirePublicationAsync(
                cancellationToken).ConfigureAwait(false);
            try
            {
                await store.StageProductionMailboxRuntimePublicationAsync(
                    publicationJournalKey,
                    activeBundleKey,
                    publicationJournal,
                    cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                var staged = await store.ReadProductionMailboxRuntimePublicationAsync(
                    publicationJournalKey, CancellationToken.None).ConfigureAwait(false);
                if (staged != publicationJournal) throw;
            }
            faultInjector?.Invoke(PublicationFaultPoint.AfterJournalCommit);
            await CommitTrustStateRecoveringAmbiguousOutcomeAsync(
                verified,
                trustStateStore,
                cancellationToken).ConfigureAwait(false);
            faultInjector?.Invoke(PublicationFaultPoint.AfterTrustCommit);
            // Once the protected LKG is durable, complete the SQLite side even if the
            // caller cancels. A crash/fault leaves the journal for an exact-bundle retry.
            var runtimeActivation = new MailboxRuntimeCommitActivation(
                revocationSource, publication);
            try
            {
                await store.CompleteProductionMailboxRuntimePublicationAsync(
                    [credential],
                    runtimeAuthority,
                    checkpoint,
                    publicationJournalKey,
                    activeBundleKey,
                    publicationJournal,
                    runtimeActivation,
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // SQLite may report an I/O/process fault after the durable commit. Never
                // advertise failure (and provoke a needless Registry replay) until the exact
                // coupled post-state has been read back from a fresh transaction.
                if (!await store.IsProductionMailboxRuntimePublicationCompleteAsync(
                        checkpoint,
                        publicationJournalKey,
                        activeBundleKey,
                        publicationJournal,
                        CancellationToken.None).ConfigureAwait(false))
                    throw;
                runtimeActivation.ActivateCommittedNoThrow();
            }
            faultInjector?.Invoke(PublicationFaultPoint.AfterRuntimeCommit);
            return new ImportedProductionMailboxRuntimeMaterial(
                runtimeAuthority,
                new ClientMailboxActivation(true, issuerContext, ingressConfigured: true),
                decodePolicies,
                selector,
                holder.SessionId,
                ownership);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(holderKey);
            CryptographicOperations.ZeroMemory(ownerKey);
            CryptographicOperations.ZeroMemory(idempotency);
            CryptographicOperations.ZeroMemory(mailbox);
            CryptographicOperations.ZeroMemory(placement);
            CryptographicOperations.ZeroMemory(selectionCommitment);
            CryptographicOperations.ZeroMemory(expectedOwner);
        }
    }

    private static ProductionMailboxLocalOwnerBundle FreezeLocalOwnerBundle(
        ProductionMailboxLocalOwnerBundle bundle)
    {
        byte[] encoded;
        try
        {
            encoded = ProductionMailboxLocalOwnerJournalCodec.Encode(bundle);
        }
        catch (Exception exception) when (exception is InvalidDataException or
            ArgumentException or InvalidOperationException or OverflowException)
        {
            throw new InvalidDataException(
                "Registry LocalOwner bundle is malformed or outside its bounds.", exception);
        }
        try
        {
            return ProductionMailboxLocalOwnerJournalCodec.Decode(encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static ProductionMailboxPeerDepositBundle FreezePeerDepositBundle(
        ProductionMailboxPeerDepositBundle bundle)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(bundle.ControlPlane);
            Require(bundle.Selections is { Count: 2 } && bundle.Grants is { Count: 2 },
                "Registry PeerDeposit requires exact current/next selections and grants.");
            Require(bundle.HolderEd25519PublicKey.Length == 32 &&
                    bundle.RecipientEd25519PublicKey.Length == 32 &&
                    bundle.MailboxOwnerEd25519PublicKey.Length == 32 &&
                    bundle.IdempotencyKey.Length == 32 &&
                    bundle.BlindedMailboxId.Length == 32 &&
                    bundle.BlindedPlacementId.Length == 32 &&
                    bundle.SelectionInputCommitment.Length == 32 &&
                    bundle.RouteAdvertisementSha256.Length == 32,
                "Registry PeerDeposit fixed fields have invalid lengths.");
            Require(bundle.CanonicalRouteAdvertisement.Length ==
                    ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength,
                "Registry PeerDeposit PRA1 has an invalid length.");
            var selections = bundle.Selections.Select(static binding =>
            {
                ArgumentNullException.ThrowIfNull(binding);
                Require(binding.CanonicalSelection.Length is >= 410 and <=
                        ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes &&
                        binding.Replicas is { Count: 2 },
                    "Registry PeerDeposit PMS1 envelope is outside strict bounds.");
                return new ProductionMailboxSelectionBinding(
                    binding.Epoch,
                    binding.Generation,
                    binding.CanonicalSelection.ToArray(),
                    binding.Replicas.Select(static replica =>
                    {
                        ArgumentNullException.ThrowIfNull(replica);
                        Require(replica.ReplicaId.Length == 32 &&
                                replica.CurrentSpkiSha256.Length == 32 &&
                                replica.NextSpkiSha256.Length == 32 &&
                                replica.HttpsEndpoint is not null &&
                                replica.HttpsEndpoint.OriginalString.Length <=
                                ProductionMailboxAuthorityConstants.MaximumEndpointLength,
                            "Registry PeerDeposit replica envelope is outside strict bounds.");
                        return new ProductionMailboxReplicaBinding(
                            replica.ReplicaId.ToArray(),
                            replica.HttpsEndpoint!,
                            replica.CurrentSpkiSha256.ToArray(),
                            replica.NextSpkiSha256.ToArray());
                    }).ToArray());
            }).ToArray();
            var grants = bundle.Grants.Select(static binding =>
            {
                ArgumentNullException.ThrowIfNull(binding);
                Require(binding.CanonicalGrant.Length ==
                        MailboxAuthenticatedCapabilityLimits.GrantLength,
                    "Registry PeerDeposit MCG2 envelope has an invalid length.");
                return new ProductionMailboxGrantBinding(
                    binding.Domain,
                    binding.Epoch,
                    binding.Generation,
                    binding.CanonicalGrant.ToArray());
            }).ToArray();
            return new ProductionMailboxPeerDepositBundle(
                bundle.HolderEd25519PublicKey.ToArray(),
                bundle.RecipientEd25519PublicKey.ToArray(),
                bundle.MailboxOwnerEd25519PublicKey.ToArray(),
                bundle.IdempotencyKey.ToArray(),
                bundle.BlindedMailboxId.ToArray(),
                bundle.BlindedPlacementId.ToArray(),
                bundle.SelectionInputCommitment.ToArray(),
                new ProductionMailboxControlPlaneArtifacts(
                    BoundedCopy(
                        bundle.ControlPlane.CanonicalAuthority,
                        821,
                        ProductionMailboxAuthorityConstants.MaximumArtifactBytes,
                        "PMA1"),
                    BoundedCopy(
                        bundle.ControlPlane.CanonicalRevocationSnapshot,
                        ProductionMailboxRevocationSnapshotConstants
                            .FixedArtifactBytesWithoutSerials,
                        ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes,
                        "PMR1"),
                    BoundedCopy(
                        bundle.ControlPlane.CanonicalTopology,
                        780,
                        ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes,
                        "PMT1"),
                    BoundedCopy(
                        bundle.ControlPlane.CanonicalCurrentSelection,
                        410,
                        ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes,
                        "current PMS1"),
                    BoundedCopy(
                        bundle.ControlPlane.CanonicalNextSelection,
                        410,
                        ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes,
                        "next PMS1")),
                selections,
                grants,
                bundle.CanonicalRouteAdvertisement.ToArray(),
                bundle.RouteAdvertisementSha256.ToArray(),
                bundle.IssuedAtUnixSeconds,
                bundle.ExpiresAtUnixSeconds);
        }
        catch (Exception exception) when (exception is InvalidDataException or
            ArgumentException or InvalidOperationException or OverflowException)
        {
            throw new InvalidDataException(
                "Registry PeerDeposit bundle is malformed or outside its bounds.",
                exception);
        }
    }

    private static byte[] BoundedCopy(
        ReadOnlyMemory<byte> value,
        int minimumLength,
        int maximumLength,
        string label)
    {
        Require(value.Length >= minimumLength && value.Length <= maximumLength,
            $"Registry PeerDeposit {label} is outside strict bounds.");
        return value.ToArray();
    }

    private static ProductionMailboxClientApprovalIdentity FreezeClientIdentity(
        ProductionMailboxClientApprovalIdentity identity)
    {
        if (!Enum.IsDefined(identity.Platform) ||
            string.IsNullOrWhiteSpace(identity.ApplicationIdentity) ||
            identity.ApplicationIdentity.Length > 256 ||
            identity.SigningCertificateSha256.Length != 32 ||
            identity.SigningCertificateSha256.Span.IndexOfAnyExcept((byte)0) < 0 ||
            identity.BuildArtifactSha256.Length != 32 ||
            identity.BuildArtifactSha256.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException(
                "Production mailbox client approval identity is invalid.");
        return new ProductionMailboxClientApprovalIdentity(
            identity.Platform,
            identity.ApplicationIdentity,
            identity.SigningCertificateSha256.ToArray(),
            identity.BuildArtifactSha256.ToArray());
    }

    private sealed class FixedUnixTimeProvider(ulong unixSeconds) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.FromUnixTimeSeconds(checked((long)unixSeconds));
    }

    private static VerifiedRouteClosure VerifyRouteClosure(
        ProductionMailboxLocalOwnerBundle bundle,
        VerifiedProductionMailboxControlPlane verified,
        ReadOnlySpan<byte> holderKey,
        ReadOnlySpan<byte> ownerKey,
        ReadOnlySpan<byte> mailbox,
        ReadOnlySpan<byte> placement,
        ReadOnlySpan<byte> selectionCommitment,
        ProductionMailboxClientApprovalIdentity clientIdentity,
        ulong verifiedAtUnixSeconds,
        ProductionMailboxRuntimePublicationJournal? persistedJournal)
    {
        var certificateBytes = bundle.CanonicalRouteCertificate.ToArray();
        var advertisementBytes = bundle.CanonicalRouteAdvertisement.ToArray();
        try
        {
            Require(certificateBytes.Length ==
                    ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength &&
                    advertisementBytes.Length ==
                    ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength,
                "Registry LocalOwner route closure is incomplete.");
            var certificateHash = SHA256.HashData(certificateBytes);
            var advertisementHash = SHA256.HashData(advertisementBytes);
            Require(Fixed(certificateHash, bundle.RouteCertificateSha256.Span) &&
                    Fixed(advertisementHash, bundle.RouteAdvertisementSha256.Span),
                "Registry route envelope hash differs from its canonical bytes.");

            var decodedCertificate = ProductionMailboxRouteAdvertisementCodec
                .DecodeCertificate(certificateBytes);
            Require(Fixed(decodedCertificate.MailboxOwnerEd25519PublicKey.Span, ownerKey) &&
                    Fixed(decodedCertificate.BlindedMailboxId.Span, mailbox) &&
                    Fixed(decodedCertificate.BlindedPlacementId.Span, placement) &&
                    Fixed(decodedCertificate.SelectionInputCommitment.Span,
                        selectionCommitment),
                "Registry PRC1 route differs from the LocalOwner response.");
            var certificate = ProductionMailboxRouteCertificateVerifier.Verify(
                certificateBytes,
                verified.Authority,
                verifiedAtUnixSeconds,
                0,
                new SodiumProductionMailboxRouteSignatureVerifier());
            var routeDomain = ProductionMailboxRouteAdvertisementCodec
                .ComputeRouteDomainHash(certificate.Certificate);

            var lastSequence = persistedJournal?.RouteAdvertisementSequence ?? 0;
            var lastHash = persistedJournal is null
                ? new byte[32]
                : DecodeLowerHex32(
                    persistedJournal.RouteAdvertisementSha256,
                    "persisted route advertisement hash");
            if (persistedJournal is not null)
            {
                Require(Fixed(certificateHash,
                            DecodeLowerHex32(persistedJournal.RouteCertificateSha256,
                                "persisted route certificate hash")) &&
                        Fixed(advertisementHash, lastHash) &&
                        Fixed(routeDomain,
                            DecodeLowerHex32(persistedJournal.RouteDomainSha256,
                                "persisted route domain hash")),
                    "Persisted route journal differs from its canonical closure.");
            }
            var advertisement = ProductionMailboxRouteAdvertisementVerifier.Verify(
                advertisementBytes,
                verified.Authority,
                new ProductionMailboxRouteAdvertisementVerificationContext
                {
                    NowUnixSeconds = verifiedAtUnixSeconds,
                    ClockSkewSeconds = 0,
                    ExpectedRouteDomainHash = routeDomain,
                    LastAcceptedSequence = lastSequence,
                    LastAcceptedAdvertisementHash = lastHash
                },
                new SodiumProductionMailboxRouteSignatureVerifier());
            Require(Fixed(
                    ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                        advertisement.Advertisement.Certificate),
                    certificateBytes),
                "Registry PRA1 embeds a different PRC1 certificate.");
            Require(persistedJournal is null ||
                    advertisement.NextAcceptedSequence ==
                        persistedJournal.RouteAdvertisementSequence,
                "Persisted PRA1 sequence differs from its journal.");

            Span<byte> zeros = stackalloc byte[32];
            var expectedIdempotency = ProductionMailboxIssuanceIdempotency.Compute(
                SHA256.HashData(bundle.ControlPlane.CanonicalAuthority.Span),
                SHA256.HashData(bundle.ControlPlane.CanonicalRevocationSnapshot.Span),
                SHA256.HashData(bundle.ControlPlane.CanonicalTopology.Span),
                holderKey,
                ownerKey,
                zeros,
                zeros,
                zeros,
                ProductionMailboxIssuanceIntent.LocalOwner,
                clientIdentity.Platform switch
                {
                    MailboxClientPlatform.Android => ProductionMailboxClientPlatform.Android,
                    MailboxClientPlatform.Windows => ProductionMailboxClientPlatform.Windows,
                    _ => throw new InvalidDataException(
                        "Registry LocalOwner client platform is invalid.")
                },
                clientIdentity.SigningCertificateSha256.Span,
                clientIdentity.BuildArtifactSha256.Span,
                zeros);
            Require(Fixed(expectedIdempotency, bundle.IdempotencyKey.Span),
                "Registry LocalOwner idempotency key is not bound to its issuance request.");
            return new VerifiedRouteClosure(
                certificateHash,
                advertisementHash,
                routeDomain,
                advertisement.NextAcceptedSequence,
                certificate.Certificate.ExpiresAtUnixSeconds,
                advertisement.Advertisement.ExpiresAtUnixSeconds);
        }
        catch (ProductionMailboxRouteAdvertisementException exception)
        {
            throw new InvalidDataException(
                "Registry LocalOwner route closure failed verification.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(certificateBytes);
            CryptographicOperations.ZeroMemory(advertisementBytes);
        }
    }

    private static VerifiedRouteClosure VerifyPeerRouteClosure(
        ProductionMailboxPeerDepositBundle bundle,
        VerifiedProductionMailboxControlPlane verified,
        ReadOnlySpan<byte> ownerKey,
        ReadOnlySpan<byte> mailbox,
        ReadOnlySpan<byte> placement,
        ReadOnlySpan<byte> selectionCommitment,
        ProductionMailboxClientApprovalIdentity clientIdentity,
        ulong verifiedAtUnixSeconds)
    {
        var advertisementBytes = bundle.CanonicalRouteAdvertisement.ToArray();
        try
        {
            Require(advertisementBytes.Length ==
                    ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength,
                "Registry PeerDeposit route closure is incomplete.");
            var advertisementHash = SHA256.HashData(advertisementBytes);
            Require(Fixed(advertisementHash, bundle.RouteAdvertisementSha256.Span),
                "Registry PRA1 envelope hash differs from its canonical bytes.");

            var decoded = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(
                advertisementBytes);
            var certificateBytes = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                decoded.Certificate);
            var certificateHash = SHA256.HashData(certificateBytes);
            Require(Fixed(decoded.Certificate.MailboxOwnerEd25519PublicKey.Span, ownerKey) &&
                    Fixed(decoded.Certificate.BlindedMailboxId.Span, mailbox) &&
                    Fixed(decoded.Certificate.BlindedPlacementId.Span, placement) &&
                    Fixed(decoded.Certificate.SelectionInputCommitment.Span,
                        selectionCommitment),
                "Registry PRA1 route differs from the authenticated contact route.");
            var certificate = ProductionMailboxRouteCertificateVerifier.Verify(
                certificateBytes,
                verified.Authority,
                verifiedAtUnixSeconds,
                0,
                new SodiumProductionMailboxRouteSignatureVerifier());
            var routeDomain = ProductionMailboxRouteAdvertisementCodec
                .ComputeRouteDomainHash(certificate.Certificate);
            var advertisement = ProductionMailboxRouteAdvertisementVerifier.Verify(
                advertisementBytes,
                verified.Authority,
                new ProductionMailboxRouteAdvertisementVerificationContext
                {
                    NowUnixSeconds = verifiedAtUnixSeconds,
                    ClockSkewSeconds = 0,
                    ExpectedRouteDomainHash = routeDomain,
                    LastAcceptedSequence = 0,
                    LastAcceptedAdvertisementHash = new byte[32]
                },
                new SodiumProductionMailboxRouteSignatureVerifier());
            Require(Fixed(
                    ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                        advertisement.Advertisement.Certificate),
                    certificateBytes),
                "Registry PRA1 embeds a different PRC1 certificate.");

            Span<byte> zeros = stackalloc byte[32];
            var expectedIdempotency = ProductionMailboxIssuanceIdempotency.Compute(
                SHA256.HashData(bundle.ControlPlane.CanonicalAuthority.Span),
                SHA256.HashData(bundle.ControlPlane.CanonicalRevocationSnapshot.Span),
                SHA256.HashData(bundle.ControlPlane.CanonicalTopology.Span),
                bundle.HolderEd25519PublicKey.Span,
                ownerKey,
                mailbox,
                placement,
                selectionCommitment,
                ProductionMailboxIssuanceIntent.PeerDeposit,
                clientIdentity.Platform switch
                {
                    MailboxClientPlatform.Android => ProductionMailboxClientPlatform.Android,
                    MailboxClientPlatform.Windows => ProductionMailboxClientPlatform.Windows,
                    _ => throw new InvalidDataException(
                        "Registry PeerDeposit client platform is invalid.")
                },
                clientIdentity.SigningCertificateSha256.Span,
                clientIdentity.BuildArtifactSha256.Span,
                zeros);
            Require(Fixed(expectedIdempotency, bundle.IdempotencyKey.Span),
                "Registry PeerDeposit idempotency key is not bound to its issuance request.");
            return new VerifiedRouteClosure(
                certificateHash,
                advertisementHash,
                routeDomain,
                advertisement.NextAcceptedSequence,
                certificate.Certificate.ExpiresAtUnixSeconds,
                advertisement.Advertisement.ExpiresAtUnixSeconds);
        }
        catch (ProductionMailboxRouteAdvertisementException exception)
        {
            throw new InvalidDataException(
                "Registry PeerDeposit route closure failed verification.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(advertisementBytes);
        }
    }

    private static byte[] DecodeLowerHex32(string value, string label)
    {
        if (value is null || value.Length != 64 || value.Any(static character =>
                character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new InvalidDataException($"Registry {label} is invalid.");
        return Convert.FromHexString(value);
    }

    private static byte[] UInt64Bytes(ulong value)
    {
        var encoded = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        return encoded;
    }

    private static bool IsPersistedCorruption(Exception exception) =>
        exception is InvalidDataException or CryptographicException or
            ProductionMailboxRouteAdvertisementException;

    private sealed record VerifiedRouteClosure(
        byte[] CertificateHash,
        byte[] AdvertisementHash,
        byte[] RouteDomainHash,
        ulong Sequence,
        ulong CertificateExpiresAtUnixSeconds,
        ulong AdvertisementExpiresAtUnixSeconds);

    private static string PublicationJournalKey(MailboxHolderIdentity holder) =>
        "deep.mailbox.production-local-owner.v1:" + holder.SessionId.Value +
        ":publication-v1";

    private static string ActiveBundleKey(MailboxHolderIdentity holder) =>
        "deep.mailbox.production-local-owner.v1:" + holder.SessionId.Value +
        ":active-public-bundle-v1";

    private static async Task CommitTrustStateRecoveringAmbiguousOutcomeAsync(
        VerifiedProductionMailboxControlPlane verified,
        IProductionMailboxTrustStateStore trustStateStore,
        CancellationToken cancellationToken)
    {
        try
        {
            await ProductionMailboxControlPlaneVerifier.CommitAsync(
                verified, trustStateStore, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception commitException)
        {
            ProductionMailboxTrustState? observed;
            try
            {
                observed = await trustStateStore.ReadAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch
            {
                throw commitException;
            }
            if (!TrustStateEquals(observed, verified.StateToCommit))
                throw;
        }
    }

    private static bool TrustStateEquals(
        ProductionMailboxTrustState? left,
        ProductionMailboxTrustState right)
    {
        if (left is null) return false;
        var leftBytes = ProductionMailboxTrustStateCodec.Encode(left);
        var rightBytes = ProductionMailboxTrustStateCodec.Encode(right);
        try
        {
            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static DecodedGrant DecodeGrant(ProductionMailboxGrantBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        var bytes = binding.CanonicalGrant.ToArray();
        try
        {
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(bytes);
            Require(Fixed(bytes, MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)) &&
                    binding.Domain == grant.Domain && binding.Epoch == grant.Epoch &&
                    binding.Generation == grant.Generation,
                "Registry MCG2 envelope differs from its canonical grant.");
            return new DecodedGrant(binding, grant);
        }
        catch (MailboxAuthenticatedCapabilityException exception)
        {
            throw new InvalidDataException("Registry MCG2 is malformed.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void ValidateGrant(
        DecodedGrant decoded,
        MailboxCapabilityDomain expectedDomain,
        ReadOnlySpan<byte> holder,
        ProductionMailboxAuthority authority,
        ProductionMailboxTopologyEpoch epoch,
        BlindedPlacementId placement,
        string lane)
    {
        var grant = decoded.Grant;
        Require(grant.Domain == expectedDomain &&
                grant.Lifecycle == MailboxCapabilityLifecycle.Active &&
                grant.OverlapUntilUnixSeconds == 0 &&
                grant.Epoch == epoch.Epoch && grant.Generation == epoch.Generation &&
                grant.NotBeforeUnixSeconds == epoch.NotBeforeUnixSeconds &&
                grant.ExpiresAtUnixSeconds == epoch.NotAfterUnixSeconds &&
                Fixed(grant.NetworkId.Span, authority.NetworkId.Span) &&
                Fixed(grant.HolderPublicKey.Span, holder) &&
                Fixed(grant.IssuerPublicKey.Span,
                    authority.MailboxIssuerEd25519PublicKey.Span) &&
                Fixed(grant.PlacementCommitment.Span,
                    MailboxPlacementCommitment.Compute(placement)) &&
                Fixed(grant.MembershipCommitment.Span,
                    epoch.MembershipCommitment.Span) &&
                new SodiumMailboxCapabilityCrypto().VerifyIssuer(
                    grant.IssuerPublicKey.Span,
                    MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant),
                    grant.IssuerSignature.Span),
            $"Registry {lane} grant is not bound to the verified control plane.");
    }

    private static void ValidateSelectionBinding(
        ProductionMailboxSelectionBinding binding,
        VerifiedProductionMailboxSelection verified)
    {
        ArgumentNullException.ThrowIfNull(binding);
        var proof = verified.Proof;
        Require(binding.Epoch == proof.Epoch && binding.Generation == proof.Generation &&
                Fixed(binding.CanonicalSelection.Span,
                    ProductionMailboxTopologyCodec.EncodeSelection(proof)) &&
                binding.Replicas is { Count: 2 } && verified.Replicas.Count == 2,
            "Registry PMS1 envelope differs from its verified selection.");
        for (var index = 0; index < 2; index++)
        {
            var actual = binding.Replicas[index];
            var expected = verified.Replicas[index];
            Require(actual is not null && actual.HttpsEndpoint == expected.HttpsEndpoint &&
                    Fixed(actual.ReplicaId.Span, expected.ReplicaId.Span) &&
                    Fixed(actual.CurrentSpkiSha256.Span,
                        expected.CurrentSpkiSha256.Span) &&
                    Fixed(actual.NextSpkiSha256.Span,
                        expected.NextSpkiSha256.Span),
                "Registry replica envelope differs from its verified MIP1 route.");
        }
    }

    private static IReadOnlyList<MailboxCapabilityIssuerAuthority> IssuerAuthorities(
        ReadOnlyMemory<byte> issuer,
        ProductionMailboxTopologySnapshot topology) =>
    [
        IssuerAuthority(MailboxCapabilityDomain.Deposit, issuer, topology),
        IssuerAuthority(MailboxCapabilityDomain.Retrieve, issuer, topology)
    ];

    private static MailboxCapabilityIssuerAuthority IssuerAuthority(
        MailboxCapabilityDomain domain,
        ReadOnlyMemory<byte> issuer,
        ProductionMailboxTopologySnapshot topology) => new()
    {
        PublicKey = issuer.ToArray(),
        Domain = domain,
        AllowedLifecycle = MailboxCapabilityLifecycle.Active,
        MinimumGeneration = topology.CurrentEpoch.Generation,
        MaximumGeneration = topology.NextEpoch.Generation,
        ValidFromUnixSeconds = topology.CurrentEpoch.NotBeforeUnixSeconds,
        ValidUntilUnixSeconds = topology.NextEpoch.NotAfterUnixSeconds
    };

    private static MailboxCredentialEpoch ToEpoch(
        ProductionMailboxTopologyEpoch epoch,
        BlindedPlacementId placement) => new(
            epoch.Epoch,
            epoch.NotBeforeUnixSeconds,
            epoch.NotAfterUnixSeconds,
            epoch.MembershipCommitment.Span,
            placement.Bytes.Span,
            MailboxPlacementCommitment.Compute(placement));

    private static MailboxCredentialReplicaPair ReplicaPair(
        VerifiedProductionMailboxSelection selection) => new(
            selection.Replicas[0].ReplicaId.Span,
            MailboxPeerReplicationCodec.DecodeMembershipProof(
                selection.Replicas[0].CanonicalMIP1Proof.Span).SigningPublicKey.Span,
            selection.Replicas[1].ReplicaId.Span,
            MailboxPeerReplicationCodec.DecodeMembershipProof(
                selection.Replicas[1].CanonicalMIP1Proof.Span).SigningPublicKey.Span);

    private static string[] BuildRevocationKeys(
        IReadOnlyList<ReadOnlyMemory<byte>> serials,
        ReadOnlySpan<byte> issuer,
        ProductionMailboxTopologySnapshot topology)
    {
        var values = new List<string>(checked(serials.Count * 4));
        foreach (var serial in serials)
        foreach (var domain in new[]
                 { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
        foreach (var epoch in new[] { topology.CurrentEpoch, topology.NextEpoch })
        {
            values.Add(DurableMailboxRevocationSnapshot.Key(
                issuer,
                serial.Span,
                domain,
                epoch.Generation,
                epoch.Epoch,
                epoch.MembershipCommitment.Span));
        }
        return values.Distinct(StringComparer.Ordinal)
            .OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    }

    private static SessionId SessionIdFromEd25519(ReadOnlySpan<byte> ed25519)
    {
        var curve = Sodium.PublicKeyAuth
            .ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519.ToArray());
        try
        {
            return new SessionId(
                $"05{Convert.ToHexString(curve).ToLowerInvariant()}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(curve);
        }
    }

    private static byte[] DomainHash(
        ReadOnlySpan<byte> domain,
        params ReadOnlyMemory<byte>[] values)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain);
        foreach (var value in values) hash.AppendData(value.Span);
        return hash.GetHashAndReset();
    }

    private static byte[] ExactNonzero(ReadOnlySpan<byte> value, int length, string label)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"Registry {label} is invalid.");
        return value.ToArray();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }

    private sealed record DecodedGrant(
        ProductionMailboxGrantBinding Binding,
        MailboxAuthenticatedGrant Grant);
}
