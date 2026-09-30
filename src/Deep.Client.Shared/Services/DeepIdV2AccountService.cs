using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Registry;
using Deep.Protocol.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Client.Shared.Persistence.XPointNetworkV1;

namespace Deep.Client.Shared.Services;

/// <summary>Exact public bytes released only from a verified DID2 account
/// and its protected-tip-verified pre-key inventory. No private DPK2 leaves
/// the account owner.</summary>
public sealed class StagedDeepIdV2PreKeyPublication
{
    private readonly byte[] xpp;
    private readonly byte[] did;
    private readonly byte[] dca;
    private readonly byte[] xps;

    internal StagedDeepIdV2PreKeyPublication(ReadOnlySpan<byte> exactXpp1,
        ReadOnlySpan<byte> exactDid2, ReadOnlySpan<byte> exactDca1,
        ReadOnlySpan<byte> exactXps1)
    {
        xpp = exactXpp1.ToArray();
        did = exactDid2.ToArray();
        dca = exactDca1.ToArray();
        xps = exactXps1.ToArray();
    }

    public ReadOnlyMemory<byte> ExactXpp1 => xpp.ToArray();
    public ReadOnlyMemory<byte> ExactDid2 => did.ToArray();
    public ReadOnlyMemory<byte> ExactDca1 => dca.ToArray();
    public ReadOnlyMemory<byte> ExactXps1 => xps.ToArray();
}

/// <summary>Durable evidence of a two-replica DID2 pre-key publication.
/// A current placement and claim must still be verified independently.</summary>
public sealed class DeepIdV2PreKeyCommitSnapshot
{
    private readonly byte[] first;
    private readonly byte[] second;

    internal DeepIdV2PreKeyCommitSnapshot(ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second)
    {
        this.first = first.ToArray();
        this.second = second.ToArray();
    }

    public ReadOnlyMemory<byte> ExactFirstXic1 => first.ToArray();
    public ReadOnlyMemory<byte> ExactSecondXic1 => second.ToArray();
}

/// <summary>
/// DID2 account entry point for a single private device store. Local creation
/// is network-free; network operations require independently verified authority.
/// It never reads or migrates the incompatible STORE-V1 namespace.
/// </summary>
public sealed class DeepIdV2AccountService
{
    private readonly ProtectedDeepIdV2AccountOwner owner;
    private readonly IClock clock;
    private readonly ushort deploymentProfileId;
    private readonly Func<IDeepMlDsa65VerifierLease> verifierFactory;
    private readonly SemaphoreSlim initialPreKeyGate = new(1, 1);

    public DeepIdV2AccountService(IDeepSecureStorage storage,
        string privateDirectory, ReadOnlySpan<byte> networkId,
        ushort deploymentProfileId, IClock clock,
        Func<IDeepMlDsa65VerifierLease> verifierFactory)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateDirectory);
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.deploymentProfileId = deploymentProfileId;
        this.verifierFactory = verifierFactory ??
            throw new ArgumentNullException(nameof(verifierFactory));
        var directory = Path.GetFullPath(privateDirectory);
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException(
                "The DID2 account requires an existing private directory.");
        owner = new ProtectedDeepIdV2AccountOwner(storage,
            new DeepIdV2AccountFileLease(Path.Combine(directory,
                "deep-store-v2-account.lock")),
            Path.Combine(directory, "deep-store-v2-account.dsv2"),
            networkId, deploymentProfileId);
    }

    public async Task<DeepIdV2AccountSnapshot?> GetCurrentAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        var trustedUnixSeconds = TrustedUnixSeconds();
        using var current = await owner.ReadCurrentAsync(trustedUnixSeconds,
            verifier, cancellationToken).ConfigureAwait(false);
        return current is null ? null : Snapshot(current);
    }

    /// <summary>
    /// Opens only the verified local device's DPH2 agreement capability.
    /// The caller must dispose it; each use still requires an exact current,
    /// unforked directory lineage and a purpose-bound one-shot operation.
    /// No V1 account state or raw private key is returned.
    /// </summary>
    public async Task<LocalDeviceX25519AgreementAuthority>
        OpenLocalDeviceAgreementAuthorityAsync(
            CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        using var current = await owner.ReadCurrentAsync(TrustedUnixSeconds(),
            verifier, cancellationToken).ConfigureAwait(false) ??
            throw new InvalidOperationException(
                "A verified DID2 account is required for device agreement.");
        var relativeDevices = current.Verified.PublicEvidence.Binding.Identity
            .ActiveDeviceRelatives;
        if (relativeDevices.Count != 1)
            throw new CryptographicException(
                "The local DID2 genesis does not have one exact verified device relative.");
        return current.Verified.DeviceSecrets.CreateAgreementAuthority(
            relativeDevices[0]);
    }

    /// <summary>
    /// Installs the exact, locally verified DID2 genesis DMD1 into the durable
    /// current-device authority store. A caller cannot supply a DMD1 or a
    /// lineage state. Success does not authorize a DPH2 operation: that still
    /// requires the store's separate one-use agreement transaction.
    /// </summary>
    public async Task<ProtectedCurrentDmd1CommitResult>
        CommitOwnGenesisDmd1Async(SqliteDeviceStateStore deviceStore,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(deviceStore);
        using var verifier = OpenVerifier();
        using var current = await owner.ReadCurrentAsync(TrustedUnixSeconds(),
            verifier, cancellationToken).ConfigureAwait(false) ??
            throw new InvalidOperationException(
                "A verified DID2 account is required for device-directory custody.");
        return await DeepIdV2GenesisDmd1Custody.CommitAsync(current,
            deviceStore, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Opens the account-bound encrypted device protocol state and ensures its
    /// exact DID2 genesis DMD1 is durable. The caller owns the returned store.
    /// A protected install marker prevents silent recreation after state loss.
    /// This does not by itself authorize a device agreement operation.
    /// </summary>
    public async Task<SqliteDeviceStateStore> OpenCurrentDeviceStateStoreAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        return await owner.OpenCurrentDeviceStateStoreAsync(
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Opens local account/instance-bound ONION guards and durable
    /// entropy reservations. This releases no device scalar or network authority.</summary>
    public async Task<DeepIdV2OnionClientCustody> OpenOwnOnionClientCustodyAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        return await owner.OpenOnionCustodyAsync(TrustedUnixSeconds(), verifier,
            this, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<DeepIdV2ClaimRequestCustody> OpenOwnClaimRequestCustodyAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        return await owner.OpenClaimRequestCustodyAsync(TrustedUnixSeconds(),
            verifier, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts the DID2-only pre-XPK1 initiator claim from this protected
    /// account and an independently verified, still-current directory proof.
    /// No private agreement operation is spent until an exact DPK2 is known.
    /// </summary>
    public async Task<InitiatorDph2PreKeyClaim> BeginOwnDph2ClaimAsync(
        DeepIdV2DirectoryProofClient proofClient,
        VerifiedXPointNetworkAuthority networkAuthority,
        VerifiedDeepIdV2DirectoryFreshness currentProof,
        ReadOnlyMemory<byte> currentBootId, ulong currentMonotonicSample,
        int maximumMessagesWithoutPqInjection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proofClient);
        await proofClient.RequireStillFreshAsync(currentProof,
            networkAuthority, cancellationToken).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        using var current = await owner.ReadCurrentAsync(TrustedUnixSeconds(),
            verifier, cancellationToken).ConfigureAwait(false) ??
            throw new InvalidOperationException(
                "A verified DID2 account is required for DPH2 initiation.");
        var directory = RequireOwnCurrentDirectory(current, currentProof,
            currentBootId.Span, currentMonotonicSample);
        await proofClient.RequireStillFreshAsync(currentProof,
            networkAuthority, cancellationToken).ConfigureAwait(false);
        using var authority = OwnAgreementAuthority(current);
        return new ManagedInitiatorInitialSessionFactory(
            maximumMessagesWithoutPqInjection).BeginClaim(
                authority, directory, currentProof, currentBootId.Span,
                currentMonotonicSample);
    }

    /// <summary>
    /// Burns the exact claim operation in the protected current-DMD1 store and
    /// consumes its one-shot DH lease inside Protocol. Neither the scalar nor
    /// the lease is returned to MAUI. The resulting preparation is still not
    /// a sent DPH2, an accepted contact or a delivery acknowledgement.
    /// </summary>
    public async Task<InitiatorDph2ClaimPreparation> CompleteOwnDph2ClaimAsync(
        InitiatorDph2PreKeyClaim startedClaim,
        ReadOnlyMemory<byte> exactDpk2,
        DeepIdV2DirectoryProofClient proofClient,
        VerifiedXPointNetworkAuthority networkAuthority,
        VerifiedDeepIdV2DirectoryFreshness currentProof,
        VerifiedDeepIdV2DirectoryFreshness currentPeerProof,
        ReadOnlyMemory<byte> currentBootId, ulong currentMonotonicSample,
        int maximumMessagesWithoutPqInjection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(startedClaim);
        ArgumentNullException.ThrowIfNull(proofClient);
        await proofClient.RequireStillFreshAsync(currentProof,
            networkAuthority, cancellationToken).ConfigureAwait(false);
        await proofClient.RequireStillFreshAsync(currentPeerProof,
            networkAuthority, cancellationToken).ConfigureAwait(false);
        var verifiedOffering = DeepIdV2Dpk2PreClaimVerifier.Verify(
            exactDpk2.Span, currentPeerProof, currentBootId.Span,
            currentMonotonicSample);
        using var verifier = OpenVerifier();
        using var current = await owner.ReadCurrentAsync(TrustedUnixSeconds(),
            verifier, cancellationToken).ConfigureAwait(false) ??
            throw new InvalidOperationException(
                "A verified DID2 account is required for DPH2 completion.");
        var directory = RequireOwnCurrentDirectory(current, currentProof,
            currentBootId.Span, currentMonotonicSample);
        if (!Fixed(startedClaim.NetworkId.Span,
                current.Verified.PublicEvidence.Binding.Identity.Account
                    .Certificate.NetworkId.Span) ||
            !Fixed(verifiedOffering.NetworkId.Span, startedClaim.NetworkId.Span))
            throw new CryptographicException(
                "The DPH2 claim or offering belongs to another network.");
        using var authority = OwnAgreementAuthority(current);
        startedClaim.RequireCurrentInitiator(authority, directory,
            currentProof, currentBootId.Span, currentMonotonicSample);
        using var store = await OpenCurrentDeviceStateStoreAsync(
            cancellationToken).ConfigureAwait(false);
        await proofClient.RequireStillFreshAsync(currentProof,
            networkAuthority, cancellationToken).ConfigureAwait(false);
        await proofClient.RequireStillFreshAsync(currentPeerProof,
            networkAuthority, cancellationToken).ConfigureAwait(false);
        var operation = startedClaim.ClaimOperationId;
        var authorized = await ProtectedDeviceAgreementLeaseIssuer
            .AuthorizeAndRedeemAsync(store,
                DeviceOperationId32.FromBytes(operation.Span), directory,
                authority, LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                operation, verifiedOffering.InitiatorAgreementPeerPublicKey,
                cancellationToken).ConfigureAwait(false);
        if (authorized.Disposition != ProtectedDeviceAgreementDisposition.Granted ||
            authorized.Lease is null)
            throw new CryptographicException(
                "The protected DID2 device agreement was not authorized.");
        using var lease = authorized.Lease;
        return new ManagedInitiatorInitialSessionFactory(
            maximumMessagesWithoutPqInjection).CompleteClaim(
                startedClaim, verifiedOffering, lease);
    }

    private static Dmd1LineageState RequireOwnCurrentDirectory(
        VerifiedDeepIdV2CurrentAccount current,
        VerifiedDeepIdV2DirectoryFreshness proof,
        ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(proof);
        var local = current.Verified.PublicEvidence;
        var checkpoint = proof.CurrentCheckpoint;
        if (proof.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue ||
            checkpoint is null ||
            !proof.IsCurrentAtMonotonic(currentBootId,
                currentMonotonicSample) ||
            !Fixed(checkpoint.Binding.Record.CanonicalBytes.Span,
                local.Binding.Record.CanonicalBytes.Span) ||
            !Fixed(checkpoint.Directory.Record.CanonicalBytes.Span,
                local.Directory.Record.CanonicalBytes.Span))
            throw new CryptographicException(
                "The current DID2 proof does not bind this exact local account and DMD1.");
        return ApplicationCoreVerifier.StartDmd1Lineage(local.Directory).Next;
    }

    private static LocalDeviceX25519AgreementAuthority OwnAgreementAuthority(
        VerifiedDeepIdV2CurrentAccount current)
    {
        var relatives = current.Verified.PublicEvidence.Binding.Identity
            .ActiveDeviceRelatives;
        if (relatives.Count != 1)
            throw new CryptographicException(
                "The DID2 account does not have one verified local device.");
        return current.Verified.DeviceSecrets.CreateAgreementAuthority(
            relatives[0]);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    /// <summary>
    /// Opens a DPK2 author for the exact verified DID2 genesis device.
    /// Authoring an offering still requires a caller-supplied current,
    /// unforked DMD1 lineage; this method grants no publication authority.
    /// </summary>
    public async Task<Dpk2AuthoringAuthority> OpenLocalPreKeyAuthoringAuthorityAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        using var current = await owner.ReadCurrentAsync(TrustedUnixSeconds(),
            verifier, cancellationToken).ConfigureAwait(false) ??
            throw new InvalidOperationException(
                "A verified DID2 account is required for prekey authoring.");
        var relativeDevices = current.Verified.PublicEvidence.Binding.Identity
            .ActiveDeviceRelatives;
        if (relativeDevices.Count != 1)
            throw new CryptographicException(
                "The local DID2 genesis does not have one exact verified device relative.");
        return current.Verified.DeviceSecrets.CreateDpk2AuthoringAuthority(
            relativeDevices[0]);
    }

    /// <summary>
    /// Seals the complete first DID2 inventory into account-owned SQLCipher
    /// and records an add-only protected tip before returning. An interrupted
    /// tip is recovered from the exact committed inventory on reopen. The
    /// operation does not publish XPP1 or authorize a remote claim.
    /// </summary>
    public async Task StageOwnInitialPreKeyInventoryAsync(
        AuthoredDeepIdV2PreKeyService service,
        AuthoredDpk2InventoryV2 inventory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(service);
        ArgumentNullException.ThrowIfNull(inventory);
        using var verifier = OpenVerifier();
        await owner.StageOwnInitialPreKeyInventoryAsync(TrustedUnixSeconds(),
            verifier, service, inventory, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Authors and seals the first inventory from fresh account-owned DID2 and
    /// network authority. Retries return the exact protected staged operation,
    /// never replacement keys. No transport dispatch or remote claim is granted.
    /// </summary>
    public async Task<StagedDeepIdV2PreKeyPublication> EnsureOwnInitialPreKeyInventoryAsync(
        DeepIdV2ContactPathAuthoritySource authoritySource,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authoritySource);
        authoritySource.RequireAccountOwner(this);
        await initialPreKeyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var staged = await ReadOwnStagedPreKeyPublicationAsync(cancellationToken).ConfigureAwait(false);
            if (staged is not null) return staged; // Historical exact retry, not live placement authority.
            var fresh = await authoritySource.VerifyForOwnPreKeyAuthoringAsync(this,
                cancellationToken).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            using var current = await owner.ReadCurrentAsync(TrustedUnixSeconds(), verifier,
                cancellationToken).ConfigureAwait(false) ?? throw new InvalidOperationException(
                    "A verified DID2 account is required for initial inventory authoring.");
            var reading = await authoritySource.RecheckOwnPreKeyAuthoringAsync(fresh,
                cancellationToken).ConfigureAwait(false);
            var directory = RequireOwnCurrentDirectory(current, fresh.Proof,
                reading.BootId.Span, reading.SampleSeconds);
            var local = current.Verified.PublicEvidence;
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof,
                local.Authorization, reading.BootId.Span, reading.SampleSeconds);
            var relatives = local.Binding.Identity.ActiveDeviceRelatives;
            if (relatives.Count != 1)
                throw new CryptographicException("Initial inventory requires one exact protected local device.");
            using var author = current.Verified.DeviceSecrets.CreateDpk2AuthoringAuthority(relatives[0]);
            var issued = authorization.TrustedLowerUnixSeconds;
            // Conservative initial policy. Later replenishment is a separate
            // generation operation, never silent replacement on a failed send.
            // ADH1/DTT1 prove that this device is current NOW. Their short
            // refresh windows are not the lifetime of its signed pre-keys.
            // Each remote commit/claim must independently fetch fresh proof;
            // retain the unchanged signed identity/delegation bounds here.
            var expires = Math.Min(checked(issued + 86_400),
                Math.Min(authorization.Authorization.Record.ExpiresAtUnixSeconds,
                    local.Binding.Identity.ActiveDevices.Single().Certificate.ExpiresAtUnixSeconds));
            if (expires <= authorization.TrustedUpperUnixSeconds)
                throw new CryptographicException("Initial inventory cannot cover the authenticated time interval.");
            var context = new Dpk2AuthoringContext(directory, 1, 1, 1, issued, issued, expires);
            var service = author.AuthorPreKeyServiceV2(context, local.Binding, 32, 1);
            var placement = ContactServicePlacementFactory.Create(fresh.Network,
                ContactServiceRequestKind.PublishPreKeyInventory, service.ServiceCapability);
            var drsReference = new byte[38];
            DeepProtocolIdentifiers.MagicBytes.DRS1.CopyTo(drsReference);
            BinaryPrimitives.WriteUInt16BigEndian(drsReference.AsSpan(4), 1);
            local.Binding.Identity.Revocations.Snapshot.CanonicalHash.Span.CopyTo(drsReference.AsSpan(6));
            byte[] operation;
            do { operation = RandomNumberGenerator.GetBytes(32); }
            while (operation.AsSpan().IndexOfAnyExcept((byte)0) < 0);
            cancellationToken.ThrowIfCancellationRequested();
            using var inventory = author.AuthorInventoryV2(context, local.Binding, service,
                drsReference, new byte[32], operation, placement.PlacementHash.Span, 32, 1);
            reading = await authoritySource.RecheckOwnPreKeyAuthoringAsync(fresh,
                cancellationToken).ConfigureAwait(false);
            authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof,
                local.Authorization, reading.BootId.Span, reading.SampleSeconds);
            DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(local.Binding.DeepId,
                service.ExactXps1.Span, authorization,
                DeepIdV2PreKeyPublicationCodec.Decode(inventory.ExactXpp1.Span),
                reading.BootId.Span, reading.SampleSeconds);
            await StageOwnInitialPreKeyInventoryAsync(service, inventory, cancellationToken).ConfigureAwait(false);
            return await ReadOwnStagedPreKeyPublicationAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new CryptographicException("The initial inventory did not become protected staged state.");
        }
        finally { initialPreKeyGate.Release(); }
    }

    public async Task<bool> HasOwnStagedPreKeyInventoryAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        return await owner.HasOwnStagedPreKeyInventoryAsync(
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Reads exact public XPP1 and DID2/DCA1/XPS1 support only after account verification and
    /// protected-tip recovery. It never returns DPK2 secret material and does
    /// not authorize transport dispatch or claim activation by itself.
    /// </summary>
    public async Task<StagedDeepIdV2PreKeyPublication?> ReadOwnStagedPreKeyPublicationAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadOwnStagedPreKeyPublicationAsync(
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Completes publication of the protected exact inventory. A
    /// completed protected pair is reauthenticated against fresh account and
    /// network authority without dispatch; otherwise both current ONION exits
    /// must return verified XIC1 before the pair is recorded. Neither result
    /// grants claim authority or proves present replica availability.</summary>
    public async Task<DeepIdV2PreKeyCommitSnapshot>
        PublishOwnStagedPreKeyInventoryAsync(
            DeepIdV2ContactPathAuthoritySource authoritySource,
            DeepIdV2OnionClientCustody custody,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authoritySource);
        ArgumentNullException.ThrowIfNull(custody);
        authoritySource.RequireAccountOwner(this);
        if (!ReferenceEquals(custody.Owner, this))
            throw new ArgumentException("DID2 publication requires this account's ONION custody.", nameof(custody));
        var staged = await ReadOwnStagedPreKeyPublicationAsync(
            cancellationToken).ConfigureAwait(false) ?? throw new
            InvalidOperationException("No protected DID2 pre-key inventory is staged.");
        // A protected exact retry is durable evidence, not live authority.
        // Reject expired/revoked/changed device support locally before sending
        // even the manifest, using the same independently refreshed proof as
        // authoring rather than wall-clock guesses or extending signed bytes.
        var fresh = await authoritySource.VerifyForOwnPreKeyAuthoringAsync(this,
            cancellationToken).ConfigureAwait(false);
        var checkpoint = fresh.Proof.CurrentCheckpoint ?? throw new CryptographicException(
            "A current DID2 checkpoint is required before pre-key dispatch.");
        var authorization = DeepIdV2ContactAuthorizationCodec.Verify(
            DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span),
            checkpoint.Binding, checkpoint.Directory);
        var reading = await authoritySource.RecheckOwnPreKeyAuthoringAsync(fresh,
            cancellationToken).ConfigureAwait(false);
        var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof,
            authorization, reading.BootId.Span, reading.SampleSeconds);
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
        DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(
            DeepIdV2Codec.DecodeDid2(staged.ExactDid2.Span), staged.ExactXps1.Span,
            current, publication,
            reading.BootId.Span, reading.SampleSeconds);
        var completed = await ReadOwnPreKeyCommitPairAsync(cancellationToken)
            .ConfigureAwait(false);
        if (completed is not null)
        {
            // An add-only completion marker is not a cached live capability.
            // Authenticate its exact signatures, selected replicas and operation
            // against this fresh placement; never silently republish a bad pair.
            var placement = ContactServicePlacementFactory.Create(fresh.Network,
                ContactServiceRequestKind.PublishPreKeyInventory, publication.Manifest.Field(2));
            DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(publication, placement,
                DeepIdV2PreKeyCommitReceiptCodec.Decode(completed.ExactFirstXic1.Span),
                DeepIdV2PreKeyCommitReceiptCodec.Decode(completed.ExactSecondXic1.Span));
            // Protected storage reads may suspend; expiry, cancellation, fork
            // or changed network custody after that read must still reject.
            reading = await authoritySource.RecheckOwnPreKeyAuthoringAsync(fresh,
                cancellationToken).ConfigureAwait(false);
            current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof,
                authorization, reading.BootId.Span, reading.SampleSeconds);
            DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(
                DeepIdV2Codec.DecodeDid2(staged.ExactDid2.Span), staged.ExactXps1.Span,
                current, publication, reading.BootId.Span, reading.SampleSeconds);
            return completed;
        }
        var pair = await new DeepIdV2PreKeyPublicationTransport(
            authoritySource, new DeepIdV2PublicationOnionTransport(authoritySource, custody))
            .PublishAsync(staged, cancellationToken)
            .ConfigureAwait(false);
        await RecordPreKeyCommitPairAfterVerificationAsync(
            staged.ExactXpp1, pair.First, pair.Second,
            cancellationToken).ConfigureAwait(false);
        return new DeepIdV2PreKeyCommitSnapshot(
            pair.First.CanonicalBytes.Span,
            pair.Second.CanonicalBytes.Span);
    }

    // The only production caller is the transport path after VerifyPair.
    // Kept internal so persistence tests can exercise the crash boundary
    // independently of network routing and replica signatures.
    internal async Task RecordPreKeyCommitPairAfterVerificationAsync(
        ReadOnlyMemory<byte> exactXpp1, ParsedXic1V2 first,
        ParsedXic1V2 second, CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        await owner.RecordOwnPreKeyCommitPairAsync(TrustedUnixSeconds(),
            verifier, exactXpp1, first, second,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads the protected pair recorded after live two-replica
    /// verification. This is historical evidence, not current claim authority.</summary>
    public async Task<DeepIdV2PreKeyCommitSnapshot?>
        ReadOwnPreKeyCommitPairAsync(
            CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        var pair = await owner.ReadOwnPreKeyCommitPairAsync(
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
        return pair is null ? null : new DeepIdV2PreKeyCommitSnapshot(
            pair.Value.First, pair.Value.Second);
    }

    /// <summary>Refreshes current DID2 authority without replaying admission.
    /// The proof must bind the exact protected local DAB2/DMD1 before and
    /// after the asynchronous exchange; no caller-authored identity is used.</summary>
    public async Task<VerifiedDeepIdV2DirectoryFreshness> FetchOwnCurrentDirectoryProofAsync(
        DeepIdV2DirectoryProofClient proofClient, VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proofClient);
        ArgumentNullException.ThrowIfNull(authority);
        using var verifier = OpenVerifier();
        using var current = await owner.ReadCurrentAsync(TrustedUnixSeconds(), verifier,
            cancellationToken).ConfigureAwait(false) ?? throw new InvalidOperationException(
                "A protected DID2 account is required for a current proof.");
        var local = current.Verified.PublicEvidence;
        var fresh = await proofClient.FetchOwnGenesisAsync(local.Binding, authority,
            deploymentProfileId, supportedReader: 2, cancellationToken).ConfigureAwait(false);
        var checkpoint = fresh.CurrentCheckpoint ?? throw new CryptographicException(
            "The current DID2 proof has no account checkpoint.");
        if (!Fixed(checkpoint.Binding.Record.CanonicalBytes.Span, local.Binding.Record.CanonicalBytes.Span) ||
            !Fixed(checkpoint.Directory.Record.CanonicalBytes.Span, local.Directory.Record.CanonicalBytes.Span))
            throw new CryptographicException("The current DID2 proof differs from this local account or device directory.");
        using var finalVerifier = OpenVerifier();
        using var final = await owner.ReadCurrentAsync(TrustedUnixSeconds(), finalVerifier,
            cancellationToken).ConfigureAwait(false) ?? throw new CryptographicException(
                "The protected DID2 account disappeared during the exchange.");
        if (!Fixed(final.Verified.PublicEvidence.Binding.Record.CanonicalBytes.Span,
                local.Binding.Record.CanonicalBytes.Span) ||
            !Fixed(final.Verified.PublicEvidence.Directory.Record.CanonicalBytes.Span,
                local.Directory.Record.CanonicalBytes.Span))
            throw new CryptographicException("The protected DID2 account changed during the exchange.");
        await proofClient.RequireStillFreshAsync(fresh, authority, cancellationToken).ConfigureAwait(false);
        return fresh;
    }

    public async Task<DeepIdV2AccountSnapshot> CreateAsync(
        string displayName, CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        using var current = await owner.CreateFreshAsync(displayName,
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
        using var deviceState = await owner.OpenCurrentDeviceStateStoreAsync(
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
        return Snapshot(current);
    }

    /// <summary>
    /// Re-authors the same public DGA1 V2 admission from the protected exact
    /// genesis closure on every retry. This is not a Registry acceptance or
    /// a directory freshness capability.
    /// </summary>
    public async Task<byte[]> PrepareGenesisAdmissionAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        var trustedUnixSeconds = TrustedUnixSeconds();
        using var current = await owner.ReadCurrentAsync(trustedUnixSeconds,
            verifier, cancellationToken).ConfigureAwait(false) ??
            throw new InvalidOperationException(
                "A verified DID2 account is required for genesis admission.");
        return EncodeGenesisAdmission(current, trustedUnixSeconds, verifier);
    }

    private byte[] EncodeGenesisAdmission(
        VerifiedDeepIdV2CurrentAccount current, ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier)
    {
        var evidence = current.Verified.PublicEvidence;
        var binding = evidence.Binding;
        var identity = binding.Identity;
        var request = new DeepIdV2GenesisAdmissionRequest(
            identity.Account.Certificate.CanonicalBytes.Span,
            identity.Revocations.Snapshot.CanonicalBytes.Span,
            identity.ActiveDevices.Select(device => device.Certificate.CanonicalBytes)
                .ToArray(),
            binding.DeepId.CanonicalBytes.Span,
            binding.Record.CanonicalBytes.Span,
            evidence.Directory.Record.CanonicalBytes.Span,
            evidence.Checkpoint.Checkpoint.CanonicalBytes.Span, []);
        _ = DeepIdV2GenesisAdmissionVerifier.Verify(request,
            trustedUnixSeconds, deploymentProfileId, 2, verifier);
        var operationId = GenesisOperationId(binding.DeepId.RecordHash.Span,
            binding.Record.RecordHash.Span);
        return DeepIdV2GenesisAdmissionWireCodec.EncodeRequest(
            new DeepIdV2GenesisAdmissionWireRequest(operationId, request));
    }

    /// <summary>
    /// A DGR1 receipt is only an untrusted transport acknowledgement. This
    /// operation succeeds only after an independent DID2-bound, nonce-fresh
    /// ADH1/DTT1/ADP1 proof is verified and its rollback floor is committed.
    /// </summary>
    public async Task<VerifiedDeepIdV2DirectoryFreshness>
        AdmitAndVerifyGenesisAsync(
            DeepIdV2GenesisAdmissionClient admissionClient,
            DeepIdV2DirectoryProofClient proofClient,
            VerifiedXPointNetworkAuthority authority,
            ushort supportedReader = 2,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(admissionClient);
        ArgumentNullException.ThrowIfNull(proofClient);
        ArgumentNullException.ThrowIfNull(authority);
        byte[] exactDga1;
        VerifiedDab2 binding;
        using (var verifier = OpenVerifier())
        {
            var trustedUnixSeconds = TrustedUnixSeconds();
            using var current = await owner.ReadCurrentAsync(trustedUnixSeconds,
                    verifier, cancellationToken).ConfigureAwait(false) ??
                throw new InvalidOperationException(
                    "A verified DID2 account is required for genesis admission.");
            exactDga1 = EncodeGenesisAdmission(current, trustedUnixSeconds,
                verifier);
            binding = current.Verified.PublicEvidence.Binding;
        }
        try
        {
            var request = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(
                exactDga1).Admission;
            _ = await admissionClient.AdmitAsync(exactDga1, cancellationToken)
                .ConfigureAwait(false);
            var verified = await proofClient.FetchOwnGenesisAsync(
                    binding, authority, deploymentProfileId,
                    supportedReader, cancellationToken).ConfigureAwait(false);
            var checkpoint = verified.CurrentCheckpoint;
            if (checkpoint is null ||
                !CryptographicOperations.FixedTimeEquals(
                    checkpoint.Binding.DeepId.CanonicalBytes.Span,
                    request.ExactDid2.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    checkpoint.Binding.Record.CanonicalBytes.Span,
                    request.ExactDab2.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    checkpoint.Checkpoint.CanonicalBytes.Span,
                    request.ExactAdc1V2.Span))
                throw new CryptographicException(
                    "The authenticated DID2 proof does not confirm the exact local genesis admission.");
            using var finalVerifier = OpenVerifier();
            using var finalCurrent = await owner.ReadCurrentAsync(
                    TrustedUnixSeconds(), finalVerifier, cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "The DID2 account disappeared during directory verification.");
            var finalBinding = finalCurrent.Verified.PublicEvidence.Binding;
            if (!CryptographicOperations.FixedTimeEquals(
                    finalBinding.DeepId.CanonicalBytes.Span,
                    request.ExactDid2.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    finalBinding.Record.CanonicalBytes.Span,
                    request.ExactDab2.Span))
                throw new CryptographicException(
                    "The local DID2 account changed during directory verification.");
            await proofClient.RequireStillFreshAsync(verified, authority,
                cancellationToken).ConfigureAwait(false);
            return verified;
        }
        finally { CryptographicOperations.ZeroMemory(exactDga1); }
    }

    /// <summary>
    /// Opens the account-owned, SQLCipher-backed DID2 directory floor. The
    /// caller supplies the separately pinned signed empty V2 head; no V1
    /// directory state is read or migrated.
    /// </summary>
    public async Task<IDeepIdV2DirectoryProtectedLkgStore>
        OpenDirectoryLkgStoreAsync(
            VerifiedXPointNetworkAuthority authority,
            ReadOnlyMemory<byte> exactGenesisAdh1,
            ReadOnlyMemory<byte> protectedGenesisCoreHash,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        using var verifier = OpenVerifier();
        return await owner.OpenDirectoryLkgStoreAsync(TrustedUnixSeconds(),
            verifier, authority, exactGenesisAdh1,
            protectedGenesisCoreHash, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Opens the DID2 account-owned network floor and
    /// complete-history custody. This does not authorize current network
    /// placement, reset a missing floor, migrate a projection-only store, or open
    /// any pre-cutover store. Every operation rechecks protected custody.</summary>
    public async Task<IXPointNetworkStateStore> OpenNetworkLkgStoreAsync(
        XPointNetworkGenesisPin genesisPin, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(genesisPin);
        using var verifier = OpenVerifier();
        return await owner.OpenNetworkLkgStoreAsync(TrustedUnixSeconds(), verifier,
            genesisPin, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Caller owns and must dispose the returned phrase. Null means the user
    /// permanently deleted this device's retained phrase.
    /// </summary>
    public async Task<VerifiedDeepRecoveryPhrase?> ReadRetainedRecoveryPhraseAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadRetainedRecoveryPhraseAsync(
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task DeleteRetainedRecoveryPhraseAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        await owner.DeleteRetainedRecoveryPhraseAsync(TrustedUnixSeconds(),
            verifier, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Explicit destructive reset, never an automatic repair path.</summary>
    public Task ResetExplicitlyAsync(CancellationToken cancellationToken = default) =>
        owner.ResetExplicitlyAsync(cancellationToken).AsTask();

    private IDeepMlDsa65VerifierLease OpenVerifier() =>
        verifierFactory() ?? throw new InvalidOperationException(
            "The DID2 verifier factory returned no verifier lease.");

    private static byte[] GenesisOperationId(ReadOnlySpan<byte> did2Hash,
        ReadOnlySpan<byte> dab2Hash)
    {
        ReadOnlySpan<byte> domain =
            "Deep/Application/V2/genesis-admission-operation"u8;
        var transcript = new byte[domain.Length + 64];
        domain.CopyTo(transcript);
        did2Hash.CopyTo(transcript.AsSpan(domain.Length));
        dab2Hash.CopyTo(transcript.AsSpan(domain.Length + 32));
        return SHA256.HashData(transcript);
    }

    private ulong TrustedUnixSeconds()
    {
        var seconds = clock.UtcNow.ToUnixTimeSeconds();
        if (seconds < 0)
            throw new InvalidOperationException(
                "The DID2 account clock precedes the Unix epoch.");
        return checked((ulong)seconds);
    }

    private static DeepIdV2AccountSnapshot Snapshot(
        VerifiedDeepIdV2CurrentAccount current) =>
        new(current.DisplayName, current.AccountId.Span,
            current.PermanentId);
}

public sealed class DeepIdV2AccountSnapshot
{
    private readonly byte[] accountId;

    internal DeepIdV2AccountSnapshot(string displayName,
        ReadOnlySpan<byte> accountId, DeepPermanentIdV2 permanentId)
    {
        DisplayName = displayName;
        this.accountId = accountId.ToArray();
        PermanentId = permanentId;
    }

    public string DisplayName { get; }
    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public DeepPermanentIdV2 PermanentId { get; }
}
