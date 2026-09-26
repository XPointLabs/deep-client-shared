using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Registry;
using Sodium;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Network-free DID2 account entry point for a single private device store.
/// It never reads or migrates the incompatible STORE-V1 namespace.
/// </summary>
public sealed class DeepIdV2AccountService
{
    private readonly ProtectedDeepIdV2AccountOwner owner;
    private readonly IClock clock;
    private readonly ushort deploymentProfileId;
    private readonly Func<IDeepMlDsa65VerifierLease> verifierFactory;

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
        var verifiedOffering = MessagingWireVerification.VerifyDpk2(
            exactDpk2.Span, new CurrentDid2PeerDpk2Callbacks(currentPeerProof));
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
        using var store = await OpenCurrentDeviceStateStoreAsync(
            cancellationToken).ConfigureAwait(false);
        using var authority = OwnAgreementAuthority(current);
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
    /// DPK2 signatures alone are insufficient: the exact responder device,
    /// generation and DMD1 head must be present in a current DID2 proof. The
    /// later XPC1 receipt still grants the one-time prekey claim separately.
    /// </summary>
    private sealed class CurrentDid2PeerDpk2Callbacks(
        VerifiedDeepIdV2DirectoryFreshness peerProof)
        : IDpk2VerificationCallbacks
    {
        public Dpk2ResolvedDevice ResolveActiveDevice(Dpk2Record offering)
        {
            var checkpoint = peerProof.CurrentCheckpoint ??
                throw new CryptographicException(
                    "The DID2 peer has no current directory checkpoint.");
            var identity = checkpoint.Binding.Identity;
            var directory = checkpoint.Directory.Record;
            if (peerProof.ResultKind !=
                    AccountDirectoryAdp1ResultKind.CurrentValue ||
                !Fixed(offering.NetworkId.Span, peerProof.NetworkId.Span) ||
                !Fixed(offering.ResponderAccountId.Span,
                    identity.Account.DeepAccountIdHash.Span) ||
                !Fixed(directory.NetworkId.Span, peerProof.NetworkId.Span) ||
                !Fixed(directory.DeepAccountId.Span,
                    offering.ResponderAccountId.Span) ||
                offering.DeviceDirectoryGeneration !=
                    directory.DirectoryGeneration ||
                !Fixed(offering.DeviceDirectoryHeadHash.Span,
                    directory.RecordHash.Span) ||
                offering.IssuedAt < directory.IssuedAtUnixSeconds ||
                peerProof.TrustedLowerUnixSeconds < offering.NotBefore ||
                peerProof.TrustedUpperUnixSeconds >= offering.ExpiresAt)
                throw new CryptographicException(
                    "DPK2 is outside the exact current DID2 peer directory or validity window.");
            var entry = directory.ActiveDevices.SingleOrDefault(device =>
                Fixed(device.DeviceId.Span,
                    offering.ResponderDeviceId.Span));
            var device = identity.ActiveDevices.SingleOrDefault(candidate =>
                Fixed(candidate.Certificate.DeviceId.Span,
                    offering.ResponderDeviceId.Span));
            if (entry is null || device is null ||
                device.Certificate.DeviceGeneration !=
                    offering.ResponderDeviceGeneration ||
                !offering.ResponderDpd1Ref.Span[..4].SequenceEqual(
                    DeepProtocolIdentifiers.MagicBytes.DPD1) ||
                offering.ResponderDpd1Ref.Span[4] != 0 ||
                offering.ResponderDpd1Ref.Span[5] != 1 ||
                !Fixed(offering.ResponderDpd1Ref.Span[6..],
                    entry.Dpd1Reference.CanonicalHash.Span) ||
                !Fixed(entry.Dpd1Reference.CanonicalHash.Span,
                    device.Certificate.CanonicalHash.Span))
                throw new CryptographicException(
                    "DPK2 responder is not an exact active DID2 device.");
            return new Dpk2ResolvedDevice(
                device.Certificate.DeviceEd25519PublicKey.Span,
                device.Certificate.DeviceX25519PublicKey.Span);
        }

        public bool VerifyEd25519(ReadOnlyMemory<byte> publicKey,
            ReadOnlyMemory<byte> signatureInput,
            ReadOnlyMemory<byte> signature) =>
            PublicKeyAuth.VerifyDetached(signature.ToArray(),
                signatureInput.ToArray(), publicKey.ToArray());
    }

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
