using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Persistence.PreKeyV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Services.MessagingV1;

/// <summary>
/// Public, key-free request for one durable local DPK2 inventory. All identity,
/// XPS1, placement, policy and directory facts remain verifier-minted objects;
/// the caller supplies only the bounded epoch policy and idempotency values.
/// </summary>
public sealed class DeepDirectMessagingInventoryRequest
{
    private readonly byte[] predecessorXpi1Hash;
    private readonly byte[] publicationOperationId;

    public DeepDirectMessagingInventoryRequest(
        Dmd1LineageState currentDirectory,
        VerifiedContactPreKeyService preKeyService,
        VerifiedContactServicePlacement placement,
        ulong inventoryEpoch,
        ulong notBeforeUnixSeconds,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ReadOnlySpan<byte> predecessorXpi1Hash,
        ReadOnlySpan<byte> publicationOperationId,
        ushort oneTimePreKeyCount,
        ushort lastResortReuseLimit)
    {
        CurrentDirectory = currentDirectory ??
            throw new ArgumentNullException(nameof(currentDirectory));
        PreKeyService = preKeyService ??
            throw new ArgumentNullException(nameof(preKeyService));
        Placement = placement ?? throw new ArgumentNullException(nameof(placement));
        if (inventoryEpoch is < 1 or > 14)
            throw new ArgumentOutOfRangeException(nameof(inventoryEpoch));
        if (predecessorXpi1Hash.Length != 32 ||
            (inventoryEpoch == 1) != IsZero(predecessorXpi1Hash))
        {
            throw new ArgumentException(
                "The predecessor XPI1 hash must be ZERO32 exactly for inventory epoch 1.",
                nameof(predecessorXpi1Hash));
        }
        if (publicationOperationId.Length != 32 || IsZero(publicationOperationId))
        {
            throw new ArgumentException(
                "The publication operation ID must be exactly 32 nonzero bytes.",
                nameof(publicationOperationId));
        }
        if (issuedAtUnixSeconds > notBeforeUnixSeconds ||
            notBeforeUnixSeconds >= expiresAtUnixSeconds ||
            expiresAtUnixSeconds - notBeforeUnixSeconds > 2_592_000)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiresAtUnixSeconds),
                "Inventory authoring requires issuedAt <= notBefore < expiresAt and at most 30 days.");
        }
        if (oneTimePreKeyCount is < 32 or > 4096)
            throw new ArgumentOutOfRangeException(nameof(oneTimePreKeyCount));
        if (lastResortReuseLimit is < 1 or > 64)
            throw new ArgumentOutOfRangeException(nameof(lastResortReuseLimit));

        InventoryEpoch = inventoryEpoch;
        NotBeforeUnixSeconds = notBeforeUnixSeconds;
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        this.predecessorXpi1Hash = predecessorXpi1Hash.ToArray();
        this.publicationOperationId = publicationOperationId.ToArray();
        OneTimePreKeyCount = oneTimePreKeyCount;
        LastResortReuseLimit = lastResortReuseLimit;
    }

    public Dmd1LineageState CurrentDirectory { get; }
    public VerifiedContactPreKeyService PreKeyService { get; }
    public VerifiedContactServicePlacement Placement { get; }
    public ulong InventoryEpoch { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> PredecessorXpi1Hash => predecessorXpi1Hash.ToArray();
    public ReadOnlyMemory<byte> PublicationOperationId => publicationOperationId.ToArray();
    public ushort OneTimePreKeyCount { get; }
    public ushort LastResortReuseLimit { get; }

    private static bool IsZero(ReadOnlySpan<byte> value) =>
        value.IndexOfAnyExcept((byte)0) < 0;
}

/// <summary>
/// Opaque account-scoped owner for the durable direct-messaging graph. The host
/// supplies only verifier-minted local-device capabilities; SQLCipher stores,
/// pre-key secret owners, ratchet state, and persistence keys never cross this
/// boundary.
/// </summary>
public sealed class DeepDirectMessagingStorageFacade : IAsyncDisposable
{
    private readonly DeepDirectMessagingLocalAuthorityBinding authority;
    private DeepDirectMessagingStorageOwner? owner;

    private DeepDirectMessagingStorageFacade(
        DeepDirectMessagingLocalAuthorityBinding authority,
        DeepDirectMessagingStorageOwner owner)
    {
        this.authority = authority;
        this.owner = owner;
    }

    public static async Task<DeepDirectMessagingStorageFacade> OpenAsync(
        string appDataDirectory,
        DeepAccountService accountService,
        LocalDeviceX25519AgreementAuthority localAgreementAuthority,
        VerifiedDeviceRelative verifiedDevice,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountService);
        var identity = await accountService.GetLocalIdentityAsync(cancellationToken)
            .ConfigureAwait(false) ?? throw new CryptographicException(
                "Direct-message storage requires a current local account identity.");
        var authority = DeepDirectMessagingLocalAuthorityBinding.FromVerified(
            localAgreementAuthority,
            verifiedDevice);
        var owner = await DeepDirectMessagingStorageOwner.OpenAsync(
                appDataDirectory,
                accountService.SecureStorageForOwnedComposition,
                accountService,
                identity,
                authority,
                cancellationToken)
            .ConfigureAwait(false);
        return new DeepDirectMessagingStorageFacade(authority, owner);
    }

    public bool IsBoundTo(
        LocalDeviceX25519AgreementAuthority localAgreementAuthority,
        VerifiedDeviceRelative verifiedDevice)
    {
        ObjectDisposedException.ThrowIf(owner is null, this);
        var requested = DeepDirectMessagingLocalAuthorityBinding.FromVerified(
            localAgreementAuthority,
            verifiedDevice);
        return authority.Matches(requested);
    }

    /// <summary>
    /// Authors and atomically stages one complete XPI1/XPP1 inventory. Private
    /// pre-key capabilities enter SQLCipher before exact publication bytes are
    /// returned; the caller never receives key material.
    /// </summary>
    public async ValueTask<DeepDirectMessagingInventoryPublication>
        EnsureInventoryAsync(
            DeepDirectMessagingInventoryRequest request,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var directory = request.CurrentDirectory;
        var record = directory.Head.Record;
        var service = request.PreKeyService;
        var placement = request.Placement;
        if (directory.ForkLatched ||
            record.AccountGeneration != authority.AccountGeneration ||
            !Fixed(record.NetworkId.Span, authority.NetworkId) ||
            !Fixed(record.DeepAccountId.Span, authority.AccountId) ||
            !Fixed(service.NetworkId.Span, authority.NetworkId) ||
            !Fixed(service.DeviceId.Span, authority.DeviceId))
        {
            throw new CryptographicException(
                "The DPK2 inventory request is outside the current local account/device authority.");
        }

        var device = record.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.DeviceId.Span, authority.DeviceId));
        if (device is null ||
            !Fixed(device.Dpd1Reference.CanonicalHash.Span, authority.ExactDpd1Hash) ||
            !Fixed(device.Dpd1Reference.CanonicalBytes.Span, service.Dpd1Reference.Span) ||
            placement.RequestKind != ContactServiceRequestKind.PublishPreKeyInventory ||
            placement.ServiceClass != ContactServiceClass.PreKeyClaim ||
            !placement.Binds(
                ContactServiceRequestKind.PublishPreKeyInventory,
                service.ServiceCapability) ||
            !Fixed(placement.Network.NetworkId.Span, authority.NetworkId) ||
            placement.PolicyGeneration == 0)
        {
            throw new CryptographicException(
                "The DPK2 inventory request is not bound to the exact current XPS1 placement.");
        }

        if (request.OneTimePreKeyCount < service.MinimumOneTimeInventory ||
            request.LastResortReuseLimit > service.LastResortReuseLimit ||
            request.NotBeforeUnixSeconds < service.IssuedAtUnixSeconds ||
            request.ExpiresAtUnixSeconds > service.ExpiresAtUnixSeconds ||
            request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
        {
            throw new CryptographicException(
                "The DPK2 inventory policy or lifetime exceeds its XPS1/placement authority.");
        }

        var dpk2 = new Dpk2AuthoringContext(
            directory,
            service.Generation,
            request.InventoryEpoch,
            placement.PolicyGeneration,
            request.NotBeforeUnixSeconds,
            request.IssuedAtUnixSeconds,
            request.ExpiresAtUnixSeconds);
        var context = new PreKeyV1InventoryAuthoringContext(
            dpk2,
            service.ServiceCapability.Span,
            service.Xps1Reference.Span,
            record.Drs1Reference.CanonicalBytes.Span,
            request.PredecessorXpi1Hash.Span,
            request.PublicationOperationId.Span,
            placement.PlacementHash.Span,
            request.OneTimePreKeyCount,
            request.LastResortReuseLimit);
        return await CurrentOwner.EnsureInventoryAsync(context, cancellationToken)
            .ConfigureAwait(false) ?? throw new CryptographicException(
                "The durable DPK2 inventory owner returned no publication.");
    }

    /// <summary>
    /// Publishes only an inventory capability returned by this open facade,
    /// through the exact production ONION transport and current NETCODEC path
    /// authority, then independently verifies both replica commit receipts.
    /// </summary>
    public async ValueTask<VerifiedPreKeyInventoryPublication>
        PublishInventoryAsync(
            DeepDirectMessagingInventoryPublication publication,
            PrivacyRoutedContactResolverTransport transport,
            ProductionContactResolvePathAuthoritySource pathAuthoritySource,
            VerifiedContactNetworkAuthority recipientAuthority,
            VerifiedContactBundleClosure recipientBundle,
            VerifiedPreKeyInventoryPublication? predecessor = null,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(pathAuthoritySource);
        ArgumentNullException.ThrowIfNull(recipientAuthority);
        ArgumentNullException.ThrowIfNull(recipientBundle);
        return await PublishInventoryAsync(
                publication,
                (IExactContactResolveOnionTransport)transport,
                (IContactResolvePublicationPathAuthoritySource)pathAuthoritySource,
                recipientAuthority,
                recipientBundle,
                predecessor,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask<VerifiedPreKeyInventoryPublication>
        PublishInventoryAsync(
            DeepDirectMessagingInventoryPublication publication,
            IExactContactResolveOnionTransport transport,
            IContactResolvePublicationPathAuthoritySource pathAuthoritySource,
            VerifiedContactNetworkAuthority recipientAuthority,
            VerifiedContactBundleClosure recipientBundle,
            VerifiedPreKeyInventoryPublication? predecessor = null,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(pathAuthoritySource);
        ArgumentNullException.ThrowIfNull(recipientAuthority);
        ArgumentNullException.ThrowIfNull(recipientBundle);
        cancellationToken.ThrowIfCancellationRequested();
        var operation = CurrentOwner.BindInventoryPublication(publication);
        var verifier = new ProtocolPreKeyV1PublicationVerifier(
            recipientAuthority,
            recipientBundle,
            predecessor);
        return await PreKeyV1InventoryPublicationDispatcher.PublishAsync(
                operation,
                transport,
                pathAuthoritySource,
                verifier,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public ValueTask<DeepDirectMessagingInitiatorClaimStart?>
        TryBeginInitiatorClaimAsync(
            ContactResolverReverifiedPeerAuthority? verifiedPeer,
            LocalDeviceX25519AgreementAuthority? localAgreementAuthority,
            Dmd1LineageState? exactCurrentDirectory,
            Dab1LineageState? exactCurrentAddressBinding,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryBeginInitiatorClaimAsync(
            verifiedPeer,
            localAgreementAuthority,
            exactCurrentDirectory,
            exactCurrentAddressBinding,
            cancellationToken);

    public ValueTask<DeepDirectMessagingInitiatorClaimPreparation?>
        TryCompleteInitiatorClaimAsync(
            DeepDirectMessagingInitiatorClaimStart? startedClaim,
            VerifiedDpk2Offering? verifiedOffering,
            LocalDeviceX25519AgreementLease? deviceAgreementLease,
            int maximumMessagesWithoutPqInjection,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryCompleteInitiatorClaimAsync(
            startedClaim,
            verifiedOffering,
            deviceAgreementLease,
            maximumMessagesWithoutPqInjection,
            cancellationToken);

    internal ValueTask<DeepDirectMessagingInitiatorCommitResult?>
        TryCommitInitiatorSessionAsync(
            DeepDirectMessagingInitiatorClaimPreparation? preparedClaim,
            VerifiedXpc1PreKeyClaimReceipt? verifiedClaim,
            ReadOnlyMemory<byte> exactSessionInitDmc2,
            ReadOnlyMemory<byte> exactFirstApplicationDmc2 = default,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryCommitInitiatorSessionAsync(
            preparedClaim,
            verifiedClaim,
            exactSessionInitDmc2,
            exactFirstApplicationDmc2,
            cancellationToken);

    public ValueTask<DeepDirectMessagingInitiatorCommitResult?>
        TryCommitInitiatorSessionAsync(
            DeepDirectMessagingInitiatorClaimPreparation? preparedClaim,
            VerifiedXpc1PreKeyClaimReceipt? verifiedClaim,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryCommitInitiatorSessionAsync(
            preparedClaim,
            verifiedClaim,
            cancellationToken);

#if DEEP_CLEAN_PRODUCTION
    public ValueTask<Dph2InitialClaimPreview?> TryPreviewResponderInitialClaimAsync(
        Dph2Record initiation,
        Dmd1LineageState initiatorDirectory,
        int maximumMessagesWithoutPqInjection,
        CancellationToken cancellationToken = default) =>
        CurrentOwner.TryPreviewResponderInitialClaimAsync(
            initiation, initiatorDirectory,
            maximumMessagesWithoutPqInjection, cancellationToken);

    /// <summary>
    /// Commits the initial DPH2 with both mandatory application records:
    /// SessionInit at sender sequence one and a capability-authored
    /// ContactHello at sender sequence two. Arbitrary decoded DMC2 bytes are
    /// not accepted at this production boundary.
    /// </summary>
    public ValueTask<DeepDirectMessagingInitiatorCommitResult?>
        TryCommitInitiatorSessionAsync(
            DeepDirectMessagingInitiatorClaimPreparation? preparedClaim,
            VerifiedXpc1PreKeyClaimReceipt? verifiedClaim,
            AuthoredVerifiedContactHello? contactHello,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryCommitInitiatorSessionAsync(
            preparedClaim,
            verifiedClaim,
            contactHello,
            cancellationToken);
#endif

#if DEEP_CLEAN_PRODUCTION
    public ValueTask<DirectTextOutboxEntry?> TryStageDirectTextAsync(
        DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
        SqliteDeepMailboxStore inbox,
        string text,
        DateTimeOffset createdAt,
        CancellationToken cancellationToken = default) =>
        CurrentOwner.TryStageDirectTextAsync(
            verifiedSession, inbox, text, createdAt, cancellationToken);

    public ValueTask<DirectTextOutboxEntry?> TryReadDirectTextAsync(
        DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
        SqliteDeepMailboxStore inbox,
        ReadOnlyMemory<byte> logicalMessageId,
        CancellationToken cancellationToken = default) =>
        CurrentOwner.TryReadDirectTextAsync(
            verifiedSession, inbox, logicalMessageId, cancellationToken);

    internal ValueTask<RecoveredDirectSend?> TryRecoverEstablishedSendAsync(
        DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
        ReadOnlyMemory<byte> operationId,
        CancellationToken cancellationToken = default) =>
        CurrentOwner.TryRecoverEstablishedSendAsync(
            verifiedSession, operationId, cancellationToken);

    public ValueTask<ExactDpe2SendSuccessCapability?>
        TryCommitEstablishedSendAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            ReadOnlyMemory<byte> exactDmc2,
            ReadOnlyMemory<byte> operationId,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryCommitEstablishedSendAsync(
            verifiedSession,
            exactDmc2,
            operationId,
            cancellationToken);
#endif

    public ValueTask<DeepDirectMessagingMetadataSealingPublicKey>
        PrepareMetadataSealingKeyAsync(
            VerifiedContactRouteProposalAuthority proposal,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.PrepareMetadataSealingKeyAsync(proposal, cancellationToken);

    public ValueTask<DeepDirectMessagingOpenedDeposit> OpenInboundDepositAsync(
        VerifiedContactRouteClosure currentLocalRoute,
        ReadOnlyMemory<byte> exactDao1,
        CancellationToken cancellationToken = default) =>
        CurrentOwner.OpenInboundDepositAsync(
            currentLocalRoute, exactDao1, cancellationToken);

#if DEEP_CLEAN_PRODUCTION
    public ValueTask<DeepDirectMessagingOpenedDeposit> OpenInboundDepositAsync(
        ParsedContactRouteClosure currentLocalRoute,
        ReadOnlyMemory<byte> exactDao1,
        CancellationToken cancellationToken = default) =>
        CurrentOwner.OpenInboundDepositAsync(
            currentLocalRoute, exactDao1, cancellationToken);
#endif

    /// <summary>
    /// Opens one retrieved MEO1 through exact mailbox-route/DAO1 binding.
    /// This yields plaintext inner bytes but no session, inbox or ACK authority.
    /// </summary>
    public ValueTask<DeepDirectMessagingOpenedDeposit> OpenInboundMailboxEntryAsync(
        VerifiedContactRouteClosure currentLocalRoute,
        ScopedMailboxResolvedRoute currentMailboxRoute,
        ulong cursor,
        ReadOnlyMemory<byte> exactMeo1,
        ReadOnlyMemory<byte> externalEnvelopeDigest,
        MailboxClientDecodePolicy decodePolicy,
        CancellationToken cancellationToken = default) =>
        CurrentOwner.OpenInboundMailboxEntryAsync(
            currentLocalRoute, currentMailboxRoute, cursor, exactMeo1,
            externalEnvelopeDigest, decodePolicy, cancellationToken);

#if DEEP_CLEAN_PRODUCTION
    /// <summary>
    /// Authenticates an initial DPH2 and its encrypted XPK1/XPC1 evidence
    /// against the current directory head before opening a responder session
    /// or reserving a local prekey. This does not authorize mailbox ACK.
    /// </summary>
    public ValueTask<VerifiedDph2InitialClaim?> TryVerifyResponderInitialClaimAsync(
        Dph2Record initiation,
        VerifiedDpk2Offering localOffering,
        Dmd1LineageState initiatorDirectory,
        VerifiedAccountDirectoryFreshness initiatorFreshness,
        VerifiedContactServicePlacement claimPlacement,
        VerifiedContactNetworkAuthority recipientAuthority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        int maximumMessagesWithoutPqInjection,
        CancellationToken cancellationToken = default) =>
        CurrentOwner.TryVerifyResponderInitialClaimAsync(
            initiation, localOffering, initiatorDirectory, initiatorFreshness,
            claimPlacement, recipientAuthority, recipientBundle,
            trustedTimeAuthority, maximumMessagesWithoutPqInjection,
            cancellationToken);

    public ValueTask<VerifiedDph2InitialClaim?> TryVerifyResponderInitialClaimAsync(
        Dph2Record initiation,
        Dmd1LineageState initiatorDirectory,
        VerifiedAccountDirectoryFreshness initiatorFreshness,
        VerifiedContactServicePlacement claimPlacement,
        VerifiedContactNetworkAuthority recipientAuthority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        int maximumMessagesWithoutPqInjection,
        CancellationToken cancellationToken = default) =>
        CurrentOwner.TryVerifyResponderInitialClaimAsync(
            initiation, initiatorDirectory, initiatorFreshness,
            claimPlacement, recipientAuthority, recipientBundle,
            trustedTimeAuthority, maximumMessagesWithoutPqInjection,
            cancellationToken);

    /// <summary>
    /// Stages the verified first-contact session after ContactHello endpoint
    /// checks. It does not materialize a relationship or authorize an ACK.
    /// </summary>
    public ValueTask<DeepDirectMessagingUnsolicitedCommitResult?>
        TryCommitUnsolicitedResponderSessionAsync(
            VerifiedDph2InitialClaim? verifiedInitial,
            int maximumMessagesWithoutPqInjection,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryCommitUnsolicitedResponderSessionAsync(
            verifiedInitial, maximumMessagesWithoutPqInjection,
            cancellationToken);
#endif

#if DEEP_CLEAN_PRODUCTION
    internal ValueTask<InitiatorInitialSessionDispatchEnvelope?>
        TryReadPendingInitiatorDispatchAsync(
            InitiatorInitialSessionVerifiedScope? verifiedPeerScope,
            ReadOnlyMemory<byte> exactSessionId,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryReadPendingInitiatorDispatchAsync(
            verifiedPeerScope,
            exactSessionId,
            cancellationToken);

    public ValueTask<ExactDpe2ReceiveSuccessCapability?>
        TryCommitEstablishedReceiveAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            ReadOnlyMemory<byte> exactDpe2,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryCommitEstablishedReceiveAsync(
            verifiedSession,
            exactDpe2,
            cancellationToken);

    internal ValueTask<DeepDirectMessagingVerifiedSessionBinding?>
        TryResolveEstablishedInboundSessionAsync(
            ReadOnlyMemory<byte> exactDpe2,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryResolveEstablishedInboundSessionAsync(
            exactDpe2, cancellationToken);

    internal ValueTask<DirectDmc2InboxDisposition?>
        TryMaterializeEstablishedReceiveAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            ReadOnlyMemory<byte> exactDpe2,
            SqliteDeepMailboxStore inbox,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryMaterializeEstablishedReceiveAsync(
            verifiedSession, exactDpe2, inbox, cancellationToken);

    internal ValueTask<DirectDmc2InboxDisposition?>
        TryMaterializeInitialReceiveAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            VerifiedContactBundleEvidence? relationship,
            VerifiedDph2Initiation? verifiedInitiation,
            SqliteDeepMailboxStore inbox,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryMaterializeInitialReceiveAsync(
            verifiedSession, relationship, verifiedInitiation,
            inbox, cancellationToken);

    internal ValueTask<DirectDmc2InboxDisposition?>
        TryMaterializeInitialReceiveAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            VerifiedDph2InitialClaim? verifiedInitial,
            SqliteDeepMailboxStore inbox,
            CancellationToken cancellationToken = default) =>
        CurrentOwner.TryMaterializeInitialReceiveAsync(
            verifiedSession, verifiedInitial, inbox, cancellationToken);
#endif

    public static void DeleteAccountState(string appDataDirectory) =>
        DeepDirectMessagingStorageOwner.DeleteState(appDataDirectory);

    public async ValueTask DisposeAsync()
    {
        var current = Interlocked.Exchange(ref owner, null);
        if (current is not null)
        {
            await current.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private DeepDirectMessagingStorageOwner CurrentOwner =>
        Volatile.Read(ref owner) ??
        throw new ObjectDisposedException(nameof(DeepDirectMessagingStorageFacade));
}

/// <summary>
/// Public XRA1 authoring inputs only. The private scalar remains in the
/// account-owned protected store and is never returned to MAUI.
/// </summary>
public sealed class DeepDirectMessagingMetadataSealingPublicKey
{
    private readonly byte[] keyId;
    private readonly byte[] x25519PublicKey;

    internal DeepDirectMessagingMetadataSealingPublicKey(
        MetadataSealingPublicBinding binding)
    {
        keyId = binding.KeyId.ToArray();
        x25519PublicKey = binding.X25519PublicKey.ToArray();
    }

    public ReadOnlyMemory<byte> KeyId => keyId.ToArray();
    public ReadOnlyMemory<byte> X25519PublicKey => x25519PublicKey.ToArray();
}

public enum DeepDirectMessagingInboundKind : byte
{
    InitialSession = 1,
    EstablishedSession = 2,
}

/// <summary>
/// Opened canonical DAO1 inner bytes, bound to the current local recipient.
/// This is not an E2EE commit, materialization proof or mailbox ACK authority.
/// </summary>
public sealed class DeepDirectMessagingOpenedDeposit : IDisposable
{
    private byte[]? exactInner;
    private byte[]? dao1Hash;

    internal DeepDirectMessagingOpenedDeposit(
        MessagingDao1Opened opened,
        ReadOnlySpan<byte> exactDao1)
    {
        Kind = opened.Kind switch
        {
            MessagingV1DepositKind.InitialSession =>
                DeepDirectMessagingInboundKind.InitialSession,
            MessagingV1DepositKind.EstablishedSession =>
                DeepDirectMessagingInboundKind.EstablishedSession,
            _ => throw new CryptographicException("The opened DAO1 kind is unknown."),
        };
        exactInner = opened.ExactInner.ToArray();
        dao1Hash = SHA256.HashData(exactDao1);
    }

    public DeepDirectMessagingInboundKind Kind { get; }
    public ReadOnlyMemory<byte> ExactInner =>
        (Volatile.Read(ref exactInner) ??
            throw new ObjectDisposedException(nameof(DeepDirectMessagingOpenedDeposit)))
        .ToArray();
    public ReadOnlyMemory<byte> ExactDao1Hash =>
        (Volatile.Read(ref dao1Hash) ??
            throw new ObjectDisposedException(nameof(DeepDirectMessagingOpenedDeposit)))
        .ToArray();

    public void Dispose()
    {
        var inner = Interlocked.Exchange(ref exactInner, null);
        var hash = Interlocked.Exchange(ref dao1Hash, null);
        if (inner is not null) CryptographicOperations.ZeroMemory(inner);
        if (hash is not null) CryptographicOperations.ZeroMemory(hash);
    }
}

/// <summary>
/// Byte-only projection of a verifier-minted local-device authority. It never
/// retains the authority because that capability owns the device agreement key.
/// </summary>
internal sealed class DeepDirectMessagingLocalAuthorityBinding
{
    private readonly byte[] networkId;
    private readonly byte[] accountId;
    private readonly byte[] deviceId;
    private readonly byte[] exactDpd1Hash;
    private readonly VerifiedDeviceRelative? verifiedDevice;

    private DeepDirectMessagingLocalAuthorityBinding(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> exactDpd1Hash,
        VerifiedDeviceRelative? verifiedDevice)
    {
        RequireIdentifier(networkId, 16, nameof(networkId));
        RequireIdentifier(accountId, 32, nameof(accountId));
        RequireIdentifier(deviceId, 32, nameof(deviceId));
        RequireIdentifier(exactDpd1Hash, 32, nameof(exactDpd1Hash));
        if (accountGeneration == 0 || deviceGeneration == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(accountGeneration),
                "Local account and device generations must be nonzero.");
        }

        this.networkId = networkId.ToArray();
        this.accountId = accountId.ToArray();
        this.deviceId = deviceId.ToArray();
        this.exactDpd1Hash = exactDpd1Hash.ToArray();
        this.verifiedDevice = verifiedDevice;
        AccountGeneration = accountGeneration;
        DeviceGeneration = deviceGeneration;
    }

    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> AccountId => accountId;
    internal ulong AccountGeneration { get; }
    internal ReadOnlySpan<byte> DeviceId => deviceId;
    internal ulong DeviceGeneration { get; }
    internal ReadOnlySpan<byte> ExactDpd1Hash => exactDpd1Hash;
    internal VerifiedDeviceRelative? VerifiedDevice => verifiedDevice;

    internal static DeepDirectMessagingLocalAuthorityBinding FromVerified(
        LocalDeviceX25519AgreementAuthority authority,
        VerifiedDeviceRelative verifiedDevice)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(verifiedDevice);
        var certificate = verifiedDevice.Certificate;
        if (!Fixed(authority.NetworkId.Span, certificate.NetworkId.Span) ||
            !Fixed(authority.AccountId.Span, certificate.AccountHash.Span) ||
            authority.AccountGeneration != certificate.AccountGeneration ||
            !Fixed(authority.DeviceId.Span, certificate.DeviceId.Span) ||
            authority.DeviceGeneration != certificate.DeviceGeneration ||
            !Fixed(authority.ExactDpd1Hash.Span, certificate.CanonicalHash.Span) ||
            !Fixed(authority.AgreementPublicKey.Span,
                certificate.DeviceX25519PublicKey.Span))
        {
            throw new CryptographicException(
                "The verified local device differs from the device-agreement authority.");
        }
        return new DeepDirectMessagingLocalAuthorityBinding(
            authority.NetworkId.Span,
            authority.AccountId.Span,
            authority.AccountGeneration,
            authority.DeviceId.Span,
            authority.DeviceGeneration,
            authority.ExactDpd1Hash.Span,
            verifiedDevice);
    }

#if DEEP_TEST_INTERNALS
    internal static DeepDirectMessagingLocalAuthorityBinding CreateForTests(
        DeepLocalIdentitySnapshot identity,
        ReadOnlySpan<byte> exactDpd1Hash) => new(
            identity.NetworkId.Span,
            identity.Account.AccountIdentity.AccountId.Bytes.Span,
            identity.Account.AccountIdentity.AccountGeneration,
            identity.Device.DeviceId.Bytes.Span,
            identity.Device.DeviceGeneration,
            exactDpd1Hash,
            verifiedDevice: null);

    internal static DeepDirectMessagingLocalAuthorityBinding CreateForTests(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> exactDpd1Hash) => new(
            networkId,
            accountId,
            accountGeneration,
            deviceId,
            deviceGeneration,
            exactDpd1Hash,
            verifiedDevice: null);
#endif

    internal bool Matches(DeepLocalIdentitySnapshot identity) =>
        identity.Account.AccountIdentity.AccountGeneration == AccountGeneration &&
        identity.Device.DeviceGeneration == DeviceGeneration &&
        Fixed(identity.NetworkId.Span, networkId) &&
        Fixed(identity.Account.AccountIdentity.AccountId.Bytes.Span, accountId) &&
        Fixed(identity.Device.DeviceId.Bytes.Span, deviceId);

    internal bool Matches(DeepDirectMessagingLocalAuthorityBinding other) =>
        other.AccountGeneration == AccountGeneration &&
        other.DeviceGeneration == DeviceGeneration &&
        Fixed(other.NetworkId, networkId) &&
        Fixed(other.AccountId, accountId) &&
        Fixed(other.DeviceId, deviceId) &&
        Fixed(other.ExactDpd1Hash, exactDpd1Hash);

    internal bool Matches(LocalDeviceX25519AgreementAuthority other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return other.AccountGeneration == AccountGeneration &&
            other.DeviceGeneration == DeviceGeneration &&
            Fixed(other.NetworkId.Span, networkId) &&
            Fixed(other.AccountId.Span, accountId) &&
            Fixed(other.DeviceId.Span, deviceId) &&
            Fixed(other.ExactDpd1Hash.Span, exactDpd1Hash);
    }

    private static void RequireIdentifier(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} must be exactly {length} nonzero bytes.", name);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// One verified remote device and exact DPH2 session identifier. Sender-side
/// production construction uses a ContactResolver capability; unsolicited
/// responder construction requires authenticated initial DPH2 events. Raw
/// identifiers are accepted only by the test-only factory.
/// </summary>
public sealed class DeepDirectMessagingVerifiedSessionBinding
{
    private readonly byte[] networkId;
    private readonly byte[] remoteAccountId;
    private readonly byte[] remoteDeviceId;
    private readonly byte[] conversationId;
    private readonly byte[] exactDph2Id;

    private DeepDirectMessagingVerifiedSessionBinding(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> remoteAccountId,
        ulong remoteAccountGeneration,
        ReadOnlySpan<byte> remoteDeviceId,
        ulong remoteDeviceGeneration,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> exactDph2Id)
    {
        RequireIdentifier(networkId, 16, nameof(networkId));
        RequireIdentifier(remoteAccountId, 32, nameof(remoteAccountId));
        RequireIdentifier(remoteDeviceId, 32, nameof(remoteDeviceId));
        RequireIdentifier(conversationId, 32, nameof(conversationId));
        RequireIdentifier(exactDph2Id, 32, nameof(exactDph2Id));
        if (remoteAccountGeneration == 0 || remoteDeviceGeneration == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(remoteAccountGeneration),
                "Remote account and device generations must be nonzero.");
        }

        this.networkId = networkId.ToArray();
        this.remoteAccountId = remoteAccountId.ToArray();
        this.remoteDeviceId = remoteDeviceId.ToArray();
        this.conversationId = conversationId.ToArray();
        this.exactDph2Id = exactDph2Id.ToArray();
        RemoteAccountGeneration = remoteAccountGeneration;
        RemoteDeviceGeneration = remoteDeviceGeneration;
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> RemoteAccountId => remoteAccountId.ToArray();
    public ulong RemoteAccountGeneration { get; }
    public ReadOnlyMemory<byte> RemoteDeviceId => remoteDeviceId.ToArray();
    public ulong RemoteDeviceGeneration { get; }
    public ReadOnlyMemory<byte> ConversationId => conversationId.ToArray();
    public ReadOnlyMemory<byte> ExactDph2Id => exactDph2Id.ToArray();

    public static DeepDirectMessagingVerifiedSessionBinding FromVerified(
        ContactResolverVerifiedCapabilitySet verifiedContact,
        ContactConversationId32 conversationId,
        ReadOnlySpan<byte> remoteDeviceId,
        ReadOnlySpan<byte> exactDph2Id)
    {
        ArgumentNullException.ThrowIfNull(verifiedContact);
        ArgumentNullException.ThrowIfNull(conversationId);
        RequireIdentifier(remoteDeviceId, 32, nameof(remoteDeviceId));
        RequireIdentifier(exactDph2Id, 32, nameof(exactDph2Id));

        var directory = verifiedContact.Bundle.Directory;
        var record = directory.Record;
        var selectedDeviceId = remoteDeviceId.ToArray();
        var entry = record.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.DeviceId.Span, selectedDeviceId));
        var verifiedDevice = directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, selectedDeviceId));
        if (entry is null || verifiedDevice is null ||
            entry.Dpd1Reference.TypeCode != (ushort)ArtifactType.Dpd1 ||
            entry.Dpd1Reference.CanonicalLength != 776 ||
            !Fixed(entry.Dpd1Reference.CanonicalHash.Span,
                verifiedDevice.Certificate.CanonicalHash.Span) ||
            !Fixed(verifiedDevice.Certificate.NetworkId.Span, record.NetworkId.Span) ||
            !Fixed(verifiedDevice.Certificate.AccountHash.Span, record.DeepAccountId.Span) ||
            verifiedDevice.Certificate.AccountGeneration != record.AccountGeneration)
        {
            throw new CryptographicException(
                "The selected direct-message peer is not an active device in the verified contact closure.");
        }

        return new DeepDirectMessagingVerifiedSessionBinding(
            record.NetworkId.Span,
            record.DeepAccountId.Span,
            record.AccountGeneration,
            selectedDeviceId,
            verifiedDevice.Certificate.DeviceGeneration,
            conversationId.Span,
            exactDph2Id);
    }

    internal static DeepDirectMessagingVerifiedSessionBinding FromInitiatorScope(
        InitiatorInitialSessionVerifiedScope verifiedScope,
        ReadOnlySpan<byte> exactDph2Id)
    {
        ArgumentNullException.ThrowIfNull(verifiedScope);
        return new DeepDirectMessagingVerifiedSessionBinding(
            verifiedScope.NetworkId,
            verifiedScope.RemoteAccountId,
            verifiedScope.RemoteAccountGeneration,
            verifiedScope.RemoteDeviceId,
            verifiedScope.RemoteDeviceGeneration,
            verifiedScope.ConversationId,
            exactDph2Id);
    }

    /// <summary>
    /// Called only on the events returned by the verified responder factory.
    /// This establishes a store scope, not contact acceptance or ACK authority.
    /// An unsolicited initiator has no recipient-side relationship evidence yet.
    /// </summary>
    internal static DeepDirectMessagingVerifiedSessionBinding FromAuthenticatedInbound(
        VerifiedDph2Initiation initiation,
        ReadOnlySpan<byte> exactSessionInitDmc2,
        ReadOnlySpan<byte> exactContactHelloDmc2,
        ReadOnlySpan<byte> localAccountId,
        ReadOnlySpan<byte> localDeviceId,
        ulong localDeviceGeneration)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        RequireIdentifier(localAccountId, 32, nameof(localAccountId));
        RequireIdentifier(localDeviceId, 32, nameof(localDeviceId));
        var dph2 = Dph2Codec.Decode(initiation.ExactBytes.Span);
        var session = ApplicationCoreCodec.DecodeDmc2(exactSessionInitDmc2);
        var hello = ApplicationCoreCodec.DecodeDmc2(exactContactHelloDmc2);
        if (session.ContentKind != Dmc2ContentKind.SessionInit ||
            hello.ContentKind != Dmc2ContentKind.ContactHello ||
            !Fixed(session.CanonicalBytes.Span, exactSessionInitDmc2) ||
            !Fixed(hello.CanonicalBytes.Span, exactContactHelloDmc2) ||
            !Fixed(session.NetworkId.Span, dph2.NetworkId.Span) ||
            !Fixed(hello.NetworkId.Span, dph2.NetworkId.Span) ||
            !Fixed(session.SenderAccountId.Span, dph2.InitiatorAccountId.Span) ||
            !Fixed(hello.SenderAccountId.Span, dph2.InitiatorAccountId.Span) ||
            !Fixed(session.SenderDeviceId.Span, dph2.InitiatorDeviceId.Span) ||
            !Fixed(hello.SenderDeviceId.Span, dph2.InitiatorDeviceId.Span) ||
            !Fixed(localAccountId, dph2.ResponderAccountId.Span) ||
            !Fixed(localDeviceId, dph2.ResponderDeviceId.Span) ||
            localDeviceGeneration != dph2.ResponderDeviceGeneration ||
            Fixed(localAccountId, dph2.InitiatorAccountId.Span))
            throw new CryptographicException(
                "The authenticated first-contact events differ from DPH2.");
        var sessionPayload = session.PayloadBytes.Span;
        var helloPayload = hello.PayloadBytes.Span;
        var directoryLength = BinaryPrimitives.ReadUInt32BigEndian(sessionPayload.Slice(64, 4));
        var directory = ApplicationCoreCodec.DecodeDmd1(
            sessionPayload.Slice(68, checked((int)directoryLength)));
        var relationshipId = ContactRelationshipId32.FromBytes(helloPayload[..32]);
        var conversationId = ContactConversationId32.Derive(
            dph2.NetworkId.Span, relationshipId,
            localAccountId, dph2.InitiatorAccountId.Span);
        if (!Fixed(session.ConversationId.Span, conversationId.Span) ||
            !Fixed(hello.ConversationId.Span, conversationId.Span) ||
            !Fixed(sessionPayload.Slice(32, 32), directory.RecordHash.Span) ||
            !Fixed(helloPayload.Slice(70, 32), directory.RecordHash.Span) ||
            !Fixed(directory.DeepAccountId.Span, dph2.InitiatorAccountId.Span))
            throw new CryptographicException(
                "The authenticated first-contact conversation or directory differs from DPH2.");
        var device = directory.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.DeviceId.Span, dph2.InitiatorDeviceId.Span));
        if (device is null ||
            !Fixed(device.Dpd1Reference.CanonicalHash.Span,
                dph2.InitiatorDpd1Ref.Span[6..]))
            throw new CryptographicException(
                "The authenticated first-contact device differs from DPH2.");
        return new DeepDirectMessagingVerifiedSessionBinding(
            dph2.NetworkId.Span,
            dph2.InitiatorAccountId.Span,
            directory.AccountGeneration,
            dph2.InitiatorDeviceId.Span,
            dph2.InitiatorDeviceGeneration,
            conversationId.Span,
            dph2.SessionId.Span);
    }

    internal static DeepDirectMessagingVerifiedSessionBinding FromCommittedInboundCatalog(
        VerifiedDph2Initiation initiation,
        DeepDirectMessagingSessionCatalogEntry entry,
        ReadOnlySpan<byte> localAccountId,
        ReadOnlySpan<byte> localDeviceId,
        ulong localDeviceGeneration)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        ArgumentNullException.ThrowIfNull(entry);
        RequireIdentifier(localAccountId, 32, nameof(localAccountId));
        RequireIdentifier(localDeviceId, 32, nameof(localDeviceId));
        var dph2 = Dph2Codec.Decode(initiation.ExactBytes.Span);
        if (!Fixed(localAccountId, dph2.ResponderAccountId.Span) ||
            !Fixed(localDeviceId, dph2.ResponderDeviceId.Span) ||
            localDeviceGeneration != dph2.ResponderDeviceGeneration ||
            !Fixed(entry.ExactDph2Id.Span, dph2.SessionId.Span) ||
            !Fixed(entry.RemoteAccountId.Span, dph2.InitiatorAccountId.Span) ||
            !Fixed(entry.RemoteDeviceId.Span, dph2.InitiatorDeviceId.Span) ||
            entry.RemoteDeviceGeneration != dph2.InitiatorDeviceGeneration)
            throw new CryptographicException(
                "The committed inbound session differs from verified DPH2.");
        return new DeepDirectMessagingVerifiedSessionBinding(
            dph2.NetworkId.Span,
            entry.RemoteAccountId.Span,
            entry.RemoteAccountGeneration,
            entry.RemoteDeviceId.Span,
            entry.RemoteDeviceGeneration,
            entry.ConversationId.Span,
            dph2.SessionId.Span);
    }

    internal static DeepDirectMessagingVerifiedSessionBinding FromCommittedEstablishedCatalog(
        Dpe2Record envelope,
        DeepDirectMessagingSessionCatalogEntry entry,
        DeepDirectMessagingLocalAuthorityBinding localAuthority)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(localAuthority);
        if (!Fixed(envelope.NetworkId.Span, localAuthority.NetworkId) ||
            !Fixed(envelope.RecipientDeviceId.Span, localAuthority.DeviceId) ||
            !Fixed(envelope.SenderDeviceId.Span, entry.RemoteDeviceId.Span) ||
            !Fixed(envelope.SessionId.Span, entry.ExactDph2Id.Span))
            throw new CryptographicException(
                "The established inbound envelope differs from the committed local session.");
        return new DeepDirectMessagingVerifiedSessionBinding(
            localAuthority.NetworkId,
            entry.RemoteAccountId.Span,
            entry.RemoteAccountGeneration,
            entry.RemoteDeviceId.Span,
            entry.RemoteDeviceGeneration,
            entry.ConversationId.Span,
            entry.ExactDph2Id.Span);
    }

#if DEEP_TEST_INTERNALS
    internal static DeepDirectMessagingVerifiedSessionBinding CreateForTests(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> remoteAccountId,
        ulong remoteAccountGeneration,
        ReadOnlySpan<byte> remoteDeviceId,
        ulong remoteDeviceGeneration,
        ContactConversationId32 conversationId,
        ReadOnlySpan<byte> exactDph2Id) => new(
            networkId,
            remoteAccountId,
            remoteAccountGeneration,
            remoteDeviceId,
            remoteDeviceGeneration,
            conversationId.Span,
            exactDph2Id);
#endif

    internal byte[] ComputeCatalogKey(
        DeepDirectMessagingLocalAuthorityBinding localAuthority)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Client/DirectMessaging/session-catalog-key/v1\0"u8);
        Append(hash, localAuthority.NetworkId);
        Append(hash, localAuthority.AccountId);
        Append(hash, U64(localAuthority.AccountGeneration));
        Append(hash, localAuthority.DeviceId);
        Append(hash, U64(localAuthority.DeviceGeneration));
        Append(hash, remoteAccountId);
        Append(hash, U64(RemoteAccountGeneration));
        Append(hash, remoteDeviceId);
        Append(hash, U64(RemoteDeviceGeneration));
        Append(hash, conversationId);
        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static void RequireIdentifier(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} must be exactly {length} nonzero bytes.", name);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class DeepDirectMessagingSessionCatalogEntry
{
    private readonly byte[] remoteAccountId;
    private readonly byte[] remoteDeviceId;
    private readonly byte[] conversationId;
    private readonly byte[] exactDph2Id;

    internal DeepDirectMessagingSessionCatalogEntry(
        ReadOnlySpan<byte> remoteAccountId,
        ulong remoteAccountGeneration,
        ReadOnlySpan<byte> remoteDeviceId,
        ulong remoteDeviceGeneration,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> exactDph2Id)
    {
        this.remoteAccountId = remoteAccountId.ToArray();
        this.remoteDeviceId = remoteDeviceId.ToArray();
        this.conversationId = conversationId.ToArray();
        this.exactDph2Id = exactDph2Id.ToArray();
        RemoteAccountGeneration = remoteAccountGeneration;
        RemoteDeviceGeneration = remoteDeviceGeneration;
    }

    internal ReadOnlyMemory<byte> RemoteAccountId => remoteAccountId.ToArray();
    internal ulong RemoteAccountGeneration { get; }
    internal ReadOnlyMemory<byte> RemoteDeviceId => remoteDeviceId.ToArray();
    internal ulong RemoteDeviceGeneration { get; }
    internal ContactConversationId32 ConversationId => ContactConversationId32.FromBytes(conversationId);
    internal ReadOnlyMemory<byte> ExactDph2Id => exactDph2Id.ToArray();
}

internal sealed record DeepDirectMessagingSessionStoreBinding(
    DeepDirectMessagingSessionCatalogEntry CatalogEntry,
    SqliteMessagingCryptoV1Store Store);

public sealed class DeepDirectMessagingInventoryPublication
{
    private readonly object ownerToken;
    private readonly PreKeyV1PublicationRequest publicationRequest;
    private readonly byte[] operationId;
    private readonly byte[] predecessorXpi1Hash;
    private readonly byte[] currentDmd1Hash;
    private readonly byte[] xpi1Hash;
    private readonly byte[] exactXpi1;
    private readonly byte[] exactXpp1;

    internal DeepDirectMessagingInventoryPublication(
        PreKeyV1InventoryStageResult staged,
        object ownerToken)
    {
        ArgumentNullException.ThrowIfNull(staged);
        this.ownerToken = ownerToken ?? throw new ArgumentNullException(nameof(ownerToken));
        var publication = staged.Publication ?? throw new CryptographicException(
            "The durable DPK2 inventory result contains no publication request.");
        publicationRequest = publication;
        if (staged.ForkLatched ||
            staged.Disposition is PreKeyV1InventoryStageDisposition.ForkLatched or
                PreKeyV1InventoryStageDisposition.AlreadyForkLatched)
        {
            throw new CryptographicException(
                "The DPK2 inventory lineage is fork-latched and cannot be published.");
        }
        IsExactReplay = staged.Disposition == PreKeyV1InventoryStageDisposition.ExactReplay;
        InventoryEpoch = publication.InventoryEpoch;
        ServiceGeneration = publication.ServiceGeneration;
        CurrentDmd1Generation = publication.CurrentDmd1Generation;
        operationId = publication.OperationId.ToArray();
        predecessorXpi1Hash = publication.PredecessorXpi1Hash.ToArray();
        currentDmd1Hash = publication.CurrentDmd1Hash.ToArray();
        xpi1Hash = publication.Xpi1Hash.ToArray();
        exactXpi1 = publication.ExactXpi1.ToArray();
        exactXpp1 = publication.ExactPublicationRequest.ToArray();
    }

    public bool IsExactReplay { get; }
    public ulong InventoryEpoch { get; }
    public ulong ServiceGeneration { get; }
    public ulong CurrentDmd1Generation { get; }
    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public ReadOnlyMemory<byte> PredecessorXpi1Hash => predecessorXpi1Hash.ToArray();
    public ReadOnlyMemory<byte> CurrentDmd1Hash => currentDmd1Hash.ToArray();
    public ReadOnlyMemory<byte> Xpi1Hash => xpi1Hash.ToArray();
    public ReadOnlyMemory<byte> ExactXpi1 => exactXpi1.ToArray();
    public ReadOnlyMemory<byte> ExactPublicationRequest => exactXpp1.ToArray();

    internal PreKeyV1DurablePublicationOperation BindDurableOperation(
        object expectedOwnerToken)
    {
        if (!ReferenceEquals(ownerToken, expectedOwnerToken))
            throw new CryptographicException(
                "The DPK2 publication belongs to another direct-message owner.");
        return new PreKeyV1DurablePublicationOperation(publicationRequest);
    }
}

/// <summary>
/// One-use Protocol DPH2 preparation plus the verifier-minted contact/device
/// scope needed by the later privacy-routed XPK1 adapter. It owns all ephemeral
/// initiator material until completion or disposal.
/// </summary>
public sealed class DeepDirectMessagingInitiatorClaimPreparation : IDisposable
{
    private readonly object ownerToken;
    private readonly byte[] networkId;
    private readonly byte[] operationId;
    private readonly byte[] responderAccountId;
    private readonly byte[] responderDeviceId;
    private readonly byte[] senderEphemeralCommitment;
    private readonly byte[] exactDpk2;
    private readonly byte[] exactDpk2Hash;
    private InitiatorDph2ClaimPreparation? preparation;
    private int disposed;

    internal DeepDirectMessagingInitiatorClaimPreparation(
        object ownerToken,
        ContactResolverReverifiedPeerAuthority verifiedPeer,
        VerifiedDpk2Offering verifiedOffering,
        InitiatorInitialSessionVerifiedScope verifiedScope,
        VerifiedDmd1 currentDirectory,
        InitiatorDph2ClaimPreparation preparation)
    {
        this.ownerToken = ownerToken ?? throw new ArgumentNullException(nameof(ownerToken));
        VerifiedPeer = verifiedPeer ?? throw new ArgumentNullException(nameof(verifiedPeer));
        VerifiedOffering = verifiedOffering ?? throw new ArgumentNullException(nameof(verifiedOffering));
        VerifiedScope = verifiedScope ?? throw new ArgumentNullException(nameof(verifiedScope));
        CurrentDirectory = currentDirectory ?? throw new ArgumentNullException(nameof(currentDirectory));
        this.preparation = preparation ?? throw new ArgumentNullException(nameof(preparation));
        networkId = preparation.NetworkId.ToArray();
        operationId = preparation.ClaimOperationId.ToArray();
        responderAccountId = preparation.ResponderAccountId.ToArray();
        responderDeviceId = preparation.ResponderDeviceId.ToArray();
        senderEphemeralCommitment = preparation.SenderEphemeralCommitment.ToArray();
        exactDpk2 = verifiedOffering.ExactBytes.ToArray();
        exactDpk2Hash = verifiedOffering.ExactHash.ToArray();
    }

    internal ContactResolverReverifiedPeerAuthority VerifiedPeer { get; }
    internal VerifiedDpk2Offering VerifiedOffering { get; }
    internal InitiatorInitialSessionVerifiedScope VerifiedScope { get; }
    internal VerifiedDmd1 CurrentDirectory { get; }
    public ReadOnlyMemory<byte> NetworkId => Copy(networkId);
    public ReadOnlyMemory<byte> ClaimOperationId => Copy(operationId);
    public ReadOnlyMemory<byte> ResponderAccountId => Copy(responderAccountId);
    public ReadOnlyMemory<byte> ResponderDeviceId => Copy(responderDeviceId);
    public ReadOnlyMemory<byte> SenderEphemeralCommitment => Copy(senderEphemeralCommitment);
    public ReadOnlyMemory<byte> ExactDpk2 => Copy(exactDpk2);
    public ReadOnlyMemory<byte> ExactDpk2Hash => Copy(exactDpk2Hash);

    internal InitiatorInitialSessionCommitCapability Complete(
        object expectedOwnerToken,
        VerifiedXpc1PreKeyClaimReceipt verifiedClaim,
        ReadOnlySpan<byte> exactSessionInitDmc2,
        ReadOnlySpan<byte> exactFirstApplicationDmc2)
    {
        ArgumentNullException.ThrowIfNull(verifiedClaim);
        if (!ReferenceEquals(ownerToken, expectedOwnerToken))
        {
            throw new CryptographicException(
                "The DPH2 preparation belongs to another direct-message owner.");
        }
        var owned = Interlocked.Exchange(ref preparation, null) ??
            throw new ObjectDisposedException(nameof(DeepDirectMessagingInitiatorClaimPreparation));
        try
        {
            return owned.Complete(
                verifiedClaim,
                exactSessionInitDmc2,
                exactFirstApplicationDmc2);
        }
        finally
        {
            owned.Dispose();
            DisposePublicValues();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }
        Interlocked.Exchange(ref preparation, null)?.Dispose();
        DisposePublicValues();
    }

    private void DisposePublicValues()
    {
        CryptographicOperations.ZeroMemory(networkId);
        CryptographicOperations.ZeroMemory(operationId);
        CryptographicOperations.ZeroMemory(responderAccountId);
        CryptographicOperations.ZeroMemory(responderDeviceId);
        CryptographicOperations.ZeroMemory(senderEphemeralCommitment);
        CryptographicOperations.ZeroMemory(exactDpk2);
        CryptographicOperations.ZeroMemory(exactDpk2Hash);
        Interlocked.Exchange(ref disposed, 1);
    }

    private byte[] Copy(byte[] value)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return value.ToArray();
    }
}

/// <summary>
/// One-use pre-XPK1 owner. It keeps the freshly generated initiator secrets
/// private while exposing only the operation ID and sender commitment required
/// by the exact XPK1 claim.
/// </summary>
public sealed class DeepDirectMessagingInitiatorClaimStart : IDisposable
{
    private readonly object ownerToken;
    private readonly byte[] operationId;
    private readonly byte[] senderCommitment;
    private InitiatorDph2PreKeyClaim? claim;
    private int disposed;

    internal DeepDirectMessagingInitiatorClaimStart(
        object ownerToken,
        ContactResolverReverifiedPeerAuthority verifiedPeer,
        VerifiedDmd1 currentDirectory,
        InitiatorDph2PreKeyClaim claim)
    {
        this.ownerToken = ownerToken ?? throw new ArgumentNullException(nameof(ownerToken));
        VerifiedPeer = verifiedPeer ?? throw new ArgumentNullException(nameof(verifiedPeer));
        CurrentDirectory = currentDirectory ?? throw new ArgumentNullException(nameof(currentDirectory));
        this.claim = claim ?? throw new ArgumentNullException(nameof(claim));
        operationId = claim.ClaimOperationId.ToArray();
        senderCommitment = claim.SenderEphemeralCommitment.ToArray();
    }

    internal ContactResolverReverifiedPeerAuthority VerifiedPeer { get; }
    internal VerifiedDmd1 CurrentDirectory { get; }
    public ReadOnlyMemory<byte> ClaimOperationId => Copy(operationId);
    public ReadOnlyMemory<byte> SenderEphemeralCommitment => Copy(senderCommitment);

    internal InitiatorDph2PreKeyClaim Consume(object expectedOwnerToken)
    {
        if (!ReferenceEquals(ownerToken, expectedOwnerToken))
            throw new CryptographicException("The pre-XPK1 claim belongs to another direct-message owner.");
        var owned = Interlocked.Exchange(ref claim, null) ??
            throw new ObjectDisposedException(nameof(DeepDirectMessagingInitiatorClaimStart));
        DisposePublicValues();
        return owned;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        Interlocked.Exchange(ref claim, null)?.Dispose();
        CryptographicOperations.ZeroMemory(operationId);
        CryptographicOperations.ZeroMemory(senderCommitment);
    }

    private void DisposePublicValues()
    {
        CryptographicOperations.ZeroMemory(operationId);
        CryptographicOperations.ZeroMemory(senderCommitment);
        Interlocked.Exchange(ref disposed, 1);
    }

    private byte[] Copy(byte[] value)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return value.ToArray();
    }
}

public sealed class DeepDirectMessagingInitiatorCommitResult : IDisposable
{
    private readonly byte[] stateCommitment;
    private readonly byte[] journalHead;
    private byte[]? exactDph2;
    private byte[]? claimOperationId;
    private byte[]? fullReplayHash;

    internal DeepDirectMessagingInitiatorCommitResult(
        MessagingCryptoV1CommitResult commit,
        InitiatorInitialSessionDispatchEnvelope dispatch,
        DeepDirectMessagingVerifiedSessionBinding session)
    {
        ArgumentNullException.ThrowIfNull(commit);
        ArgumentNullException.ThrowIfNull(dispatch);
        Session = session ?? throw new ArgumentNullException(nameof(session));
        Disposition = commit.Disposition;
        StateGeneration = commit.StateGeneration;
        JournalGeneration = commit.JournalGeneration;
        ForkLatched = commit.ForkLatched;
        TerminallyLatched = commit.TerminallyLatched;
        stateCommitment = commit.StateCommitment.ToArray();
        journalHead = commit.JournalHead.ToArray();
        exactDph2 = dispatch.ExactDph2.ToArray();
        claimOperationId = dispatch.OperationId.ToArray();
        fullReplayHash = dispatch.ReplayHash.ToArray();
    }

    internal MessagingCryptoV1CommitDisposition Disposition { get; }
    public DeepDirectMessagingVerifiedSessionBinding Session { get; }
    public ulong StateGeneration { get; }
    public ReadOnlyMemory<byte> StateCommitment => stateCommitment.ToArray();
    public ulong JournalGeneration { get; }
    public ReadOnlyMemory<byte> JournalHead => journalHead.ToArray();
    public bool ForkLatched { get; }
    public bool TerminallyLatched { get; }
    public ReadOnlyMemory<byte> ExactDph2 => Value(exactDph2).ToArray();
    public ReadOnlyMemory<byte> ClaimOperationId => Value(claimOperationId).ToArray();
    public ReadOnlyMemory<byte> FullReplayHash => Value(fullReplayHash).ToArray();

    public void Dispose()
    {
        Zero(Interlocked.Exchange(ref exactDph2, null));
        Zero(Interlocked.Exchange(ref claimOperationId, null));
        Zero(Interlocked.Exchange(ref fullReplayHash, null));
        CryptographicOperations.ZeroMemory(stateCommitment);
        CryptographicOperations.ZeroMemory(journalHead);
    }

    private static byte[] Value(byte[]? value) =>
        value ?? throw new ObjectDisposedException(nameof(DeepDirectMessagingInitiatorCommitResult));
    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}

/// <summary>
/// Account-owned storage graph for the clean-break direct-message path. It owns
/// one device-wide DPK2 secret store and one independently keyed DPE2 ratchet
/// store per verified contact/device/session tuple. It performs no network I/O.
/// </summary>
public sealed class DeepDirectMessagingUnsolicitedCommitResult
{
    internal DeepDirectMessagingUnsolicitedCommitResult(
        PreKeyV1InitialSessionSagaResult saga,
        DeepDirectMessagingVerifiedSessionBinding? session)
    {
        Saga = saga;
        Session = session;
    }

    internal PreKeyV1InitialSessionSagaResult Saga { get; }
    public bool IsDurablyStaged =>
        Saga.Disposition is PreKeyV1InitialSessionSagaDisposition.Initialized or
            PreKeyV1InitialSessionSagaDisposition.ExactReplay;
    public DeepDirectMessagingVerifiedSessionBinding? Session { get; }
}

internal sealed class DeepDirectMessagingStorageOwner : IAsyncDisposable
{
    private const string PreKeyPath = "deep-store-v1/direct-prekeys.dpk2";
    private const string CatalogPath = "deep-store-v1/direct-sessions.dsc1";
    private const string SessionsDirectory = "deep-store-v1/direct-sessions";
    private const string PreKeySlotSuffix = ".direct-prekey-v1-key";
    private const string CatalogSlotSuffix = ".direct-session-catalog-key";
    private const string SessionSlotSuffix = ".direct-session-key.";
    private readonly string appDataDirectory;
    private readonly IDeepSecureStorage secureStorage;
    private readonly DeepAccountService accountService;
    private readonly DeepLocalIdentitySnapshot identity;
    private readonly DeepDirectMessagingLocalAuthorityBinding localAuthority;
    private readonly SqlitePreKeyV1SecretOwner preKeyOwner;
    private readonly ProductionPreKeyV1InventoryOwner? inventoryOwner;
    private readonly DeepDirectMessagingSessionCatalog catalog;
    private readonly object ownerToken = new();
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly SemaphoreSlim responderSagaGate = new(1, 1);
    private readonly Dictionary<string, DeepDirectMessagingSessionStoreBinding> sessions =
        new(StringComparer.Ordinal);
    private int disposed;

    private DeepDirectMessagingStorageOwner(
        string appDataDirectory,
        IDeepSecureStorage secureStorage,
        DeepAccountService accountService,
        DeepLocalIdentitySnapshot identity,
        DeepDirectMessagingLocalAuthorityBinding localAuthority,
        SqlitePreKeyV1SecretOwner preKeyOwner,
        ProductionPreKeyV1InventoryOwner? inventoryOwner,
        DeepDirectMessagingSessionCatalog catalog)
    {
        this.appDataDirectory = appDataDirectory;
        this.secureStorage = secureStorage;
        this.accountService = accountService;
        this.identity = identity;
        this.localAuthority = localAuthority;
        this.preKeyOwner = preKeyOwner;
        this.inventoryOwner = inventoryOwner;
        this.catalog = catalog;
    }

    internal SqlitePreKeyV1SecretOwner PreKeyOwner => preKeyOwner;
    internal bool IsCatalogKeyZeroedForTesting => catalog.IsKeyZeroedForTesting;
    internal bool IsPreKeyOwnerKeyZeroedForTesting => preKeyOwner.IsKeyZeroedForTesting;
    internal bool HasProductionInventoryOwner => inventoryOwner is not null;

    internal static async Task<DeepDirectMessagingStorageOwner> OpenAsync(
        string appDataDirectory,
        IDeepSecureStorage secureStorage,
        DeepAccountService accountService,
        DeepLocalIdentitySnapshot identity,
        DeepDirectMessagingLocalAuthorityBinding localAuthority,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appDataDirectory);
        ArgumentNullException.ThrowIfNull(secureStorage);
        ArgumentNullException.ThrowIfNull(accountService);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(localAuthority);
        cancellationToken.ThrowIfCancellationRequested();
        if (!localAuthority.Matches(identity))
        {
            throw new CryptographicException(
                "The verified local messaging authority belongs to another account or device generation.");
        }

        var root = Path.GetFullPath(appDataDirectory);
        var preKeyPath = Path.Combine(root, PreKeyPath);
        var catalogPath = Path.Combine(root, CatalogPath);
        var preKeySlot = ScopedSlot(
            identity.SecureSlots.MessageStoreInstanceId,
            PreKeySlotSuffix,
            "direct pre-key owner");
        var catalogSlot = ScopedSlot(
            identity.SecureSlots.MessageStoreInstanceId,
            CatalogSlotSuffix,
            "direct session catalog");
        byte[]? preKeyKey = null;
        byte[]? catalogKey = null;
        var createdSlots = new List<string>(2);
        SqlitePreKeyV1SecretOwner? openedPreKeys = null;
        ProductionPreKeyV1InventoryOwner? openedInventory = null;
        DeepDirectMessagingSessionCatalog? openedCatalog = null;
        try
        {
            preKeyKey = await ReadKeyAsync(
                    secureStorage, preKeySlot, "direct pre-key", cancellationToken)
                .ConfigureAwait(false);
            catalogKey = await ReadKeyAsync(
                    secureStorage, catalogSlot, "direct session catalog", cancellationToken)
                .ConfigureAwait(false);
            if (preKeyKey is null && SqliteFamilyExists(preKeyPath))
            {
                throw ResetRequired(
                    "The direct pre-key database exists without its protected SQLCipher key.");
            }
            if (catalogKey is null && SqliteFamilyExists(catalogPath))
            {
                throw ResetRequired(
                    "The direct session catalog exists without its protected SQLCipher key.");
            }

            var writes = new List<DeepSecureStorageWrite>(2);
            if (preKeyKey is null)
            {
                preKeyKey = CreateNonzeroKey();
                writes.Add(new DeepSecureStorageWrite(preKeySlot, preKeyKey));
                createdSlots.Add(preKeySlot);
            }
            if (catalogKey is null)
            {
                do
                {
                    if (catalogKey is not null)
                    {
                        CryptographicOperations.ZeroMemory(catalogKey);
                    }
                    catalogKey = CreateNonzeroKey();
                }
                while (CryptographicOperations.FixedTimeEquals(preKeyKey, catalogKey));
                writes.Add(new DeepSecureStorageWrite(catalogSlot, catalogKey));
                createdSlots.Add(catalogSlot);
            }
            if (CryptographicOperations.FixedTimeEquals(preKeyKey, catalogKey))
            {
                throw ResetRequired(
                    "The direct pre-key and session-catalog SQLCipher keys are not distinct.");
            }
            if (writes.Count != 0)
            {
                await secureStorage.WriteBatchAsync(writes, cancellationToken)
                    .ConfigureAwait(false);
            }

            var dpd1Reference = CreateDpd1Reference(localAuthority.ExactDpd1Hash);
            try
            {
                var preKeyScope = new PreKeyV1StoreScope(
                    localAuthority.NetworkId,
                    localAuthority.AccountId,
                    localAuthority.AccountGeneration,
                    localAuthority.DeviceId,
                    localAuthority.DeviceGeneration,
                    dpd1Reference,
                    localAuthority.ExactDpd1Hash,
                    checked((ulong)identity.StoreGeneration));
                using var preKeyOptions = new PreKeyV1StoreOptions(
                    preKeyPath,
                    preKeyKey,
                    preKeyScope);
                openedPreKeys = new SqlitePreKeyV1SecretOwner(preKeyOptions);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dpd1Reference);
            }

            if (localAuthority.VerifiedDevice is { } verifiedDevice)
            {
                openedInventory = await ProductionPreKeyV1InventoryOwner.CreateAsync(
                        openedPreKeys,
                        accountService,
                        identity,
                        verifiedDevice,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            var storeInstanceId = await ReadStoreInstanceIdAsync(
                    secureStorage,
                    identity.SecureSlots.MessageStoreInstanceId,
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                openedCatalog = new DeepDirectMessagingSessionCatalog(
                    catalogPath,
                    catalogKey,
                    new DeepDirectMessagingCatalogScope(
                        localAuthority,
                        checked((ulong)identity.StoreGeneration),
                        storeInstanceId));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(storeInstanceId);
            }

            var result = new DeepDirectMessagingStorageOwner(
                root,
                secureStorage,
                accountService,
                identity,
                localAuthority,
                openedPreKeys,
                openedInventory,
                openedCatalog);
            openedPreKeys = null;
            openedInventory = null;
            openedCatalog = null;
            return result;
        }
        catch (Exception exception)
        {
            openedInventory?.Dispose();
            openedInventory = null;
            if (openedPreKeys is not null)
            {
                await openedPreKeys.DisposeAsync().ConfigureAwait(false);
                openedPreKeys = null;
            }
            openedCatalog?.Dispose();
            openedCatalog = null;
            if (createdSlots.Count != 0)
            {
                await secureStorage.DeleteBatchAsync(createdSlots, CancellationToken.None)
                    .ConfigureAwait(false);
                if (createdSlots.Contains(preKeySlot, StringComparer.Ordinal))
                {
                    DeleteSqliteFamily(preKeyPath);
                }
                if (createdSlots.Contains(catalogSlot, StringComparer.Ordinal))
                {
                    DeleteSqliteFamily(catalogPath);
                }
            }
            if (exception is PreKeyV1StoreOpenException)
            {
                throw ResetRequired(
                    "The protected direct pre-key store cannot be opened.",
                    exception);
            }
            throw;
        }
        finally
        {
            openedInventory?.Dispose();
            if (openedPreKeys is not null)
            {
                await openedPreKeys.DisposeAsync().ConfigureAwait(false);
            }
            openedCatalog?.Dispose();
            Zero(preKeyKey);
            Zero(catalogKey);
        }
    }

    internal bool MatchesAuthority(DeepDirectMessagingLocalAuthorityBinding authority) =>
        localAuthority.Matches(authority);

    internal async ValueTask<DeepDirectMessagingMetadataSealingPublicKey>
        PrepareMetadataSealingKeyAsync(
            VerifiedContactRouteProposalAuthority proposal,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proposal);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var current = await accountService.GetLocalIdentityAsync(cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "Metadata-sealing key authoring requires a current local account.");
            if (current.StoreGeneration != identity.StoreGeneration ||
                !localAuthority.Matches(current))
                throw new CryptographicException(
                    "The metadata-sealing key owner no longer belongs to the current account generation.");
            var keys = new ReachabilityMetadataSealingKeyAuthority(secureStorage);
            var binding = await keys.OpenOrCreateForAuthoringAsync(
                current, proposal, cancellationToken).ConfigureAwait(false);
            return new DeepDirectMessagingMetadataSealingPublicKey(binding);
        }
        finally
        {
            gate.Release();
        }
    }

    internal async ValueTask<DeepDirectMessagingOpenedDeposit> OpenInboundDepositAsync(
        VerifiedContactRouteClosure currentLocalRoute,
        ReadOnlyMemory<byte> exactDao1,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentLocalRoute);
        if (exactDao1.IsEmpty)
            throw new ArgumentException("The exact inbound DAO1 is empty.", nameof(exactDao1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var current = await accountService.GetLocalIdentityAsync(cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "Opening an inbound DAO1 requires a current local account.");
            if (current.StoreGeneration != identity.StoreGeneration ||
                !localAuthority.Matches(current))
                throw new CryptographicException(
                    "The DAO1 opening key no longer belongs to the current account generation.");
            var keys = new ReachabilityMetadataSealingKeyAuthority(secureStorage);
            using var opener = await keys.OpenForCurrentRouteAsync(
                current, currentLocalRoute, cancellationToken).ConfigureAwait(false);
            using var opened = await opener.OpenAsync(
                exactDao1, cancellationToken).ConfigureAwait(false);
            MessagingV1InboundInnerValidator.Validate(
                opened.Kind, opened.ExactInner.Span,
                localAuthority.NetworkId, localAuthority.AccountId,
                localAuthority.DeviceId, localAuthority.DeviceGeneration);
            return new DeepDirectMessagingOpenedDeposit(opened, exactDao1.Span);
        }
        finally
        {
            gate.Release();
        }
    }

#if DEEP_CLEAN_PRODUCTION
    internal async ValueTask<DeepDirectMessagingOpenedDeposit> OpenInboundDepositAsync(
        ParsedContactRouteClosure currentLocalRoute,
        ReadOnlyMemory<byte> exactDao1,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentLocalRoute);
        if (exactDao1.IsEmpty)
            throw new ArgumentException("The exact inbound DAO1 is empty.", nameof(exactDao1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var current = await accountService.GetLocalIdentityAsync(cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "Opening an inbound DAO1 requires a current local account.");
            if (current.StoreGeneration != identity.StoreGeneration ||
                !localAuthority.Matches(current))
                throw new CryptographicException(
                    "The DAO1 opening key no longer belongs to the current account generation.");
            var keys = new ReachabilityMetadataSealingKeyAuthority(secureStorage);
            using var opener = await keys.OpenForCurrentRouteAsync(
                current, currentLocalRoute, cancellationToken).ConfigureAwait(false);
            using var opened = await opener.OpenAsync(
                exactDao1, cancellationToken).ConfigureAwait(false);
            MessagingV1InboundInnerValidator.Validate(
                opened.Kind, opened.ExactInner.Span,
                localAuthority.NetworkId, localAuthority.AccountId,
                localAuthority.DeviceId, localAuthority.DeviceGeneration);
            return new DeepDirectMessagingOpenedDeposit(opened, exactDao1.Span);
        }
        finally
        {
            gate.Release();
        }
    }
#endif

    internal async ValueTask<DeepDirectMessagingOpenedDeposit> OpenInboundMailboxEntryAsync(
        VerifiedContactRouteClosure currentLocalRoute,
        ScopedMailboxResolvedRoute currentMailboxRoute,
        ulong cursor,
        ReadOnlyMemory<byte> exactMeo1,
        ReadOnlyMemory<byte> externalEnvelopeDigest,
        MailboxClientDecodePolicy decodePolicy,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentLocalRoute);
        ArgumentNullException.ThrowIfNull(currentMailboxRoute);
        ArgumentNullException.ThrowIfNull(decodePolicy);
        cancellationToken.ThrowIfCancellationRequested();
        if (cursor == 0 ||
            exactMeo1.Length is < MailboxClientLimits.EncryptedEnvelopeHeaderLength or
                > MailboxClientLimits.MaximumEncryptedEnvelopeLength ||
            externalEnvelopeDigest.Length != MailboxClientLimits.DigestLength ||
            !Fixed(exactMeo1.Span.Slice(96, MailboxClientLimits.DigestLength),
                externalEnvelopeDigest.Span))
            throw new CryptographicException(
                "The retrieved MEO1 cursor or external digest is invalid.");
        var envelope = MailboxClientCodec.DecodeEncryptedEnvelope(
            exactMeo1.Span, decodePolicy);
        var canonical = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        if (!Fixed(canonical, exactMeo1.Span))
            throw new CryptographicException(
                "The retrieved MEO1 is not exact canonical wire.");
        PrivacyRoutedMessagingTransport.ValidateRetrievedEnvelope(
            envelope, cursor, currentMailboxRoute, localAuthority.NetworkId);
        return await OpenInboundDepositAsync(
                currentLocalRoute, envelope.Ciphertext, cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask<DeepDirectMessagingInventoryPublication?>
        EnsureInventoryAsync(
            PreKeyV1InventoryAuthoringContext? authoringContext,
            CancellationToken cancellationToken = default)
    {
        if (authoringContext is null)
        {
            return null;
        }
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var owner = inventoryOwner ?? throw new CryptographicException(
                "DPK2 inventory requires a current verified local DPD1/DMD1 authority.");
            var staged = await owner.EnsureInventoryAsync(authoringContext, cancellationToken)
                .ConfigureAwait(false);
            return new DeepDirectMessagingInventoryPublication(staged, ownerToken);
        }
        finally
        {
            gate.Release();
        }
    }

    internal PreKeyV1DurablePublicationOperation BindInventoryPublication(
        DeepDirectMessagingInventoryPublication publication)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ThrowIfDisposed();
        return publication.BindDurableOperation(ownerToken);
    }

    internal async ValueTask<DeepDirectMessagingInitiatorClaimStart?>
        TryBeginInitiatorClaimAsync(
            ContactResolverReverifiedPeerAuthority? verifiedPeer,
            LocalDeviceX25519AgreementAuthority? localAgreementAuthority,
            Dmd1LineageState? exactCurrentDirectory,
            Dab1LineageState? exactCurrentAddressBinding,
            CancellationToken cancellationToken = default)
    {
        if (verifiedPeer is null || localAgreementAuthority is null ||
            exactCurrentDirectory is null || exactCurrentAddressBinding is null)
        {
            return null;
        }
        if (!localAuthority.Matches(localAgreementAuthority) ||
            !Fixed(verifiedPeer.Bundle.Directory.Record.NetworkId.Span, localAuthority.NetworkId))
        {
            throw new CryptographicException(
                "The pre-XPK1 claim is outside the verified local or remote account authority.");
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            throw new CryptographicException(
                "The V1 contact runtime cannot initiate a DID2 DPH2 session.");
        }
        finally
        {
            gate.Release();
        }
    }

    internal async ValueTask<DeepDirectMessagingInitiatorClaimPreparation?>
        TryCompleteInitiatorClaimAsync(
            DeepDirectMessagingInitiatorClaimStart? startedClaim,
            VerifiedDpk2Offering? verifiedOffering,
            LocalDeviceX25519AgreementLease? deviceAgreementLease,
            int maximumMessagesWithoutPqInjection,
            CancellationToken cancellationToken = default)
    {
        if (startedClaim is null || verifiedOffering is null || deviceAgreementLease is null)
        {
            startedClaim?.Dispose();
            deviceAgreementLease?.Dispose();
            return null;
        }
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
        {
            startedClaim.Dispose();
            deviceAgreementLease.Dispose();
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        }

        InitiatorDph2PreKeyClaim? started = null;
        InitiatorDph2ClaimPreparation? prepared = null;
        var leaseTransferred = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                var scope = InitiatorInitialSessionVerifiedScope.FromReverifiedPeer(
                    startedClaim.VerifiedPeer,
                    verifiedOffering.ResponderDeviceId.Span);
                RequireLocalInitiatorLease(deviceAgreementLease);
                RequireVerifiedOfferingMatchesScope(
                    verifiedOffering, startedClaim.VerifiedPeer, scope);
                started = startedClaim.Consume(ownerToken);
                prepared = new ManagedInitiatorInitialSessionFactory(
                        maximumMessagesWithoutPqInjection)
                    .CompleteClaim(started, verifiedOffering, deviceAgreementLease);
                started = null;
                leaseTransferred = true;
                var result = new DeepDirectMessagingInitiatorClaimPreparation(
                    ownerToken,
                    startedClaim.VerifiedPeer,
                    verifiedOffering,
                    scope,
                    startedClaim.CurrentDirectory,
                    prepared);
                prepared = null;
                return result;
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            started?.Dispose();
            prepared?.Dispose();
            startedClaim.Dispose();
            if (!leaseTransferred)
                deviceAgreementLease.Dispose();
        }
    }

    internal async ValueTask<DeepDirectMessagingInitiatorCommitResult?>
        TryCommitInitiatorSessionAsync(
            DeepDirectMessagingInitiatorClaimPreparation? preparedClaim,
            VerifiedXpc1PreKeyClaimReceipt? verifiedClaim,
            ReadOnlyMemory<byte> exactSessionInitDmc2,
            ReadOnlyMemory<byte> exactFirstApplicationDmc2 = default,
            CancellationToken cancellationToken = default)
    {
        if (preparedClaim is null || verifiedClaim is null)
        {
            preparedClaim?.Dispose();
            return null;
        }
        InitiatorInitialSessionCommitCapability? capability = null;
        byte[]? exactDph2Id = null;
        try
        {
            ThrowIfDisposed();
            capability = preparedClaim.Complete(
                ownerToken,
                verifiedClaim,
                exactSessionInitDmc2.Span,
                exactFirstApplicationDmc2.Span);
            exactDph2Id = capability.SessionId.ToArray();
            var session = DeepDirectMessagingVerifiedSessionBinding.FromInitiatorScope(
                preparedClaim.VerifiedScope,
                exactDph2Id);
            var opened = await TryOpenSessionAsync(
                    session,
                    createIfMissing: true,
                    cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "The verified initiator DPH2 session store was not opened.");

            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                var catalogKey = session.ComputeCatalogKey(localAuthority);
                try
                {
                    var keyText = Convert.ToHexStringLower(catalogKey);
                    if (!sessions.TryGetValue(keyText, out var current) ||
                        !ReferenceEquals(current.Store, opened.Store))
                    {
                        throw new CryptographicException(
                            "The initiator session store lost its account-owner binding.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(catalogKey);
                }

                var adapter = new ManagedInitiatorInitialSessionSqliteAdapter(
                    opened.Store,
                    preparedClaim.VerifiedScope);
                var committed = await adapter.CommitAsync(capability, cancellationToken)
                    .ConfigureAwait(false);
                capability = null;
                using var dispatch = await adapter.ReadPendingDispatchAsync(cancellationToken)
                    .ConfigureAwait(false) ?? throw new CryptographicException(
                    "The committed initiator TRS1 has no exact durable DPH2 dispatch.");
                return new DeepDirectMessagingInitiatorCommitResult(
                    committed,
                    dispatch,
                    session);
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            capability?.Dispose();
            preparedClaim.Dispose();
            Zero(exactDph2Id);
        }
    }

    internal ValueTask<DeepDirectMessagingInitiatorCommitResult?>
        TryCommitInitiatorSessionAsync(
            DeepDirectMessagingInitiatorClaimPreparation? preparedClaim,
            VerifiedXpc1PreKeyClaimReceipt? verifiedClaim,
            CancellationToken cancellationToken = default)
    {
        if (preparedClaim is null || verifiedClaim is null)
        {
            preparedClaim?.Dispose();
            return ValueTask.FromResult<DeepDirectMessagingInitiatorCommitResult?>(null);
        }

        byte[]? logicalMessageId = null;
        byte[]? handshakeNonce = null;
        byte[]? exactSessionInit = null;
        try
        {
            logicalMessageId = CreateNonzeroKey();
            handshakeNonce = CreateNonzeroKey();
            var createdAt = checked(verifiedClaim.ServerTimeUnixSeconds * 1000UL);
            var expiresAt = checked(createdAt + 3_600_000UL);
            var payload = ApplicationCoreCodec.CreateSessionInitPayload(
                handshakeNonce,
                preparedClaim.CurrentDirectory.Record,
                SessionInitCapabilities.TextCore |
                SessionInitCapabilities.DeviceControl |
                SessionInitCapabilities.AttachmentCodec);
            var authored = ApplicationCoreCodec.AuthorDmc2(
                preparedClaim.VerifiedScope.NetworkId,
                logicalMessageId,
                preparedClaim.VerifiedScope.ConversationId,
                localAuthority.AccountId,
                localAuthority.DeviceId,
                senderClientSequence: 1,
                createdAt,
                expiresAt,
                Dmc2Flags.None,
                ReadOnlySpan<byte>.Empty,
                payload);
            exactSessionInit = authored.CanonicalBytes.ToArray();
            return TryCommitInitiatorSessionAsync(
                preparedClaim,
                verifiedClaim,
                exactSessionInit,
                cancellationToken: cancellationToken);
        }
        catch
        {
            preparedClaim.Dispose();
            throw;
        }
        finally
        {
            Zero(logicalMessageId);
            Zero(handshakeNonce);
            Zero(exactSessionInit);
        }
    }

#if DEEP_CLEAN_PRODUCTION
    internal ValueTask<DeepDirectMessagingInitiatorCommitResult?>
        TryCommitInitiatorSessionAsync(
            DeepDirectMessagingInitiatorClaimPreparation? preparedClaim,
            VerifiedXpc1PreKeyClaimReceipt? verifiedClaim,
            AuthoredVerifiedContactHello? contactHello,
            CancellationToken cancellationToken = default)
    {
        if (preparedClaim is null || verifiedClaim is null || contactHello is null)
        {
            preparedClaim?.Dispose();
            return ValueTask.FromResult<DeepDirectMessagingInitiatorCommitResult?>(null);
        }

        byte[]? logicalMessageId = null;
        byte[]? handshakeNonce = null;
        byte[]? exactSessionInit = null;
        byte[]? exactContactHello = null;
        try
        {
            var hello = contactHello.Record;
            if (hello.ContentKind != Dmc2ContentKind.ContactHello ||
                hello.SenderClientSequence != 2 ||
                !Fixed(hello.NetworkId.Span, preparedClaim.VerifiedScope.NetworkId) ||
                !Fixed(hello.ConversationId.Span,
                    preparedClaim.VerifiedScope.ConversationId) ||
                !Fixed(hello.SenderAccountId.Span, localAuthority.AccountId) ||
                !Fixed(hello.SenderDeviceId.Span, localAuthority.DeviceId))
            {
                throw new CryptographicException(
                    "The authored ContactHello differs from the verified initiator scope.");
            }

            logicalMessageId = CreateNonzeroKey();
            handshakeNonce = CreateNonzeroKey();
            var createdAt = checked(verifiedClaim.ServerTimeUnixSeconds * 1000UL);
            var expiresAt = checked(createdAt + 3_600_000UL);
            var payload = ApplicationCoreCodec.CreateSessionInitPayload(
                handshakeNonce,
                preparedClaim.CurrentDirectory.Record,
                SessionInitCapabilities.TextCore |
                SessionInitCapabilities.DeviceControl |
                SessionInitCapabilities.AttachmentCodec);
            var authored = ApplicationCoreCodec.AuthorDmc2(
                preparedClaim.VerifiedScope.NetworkId,
                logicalMessageId,
                preparedClaim.VerifiedScope.ConversationId,
                localAuthority.AccountId,
                localAuthority.DeviceId,
                senderClientSequence: 1,
                createdAt,
                expiresAt,
                Dmc2Flags.None,
                ReadOnlySpan<byte>.Empty,
                payload);
            exactSessionInit = authored.CanonicalBytes.ToArray();
            exactContactHello = contactHello.CanonicalBytes.ToArray();
            return TryCommitInitiatorSessionAsync(
                preparedClaim,
                verifiedClaim,
                exactSessionInit,
                exactContactHello,
                cancellationToken);
        }
        catch
        {
            preparedClaim.Dispose();
            throw;
        }
        finally
        {
            Zero(logicalMessageId);
            Zero(handshakeNonce);
            Zero(exactSessionInit);
            Zero(exactContactHello);
        }
    }
#endif

#if DEEP_CLEAN_PRODUCTION
    /// <summary>
    /// Reopens only the exact durable initiator DPH2 for a currently reverified
    /// ContactV1 peer/device scope. A raw session identifier is a selector, not
    /// authority; the account owner and the SQLCipher adapter recheck both
    /// scopes before any bytes are released for a network retry.
    /// </summary>
    internal async ValueTask<InitiatorInitialSessionDispatchEnvelope?>
        TryReadPendingInitiatorDispatchAsync(
            InitiatorInitialSessionVerifiedScope? verifiedPeerScope,
            ReadOnlyMemory<byte> exactSessionId,
            CancellationToken cancellationToken = default)
    {
        if (verifiedPeerScope is null)
            return null;
        if (!Fixed(verifiedPeerScope.NetworkId, localAuthority.NetworkId) ||
            !Fixed(verifiedPeerScope.LocalAccountId, localAuthority.AccountId))
            throw new CryptographicException(
                "The pending DPH2 peer scope belongs to another local account or network.");

        var session = DeepDirectMessagingVerifiedSessionBinding.FromInitiatorScope(
            verifiedPeerScope, exactSessionId.Span);
        var opened = await TryOpenSessionAsync(
                session, createIfMissing: false, cancellationToken)
            .ConfigureAwait(false);
        if (opened is null)
            return null;

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var adapter = new ManagedInitiatorInitialSessionSqliteAdapter(
                opened.Store, verifiedPeerScope);
            return await adapter.ReadPendingDispatchAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>
    /// Verifies the encrypted claim evidence before any responder session
    /// store is opened or local prekey row is reserved. The caller must
    /// supply a verified initiator DMD1 head and fresh account-directory
    /// proof, which Protocol cross-checks at the current monotonic sample.
    /// The caller must then commit the
    /// returned claim through the normal initial-session/inbox saga.
    /// </summary>
    internal async ValueTask<VerifiedDph2InitialClaim?> TryVerifyResponderInitialClaimAsync(
        Dph2Record initiation,
        VerifiedDpk2Offering localOffering,
        Dmd1LineageState initiatorDirectory,
        VerifiedAccountDirectoryFreshness initiatorFreshness,
        VerifiedContactServicePlacement claimPlacement,
        VerifiedContactNetworkAuthority recipientAuthority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        int maximumMessagesWithoutPqInjection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        ArgumentNullException.ThrowIfNull(localOffering);
        ArgumentNullException.ThrowIfNull(initiatorDirectory);
        ArgumentNullException.ThrowIfNull(initiatorFreshness);
        ArgumentNullException.ThrowIfNull(claimPlacement);
        ArgumentNullException.ThrowIfNull(recipientAuthority);
        ArgumentNullException.ThrowIfNull(recipientBundle);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        cancellationToken.ThrowIfCancellationRequested();
        if (localAuthority.VerifiedDevice is null ||
            !Fixed(initiation.NetworkId.Span, localAuthority.NetworkId) ||
            !Fixed(initiation.ResponderAccountId.Span, localAuthority.AccountId) ||
            !Fixed(initiation.ResponderDeviceId.Span, localAuthority.DeviceId) ||
            initiation.ResponderDeviceGeneration != localAuthority.DeviceGeneration ||
            !Fixed(localOffering.NetworkId.Span, localAuthority.NetworkId) ||
            !Fixed(localOffering.ResponderAccountId.Span, localAuthority.AccountId) ||
            !Fixed(localOffering.ResponderDeviceId.Span, localAuthority.DeviceId) ||
            localOffering.ResponderDeviceGeneration != localAuthority.DeviceGeneration)
            throw new CryptographicException(
                "The initial DPH2/DPK2 is outside the verified local device scope.");

        // The verified offering must also be the exact, still-owned local
        // inventory row selected by this DPH2. A remote or stale but correctly
        // signed DPK2 cannot drive protected pre-claim secret restoration.
        var storedOffering = await preKeyOwner.TryReadResponderOfferingAsync(
                initiation, cancellationToken).ConfigureAwait(false);
        if (storedOffering is null)
            return null;
        if (!Fixed(storedOffering, localOffering.ExactBytes.Span))
            throw new CryptographicException(
                "The verified DPK2 differs from the current local pre-key inventory.");

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            using var identityLease = await accountService
                .OpenCurrentResponderIdentitySecretLeaseAsync(
                    identity, maximumMessagesWithoutPqInjection, cancellationToken)
                .ConfigureAwait(false);
            using var factory = identityLease.OpenFactory();
            var preview = await preKeyOwner.TryPreviewInitialClaimAsync(
                    initiation, localOffering, initiatorDirectory, factory,
                    cancellationToken)
                .ConfigureAwait(false);
            if (preview is null)
                return null;
            throw new CryptographicException(
                "The V1 contact runtime cannot promote a DID2 DPH2 claim.");
        }
        finally
        {
            gate.Release();
        }
    }

    internal async ValueTask<Dph2InitialClaimPreview?>
        TryPreviewResponderInitialClaimAsync(
            Dph2Record initiation,
            Dmd1LineageState initiatorDirectory,
            int maximumMessagesWithoutPqInjection,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        ArgumentNullException.ThrowIfNull(initiatorDirectory);
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(
                nameof(maximumMessagesWithoutPqInjection));
        if (localAuthority.VerifiedDevice is null ||
            !Fixed(initiation.NetworkId.Span, localAuthority.NetworkId) ||
            !Fixed(initiation.ResponderAccountId.Span, localAuthority.AccountId) ||
            !Fixed(initiation.ResponderDeviceId.Span, localAuthority.DeviceId) ||
            initiation.ResponderDeviceGeneration != localAuthority.DeviceGeneration)
            throw new CryptographicException(
                "The initial DPH2 is outside the verified local device scope.");

        var exactOffering = await preKeyOwner.TryReadResponderOfferingAsync(
                initiation, cancellationToken)
            .ConfigureAwait(false);
        if (exactOffering is null)
            return null;
        try
        {
            var offering = MessagingWireVerification.VerifyDpk2(
                exactOffering,
                new CurrentLocalDpk2VerificationCallbacks(localAuthority));
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                using var identityLease = await accountService
                    .OpenCurrentResponderIdentitySecretLeaseAsync(
                        identity, maximumMessagesWithoutPqInjection,
                        cancellationToken)
                    .ConfigureAwait(false);
                using var factory = identityLease.OpenFactory();
                return await preKeyOwner.TryPreviewInitialClaimAsync(
                        initiation, offering, initiatorDirectory, factory,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            Zero(exactOffering);
        }
    }

    internal async ValueTask<VerifiedDph2InitialClaim?> TryVerifyResponderInitialClaimAsync(
        Dph2Record initiation,
        Dmd1LineageState initiatorDirectory,
        VerifiedAccountDirectoryFreshness initiatorFreshness,
        VerifiedContactServicePlacement claimPlacement,
        VerifiedContactNetworkAuthority recipientAuthority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        int maximumMessagesWithoutPqInjection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        var exactOffering = await preKeyOwner.TryReadResponderOfferingAsync(
                initiation, cancellationToken)
            .ConfigureAwait(false);
        if (exactOffering is null)
            return null;
        try
        {
            var offering = MessagingWireVerification.VerifyDpk2(
                exactOffering,
                new CurrentLocalDpk2VerificationCallbacks(localAuthority));
            return await TryVerifyResponderInitialClaimAsync(
                    initiation,
                    offering,
                    initiatorDirectory,
                    initiatorFreshness,
                    claimPlacement,
                    recipientAuthority,
                    recipientBundle,
                    trustedTimeAuthority,
                    maximumMessagesWithoutPqInjection,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            Zero(exactOffering);
        }
    }

    private sealed class CurrentLocalDpk2VerificationCallbacks(
        DeepDirectMessagingLocalAuthorityBinding authority)
        : IDpk2VerificationCallbacks
    {
        public Dpk2ResolvedDevice ResolveActiveDevice(Dpk2Record offering)
        {
            var verified = authority.VerifiedDevice ??
                throw new CryptographicException(
                    "The local DPK2 verifier has no current device capability.");
            var certificate = verified.Certificate;
            if (!Fixed(offering.NetworkId.Span, authority.NetworkId) ||
                !Fixed(offering.ResponderAccountId.Span, authority.AccountId) ||
                !Fixed(offering.ResponderDeviceId.Span, authority.DeviceId) ||
                offering.ResponderDeviceGeneration != authority.DeviceGeneration ||
                !Fixed(offering.ResponderDpd1Ref.Span[6..],
                    authority.ExactDpd1Hash))
                throw new CryptographicException(
                    "The stored DPK2 differs from the current local device authority.");
            return new Dpk2ResolvedDevice(
                certificate.DeviceEd25519PublicKey.Span,
                certificate.DeviceX25519PublicKey.Span);
        }

        public bool VerifyEd25519(
            ReadOnlyMemory<byte> publicKey,
            ReadOnlyMemory<byte> signatureInput,
            ReadOnlyMemory<byte> signature) =>
            PublicKeyAuth.VerifyDetached(
                signature.ToArray(), signatureInput.ToArray(), publicKey.ToArray());
    }

    /// <summary>
    /// Commits a verified unsolicited initial session without assuming that a
    /// relationship or conversation-scoped store existed before ContactHello
    /// was decrypted. The authenticated first event selects the fresh store;
    /// an exact finalized replay resolves only an existing protected catalog
    /// entry. This stages DMC2 but does not apply contact state or grant ACK.
    /// </summary>
    internal async ValueTask<DeepDirectMessagingUnsolicitedCommitResult?>
        TryCommitUnsolicitedResponderSessionAsync(
            VerifiedDph2InitialClaim? verifiedInitial,
            int maximumMessagesWithoutPqInjection,
            CancellationToken cancellationToken = default)
    {
        if (verifiedInitial is null) return null;
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        var claim = verifiedInitial.Claim;
        var initiation = verifiedInitial.Initiation;
        var checkpoint = verifiedInitial.InitiatorCheckpoint;
        var recipientBundle = verifiedInitial.RecipientBundle;
        if (checkpoint is null || recipientBundle is null)
            throw new CryptographicException(
                "An unsolicited responder needs current, verified ContactHello endpoint evidence.");
        var dph2 = Dph2Codec.Decode(initiation.ExactBytes.Span);
        if (!Fixed(dph2.NetworkId.Span, localAuthority.NetworkId) ||
            !Fixed(dph2.ResponderAccountId.Span, localAuthority.AccountId) ||
            !Fixed(dph2.ResponderDeviceId.Span, localAuthority.DeviceId) ||
            dph2.ResponderDeviceGeneration != localAuthority.DeviceGeneration ||
            !preKeyOwner.OwnsResponder(
                claim.NetworkId.Span, claim.ResponderAccountId.Span,
                claim.ResponderDeviceId.Span, claim.ResponderDeviceGeneration))
            throw new CryptographicException(
                "The unsolicited DPH2 claim is outside the current local responder scope.");
        if (!Fixed(checkpoint.Binding.Identity.Account.DeepAccountIdHash.Span,
                dph2.InitiatorAccountId.Span) ||
            !Fixed(recipientBundle.Binding.Identity.Account.DeepAccountIdHash.Span,
                localAuthority.AccountId))
            throw new CryptographicException(
                "The verified first-contact endpoints differ from DPH2 or the local account.");

        await responderSagaGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            using var identityLease = await accountService
                .OpenCurrentResponderIdentitySecretLeaseAsync(
                    identity, maximumMessagesWithoutPqInjection, cancellationToken)
                .ConfigureAwait(false);
            using var boundClaim = claim.BindForInitialSession(initiation);
            using var reservation = boundClaim.ConsumeForDevicePreKeyOwner();
            var resolver = new UnsolicitedInitialSessionStoreResolver(
                this, initiation, dph2, verifiedInitial);
            var result = await preKeyOwner.CommitInitialSessionSagaAsync(
                    reservation,
                    boundClaim,
                    resolver,
                    identityLease.OpenFactory(),
                    cancellationToken)
                .ConfigureAwait(false);
            return new DeepDirectMessagingUnsolicitedCommitResult(
                result,
                result.Disposition is PreKeyV1InitialSessionSagaDisposition.Initialized or
                    PreKeyV1InitialSessionSagaDisposition.ExactReplay
                    ? resolver.Session ?? throw new CryptographicException(
                        "The committed inbound DPH2 has no verified session scope.")
                    : null);
        }
        finally { responderSagaGate.Release(); }
    }

    internal sealed class UnsolicitedInitialSessionStoreResolver(
        DeepDirectMessagingStorageOwner owner,
        VerifiedDph2Initiation initiation,
        Dph2Record dph2,
        VerifiedDph2InitialClaim? endpointEvidence) : IInitialSessionStoreResolver
    {
#if DEEP_TEST_INTERNALS
        internal UnsolicitedInitialSessionStoreResolver(
            DeepDirectMessagingStorageOwner owner,
            VerifiedDph2Initiation initiation,
            Dph2Record dph2)
            : this(owner, initiation, dph2, null) { }
#endif
        internal DeepDirectMessagingVerifiedSessionBinding? Session { get; private set; }

        public async ValueTask<SqliteMessagingCryptoV1Store?> ResolveAsync(
            ReadOnlyMemory<byte> exactSessionInitDmc2,
            ReadOnlyMemory<byte> exactFirstApplicationDmc2,
            CancellationToken cancellationToken)
        {
            if (exactSessionInitDmc2.IsEmpty && exactFirstApplicationDmc2.IsEmpty)
            {
                var matches = (await owner.ReadCatalogAsync(cancellationToken)
                        .ConfigureAwait(false))
                    .Where(entry =>
                        Fixed(entry.ExactDph2Id.Span, dph2.SessionId.Span) &&
                        Fixed(entry.RemoteAccountId.Span,
                            dph2.InitiatorAccountId.Span) &&
                        Fixed(entry.RemoteDeviceId.Span,
                            dph2.InitiatorDeviceId.Span))
                    .ToArray();
                if (matches.Length == 0) return null;
                if (matches.Length != 1)
                    throw new CryptographicException(
                        "The exact inbound DPH2 has ambiguous session catalog state.");
                Session = DeepDirectMessagingVerifiedSessionBinding
                    .FromCommittedInboundCatalog(
                        initiation, matches[0], owner.localAuthority.AccountId,
                        owner.localAuthority.DeviceId,
                        owner.localAuthority.DeviceGeneration);
                return (await owner.TryOpenSessionAsync(
                        Session, createIfMissing: false, cancellationToken)
                    .ConfigureAwait(false))?.Store;
            }

            if (exactSessionInitDmc2.IsEmpty || exactFirstApplicationDmc2.IsEmpty)
                throw new CryptographicException(
                    "An unsolicited DPH2 must authenticate SessionInit and ContactHello.");
            var checkpoint = endpointEvidence?.InitiatorCheckpoint ??
                throw new CryptographicException(
                    "The verified DPH2 lacks a current initiator checkpoint.");
            var recipient = endpointEvidence.RecipientBundle ??
                throw new CryptographicException(
                    "The verified DPH2 lacks recipient publication evidence.");
            if (!Fixed(recipient.Binding.Identity.Account.DeepAccountIdHash.Span,
                    owner.localAuthority.AccountId))
                throw new CryptographicException(
                    "The verified recipient publication differs from the local account.");
            throw new CryptographicException(
                "The V1 ContactHello cannot bind a DID2 DPH2 session.");
        }
    }

    internal async ValueTask<PreKeyV1InitialSessionSagaResult?>
        TryCommitResponderSessionAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            VerifiedContactBundleEvidence? relationship,
            VerifiedXpc1PreKeyClaimReceipt? verifiedClaim,
            VerifiedDph2Initiation? verifiedInitiation,
            int maximumMessagesWithoutPqInjection,
            CancellationToken cancellationToken = default)
    {
        if (verifiedSession is null || relationship is null ||
            verifiedClaim is null || verifiedInitiation is null)
        {
            return null;
        }
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        }
        RequireResponderSessionBinding(
            verifiedSession,
            relationship,
            verifiedInitiation);
        var opened = await TryOpenSessionAsync(
                verifiedSession,
                createIfMissing: true,
                cancellationToken)
            .ConfigureAwait(false) ?? throw new CryptographicException(
                "The verified responder DPH2 session store was not opened.");

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var coordinator = new ContactInitialSessionCoordinator(
                preKeyOwner,
                opened.Store,
                relationship,
                accountService,
                identity,
                maximumMessagesWithoutPqInjection);
            return await coordinator.CommitAsync(
                    verifiedClaim,
                    verifiedInitiation,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    internal async ValueTask<DirectTextOutboxEntry?> TryStageDirectTextAsync(
        DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
        SqliteDeepMailboxStore inbox,
        string text,
        DateTimeOffset createdAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        if (verifiedSession is null) return null;
        var opened = await TryOpenSessionAsync(
                verifiedSession, createIfMissing: false, cancellationToken)
            .ConfigureAwait(false);
        if (opened is null) return null;
        return await inbox.StageDirectTextAsync(
                localAuthority.NetworkId.ToArray(),
                localAuthority.AccountId.ToArray(),
                localAuthority.AccountGeneration,
                localAuthority.DeviceId.ToArray(),
                verifiedSession.ConversationId,
                verifiedSession.RemoteAccountId,
                verifiedSession.RemoteDeviceId,
                text,
                createdAt,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask<DirectTextOutboxEntry?> TryReadDirectTextAsync(
        DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
        SqliteDeepMailboxStore inbox,
        ReadOnlyMemory<byte> logicalMessageId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        if (verifiedSession is null) return null;
        var opened = await TryOpenSessionAsync(
                verifiedSession, createIfMissing: false, cancellationToken)
            .ConfigureAwait(false);
        if (opened is null) return null;
        return await inbox.ReadDirectTextAsync(
                localAuthority.NetworkId.ToArray(),
                localAuthority.AccountId.ToArray(),
                localAuthority.AccountGeneration,
                verifiedSession.ConversationId,
                logicalMessageId,
                verifiedSession.RemoteAccountId,
                verifiedSession.RemoteDeviceId,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask<RecoveredDirectSend?> TryRecoverEstablishedSendAsync(
        DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
        ReadOnlyMemory<byte> operationId,
        CancellationToken cancellationToken = default)
    {
        if (verifiedSession is null) return null;
        var opened = await TryOpenSessionAsync(
                verifiedSession, createIfMissing: false, cancellationToken)
            .ConfigureAwait(false);
        if (opened is null) return null;
        var exact = await opened.Store.ReadPendingOutboundDpe2Async(
                operationId, cancellationToken)
            .ConfigureAwait(false);
        if (exact is null) return null;
        try
        {
            var envelope = Dpe2Codec.Decode(exact);
            var canonical = Dpe2Codec.Encode(envelope);
            try
            {
                if (!Fixed(canonical, exact) ||
                    !Fixed(envelope.NetworkId.Span, localAuthority.NetworkId) ||
                    !Fixed(envelope.SessionId.Span, verifiedSession.ExactDph2Id.Span) ||
                    !Fixed(envelope.SenderDeviceId.Span, localAuthority.DeviceId) ||
                    !Fixed(envelope.RecipientDeviceId.Span, verifiedSession.RemoteDeviceId.Span) ||
                    !Fixed(envelope.OperationId.Span, operationId.Span))
                    throw new CryptographicException(
                        "The recovered DPE2 differs from its verified direct session.");
                var hash = MessagingWireCryptographicInputs
                    .ComputeDpe2FullReplayHash(envelope);
                try { return new RecoveredDirectSend(exact, operationId.Span, hash); }
                finally { Zero(hash); }
            }
            finally { Zero(canonical); }
        }
        finally { Zero(exact); }
    }

    /// <summary>
    /// Advances one verified, already activated direct session and commits the
    /// exact DPE2 send transition before releasing the single-use network
    /// dispatch capability. Neither raw TRS1 state nor a caller-provided
    /// persistence authority crosses the account owner boundary.
    /// </summary>
    internal async ValueTask<ExactDpe2SendSuccessCapability?>
        TryCommitEstablishedSendAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            ReadOnlyMemory<byte> exactDmc2,
            ReadOnlyMemory<byte> operationId,
            CancellationToken cancellationToken = default)
    {
        if (verifiedSession is null)
        {
            return null;
        }

        var opened = await TryOpenSessionAsync(
                verifiedSession,
                createIfMissing: false,
                cancellationToken)
            .ConfigureAwait(false);
        if (opened is null)
        {
            return null;
        }

        using var lease = await opened.Store
            .AcquireSendPreparationLeaseAsync(cancellationToken)
            .ConfigureAwait(false);
        using var prepared = lease.PrepareSend(
            exactDmc2.Span,
            localAuthority.NetworkId,
            operationId.Span);
        return await prepared.CommitAsync(
                new ExactDpe2SqliteDurableTransactionAuthority(opened.Store),
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Opens and durably commits one exact DPE2 against its verified session.
    /// The returned capability contains authenticated DMC2 only after the
    /// SQLCipher ratchet/replay/deletion transaction has committed.
    /// </summary>
    internal async ValueTask<ExactDpe2ReceiveSuccessCapability?>
        TryCommitEstablishedReceiveAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            ReadOnlyMemory<byte> exactDpe2,
            CancellationToken cancellationToken = default)
    {
        if (verifiedSession is null)
        {
            return null;
        }

        var opened = await TryOpenSessionAsync(
                verifiedSession,
                createIfMissing: false,
                cancellationToken)
            .ConfigureAwait(false);
        if (opened is null)
        {
            return null;
        }

        using var lease = await opened.Store
            .AcquireReceivePreparationLeaseAsync(exactDpe2, cancellationToken)
            .ConfigureAwait(false);
        using var prepared = lease.PrepareReceive();
        return await prepared.CommitAsync(
                new ExactDpe2SqliteDurableTransactionAuthority(opened.Store),
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Selects an existing active session from the protected catalog using
    /// only canonical DPE2 routing fields. This grants no plaintext or ACK;
    /// the ratchet and inbox commits still authenticate the envelope.
    /// </summary>
    internal async ValueTask<DeepDirectMessagingVerifiedSessionBinding?>
        TryResolveEstablishedInboundSessionAsync(
            ReadOnlyMemory<byte> exactDpe2,
            CancellationToken cancellationToken = default)
    {
        var envelope = Dpe2Codec.Decode(exactDpe2.Span);
        var canonical = Dpe2Codec.Encode(envelope);
        try
        {
            if (!Fixed(canonical, exactDpe2.Span) ||
                !Fixed(envelope.NetworkId.Span, localAuthority.NetworkId) ||
                !Fixed(envelope.RecipientDeviceId.Span, localAuthority.DeviceId))
                throw new CryptographicException(
                    "The established inbound envelope is not canonical or not addressed to this device.");
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                var matches = catalog.ReadAll().Where(row =>
                    row.State == DirectSessionCatalogState.Active &&
                    Fixed(row.ExactDph2Id, envelope.SessionId.Span) &&
                    Fixed(row.RemoteDeviceId, envelope.SenderDeviceId.Span))
                    .Take(2).ToArray();
                if (matches.Length == 0) return null;
                if (matches.Length != 1)
                    throw new CryptographicException(
                        "The established inbound envelope has ambiguous committed session state.");
                return DeepDirectMessagingVerifiedSessionBinding
                    .FromCommittedEstablishedCatalog(
                        envelope, matches[0].ToEntry(), localAuthority);
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            Zero(canonical);
        }
    }

    /// <summary>
    /// Replays the recoverable DMC2 handoff into the account-wide semantic
    /// inbox. The exact session envelope and verified peer are checked before
    /// the protected stage is read. No mailbox ACK is minted here.
    /// </summary>
    internal async ValueTask<DirectDmc2InboxDisposition?>
        TryMaterializeEstablishedReceiveAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            ReadOnlyMemory<byte> exactDpe2,
            SqliteDeepMailboxStore inbox,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        if (verifiedSession is null) return null;
        var opened = await TryOpenSessionAsync(
                verifiedSession, createIfMissing: false, cancellationToken)
            .ConfigureAwait(false);
        if (opened is null) return null;

        var record = Dpe2Codec.Decode(exactDpe2.Span);
        var canonical = Dpe2Codec.Encode(record);
        var envelopeHash = MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(record);
        var localNetwork = localAuthority.NetworkId.ToArray();
        var localAccount = localAuthority.AccountId.ToArray();
        try
        {
            if (!Fixed(canonical, exactDpe2.Span) ||
                !Fixed(record.NetworkId.Span, localAuthority.NetworkId) ||
                !Fixed(record.NetworkId.Span, verifiedSession.NetworkId.Span) ||
                !Fixed(record.SessionId.Span, verifiedSession.ExactDph2Id.Span) ||
                !Fixed(record.SenderDeviceId.Span, verifiedSession.RemoteDeviceId.Span) ||
                !Fixed(record.RecipientDeviceId.Span, localAuthority.DeviceId))
                throw new CryptographicException(
                    "The direct inbox handoff is outside the verified DPE2 session.");

            using var handoff = await AuthenticatedDirectDmc2.FromCommittedStageAsync(
                opened.Store,
                record.OperationId,
                envelopeHash,
                localNetwork,
                localAccount,
                localAuthority.AccountGeneration,
                verifiedSession.ConversationId,
                verifiedSession.RemoteAccountId,
                verifiedSession.RemoteDeviceId,
                cancellationToken).ConfigureAwait(false);
            if (handoff is null) return null;
            return await inbox.MaterializeDirectDmc2Async(handoff, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            Zero(canonical);
            Zero(envelopeHash);
            Zero(localNetwork);
            Zero(localAccount);
        }
    }

    /// <summary>
    /// Replays the authenticated DPH2 batch staged with the initial TRS1 into
    /// the account inbox. This does not apply ContactHello relationship state
    /// and therefore cannot mint a transport ACK by itself.
    /// </summary>
    internal async ValueTask<DirectDmc2InboxDisposition?>
        TryMaterializeInitialReceiveAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            VerifiedContactBundleEvidence? relationship,
            VerifiedDph2Initiation? verifiedInitiation,
            SqliteDeepMailboxStore inbox,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        if (verifiedSession is null || relationship is null || verifiedInitiation is null)
            return null;
        RequireResponderSessionBinding(verifiedSession, relationship, verifiedInitiation);
        var opened = await TryOpenSessionAsync(
                verifiedSession, createIfMissing: false, cancellationToken)
            .ConfigureAwait(false);
        if (opened is null) return null;
        var localNetwork = localAuthority.NetworkId.ToArray();
        var localAccount = localAuthority.AccountId.ToArray();
        try
        {
            using var batch = await AuthenticatedInitialDmc2Batch.FromCommittedStageAsync(
                opened.Store,
                verifiedInitiation.ClaimOperationId,
                verifiedInitiation.FullReplayHash,
                localNetwork,
                localAccount,
                localAuthority.AccountGeneration,
                verifiedSession.ConversationId,
                verifiedSession.RemoteAccountId,
                verifiedSession.RemoteDeviceId,
                relationship.RelationshipId.ToArray(),
                relationship.ArtifactHashes[ContactVerifiedArtifactKind.Dab1].ToArray(),
                relationship.ArtifactHashes[ContactVerifiedArtifactKind.Dmd1].ToArray(),
                cancellationToken).ConfigureAwait(false);
            if (batch is null) return null;
            return await inbox.MaterializeInitialDmc2BatchAsync(batch, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            Zero(localNetwork);
            Zero(localAccount);
        }
    }

    /// <summary>
    /// Materializes an unsolicited SessionInit + ContactHello only from the
    /// exact committed DPH2 and its current initiator checkpoint. This stores
    /// the inbound contact request durably without pretending that a full
    /// resolver bundle for the initiator already exists.
    /// </summary>
    internal async ValueTask<DirectDmc2InboxDisposition?>
        TryMaterializeInitialReceiveAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            VerifiedDph2InitialClaim? verifiedInitial,
            SqliteDeepMailboxStore inbox,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        if (verifiedSession is null || verifiedInitial is null)
            return null;
        var initiation = verifiedInitial.Initiation;
        var dph2 = Dph2Codec.Decode(initiation.ExactBytes.Span);
        if (!Fixed(verifiedSession.NetworkId.Span, dph2.NetworkId.Span) ||
            !Fixed(verifiedSession.ExactDph2Id.Span, dph2.SessionId.Span) ||
            !Fixed(verifiedSession.RemoteAccountId.Span,
                dph2.InitiatorAccountId.Span) ||
            !Fixed(verifiedSession.RemoteDeviceId.Span,
                dph2.InitiatorDeviceId.Span) ||
            !Fixed(localAuthority.AccountId, dph2.ResponderAccountId.Span) ||
            !Fixed(localAuthority.DeviceId, dph2.ResponderDeviceId.Span))
            throw new CryptographicException(
                "The unsolicited inbox handoff differs from its verified DPH2 session.");
        var opened = await TryOpenSessionAsync(
                verifiedSession, createIfMissing: false, cancellationToken)
            .ConfigureAwait(false);
        if (opened is null)
            return null;
        var localAccount = localAuthority.AccountId.ToArray();
        try
        {
            using var batch = await AuthenticatedInitialDmc2Batch
                .FromCommittedVerifiedInitialStageAsync(
                    opened.Store,
                    verifiedInitial,
                    verifiedSession,
                    localAccount,
                    localAuthority.AccountGeneration,
                    cancellationToken)
                .ConfigureAwait(false);
            if (batch is null)
                return null;
            return await inbox.MaterializeInitialDmc2BatchAsync(
                    batch, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            Zero(localAccount);
        }
    }
#endif

    internal async ValueTask<DeepDirectMessagingSessionStoreBinding?> TryOpenSessionAsync(
        DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
        bool createIfMissing,
        CancellationToken cancellationToken = default)
    {
        if (verifiedSession is null)
        {
            return null;
        }
        if (!CryptographicOperations.FixedTimeEquals(
                verifiedSession.NetworkId.Span,
                localAuthority.NetworkId))
        {
            throw new CryptographicException(
                "The verified direct-message peer belongs to another network.");
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var catalogKey = verifiedSession.ComputeCatalogKey(localAuthority);
            try
            {
                var keyText = Convert.ToHexStringLower(catalogKey);
                if (sessions.TryGetValue(keyText, out var existing))
                {
                    RequireExactSession(existing.CatalogEntry, verifiedSession);
                    return existing;
                }

                var row = catalog.Read(catalogKey);
                var inserted = false;
                if (row is null)
                {
                    if (!createIfMissing)
                    {
                        return null;
                    }
                    row = CreatePendingRow(catalogKey, verifiedSession);
                    catalog.InsertPending(row);
                    inserted = true;
                }
                RequireExactSession(row, verifiedSession);

                var statePath = Path.Combine(appDataDirectory, row.RelativePath);
                byte[]? sessionKey = await ReadKeyAsync(
                        secureStorage,
                        row.KeySlot,
                        "direct message session",
                        cancellationToken)
                    .ConfigureAwait(false);
                var databaseExisted = SqliteFamilyExists(statePath);
                var createdKey = sessionKey is null;
                if (createdKey && row.State == DirectSessionCatalogState.Active)
                {
                    throw ResetRequired(
                        "An active direct-message session exists without its protected SQLCipher key.");
                }
                if (createdKey && databaseExisted)
                {
                    throw ResetRequired(
                        "The direct-message session database exists without its protected SQLCipher key.");
                }

                sessionKey ??= CreateNonzeroKey();
                SqliteMessagingCryptoV1Store? opened = null;
                try
                {
                    if (createdKey)
                    {
                        await secureStorage.WriteBatchAsync(
                                [new DeepSecureStorageWrite(row.KeySlot, sessionKey)],
                                cancellationToken)
                            .ConfigureAwait(false);
                    }

                    var scope = new MessagingCryptoV1StoreScope(
                        localAuthority.AccountId,
                        localAuthority.AccountGeneration,
                        localAuthority.DeviceId,
                        localAuthority.DeviceGeneration,
                        verifiedSession.ConversationId.Span,
                        verifiedSession.ExactDph2Id.Span,
                        checked((ulong)identity.StoreGeneration));
                    using var options = new MessagingCryptoV1StoreOptions(
                        statePath,
                        sessionKey,
                        scope);
                    opened = new SqliteMessagingCryptoV1Store(options);
                    catalog.Activate(catalogKey);
                    var entry = row.ToEntry();
                    var binding = new DeepDirectMessagingSessionStoreBinding(entry, opened);
                    sessions.Add(keyText, binding);
                    opened = null;
                    return binding;
                }
                catch (Exception exception)
                {
                    if (opened is not null)
                    {
                        await opened.DisposeAsync().ConfigureAwait(false);
                        opened = null;
                    }
                    if (inserted && createdKey && !databaseExisted)
                    {
                        await secureStorage.DeleteBatchAsync([row.KeySlot], CancellationToken.None)
                            .ConfigureAwait(false);
                        catalog.RemovePending(catalogKey);
                        DeleteSqliteFamily(statePath);
                    }
                    if (exception is MessagingCryptoV1StoreOpenException)
                    {
                        throw ResetRequired(
                            "The protected direct-message session store cannot be opened.",
                            exception);
                    }
                    throw;
                }
                finally
                {
                    if (opened is not null)
                    {
                        await opened.DisposeAsync().ConfigureAwait(false);
                    }
                    Zero(sessionKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(catalogKey);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    internal async ValueTask<IReadOnlyList<DeepDirectMessagingSessionCatalogEntry>>
        ReadCatalogAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return catalog.ReadAll().Select(static row => row.ToEntry()).ToArray();
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }
        await responderSagaGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await gate.WaitAsync().ConfigureAwait(false);
            try
            {
                foreach (var binding in sessions.Values)
                {
                    await binding.Store.DisposeAsync().ConfigureAwait(false);
                }
                sessions.Clear();
                catalog.Dispose();
                inventoryOwner?.Dispose();
                await preKeyOwner.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            responderSagaGate.Release();
        }
    }

    internal static void DeleteState(string appDataDirectory)
    {
        var root = Path.GetFullPath(appDataDirectory);
        DeleteSqliteFamily(Path.Combine(root, PreKeyPath));
        DeleteSqliteFamily(Path.Combine(root, CatalogPath));
        var sessionDirectory = Path.Combine(root, SessionsDirectory);
        if (!Directory.Exists(sessionDirectory))
        {
            return;
        }
        foreach (var file in Directory.GetFiles(sessionDirectory))
        {
            File.Delete(file);
        }
        Directory.Delete(sessionDirectory, recursive: false);
    }

    private DirectSessionCatalogRow CreatePendingRow(
        ReadOnlySpan<byte> catalogKey,
        DeepDirectMessagingVerifiedSessionBinding session)
    {
        var keyText = Convert.ToHexStringLower(catalogKey);
        var relativePath = SessionsDirectory.Replace('/', Path.DirectorySeparatorChar) +
                           Path.DirectorySeparatorChar + keyText + ".mcr1";
        var keySlot = ScopedSlot(
            identity.SecureSlots.MessageStoreInstanceId,
            SessionSlotSuffix + keyText,
            "direct message session");
        return new DirectSessionCatalogRow(
            catalogKey.ToArray(),
            session.RemoteAccountId.ToArray(),
            session.RemoteAccountGeneration,
            session.RemoteDeviceId.ToArray(),
            session.RemoteDeviceGeneration,
            session.ConversationId.ToArray(),
            session.ExactDph2Id.ToArray(),
            keySlot,
            relativePath,
            DirectSessionCatalogState.Pending);
    }

    private static void RequireExactSession(
        DeepDirectMessagingSessionCatalogEntry entry,
        DeepDirectMessagingVerifiedSessionBinding expected)
    {
        if (entry.RemoteAccountGeneration != expected.RemoteAccountGeneration ||
            entry.RemoteDeviceGeneration != expected.RemoteDeviceGeneration ||
            !Fixed(entry.RemoteAccountId.Span, expected.RemoteAccountId.Span) ||
            !Fixed(entry.RemoteDeviceId.Span, expected.RemoteDeviceId.Span) ||
            !Fixed(entry.ConversationId.Span, expected.ConversationId.Span) ||
            !Fixed(entry.ExactDph2Id.Span, expected.ExactDph2Id.Span))
        {
            throw new CryptographicException(
                "The verified direct-message session conflicts with its durable catalog entry.");
        }
    }

    private static void RequireExactSession(
        DirectSessionCatalogRow row,
        DeepDirectMessagingVerifiedSessionBinding expected) =>
        RequireExactSession(row.ToEntry(), expected);

    private void RequireLocalInitiatorLease(
        LocalDeviceX25519AgreementLease lease)
    {
        if (lease.Purpose != LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1 ||
            lease.AccountGeneration != localAuthority.AccountGeneration ||
            lease.DeviceGeneration != localAuthority.DeviceGeneration ||
            !Fixed(lease.NetworkId.Span, localAuthority.NetworkId) ||
            !Fixed(lease.AccountId.Span, localAuthority.AccountId) ||
            !Fixed(lease.DeviceId.Span, localAuthority.DeviceId) ||
            !Fixed(lease.ExactDpd1Hash.Span, localAuthority.ExactDpd1Hash))
        {
            throw new CryptographicException(
                "The protected DPH2 initiator lease is outside the local account/device authority.");
        }
    }

    private void RequireVerifiedOfferingMatchesScope(
        VerifiedDpk2Offering offering,
        ContactResolverReverifiedPeerAuthority peer,
        InitiatorInitialSessionVerifiedScope scope)
    {
        var exact = offering.ExactBytes.ToArray();
        byte[]? canonical = null;
        byte[]? expectedDpd1Reference = null;
        byte[]? exactHash = null;
        try
        {
            var record = Dpk2Codec.Decode(exact);
            canonical = Dpk2Codec.Encode(record);
            exactHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record);
            var directory = peer.Bundle.Directory;
            var directoryRecord = directory.Record;
            var selected = directory.Identity.ActiveDevices.SingleOrDefault(device =>
                Fixed(device.Certificate.DeviceId.Span, scope.RemoteDeviceId));
            if (selected is null)
            {
                throw new CryptographicException(
                    "The verified DPK2 responder is absent from the current contact closure.");
            }
            expectedDpd1Reference = CreateDpd1Reference(
                selected.Certificate.CanonicalHash.Span);
            if (!Fixed(scope.NetworkId, localAuthority.NetworkId) ||
                !Fixed(scope.LocalAccountId, localAuthority.AccountId) ||
                !Fixed(record.NetworkId.Span, scope.NetworkId) ||
                !Fixed(record.ResponderAccountId.Span, scope.RemoteAccountId) ||
                !Fixed(record.ResponderDeviceId.Span, scope.RemoteDeviceId) ||
                record.ResponderDeviceGeneration != scope.RemoteDeviceGeneration ||
                !Fixed(record.ResponderDpd1Ref.Span, expectedDpd1Reference) ||
                record.DeviceDirectoryGeneration != scope.RemoteDirectoryGeneration ||
                !Fixed(record.DeviceDirectoryHeadHash.Span,
                    directoryRecord.RecordHash.Span) ||
                !Fixed(canonical, exact) ||
                !Fixed(exactHash, offering.ExactHash.Span))
            {
                throw new CryptographicException(
                    "The verified DPK2 offering differs from the current contact/device closure.");
            }
        }
        finally
        {
            Zero(exact);
            Zero(canonical);
            Zero(expectedDpd1Reference);
            Zero(exactHash);
        }
    }

    private void RequireResponderSessionBinding(
        DeepDirectMessagingVerifiedSessionBinding session,
        VerifiedContactBundleEvidence relationship,
        VerifiedDph2Initiation initiation)
    {
        var exact = initiation.ExactBytes.ToArray();
        byte[]? canonical = null;
        try
        {
            var record = Dph2Codec.Decode(exact);
            canonical = Dph2Codec.Encode(record);
            if (!Fixed(session.NetworkId.Span, localAuthority.NetworkId) ||
                !Fixed(relationship.Address.NetworkId.Span, localAuthority.NetworkId) ||
                !Fixed(relationship.Scope.AccountId.Bytes.Span, localAuthority.AccountId) ||
                !Fixed(relationship.RemoteAccountId.Span, session.RemoteAccountId.Span) ||
                !Fixed(relationship.ConversationId.Span, session.ConversationId.Span) ||
                !Fixed(record.NetworkId.Span, localAuthority.NetworkId) ||
                !Fixed(record.InitiatorAccountId.Span, session.RemoteAccountId.Span) ||
                !Fixed(record.InitiatorDeviceId.Span, session.RemoteDeviceId.Span) ||
                record.InitiatorDeviceGeneration != session.RemoteDeviceGeneration ||
                !Fixed(record.ResponderAccountId.Span, localAuthority.AccountId) ||
                !Fixed(record.ResponderDeviceId.Span, localAuthority.DeviceId) ||
                record.ResponderDeviceGeneration != localAuthority.DeviceGeneration ||
                !Fixed(record.SessionId.Span, session.ExactDph2Id.Span) ||
                !Fixed(canonical, exact))
            {
                throw new CryptographicException(
                    "The verified responder DPH2 differs from the contact/session owner scope.");
            }
        }
        finally
        {
            Zero(exact);
            Zero(canonical);
        }
    }

    private static async Task<byte[]?> ReadKeyAsync(
        IDeepSecureStorage secureStorage,
        string slot,
        string purpose,
        CancellationToken cancellationToken)
    {
        using var stored = await secureStorage.ReadOwnedAsync(slot, cancellationToken)
            .ConfigureAwait(false);
        if (stored is null)
        {
            return null;
        }
        if (stored.Length != 32)
        {
            throw ResetRequired($"The {purpose} SQLCipher key is invalid.");
        }
        var result = new byte[32];
        stored.CopyTo(result);
        if (result.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            CryptographicOperations.ZeroMemory(result);
            throw ResetRequired($"The {purpose} SQLCipher key is invalid.");
        }
        return result;
    }

    private static async Task<byte[]> ReadStoreInstanceIdAsync(
        IDeepSecureStorage secureStorage,
        string slot,
        CancellationToken cancellationToken)
    {
        var value = await ReadKeyAsync(
                secureStorage,
                slot,
                "message-store instance",
                cancellationToken)
            .ConfigureAwait(false);
        return value ?? throw ResetRequired("The message-store instance ID is missing.");
    }

    private static byte[] CreateDpd1Reference(ReadOnlySpan<byte> dpd1Hash)
    {
        if (dpd1Hash.Length != 32 || dpd1Hash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The exact DPD1 hash must be 32 nonzero bytes.",
                nameof(dpd1Hash));
        }
        var result = new byte[38];
        "DPD1"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        dpd1Hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private static string ScopedSlot(
        string messageStoreInstanceSlot,
        string suffix,
        string purpose)
    {
        const string sourceSuffix = ".message-store-instance";
        if (!messageStoreInstanceSlot.StartsWith("deep.store.v1.", StringComparison.Ordinal) ||
            !messageStoreInstanceSlot.EndsWith(sourceSuffix, StringComparison.Ordinal) ||
            suffix.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw ResetRequired($"The {purpose} secure-storage scope is invalid.");
        }
        return messageStoreInstanceSlot[..^sourceSuffix.Length] + suffix;
    }

    private static byte[] CreateNonzeroKey()
    {
        while (true)
        {
            var key = RandomNumberGenerator.GetBytes(32);
            if (key.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
            {
                return key;
            }
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private static LocalStateResetRequiredException ResetRequired(
        string message,
        Exception? inner = null) => new(
            inner is PreKeyV1StoreOpenException { Reason: PreKeyV1StoreOpenFailure.UnreadableOrWrongKey } or
                MessagingCryptoV1StoreOpenException { Reason: MessagingCryptoV1StoreOpenFailure.UnreadableOrWrongKey }
                ? LocalStateResetRequiredReason.UnreadableOrWrongKey
                : LocalStateResetRequiredReason.InvalidCurrentSchema,
            message,
            inner);

    private static bool SqliteFamilyExists(string statePath) =>
        File.Exists(statePath) || File.Exists(statePath + "-wal") ||
        File.Exists(statePath + "-shm") || File.Exists(statePath + "-journal");

    private static void DeleteSqliteFamily(string statePath)
    {
        foreach (var path in new[]
                 {
                     statePath,
                     statePath + "-wal",
                     statePath + "-shm",
                     statePath + "-journal"
                 })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
}

internal sealed class DeepDirectMessagingCatalogScope
{
    private readonly byte[] networkId;
    private readonly byte[] localAccountId;
    private readonly byte[] localDeviceId;
    private readonly byte[] storeInstanceId;

    internal DeepDirectMessagingCatalogScope(
        DeepDirectMessagingLocalAuthorityBinding authority,
        ulong databaseGeneration,
        ReadOnlySpan<byte> storeInstanceId)
    {
        networkId = authority.NetworkId.ToArray();
        localAccountId = authority.AccountId.ToArray();
        localDeviceId = authority.DeviceId.ToArray();
        this.storeInstanceId = storeInstanceId.ToArray();
        AccountGeneration = authority.AccountGeneration;
        DeviceGeneration = authority.DeviceGeneration;
        DatabaseGeneration = databaseGeneration;
    }

    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> LocalAccountId => localAccountId;
    internal ulong AccountGeneration { get; }
    internal ReadOnlySpan<byte> LocalDeviceId => localDeviceId;
    internal ulong DeviceGeneration { get; }
    internal ulong DatabaseGeneration { get; }
    internal ReadOnlySpan<byte> StoreInstanceId => storeInstanceId;
}

internal enum DirectSessionCatalogState
{
    Pending = 1,
    Active = 2,
}

internal sealed record DirectSessionCatalogRow(
    byte[] CatalogKey,
    byte[] RemoteAccountId,
    ulong RemoteAccountGeneration,
    byte[] RemoteDeviceId,
    ulong RemoteDeviceGeneration,
    byte[] ConversationId,
    byte[] ExactDph2Id,
    string KeySlot,
    string RelativePath,
    DirectSessionCatalogState State)
{
    internal DeepDirectMessagingSessionCatalogEntry ToEntry() => new(
        RemoteAccountId,
        RemoteAccountGeneration,
        RemoteDeviceId,
        RemoteDeviceGeneration,
        ConversationId,
        ExactDph2Id);
}

/// <summary>
/// Encrypted, generation-bound index. It stores no ratchet or pre-key secret;
/// every session database has a separate protected SQLCipher key.
/// </summary>
internal sealed class DeepDirectMessagingSessionCatalog : IDisposable
{
    private const int ApplicationId = 0x44534331; // DSC1
    private const int SchemaGeneration = 1;
    private const int MaximumSessions = 4096;
    private const string SchemaDdl = """
        CREATE TABLE direct_session_catalog_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),database_generation BLOB NOT NULL CHECK(length(database_generation)=8),network_id BLOB NOT NULL CHECK(length(network_id)=16),local_account_id BLOB NOT NULL CHECK(length(local_account_id)=32),account_generation BLOB NOT NULL CHECK(length(account_generation)=8),local_device_id BLOB NOT NULL CHECK(length(local_device_id)=32),device_generation BLOB NOT NULL CHECK(length(device_generation)=8),store_instance_id BLOB NOT NULL CHECK(length(store_instance_id)=32));
        CREATE TABLE direct_sessions(catalog_key BLOB PRIMARY KEY CHECK(length(catalog_key)=32),remote_account_id BLOB NOT NULL CHECK(length(remote_account_id)=32),remote_account_generation BLOB NOT NULL CHECK(length(remote_account_generation)=8),remote_device_id BLOB NOT NULL CHECK(length(remote_device_id)=32),remote_device_generation BLOB NOT NULL CHECK(length(remote_device_generation)=8),conversation_id BLOB NOT NULL CHECK(length(conversation_id)=32),dph2_id BLOB NOT NULL UNIQUE CHECK(length(dph2_id)=32),key_slot TEXT NOT NULL UNIQUE CHECK(length(key_slot) BETWEEN 1 AND 192),relative_path TEXT NOT NULL UNIQUE CHECK(length(relative_path) BETWEEN 1 AND 192),state INTEGER NOT NULL CHECK(state IN(1,2)),UNIQUE(remote_account_id,remote_account_generation,remote_device_id,remote_device_generation,conversation_id));
        """;
    private static readonly byte[] ExpectedSchemaFingerprint = HashSchema(
        ExpectedSchemaObjects());
    private readonly byte[] key;
    private readonly string statePath;
    private readonly string connectionString;
    private readonly DeepDirectMessagingCatalogScope scope;
    private SqliteConnection? connection;
    private int disposed;

    static DeepDirectMessagingSessionCatalog() => SQLitePCL.Batteries_V2.Init();

    internal DeepDirectMessagingSessionCatalog(
        string statePath,
        ReadOnlySpan<byte> encryptionKey,
        DeepDirectMessagingCatalogScope scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        if (encryptionKey.Length != 32 || encryptionKey.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A nonzero 32-byte direct session catalog key is required.",
                nameof(encryptionKey));
        }
        this.statePath = Path.GetFullPath(statePath);
        this.scope = scope ?? throw new ArgumentNullException(nameof(scope));
        key = encryptionKey.ToArray();
        var exists = File.Exists(this.statePath);
        if (exists && new FileInfo(this.statePath).Length == 0)
        {
            CryptographicOperations.ZeroMemory(key);
            throw ResetRequired("The direct session catalog is empty.");
        }
        var directory = Path.GetDirectoryName(this.statePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = this.statePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();
        try
        {
            using var opened = Open();
            if (exists)
            {
                Validate(opened);
            }
            else
            {
                Create(opened);
            }
            ValidateEncryptedHeader();
            connection = Open();
        }
        catch (LocalStateResetRequiredException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        catch (SqliteException exception)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.UnreadableOrWrongKey,
                "The protected direct session catalog is unreadable or corrupt.",
                exception);
        }
        catch (Exception exception) when (exception is FormatException or
            InvalidOperationException or OverflowException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw ResetRequired("The protected direct session catalog is corrupt.", exception);
        }
    }

    internal bool IsKeyZeroedForTesting => key.All(static value => value == 0);

    internal DirectSessionCatalogRow? Read(ReadOnlySpan<byte> catalogKey)
    {
        ThrowIfDisposed();
        using var command = GetConnection().CreateCommand();
        command.CommandText = """
            SELECT remote_account_id,remote_account_generation,remote_device_id,
                   remote_device_generation,conversation_id,dph2_id,key_slot,
                   relative_path,state
            FROM direct_sessions WHERE catalog_key=$key;
            """;
        Add(command, "$key", catalogKey.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }
        var result = ReadRow(reader, catalogKey.ToArray());
        if (reader.Read())
        {
            throw ResetRequired("The direct session catalog contains duplicate keys.");
        }
        return result;
    }

    internal IReadOnlyList<DirectSessionCatalogRow> ReadAll()
    {
        ThrowIfDisposed();
        return ReadAll(GetConnection());
    }

    private IReadOnlyList<DirectSessionCatalogRow> ReadAll(SqliteConnection database)
    {
        using var command = database.CreateCommand();
        command.CommandText = """
            SELECT catalog_key,remote_account_id,remote_account_generation,
                   remote_device_id,remote_device_generation,conversation_id,
                   dph2_id,key_slot,relative_path,state
            FROM direct_sessions ORDER BY catalog_key;
            """;
        using var reader = command.ExecuteReader();
        var result = new List<DirectSessionCatalogRow>();
        while (reader.Read())
        {
            var keyBytes = FixedColumn(reader, 0, 32, "catalog key");
            result.Add(ReadRow(reader, keyBytes, offset: 1));
            if (result.Count > MaximumSessions)
            {
                throw ResetRequired("The direct session catalog exceeds its sealed capacity.");
            }
        }
        return result;
    }

    internal void InsertPending(DirectSessionCatalogRow row)
    {
        ThrowIfDisposed();
        if (row.State != DirectSessionCatalogState.Pending)
        {
            throw new ArgumentException("A new direct session must be pending.", nameof(row));
        }
        var database = GetConnection();
        using var transaction = database.BeginTransaction();
        if (ScalarLong(database, transaction, "SELECT count(*) FROM direct_sessions;") >=
            MaximumSessions)
        {
            throw new InvalidOperationException("The direct session catalog is full.");
        }
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO direct_sessions(
                catalog_key,remote_account_id,remote_account_generation,
                remote_device_id,remote_device_generation,conversation_id,
                dph2_id,key_slot,relative_path,state)
            VALUES($catalog,$account,$accountGeneration,$device,$deviceGeneration,
                $conversation,$dph2,$slot,$path,1);
            """;
        Add(command, "$catalog", row.CatalogKey);
        Add(command, "$account", row.RemoteAccountId);
        Add(command, "$accountGeneration", U64(row.RemoteAccountGeneration));
        Add(command, "$device", row.RemoteDeviceId);
        Add(command, "$deviceGeneration", U64(row.RemoteDeviceGeneration));
        Add(command, "$conversation", row.ConversationId);
        Add(command, "$dph2", row.ExactDph2Id);
        Add(command, "$slot", row.KeySlot);
        Add(command, "$path", row.RelativePath.Replace('\\', '/'));
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    internal void Activate(ReadOnlySpan<byte> catalogKey)
    {
        ThrowIfDisposed();
        using var command = GetConnection().CreateCommand();
        command.CommandText =
            "UPDATE direct_sessions SET state=2 WHERE catalog_key=$key AND state IN(1,2);";
        Add(command, "$key", catalogKey.ToArray());
        if (command.ExecuteNonQuery() != 1)
        {
            throw ResetRequired("The pending direct session catalog entry disappeared.");
        }
    }

    internal void RemovePending(ReadOnlySpan<byte> catalogKey)
    {
        ThrowIfDisposed();
        using var command = GetConnection().CreateCommand();
        command.CommandText =
            "DELETE FROM direct_sessions WHERE catalog_key=$key AND state=1;";
        Add(command, "$key", catalogKey.ToArray());
        command.ExecuteNonQuery();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }
        connection?.Dispose();
        connection = null;
        CryptographicOperations.ZeroMemory(key);
    }

    private void Create(SqliteConnection database)
    {
        Execute(database, null,
            $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        Execute(database, null, SchemaDdl);
        using var command = database.CreateCommand();
        command.CommandText = """
            INSERT INTO direct_session_catalog_meta VALUES(
                1,$database,$network,$account,$accountGeneration,$device,
                $deviceGeneration,$instance);
            """;
        Add(command, "$database", U64(scope.DatabaseGeneration));
        Add(command, "$network", scope.NetworkId.ToArray());
        Add(command, "$account", scope.LocalAccountId.ToArray());
        Add(command, "$accountGeneration", U64(scope.AccountGeneration));
        Add(command, "$device", scope.LocalDeviceId.ToArray());
        Add(command, "$deviceGeneration", U64(scope.DeviceGeneration));
        Add(command, "$instance", scope.StoreInstanceId.ToArray());
        command.ExecuteNonQuery();
        Execute(database, null, "PRAGMA wal_checkpoint(FULL);");
        Validate(database);
    }

    private void Validate(SqliteConnection database)
    {
        if (ScalarLong(database, null, "PRAGMA application_id;") != ApplicationId)
        {
            throw ResetRequired("Unexpected direct session catalog application ID.");
        }
        if (ScalarLong(database, null, "PRAGMA user_version;") != SchemaGeneration)
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.UnsupportedVersion,
                "The direct session catalog generation is unsupported.");
        }
        ValidateCipher(database);
        if (!string.Equals(
                Convert.ToString(Scalar(database, null, "PRAGMA quick_check;"),
                    CultureInfo.InvariantCulture),
                "ok",
                StringComparison.OrdinalIgnoreCase))
        {
            throw ResetRequired("The direct session catalog quick check failed.");
        }

        var actualSchema = HashSchema(ReadSchemaObjects(database));
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(ExpectedSchemaFingerprint, actualSchema))
            {
                throw ResetRequired(
                    "The direct session catalog DDL differs from its sealed schema.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualSchema);
        }

        using (var command = database.CreateCommand())
        {
            command.CommandText = """
                SELECT database_generation,network_id,local_account_id,
                       account_generation,local_device_id,device_generation,
                       store_instance_id
                FROM direct_session_catalog_meta WHERE singleton=1;
                """;
            using var reader = command.ExecuteReader();
            if (!reader.Read() ||
                !FixedColumn(reader, 0, U64(scope.DatabaseGeneration)) ||
                !FixedColumn(reader, 1, scope.NetworkId) ||
                !FixedColumn(reader, 2, scope.LocalAccountId) ||
                !FixedColumn(reader, 3, U64(scope.AccountGeneration)) ||
                !FixedColumn(reader, 4, scope.LocalDeviceId) ||
                !FixedColumn(reader, 5, U64(scope.DeviceGeneration)) ||
                !FixedColumn(reader, 6, scope.StoreInstanceId) || reader.Read())
            {
                throw ResetRequired(
                    "The direct session catalog belongs to another account, device, or store generation.");
            }
        }

        _ = ReadAll(database);
    }

    private DirectSessionCatalogRow ReadRow(
        SqliteDataReader reader,
        byte[] catalogKey,
        int offset = 0)
    {
        var account = FixedColumn(reader, offset, 32, "remote account ID");
        var accountGeneration = ReadU64(
            FixedColumn(reader, offset + 1, 8, "remote account generation"));
        var device = FixedColumn(reader, offset + 2, 32, "remote device ID");
        var deviceGeneration = ReadU64(
            FixedColumn(reader, offset + 3, 8, "remote device generation"));
        var conversation = FixedColumn(reader, offset + 4, 32, "conversation ID");
        var session = FixedColumn(reader, offset + 5, 32, "session ID");
        var keySlot = reader.GetString(offset + 6);
        var relativePath = reader.GetString(offset + 7);
        var stateValue = reader.GetInt32(offset + 8);
        if (accountGeneration == 0 || deviceGeneration == 0 ||
            stateValue is not (1 or 2) ||
            !Regex.IsMatch(
                keySlot,
                "^deep\\.store\\.v1\\.[0-9a-f]{32}\\.direct-session-key\\.[0-9a-f]{64}$",
                RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(
                relativePath,
                "^deep-store-v1/direct-sessions/[0-9a-f]{64}\\.mcr1$",
                RegexOptions.CultureInvariant))
        {
            throw ResetRequired("A direct session catalog row is malformed.");
        }

        var expectedPathTail = Convert.ToHexStringLower(catalogKey);
        if (!keySlot.EndsWith(expectedPathTail, StringComparison.Ordinal) ||
            !relativePath.EndsWith(expectedPathTail + ".mcr1", StringComparison.Ordinal))
        {
            throw ResetRequired(
                "A direct session catalog row is not bound to its canonical key.");
        }
        return new DirectSessionCatalogRow(
            catalogKey,
            account,
            accountGeneration,
            device,
            deviceGeneration,
            conversation,
            session,
            keySlot,
            relativePath.Replace('/', Path.DirectorySeparatorChar),
            (DirectSessionCatalogState)stateValue);
    }

    private SqliteConnection Open()
    {
        var database = new SqliteConnection(connectionString);
        try
        {
            database.Open();
            var result = SQLitePCL.raw.sqlite3_key(database.Handle, key);
            if (result != SQLitePCL.raw.SQLITE_OK)
            {
                throw new SqliteException(
                    "SQLCipher rejected the direct session catalog key.",
                    result);
            }
            Execute(database, null,
                "PRAGMA cipher_memory_security=ON; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;");
            return database;
        }
        catch (SqliteException exception)
        {
            database.Dispose();
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.UnreadableOrWrongKey,
                "The protected direct session catalog cannot be opened.",
                exception);
        }
        catch
        {
            database.Dispose();
            throw;
        }
    }

    private static void ValidateCipher(SqliteConnection database)
    {
        if (Scalar(database, null, "PRAGMA cipher_version;") is not string version ||
            !version.StartsWith("4.", StringComparison.Ordinal))
        {
            throw ResetRequired("SQLCipher v4 is unavailable for the direct session catalog.");
        }
        using var command = database.CreateCommand();
        command.CommandText = "PRAGMA cipher_integrity_check;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (!string.Equals(reader.GetString(0), "ok", StringComparison.OrdinalIgnoreCase))
            {
                throw ResetRequired("The direct session catalog cipher integrity check failed.");
            }
        }
    }

    private void ValidateEncryptedHeader()
    {
        using var stream = new FileStream(
            statePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        Span<byte> header = stackalloc byte[16];
        if (stream.Read(header) != header.Length || header.SequenceEqual("SQLite format 3\0"u8))
        {
            throw ResetRequired(
                "The direct session catalog is truncated or has a plaintext SQLite header.");
        }
    }

    private SqliteConnection GetConnection() => connection ??
        throw new ObjectDisposedException(nameof(DeepDirectMessagingSessionCatalog));

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

    private static byte[] FixedColumn(
        SqliteDataReader reader,
        int ordinal,
        int length,
        string purpose)
    {
        if (reader[ordinal] is not byte[] value || value.Length != length ||
            value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            throw ResetRequired($"The direct session catalog {purpose} is invalid.");
        }
        return value;
    }

    private static bool FixedColumn(
        SqliteDataReader reader,
        int ordinal,
        ReadOnlySpan<byte> expected) =>
        reader[ordinal] is byte[] value && value.Length == expected.Length &&
        CryptographicOperations.FixedTimeEquals(value, expected);

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static ulong ReadU64(ReadOnlySpan<byte> value) =>
        value.Length == 8
            ? BinaryPrimitives.ReadUInt64BigEndian(value)
            : throw ResetRequired("A direct session catalog generation is invalid.");

    private static void Add(SqliteCommand command, string name, object value) =>
        command.Parameters.AddWithValue(name, value);

    private static object? Scalar(
        SqliteConnection database,
        SqliteTransaction? transaction,
        string sql)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static long ScalarLong(
        SqliteConnection database,
        SqliteTransaction? transaction,
        string sql) => Convert.ToInt64(
            Scalar(database, transaction, sql),
            CultureInfo.InvariantCulture);

    private static void Execute(
        SqliteConnection database,
        SqliteTransaction? transaction,
        string sql)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static string[] ExpectedSchemaObjects() => SchemaDdl
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(static statement =>
        {
            var match = Regex.Match(
                statement,
                "^CREATE\\s+TABLE\\s+([a-z0-9_]+)",
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (!match.Success)
            {
                throw new InvalidOperationException(
                    "The sealed direct session catalog schema is malformed.");
            }
            return $"table|{match.Groups[1].Value}|{match.Groups[1].Value}|{NormalizeSql(statement)}";
        })
        .OrderBy(static value => value, StringComparer.Ordinal)
        .ToArray();

    private static string[] ReadSchemaObjects(SqliteConnection database)
    {
        using var command = database.CreateCommand();
        command.CommandText = """
            SELECT type,name,tbl_name,sql FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name;
            """;
        using var reader = command.ExecuteReader();
        var result = new List<string>();
        while (reader.Read())
        {
            if (reader.IsDBNull(3))
            {
                throw ResetRequired("The direct session catalog has an unsealed schema object.");
            }
            result.Add(
                $"{reader.GetString(0)}|{reader.GetString(1)}|{reader.GetString(2)}|" +
                NormalizeSql(reader.GetString(3)));
        }
        return result.ToArray();
    }

    private static string NormalizeSql(string sql) => Regex.Replace(
        sql.Trim().TrimEnd(';'),
        "\\s+",
        " ",
        RegexOptions.CultureInvariant).ToLowerInvariant();

    private static byte[] HashSchema(IEnumerable<string> objects)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        foreach (var item in objects)
        {
            var bytes = Encoding.UTF8.GetBytes(item);
            try
            {
                BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
                hash.AppendData(length);
                hash.AppendData(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        return hash.GetHashAndReset();
    }

    private static LocalStateResetRequiredException ResetRequired(
        string message,
        Exception? inner = null) => new(
            LocalStateResetRequiredReason.InvalidCurrentSchema,
            message,
            inner);
}
