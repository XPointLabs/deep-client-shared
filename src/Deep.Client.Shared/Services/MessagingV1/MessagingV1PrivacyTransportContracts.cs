using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services.MessagingV1;

internal enum MessagingV1DepositKind : byte
{
    InitialSession = 1,
    EstablishedSession = 2,
}

internal enum MessagingV1DispatchFailureClass : byte
{
    RejectedBeforeForward = 1,
    OutcomeUnknown = 2,
    TerminalRejected = 3,
}

internal sealed class MessagingV1DispatchException : IOException
{
    internal MessagingV1DispatchException(
        MessagingV1DispatchFailureClass failureClass,
        bool retryable,
        string message,
        Exception innerException)
        : base(message, innerException)
    {
        if (!Enum.IsDefined(failureClass))
            throw new ArgumentOutOfRangeException(nameof(failureClass));
        FailureClass = failureClass;
        Retryable = retryable;
    }

    internal MessagingV1DispatchFailureClass FailureClass { get; }
    internal bool Retryable { get; }
}

/// <summary>
/// Account/device context held by the unlocked account owner. It contains only
/// public identifiers and is used to reject a DPH2/DPE2 for another local
/// account or device before any mailbox mutation.
/// </summary>
internal sealed class MessagingV1LocalContext
{
    private readonly byte[] networkId;
    private readonly byte[] accountId;
    private readonly byte[] deviceId;

    internal MessagingV1LocalContext(
        OutboxAccountScope outboxScope,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration)
    {
        OutboxScope = outboxScope ?? throw new ArgumentNullException(nameof(outboxScope));
        Require(networkId, 16, nameof(networkId));
        Require(accountId, 32, nameof(accountId));
        Require(deviceId, 32, nameof(deviceId));
        if (deviceGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(deviceGeneration));
        this.networkId = networkId.ToArray();
        this.accountId = accountId.ToArray();
        this.deviceId = deviceId.ToArray();
        DeviceGeneration = deviceGeneration;
    }

    internal OutboxAccountScope OutboxScope { get; }
    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> AccountId => accountId;
    internal ReadOnlySpan<byte> DeviceId => deviceId;
    internal ulong DeviceGeneration { get; }

    private static void Require(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must contain exactly {length} nonzero bytes.", name);
    }
}

/// <summary>
/// One current reachability-scoped mailbox grant together with the only holder
/// key allowed to present it.  The selector is derived from the grant and exact
/// route closure; no Session identity or caller-authored alias participates.
/// </summary>
internal sealed class VerifiedMessagingMailboxAccess
{
    private readonly byte[] exactGrant;

    private VerifiedMessagingMailboxAccess(
        MailboxCredentialSelector selector,
        IMailboxOperationSigner signer,
        MailboxCapabilityDomain domain,
        ReadOnlySpan<byte> exactGrant)
    {
        Selector = selector ?? throw new ArgumentNullException(nameof(selector));
        Signer = signer ?? throw new ArgumentNullException(nameof(signer));
        if (domain is not (
            MailboxCapabilityDomain.Deposit or MailboxCapabilityDomain.Retrieve))
            throw new ArgumentOutOfRangeException(nameof(domain));
        if (domain == MailboxCapabilityDomain.Retrieve &&
            selector.Kind != MailboxCredentialScopeKind.Self ||
            domain == MailboxCapabilityDomain.Deposit &&
            selector.Kind == MailboxCredentialScopeKind.Self)
            throw new CryptographicException(
                "The mailbox access role does not match its credential scope.");
        var holder = signer.GetEd25519PublicKey();
        try
        {
            if (holder.Length != 32 || holder.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !Fixed(holder, selector.SubjectId.Span))
                throw new CryptographicException(
                    "The mailbox access selector does not bind its holder key.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(holder);
        }
        Domain = domain;
        this.exactGrant = exactGrant.ToArray();
    }

    internal MailboxCredentialSelector Selector { get; }
    internal IMailboxOperationSigner Signer { get; }
    internal MailboxCapabilityDomain Domain { get; }
    internal ReadOnlyMemory<byte> ExactGrant => exactGrant.ToArray();

    internal static VerifiedMessagingMailboxAccess FromCurrentGrant(
        OutboxAccountScope accountScope,
        MailboxCredentialScopeKind kind,
        VerifiedCurrentMailboxGrant grant,
        IMailboxOperationSigner signer,
        ReadOnlySpan<byte> groupMembershipCommitment = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(signer);
        var expectedDomain = kind == MailboxCredentialScopeKind.Self
            ? MailboxCapabilityDomain.Retrieve
            : MailboxCapabilityDomain.Deposit;
        if (grant.Domain != expectedDomain)
            throw new CryptographicException(
                "The current mailbox grant does not authorize this access role.");
        var routeContext = SHA256.HashData(grant.ExactRouteClosure.Span);
        try
        {
            var selector = new MailboxCredentialSelector(
                accountScope,
                kind,
                grant.HolderPublicKey.Span,
                routeContext,
                groupMembershipCommitment);
            return new VerifiedMessagingMailboxAccess(
                selector, signer, grant.Domain, grant.ExactGrant.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(routeContext);
        }
    }

#if DEEP_TEST_INTERNALS
    internal static VerifiedMessagingMailboxAccess CreateForTests(
        MailboxCredentialSelector selector,
        IMailboxOperationSigner signer,
        MailboxCapabilityDomain domain) =>
        new(selector, signer, domain, ReadOnlySpan<byte>.Empty);
#endif

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Opaque recipient/deposit authority minted only from the reverified ContactV1
/// closure and the matching installed peer-deposit mailbox capability.
/// </summary>
internal sealed class VerifiedMessagingRecipientDeposit
{
    private readonly byte[] networkId;
    private readonly byte[] accountId;
    private readonly byte[] deviceId;
    private readonly byte[] sealingKeyId;
    private readonly byte[] sealingPublicKey;

    private VerifiedMessagingRecipientDeposit(
        OutboxAccountScope localOutboxScope,
        VerifiedMessagingMailboxAccess mailboxAccess,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ulong directoryGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> sealingKeyId,
        ReadOnlySpan<byte> sealingPublicKey,
        ulong expiresAtUnixSeconds)
    {
        LocalOutboxScope = localOutboxScope ?? throw new ArgumentNullException(nameof(localOutboxScope));
        MailboxAccess = mailboxAccess ?? throw new ArgumentNullException(nameof(mailboxAccess));
        Require(networkId, 16, nameof(networkId));
        Require(accountId, 32, nameof(accountId));
        Require(deviceId, 32, nameof(deviceId));
        Require(sealingKeyId, 32, nameof(sealingKeyId));
        Require(sealingPublicKey, 32, nameof(sealingPublicKey));
        if (!mailboxAccess.Selector.AccountScope.Equals(localOutboxScope) ||
            mailboxAccess.Selector.Kind != MailboxCredentialScopeKind.Peer ||
            mailboxAccess.Domain != MailboxCapabilityDomain.Deposit)
            throw new CryptographicException("The mailbox selector is not the verified peer-deposit capability for this local account.");
        if (accountGeneration == 0 || directoryGeneration == 0 ||
            deviceGeneration == 0 || expiresAtUnixSeconds == 0)
            throw new ArgumentOutOfRangeException(nameof(accountGeneration));

        this.networkId = networkId.ToArray();
        this.accountId = accountId.ToArray();
        this.deviceId = deviceId.ToArray();
        this.sealingKeyId = sealingKeyId.ToArray();
        this.sealingPublicKey = sealingPublicKey.ToArray();
        AccountGeneration = accountGeneration;
        DirectoryGeneration = directoryGeneration;
        DeviceGeneration = deviceGeneration;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    internal OutboxAccountScope LocalOutboxScope { get; }
    internal VerifiedMessagingMailboxAccess MailboxAccess { get; }
    internal MailboxCredentialSelector Selector => MailboxAccess.Selector;
    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> AccountId => accountId;
    internal ulong AccountGeneration { get; }
    internal ulong DirectoryGeneration { get; }
    internal ReadOnlySpan<byte> DeviceId => deviceId;
    internal ulong DeviceGeneration { get; }
    internal ReadOnlySpan<byte> SealingKeyId => sealingKeyId;
    internal ReadOnlySpan<byte> SealingPublicKey => sealingPublicKey;
    internal ulong ExpiresAtUnixSeconds { get; }

    internal static VerifiedMessagingRecipientDeposit FromReverifiedPeer(
        ContactResolverReverifiedPeerAuthority peer,
        OutboxAccountScope localOutboxScope,
        VerifiedMessagingMailboxAccess mailboxAccess,
        ReadOnlySpan<byte> recipientDeviceId)
    {
        ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(localOutboxScope);
        ArgumentNullException.ThrowIfNull(mailboxAccess);
        Require(recipientDeviceId, 32, nameof(recipientDeviceId));
        var selectedDeviceId = recipientDeviceId.ToArray();

        var directory = peer.Bundle.Directory;
        var device = directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, selectedDeviceId));
        var directoryEntry = directory.Record.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.DeviceId.Span, selectedDeviceId));
        var xrr1 = peer.Route.Reachability;
        var xra1 = peer.Route.Authorization;
        var exactRoute = ContactRouteClosureCodec.Encode(peer.Route);
        var routeContext = SHA256.HashData(exactRoute);
        try
        {
            if (!StringComparer.Ordinal.Equals(xrr1.Magic, "XRR1") ||
                !StringComparer.Ordinal.Equals(xra1.Magic, "XRA1") ||
                device is null || directoryEntry is null ||
                !Fixed(xrr1.Field(1).Span, directory.Record.NetworkId.Span) ||
                !Fixed(xra1.Field(1).Span, directory.Record.NetworkId.Span) ||
                !Fixed(xra1.Field(14).Span, selectedDeviceId) ||
                !Fixed(mailboxAccess.Selector.IssuerContext.Span, routeContext) ||
                !Fixed(directoryEntry.Dpd1Reference.CanonicalHash.Span,
                    device.Certificate.CanonicalHash.Span))
            {
                throw new CryptographicException(
                    "The requested recipient/deposit capability is outside the reverified ContactV1 closure.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactRoute);
            CryptographicOperations.ZeroMemory(routeContext);
        }

        var xrrExpiry = U64(xrr1.Field(17).Span, "XRR1 expiry");
        var xraExpiry = U64(xra1.Field(13).Span, "XRA1 expiry");
        return new VerifiedMessagingRecipientDeposit(
            localOutboxScope,
            mailboxAccess,
            directory.Record.NetworkId.Span,
            directory.Record.DeepAccountId.Span,
            directory.Record.AccountGeneration,
            directory.Record.DirectoryGeneration,
            selectedDeviceId,
            device.Certificate.DeviceGeneration,
            xra1.Field(10).Span,
            xra1.Field(11).Span,
            Math.Min(xrrExpiry, xraExpiry));
    }

#if DEEP_TEST_INTERNALS
    internal static VerifiedMessagingRecipientDeposit CreateForTests(
        OutboxAccountScope localOutboxScope,
        MailboxCredentialSelector selector,
        IMailboxOperationSigner signer,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ulong directoryGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> sealingKeyId,
        ReadOnlySpan<byte> sealingPublicKey,
        ulong expiresAtUnixSeconds) => new(
            localOutboxScope,
            VerifiedMessagingMailboxAccess.CreateForTests(
                selector, signer, MailboxCapabilityDomain.Deposit),
            networkId, accountId, accountGeneration,
            directoryGeneration, deviceId, deviceGeneration, sealingKeyId,
            sealingPublicKey, expiresAtUnixSeconds);
#endif

    private static ulong U64(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != sizeof(ulong))
            throw new CryptographicException($"The verified {name} is malformed.");
        return BinaryPrimitives.ReadUInt64BigEndian(value);
    }

    private static void Require(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must contain exactly {length} nonzero bytes.", name);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal abstract class MessagingV1DispatchReceipt
{
    private readonly byte[] innerOperationId;
    private readonly byte[] dao1OperationId;
    private readonly byte[] mailboxOperationId;
    private readonly byte[] exactDao1Hash;
    private readonly byte[] recipientAccountId;
    private readonly byte[] recipientDeviceId;
    private readonly byte[] coordinatorId;

    protected MessagingV1DispatchReceipt(
        MessagingV1DepositKind kind,
        ReadOnlySpan<byte> innerOperationId,
        ReadOnlySpan<byte> dao1OperationId,
        ReadOnlySpan<byte> mailboxOperationId,
        ReadOnlySpan<byte> exactDao1Hash,
        ReadOnlySpan<byte> recipientAccountId,
        ReadOnlySpan<byte> recipientDeviceId,
        ulong recipientAccountGeneration,
        ulong recipientDeviceGeneration,
        ulong cursor,
        bool exactReplay,
        ReadOnlySpan<byte> coordinatorId)
    {
        if (!Enum.IsDefined(kind) || cursor == 0)
            throw new ArgumentOutOfRangeException(nameof(kind));
        Require32(innerOperationId, nameof(innerOperationId));
        Require32(dao1OperationId, nameof(dao1OperationId));
        Require16(mailboxOperationId, nameof(mailboxOperationId));
        Require32(exactDao1Hash, nameof(exactDao1Hash));
        Require32(recipientAccountId, nameof(recipientAccountId));
        Require32(recipientDeviceId, nameof(recipientDeviceId));
        Require32(coordinatorId, nameof(coordinatorId));
        if (recipientAccountGeneration == 0 || recipientDeviceGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(recipientAccountGeneration));
        Kind = kind;
        this.innerOperationId = innerOperationId.ToArray();
        this.dao1OperationId = dao1OperationId.ToArray();
        this.mailboxOperationId = mailboxOperationId.ToArray();
        this.exactDao1Hash = exactDao1Hash.ToArray();
        this.recipientAccountId = recipientAccountId.ToArray();
        this.recipientDeviceId = recipientDeviceId.ToArray();
        this.coordinatorId = coordinatorId.ToArray();
        RecipientAccountGeneration = recipientAccountGeneration;
        RecipientDeviceGeneration = recipientDeviceGeneration;
        Cursor = cursor;
        ExactReplay = exactReplay;
    }

    internal MessagingV1DepositKind Kind { get; }
    internal ReadOnlyMemory<byte> InnerOperationId => innerOperationId.ToArray();
    internal ReadOnlyMemory<byte> Dao1OperationId => dao1OperationId.ToArray();
    internal ReadOnlyMemory<byte> MailboxOperationId => mailboxOperationId.ToArray();
    internal ReadOnlyMemory<byte> ExactDao1Hash => exactDao1Hash.ToArray();
    internal ReadOnlyMemory<byte> RecipientAccountId => recipientAccountId.ToArray();
    internal ReadOnlyMemory<byte> RecipientDeviceId => recipientDeviceId.ToArray();
    internal ulong RecipientAccountGeneration { get; }
    internal ulong RecipientDeviceGeneration { get; }
    internal ulong Cursor { get; }
    internal bool ExactReplay { get; }
    internal ReadOnlyMemory<byte> CoordinatorId => coordinatorId.ToArray();

    private static void Require16(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != MailboxClientLimits.OperationIdLength ||
            value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                $"{name} must contain exactly {MailboxClientLimits.OperationIdLength} nonzero bytes.",
                name);
    }

    protected static void Require32(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must contain exactly 32 nonzero bytes.", name);
    }
}

/// <summary>
/// Durable authenticated mailbox evidence for the exact initial DPH2 deposit.
/// This is the sole capability that can activate an established DPE2 route.
/// </summary>
internal sealed class MessagingV1InitialSessionDeliveryReceipt : MessagingV1DispatchReceipt
{
    private readonly byte[] networkId;
    private readonly byte[] sessionId;

    internal MessagingV1InitialSessionDeliveryReceipt(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> innerOperationId,
        ReadOnlySpan<byte> dao1OperationId,
        ReadOnlySpan<byte> mailboxOperationId,
        ReadOnlySpan<byte> exactDao1Hash,
        ReadOnlySpan<byte> recipientAccountId,
        ReadOnlySpan<byte> recipientDeviceId,
        ulong recipientAccountGeneration,
        ulong recipientDeviceGeneration,
        ulong cursor,
        bool exactReplay,
        ReadOnlySpan<byte> coordinatorId)
        : base(
            MessagingV1DepositKind.InitialSession,
            innerOperationId,
            dao1OperationId,
            mailboxOperationId,
            exactDao1Hash,
            recipientAccountId,
            recipientDeviceId,
            recipientAccountGeneration,
            recipientDeviceGeneration,
            cursor,
            exactReplay,
            coordinatorId)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("networkId must contain exactly 16 nonzero bytes.", nameof(networkId));
        Require32(sessionId, nameof(sessionId));
        this.networkId = networkId.ToArray();
        this.sessionId = sessionId.ToArray();
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> SessionId => sessionId.ToArray();

    internal VerifiedMessagingEstablishedRoute Activate(
        VerifiedMessagingRecipientDeposit currentRecipient) =>
        VerifiedMessagingEstablishedRoute.FromDeliveredInitialSession(this, currentRecipient);
}

/// <summary>Durable authenticated mailbox evidence for one exact DPE2 deposit.</summary>
internal sealed class MessagingV1EstablishedDeliveryReceipt : MessagingV1DispatchReceipt
{
    internal MessagingV1EstablishedDeliveryReceipt(
        ReadOnlySpan<byte> innerOperationId,
        ReadOnlySpan<byte> dao1OperationId,
        ReadOnlySpan<byte> mailboxOperationId,
        ReadOnlySpan<byte> exactDao1Hash,
        ReadOnlySpan<byte> recipientAccountId,
        ReadOnlySpan<byte> recipientDeviceId,
        ulong recipientAccountGeneration,
        ulong recipientDeviceGeneration,
        ulong cursor,
        bool exactReplay,
        ReadOnlySpan<byte> coordinatorId)
        : base(
            MessagingV1DepositKind.EstablishedSession,
            innerOperationId,
            dao1OperationId,
            mailboxOperationId,
            exactDao1Hash,
            recipientAccountId,
            recipientDeviceId,
            recipientAccountGeneration,
            recipientDeviceGeneration,
            cursor,
            exactReplay,
            coordinatorId)
    {
    }
}

/// <summary>
/// Current verified peer-deposit route, activated only by a durable receipt for
/// the exact DPH2 which established this session and recipient generation.
/// </summary>
internal sealed class VerifiedMessagingEstablishedRoute
{
    private readonly byte[] sessionId;

    private VerifiedMessagingEstablishedRoute(
        VerifiedMessagingRecipientDeposit recipient,
        ReadOnlySpan<byte> sessionId)
    {
        Recipient = recipient;
        this.sessionId = sessionId.ToArray();
    }

    internal VerifiedMessagingRecipientDeposit Recipient { get; }
    internal ReadOnlySpan<byte> SessionId => sessionId;

    internal static VerifiedMessagingEstablishedRoute FromDeliveredInitialSession(
        MessagingV1InitialSessionDeliveryReceipt delivered,
        VerifiedMessagingRecipientDeposit currentRecipient)
    {
        ArgumentNullException.ThrowIfNull(delivered);
        ArgumentNullException.ThrowIfNull(currentRecipient);
        if (!Fixed(delivered.NetworkId.Span, currentRecipient.NetworkId) ||
            !Fixed(delivered.RecipientAccountId.Span, currentRecipient.AccountId) ||
            !Fixed(delivered.RecipientDeviceId.Span, currentRecipient.DeviceId) ||
            delivered.RecipientAccountGeneration != currentRecipient.AccountGeneration ||
            delivered.RecipientDeviceGeneration != currentRecipient.DeviceGeneration)
            throw new CryptographicException(
                "The current peer route does not match the durably delivered DPH2 session generation.");
        return new VerifiedMessagingEstablishedRoute(
            currentRecipient, delivered.SessionId.Span);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class MessagingV1ReceivedDeposit : IDisposable
{
    private byte[]? exactInner;
    private readonly MailboxRetrievedEnvelope source;

    internal MessagingV1ReceivedDeposit(
        MessagingV1DepositKind kind,
        ParsedDao1 dao1,
        ReadOnlySpan<byte> exactInner,
        MailboxRetrievedEnvelope source)
    {
        Kind = kind;
        Dao1 = dao1 ?? throw new ArgumentNullException(nameof(dao1));
        this.source = source ?? throw new ArgumentNullException(nameof(source));
        this.exactInner = exactInner.ToArray();
    }

    internal MessagingV1DepositKind Kind { get; }
    internal ParsedDao1 Dao1 { get; }
    internal ReadOnlyMemory<byte> ExactInner =>
        (exactInner ?? throw new ObjectDisposedException(nameof(MessagingV1ReceivedDeposit))).ToArray();
    internal byte[] CopyExactInner() =>
        (exactInner ?? throw new ObjectDisposedException(nameof(MessagingV1ReceivedDeposit))).ToArray();
    internal MailboxAcknowledgement Acknowledgement => source.ToAcknowledgement();

    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref exactInner, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

internal sealed class MessagingV1ReceiveBatch : IDisposable
{
    private readonly byte[] continuationToken;
    private readonly byte[] mailboxScopeId;
    private int disposed;

    internal MessagingV1ReceiveBatch(
        IReadOnlyList<MessagingV1ReceivedDeposit> items,
        MailboxCredentialSelector selfRetrieveSelector,
        bool hasMore,
        ReadOnlySpan<byte> continuationToken)
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentNullException.ThrowIfNull(selfRetrieveSelector);
        if (selfRetrieveSelector.Kind != MailboxCredentialScopeKind.Self)
            throw new CryptographicException(
                "An inbound batch requires a self-retrieve mailbox scope.");
        Items = items.ToArray();
        mailboxScopeId = selfRetrieveSelector.ScopeId.ToArray();
        HasMore = hasMore;
        this.continuationToken = continuationToken.ToArray();
    }

    internal IReadOnlyList<MessagingV1ReceivedDeposit> Items { get; }
    internal bool HasMore { get; }
    internal bool BelongsTo(MailboxCredentialSelector selector)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(selector);
        return selector.Kind == MailboxCredentialScopeKind.Self &&
            CryptographicOperations.FixedTimeEquals(
                mailboxScopeId, selector.ScopeId.Span);
    }
    internal ReadOnlyMemory<byte> ContinuationToken
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            return continuationToken.ToArray();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var item in Items) item.Dispose();
        CryptographicOperations.ZeroMemory(continuationToken);
        CryptographicOperations.ZeroMemory(mailboxScopeId);
    }
}

/// <summary>
/// Opaque evidence that the authenticated inner event has been durably
/// materialized before its mailbox envelope is acknowledged. A ratchet or
/// pre-key commit alone is insufficient because it does not persist DMC2 in
/// the application inbox and may not survive a crash before materialization.
/// </summary>
internal sealed class MessagingV1InboundCommitReceipt
{
    private readonly byte[] dao1Hash;
    private readonly byte[] innerOperationId;
    private readonly byte[] innerReplayHash;

    private MessagingV1InboundCommitReceipt(
        ReadOnlySpan<byte> dao1Hash,
        ReadOnlySpan<byte> innerOperationId,
        ReadOnlySpan<byte> innerReplayHash)
    {
        Require(dao1Hash, nameof(dao1Hash));
        Require(innerOperationId, nameof(innerOperationId));
        Require(innerReplayHash, nameof(innerReplayHash));
        this.dao1Hash = dao1Hash.ToArray();
        this.innerOperationId = innerOperationId.ToArray();
        this.innerReplayHash = innerReplayHash.ToArray();
    }

#if DEEP_CLEAN_PRODUCTION
    /// <summary>
    /// The only production receipt path for an established direct DPE2.
    /// It commits the authenticated ratchet receive, replays its protected
    /// DMC2 stage into the durable account inbox, and only then binds the
    /// exact opened DAO1 to ACK authority. An exact replay recovers the
    /// already committed stage without decrypting a second time.
    /// </summary>
    internal static async ValueTask<MessagingV1InboundCommitReceipt>
        CommitAndMaterializeDirectDmc2Async(
            MessagingV1ReceivedDeposit received,
            DeepDirectMessagingStorageFacade owner,
            DeepDirectMessagingVerifiedSessionBinding verifiedSession,
            SqliteDeepMailboxStore inbox,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(received);
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(verifiedSession);
        ArgumentNullException.ThrowIfNull(inbox);
        if (received.Kind != MessagingV1DepositKind.EstablishedSession)
            throw new CryptographicException(
                "Only an established direct DPE2 can use this inbox receipt path.");
        var exact = received.CopyExactInner();
        try
        {
            using var committed = await owner.TryCommitEstablishedReceiveAsync(
                    verifiedSession, exact, cancellationToken).ConfigureAwait(false)
                ?? throw new CryptographicException(
                    "The verified direct DPE2 session is not available.");
            if (committed.Outcome is not (
                    ExactDpe2ReceiveSuccessOutcome.Fresh or
                    ExactDpe2ReceiveSuccessOutcome.OutOfOrderSkippedKey or
                    ExactDpe2ReceiveSuccessOutcome.ExactReplay))
                throw new CryptographicException(
                    "The direct DPE2 receive did not commit.");
            if (committed.Outcome != ExactDpe2ReceiveSuccessOutcome.ExactReplay &&
                !committed.HasAuthenticatedDmc2)
                throw new CryptographicException(
                    "The fresh direct DPE2 commit has no authenticated DMC2.");
            var disposition = await owner.TryMaterializeEstablishedReceiveAsync(
                    verifiedSession, exact, inbox, cancellationToken)
                .ConfigureAwait(false);
            if (disposition is not (DirectDmc2InboxDisposition.Materialized or
                    DirectDmc2InboxDisposition.ExactReplay))
                throw new CryptographicException(
                    "The authenticated direct event is not durably materialized.");
            return CreateBound(received);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    /// <summary>
    /// Commits and materializes an unsolicited DPH2 only after its encrypted
    /// SessionInit and ContactHello have been authenticated against the
    /// current initiator checkpoint. The durable ContactHello inbox entry is
    /// the pending contact-request state required before mailbox ACK.
    /// </summary>
    internal static async ValueTask<MessagingV1InboundCommitReceipt>
        CommitAndMaterializeInitialSessionAsync(
            MessagingV1ReceivedDeposit received,
            DeepDirectMessagingStorageFacade owner,
            VerifiedDph2InitialClaim verifiedInitial,
            SqliteDeepMailboxStore inbox,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(received);
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(verifiedInitial);
        ArgumentNullException.ThrowIfNull(inbox);
        if (received.Kind != MessagingV1DepositKind.InitialSession)
            throw new CryptographicException(
                "Only an initial DPH2 can use the unsolicited inbox receipt path.");
        var exact = received.CopyExactInner();
        try
        {
            if (!Fixed(exact, verifiedInitial.Initiation.ExactBytes.Span))
                throw new CryptographicException(
                    "The retrieved DPH2 differs from its verified initial claim.");
            var committed = await owner.TryCommitUnsolicitedResponderSessionAsync(
                    verifiedInitial,
                    maximumMessagesWithoutPqInjection: 64,
                    cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "The verified unsolicited DPH2 session was not committed.");
            if (!committed.IsDurablyStaged || committed.Session is null)
                throw new CryptographicException(
                    "The unsolicited DPH2 has no durable verified session stage.");
            var disposition = await owner.TryMaterializeInitialReceiveAsync(
                    committed.Session,
                    verifiedInitial,
                    inbox,
                    cancellationToken)
                .ConfigureAwait(false);
            if (disposition is not (DirectDmc2InboxDisposition.Materialized or
                    DirectDmc2InboxDisposition.ExactReplay))
                throw new CryptographicException(
                    "The authenticated initial events are not durably materialized.");
            return CreateBound(received);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact);
        }
    }
#endif

#if DEEP_TEST_INTERNALS
    internal static MessagingV1InboundCommitReceipt CreateForTests(
        MessagingV1ReceivedDeposit received)
    {
        ArgumentNullException.ThrowIfNull(received);
        return CreateBound(received);
    }
#endif

    private static MessagingV1InboundCommitReceipt CreateBound(
        MessagingV1ReceivedDeposit received)
    {
        var exact = received.CopyExactInner();
        try
        {
            if (received.Kind == MessagingV1DepositKind.InitialSession)
            {
                var record = Dph2Codec.Decode(exact);
                return new MessagingV1InboundCommitReceipt(
                    SHA256.HashData(received.Dao1.CanonicalBytes.Span),
                    record.ClaimOperationId.Span,
                    MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(record));
            }
            var dpe2 = Dpe2Codec.Decode(exact);
            return new MessagingV1InboundCommitReceipt(
                SHA256.HashData(received.Dao1.CanonicalBytes.Span),
                dpe2.OperationId.Span,
                MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(dpe2));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact);
        }
    }

    internal bool Matches(MessagingV1ReceivedDeposit received)
    {
        var exact = received.CopyExactInner();
        try
        {
            byte[] replayHash;
            ReadOnlyMemory<byte> operationId;
            if (received.Kind == MessagingV1DepositKind.InitialSession)
            {
                var record = Dph2Codec.Decode(exact);
                replayHash = MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(record);
                operationId = record.ClaimOperationId;
            }
            else
            {
                var record = Dpe2Codec.Decode(exact);
                replayHash = MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(record);
                operationId = record.OperationId;
            }
            try
            {
                return Fixed(dao1Hash, SHA256.HashData(received.Dao1.CanonicalBytes.Span)) &&
                    Fixed(innerOperationId, operationId.Span) &&
                    Fixed(innerReplayHash, replayHash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(replayHash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Require(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must contain exactly 32 nonzero bytes.", name);
    }
}

internal interface IMessagingV1PrivacyTransport
{
    ValueTask<MessagingV1InitialSessionDeliveryReceipt> SendInitialSessionAsync(
        InitiatorInitialSessionDispatchEnvelope pending,
        VerifiedMessagingRecipientDeposit recipient,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken = default);

    ValueTask<MessagingV1EstablishedDeliveryReceipt> SendEstablishedAsync(
        ExactDpe2SendSuccessCapability committed,
        VerifiedMessagingEstablishedRoute route,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken = default);

    ValueTask<MessagingV1ReceiveBatch> RetrieveAsync(
        VerifiedMessagingMailboxAccess selfRetrieveAccess,
        ushort maximumItems,
        CancellationToken cancellationToken = default);

    ValueTask AcknowledgeAsync(
        VerifiedMessagingMailboxAccess selfRetrieveAccess,
        MessagingV1ReceiveBatch batch,
        IReadOnlyList<MessagingV1InboundCommitReceipt> committed,
        CancellationToken cancellationToken = default);
}
