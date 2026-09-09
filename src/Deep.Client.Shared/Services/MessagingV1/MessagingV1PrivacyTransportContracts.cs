using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.PreKeyV1;
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
        MailboxCredentialSelector selector,
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
        Selector = selector ?? throw new ArgumentNullException(nameof(selector));
        Require(networkId, 16, nameof(networkId));
        Require(accountId, 32, nameof(accountId));
        Require(deviceId, 32, nameof(deviceId));
        Require(sealingKeyId, 32, nameof(sealingKeyId));
        Require(sealingPublicKey, 32, nameof(sealingPublicKey));
        if (!selector.AccountScope.Equals(localOutboxScope) ||
            selector.Kind != MailboxCredentialScopeKind.Peer)
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
    internal MailboxCredentialSelector Selector { get; }
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
        MailboxCredentialSelector selector,
        ReadOnlySpan<byte> recipientDeviceId)
    {
        ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(localOutboxScope);
        ArgumentNullException.ThrowIfNull(selector);
        Require(recipientDeviceId, 32, nameof(recipientDeviceId));
        var selectedDeviceId = recipientDeviceId.ToArray();

        var directory = peer.Bundle.Directory;
        var device = directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, selectedDeviceId));
        var directoryEntry = directory.Record.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.DeviceId.Span, selectedDeviceId));
        var xrr1 = peer.Route.Reachability;
        var xra1 = peer.Route.Authorization;
        if (!StringComparer.Ordinal.Equals(xrr1.Magic, "XRR1") ||
            !StringComparer.Ordinal.Equals(xra1.Magic, "XRA1") ||
            device is null || directoryEntry is null ||
            !Fixed(xrr1.Field(1).Span, directory.Record.NetworkId.Span) ||
            !Fixed(xra1.Field(1).Span, directory.Record.NetworkId.Span) ||
            !Fixed(xra1.Field(14).Span, selectedDeviceId) ||
            !Fixed(selector.SubjectId.Span, xrr1.Field(10).Span) ||
            !Fixed(directoryEntry.Dpd1Reference.CanonicalHash.Span,
                device.Certificate.CanonicalHash.Span))
        {
            throw new CryptographicException(
                "The requested recipient/deposit capability is outside the reverified ContactV1 closure.");
        }

        var xrrExpiry = U64(xrr1.Field(17).Span, "XRR1 expiry");
        var xraExpiry = U64(xra1.Field(13).Span, "XRA1 expiry");
        return new VerifiedMessagingRecipientDeposit(
            localOutboxScope,
            selector,
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
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ulong directoryGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> sealingKeyId,
        ReadOnlySpan<byte> sealingPublicKey,
        ulong expiresAtUnixSeconds) => new(
            localOutboxScope, selector, networkId, accountId, accountGeneration,
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
    private readonly byte[] logicalOperationId;
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
        // Compatibility alias for the durable DAO1 operation. New code should
        // use the explicitly typed identifier properties below.
        logicalOperationId = this.dao1OperationId;
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
    internal ReadOnlyMemory<byte> LogicalOperationId => logicalOperationId.ToArray();
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
    private int disposed;

    internal MessagingV1ReceiveBatch(
        IReadOnlyList<MessagingV1ReceivedDeposit> items,
        bool hasMore,
        ReadOnlySpan<byte> continuationToken)
    {
        ArgumentNullException.ThrowIfNull(items);
        Items = items.ToArray();
        HasMore = hasMore;
        this.continuationToken = continuationToken.ToArray();
    }

    internal IReadOnlyList<MessagingV1ReceivedDeposit> Items { get; }
    internal bool HasMore { get; }
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
    }
}

/// <summary>
/// Opaque evidence that the authenticated inner object has already committed
/// to its ratchet/application store. It cannot be created from a boolean or raw
/// caller-provided hash.
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

    internal static MessagingV1InboundCommitReceipt FromCommittedDpe2(
        MessagingV1ReceivedDeposit received,
        ExactDpe2ReceiveSuccessCapability committed)
    {
        ArgumentNullException.ThrowIfNull(received);
        ArgumentNullException.ThrowIfNull(committed);
        if (received.Kind != MessagingV1DepositKind.EstablishedSession)
            throw new CryptographicException("A DPE2 commit capability cannot acknowledge DPH2.");
        var exact = received.ExactInner.ToArray();
        try
        {
            var record = Dpe2Codec.Decode(exact);
            var replayHash = MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(record);
            var operationId = committed.OperationId.ToArray();
            var committedHash = committed.ExactEnvelopeHash.ToArray();
            try
            {
                if (!Fixed(operationId, record.OperationId.Span) ||
                    !Fixed(committedHash, replayHash))
                    throw new CryptographicException("The durable DPE2 commit receipt is for another envelope.");
                return new MessagingV1InboundCommitReceipt(
                    SHA256.HashData(received.Dao1.CanonicalBytes.Span),
                    operationId,
                    replayHash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(operationId);
                CryptographicOperations.ZeroMemory(committedHash);
                CryptographicOperations.ZeroMemory(replayHash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact);
        }
    }

    /// <summary>
    /// Verifies and commits an inbound DPH2 through the production ContactV1 /
    /// device-wide pre-key saga before minting mailbox acknowledgement authority.
    /// A decoded DPH2, a boolean, or a store result cannot bypass this boundary.
    /// </summary>
    internal static async ValueTask<MessagingV1InboundCommitReceipt>
        CommitInitialSessionAsync(
        MessagingV1ReceivedDeposit received,
        ContactInitialSessionCoordinator coordinator,
        VerifiedXpc1PreKeyClaimReceipt claimReceipt,
        VerifiedDph2Initiation initiation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(received);
        ArgumentNullException.ThrowIfNull(coordinator);
        ArgumentNullException.ThrowIfNull(claimReceipt);
        ArgumentNullException.ThrowIfNull(initiation);
        if (received.Kind != MessagingV1DepositKind.InitialSession)
            throw new CryptographicException("An initial-session commit cannot acknowledge DPE2.");

        var receivedExact = received.ExactInner.ToArray();
        var verifiedExact = initiation.ExactBytes.ToArray();
        try
        {
            if (!Fixed(receivedExact, verifiedExact))
                throw new CryptographicException(
                    "The verified DPH2 initiation is for another retrieved DAO1.");
            var committed = await coordinator.CommitAsync(
                claimReceipt, initiation, cancellationToken).ConfigureAwait(false);
            if (committed.ForkLatched ||
                committed.Disposition is not (
                    PreKeyV1InitialSessionSagaDisposition.Initialized or
                    PreKeyV1InitialSessionSagaDisposition.ExactReplay) ||
                committed.SessionDisposition is not (
                    MessagingCryptoV1CommitDisposition.Initialized or
                    MessagingCryptoV1CommitDisposition.ExactReplay))
                throw new CryptographicException(
                    "The verified DPH2 did not durably establish an exact local session.");
            return CreateBound(received);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(receivedExact);
            CryptographicOperations.ZeroMemory(verifiedExact);
        }
    }

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
        var exact = received.ExactInner.ToArray();
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
        var exact = received.ExactInner.ToArray();
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
        MailboxCredentialSelector selfRetrieveSelector,
        ushort maximumItems,
        CancellationToken cancellationToken = default);

    ValueTask AcknowledgeAsync(
        MailboxCredentialSelector selfRetrieveSelector,
        MessagingV1ReceiveBatch batch,
        IReadOnlyList<MessagingV1InboundCommitReceipt> committed,
        CancellationToken cancellationToken = default);
}
