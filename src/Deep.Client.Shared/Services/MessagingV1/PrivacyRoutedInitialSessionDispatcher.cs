#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.MessagingV1;

/// <summary>
/// Public, capability-based composition for the first clean-break MSG-01
/// delivery.  Callers cannot inject mailbox issuer trust: the runtime is
/// created only from an already verified XMC1 grant and its authenticated
/// PMA2 authority.
/// </summary>
public sealed class PrivacyRoutedInitialSessionDispatcher : IDisposable
{
    private static ReadOnlySpan<byte> AccountScopeDomain =>
        "deep.mailbox.account-scope.v1"u8;

    private readonly VerifiedMessagingMailboxAccess access;
    private readonly SqliteDeepMailboxStore store;
    private readonly PrivacyRoutedMailboxBinaryIngress ingress;
    private readonly MessagingDao1SealingAuthority sealer;
    private readonly PrivacyRoutedMessagingTransport transport;
    private readonly ulong grantExpiresAt;
    private readonly TimeProvider timeProvider;
    private int disposed;

    private PrivacyRoutedInitialSessionDispatcher(
        VerifiedMessagingMailboxAccess access,
        SqliteDeepMailboxStore store,
        PrivacyRoutedMailboxBinaryIngress ingress,
        MessagingDao1SealingAuthority sealer,
        PrivacyRoutedMessagingTransport transport,
        ulong grantExpiresAt,
        TimeProvider timeProvider)
    {
        this.access = access;
        this.store = store;
        this.ingress = ingress;
        this.sealer = sealer;
        this.transport = transport;
        this.grantExpiresAt = grantExpiresAt;
        this.timeProvider = timeProvider;
    }

    public static PrivacyRoutedInitialSessionDispatcher Create(
        DeepLocalIdentitySnapshot localIdentity,
        SqliteDeepMailboxStore store,
        VerifiedCurrentMailboxGrant grant,
        ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner holder,
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        PrivacyRoutingCodec codec,
        ReadOnlySpan<byte> protectedDao1Seed,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(localIdentity);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(holder);
        ArgumentNullException.ThrowIfNull(primaryRoute);
        ArgumentNullException.ThrowIfNull(fallbackRoute);
        ArgumentNullException.ThrowIfNull(codec);
        if (grant.Domain != MailboxCapabilityDomain.Deposit)
            throw new CryptographicException(
                "Initial MSG-01 dispatch requires a verified peer-deposit grant.");
        if (!localIdentity.Account.AccountIdentity.NetworkId.Matches(
                localIdentity.NetworkId.Span))
            throw new CryptographicException(
                "The local MSG-01 identity has a cross-network binding.");

        var clock = timeProvider ?? TimeProvider.System;
        var holderKey = holder.GetEd25519PublicKey();
        var accountDigest = DomainHash(AccountScopeDomain, holderKey);
        try
        {
            var scope = OutboxAccountScope.FromBytes(accountDigest);
            var access = VerifiedMessagingMailboxAccess.FromCurrentGrant(
                scope,
                MailboxCredentialScopeKind.Peer,
                grant,
                holder);
            var decodePolicies = new TimeProviderMailboxClientDecodePolicyProvider(
                new MailboxEpochWindow
                {
                    CurrentEpoch = grant.Epoch,
                    NextEpoch = 0,
                    CurrentNotBeforeUnixSeconds = grant.NotBeforeUnixSeconds,
                    NextNotBeforeUnixSeconds = 0,
                    CurrentExpiresAtUnixSeconds = grant.ExpiresAtUnixSeconds,
                    NextExpiresAtUnixSeconds = 0
                },
                new MailboxCapabilityDecodePolicy
                {
                    CurrentBucket = checked((uint)grant.Epoch),
                    MinimumGeneration = grant.Generation
                },
                clock);
            _ = decodePolicies.GetCurrent();
            var ingress = new PrivacyRoutedMailboxBinaryIngress(
                primaryRoute, fallbackRoute, decodePolicies, codec);
            try
            {
                var requests = new MailboxAuthenticatedRequestFactory(
                    store, grant.RuntimeAuthority);
                var adapter = new ClientMailboxAdapter(
                    ClientFeatureFlags.ReleaseDefaults with
                    {
                        PersistentTransportOutboxEnabled = true,
                        ClientMailboxAdapterEnabled = true
                    },
                    new ClientMailboxActivation(
                        enabled: true,
                        access.Selector.IssuerContext.Span,
                        ingressConfigured: true),
                    ingress,
                    store,
                    store,
                    store,
                    store,
                    new PinnedClientMailboxReceiptVerifier(
                        new SodiumMailboxPeerReplicationCrypto()),
                    requests,
                    decodePolicies,
                    clock);
                var mailbox = new PrivacyRoutedMessagingMailboxClient(
                    adapter, requests, ingress);
                var local = new MessagingV1LocalContext(
                    scope,
                    localIdentity.NetworkId.Span,
                    localIdentity.Account.AccountIdentity.AccountId.Bytes.Span,
                    localIdentity.Device.DeviceId.Bytes.Span,
                    localIdentity.Device.DeviceGeneration);
                var sealer = new MessagingDao1SealingAuthority(protectedDao1Seed);
                try
                {
                    var transport = new PrivacyRoutedMessagingTransport(
                        local,
                        mailbox,
                        sealer,
                        OutboundOnlyMessagingDao1OpenAuthority.Instance,
                        clock);
                    return new PrivacyRoutedInitialSessionDispatcher(
                        access,
                        store,
                        ingress,
                        sealer,
                        transport,
                        grant.ExpiresAtUnixSeconds,
                        clock);
                }
                catch
                {
                    sealer.Dispose();
                    throw;
                }
            }
            catch
            {
                ingress.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(holderKey);
            CryptographicOperations.ZeroMemory(accountDigest);
        }
    }

    public async ValueTask<DeepDirectMessagingInitialDeliveryResult> SendAsync(
        DeepDirectMessagingInitiatorCommitResult committed,
        ContactResolverReverifiedPeerAuthority peer,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(committed);
        ArgumentNullException.ThrowIfNull(peer);
        var recipient = VerifiedMessagingRecipientDeposit.FromReverifiedPeer(
            peer,
            access.Selector.AccountScope,
            access,
            committed.Session.RemoteDeviceId.Span);
        var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (now <= 0)
            throw new InvalidOperationException("MSG-01 time is outside its valid range.");
        var expiresAt = Math.Min(
            checked((ulong)now + 600),
            Math.Min(grantExpiresAt, recipient.ExpiresAtUnixSeconds));
        using var pending = new InitiatorInitialSessionDispatchEnvelope(
            committed.ExactDph2.Span,
            committed.ClaimOperationId.Span,
            committed.Session.ExactDph2Id.Span,
            committed.FullReplayHash.Span);
        var delivered = await transport.SendInitialSessionAsync(
                pending,
                recipient,
                expiresAt,
                cancellationToken)
            .ConfigureAwait(false);
        return new DeepDirectMessagingInitialDeliveryResult(
            committed.Session, delivered);
    }

    /// <summary>
    /// Sends an exact account-owned text event on the session whose initial
    /// DPH2 has a verified durable mailbox receipt. A retry reuses the exact
    /// DPE2 ciphertext committed with the ratchet, never encrypts again.
    /// </summary>
    public async ValueTask<DeepDirectTextDeliveryResult?> SendStagedTextAsync(
        DeepDirectMessagingInitialDeliveryResult initialDelivery,
        ContactResolverReverifiedPeerAuthority peer,
        DeepDirectMessagingStorageFacade messaging,
        ReadOnlyMemory<byte> logicalMessageId,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(initialDelivery);
        ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(messaging);
        var recipient = VerifiedMessagingRecipientDeposit.FromReverifiedPeer(
            peer, access.Selector.AccountScope, access,
            initialDelivery.Session.RemoteDeviceId.Span);
        var route = initialDelivery.Receipt.Activate(recipient);
        using var staged = await messaging.TryReadDirectTextAsync(
                initialDelivery.Session, store, logicalMessageId, cancellationToken)
            .ConfigureAwait(false);
        if (staged is null) return null;
        var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (now <= 0)
            throw new InvalidOperationException("MSG-01 time is outside its valid range.");
        var expiresAt = Math.Min(
            checked((ulong)now + 600),
            Math.Min(grantExpiresAt, recipient.ExpiresAtUnixSeconds));
        using var recovered = await messaging.TryRecoverEstablishedSendAsync(
                initialDelivery.Session, staged.OperationId, cancellationToken)
            .ConfigureAwait(false);
        MessagingV1EstablishedDeliveryReceipt delivered;
        if (recovered is not null)
        {
            delivered = await transport.SendRecoveredEstablishedAsync(
                    recovered, route, expiresAt, cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            using var committed = await messaging.TryCommitEstablishedSendAsync(
                    initialDelivery.Session,
                    staged.ExactDmc2,
                    staged.OperationId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (committed is null) return null;
            delivered = await transport.SendEstablishedAsync(
                    committed, route, expiresAt, cancellationToken)
                .ConfigureAwait(false);
        }
        return new DeepDirectTextDeliveryResult(
            staged.LogicalMessageId, delivered.Cursor, delivered.ExactReplay);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        sealer.Dispose();
        ingress.Dispose();
    }

    private static byte[] DomainHash(
        ReadOnlySpan<byte> domain,
        ReadOnlySpan<byte> value)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    private sealed class OutboundOnlyMessagingDao1OpenAuthority :
        IMessagingDao1OpenAuthority
    {
        internal static OutboundOnlyMessagingDao1OpenAuthority Instance { get; } = new();

        public ValueTask<MessagingDao1Opened> OpenAsync(
            ReadOnlyMemory<byte> exactDao1,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException(
                "An outbound-only MSG-01 dispatcher cannot open inbound DAO1.");
    }
}

public sealed class DeepDirectMessagingInitialDeliveryResult
{
    internal DeepDirectMessagingInitialDeliveryResult(
        DeepDirectMessagingVerifiedSessionBinding session,
        MessagingV1InitialSessionDeliveryReceipt receipt)
    {
        Session = session ?? throw new ArgumentNullException(nameof(session));
        Receipt = receipt ?? throw new ArgumentNullException(nameof(receipt));
        if (!Session.NetworkId.Span.SequenceEqual(receipt.NetworkId.Span) ||
            !Session.ExactDph2Id.Span.SequenceEqual(receipt.SessionId.Span) ||
            !Session.RemoteAccountId.Span.SequenceEqual(receipt.RecipientAccountId.Span) ||
            !Session.RemoteDeviceId.Span.SequenceEqual(receipt.RecipientDeviceId.Span) ||
            Session.RemoteAccountGeneration != receipt.RecipientAccountGeneration ||
            Session.RemoteDeviceGeneration != receipt.RecipientDeviceGeneration)
            throw new CryptographicException(
                "The initial delivery receipt differs from its verified session.");
    }

    public DeepDirectMessagingVerifiedSessionBinding Session { get; }
    internal MessagingV1InitialSessionDeliveryReceipt Receipt { get; }
    public ReadOnlyMemory<byte> SessionId => Receipt.SessionId;
    public ReadOnlyMemory<byte> ClaimOperationId => Receipt.InnerOperationId;
    public ReadOnlyMemory<byte> Dao1OperationId => Receipt.Dao1OperationId;
    public ReadOnlyMemory<byte> MailboxOperationId => Receipt.MailboxOperationId;
    public ulong Cursor => Receipt.Cursor;
    public bool ExactReplay => Receipt.ExactReplay;
}

public sealed record DeepDirectTextDeliveryResult(
    ReadOnlyMemory<byte> LogicalMessageId,
    ulong Cursor,
    bool ExactReplay);
#endif
