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
    private readonly PrivacyRoutedMailboxBinaryIngress ingress;
    private readonly MessagingDao1SealingAuthority sealer;
    private readonly PrivacyRoutedMessagingTransport transport;
    private readonly ulong grantExpiresAt;
    private readonly TimeProvider timeProvider;
    private int disposed;

    private PrivacyRoutedInitialSessionDispatcher(
        VerifiedMessagingMailboxAccess access,
        PrivacyRoutedMailboxBinaryIngress ingress,
        MessagingDao1SealingAuthority sealer,
        PrivacyRoutedMessagingTransport transport,
        ulong grantExpiresAt,
        TimeProvider timeProvider)
    {
        this.access = access;
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
            delivered.SessionId,
            delivered.InnerOperationId,
            delivered.Dao1OperationId,
            delivered.MailboxOperationId,
            delivered.Cursor,
            delivered.ExactReplay);
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

public sealed record DeepDirectMessagingInitialDeliveryResult(
    ReadOnlyMemory<byte> SessionId,
    ReadOnlyMemory<byte> ClaimOperationId,
    ReadOnlyMemory<byte> Dao1OperationId,
    ReadOnlyMemory<byte> MailboxOperationId,
    ulong Cursor,
    bool ExactReplay);
#endif
