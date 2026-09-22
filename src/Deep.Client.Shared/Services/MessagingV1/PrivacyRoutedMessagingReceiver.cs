#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services.MessagingV1;

public enum DeepDirectMessagingInboundEnvelopeKind : byte
{
    InitialSession = 1,
    EstablishedSession = 2,
}

public sealed class DeepDirectMessagingInboundEnvelope : IDisposable
{
    private byte[]? exactInner;

    internal DeepDirectMessagingInboundEnvelope(
        DeepDirectMessagingInboundEnvelopeKind kind,
        ReadOnlySpan<byte> exactInner)
    {
        Kind = kind;
        this.exactInner = exactInner.ToArray();
    }

    public DeepDirectMessagingInboundEnvelopeKind Kind { get; }
    public ReadOnlyMemory<byte> ExactInner =>
        (Volatile.Read(ref exactInner) ??
            throw new ObjectDisposedException(nameof(DeepDirectMessagingInboundEnvelope)))
        .ToArray();

    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref exactInner, null);
        if (owned is not null)
            CryptographicOperations.ZeroMemory(owned);
    }
}

public sealed class DeepDirectMessagingInboundBatch : IDisposable
{
    private readonly object token = new();
    private MessagingV1ReceiveBatch? inner;

    internal DeepDirectMessagingInboundBatch(MessagingV1ReceiveBatch inner)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        try
        {
            Items = inner.Items.Select(static item =>
                new DeepDirectMessagingInboundEnvelope(
                    item.Kind switch
                    {
                        MessagingV1DepositKind.InitialSession =>
                            DeepDirectMessagingInboundEnvelopeKind.InitialSession,
                        MessagingV1DepositKind.EstablishedSession =>
                            DeepDirectMessagingInboundEnvelopeKind.EstablishedSession,
                        _ => throw new CryptographicException(
                            "The retrieved mailbox item has an unsupported inner kind.")
                    },
                    item.ExactInner.Span)).ToArray();
        }
        catch
        {
            this.inner = null;
            inner.Dispose();
            throw;
        }
    }

    public IReadOnlyList<DeepDirectMessagingInboundEnvelope> Items { get; }
    public bool HasMore => Current.HasMore;

    internal object Token => token;
    internal MessagingV1ReceiveBatch Current =>
        Volatile.Read(ref inner) ??
        throw new ObjectDisposedException(nameof(DeepDirectMessagingInboundBatch));

    public void Dispose()
    {
        foreach (var item in Items)
            item.Dispose();
        Interlocked.Exchange(ref inner, null)?.Dispose();
    }
}

public sealed class DeepDirectMessagingInboundCommit
{
    private readonly object batchToken;
    internal DeepDirectMessagingInboundCommit(
        object batchToken,
        int index,
        MessagingV1InboundCommitReceipt receipt)
    {
        this.batchToken = batchToken;
        Index = index;
        Receipt = receipt;
    }

    internal int Index { get; }
    internal MessagingV1InboundCommitReceipt Receipt { get; }
    internal bool BelongsTo(DeepDirectMessagingInboundBatch batch) =>
        ReferenceEquals(batchToken, batch.Token);
}

public sealed record DeepDirectMessagingPollResult(
    int RetrievedCount,
    int CommittedCount,
    bool Acknowledged,
    bool HasMore);

/// <summary>
/// Current-only production receive boundary. It retrieves only through the
/// privacy-routed mailbox adapter, opens DAO1 with the protected key belonging
/// to the confirmed local XPU1 route, and grants ACK only for exact durable
/// inner-commit capabilities minted by this instance.
/// </summary>
public sealed class PrivacyRoutedMessagingReceiver : IDisposable
{
    private static ReadOnlySpan<byte> AccountScopeDomain =>
        "deep.mailbox.account-scope.v1"u8;

    private readonly VerifiedMessagingMailboxAccess access;
    private readonly DeepDirectMessagingStorageFacade owner;
    private readonly SqliteDeepMailboxStore inbox;
    private readonly ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner holder;
    private readonly PrivacyRoutedMailboxBinaryIngress ingress;
    private readonly MessagingDao1SealingAuthority sealer;
    private readonly PrivacyRoutedMessagingTransport transport;
    private readonly ProductionContactResolvePathAuthoritySource pathAuthority;
    private readonly VerifiedLocalMessagingRecipient localRecipient;
    private int disposed;

    private PrivacyRoutedMessagingReceiver(
        VerifiedMessagingMailboxAccess access,
        DeepDirectMessagingStorageFacade owner,
        SqliteDeepMailboxStore inbox,
        ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner holder,
        PrivacyRoutedMailboxBinaryIngress ingress,
        MessagingDao1SealingAuthority sealer,
        PrivacyRoutedMessagingTransport transport,
        ProductionContactResolvePathAuthoritySource pathAuthority,
        VerifiedLocalMessagingRecipient localRecipient)
    {
        this.access = access;
        this.owner = owner;
        this.inbox = inbox;
        this.holder = holder;
        this.ingress = ingress;
        this.sealer = sealer;
        this.transport = transport;
        this.pathAuthority = pathAuthority;
        this.localRecipient = localRecipient;
    }

    public static PrivacyRoutedMessagingReceiver Create(
        DeepLocalIdentitySnapshot localIdentity,
        SqliteDeepMailboxStore store,
        DeepDirectMessagingStorageFacade owner,
        ParsedContactRouteClosure currentLocalRoute,
        VerifiedCurrentMailboxGrant retrieveGrant,
        ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner holder,
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        PrivacyRoutingCodec codec,
        ReadOnlySpan<byte> protectedDao1Seed,
        ProductionContactResolvePathAuthoritySource pathAuthority,
        VerifiedLocalMessagingRecipient localRecipient,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(localIdentity);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(currentLocalRoute);
        ArgumentNullException.ThrowIfNull(retrieveGrant);
        ArgumentNullException.ThrowIfNull(holder);
        ArgumentNullException.ThrowIfNull(pathAuthority);
        ArgumentNullException.ThrowIfNull(localRecipient);
        if (retrieveGrant.Domain != MailboxCapabilityDomain.Retrieve)
            throw new CryptographicException(
                "MSG-01 receive requires a verified self-retrieve grant.");

        var clock = timeProvider ?? TimeProvider.System;
        var holderKey = holder.GetEd25519PublicKey();
        var accountDigest = DomainHash(AccountScopeDomain, holderKey);
        try
        {
            var scope = OutboxAccountScope.FromBytes(accountDigest);
            var access = VerifiedMessagingMailboxAccess.FromCurrentGrant(
                scope,
                MailboxCredentialScopeKind.Self,
                retrieveGrant,
                holder);
            var decodePolicies = new TimeProviderMailboxClientDecodePolicyProvider(
                new MailboxEpochWindow
                {
                    CurrentEpoch = retrieveGrant.Epoch,
                    NextEpoch = 0,
                    CurrentNotBeforeUnixSeconds = retrieveGrant.NotBeforeUnixSeconds,
                    NextNotBeforeUnixSeconds = 0,
                    CurrentExpiresAtUnixSeconds = retrieveGrant.ExpiresAtUnixSeconds,
                    NextExpiresAtUnixSeconds = 0
                },
                new MailboxCapabilityDecodePolicy
                {
                    CurrentBucket = checked((uint)retrieveGrant.Epoch),
                    MinimumGeneration = retrieveGrant.Generation
                },
                clock);
            _ = decodePolicies.GetCurrent();
            var ingress = new PrivacyRoutedMailboxBinaryIngress(
                primaryRoute, fallbackRoute, decodePolicies, codec);
            try
            {
                var requests = new MailboxAuthenticatedRequestFactory(
                    store, retrieveGrant.RuntimeAuthority);
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
                        new StorageOwnedDao1OpenAuthority(owner, currentLocalRoute),
                        clock);
                    return new PrivacyRoutedMessagingReceiver(
                        access, owner, store, holder, ingress, sealer, transport,
                        pathAuthority, localRecipient);
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

    public async ValueTask<DeepDirectMessagingInboundBatch> RetrieveAsync(
        ushort maximumItems = 32,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return new DeepDirectMessagingInboundBatch(
            await transport.RetrieveAsync(access, maximumItems, cancellationToken)
                .ConfigureAwait(false));
    }

    /// <summary>
    /// Processes one bounded self-mailbox batch. A partial batch stays
    /// unacknowledged so every item can be replayed after a crash or a later
    /// authority refresh. No caller-supplied commit receipts are accepted.
    /// </summary>
    public async ValueTask<DeepDirectMessagingPollResult> PollOnceAsync(
        ushort maximumItems = 32,
        CancellationToken cancellationToken = default)
    {
        using var batch = await RetrieveAsync(maximumItems, cancellationToken)
            .ConfigureAwait(false);
        var committed = new List<DeepDirectMessagingInboundCommit>(batch.Items.Count);
        for (var index = 0; index < batch.Items.Count; index++)
        {
            var receipt = batch.Items[index].Kind switch
            {
                DeepDirectMessagingInboundEnvelopeKind.InitialSession =>
                    await ProcessInitialAsync(batch, index,
                        cancellationToken: cancellationToken).ConfigureAwait(false),
                DeepDirectMessagingInboundEnvelopeKind.EstablishedSession =>
                    await ProcessEstablishedAsync(batch, index, cancellationToken)
                        .ConfigureAwait(false),
                _ => throw new CryptographicException(
                    "The inbound mailbox contains an unsupported envelope kind.")
            };
            if (receipt is null)
                return new DeepDirectMessagingPollResult(
                    batch.Items.Count, committed.Count, false, batch.HasMore);
            committed.Add(receipt);
        }
        if (committed.Count != 0)
            await AcknowledgeAsync(batch, committed, cancellationToken)
                .ConfigureAwait(false);
        return new DeepDirectMessagingPollResult(
            batch.Items.Count, committed.Count, committed.Count != 0,
            batch.HasMore);
    }

    public async ValueTask<DeepDirectMessagingInboundCommit> CommitInitialAsync(
        DeepDirectMessagingInboundBatch batch,
        int index,
        VerifiedDph2InitialClaim verifiedInitial,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(batch);
        ArgumentNullException.ThrowIfNull(verifiedInitial);
        var current = batch.Current;
        if ((uint)index >= (uint)current.Items.Count)
            throw new ArgumentOutOfRangeException(nameof(index));
        var receipt = await MessagingV1InboundCommitReceipt
            .CommitAndMaterializeInitialSessionAsync(
                current.Items[index], owner, verifiedInitial, inbox,
                cancellationToken)
            .ConfigureAwait(false);
        return new DeepDirectMessagingInboundCommit(batch.Token, index, receipt);
    }

    public async ValueTask<DeepDirectMessagingInboundCommit?>
        ProcessInitialAsync(
            DeepDirectMessagingInboundBatch batch,
            int index,
            int maximumMessagesWithoutPqInjection = 64,
            CancellationToken cancellationToken = default)
    {
        var sender = await ResolveInitialSenderAsync(
                batch, index, pathAuthority, cancellationToken)
            .ConfigureAwait(false);
        var verified = await VerifyInitialClaimAsync(
                batch, index, sender, localRecipient,
                maximumMessagesWithoutPqInjection, cancellationToken)
            .ConfigureAwait(false);
        return verified is null
            ? null
            : await CommitInitialAsync(
                    batch, index, verified, cancellationToken)
                .ConfigureAwait(false);
    }

    public async ValueTask<DeepDirectMessagingInboundCommit?>
        ProcessEstablishedAsync(
            DeepDirectMessagingInboundBatch batch,
            int index,
            CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(batch);
        var current = batch.Current;
        if ((uint)index >= (uint)current.Items.Count)
            throw new ArgumentOutOfRangeException(nameof(index));
        var item = current.Items[index];
        if (item.Kind != MessagingV1DepositKind.EstablishedSession)
            throw new CryptographicException(
                "Only an established DPE2 can use this receive path.");
        var verifiedSession = await owner.TryResolveEstablishedInboundSessionAsync(
                item.ExactInner, cancellationToken)
            .ConfigureAwait(false);
        if (verifiedSession is null)
            return null;
        var receipt = await MessagingV1InboundCommitReceipt
            .CommitAndMaterializeDirectDmc2Async(
                item, owner, verifiedSession, inbox, cancellationToken)
            .ConfigureAwait(false);
        return new DeepDirectMessagingInboundCommit(batch.Token, index, receipt);
    }

    public async ValueTask<VerifiedInboundInitiatorDirectory>
        ResolveInitialSenderAsync(
            DeepDirectMessagingInboundBatch batch,
            int index,
            ProductionContactResolvePathAuthoritySource pathAuthority,
            CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(batch);
        ArgumentNullException.ThrowIfNull(pathAuthority);
        var current = batch.Current;
        if ((uint)index >= (uint)current.Items.Count)
            throw new ArgumentOutOfRangeException(nameof(index));
        var item = current.Items[index];
        if (item.Kind != MessagingV1DepositKind.InitialSession)
            throw new CryptographicException(
                "Only an initial DPH2 can resolve an unsolicited sender directory.");
        var initiation = Dph2Codec.Decode(item.ExactInner.Span);
        return await pathAuthority.ResolveInboundInitiatorDirectoryAsync(
                initiation, cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask<Dph2InitialClaimPreview?> PreviewInitialClaimAsync(
        DeepDirectMessagingInboundBatch batch,
        int index,
        VerifiedInboundInitiatorDirectory senderDirectory,
        int maximumMessagesWithoutPqInjection = 64,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(batch);
        ArgumentNullException.ThrowIfNull(senderDirectory);
        var current = batch.Current;
        if ((uint)index >= (uint)current.Items.Count)
            throw new ArgumentOutOfRangeException(nameof(index));
        var item = current.Items[index];
        if (item.Kind != MessagingV1DepositKind.InitialSession)
            throw new CryptographicException(
                "Only an initial DPH2 can be opened as a pre-claim preview.");
        var initiation = Dph2Codec.Decode(item.ExactInner.Span);
        return await owner.TryPreviewResponderInitialClaimAsync(
                initiation,
                senderDirectory.Closure.Directory,
                maximumMessagesWithoutPqInjection,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask<VerifiedDph2InitialClaim?> VerifyInitialClaimAsync(
        DeepDirectMessagingInboundBatch batch,
        int index,
        VerifiedInboundInitiatorDirectory senderDirectory,
        VerifiedLocalMessagingRecipient localRecipient,
        int maximumMessagesWithoutPqInjection = 64,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(localRecipient);
        var preview = await PreviewInitialClaimAsync(
                batch,
                index,
                senderDirectory,
                maximumMessagesWithoutPqInjection,
                cancellationToken)
            .ConfigureAwait(false);
        if (preview is null)
            return null;
        var placement = localRecipient.RequireClaimPlacement(preview.Request);
        return await preview.VerifyCurrentAsync(
                senderDirectory.Freshness,
                placement,
                localRecipient.Authority,
                localRecipient.Bundle,
                localRecipient.TrustedTimeAuthority,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask AcknowledgeAsync(
        DeepDirectMessagingInboundBatch batch,
        IReadOnlyList<DeepDirectMessagingInboundCommit> committed,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(batch);
        ArgumentNullException.ThrowIfNull(committed);
        var current = batch.Current;
        if (committed.Count != current.Items.Count ||
            committed.Any(item => item is null || !item.BelongsTo(batch)) ||
            committed.Select(item => item.Index).Distinct().Count() != committed.Count)
            throw new CryptographicException(
                "The inbound commit set does not cover the exact retrieved batch.");
        await transport.AcknowledgeAsync(
                access,
                current,
                committed.OrderBy(item => item.Index)
                    .Select(item => item.Receipt).ToArray(),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        sealer.Dispose();
        ingress.Dispose();
        holder.Dispose();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(
        Volatile.Read(ref disposed) != 0, this);

    private static byte[] DomainHash(
        ReadOnlySpan<byte> domain,
        ReadOnlySpan<byte> value)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    private sealed class StorageOwnedDao1OpenAuthority(
        DeepDirectMessagingStorageFacade owner,
        ParsedContactRouteClosure currentLocalRoute) : IMessagingDao1OpenAuthority
    {
        public async ValueTask<MessagingDao1Opened> OpenAsync(
            ReadOnlyMemory<byte> exactDao1,
            CancellationToken cancellationToken = default)
        {
            using var opened = await owner.OpenInboundDepositAsync(
                    currentLocalRoute, exactDao1, cancellationToken)
                .ConfigureAwait(false);
            var kind = opened.Kind switch
            {
                DeepDirectMessagingInboundKind.InitialSession =>
                    MessagingV1DepositKind.InitialSession,
                DeepDirectMessagingInboundKind.EstablishedSession =>
                    MessagingV1DepositKind.EstablishedSession,
                _ => throw new CryptographicException(
                    "The opened DAO1 has an unknown inner kind.")
            };
            return new MessagingDao1Opened(
                ApplicationCoreCodec.DecodeDao1(exactDao1.Span),
                kind,
                opened.ExactInner.Span);
        }
    }
}
#endif
