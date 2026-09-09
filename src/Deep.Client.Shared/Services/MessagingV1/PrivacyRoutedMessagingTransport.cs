using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services.MessagingV1;

internal interface IPrivacyRoutedMessagingMailboxClient
{
    ValueTask<ScopedMailboxResolvedRoute> ReadRouteAsync(
        MailboxCredentialSelector selector,
        CancellationToken cancellationToken);

    ValueTask<ClientMailboxStoreResult> StoreAsync(
        OutboxAccountScope scope,
        IMailboxOperationSigner signer,
        MailboxCredentialSelector selector,
        MailboxEncryptedEnvelope envelope,
        CancellationToken cancellationToken);

    ValueTask<ClientMailboxRetrieveResult> RetrieveAsync(
        OutboxAccountScope scope,
        IMailboxOperationSigner signer,
        MailboxCredentialSelector selector,
        ushort maximumItems,
        CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<MailboxRetrievedEnvelope>> ReadDurableInboxAsync(
        MailboxCredentialSelector selector,
        CancellationToken cancellationToken);

    ValueTask<ClientMailboxAckResult> AcknowledgeAsync(
        OutboxAccountScope scope,
        IMailboxOperationSigner signer,
        MailboxCredentialSelector selector,
        ReadOnlyMemory<byte> operationId,
        bool isFinalPage,
        ReadOnlyMemory<byte> continuationToken,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken);
}

/// <summary>
/// Production proof that the high-level messaging boundary and the durable
/// mailbox adapter share the same PrivacyRoutedMailboxBinaryIngress and request
/// factory. No direct HTTPS mailbox implementation can satisfy this factory.
/// </summary>
internal sealed class PrivacyRoutedMessagingMailboxClient : IPrivacyRoutedMessagingMailboxClient
{
    private readonly ClientMailboxAdapter adapter;
    private readonly MailboxAuthenticatedRequestFactory requests;

    internal PrivacyRoutedMessagingMailboxClient(
        ClientMailboxAdapter adapter,
        MailboxAuthenticatedRequestFactory requests,
        PrivacyRoutedMailboxBinaryIngress privacyIngress)
    {
        this.adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
        this.requests = requests ?? throw new ArgumentNullException(nameof(requests));
        ArgumentNullException.ThrowIfNull(privacyIngress);
        if (!adapter.Uses(privacyIngress, requests))
            throw new InvalidOperationException(
                "MSG-01 requires one adapter/request factory bound to the exact privacy-routed ingress.");
    }

    public async ValueTask<ScopedMailboxResolvedRoute> ReadRouteAsync(
        MailboxCredentialSelector selector,
        CancellationToken cancellationToken) =>
        await requests.ReadRouteAsync(selector, cancellationToken).ConfigureAwait(false);

    public async ValueTask<ClientMailboxStoreResult> StoreAsync(
        OutboxAccountScope scope,
        IMailboxOperationSigner signer,
        MailboxCredentialSelector selector,
        MailboxEncryptedEnvelope envelope,
        CancellationToken cancellationToken) =>
        await adapter.StoreAsync(scope, signer, selector, envelope, cancellationToken)
            .ConfigureAwait(false);

    public async ValueTask<ClientMailboxRetrieveResult> RetrieveAsync(
        OutboxAccountScope scope,
        IMailboxOperationSigner signer,
        MailboxCredentialSelector selector,
        ushort maximumItems,
        CancellationToken cancellationToken) =>
        await adapter.RetrieveAsync(scope, signer, selector, maximumItems, cancellationToken)
            .ConfigureAwait(false);

    public async ValueTask<IReadOnlyList<MailboxRetrievedEnvelope>> ReadDurableInboxAsync(
        MailboxCredentialSelector selector,
        CancellationToken cancellationToken) =>
        await adapter.ReadDurableInboxAsync(selector, cancellationToken).ConfigureAwait(false);

    public async ValueTask<ClientMailboxAckResult> AcknowledgeAsync(
        OutboxAccountScope scope,
        IMailboxOperationSigner signer,
        MailboxCredentialSelector selector,
        ReadOnlyMemory<byte> operationId,
        bool isFinalPage,
        ReadOnlyMemory<byte> continuationToken,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken) =>
        await adapter.AcknowledgeAsync(
            scope, signer, selector, operationId, isFinalPage,
            continuationToken, acknowledgements, cancellationToken).ConfigureAwait(false);
}

/// <summary>
/// Clean-break MSG-01 network boundary. DPH2 and DPE2 are first hidden inside
/// exact DAO1 and then deposited through the already durable MAU2/mailbox stack
/// over a verified three-hop privacy path.
/// </summary>
internal sealed class PrivacyRoutedMessagingTransport : IMessagingV1PrivacyTransport
{
    private static ReadOnlySpan<byte> AckOperationDomain =>
        "Deep/Client/MSG01/mailbox-ack-v1"u8;
    private readonly MessagingV1LocalContext local;
    private readonly IMailboxOperationSigner signer;
    private readonly IPrivacyRoutedMessagingMailboxClient mailbox;
    private readonly MessagingDao1SealingAuthority sealer;
    private readonly IMessagingDao1OpenAuthority opener;
    private readonly TimeProvider timeProvider;

    internal PrivacyRoutedMessagingTransport(
        MessagingV1LocalContext local,
        IMailboxOperationSigner signer,
        PrivacyRoutedMessagingMailboxClient mailbox,
        MessagingDao1SealingAuthority sealer,
        ManagedMessagingDao1OpenAuthority opener,
        TimeProvider? timeProvider = null)
        : this(local, signer, (IPrivacyRoutedMessagingMailboxClient)mailbox,
            sealer, opener, timeProvider)
    {
    }

#if DEEP_TEST_INTERNALS
    internal PrivacyRoutedMessagingTransport(
        MessagingV1LocalContext local,
        IMailboxOperationSigner signer,
        IPrivacyRoutedMessagingMailboxClient mailbox,
        MessagingDao1SealingAuthority sealer,
        IMessagingDao1OpenAuthority opener,
        TimeProvider? timeProvider = null)
#else
    private PrivacyRoutedMessagingTransport(
        MessagingV1LocalContext local,
        IMailboxOperationSigner signer,
        IPrivacyRoutedMessagingMailboxClient mailbox,
        MessagingDao1SealingAuthority sealer,
        IMessagingDao1OpenAuthority opener,
        TimeProvider? timeProvider = null)
#endif
    {
        this.local = local ?? throw new ArgumentNullException(nameof(local));
        this.signer = signer ?? throw new ArgumentNullException(nameof(signer));
        this.mailbox = mailbox ?? throw new ArgumentNullException(nameof(mailbox));
        this.sealer = sealer ?? throw new ArgumentNullException(nameof(sealer));
        this.opener = opener ?? throw new ArgumentNullException(nameof(opener));
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<MessagingV1InitialSessionDeliveryReceipt> SendInitialSessionAsync(
        InitiatorInitialSessionDispatchEnvelope pending,
        VerifiedMessagingRecipientDeposit recipient,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pending);
        var exactDph2 = pending.ExactDph2.ToArray();
        try
        {
            var record = Dph2Codec.Decode(exactDph2);
            var canonical = Dph2Codec.Encode(record);
            try
            {
                var replayHash = MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(record);
                try
                {
                    if (!Fixed(canonical, exactDph2) ||
                        !Fixed(pending.OperationId.Span, record.ClaimOperationId.Span) ||
                        !Fixed(pending.SessionId.Span, record.SessionId.Span) ||
                        !Fixed(pending.ReplayHash.Span, replayHash))
                        throw new CryptographicException(
                            "The durable pending DPH2 metadata does not bind its exact canonical envelope.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(replayHash);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(canonical);
            }
            using var dispatched = await SendCoreAsync(
                exactDph2, MessagingV1DepositKind.InitialSession,
                recipient, expiresAtUnixSeconds, cancellationToken).ConfigureAwait(false);
            return new MessagingV1InitialSessionDeliveryReceipt(
                record.NetworkId.Span,
                record.SessionId.Span,
                record.ClaimOperationId.Span,
                dispatched.Dao1OperationId,
                dispatched.MailboxOperationId,
                dispatched.ExactDao1Hash,
                recipient.AccountId,
                recipient.DeviceId,
                recipient.AccountGeneration,
                recipient.DeviceGeneration,
                dispatched.Cursor,
                dispatched.ExactReplay,
                dispatched.CoordinatorId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactDph2);
        }
    }

    public async ValueTask<MessagingV1EstablishedDeliveryReceipt> SendEstablishedAsync(
        ExactDpe2SendSuccessCapability committed,
        VerifiedMessagingEstablishedRoute route,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(committed);
        ArgumentNullException.ThrowIfNull(route);
        var recipient = route.Recipient;
        var expectedOperationId = committed.OperationId.ToArray();
        var expectedEnvelopeHash = committed.ExactEnvelopeHash.ToArray();
        var exactDpe2 = committed.TakeExactEnvelope();
        try
        {
            var record = Dpe2Codec.Decode(exactDpe2);
            var canonical = Dpe2Codec.Encode(record);
            var replayHash = MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(record);
            try
            {
                if (!Fixed(canonical, exactDpe2) ||
                    !Fixed(expectedOperationId, record.OperationId.Span) ||
                    !Fixed(expectedEnvelopeHash, replayHash) ||
                    !Fixed(record.SessionId.Span, route.SessionId))
                    throw new CryptographicException(
                        "The committed DPE2 capability does not bind the exact activated session envelope.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(canonical);
                CryptographicOperations.ZeroMemory(replayHash);
            }
            using var dispatched = await SendCoreAsync(
                exactDpe2, MessagingV1DepositKind.EstablishedSession,
                recipient, expiresAtUnixSeconds, cancellationToken).ConfigureAwait(false);
            return new MessagingV1EstablishedDeliveryReceipt(
                record.OperationId.Span,
                dispatched.Dao1OperationId,
                dispatched.MailboxOperationId,
                dispatched.ExactDao1Hash,
                recipient.AccountId,
                recipient.DeviceId,
                recipient.AccountGeneration,
                recipient.DeviceGeneration,
                dispatched.Cursor,
                dispatched.ExactReplay,
                dispatched.CoordinatorId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedOperationId);
            CryptographicOperations.ZeroMemory(expectedEnvelopeHash);
            CryptographicOperations.ZeroMemory(exactDpe2);
        }
    }

    public async ValueTask<MessagingV1ReceiveBatch> RetrieveAsync(
        MailboxCredentialSelector selfRetrieveSelector,
        ushort maximumItems,
        CancellationToken cancellationToken = default)
    {
        ValidateSelfSelector(selfRetrieveSelector);
        if (maximumItems == 0)
            throw new ArgumentOutOfRangeException(nameof(maximumItems));
        ClientMailboxRetrieveResult retrieved;
        try
        {
            retrieved = await mailbox.RetrieveAsync(
                local.OutboxScope, signer, selfRetrieveSelector,
                maximumItems, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (TryMapDispatch(exception, out var mapped))
        {
            throw mapped;
        }

        var durable = await mailbox.ReadDurableInboxAsync(
            selfRetrieveSelector, cancellationToken).ConfigureAwait(false);
        var route = await mailbox.ReadRouteAsync(
            selfRetrieveSelector, cancellationToken).ConfigureAwait(false);
        var opened = new List<MessagingV1ReceivedDeposit>(durable.Count);
        try
        {
            foreach (var item in durable.OrderBy(static value => value.Cursor))
            {
                ValidateRetrievedEnvelope(item, route);
                using var dao = await opener.OpenAsync(
                    item.Envelope.Ciphertext, cancellationToken).ConfigureAwait(false);
                ValidateInboundInner(dao.Kind, dao.ExactInner.Span);
                opened.Add(new MessagingV1ReceivedDeposit(
                    dao.Kind, dao.Parsed, dao.ExactInner.Span, item));
            }
            return new MessagingV1ReceiveBatch(
                opened, retrieved.HasMore, retrieved.ContinuationToken.Span);
        }
        catch
        {
            foreach (var item in opened) item.Dispose();
            throw;
        }
    }

    public async ValueTask AcknowledgeAsync(
        MailboxCredentialSelector selfRetrieveSelector,
        MessagingV1ReceiveBatch batch,
        IReadOnlyList<MessagingV1InboundCommitReceipt> committed,
        CancellationToken cancellationToken = default)
    {
        ValidateSelfSelector(selfRetrieveSelector);
        ArgumentNullException.ThrowIfNull(batch);
        ArgumentNullException.ThrowIfNull(committed);
        if (batch.Items.Count == 0 || committed.Count != batch.Items.Count)
            throw new InvalidOperationException(
                "Mailbox acknowledgement requires one durable inner commit receipt per retrieved DAO1.");

        var remaining = committed.ToList();
        foreach (var item in batch.Items)
        {
            var index = remaining.FindIndex(receipt => receipt is not null && receipt.Matches(item));
            if (index < 0)
                throw new CryptographicException(
                    "A mailbox item lacks its exact durable inner commit receipt.");
            remaining.RemoveAt(index);
        }

        var acknowledgements = batch.Items
            .Select(static item => item.Acknowledgement)
            .OrderBy(static acknowledgement => acknowledgement.Cursor)
            .ToArray();
        var operationId = AckOperationId(
            acknowledgements, batch.HasMore, batch.ContinuationToken.Span);
        try
        {
            ClientMailboxAckResult result;
            try
            {
                result = await mailbox.AcknowledgeAsync(
                    local.OutboxScope, signer, selfRetrieveSelector,
                    operationId, !batch.HasMore, batch.ContinuationToken,
                    acknowledgements, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (TryMapDispatch(exception, out var mapped))
            {
                throw mapped;
            }
            if (result.DurableTombstones != acknowledgements.Length)
                throw new CryptographicException(
                    "The typed mailbox acknowledgement receipt changed item cardinality.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(operationId);
        }
    }

    private async ValueTask<MessagingV1DispatchCoreReceipt> SendCoreAsync(
        ReadOnlyMemory<byte> exactInner,
        MessagingV1DepositKind expectedKind,
        VerifiedMessagingRecipientDeposit recipient,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        if (!recipient.LocalOutboxScope.Equals(local.OutboxScope))
            throw new CryptographicException("The recipient capability belongs to another local account scope.");
        var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
        if (expiresAtUnixSeconds <= now ||
            expiresAtUnixSeconds > recipient.ExpiresAtUnixSeconds ||
            expiresAtUnixSeconds - now is
                < MailboxClientLimits.MinimumTtlSeconds or
                > MailboxClientLimits.MaximumTtlSeconds)
            throw new CryptographicException(
                "The mailbox ciphertext expiry is outside the verified route or canonical TTL window.");

        using var dao = sealer.Seal(local, recipient, exactInner.Span);
        if (dao.Kind != expectedKind)
            throw new CryptographicException("The DAO1 inner kind changed during sealing.");
        var canonicalDao1 = dao.Canonical.ToArray();
        var dao1Hash = SHA256.HashData(canonicalDao1);
        var mailboxOperationId = MessagingDao1Crypto.DeriveMailboxOperationId(
            dao.Parsed.DepositOperationId.Span);
        try
        {
            var route = await mailbox.ReadRouteAsync(
                recipient.Selector, cancellationToken).ConfigureAwait(false);
            if (expiresAtUnixSeconds > route.ExpiresAtUnixSeconds)
                throw new CryptographicException(
                    "The mailbox ciphertext expiry exceeds the current verified mailbox route.");
            var envelope = new MailboxEncryptedEnvelope
            {
                Epoch = route.Epoch,
                MailboxId = route.MailboxId,
                PlacementId = route.PlacementId,
                OperationId = mailboxOperationId.ToArray(),
                DeduplicationDigest = dao1Hash.ToArray(),
                CreatedAtUnixSeconds = now,
                ExpiresAtUnixSeconds = expiresAtUnixSeconds,
                Ciphertext = canonicalDao1.ToArray(),
            };
            ClientMailboxStoreResult stored;
            try
            {
                stored = await mailbox.StoreAsync(
                    local.OutboxScope, signer, recipient.Selector,
                    envelope, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (TryMapDispatch(exception, out var mapped))
            {
                throw mapped;
            }

            if (stored.Cursor is null or 0 ||
                stored.Disposition is not (
                    MailboxReplicaDisposition.Stored or MailboxReplicaDisposition.Duplicate))
                throw new CryptographicException(
                    "The verified mailbox receipt is not a durable Stored/Duplicate result.");
            return new MessagingV1DispatchCoreReceipt(
                dao.Parsed.DepositOperationId.Span,
                mailboxOperationId,
                dao1Hash,
                stored.Cursor.Value,
                stored.Disposition == MailboxReplicaDisposition.Duplicate || !stored.IngressDispatched,
                stored.EntryRouterId.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonicalDao1);
            CryptographicOperations.ZeroMemory(dao1Hash);
            CryptographicOperations.ZeroMemory(mailboxOperationId);
        }
    }

    private void ValidateRetrievedEnvelope(
        MailboxRetrievedEnvelope item,
        ScopedMailboxResolvedRoute route)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentNullException.ThrowIfNull(item.Envelope);
        ArgumentNullException.ThrowIfNull(route);
        var envelope = item.Envelope;
        _ = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        var dao1 = ApplicationCoreCodec.DecodeDao1(envelope.Ciphertext.Span);
        var digest = SHA256.HashData(envelope.Ciphertext.Span);
        var operationId = MessagingDao1Crypto.DeriveMailboxOperationId(
            dao1.DepositOperationId.Span);
        try
        {
            if (item.Cursor == 0 ||
                envelope.Epoch != route.Epoch ||
                !Fixed(envelope.MailboxId.Bytes.Span, route.MailboxId.Bytes.Span) ||
                !Fixed(envelope.PlacementId.Bytes.Span, route.PlacementId.Bytes.Span) ||
                !Fixed(dao1.CanonicalBytes.Span, envelope.Ciphertext.Span) ||
                !Fixed(dao1.NetworkId.Span, local.NetworkId) ||
                !Fixed(operationId, envelope.OperationId.Span) ||
                !Fixed(digest, envelope.DeduplicationDigest.Span))
                throw new CryptographicException(
                    "The durable mailbox envelope does not bind its exact canonical DAO1.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
            CryptographicOperations.ZeroMemory(operationId);
        }
    }

    private void ValidateInboundInner(
        MessagingV1DepositKind kind,
        ReadOnlySpan<byte> exactInner)
    {
        if (kind == MessagingV1DepositKind.InitialSession)
        {
            var record = Dph2Codec.Decode(exactInner);
            if (!Fixed(record.NetworkId.Span, local.NetworkId) ||
                !Fixed(record.ResponderAccountId.Span, local.AccountId) ||
                !Fixed(record.ResponderDeviceId.Span, local.DeviceId) ||
                record.ResponderDeviceGeneration != local.DeviceGeneration)
                throw new CryptographicException("Retrieved DPH2 is for another local account/device generation.");
            return;
        }

        var dpe2 = Dpe2Codec.Decode(exactInner);
        if (!Fixed(dpe2.NetworkId.Span, local.NetworkId) ||
            !Fixed(dpe2.RecipientDeviceId.Span, local.DeviceId))
            throw new CryptographicException("Retrieved DPE2 is for another local device.");
    }

    private void ValidateSelfSelector(MailboxCredentialSelector selector)
    {
        ArgumentNullException.ThrowIfNull(selector);
        var holder = signer.GetEd25519PublicKey();
        try
        {
            if (!selector.AccountScope.Equals(local.OutboxScope) ||
                selector.Kind != MailboxCredentialScopeKind.Self ||
                !Fixed(selector.SubjectId.Span, holder))
                throw new CryptographicException(
                    "MSG-01 retrieve requires this device holder's verified self-retrieve capability.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(holder);
        }
    }

    private static byte[] AckOperationId(
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        bool hasMore,
        ReadOnlySpan<byte> continuationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(AckOperationDomain);
        hash.AppendData([hasMore ? (byte)1 : (byte)0]);
        Span<byte> scalar = stackalloc byte[8];
        foreach (var acknowledgement in acknowledgements)
        {
            BinaryPrimitives.WriteUInt64BigEndian(scalar, acknowledgement.Cursor);
            hash.AppendData(scalar);
            hash.AppendData(acknowledgement.EnvelopeDigest.Span);
        }
        hash.AppendData(continuationToken);
        var full = hash.GetHashAndReset();
        try
        {
            return full[..MailboxClientLimits.OperationIdLength];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(full);
        }
    }

    private static bool TryMapDispatch(
        Exception exception,
        out MessagingV1DispatchException mapped)
    {
        if (exception is ClientMailboxDispatchOutcomeUnknownException unknown)
        {
            mapped = new MessagingV1DispatchException(
                MessagingV1DispatchFailureClass.OutcomeUnknown,
                retryable: true,
                "Privacy-routed mailbox outcome is unknown; retry the same durable logical operation.",
                unknown);
            return true;
        }
        if (exception is ClientMailboxTransportException transport)
        {
            var beforeForward = transport.InnerException is PrivacyIngressRejectedBeforeForwardException;
            mapped = new MessagingV1DispatchException(
                beforeForward
                    ? MessagingV1DispatchFailureClass.RejectedBeforeForward
                    : MessagingV1DispatchFailureClass.TerminalRejected,
                transport.Retryable,
                beforeForward
                    ? "Privacy ingress rejected the operation before forwarding."
                    : "The authenticated mailbox operation was terminally rejected.",
                transport);
            return true;
        }
        mapped = null!;
        return false;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed class MessagingV1DispatchCoreReceipt : IDisposable
    {
        private readonly byte[] dao1OperationId;
        private readonly byte[] mailboxOperationId;
        private readonly byte[] exactDao1Hash;
        private readonly byte[] coordinatorId;

        internal MessagingV1DispatchCoreReceipt(
            ReadOnlySpan<byte> dao1OperationId,
            ReadOnlySpan<byte> mailboxOperationId,
            ReadOnlySpan<byte> exactDao1Hash,
            ulong cursor,
            bool exactReplay,
            ReadOnlySpan<byte> coordinatorId)
        {
            this.dao1OperationId = dao1OperationId.ToArray();
            this.mailboxOperationId = mailboxOperationId.ToArray();
            this.exactDao1Hash = exactDao1Hash.ToArray();
            this.coordinatorId = coordinatorId.ToArray();
            Cursor = cursor;
            ExactReplay = exactReplay;
        }

        internal ReadOnlySpan<byte> Dao1OperationId => dao1OperationId;
        internal ReadOnlySpan<byte> MailboxOperationId => mailboxOperationId;
        internal ReadOnlySpan<byte> ExactDao1Hash => exactDao1Hash;
        internal ReadOnlySpan<byte> CoordinatorId => coordinatorId;
        internal ulong Cursor { get; }
        internal bool ExactReplay { get; }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(dao1OperationId);
            CryptographicOperations.ZeroMemory(mailboxOperationId);
            CryptographicOperations.ZeroMemory(exactDao1Hash);
            CryptographicOperations.ZeroMemory(coordinatorId);
        }
    }
}
