using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Production native-MAU2 transport facade. All official-cloud fan-out frames are prepared in
/// one scoped SQLite transaction before any HTTP dispatch. The facade never implements a free
/// transport marker and therefore cannot be selected by a free delivery policy.
/// </summary>
public sealed class NativeMau2MailboxTransport :
    IAuthenticatedOpaqueMailboxTransport,
    IResumableMailboxIdentityAuthenticatedRawTransport,
    IAuthenticatedInboxTransport,
    IMailboxAckCorrelationProjectionSource,
    IMetadataPrivateSessionMessageTransport,
    IDisposable
{
    private const string ItemHandlePrefix = "mau2-item-v1:";
    private const int RetrievalLimit = 1;
    private static ReadOnlySpan<byte> StoreOperationDomain =>
        "deep.mau2.store-operation.v1"u8;
    private static ReadOnlySpan<byte> AckOperationDomain =>
        "deep.mau2.ack-operation.v1"u8;

    private readonly ClientMailboxAdapter adapter;
    private readonly IScopedMailboxCredentialRepository credentials;
    private readonly ITransportOutboxRepository outbox;
    private readonly VerifiedOfficialMailboxAuthority authority;
    private readonly IMailboxClientDecodePolicyProvider decodePolicies;
    private readonly Func<SessionId, MailboxCredentialSelector> selfSelector;
    private readonly IMailboxDispatchRouteUsageObserver? routeUsageObserver;
    private readonly IDisposable? ownedIngress;
    private int disposed;

    public NativeMau2MailboxTransport(
        ClientFeatureFlags flags,
        ClientMailboxActivation activation,
        IClientMailboxBinaryIngress ingress,
        SqliteSessionStore localStore,
        IClientMailboxReceiptVerifier receipts,
        IMailboxClientDecodePolicyProvider decodePolicies,
        VerifiedOfficialMailboxAuthority authority,
        Func<SessionId, MailboxCredentialSelector> selfSelector,
        bool ownsIngress = false,
        TimeProvider? timeProvider = null,
        IMailboxDispatchRouteUsageObserver? routeUsageObserver = null)
    {
        ArgumentNullException.ThrowIfNull(ingress);
        credentials = localStore ?? throw new ArgumentNullException(nameof(localStore));
        outbox = localStore;
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        this.decodePolicies = decodePolicies ?? throw new ArgumentNullException(nameof(decodePolicies));
        this.selfSelector = selfSelector ?? throw new ArgumentNullException(nameof(selfSelector));
        this.routeUsageObserver = routeUsageObserver;
        if (!authority.UsesSharedPolicyCoordinator(
                localStore.CanonicalStateIdentity,
                activation.IssuerContext.Span))
            throw new InvalidOperationException(
                "Native MAU2 requires the exact store-bound shared policy authority.");
        authority.Validate();
        var requests = new MailboxAuthenticatedRequestFactory(credentials, authority);
        adapter = new ClientMailboxAdapter(
            flags, activation, ingress, localStore, receipts, requests,
            decodePolicies, timeProvider);
        ownedIngress = ownsIngress ? ingress as IDisposable ?? throw new ArgumentException(
            "An owned mailbox ingress must be disposable.", nameof(ingress)) : null;
    }

    public int InboxNamespace => unchecked((int)0x4d415532); // "MAU2"
    public bool UsesMetadataPrivateTransport => true;

    public async Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>
        PrepareScopedMailboxLogicalBatchAsync(
        IMailboxOperationSigner signer,
        MailboxLogicalSendBatch logicalBatch,
        IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(logicalBatch);
        ArgumentNullException.ThrowIfNull(targets);
        if (targets.Count is 0 or > SqliteSessionStore.MaximumScopedMailboxBatchTargets ||
            targets.Any(static target => target is null))
        {
            throw new ArgumentException("Mailbox send batch is empty or outside its bound.", nameof(targets));
        }
        ValidateLogicalTargets(logicalBatch, targets);

        authority.Validate();
        var bindings = new List<ScopedMailboxBatchTarget>(targets.Count);
        var preparedMetadata = new List<PreparedMetadata>(targets.Count);
        foreach (var target in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureAuthority(target.Authority);
            if (target.Envelope.Sender != signer.SessionId)
                throw new InvalidOperationException("Mailbox target sender does not match the operation signer.");
            var route = await credentials.ReadScopedMailboxRouteAsync(
                target.Selector, authority, cancellationToken).ConfigureAwait(false);
            var ciphertext = DecodeDpe1(target.Envelope.Body);
            try
            {
                var createdAtUnixSeconds = ToUnixSeconds(
                    target.Envelope.CreatedAt,
                    nameof(targets));
                var requestedExpiresAtUnixSeconds = ToUnixSeconds(
                    target.Envelope.ExpiresAt ?? throw new InvalidOperationException(
                        "Mailbox DPE1 target requires its protocol expiry."),
                    nameof(targets));
                var expiresAtUnixSeconds = Math.Min(
                    requestedExpiresAtUnixSeconds,
                    route.ExpiresAtUnixSeconds);
                if (expiresAtUnixSeconds <= createdAtUnixSeconds ||
                    expiresAtUnixSeconds - createdAtUnixSeconds <
                        MailboxClientLimits.MinimumTtlSeconds)
                {
                    throw new InvalidOperationException(
                        "The active mailbox epoch cannot retain this message for the minimum protocol lifetime.");
                }
                var operationId = OperationId(StoreOperationDomain, ciphertext);
                var envelope = new MailboxEncryptedEnvelope
                {
                    Epoch = route.Epoch,
                    MailboxId = route.MailboxId,
                    PlacementId = route.PlacementId,
                    OperationId = operationId,
                    DeduplicationDigest = SHA256.HashData(ciphertext),
                    CreatedAtUnixSeconds = createdAtUnixSeconds,
                    ExpiresAtUnixSeconds = expiresAtUnixSeconds,
                    Ciphertext = ciphertext.ToArray()
                };
                var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
                bindings.Add(new ScopedMailboxBatchTarget(target.Selector, binding));
                preparedMetadata.Add(new PreparedMetadata(
                    target.Selector.AccountScope,
                    target.Selector,
                    DirectUsage(logicalBatch.Kind, target.Envelope)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertext);
            }
        }

        var account = preparedMetadata[0].Account;
        if (preparedMetadata.Any(item => !item.Account.Equals(account)))
            throw new InvalidOperationException("A mailbox batch cannot cross account scopes.");
        var batch = await credentials.PrepareScopedMailboxBatchAsync(
            new ScopedMailboxPrepareBatchRequest(
                account,
                logicalBatch.Id,
                logicalBatch.SemanticId,
                LogicalSelectors(logicalBatch),
                bindings,
                TransportOutboxTime.Canonical(authority.TimeProvider.GetUtcNow())),
            signer, authority, cancellationToken).ConfigureAwait(false);
        if (batch.Frames.Count != preparedMetadata.Count)
            throw new InvalidOperationException("Scoped mailbox batch returned an invalid frame count.");
        return batch.Frames.Select((frame, index) =>
            (IPreparedMailboxAuthenticatedSend)new PreparedSend(
                this, preparedMetadata[index], frame)).ToArray();
    }

    public Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>
        PrepareScopedMailboxBatchAsync(
        IMailboxOperationSigner signer,
        IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targets);
        if (targets.Count == 0 || targets[0].Envelope.Id is not { } semanticId)
            throw new ArgumentException(
                "Mailbox send targets require stable wire IDs.", nameof(targets));
        var logical = new MailboxLogicalSendBatch(
            semanticId,
            MailboxDeliveryKind.Direct,
            targets.Select(target => new MailboxLogicalSendTarget(
                target.Envelope.Id ?? throw new ArgumentException(
                    "Mailbox send targets require stable wire IDs.", nameof(targets)),
                target.Selector,
                target.Authority,
                target.Envelope.Sender,
                target.Envelope.Recipient)).ToArray());
        return PrepareScopedMailboxLogicalBatchAsync(
            signer, logical, targets, cancellationToken);
    }

    public async Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>?>
        TryResumeScopedMailboxBatchAsync(
        IMailboxOperationSigner signer,
        MailboxLogicalSendBatch batch,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(batch);
        authority.Validate();
        var logicalTargets = batch.Targets;
        foreach (var target in logicalTargets)
        {
            EnsureAuthority(target.Authority);
            if (target.Selector.AccountScope is null)
                throw new InvalidOperationException("Mailbox logical target has no account scope.");
        }
        var account = logicalTargets[0].Selector.AccountScope;
        if (logicalTargets.Any(target => !target.Selector.AccountScope.Equals(account)))
            throw new InvalidOperationException("A mailbox batch cannot cross account scopes.");
        var resumed = await credentials.TryResumeScopedMailboxBatchAsync(
            new ScopedMailboxResumeBatchRequest(
                account, batch.Id, batch.SemanticId, LogicalSelectors(batch)),
            signer, authority, cancellationToken).ConfigureAwait(false);
        if (resumed is null)
            return null;
        if (resumed.Frames.Count != logicalTargets.Count)
            throw new InvalidDataException("Scoped mailbox resume returned an invalid frame count.");
        return resumed.Frames.Select((frame, index) =>
            (IPreparedMailboxAuthenticatedSend)new PreparedSend(
                this,
                new PreparedMetadata(
                    account,
                    logicalTargets[index].Selector,
                    DirectUsage(batch.Kind, logicalTargets[index])),
                frame)).ToArray();
    }

    public async Task SendPreparedMailboxAuthenticatedAsync(
        IPreparedMailboxAuthenticatedSend preparedSend,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (preparedSend is not PreparedSend prepared || !ReferenceEquals(prepared.Owner, this))
            throw new ArgumentException("Prepared mailbox handle belongs to another transport.", nameof(preparedSend));
        if (Interlocked.Exchange(ref prepared.Dispatched, 1) != 0)
            throw new InvalidOperationException("Prepared mailbox handle was already dispatched.");
        var usage = prepared.Metadata.DirectUsage;
        var attemptId = Guid.NewGuid();
        PublishTerminalRouteUsage(
            usage,
            attemptId,
            MailboxDispatchRouteOutcome.Started);
        try
        {
            var result = await adapter.DispatchPreparedStoreAsync(
                prepared.Metadata.Account, prepared.Metadata.Selector,
                prepared.Frame, cancellationToken).ConfigureAwait(false);
            if (usage is not null)
            {
                PublishRouteUsage(new MailboxDispatchRouteUsage(
                    usage.MessageId,
                    usage.ConversationId,
                    usage.Recipient,
                    attemptId,
                    result.IngressDispatched
                        ? MailboxDispatchRouteOutcome.Durable
                        : MailboxDispatchRouteOutcome.NoDispatch,
                    result.IngressDispatched
                        ? result.EntryRouterId.Span
                        : ReadOnlySpan<byte>.Empty));
            }
        }
        catch (OperationCanceledException)
        {
            PublishTerminalRouteUsage(usage, attemptId, MailboxDispatchRouteOutcome.Canceled);
            throw;
        }
        catch
        {
            PublishTerminalRouteUsage(usage, attemptId, MailboxDispatchRouteOutcome.Failed);
            throw;
        }
    }

    public Task SendAsync(
        OutboundMessageEnvelope envelope,
        CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException(
            "Official cloud accepts only an atomically prepared authenticated MAU2 send.");

    public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
        SessionId recipient,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return Task.FromException<IReadOnlyList<InboundMessageEnvelope>>(
            new InvalidOperationException(
                "Official mailbox retrieval requires the authenticated local identity."));
    }

    public async Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
        SessionIdentityProvider identity,
        CancellationToken cancellationToken = default)
    {
        var batch = await RetrieveAuthenticatedAsync(
            identity, cursor: null, DurableInboxLimits.MaxBatchCount,
            cancellationToken).ConfigureAwait(false);
        var result = new List<InboundMessageEnvelope>(batch.Entries.Count);
        foreach (var entry in batch.Entries)
        {
            if (!TryDecodeInboxEntry(entry, identity.SessionId, out var envelope))
                throw new InvalidDataException("Native mailbox returned a noncanonical MEO1 entry.");
            result.Add(envelope);
        }
        return result;
    }

    public async Task<AuthenticatedInboxBatch> RetrieveAuthenticatedAsync(
        SessionIdentityProvider identity,
        string? cursor,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(identity);
        if (limit is <= 0 or > DurableInboxLimits.MaxBatchCount)
            throw new ArgumentOutOfRangeException(nameof(limit));
        using var signer = new IdentitySigner(identity);
        var selector = RequireSelfSelector(identity.SessionId);
        var current = await adapter.ReadTraversalAsync(selector, cancellationToken)
            .ConfigureAwait(false);
        if (cursor is not null)
        {
            // The generic durable-inbox repository owns cursor continuity.  Native only
            // requires the exact canonical item-handle shape; the item may already have been
            // acknowledged and removed from the MAU2 durable inbox before the next poll.
            _ = DecodeItemHandle(cursor);
        }
        var page = await RetrieveOpaqueMailboxInboxAsync(
            signer,
            new OpaqueMailboxContinuation(
                current.AfterCursor, current.ContinuationToken),
            cancellationToken).ConfigureAwait(false);
        var entries = page.Entries.Select(entry =>
            DurableInboxWireEntry.CreateBounded(
                EncodeItemHandle(entry.Cursor, entry.GetEnvelopeDigestCopy()),
                authority.TimeProvider.GetUtcNow().ToUnixTimeMilliseconds(),
                Convert.ToBase64String(entry.GetCanonicalMeo1Copy()))).ToArray();
        // The external durable-inbox cursor is its final staged ServerHash.  The MAU2
        // continuation remains private in ClientMailboxTraversal and is never exposed as
        // the repository cursor: these are distinct monotonic namespaces.
        var nextCursor = entries.Length == 0 ? cursor : entries[^1].ServerHash;
        return new AuthenticatedInboxBatch(entries, nextCursor);
    }

    public bool TryDecodeInboxEntry(
        DurableInboxWireEntry entry,
        SessionId recipient,
        out InboundMessageEnvelope envelope)
    {
        envelope = default!;
        try
        {
            var (cursor, digest) = DecodeItemHandle(entry.ServerHash);
            var encoded = Convert.FromBase64String(entry.WirePayload);
            var decodePolicy = decodePolicies.GetCurrent();
            var opaque = OpaqueMailboxWireEntry.DecodeAndVerify(
                cursor, encoded, digest, decodePolicy);
            var decoded = MailboxClientCodec.DecodeEncryptedEnvelope(
                opaque.GetCanonicalMeo1Copy(), decodePolicy);
            var body = EncodeDpe1(decoded.Ciphertext.Span);
            var messageId = new MessageId(Convert.ToHexStringLower(
                SHA256.HashData(decoded.OperationId.Span)));
            envelope = new InboundMessageEnvelope(
                messageId, recipient, recipient, body, [],
                DateTimeOffset.FromUnixTimeSeconds(checked((long)decoded.CreatedAtUnixSeconds)),
                DateTimeOffset.FromUnixTimeSeconds(checked((long)decoded.ExpiresAtUnixSeconds)),
                entry.ServerHash);
            return true;
        }
        catch (Exception exception) when (exception is
            MailboxClientException or ArgumentException or FormatException or
            OverflowException or CryptographicException)
        {
            return false;
        }
    }

    public async Task<OpaqueMailboxInboxPage> RetrieveOpaqueMailboxInboxAsync(
        IMailboxOperationSigner signer,
        OpaqueMailboxContinuation continuation,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(continuation);
        var selector = RequireSelfSelector(signer.SessionId);
        var result = await adapter.RetrieveAsync(
            selector.AccountScope, signer, selector,
            RetrievalLimit, cancellationToken).ConfigureAwait(false);
        var durable = result.NewItems.Count > 0
            ? result.NewItems
            : await adapter.ReadDurableInboxAsync(selector, cancellationToken).ConfigureAwait(false);
        var item = durable
            .Where(candidate => candidate.Cursor > continuation.AfterCursor || continuation.AfterCursor == 0)
            .OrderBy(static candidate => candidate.Cursor)
            .Take(1)
            .Select(candidate => OpaqueMailboxWireEntry.DecodeAndVerify(
                candidate.Cursor,
                MailboxClientCodec.EncodeEncryptedEnvelope(candidate.Envelope),
                candidate.Envelope.DeduplicationDigest.Span,
                decodePolicies.GetCurrent()))
            .ToArray();
        var next = result.HasMore
            ? new OpaqueMailboxContinuation(result.AfterCursor, result.ContinuationToken.Span)
            : new OpaqueMailboxContinuation(0, []);
        return new OpaqueMailboxInboxPage(continuation, next, item);
    }

    /// <summary>
    /// Retires only the exact current RETRIEVE after a canonical, non-retryable privacy-terminal
    /// credential rejection. The attempted outbox row is retained; only its traversal poll
    /// generation is atomically rolled forward. Outcome-unknown and retryable failures are
    /// rejected by contract.
    /// </summary>
    public async Task RetireTerminallyRejectedRetrieveAsync(
        SessionId account,
        ClientMailboxTransportException terminalFailure,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(terminalFailure);
        if (terminalFailure.Retryable ||
            terminalFailure.Failure is not (
                ClientMailboxTransportFailure.AuthorizationRejected or
                ClientMailboxTransportFailure.ConflictOrExpired))
        {
            throw new ArgumentException(
                "Retrieve retirement requires a non-retryable credential terminal rejection.",
                nameof(terminalFailure));
        }

        var selector = RequireSelfSelector(account);
        await adapter.RetireTerminallyRejectedRetrieveAsync(
                selector.AccountScope,
                selector,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task AcknowledgeOpaqueMailboxInboxAsync(
        IMailboxOperationSigner signer,
        string opaqueItemHandle,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(signer);
        var (cursor, digest) = DecodeItemHandle(opaqueItemHandle);
        var selector = RequireSelfSelector(signer.SessionId);
        var traversal = await adapter.ReadTraversalAsync(selector, cancellationToken)
            .ConfigureAwait(false);
        var operationId = OperationId(AckOperationDomain, CursorMaterial(cursor, digest));
        await adapter.AcknowledgeAsync(
            selector.AccountScope, signer, selector, operationId,
            traversal.AfterCursor == 0,
            traversal.ContinuationToken.ToArray(),
            [new MailboxAcknowledgement { Cursor = cursor, EnvelopeDigest = digest }],
            cancellationToken).ConfigureAwait(false);
    }

    async Task<MailboxAckCorrelationProjection?>
        IMailboxAckCorrelationProjectionSource.ProjectMailboxAckCorrelationAsync(
        SessionId account,
        string serverHash,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var selector = RequireSelfSelector(account);
        var (cursor, digest) = DecodeItemHandle(serverHash);
        byte[]? material = null;
        byte[]? operationId = null;
        byte[]? canonical = null;
        byte[]? canonicalHash = null;
        try
        {
            material = CursorMaterial(cursor, digest);
            operationId = OperationId(AckOperationDomain, material);
            var logicalId = OutboxLogicalId.FromBytes(operationId);
            var read = await outbox.ReadTransportOutboxAsync(
                selector.AccountScope, logicalId, cancellationToken).ConfigureAwait(false);
            if (read.Result == TransportOutboxReadResult.Missing) return null;
            var item = read.Result == TransportOutboxReadResult.Found
                ? read.Item ?? throw new InvalidDataException(
                    "ACK outbox projection returned no item.")
                : throw new InvalidDataException("ACK outbox projection returned an invalid result.");
            canonical = item.GetCiphertextBundleCopy();
            var authenticated = MailboxAuthenticatedClientRequestCodec.Decode(canonical);
            if (authenticated.Binding.Operation != MailboxAuthenticatedOperation.Ack
                || authenticated.Presentation.Operation != MailboxAuthenticatedOperation.Ack
                || !CryptographicOperations.FixedTimeEquals(
                    authenticated.Binding.OperationId.Span, operationId)
                || !CryptographicOperations.FixedTimeEquals(
                    item.LogicalId.Value, operationId)
                || !CryptographicOperations.FixedTimeEquals(
                    item.DedupMaterial.Value, authenticated.Binding.RequestDigest.Span))
                throw new InvalidDataException(
                    "Persisted ACK outbox binding is not canonical.");
            var request = MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                authenticated.Binding.CanonicalRequest.Span);
            if (!CryptographicOperations.FixedTimeEquals(request.OperationId.Span, operationId)
                || request.Acknowledgements.Count != 1
                || request.Acknowledgements[0].Cursor != cursor
                || !CryptographicOperations.FixedTimeEquals(
                    request.Acknowledgements[0].EnvelopeDigest.Span, digest))
                throw new InvalidDataException(
                    "Persisted ACK outbox does not match the exact inbox row.");
            if ((item.State == TransportOutboxState.Prepared && item.Attempts.Count == 0)
                || (item.State == TransportOutboxState.Durable && item.Attempts.Count == 1
                    && item.Attempts[0].State == TransportOutboxAttemptState.Durable))
                return null;
            var state = item.State switch
            {
                TransportOutboxState.Attempted when item.Attempts.Count == 1
                    && item.Attempts[0].State == TransportOutboxAttemptState.Attempted =>
                    MailboxAckCorrelationState.AmbiguousAttempted,
                TransportOutboxState.Durable when item.Attempts.Count == 2
                    && item.Attempts.Count(static attempt =>
                        attempt.State == TransportOutboxAttemptState.Attempted) == 1
                    && item.Attempts.Count(static attempt =>
                        attempt.State == TransportOutboxAttemptState.Durable) == 1 =>
                    MailboxAckCorrelationState.RecoveredDurable,
                _ => throw new InvalidDataException(
                    "Persisted ACK outbox is not an exact crash-recovery lifecycle.")
            };
            canonicalHash = SHA256.HashData(canonical);
            using var correlation = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            correlation.AppendData("deep.physical-e2e.ack-correlation.v1\0"u8);
            correlation.AppendData(operationId);
            correlation.AppendData(canonicalHash);
            return new MailboxAckCorrelationProjection(
                Convert.ToHexStringLower(correlation.GetHashAndReset()),
                state,
                item.Attempts.Count);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
            if (material is not null) CryptographicOperations.ZeroMemory(material);
            if (operationId is not null) CryptographicOperations.ZeroMemory(operationId);
            if (canonical is not null) CryptographicOperations.ZeroMemory(canonical);
            if (canonicalHash is not null) CryptographicOperations.ZeroMemory(canonicalHash);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            ownedIngress?.Dispose();
    }

    private MailboxCredentialSelector RequireSelfSelector(SessionId sessionId)
    {
        var selector = selfSelector(sessionId) ?? throw new InvalidOperationException(
            "Official cloud has no self-mailbox credential selector.");
        if (selector.Kind != MailboxCredentialScopeKind.Self)
            throw new InvalidOperationException("Mailbox retrieval requires a self selector.");
        return selector;
    }

    private void EnsureAuthority(VerifiedOfficialMailboxAuthority candidate)
    {
        candidate.Validate();
        if (!CryptographicOperations.FixedTimeEquals(
                candidate.PolicyFingerprint.Span, authority.PolicyFingerprint.Span))
            throw new InvalidOperationException("Mailbox target selected a different official authority.");
    }

    private static byte[] DecodeDpe1(string body)
    {
        if (string.IsNullOrWhiteSpace(body) ||
            !body.StartsWith(E2eeClientTransport.WireBodyPrefix, StringComparison.Ordinal))
            throw new InvalidDataException("Mailbox send requires canonical DPE1 wire data.");
        var value = body[E2eeClientTransport.WireBodyPrefix.Length..]
            .Replace('-', '+').Replace('_', '/');
        value = value.PadRight(value.Length + ((4 - value.Length % 4) % 4), '=');
        try { return Convert.FromBase64String(value); }
        catch (FormatException exception) { throw new InvalidDataException("DPE1 wire data is malformed.", exception); }
    }

    private static string EncodeDpe1(ReadOnlySpan<byte> bytes) =>
        E2eeClientTransport.WireBodyPrefix + Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static ulong ToUnixSeconds(DateTimeOffset value, string parameter)
    {
        var seconds = value.ToUnixTimeSeconds();
        if (seconds <= 0) throw new ArgumentOutOfRangeException(parameter);
        return checked((ulong)seconds);
    }

    private static byte[] OperationId(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> material)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain);
        hash.AppendData(material);
        return hash.GetHashAndReset()[..MailboxClientLimits.OperationIdLength];
    }

    private static IReadOnlyList<ScopedMailboxBatchSelector> LogicalSelectors(
        MailboxLogicalSendBatch batch) =>
        batch.Targets.Select(target => new ScopedMailboxBatchSelector(
            target.Selector,
            target.WireMessageId,
            MailboxAuthenticatedOperation.Store)).ToArray();

    private static void ValidateLogicalTargets(
        MailboxLogicalSendBatch batch,
        IReadOnlyList<MailboxAuthenticatedSendTarget> targets)
    {
        if (batch.Targets.Count != targets.Count)
            throw new InvalidOperationException("Logical mailbox fan-out target count changed.");
        for (var ordinal = 0; ordinal < targets.Count; ordinal++)
        {
            var logical = batch.Targets[ordinal];
            var target = targets[ordinal];
            if (target.Envelope.Id != logical.WireMessageId ||
                target.Envelope.Sender != logical.Sender ||
                target.Envelope.Recipient != logical.Recipient ||
                !target.Selector.ScopeId.Span.SequenceEqual(logical.Selector.ScopeId.Span) ||
                !target.Authority.PolicyFingerprint.Span.SequenceEqual(
                    logical.Authority.PolicyFingerprint.Span))
            {
                throw new InvalidOperationException(
                    "Logical mailbox fan-out changed before preparation.");
            }
        }
    }

    private static DirectUsageMetadata? DirectUsage(
        MailboxDeliveryKind kind,
        OutboundMessageEnvelope envelope) =>
        kind == MailboxDeliveryKind.Direct
            ? new DirectUsageMetadata(
                envelope.Id ?? throw new InvalidOperationException(
                    "A direct mailbox target requires a stable wire message ID."),
                ConversationId.ForOneToOne(envelope.Recipient),
                envelope.Recipient)
            : null;

    private static DirectUsageMetadata? DirectUsage(
        MailboxDeliveryKind kind,
        MailboxLogicalSendTarget target) =>
        kind == MailboxDeliveryKind.Direct
            ? new DirectUsageMetadata(
                target.WireMessageId,
                ConversationId.ForOneToOne(target.Recipient),
                target.Recipient)
            : null;

    private void PublishTerminalRouteUsage(
        DirectUsageMetadata? usage,
        Guid attemptId,
        MailboxDispatchRouteOutcome outcome)
    {
        if (usage is null)
            return;
        PublishRouteUsage(new MailboxDispatchRouteUsage(
            usage.MessageId,
            usage.ConversationId,
            usage.Recipient,
            attemptId,
            outcome,
            ReadOnlySpan<byte>.Empty));
    }

    private void PublishRouteUsage(MailboxDispatchRouteUsage usage)
    {
        try
        {
            routeUsageObserver?.Observe(usage);
        }
        catch
        {
            // Diagnostic observers must never alter delivery semantics.
        }
    }

    private static byte[] CursorMaterial(ulong cursor, ReadOnlySpan<byte> token)
    {
        var material = new byte[8 + token.Length];
        BinaryPrimitives.WriteUInt64BigEndian(material, cursor);
        token.CopyTo(material.AsSpan(8));
        return material;
    }

    private static string EncodeItemHandle(ulong cursor, ReadOnlySpan<byte> digest) =>
        $"{ItemHandlePrefix}{cursor:x16}:{Convert.ToHexStringLower(digest)}";

    private static (ulong Cursor, byte[] Digest) DecodeItemHandle(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || !value.StartsWith(ItemHandlePrefix, StringComparison.Ordinal))
            throw new ArgumentException("Opaque mailbox item handle is invalid.", nameof(value));
        var parts = value[ItemHandlePrefix.Length..].Split(':');
        if (parts.Length != 2 || parts[0].Length != 16 || parts[1].Length != 64 ||
            !ulong.TryParse(parts[0], System.Globalization.NumberStyles.AllowHexSpecifier,
                System.Globalization.CultureInfo.InvariantCulture, out var cursor) || cursor == 0)
            throw new ArgumentException("Opaque mailbox item handle is invalid.", nameof(value));
        var digest = Convert.FromHexString(parts[1]);
        return (cursor, digest);
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(
        Volatile.Read(ref disposed) != 0, this);

    private sealed record PreparedMetadata(
        OutboxAccountScope Account,
        MailboxCredentialSelector Selector,
        DirectUsageMetadata? DirectUsage);

    private sealed record DirectUsageMetadata(
        MessageId MessageId,
        ConversationId ConversationId,
        SessionId Recipient);

    private sealed class PreparedSend : IPreparedMailboxAuthenticatedSend
    {
        public PreparedSend(
            NativeMau2MailboxTransport owner,
            PreparedMetadata metadata,
            MailboxAuthenticatedRequestFrame frame)
        {
            Owner = owner;
            Metadata = metadata;
            Frame = frame;
        }

        public NativeMau2MailboxTransport Owner { get; }
        public PreparedMetadata Metadata { get; }
        public MailboxAuthenticatedRequestFrame Frame { get; }
        public int Dispatched;

    }

    private sealed class IdentitySigner(SessionIdentityProvider identity) :
        IMailboxOperationSigner, IDisposable
    {
        private SessionIdentityProvider? active = identity;
        public SessionId SessionId => Current.SessionId;
        public byte[] GetEd25519PublicKey() => Current.GetEd25519PublicKey();
        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> canonicalPresentationSigningBytes)
        {
            var tag = operation switch
            {
                MailboxAuthenticatedOperation.Store => "DEEP-MCP2-STR\0\0\0"u8,
                MailboxAuthenticatedOperation.Retrieve => "DEEP-MCP2-GET\0\0\0"u8,
                MailboxAuthenticatedOperation.Ack => "DEEP-MCP2-ACK\0\0\0"u8,
                _ => throw new ArgumentOutOfRangeException(nameof(operation))
            };
            if (canonicalPresentationSigningBytes.Length !=
                    MailboxAuthenticatedCapabilityLimits.PresentationLength -
                    MailboxAuthenticatedCapabilityLimits.SignatureLength + tag.Length ||
                !CryptographicOperations.FixedTimeEquals(
                    canonicalPresentationSigningBytes[..tag.Length], tag))
            {
                throw new ArgumentException(
                    "Mailbox signing requires the exact MCP2 presentation transcript.",
                    nameof(canonicalPresentationSigningBytes));
            }
            return Current.SignDetached(canonicalPresentationSigningBytes);
        }
        public void Dispose() => active = null;
        private SessionIdentityProvider Current => active ?? throw new ObjectDisposedException(nameof(IdentitySigner));
    }
}
