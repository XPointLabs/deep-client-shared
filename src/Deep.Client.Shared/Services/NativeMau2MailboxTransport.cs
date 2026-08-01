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
    IAuthenticatedInboxTransport,
    IMetadataPrivateSessionMessageTransport,
    IDisposable
{
    private const string ItemHandlePrefix = "mau2-item-v1:";
    private const int RetrievalLimit = 1;
    private static ReadOnlySpan<byte> StoreOperationDomain =>
        "deep.mau2.store-operation.v1"u8;
    private static ReadOnlySpan<byte> BatchOperationDomain =>
        "deep.mau2.store-batch.v1"u8;
    private static ReadOnlySpan<byte> RetrieveOperationDomain =>
        "deep.mau2.retrieve-operation.v1"u8;
    private static ReadOnlySpan<byte> AckOperationDomain =>
        "deep.mau2.ack-operation.v1"u8;

    private readonly ClientMailboxAdapter adapter;
    private readonly IScopedMailboxCredentialRepository credentials;
    private readonly VerifiedOfficialMailboxAuthority authority;
    private readonly IMailboxClientDecodePolicyProvider decodePolicies;
    private readonly Func<SessionId, MailboxCredentialSelector> selfSelector;
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
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(ingress);
        credentials = localStore ?? throw new ArgumentNullException(nameof(localStore));
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        this.decodePolicies = decodePolicies ?? throw new ArgumentNullException(nameof(decodePolicies));
        this.selfSelector = selfSelector ?? throw new ArgumentNullException(nameof(selfSelector));
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
        PrepareScopedMailboxBatchAsync(
        IMailboxOperationSigner signer,
        IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(targets);
        if (targets.Count is 0 or > SqliteSessionStore.MaximumScopedMailboxBatchTargets ||
            targets.Any(static target => target is null))
        {
            throw new ArgumentException("Mailbox send batch is empty or outside its bound.", nameof(targets));
        }

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
                var operationId = OperationId(StoreOperationDomain, ciphertext);
                var envelope = new MailboxEncryptedEnvelope
                {
                    Epoch = route.Epoch,
                    MailboxId = route.MailboxId,
                    PlacementId = route.PlacementId,
                    OperationId = operationId,
                    DeduplicationDigest = SHA256.HashData(ciphertext),
                    CreatedAtUnixSeconds = ToUnixSeconds(target.Envelope.CreatedAt, nameof(targets)),
                    ExpiresAtUnixSeconds = ToUnixSeconds(
                        target.Envelope.ExpiresAt ?? throw new InvalidOperationException(
                            "Mailbox DPE1 target requires its protocol expiry."), nameof(targets)),
                    Ciphertext = ciphertext.ToArray()
                };
                var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
                bindings.Add(new ScopedMailboxBatchTarget(target.Selector, binding));
                preparedMetadata.Add(new PreparedMetadata(
                    target.Selector.AccountScope, target.Selector));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertext);
            }
        }

        var account = preparedMetadata[0].Account;
        if (preparedMetadata.Any(item => !item.Account.Equals(account)))
            throw new InvalidOperationException("A mailbox batch cannot cross account scopes.");
        var parentOperationId = BatchOperationId(bindings);
        var batch = await credentials.PrepareScopedMailboxBatchAsync(
            new ScopedMailboxPrepareBatchRequest(
                account, parentOperationId, bindings,
                TransportOutboxTime.Canonical(authority.TimeProvider.GetUtcNow())),
            signer, authority, cancellationToken).ConfigureAwait(false);
        if (batch.Frames.Count != preparedMetadata.Count)
            throw new InvalidOperationException("Scoped mailbox batch returned an invalid frame count.");
        return batch.Frames.Select((frame, index) =>
            (IPreparedMailboxAuthenticatedSend)new PreparedSend(
                this, preparedMetadata[index], frame)).ToArray();
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
        await adapter.DispatchPreparedStoreAsync(
            prepared.Metadata.Account, prepared.Metadata.Selector,
            prepared.Frame, cancellationToken).ConfigureAwait(false);
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
            ArgumentException or FormatException or OverflowException or CryptographicException)
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
        var operationId = OperationId(
            RetrieveOperationDomain,
            CursorMaterial(continuation.AfterCursor, continuation.GetTokenCopy()));
        var result = await adapter.RetrieveAsync(
            selector.AccountScope, signer, selector, operationId,
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

    private static byte[] BatchOperationId(IReadOnlyList<ScopedMailboxBatchTarget> targets)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(BatchOperationDomain);
        foreach (var target in targets)
        {
            hash.AppendData(target.Selector.ScopeId.Span);
            hash.AppendData(target.Binding.OperationId.Span);
        }
        return hash.GetHashAndReset()[..MailboxClientLimits.OperationIdLength];
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
        MailboxCredentialSelector Selector);

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
