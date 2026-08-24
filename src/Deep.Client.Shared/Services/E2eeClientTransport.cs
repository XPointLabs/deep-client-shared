using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

public sealed record AuthenticatedInboxBatch(
    IReadOnlyList<DurableInboxWireEntry> Entries,
    string? NextCursor);

/// <summary>
/// Per-operation facade for the mailbox protocol. It intentionally exposes only the public
/// identity and exact MCP2 presentation signing; it never exposes generic signing or private-key
/// access. The facade becomes invalid when its E2EE operation completes.
/// </summary>
public interface IMailboxOperationSigner
{
    SessionId SessionId { get; }

    byte[] GetEd25519PublicKey();

    byte[] SignMailboxPresentation(
        MailboxAuthenticatedOperation operation,
        ReadOnlySpan<byte> canonicalPresentationSigningBytes);
}

/// <summary>
/// Explicit composition capability for the free direct-P2P lane. Implementing
/// it is a promise that <see cref="ISessionMessageTransport.SendAsync"/> does
/// not consume official managed mailbox/storage infrastructure.
/// </summary>
public interface IDirectP2pSessionMessageTransport : ISessionMessageTransport
{
}

public interface IMetadataPrivateSessionMessageTransport : ISessionMessageTransport
{
    bool UsesMetadataPrivateTransport { get; }
}

/// <summary>
/// Opaque, immutable result of one successful local mailbox-send preparation. A handle may be
/// dispatched only through the transport which created it.
/// </summary>
public interface IPreparedMailboxAuthenticatedSend
{
}

/// <summary>
/// Mailbox producer seam. Every target must be prepared successfully before any prepared send is
/// dispatched. Implementations must bind this single call to one durable
/// <see cref="IScopedMailboxCredentialRepository.PrepareScopedMailboxBatchAsync"/>
/// transaction; per-target preparation is not a supported implementation.
/// </summary>
public interface IMailboxIdentityAuthenticatedRawTransport : ISessionMessageTransport
{
    Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>
        PrepareScopedMailboxBatchAsync(
        IMailboxOperationSigner signer,
        IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
        CancellationToken cancellationToken = default);

    Task SendPreparedMailboxAuthenticatedAsync(
        IPreparedMailboxAuthenticatedSend preparedSend,
        CancellationToken cancellationToken = default);
}

public interface IResumableMailboxIdentityAuthenticatedRawTransport :
    IMailboxIdentityAuthenticatedRawTransport
{
    Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>?>
        TryResumeScopedMailboxBatchAsync(
        IMailboxOperationSigner signer,
        MailboxLogicalSendBatch batch,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>
        PrepareScopedMailboxLogicalBatchAsync(
        IMailboxOperationSigner signer,
        MailboxLogicalSendBatch batch,
        IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
        CancellationToken cancellationToken = default);
}

public sealed record MailboxAuthenticatedSendTarget(
    OutboundMessageEnvelope Envelope,
    MailboxCredentialSelector Selector,
    VerifiedOfficialMailboxAuthority Authority);

/// <summary>
/// Ciphertext-independent identity of one semantic official-cloud fan-out. The 16-byte value is
/// domain separated and commits to operation kind plus the exact ordered wire and credential
/// scope identifiers. Its value is deliberately never formatted or logged.
/// </summary>
public sealed class MailboxLogicalSendBatch
{
    private const int MaximumIdentifierUtf8Bytes = 512;
    private static ReadOnlySpan<byte> Domain => "deep.mailbox.logical-send-batch.v1"u8;
    private static ReadOnlySpan<byte> SemanticDomain => "deep.mailbox.semantic-send.v1"u8;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly byte[] id;
    private readonly byte[] semanticId;
    private readonly IReadOnlyList<MailboxLogicalSendTarget> targets;

    public MailboxLogicalSendBatch(
        MessageId semanticMessageId,
        MailboxDeliveryKind kind,
        IReadOnlyList<MailboxLogicalSendTarget> targets)
    {
        if (string.IsNullOrWhiteSpace(semanticMessageId.Value))
            throw new ArgumentException("Semantic message ID is required.", nameof(semanticMessageId));
        if (!Enum.IsDefined(kind))
            throw new ArgumentOutOfRangeException(nameof(kind));
        ArgumentNullException.ThrowIfNull(targets);
        if (targets.Count is < 1 or > SqliteSessionStore.MaximumScopedMailboxBatchTargets ||
            targets.Any(static target => target is null))
            throw new ArgumentException("Logical mailbox fan-out is invalid.", nameof(targets));

        SemanticMessageId = semanticMessageId;
        Kind = kind;
        this.targets = Array.AsReadOnly(targets.ToArray());
        using (var semanticHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            semanticHash.AppendData(SemanticDomain);
            semanticHash.AppendData([(byte)kind]);
            AppendString(semanticHash, semanticMessageId.Value);
            semanticId = semanticHash.GetHashAndReset()[..MailboxClientLimits.OperationIdLength];
        }
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        hash.AppendData([(byte)kind]);
        AppendString(hash, semanticMessageId.Value);
        foreach (var target in targets)
        {
            ArgumentNullException.ThrowIfNull(target.Selector);
            ArgumentNullException.ThrowIfNull(target.Authority);
            if (string.IsNullOrWhiteSpace(target.WireMessageId.Value))
                throw new ArgumentException("Logical mailbox wire ID is invalid.", nameof(targets));
            hash.AppendData(target.Selector.ScopeId.Span);
            AppendString(hash, target.WireMessageId.Value);
        }
        id = hash.GetHashAndReset()[..MailboxClientLimits.OperationIdLength];
    }

    public MessageId SemanticMessageId { get; }
    public MailboxDeliveryKind Kind { get; }
    public IReadOnlyList<MailboxLogicalSendTarget> Targets => targets;
    internal ReadOnlyMemory<byte> Id => id.ToArray();
    internal ReadOnlyMemory<byte> SemanticId => semanticId.ToArray();
    public override string ToString() => "[opaque-mailbox-logical-send-batch]";

    private static void AppendString(IncrementalHash hash, string value)
    {
        byte[] bytes;
        try
        {
            bytes = StrictUtf8.GetBytes(value);
        }
        catch (EncoderFallbackException exception)
        {
            throw new ArgumentException("Logical mailbox identifier is not valid UTF-8.", exception);
        }
        if (bytes.Length is 0 or > MaximumIdentifierUtf8Bytes)
            throw new ArgumentException("Logical mailbox identifier exceeds its bound.");
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}

public sealed record MailboxLogicalSendTarget(
    MessageId WireMessageId,
    MailboxCredentialSelector Selector,
    VerifiedOfficialMailboxAuthority Authority,
    SessionId Sender,
    SessionId Recipient);

/// <summary>
/// Opaque mailbox retrieval item. Deliberately contains no sender, recipient, Session ID, or
/// storage-server identifier: those values remain inside the canonical MEO1/DPE1 ciphertext.
/// </summary>
public sealed class OpaqueMailboxWireEntry
{
    private readonly byte[] canonicalMeo1;
    private readonly byte[] envelopeDigest;

    private OpaqueMailboxWireEntry(
        ulong cursor,
        ReadOnlySpan<byte> canonicalMeo1,
        ReadOnlySpan<byte> envelopeDigest)
    {
        Cursor = cursor;
        this.canonicalMeo1 = canonicalMeo1.ToArray();
        this.envelopeDigest = envelopeDigest.ToArray();
    }

    /// <summary>
    /// Strictly decodes MEO1 under the operation's already-verified policy, re-encodes it, and
    /// binds the externally supplied acknowledgement digest to MEO1 header bytes 96 through 127.
    /// </summary>
    public static OpaqueMailboxWireEntry DecodeAndVerify(
        ulong cursor,
        ReadOnlySpan<byte> encodedMeo1,
        ReadOnlySpan<byte> externalEnvelopeDigest,
        MailboxClientDecodePolicy policy)
    {
        if (cursor == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(cursor));
        }

        ArgumentNullException.ThrowIfNull(policy);
        if (externalEnvelopeDigest.Length != MailboxClientLimits.DigestLength)
        {
            throw new ArgumentException("Opaque mailbox entry digest has an invalid length.", nameof(externalEnvelopeDigest));
        }

        var decoded = MailboxClientCodec.DecodeEncryptedEnvelope(encodedMeo1, policy);
        var canonical = MailboxClientCodec.EncodeEncryptedEnvelope(decoded);
        if (!CryptographicOperations.FixedTimeEquals(canonical, encodedMeo1) ||
            !CryptographicOperations.FixedTimeEquals(
                canonical.AsSpan(96, MailboxClientLimits.DigestLength),
                externalEnvelopeDigest))
        {
            throw new ArgumentException("Opaque mailbox entry does not bind a canonical MEO1 digest.");
        }

        return new OpaqueMailboxWireEntry(cursor, canonical, externalEnvelopeDigest);
    }

    public ulong Cursor { get; }

    public byte[] GetCanonicalMeo1Copy() => canonicalMeo1.ToArray();

    public byte[] GetEnvelopeDigestCopy() => envelopeDigest.ToArray();
}

/// <summary>
/// The opaque continuation authority for a mailbox retrieval sequence.
/// </summary>
public sealed class OpaqueMailboxContinuation
{
    private readonly byte[] token;

    public OpaqueMailboxContinuation(ulong afterCursor, ReadOnlySpan<byte> token)
    {
        if (afterCursor == 0 != token.IsEmpty ||
            token.Length > MailboxClientLimits.MaximumContinuationTokenLength)
        {
            throw new ArgumentException("Opaque mailbox continuation is invalid.");
        }

        AfterCursor = afterCursor;
        this.token = token.ToArray();
    }

    public ulong AfterCursor { get; }

    public byte[] GetTokenCopy() => token.ToArray();
}

/// <summary>
/// A committed opaque mailbox page. This bridge seam deliberately authorizes at most one entry per
/// traversal so the eventual authenticated MBA2 acknowledgement is an ordered one-item prefix.
/// </summary>
public sealed class OpaqueMailboxInboxPage
{
    private readonly IReadOnlyList<OpaqueMailboxWireEntry> entries;

    public OpaqueMailboxInboxPage(
        OpaqueMailboxContinuation requested,
        OpaqueMailboxContinuation next,
        IReadOnlyList<OpaqueMailboxWireEntry> entries)
    {
        Requested = requested ?? throw new ArgumentNullException(nameof(requested));
        Next = next ?? throw new ArgumentNullException(nameof(next));
        ArgumentNullException.ThrowIfNull(entries);
        if (entries.Count > 1 || entries.Any(static entry => entry is null))
        {
            throw new ArgumentException(
                "Opaque mailbox pages must contain zero or one non-null entry.",
                nameof(entries));
        }

        this.entries = Array.AsReadOnly(entries.ToArray());
        if (this.entries.Count == 0 && Next.AfterCursor != 0)
        {
            throw new ArgumentException("An empty mailbox page must be terminal.", nameof(next));
        }

        if (this.entries.Count == 1)
        {
            var entry = this.entries[0];
            if (entry.Cursor <= Requested.AfterCursor)
            {
                throw new ArgumentException("Mailbox cursor regressed or repeated.", nameof(entries));
            }

            if (Next.AfterCursor != 0 && Next.AfterCursor != entry.Cursor)
            {
                throw new ArgumentException("Mailbox continuation must be bound to the returned cursor.", nameof(next));
            }
        }
    }

    /// <summary>
    /// The next durable traversal authority. A zero cursor has an empty token and ends this
    /// retrieval cycle; a nonzero cursor has the nonempty opaque continuation token required for
    /// the next one-item retrieval.
    /// </summary>
    public OpaqueMailboxContinuation Requested { get; }

    public OpaqueMailboxContinuation Next { get; }

    public IReadOnlyList<OpaqueMailboxWireEntry> Entries => entries;
}

/// <summary>
/// Dormant opaque mailbox read seam. It is intentionally not consumed by the current inbox
/// pipeline until mailbox cursor/ack persistence is introduced.
/// </summary>
public interface IAuthenticatedOpaqueMailboxTransport :
    IMailboxIdentityAuthenticatedRawTransport
{
    Task<OpaqueMailboxInboxPage> RetrieveOpaqueMailboxInboxAsync(
        IMailboxOperationSigner signer,
        OpaqueMailboxContinuation continuation,
        CancellationToken cancellationToken = default);

    Task AcknowledgeOpaqueMailboxInboxAsync(
        IMailboxOperationSigner signer,
        string opaqueItemHandle,
        CancellationToken cancellationToken = default);
}

public sealed class E2eeMailboxPayloadTooLargeException(
    int payloadBytes,
    int maximumPayloadBytes) : CryptographicException(
        $"DPE1 payload is {payloadBytes} bytes, exceeding the mailbox ciphertext limit of {maximumPayloadBytes} bytes.")
{
    public int PayloadBytes { get; } = payloadBytes;

    public int MaximumPayloadBytes { get; } = maximumPayloadBytes;
}

public interface IAuthenticatedInboxTransport
{
    int InboxNamespace => 0;

    Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
        SessionIdentityProvider identity,
        CancellationToken cancellationToken = default);

    async Task<AuthenticatedInboxBatch> RetrieveAuthenticatedAsync(
        SessionIdentityProvider identity,
        string? cursor,
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit is <= 0 or > DurableInboxLimits.MaxBatchCount)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        var envelopes = await ReceiveAuthenticatedAsync(identity, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The authenticated inbox transport returned a null batch.");
        var entries = envelopes
            .Take(limit)
            .Where(static envelope => envelope is not null && !string.IsNullOrWhiteSpace(envelope.ServerHash))
            .Select(AuthenticatedInboxEnvelopeCodec.Encode)
            .ToArray();
        return new AuthenticatedInboxBatch(entries, entries.Length == 0 ? cursor : entries[^1].ServerHash);
    }

    bool TryDecodeInboxEntry(
        DurableInboxWireEntry entry,
        SessionId recipient,
        out InboundMessageEnvelope envelope) =>
        AuthenticatedInboxEnvelopeCodec.TryDecode(entry, recipient, out envelope);
}

internal static class AuthenticatedInboxEnvelopeCodec
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static DurableInboxWireEntry Encode(InboundMessageEnvelope envelope)
    {
        var payload = JsonSerializer.Serialize(envelope, JsonOptions);
        return DurableInboxWireEntry.CreateBounded(
            envelope.ServerHash,
            envelope.CreatedAt.ToUnixTimeMilliseconds(),
            payload);
    }

    public static bool TryDecode(
        DurableInboxWireEntry entry,
        SessionId recipient,
        out InboundMessageEnvelope envelope)
    {
        envelope = default!;
        try
        {
            var decoded = JsonSerializer.Deserialize<InboundMessageEnvelope>(entry.WirePayload, JsonOptions);
            if (decoded is null
                || decoded.Recipient != recipient
                || !string.Equals(decoded.ServerHash, entry.ServerHash, StringComparison.Ordinal))
            {
                return false;
            }

            envelope = decoded;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }
}

public interface IDurableInboxAcknowledger
{
    Task AcknowledgeInboxItemAsync(
        SessionId account,
        string serverHash,
        CancellationToken cancellationToken = default);
}

public interface IKnownGroupInboxReceiver
{
    Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveKnownGroupMessagesAsync(
        SessionId account,
        IReadOnlyCollection<ConversationId> groupIds,
        CancellationToken cancellationToken = default);
}

public interface IGroupInboxMaintenance
{
    Task<int> DiscardUnknownGroupMessagesAsync(
        SessionId account,
        IReadOnlyCollection<ConversationId> knownGroupIds,
        CancellationToken cancellationToken = default);
}

public sealed class E2eeClientTransport :
    ISessionMessageTransport,
    IGroupSyncTransport,
    IDurableInboxAcknowledger,
    IKnownGroupInboxReceiver,
    IGroupInboxMaintenance,
    IDisposable
{
    public const string WireBodyPrefix = "dpe1:";
    public const int MaxRawBatchCount = 256;
    public const int MaxCachedDirectMessages = 512;
    public const int MaxCachedGroupStates = 256;
    public const int MaxCachedGroupMessages = 1024;
    public const int MaxServerHashChars = 512;

    private const int ReplayClaimsPerPrune = 128;
    private const int GroupFanOutConcurrency = 8;
    private static readonly TimeSpan ReplayPruneInterval = TimeSpan.FromMinutes(30);
    private static readonly int MaxWireBodyChars =
        WireBodyPrefix.Length + (((E2eeEnvelopeCodec.MaxEnvelopeBytes + 2) / 3) * 4);

    private readonly ISessionMessageTransport rawTransport;
    private readonly Func<CancellationToken, Task<string?>> recoveryPhraseProvider;
    private readonly IClock clock;
    private readonly IDurableInboxRepository inboxRepository;
    private readonly IMailboxDeliveryPolicy deliveryPolicy;
    private readonly IDisposable? ownedRawTransport;
    private readonly object identityGate = new();
    private readonly SemaphoreSlim receiveGate = new(1, 1);
    private readonly object deliveredItemsGate = new();
    private readonly HashSet<InboxDeliveryKey> deliveredItems = [];

    private IdentityCacheEntry? cachedIdentity;
    private int replayClaimsSincePrune;
    private DateTimeOffset? lastReplayPruneAt;
    private int disposed;

    public E2eeClientTransport(
        ISessionMessageTransport rawTransport,
        Func<CancellationToken, Task<string?>> recoveryPhraseProvider,
        IClock clock,
        IDurableInboxRepository inboxRepository,
        IMailboxDeliveryPolicy deliveryPolicy,
        bool ownsRawTransport = false)
    {
        this.rawTransport = rawTransport ?? throw new ArgumentNullException(nameof(rawTransport));
        this.recoveryPhraseProvider = recoveryPhraseProvider ?? throw new ArgumentNullException(nameof(recoveryPhraseProvider));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.inboxRepository = inboxRepository ?? throw new ArgumentNullException(nameof(inboxRepository));
        this.deliveryPolicy = deliveryPolicy ?? throw new ArgumentNullException(nameof(deliveryPolicy));
        ownedRawTransport = ownsRawTransport
            ? rawTransport as IDisposable ?? throw new ArgumentException(
                "An owned raw transport must implement IDisposable.",
                nameof(rawTransport))
            : null;
    }

    public async Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        envelope = envelope with { Id = envelope.Id ?? MessageId.NewId() };
        var plans = await WithIdentityAsync(
            identity => BuildDirectPlans(identity, envelope),
            cancellationToken).ConfigureAwait(false);
        await SendPolicySelectedPlansAsync(
            plans, envelope.Id.Value, MailboxDeliveryKind.Direct,
            concurrent: false, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
        SessionId recipient,
        CancellationToken cancellationToken = default)
    {
        await receiveGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await WithIdentityAsync(
                async identity =>
                {
                    EnsureLocalAccount(identity, recipient, nameof(recipient));
                    var candidates = await ReceiveCandidatesAsync(
                        identity,
                        DurableInboxItemKind.DirectMessage,
                        routeKey: null,
                        cancellationToken).ConfigureAwait(false);
                    return candidates.Select(static candidate => ToDirectEnvelope(candidate)).ToArray();
                },
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            receiveGate.Release();
        }
    }

    public async Task PublishGroupStateAsync(
        Group group,
        DateTimeOffset updatedAt,
        IEnumerable<SessionId>? recipients = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(group);
        var plans = await WithIdentityAsync(
            identity => BuildGroupStatePlans(identity, group, updatedAt, recipients),
            cancellationToken).ConfigureAwait(false);
        var stateId = DeterministicMessageId(
            "group-state", group.Id.Value,
            group.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        await SendPolicySelectedPlansAsync(
            plans, stateId, MailboxDeliveryKind.GroupState,
            concurrent: true, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
        SessionId member,
        CancellationToken cancellationToken = default)
    {
        await receiveGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await WithIdentityAsync(
                async identity =>
                {
                    EnsureLocalAccount(identity, member, nameof(member));
                    var candidates = await ReceiveCandidatesAsync(
                        identity,
                        DurableInboxItemKind.GroupState,
                        routeKey: null,
                        cancellationToken).ConfigureAwait(false);
                    return candidates.Select(static candidate => ToGroupStateEnvelope(candidate)).ToArray();
                },
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            receiveGate.Release();
        }
    }

    public async Task SendGroupMessageAsync(
        OutboundGroupMessageEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var plans = await WithIdentityAsync(
            identity => BuildGroupMessagePlans(identity, envelope),
            cancellationToken).ConfigureAwait(false);
        await SendPolicySelectedPlansAsync(
            plans, envelope.Id, MailboxDeliveryKind.GroupMessage,
            concurrent: true, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
        ConversationId groupId,
        CancellationToken cancellationToken = default)
    {
        EnsureCanonicalGroupId(groupId, nameof(groupId));
        await receiveGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await WithIdentityAsync(
                async identity =>
                {
                    var candidates = await ReceiveCandidatesAsync(
                        identity,
                        DurableInboxItemKind.GroupMessage,
                        groupId.Value,
                        cancellationToken).ConfigureAwait(false);
                    return candidates.Select(static candidate => ToGroupMessageEnvelope(candidate)).ToArray();
                },
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            receiveGate.Release();
        }
    }

    public async Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveKnownGroupMessagesAsync(
        SessionId account,
        IReadOnlyCollection<ConversationId> groupIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(groupIds);
        var routeKeys = groupIds
            .Distinct()
            .Select(groupId =>
            {
                EnsureCanonicalGroupId(groupId, nameof(groupIds));
                return groupId.Value;
            })
            .ToHashSet(StringComparer.Ordinal);
        if (routeKeys.Count == 0)
        {
            return [];
        }

        await receiveGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await WithIdentityAsync(
                async identity =>
                {
                    EnsureLocalAccount(identity, account, nameof(account));
                    var candidates = await ReceiveCandidatesAsync(
                        identity,
                        DurableInboxItemKind.GroupMessage,
                        routeKey: null,
                        cancellationToken,
                        routeKeys).ConfigureAwait(false);
                    return candidates.Select(static candidate => ToGroupMessageEnvelope(candidate)).ToArray();
                },
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            receiveGate.Release();
        }
    }

    public async Task<int> DiscardUnknownGroupMessagesAsync(
        SessionId account,
        IReadOnlyCollection<ConversationId> knownGroupIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(knownGroupIds);
        var retainedRouteKeys = knownGroupIds
            .Distinct()
            .Select(groupId =>
            {
                EnsureCanonicalGroupId(groupId, nameof(knownGroupIds));
                return groupId.Value;
            })
            .ToHashSet(StringComparer.Ordinal);

        await receiveGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await WithIdentityAsync(
                async identity =>
                {
                    EnsureLocalAccount(identity, account, nameof(account));
                    if (rawTransport is not IAuthenticatedInboxTransport authenticatedTransport)
                    {
                        throw new InvalidOperationException(
                            "The raw personal-inbox transport does not support authenticated retrieval.");
                    }

                    var scope = new DurableInboxScope(account, authenticatedTransport.InboxNamespace);
                    while (await ClassifyStagedItemsAsync(
                               identity,
                               authenticatedTransport,
                               scope,
                               cancellationToken).ConfigureAwait(false) == MaxRawBatchCount)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                    }

                    var discarded = await inboxRepository.DiscardDecodedInboxItemsOutsideRoutesAsync(
                        scope,
                        DurableInboxItemKind.GroupMessage,
                        retainedRouteKeys,
                        cancellationToken).ConfigureAwait(false);
                    if (discarded > 0)
                    {
                        ForgetDelivered(scope);
                    }

                    return discarded;
                },
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            receiveGate.Release();
        }
    }

    public void Dispose()
    {
        IdentityCacheEntry? identityToDestroy;
        lock (identityGate)
        {
            if (disposed != 0)
            {
                return;
            }

            Volatile.Write(ref disposed, 1);
            identityToDestroy = RetireIdentityEntry(cachedIdentity);
            cachedIdentity = null;
        }

        try
        {
            identityToDestroy?.Destroy();

            lock (deliveredItemsGate)
            {
                deliveredItems.Clear();
            }
        }
        finally
        {
            ownedRawTransport?.Dispose();
        }
    }

    public void RetireCachedIdentity()
    {
        IdentityCacheEntry? identityToDestroy;
        lock (identityGate)
        {
            if (disposed != 0)
            {
                return;
            }

            identityToDestroy = RetireIdentityEntry(cachedIdentity);
            cachedIdentity = null;
        }

        identityToDestroy?.Destroy();
        lock (deliveredItemsGate)
        {
            deliveredItems.Clear();
        }
    }

    private IReadOnlyList<WireCopyPlan> BuildDirectPlans(
        SessionIdentityProvider identity,
        OutboundMessageEnvelope envelope)
    {
        EnsureLocalAccount(identity, envelope.Sender, nameof(envelope.Sender));
        var now = clock.UtcNow;
        var protocolExpiresAt = GetProtocolExpiry(envelope.CreatedAt, now);
        ValidateUserExpiry(envelope.ExpiresAt, envelope.CreatedAt, protocolExpiresAt, now);
        var content = new E2eeContent(
            envelope.Reaction is null ? E2eeContentKind.Message : E2eeContentKind.Reaction,
            envelope.Id ?? MessageId.NewId(),
            ConversationKind.OneToOne,
            ConversationId.ForOneToOne(envelope.Recipient),
            envelope.Sender,
            envelope.Recipient,
            envelope.CreatedAt,
            protocolExpiresAt,
            envelope.ExpiresAt,
            envelope.Body,
            envelope.Attachments,
            envelope.ReplyTo,
            envelope.Reaction);

        var targets = new[] { envelope.Recipient, envelope.Sender }.Distinct().ToArray();
        return BuildWirePlans(content, targets, now);
    }

    private IReadOnlyList<WireCopyPlan> BuildGroupMessagePlans(
        SessionIdentityProvider identity,
        OutboundGroupMessageEnvelope envelope)
    {
        EnsureLocalAccount(identity, envelope.Sender, nameof(envelope.Sender));
        EnsureCanonicalGroupId(envelope.GroupId, nameof(envelope.GroupId));
        var now = clock.UtcNow;
        var protocolExpiresAt = GetProtocolExpiry(envelope.CreatedAt, now);
        ValidateUserExpiry(envelope.ExpiresAt, envelope.CreatedAt, protocolExpiresAt, now);
        var targets = (envelope.NotifyRecipients ?? [])
            .Append(envelope.Sender)
            .Distinct()
            .ToArray();
        var copies = new List<WireCopyPlan>(targets.Length);

        foreach (var target in targets)
        {
            var content = new E2eeContent(
                envelope.Reaction is null ? E2eeContentKind.Message : E2eeContentKind.Reaction,
                envelope.Id,
                ConversationKind.GroupV2,
                envelope.GroupId,
                envelope.Sender,
                target,
                envelope.CreatedAt,
                protocolExpiresAt,
                envelope.ExpiresAt,
                envelope.Body,
                envelope.Attachments,
                envelope.ReplyTo,
                envelope.Reaction);
            copies.Add(new WireCopyPlan(content, target, now));
        }

        return copies;
    }

    private IReadOnlyList<WireCopyPlan> BuildGroupStatePlans(
        SessionIdentityProvider identity,
        Group group,
        DateTimeOffset updatedAt,
        IEnumerable<SessionId>? recipients)
    {
        EnsureCanonicalGroupId(group.Id, nameof(group));
        var now = clock.UtcNow;
        var protocolExpiresAt = GetProtocolExpiry(updatedAt, now);
        var targets = (recipients ?? group.Members.Select(static member => member.SessionId))
            .Append(group.CreatedBy)
            .Append(identity.SessionId)
            .Distinct()
            .ToArray();
        var stateId = DeterministicMessageId(
            "group-state",
            group.Id.Value,
            group.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var copies = new List<WireCopyPlan>(targets.Length);

        foreach (var target in targets)
        {
            var content = new E2eeContent(
                E2eeContentKind.GroupState,
                stateId,
                ConversationKind.GroupV2,
                group.Id,
                identity.SessionId,
                target,
                updatedAt,
                protocolExpiresAt,
                null,
                string.Empty,
                [],
                GroupState: group);
            copies.Add(new WireCopyPlan(content, target, now));
        }

        return copies;
    }

    private static IReadOnlyList<WireCopyPlan> BuildWirePlans(
        E2eeContent content,
        IReadOnlyList<SessionId> targets,
        DateTimeOffset wireCreatedAt)
    {
        var copies = new WireCopyPlan[targets.Count];
        for (var index = 0; index < targets.Count; index++)
        {
            copies[index] = new WireCopyPlan(content, targets[index], wireCreatedAt);
        }

        return copies;
    }

    private OutboundMessageEnvelope BuildWireCopy(
        SessionIdentityProvider identity,
        WireCopyPlan plan)
    {
        var encrypted = identity.CreateEnvelopeCodec().EncryptContent(plan.Content, plan.Target);
        try
        {
            return new OutboundMessageEnvelope(
                identity.SessionId,
                plan.Target,
                EncodeWireBody(encrypted),
                [],
                plan.WireCreatedAt,
                plan.Content.ProtocolExpiresAt,
                plan.WireMessageId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encrypted);
        }
    }

    private async Task SendCopiesSequentiallyAsync(
        IReadOnlyList<OutboundMessageEnvelope> copies,
        CancellationToken cancellationToken)
    {
        foreach (var copy in copies)
        {
            await rawTransport.SendAsync(copy, cancellationToken).ConfigureAwait(false);
        }
    }

    private Task SendCopiesWithBoundedConcurrencyAsync(
        IReadOnlyList<OutboundMessageEnvelope> copies,
        CancellationToken cancellationToken) =>
        Parallel.ForEachAsync(
            copies,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = GroupFanOutConcurrency,
                CancellationToken = cancellationToken
            },
            async (copy, itemCancellationToken) =>
                await rawTransport.SendAsync(copy, itemCancellationToken).ConfigureAwait(false));

    private async Task SendPolicySelectedPlansAsync(
        IReadOnlyList<WireCopyPlan> plans,
        MessageId semanticMessageId,
        MailboxDeliveryKind kind,
        bool concurrent,
        CancellationToken cancellationToken)
    {
        var directPlans = new List<WireCopyPlan>(plans.Count);
        var cloudPlans = new List<(WireCopyPlan Plan, MailboxDeliveryDecision Decision)>(plans.Count);
        var durableTargets = new List<DurableLogicalDispatchTarget>(plans.Count);
        foreach (var plan in plans)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var decision = await deliveryPolicy.DecideAsync(
                    new MailboxDeliveryRequest(plan.RoutingEnvelope, kind), cancellationToken)
                .ConfigureAwait(false) ?? throw new InvalidOperationException(
                    "Mailbox delivery policy returned no decision.");
            decision.Validate();
            if (decision.Protocol == MailboxTransportProtocol.DirectP2p)
            {
                directPlans.Add(plan);
                durableTargets.Add(new DurableLogicalDispatchTarget(
                    plan.Target,
                    plan.WireMessageId,
                    DurableLogicalDispatchRoute.DirectP2p,
                    ReadOnlyMemory<byte>.Empty));
            }
            else
            {
                cloudPlans.Add((plan, decision));
                durableTargets.Add(new DurableLogicalDispatchTarget(
                    plan.Target,
                    plan.WireMessageId,
                    DurableLogicalDispatchRoute.OfficialCloud,
                    decision.Selector!.ScopeId));
            }
        }
        var dispatchPlans = inboxRepository as ILogicalDispatchPlanRepository
            ?? throw new InvalidOperationException(
                "E2EE sending requires durable logical dispatch-plan storage.");
        await dispatchPlans.EnsureLogicalDispatchPlanAsync(
            new DurableLogicalDispatchPlan(
                plans[0].Content.Sender,
                semanticMessageId,
                kind switch
                {
                    MailboxDeliveryKind.Direct =>
                        DurableLogicalDispatchKind.DirectMessage,
                    MailboxDeliveryKind.GroupMessage =>
                        DurableLogicalDispatchKind.GroupMessage,
                    MailboxDeliveryKind.GroupState =>
                        DurableLogicalDispatchKind.GroupState,
                    _ => throw new ArgumentOutOfRangeException(nameof(kind))
                },
                durableTargets
                    .OrderBy(static target => target.Recipient.Value,
                        StringComparer.Ordinal)
                    .ThenBy(static target => target.WireMessageId.Value,
                        StringComparer.Ordinal)
                    .ToArray(),
                TransportOutboxTime.Canonical(clock.UtcNow)),
            cancellationToken).ConfigureAwait(false);
        cloudPlans = cloudPlans
            .OrderBy(item => Convert.ToHexString(item.Decision.Selector!.ScopeId.Span),
                StringComparer.Ordinal)
            .ThenBy(item => item.Plan.WireMessageId.Value, StringComparer.Ordinal)
            .ToList();
        EnsureDirectP2pTransport(directPlans.Select(static plan => plan.RoutingEnvelope).ToArray());
        IReadOnlyList<IPreparedMailboxAuthenticatedSend> prepared = [];
        IResumableMailboxIdentityAuthenticatedRawTransport? cloudTransport = null;
        if (cloudPlans.Count > 0)
        {
            cloudTransport = rawTransport as IResumableMailboxIdentityAuthenticatedRawTransport
                ?? throw new InvalidOperationException(
                    "Official cloud delivery requires durable logical-batch resumption.");
            var logicalBatch = new MailboxLogicalSendBatch(
                semanticMessageId,
                kind,
                cloudPlans.Select(item => new MailboxLogicalSendTarget(
                    item.Plan.WireMessageId,
                    item.Decision.Selector!,
                    item.Decision.Authority!,
                    item.Plan.RoutingEnvelope.Sender,
                    item.Plan.RoutingEnvelope.Recipient)).ToArray());
            prepared = await WithMailboxOperationSignerAsync(
                async (_, signer) =>
                    await cloudTransport.TryResumeScopedMailboxBatchAsync(
                        signer, logicalBatch, cancellationToken).ConfigureAwait(false)
                    ?? await PrepareFreshCloudBatchAsync(
                        cloudTransport, signer, logicalBatch, cloudPlans,
                        cancellationToken).ConfigureAwait(false),
                cancellationToken)
                .ConfigureAwait(false);
            if (prepared is null || prepared.Count != cloudPlans.Count ||
                prepared.Any(static value => value is null))
                throw new InvalidOperationException(
                    "Mailbox batch preparation returned invalid handles.");
        }
        var direct = await WithIdentityAsync(
            identity => directPlans.Select(plan => BuildWireCopy(identity, plan)).ToArray(),
            cancellationToken).ConfigureAwait(false);
        if (concurrent)
        {
            EnsureDirectP2pTransport(direct);
            await SendCopiesWithBoundedConcurrencyAsync(direct, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            EnsureDirectP2pTransport(direct);
            await SendCopiesSequentiallyAsync(direct, cancellationToken).ConfigureAwait(false);
        }
        if (cloudTransport is not null)
        {
            if (concurrent)
                await SendPreparedMailboxCopiesWithBoundedConcurrencyAsync(
                    cloudTransport, prepared, cancellationToken).ConfigureAwait(false);
            else
                await SendPreparedMailboxCopiesSequentiallyAsync(
                    cloudTransport, prepared, cancellationToken).ConfigureAwait(false);
        }
    }

    private void EnsureDirectP2pTransport(
        IReadOnlyCollection<OutboundMessageEnvelope> direct)
    {
        if (direct.Count > 0 &&
            rawTransport is not IDirectP2pSessionMessageTransport)
        {
            throw new InvalidOperationException(
                "Direct P2P delivery requires an explicit direct-P2P transport.");
        }
    }

    private async Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>
        PrepareFreshCloudBatchAsync(
        IResumableMailboxIdentityAuthenticatedRawTransport cloudTransport,
        IMailboxOperationSigner signer,
        MailboxLogicalSendBatch logicalBatch,
        IReadOnlyList<(WireCopyPlan Plan, MailboxDeliveryDecision Decision)> cloudPlans,
        CancellationToken cancellationToken)
    {
        var cloud = await WithIdentityAsync(
            identity => cloudPlans.Select(item => new MailboxAuthenticatedSendTarget(
                BuildWireCopy(identity, item.Plan),
                item.Decision.Selector!,
                item.Decision.Authority!)).ToArray(),
            cancellationToken).ConfigureAwait(false);
        foreach (var target in cloud)
        {
            if (!TryDecodeWireBody(target.Envelope.Body, out var payload))
                throw new InvalidDataException("Cloud delivery requires canonical DPE1.");
            try
            {
                if (payload.Length > MailboxClientLimits.MaximumCiphertextLength)
                    throw new E2eeMailboxPayloadTooLargeException(
                        payload.Length, MailboxClientLimits.MaximumCiphertextLength);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
        return await cloudTransport.PrepareScopedMailboxLogicalBatchAsync(
            signer, logicalBatch, cloud, cancellationToken).ConfigureAwait(false);
    }

    private static async Task SendPreparedMailboxCopiesSequentiallyAsync(
        IMailboxIdentityAuthenticatedRawTransport authenticatedTransport,
        IReadOnlyList<IPreparedMailboxAuthenticatedSend> prepared,
        CancellationToken cancellationToken)
    {
        foreach (var preparedSend in prepared)
        {
            await authenticatedTransport.SendPreparedMailboxAuthenticatedAsync(preparedSend, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static Task SendPreparedMailboxCopiesWithBoundedConcurrencyAsync(
        IMailboxIdentityAuthenticatedRawTransport authenticatedTransport,
        IReadOnlyList<IPreparedMailboxAuthenticatedSend> prepared,
        CancellationToken cancellationToken) =>
        Parallel.ForEachAsync(
            prepared,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = GroupFanOutConcurrency,
                CancellationToken = cancellationToken
            },
            async (preparedSend, itemCancellationToken) =>
                await authenticatedTransport.SendPreparedMailboxAuthenticatedAsync(
                    preparedSend,
                    itemCancellationToken).ConfigureAwait(false));

    public async Task AcknowledgeInboxItemAsync(
        SessionId account,
        string serverHash,
        CancellationToken cancellationToken = default)
    {
        var result = await WithIdentityAsync(
            async identity =>
            {
                EnsureLocalAccount(identity, account, nameof(account));
                if (rawTransport is not IAuthenticatedInboxTransport authenticatedTransport)
                {
                    throw new InvalidOperationException(
                        "The raw personal-inbox transport does not support authenticated retrieval.");
                }

                var scope = new DurableInboxScope(account, authenticatedTransport.InboxNamespace);
                if (rawTransport is IAuthenticatedOpaqueMailboxTransport opaqueMailbox)
                {
                    using var signer = new MailboxOperationSignerLease(identity);
                    await opaqueMailbox.AcknowledgeOpaqueMailboxInboxAsync(
                        signer, serverHash, cancellationToken).ConfigureAwait(false);
                }
                var ack = await inboxRepository.AcknowledgeInboxItemAsync(
                    scope,
                    serverHash,
                    cancellationToken).ConfigureAwait(false);
                ForgetDelivered(scope, serverHash);
                return ack;
            },
            cancellationToken).ConfigureAwait(false);

        await PruneReplayClaimsIfNeededAsync(cancellationToken).ConfigureAwait(false);
        if (result == DurableInboxAckResult.RejectedDigestMismatch)
        {
            throw new E2eeProtocolException("The durable inbox replay digest changed before acknowledgement.");
        }
    }

    private async Task<IReadOnlyList<DecodedCandidate>> ReceiveCandidatesAsync(
        SessionIdentityProvider identity,
        DurableInboxItemKind kind,
        string? routeKey,
        CancellationToken cancellationToken,
        IReadOnlySet<string>? retainedRouteKeys = null)
    {
        if (rawTransport is not IAuthenticatedInboxTransport authenticatedTransport)
        {
            throw new InvalidOperationException(
                "The raw personal-inbox transport does not support authenticated retrieval.");
        }

        var scope = new DurableInboxScope(identity.SessionId, authenticatedTransport.InboxNamespace);
        await ClassifyStagedItemsAsync(identity, authenticatedTransport, scope, cancellationToken)
            .ConfigureAwait(false);
        var items = await inboxRepository.ListDecodedInboxItemsAsync(
            scope,
            kind,
            routeKey,
            MaxRawBatchCount,
            cancellationToken).ConfigureAwait(false);
        items = RetainRoutes(items, retainedRouteKeys);

        if ((items.Count == 0 || items.All(item => WasDelivered(scope, item.ServerHash)))
            && await inboxRepository.CountPendingInboxItemsAsync(scope, cancellationToken).ConfigureAwait(false)
                < DurableInboxLimits.MaxPendingItemCount)
        {
            await RetrieveAndStageAsync(identity, authenticatedTransport, scope, cancellationToken)
                .ConfigureAwait(false);
            await ClassifyStagedItemsAsync(identity, authenticatedTransport, scope, cancellationToken)
                .ConfigureAwait(false);
            items = await inboxRepository.ListDecodedInboxItemsAsync(
                scope,
                kind,
                routeKey,
                MaxRawBatchCount,
                cancellationToken).ConfigureAwait(false);
            items = RetainRoutes(items, retainedRouteKeys);
        }

        var candidates = new List<DecodedCandidate>(items.Count);
        foreach (var item in items)
        {
            try
            {
                var candidate = DecodeCandidate(identity, authenticatedTransport, item);
                if (!Equals(CreateDecodedMetadata(candidate.Content, candidate.EnvelopeDigest), item.Decoded))
                {
                    throw new E2eeProtocolException("Staged inbox metadata no longer matches its wire entry.");
                }

                candidates.Add(candidate);
                MarkDelivered(scope, item.ServerHash);
            }
            catch (Exception exception) when (IsRejectedWireEntry(exception))
            {
                await inboxRepository.DiscardInboxItemAsync(scope, item.ServerHash, cancellationToken)
                    .ConfigureAwait(false);
                ForgetDelivered(scope, item.ServerHash);
            }
        }

        return candidates;
    }

    private static IReadOnlyList<DurableInboxItem> RetainRoutes(
        IReadOnlyList<DurableInboxItem> items,
        IReadOnlySet<string>? retainedRouteKeys)
    {
        if (retainedRouteKeys is null)
        {
            return items;
        }

        return items
            .Where(item => item.Decoded is { } decoded && retainedRouteKeys.Contains(decoded.RouteKey))
            .ToArray();
    }

    private async Task RetrieveAndStageAsync(
        SessionIdentityProvider identity,
        IAuthenticatedInboxTransport authenticatedTransport,
        DurableInboxScope scope,
        CancellationToken cancellationToken)
    {
        var cursor = await inboxRepository.GetInboxCursorAsync(scope, cancellationToken).ConfigureAwait(false);
        var batch = await authenticatedTransport.RetrieveAuthenticatedAsync(
            identity,
            cursor,
            MaxRawBatchCount,
            cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The authenticated inbox transport returned a null batch.");
        if (batch.Entries is null || batch.Entries.Count > MaxRawBatchCount)
        {
            throw new InvalidOperationException("The authenticated inbox transport returned an invalid batch.");
        }

        if (batch.Entries.Count == 0)
        {
            if (!string.Equals(batch.NextCursor, cursor, StringComparison.Ordinal))
            {
                throw new E2eeProtocolException("An empty authenticated inbox batch attempted to advance its cursor.");
            }

            return;
        }

        await inboxRepository.StageInboxBatchAsync(
            scope,
            cursor,
            batch.NextCursor,
            batch.Entries,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<int> ClassifyStagedItemsAsync(
        SessionIdentityProvider identity,
        IAuthenticatedInboxTransport authenticatedTransport,
        DurableInboxScope scope,
        CancellationToken cancellationToken)
    {
        var staged = await inboxRepository.ListStagedInboxItemsAsync(
            scope,
            MaxRawBatchCount,
            cancellationToken).ConfigureAwait(false);
        foreach (var item in staged)
        {
            try
            {
                var candidate = DecodeCandidate(identity, authenticatedTransport, item);
                await inboxRepository.PrepareInboxItemAsync(
                    scope,
                    item.ServerHash,
                    CreateDecodedMetadata(candidate.Content, candidate.EnvelopeDigest),
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (IsRejectedWireEntry(exception))
            {
                await inboxRepository.DiscardInboxItemAsync(scope, item.ServerHash, cancellationToken)
                    .ConfigureAwait(false);
                ForgetDelivered(scope, item.ServerHash);
            }
        }

        return staged.Count;
    }

    private bool WasDelivered(DurableInboxScope scope, string serverHash)
    {
        lock (deliveredItemsGate)
        {
            return deliveredItems.Contains(ToDeliveryKey(scope, serverHash));
        }
    }

    private void MarkDelivered(DurableInboxScope scope, string serverHash)
    {
        lock (deliveredItemsGate)
        {
            deliveredItems.Add(ToDeliveryKey(scope, serverHash));
        }
    }

    private void ForgetDelivered(DurableInboxScope scope, string serverHash)
    {
        lock (deliveredItemsGate)
        {
            deliveredItems.Remove(ToDeliveryKey(scope, serverHash));
        }
    }

    private void ForgetDelivered(DurableInboxScope scope)
    {
        lock (deliveredItemsGate)
        {
            deliveredItems.RemoveWhere(key =>
                string.Equals(key.AccountSessionId, scope.Account.Value, StringComparison.Ordinal)
                && key.Namespace == scope.Namespace);
        }
    }

    private static InboxDeliveryKey ToDeliveryKey(DurableInboxScope scope, string serverHash) =>
        new(scope.Account.Value, scope.Namespace, serverHash);

    private DecodedCandidate DecodeCandidate(
        SessionIdentityProvider identity,
        IAuthenticatedInboxTransport authenticatedTransport,
        DurableInboxItem item)
    {
        var entry = new DurableInboxWireEntry(
            item.ServerHash,
            item.StorageTimestamp,
            item.WirePayload,
            item.WireDigest);
        if (!authenticatedTransport.TryDecodeInboxEntry(entry, identity.SessionId, out var raw))
        {
            throw new E2eeProtocolException("Staged storage data is not a valid raw inbox entry.");
        }

        return DecodeCandidate(
            identity,
            raw,
            trustCiphertextSender: authenticatedTransport is IAuthenticatedOpaqueMailboxTransport);
    }

    private DecodedCandidate DecodeCandidate(
        SessionIdentityProvider identity,
        InboundMessageEnvelope raw,
        bool trustCiphertextSender = false)
    {
        if (raw is null || raw.Recipient != identity.SessionId || raw.Attachments is null || raw.Attachments.Count != 0 ||
            raw.ReplyTo is not null || raw.Reaction is not null || string.IsNullOrWhiteSpace(raw.ServerHash) ||
            raw.ServerHash.Length > MaxServerHashChars || !TryDecodeWireBody(raw.Body, out var envelope))
        {
            throw new E2eeProtocolException("Raw inbox entry is not a valid DPE1 wire blob.");
        }

        try
        {
            var decoded = identity.CreateEnvelopeCodec().DecryptContent(
                envelope,
                clock.UtcNow,
                E2eeContentCodec.DefaultMaxFutureSkew);
            if (!trustCiphertextSender &&
                raw.Sender != decoded.Envelope.Sender)
            {
                throw new E2eeProtocolException("Raw sender does not match the authenticated DPE1 sender.");
            }

            ValidateLocalSemanticBinding(decoded.Content, identity.SessionId);
            return new DecodedCandidate(decoded.Content, decoded.Envelope.EnvelopeDigestHex, raw.ServerHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    private static void ValidateLocalSemanticBinding(E2eeContent content, SessionId localSessionId)
    {
        if (content.Kind == E2eeContentKind.GroupState)
        {
            if (content.Recipient != localSessionId || content.GroupState is null)
            {
                throw new E2eeProtocolException("DMC1 group state is not addressed to the local account.");
            }

            return;
        }

        if (content.ConversationKind == ConversationKind.OneToOne)
        {
            if (content.Sender != localSessionId && content.Recipient != localSessionId)
            {
                throw new E2eeProtocolException("DMC1 direct message does not involve the local account.");
            }

            return;
        }

        if (content.ConversationKind != ConversationKind.GroupV2 || content.Recipient != localSessionId)
        {
            throw new E2eeProtocolException("DMC1 group message is not addressed to the local account.");
        }
    }

    private static DurableInboxDecodedMetadata CreateDecodedMetadata(E2eeContent content, string envelopeDigest) =>
        new(
            content.Kind == E2eeContentKind.GroupState
                ? DurableInboxItemKind.GroupState
                : content.ConversationKind == ConversationKind.OneToOne
                    ? DurableInboxItemKind.DirectMessage
                    : DurableInboxItemKind.GroupMessage,
            content.ConversationId.Value,
            content.Sender,
            content.MessageId,
            envelopeDigest,
            content.ProtocolExpiresAt);

    private static MessageId DeterministicMessageId(string scope, params string[] values)
    {
        var material = Encoding.UTF8.GetBytes(string.Join('\n', ["deep-message-id-v1", scope, .. values]));
        try
        {
            return new MessageId(Convert.ToHexStringLower(SHA256.HashData(material)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
        }
    }

    private static InboundMessageEnvelope ToDirectEnvelope(DecodedCandidate candidate)
    {
        var content = candidate.Content;
        return new InboundMessageEnvelope(
            content.MessageId,
            content.Sender,
            content.Recipient,
            content.Body,
            content.Attachments,
            content.IssuedAt,
            content.UserExpiresAt,
            candidate.ServerHash,
            content.Reply,
            content.Reaction);
    }

    private static InboundGroupStateEnvelope ToGroupStateEnvelope(DecodedCandidate candidate)
    {
        var content = candidate.Content;
        return new InboundGroupStateEnvelope(
            content.GroupState!,
            content.IssuedAt,
            candidate.ServerHash,
            content.Sender);
    }

    private static InboundGroupMessageEnvelope ToGroupMessageEnvelope(DecodedCandidate candidate)
    {
        var content = candidate.Content;
        return new InboundGroupMessageEnvelope(
            content.MessageId,
            content.ConversationId,
            content.Sender,
            content.Body,
            content.Attachments,
            content.IssuedAt,
            content.UserExpiresAt,
            candidate.ServerHash,
            content.Reply,
            content.Reaction);
    }

    private async Task PruneReplayClaimsIfNeededAsync(CancellationToken cancellationToken)
    {
        replayClaimsSincePrune++;
        var now = clock.UtcNow;
        if (lastReplayPruneAt is { } lastPrune &&
            replayClaimsSincePrune < ReplayClaimsPerPrune &&
            now - lastPrune < ReplayPruneInterval)
        {
            return;
        }

        await inboxRepository.PruneExpiredAsync(now, cancellationToken).ConfigureAwait(false);
        replayClaimsSincePrune = 0;
        lastReplayPruneAt = now;
    }

    private async Task<T> WithIdentityAsync<T>(
        Func<SessionIdentityProvider, T> operation,
        CancellationToken cancellationToken)
    {
        using var identityLease = await AcquireIdentityLeaseAsync(cancellationToken).ConfigureAwait(false);
        return operation(identityLease.Identity);
    }

    private async Task<T> WithIdentityAsync<T>(
        Func<SessionIdentityProvider, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        using var identityLease = await AcquireIdentityLeaseAsync(cancellationToken).ConfigureAwait(false);
        return await operation(identityLease.Identity).ConfigureAwait(false);
    }

    private async Task WithIdentityAsync(
        Func<SessionIdentityProvider, Task> operation,
        CancellationToken cancellationToken)
    {
        using var identityLease = await AcquireIdentityLeaseAsync(cancellationToken).ConfigureAwait(false);
        await operation(identityLease.Identity).ConfigureAwait(false);
    }

    private async Task WithMailboxOperationSignerAsync(
        Func<SessionIdentityProvider, IMailboxOperationSigner, Task> operation,
        CancellationToken cancellationToken)
    {
        using var identityLease = await AcquireIdentityLeaseAsync(cancellationToken).ConfigureAwait(false);
        using var signer = new MailboxOperationSignerLease(identityLease.Identity);
        await operation(identityLease.Identity, signer).ConfigureAwait(false);
    }

    private async Task<T> WithMailboxOperationSignerAsync<T>(
        Func<SessionIdentityProvider, IMailboxOperationSigner, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        using var identityLease = await AcquireIdentityLeaseAsync(cancellationToken).ConfigureAwait(false);
        using var signer = new MailboxOperationSignerLease(identityLease.Identity);
        return await operation(identityLease.Identity, signer).ConfigureAwait(false);
    }

    private async Task<IdentityLease> AcquireIdentityLeaseAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var phrase = await recoveryPhraseProvider(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(phrase))
        {
            throw new InvalidOperationException("An active recovery phrase is required for E2EE transport.");
        }

        var fingerprint = ComputePhraseFingerprint(phrase);
        IdentityCacheEntry? identityToDestroy = null;
        var identityChanged = false;
        try
        {
            lock (identityGate)
            {
                ThrowIfDisposed();
                if (cachedIdentity is null ||
                    !CryptographicOperations.FixedTimeEquals(cachedIdentity.PhraseFingerprint, fingerprint))
                {
                    var replacement = new IdentityCacheEntry(
                        new SessionIdentityProvider(phrase),
                        fingerprint.ToArray());
                    identityToDestroy = RetireIdentityEntry(cachedIdentity);
                    cachedIdentity = replacement;
                    identityChanged = true;
                }

                cachedIdentity.LeaseCount++;
                return new IdentityLease(this, cachedIdentity);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fingerprint);
            identityToDestroy?.Destroy();
            if (identityChanged)
            {
                lock (deliveredItemsGate)
                {
                    deliveredItems.Clear();
                }
            }
        }
    }

    private void ReleaseIdentity(IdentityCacheEntry entry)
    {
        IdentityCacheEntry? identityToDestroy;
        lock (identityGate)
        {
            if (entry.LeaseCount <= 0)
            {
                throw new InvalidOperationException("An E2EE identity lease was released more than once.");
            }

            entry.LeaseCount--;
            identityToDestroy = TryClaimIdentityForDestruction(entry);
        }

        identityToDestroy?.Destroy();
    }

    private static IdentityCacheEntry? RetireIdentityEntry(IdentityCacheEntry? entry)
    {
        if (entry is null)
        {
            return null;
        }

        entry.Retired = true;
        return TryClaimIdentityForDestruction(entry);
    }

    private static IdentityCacheEntry? TryClaimIdentityForDestruction(IdentityCacheEntry entry)
    {
        if (!entry.Retired || entry.LeaseCount != 0 || entry.DestructionClaimed)
        {
            return null;
        }

        entry.DestructionClaimed = true;
        return entry;
    }

    private static byte[] ComputePhraseFingerprint(string phrase)
    {
        var normalized = SessionIdentityMaterial.NormalizeRecoveryPhrase(phrase)
            .Normalize(NormalizationForm.FormKD);
        var bytes = Encoding.UTF8.GetBytes(normalized);
        try
        {
            return SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static DateTimeOffset GetProtocolExpiry(DateTimeOffset issuedAt, DateTimeOffset now)
    {
        DateTimeOffset latestIssueTime;
        DateTimeOffset protocolExpiresAt;
        try
        {
            latestIssueTime = now.Add(E2eeContentCodec.DefaultMaxFutureSkew);
            protocolExpiresAt = issuedAt.Add(E2eeContentCodec.MaxProtocolLifetime);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new ArgumentOutOfRangeException(
                nameof(issuedAt),
                issuedAt,
                $"The E2EE protocol timestamp is out of range: {exception.Message}");
        }

        if (issuedAt > latestIssueTime || protocolExpiresAt <= now)
        {
            throw new ArgumentOutOfRangeException(nameof(issuedAt), "The E2EE protocol timestamp is expired or too far in the future.");
        }

        return protocolExpiresAt;
    }

    private static void ValidateUserExpiry(
        DateTimeOffset? userExpiresAt,
        DateTimeOffset issuedAt,
        DateTimeOffset protocolExpiresAt,
        DateTimeOffset now)
    {
        if (userExpiresAt is { } expiry &&
            (expiry <= issuedAt || expiry > protocolExpiresAt || expiry <= now))
        {
            throw new ArgumentOutOfRangeException(
                nameof(userExpiresAt),
                "Message expiry must be active and contained within the 7-day protocol lifetime.");
        }
    }

    private static void EnsureLocalAccount(
        SessionIdentityProvider identity,
        SessionId expected,
        string parameterName)
    {
        if (identity.SessionId != expected)
        {
            throw new InvalidOperationException(
                $"The active recovery phrase does not match {parameterName}.");
        }
    }

    private static void EnsureCanonicalGroupId(ConversationId groupId, string parameterName)
    {
        var value = groupId.Value;
        if (value is null || value.Length != 66 || !value.StartsWith("03", StringComparison.Ordinal) ||
            value.Any(static character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException("A canonical group-v2 ID is required.", parameterName);
        }
    }

    private static string EncodeWireBody(ReadOnlySpan<byte> envelope) =>
        WireBodyPrefix + Convert.ToBase64String(envelope)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static bool TryDecodeWireBody(string? body, out byte[] envelope)
    {
        envelope = [];
        if (body is null || body.Length <= WireBodyPrefix.Length || body.Length > MaxWireBodyChars ||
            !body.StartsWith(WireBodyPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        var payload = body[WireBodyPrefix.Length..];
        if (payload.Any(char.IsWhiteSpace) || payload.Contains('=') && !payload.EndsWith("=", StringComparison.Ordinal))
        {
            return false;
        }

        var standard = payload.Replace('-', '+').Replace('_', '/');
        var remainder = standard.Length % 4;
        if (remainder == 1)
        {
            return false;
        }

        if (remainder != 0)
        {
            standard = standard.PadRight(standard.Length + (4 - remainder), '=');
        }

        try
        {
            envelope = Convert.FromBase64String(standard);
            return envelope.Length <= E2eeEnvelopeCodec.MaxEnvelopeBytes;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsRejectedWireEntry(Exception exception) =>
        exception is E2eeProtocolException or ArgumentException or FormatException or OverflowException;

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

    private sealed class MailboxOperationSignerLease(SessionIdentityProvider identity) :
        IMailboxOperationSigner,
        IDisposable
    {
        private SessionIdentityProvider? activeIdentity = identity;

        public SessionId SessionId => GetActiveIdentity().SessionId;

        public byte[] GetEd25519PublicKey() => GetActiveIdentity().GetEd25519PublicKey();

        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> canonicalPresentationSigningBytes)
        {
            var expectedTag = operation switch
            {
                MailboxAuthenticatedOperation.Store => "DEEP-MCP2-STR\0\0\0"u8,
                MailboxAuthenticatedOperation.Retrieve => "DEEP-MCP2-GET\0\0\0"u8,
                MailboxAuthenticatedOperation.Ack => "DEEP-MCP2-ACK\0\0\0"u8,
                _ => throw new ArgumentOutOfRangeException(nameof(operation))
            };
            var expectedLength = MailboxAuthenticatedCapabilityLimits.PresentationLength -
                MailboxAuthenticatedCapabilityLimits.SignatureLength + expectedTag.Length;
            if (canonicalPresentationSigningBytes.Length != expectedLength ||
                !CryptographicOperations.FixedTimeEquals(
                    canonicalPresentationSigningBytes[..expectedTag.Length],
                    expectedTag))
            {
                throw new ArgumentException(
                    "Mailbox signing requires the exact domain-separated MCP2 presentation transcript.",
                    nameof(canonicalPresentationSigningBytes));
            }

            return GetActiveIdentity().SignDetached(canonicalPresentationSigningBytes);
        }

        public void Dispose() => Interlocked.Exchange(ref activeIdentity, null);

        private SessionIdentityProvider GetActiveIdentity() =>
            Interlocked.CompareExchange(ref activeIdentity, null, null) ??
            throw new ObjectDisposedException(nameof(MailboxOperationSignerLease));
    }

    private sealed class IdentityLease(
        E2eeClientTransport owner,
        IdentityCacheEntry entry) : IDisposable
    {
        private IdentityCacheEntry? leasedEntry = entry;

        public SessionIdentityProvider Identity =>
            leasedEntry?.Identity ?? throw new ObjectDisposedException(nameof(IdentityLease));

        public void Dispose()
        {
            var releasedEntry = Interlocked.Exchange(ref leasedEntry, null);
            if (releasedEntry is not null)
            {
                owner.ReleaseIdentity(releasedEntry);
            }
        }
    }

    private sealed class IdentityCacheEntry(
        SessionIdentityProvider identity,
        byte[] phraseFingerprint)
    {
        public SessionIdentityProvider Identity { get; } = identity;

        public byte[] PhraseFingerprint { get; } = phraseFingerprint;

        public int LeaseCount { get; set; }

        public bool Retired { get; set; }

        public bool DestructionClaimed { get; set; }

        public void Destroy()
        {
            try
            {
                Identity.Dispose();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(PhraseFingerprint);
            }
        }
    }

    private sealed record DecodedCandidate(
        E2eeContent Content,
        string EnvelopeDigest,
        string ServerHash);

    private sealed record WireCopyPlan(
        E2eeContent Content,
        SessionId Target,
        DateTimeOffset WireCreatedAt)
    {
        public MessageId WireMessageId { get; } =
            DeterministicMessageId("wire", Content.MessageId.Value, Target.Value);

        public OutboundMessageEnvelope RoutingEnvelope { get; } = new(
            Content.Sender,
            Target,
            string.Empty,
            [],
            WireCreatedAt,
            Content.ProtocolExpiresAt,
            DeterministicMessageId("wire", Content.MessageId.Value, Target.Value));
    }

    private sealed record InboxDeliveryKey(string AccountSessionId, int Namespace, string ServerHash);
}
