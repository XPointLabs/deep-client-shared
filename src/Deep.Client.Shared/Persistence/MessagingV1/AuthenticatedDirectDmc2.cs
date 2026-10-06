using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;
using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Persistence.MessagingV1;

/// <summary>
/// Account-owned handoff from a committed direct DPE2 receive. Construction
/// requires the verified local and remote session scope; canonical bytes alone
/// are not proof of E2EE authentication. This type never grants mailbox ACK.
/// </summary>
internal sealed class AuthenticatedDirectDmc2 : IDisposable, IAuthenticatedDmc2InboxEvent
{
    private readonly byte[] exactDmc2;
    private readonly byte[] localAccountId;
    private readonly byte[] localDeviceId;
    private readonly byte[] conversationId;
    private readonly byte[] logicalMessageId;
    private readonly byte[] authorAccountId;
    private readonly byte[] authorDeviceId;
    private readonly byte[] operationId;
    private readonly byte[] exactEnvelopeHash;
    private int disposed;

    private AuthenticatedDirectDmc2(
        ReadOnlySpan<byte> authenticatedDmc2,
        ReadOnlySpan<byte> expectedNetworkId,
        ReadOnlySpan<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlySpan<byte> localDeviceId,
        ReadOnlySpan<byte> expectedConversationId,
        ReadOnlySpan<byte> expectedAuthorAccountId,
        ReadOnlySpan<byte> expectedAuthorDeviceId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactEnvelopeHash)
    {
        Require32(localAccountId, nameof(localAccountId));
        Require32(localDeviceId, nameof(localDeviceId));
        Require32(operationId, nameof(operationId));
        Require32(exactEnvelopeHash, nameof(exactEnvelopeHash));
        if (expectedNetworkId.Length != 16 ||
            expectedNetworkId.IndexOfAnyExcept((byte)0) < 0 ||
            localAccountGeneration == 0)
            throw new CryptographicException("The direct inbox local scope is invalid.");

        var parsed = ApplicationCoreCodec.DecodeDmc2(authenticatedDmc2);
        var canonical = parsed.CanonicalBytes.ToArray();
        try
        {
            if (!Fixed(canonical, authenticatedDmc2) ||
                !Fixed(parsed.NetworkId.Span, expectedNetworkId) ||
                !Fixed(parsed.ConversationId.Span, expectedConversationId) ||
                !Fixed(parsed.SenderAccountId.Span, expectedAuthorAccountId) ||
                !Fixed(parsed.SenderDeviceId.Span, expectedAuthorDeviceId) ||
                !IsDirectKind(parsed.ContentKind) || parsed.SenderClientSequence < 3)
                throw new CryptographicException(
                    "The authenticated DMC2 is not a direct event in the verified session scope.");

            exactDmc2 = authenticatedDmc2.ToArray();
            this.localAccountId = localAccountId.ToArray();
            this.localDeviceId = localDeviceId.ToArray();
            LocalAccountGeneration = localAccountGeneration;
            conversationId = parsed.ConversationId.ToArray();
            logicalMessageId = parsed.LogicalMessageId.ToArray();
            authorAccountId = parsed.SenderAccountId.ToArray();
            authorDeviceId = parsed.SenderDeviceId.ToArray();
            this.operationId = operationId.ToArray();
            this.exactEnvelopeHash = exactEnvelopeHash.ToArray();
            ContentKind = parsed.ContentKind;
        }
        finally
        {
            if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose();
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    internal ulong LocalAccountGeneration { get; }
    internal Dmc2ContentKind ContentKind { get; }
    internal ReadOnlyMemory<byte> ExactDmc2 => Copy(exactDmc2);
    internal ReadOnlyMemory<byte> LocalAccountId => Copy(localAccountId);
    internal ReadOnlyMemory<byte> LocalDeviceId => Copy(localDeviceId);
    internal ReadOnlyMemory<byte> ConversationId => Copy(conversationId);
    internal ReadOnlyMemory<byte> LogicalMessageId => Copy(logicalMessageId);
    internal ReadOnlyMemory<byte> AuthorAccountId => Copy(authorAccountId);
    internal ReadOnlyMemory<byte> AuthorDeviceId => Copy(authorDeviceId);
    internal ReadOnlyMemory<byte> OperationId => Copy(operationId);
    internal ReadOnlyMemory<byte> ExactEnvelopeHash => Copy(exactEnvelopeHash);
    ReadOnlyMemory<byte> IAuthenticatedDmc2InboxEvent.ExactDmc2 => ExactDmc2;
    ReadOnlyMemory<byte> IAuthenticatedDmc2InboxEvent.LocalAccountId => LocalAccountId;
    ulong IAuthenticatedDmc2InboxEvent.LocalAccountGeneration => LocalAccountGeneration;
    ReadOnlyMemory<byte> IAuthenticatedDmc2InboxEvent.ConversationId => ConversationId;
    ReadOnlyMemory<byte> IAuthenticatedDmc2InboxEvent.LogicalMessageId => LogicalMessageId;
    ReadOnlyMemory<byte> IAuthenticatedDmc2InboxEvent.AuthorAccountId => AuthorAccountId;
    ReadOnlyMemory<byte> IAuthenticatedDmc2InboxEvent.AuthorDeviceId => AuthorDeviceId;
    Dmc2ContentKind IAuthenticatedDmc2InboxEvent.ContentKind => ContentKind;

    internal static AuthenticatedDirectDmc2 FromOwnedDid2Commit(
        OwnedDid2MessagingStorage opened, Did2MessagingFloor floor,
        ReadOnlySpan<byte> operation, ReadOnlySpan<byte> localSendDmc2)
    {
        var scope = opened.Scope;
        using var retained = opened.Sql.ReadVerifiedOperation(floor, operation) ??
            throw new CryptographicException("DID2 semantic handoff has no actual committed event.");
        var send = retained.Direction == 1;
        using var owned = send ? new OwnedDeepSecret(localSendDmc2) : retained.OwnAuthenticatedDmc2();
        var op = operation.ToArray();
        try
        {
            return owned.Use(exact =>
            {
                if (!Fixed(SHA256.HashData(exact), retained.EventHash))
                    throw new CryptographicException("DID2 semantic handoff differs from the committed event hash.");
                return new AuthenticatedDirectDmc2(exact, scope.Network, scope.LocalAccount,
                    BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope.LocalDevice, scope.Conversation,
                    send ? scope.LocalAccount : scope.RemoteAccount,
                    send ? scope.LocalDevice : scope.RemoteDevice, op, retained.EnvelopeHash);
            });
        }
        finally { CryptographicOperations.ZeroMemory(op); }
    }

    internal static async ValueTask<AuthenticatedDirectDmc2?> FromCommittedStageAsync(
        SqliteMessagingCryptoV1Store store,
        ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> exactEnvelopeHash,
        ReadOnlyMemory<byte> expectedNetworkId,
        ReadOnlyMemory<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlyMemory<byte> localDeviceId,
        ReadOnlyMemory<byte> expectedConversationId,
        ReadOnlyMemory<byte> expectedAuthorAccountId,
        ReadOnlyMemory<byte> expectedAuthorDeviceId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        store.RequireInboundMaterializationScope(localAccountId.Span,
            localAccountGeneration, localDeviceId.Span, expectedConversationId.Span);
        var staged = await store.ReadPendingInboundDmc2Async(
                operationId, exactEnvelopeHash, cancellationToken)
            .ConfigureAwait(false);
        if (staged is null) return null;
        try
        {
            return new AuthenticatedDirectDmc2(
                staged, expectedNetworkId.Span, localAccountId.Span,
                localAccountGeneration, localDeviceId.Span, expectedConversationId.Span,
                expectedAuthorAccountId.Span, expectedAuthorDeviceId.Span,
                operationId.Span, exactEnvelopeHash.Span);
        }
        finally { CryptographicOperations.ZeroMemory(staged); }
    }

#if DEEP_TEST_INTERNALS
    internal static AuthenticatedDirectDmc2 CreateForTests(
        ReadOnlySpan<byte> authenticatedDmc2,
        ReadOnlySpan<byte> expectedNetworkId,
        ReadOnlySpan<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlySpan<byte> localDeviceId,
        ReadOnlySpan<byte> expectedConversationId,
        ReadOnlySpan<byte> expectedAuthorAccountId,
        ReadOnlySpan<byte> expectedAuthorDeviceId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactEnvelopeHash) => new(
            authenticatedDmc2, expectedNetworkId, localAccountId,
            localAccountGeneration, localDeviceId, expectedConversationId,
            expectedAuthorAccountId, expectedAuthorDeviceId,
            operationId, exactEnvelopeHash);
#endif

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var value in new[] { exactDmc2, localAccountId, localDeviceId, conversationId,
                     logicalMessageId, authorAccountId, authorDeviceId, operationId,
                     exactEnvelopeHash })
            CryptographicOperations.ZeroMemory(value);
    }

    private ReadOnlyMemory<byte> Copy(byte[] value)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return value.ToArray();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void Require32(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte identifier is required.", name);
    }

    internal static bool IsDirectKind(Dmc2ContentKind kind) => kind is
        Dmc2ContentKind.MessageCreate or Dmc2ContentKind.MessageEdit or
        Dmc2ContentKind.MessageDelete or Dmc2ContentKind.ReactionSet or
        Dmc2ContentKind.ReceiptDelivered or Dmc2ContentKind.ReceiptRead or
        Dmc2ContentKind.AttachmentOffer or Dmc2ContentKind.AttachmentCancel;
}

internal enum DirectDmc2InboxDisposition
{
    Materialized = 1,
    ExactReplay = 2,
    ForkLatched = 3,
    CapacityExceeded = 4,
}
