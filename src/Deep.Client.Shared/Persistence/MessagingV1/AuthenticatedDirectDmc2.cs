using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.MessagingV1;

/// <summary>
/// Account-owned handoff from a committed direct DPE2 receive. Construction
/// requires the verified local and remote session scope; canonical bytes alone
/// are not proof of E2EE authentication. This type never grants mailbox ACK.
/// </summary>
internal sealed class AuthenticatedDirectDmc2 : IDisposable
{
    private readonly byte[] exactDmc2;
    private readonly byte[] localAccountId;
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
        ReadOnlySpan<byte> expectedConversationId,
        ReadOnlySpan<byte> expectedAuthorAccountId,
        ReadOnlySpan<byte> expectedAuthorDeviceId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactEnvelopeHash)
    {
        Require32(localAccountId, nameof(localAccountId));
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
                !IsDirectKind(parsed.ContentKind))
                throw new CryptographicException(
                    "The authenticated DMC2 is not a direct event in the verified session scope.");

            exactDmc2 = authenticatedDmc2.ToArray();
            this.localAccountId = localAccountId.ToArray();
            LocalAccountGeneration = localAccountGeneration;
            conversationId = parsed.ConversationId.ToArray();
            logicalMessageId = parsed.LogicalMessageId.ToArray();
            authorAccountId = parsed.SenderAccountId.ToArray();
            authorDeviceId = parsed.SenderDeviceId.ToArray();
            this.operationId = operationId.ToArray();
            this.exactEnvelopeHash = exactEnvelopeHash.ToArray();
            ContentKind = parsed.ContentKind;
        }
        finally { CryptographicOperations.ZeroMemory(canonical); }
    }

    internal ulong LocalAccountGeneration { get; }
    internal Dmc2ContentKind ContentKind { get; }
    internal ReadOnlyMemory<byte> ExactDmc2 => Copy(exactDmc2);
    internal ReadOnlyMemory<byte> LocalAccountId => Copy(localAccountId);
    internal ReadOnlyMemory<byte> ConversationId => Copy(conversationId);
    internal ReadOnlyMemory<byte> LogicalMessageId => Copy(logicalMessageId);
    internal ReadOnlyMemory<byte> AuthorAccountId => Copy(authorAccountId);
    internal ReadOnlyMemory<byte> AuthorDeviceId => Copy(authorDeviceId);
    internal ReadOnlyMemory<byte> OperationId => Copy(operationId);
    internal ReadOnlyMemory<byte> ExactEnvelopeHash => Copy(exactEnvelopeHash);

    internal static async ValueTask<AuthenticatedDirectDmc2?> FromCommittedStageAsync(
        SqliteMessagingCryptoV1Store store,
        ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> exactEnvelopeHash,
        ReadOnlyMemory<byte> expectedNetworkId,
        ReadOnlyMemory<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlyMemory<byte> expectedConversationId,
        ReadOnlyMemory<byte> expectedAuthorAccountId,
        ReadOnlyMemory<byte> expectedAuthorDeviceId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        store.RequireInboundMaterializationScope(localAccountId.Span,
            localAccountGeneration, expectedConversationId.Span);
        var staged = await store.ReadPendingInboundDmc2Async(
                operationId, exactEnvelopeHash, cancellationToken)
            .ConfigureAwait(false);
        if (staged is null) return null;
        try
        {
            return new AuthenticatedDirectDmc2(
                staged, expectedNetworkId.Span, localAccountId.Span,
                localAccountGeneration, expectedConversationId.Span,
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
        ReadOnlySpan<byte> expectedConversationId,
        ReadOnlySpan<byte> expectedAuthorAccountId,
        ReadOnlySpan<byte> expectedAuthorDeviceId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactEnvelopeHash) => new(
            authenticatedDmc2, expectedNetworkId, localAccountId,
            localAccountGeneration, expectedConversationId,
            expectedAuthorAccountId, expectedAuthorDeviceId,
            operationId, exactEnvelopeHash);
#endif

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var value in new[] { exactDmc2, localAccountId, conversationId,
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
