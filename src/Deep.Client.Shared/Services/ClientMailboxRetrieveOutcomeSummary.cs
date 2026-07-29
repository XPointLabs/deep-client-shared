using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

internal sealed class ClientMailboxRetrieveOutcomeSummary
{
    private const int FixedLength = 92;
    private const byte Version = 1;
    private const byte HasMoreFlag = 1;
    private static ReadOnlySpan<byte> Domain => "MRSO"u8;

    private readonly byte[] operationId;
    private readonly byte[] responseDigest;
    private readonly byte[] continuationToken;

    private ClientMailboxRetrieveOutcomeSummary(
        ulong epoch,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> responseDigest,
        ulong requestAfterCursor,
        ulong responseNextCursor,
        ulong resultAfterCursor,
        bool hasMore,
        ushort itemCount,
        ReadOnlySpan<byte> continuationToken)
    {
        Epoch = epoch;
        this.operationId = operationId.ToArray();
        this.responseDigest = responseDigest.ToArray();
        RequestAfterCursor = requestAfterCursor;
        ResponseNextCursor = responseNextCursor;
        ResultAfterCursor = resultAfterCursor;
        HasMore = hasMore;
        ItemCount = itemCount;
        this.continuationToken = continuationToken.ToArray();
    }

    public ulong Epoch { get; }
    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public ReadOnlyMemory<byte> ResponseDigest => responseDigest.ToArray();
    public ulong RequestAfterCursor { get; }
    public ulong ResponseNextCursor { get; }
    public ulong ResultAfterCursor { get; }
    public bool HasMore { get; }
    public ushort ItemCount { get; }
    public ReadOnlyMemory<byte> ContinuationToken => continuationToken.ToArray();

    public static byte[] Encode(
        MailboxAuthenticatedRetrieveBody request,
        MailboxRetrievePage page,
        ReadOnlySpan<byte> canonicalMrp1)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(page);
        if (page.Epoch != request.Epoch ||
            !FixedEquals(page.OperationId.Span, request.OperationId.Span) ||
            page.Items.Count > MailboxClientLimits.MaximumPageItems ||
            page.ContinuationToken.Length >
                MailboxClientLimits.MaximumContinuationTokenLength)
        {
            throw new InvalidDataException(
                "MRP1 cannot be summarized for the authenticated retrieve operation.");
        }

        var resultAfterCursor = page.HasMore ? page.NextCursor : 0UL;
        var resultToken = page.HasMore
            ? page.ContinuationToken.Span
            : ReadOnlySpan<byte>.Empty;
        if (page.HasMore != !resultToken.IsEmpty ||
            page.HasMore && resultAfterCursor == 0)
        {
            throw new InvalidDataException(
                "MRP1 continuation authority is invalid.");
        }

        var encoded = new byte[checked(FixedLength + resultToken.Length)];
        Domain.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = page.HasMore ? HasMoreFlag : (byte)0;
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(6, 2),
            checked((ushort)resultToken.Length));
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), request.Epoch);
        request.OperationId.Span.CopyTo(encoded.AsSpan(16, 16));
        SHA256.HashData(canonicalMrp1).CopyTo(encoded.AsSpan(32, 32));
        BinaryPrimitives.WriteUInt64BigEndian(
            encoded.AsSpan(64, 8),
            request.AfterCursor);
        BinaryPrimitives.WriteUInt64BigEndian(
            encoded.AsSpan(72, 8),
            page.NextCursor);
        BinaryPrimitives.WriteUInt64BigEndian(
            encoded.AsSpan(80, 8),
            resultAfterCursor);
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(88, 2),
            checked((ushort)page.Items.Count));
        resultToken.CopyTo(encoded.AsSpan(FixedLength));
        return encoded;
    }

    public static ClientMailboxRetrieveOutcomeSummary DecodeAndValidate(
        ReadOnlySpan<byte> encoded,
        MailboxAuthenticatedRetrieveBody request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (encoded.Length < FixedLength ||
            !encoded[..4].SequenceEqual(Domain) ||
            encoded[4] != Version ||
            (encoded[5] & ~HasMoreFlag) != 0 ||
            encoded[90] != 0 ||
            encoded[91] != 0)
        {
            throw new InvalidDataException(
                "Retrieve outcome summary domain or version is invalid.");
        }

        var tokenLength = BinaryPrimitives.ReadUInt16BigEndian(
            encoded.Slice(6, 2));
        if (tokenLength > MailboxClientLimits.MaximumContinuationTokenLength ||
            encoded.Length != FixedLength + tokenLength)
        {
            throw new InvalidDataException(
                "Retrieve outcome summary length is invalid.");
        }

        var epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8));
        var operationId = encoded.Slice(16, 16);
        var requestAfterCursor = BinaryPrimitives.ReadUInt64BigEndian(
            encoded.Slice(64, 8));
        var responseNextCursor = BinaryPrimitives.ReadUInt64BigEndian(
            encoded.Slice(72, 8));
        var resultAfterCursor = BinaryPrimitives.ReadUInt64BigEndian(
            encoded.Slice(80, 8));
        var itemCount = BinaryPrimitives.ReadUInt16BigEndian(
            encoded.Slice(88, 2));
        var hasMore = (encoded[5] & HasMoreFlag) != 0;
        var token = encoded[FixedLength..];
        if (epoch != request.Epoch ||
            !FixedEquals(operationId, request.OperationId.Span) ||
            requestAfterCursor != request.AfterCursor ||
            itemCount > MailboxClientLimits.MaximumPageItems ||
            hasMore != !token.IsEmpty ||
            (hasMore
                ? resultAfterCursor == 0 ||
                  resultAfterCursor != responseNextCursor
                : resultAfterCursor != 0 ||
                  !token.IsEmpty))
        {
            throw new InvalidDataException(
                "Retrieve outcome summary equivocated from persisted MAU2.");
        }

        return new ClientMailboxRetrieveOutcomeSummary(
            epoch,
            operationId,
            encoded.Slice(32, SHA256.HashSizeInBytes),
            requestAfterCursor,
            responseNextCursor,
            resultAfterCursor,
            hasMore,
            itemCount,
            token);
    }

    private static bool FixedEquals(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
