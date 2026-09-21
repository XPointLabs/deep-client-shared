using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.MessagingV1;

/// <summary>
/// The exact initial DPH2 events recovered from the committed SQLCipher
/// session stage. This capability grants inbox materialization, never ACK.
/// </summary>
internal sealed class AuthenticatedInitialDmc2Batch : IDisposable
{
    private readonly byte[] sessionInit;
    private readonly byte[]? firstApplication;
    private readonly byte[] localAccountId;
    private readonly byte[] conversationId;
    private int disposed;

    private AuthenticatedInitialDmc2Batch(
        ReadOnlySpan<byte> exactSessionInit,
        ReadOnlySpan<byte> exactFirstApplication,
        ReadOnlySpan<byte> expectedNetworkId,
        ReadOnlySpan<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlySpan<byte> expectedConversationId,
        ReadOnlySpan<byte> expectedAuthorAccountId,
        ReadOnlySpan<byte> expectedAuthorDeviceId,
        ReadOnlySpan<byte> expectedRelationshipId,
        ReadOnlySpan<byte> expectedAuthorDab1Hash,
        ReadOnlySpan<byte> expectedAuthorDmd1Hash)
    {
        if (expectedNetworkId.Length != 16 || localAccountId.Length != 32 ||
            expectedConversationId.Length != 32 ||
            expectedAuthorAccountId.Length != 32 || expectedAuthorDeviceId.Length != 32 ||
            expectedRelationshipId.Length != 32 || expectedAuthorDab1Hash.Length != 32 ||
            expectedAuthorDmd1Hash.Length != 32 ||
            localAccountGeneration == 0)
            throw new CryptographicException("The initial inbox scope is invalid.");
        var session = ApplicationCoreCodec.DecodeDmc2(exactSessionInit);
        if (session.ContentKind != Dmc2ContentKind.SessionInit ||
            !Fixed(session.CanonicalBytes.Span, exactSessionInit) ||
            !MatchesScope(session, expectedNetworkId, expectedConversationId,
                expectedAuthorAccountId, expectedAuthorDeviceId))
            throw new CryptographicException(
                "The staged SessionInit is outside the verified initial session.");
        if (!exactFirstApplication.IsEmpty)
        {
            var first = ApplicationCoreCodec.DecodeDmc2(exactFirstApplication);
            if (!Fixed(first.CanonicalBytes.Span, exactFirstApplication) ||
                !MatchesScope(first, expectedNetworkId, expectedConversationId,
                    expectedAuthorAccountId, expectedAuthorDeviceId) ||
                !IsSupportedInitialApplicationKind(first.ContentKind) ||
                Fixed(first.LogicalMessageId.Span, session.LogicalMessageId.Span) ||
                first.SenderClientSequence <= session.SenderClientSequence ||
                first.CreatedAtUnixMilliseconds < session.CreatedAtUnixMilliseconds)
                throw new CryptographicException(
                    "The first staged DMC2 is not a supported direct initial event.");
            if (first.ContentKind == Dmc2ContentKind.ContactHello &&
                !MatchesContactHello(first.PayloadBytes.Span, session.PayloadBytes.Span,
                    first.CreatedAtUnixMilliseconds, expectedNetworkId,
                    localAccountId, expectedAuthorAccountId,
                    expectedConversationId, expectedAuthorDeviceId, expectedRelationshipId,
                    expectedAuthorDab1Hash, expectedAuthorDmd1Hash))
                throw new CryptographicException(
                    "The authenticated ContactHello differs from the verified peer closure.");
        }
        this.sessionInit = exactSessionInit.ToArray();
        firstApplication = exactFirstApplication.IsEmpty ? null : exactFirstApplication.ToArray();
        this.localAccountId = localAccountId.ToArray();
        LocalAccountGeneration = localAccountGeneration;
        conversationId = expectedConversationId.ToArray();
    }

    internal byte[] SessionInitDmc2 => Copy(sessionInit);
    internal byte[] FirstApplicationDmc2
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            return firstApplication is null ? [] : Copy(firstApplication);
        }
    }
    internal byte[] LocalAccountId => Copy(localAccountId);
    internal ulong LocalAccountGeneration { get; }
    internal ReadOnlyMemory<byte> ConversationId => Copy(conversationId);
    internal int EventCount => firstApplication is null ? 1 : 2;

    internal static async ValueTask<AuthenticatedInitialDmc2Batch?> FromCommittedStageAsync(
        SqliteMessagingCryptoV1Store store,
        ReadOnlyMemory<byte> claimOperationId,
        ReadOnlyMemory<byte> dph2FullReplayHash,
        ReadOnlyMemory<byte> expectedNetworkId,
        ReadOnlyMemory<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlyMemory<byte> expectedConversationId,
        ReadOnlyMemory<byte> expectedAuthorAccountId,
        ReadOnlyMemory<byte> expectedAuthorDeviceId,
        ReadOnlyMemory<byte> expectedRelationshipId,
        ReadOnlyMemory<byte> expectedAuthorDab1Hash,
        ReadOnlyMemory<byte> expectedAuthorDmd1Hash,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        store.RequireInboundMaterializationScope(
            localAccountId.Span, localAccountGeneration, expectedConversationId.Span);
        var staged = await store.ReadPendingInitialDmc2Async(
                claimOperationId, dph2FullReplayHash, cancellationToken)
            .ConfigureAwait(false);
        if (staged is null) return null;
        try
        {
            return new AuthenticatedInitialDmc2Batch(
                staged.Value.SessionInit, staged.Value.FirstApplication ?? [],
                expectedNetworkId.Span, localAccountId.Span,
                localAccountGeneration, expectedConversationId.Span,
                expectedAuthorAccountId.Span, expectedAuthorDeviceId.Span,
                expectedRelationshipId.Span, expectedAuthorDab1Hash.Span,
                expectedAuthorDmd1Hash.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(staged.Value.SessionInit);
            if (staged.Value.FirstApplication is { } first)
                CryptographicOperations.ZeroMemory(first);
        }
    }

    internal static async ValueTask<AuthenticatedInitialDmc2Batch?>
        FromCommittedVerifiedInitialStageAsync(
            SqliteMessagingCryptoV1Store store,
            VerifiedDph2InitialClaim verifiedInitial,
            Deep.Client.Shared.Services.MessagingV1.DeepDirectMessagingVerifiedSessionBinding session,
            ReadOnlyMemory<byte> localAccountId,
            ulong localAccountGeneration,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(verifiedInitial);
        ArgumentNullException.ThrowIfNull(session);
        var checkpoint = verifiedInitial.InitiatorCheckpoint ??
            throw new CryptographicException(
                "Initial inbox materialization requires the verified initiator checkpoint.");
        var initiation = verifiedInitial.Initiation;
        var dph2 = Dph2Codec.Decode(initiation.ExactBytes.Span);
        store.RequireInboundMaterializationScope(
            localAccountId.Span, localAccountGeneration, session.ConversationId.Span);
        var staged = await store.ReadPendingInitialDmc2Async(
                initiation.ClaimOperationId,
                initiation.FullReplayHash,
                cancellationToken)
            .ConfigureAwait(false);
        if (staged is null)
            return null;
        try
        {
            if (staged.Value.FirstApplication is not { Length: > 0 } firstExact)
                throw new CryptographicException(
                    "An unsolicited initial session has no authenticated ContactHello.");
            var hello = ApplicationCoreCodec.DecodeDmc2(firstExact);
            if (hello.ContentKind != Dmc2ContentKind.ContactHello ||
                hello.PayloadBytes.Length < 32)
                throw new CryptographicException(
                    "The first unsolicited application event is not ContactHello.");
            var relationshipId = hello.PayloadBytes.Slice(0, 32);
            return new AuthenticatedInitialDmc2Batch(
                staged.Value.SessionInit,
                firstExact,
                dph2.NetworkId.Span,
                localAccountId.Span,
                localAccountGeneration,
                session.ConversationId.Span,
                dph2.InitiatorAccountId.Span,
                dph2.InitiatorDeviceId.Span,
                relationshipId.Span,
                checkpoint.Binding.Record.RecordHash.Span,
                checkpoint.Directory.Record.RecordHash.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(staged.Value.SessionInit);
            if (staged.Value.FirstApplication is { } first)
                CryptographicOperations.ZeroMemory(first);
        }
    }

    internal static bool IsSupportedInitialApplicationKind(Dmc2ContentKind kind) =>
        kind == Dmc2ContentKind.ContactHello || AuthenticatedDirectDmc2.IsDirectKind(kind);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        CryptographicOperations.ZeroMemory(sessionInit);
        if (firstApplication is not null) CryptographicOperations.ZeroMemory(firstApplication);
        CryptographicOperations.ZeroMemory(localAccountId);
        CryptographicOperations.ZeroMemory(conversationId);
    }

    private byte[] Copy(byte[] value)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return value.ToArray();
    }

    private static bool MatchesScope(
        ParsedDmc2 record,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> conversation,
        ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> device) =>
        Fixed(record.NetworkId.Span, network) &&
        Fixed(record.ConversationId.Span, conversation) &&
        Fixed(record.SenderAccountId.Span, account) &&
        Fixed(record.SenderDeviceId.Span, device);

    private static bool MatchesContactHello(
        ReadOnlySpan<byte> hello,
        ReadOnlySpan<byte> session,
        ulong createdAtUnixMilliseconds,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> localAccount,
        ReadOnlySpan<byte> authorAccount,
        ReadOnlySpan<byte> conversation,
        ReadOnlySpan<byte> senderDevice,
        ReadOnlySpan<byte> relationship,
        ReadOnlySpan<byte> dab1Hash,
        ReadOnlySpan<byte> dmd1Hash)
    {
        // Both payloads have already passed the canonical DMC2 codec. Read only
        // their frozen kind-specific fields; CONTACT-CODEC emission is inactive
        // and this check must not create a second authoring path.
        if (hello.Length != 678 || session.Length < 72 ||
            !Fixed(hello[..32], relationship) ||
            !Fixed(hello.Slice(38, 32), dab1Hash) ||
            !Fixed(hello.Slice(70, 32), dmd1Hash) ||
            !Fixed(session.Slice(32, 32), dmd1Hash))
            return false;
        if (Fixed(localAccount, authorAccount)) return false;
        var derivedConversation = ContactConversationId32.Derive(
            network, ContactRelationshipId32.FromBytes(relationship),
            localAccount, authorAccount);
        if (!Fixed(derivedConversation.ToArray(), conversation)) return false;
        var directoryLength = BinaryPrimitives.ReadUInt32BigEndian(session.Slice(64, 4));
        if (directoryLength != session.Length - 72) return false;
        var directory = ApplicationCoreCodec.DecodeDmd1(
            session.Slice(68, checked((int)directoryLength)));
        DeviceDirectoryEntry? device = null;
        foreach (var entry in directory.ActiveDevices)
        {
            if (!Fixed(entry.DeviceId.Span, senderDevice)) continue;
            device = entry;
            break;
        }
        if (device is null) return false;
        var xur = ContactCodec.Decode("XUR1", hello.Slice(140, 538));
        var issued = BinaryPrimitives.ReadUInt64BigEndian(xur.Field(11).Span);
        var expires = BinaryPrimitives.ReadUInt64BigEndian(xur.Field(12).Span);
        var createdSeconds = createdAtUnixMilliseconds / 1_000;
        return Fixed(xur.Field(1).Span, network) &&
               Fixed(xur.Field(13).Span, senderDevice) &&
               Fixed(xur.Field(14).Span[6..], device.Dpd1Reference.CanonicalHash.Span) &&
               createdSeconds >= issued && createdSeconds < expires;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
