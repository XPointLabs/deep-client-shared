using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.MessagingV1;

// Positive historical native processing, not a current mailbox route, user
// message, AppAck or transport ACK. No raw or synthetic positive constructor.
internal sealed class AuthenticatedPeerRouteUpdateDmc2 : IAuthenticatedDmc2InboxEvent, IDisposable
{
    private readonly byte[] exact, local, conversation, logical, author, device;
    private int disposed;
    private AuthenticatedPeerRouteUpdateDmc2(ReadOnlySpan<byte> exact, Did2MessagingSessionScope scope)
    {
        if (exact.Length is < 4497 or > 23649)
            throw new InvalidDataException("Peer route control exceeds its closed record bound.");
        var message = ApplicationCoreCodec.DecodeDmc2(exact);
        try
        {
            if (message.ContentKind != Dmc2ContentKind.ContactRouteUpdate ||
                message.ParsedPayload is not ContactRouteUpdateDmc2Payload update ||
                message.Flags != Dmc2Flags.None || message.ReplyToLogicalMessageId.Length != 0 ||
                message.ExpiresAtUnixMilliseconds == 0 || message.SenderClientSequence < (scope.IsInitiator ? 4UL : 3UL) ||
                !Fixed(message.CanonicalBytes.Span, exact) || !Fixed(message.NetworkId.Span, scope.Network) ||
                !Fixed(message.ConversationId.Span, scope.Conversation) || !Fixed(update.RelationshipId.Span, scope.Relationship) ||
                !Fixed(message.SenderAccountId.Span, scope.RemoteAccount) || !Fixed(message.SenderDeviceId.Span, scope.RemoteDevice))
                throw new CryptographicException("Peer route control differs from its verified native receive scope.");
            this.exact = exact.ToArray(); local = scope.LocalAccount.ToArray(); conversation = message.ConversationId.ToArray();
            logical = message.LogicalMessageId.ToArray(); author = message.SenderAccountId.ToArray(); device = message.SenderDeviceId.ToArray();
            LocalAccountGeneration = BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]);
        }
        finally { if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
    }

    public ReadOnlyMemory<byte> ExactDmc2 => Copy(exact);
    public ReadOnlyMemory<byte> LocalAccountId => Copy(local);
    public ulong LocalAccountGeneration { get; }
    public ReadOnlyMemory<byte> ConversationId => Copy(conversation);
    public ReadOnlyMemory<byte> LogicalMessageId => Copy(logical);
    public ReadOnlyMemory<byte> AuthorAccountId => Copy(author);
    public ReadOnlyMemory<byte> AuthorDeviceId => Copy(device);
    public Dmc2ContentKind ContentKind => Dmc2ContentKind.ContactRouteUpdate;

    internal static async Task<AuthenticatedPeerRouteUpdateDmc2> FromOwnedCommitAsync(
        ProtectedDeepIdV2AccountOwner owner, VerifiedDeepIdV2CurrentAccount account,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(owner); ArgumentNullException.ThrowIfNull(opened);
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var op = operation.ToArray(); byte[] exact = [];
        try
        {
            exact = await owner.ReadVerifiedPeerRouteControlCommitUnderLeaseAsync(account, held, opened,
                op, own, peer, source, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return new(exact, opened.Scope);
        }
        finally { CryptographicOperations.ZeroMemory(op); CryptographicOperations.ZeroMemory(exact); }
    }
    private ReadOnlyMemory<byte> Copy(byte[] value)
    { ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this); return value.ToArray(); }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var value in new[] { exact, local, conversation, logical, author, device }) CryptographicOperations.ZeroMemory(value);
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);
}
