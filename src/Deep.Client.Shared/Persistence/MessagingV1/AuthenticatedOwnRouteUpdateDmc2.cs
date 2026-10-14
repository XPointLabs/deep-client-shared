using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.MessagingV1;

// Historical own-control custody only. No current route, incoming acceptance,
// transport ACK or user/application receipt authority is returned.
internal sealed class AuthenticatedOwnRouteUpdateDmc2 : IAuthenticatedDmc2InboxEvent, IDisposable
{
    private readonly byte[] exact, local, conversation, logical, author, device;
    private int disposed;
    private AuthenticatedOwnRouteUpdateDmc2(ReadOnlySpan<byte> exact, Did2MessagingSessionScope scope)
    {
        if (exact.Length is < 4497 or > 23649)
            throw new InvalidDataException("Own route control exceeds its exact closed record bound.");
        var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
        try
        {
            if (parsed.ContentKind != Dmc2ContentKind.ContactRouteUpdate ||
                parsed.ParsedPayload is not ContactRouteUpdateDmc2Payload update ||
                parsed.Flags != Dmc2Flags.None || parsed.ReplyToLogicalMessageId.Length != 0 ||
                parsed.ExpiresAtUnixMilliseconds == 0 || parsed.SenderClientSequence < (scope.IsInitiator ? 3UL : 4UL) ||
                !Fixed(parsed.CanonicalBytes.Span, exact) || !Fixed(parsed.NetworkId.Span, scope.Network) ||
                !Fixed(parsed.ConversationId.Span, scope.Conversation) || !Fixed(update.RelationshipId.Span, scope.Relationship) ||
                !Fixed(parsed.SenderAccountId.Span, scope.LocalAccount) || !Fixed(parsed.SenderDeviceId.Span, scope.LocalDevice))
                throw new CryptographicException("Own route control differs from its verified native/authored scope.");
            this.exact = exact.ToArray(); local = scope.LocalAccount.ToArray(); conversation = parsed.ConversationId.ToArray();
            logical = parsed.LogicalMessageId.ToArray(); author = parsed.SenderAccountId.ToArray(); device = parsed.SenderDeviceId.ToArray();
            LocalAccountGeneration = BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]);
        }
        finally { if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
    }

    public ReadOnlyMemory<byte> ExactDmc2 => Copy(exact);
    public ReadOnlyMemory<byte> LocalAccountId => Copy(local);
    public ulong LocalAccountGeneration { get; }
    public ReadOnlyMemory<byte> ConversationId => Copy(conversation);
    public ReadOnlyMemory<byte> LogicalMessageId => Copy(logical);
    public ReadOnlyMemory<byte> AuthorAccountId => Copy(author);
    public ReadOnlyMemory<byte> AuthorDeviceId => Copy(device);
    public Dmc2ContentKind ContentKind => Dmc2ContentKind.ContactRouteUpdate;

    internal static async Task<AuthenticatedOwnRouteUpdateDmc2> FromOwnedCommitAsync(
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
            // The real owner reads its own protected root, complete SQL mirror,
            // actual committed native event, consent and ordered signed history.
            // No supplied plaintext, previous hash, route or currentness flag.
            exact = await owner.ReadVerifiedOwnRouteControlCommitUnderLeaseAsync(account, held, opened,
                op, own, peer, source, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            return new(exact, opened.Scope);
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
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => Did2MessagingSessionScope.Fixed(left, right);
}
