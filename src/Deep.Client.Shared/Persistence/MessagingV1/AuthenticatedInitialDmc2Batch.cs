using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV2;

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

    // Independent DID2 construction: no V1 scope, identity conversion or source-key reopening.
    private AuthenticatedInitialDmc2Batch(byte[] initial, byte[] hello, Did2MessagingSessionScope scope)
    {
        var init = ApplicationCoreCodec.DecodeDmc2(initial);
        var first = ApplicationCoreCodec.DecodeDmc2(hello);
        var author = scope.IsInitiator ? scope.LocalAccount : scope.RemoteAccount;
        var device = scope.IsInitiator ? scope.LocalDevice : scope.RemoteDevice;
        var directory = scope.IsInitiator ? scope.LocalDirectory : scope.RemoteDirectory;
        if (!Fixed(init.CanonicalBytes.Span, initial) || !Fixed(first.CanonicalBytes.Span, hello) ||
            !MatchesScope(init, scope.Network, scope.Conversation, author, device) ||
            !MatchesScope(first, scope.Network, scope.Conversation, author, device) ||
            init.ParsedPayload is not SessionInitDmc2Payload session ||
            first.ParsedPayload is not ContactHelloDmc2Payload contact ||
            init.SenderClientSequence != 1 || first.SenderClientSequence != 2 ||
            first.CreatedAtUnixMilliseconds < init.CreatedAtUnixMilliseconds ||
            Fixed(init.LogicalMessageId.Span, first.LogicalMessageId.Span) ||
            !Fixed(session.SenderDirectory.RecordHash.Span, directory) ||
            !Fixed(contact.InitiatorDmd1Hash.Span, directory) ||
            !Fixed(contact.RelationshipId.Span, scope.Relationship) ||
            !Fixed(scope.Conversation, ApplicationCoreVerifier.ComputeContactConversationId(scope.Network,
                scope.Relationship, scope.LocalAccount, scope.RemoteAccount)))
            throw new CryptographicException("The retained initial batch differs from the owned DID2 semantic scope.");
        sessionInit = initial.ToArray(); firstApplication = hello.ToArray();
        localAccountId = scope.LocalAccount.ToArray(); conversationId = scope.Conversation.ToArray();
        LocalAccountGeneration = BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]);
    }

    internal static async Task<AuthenticatedInitialDmc2Batch> FromOwnedDid2Async(
        OwnedDid2MessagingStorage opened, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireActive();
        var scope = opened.Scope;
        var first = await source.RecheckEndpointPairUnderLeaseAsync(own, peer, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var retained = opened.Sql.ReadVerifiedActiveInitialEvents(floor);
        AuthenticatedInitialDmc2Batch? batch = null;
        try
        {
            await ApplicationCoreVerifier.RequireRetainedContactHelloEndpointBindingsAsync(
                ApplicationCoreCodec.DecodeDmc2(retained.Hello), scope.IsInitiator ? own.Proof : peer,
                scope.IsInitiator ? peer : own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var hello = (ContactHelloDmc2Payload)ApplicationCoreCodec.DecodeDmc2(retained.Hello).ParsedPayload;
            await RequireRetainedMailboxRouteFactsAsync(hello.MailboxRoute, scope.IsInitiator ? own.Proof : peer,
                own, source, held, ct).ConfigureAwait(false);
            batch = new(retained.SessionInit, retained.Hello, scope);
            var final = await source.RecheckEndpointPairUnderLeaseAsync(own, peer, held, ct).ConfigureAwait(false);
            if (!Fixed(first.BootId.Span, final.BootId.Span) || final.SampleSeconds < first.SampleSeconds)
                throw new CryptographicException("Initial application handoff crossed a clock discontinuity.");
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, final);
            var confirmedFloor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!Fixed(floor.Exact.Span, confirmedFloor.Exact.Span))
                throw new CryptographicException("Retained initial source changed during semantic verification.");
            var confirmed = opened.Sql.ReadVerifiedActiveInitialEvents(confirmedFloor);
            try
            {
                if (!Fixed(retained.SessionInit, confirmed.SessionInit) || !Fixed(retained.Hello, confirmed.Hello))
                    throw new CryptographicException("Retained initial events changed during semantic verification.");
            }
            finally { CryptographicOperations.ZeroMemory(confirmed.SessionInit); CryptographicOperations.ZeroMemory(confirmed.Hello); }
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            var result = batch; batch = null; return result;
        }
        finally
        {
            batch?.Dispose(); CryptographicOperations.ZeroMemory(retained.SessionInit);
            CryptographicOperations.ZeroMemory(retained.Hello);
        }
    }

    // Only the actual native-committed Hello/Accept handoffs call this reader.
    // Its route is historical event data, not the current route for a new Store.
    // Keep signature/identity/graph checks, but do not turn rematerialization
    // into renewal or require an expired old publication to be live again.
    internal static async Task RequireRetainedMailboxRouteFactsAsync(ParsedDeepIdV2ContactMailboxRoute package,
        VerifiedDeepIdV2DirectoryFreshness author, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireActive(); ct.ThrowIfCancellationRequested();
        var checkpoint = author.CurrentCheckpoint ?? throw new CryptographicException("Retained contact route has no current author identity.");
        var dca = DeepIdV2ContactAuthorizationCodec.Verify(package.Authorization, checkpoint.Binding, checkpoint.Directory);
        var reading = await source.RecheckEndpointPairUnderLeaseAsync(own, author, held, ct).ConfigureAwait(false);
        var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(author, dca, reading.BootId.Span, reading.SampleSeconds);
        await DeepIdV2ContactRouteVerifier.RequireRetainedEventRouteFactsAsync(authorization, own.Network, own.Authority,
            package.Invite.CanonicalBytes, package.Route.ExactBytes, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireActive();
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

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
