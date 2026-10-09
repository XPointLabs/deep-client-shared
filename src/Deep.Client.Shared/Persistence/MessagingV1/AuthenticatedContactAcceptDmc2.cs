using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.MessagingV1;

// Only the actual DPE2 commit plus authenticated retained Hello and current
// endpoint closure may construct this handoff. Never a route or mailbox ACK.
internal sealed class AuthenticatedContactAcceptDmc2 : IAuthenticatedDmc2InboxEvent, IDisposable
{
    private readonly byte[] exact, local, conversation, logical, author, device;
    private int disposed;
    private AuthenticatedContactAcceptDmc2(ReadOnlySpan<byte> exact, Did2MessagingSessionScope scope)
    {
        var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
        if (exact.Length is < ApplicationCoreCodec.MinimumContactControlRecordBytes or > ApplicationCoreCodec.MaximumContactControlRecordBytes || !Fixed(parsed.CanonicalBytes.Span, exact) ||
            parsed.ContentKind != Dmc2ContentKind.ContactAccept || parsed.SenderClientSequence != 3 ||
            !Fixed(parsed.NetworkId.Span, scope.Network) || !Fixed(parsed.ConversationId.Span, scope.Conversation) ||
            !Fixed(parsed.SenderAccountId.Span, scope.IsInitiator ? scope.RemoteAccount : scope.LocalAccount) ||
            !Fixed(parsed.SenderDeviceId.Span, scope.IsInitiator ? scope.RemoteDevice : scope.LocalDevice))
            throw new CryptographicException("ContactAccept is outside its authenticated responder position.");
        this.exact = exact.ToArray(); local = scope.LocalAccount.ToArray(); conversation = parsed.ConversationId.ToArray();
        logical = parsed.LogicalMessageId.ToArray(); author = parsed.SenderAccountId.ToArray(); device = parsed.SenderDeviceId.ToArray();
        LocalAccountGeneration = BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]);
    }
    public ReadOnlyMemory<byte> ExactDmc2 => Copy(exact);
    public ReadOnlyMemory<byte> LocalAccountId => Copy(local);
    public ulong LocalAccountGeneration { get; }
    public ReadOnlyMemory<byte> ConversationId => Copy(conversation);
    public ReadOnlyMemory<byte> LogicalMessageId => Copy(logical);
    public ReadOnlyMemory<byte> AuthorAccountId => Copy(author);
    public ReadOnlyMemory<byte> AuthorDeviceId => Copy(device);
    public Dmc2ContentKind ContentKind => Dmc2ContentKind.ContactAccept;

    internal static async Task<AuthenticatedContactAcceptDmc2> FromOwnedCommitAsync(
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> localSendDmc2,
        IDeepSecureStorage storage, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        if (!localSendDmc2.IsEmpty && localSendDmc2.Length is < ApplicationCoreCodec.MinimumContactControlRecordBytes or > ApplicationCoreCodec.MaximumContactControlRecordBytes)
            throw new InvalidDataException("A local Accept has an invalid bound.");
        var op = operation.ToArray(); var sent = localSendDmc2.ToArray(); byte[] accepted = [], hello = [];
        AuthenticatedContactAcceptDmc2? handoff = null;
        try
        {
            held.RequireActive();
            var scope = opened.Scope;
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            using var retained = opened.Sql.ReadVerifiedOperation(floor, op) ??
                throw new CryptographicException("ContactAccept has no actual committed DPE2 event.");
            if (retained.Direction != (scope.IsInitiator ? 2 : 1))
                throw new CryptographicException("ContactAccept has the wrong authenticated directional role.");
            if (retained.Direction == 2)
            { using var plain = retained.OwnAuthenticatedDmc2(); accepted = plain.Use(bytes => bytes.ToArray()); }
            else accepted = sent.ToArray();
            if (accepted.Length is < ApplicationCoreCodec.MinimumContactControlRecordBytes or > ApplicationCoreCodec.MaximumContactControlRecordBytes || !Fixed(SHA256.HashData(accepted), retained.EventHash))
                throw new CryptographicException("ContactAccept differs from its actual committed event hash.");
            using var pending = await AuthenticatedInitialDmc2Batch.FromOwnedDid2Async(opened, own, peer, source, held, ct).ConfigureAwait(false);
            hello = pending.FirstApplicationDmc2;
            if (!scope.IsInitiator)
            {
                using var journalOwner = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Local explicit acceptance custody is absent.");
                using var journal = journalOwner.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes,
                    scope.Network, scope.LocalAccount, scope.Instance));
                var winner = journal.FindScope(scope);
                if (winner is null || !Fixed(winner.Operation, op) || !Fixed(winner.Accept, accepted) ||
                    !Fixed(winner.HelloHash, SHA256.HashData(hello)))
                    throw new CryptographicException("A local Accept was not this account's durable explicit-command winner.");
            }
            await ApplicationCoreVerifier.RequireContactAcceptEndpointBindingsAsync(ApplicationCoreCodec.DecodeDmc2(accepted),
                ApplicationCoreCodec.DecodeDmc2(hello), scope.IsInitiator ? own.Proof : peer,
                scope.IsInitiator ? peer : own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var parsedAccept = ApplicationCoreCodec.DecodeDmc2(accepted);
            await AuthenticatedInitialDmc2Batch.RequireRetainedMailboxRouteFactsAsync(
                ((ContactAcceptDmc2Payload)parsedAccept.ParsedPayload).MailboxRoute, scope.IsInitiator ? peer : own.Proof,
                own, source, held, ct).ConfigureAwait(false);
            handoff = new(accepted, scope);
            var reading = await source.RecheckEndpointPairUnderLeaseAsync(own, peer, held, ct).ConfigureAwait(false);
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, reading);
            var confirmedFloor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!Fixed(floor.Exact.Span, confirmedFloor.Exact.Span))
                throw new CryptographicException("ContactAccept source changed during semantic verification.");
            using var confirmed = opened.Sql.ReadVerifiedOperation(confirmedFloor, op) ??
                throw new CryptographicException("ContactAccept lost its actual native commit during verification.");
            if (confirmed.Direction != retained.Direction || !Fixed(confirmed.EventHash, SHA256.HashData(accepted)))
                throw new CryptographicException("ContactAccept changed its committed event during verification.");
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            var result = handoff; handoff = null; return result;
        }
        finally
        {
            handoff?.Dispose(); foreach (var bytes in new[] { op, sent, accepted, hello }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

#if DEEP_TEST_INTERNALS
    internal static AuthenticatedContactAcceptDmc2 CreateForTests(ReadOnlySpan<byte> exact, Did2MessagingSessionScope scope) => new(exact, scope);
#endif
    private ReadOnlyMemory<byte> Copy(byte[] bytes)
    { ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this); return bytes.ToArray(); }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var bytes in new[] { exact, local, conversation, logical, author, device }) CryptographicOperations.ZeroMemory(bytes);
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);
}
