using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private sealed record OwnNativeRouteHead(ParsedDeepIdV2ContactMailboxRoute Original,
        ReadOnlyMemory<byte> ExactRoute, ReadOnlyMemory<byte> EventHash, ReadOnlyMemory<byte> NativeFloor);

    // The caller already holds the account lease and has reconciled the common
    // authored root/SQL mirror. Outgoing metadata never substitutes for the
    // actual committed native event hash or independently signed route graph.
    private async Task<OwnNativeRouteHead> ReadOwnNativeRouteHeadUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        SqliteDeepMailboxStore application, ProtectedDid2DirectTextJournal.State journal,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested(); var scope = opened.Scope;
        // Authenticate actual native consent below, independently of the
        // latest peer delivery route. Reconstructing own committed history
        // must not need a newly current peer mailbox or remint its route.
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var initial = opened.Sql.ReadVerifiedActiveInitialEvents(floor); byte[] accepted = [], headHash = [];
        try
        {
            var hello = ApplicationCoreCodec.DecodeDmc2(initial.Hello);
            if (hello.ParsedPayload is not ContactHelloDmc2Payload greeting ||
                (greeting.Policy & ContactPolicy.AllowRouteUpdates) == 0 ||
                !FixedRoute(greeting.RelationshipId.Span, scope.Relationship))
                throw new CryptographicException("Actual native Hello forbids own private route updates.");
            ParsedDeepIdV2ContactMailboxRoute original;
            ulong acceptanceOrdinal;
            if (scope.IsInitiator)
            {
                original = greeting.MailboxRoute; headHash = SHA256.HashData(initial.Hello);
                accepted = await application.ReadContactAcceptAsync(current.AccountId,
                    BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope.Conversation.ToArray(),
                    scope.RemoteAccount.ToArray(), scope.RemoteDevice.ToArray(), ct).ConfigureAwait(false) ??
                    throw new CryptographicException("Own route update has no actual peer acceptance.");
                using var native = opened.Sql.ReadVerifiedReceiveForEvent(floor, SHA256.HashData(accepted)) ??
                    throw new CryptographicException("Own route update lost native peer acceptance custody.");
                using var exact = native.OwnAuthenticatedDmc2();
                if (!exact.Use(bytes => FixedRoute(bytes, accepted)))
                    throw new CryptographicException("Own route update peer acceptance projection changed.");
                var operation = Dpe2Codec.Decode(native.ExactEnvelope).OperationId;
                using var verifiedAccept = await AuthenticatedContactAcceptDmc2.FromOwnedCommitAsync(opened,
                    operation, ReadOnlyMemory<byte>.Empty, storage, own, peer, source, held, ct).ConfigureAwait(false);
                acceptanceOrdinal = native.Ordinal;
            }
            else
            {
                await RequireRetainedAcceptanceForTextAsync(opened, application, own, peer, source, held, ct).ConfigureAwait(false);
                accepted = await application.ReadContactAcceptAsync(current.AccountId,
                    BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope.Conversation.ToArray(),
                    scope.LocalAccount.ToArray(), scope.LocalDevice.ToArray(), ct).ConfigureAwait(false) ??
                    throw new CryptographicException("Own route update lost actual local acceptance.");
                using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new CryptographicException("Own route update lost protected local acceptance.");
                using var commands = raw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes,
                    scope.Network, scope.LocalAccount, scope.Instance));
                var command = commands.FindScope(scope) ??
                    throw new CryptographicException("Own route update has no local acceptance winner.");
                using var native = opened.Sql.ReadVerifiedOperation(floor, command.Operation) ??
                    throw new CryptographicException("Own route update lost native local acceptance.");
                if (native.Direction != 1 || !FixedRoute(native.EventHash, SHA256.HashData(accepted)))
                    throw new CryptographicException("Own route update local acceptance differs from its native source.");
                original = ((ContactAcceptDmc2Payload)ApplicationCoreCodec.DecodeDmc2(accepted).ParsedPayload).MailboxRoute;
                headHash = native.EventHash.ToArray(); acceptanceOrdinal = native.Ordinal;
            }
            if (ApplicationCoreCodec.DecodeDmc2(accepted).ParsedPayload is not ContactAcceptDmc2Payload consent ||
                (consent.Policy & ContactPolicy.AllowRouteUpdates) == 0)
                throw new CryptographicException("Actual native acceptance forbids own private route updates.");
            var head = original.Route;
            foreach (var native in opened.Sql.ReadVerifiedOutgoingEvents(floor, ct))
            {
                if (FixedRoute(native.EventHash, headHash)) continue;
                var operation = Dpe2Codec.Decode(native.ExactEnvelope).OperationId;
                byte[] exact = [];
                try
                {
                    if (journal.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command))
                    {
                        if (command.Pending || !FixedRoute(command.Scope.Exact, scope.Exact) ||
                            !FixedRoute(command.EventHash, native.EventHash))
                            throw new CryptographicException("Native advertised history differs from its authored command.");
                        if (command.Kind != Dmc2ContentKind.ContactRouteUpdate) continue;
                        using var row = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                            BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, operation, ct,
                            requireStableReadOnly: true).ConfigureAwait(false);
                        if (row is null) throw new CryptographicException("Native route control lost its actual authored SQL row.");
                        exact = OwnedByteExports.TakeArray(row.ExactDmc2);
                        command.RequireEvent(exact);
                    }
                    else exact = await application.ReadRetainedAuthoredEventAsync(scope, native.EventHash.ToArray(), ct).ConfigureAwait(false) ??
                        throw new CryptographicException("Compacted native advertised history lost its exact authored event.");
                    var message = ApplicationCoreCodec.DecodeDmc2(exact);
                    try
                    {
                        if (!FixedRoute(SHA256.HashData(exact), native.EventHash) ||
                            !FixedRoute(message.NetworkId.Span, scope.Network) ||
                            !FixedRoute(message.SenderAccountId.Span, scope.LocalAccount) ||
                            !FixedRoute(message.SenderDeviceId.Span, scope.LocalDevice) ||
                            !FixedRoute(message.ConversationId.Span, scope.Conversation) ||
                            message.SenderClientSequence >= journal.NextSequence(scope))
                            throw new CryptographicException("Native advertised history lost its actual authored scope/floor.");
                        if (message.ContentKind != Dmc2ContentKind.ContactRouteUpdate) continue;
                        if (native.Ordinal <= acceptanceOrdinal ||
                            message.ParsedPayload is not ContactRouteUpdateDmc2Payload update ||
                            !FixedRoute(update.PredecessorRouteUpdateHash.Span, headHash))
                            throw new CryptographicException("Native advertised route update precedes consent or changes its predecessor.");
                        head = await DeepIdV2ContactRouteUpdateVerifier.RequireRetainedSuccessorFactsAsync(original, own.Proof,
                            own.Network, own.Authority, source.RendezvousTrustedTime, head.ExactBytes, headHash,
                            scope.Relationship.ToArray(), scope.Conversation.ToArray(), message.CanonicalBytes, ct).ConfigureAwait(false);
                        CryptographicOperations.ZeroMemory(headHash); headHash = native.EventHash.ToArray();
                    }
                    finally { if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
                }
                finally { CryptographicOperations.ZeroMemory(exact); }
            }
            var final = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(final.Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Own advertised native route history changed during verification.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return new(original, head.ExactBytes, headHash.ToArray(), floor.Exact.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(initial.SessionInit); CryptographicOperations.ZeroMemory(initial.Hello);
            CryptographicOperations.ZeroMemory(accepted); CryptographicOperations.ZeroMemory(headHash);
        }
    }
}
