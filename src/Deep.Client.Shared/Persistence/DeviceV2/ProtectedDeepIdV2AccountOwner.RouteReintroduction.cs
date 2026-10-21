using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task RequireRouteReintroductionAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(
            storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
        await RequireRouteReintroductionUnderLeaseAsync(current, held, opened, resolved, source,
            ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
    }

    private async Task RequireRouteReintroductionUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved,
        DeepIdV2ContactPathAuthoritySource source, ReadOnlyMemory<byte> operation, CancellationToken ct)
    {
        var contact = await RecheckPermanentContactUnderLeaseAsync(current, source, resolved, held, ct).ConfigureAwait(false);
        var peer = contact.Contact.Authorization.Freshness;
        var first = await RequireMessagingFreshnessAsync(current, resolved.Own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(opened.Scope, resolved.Own.Proof, peer, first);
        var history = await ReadAuthenticatedPeerRouteHistoryUnderLeaseAsync(current, opened,
            resolved.Own, peer, source, held, ct).ConfigureAwait(false);
        if (history.Faulted || !await history.HasConsent(ulong.MaxValue, ct).ConfigureAwait(false))
            throw new CryptographicException("Re-introduction requires actual mutual native route-update consent and no route fault.");
        await AuthenticatedInitialDmc2Batch.RequireRetainedMailboxRouteFactsAsync(history.Original,
            peer, resolved.Own, source, held, ct).ConfigureAwait(false);
        if (!operation.IsEmpty) await RequireNativeRouteReintroductionControlAsync(current, opened, held, operation, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (!FixedRoute(floor.Exact.Span, history.NativeFloor.Span))
            throw new CryptographicException("Re-introduction lost its actual native relationship floor.");
        await RequireFinalMessagingFreshnessAsync(current, opened.Scope, resolved.Own, peer, source, held, first, ct).ConfigureAwait(false);
        await contact.Contact.Route.EnsureCurrentAsync(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    // Classification comes from the original independently authenticated native
    // send, never DCR presence, a caller flag, an outbox column or decoded input.
    private async Task RequireNativeRouteReintroductionControlAsync(VerifiedDeepIdV2CurrentAccount current, OwnedDid2MessagingStorage opened,
        HeldDeepIdV2AccountLease held, ReadOnlyMemory<byte> operation, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested(); var scope = opened.Scope;
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using var native = opened.Sql.ReadVerifiedOperation(floor, operation.Span) ??
            throw new CryptographicException("Re-introduction lost its exact native send.");
        if (native.Direction != 1) throw new CryptographicException("Re-introduction requires an outgoing native control.");
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
            storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
        using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Re-introduction lost mandatory authored custody.");
        using var journal = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        byte[] exact;
        if (journal.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command))
        {
            if (command.Pending || command.Kind != Dmc2ContentKind.ContactRouteUpdate ||
                !FixedRoute(command.Scope.Exact, scope.Exact) || !FixedRoute(command.EventHash, native.EventHash))
                throw new CryptographicException("Re-introduction differs from its exact protected route control.");
            using var row = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, operation, ct,
                requireStableReadOnly: true).ConfigureAwait(false) ?? throw new CryptographicException("Re-introduction lost its exact authored SQL.");
            exact = OwnedByteExports.TakeArray(row.ExactDmc2); command.RequireEvent(exact);
        }
        else exact = await ReadOwnedAuthoredHistoryUnderLeaseAsync(current, application, scope, operation,
            native.EventHash.ToArray(), ct).ConfigureAwait(false) ?? throw new CryptographicException("Re-introduction lost its exact compacted control.");
        ParsedDmc2? message = null;
        try
        {
            message = ApplicationCoreCodec.DecodeDmc2(exact);
            if (!FixedRoute(SHA256.HashData(exact), native.EventHash) || message.ParsedPayload is not ContactRouteUpdateDmc2Payload update ||
                message.Flags != Dmc2Flags.None || !message.ReplyToLogicalMessageId.IsEmpty ||
                !FixedRoute(message.NetworkId.Span, scope.Network) ||
                !FixedRoute(message.SenderAccountId.Span, scope.LocalAccount) ||
                !FixedRoute(message.SenderDeviceId.Span, scope.LocalDevice) ||
                !FixedRoute(message.ConversationId.Span, scope.Conversation) ||
                !FixedRoute(update.RelationshipId.Span, scope.Relationship))
                throw new CryptographicException("Only an exact owned native route-maintenance control may use publication carriage.");
        }
        finally { CryptographicOperations.ZeroMemory(exact); if (message?.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    private async Task<ParsedContactRouteClosure> ReadAttemptStorePeerRouteAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        SqliteDeepMailboxStore application, ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> attempt,
        ParsedContactRouteClosure original, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var evidence = await application.ReadStorePublicEvidenceIfPresentAsync(opened.Scope, operation, attempt, ct).ConfigureAwait(false);
        if (evidence is null)
            return await ReadOriginalPeerStoreRouteAsync(current, held, opened, application, original.ExactBytes, ct).ConfigureAwait(false);
        await RequireStoreEvidenceCommitmentUnderLeaseAsync(held, opened.Scope, operation, attempt, evidence, ct).ConfigureAwait(false);
        var route = await ReadStoreEvidencePeerRouteAsync(current, held, opened, application, operation, evidence, own, source, ct).ConfigureAwait(false);
        if (!FixedRoute(route.ExactBytes.Span, original.ExactBytes.Span))
            throw new CryptographicException("Attempt lost its exact original independently verified recipient route.");
        return route;
    }

    // Historical comparison only. MAC/native purpose, exact protected DID2,
    // original holder request and independently signed publication are joined
    // even after cold reopen. No current route or admission capability is made.
    private async Task<ParsedContactRouteClosure> ReadStoreEvidencePeerRouteAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        SqliteDeepMailboxStore application, ReadOnlyMemory<byte> operation, Did2StorePublicEvidence evidence,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        if (!evidence.HasPublication)
            return await ReadOriginalPeerStoreRouteAsync(current, held, opened, application, evidence.OriginalRoute, ct).ConfigureAwait(false);
        await RequireNativeRouteReintroductionControlAsync(current, opened, held, operation, ct).ConfigureAwait(false);
        var scope = opened.Scope;
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope), ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Re-introduction lost its protected peer credential.");
        var exact = raw.Use(bytes => bytes.ToArray()); byte[] requestBytes = [];
        try
        {
            var peer = ProtectedDid2MessagingPeerBootstrap.Restore(exact, scope);
            var read = await application.ReadTransportOutboxAsync(OutboxAccountScope.FromBytes(evidence.AccountScope.Span),
                OutboxLogicalId.FromBytes(evidence.Logical.Span), ct).ConfigureAwait(false);
            requestBytes = read.Item?.GetCiphertextBundleCopy() ?? throw new CryptographicException("Re-introduction lost its original holder request.");
            var request = MailboxAuthenticatedClientRequestCodec.Decode(requestBytes);
            var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Binding.CanonicalRequest.Span);
            var route = source.AccountOwner.VerifyOriginalRoutePublication(own, peer, evidence.OriginalPeerAdp.Span,
                evidence.OriginalDcr.Span, evidence.OriginalRoute.Span, body.CreatedAtUnixSeconds);
            var dcr = Deep.Protocol.ContactV2.DeepIdV2ResolverClosureCodec.Decode(evidence.OriginalDcr.Span);
            var directory = ApplicationCoreCodec.DecodeDmd1(dcr.Bundle.Field(5).Span);
            var dca = DeepIdV2ContactAuthorizationCodec.Decode(dcr.Bundle.Field(6).Span);
            if (!FixedRoute(directory.DeepAccountId.Span, scope.RemoteAccount) ||
                !FixedRoute(directory.RecordHash.Span, scope.RemoteDirectory) ||
                directory.AccountGeneration != BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[164..]) ||
                !FixedRoute(dca.PublisherDeviceId.Span, scope.RemoteDevice))
                throw new CryptographicException("Re-introduction publication differs from the original session endpoint.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope), exact, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return route;
        }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(requestBytes); }
    }
}
