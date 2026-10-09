using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<Did2MessagingSessionScope?> TryFindCompletedContactMessagingScopeAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        DeepPermanentIdV2 address, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Contact start lost its mandatory draft registration.");
            using var drafts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, networkId, current.AccountId.Span, instance));
            drafts.Entries.TryGetValue(Convert.ToHexString(intent.Span), out var draft);
            if (draft is not null && !FixedRoute(draft.Exact.Slice(32, 32), address.ExactDid2Hash.Span))
                throw new CryptographicException("The contact intent already belongs to another exact peer.");
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            using var source = await SqliteDeepIdV2AccountGeneration.TryOpenExistingMessagingSenderSourceUnderLeaseAsync(storage, sqlStatePath, current, ct).ConfigureAwait(false);
            if (source is null)
            {
                if (Enumerable.Range(0, catalog.Count).Any(index => catalog.Scope(index).IsInitiator))
                    throw new InvalidDataException("A registered sender lost its mandatory initial source; no provisioning is allowed.");
                ct.ThrowIfCancellationRequested(); held.RequireActive(); return null;
            }
            if (!await source.HasCompletedInitialSessionAsync(intent, ct).ConfigureAwait(false)) return null;
            if (draft is null) throw new CryptographicException("Completed initial contact lost its original draft; no reauthoring is allowed.");
            using var retained = await source.ReadMessagingSourceByIntentUnderLeaseAsync(intent, ct).ConfigureAwait(false);
            var scope = catalog.FindSource(retained.SessionId.Span, SHA256.HashData(retained.CanonicalSpan));
            if (scope is null) return null; // Actual source transfer may still be working.
            var index = catalog.FindExact(scope);
            if (index < 0 || catalog.Phase(index) != 2 || retained.HasInitialState) return null;
            Did2MessagingSourceScope.RequireSender(scope, retained);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return scope;
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    internal async Task<ClientMailboxStoreResult?> ReadRetainedInitialStoreAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> intent,
        DeepPermanentIdV2 address, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
        return await TryReadRetainedInitialStoreUnderLeaseAsync(current, held, opened, scope, intent,
            address, own, source, verifier, ct).ConfigureAwait(false);
    }

    private async Task<ClientMailboxStoreResult?> TryReadRetainedInitialStoreUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> intent, DeepPermanentIdV2? address,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, DeepIdV2ContactPathAuthoritySource source,
        IDeepMlDsa65Verifier verifier, CancellationToken ct)
    {
        var operation = InitialMailboxOperation(intent.Span);
        var envelope = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, operation, intent, ct).ConfigureAwait(false);
        var logical = MailboxSendOperation(scope, operation, envelope);
        byte[] sendRoot = [], peerRoot = [];
        try
        {
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            var evidence = await application.ReadDurableStorePublicEvidenceAsync(scope, operation, logical, ct).ConfigureAwait(false);
            if (evidence is null)
            {
                await application.RequireAttemptedStoreEvidenceAsync(scope, operation, logical, ct).ConfigureAwait(false);
                return null; // Original pending evidence is not success.
            }
            if (!evidence.IsInitial) throw new CryptographicException("Initial Store lost its original recipient proof.");
            using (var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Initial Store lost mandatory send custody.")) sendRoot = raw.Use(bytes => bytes.ToArray());
            using (var sends = ProtectedDid2MailboxSendJournal.Decode(sendRoot, scope.Network, scope.LocalAccount, scope.Instance)) { }
            using (var raw = await storage.ReadOwnedAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope), ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Initial Store lost its protected peer credential.")) peerRoot = raw.Use(bytes => bytes.ToArray());
            var pinned = ProtectedDid2MessagingPeerBootstrap.Restore(peerRoot, scope);
            if (address is not null && !address.MatchesExactCredential(pinned)) throw new CryptographicException("Initial Store belongs to another permanent contact descriptor.");
            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            RequireRetainedStoreOwnScope(scope, own);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            await RequireRetainedInitialContactFactsUnderLeaseAsync(current, held, opened, intent, evidence, envelope, ct).ConfigureAwait(false);
            var route = ContactRouteClosureCodec.Decode(evidence.OriginalRoute.Span);
            var replicas = MailboxStoreReplicaEvidenceVerifier.Verify(own.Network, own.Authority, route, evidence.Replicas);
            var upper = checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample);
            var receipt = await VerifyOriginalStoreOutcomeAsync(scope, operation, envelope, application,
                route, evidence, replicas, own.Authority, upper, ct).ConfigureAwait(false);
            // Only holder/quorum authenticated times enter historical identity
            // verification. No supplied scalar becomes current time authority.
            var transport = await application.ReadTransportOutboxAsync(OutboxAccountScope.FromBytes(evidence.AccountScope.Span),
                OutboxLogicalId.FromBytes(logical), ct).ConfigureAwait(false);
            if (transport is not { Result: TransportOutboxReadResult.Found, Item.State: TransportOutboxState.Durable })
                throw new CryptographicException("Initial Store lost its actual durable request during verification.");
            var exact = transport.Item.GetCiphertextBundleCopy();
            try
            {
                var request = MailboxAuthenticatedClientRequestCodec.Decode(exact);
                var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Binding.CanonicalRequest.Span);
                foreach (var originalTime in receipt.ReplicaReceipts.Select(item => item.AcceptedAtUnixSeconds).Append(body.CreatedAtUnixSeconds).Distinct())
                    _ = DeepIdV2OriginalContactStoreVerifier.Verify(own.Authority, pinned, evidence.OriginalPeerAdp.Span,
                        evidence.OriginalDcr.Span, evidence.OriginalRoute.Span, originalTime, deploymentProfileId, 2, verifier);
            }
            finally { CryptographicOperations.ZeroMemory(exact); }
            await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            await RequireRetainedInitialContactFactsUnderLeaseAsync(current, held, opened, intent, evidence, envelope, ct).ConfigureAwait(false);
            if (!FixedRoute((await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false)).Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Initial Store native custody changed during verification.");
            var final = await application.RequireStorePublicEvidenceAsync(scope, operation, ct).ConfigureAwait(false);
            RequireSameInitialStoreEvidence(evidence, final);
            var repeated = await VerifyOriginalStoreOutcomeAsync(scope, operation, envelope, application,
                route, final, replicas, own.Authority, upper, ct).ConfigureAwait(false);
            if (!FixedRoute(MailboxReceiptV3Codec.EncodeDurableQuorum(receipt.CoordinatorReceipt),
                    MailboxReceiptV3Codec.EncodeDurableQuorum(repeated.CoordinatorReceipt)))
                throw new CryptographicException("Initial Store coordinator outcome changed during verification.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, sendRoot, ct).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope), peerRoot, ct).ConfigureAwait(false);
            await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return new(receipt.Cursor, receipt.Disposition, false, receipt.CoordinatorReceipt.CoordinatorId.Span);
        }
        finally { foreach (var bytes in new[] { operation, envelope, logical, sendRoot, peerRoot }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task<Did2StorePublicEvidence> RetainInitialStoreEvidenceUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> intent, ReadOnlyMemory<byte> envelope,
        Did2StorePublicEvidence evidence, VerifiedXPointNetworkAuthority authority, IDeepMlDsa65Verifier verifier,
        ulong originalCreated, bool requireExisting, CancellationToken ct)
    {
        if (!evidence.IsInitial || !FixedRoute(InitialMailboxOperation(intent.Span), operation.Span))
            throw new CryptographicException("Initial Store preparation has another operation or recipient evidence.");
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
            storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
        await RequireRetainedInitialContactFactsUnderLeaseAsync(current, held, opened, intent, evidence, envelope, ct).ConfigureAwait(false);
        if (requireExisting)
            RequireSameInitialStoreEvidence(evidence, await application.RequireStorePublicEvidenceAsync(scope, operation, ct).ConfigureAwait(false));
        else
        {
            var retained = await application.ReadStorePublicEvidenceIfPresentAsync(scope, operation, ct).ConfigureAwait(false);
            if (retained is not null)
            {
                // Fresh nonce-bound ADP bytes differ on every lookup. Preserve
                // the original proof; every other original record must still
                // match this exact prepared request and current route.
                var expected = evidence.CopyRecords(); var actual = retained.CopyRecords();
                try
                {
                    if (!retained.IsInitial || expected.Take(8).Where((bytes, index) => !FixedRoute(bytes, actual[index])).Any())
                        throw new CryptographicException("Initial retry differs from its first original public evidence.");
                }
                finally { foreach (var bytes in expected.Concat(actual)) CryptographicOperations.ZeroMemory(bytes); }
                using var peer = await storage.ReadOwnedAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope), ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Initial retry lost its protected peer credential.");
                var pinned = peer.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope));
                _ = DeepIdV2OriginalContactStoreVerifier.Verify(authority, pinned, retained.OriginalPeerAdp.Span,
                    retained.OriginalDcr.Span, retained.OriginalRoute.Span, originalCreated, deploymentProfileId, 2, verifier);
                evidence = retained;
            }
            else
            {
                var outbox = await application.ReadTransportOutboxAsync(OutboxAccountScope.FromBytes(evidence.AccountScope.Span),
                    OutboxLogicalId.FromBytes(evidence.Logical.Span), ct).ConfigureAwait(false);
                if (outbox is not { Result: TransportOutboxReadResult.Found, Item.State: TransportOutboxState.Prepared } || outbox.Item.Attempts.Count != 0)
                    throw new CryptographicException("Attempted initial Store lost its original public evidence; no reconstruction is allowed.");
                await application.RecordStorePublicEvidenceAsync(scope, operation, evidence, ct).ConfigureAwait(false);
            }
        }
        await RequireRetainedInitialContactFactsUnderLeaseAsync(current, held, opened, intent, evidence, envelope, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return evidence;
    }

    private async Task RequireRetainedInitialContactFactsUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> intent,
        Did2StorePublicEvidence evidence, ReadOnlyMemory<byte> expectedEnvelope, CancellationToken ct)
    {
        var scope = opened.Scope;
        if (!scope.IsInitiator || !evidence.IsInitial) throw new CryptographicException("Initial Store has no original sender scope.");
        using var source = await SqliteDeepIdV2AccountGeneration.OpenExistingMessagingSenderSourceUnderLeaseAsync(storage, sqlStatePath, current, ct).ConfigureAwait(false);
        using var retained = await source.ReadMessagingSourceByIntentUnderLeaseAsync(intent, ct).ConfigureAwait(false);
        Did2MessagingSourceScope.RequireSender(scope, retained);
        if (retained.HasInitialState || !FixedRoute(retained.ExactDph2.Span, expectedEnvelope.Span))
            throw new CryptographicException("Initial Store differs from the actual key-retired sender source.");
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var initial = opened.Sql.ReadVerifiedActiveInitialEvents(floor);
        try
        {
            var conversation = retained.RequireInitialConversation(initial.SessionInit, initial.Hello);
            try { if (!FixedRoute(conversation, scope.Conversation)) throw new CryptographicException("Initial Store has another native conversation."); }
            finally { CryptographicOperations.ZeroMemory(conversation); }
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Initial Store lost its protected explicit draft.");
            using var drafts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            if (!drafts.Entries.TryGetValue(Convert.ToHexString(intent.Span), out var draft) ||
                !FixedRoute(draft.Init, initial.SessionInit) || !FixedRoute(draft.Hello, initial.Hello) ||
                !FixedRoute(draft.Exact.Slice(192, 32), SHA256.HashData(evidence.OriginalDcr.Span)))
                throw new CryptographicException("Initial Store lost its exact original draft/contact join.");
            var dcr = DeepIdV2ResolverClosureCodec.Decode(evidence.OriginalDcr.Span);
            var directory = ApplicationCoreCodec.DecodeDmd1(dcr.Bundle.Field(5).Span);
            var dca = DeepIdV2ContactAuthorizationCodec.Decode(dcr.Bundle.Field(6).Span);
            if (!FixedRoute(directory.DeepAccountId.Span, scope.RemoteAccount) ||
                !FixedRoute(directory.RecordHash.Span, scope.RemoteDirectory) ||
                directory.AccountGeneration != BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[164..]) ||
                !FixedRoute(dca.PublisherDeviceId.Span, scope.RemoteDevice) ||
                !FixedRoute(draft.Exact.Slice(32, 32), DeepIdV2Codec.DecodeDid2(dcr.Bundle.Field(23).Span).RecordHash.Span))
                throw new CryptographicException("Initial Store recipient differs from its exact original endpoint.");
            ct.ThrowIfCancellationRequested(); held.RequireActive();
        }
        finally { CryptographicOperations.ZeroMemory(initial.SessionInit); CryptographicOperations.ZeroMemory(initial.Hello); }
    }

    private static void RequireSameInitialStoreEvidence(Did2StorePublicEvidence expected, Did2StorePublicEvidence actual)
    {
        var before = expected.CopyRecords(); var after = actual.CopyRecords();
        try
        {
            if (before.Length != after.Length || before.Where((bytes, index) => !FixedRoute(bytes, after[index])).Any())
                throw new CryptographicException("Initial Store original public evidence changed; no repair is permitted.");
        }
        finally { foreach (var bytes in before.Concat(after)) CryptographicOperations.ZeroMemory(bytes); }
    }
}
