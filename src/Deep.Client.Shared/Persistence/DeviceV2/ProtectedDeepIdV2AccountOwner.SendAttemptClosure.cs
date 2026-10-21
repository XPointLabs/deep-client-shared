using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Reopen authenticates the whole closed prefix again. A protected phase is
    // not permission to replace changed/missing SQL or an original acquisition.
    // The same guard is used before issuer, signer and ingress callbacks.
    private async Task RequireClosedMailboxChainForSuccessorUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> initialIntent, VerifiedDeepIdV2PermanentContactResolveClosure? initialRecipient,
        Deep.Protocol.ApplicationCore.IDeepMlDsa65Verifier verifier,
        ReadOnlyMemory<byte> nativeEnvelope, ProtectedDid2MailboxSendJournal.State sends,
        byte[] snapshot, byte[] instance, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        var chain = sends.Chain(scope.Hash, operation.Span);
        var tail = chain[^1];
        if (tail.Closed && (sends.Entries.Count >= ProtectedDid2MailboxSendJournal.MaximumEntries ||
            tail.Ordinal >= ProtectedDid2MailboxSendJournal.MaximumEntries))
            throw new IOException("Protected send attempts are full; unresolved attempts cannot be evicted.");
        var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
        var elapsed = checked(first.SampleSeconds - own.Proof.MonotonicSample);
        var lower = checked(own.Proof.TrustedLowerUnixSeconds + elapsed);
        var upper = checked(own.Proof.TrustedUpperUnixSeconds + elapsed);
        if (upper >= tail.RetryUntil) throw new IOException("The original logical retry deadline forbids replacement work.");
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var retained = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, operation,
            initialIntent, ct).ConfigureAwait(false);
        try
        {
            if (!FixedRoute(retained, nativeEnvelope.Span))
                throw new CryptographicException("Replacement work lost its exact committed native ciphertext.");
        }
        finally { CryptographicOperations.ZeroMemory(retained); }
        using var grantRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Replacement work lost original acquisition custody.");
        var originalGrants = grantRoot.Use(bytes => bytes.ToArray());
        try
        {
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(originalGrants, networkId, current.AccountId.Span, instance);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            ParsedContactRouteClosure? nativeRoute = null;
            if (initialIntent.IsEmpty)
            {
                if (initialRecipient is not null) throw new CryptographicException("Ordinary replacement cannot use permanent-contact proof.");
            }
            else
            {
                if (initialRecipient is null) throw new CryptographicException("Initial replacement lost independently verified recipient custody.");
                await RequireRetainedInitialDraftAndRecipientUnderLeaseAsync(current, held, opened, initialIntent,
                    initialRecipient.Contact.CanonicalBytes, nativeEnvelope, ct).ConfigureAwait(false);
                using var peer = await storage.ReadOwnedAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope), ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Initial replacement lost its pinned peer credential.");
                var pinned = peer.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope));
                nativeRoute = DeepIdV2OriginalContactStoreVerifier.Verify(own.Authority, pinned,
                    initialRecipient.Authorization.Freshness.ExactAdp1V2.Span, initialRecipient.Contact.CanonicalBytes.Span,
                    initialRecipient.Route.ExactRouteClosure.Span, upper, deploymentProfileId, 2, verifier);
            }
            foreach (var entry in chain)
            {
                if (!entry.Closed)
                {
                    if (!ReferenceEquals(entry, tail)) throw new CryptographicException("An open predecessor cannot authorize a successor.");
                    continue;
                }
                if (lower < entry.ClosedAtLower || entry.ClosedAtLower < entry.AdmissionUntil)
                    throw new CryptographicException("Replacement work has no independently current original admission closure.");
                var acquisition = grants.Entries.Values.SingleOrDefault(value =>
                    ProtectedDid2MailboxGrantJournal.HasWinner(value) && FixedRoute(SHA256.HashData(
                        ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(value).Span).Field(8).Span), entry.GrantHash)) ??
                    throw new CryptographicException("Replacement work lost an original exact acquisition winner.");
                var (grant, route) = await RequireOriginalAttemptGrantAsync(entry, acquisition, own, source, scope, ct).ConfigureAwait(false);
                var originalNativeRoute = nativeRoute ?? await ReadAttemptStorePeerRouteAsync(current, held, opened,
                    application, operation, entry.Attempt.ToArray(), route, own, source, ct).ConfigureAwait(false);
                if (!FixedRoute(route.ExactBytes.Span, originalNativeRoute.ExactBytes.Span))
                    throw new CryptographicException("Replacement predecessor route lost its authenticated native recipient binding.");
                sends.RequireGrant(grant);
                var read = await application.ReadTransportOutboxAsync(VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span),
                    OutboxLogicalId.FromBytes(entry.MailboxOperation), ct).ConfigureAwait(false);
                if (read.Result == TransportOutboxReadResult.Corrupt || entry.Prepared && read.Item is null)
                    throw new CryptographicException("Replacement work cannot reconstruct a missing original request.");
                if (read.Item is { State: TransportOutboxState.Durable or TransportOutboxState.Delivered })
                    throw new CryptographicException("Original Store must be authenticated and reconciled before replacement.");
                if (read.Item is not null)
                {
                    var exact = read.Item.GetCiphertextBundleCopy();
                    try
                    {
                        RequireOriginalAttemptRequest(entry, grant, route, scope,
                            MailboxAuthenticatedClientRequestCodec.Decode(exact), exact, nativeEnvelope.Span, read.Item);
                        if (!entry.Prepared || sends.MinimumCounter(entry.GrantHash) <= entry.Counter)
                            throw new CryptographicException("Replacement work lost its independently reserved original counter.");
                    }
                    finally { CryptographicOperations.ZeroMemory(exact); }
                }
                else if (read.Result != TransportOutboxReadResult.Missing || entry.Prepared)
                    throw new CryptographicException("Replacement work lost its original SQL outcome.");
                else RequireOriginalAttemptBody(entry, grant, route, scope, nativeEnvelope);
            }
            await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            var finalFloor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(floor.Exact.Span, finalFloor.Exact.Span))
                throw new CryptographicException("Native custody changed during replacement preflight.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, originalGrants, ct).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        }
        finally { CryptographicOperations.ZeroMemory(originalGrants); }
    }

    // The evidence writer never receives a caller-selected trusted attempt.
    // Its current selector comes from mandatory protected prepared custody and
    // is joined again to actual native ciphertext before a public SQL insert.
    private async Task<byte[]> RequireCurrentStoreEvidenceAttemptUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> initialIntent,
        Did2StorePublicEvidence evidence, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        using var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Store evidence lost mandatory send-attempt custody.");
        var snapshot = root.Use(bytes => bytes.ToArray());
        byte[] envelope = [], logical = [];
        try
        {
            envelope = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, operation, initialIntent, ct).ConfigureAwait(false);
            using var sends = ProtectedDid2MailboxSendJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
            var entry = sends.Current(scope.Hash, operation.Span) ??
                throw new CryptographicException("Store evidence cannot create an absent owned attempt.");
            logical = MailboxSendOperation(scope, entry.Attempt, envelope);
            if (!entry.Prepared || entry.Closed || entry.HasSuccessor ||
                !FixedRoute(entry.Operation, operation.Span) || !FixedRoute(entry.ScopeHash, scope.Hash) ||
                !FixedRoute(entry.EnvelopeHash, SHA256.HashData(envelope)) ||
                !FixedRoute(entry.RouteHash, SHA256.HashData(evidence.OriginalRoute.Span)) ||
                !FixedRoute(entry.MailboxOperation, logical) || !FixedRoute(evidence.Logical.Span, logical) ||
                sends.MinimumCounter(entry.GrantHash) <= entry.Counter)
                throw new CryptographicException("Store evidence differs from actual prepared native/attempt custody.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return entry.Attempt.ToArray();
        }
        finally { foreach (var bytes in new[] { snapshot, envelope, logical }) CryptographicOperations.ZeroMemory(bytes); }
    }

    // An expired admission is not non-delivery. This producer retains the
    // original request/floor and marks only its independently proven closure.
    // It neither installs expired credentials nor invokes a signer/transport.
    private async Task<byte[]?> CloseExpiredMailboxAttemptUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> initialIntent, ReadOnlyMemory<byte> nativeEnvelope,
        ProtectedDid2MailboxSendJournal.State sends, byte[] snapshot, byte[] instance,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, CancellationToken ct)
    {
        var entry = sends.Current(scope.Hash, operation.Span);
        if (entry is null || entry.Closed) return null;
        var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
        var lower = checked(own.Proof.TrustedLowerUnixSeconds + checked(first.SampleSeconds - own.Proof.MonotonicSample));
        // Crossing expiry with upper time only denies dispatch; it cannot close.
        if (lower < entry.AdmissionUntil) return null;
        if (!FixedRoute(entry.ScopeHash, scope.Hash) || !FixedRoute(entry.Operation, operation.Span) ||
            !FixedRoute(entry.EnvelopeHash, SHA256.HashData(nativeEnvelope.Span)))
            throw new CryptographicException("Attempt closure lost its original native ciphertext binding.");

        var nativeFloor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var retainedEnvelope = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, operation, initialIntent, ct).ConfigureAwait(false);
        try
        {
            if (!FixedRoute(retainedEnvelope, nativeEnvelope.Span))
                throw new CryptographicException("Attempt closure differs from independently retained native custody.");
        }
        finally { CryptographicOperations.ZeroMemory(retainedEnvelope); }

        using var grantRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Attempt closure lost its original grant acquisition custody.");
        var originalGrants = grantRoot.Use(bytes => bytes.ToArray());
        byte[] exact = [];
        try
        {
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(originalGrants, networkId, current.AccountId.Span, instance);
            var acquisition = grants.Entries.Values.SingleOrDefault(value =>
                ProtectedDid2MailboxGrantJournal.HasWinner(value) && FixedRoute(
                    SHA256.HashData(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(value).Span).Field(8).Span), entry.GrantHash)) ??
                throw new CryptographicException("Attempt closure lost its exact acquisition winner.");
            var (grant, originalRoute) = await RequireOriginalAttemptGrantAsync(entry, acquisition, own, source, scope, ct).ConfigureAwait(false);
            sends.RequireGrant(grant);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            if (initialIntent.IsEmpty)
                _ = await ReadAttemptStorePeerRouteAsync(current, held, opened, application,
                    operation, entry.Attempt.ToArray(), originalRoute, own, source, ct).ConfigureAwait(false);
            var accountScope = VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span);
            var read = await application.ReadTransportOutboxAsync(accountScope,
                OutboxLogicalId.FromBytes(entry.MailboxOperation), ct).ConfigureAwait(false);
            if (read.Result == TransportOutboxReadResult.Corrupt || entry.Prepared && read.Item is null)
                throw new CryptographicException("Attempt closure cannot repair absent or corrupt prepared SQL custody.");
            if (read.Item is { State: TransportOutboxState.Durable or TransportOutboxState.Delivered })
                throw new CryptographicException("An original durable outcome must be reconciled before attempt closure.");
            if (read.Item is not null)
            {
                exact = read.Item.GetCiphertextBundleCopy();
                var mau = MailboxAuthenticatedClientRequestCodec.Decode(exact);
                RequireOriginalAttemptRequest(entry, grant, originalRoute, scope, mau, exact, nativeEnvelope.Span, read.Item);
                if (entry.Prepared)
                {
                    if (sends.MinimumCounter(entry.GrantHash) <= entry.Counter)
                        throw new CryptographicException("Attempt closure lost the independent reserved counter floor.");
                }
                else
                {
                    if (read.Item.State != TransportOutboxState.Prepared ||
                        mau.Presentation.ReplayCounter < sends.MinimumCounter(entry.GrantHash))
                        throw new CryptographicException("Pending attempt closure cannot invent or reuse a SQL replay counter.");
                    var prepared = entry.WithPrepared(exact, mau.Presentation.ReplayCounter);
                    sends.AdvanceCounter(entry.GrantHash, mau.Presentation.ReplayCounter);
                    sends.Entries[entry.Name] = prepared; entry.Dispose(); entry = prepared;
                }
            }
            else if (read.Result != TransportOutboxReadResult.Missing)
                throw new CryptographicException("Attempt closure requires an exact SQL read outcome.");
            else RequireOriginalAttemptBody(entry, grant, originalRoute, scope, nativeEnvelope);

            await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            var finalFloor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(nativeFloor.Exact.Span, finalFloor.Exact.Span))
                throw new CryptographicException("Native custody changed during attempt closure.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, originalGrants, ct).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, ct).ConfigureAwait(false);
            var closed = entry.CloseUnknown(lower);
            sends.Entries[entry.Name] = closed; entry.Dispose(); sends.Revision = checked(sends.Revision + 1);
#if DEEP_TEST_INTERNALS
            Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeClosureRoot);
#endif
            var adopted = await SaveMailboxSendJournalAsync(sends, snapshot, current, instance, held, ct).ConfigureAwait(false);
            try
            {
#if DEEP_TEST_INTERNALS
                Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterClosureRoot);
#endif
                await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, adopted, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return adopted.ToArray();
            }
            finally { CryptographicOperations.ZeroMemory(adopted); }
        }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(originalGrants); }
    }

    // Historical authentication only, never a current grant capability. The
    // independent lower clock above is supplied by the held owner, not callers.
    private static async Task<(MailboxAuthenticatedGrant Grant, ParsedContactRouteClosure Route)> RequireOriginalAttemptGrantAsync(
        ProtectedDid2MailboxSendJournal.Entry entry, byte[] acquisition,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, Did2MessagingSessionScope scope, CancellationToken ct)
    {
        var request = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(acquisition).Span);
        var response = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(acquisition).Span);
        var route = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(acquisition).Span);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(response.Field(8).Span);
        // Original signing facts are authenticated in the independently current
        // retained namespace, not reinterpreted as a current issuer capability.
        // Latest XNA1 need not be the exact ancestor that signed this old PMA2.
        var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(own.Network, own.Authority,
            own.MailboxAuthority.ExactPma2, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        await host.RequireOriginalNamespaceAsync(ProtectedDid2MailboxGrantJournal.OriginalPolicy(acquisition),
            route.Projection.CanonicalBytes, ct).ConfigureAwait(false);
        var policy = ContactCodec.Decode("PMA2", ProtectedDid2MailboxGrantJournal.OriginalPolicy(acquisition).Span);
        var issuerKey = policy.Field(5);
        var notBefore = BinaryPrimitives.ReadUInt64BigEndian(policy.Field(11).Span);
        var expiresAt = BinaryPrimitives.ReadUInt64BigEndian(policy.Field(12).Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        ContactCodec.ValidateMailboxGrantResultBinding(request, response);
        ContactCodec.ValidateMailboxGrantResultRouteBinding(response, route);
        var maximumExpiry = new[] { expiresAt,
            BinaryPrimitives.ReadUInt64BigEndian(route.Reachability.Field(17).Span),
            BinaryPrimitives.ReadUInt64BigEndian(route.Authorization.Field(13).Span),
            BinaryPrimitives.ReadUInt64BigEndian(route.Route.Field(18).Span),
            BinaryPrimitives.ReadUInt64BigEndian(route.Successor.Field(11).Span),
            BinaryPrimitives.ReadUInt64BigEndian(route.Selection.Field(9).Span) }.Min();
        if (grant.Domain != MailboxCapabilityDomain.Deposit || grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
            !FixedRoute(grant.NetworkId.Span, scope.Network) ||
            !FixedRoute(SHA256.HashData(response.Field(8).Span), entry.GrantHash) ||
            !FixedRoute(SHA256.HashData(route.ExactBytes.Span), entry.RouteHash) ||
            !FixedRoute(request.Field(7).Span, ContactCodec.ArtifactReference("PMT2", route.Projection).CanonicalBytes.Span) ||
            !FixedRoute(request.Field(8).Span, route.Selection.ArtifactHash.Span) ||
            !FixedRoute(request.Field(4).Span, route.Reachability.Field(10).Span) ||
            !FixedRoute(grant.MembershipCommitment.Span, route.Projection.ArtifactHash.Span) ||
            !FixedRoute(grant.IssuerPublicKey.Span, issuerKey.Span) ||
            grant.Generation < BinaryPrimitives.ReadUInt64BigEndian(policy.Field(7).Span) || grant.NotBeforeUnixSeconds < notBefore ||
            grant.ExpiresAtUnixSeconds > maximumExpiry ||
            grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds > BinaryPrimitives.ReadUInt32BigEndian(policy.Field(8).Span) ||
            entry.Created < grant.NotBeforeUnixSeconds || entry.Created >= grant.ExpiresAtUnixSeconds ||
            entry.AdmissionUntil != Math.Min(grant.ExpiresAtUnixSeconds, entry.RetryUntil) ||
            !PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), issuerKey.ToArray()))
            throw new CryptographicException("Attempt closure differs from its signed original grant/route interval.");
        return (grant, route);
    }

    private static void RequireOriginalAttemptRequest(ProtectedDid2MailboxSendJournal.Entry entry,
        MailboxAuthenticatedGrant grant, ParsedContactRouteClosure route, Did2MessagingSessionScope scope,
        MailboxAuthenticatedClientRequest mau, ReadOnlySpan<byte> exact,
        ReadOnlySpan<byte> nativeEnvelope, TransportOutboxItemSnapshot item)
    {
        var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(mau.Binding.CanonicalRequest.Span);
        if (mau.Binding.Operation != MailboxAuthenticatedOperation.Store ||
            !FixedRoute(entry.MailboxOperation, MailboxSendOperation(scope, entry.Attempt, nativeEnvelope)) ||
            !FixedRoute(entry.EnvelopeHash, SHA256.HashData(nativeEnvelope)) ||
            !FixedRoute(mau.Binding.OperationId.Span, entry.MailboxOperation) ||
            !FixedRoute(body.OperationId.Span, entry.MailboxOperation) || body.Epoch != grant.Epoch ||
            !FixedRoute(body.MailboxId.Bytes.Span, route.Reachability.Field(2).Span) ||
            !FixedRoute(body.PlacementId.Bytes.Span, route.Reachability.Field(10).Span) ||
            !FixedRoute(MailboxPlacementCommitment.Compute(body.PlacementId), grant.PlacementCommitment.Span) ||
            !FixedRoute(SHA256.HashData(mau.Binding.CanonicalRequest.Span), entry.BodyHash) ||
            !FixedRoute(item.DedupMaterial.Value, mau.Binding.RequestDigest.Span) ||
            !FixedRoute(MailboxAuthenticatedCapabilityCodec.EncodeGrant(mau.Presentation.Grant), MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)) ||
            !FixedRoute(body.Ciphertext.Span, nativeEnvelope) ||
            body.CreatedAtUnixSeconds != entry.Created || body.ExpiresAtUnixSeconds != entry.Expires ||
            entry.Prepared && (mau.Presentation.ReplayCounter != entry.Counter || !FixedRoute(SHA256.HashData(exact), entry.MauHash)) ||
            !PublicKeyAuth.VerifyDetached(mau.Presentation.HolderSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(mau.Presentation), grant.HolderPublicKey.ToArray()))
            throw new CryptographicException("Attempt closure lost its exact original signed SQL request.");
    }

    private static void RequireOriginalAttemptBody(ProtectedDid2MailboxSendJournal.Entry entry,
        MailboxAuthenticatedGrant grant, ParsedContactRouteClosure route, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> nativeEnvelope)
    {
        var operation = MailboxSendOperation(scope, entry.Attempt, nativeEnvelope.Span);
        var body = MailboxAuthenticatedRequestTranscript.ForStore(new MailboxEncryptedEnvelope
        {
            Epoch = grant.Epoch,
            MailboxId = new BlindedMailboxId(route.Reachability.Field(2).Span),
            PlacementId = new BlindedPlacementId(route.Reachability.Field(10).Span),
            OperationId = operation,
            DeduplicationDigest = MailboxAttemptEnvelopeDigest(operation, nativeEnvelope.Span),
            CreatedAtUnixSeconds = entry.Created,
            ExpiresAtUnixSeconds = entry.Expires,
            Ciphertext = nativeEnvelope
        }).CanonicalRequest.ToArray();
        try
        {
            if (!FixedRoute(operation, entry.MailboxOperation) ||
                !FixedRoute(SHA256.HashData(body), entry.BodyHash) ||
                entry.Expires - entry.Created > MailboxClientLimits.MaximumTtlSeconds)
                throw new CryptographicException("Attempt closure lost its original exact pending body.");
        }
        finally { CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(body); }
    }
}
