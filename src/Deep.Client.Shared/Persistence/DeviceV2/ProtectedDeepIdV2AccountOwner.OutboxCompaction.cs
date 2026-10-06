using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Read-only owned selection, not a stage/deletion capability. The batch
    // removes only redundant ordinary work, never native events, transport
    // requests/evidence, history, asset keys, receipt obligations or floors.
    internal async Task<Did2CompactionPlan.Preparation> PrepareOwnedOrdinaryOutboxCompactionAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope requestedScope, int maximumRows,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        if (maximumRows is < 1 or > Did2CompactionPlan.MaximumRows) throw new ArgumentOutOfRangeException(nameof(maximumRows));
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false); using var borrowed = held.BorrowFor(lease);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        return await PrepareOrdinaryOutboxUnderLeaseAsync(current, scope, maximumRows, own, peer, source, held, ct).ConfigureAwait(false);
    }

    private async Task<Did2CompactionPlan.Preparation> PrepareOrdinaryOutboxUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, int maximumRows,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        using var plans = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, scope.Network.ToArray(),
            scope.LocalAccount.ToArray(), scope.Instance.ToArray(), ct).ConfigureAwait(false);
        if (plans.Phase != 0) throw new InvalidOperationException("An active compaction batch owns recovery.");
        using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
        var stable = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        var slots = OrdinaryOutboxSlots(scope);
        var kinds = OrdinaryOutboxRootKinds;
        var roots = new List<OwnedDeepSecret>(); var retained = new List<DirectTextOutboxEntry>(); byte[] successor = [];
        try
        {
            foreach (var slot in slots)
                roots.Add(await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Outbox selection lost a mandatory dependency."));
            using var journal = roots[0].Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            using var sends = roots[1].Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            using var grants = roots[2].Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            using var reads = roots[3].Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            using var catalog = roots[4].Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            using var assets = roots[6].Use(bytes => ProtectedDid2AttachmentJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var index = catalog.FindExact(scope);
            if (index < 0 || catalog.Phase(index) != 2 || !roots[5].Use(bytes => FixedRoute(bytes, stable.Exact.Span)))
                throw new CryptographicException("Outbox selection lost its initialized stable native scope.");
            _ = roots[8].Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
            _ = roots[9].Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope));
            using (var registration = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(storage,
                scope.Network.ToArray(), scope.LocalAccount.ToArray(), ct).ConfigureAwait(false))
                if (!registration.Use(bytes => FixedRoute(bytes.Slice(56, 32), scope.Instance)) ||
                    !registration.Use(bytes => FixedRoute(SHA256.HashData(bytes), roots[7].Use(raw => SHA256.HashData(raw)))))
                    throw new CryptographicException("Outbox selection differs from its actual account instance.");
            // A retained suffix is required by the ordinary reader. Never skip
            // an earlier unknown command in order to reclaim a later slot.
            var selected = journal.Entries.Values.Where(entry => FixedRoute(entry.Scope.Exact, scope.Exact))
                .OrderBy(entry => entry.Sequence).TakeWhile(entry => entry.Stored).Take(maximumRows).ToArray();
            if (selected.Length == 0) throw new InvalidOperationException("No settled ordinary prefix is eligible.");
            using (await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, ReadOnlyMemory<byte>.Empty, ct,
                retained, requireStableReadOnly: true).ConfigureAwait(false)) { }
            var route = await ReadAuthenticatedPeerMailboxRouteUnderLeaseAsync(current, opened, own, peer, source, held, ct).ConfigureAwait(false);
            var time = await route.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
            var policy = MailboxAuthorityV2Verifier.Verify(route.Route.NetworkAuthority, own.MailboxAuthority.ExactPma2.Span,
                time.LowerUnixSeconds, time.UpperUnixSeconds);
            if (!policy.BindsProjection(route.Route.Route.Projection.CanonicalBytes.Span))
                throw new CryptographicException("Outbox settlement is outside the independently current issuer projection.");
            foreach (var command in selected)
            {
                var payload = retained.Single(item => FixedRoute(item.OperationId.Span, command.Operation)).ExactDmc2.ToArray();
                try
                {
                    using var native = opened.Sql.ReadVerifiedOperation(stable, command.Operation) ??
                        throw new CryptographicException("Outbox settlement has no verified committed native event.");
                    if (native.Direction != 1 || !FixedRoute(native.EventHash, command.EventHash))
                        throw new CryptographicException("Outbox settlement differs from native event custody.");
                    var history = await application.ReadDirectDmc2Async(current.AccountId, BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]),
                        scope.Conversation.ToArray(), command.Logical.ToArray(), scope.LocalDevice.ToArray(), ct).ConfigureAwait(false) ??
                        throw new InvalidDataException("Outbox cleanup cannot remove the sole local event source.");
                    try { command.RequireEvent(history); if (!FixedRoute(history, payload)) throw new CryptographicException("Independent history differs from authored work."); }
                    finally { CryptographicOperations.ZeroMemory(history); }
                    await RequireOrdinaryStoreCustodyAsync(scope, command, native, application, sends, grants, route, policy,
                        time.UpperUnixSeconds, ct).ConfigureAwait(false);
                    var parsed = ApplicationCoreCodec.DecodeDmc2(payload);
                    if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer)
                    {
                        using var manifest = offer.Manifest;
                        var asset = assets.Entries.Values.SingleOrDefault(item => FixedRoute(item.Object, manifest.ObjectId.Span)) ??
                            throw new InvalidDataException("A retained attachment offer lost its protected local object.");
                        using var actual = await ReadStableAttachmentManifestUnderLeaseAsync(current, held, application, asset.Operation.ToArray(), ct).ConfigureAwait(false);
                        if (!FixedRoute(actual.CanonicalBytes.Span, manifest.CanonicalBytes.Span))
                            throw new CryptographicException("Retained attachment keys differ from the independently preserved offer.");
                    }
                }
                finally { CryptographicOperations.ZeroMemory(payload); }
            }
            var effects = await application.CaptureOrdinaryOutboxEffectsAsync(scope, selected, ct).ConfigureAwait(false);
            var rows = selected.Select(entry => new Did2CompactionPlan.Row(Did2CompactionPlan.Disposition.OutboxPayload,
                entry.Operation.ToArray(), SHA256.HashData(entry.Exact))).OrderBy(row => Convert.ToHexString(row.Selector.Span), StringComparer.Ordinal).ToArray();
            foreach (var entry in selected) { journal.Entries.Remove(Convert.ToHexString(entry.Operation)); entry.Dispose(); }
            journal.Revision = checked(journal.Revision + 1);
            successor = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            var descriptors = new List<Did2CompactionPlan.Root>();
            for (var rootIndex = 0; rootIndex < roots.Count; rootIndex++)
            {
                var digest = roots[rootIndex].Use(bytes => SHA256.HashData(bytes));
                descriptors.Add(rootIndex == 0
                    ? new(kinds[rootIndex], CompactionSlotSelector(slots[rootIndex]), digest, SHA256.HashData(successor), false, successor)
                    : Guard(kinds[rootIndex], slots[rootIndex], digest));
            }
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            var final = await route.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(time.BootId.Span, final.BootId.Span) || final.MonotonicSample < time.MonotonicSample)
                throw new CryptographicException("Outbox selection crossed protected clock continuity.");
            _ = MailboxAuthorityV2Verifier.Verify(route.Route.NetworkAuthority, policy.ExactPma2.Span, final.LowerUnixSeconds, final.UpperUnixSeconds);
            for (var rootIndex = 0; rootIndex < slots.Length; rootIndex++)
            {
                using var readback = await storage.ReadOwnedAsync(slots[rootIndex], ct).ConfigureAwait(false) ?? throw new InvalidDataException("Outbox dependency disappeared.");
                if (!readback.Use(bytes => FixedRoute(SHA256.HashData(bytes), descriptors[rootIndex].Before.Span)))
                    throw new CryptographicException("Outbox dependency changed during selection.");
            }
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return plans.Prepare(Did2CompactionPlan.SqlTarget.Application, RandomNumberGenerator.GetBytes(32), scope.Hash,
                effects.Before, effects.After, descriptors, rows);
        }
        finally { foreach (var root in roots) root.Dispose(); foreach (var item in retained) item.Dispose(); CryptographicOperations.ZeroMemory(successor); }
    }

    internal async Task CompactOwnedOrdinaryOutboxAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope requestedScope, int maximumRows,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        if (maximumRows is < 1 or > Did2CompactionPlan.MaximumRows) throw new ArgumentOutOfRangeException(nameof(maximumRows));
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false); using var borrowed = held.BorrowFor(lease);
        var registered = await SqliteDeepIdV2AccountGeneration.ReadCompactionOwnerScopeUnderLeaseAsync(storage, networkId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, registered.Account, registered.Instance);
            using var prior = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (prior.Phase != 0)
            {
                if (prior.Target != Did2CompactionPlan.SqlTarget.Application || !FixedRoute(prior.SqlSelector, scope.Hash))
                    throw new CryptographicException("Another stored batch owns local recovery.");
                await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false); return;
            }
            using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
            using var selected = await PrepareOrdinaryOutboxUnderLeaseAsync(current, scope, maximumRows, own, peer, source, held, ct).ConfigureAwait(false);
            await plans.StageAsync(prior, selected, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(registered.Account); CryptographicOperations.ZeroMemory(registered.Instance); }
    }

    private static async Task RequireOrdinaryStoreCustodyAsync(Did2MessagingSessionScope scope,
        ProtectedDid2DirectTextJournal.Entry command, OwnedDid2MessagingPersistedEvent native, SqliteDeepMailboxStore application,
        ProtectedDid2MailboxSendJournal.State sends, ProtectedDid2MailboxGrantJournal.State grants,
        VerifiedDeepIdV2ContactMailboxRoute route, VerifiedMailboxAuthorityV2 policy, ulong currentUpper, CancellationToken ct)
    {
        if (!sends.Entries.TryGetValue(Convert.ToHexString(ProtectedDid2MailboxSendJournal.Key(scope.Hash, command.Operation)), out var send) || !send.Prepared ||
            !FixedRoute(send.RouteHash, SHA256.HashData(route.Route.ExactRouteClosure.Span)) ||
            !FixedRoute(send.EnvelopeHash, SHA256.HashData(native.ExactEnvelope)))
            throw new CryptographicException("Stored ordinary work has no matching protected request/native route.");
        var grantName = Convert.ToHexString(ProtectedDid2MailboxGrantJournal.Scope(send.RouteHash, route.LocatorHash.Span, (byte)MailboxCapabilityDomain.Deposit));
        var retained = ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(grants, grantName, send.GrantHash);
        var response = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(retained).Span);
        var request = ContactCodec.Decode("XMG1", ProtectedDid2MailboxGrantJournal.Request(retained).Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request); ContactCodec.ValidateMailboxGrantResultBinding(request, response);
        ContactCodec.ValidateMailboxGrantResultRouteBinding(response, route.Route.Route);
        if (!FixedRoute(request.Field(1).Span, scope.Network) || !FixedRoute(request.Field(3).Span, route.LocatorHash.Span) ||
            !FixedRoute(request.Field(4).Span, route.Route.Route.Reachability.Field(10).Span) || request.Field(6).Span[0] != (byte)MailboxCapabilityDomain.Deposit ||
            !FixedRoute(request.Field(7).Span, ContactCodec.ArtifactReference("PMT2", route.Route.Route.Projection).CanonicalBytes.Span) ||
            !FixedRoute(request.Field(8).Span, route.Route.Route.Selection.ArtifactHash.Span))
            throw new CryptographicException("Past acquisition differs from the original authenticated peer route.");
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(response.Field(8).Span);
        var issuer = policy.ResolveIssuer(MailboxCapabilityDomain.Deposit);
        if (grant.Domain != MailboxCapabilityDomain.Deposit || grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
            !FixedRoute(grant.NetworkId.Span, scope.Network) || !FixedRoute(grant.IssuerPublicKey.Span, issuer.PublicKey.Span) ||
            grant.NotBeforeUnixSeconds < issuer.ValidFromUnixSeconds || grant.ExpiresAtUnixSeconds > issuer.ValidUntilUnixSeconds ||
            grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds > policy.MaximumGrantLifetimeSeconds ||
            !PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(), MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), issuer.PublicKey.ToArray()))
            throw new CryptographicException("Past Store has no signed grant under the independently current issuer lineage.");
        sends.RequireGrant(grant);
        var read = await application.ReadTransportOutboxAsync(VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span),
            OutboxLogicalId.FromBytes(send.MailboxOperation), ct).ConfigureAwait(false);
        if (read is not { Result: TransportOutboxReadResult.Found, Item.State: TransportOutboxState.Durable })
            throw new CryptographicException("Stored work has no durable actual SQL transport custody.");
        var exact = read.Item.GetCiphertextBundleCopy(); var quorum = read.Item.Attempts.Single(attempt => attempt.State == TransportOutboxAttemptState.Durable).GetEvidenceCopy();
        try
        {
            var mau = MailboxAuthenticatedClientRequestCodec.Decode(exact);
            if (!FixedRoute(SHA256.HashData(exact), send.MauHash) || mau.Presentation.ReplayCounter != send.Counter ||
                mau.Binding.Operation != MailboxAuthenticatedOperation.Store || !FixedRoute(mau.Binding.OperationId.Span, send.MailboxOperation) ||
                !FixedRoute(SHA256.HashData(mau.Binding.CanonicalRequest.Span), send.BodyHash) ||
                !FixedRoute(MailboxAuthenticatedCapabilityCodec.EncodeGrant(mau.Presentation.Grant), response.Field(8).Span) ||
                !PublicKeyAuth.VerifyDetached(mau.Presentation.HolderSignature.ToArray(), MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(mau.Presentation), grant.HolderPublicKey.ToArray()))
                throw new CryptographicException("Stored request differs from original protected MAU/grant/counter custody.");
            var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(mau.Binding.CanonicalRequest.Span);
            if (!FixedRoute(envelope.Ciphertext.Span, native.ExactEnvelope) || envelope.CreatedAtUnixSeconds != send.Created || envelope.ExpiresAtUnixSeconds != send.Expires ||
                envelope.Epoch != grant.Epoch || !FixedRoute(envelope.MailboxId.Bytes.Span, route.Route.Route.Reachability.Field(2).Span) ||
                !FixedRoute(envelope.PlacementId.Bytes.Span, route.Route.Route.Reachability.Field(10).Span) ||
                !FixedRoute(MailboxPlacementCommitment.Compute(envelope.PlacementId), grant.PlacementCommitment.Span) ||
                !FixedRoute(MailboxSendOperation(scope, command.Operation, native.ExactEnvelope), send.MailboxOperation) ||
                envelope.CreatedAtUnixSeconds < grant.NotBeforeUnixSeconds || envelope.CreatedAtUnixSeconds >= grant.ExpiresAtUnixSeconds ||
                !FixedRoute(read.Item.DedupMaterial.Value, mau.Binding.RequestDigest.Span))
                throw new CryptographicException("Stored body differs from its exact committed native event.");
            var ids = route.Route.Route.Selection.Field(6);
            var pinned = new ClientMailboxPinnedRoute(envelope.PlacementId, grant.MembershipCommitment.Span,
                ids.Span[..32], route.Route.Network.ResolveNodeIdentityPublicKey(ids[..32]).Span,
                ids.Span[32..], route.Route.Network.ResolveNodeIdentityPublicKey(ids[32..]).Span);
            var verified = new PinnedClientMailboxReceiptVerifier(new SodiumMailboxPeerReplicationCrypto()).VerifyDurable(quorum, new()
            {
                Epoch = grant.Epoch, OperationId = envelope.OperationId, MailboxId = envelope.MailboxId, Route = pinned,
                EnvelopeDigest = SHA256.HashData(native.ExactEnvelope), ExpiresAtUnixSeconds = envelope.ExpiresAtUnixSeconds,
                AllowedDispositions = new HashSet<MailboxReplicaDisposition> { MailboxReplicaDisposition.Stored, MailboxReplicaDisposition.Duplicate }
            });
            if (!FixedRoute(verified.CoordinatorReceipt.CoordinatorId.Span, ids.Span[..32]) ||
                verified.ReplicaReceipts.Any(receipt => receipt.AcceptedAtUnixSeconds < grant.NotBeforeUnixSeconds || receipt.AcceptedAtUnixSeconds >= grant.ExpiresAtUnixSeconds ||
                    receipt.AcceptedAtUnixSeconds < envelope.CreatedAtUnixSeconds || receipt.DurableAtUnixSeconds > currentUpper))
                throw new CryptographicException("Past Store receipt is outside its original signed acceptance interval or sole writer.");
        }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(quorum); }
    }
}
