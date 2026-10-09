using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Read-only owned selection, not a stage/deletion capability. The batch
    // removes only redundant ordinary/send commitments, never native events, transport
    // requests/evidence, history, asset keys, receipt obligations or floors.
    internal async Task<Did2CompactionPlan.Preparation> PrepareOwnedOrdinaryOutboxCompactionAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope requestedScope, int maximumRows,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        if (maximumRows is < 1 or > Did2CompactionPlan.MaximumRows) throw new ArgumentOutOfRangeException(nameof(maximumRows));
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false); using var borrowed = held.BorrowFor(lease);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        return await PrepareOrdinaryOutboxUnderLeaseAsync(current, scope, maximumRows, own, source, held, ct).ConfigureAwait(false);
    }

    private async Task<Did2CompactionPlan.Preparation> PrepareOrdinaryOutboxUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, int maximumRows,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
        RequireRetainedStoreOwnScope(scope, own);
        using var plans = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, scope.Network.ToArray(),
            scope.LocalAccount.ToArray(), scope.Instance.ToArray(), ct).ConfigureAwait(false);
        if (plans.Phase != 0) throw new InvalidOperationException("An active compaction batch owns recovery.");
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
        var stable = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(storage,
            sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
        var slots = OrdinaryOutboxSlots(scope);
        var kinds = OrdinaryOutboxRootKinds;
        var roots = new List<OwnedDeepSecret>(); var retained = new List<DirectTextOutboxEntry>(); byte[] successor = [], sendSuccessor = [];
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
                    // Removal reports no new dispatch permission. Verify the
                    // original Store independently of a fresh peer/issuer,
                    // then join every removed send field to the actual MAU.
                    if (await TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope,
                        command.Operation.ToArray(), own, source, ct).ConfigureAwait(false) is null)
                        throw new CryptographicException("Outbox selection has no independently verified original Store.");
                    await RequireOriginalMailboxSendCommitmentAsync(current, held, opened, scope, command.Operation.ToArray(), native.ExactEnvelope.ToArray(),
                        application, sends, grants, ct).ConfigureAwait(false);
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
            sendSuccessor = RemoveSelectedOrdinarySendCommitments(sends, scope, rows);
            foreach (var entry in selected) { journal.Entries.Remove(Convert.ToHexString(entry.Operation)); entry.Dispose(); }
            journal.Revision = checked(journal.Revision + 1);
            successor = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            var descriptors = new List<Did2CompactionPlan.Root>();
            for (var rootIndex = 0; rootIndex < roots.Count; rootIndex++)
            {
                var digest = roots[rootIndex].Use(bytes => SHA256.HashData(bytes));
                var changed = rootIndex == 0 ? successor : sendSuccessor;
                descriptors.Add(rootIndex < 2
                    ? new(kinds[rootIndex], CompactionSlotSelector(slots[rootIndex]), digest, SHA256.HashData(changed), false, changed)
                    : Guard(kinds[rootIndex], slots[rootIndex], digest));
            }
            await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
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
        finally { foreach (var root in roots) root.Dispose(); foreach (var item in retained) item.Dispose(); CryptographicOperations.ZeroMemory(successor); CryptographicOperations.ZeroMemory(sendSuccessor); }
    }

    internal async Task CompactOwnedOrdinaryOutboxAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope requestedScope, int maximumRows,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
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
            using var selected = await PrepareOrdinaryOutboxUnderLeaseAsync(current, scope, maximumRows, own, source, held, ct).ConfigureAwait(false);
            await plans.StageAsync(prior, selected, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(registered.Account); CryptographicOperations.ZeroMemory(registered.Instance); }
    }

    private async Task RequireOriginalMailboxSendCommitmentAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> nativeEnvelope, SqliteDeepMailboxStore application,
        ProtectedDid2MailboxSendJournal.State sends, ProtectedDid2MailboxGrantJournal.State grants, CancellationToken ct)
    {
        if (!sends.Entries.TryGetValue(Convert.ToHexString(ProtectedDid2MailboxSendJournal.Key(scope.Hash, operation.Span)), out var send) ||
            !send.Prepared || !FixedRoute(send.ScopeHash, scope.Hash) || !FixedRoute(send.Operation, operation.Span) ||
            !FixedRoute(send.EnvelopeHash, SHA256.HashData(nativeEnvelope.Span)))
            throw new CryptographicException("Original Store lost the exact prepared native send commitment.");
        var evidence = await application.RequireStorePublicEvidenceAsync(scope, operation, ct).ConfigureAwait(false);
        var route = evidence.IsInitial ? ContactRouteClosureCodec.Decode(evidence.OriginalRoute.Span) :
            await ReadOriginalPeerStoreRouteAsync(current, held, opened, application, ct).ConfigureAwait(false);
        if (!FixedRoute(evidence.Logical.Span, send.MailboxOperation) ||
            !FixedRoute(send.RouteHash, SHA256.HashData(route.ExactBytes.Span)))
            throw new CryptographicException("Original send differs from retained public/native route custody.");
        var read = await application.ReadTransportOutboxAsync(OutboxAccountScope.FromBytes(evidence.AccountScope.Span),
            OutboxLogicalId.FromBytes(send.MailboxOperation), ct).ConfigureAwait(false);
        if (read is not { Result: TransportOutboxReadResult.Found, Item.State: TransportOutboxState.Durable })
            throw new CryptographicException("Original send lost its actual durable transport request.");
        var exact = read.Item.GetCiphertextBundleCopy();
        try
        {
            var mau = MailboxAuthenticatedClientRequestCodec.Decode(exact);
            var grant = mau.Presentation.Grant;
            var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(mau.Binding.CanonicalRequest.Span);
            var grantBytes = MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
            if (!FixedRoute(SHA256.HashData(exact), send.MauHash) ||
                mau.Presentation.ReplayCounter != send.Counter ||
                mau.Binding.Operation != MailboxAuthenticatedOperation.Store ||
                !FixedRoute(mau.Binding.OperationId.Span, send.MailboxOperation) ||
                !FixedRoute(SHA256.HashData(mau.Binding.CanonicalRequest.Span), send.BodyHash) ||
                !FixedRoute(SHA256.HashData(grantBytes), send.GrantHash) ||
                !FixedRoute(body.Ciphertext.Span, nativeEnvelope.Span) ||
                body.CreatedAtUnixSeconds != send.Created || body.ExpiresAtUnixSeconds != send.Expires)
                throw new CryptographicException("Original send fields differ from the actual retained holder-signed request.");
            sends.RequireGrant(grant);
            if (sends.MinimumCounter(send.GrantHash) <= send.Counter)
                throw new CryptographicException("Original send exceeds its independently retained replay floor.");
            // Keep the actual acquisition join while removing its working send.
            // Historical verification above authenticates original policy/keys;
            // no newest issuer or renewed peer route substitutes for them.
            var acquisition = grants.Entries.Values.SingleOrDefault(value =>
                ProtectedDid2MailboxGrantJournal.HasWinner(value) &&
                FixedRoute(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(value).Span).Field(8).Span, grantBytes)) ??
                throw new CryptographicException("Original send lost its exact acquisition winner.");
            if (!FixedRoute(ProtectedDid2MailboxGrantJournal.OriginalPolicy(acquisition).Span, evidence.ExactPma.Span) ||
                !FixedRoute(ProtectedDid2MailboxGrantJournal.OriginalRoute(acquisition).Span, route.ExactBytes.Span))
                throw new CryptographicException("Original acquisition differs from independent public/native custody.");
            var request = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(acquisition).Span);
            var response = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(acquisition).Span);
            ContactCodec.VerifyMailboxGrantHolderSignature(request);
            ContactCodec.ValidateMailboxGrantResultBinding(request, response);
            ContactCodec.ValidateMailboxGrantResultRouteBinding(response, route);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
}
