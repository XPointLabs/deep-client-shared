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
    // Amortized business-owner maintenance, not a scheduler or permission to
    // delete unknown work. The existing dependency-closed producer chooses and
    // verifies the actual settled prefix; the same protected plan owns recovery.
    private async Task MaintainOrdinaryOutboxUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        await RetireStoppedWorkingPayloadUnderLeaseAsync(current, held, scope, own, source, ct).ConfigureAwait(false);
        using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Ordinary maintenance lost mandatory authored custody.");
        using var ordinary = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes,
            scope.Network, scope.LocalAccount, scope.Instance));
        if (ordinary.Pending is not null || ordinary.Entries.ContainsKey(Convert.ToHexString(operation.Span))) return;
        using var sendRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Ordinary maintenance lost mandatory send custody.");
        using var sends = sendRoot.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes,
            scope.Network, scope.LocalAccount, scope.Instance));
        if (ordinary.Entries.Count < Did2CompactionPlan.MaximumRows &&
            sends.Entries.Count < ProtectedDid2MailboxSendJournal.MaximumEntries) return;
        var eligible = ordinary.Entries.Values.Where(entry => FixedRoute(entry.Scope.Exact, scope.Exact))
            .OrderBy(entry => entry.Sequence).TakeWhile(entry => entry.Stored && !entry.WorkStopped).Take(Did2CompactionPlan.MaximumRows).Count();
        eligible = Math.Min(eligible, ProtectedDid2DirectTextJournal.MaximumTerminalAudits - ordinary.TerminalAudits.Count);
        if (eligible == 0) return; // Capacity checks still refuse; unknown is never evicted.
        var plans = new ProtectedDid2CompactionPlan(storage, lease, scope.Network, scope.LocalAccount, scope.Instance);
        using var prior = await plans.ReadAsync(held, ct).ConfigureAwait(false);
        if (prior.Phase != 0) throw new InvalidDataException("Stored compaction owns recovery before new ordinary work.");
        using var selected = await PrepareOrdinaryOutboxUnderLeaseAsync(current, scope, eligible, own, source, held, ct).ConfigureAwait(false);
        await plans.StageAsync(prior, selected, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
    }

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
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct,
        Did2CompactionPlan.Disposition action = Did2CompactionPlan.Disposition.OutboxPayload)
    {
        held.RequireOwner(lease);
        if (action is not (Did2CompactionPlan.Disposition.OutboxPayload or Did2CompactionPlan.Disposition.StoppedOutboxPayload))
            throw new InvalidDataException("Unsupported ordinary maintenance disposition.");
        var stoppedOnly = action != Did2CompactionPlan.Disposition.OutboxPayload;
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
            var candidates = journal.Entries.Values.Where(entry => FixedRoute(entry.Scope.Exact, scope.Exact)).OrderBy(entry => entry.Sequence);
            var selected = (stoppedOnly ? candidates.Where(entry => entry.WorkStopped)
                : candidates.TakeWhile(entry => entry.Stored && !entry.WorkStopped))
                .Take(Math.Min(maximumRows, ProtectedDid2DirectTextJournal.MaximumTerminalAudits - journal.TerminalAudits.Count)).ToArray();
            if (selected.Length == 0) throw new InvalidOperationException("No settled ordinary prefix is eligible.");
            using (await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, ReadOnlyMemory<byte>.Empty, ct,
                retained, requireStableReadOnly: true).ConfigureAwait(false)) { }
            foreach (var command in selected)
            {
                var payload = OwnedByteExports.TakeArray(retained.Single(item => FixedRoute(item.OperationId.Span, command.Operation)).ExactDmc2);
                try
                {
                    using var native = opened.Sql.ReadVerifiedOperation(stable, command.Operation);
                    if (native is null)
                    {
                        if (!stoppedOnly) throw new CryptographicException("Store settlement has no verified committed native event.");
                        await RequireUnencryptedCancelledDraftAsync(scope, command, application, sends, ct).ConfigureAwait(false);
                    }
                    else
                    {
                        if (native.Direction != 1 || !FixedRoute(native.EventHash, command.EventHash))
                            throw new CryptographicException("Outbox settlement differs from native event custody.");
                        var history = await ReadOwnedAuthoredHistoryUnderLeaseAsync(current, application, scope,
                            command.Operation.ToArray(), native.EventHash.ToArray(), ct).ConfigureAwait(false) ??
                            throw new InvalidDataException("Outbox cleanup cannot remove the sole local event source.");
                        try { command.RequireEvent(history); if (!FixedRoute(history, payload)) throw new CryptographicException("Independent history differs from authored work."); }
                        finally { CryptographicOperations.ZeroMemory(history); }
                    }
                    // Removal reports no new dispatch permission. Verify the
                    // original Store independently of a fresh peer/issuer,
                    // then join every removed send field to the actual MAU.
                    if (!stoppedOnly && await TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope,
                        command.Operation.ToArray(), own, source, ct).ConfigureAwait(false) is null)
                        throw new CryptographicException("Outbox selection has no independently verified original Store.");
                    if (!stoppedOnly) await RequireOriginalMailboxSendChainAsync(current, held, opened, scope, command.Operation.ToArray(), native!.ExactEnvelope.ToArray(),
                        application, sends, grants, own, source,
                        checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample), ct).ConfigureAwait(false);
                    var parsed = ApplicationCoreCodec.DecodeDmc2(payload);
                    if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer)
                    {
                        using var manifest = offer.Manifest;
                        var asset = assets.Entries.Values.SingleOrDefault(item => FixedRoute(item.Object, manifest.ObjectId.Span)) ??
                            throw new InvalidDataException("A retained attachment offer lost its protected local object.");
                        using var actual = await ReadStableAttachmentManifestUnderLeaseAsync(current, held, application, asset.Operation.ToArray(), ct).ConfigureAwait(false);
                        if (!EqualOwnedAttachmentManifests(actual, manifest))
                            throw new CryptographicException("Retained attachment keys differ from the independently preserved offer.");
                    }
                }
                finally { CryptographicOperations.ZeroMemory(payload); }
            }
            var effects = await application.CaptureOrdinaryOutboxEffectsAsync(scope, selected, ct, action).ConfigureAwait(false);
            var rows = selected.Select(entry => new Did2CompactionPlan.Row(action,
                entry.Operation.ToArray(), SHA256.HashData(entry.Exact))).OrderBy(row => Convert.ToHexString(row.Selector.Span), StringComparer.Ordinal).ToArray();
            if (stoppedOnly)
                foreach (var entry in selected)
                    journal.RetireWorkingPayload(Convert.ToHexString(entry.Operation));
            else
            {
                sendSuccessor = RemoveSelectedOrdinarySendCommitments(sends, scope, rows);
                journal.RetireSuccessfulCommands(selected);
            }
            successor = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            var descriptors = new List<Did2CompactionPlan.Root>();
            for (var rootIndex = 0; rootIndex < roots.Count; rootIndex++)
            {
                var digest = roots[rootIndex].Use(bytes => SHA256.HashData(bytes));
                var changed = rootIndex == 0 ? successor : sendSuccessor;
                descriptors.Add(rootIndex == 0 || rootIndex == 1 && !stoppedOnly
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

    private async Task RequireOriginalMailboxSendChainAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> nativeEnvelope, SqliteDeepMailboxStore application,
        ProtectedDid2MailboxSendJournal.State sends, ProtectedDid2MailboxGrantJournal.State grants,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, DeepIdV2ContactPathAuthoritySource source,
        ulong currentUpper, CancellationToken ct,
        ReadOnlyMemory<byte> initialIntent = default, IDeepMlDsa65Verifier? initialVerifier = null)
    {
        foreach (var send in sends.RequirePreparedChain(scope.Hash, operation.Span))
        {
            var attempt = send.Attempt.ToArray(); var logical = MailboxSendOperation(scope, attempt, nativeEnvelope.Span);
            try
            {
                // Known loss of possibly-forwarded public evidence is corruption;
                // still-pending/unknown work is backpressure, never deletion proof.
                await application.RequireAttemptedStoreEvidenceAsync(scope, operation, attempt, logical, ct).ConfigureAwait(false);
                if (await application.ReadDurableStorePublicEvidenceAsync(scope, operation, attempt, logical, ct).ConfigureAwait(false) is null)
                    throw new IOException("An unresolved attempt pins the complete native send chain.");
                await RequireOriginalMailboxSendCommitmentAsync(current, held, opened, scope, operation, attempt, nativeEnvelope,
                    application, sends, grants, own, source, currentUpper, ct, initialIntent, initialVerifier).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(attempt); CryptographicOperations.ZeroMemory(logical); }
        }
    }

    private async Task RequireOriginalMailboxSendCommitmentAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> attempt, ReadOnlyMemory<byte> nativeEnvelope, SqliteDeepMailboxStore application,
        ProtectedDid2MailboxSendJournal.State sends, ProtectedDid2MailboxGrantJournal.State grants,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, DeepIdV2ContactPathAuthoritySource source,
        ulong currentUpper, CancellationToken ct,
        ReadOnlyMemory<byte> initialIntent = default, IDeepMlDsa65Verifier? initialVerifier = null)
    {
        if (!sends.Entries.TryGetValue(Convert.ToHexString(ProtectedDid2MailboxSendJournal.Key(scope.Hash, attempt.Span)), out var send) ||
            !send.Prepared || !FixedRoute(send.ScopeHash, scope.Hash) || !FixedRoute(send.Operation, operation.Span) ||
            !FixedRoute(send.Attempt, attempt.Span) ||
            !FixedRoute(send.EnvelopeHash, SHA256.HashData(nativeEnvelope.Span)))
            throw new CryptographicException("Original Store lost the exact prepared native send commitment.");
        var evidence = await application.RequireStorePublicEvidenceAsync(scope, operation, attempt, ct).ConfigureAwait(false);
        await RequireStoreEvidenceCommitmentUnderLeaseAsync(held, scope, operation, attempt, evidence, ct).ConfigureAwait(false);
        if (evidence.IsInitial != !initialIntent.IsEmpty)
            throw new CryptographicException("Original chain recipient evidence differs from its native send kind.");
        var route = evidence.IsInitial ? ContactRouteClosureCodec.Decode(evidence.OriginalRoute.Span) :
            await ReadOriginalPeerStoreRouteAsync(current, held, opened, application, evidence.OriginalRoute, ct).ConfigureAwait(false);
        if (!FixedRoute(evidence.Logical.Span, send.MailboxOperation) ||
            !FixedRoute(send.RouteHash, SHA256.HashData(route.ExactBytes.Span)))
            throw new CryptographicException("Original send differs from retained public/native route custody.");
        var read = await application.ReadTransportOutboxAsync(OutboxAccountScope.FromBytes(evidence.AccountScope.Span),
            OutboxLogicalId.FromBytes(send.MailboxOperation), ct).ConfigureAwait(false);
        if (read is not { Result: TransportOutboxReadResult.Found, Item.State: TransportOutboxState.Durable or TransportOutboxState.Delivered })
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
            var keys = MailboxStoreReplicaEvidenceVerifier.Verify(own.Network, own.Authority, route, evidence.Replicas);
            var receipt = await VerifyOriginalStoreOutcomeAsync(scope, attempt, nativeEnvelope, application, route,
                evidence, keys, own, source, currentUpper, ct).ConfigureAwait(false);
            if (evidence.IsInitial)
                await RequireOriginalInitialStoreRecipientUnderLeaseAsync(current, held, opened, scope, initialIntent,
                    evidence, nativeEnvelope, exact, receipt, own.Authority,
                    initialVerifier ?? throw new CryptographicException("Initial chain lost its live approved verifier."), ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
}
