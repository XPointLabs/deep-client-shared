using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal sealed partial class MailboxEpochExclusion
    {
        // Called only by the service while its original verifier is alive.
        // A copied clock, SQL count or caller's terminal flag cannot authorize
        // this transition. All accepted objects, original public Store evidence,
        // native peer routes, source/history and receipt obligations remain
        // independently held: this removes a write-holder, not a read path or
        // object. No recipient Delivered/Read outcome is synthesized.
        internal async Task RetireUsedDepositAcquisitionAsync(IDeepMlDsa65Verifier verifier, CancellationToken ct)
            => await RetireAdoptedDepositAcquisitionAsync(verifier, requireOriginalWork: true, ct).ConfigureAwait(false);

        // Private maintenance producer only. SQL absence chooses a candidate,
        // not permission. Actual native-forward and SQL-reverse coverage below
        // must both prove no original work for this exact excluded grant.
        internal async Task RetireUnusedAdoptedDepositAcquisitionAsync(IDeepMlDsa65Verifier verifier, CancellationToken ct)
            => await RetireAdoptedDepositAcquisitionAsync(verifier, requireOriginalWork: false, ct).ConfigureAwait(false);

        private async Task RetireAdoptedDepositAcquisitionAsync(IDeepMlDsa65Verifier verifier,
            bool requireOriginalWork, CancellationToken ct)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                var dependencies = await RetirementDependencies.CaptureUnderGateAsync(this, ct).ConfigureAwait(false);
                const RetirementDependency closedHere = RetirementDependency.AcquisitionChain | RetirementDependency.UnresolvedReceiptOrObject;
                if ((dependencies.Dependencies & ~closedHere) != RetirementDependency.None)
                    throw new IOException("Working mailbox, counter, traversal or asset dependencies pin Deposit retirement.");
                using var grants = ProtectedDid2MailboxGrantJournal.Decode(root, owner.networkId, current.AccountId.Span, instance);
                var entry = ProtectedDid2MailboxGrantJournal.RequireOldestAdoptedDeposit(grants, acquisition);
                var exactGrant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).ToArray();
                var before = await owner.CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
                byte[] successor = [];
                try
                {
                    var hasOriginalWork = await RequireOriginalStoreObjectClosureUnderGateAsync(entry, exactGrant, verifier, ct).ConfigureAwait(false);
                    if (hasOriginalWork != requireOriginalWork)
                        throw new IOException("Deposit retirement profile differs from independently verified original work.");
                    var plans = new ProtectedDid2CompactionPlan(owner.storage, owner.lease, owner.networkId, current.AccountId.Span, instance);
                    using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                    if (idle.Phase != 0) throw new InvalidOperationException("An active local plan owns recovery.");
                    var row = new Did2CompactionPlan.Row(Did2CompactionPlan.Disposition.ReplayScope, acquisition.ToArray(), SHA256.HashData(entry));
                    var scope = entry.AsSpan(0, 32).ToArray();
                    try
                    {
                        successor = ProtectedDid2MailboxGrantJournal.RemoveOldestAdoptedDeposit(grants, acquisition,
                            owner.networkId, current.AccountId.Span, instance);
                        var roots = before.Select((guard, index) => new Did2CompactionPlan.Root(guard.Kind, guard.Selector,
                            guard.Digest, index == 2 ? SHA256.HashData(successor) : guard.Digest,
                            index != 2, index == 2 ? successor : ReadOnlyMemory<byte>.Empty)).ToArray();
                        using var prepared = idle.Prepare(Did2CompactionPlan.SqlTarget.ProtectedOnly, RandomNumberGenerator.GetBytes(32),
                            scope, new byte[32], new byte[32], roots, [row]);
                        await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                        await dependencies.RequireExactGuardsUnderGateAsync(ct).ConfigureAwait(false);
                        await owner.RequireCompletedContactSendGuardsUnderLeaseAsync(current, held, before, ct).ConfigureAwait(false);
                        await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                        await plans.StageAsync(idle, prepared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
                        await owner.ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                    }
                    finally { CryptographicOperations.ZeroMemory(scope); }
                }
                finally { CryptographicOperations.ZeroMemory(exactGrant); CryptographicOperations.ZeroMemory(successor); }
            }
            finally { gate.Release(); }
        }

        private async Task<bool> RequireOriginalStoreObjectClosureUnderGateAsync(byte[] entry, byte[] exactGrant,
            IDeepMlDsa65Verifier verifier, CancellationToken ct)
        {
            await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
            var route = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span);
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(owner.storage, owner.networkId, current.AccountId.Span, instance)
                .ReadAsync(ct).ConfigureAwait(false);
            using var draftRaw = await owner.storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Deposit retirement lost original contact-start custody.");
            using var drafts = draftRaw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, owner.networkId, current.AccountId.Span, instance));
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                owner.storage, owner.sqlStatePath, owner.networkId, current.AccountId, instance, held, owner.lease, ct).ConfigureAwait(false);

            async Task<bool> VerifyOriginal(Did2MessagingSessionScope scope, OwnedDid2MessagingStorage opened,
                ReadOnlyMemory<byte> operation, CancellationToken token)
            {
                var draft = scope.IsInitiator ? RequireRetirementInitialDraft(drafts, scope) : null;
                var intent = draft is not null && FixedRoute(InitialMailboxOperation(draft.Intent), operation.Span)
                    ? draft.Intent.ToArray() : [];
                byte[][] attempts = [];
                byte[] envelope = [];
                try
                {
                    if (intent.Length != 0)
                    {
                        if (await owner.TryReadRetainedInitialStoreUnderLeaseAsync(current, held, opened, scope, intent,
                            null, fresh, source, verifier, token).ConfigureAwait(false) is null)
                            throw new IOException("An unknown original initial Store pins Deposit retirement.");
                    }
                    else if (await owner.TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope, operation,
                        fresh, source, token).ConfigureAwait(false) is null)
                        throw new IOException("An unknown original outgoing Store pins Deposit retirement.");
                    // One native event may have several original attempts/holders.
                    // A selected predecessor outcome cannot authenticate a successor
                    // or prove that this selected grant has complete object custody.
                    attempts = await application.ReadStoreAttemptCandidatesAsync(scope, operation, token).ConfigureAwait(false);
                    if (attempts.Length == 0) throw new IOException("Actual outgoing work lost original Store attempts.");
                    envelope = await owner.ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, operation,
                        intent, token).ConfigureAwait(false);
                    var reading = await RecheckRouteFreshnessAsync(current, source, fresh, held, first, token).ConfigureAwait(false);
                    var upper = checked(fresh.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - fresh.Proof.MonotonicSample);
                    var belongs = false;
                    foreach (var attempt in attempts)
                    {
                        var metadata = await application.RequireStorePublicEvidenceAsync(scope, operation, attempt, token).ConfigureAwait(false);
                        await owner.RequireStoreEvidenceCommitmentUnderLeaseAsync(held, scope, operation, attempt, metadata, token).ConfigureAwait(false);
                        if (metadata.IsInitial != (intent.Length != 0))
                            throw new CryptographicException("Original grant attempt differs from its actual native send kind.");
                        var originalRoute = metadata.IsInitial ? ContactRouteClosureCodec.Decode(metadata.OriginalRoute.Span) :
                            await owner.ReadOriginalPeerStoreRouteAsync(current, held, opened, application, metadata.OriginalRoute, token).ConfigureAwait(false);
                        var replicas = MailboxStoreReplicaEvidenceVerifier.Verify(fresh.Network, fresh.Authority, originalRoute, metadata.Replicas);
                        var receipt = await VerifyOriginalStoreOutcomeAsync(scope, attempt, envelope, application,
                            originalRoute, metadata, replicas, fresh, source, upper, token).ConfigureAwait(false);
                        if (metadata.IsInitial)
                        {
                            var stored = await application.ReadTransportOutboxAsync(OutboxAccountScope.FromBytes(metadata.AccountScope.Span),
                                OutboxLogicalId.FromBytes(metadata.Logical.Span), token).ConfigureAwait(false);
                            var request = stored.Item?.GetCiphertextBundleCopy() ?? throw new CryptographicException("Original Initial request disappeared.");
                            try
                            {
                                await owner.RequireOriginalInitialStoreRecipientUnderLeaseAsync(current, held, opened, scope, intent,
                                    metadata, envelope, request, receipt, fresh.Authority, verifier, token).ConfigureAwait(false);
                            }
                            finally { CryptographicOperations.ZeroMemory(request); }
                        }
                        // SQL membership is only a fact AFTER each exact native,
                        // original request/policy/replica/coordinator verification.
                        belongs |= await application.IsOriginalStoreForGrantRetirementAsync(scope, operation, attempt,
                            exactGrant, token).ConfigureAwait(false);
                    }
                    return belongs;
                }
                finally
                {
                    foreach (var bytes in attempts) CryptographicOperations.ZeroMemory(bytes);
                    CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(intent);
                }
            }

            // Forward join from independently protected native custody. Missing
            // application rows never make actual outgoing work disappear.
            var hasSelectedNativeWork = false;
            for (var index = 0; index < catalog.Count; index++)
            {
                var scope = catalog.Scope(index);
                if (!FixedRoute(scope.RemoteDevice, route.Authorization.Field(14).Span)) continue;
                if (catalog.Phase(index) != 2) throw new IOException("Uninitialized outgoing custody pins Deposit retirement.");
                using var opened = await owner.OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
                if (scope.IsInitiator)
                {
                    var draft = RequireRetirementInitialDraft(drafts, scope);
                    var operation = InitialMailboxOperation(draft.Intent);
                    try { hasSelectedNativeWork |= await VerifyOriginal(scope, opened, operation, ct).ConfigureAwait(false); }
                    finally { CryptographicOperations.ZeroMemory(operation); }
                }
                var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                foreach (var operation in opened.Sql.ReadVerifiedOutgoingOperations(floor, ct))
                {
                    try { hasSelectedNativeWork |= await VerifyOriginal(scope, opened, operation, ct).ConfigureAwait(false); }
                    finally { CryptographicOperations.ZeroMemory(operation); }
                }
            }

            // Reverse join: every actual original MAU for this holder/grant
            // must have independently verified native/source custody. Streaming
            // pages keep memory fixed even when retained history grows.
            var selectedSqlWork = await application.ReadCompleteGrantStoreCoverageAsync(exactGrant, async (scopeHash, operation, token) =>
            {
                Did2MessagingSessionScope? selected = null;
                for (var index = 0; index < catalog.Count; index++)
                {
                    var scope = catalog.Scope(index);
                    if (FixedRoute(scope.Hash, scopeHash.Span))
                    {
                        if (catalog.Phase(index) != 2) throw new IOException("Original Store has no initialized native custody.");
                        selected = scope; break;
                    }
                }
                if (selected is null) throw new CryptographicException("Original grant Store lost its protected native session.");
                if (!FixedRoute(selected.RemoteDevice, route.Authorization.Field(14).Span))
                    throw new CryptographicException("Original grant Store has another recipient device.");
                using var opened = await owner.OpenLocalHistoryUnderLeaseAsync(current, selected, token).ConfigureAwait(false);
                if (!await VerifyOriginal(selected, opened, operation, token).ConfigureAwait(false))
                    throw new CryptographicException("Original grant SQL coverage selected another native Store request.");
            }, ct).ConfigureAwait(false);
            if (hasSelectedNativeWork != (selectedSqlWork != 0))
                throw new CryptographicException("Original grant native and SQL coverage disagree.");
            return hasSelectedNativeWork;
        }
    }

    private static ProtectedDid2ContactStartJournal.Entry RequireRetirementInitialDraft(
        ProtectedDid2ContactStartJournal.State drafts, Did2MessagingSessionScope scope)
    {
        ProtectedDid2ContactStartJournal.Entry? result = null;
        foreach (var draft in drafts.Entries.Values)
        {
            if (!FixedRoute(draft.Conversation, scope.Conversation) || !FixedRoute(draft.LocalDevice, scope.LocalDevice) ||
                !FixedRoute(draft.Exact.Slice(64, 32), scope.RemoteAccount)) continue;
            if (result is not null) throw new CryptographicException("Initial native custody has ambiguous original drafts.");
            result = draft;
        }
        return result ?? throw new CryptographicException("Initial native custody lost its original contact draft.");
    }

    private void RequireAdoptedAcquisitionSuccessor(Did2CompactionPlan plan, ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> successor)
    {
        using var state = ProtectedDid2MailboxGrantJournal.Decode(predecessor, networkId,
            plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
        var row = plan.ReadRow(0);
        var original = state.Entries[Convert.ToHexString(row.Selector.Span)];
        var retrieve = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(original).Span).Field(6).Span[0] ==
            (byte)MailboxCapabilityDomain.Retrieve;
        if (retrieve && ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(original))
        {
            var scope = RequireUnusedClosedRetrieve(state, row.Selector.Span);
            try
            {
                if (!FixedRoute(scope, plan.SqlSelector) || !FixedRoute(SHA256.HashData(original), row.Commitment.Span))
                    throw new CryptographicException("Closed Retrieve retirement changed its original selection.");
                var closedSuccessor = RemoveUnusedClosedRetrieve(state, row.Selector.Span, networkId,
                    plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
                try { if (!FixedRoute(closedSuccessor, successor)) throw new CryptographicException("Closed Retrieve successor changed unrelated custody."); }
                finally { CryptographicOperations.ZeroMemory(closedSuccessor); }
            }
            finally { CryptographicOperations.ZeroMemory(scope); }
            return;
        }
        var entry = retrieve ? ProtectedDid2MailboxGrantJournal.RequireSupersededRetrieve(state, row.Selector.Span) :
            ProtectedDid2MailboxGrantJournal.RequireOldestAdoptedDeposit(state, row.Selector.Span);
        if (!FixedRoute(entry.AsSpan(0, 32), plan.SqlSelector) || !FixedRoute(SHA256.HashData(entry), row.Commitment.Span))
            throw new CryptographicException("Used Deposit retirement changed its original selection.");
        var expected = retrieve ? ProtectedDid2MailboxGrantJournal.RemoveSupersededRetrieve(state, row.Selector.Span,
            networkId, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span) :
            ProtectedDid2MailboxGrantJournal.RemoveOldestAdoptedDeposit(state, row.Selector.Span,
                networkId, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
        try { if (!FixedRoute(expected, successor)) throw new CryptographicException("Used Deposit successor changed unrelated custody."); }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }
}
