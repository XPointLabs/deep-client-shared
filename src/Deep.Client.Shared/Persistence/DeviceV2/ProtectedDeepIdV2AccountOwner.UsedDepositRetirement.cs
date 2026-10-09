using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

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
                    await RequireOriginalStoreObjectClosureUnderGateAsync(entry, exactGrant, verifier, ct).ConfigureAwait(false);
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

        private async Task RequireOriginalStoreObjectClosureUnderGateAsync(byte[] entry, byte[] exactGrant,
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
                var metadata = await application.RequireStorePublicEvidenceAsync(scope, operation, token).ConfigureAwait(false);
                if (metadata.IsInitial)
                {
                    var draft = RequireRetirementInitialDraft(drafts, scope);
                    if (!FixedRoute(InitialMailboxOperation(draft.Intent), operation.Span))
                        throw new CryptographicException("Original initial Store has a different native intent.");
                    if (await owner.TryReadRetainedInitialStoreUnderLeaseAsync(current, held, opened, scope, draft.Intent.ToArray(),
                        null, fresh, source, verifier, token).ConfigureAwait(false) is null)
                        throw new IOException("An unknown original initial Store pins Deposit retirement.");
                }
                else if (await owner.TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope, operation,
                    fresh, source, token).ConfigureAwait(false) is null)
                    throw new IOException("An unknown original outgoing Store pins Deposit retirement.");
                // The historical verifier above reconstructs the original
                // recipient route from independent public/native custody and
                // verifies the exact accepted body, holder signature, quorum
                // and coordinator. It never reads a private Deposit holder.
                // Keep those complete paths byte-exact under the ninth guard;
                // a live object is preserved, not shortened to grant expiry.
                return await application.IsOriginalStoreForGrantRetirementAsync(scope, operation, exactGrant, token).ConfigureAwait(false);
            }

            // Forward join from independently protected native custody. Missing
            // application rows never make actual outgoing work disappear.
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
                    try { await VerifyOriginal(scope, opened, operation, ct).ConfigureAwait(false); }
                    finally { CryptographicOperations.ZeroMemory(operation); }
                }
                var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                foreach (var operation in opened.Sql.ReadVerifiedOutgoingOperations(floor, ct))
                {
                    try { await VerifyOriginal(scope, opened, operation, ct).ConfigureAwait(false); }
                    finally { CryptographicOperations.ZeroMemory(operation); }
                }
            }

            // Reverse join: every actual original MAU for this holder/grant
            // must have independently verified native/source custody. Streaming
            // pages keep memory fixed even when retained history grows.
            await application.RequireCompleteGrantStoreCoverageAsync(exactGrant, async (scopeHash, operation, token) =>
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
        }
    }

    private static ProtectedDid2ContactStartJournal.Entry RequireRetirementInitialDraft(
        ProtectedDid2ContactStartJournal.State drafts, Did2MessagingSessionScope scope)
    {
        ProtectedDid2ContactStartJournal.Entry? result = null;
        foreach (var draft in drafts.Entries.Values)
        {
            var init = ApplicationCoreCodec.DecodeDmc2(draft.Init);
            if (!FixedRoute(init.ConversationId.Span, scope.Conversation) || !FixedRoute(init.SenderDeviceId.Span, scope.LocalDevice) ||
                !FixedRoute(draft.Exact.Slice(64, 32), scope.RemoteAccount)) continue;
            if (result is not null) throw new CryptographicException("Initial native custody has ambiguous original drafts.");
            result = draft;
        }
        return result ?? throw new CryptographicException("Initial native custody lost its original contact draft.");
    }

    private void RequireUsedDepositSuccessor(Did2CompactionPlan plan, ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> successor)
    {
        using var state = ProtectedDid2MailboxGrantJournal.Decode(predecessor, networkId,
            plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
        var row = plan.ReadRow(0);
        var entry = ProtectedDid2MailboxGrantJournal.RequireOldestAdoptedDeposit(state, row.Selector.Span);
        if (!FixedRoute(entry.AsSpan(0, 32), plan.SqlSelector) || !FixedRoute(SHA256.HashData(entry), row.Commitment.Span))
            throw new CryptographicException("Used Deposit retirement changed its original selection.");
        var expected = ProtectedDid2MailboxGrantJournal.RemoveOldestAdoptedDeposit(state, row.Selector.Span,
            networkId, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
        try { if (!FixedRoute(expected, successor)) throw new CryptographicException("Used Deposit successor changed unrelated custody."); }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }
}
