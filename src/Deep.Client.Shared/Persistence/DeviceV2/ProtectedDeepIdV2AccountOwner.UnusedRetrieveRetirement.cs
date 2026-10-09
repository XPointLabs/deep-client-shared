using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal sealed partial class MailboxEpochExclusion
    {
        // A closed unknown grant response is not a completed read or a negative
        // issuance result. Retire only its excluded private acquisition, keeping
        // the actual permanent publication and owner read capability intact.
        internal async Task RetireUnusedClosedRetrieveAcquisitionAsync(CancellationToken ct = default)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                var dependencies = await RetirementDependencies.CaptureUnderGateAsync(this, ct).ConfigureAwait(false);
                using var grants = ProtectedDid2MailboxGrantJournal.Decode(root, owner.networkId, current.AccountId.Span, instance);
                var selector = RequireUnusedClosedRetrieve(grants, acquisition);
                byte[] successor = [];
                try
                {
                    var entry = grants.Entries[Convert.ToHexString(acquisition)];
                    var linked = ProtectedDid2MailboxGrantJournal.CurrentWinner(grants, Convert.ToHexString(selector)) is not null;
                    var preserved = linked
                        ? RetirementDependency.AcquisitionChain | RetirementDependency.ReadTraversal |
                          RetirementDependency.UnresolvedReceiptOrObject | RetirementDependency.RetainedRetrievePath
                        : RetirementDependency.RetainedRetrievePath;
                    if ((dependencies.Dependencies & ~preserved) != RetirementDependency.None)
                        throw new IOException("Working requests, counters or assets pin closed Retrieve retirement.");
                    var request = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span);
                    using var publication = await owner.OpenOwnRetainedPublicationUnderLeaseAsync(current, held, source, fresh, ct,
                        ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span).ExactHash).ConfigureAwait(false);
                    if (!FixedRoute(publication.Route.ExactBytes.Span, ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span) ||
                        !FixedRoute(request.Field(3).Span, publication.Locator.Span) ||
                        !FixedRoute(request.Field(4).Span, publication.Capability.Span))
                        throw new CryptographicException("Closed Retrieve lost its actual original private publication.");
                    if (linked) await RequireOriginalReadCustodyAsync(grants, publication, dependencies.Dependencies, ct).ConfigureAwait(false);
                    var before = await owner.CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
                    var plans = new ProtectedDid2CompactionPlan(owner.storage, owner.lease, owner.networkId, current.AccountId.Span, instance);
                    using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                    if (idle.Phase != 0) throw new InvalidOperationException("An active local plan owns recovery.");
                    var row = new Did2CompactionPlan.Row(Did2CompactionPlan.Disposition.ReplayScope, acquisition.ToArray(), SHA256.HashData(entry));
                    successor = RemoveUnusedClosedRetrieve(grants, acquisition, owner.networkId, current.AccountId.Span, instance);
                    var roots = before.Select((guard, index) => new Did2CompactionPlan.Root(guard.Kind, guard.Selector,
                        guard.Digest, index == 2 ? SHA256.HashData(successor) : guard.Digest, index != 2,
                        index == 2 ? successor : ReadOnlyMemory<byte>.Empty)).ToArray();
                    using var prepared = idle.Prepare(Did2CompactionPlan.SqlTarget.ProtectedOnly, RandomNumberGenerator.GetBytes(32),
                        selector, new byte[32], new byte[32], roots, [row]);
                    await publication.RecheckAsync(ct).ConfigureAwait(false);
                    await dependencies.RequireExactGuardsUnderGateAsync(ct).ConfigureAwait(false);
                    await owner.RequireCompletedContactSendGuardsUnderLeaseAsync(current, held, before, ct).ConfigureAwait(false);
                    await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                    await plans.StageAsync(idle, prepared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
                    await owner.ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(selector); CryptographicOperations.ZeroMemory(successor); }
            }
            finally { gate.Release(); }
        }

        private async Task RequireOriginalReadCustodyAsync(ProtectedDid2MailboxGrantJournal.State grants,
            OwnRetainedPublication publication, RetirementDependency dependencies, CancellationToken ct)
        {
            var candidate = grants.Entries[Convert.ToHexString(acquisition)];
            var original = ProtectedDid2MailboxGrantJournal.CurrentWinner(grants, Convert.ToHexString(candidate.AsSpan(0, 32)))!;
            using var raw = await owner.storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Closed renewal lost mandatory read custody.");
            using var read = raw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, owner.networkId, current.AccountId.Span, instance));
            if (read.Phase != 0 || read.Active is not null) throw new IOException("An active read/ACK pins closed renewal retirement.");
            var mailbox = new BlindedMailboxId(publication.Route.Reachability.Field(2).Span);
            var placement = new BlindedPlacementId(publication.Route.Reachability.Field(10).Span);
            var grant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(original).Span).Field(8);
            var decoded = MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant.Span);
            var scope = ClientMailboxScope.Derive(publication.Route.ExactHash.Span, mailbox, decoded.Epoch);
            if (!read.Traversals.TryGetValue(Convert.ToHexString(scope.Value), out var traversal))
            {
                if ((dependencies & RetirementDependency.UnresolvedReceiptOrObject) != 0)
                    throw new IOException("Original semantic work has no completed read/ACK custody.");
                return; // No read state is deleted or synthesized for an unused original holder.
            }
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                owner.storage, owner.sqlStatePath, owner.networkId, current.AccountId, instance, held, owner.lease, ct).ConfigureAwait(false);
            RequireReadTraversal(await application.ReadTraversalAsync(scope, ct).ConfigureAwait(false), traversal);
            await application.RequireSettledGrantReadCoverageAsync(grant, scope, traversal, mailbox, placement, ct).ConfigureAwait(false);
        }
    }

    private static byte[] RequireUnusedClosedRetrieve(ProtectedDid2MailboxGrantJournal.State state, ReadOnlySpan<byte> acquisition) =>
        ProtectedDid2MailboxGrantJournal.RequireUnusedClosedRetrieveTail(state, acquisition).AsSpan(0, 32).ToArray();

    private static byte[] RemoveUnusedClosedRetrieve(ProtectedDid2MailboxGrantJournal.State state, ReadOnlySpan<byte> acquisition,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance) =>
        ProtectedDid2MailboxGrantJournal.RemoveUnusedClosedRetrieveTail(state, acquisition, network, account, instance);
}
