using System.Security.Cryptography;
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
                if (dependencies.Dependencies != RetirementDependency.RetainedRetrievePath)
                    throw new IOException("Working, linked or previously read custody pins closed Retrieve retirement.");
                using var grants = ProtectedDid2MailboxGrantJournal.Decode(root, owner.networkId, current.AccountId.Span, instance);
                var selector = RequireUnusedClosedRetrieve(grants, acquisition);
                byte[] successor = [];
                try
                {
                    var entry = grants.Entries[Convert.ToHexString(acquisition)];
                    var request = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span);
                    using var publication = await owner.OpenOwnRetainedPublicationUnderLeaseAsync(current, held, source, fresh, ct,
                        ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span).ExactHash).ConfigureAwait(false);
                    if (!FixedRoute(publication.Route.ExactBytes.Span, ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span) ||
                        !FixedRoute(request.Field(3).Span, publication.Locator.Span) ||
                        !FixedRoute(request.Field(4).Span, publication.Capability.Span))
                        throw new CryptographicException("Closed Retrieve lost its actual original private publication.");
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
    }

    private static byte[] RequireUnusedClosedRetrieve(ProtectedDid2MailboxGrantJournal.State state, ReadOnlySpan<byte> acquisition) =>
        RequireUnusedClosedAcquisition(state, acquisition, MailboxCapabilityDomain.Retrieve);

    private static byte[] RemoveUnusedClosedRetrieve(ProtectedDid2MailboxGrantJournal.State state, ReadOnlySpan<byte> acquisition,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance) =>
        RemoveUnusedClosedAcquisition(state, acquisition, network, account, instance, MailboxCapabilityDomain.Retrieve);
}
