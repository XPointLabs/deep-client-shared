using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal sealed partial class MailboxEpochExclusion
    {
        internal async Task RetireSupersededRetrieveAcquisitionAsync(IDeepMlDsa65Verifier verifier, CancellationToken ct)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                var dependencies = await RetirementDependencies.CaptureUnderGateAsync(this, ct).ConfigureAwait(false);
                const RetirementDependency preserved = RetirementDependency.AcquisitionChain | RetirementDependency.ReadTraversal |
                    RetirementDependency.RetainedRetrievePath | RetirementDependency.UnresolvedReceiptOrObject;
                if ((dependencies.Dependencies & ~preserved) != RetirementDependency.None)
                    throw new IOException("Working requests, counters or unresolved assets pin Retrieve holder retirement.");
                using var grants = ProtectedDid2MailboxGrantJournal.Decode(root, owner.networkId, current.AccountId.Span, instance);
                var entry = ProtectedDid2MailboxGrantJournal.RequireSupersededRetrieve(grants, acquisition);
                var replacement = ProtectedDid2MailboxGrantJournal.CurrentWinner(grants, Convert.ToHexString(entry.AsSpan(0, 32)))!;
                var before = await owner.CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
                using var publication = await owner.OpenOwnRetainedPublicationUnderLeaseAsync(current, held, source, fresh, ct,
                    ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span).ExactHash).ConfigureAwait(false);
                if (!FixedRoute(publication.Route.ExactBytes.Span, ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span))
                    throw new CryptographicException("Replacement read path lost this account's actual original publication.");
                var winner = await publication.Host.VerifyRetainedReadSuccessAsync(publication.Route.ExactBytes,
                    ProtectedDid2MailboxGrantJournal.Request(replacement), ProtectedDid2MailboxGrantJournal.Response(replacement), ct).ConfigureAwait(false);
                var request = ContactCodec.Decode("XMG2", winner.ExactXmg2.Span);
                if (!FixedRoute(request.Field(3).Span, publication.Locator.Span) || !FixedRoute(request.Field(4).Span, publication.Capability.Span))
                    throw new CryptographicException("Replacement Retrieve holder lost actual private publication capability custody.");
                var replicas = await publication.Host.GetSelectedRetainedReadReplicasAsync(winner.ExactGrant, ct).ConfigureAwait(false);
                var ids = publication.Route.Selection.Field(6);
                if (replicas.Count != 2 || !FixedRoute(replicas[0].NodeId.Span, ids.Span[..32]) ||
                    !FixedRoute(replicas[1].NodeId.Span, ids.Span[32..]))
                    throw new CryptographicException("Replacement read path cannot rerank the original replicas.");
                using var policy = await OpenRetainedInstallationPolicyAsync(current, held, publication, winner, source, fresh, ct).ConfigureAwait(false);
                var authority = new VerifiedOfficialMailboxAuthority(fresh.MailboxAuthority.NetworkId, fresh.MailboxAuthority.MinimumGrantGeneration,
                    [fresh.MailboxAuthority.ResolveIssuer(MailboxCapabilityDomain.Retrieve)], false, static () => true, policy, policy.Clock);
                var credential = new VerifiedCurrentMailboxGrant(request, ContactCodec.Decode("XMC2", winner.ExactXmc2.Span),
                    MailboxAuthenticatedCapabilityCodec.DecodeGrant(winner.ExactGrant.Span), publication.Route,
                    replicas.Select(replica => new VerifiedCurrentMailboxReplica(replica.NodeId.Span, replica.SigningPublicKey.Span)).ToArray(), authority);
                using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                    owner.storage, owner.sqlStatePath, owner.networkId, current.AccountId, instance, held, owner.lease, ct).ConfigureAwait(false);
                await credential.RequireInstalledRetrieveAsync(application, ct).ConfigureAwait(false);
                using var raw = await owner.storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                using var read = raw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, owner.networkId, current.AccountId.Span, instance));
                var scope = ClientMailboxScope.Derive(publication.Route.ExactHash.Span, credential.MailboxId, credential.Epoch);
                if (read.Phase != 0 || read.Active is not null || !read.Traversals.TryGetValue(Convert.ToHexString(scope.Value), out var traversal))
                    throw new IOException("Incomplete read/ACK or missing protected traversal pins holder retirement.");
                RequireReadTraversal(await application.ReadTraversalAsync(scope, ct).ConfigureAwait(false), traversal);
                var exactGrant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8);
                await application.RequireSettledGrantReadCoverageAsync(exactGrant, scope, traversal, credential.MailboxId, credential.PlacementId, ct).ConfigureAwait(false);
                await application.RequireSettledGrantReadCoverageAsync(winner.ExactGrant, scope, traversal, credential.MailboxId, credential.PlacementId, ct).ConfigureAwait(false);
                var plans = new ProtectedDid2CompactionPlan(owner.storage, owner.lease, owner.networkId, current.AccountId.Span, instance);
                using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                if (idle.Phase != 0) throw new InvalidOperationException("An active local plan owns recovery.");
                var row = new Did2CompactionPlan.Row(Did2CompactionPlan.Disposition.ReplayScope, acquisition.ToArray(), SHA256.HashData(entry));
                var selector = entry.AsSpan(0, 32).ToArray();
                var successor = ProtectedDid2MailboxGrantJournal.RemoveSupersededRetrieve(grants, acquisition,
                    owner.networkId, current.AccountId.Span, instance);
                try
                {
                    var roots = before.Select((guard, index) => new Did2CompactionPlan.Root(guard.Kind, guard.Selector,
                        guard.Digest, index == 2 ? SHA256.HashData(successor) : guard.Digest, index != 2,
                        index == 2 ? successor : ReadOnlyMemory<byte>.Empty)).ToArray();
                    using var prepared = idle.Prepare(Did2CompactionPlan.SqlTarget.ProtectedOnly, RandomNumberGenerator.GetBytes(32),
                        selector, new byte[32], new byte[32], roots, [row]);
                    await publication.RecheckAsync(ct).ConfigureAwait(false); await winner.EnsureCurrentAsync(ct).ConfigureAwait(false);
                    await credential.RequireInstalledRetrieveAsync(application, ct).ConfigureAwait(false);
                    await dependencies.RequireExactGuardsUnderGateAsync(ct).ConfigureAwait(false);
                    await owner.RequireCompletedContactSendGuardsUnderLeaseAsync(current, held, before, ct).ConfigureAwait(false);
                    await RecheckUnderGateAsync(ct).ConfigureAwait(false); policy.ValidateFreshness();
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
}
