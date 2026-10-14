using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Control-specific original-outcome proof, existing generic protected-only
    // Audit recovery. Retire redundant send commitments, NOT native purpose,
    // exact SQL/frame/evidence, grant/holder/object work or independent floors.
    internal async Task RetireOwnedCompletedBraidSendAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope requestedScope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var op = operation.ToArray(); var key = ProtectedDid2MailboxSendJournal.Key(scope.Hash, op);
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, scope.LocalAccount, scope.Instance);
            using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (idle.Phase != 0)
            {
                if (idle.Target != Did2CompactionPlan.SqlTarget.ProtectedOnly ||
                    idle.ReadRow(0).Action != Did2CompactionPlan.Disposition.Audit ||
                    !FixedRoute(idle.SqlSelector, scope.Hash) || !FixedRoute(idle.ReadRow(0).Selector.Span, key))
                    throw new InvalidOperationException("Another exact local plan owns control Store recovery.");
                await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false); return;
            }
            using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            RequireRetainedStoreOwnScope(scope, own);
            using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            using var native = RequireOwnedBraidSend(opened, scope, floor, op);
            var before = await CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
            if (await TryReadRetainedBraidStoreUnderLeaseAsync(current, held, opened, scope, op, own, source, ct).ConfigureAwait(false) is null)
                throw new IOException("Unknown control Store pins its original transport commitments.");
            using var sendRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Control retirement lost mandatory send registration.");
            var predecessor = sendRaw.Use(bytes => bytes.ToArray()); byte[] exact = [], successor = [];
            try
            {
                using var sends = ProtectedDid2MailboxSendJournal.Decode(predecessor, scope.Network, scope.LocalAccount, scope.Instance);
                if (!sends.Entries.TryGetValue(Convert.ToHexString(key), out var selected))
                {
                    await RequireCompletedContactSendGuardsUnderLeaseAsync(current, held, before, ct).ConfigureAwait(false);
                    await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
                    return; // Verified original outcome; already retired, never repaired/enrolled.
                }
                if (!selected.Prepared) throw new IOException("Unprepared control transport work cannot retire.");
                using var grantRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Control retirement lost original grant custody.");
                using var grants = grantRaw.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                    storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
                exact = native.ExactControl.ToArray();
                await RequireOriginalMailboxSendChainAsync(current, held, opened, scope, op, exact, application, sends,
                    grants, own, source, checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample), ct).ConfigureAwait(false);
                var row = new Did2CompactionPlan.Row(Did2CompactionPlan.Disposition.Audit, key, sends.ChainCommitment(scope.Hash, op));
                successor = RemoveCompletedContactSend(sends, scope.Hash, row, scope.Network, scope.LocalAccount, scope.Instance);
                var roots = before.Select((guard, index) => new Did2CompactionPlan.Root(guard.Kind, guard.Selector, guard.Digest,
                    index == 1 ? SHA256.HashData(successor) : guard.Digest, index != 1,
                    index == 1 ? successor : ReadOnlyMemory<byte>.Empty)).ToArray();
                using var prepared = idle.Prepare(Did2CompactionPlan.SqlTarget.ProtectedOnly, RandomNumberGenerator.GetBytes(32),
                    scope.Hash, new byte[32], new byte[32], roots, [row]);
                await RequireCompletedContactSendGuardsUnderLeaseAsync(current, held, before, ct).ConfigureAwait(false);
                await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
                await plans.StageAsync(idle, prepared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
                await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(predecessor); CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(successor); }
        }
        finally { CryptographicOperations.ZeroMemory(op); CryptographicOperations.ZeroMemory(key); }
    }
}
