using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal sealed partial class MailboxEpochExclusion
    {
        // Retire only the excluded grant's idle counter namespace. This does
        // NOT retire an acquisition, retained route, traversal or object path.
        // Their custody and every semantic/receipt/asset root remain unchanged.
        internal async Task RetireIdleMailboxCounterFloorAsync(CancellationToken ct = default)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                var dependencies = await RetirementDependencies.CaptureUnderGateAsync(this, ct).ConfigureAwait(false);
                using var grants = ProtectedDid2MailboxGrantJournal.Decode(root, owner.networkId, current.AccountId.Span, instance);
                var entry = RequireKnownMailboxFloorEntry(grants, acquisition);
                var changedIndex = MailboxFloorRootIndex(entry);
                var slot = ClosedAcquisitionRootSlots[changedIndex];
                using var original = await owner.storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Mailbox floor retirement lost its mandatory counter root.");
                var before = original.Use(bytes => bytes.ToArray());
                byte[] successor = [];
                try
                {
                    successor = RemoveIdleMailboxFloor(before, entry, owner.networkId, current.AccountId.Span, instance);
                    var storeState = await owner.ReadMailboxStoreStateUnderLeaseAsync(current.AccountId, instance, held, ct).ConfigureAwait(false);
                    var plans = new ProtectedDid2CompactionPlan(owner.storage, owner.lease, owner.networkId, current.AccountId.Span, instance);
                    using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                    if (idle.Phase != 0) throw new InvalidOperationException("An active local plan owns recovery.");
                    var roots = dependencies.Guards.Select((guard, index) => new Did2CompactionPlan.Root(guard.Kind, guard.Selector,
                        guard.Digest, index == changedIndex ? SHA256.HashData(successor) : guard.Digest,
                        index != changedIndex, index == changedIndex ? successor : ReadOnlyMemory<byte>.Empty))
                        .Append(new Did2CompactionPlan.Root(storeState.Kind, storeState.Selector, storeState.Digest,
                            storeState.Digest, true, ReadOnlyMemory<byte>.Empty)).ToArray();
                    var row = new Did2CompactionPlan.Row(Did2CompactionPlan.Disposition.ReplayScope, acquisition.ToArray(), SHA256.HashData(entry));
                    using var preparation = idle.Prepare(Did2CompactionPlan.SqlTarget.ProtectedOnly, RandomNumberGenerator.GetBytes(32),
                        entry.AsSpan(0, 32), new byte[32], new byte[32], roots, [row]);
                    await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                    await dependencies.RequireExactGuardsUnderGateAsync(ct).ConfigureAwait(false);
                    var latestStoreState = await owner.ReadMailboxStoreStateUnderLeaseAsync(current.AccountId, instance, held, ct).ConfigureAwait(false);
                    if (!FixedRoute(storeState.Selector.Span, latestStoreState.Selector.Span) ||
                        !FixedRoute(storeState.Digest.Span, latestStoreState.Digest.Span))
                        throw new CryptographicException("Mailbox state changed before counter retirement staging.");
                    await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                    await plans.StageAsync(idle, preparation, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
                    await owner.ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(successor); }
            }
            finally { gate.Release(); }
        }
    }

    private static byte[] RequireKnownMailboxFloorEntry(ProtectedDid2MailboxGrantJournal.State grants, ReadOnlySpan<byte> acquisition)
    {
        if (!grants.Entries.TryGetValue(Convert.ToHexString(acquisition), out var entry) || entry[96] is not (2 or 5) ||
            !ProtectedDid2MailboxGrantJournal.HasWinner(entry))
            throw new IOException("Counter retirement requires an adopted exact known grant; unknown acquisitions remain pinned.");
        return entry;
    }

    private static int MailboxFloorRootIndex(byte[] entry) =>
        ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span).Field(6).Span[0] switch
        {
            (byte)MailboxCapabilityDomain.Deposit => 1,
            (byte)MailboxCapabilityDomain.Retrieve => 3,
            _ => throw new InvalidDataException("Counter retirement has an unsupported grant domain.")
        };

    // Structural exact dependency index for the counter ONLY. Caller holds
    // the independently checked epoch exclusion and pins protected/native SQL roots.
    // Any matching send commitment (including pending/unknown) pins its floor;
    // any captured Retrieve/ACK cycle pins its original grant counter.
    // Unrelated work is preserved, not reclassified as terminal or evicted.
    private static byte[] RemoveIdleMailboxFloor(ReadOnlySpan<byte> original, byte[] entry,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var exactGrant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(exactGrant.Span);
        var digest = SHA256.HashData(exactGrant.Span);
        try
        {
            if (MailboxFloorRootIndex(entry) == 1)
            {
                using var state = ProtectedDid2MailboxSendJournal.Decode(original, network, account, instance);
                state.RequireGrant(grant);
                if (state.Entries.Values.Any(value => FixedRoute(value.GrantHash, digest)))
                    throw new IOException("An exact send commitment still depends on this counter floor.");
                var replayScope = Convert.ToHexString(MailboxCapabilityReplayStateMachine.ComputeScopeKey(grant, MailboxAuthenticatedOperation.Store));
                var floor = state.Floors[replayScope];
                state.Floors.Remove(replayScope); CryptographicOperations.ZeroMemory(floor.GrantHash);
                state.Revision = checked(state.Revision + 1);
                return ProtectedDid2MailboxSendJournal.Encode(state, network, account, instance);
            }
            using (var state = ProtectedDid2MailboxReadJournal.Decode(original, network, account, instance))
            {
                if (state.Active is { } active && FixedRoute(active.Grant, digest))
                    throw new IOException("A captured Retrieve/ACK cycle still depends on this counter floor.");
                if (!state.Counters.Remove(Convert.ToHexString(digest)))
                    throw new InvalidDataException("The exact known read counter floor is absent; no repair is permitted.");
                state.Revision = checked(state.Revision + 1);
                // The original traversal and all other grant counters remain.
                return ProtectedDid2MailboxReadJournal.Encode(state, network, account, instance);
            }
        }
        finally { CryptographicOperations.ZeroMemory(digest); }
    }

    private async Task RequireMailboxFloorSuccessorAsync(Did2CompactionPlan plan, int changedIndex,
        byte[] predecessor, byte[] successor, CancellationToken ct)
    {
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Mailbox floor recovery lost its unchanged original grant custody.");
        if (!raw.Use(bytes => FixedRoute(SHA256.HashData(bytes), plan.ReadRoot(2).Before.Span)))
            throw new CryptographicException("Mailbox floor recovery changed original grant custody.");
        using var grants = raw.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, networkId,
            plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span));
        var row = plan.ReadRow(0); var entry = RequireKnownMailboxFloorEntry(grants, row.Selector.Span);
        if (MailboxFloorRootIndex(entry) != changedIndex || !FixedRoute(entry.AsSpan(0, 32), plan.SqlSelector) ||
            !FixedRoute(SHA256.HashData(entry), row.Commitment.Span))
            throw new CryptographicException("Mailbox floor recovery selected a different exact original grant.");
        var expected = RemoveIdleMailboxFloor(predecessor, entry, networkId, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
        try { if (!FixedRoute(expected, successor)) throw new CryptographicException("Mailbox floor successor changed unrelated custody."); }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }
}
