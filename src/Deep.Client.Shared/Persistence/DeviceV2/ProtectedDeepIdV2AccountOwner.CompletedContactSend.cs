using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Selector inputs only. The owner derives success from original native,
    // semantic, public-policy, MAU/quorum and coordinator custody, not flags.
    internal async Task RetireOwnedCompletedContactMailboxSendAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope requestedScope, ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> initialIntent,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        if (scope.IsInitiator)
        {
            ProtectedDph2PreClaimJournal.RequireIntent(initialIntent.Span);
            if (!FixedRoute(operation.Span, InitialMailboxOperation(initialIntent.Span)))
                throw new ArgumentException("An initial contact send must select its exact original intent.", nameof(operation));
        }
        else if (!initialIntent.IsEmpty) throw new ArgumentException("ContactAccept cannot use an initial sender intent.", nameof(initialIntent));
        var op = operation.ToArray(); var intent = initialIntent.ToArray(); var key = ProtectedDid2MailboxSendJournal.Key(scope.Hash, op);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, scope.LocalAccount, scope.Instance);
            using var prior = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (prior.Phase != 0)
            {
                var controlAudit = prior.Target == Did2CompactionPlan.SqlTarget.Application && prior.RowCount == 1 &&
                    (prior.ReadRow(0).Action is Did2CompactionPlan.Disposition.StoppedControlPayload or Did2CompactionPlan.Disposition.ExpiredControlAudit) &&
                    FixedRoute(prior.SqlSelector, scope.Hash) &&
                    FixedRoute(prior.ReadRow(0).Selector.Span, op);
                var sendRetirement = prior.Target == Did2CompactionPlan.SqlTarget.ProtectedOnly && prior.RowCount == 1 &&
                    (prior.ReadRow(0).Action is Did2CompactionPlan.Disposition.InitialPayload or Did2CompactionPlan.Disposition.ContactAcceptPayload) &&
                    FixedRoute(prior.SqlSelector, scope.Hash) && FixedRoute(prior.ReadRow(0).Selector.Span, key);
                if (!controlAudit && !sendRetirement)
                    throw new InvalidOperationException("Another exact local plan owns recovery.");
                await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                if (sendRetirement) return;
                // The audit is the first owned phase. Its recovery must finish
                // before selecting the remaining original send-chain closure.
            }
            using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            RequireRetainedStoreOwnScope(scope, own);
            using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
            if (!scope.IsInitiator)
            {
                using var accepts = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Completed send selection lost its explicit ContactAccept command.");
                using var commands = accepts.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                var command = commands.FindScope(scope);
                if (command is null || !FixedRoute(command.Operation, op))
                    throw new CryptographicException("Completed ContactAccept selection has another explicit command.");
            }
            var result = scope.IsInitiator
                ? await TryReadRetainedInitialStoreUnderLeaseAsync(current, held, opened, scope, intent, null, own, source, verifier, ct).ConfigureAwait(false)
                : await TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope, op, own, source, ct).ConfigureAwait(false);
            if (result is null) throw new IOException("An unknown or incomplete original Store pins its contact send.");
            using var sendRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Completed send selection lost its mandatory send registration.");
            var predecessor = sendRaw.Use(bytes => bytes.ToArray()); byte[] envelope = [], successor = [], consentSuccessor = [], grantPredecessor = [];
            try
            {
                using var sends = ProtectedDid2MailboxSendJournal.Decode(predecessor, scope.Network, scope.LocalAccount, scope.Instance);
                if (!sends.Entries.TryGetValue(Convert.ToHexString(key), out var selected))
                {
                    if (scope.IsInitiator)
                    {
                        using var draft = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                        using var commands = draft.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                        if (!commands.Entries.TryGetValue(Convert.ToHexString(intent), out var command) || !command.PayloadRetired)
                            throw new CryptographicException("A missing working send cannot initialize Initial payload retirement.");
                    }
                    else
                    {
                        using var consent = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                        using var commands = consent.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                        var command = commands.FindScope(scope) ?? throw new CryptographicException("Completed send lost its explicit consent marker.");
                        if (!command.PayloadRetired) throw new CryptographicException("A missing working send cannot initialize consent payload retirement.");
                    }
                    // Positive original Store was independently verified above.
                    // Already retired is idempotent, never an enrollment/repair.
                    await MaintainStoppedControlUnderLeaseAsync(current, held, scope, op, own, source, ct).ConfigureAwait(false);
                    var retiredGuards = await CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct,
                        scope.IsInitiator ? MailboxCustodyProfile.InitialPayload : MailboxCustodyProfile.ContactPayload).ConfigureAwait(false);
                    await RequireCompletedContactSendGuardsUnderLeaseAsync(current, held, retiredGuards, ct).ConfigureAwait(false);
                    await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false); return;
                }
                if (!selected.Prepared) throw new IOException("Pending exact send work cannot retire.");
                using var grantRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Completed send lost original grant custody.");
                grantPredecessor = grantRaw.Use(bytes => bytes.ToArray());
                using var grants = grantRaw.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                    storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
                if (scope.IsInitiator)
                    envelope = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, op, intent, ct).ConfigureAwait(false);
                else
                {
                    var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                    using var native = opened.Sql.ReadVerifiedOperation(floor, op) ?? throw new CryptographicException("Completed ContactAccept lost its native send.");
                    if (native.Direction != 1) throw new CryptographicException("A receive event cannot retire an outgoing send.");
                    envelope = native.ExactEnvelope.ToArray();
                }
                await RequireOriginalMailboxSendChainAsync(current, held, opened, scope, op, envelope, application, sends, grants,
                    own, source, checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample), ct,
                    intent, verifier).ConfigureAwait(false);
                // A late positive parent result cannot advance even local
                // maintenance while another attempt remains pending/unknown.
                // Verify the complete chain BEFORE any audit/plan mutation.
                await MaintainStoppedControlUnderLeaseAsync(current, held, scope, op, own, source, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, predecessor, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot,
                    grantPredecessor, ct).ConfigureAwait(false);
                // Maintenance advances the plan revision. Re-read the actual
                // idle state and guards instead of overwriting its predecessor.
                using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                if (idle.Phase != 0) throw new InvalidOperationException("Another exact local plan owns recovery.");
                var before = await CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct,
                    scope.IsInitiator ? MailboxCustodyProfile.InitialPayload : MailboxCustodyProfile.ContactPayload).ConfigureAwait(false);
                var row = new Did2CompactionPlan.Row(scope.IsInitiator ? Did2CompactionPlan.Disposition.InitialPayload :
                    Did2CompactionPlan.Disposition.ContactAcceptPayload, key, sends.ChainCommitment(scope.Hash, op));
                successor = RemoveCompletedContactSend(sends, scope.Hash, row, scope.Network, scope.LocalAccount, scope.Instance);
                if (scope.IsInitiator)
                {
                    using var draft = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                        throw new InvalidDataException("Completed Initial lost its working draft root.");
                    consentSuccessor = draft.Use(bytes => RemoveCompletedInitialPayload(bytes, scope.Hash, row.Selector.Span,
                        scope.Network, scope.LocalAccount, scope.Instance));
                }
                else
                {
                    using var consent = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                        throw new InvalidDataException("Completed acceptance lost its working payload root.");
                    consentSuccessor = consent.Use(bytes => RemoveCompletedContactAcceptPayload(bytes, scope.Hash, row.Selector.Span,
                        scope.Network, scope.LocalAccount, scope.Instance));
                }
                var roots = before.Select((guard, index) => new Did2CompactionPlan.Root(guard.Kind, guard.Selector, guard.Digest,
                    guard.Kind is Did2CompactionPlan.RootKind.ContactAccept or Did2CompactionPlan.RootKind.ContactStart ? SHA256.HashData(consentSuccessor) :
                        index == 1 ? SHA256.HashData(successor) : guard.Digest,
                    index != 1 && guard.Kind is not (Did2CompactionPlan.RootKind.ContactAccept or Did2CompactionPlan.RootKind.ContactStart),
                    guard.Kind is Did2CompactionPlan.RootKind.ContactAccept or Did2CompactionPlan.RootKind.ContactStart ? consentSuccessor :
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
            finally { CryptographicOperations.ZeroMemory(predecessor); CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(successor); CryptographicOperations.ZeroMemory(consentSuccessor); CryptographicOperations.ZeroMemory(grantPredecessor); }
        }
        finally { CryptographicOperations.ZeroMemory(op); CryptographicOperations.ZeroMemory(intent); CryptographicOperations.ZeroMemory(key); }
    }

    private async Task<IReadOnlyList<Did2CompactionPlan.RootReadback>> CaptureCompletedContactSendGuardsUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, CancellationToken ct,
        MailboxCustodyProfile profile = MailboxCustodyProfile.Complete)
    {
        if (profile is not (MailboxCustodyProfile.Complete or MailboxCustodyProfile.InitialPayload or MailboxCustodyProfile.ContactPayload or
            MailboxCustodyProfile.StoppedInitial or MailboxCustodyProfile.StoppedAccept))
            throw new ArgumentOutOfRangeException(nameof(profile));
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            var guards = await ReadMailboxProtectedRootsUnderLeaseAsync(current.AccountId, instance, held, ct).ConfigureAwait(false);
            guards.Add(await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(storage, lease, sqlStatePath, current, held, ct).ConfigureAwait(false));
            if (profile == MailboxCustodyProfile.Complete)
                guards.Add(await ReadMailboxStoreStateUnderLeaseAsync(current.AccountId, instance, held, ct).ConfigureAwait(false));
            else if (profile is MailboxCustodyProfile.ContactPayload or MailboxCustodyProfile.StoppedAccept)
            {
                using var consent = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Completed acceptance lost its explicit consent root.");
                guards.Add(new(Did2CompactionPlan.RootKind.ContactAccept, CompactionSlotSelector(ProtectedDid2ContactAcceptJournal.Slot),
                    consent.Use(bytes => SHA256.HashData(bytes))));
                guards.Add(profile == MailboxCustodyProfile.StoppedAccept
                    ? await ReadStoppedControlCustodyUnderLeaseAsync(current.AccountId, instance, held, false, ct).ConfigureAwait(false)
                    : await ReadMailboxContactCustodyUnderLeaseAsync(current.AccountId, instance, held, ct).ConfigureAwait(false));
            }
            else
            {
                guards.Add(profile == MailboxCustodyProfile.StoppedInitial
                    ? await ReadStoppedControlCustodyUnderLeaseAsync(current.AccountId, instance, held, true, ct).ConfigureAwait(false)
                    : await ReadMailboxInitialCustodyUnderLeaseAsync(current.AccountId, instance, held, ct).ConfigureAwait(false));
                using var draft = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Completed Initial lost its explicit draft root.");
                guards.Add(new(Did2CompactionPlan.RootKind.ContactStart, CompactionSlotSelector(ProtectedDid2ContactStartJournal.Slot),
                    draft.Use(bytes => SHA256.HashData(bytes))));
            }
            return guards;
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    private async Task RequireCompletedContactSendGuardsUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, IReadOnlyList<Did2CompactionPlan.RootReadback> original, CancellationToken ct)
    {
        var latest = await CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct,
            original.Any(guard => guard.Kind == Did2CompactionPlan.RootKind.ContactStart) ? MailboxCustodyProfile.InitialPayload :
                original.Any(guard => guard.Kind == Did2CompactionPlan.RootKind.ContactAccept) ? MailboxCustodyProfile.ContactPayload : MailboxCustodyProfile.Complete).ConfigureAwait(false);
        if (latest.Count != original.Count || latest.Where((guard, index) => guard.Kind != original[index].Kind ||
            !FixedRoute(guard.Selector.Span, original[index].Selector.Span) || !FixedRoute(guard.Digest.Span, original[index].Digest.Span)).Any())
            throw new CryptographicException("Completed contact-send custody changed before staging.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    private static byte[] RemoveCompletedContactSend(ProtectedDid2MailboxSendJournal.State sends, ReadOnlySpan<byte> scope,
        Did2CompactionPlan.Row row, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var name = Convert.ToHexString(row.Selector.Span);
        if (row.Action is not (Did2CompactionPlan.Disposition.Audit or Did2CompactionPlan.Disposition.ContactAcceptPayload or Did2CompactionPlan.Disposition.InitialPayload) || !sends.Entries.TryGetValue(name, out var send) ||
            !FixedRoute(send.ScopeHash, scope) || !FixedRoute(ProtectedDid2MailboxSendJournal.Key(scope, send.Operation), row.Selector.Span))
            throw new CryptographicException("Completed send disposition differs from exact original custody or replay floor.");
        var chain = sends.RequirePreparedChain(scope, send.Operation);
        var commitment = sends.ChainCommitment(scope, send.Operation);
        try
        {
            if (!FixedRoute(commitment, row.Commitment.Span)) throw new CryptographicException("Completed send plan lost part of its original attempt chain.");
        }
        finally { CryptographicOperations.ZeroMemory(commitment); }
        var revision = checked(sends.Revision + 1);
        foreach (var entry in chain) { sends.Entries.Remove(entry.Name); entry.Dispose(); }
        sends.Revision = revision;
        return ProtectedDid2MailboxSendJournal.Encode(sends, network, account, instance);
    }

    private static void RequireCompletedContactSendSuccessor(Did2CompactionPlan plan, ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> successor)
    {
        using var sends = ProtectedDid2MailboxSendJournal.Decode(predecessor, plan.Exact.Slice(16, 16).Span,
            plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
        var expected = RemoveCompletedContactSend(sends, plan.SqlSelector, plan.ReadRow(0), plan.Exact.Slice(16, 16).Span,
            plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
        try { if (!FixedRoute(expected, successor)) throw new CryptographicException("Completed send successor changed unrelated work or replay floors."); }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }
}
