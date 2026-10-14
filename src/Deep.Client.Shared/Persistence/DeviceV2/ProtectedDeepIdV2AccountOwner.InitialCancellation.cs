using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task StopInitialContactIntentAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        ReadOnlyMemory<byte> intent, ProtectedDid2DirectTextJournal.WorkStopReason reason,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span);
        var op = intent.ToArray(); byte[] before = [], after = [], instance = [];
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
            instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            before = raw.Use(bytes => bytes.ToArray());
            using var drafts = ProtectedDid2ContactStartJournal.Decode(before, networkId, current.AccountId.Span, instance);
            if (!drafts.Entries.TryGetValue(Convert.ToHexString(op), out var draft)) throw new CryptographicException("Initial cancellation has no owned draft intent.");
            if (!draft.WorkStopped && !draft.PayloadRetired)
                RequireControlStopExpiry(reason, Did2ControlWorkStop.ProvenExpirySecond(draft.ExpiresAtUnixMilliseconds),
                    checked(own.Proof.TrustedLowerUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample), ct);
            using (var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage,
                sqlStatePath, current, held, ct).ConfigureAwait(false))
                await application.BindPreSessionAuditAccountAsync(current, ct).ConfigureAwait(false);
            // An absent device source may be provisioned only before stop under
            // independently current account ownership. Existing missing state
            // is never repaired; local recovery thereafter only reopens it.
            using var sourceStore = await SqliteDeepIdV2AccountGeneration.OpenCurrentDeviceStateStoreAsync(storage, sqlStatePath, current, ct).ConfigureAwait(false);
            using var completed = await sourceStore.HasCompletedInitialSessionAsync(op, ct).ConfigureAwait(false)
                ? await sourceStore.ReadMessagingSourceByIntentUnderLeaseAsync(op, ct).ConfigureAwait(false) : null;
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            Did2MessagingSessionScope? selected = null;
            if (completed is not null)
            {
                if (!draft.PayloadRetired)
                {
                    var conversation = completed.RequireInitialConversation(draft.Init, draft.Hello);
                    try { if (!FixedRoute(conversation, draft.Conversation)) throw new CryptographicException("Initial cancellation selected another completed source."); }
                    finally { CryptographicOperations.ZeroMemory(conversation); }
                }
                selected = catalog.FindSource(completed.SessionId.Span, SHA256.HashData(completed.CanonicalSpan));
            }
            for (var index = 0; index < catalog.Count; index++)
            {
                var scope = catalog.Scope(index);
                if (scope.IsInitiator && FixedRoute(scope.Conversation, draft.Conversation) && FixedRoute(scope.LocalDevice, draft.LocalDevice) &&
                    FixedRoute(scope.RemoteAccount, draft.Exact.Slice(64, 32)) && (selected is null || !FixedRoute(selected.Exact, scope.Exact)))
                    throw new CryptographicException("Initial cancellation has foreign or lost source/catalog custody.");
            }
            if (selected is not null)
            {
                using var opened = await SqliteDeepIdV2AccountGeneration.OpenRegisteredMessagingUnderLeaseAsync(storage, sqlStatePath,
                    networkId, current.AccountId, selected, ct).ConfigureAwait(false);
                var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                if (floor.Ordinal != 0)
                {
                    if (draft.WorkStopped && draft.NativeStopMode != 1) throw new CryptographicException("Pre-session stopped intent acquired native work.");
                    completed?.Dispose();
                    await CompleteMessagingTransferUnderLeaseAsync(current, opened, ct).ConfigureAwait(false);
                    if (!await TryStopControlWorkUnderLeaseAsync(current, held, opened, selected, InitialMailboxOperation(op), reason,
                        verifier, own, source, ct).ConfigureAwait(false)) throw new CryptographicException("Committed native Initial lost its exact draft.");
                    return;
                }
                if (!FixedRoute(floor.Exact.Span, Did2MessagingFloor.Empty(selected).Exact.Span)) throw new CryptographicException("Initial has unresolved native import custody.");
            }
            var retirements = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            if (retirements.Entries.Values.Any(entry => entry.Role == 1 && FixedRoute(entry.Intent, op)))
                throw new CryptographicException("A transferred sender cannot infer cancellation from missing native import.");
            if (draft.WorkStopped)
            {
                if (draft.NativeStopMode != 2) throw new CryptographicException("Admitted Initial lost its native scope.");
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2ContactStartJournal.Slot, before, ct).ConfigureAwait(false);
            }
            else
            {
                if (draft.PayloadRetired) throw new CryptographicException("Completed Initial cannot borrow pre-session absence.");
                var final = await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
                var stopped = draft.WithStoppedWork(reason, checked(own.Proof.TrustedUpperUnixSeconds + final.SampleSeconds - own.Proof.MonotonicSample),
                    networkId, current.AccountId.Span, nativeCommitted: false);
                drafts.Entries[Convert.ToHexString(op)] = stopped; draft.Dispose(); drafts.Revision = checked(drafts.Revision + 1);
                after = ProtectedDid2ContactStartJournal.Encode(drafts, networkId, current.AccountId.Span, instance);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
#if DEEP_TEST_INTERNALS
                Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeWorkStopRoot);
#endif
                if (!await storage.CompareExchangeAsync(ProtectedDid2ContactStartJournal.Slot, before, after, ct).ConfigureAwait(false))
                    throw new CryptographicException("Pre-session Initial changed before stop commitment.");
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2ContactStartJournal.Slot, after, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterWorkStopRoot);
#endif
            }
            completed?.Dispose();
            await sourceStore.RetireCancelledInitialUnderLeaseAsync(sqlStatePath, op, held, lease, ct).ConfigureAwait(false);
            await MaintainPreSessionControlUnderLeaseAsync(current, held, op, instance, own, source, ct).ConfigureAwait(false);
        }
        finally { foreach (var bytes in new[] { op, before, after, instance }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task ResumeInitialCancellationKeysUnderLeaseAsync(ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var retirements = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, networkId, account, ct).ConfigureAwait(false);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var drafts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, networkId, account.Span, instance.Span));
        foreach (var draft in drafts.Entries.Values.Where(entry => entry.WorkStopped && entry.NativeStopMode == 2))
        {
            if (retirements.FindCancellation(draft.Intent)?.Phase == 2) continue;
            using var store = await SqliteDeepIdV2AccountGeneration.OpenExistingCancellationSourceUnderLeaseAsync(storage,
                sqlStatePath, networkId, account, instance, held, lease, ct).ConfigureAwait(false);
            await store.RetireCancelledInitialUnderLeaseAsync(sqlStatePath, draft.Intent.ToArray(), held, lease, ct).ConfigureAwait(false);
        }
    }
}
