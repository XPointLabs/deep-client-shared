using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task<bool> TryStopControlWorkUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ProtectedDid2DirectTextJournal.WorkStopReason reason, IDeepMlDsa65Verifier verifier,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, DeepIdV2ContactPathAuthoritySource source,
        CancellationToken ct)
    {
        held.RequireOwner(lease);
        var slot = scope.IsInitiator ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var raw = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Control stop lost mandatory command custody.");
        var before = raw.Use(bytes => bytes.ToArray()); byte[] after = [];
        try
        {
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            if (scope.IsInitiator)
            {
                using var journal = ProtectedDid2ContactStartJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                var winner = FindControlInitial(journal, scope, operation.Span);
                if (winner is null) return false;
                if (winner.WorkStopped && winner.NativeStopMode != 1)
                    throw new CryptographicException("Pre-session stopped Initial cannot masquerade as admitted native work.");
                var events = await ReadRetainedInitialDraftEventsUnderLeaseAsync(current, held, winner, scope.Instance.ToArray(), ct).ConfigureAwait(false);
                try { winner.RequireExactEvents(events.Init, events.Hello, scope.Network, scope.LocalAccount); }
                finally { CryptographicOperations.ZeroMemory(events.Init); CryptographicOperations.ZeroMemory(events.Hello); }
                if (!winner.WorkStopped && floor.Ordinal != 0 &&
                    await TryReadRetainedInitialStoreUnderLeaseAsync(current, held, opened, scope, winner.Intent.ToArray(),
                        null, own, source, verifier, ct).ConfigureAwait(false) is not null)
                {
                    await MaintainStoppedControlUnderLeaseAsync(current, held, scope, operation, own, source, ct).ConfigureAwait(false);
                    return true;
                }
                if (winner.SuccessfullyStored) throw new CryptographicException("Successful Initial lost its original Store.");
                if (winner.WorkStopped)
                {
                    await RequireExactProtectedMailboxRootAsync(slot, before, ct).ConfigureAwait(false);
                    await MaintainStoppedControlUnderLeaseAsync(current, held, scope, operation, own, source, ct).ConfigureAwait(false);
                    return true;
                }
                RequireControlStopExpiry(reason, Did2ControlWorkStop.ProvenExpirySecond(winner.ExpiresAtUnixMilliseconds),
                    checked(own.Proof.TrustedLowerUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample), ct);
                var stopTime = await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
                var upper = checked(own.Proof.TrustedUpperUnixSeconds + stopTime.SampleSeconds - own.Proof.MonotonicSample);
                var next = winner.WithStoppedWork(reason, upper, scope.Network, scope.LocalAccount, nativeCommitted: true);
                journal.Entries[Convert.ToHexString(winner.Intent)] = next; winner.Dispose(); journal.Revision = checked(journal.Revision + 1);
                after = ProtectedDid2ContactStartJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            }
            else
            {
                using var journal = ProtectedDid2ContactAcceptJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                var winner = journal.FindScope(scope);
                if (winner is null || !FixedRoute(winner.Operation, operation.Span)) return false;
                using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                    storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
                using var native = opened.Sql.ReadVerifiedOperation(floor, operation.Span);
                ulong deadline;
                if (native is null)
                {
                    if (winner.PayloadRetired && winner.NativeStopMode != 2 || winner.WorkStopped && winner.NativeStopMode == 1)
                        throw new CryptographicException("Retired acceptance lost its original native operation.");
                    using var sendsRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                    using var sends = sendsRaw.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                    if (sends.Entries.Values.Any(entry => FixedRoute(entry.Operation, operation.Span)))
                        throw new CryptographicException("Transport-owned acceptance cannot masquerade as an unencrypted draft.");
                    var history = await application.ReadRetainedAuthoredEventAsync(scope, winner.EventHash.ToArray(), ct).ConfigureAwait(false);
                    try { if (history is not null) throw new CryptographicException("Missing native acceptance cannot retain semantic history."); }
                    finally { if (history is not null) CryptographicOperations.ZeroMemory(history); }
                    deadline = winner.WorkStopped ? 0 : Did2ControlWorkStop.ProvenExpirySecond(ApplicationCoreCodec.DecodeDmc2(winner.Accept).ExpiresAtUnixMilliseconds);
                }
                else
                {
                    if (winner.WorkStopped && winner.NativeStopMode == 2)
                        throw new CryptographicException("An unencrypted stopped acceptance acquired a foreign native operation.");
                    using var history = await ReadRetainedContactAcceptEventUnderLeaseAsync(held, opened, application, winner, operation, ct).ConfigureAwait(false);
                    deadline = history.Use(bytes => Did2ControlWorkStop.ProvenExpirySecond(ApplicationCoreCodec.DecodeDmc2(bytes).ExpiresAtUnixMilliseconds));
                }
                if (!winner.WorkStopped && native is not null &&
                    await TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope, operation, own, source, ct).ConfigureAwait(false) is not null)
                {
                    await MaintainStoppedControlUnderLeaseAsync(current, held, scope, operation, own, source, ct).ConfigureAwait(false);
                    return true;
                }
                if (winner.SuccessfullyStored) throw new CryptographicException("Successful acceptance lost its original Store.");
                if (winner.WorkStopped)
                {
                    await RequireExactProtectedMailboxRootAsync(slot, before, ct).ConfigureAwait(false);
                    await MaintainStoppedControlUnderLeaseAsync(current, held, scope, operation, own, source, ct).ConfigureAwait(false);
                    return true;
                }
                RequireControlStopExpiry(reason, deadline,
                    checked(own.Proof.TrustedLowerUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample), ct);
                var stopTime = await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
                var upper = checked(own.Proof.TrustedUpperUnixSeconds + stopTime.SampleSeconds - own.Proof.MonotonicSample);
                var next = winner.WithStoppedWork(reason, upper, native is not null);
                journal.Entries[Convert.ToHexString(winner.Operation)] = next; winner.Dispose(); journal.Revision = checked(journal.Revision + 1);
                after = ProtectedDid2ContactAcceptJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            }
            var confirmed = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(floor.Exact.Span, confirmed.Exact.Span)) throw new CryptographicException("Control native custody changed before stop.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
#if DEEP_TEST_INTERNALS
            Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeWorkStopRoot);
#endif
            if (!await storage.CompareExchangeAsync(slot, before, after, ct).ConfigureAwait(false)) throw new CryptographicException("Control command changed before stop commitment.");
            await RequireExactProtectedMailboxRootAsync(slot, after, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterWorkStopRoot);
#endif
            await MaintainStoppedControlUnderLeaseAsync(current, held, scope, operation, own, source, ct).ConfigureAwait(false);
            return true;
        }
        finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
    }

    private static ProtectedDid2ContactStartJournal.Entry? FindControlInitial(ProtectedDid2ContactStartJournal.State journal,
        Did2MessagingSessionScope scope, ReadOnlySpan<byte> operation)
    {
        ProtectedDid2ContactStartJournal.Entry? winner = null;
        foreach (var entry in journal.Entries.Values)
        {
            var original = InitialMailboxOperation(entry.Intent);
            try
            {
                if (!FixedRoute(original, operation)) continue;
                if (winner is not null || !FixedRoute(entry.Conversation, scope.Conversation) ||
                    !FixedRoute(entry.LocalDevice, scope.LocalDevice) || !FixedRoute(entry.Exact.Slice(64, 32), scope.RemoteAccount))
                    throw new CryptographicException("Control stop selected another or ambiguous Initial scope.");
                winner = entry;
            }
            finally { CryptographicOperations.ZeroMemory(original); }
        }
        return winner;
    }

    private static void RequireControlStopExpiry(ProtectedDid2DirectTextJournal.WorkStopReason reason, ulong deadline,
        ulong authenticatedLower, CancellationToken ct)
    {
        if (reason is not (ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled or ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired))
            throw new ArgumentOutOfRangeException(nameof(reason));
        if (reason == ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired &&
            authenticatedLower < deadline)
            throw new IOException("Authenticated lower time has not proven the control retry deadline.");
        ct.ThrowIfCancellationRequested();
    }

    private async Task<bool> RequireControlWorkNotStoppedUnderLeaseAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var slot = scope.IsInitiator ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var root = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Control retry lost mandatory command custody.");
        var found = false;
        if (scope.IsInitiator)
        {
            using var journal = root.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var initial = FindControlInitial(journal, scope, operation.Span);
            found = initial is not null;
            if (initial?.WorkStopped == true)
                throw new IOException("Initial sender work is permanently stopped; stop is not recall or proof of non-delivery.");
        }
        else
        {
            using var journal = root.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var winner = journal.FindScope(scope);
            found = winner is not null && FixedRoute(winner.Operation, operation.Span);
            if (found && winner!.WorkStopped)
                throw new IOException("ContactAccept sender work is permanently stopped; stop is not recall or proof of non-delivery.");
        }
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        return found;
    }

    private async Task ResumeStoppedControlWorkUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, IDeepMlDsa65Verifier verifier,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var slot = scope.IsInitiator ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var raw = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        ProtectedDid2DirectTextJournal.WorkStopReason reason;
        if (scope.IsInitiator)
        {
            using var root = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            reason = FindControlInitial(root, scope, operation.Span)?.StopReason ?? ProtectedDid2DirectTextJournal.WorkStopReason.Active;
        }
        else
        {
            using var root = raw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var entry = root.FindScope(scope);
            reason = entry is not null && FixedRoute(entry.Operation, operation.Span) ? entry.StopReason : ProtectedDid2DirectTextJournal.WorkStopReason.Active;
        }
        if (reason != ProtectedDid2DirectTextJournal.WorkStopReason.Active)
            if (!await TryStopControlWorkUnderLeaseAsync(current, held, opened, scope, operation, reason, verifier, own, source, ct).ConfigureAwait(false))
                throw new CryptographicException("Stopped control lost its exact command.");
    }
}
