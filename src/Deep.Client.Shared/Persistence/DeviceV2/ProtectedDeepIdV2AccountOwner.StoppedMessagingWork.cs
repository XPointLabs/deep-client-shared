using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task CancelMessagingWorkAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
        using (var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException())
        using (var journal = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance)))
            if (!journal.Entries.ContainsKey(Convert.ToHexString(operation.Span)))
            {
                if (journal.TerminalAudits.TryGetValue(Convert.ToHexString(operation.Span), out var audit) && audit.Reason is 1 or 2)
                {
                    using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                        storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
                    await application.ValidateCompleteStoppedAuditsAsync(journal, ct).ConfigureAwait(false);
                    await ExpireTerminalAuditsUnderLeaseAsync(current, held, scope, own, source, ct).ConfigureAwait(false);
                    return; // Already stopped; this grants neither Store nor dispatch authority.
                }
                if (!await TryStopControlWorkUnderLeaseAsync(current, held, opened, scope, operation,
                    ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, verifier, own, source, ct).ConfigureAwait(false) &&
                    await TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope,
                        operation, own, source, ct).ConfigureAwait(false) is null)
                    throw new IOException("No retained cancellable command exists; absence is not delivery evidence.");
                // Compacted success remains success, including after diagnostic
                // audit expiry. Only the actual original Store proves this;
                // absence or an audit marker alone never authorizes a no-op.
                return;
            }
        await StabilizeCancelledPendingAuthorUnderLeaseAsync(current, held, scope, operation, own, source, ct).ConfigureAwait(false);
        await StopOrdinaryWorkUnderLeaseAsync(current, held, opened, scope, operation,
            ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, own, source, ct).ConfigureAwait(false);
    }

    // Finish only the existing authored reservation/SQL mirror. Cancellation
    // never calls the author, peer resolver, signer, grant issuer or ratchet.
    // Before the stop CAS a failed cancellation still leaves active work.
    private async Task StabilizeCancelledPendingAuthorUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Cancelling a draft lost mandatory authored custody.");
        var snapshot = raw.Use(bytes => bytes.ToArray()); byte[] next = [];
        try
        {
            using var journal = ProtectedDid2DirectTextJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
            if (!journal.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command) ||
                !FixedRoute(command.Scope.Exact, scope.Exact))
                throw new CryptographicException("Cancellation requires the exact retained authored command.");
            if (!command.Pending) return;
            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            using var mirrored = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, operation, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Cancellation lost its exact pending SQL readback.");
            var mirroredExact = OwnedByteExports.TakeArray(mirrored.ExactDmc2);
            try { command.RequireEvent(mirroredExact); }
            finally { CryptographicOperations.ZeroMemory(mirroredExact); }
#if DEEP_TEST_INTERNALS
            Did2TextOutboxTestHooks.Hit(Did2TextOutboxFailpoint.AfterCancelledPendingSql);
#endif
            await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            journal.Stabilize(Convert.ToHexString(operation.Span));
            next = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            if (!await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, snapshot, next, ct).ConfigureAwait(false))
                throw new CryptographicException("Pending cancellation changed its authored predecessor.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, next, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2TextOutboxTestHooks.Hit(Did2TextOutboxFailpoint.AfterCancelledPendingStable);
#endif
        }
        finally { CryptographicOperations.ZeroMemory(snapshot); CryptographicOperations.ZeroMemory(next); }
    }

    // Absence is read only after the independently protected native tip has
    // been verified. A stored/transport-owned/history-bearing event cannot be
    // relabelled as a never-encrypted draft to bypass native custody.
    private static async Task RequireUnencryptedCancelledDraftAsync(Did2MessagingSessionScope scope,
        ProtectedDid2DirectTextJournal.Entry command, SqliteDeepMailboxStore application,
        ProtectedDid2MailboxSendJournal.State sends, CancellationToken ct, bool beforeUserStop = false)
    {
        if (command.Pending || command.Stored ||
            command.StopReason != (beforeUserStop ? ProtectedDid2DirectTextJournal.WorkStopReason.Active : ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled) ||
            !FixedRoute(command.Scope.Exact, scope.Exact) || sends.Entries.Values.Any(entry =>
                FixedRoute(entry.Operation, command.Operation)))
            throw new CryptographicException("Missing native custody is not evidence for a stopped committed send.");
        var history = await application.ReadRetainedAuthoredEventAsync(scope, command.EventHash.ToArray(), ct).ConfigureAwait(false);
        try
        {
            if (history is not null)
                throw new CryptographicException("An unencrypted cancelled draft cannot have committed local history.");
        }
        finally { if (history is not null) CryptographicOperations.ZeroMemory(history); }
    }

    internal async Task RequireMessagingWorkNotStoppedAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var authoredRoot = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Retry expiry lost mandatory authored custody.");
        using var authored = authoredRoot.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes,
            scope.Network, scope.LocalAccount, scope.Instance));
        if (authored.TerminalAudits.TryGetValue(Convert.ToHexString(operation.Span), out var terminal) && terminal.Reason is 1 or 2)
        {
            await ExpireTerminalAuditsUnderLeaseAsync(current, held, scope, own, source, ct).ConfigureAwait(false);
            throw new IOException("Owned message work is stopped; cancellation is not recall or non-delivery.");
        }
        if (authored.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var stopped) && stopped.WorkStopped)
        {
            await RetireStoppedWorkingPayloadUnderLeaseAsync(current, held, scope, own, source, ct).ConfigureAwait(false);
            throw new IOException("Owned message work is stopped; cancellation is not recall or non-delivery.");
        }
        if (!authored.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command))
        {
            using var acceptsRaw = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Retry preflight lost mandatory ContactAccept custody.");
            using var accepts = acceptsRaw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes,
                scope.Network, scope.LocalAccount, scope.Instance));
            var acceptance = accepts.FindScope(scope);
            if (acceptance is not null && FixedRoute(acceptance.Operation, operation.Span))
                await RequireContactControlRetryTimeUnderLeaseAsync(current, held, scope, operation,
                    ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, verifier, own, source, ct).ConfigureAwait(false);
            return;
        }
        if (command.Pending) return;
        using var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Retry expiry lost mandatory original send custody.");
        var snapshot = root.Use(bytes => bytes.ToArray()); byte[] nativeEnvelope = [], closed = [];
        try
        {
            using var sends = ProtectedDid2MailboxSendJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
            var entry = sends.Current(scope.Hash, operation.Span);
            if (entry is null) return;
            var time = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            if (checked(own.Proof.TrustedLowerUnixSeconds + time.SampleSeconds - own.Proof.MonotonicSample) < entry.RetryUntil) return;
            using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
            var applicationDeadline = await ReadMailboxApplicationRetryDeadlineUnderLeaseAsync(current, held, opened,
                scope, operation, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
            if (entry.RetryUntil != Math.Min(entry.Expires, applicationDeadline))
                throw new CryptographicException("Retry expiry differs from its authenticated original application deadline.");
            nativeEnvelope = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, operation,
                ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
            // Expired attempt uncertainty closes under its existing original
            // custody checks before the independent logical work stop. No peer
            // refresh, grant acquisition or retained request dispatch occurs.
            closed = await CloseExpiredMailboxAttemptUnderLeaseAsync(current, held, opened, scope, operation,
                ReadOnlyMemory<byte>.Empty, nativeEnvelope, sends, snapshot, scope.Instance.ToArray(), source, own, ct).ConfigureAwait(false) ?? [];
            await StopExpiredOrdinaryWorkUnderLeaseAsync(current, held, opened, scope, operation, own, source, ct).ConfigureAwait(false);
            throw new IOException("The original logical retry deadline permanently stops sender work.");
        }
        finally { foreach (var bytes in new[] { snapshot, nativeEnvelope, closed }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task RequireOrdinaryWorkNotStoppedUnderLeaseAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Dispatch lost mandatory ordinary work custody.");
        using var journal = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes,
            scope.Network, scope.LocalAccount, scope.Instance));
        if (journal.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command))
        {
            if (!FixedRoute(command.Scope.Exact, scope.Exact))
                throw new CryptographicException("Dispatch selected another owned work scope.");
            if (command.WorkStopped) throw new IOException("Owned message work is stopped; cancellation is not recall or non-delivery.");
        }
        else if (!await RequireControlWorkNotStoppedUnderLeaseAsync(scope, operation, held, ct).ConfigureAwait(false))
            throw new IOException("No retained dispatchable command exists; retry cannot create or revive work.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    private async Task StopOrdinaryWorkUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ProtectedDid2DirectTextJournal.WorkStopReason reason,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Stopping work lost mandatory authored custody.");
        var snapshot = raw.Use(bytes => bytes.ToArray()); byte[] next = [], history = [];
        try
        {
            using var journal = ProtectedDid2DirectTextJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
            if (!journal.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command))
                throw new CryptographicException("Only retained actual ordinary work can be stopped.");
            if (command.Pending || !FixedRoute(command.Scope.Exact, scope.Exact))
                throw new CryptographicException("Stopping work requires the exact stable owned command.");
            if (command.Stored && !command.WorkStopped)
            {
                if (await TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope, operation, own, source, ct).ConfigureAwait(false) is null)
                    throw new CryptographicException("Successful terminal work lost its independently verified Store.");
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, snapshot, ct).ConfigureAwait(false);
                return; // First successful terminal outcome cannot become a later cancellation.
            }
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            using var native = opened.Sql.ReadVerifiedOperation(floor, operation.Span);
            if (native is not null && (native.Direction != 1 || !FixedRoute(native.EventHash, command.EventHash)))
                throw new CryptographicException("Stopping work cannot replace committed native custody.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            if (native is null)
            {
                using var sendRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Draft cancellation lost mandatory send custody.");
                using var sends = sendRoot.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                await RequireUnencryptedCancelledDraftAsync(scope, command, application, sends, ct,
                    beforeUserStop: !command.WorkStopped && reason == ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled).ConfigureAwait(false);
                using var exact = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                    System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, operation, ct,
                    requireStableReadOnly: true).ConfigureAwait(false);
                if (exact is null) throw new CryptographicException("Cancelled draft lost its only exact payload.");
                var draftExact = OwnedByteExports.TakeArray(exact.ExactDmc2);
                try { command.RequireEvent(draftExact); }
                finally { CryptographicOperations.ZeroMemory(draftExact); }
            }
            else
            {
                history = await application.ReadRetainedAuthoredEventAsync(scope, native.EventHash.ToArray(), ct).ConfigureAwait(false) ??
                    throw new CryptographicException("Stopping work lost its independent local history.");
                command.RequireEvent(history);
            }
            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            if (command.WorkStopped)
            {
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, snapshot, ct).ConfigureAwait(false);
                var unchanged = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                if (!FixedRoute(floor.Exact.Span, unchanged.Exact.Span))
                    throw new CryptographicException("Idempotent stop lost its unchanged native custody.");
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                await RetireStoppedWorkingPayloadUnderLeaseAsync(current, held, scope, own, source, ct).ConfigureAwait(false);
                return;
            }
            if (reason == ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired)
            {
                var deadline = await ReadMailboxApplicationRetryDeadlineUnderLeaseAsync(current, held, opened,
                    scope, operation, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
                using var sendRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Expired work lost its original attempt deadline.");
                using var sends = sendRoot.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes,
                    scope.Network, scope.LocalAccount, scope.Instance));
                var original = sends.Current(scope.Hash, operation.Span) ??
                    throw new CryptographicException("Expired transport work has no original attempt.");
                if (original.RetryUntil != Math.Min(original.Expires, deadline) ||
                    checked(own.Proof.TrustedLowerUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample) < original.RetryUntil)
                    throw new IOException("Current authenticated lower time has not proven the original retry deadline.");
            }
            var final = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(floor.Exact.Span, final.Exact.Span))
                throw new CryptographicException("Native custody changed while stopping work.");
            var stopTime = await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            // Capture the final authenticated upper observation, not caller
            // UTC, event creation, retry deadline or the earlier selection time.
            var stoppedAtUpper = checked(own.Proof.TrustedUpperUnixSeconds + stopTime.SampleSeconds - own.Proof.MonotonicSample);
            journal.StopWork(Convert.ToHexString(operation.Span), reason, stoppedAtUpper);
            next = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
#if DEEP_TEST_INTERNALS
            Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeWorkStopRoot);
#endif
            if (!await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, snapshot, next, ct).ConfigureAwait(false))
                throw new CryptographicException("Owned work changed before the stop commitment.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, next, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterWorkStopRoot);
#endif
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            await RetireStoppedWorkingPayloadUnderLeaseAsync(current, held, scope, own, source, ct).ConfigureAwait(false);
        }
        finally { foreach (var bytes in new[] { snapshot, next, history }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task RetireStoppedWorkingPayloadUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, Did2MessagingSessionScope scope,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease);
        await ExpireTerminalAuditsUnderLeaseAsync(current, held, scope, own, source, ct).ConfigureAwait(false);
        while (true)
        {
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Stopped payload cleanup lost authored custody.");
            using var journal = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            if (journal.Pending is not null) return;
            if (!journal.Entries.Values.Any(entry => FixedRoute(entry.Scope.Exact, scope.Exact) && entry.WorkStopped)) break;
            var plans = new ProtectedDid2CompactionPlan(storage, lease, scope.Network, scope.LocalAccount, scope.Instance);
            using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (idle.Phase != 0) throw new InvalidDataException("An existing cleanup plan owns stopped-work recovery.");
            using var selected = await PrepareOrdinaryOutboxUnderLeaseAsync(current, scope, Did2CompactionPlan.MaximumRows,
                own, source, held, ct, Did2CompactionPlan.Disposition.StoppedOutboxPayload).ConfigureAwait(false);
            await plans.StageAsync(idle, selected, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
    }

    private async Task StopExpiredOrdinaryWorkUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        // ContactAccept/initial retain their distinct owner; do not manufacture
        // an ordinary command for them. Their stopped-retention closure is separate.
        using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Expired work lost mandatory ordinary custody.");
        using var journal = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes,
            scope.Network, scope.LocalAccount, scope.Instance));
        if (journal.Entries.ContainsKey(Convert.ToHexString(operation.Span)))
            await StopOrdinaryWorkUnderLeaseAsync(current, held, opened, scope, operation,
                ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired, own, source, ct).ConfigureAwait(false);
    }
}
