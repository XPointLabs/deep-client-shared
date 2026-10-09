using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal Task<DirectTextOutboxEntry> PrepareDirectTextAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        string text, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
        => PrepareDirectAuthoredAsync(trustedUnixSeconds, verifier, scope, operation, text, ReadOnlyMemory<byte>.Empty, own, peer, source, ct);

    internal Task<DirectTextOutboxEntry> PrepareDirectAttachmentOfferAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> assetOperation, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
        => PrepareDirectAuthoredAsync(trustedUnixSeconds, verifier, scope, operation, null, assetOperation, own, peer, source, ct);

    private async Task<DirectTextOutboxEntry> PrepareDirectAuthoredAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        string? text, ReadOnlyMemory<byte> assetOperation, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope); ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        if (assetOperation.IsEmpty) ArgumentNullException.ThrowIfNull(text);
        else { ProtectedDph2PreClaimJournal.RequireIntent(assetOperation.Span); if (text is not null) throw new ArgumentException("An ordinary command has one closed payload kind."); }
        var op = operation.ToArray(); byte[] root = [], pendingBytes = [], stableBytes = [];
        DirectTextOutboxEntry? result = null;
        ParsedDam1? manifest = null;
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
            var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (floor.Status != 1) throw new InvalidDataException("An inactive session cannot prepare a text command.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            if (!assetOperation.IsEmpty)
            {
                manifest = await ReadStableAttachmentManifestUnderLeaseAsync(current, held, application, assetOperation, ct).ConfigureAwait(false);
                RequireAttachmentOfferTime(manifest, own, peer, first);
            }
            var payload = manifest is null ? (Dmc2Payload)ApplicationCoreCodec.CreateMessageCreatePayload(text!) :
                ApplicationCoreCodec.CreateAttachmentOfferPayload(manifest);
            if (!scope.IsInitiator)
                await RequireRetainedAcceptanceForTextAsync(opened, application, own, peer, source, held, ct).ConfigureAwait(false);
            using var owner = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected text command custody is absent; no regeneration is permitted.");
            root = owner.Use(bytes => bytes.ToArray());
            using var journal = ProtectedDid2DirectTextJournal.Decode(root, scope.Network, scope.LocalAccount, scope.Instance);
            var name = Convert.ToHexString(op);
            journal.Entries.TryGetValue(name, out var entry);
            if (entry is not null && !Did2MessagingSessionScope.Fixed(entry.Scope.Exact, scope.Exact))
                throw new CryptographicException("Text command belongs to another exact session scope.");
            if (journal.Pending is { } pending && (entry is null || !ReferenceEquals(pending, entry)))
                throw new InvalidOperationException("Resume the existing pending text command before preparing another.");
            if (entry?.Pending == true) RequireRequestedOrdinaryPayload(entry.PendingDmc2, payload);
            if (entry is null)
            {
                // Removing ordinary working custody cannot turn an already
                // committed native operation into a new logical command.
                using var committed = opened.Sql.ReadVerifiedOperation(floor, op);
                if (committed is not null)
                    throw new CryptographicException("A committed operation without ordinary working custody cannot be authored again.");
                journal.RequireCapacity(scope);
            }
            result = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, entry is null ? ReadOnlyMemory<byte>.Empty : op, ct).ConfigureAwait(false);
            if (entry is null)
            {
                var logical = RandomNumberGenerator.GetBytes(32);
                try
                {
                    var upper = Math.Max(checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample),
                        checked(peer.TrustedUpperUnixSeconds + first.SampleSeconds - peer.MonotonicSample));
                    var authored = ApplicationCoreCodec.AuthorDmc2(scope.Network, logical, scope.Conversation,
                        scope.LocalAccount, scope.LocalDevice, journal.NextSequence(scope), checked((upper + 1) * 1000),
                        0, Dmc2Flags.None, [], payload);
                    entry = ProtectedDid2DirectTextJournal.Entry.Prepare(scope, op, authored);
                }
                finally { CryptographicOperations.ZeroMemory(logical); }
                try { journal.AddPending(entry); }
                catch { entry.Dispose(); throw; }
                pendingBytes = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
                ct.ThrowIfCancellationRequested(); held.RequireActive();
                if (!await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, root, pendingBytes, ct).ConfigureAwait(false))
                    throw new CryptographicException("Text command custody changed under its account lease.");
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, pendingBytes, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2TextOutboxTestHooks.Hit(Did2TextOutboxFailpoint.AfterPending);
#endif
                result?.Dispose();
                result = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                    BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, op, ct).ConfigureAwait(false);
            }
            if (result is null) throw new CryptographicException("The owned text command has no exact SQL readback.");
            var exact = result.ExactDmc2.ToArray();
            try { entry!.RequireEvent(exact); RequireRequestedOrdinaryPayload(exact, payload); }
            finally { CryptographicOperations.ZeroMemory(exact); }
            if (entry!.Pending)
            {
#if DEEP_TEST_INTERNALS
                Did2TextOutboxTestHooks.Hit(Did2TextOutboxFailpoint.AfterSql);
#endif
                journal.Stabilize(name);
                stableBytes = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
                ct.ThrowIfCancellationRequested(); held.RequireActive();
                if (!await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot,
                    pendingBytes.Length == 0 ? root : pendingBytes, stableBytes, ct).ConfigureAwait(false))
                    throw new CryptographicException("The pending text command changed before stable readback.");
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, stableBytes, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2TextOutboxTestHooks.Hit(Did2TextOutboxFailpoint.AfterStable);
#endif
            }
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            if (manifest is not null)
            {
                var final = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
                if (final.SampleSeconds < first.SampleSeconds || !Did2MessagingSessionScope.Fixed(final.BootId.Span, first.BootId.Span))
                    throw new CryptographicException("Attachment offer preparation crossed protected clock continuity.");
                RequireAttachmentOfferTime(manifest, own, peer, final);
            }
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot,
                stableBytes.Length != 0 ? stableBytes : pendingBytes.Length != 0 ? pendingBytes : root, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            var released = result; result = null; return released;
        }
        finally
        {
            manifest?.Dispose(); result?.Dispose(); foreach (var bytes in new[] { op, root, pendingBytes, stableBytes }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void RequireRequestedOrdinaryPayload(ReadOnlySpan<byte> exact, Dmc2Payload requested)
    {
        var message = ApplicationCoreCodec.DecodeDmc2(exact);
        var retained = message.PayloadBytes.ToArray(); var candidate = requested.CanonicalBytes.ToArray();
        try
        {
            if (message.ContentKind != requested.Kind || !Did2MessagingSessionScope.Fixed(retained, candidate))
                throw new CryptographicException("A repeated ordinary command changed its kind or exact payload.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(retained); CryptographicOperations.ZeroMemory(candidate);
            if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose();
        }
    }

    private async Task RequireOwnedTextForSendAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> exact, CancellationToken ct)
    {
        using var owner = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Protected text command custody is absent.");
        using var journal = owner.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        if (journal.Pending is not null)
            throw new CryptographicException("Only a stable exact owned text command may enter DPE2 send.");
        if (!journal.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command))
        {
            await RequireRetainedOrdinaryEventUnderLeaseAsync(current, held, opened, scope, operation, journal, exact, ct).ConfigureAwait(false);
            return; // Only an existing exact native event, never fresh encryption.
        }
        if (command.Pending || !Did2MessagingSessionScope.Fixed(command.Scope.Exact, scope.Exact))
            throw new CryptographicException("Only a stable exact owned text command may enter DPE2 send.");
        command.RequireEvent(exact.Span);
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        using var retained = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
            BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, operation, ct).ConfigureAwait(false) ??
            throw new CryptographicException("The stable text command has no SQL readback.");
        var bytes = retained.ExactDmc2.ToArray();
        try
        {
            if (!Did2MessagingSessionScope.Fixed(bytes, exact.Span))
                throw new CryptographicException("The requested send differs from actual owned text custody.");
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task RetainOrdinaryStoreCompletionUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        Did2StorePublicEvidence publicEvidence, CancellationToken ct)
    {
        byte[] snapshot = [], next = [];
        try
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Ordinary Store completion requires mandatory command custody.");
            snapshot = root.Use(bytes => bytes.ToArray());
            using var journal = ProtectedDid2DirectTextJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
            var name = Convert.ToHexString(operation.Span);
            if (!journal.Entries.TryGetValue(name, out var command))
            {
                using var accepted = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("The dispatched command has no ordinary or acceptance custody.");
                using var accepts = accepted.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                var winner = accepts.FindScope(scope);
                if (winner is not null && Did2MessagingSessionScope.Fixed(winner.Operation, operation.Span))
                {
                    using var acceptanceApplication = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                        storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
                    await RequireRetainedContactAcceptEventUnderLeaseAsync(held, opened, acceptanceApplication, winner, operation, ct).ConfigureAwait(false);
                    // Ingress is an external callback. Its verified Store is
                    // durable, but a lost/substituted original local source
                    // must not be silently repaired before reporting success.
                    var retainedEvidence = await acceptanceApplication.RequireStorePublicEvidenceAsync(scope, operation, ct).ConfigureAwait(false);
                    var expectedRecords = publicEvidence.CopyRecords(); var actualRecords = retainedEvidence.CopyRecords();
                    var acceptanceSnapshot = accepted.Use(bytes => bytes.ToArray());
                    try
                    {
                        if (expectedRecords.Where((bytes, index) => !FixedRoute(bytes, actualRecords[index])).Any())
                            throw new CryptographicException("ContactAccept original Store evidence changed during ingress.");
                        await RequireRetainedContactAcceptEventUnderLeaseAsync(held, opened, acceptanceApplication, winner, operation, ct).ConfigureAwait(false);
                        await RequireExactProtectedMailboxRootAsync(ProtectedDid2ContactAcceptJournal.Slot, acceptanceSnapshot, ct).ConfigureAwait(false);
                        held.RequireActive(); ct.ThrowIfCancellationRequested(); return;
                    }
                    finally
                    {
                        foreach (var bytes in expectedRecords.Concat(actualRecords)) CryptographicOperations.ZeroMemory(bytes);
                        CryptographicOperations.ZeroMemory(acceptanceSnapshot);
                    }
                }
                // Compacted ordinary work keeps independent native/history and
                // transport custody. A cached exact Store completes without
                // recreating either its authored command or its SQL payload.
                await RequireRetainedOrdinaryEventUnderLeaseAsync(current, held, opened, scope, operation, journal,
                    ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
                held.RequireActive(); ct.ThrowIfCancellationRequested(); return;
            }
            if (command.Pending || !Did2MessagingSessionScope.Fixed(command.Scope.Exact, scope.Exact))
                throw new CryptographicException("Store completion requires a stable command in its actual scope.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            using var retained = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, operation, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Store completion lost its verified ordinary SQL row.");
            // Retain original public evidence before protected Stored allows
            // compaction. Interrupted insertion leaves the exact send pending;
            // retries accept only the immutable same records, never replacements.
            await application.RecordStorePublicEvidenceAsync(scope, operation, publicEvidence, ct).ConfigureAwait(false);
            if (!command.Stored)
            {
                journal.RetainStore(name);
                next = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
                ct.ThrowIfCancellationRequested(); held.RequireActive();
                if (!await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, snapshot, next, ct).ConfigureAwait(false))
                    throw new CryptographicException("Ordinary Store completion changed under its account lease.");
            }
            using var readback = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Ordinary Store completion disappeared before readback.");
            var expected = next.Length == 0 ? snapshot : next;
            if (!readback.Use(bytes => Did2MessagingSessionScope.Fixed(bytes, expected)))
                throw new CryptographicException("Ordinary Store completion has no exact protected readback.");
            ct.ThrowIfCancellationRequested(); held.RequireActive();
        }
        finally { CryptographicOperations.ZeroMemory(snapshot); CryptographicOperations.ZeroMemory(next); }
    }

    private async Task RequireRetainedOrdinaryEventUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ProtectedDid2DirectTextJournal.State journal,
        ReadOnlyMemory<byte> expectedEvent, CancellationToken ct)
    {
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using var native = opened.Sql.ReadVerifiedOperation(floor, operation.Span) ??
            throw new CryptographicException("Absent ordinary work has no retained native event.");
        if (native.Direction != 1) throw new CryptographicException("Absent ordinary work selected a receive event.");
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        var history = await application.ReadRetainedAuthoredEventAsync(scope, native.EventHash.ToArray(), ct).ConfigureAwait(false) ??
            throw new CryptographicException("Absent ordinary work lost its independent local history.");
        try
        {
            if (!expectedEvent.IsEmpty && !Did2MessagingSessionScope.Fixed(history, expectedEvent.Span))
                throw new CryptographicException("Cached ordinary encryption cannot accept changed event bytes.");
            var parsed = ApplicationCoreCodec.DecodeDmc2(history);
            try
            {
                if (parsed.ContentKind is not (Dmc2ContentKind.MessageCreate or Dmc2ContentKind.AttachmentOffer) ||
                    parsed.SenderClientSequence >= journal.NextSequence(scope))
                    throw new CryptographicException("Absent ordinary work differs from the preserved authored floor.");
            }
            finally { if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        }
        finally { CryptographicOperations.ZeroMemory(history); }
        held.RequireActive(); ct.ThrowIfCancellationRequested();
    }

    private async Task RequireRetainedAcceptanceForTextAsync(OwnedDid2MessagingStorage opened,
        SqliteDeepMailboxStore application, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var scope = opened.Scope;
        var accepted = await application.ReadContactAcceptAsync(scope.LocalAccount.ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope.Conversation.ToArray(),
            scope.LocalAccount.ToArray(), scope.LocalDevice.ToArray(), ct).ConfigureAwait(false) ??
            throw new InvalidOperationException("The recipient must explicitly accept the request before authoring text.");
        byte[] op = [];
        try
        {
            using var marker = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("The local acceptance command is absent.");
            using var commands = marker.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var winner = commands.FindScope(scope) ?? throw new CryptographicException("There is no local acceptance winner.");
            op = winner.Operation.ToArray();
            if (!Did2MessagingSessionScope.Fixed(winner.Accept, accepted))
                throw new CryptographicException("Retained local acceptance differs from the explicit command.");
            using var verified = await AuthenticatedContactAcceptDmc2.FromOwnedCommitAsync(opened, op, accepted,
                storage, own, peer, source, held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(accepted); CryptographicOperations.ZeroMemory(op); }
    }
}
