using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal Task<DirectTextOutboxEntry> CreateDirectTextAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, string text,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
        => PrepareDirectAuthoredAsync(trustedUnixSeconds, verifier, scope, null, text, ReadOnlyMemory<byte>.Empty, own, peer, source, ct);

    internal Task<DirectTextOutboxEntry> CreateDirectAttachmentOfferAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> assetOperation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
        => PrepareDirectAuthoredAsync(trustedUnixSeconds, verifier, scope, null, null, assetOperation, own, peer, source, ct);

    internal Task<DirectTextOutboxEntry> CreateDirectRouteUpdateAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
        => PrepareDirectAuthoredAsync(trustedUnixSeconds, verifier, scope, null, null,
            ReadOnlyMemory<byte>.Empty, own, peer, source, ct, routeUpdate: true);

    // Supplied operations select exact retained work only. There is no caller
    // operation that can authorize new ordinary authoring after cleanup.
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

    internal Task<DirectTextOutboxEntry> PrepareDirectRouteUpdateAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
        => PrepareDirectAuthoredAsync(trustedUnixSeconds, verifier, scope, operation, null,
            ReadOnlyMemory<byte>.Empty, own, peer, source, ct, routeUpdate: true);

    private async Task<DirectTextOutboxEntry> PrepareDirectAuthoredAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte>? operation,
        string? text, ReadOnlyMemory<byte> assetOperation, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct, bool routeUpdate = false)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (operation is { } retryOperation) ProtectedDph2PreClaimJournal.RequireIntent(retryOperation.Span);
        if (routeUpdate)
        {
            if (text is not null || !assetOperation.IsEmpty)
                throw new ArgumentException("An owned route control has no caller-supplied payload.");
        }
        else if (assetOperation.IsEmpty) ArgumentNullException.ThrowIfNull(text);
        else { ProtectedDph2PreClaimJournal.RequireIntent(assetOperation.Span); if (text is not null) throw new ArgumentException("An ordinary command has one closed payload kind."); }
        var op = operation?.ToArray() ?? []; byte[] root = [], pendingBytes = [], stableBytes = [];
        DirectTextOutboxEntry? result = null;
        ParsedDam1? manifest = null;
        OwnPermanentMailboxPublication? publication = null;
        OwnNativeRouteHead? advertised = null;
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
            await ResumeGroupOrdinaryUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
            var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
            if (operation is null) op = RandomNumberGenerator.GetBytes(32);
            await MaintainOrdinaryOutboxUnderLeaseAsync(current, held, scope, op, own, source, ct).ConfigureAwait(false);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (floor.Status != 1) throw new InvalidDataException("An inactive session cannot prepare a text command.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            if (!assetOperation.IsEmpty)
            {
                manifest = await ReadStableAttachmentManifestUnderLeaseAsync(current, held, application, assetOperation, ct).ConfigureAwait(false);
                RequireAttachmentOfferTime(manifest, own, peer, first);
            }
            Dmc2Payload? payload = routeUpdate ? null : manifest is null ? ApplicationCoreCodec.CreateMessageCreatePayload(text!) :
                ApplicationCoreCodec.CreateAttachmentOfferPayload(manifest);
            if (!scope.IsInitiator)
                await RequireRetainedAcceptanceForTextAsync(opened, application, own, peer, source, held, ct).ConfigureAwait(false);
            using var owner = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected text command custody is absent; no regeneration is permitted.");
            root = owner.Use(bytes => bytes.ToArray());
            using var journal = ProtectedDid2DirectTextJournal.Decode(root, scope.Network, scope.LocalAccount, scope.Instance);
            var name = Convert.ToHexString(op);
            journal.Entries.TryGetValue(name, out var entry);
            if (operation is null && entry is not null)
                throw new CryptographicException("A newly allocated ordinary operation collided with retained work.");
            if (operation is not null && entry is null)
                throw new IOException("No retained ordinary command exists; retry cannot author new work.");
            if (entry is not null && !Did2MessagingSessionScope.Fixed(entry.Scope.Exact, scope.Exact))
                throw new CryptographicException("Text command belongs to another exact session scope.");
            if (entry?.WorkStopped == true)
                throw new IOException("Stopped authored work cannot become a new or resumed command.");
            if (journal.Pending is { } pending && (entry is null || !ReferenceEquals(pending, entry)))
                throw new InvalidOperationException("Resume the existing pending text command before preparing another.");
            if (entry?.Pending == true) RequireRequestedAuthoredKind(entry.PendingDmc2, payload, routeUpdate, scope);
            if (entry is null)
            {
                // Removing ordinary working custody cannot turn an already
                // committed native operation into a new logical command.
                using var committed = opened.Sql.ReadVerifiedOperation(floor, op);
                if (committed is not null)
                    throw new CryptographicException("A committed operation without ordinary working custody cannot be authored again.");
                journal.RequireCapacity(scope);
                await RequireNewMailboxWorkCapacityUnderLeaseAsync(current, held, opened, scope, op,
                    own, peer, source, verifier, ct).ConfigureAwait(false);
            }
            result = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, entry is null ? ReadOnlyMemory<byte>.Empty : op, ct).ConfigureAwait(false);
            if (entry is not null && result is not null)
            {
                var retryExact = OwnedByteExports.TakeArray(result.ExactDmc2);
                try { RequireRequestedAuthoredKind(retryExact, payload, routeUpdate, scope); }
                finally { CryptographicOperations.ZeroMemory(retryExact); }
            }
            if (entry is null)
            {
                var logical = RandomNumberGenerator.GetBytes(32);
                ParsedDmc2? authored = null;
                try
                {
                    if (routeUpdate)
                    {
                        // Only actual adopted own publication/native-advertised
                        // history selects this payload. Existing commands above
                        // resume exactly, without reopening/reminting latest state.
                        publication = await OpenOwnPermanentMailboxPublicationUnderLeaseAsync(current, held, source, own, ct).ConfigureAwait(false);
                        advertised = await ReadOwnNativeRouteHeadUnderLeaseAsync(current, held, opened, application,
                            journal, own, peer, source, ct).ConfigureAwait(false);
                        var control = await ApplicationCoreCodec.AuthorVerifiedContactRouteUpdateAsync(publication.Route,
                            advertised.Original, advertised.ExactRoute, advertised.EventHash, scope.Relationship.ToArray(),
                            scope.Conversation.ToArray(), logical, journal.NextSequence(scope), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                        await publication.RecheckAsync(ct).ConfigureAwait(false);
                        authored = control.Record;
                    }
                    else
                    {
                        var upper = Math.Max(checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample),
                            checked(peer.TrustedUpperUnixSeconds + first.SampleSeconds - peer.MonotonicSample));
                        authored = ApplicationCoreCodec.AuthorDmc2(scope.Network, logical, scope.Conversation,
                            scope.LocalAccount, scope.LocalDevice, journal.NextSequence(scope), checked((upper + 1) * 1000),
                            0, Dmc2Flags.None, [], payload!);
                    }
                    entry = ProtectedDid2DirectTextJournal.Entry.Prepare(scope, op, authored);
                }
                finally
                {
                    if (authored?.ParsedPayload is AttachmentOfferDmc2Payload authoredOffer)
                        authoredOffer.Manifest.Dispose();
                    CryptographicOperations.ZeroMemory(logical);
                }
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
            var exact = OwnedByteExports.TakeArray(result.ExactDmc2);
            try { entry!.RequireEvent(exact); RequireRequestedAuthoredKind(exact, payload, routeUpdate, scope); }
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
            if (publication is not null)
            {
                await publication.RecheckAsync(ct).ConfigureAwait(false);
                var native = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                if (!FixedRoute(native.Exact.Span, advertised!.NativeFloor.Span))
                    throw new CryptographicException("Own route-control native predecessor changed during command adoption.");
                var time = await publication.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
                var controlExact = OwnedByteExports.TakeArray(result.ExactDmc2);
                try
                {
                    var control = ApplicationCoreCodec.DecodeDmc2(controlExact);
                    try
                    {
                        if (checked(time.UpperUnixSeconds * 1000) >= control.ExpiresAtUnixMilliseconds)
                            throw new CryptographicException("Own route control expired before exact command readback.");
                    }
                    finally { if (control.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
                }
                finally { CryptographicOperations.ZeroMemory(controlExact); }
            }
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
            publication?.Dispose(); manifest?.Dispose(); result?.Dispose();
            foreach (var bytes in new[] { op, root, pendingBytes, stableBytes }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void RequireRequestedAuthoredKind(ReadOnlySpan<byte> exact, Dmc2Payload? requested,
        bool routeUpdate, Did2MessagingSessionScope scope)
    {
        if (!routeUpdate)
        {
            RequireRequestedOrdinaryPayload(exact, requested ?? throw new InvalidDataException("Ordinary command lost its requested payload."));
            return;
        }
        var message = ApplicationCoreCodec.DecodeDmc2(exact);
        try
        {
            if (requested is not null || message.ContentKind != Dmc2ContentKind.ContactRouteUpdate ||
                message.ParsedPayload is not ContactRouteUpdateDmc2Payload update ||
                message.Flags != Dmc2Flags.None || message.ReplyToLogicalMessageId.Length != 0 ||
                message.ExpiresAtUnixMilliseconds == 0 ||
                !FixedRoute(update.RelationshipId.Span, scope.Relationship) ||
                !FixedRoute(message.NetworkId.Span, scope.Network) ||
                !FixedRoute(message.ConversationId.Span, scope.Conversation) ||
                !FixedRoute(message.SenderAccountId.Span, scope.LocalAccount) ||
                !FixedRoute(message.SenderDeviceId.Span, scope.LocalDevice))
                throw new CryptographicException("A repeated owned route control changed its actual command kind or scope.");
        }
        finally { if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
    }

    private static void RequireRequestedOrdinaryPayload(ReadOnlySpan<byte> exact, Dmc2Payload requested)
    {
        var message = ApplicationCoreCodec.DecodeDmc2(exact);
        ReadOnlyMemory<byte> retained = default, candidate = default;
        try
        {
            retained = message.PayloadBytes; candidate = requested.CanonicalBytes;
            if (message.ContentKind != requested.Kind || !Did2MessagingSessionScope.Fixed(retained.Span, candidate.Span))
                throw new CryptographicException("A repeated ordinary command changed its kind or exact payload.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsMemory(retained).Span);
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsMemory(candidate).Span);
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
        var bytes = OwnedByteExports.TakeArray(retained.ExactDmc2);
        try
        {
            if (!Did2MessagingSessionScope.Fixed(bytes, exact.Span))
                throw new CryptographicException("The requested send differs from actual owned text custody.");
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task RetainOrdinaryStoreEvidenceBeforeDispatchUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, Did2StorePublicEvidence evidence, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Ordinary Store preparation lost mandatory authored custody.");
        var original = root.Use(bytes => bytes.ToArray());
        byte[] exact = [];
        try
        {
            using var journal = ProtectedDid2DirectTextJournal.Decode(original, scope.Network, scope.LocalAccount, scope.Instance);
            if (!journal.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command) || command.Pending ||
                !FixedRoute(command.Scope.Exact, scope.Exact))
                throw new CryptographicException("New ordinary Store evidence requires its exact stable authored command.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            using var retained = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, operation, ct,
                requireStableReadOnly: true).ConfigureAwait(false) ??
                throw new CryptographicException("Ordinary Store evidence lost stable authored SQL custody.");
            exact = OwnedByteExports.TakeArray(retained.ExactDmc2);
            command.RequireEvent(exact);
            await RequireRetainedOrdinaryEventUnderLeaseAsync(current, held, opened, scope, operation, journal,
                exact, ct).ConfigureAwait(false);
            var attempt = await RequireCurrentStoreEvidenceAttemptUnderLeaseAsync(current, held, opened, scope, operation,
                ReadOnlyMemory<byte>.Empty, evidence, ct).ConfigureAwait(false);
            try { await application.RecordStorePublicEvidenceAsync(scope, operation, attempt, evidence, ct).ConfigureAwait(false); }
            finally { CryptographicOperations.ZeroMemory(attempt); }
            await RequireRetainedOrdinaryEventUnderLeaseAsync(current, held, opened, scope, operation, journal,
                exact, ct).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, original, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive();
        }
        finally { CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(exact); }
    }

    private async Task RetainOrdinaryStoreCompletionUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> attempt, Did2StorePublicEvidence publicEvidence,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
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
                    var retainedEvidence = await acceptanceApplication.RequireStorePublicEvidenceAsync(scope, operation, attempt, ct).ConfigureAwait(false);
                    var expectedRecords = publicEvidence.CopyRecords(); var actualRecords = retainedEvidence.CopyRecords();
                    var acceptanceSnapshot = accepted.Use(bytes => bytes.ToArray());
                    try
                    {
                        if (expectedRecords.Where((bytes, index) => !FixedRoute(bytes, actualRecords[index])).Any())
                            throw new CryptographicException("ContactAccept original Store evidence changed during ingress.");
                        await RequireRetainedContactAcceptEventUnderLeaseAsync(held, opened, acceptanceApplication, winner, operation, ct).ConfigureAwait(false);
                        await RequireExactProtectedMailboxRootAsync(ProtectedDid2ContactAcceptJournal.Slot, acceptanceSnapshot, ct).ConfigureAwait(false);
                        _ = await TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope,
                            operation, own, source, ct).ConfigureAwait(false) ??
                            throw new CryptographicException("Acceptance completion lost its independently verified original Store.");
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
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, operation, ct).ConfigureAwait(false);
            if (retained is null)
                throw new CryptographicException("Store completion lost its verified ordinary SQL row.");
            // Preparation persisted these exact records before the callback.
            // Completion must not repair evidence removed/substituted during
            // ingress or a cold handover, even after a verified SQL Durable fact.
            var originalEvidence = await application.RequireStorePublicEvidenceAsync(scope, operation, attempt, ct).ConfigureAwait(false);
            var expectedOrdinaryRecords = publicEvidence.CopyRecords(); var actualOrdinaryRecords = originalEvidence.CopyRecords();
            try
            {
                if (expectedOrdinaryRecords.Where((bytes, index) => !FixedRoute(bytes, actualOrdinaryRecords[index])).Any())
                    throw new CryptographicException("Ordinary original Store evidence changed before protected completion.");
            }
            finally { foreach (var bytes in expectedOrdinaryRecords.Concat(actualOrdinaryRecords)) CryptographicOperations.ZeroMemory(bytes); }
            if (!command.Stored)
            {
                var completionTime = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
                journal.RetainStore(name, checked(own.Proof.TrustedUpperUnixSeconds + completionTime.SampleSeconds - own.Proof.MonotonicSample));
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
        using var groups = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        var history = RequireGroupAuthoredEvent(groups.State, scope, operation.Span, native.EventHash) ??
            await application.ReadRetainedAuthoredEventAsync(scope, native.EventHash.ToArray(), ct).ConfigureAwait(false) ??
            throw new CryptographicException("Absent ordinary work lost its independent local history.");
        try
        {
            if (journal.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command))
            {
                if (command.Pending || !FixedRoute(command.Scope.Exact, scope.Exact) || !FixedRoute(command.EventHash, native.EventHash))
                    throw new CryptographicException("Retained ordinary history differs from actual command/native custody.");
                command.RequireEvent(history);
            }
            if (!expectedEvent.IsEmpty && !Did2MessagingSessionScope.Fixed(history, expectedEvent.Span))
                throw new CryptographicException("Cached ordinary encryption cannot accept changed event bytes.");
            var parsed = ApplicationCoreCodec.DecodeDmc2(history);
            try
            {
                if (parsed.ContentKind is not (Dmc2ContentKind.MessageCreate or Dmc2ContentKind.AttachmentOffer or Dmc2ContentKind.ContactRouteUpdate) && !ProtectedDid2GroupJournal.IsKind(parsed.ContentKind) ||
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
            winner.RequireExactAccept(accepted);
            using var verified = await AuthenticatedContactAcceptDmc2.FromOwnedCommitAsync(opened, op, accepted,
                storage, own, peer, source, held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(accepted); CryptographicOperations.ZeroMemory(op); }
    }
}
