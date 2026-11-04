using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Client.Shared.Persistence.MessagingV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private enum OwnedRouteHistoryCommand { Announcement, Request, Response }
    private sealed class RouteHistoryWorkNotRequiredException : Exception { }
    private sealed class RouteHistoryRequestUnmatchedException : Exception { }

    internal async Task<DirectTextOutboxEntry?> PrepareRouteHistoryCommandAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, bool response, ReadOnlyMemory<byte> receivedOperation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        if (response || !receivedOperation.IsEmpty) ProtectedDph2PreClaimJournal.RequireIntent(receivedOperation.Span);
        try
        {
            return await PrepareDirectAuthoredAsync(seconds, verifier, scope, null, null, ReadOnlyMemory<byte>.Empty,
                own, peer, source, ct, routeUpdate: true,
                response ? OwnedRouteHistoryCommand.Response : OwnedRouteHistoryCommand.Request, receivedOperation).ConfigureAwait(false);
        }
        catch (RouteHistoryWorkNotRequiredException) { return null; }
        catch (RouteHistoryRequestUnmatchedException) { return null; }
    }

    private sealed record OwnedRouteHistoryExchange(DeepIdV2ContactRouteRecordedPair Pair,
        ReadOnlyMemory<byte> Invite, ReadOnlyMemory<byte> Route);

    private async Task<(QualifiedRouteHistoryRead Read, VerifiedDeepIdV2ContactRouteHistory Facts)> ReadRouteHistoryAtCursorUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, byte subject, ReadOnlyMemory<byte> cursor, ReadOnlyMemory<byte> invite,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct,
        bool allowUnmatchedRequest = false)
    {
        if (cursor.Length != 112 || invite.Length != 611) throw new InvalidDataException("A historical selection has another closed width.");
        var selection = Did2RouteHistorySelection.Initial([
            HistorySelector(subject, 1, BinaryPrimitives.ReadUInt64BigEndian(cursor.Span)),
            HistorySelector(subject, 2, BinaryPrimitives.ReadUInt64BigEndian(cursor.Span[40..]))]);
        var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject, selection, held, ct).ConfigureAwait(false);
        try
        {
            RequireRouteHistoryConsent(read);
            if (allowUnmatchedRequest && (!HasVerifiedHistoryFact(read, 1, BinaryPrimitives.ReadUInt64BigEndian(cursor.Span)) ||
                !HasVerifiedHistoryFact(read, 2, BinaryPrimitives.ReadUInt64BigEndian(cursor.Span[40..]))))
                throw new RouteHistoryRequestUnmatchedException();
            var c = FirstVerifiedHistoryDecision(read, 1, BinaryPrimitives.ReadUInt64BigEndian(cursor.Span));
            var p = FirstVerifiedHistoryDecision(read, 2, BinaryPrimitives.ReadUInt64BigEndian(cursor.Span[40..]));
            var facts = await RestoreRouteHistoryUnderLeaseAsync(read, c.Body.C, p.Body.P, own, peer, source, held, ct).ConfigureAwait(false);
            if (!FixedRoute(facts.Cursor.Span, cursor.Span) || !FixedRoute(facts.ExactCompletedXir1V2.Span, invite.Span))
            {
                if (allowUnmatchedRequest) throw new RouteHistoryRequestUnmatchedException();
                throw new CryptographicException("A route-history hint differs from authenticated retained originals.");
            }
            await opened.WithPairedSqlAsync(read.Authored.PairedRead,
                sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
            return (read, facts);
        }
        catch { read.Dispose(); throw; }
    }

    private async Task RequireFreshOwnedRouteHistoryControlUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> exact, ContactRouteHistoryDmc2Payload control,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var subject = control.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest ? (byte)2 : (byte)1;
        var history = await ReadRouteHistoryAtCursorUnderLeaseAsync(opened, subject, control.LeftCursor,
            control.ExactLeftXir1V2, own, peer, source, held, ct).ConfigureAwait(false);
        using var read = history.Read;
        if (!FixedRoute(control.OriginalAnchorHash.Span, history.Facts.OriginalAnchorHash.Span))
            throw new CryptographicException("A fresh owned history control changed its native immutable anchor.");
        using var publication = await OpenOwnPermanentMailboxPublicationUnderLeaseAsync(current, held, source, own, ct).ConfigureAwait(false);
        QualifiedRouteHistoryRead? requestRead = null;
        try
        {
        if (control.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest)
            await DeepIdV2ContactRouteUpdateVerifier.RequireCurrentHistoryRequestAsync(history.Facts, exact,
                publication.Route.Recipient, own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        else
        {
            if (control.RequestEventHash.Span.IndexOfAnyExcept((byte)0) >= 0)
            {
                var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                using var received = await opened.WithSqlAsync(sql => sql.ReadVerifiedReceiveForEvent(floor,
                    control.RequestEventHash.Span), ct).ConfigureAwait(false) ??
                    throw new CryptographicException("Fresh response lost its exact native received request.");
                using var requestBytes = received.OwnAuthenticatedDmc2();
                var exactRequest = requestBytes.Use(bytes => bytes.ToArray());
                try
                {
                    requestRead = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 1,
                        Did2RouteHistorySelection.Custody(Dpe2Codec.Decode(received.ExactEnvelope).OperationId.Span), held, ct).ConfigureAwait(false);
                    _ = RequireIncomingHistoryRequest(requestRead);
                    if (!FixedRoute(exactRequest, requestRead.Original(requestRead.Snapshot.SelectedOriginal.Reference).Span))
                        throw new CryptographicException("Fresh response changed its selected received request original.");
                    DeepIdV2ContactRouteUpdateVerifier.RequireHistoryResponseCorrelation(control, exactRequest);
                    await RequireCurrentIncomingHistoryRequestUnderLeaseAsync(opened, history.Facts, exactRequest,
                        own, peer, source, held, ct).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(exactRequest); }
            }
            var endpoint = await DeepIdV2ContactRouteUpdateVerifier.VerifyHistoryPageAsync(history.Facts, exact,
                own.Proof, own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            if (control.Mode is DeepIdV2ContactRouteHistoryMode.Announcement or DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement)
            {
                var route = await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentHistoryAnnouncementAsync(endpoint, exact,
                    own.Proof, own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                if (!FixedRoute(route.ExactRouteClosure.Span, publication.Route.ExactRouteClosure.Span))
                    throw new CryptographicException("Fresh route announcement differs from the actual adopted publication.");
                await route.EnsureCurrentAsync(ct).ConfigureAwait(false);
            }
        }
        await publication.RecheckAsync(ct).ConfigureAwait(false);
        await RejoinOwnedHistoryReadsAsync(opened, ct, requestRead is null ? [read] : [read, requestRead]).ConfigureAwait(false);
        }
        finally { requestRead?.Dispose(); }
    }

    private async Task<(QualifiedRouteHistoryRead Read, VerifiedDeepIdV2ContactRouteHistory Facts)> ReadAdoptedRouteHistoryUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, OwnedDid2MessagingStorage opened, byte subject,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        await EnsureRouteHistoryBootstrapUnderLeaseAsync(current, opened, subject, own, peer, source, held, ct).ConfigureAwait(false);
        Did2RouteHistorySelection selection;
        using (var first = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject, Did2RouteHistorySelection.Initial(), held, ct).ConfigureAwait(false))
            selection = SelectAdoptedHistoryFacts(first);
        var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject, selection, held, ct).ConfigureAwait(false);
        try
        {
            RequireRouteHistoryConsent(read);
            var facts = await RestoreRouteHistoryUnderLeaseAsync(read, read.Snapshot.C, read.Snapshot.P, own, peer, source, held, ct).ConfigureAwait(false);
            _ = FirstVerifiedHistoryDecision(read, 1, BinaryPrimitives.ReadUInt64BigEndian(facts.Cursor.Span));
            _ = FirstVerifiedHistoryDecision(read, 2, BinaryPrimitives.ReadUInt64BigEndian(facts.Cursor.Span[40..]));
            await opened.WithPairedSqlAsync(read.Authored.PairedRead,
                sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
            return (read, facts);
        }
        catch { read.Dispose(); throw; }
    }

    private async Task<(IReadOnlyList<OwnedRouteHistoryExchange> Exchanges, byte[] RootHash,
        IReadOnlyDictionary<string, byte[]> OriginalRoots)> ReadOwnRouteHistoryExchangesUnderLeaseAsync(
        Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var entries = new List<(DeepIdV2ContactRouteRecordedPair Pair, ReadOnlyMemory<byte> Invite, ReadOnlyMemory<byte> Route)>();
        var originalRoots = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        byte[] rootHash;
        using (var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Own route history lost its protected original public exchanges."))
        {
            rootHash = raw.Use(bytes => SHA256.HashData(bytes));
            using var state = raw.Use(bytes => ProtectedDid2ContactRouteJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            foreach (var entry in state.Entries.Values)
            {
                if (entry.Kind != 1 || entry.Phase < 2) continue;
                var request = ContactRouteAuthorityWireCodec.DecodeRequest(entry.Record(12).Span);
                if (!request.HasPredecessor) continue;
                var response = new ContactRouteAuthorityWireResponse(scope.Network, request.RequestNonce.Span,
                    entry.Record(2).Span, entry.Record(3).Span, entry.Record(4).Span, entry.Record(13).Span);
                var pair = new DeepIdV2ContactRouteRecordedPair(entry.Record(12).Span, ContactRouteAuthorityWireCodec.EncodeResponse(request, response));
                entries.Add((pair, entry.Phase >= 3 ? entry.Record(5) : ReadOnlyMemory<byte>.Empty,
                    entry.Phase >= 3 ? entry.Record(6) : ReadOnlyMemory<byte>.Empty));
            }
        }
        var result = new List<OwnedRouteHistoryExchange>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            var request = entry.Pair.ExactRequest;
            for (var depth = 0; ; depth++)
            {
                var requestHash = SHA256.HashData(request.Span);
                var originSlot = ProtectedDid2ContactRenewalClosure.OriginSlot(requestHash);
                using var origin = await storage.ReadOwnedAsync(originSlot, ct).ConfigureAwait(false);
                if (origin is null) break;
                if (depth == 3) throw new InvalidDataException("An owned recorded exchange exceeds its exact retained origin bound.");
                var originBytes = origin.Use(bytes => bytes.ToArray());
                try
                {
                    if (originBytes.Length != ProtectedDid2ContactRenewalClosure.OriginBytes)
                        throw new InvalidDataException("An owned recorded history origin is truncated.");
                    originalRoots[originSlot] = SHA256.HashData(originBytes);
                    var closedSlot = ProtectedDid2ContactRenewalClosure.ClosedSlot(originBytes.AsSpan(120, 32));
                    using var raw = await storage.ReadOwnedAsync(closedSlot, ct).ConfigureAwait(false) ??
                        throw new InvalidDataException("An owned recorded history origin lost its exact closure.");
                    originalRoots[closedSlot] = raw.Use(bytes => SHA256.HashData(bytes));
                    using var closure = raw.Use(bytes => ProtectedDid2ContactRenewalClosure.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                    closure.RequireOrigin(originBytes, requestHash);
                    using var old = ProtectedDid2ContactRouteJournal.Entry.Decode(closure.ExactOldPhase1.Span, scope.Network, scope.LocalAccount);
                    var pair = new DeepIdV2ContactRouteRecordedPair(old.Record(12).Span, closure.ExactRecordedResponse.Span);
                    Add(new(pair, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty)); request = pair.ExactRequest;
                }
                finally { CryptographicOperations.ZeroMemory(originBytes); }
            }
            Add(new(entry.Pair, entry.Invite, entry.Route));
        }
        await RequireOwnedRouteHistoryExchangesCurrentAsync(rootHash, originalRoots, held, ct).ConfigureAwait(false);
        return (result, rootHash, originalRoots);
        void Add(OwnedRouteHistoryExchange exchange)
        {
            var id = Convert.ToHexString(SHA256.HashData(exchange.Pair.ExactRequest.Span)) +
                Convert.ToHexString(SHA256.HashData(exchange.Pair.ExactResponse.Span)) + (exchange.Invite.IsEmpty ? "P" : "C");
            if (seen.Add(id)) result.Add(exchange);
        }
    }

    private async Task RequireOwnedRouteHistoryExchangesCurrentAsync(byte[] rootHash,
        IReadOnlyDictionary<string, byte[]> originalRoots, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using (var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Own route history lost its protected original source."))
            if (!raw.Use(bytes => FixedRoute(SHA256.HashData(bytes), rootHash)))
                throw new CryptographicException("Own public history originals changed during bounded page qualification.");
        var slots = originalRoots.Keys.Order(StringComparer.Ordinal).ToArray();
        for (var offset = 0; offset < slots.Length; offset += 32)
        {
            var group = slots.Skip(offset).Take(32).ToArray();
            using var originals = await storage.ReadOwnedBatchAsync(group, ct).ConfigureAwait(false);
            if (originals.Count != group.Length) throw new InvalidDataException("Own historical original readback has another shape.");
            for (var index = 0; index < group.Length; index++)
                if (originals[index] is not { } original || !original.Use(bytes => FixedRoute(SHA256.HashData(bytes), originalRoots[group[index]])))
                    throw new CryptographicException("A retained recorded history original changed during page qualification.");
        }
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
    }

    private async Task<ParsedDmc2> AuthorOwnRouteHistoryUpdateUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, OwnPermanentMailboxPublication publication, ReadOnlyMemory<byte> logical,
        ulong sequence, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var adopted = await ReadAdoptedRouteHistoryUnderLeaseAsync(current, opened, 1, own, peer, source, held, ct).ConfigureAwait(false);
        using var read = adopted.Read;
        return await AuthorOwnRouteHistoryPageUnderLeaseAsync(current, opened, publication, read, adopted.Facts,
            new byte[32], logical, sequence, own, peer, source, held, ct).ConfigureAwait(false);
    }

    private async Task<ParsedDmc2> AuthorOwnRouteHistoryPageUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, OwnPermanentMailboxPublication publication, QualifiedRouteHistoryRead read,
        VerifiedDeepIdV2ContactRouteHistory before, ReadOnlyMemory<byte> requestHash, ReadOnlyMemory<byte> logical,
        ulong sequence, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var originals = await ReadOwnRouteHistoryExchangesUnderLeaseAsync(opened.Scope, held, ct).ConfigureAwait(false);
        var steps = new List<VerifiedDeepIdV2ContactRouteHistoryStep>(); var after = before;
        var length = DeepIdV2ContactRouteHistoryCodec.HeaderBytes;
        for (var count = 0; count < DeepIdV2ContactRouteHistoryCodec.MaximumAtoms; count++)
        {
            var completedGeneration = BinaryPrimitives.ReadUInt64BigEndian(after.Cursor.Span);
            var proposalGeneration = BinaryPrimitives.ReadUInt64BigEndian(after.Cursor.Span[40..]);
            var candidates = originals.Exchanges.Where(value =>
                FixedRoute(value.Pair.Request.ExactPredecessorXir1V2.Span, after.ExactCompletedXir1V2.Span) &&
                FixedRoute(value.Pair.Request.ExactPredecessorRouteClosure.Span, after.ExactCompletedRoute.Span))
                .Where(value =>
                {
                    var generation = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", value.Pair.Request.ExactXra1.Span).Field(3).Span);
                    return proposalGeneration < ulong.MaxValue && generation == proposalGeneration + 1 ||
                        !value.Invite.IsEmpty && generation == proposalGeneration &&
                        BinaryPrimitives.ReadUInt64BigEndian(ContactRouteClosureCodec.Decode(value.Route.Span).Reachability.Field(3).Span) == checked(completedGeneration + 1);
                })
                .OrderBy(value => BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", value.Pair.Request.ExactXra1.Span).Field(3).Span))
                .ThenByDescending(value => !value.Invite.IsEmpty).ToArray();
            if (candidates.Length == 0) break;
            var selected = candidates[0];
            var selectedGeneration = ContactCodec.Decode("XRA1", selected.Pair.Request.ExactXra1.Span).Field(3);
            if (candidates.Any(value => FixedRoute(ContactCodec.Decode("XRA1", value.Pair.Request.ExactXra1.Span).Field(3).Span, selectedGeneration.Span) &&
                (!FixedRoute(value.Pair.ExactRequest.Span, selected.Pair.ExactRequest.Span) ||
                 !FixedRoute(value.Pair.ExactResponse.Span, selected.Pair.ExactResponse.Span))))
                throw new CryptographicException("Owned public history has competing exact adjacent original requests.");
            var atomLength = checked(1132 + selected.Pair.ExactResponse.Length + (selected.Invite.IsEmpty ? 0 :
                1258 + ContactRouteClosureCodec.Decode(selected.Route.Span).Projection.CanonicalBytes.Length));
            if (checked(length + 4 + atomLength) > DeepIdV2ContactRouteHistoryCodec.MaximumPayloadBytes) break;
            var step = await DeepIdV2ContactRouteUpdateVerifier.VerifyOriginalHistoryStepAsync(after,
                selected.Pair.ExactRequest, selected.Pair.ExactResponse, selected.Invite, selected.Route,
                own.Proof, own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            steps.Add(step); after = step.After; length = checked(length + 4 + atomLength);
        }
        var announce = FixedRoute(after.ExactCompletedRoute.Span, publication.Route.ExactRouteClosure.Span);
        if (steps.Count == 0 && !announce)
            throw new CryptographicException("The actual adopted publication has a missing public historical prefix.");
        var authored = await ApplicationCoreCodec.AuthorVerifiedContactRouteHistoryPageAsync(before, steps, announce,
            requestHash, publication.Route.Recipient, own.Network, own.Authority, logical, sequence, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        await publication.RecheckAsync(ct).ConfigureAwait(false);
        await RequireOwnedRouteHistoryExchangesCurrentAsync(originals.RootHash, originals.OriginalRoots, held, ct).ConfigureAwait(false);
        await opened.WithPairedSqlAsync(read.Authored.PairedRead,
            sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
        return authored.Record;
    }

    private async Task<byte[]?> SelectRouteHistoryCommandUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, SqliteDeepMailboxStore application, ProtectedDid2DirectTextJournal.State journal,
        Did2MessagingSessionScope scope, OwnedRouteHistoryCommand kind, ReadOnlyMemory<byte> receivedOperation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, OnionMonotonicReading reading, CancellationToken ct)
    {
        byte[] requestHash = [];
        try
        {
            if (kind == OwnedRouteHistoryCommand.Response)
            {
                using var request = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 1,
                    Did2RouteHistorySelection.Custody(receivedOperation.Span), held, ct).ConfigureAwait(false);
                _ = RequireIncomingHistoryRequest(request);
                requestHash = SHA256.HashData(request.Original(request.Snapshot.SelectedOriginal.Reference).Span);
            }
            if (journal.Pending is { } pending && (pending.Kind != Dmc2ContentKind.ContactRouteUpdate ||
                !FixedRoute(pending.Scope.Exact, scope.Exact) || ClassifyOwnedRouteHistory(pending.PendingDmc2) != kind))
                throw new InvalidOperationException("Resume the existing pending authored command before route-history work.");
            foreach (var command in journal.Entries.Values.Where(entry => entry.Kind == Dmc2ContentKind.ContactRouteUpdate &&
                FixedRoute(entry.Scope.Exact, scope.Exact) && !entry.Stored && !entry.WorkStopped).OrderBy(entry => entry.Sequence))
            {
                var exact = await ReadOwnedHistoryCommandUnderLeaseAsync(current, application, journal, scope, command, ct).ConfigureAwait(false);
                try
                {
                    if (ClassifyOwnedRouteHistory(exact) != kind) continue;
                    if (kind == OwnedRouteHistoryCommand.Response &&
                        !FixedRoute(((ContactRouteHistoryDmc2Payload)ApplicationCoreCodec.DecodeDmc2(exact).ParsedPayload).RequestEventHash.Span, requestHash))
                        throw new InvalidOperationException("The existing response must close before another request may receive a response.");
                    return command.Operation.ToArray();
                }
                finally { CryptographicOperations.ZeroMemory(exact); }
            }
            if (kind == OwnedRouteHistoryCommand.Response)
            {
                var selector = new Did2RouteHistoryFactSelector(Did2MessagingArchiveFamily.RouteControl,
                    Did2MessagingArchiveRouteFacts.CorrelationSelector(3, requestHash));
                using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 1,
                    new Did2RouteHistorySelection(receivedOperation.Span, 0, [selector]), held, ct).ConfigureAwait(false);
                _ = RequireIncomingHistoryRequest(read);
                var response = read.Snapshot.Facts.Single().Value;
                if (response is { } value)
                {
                    var reference = Did2MessagingArchiveReference.Decode(value.Span, false);
                    var exact = read.Original(reference);
                    if (reference.Direction != 1 || ApplicationCoreCodec.DecodeDmc2(exact.Span).ParsedPayload is not ContactRouteHistoryDmc2Payload page)
                        throw new CryptographicException("A retained response hint lost its actual outgoing original.");
                    DeepIdV2ContactRouteUpdateVerifier.RequireHistoryResponseCorrelation(page,
                        read.Original(read.Snapshot.SelectedOriginal.Reference).Span);
                    await RejoinOwnedHistoryReadAsync(opened, read, ct).ConfigureAwait(false);
                    throw new RouteHistoryWorkNotRequiredException();
                }
                return null;
            }
            var adopted = await ReadAdoptedRouteHistoryUnderLeaseAsync(current, opened, 2, own, peer, source, held, ct).ConfigureAwait(false);
            using var adoptedRead = adopted.Read;
            if (!receivedOperation.IsEmpty)
            {
                using var hint = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 2,
                    Did2RouteHistorySelection.Custody(receivedOperation.Span), held, ct).ConfigureAwait(false);
                if (hint.Snapshot.SelectedOriginal.Reference.Direction != 2 ||
                    ApplicationCoreCodec.DecodeDmc2(hint.Original(hint.Snapshot.SelectedOriginal.Reference).Span).ParsedPayload is not ContactRouteHistoryDmc2Payload page ||
                    page.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest)
                    throw new CryptographicException("A history-gap hint must select its actual received page.");
                await RejoinOwnedHistoryReadAsync(opened, hint, ct).ConfigureAwait(false);
                if (FixedRoute(page.RightCursor.Span, adopted.Facts.Cursor.Span))
                {
                    await RejoinOwnedHistoryReadAsync(opened, adoptedRead, ct).ConfigureAwait(false);
                    throw new RouteHistoryWorkNotRequiredException();
                }
            }
            var latestSelector = new Did2RouteHistoryFactSelector(Did2MessagingArchiveFamily.RouteControl,
                Did2MessagingArchiveRouteFacts.LatestRequestSelector());
            using var latest = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 2,
                Did2RouteHistorySelection.Initial([latestSelector]), held, ct).ConfigureAwait(false);
            var awaitingProgress = false;
            if (latest.Snapshot.Facts.Single().Value is { } latestValue)
            {
                if (latestValue.Length != 96) throw new CryptographicException("Latest request hint has another closed width.");
                var reference = Did2MessagingArchiveReference.Decode(latestValue.Span[..88], false);
                var message = ApplicationCoreCodec.DecodeDmc2(latest.Original(reference).Span);
                if (reference.Direction != 1 || ClassifyOwnedRouteHistory(message.CanonicalBytes.Span) != OwnedRouteHistoryCommand.Request ||
                    message.SenderClientSequence != BinaryPrimitives.ReadUInt64BigEndian(latestValue.Span[88..]))
                    throw new CryptographicException("Latest request hint differs from its authenticated outgoing source and counter.");
                var request = (ContactRouteHistoryDmc2Payload)message.ParsedPayload;
                var lower = checked(own.Proof.TrustedLowerUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample);
                awaitingProgress = FixedRoute(request.LeftCursor.Span, adopted.Facts.Cursor.Span) &&
                    checked(lower * 1000) < message.ExpiresAtUnixMilliseconds;
            }
            await RejoinOwnedHistoryReadAsync(opened, adoptedRead, ct).ConfigureAwait(false);
            await RejoinOwnedHistoryReadAsync(opened, latest, ct).ConfigureAwait(false);
            if (awaitingProgress) throw new RouteHistoryWorkNotRequiredException();
            return null;
        }
        finally { CryptographicOperations.ZeroMemory(requestHash); }
    }

    private static OwnedRouteHistoryCommand ClassifyOwnedRouteHistory(ReadOnlySpan<byte> exact)
    {
        var message = ApplicationCoreCodec.DecodeDmc2(exact);
        return message.ParsedPayload switch
        {
            ContactRouteUpdateDmc2Payload => OwnedRouteHistoryCommand.Announcement,
            ContactRouteHistoryDmc2Payload page when page.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest => OwnedRouteHistoryCommand.Request,
            ContactRouteHistoryDmc2Payload page when page.RequestEventHash.Span.IndexOfAnyExcept((byte)0) >= 0 => OwnedRouteHistoryCommand.Response,
            ContactRouteHistoryDmc2Payload => OwnedRouteHistoryCommand.Announcement,
            _ => throw new CryptographicException("Route-history work has another actual authored payload kind.")
        };
    }

    private static async Task<byte[]> ReadOwnedHistoryCommandUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        SqliteDeepMailboxStore application, ProtectedDid2DirectTextJournal.State journal, Did2MessagingSessionScope scope,
        ProtectedDid2DirectTextJournal.Entry command, CancellationToken ct)
    {
        if (command.Pending) return command.PendingDmc2.ToArray();
        using var row = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
            BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, command.Operation.ToArray(), ct,
            requireStableReadOnly: true).ConfigureAwait(false) ?? throw new CryptographicException("Route-history work lost exact authored SQL custody.");
        var exact = OwnedByteExports.TakeArray(row.ExactDmc2);
        try { command.RequireEvent(exact); return exact; }
        catch { CryptographicOperations.ZeroMemory(exact); throw; }
    }

    private static ContactRouteHistoryDmc2Payload RequireIncomingHistoryRequest(QualifiedRouteHistoryRead read)
    {
        RequireRouteHistoryConsent(read);
        if (read.Snapshot.SelectedOriginal.Reference.Kind != 2 || read.Snapshot.SelectedOriginal.Reference.Direction != 2 ||
            ApplicationCoreCodec.DecodeDmc2(read.Original(read.Snapshot.SelectedOriginal.Reference).Span).ParsedPayload is not ContactRouteHistoryDmc2Payload request ||
            request.Mode != DeepIdV2ContactRouteHistoryMode.HistoryRequest)
            throw new CryptographicException("A response requires the exact authenticated native mode4 request.");
        return request;
    }

    private static Task RejoinOwnedHistoryReadAsync(OwnedDid2MessagingStorage opened, QualifiedRouteHistoryRead read, CancellationToken ct) =>
        RejoinOwnedHistoryReadsAsync(opened, ct, read);

    private static Task RejoinOwnedHistoryReadsAsync(OwnedDid2MessagingStorage opened, CancellationToken ct,
        params QualifiedRouteHistoryRead[] reads)
    {
        if (reads.Length == 0) throw new ArgumentException("A final history join requires actual selected sources.", nameof(reads));
        var roots = reads[0].Authored.Roots;
        foreach (var read in reads)
            if (!FixedRoute(read.Snapshot.Before.Exact.Span, reads[0].Snapshot.Before.Exact.Span) || roots.Count != read.Authored.Roots.Count ||
                roots.Any(pair => !read.Authored.Roots.TryGetValue(pair.Key, out var value) ||
                    (pair.Value is null ? value is not null : value is null || !FixedRoute(pair.Value, value))))
                throw new CryptographicException("Selected history originals do not share their exact actual roots and native predecessor.");
        var paired = new Did2MessagingArchiveAuthoredRead(roots,
            connection => { foreach (var read in reads) read.Authored.PairedRead.Verify(connection); },
            reads.Any(read => read.Authored.PairedRead.HasSources));
        return opened.WithPairedSqlAsync(paired, sql =>
        {
            foreach (var read in reads) sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events);
            return true;
        }, ct);
    }

    private async Task<ParsedDmc2> AuthorOwnRouteHistoryRequestUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, OwnPermanentMailboxPublication publication, ReadOnlyMemory<byte> logical, ulong sequence,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var adopted = await ReadAdoptedRouteHistoryUnderLeaseAsync(current, opened, 2, own, peer, source, held, ct).ConfigureAwait(false);
        using var read = adopted.Read;
        var result = await ApplicationCoreCodec.AuthorVerifiedContactRouteHistoryRequestAsync(adopted.Facts,
            publication.Route.Recipient, own.Network, own.Authority, logical, sequence, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        await publication.RecheckAsync(ct).ConfigureAwait(false);
        await RejoinOwnedHistoryReadAsync(opened, read, ct).ConfigureAwait(false);
        return result.Record;
    }

    private async Task<ParsedDmc2> AuthorOwnRouteHistoryResponseUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, OwnPermanentMailboxPublication publication, ReadOnlyMemory<byte> requestOperation,
        ReadOnlyMemory<byte> logical, ulong sequence, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        await EnsureRouteHistoryBootstrapUnderLeaseAsync(current, opened, 1, own, peer, source, held, ct).ConfigureAwait(false);
        await EnsureRouteHistoryBootstrapUnderLeaseAsync(current, opened, 2, own, peer, source, held, ct).ConfigureAwait(false);
        using var requestRead = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 1,
            Did2RouteHistorySelection.Custody(requestOperation.Span), held, ct).ConfigureAwait(false);
        var request = RequireIncomingHistoryRequest(requestRead);
        var history = await ReadRouteHistoryAtCursorUnderLeaseAsync(opened, 1, request.LeftCursor,
            request.ExactLeftXir1V2, own, peer, source, held, ct, allowUnmatchedRequest: true).ConfigureAwait(false);
        using var read = history.Read;
        var exactRequest = requestRead.Original(requestRead.Snapshot.SelectedOriginal.Reference);
        await RequireCurrentIncomingHistoryRequestUnderLeaseAsync(opened, history.Facts, exactRequest,
            own, peer, source, held, ct, unavailableIsNoWork: true).ConfigureAwait(false);
        var result = await AuthorOwnRouteHistoryPageUnderLeaseAsync(current, opened, publication, read, history.Facts,
            SHA256.HashData(exactRequest.Span), logical, sequence, own, peer, source, held, ct).ConfigureAwait(false);
        DeepIdV2ContactRouteUpdateVerifier.RequireHistoryResponseCorrelation((ContactRouteHistoryDmc2Payload)result.ParsedPayload, exactRequest.Span);
        await RejoinOwnedHistoryReadsAsync(opened, ct, read, requestRead).ConfigureAwait(false);
        return result;
    }

    private async Task RequireCurrentIncomingHistoryRequestUnderLeaseAsync(OwnedDid2MessagingStorage opened,
        VerifiedDeepIdV2ContactRouteHistory selectedOwn, ReadOnlyMemory<byte> exactRequest,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct,
        bool unavailableIsNoWork = false)
    {
        using var peerRead = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 2, Did2RouteHistorySelection.Initial(), held, ct).ConfigureAwait(false);
        RequireRouteHistoryConsent(peerRead);
        var anchor = ApplicationCoreCodec.DecodeDmc2(peerRead.Original(peerRead.Snapshot.Anchor).Span);
        var package = anchor.ParsedPayload switch
        {
            ContactHelloDmc2Payload hello => hello.MailboxRoute,
            ContactAcceptDmc2Payload accept => accept.MailboxRoute,
            _ => throw new CryptographicException("Current requester authorization lost its native relationship anchor.")
        };
        var checkpoint = peer.CurrentCheckpoint ?? throw new CryptographicException("A fresh response requires current requester authority.");
        var delegation = DeepIdV2ContactAuthorizationCodec.Verify(package.Authorization, checkpoint.Binding, checkpoint.Directory);
        var reading = await source.RecheckEndpointPairUnderLeaseAsync(own, peer, held, ct).ConfigureAwait(false);
        var message = ApplicationCoreCodec.DecodeDmc2(exactRequest.Span);
        var upper = checked(peer.TrustedUpperUnixSeconds + reading.SampleSeconds - peer.MonotonicSample);
        if (message.ExpiresAtUnixMilliseconds == 0 || checked(upper * 1000) >= message.ExpiresAtUnixMilliseconds ||
            message.CreatedAtUnixMilliseconds > checked(upper * 1000))
        {
            await RejoinOwnedHistoryReadAsync(opened, peerRead, ct).ConfigureAwait(false);
            if (unavailableIsNoWork) throw new RouteHistoryWorkNotRequiredException();
            throw new CryptographicException("Fresh response lost its current original request interval.");
        }
        var requester = DeepIdV2CurrentContactAuthorizationVerifier.Verify(peer, delegation, reading.BootId.Span, reading.SampleSeconds);
        await DeepIdV2ContactRouteUpdateVerifier.RequireCurrentHistoryRequestAsync(selectedOwn, exactRequest, requester,
            own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        await RejoinOwnedHistoryReadAsync(opened, peerRead, ct).ConfigureAwait(false);
    }
}
