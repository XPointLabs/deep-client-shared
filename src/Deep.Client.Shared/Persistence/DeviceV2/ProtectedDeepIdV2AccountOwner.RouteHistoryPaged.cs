using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private sealed class RouteHistoryCannotAdvanceException : Exception { }

    private async Task RecheckStagedRouteHistoryUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, QualifiedRouteHistoryRead read,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held,
        OnionMonotonicReading first, CancellationToken ct)
    {
        await RequireFinalMessagingFreshnessAsync(current, opened.Scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        await opened.WithPairedSqlAsync(read.Authored.PairedRead,
            sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
    }

    private void ConfigureRouteHistoryDecisionRecovery(OwnedDid2MessagingStorage opened, HeldDeepIdV2AccountLease held)
    {
        held.RequireOwner(lease);
        opened.ConfigureRouteHistoryDecisionSql(async (mutation, operation, ct) =>
        {
            held.RequireOwner(lease);
            var originals = await opened.WithSqlAsync(sql => sql.ReadRouteHistoryDecisionAuthoredSources(mutation), ct).ConfigureAwait(false);
            try
            {
                using var authored = await QualifyArchiveAuthoredAsync(opened.Scope, originals, held, ct).ConfigureAwait(false);
                return await opened.WithPairedSqlAsync(authored.PairedRead, sql =>
                {
                    sql.RequireRouteDecisionSources(mutation); held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
                    return operation(sql);
                }, ct).ConfigureAwait(false);
            }
            finally { foreach (var original in originals) original.Dispose(); }
        });
    }

    private async Task<bool> ProcessRouteHistoryControlUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation, bool outgoing,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var subject = outgoing ? (byte)1 : (byte)2;
        ContactRouteHistoryDmc2Payload control;
        using (var custody = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject,
            Did2RouteHistorySelection.Custody(operation.Span), held, ct).ConfigureAwait(false))
        {
            if (ApplicationCoreCodec.DecodeDmc2(custody.Original(custody.Snapshot.SelectedOriginal.Reference).Span).ParsedPayload is not ContactRouteHistoryDmc2Payload parsed)
                throw new CryptographicException("Route-history processing lost its exact count8 native control.");
            control = parsed;
            if (!custody.Snapshot.FirstFault.IsAbsent) return false;
        }
        if (!outgoing)
        {
            await EnsureRouteHistoryBootstrapUnderLeaseAsync(current, opened, subject, own, peer, source, held, ct).ConfigureAwait(false);
            try
            {
                using var conflict = await QualifiedDid2RouteHistoryDecision.CaptureUnderLeaseAsync(this, current, opened,
                    subject, Did2RouteHistorySelection.PositionConflict(operation.Span), Did2RouteHistoryDecision.ActionKind.Conflict,
                    own, peer, source, held, ct).ConfigureAwait(false);
                _ = await opened.Custody.CommitRouteHistoryDecisionAsync(conflict, ct).ConfigureAwait(false);
                return false;
            }
            catch (RouteHistoryCannotAdvanceException) { }
        }
        if (control.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest) return false;
        await EnsureRouteHistoryBootstrapUnderLeaseAsync(current, opened, subject, own, peer, source, held, ct).ConfigureAwait(false);
        for (byte index = 1; index <= control.Atoms.Count; index++)
        {
            await MaintainNativePrefixUnderLeaseAsync(current, opened.Scope, held, ct).ConfigureAwait(false);
            try
            {
                using var qualified = await QualifiedDid2RouteHistoryDecision.CaptureUnderLeaseAsync(this, current, opened,
                    subject, new Did2RouteHistorySelection(operation.Span, index), Did2RouteHistoryDecision.ActionKind.Evidence,
                    own, peer, source, held, ct).ConfigureAwait(false);
                _ = await opened.Custody.CommitRouteHistoryDecisionAsync(qualified, ct).ConfigureAwait(false);
            }
            catch (RouteHistoryCannotAdvanceException)
            {
                // Failed adjacency is staging. Faulting additionally needs a
                // separately verified incompatible original at a qualified F7
                // position; an exception alone supplies no such evidence.
                foreach (var kind in control.Atoms[index - 1].IsCompleted ? new byte[] { 1, 2 } : new byte[] { 2 })
                {
                    try
                    {
                        using var conflict = await QualifiedDid2RouteHistoryDecision.CaptureUnderLeaseAsync(this, current, opened,
                            subject, Did2RouteHistorySelection.Conflict(operation.Span, index, kind), Did2RouteHistoryDecision.ActionKind.Conflict,
                            own, peer, source, held, ct).ConfigureAwait(false);
                        _ = await opened.Custody.CommitRouteHistoryDecisionAsync(conflict, ct).ConfigureAwait(false);
                        return false;
                    }
                    catch (RouteHistoryCannotAdvanceException) { }
                }
            }
        }
        if (control.Mode is DeepIdV2ContactRouteHistoryMode.Announcement or DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement)
        {
            await MaintainNativePrefixUnderLeaseAsync(current, opened.Scope, held, ct).ConfigureAwait(false);
            try
            {
                using var qualified = await QualifiedDid2RouteHistoryDecision.CaptureUnderLeaseAsync(this, current, opened,
                    subject, new Did2RouteHistorySelection(operation.Span, 0), Did2RouteHistoryDecision.ActionKind.Promotion,
                    own, peer, source, held, ct).ConfigureAwait(false);
                _ = await opened.Custody.CommitRouteHistoryDecisionAsync(qualified, ct).ConfigureAwait(false);
            }
            catch (RouteHistoryCannotAdvanceException) { /* History does not imply a current route. */ }
        }
        if (outgoing) return false;
        var adopted = await ReadAdoptedRouteHistoryCursorUnderLeaseAsync(opened, subject, held, ct).ConfigureAwait(false);
        return BinaryPrimitives.ReadUInt64BigEndian(control.RightCursor.Span) > BinaryPrimitives.ReadUInt64BigEndian(adopted) ||
            BinaryPrimitives.ReadUInt64BigEndian(control.RightCursor.Span[40..]) > BinaryPrimitives.ReadUInt64BigEndian(adopted.AsSpan(40));
    }

    private async Task EnsureRouteHistoryBootstrapUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, byte subject,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using (var actual = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject,
            Did2RouteHistorySelection.Initial(), held, ct).ConfigureAwait(false))
            if (actual.Snapshot.PreviousDecision is not null) return;
        var legacyRoot = subject == 1 ? await RequireRetainedLegacyRouteDraftsDrainedUnderLeaseAsync(current, opened, held, ct).ConfigureAwait(false) : null;
        await MaintainNativePrefixUnderLeaseAsync(current, opened.Scope, held, ct).ConfigureAwait(false);
        using var qualified = await QualifiedDid2RouteHistoryDecision.CaptureUnderLeaseAsync(this, current, opened,
            subject, Did2RouteHistorySelection.Initial(), Did2RouteHistoryDecision.ActionKind.Bootstrap,
            own, peer, source, held, ct, legacyRoot).ConfigureAwait(false);
        _ = await opened.Custody.CommitRouteHistoryDecisionAsync(qualified, ct).ConfigureAwait(false);
    }

    private sealed class QualifiedRouteHistoryRead(Did2RouteHistorySnapshot snapshot, QualifiedArchiveAuthored authored) : IDisposable
    {
        internal Did2RouteHistorySnapshot Snapshot { get; } = snapshot;
        internal QualifiedArchiveAuthored Authored { get; } = authored;
        internal ReadOnlyMemory<byte> Original(Did2MessagingArchiveReference reference)
        {
            if (reference.Kind == 1) return Snapshot.InitialHello;
            var source = Snapshot.FindOriginal(reference);
            return reference.Kind == 2 && reference.Direction == 1 ? Authored.Events[reference.Ordinal] : source.Plaintext;
        }
        public void Dispose() { Authored.Dispose(); Snapshot.Dispose(); }
    }

    private async Task<QualifiedRouteHistoryRead> ReadRouteHistorySourcesUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, byte subject, Did2RouteHistorySelection selection,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var stable = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        Did2RouteHistorySnapshot? snapshot = null;
        QualifiedArchiveAuthored? authored = null;
        var originals = await opened.WithSqlAsync(sql => sql.ReadRouteHistoryAuthoredSources(stable, subject, selection), ct).ConfigureAwait(false);
        try
        {
            authored = await QualifyArchiveAuthoredAsync(opened.Scope, originals, held, ct,
                maximumOriginals: selection.MaximumAuthoredOriginals).ConfigureAwait(false);
            snapshot = await opened.WithPairedSqlAsync(authored.PairedRead,
                sql => sql.CaptureRouteHistorySnapshot(stable, subject, selection, authored.Events), ct).ConfigureAwait(false);
            var result = new QualifiedRouteHistoryRead(snapshot, authored); snapshot = null; authored = null; return result;
        }
        finally { authored?.Dispose(); snapshot?.Dispose(); foreach (var original in originals) original.Dispose(); }
    }

    private static (ReadOnlyMemory<byte> Invite, ReadOnlyMemory<byte> Route) CompletedSource(
        QualifiedRouteHistoryRead read, Did2RouteHistorySource source)
    {
        if (source.IsAbsent) throw new CryptographicException("Adopted completed history has no actual source.");
        var original = ApplicationCoreCodec.DecodeDmc2(read.Original(source.Reference).Span);
        if (source.AtomIndex == 0)
        {
            var package = original.ParsedPayload switch
            {
                ContactHelloDmc2Payload hello => hello.MailboxRoute,
                ContactAcceptDmc2Payload accept => accept.MailboxRoute,
                _ => throw new CryptographicException("A seed source is not its actual Hello/Accept.")
            };
            if (!FixedRoute(source.Reference.Exact.Span, read.Snapshot.Anchor.Exact.Span))
                throw new CryptographicException("A seed source changed the immutable relationship anchor.");
            return (package.Invite.CanonicalBytes, package.Route.ExactBytes);
        }
        if (original.ParsedPayload is not ContactRouteHistoryDmc2Payload page || source.AtomIndex > page.Atoms.Count ||
            !page.Atoms[source.AtomIndex - 1].IsCompleted)
            throw new CryptographicException("Adopted completed history lost its exact completed atom.");
        var atom = page.Atoms[source.AtomIndex - 1];
        return (atom.ExactCompletedXir1V2, atom.ExactCompletedRoute);
    }

    private static DeepIdV2ContactRouteRecordedPair? ProposalSource(QualifiedRouteHistoryRead read,
        Did2RouteHistorySource completed, Did2RouteHistorySource proposal)
    {
        if (proposal.IsAbsent) throw new CryptographicException("Adopted proposal history has no actual source.");
        if (proposal.AtomIndex == 0)
        {
            if (completed.AtomIndex != 0 || !FixedRoute(completed.Exact.Span, proposal.Exact.Span) ||
                !FixedRoute(proposal.Reference.Exact.Span, read.Snapshot.Anchor.Exact.Span))
                throw new CryptographicException("Only the exact original completed/proposal seed has no retained pair.");
            return null;
        }
        var original = ApplicationCoreCodec.DecodeDmc2(read.Original(proposal.Reference).Span);
        if (original.ParsedPayload is not ContactRouteHistoryDmc2Payload page || proposal.AtomIndex > page.Atoms.Count)
            throw new CryptographicException("Adopted proposal history lost its exact original atom.");
        var atom = page.Atoms[proposal.AtomIndex - 1];
        ReadOnlyMemory<byte> invite = default, route = default;
        for (var index = 0; index < proposal.AtomIndex - 1; index++)
            if (page.Atoms[index].IsCompleted)
            { invite = page.Atoms[index].ExactCompletedXir1V2; route = page.Atoms[index].ExactCompletedRoute; }
        if (invite.IsEmpty)
        {
            // The first qualifying native decision authenticates this atom's
            // actual before-C, which may predate today's independently adopted C.
            var qualification = read.Snapshot.Decisions.Where(value =>
                value.Body.Action == Did2RouteHistoryDecision.ActionKind.Evidence &&
                value.Body.SelectedAtomIndex == proposal.AtomIndex &&
                FixedRoute(value.Body.Selected.Exact.Span, proposal.Reference.Exact.Span))
                .OrderBy(value => value.Reference.Ordinal).FirstOrDefault() ??
                throw new CryptographicException("Adopted proposal lost its native qualifying decision.");
            var before = read.Snapshot.FindDecision(qualification.Body.PreviousDecision);
            (invite, route) = CompletedSource(read, before.Body.C);
            if (!FixedRoute(invite.Span, page.ExactLeftXir1V2.Span))
                throw new CryptographicException("Retained proposal changed its exact original completed anchor.");
            var closure = ContactRouteClosureCodec.Decode(route.Span);
            if (BinaryPrimitives.ReadUInt64BigEndian(page.LeftCursor.Span) != BinaryPrimitives.ReadUInt64BigEndian(closure.Reachability.Field(3).Span) ||
                !FixedRoute(page.LeftCursor.Span.Slice(8, 32), closure.Reachability.CoreHash.Span))
                throw new CryptographicException("Retained proposal cursor changed its actual before-C closure.");
        }
        return DeepIdV2ContactRouteHistoryCodec.ReconstructOriginalPair(atom, invite.Span, route.Span);
    }

    private async Task<VerifiedDeepIdV2ContactRouteHistory> RestoreRouteHistoryUnderLeaseAsync(
        QualifiedRouteHistoryRead read, Did2RouteHistorySource completed, Did2RouteHistorySource proposal,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var endpoint = CompletedSource(read, completed);
        var facts = await DeepIdV2ContactRouteUpdateVerifier.VerifyRetainedHistoryCheckpointFactsAsync(
            read.Original(read.Snapshot.Anchor), endpoint.Invite, endpoint.Route, ProposalSource(read, completed, proposal),
            read.Snapshot.Subject == 1 ? own.Proof : peer, own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        if (!FixedRoute(facts.ExactCompletedXir1V2.Span, endpoint.Invite.Span) ||
            !FixedRoute(facts.ExactCompletedRoute.Span, endpoint.Route.Span))
            throw new CryptographicException("Restored historical facts changed their actual native sources.");
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested(); return facts;
    }

    private static Did2RouteHistoryFactSelector HistorySelector(byte subject, byte kind, ulong generation)
    {
        var key = new byte[10]; key[0] = subject; key[1] = kind;
        BinaryPrimitives.WriteUInt64BigEndian(key.AsSpan(2), generation);
        return new(Did2MessagingArchiveFamily.RouteHistory, key);
    }

    // Historical scheduling/deletion input only. Native decisions already
    // authenticated these sources; this grants no live peer permission.
    private async Task<byte[]> ReadAdoptedRouteHistoryCursorUnderLeaseAsync(OwnedDid2MessagingStorage opened,
        byte subject, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        Did2RouteHistorySelection selection;
        using (var initial = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject, Did2RouteHistorySelection.Initial(), held, ct).ConfigureAwait(false))
        {
            if (initial.Snapshot.PreviousDecision is null)
                throw new CryptographicException("An authored history request lost its adopted native checkpoint.");
            selection = SelectAdoptedHistoryFacts(initial);
        }
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject, selection, held, ct).ConfigureAwait(false);
        var completed = ContactRouteClosureCodec.Decode(CompletedSource(read, read.Snapshot.C).Route.Span);
        var proposal = ProposalSource(read, read.Snapshot.C, read.Snapshot.P);
        var authorization = proposal is null ? completed.Authorization : ContactCodec.Decode("XRA1", proposal.Request.ExactXra1.Span);
        var route = proposal is null ? completed.Route : ContactCodec.Decode("XRC1", proposal.Response.ExactXrc1.Span);
        var cursor = new byte[112]; completed.Reachability.Field(3).Span.CopyTo(cursor);
        completed.Reachability.CoreHash.Span.CopyTo(cursor.AsSpan(8)); authorization.Field(3).Span.CopyTo(cursor.AsSpan(40));
        authorization.CoreHash.Span.CopyTo(cursor.AsSpan(48)); route.CoreHash.Span.CopyTo(cursor.AsSpan(80));
        _ = FirstVerifiedHistoryDecision(read, 1, BinaryPrimitives.ReadUInt64BigEndian(cursor));
        _ = FirstVerifiedHistoryDecision(read, 2, BinaryPrimitives.ReadUInt64BigEndian(cursor.AsSpan(40)));
        await opened.WithPairedSqlAsync(read.Authored.PairedRead,
            sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested(); return cursor;
    }

    private static Did2RouteHistorySelection SelectAdoptedHistoryFacts(QualifiedRouteHistoryRead read)
    {
        var snapshot = read.Snapshot; var facts = snapshot.Selection.Facts.ToList();
        if (snapshot.PreviousDecision is not null)
        {
            var completed = ContactRouteClosureCodec.Decode(CompletedSource(read, snapshot.C).Route.Span);
            Add(HistorySelector(snapshot.Subject, 1, BinaryPrimitives.ReadUInt64BigEndian(completed.Reachability.Field(3).Span)));
            var proposalOriginal = ApplicationCoreCodec.DecodeDmc2(read.Original(snapshot.P.Reference).Span);
            var generation = snapshot.P.AtomIndex == 0 ? BinaryPrimitives.ReadUInt64BigEndian(completed.Authorization.Field(3).Span) :
                proposalOriginal.ParsedPayload is ContactRouteHistoryDmc2Payload page && snapshot.P.AtomIndex <= page.Atoms.Count ?
                    BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", page.Atoms[snapshot.P.AtomIndex - 1].ExactXra1.Span).Field(3).Span) :
                    throw new CryptographicException("Adopted P lost its actual atom while selecting its qualified fact.");
            Add(HistorySelector(snapshot.Subject, 2, generation));
            if (proposalOriginal.ParsedPayload is ContactRouteHistoryDmc2Payload retainedProposal && snapshot.P.AtomIndex > 0 &&
                retainedProposal.Atoms[snapshot.P.AtomIndex - 1].IsCompleted)
                Add(HistorySelector(snapshot.Subject, 1, BinaryPrimitives.ReadUInt64BigEndian(ContactRouteClosureCodec.Decode(
                    retainedProposal.Atoms[snapshot.P.AtomIndex - 1].ExactCompletedRoute.Span).Reachability.Field(3).Span)));
        }
        var selected = ApplicationCoreCodec.DecodeDmc2(read.Original(snapshot.SelectedOriginal.Reference).Span);
        if (!snapshot.L.IsAbsent && ApplicationCoreCodec.DecodeDmc2(read.Original(snapshot.L).Span).ParsedPayload is ContactRouteHistoryDmc2Payload retainedLive)
            Add(HistorySelector(snapshot.Subject, 1, BinaryPrimitives.ReadUInt64BigEndian(retainedLive.RightCursor.Span)));
        if (!snapshot.Selection.IsPositionConflict && selected.ParsedPayload is ContactRouteHistoryDmc2Payload control)
        {
            if (snapshot.Subject == 2 && !Did2MessagingSessionScope.Zero(control.RequestEventHash.Span))
            {
                var key = new byte[33]; key[0] = 2; control.RequestEventHash.Span.CopyTo(key.AsSpan(1));
                Add(new(Did2MessagingArchiveFamily.RouteControl, key));
            }
            // Exact endpoint restoration for an older announcement stays
            // independent of today's later adopted C/P.
            if (!snapshot.Selection.IsConflict)
            {
                Add(HistorySelector(snapshot.Subject, 1, BinaryPrimitives.ReadUInt64BigEndian(control.RightCursor.Span)));
                Add(HistorySelector(snapshot.Subject, 2, BinaryPrimitives.ReadUInt64BigEndian(control.RightCursor.Span[40..])));
            }
            if (snapshot.SelectedAtomIndex is > 0 && snapshot.SelectedAtomIndex <= control.Atoms.Count)
            {
                var atom = control.Atoms[snapshot.SelectedAtomIndex - 1];
                if (!snapshot.Selection.IsConflict || snapshot.Selection.ConflictClass == 2)
                    Add(HistorySelector(snapshot.Subject, 2, BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", atom.ExactXra1.Span).Field(3).Span)));
                if (atom.IsCompleted && (!snapshot.Selection.IsConflict || snapshot.Selection.ConflictClass == 1))
                    Add(HistorySelector(snapshot.Subject, 1, BinaryPrimitives.ReadUInt64BigEndian(ContactRouteClosureCodec.Decode(atom.ExactCompletedRoute.Span).Reachability.Field(3).Span)));
            }
        }
        return snapshot.Selection.IsPositionConflict ? Did2RouteHistorySelection.PositionConflict(snapshot.Selection.Operation.Span, facts) :
            snapshot.Selection.IsConflict ? Did2RouteHistorySelection.Conflict(snapshot.Selection.Operation.Span, snapshot.SelectedAtomIndex, snapshot.Selection.ConflictClass, facts) :
            snapshot.Selection.IsInitial ? Did2RouteHistorySelection.Initial(facts) :
            new Did2RouteHistorySelection(snapshot.Selection.Operation.Span, snapshot.SelectedAtomIndex, facts);
        void Add(Did2RouteHistoryFactSelector selector)
        {
            if (!facts.Any(value => value.Family == selector.Family && FixedRoute(value.Selector.Span, selector.Selector.Span))) facts.Add(selector);
        }
    }

    private static Did2RouteHistoryStoredDecision FirstVerifiedHistoryDecision(QualifiedRouteHistoryRead read,
        byte kind, ulong generation)
    {
        var selector = HistorySelector(read.Snapshot.Subject, kind, generation);
        var fact = read.Snapshot.Facts.SingleOrDefault(value => value.Selector.Family == selector.Family &&
            FixedRoute(value.Selector.Selector.Span, selector.Selector.Span));
        if (fact?.Value is not { } value || value.Length != 224)
            throw new CryptographicException("Adopted historical endpoint lost its authenticated first-qualified fact.");
        var reference = Did2MessagingArchiveReference.Decode(value.Span[..88], false);
        if (reference.Kind != 3) throw new CryptographicException("A staged candidate cannot restore verified historical progress.");
        var decision = read.Snapshot.FindDecision(reference);
        if (decision.Body.Subject != read.Snapshot.Subject || decision.Body.Action is not
            (Did2RouteHistoryDecision.ActionKind.Bootstrap or Did2RouteHistoryDecision.ActionKind.Evidence))
            throw new CryptographicException("A historical fact has no qualifying native bootstrap/evidence decision.");
        return decision;
    }

    private static bool HasVerifiedHistoryFact(QualifiedRouteHistoryRead read, byte kind, ulong generation)
    {
        var selector = HistorySelector(read.Snapshot.Subject, kind, generation);
        var value = read.Snapshot.Facts.SingleOrDefault(fact => fact.Selector.Family == selector.Family &&
            FixedRoute(fact.Selector.Selector.Span, selector.Selector.Span))?.Value;
        return value is { Length: 224 } exact && !Did2MessagingArchiveReference.Decode(exact.Span[..88]).IsAbsent;
    }

    private static void RequireRouteHistoryConsent(QualifiedRouteHistoryRead read)
    {
        var hello = ApplicationCoreCodec.DecodeDmc2(read.Snapshot.InitialHello.Span);
        var accepted = ApplicationCoreCodec.DecodeDmc2(read.Original(read.Snapshot.Consent).Span);
        if (hello.ParsedPayload is not ContactHelloDmc2Payload greeting ||
            accepted.ParsedPayload is not ContactAcceptDmc2Payload consent ||
            (greeting.Policy & ContactPolicy.AllowRouteUpdates) == 0 || (consent.Policy & ContactPolicy.AllowRouteUpdates) == 0 ||
            !FixedRoute(greeting.RelationshipId.Span, read.Snapshot.Scope.Relationship) ||
            !FixedRoute(consent.RelationshipId.Span, read.Snapshot.Scope.Relationship))
            throw new CryptographicException("Route history requires actual immutable Hello/Accept consent.");
    }

    private async Task<byte[]> QualifyRouteHistoryDecisionBodyUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, OwnedDid2MessagingStorage opened, QualifiedRouteHistoryRead read,
        Did2RouteHistoryDecision.ActionKind action,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var snapshot = read.Snapshot; var scope = snapshot.Scope;
        held.RequireOwner(lease); RequireRouteHistoryConsent(read);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        var c = snapshot.C; var p = snapshot.P; var live = snapshot.L;
        var related = Did2RouteHistorySource.Absent();
        var selected = snapshot.SelectedOriginal.Reference;
        VerifiedDeepIdV2UpdatedMailboxRoute? promotion = null;
        VerifiedDeepIdV2ContactRouteHistory result;
        if (action == Did2RouteHistoryDecision.ActionKind.Bootstrap)
        {
            if (snapshot.PreviousDecision is not null || !snapshot.C.IsAbsent || !snapshot.P.IsAbsent ||
                !FixedRoute(selected.Exact.Span, snapshot.Anchor.Exact.Span) || snapshot.SelectedAtomIndex != 0)
                throw new CryptographicException("Route history cannot bootstrap over an adopted decision.");
            result = await DeepIdV2ContactRouteUpdateVerifier.VerifyHistoryAnchorAsync(read.Original(snapshot.Anchor),
                snapshot.Subject == 1 ? own.Proof : peer, own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            c = Did2RouteHistorySource.From(snapshot.Anchor, 0); p = Did2RouteHistorySource.From(snapshot.Anchor, 0);
        }
        else
        {
            if (snapshot.PreviousDecision is null || !snapshot.FirstFault.IsAbsent)
                throw new CryptographicException("Route history lost adopted progress or retained its sticky fault.");
            var before = await RestoreRouteHistoryUnderLeaseAsync(read, c, p, own, peer, source, held, ct).ConfigureAwait(false);
            // These facts prove previously committed qualification, independently
            // of any raw candidate currently occupying the same F7 selector.
            _ = FirstVerifiedHistoryDecision(read, 1, BinaryPrimitives.ReadUInt64BigEndian(before.Cursor.Span));
            _ = FirstVerifiedHistoryDecision(read, 2, BinaryPrimitives.ReadUInt64BigEndian(before.Cursor.Span[40..]));
            var exact = read.Original(selected);
            if (ApplicationCoreCodec.DecodeDmc2(exact.Span).ParsedPayload is not ContactRouteHistoryDmc2Payload page)
                throw new CryptographicException("A new history decision requires its exact count8 native control.");
            if (!snapshot.Selection.IsPositionConflict && snapshot.Subject == 2 && !Did2MessagingSessionScope.Zero(page.RequestEventHash.Span))
            {
                var key = new byte[33]; key[0] = 2; page.RequestEventHash.Span.CopyTo(key.AsSpan(1));
                var requestFact = snapshot.Facts.SingleOrDefault(value => value.Selector.Family == Did2MessagingArchiveFamily.RouteControl &&
                    FixedRoute(value.Selector.Selector.Span, key))?.Value;
                if (requestFact is not { Length: 88 } requestValue)
                    throw new CryptographicException("A route-history response lost its exact retained native request correlation.");
                var request = Did2MessagingArchiveReference.Decode(requestValue.Span, false);
                if (request.Kind != 2 || request.Direction != 1)
                    throw new CryptographicException("A route-history response names a foreign request source.");
                DeepIdV2ContactRouteUpdateVerifier.RequireHistoryResponseCorrelation(page, read.Original(request).Span);
            }
            if (action == Did2RouteHistoryDecision.ActionKind.Evidence)
            {
                if (snapshot.SelectedAtomIndex == 0) throw new CryptographicException("An evidence decision selects exactly one original atom.");
                VerifiedDeepIdV2ContactRouteHistoryStep step;
                try
                {
                    step = await DeepIdV2ContactRouteUpdateVerifier.VerifyHistoryAtomAsync(before, exact,
                        snapshot.SelectedAtomIndex, snapshot.Subject == 1 ? own.Proof : peer, own.Network, own.Authority,
                        source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is CryptographicException or InvalidDataException or FormatException)
                {
                    await RecheckStagedRouteHistoryUnderLeaseAsync(current, opened, read, own, peer, source, held, first, ct).ConfigureAwait(false);
                    throw new RouteHistoryCannotAdvanceException();
                }
                result = step.After;
                p = Did2RouteHistorySource.From(selected, snapshot.SelectedAtomIndex);
                if (page.Atoms[snapshot.SelectedAtomIndex - 1].IsCompleted) c = p;
            }
            else if (action == Did2RouteHistoryDecision.ActionKind.Promotion)
            {
                if (snapshot.SelectedAtomIndex != 0) throw new CryptographicException("Current promotion selects the whole original announcement.");
                if (FixedRoute(snapshot.L.Exact.Span, selected.Exact.Span) ||
                    !snapshot.L.IsAbsent && FixedRoute(read.Original(snapshot.L).Span, exact.Span))
                {
                    await RecheckStagedRouteHistoryUnderLeaseAsync(current, opened, read, own, peer, source, held, first, ct).ConfigureAwait(false);
                    throw new RouteHistoryCannotAdvanceException();
                }
                if (!HasVerifiedHistoryFact(read, 1, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span)) ||
                    !HasVerifiedHistoryFact(read, 2, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span[40..])))
                {
                    await RecheckStagedRouteHistoryUnderLeaseAsync(current, opened, read, own, peer, source, held, first, ct).ConfigureAwait(false);
                    throw new RouteHistoryCannotAdvanceException();
                }
                var cDecision = FirstVerifiedHistoryDecision(read, 1, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span));
                var pDecision = FirstVerifiedHistoryDecision(read, 2, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span[40..]));
                result = await RestoreRouteHistoryUnderLeaseAsync(read, cDecision.Body.C, pDecision.Body.P,
                    own, peer, source, held, ct).ConfigureAwait(false);
                if (!FixedRoute(result.Cursor.Span, page.RightCursor.Span))
                    throw new CryptographicException("Announcement endpoint differs from its authenticated historical facts.");
                try
                {
                    promotion = await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentHistoryAnnouncementAsync(result, exact,
                        snapshot.Subject == 1 ? own.Proof : peer, own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is CryptographicException or InvalidDataException or FormatException)
                {
                    await RecheckStagedRouteHistoryUnderLeaseAsync(current, opened, read, own, peer, source, held, first, ct).ConfigureAwait(false);
                    throw new RouteHistoryCannotAdvanceException();
                }
                await promotion.EnsureCurrentAsync(ct).ConfigureAwait(false);
                if (!snapshot.L.IsAbsent && BinaryPrimitives.ReadUInt64BigEndian(result.Cursor.Span) <
                    BinaryPrimitives.ReadUInt64BigEndian(RetainedHistoryLiveClosure(read).Reachability.Field(3).Span))
                {
                    await RecheckStagedRouteHistoryUnderLeaseAsync(current, opened, read, own, peer, source, held, first, ct).ConfigureAwait(false);
                    throw new RouteHistoryCannotAdvanceException();
                }
                RequireMonotonicHistoryLive(read, result, equalityRequired: false);
                // Replaying an older authored announcement cannot replace a
                // newer L for this exact independently qualified endpoint.
                if (!snapshot.L.IsAbsent && FixedRoute(result.ExactCompletedRoute.Span, RetainedHistoryLiveClosure(read).ExactBytes.Span) &&
                    ApplicationCoreCodec.DecodeDmc2(read.Original(selected).Span).SenderClientSequence <=
                    ApplicationCoreCodec.DecodeDmc2(read.Original(snapshot.L).Span).SenderClientSequence)
                {
                    await RecheckStagedRouteHistoryUnderLeaseAsync(current, opened, read, own, peer, source, held, first, ct).ConfigureAwait(false);
                    throw new RouteHistoryCannotAdvanceException();
                }
                live = selected;
            }
            else if (action == Did2RouteHistoryDecision.ActionKind.Conflict)
            {
                result = before;
                if (snapshot.Selection.IsPositionConflict)
                {
                    if (snapshot.Subject != 2 || snapshot.SelectedAtomIndex != 0 || snapshot.PositionConflict is not { } earlier || earlier.Ordinal >= selected.Ordinal)
                    {
                        await RecheckStagedRouteHistoryUnderLeaseAsync(current, opened, read, own, peer, source, held, first, ct).ConfigureAwait(false);
                        throw new RouteHistoryCannotAdvanceException();
                    }
                    RequireHistoryPositionConflict(read, earlier);
                    related = Did2RouteHistorySource.From(earlier, 0);
                }
                else
                {
                if (snapshot.SelectedAtomIndex == 0 || snapshot.SelectedAtomIndex > page.Atoms.Count)
                    throw new CryptographicException("Conflict qualification lost its selected exact atom.");
                var atom = page.Atoms[snapshot.SelectedAtomIndex - 1];
                foreach (var kind in new[] { snapshot.Selection.ConflictClass })
                {
                    var generation = kind == 1 ? BinaryPrimitives.ReadUInt64BigEndian(ContactRouteClosureCodec.Decode(atom.ExactCompletedRoute.Span).Reachability.Field(3).Span) :
                        BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", atom.ExactXra1.Span).Field(3).Span);
                    if (!HasVerifiedHistoryFact(read, kind, generation)) continue;
                    var firstQualified = FirstVerifiedHistoryDecision(read, kind, generation);
                    if (firstQualified.Body.Action != Did2RouteHistoryDecision.ActionKind.Evidence) continue;
                    var firstBefore = snapshot.FindDecision(firstQualified.Body.PreviousDecision);
                    var prior = await RestoreRouteHistoryUnderLeaseAsync(read, firstBefore.Body.C, firstBefore.Body.P,
                        own, peer, source, held, ct).ConfigureAwait(false);
                    VerifiedDeepIdV2ContactRouteHistoryStep verified;
                    try
                    {
                        verified = await DeepIdV2ContactRouteUpdateVerifier.VerifyHistoryAtomAsync(prior, exact,
                            snapshot.SelectedAtomIndex, snapshot.Subject == 1 ? own.Proof : peer, own.Network, own.Authority,
                            source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is CryptographicException or InvalidDataException or FormatException) { continue; }
                    var pair = DeepIdV2ContactRouteHistoryCodec.ReconstructOriginalPair(atom, prior.ExactCompletedXir1V2.Span, prior.ExactCompletedRoute.Span);
                    var identity = VerifiedHistoryIdentity(scope, snapshot.Subject, kind, verified.After, pair);
                    var selector = HistorySelector(snapshot.Subject, kind, generation);
                    var firstFact = snapshot.Facts.Single(value => value.Selector.Family == selector.Family &&
                        FixedRoute(value.Selector.Selector.Span, selector.Selector.Span)).Value!.Value;
                    if (FixedRoute(identity, firstFact.Span.Slice(88, 32))) continue;
                    related = kind == 1 ? firstQualified.Body.C : firstQualified.Body.P;
                    break;
                }
                if (related.IsAbsent)
                {
                    await RecheckStagedRouteHistoryUnderLeaseAsync(current, opened, read, own, peer, source, held, first, ct).ConfigureAwait(false);
                    throw new RouteHistoryCannotAdvanceException();
                }
                }
            }
            else throw new InvalidOperationException("Unknown closed route-history decision action.");
            RequireMonotonicHistoryLive(read, result, equalityRequired: true);
        }
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        var reading = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        if (reading.SampleSeconds < first.SampleSeconds || !FixedRoute(reading.BootId.Span, first.BootId.Span))
            throw new CryptographicException("Route history crossed its final protected qualification clock.");
        var lower = Math.Min(checked(own.Proof.TrustedLowerUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample),
            checked(peer.TrustedLowerUnixSeconds + reading.SampleSeconds - peer.MonotonicSample));
        var upper = Math.Max(checked(own.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample),
            checked(peer.TrustedUpperUnixSeconds + reading.SampleSeconds - peer.MonotonicSample));
        var sample = reading.SampleSeconds; var boot = reading.BootId;
        if (promotion is not null)
        {
            var window = await promotion.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
            if (window.MonotonicSample < sample || !FixedRoute(window.BootId.Span, boot.Span))
                throw new CryptographicException("Current route promotion crossed its final protected qualification interval.");
            lower = window.LowerUnixSeconds; upper = window.UpperUnixSeconds; sample = window.MonotonicSample; boot = window.BootId;
        }
        var body = new byte[1024]; body[0] = 1; body[1] = (byte)action; body[2] = snapshot.Subject; scope.Hash.CopyTo(body.AsSpan(4));
        (snapshot.PreviousDecision?.Reference ?? Did2MessagingArchiveReference.Absent()).Exact.Span.CopyTo(body.AsSpan(36));
        selected.Exact.Span.CopyTo(body.AsSpan(124)); body[212] = snapshot.SelectedAtomIndex;
        c.Exact.Span.CopyTo(body.AsSpan(220)); p.Exact.Span.CopyTo(body.AsSpan(316)); live.Exact.Span.CopyTo(body.AsSpan(412));
        snapshot.FirstFault.Exact.Span.CopyTo(body.AsSpan(500)); snapshot.Consent.Exact.Span.CopyTo(body.AsSpan(588));
        body[676] = action == Did2RouteHistoryDecision.ActionKind.Promotion ? (byte)1 : (byte)3;
        BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(684), checked(lower * 1000));
        BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(692), checked(upper * 1000));
        BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(700), sample); SHA256.HashData(boot.Span, body.AsSpan(708, 32));
        SHA256.HashData(result.ExactCompletedRoute.Span, body.AsSpan(740, 32));
        related.Exact.Span.CopyTo(body.AsSpan(772));
        _ = Did2RouteHistoryDecision.Decode(body, scope);
        await opened.WithPairedSqlAsync(read.Authored.PairedRead,
            sql => { sql.RequireRouteHistorySnapshot(snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested(); return body;
    }

    private static void RequireHistoryPositionConflict(QualifiedRouteHistoryRead read, Did2MessagingArchiveReference earlier,
        Did2MessagingArchiveReference? later = null)
    {
        var selected = later ?? read.Snapshot.SelectedOriginal.Reference;
        var first = ApplicationCoreCodec.DecodeDmc2(read.Original(earlier).Span);
        var second = ApplicationCoreCodec.DecodeDmc2(read.Original(selected).Span);
        try
        {
        if (earlier.Kind != 2 || earlier.Direction != 2 || selected.Kind != 2 || selected.Direction != 2 ||
            earlier.Ordinal >= selected.Ordinal ||
            second.ParsedPayload is not ContactRouteHistoryDmc2Payload || first.SenderClientSequence != second.SenderClientSequence ||
            !FixedRoute(first.SenderAccountId.Span, second.SenderAccountId.Span) ||
            !FixedRoute(first.SenderDeviceId.Span, second.SenderDeviceId.Span) ||
            !FixedRoute(first.ConversationId.Span, second.ConversationId.Span) ||
            FixedRoute(first.CanonicalBytes.Span, second.CanonicalBytes.Span))
            throw new CryptographicException("A whole-control route fault lost its two authenticated original authored-position witnesses.");
        }
        finally { if (first.ParsedPayload is AttachmentOfferDmc2Payload attachment) attachment.Manifest.Dispose(); }
    }

    private async Task RequireRouteHistoryInboxDispositionUnderLeaseAsync(OwnedDid2MessagingStorage opened,
        ReadOnlyMemory<byte> operation, bool outgoing, DirectDmc2InboxDisposition disposition,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        if (disposition != DirectDmc2InboxDisposition.ForkLatched || outgoing)
        { RequireApplicationDisposition(disposition); return; }
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 2,
            Did2RouteHistorySelection.PositionConflict(operation.Span), held, ct).ConfigureAwait(false);
        if (read.Snapshot.FirstFault.IsAbsent || read.Snapshot.FirstFault.Kind != 3)
            throw new CryptographicException("An application authored-position fork lacks its committed native route fault.");
        var fault = read.Snapshot.FindDecision(read.Snapshot.FirstFault);
        if (fault.Body.Action != Did2RouteHistoryDecision.ActionKind.Conflict || fault.Body.SelectedAtomIndex != 0 ||
            fault.Body.Conflicting.AtomIndex != 0 ||
            !(FixedRoute(fault.Body.Selected.Exact.Span, read.Snapshot.SelectedOriginal.Reference.Exact.Span) ||
                FixedRoute(fault.Body.Conflicting.Reference.Exact.Span, read.Snapshot.SelectedOriginal.Reference.Exact.Span)))
            throw new CryptographicException("An application authored-position fork differs from its actual first native witnesses.");
        RequireHistoryPositionConflict(read, fault.Body.Conflicting.Reference, fault.Body.Selected);
    }

    private static byte[] VerifiedHistoryIdentity(Did2MessagingSessionScope scope, byte subject, byte kind,
        VerifiedDeepIdV2ContactRouteHistory endpoint, DeepIdV2ContactRouteRecordedPair? proposal)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(kind == 1 ? "Deep/STORE-V2/route-history-C"u8 : "Deep/STORE-V2/route-history-P"u8);
        hash.AppendData([0]); hash.AppendData(scope.Hash); hash.AppendData([subject]);
        var route = ContactRouteClosureCodec.Decode(endpoint.ExactCompletedRoute.Span);
        if (kind == 1)
        {
            hash.AppendData(DeepIdV2InviteRendezvousCodec.Decode(endpoint.ExactCompletedXir1V2.Span).ObjectHash.Span);
            hash.AppendData(route.Reachability.CoreHash.Span);
        }
        else
        {
            hash.AppendData(proposal is null ? route.Authorization.CoreHash.Span : ContactCodec.Decode("XRA1", proposal.Request.ExactXra1.Span).CoreHash.Span);
            hash.AppendData(proposal is null ? route.Route.CoreHash.Span : ContactCodec.Decode("XRC1", proposal.Response.ExactXrc1.Span).CoreHash.Span);
            hash.AppendData(proposal is null ? route.Successor.CoreHash.Span : ContactCodec.Decode("XSS1", proposal.Response.ExactXss1.Span).CoreHash.Span);
        }
        return hash.GetHashAndReset();
    }

    private static void RequireMonotonicHistoryLive(QualifiedRouteHistoryRead read,
        VerifiedDeepIdV2ContactRouteHistory endpoint, bool equalityRequired)
    {
        if (read.Snapshot.L.IsAbsent) return;
        var retained = RetainedHistoryLiveClosure(read);
        var oldGeneration = BinaryPrimitives.ReadUInt64BigEndian(retained.Reachability.Field(3).Span);
        var candidate = BinaryPrimitives.ReadUInt64BigEndian(endpoint.Cursor.Span);
        if ((!equalityRequired && candidate < oldGeneration) || candidate == oldGeneration &&
            !FixedRoute(endpoint.ExactCompletedRoute.Span, retained.ExactBytes.Span))
            throw new CryptographicException("Route history changed or lowered its independently qualified live endpoint.");
    }

    private static ParsedContactRouteClosure RetainedHistoryLiveClosure(QualifiedRouteHistoryRead read)
    {
        var original = ApplicationCoreCodec.DecodeDmc2(read.Original(read.Snapshot.L).Span);
        ParsedContactRouteClosure retained;
        if (original.ParsedPayload is ContactRouteHistoryDmc2Payload announcement)
        {
            var qualified = FirstVerifiedHistoryDecision(read, 1, BinaryPrimitives.ReadUInt64BigEndian(announcement.RightCursor.Span));
            retained = ContactRouteClosureCodec.Decode(CompletedSource(read, qualified.Body.C).Route.Span);
            if (!FixedRoute(retained.Reachability.CoreHash.Span, announcement.RightCursor.Span.Slice(8, 32)))
                throw new CryptographicException("Retained live history changed its independently qualified endpoint.");
        }
        else retained = ArchiveRouteClosure(original.CanonicalBytes.Span);
        return retained;
    }

    // Permanent authenticated payload custody only. A staged control has no
    // historical or current permission merely because its original is readable.
    internal sealed class OwnedRouteHistoryInboxEvent : IAuthenticatedDmc2InboxEvent, IDisposable
    {
        private readonly byte[] exact, local, conversation, logical, author, device;
        private bool disposed;
        private OwnedRouteHistoryInboxEvent(Did2MessagingSessionScope scope, ReadOnlySpan<byte> bytes, bool outgoing)
        {
            var message = ApplicationCoreCodec.DecodeDmc2(bytes);
            if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload history ||
                message.Flags != Dmc2Flags.None || !message.ReplyToLogicalMessageId.IsEmpty ||
                !FixedRoute(history.RelationshipId.Span, scope.Relationship) ||
                !FixedRoute(message.NetworkId.Span, scope.Network) || !FixedRoute(message.ConversationId.Span, scope.Conversation) ||
                !FixedRoute(message.SenderAccountId.Span, outgoing ? scope.LocalAccount : scope.RemoteAccount) ||
                !FixedRoute(message.SenderDeviceId.Span, outgoing ? scope.LocalDevice : scope.RemoteDevice))
                throw new CryptographicException("Permanent route-history custody changed its actual native scope.");
            exact = bytes.ToArray(); local = scope.LocalAccount.ToArray(); conversation = message.ConversationId.ToArray();
            logical = message.LogicalMessageId.ToArray(); author = message.SenderAccountId.ToArray(); device = message.SenderDeviceId.ToArray();
            LocalAccountGeneration = BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]);
        }
        public ReadOnlyMemory<byte> ExactDmc2 => Copy(exact);
        public ReadOnlyMemory<byte> LocalAccountId => Copy(local);
        public ulong LocalAccountGeneration { get; }
        public ReadOnlyMemory<byte> ConversationId => Copy(conversation);
        public ReadOnlyMemory<byte> LogicalMessageId => Copy(logical);
        public ReadOnlyMemory<byte> AuthorAccountId => Copy(author);
        public ReadOnlyMemory<byte> AuthorDeviceId => Copy(device);
        public Dmc2ContentKind ContentKind => Dmc2ContentKind.ContactRouteUpdate;
        private ReadOnlyMemory<byte> Copy(byte[] value)
        { ObjectDisposedException.ThrowIf(disposed, this); return value.ToArray(); }
        public void Dispose()
        {
            if (disposed) return; disposed = true;
            foreach (var value in new[] { exact, local, conversation, logical, author, device }) CryptographicOperations.ZeroMemory(value);
        }
        internal static async Task<OwnedRouteHistoryInboxEvent> CaptureUnderLeaseAsync(
            ProtectedDeepIdV2AccountOwner owner, VerifiedDeepIdV2CurrentAccount current,
            OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation, bool outgoing,
            DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
            VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
            HeldDeepIdV2AccountLease held, CancellationToken ct)
        {
            held.RequireOwner(owner.lease); var scope = opened.Scope;
            var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            var selection = Did2RouteHistorySelection.Custody(operation.Span);
            using var read = await owner.ReadRouteHistorySourcesUnderLeaseAsync(opened, outgoing ? (byte)1 : (byte)2,
                selection, held, ct).ConfigureAwait(false);
            var snapshot = read.Snapshot; var authored = read.Authored;
            RequireRouteHistoryConsent(read);
            if (!FixedRoute(snapshot.Before.Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Permanent route-history custody changed its actual before floor.");
            var original = snapshot.SelectedOriginal;
            if (original.Reference.Kind != 2 || original.Reference.Direction != (outgoing ? 1 : 2) ||
                !outgoing && original.Metadata[Did2RouteProcessingMetadata.Offset] != 3)
                throw new CryptographicException("Permanent route-history custody lost its original native send/staged receive.");
            var exact = outgoing ? authored.Events[original.Reference.Ordinal].ToArray() : original.Plaintext.ToArray();
            try
            {
                if (!FixedRoute(SHA256.HashData(exact), original.Metadata.AsSpan(300, 32)))
                    throw new CryptographicException("Permanent route-history custody changed its authenticated event hash.");
                var control = ApplicationCoreCodec.DecodeDmc2(exact).ParsedPayload as ContactRouteHistoryDmc2Payload ??
                    throw new CryptographicException("Permanent route-history custody lost its exact control.");
                var helloIsAnchor = (snapshot.Subject == 1) == scope.IsInitiator;
                if (control.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest) helloIsAnchor = !helloIsAnchor;
                var expectedAnchor = helloIsAnchor ? snapshot.InitialHello : read.Original(snapshot.Consent);
                if (!FixedRoute(control.OriginalAnchorHash.Span, SHA256.HashData(expectedAnchor.Span)))
                    throw new CryptographicException("Permanent route-history custody changed its actual immutable history anchor.");
                await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
                await opened.WithPairedSqlAsync(authored.PairedRead, sql => { sql.RequireRouteHistorySnapshot(snapshot, authored.Events); return true; }, ct).ConfigureAwait(false);
                held.RequireOwner(owner.lease); ct.ThrowIfCancellationRequested();
                return new(scope, exact, outgoing);
            }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
    }

    // Only this owner can seal qualification after its actual native sources,
    // Protocol result and final paired application/native snapshot all agree.
    // Recovery consumes the protected exact body, never a reconstructed clock
    // interval or another invocation of the original verifier.
    internal sealed class QualifiedDid2RouteHistoryDecision : IDisposable
    {
        private readonly byte[] body;
        private readonly QualifiedRouteHistoryRead read;
        private QualifiedDid2RouteHistoryDecision(QualifiedRouteHistoryRead read, ReadOnlySpan<byte> exact)
        {
            if (exact.Length != 1024) throw new InvalidDataException("A qualified route-history decision has another width.");
            this.read = read; body = exact.ToArray();
        }

        internal Did2RouteHistorySnapshot Snapshot => read.Snapshot;
        internal Did2MessagingArchiveAuthoredRead PairedRead => read.Authored.PairedRead;
        internal IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> AuthoredEvents => read.Authored.Events;

        internal static async Task<QualifiedDid2RouteHistoryDecision> CaptureUnderLeaseAsync(
            ProtectedDeepIdV2AccountOwner owner, VerifiedDeepIdV2CurrentAccount current, OwnedDid2MessagingStorage opened,
            byte subject, Did2RouteHistorySelection selection, Did2RouteHistoryDecision.ActionKind action,
            DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
            VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
            HeldDeepIdV2AccountLease held, CancellationToken ct, byte[]? expectedLegacyRoot = null)
        {
            var read = await owner.ReadRouteHistorySourcesUnderLeaseAsync(opened, subject, selection, held, ct).ConfigureAwait(false);
            byte[] body = [];
            try
            {
                if (expectedLegacyRoot is not null && (action != Did2RouteHistoryDecision.ActionKind.Bootstrap || subject != 1 ||
                    !read.Authored.Roots.TryGetValue(ProtectedDid2DirectTextJournal.Slot, out var actualLegacyRoot) ||
                    actualLegacyRoot is null || !FixedRoute(expectedLegacyRoot, actualLegacyRoot)))
                    throw new CryptographicException("Retained legacy route work changed before own history bootstrap.");
                if (action != Did2RouteHistoryDecision.ActionKind.Bootstrap)
                {
                    var enriched = SelectAdoptedHistoryFacts(read);
                    var before = read.Snapshot.Before.Exact.ToArray(); read.Dispose();
                    read = await owner.ReadRouteHistorySourcesUnderLeaseAsync(opened, subject, enriched, held, ct).ConfigureAwait(false);
                    if (!FixedRoute(before, read.Snapshot.Before.Exact.Span))
                        throw new CryptographicException("History source selection changed its actual native predecessor.");
                    if (selection.IsConflict)
                    {
                        var third = SelectConflictBeforeProposalFacts(read);
                        read.Dispose();
                        read = await owner.ReadRouteHistorySourcesUnderLeaseAsync(opened, subject, third, held, ct).ConfigureAwait(false);
                        if (!FixedRoute(before, read.Snapshot.Before.Exact.Span))
                            throw new CryptographicException("Conflict source selection changed its actual native predecessor.");
                    }
                }
                body = await owner.QualifyRouteHistoryDecisionBodyUnderLeaseAsync(current, opened, read, action,
                    own, peer, source, held, ct).ConfigureAwait(false);
                return new(read, body);
            }
            catch { read.Dispose(); throw; }
            finally { CryptographicOperations.ZeroMemory(body); }
        }

        internal byte[] CopyFor(Did2MessagingSessionScope scope, Did2MessagingFloor stable)
        {
            if (!FixedRoute(scope.Exact, Snapshot.Scope.Exact) || !FixedRoute(stable.Exact.Span, Snapshot.Before.Exact.Span) ||
                !FixedRoute(body.AsSpan(4, 32), scope.Hash) || body[2] != Snapshot.Subject)
                throw new CryptographicException("Route-history qualification belongs to another exact native predecessor.");
            return body.ToArray();
        }
        public void Dispose() { CryptographicOperations.ZeroMemory(body); read.Dispose(); }
    }

    private static Did2RouteHistorySelection SelectConflictBeforeProposalFacts(QualifiedRouteHistoryRead read)
    {
        var snapshot = read.Snapshot; var selection = snapshot.Selection;
        var facts = selection.Facts.ToList();
        var page = ApplicationCoreCodec.DecodeDmc2(read.Original(snapshot.SelectedOriginal.Reference).Span).ParsedPayload as ContactRouteHistoryDmc2Payload ??
            throw new CryptographicException("A conflict lost its selected original page.");
        var atom = page.Atoms[selection.SelectedAtomIndex - 1];
        var generation = selection.ConflictClass == 1 ? BinaryPrimitives.ReadUInt64BigEndian(ContactRouteClosureCodec.Decode(atom.ExactCompletedRoute.Span).Reachability.Field(3).Span) :
            BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", atom.ExactXra1.Span).Field(3).Span);
        if (HasVerifiedHistoryFact(read, selection.ConflictClass, generation))
        {
            var qualified = FirstVerifiedHistoryDecision(read, selection.ConflictClass, generation);
            if (!qualified.Body.PreviousDecision.IsAbsent)
            {
                var prior = snapshot.FindDecision(qualified.Body.PreviousDecision).Body.P;
                if (prior.AtomIndex > 0)
                {
                    var priorPage = ApplicationCoreCodec.DecodeDmc2(read.Original(prior.Reference).Span).ParsedPayload as ContactRouteHistoryDmc2Payload ??
                        throw new CryptographicException("A conflict lost the exact before-P original.");
                    var priorAtom = priorPage.Atoms[prior.AtomIndex - 1];
                    Add(HistorySelector(snapshot.Subject, 2, BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", priorAtom.ExactXra1.Span).Field(3).Span)));
                    if (priorAtom.IsCompleted) Add(HistorySelector(snapshot.Subject, 1,
                        BinaryPrimitives.ReadUInt64BigEndian(ContactRouteClosureCodec.Decode(priorAtom.ExactCompletedRoute.Span).Reachability.Field(3).Span)));
                }
            }
        }
        return Did2RouteHistorySelection.Conflict(selection.Operation.Span, selection.SelectedAtomIndex, selection.ConflictClass, facts);
        void Add(Did2RouteHistoryFactSelector selector)
        { if (!facts.Any(value => value.Family == selector.Family && FixedRoute(value.Selector.Span, selector.Selector.Span))) facts.Add(selector); }
    }
}
