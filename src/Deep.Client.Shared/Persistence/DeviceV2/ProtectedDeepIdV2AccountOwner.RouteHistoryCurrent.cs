using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private sealed record PagedRouteHistoryEndpoint(ParsedDeepIdV2ContactMailboxRoute Original,
        VerifiedDeepIdV2ContactRouteHistory Facts, ReadOnlyMemory<byte> Announcement,
        ReadOnlyMemory<byte> EventHash, ReadOnlyMemory<byte> NativeFloor, PagedPeerConsentFacts? PeerConsent = null);

    // Bootstrap can retain an already qualified legacy L. Its existing
    // predecessor verifier remains responsible for that payload, while this
    // join requires the result to be the exact L named by the actual decision.
    private async Task RequireLegacyHistoryLiveHeadUnderLeaseAsync(OwnedDid2MessagingStorage opened, byte subject,
        ReadOnlyMemory<byte> eventHash, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject, Did2RouteHistorySelection.Current(), held, ct).ConfigureAwait(false);
        if (read.Snapshot.PreviousDecision is null) return;
        if (read.Snapshot.L.IsAbsent || !FixedRoute(SHA256.HashData(read.Original(read.Snapshot.L).Span), eventHash.Span) ||
            ApplicationCoreCodec.DecodeDmc2(read.Original(read.Snapshot.L).Span).ParsedPayload is ContactRouteHistoryDmc2Payload)
            throw new CryptographicException("Retained legacy route result differs from the exact current L named by its native decision.");
        await opened.WithPairedSqlAsync(read.Authored.PairedRead,
            sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
    }

    // A fixed endpoint closure: latest subject decision, original L, original
    // consent/fault and first-qualified C/P sources plus P's exact request
    // anchor. It never expands raw candidates or walks prior announcements.
    private async Task<PagedRouteHistoryEndpoint?> ReadPagedLiveRouteHistoryUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, byte subject,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ReadOnlyMemory<byte> announcement; byte[] expectedFloor;
        ContactRouteHistoryDmc2Payload control;
        using (var first = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject,
            Did2RouteHistorySelection.Current(), held, ct).ConfigureAwait(false))
        {
            if (first.Snapshot.L.IsAbsent) return null;
            announcement = first.Original(first.Snapshot.L).ToArray();
            if (ApplicationCoreCodec.DecodeDmc2(announcement.Span).ParsedPayload is not ContactRouteHistoryDmc2Payload parsed) return null;
            if (!first.Snapshot.FirstFault.IsAbsent)
                throw new CryptographicException("A retained route fault fences current route qualification.");
            control = parsed; expectedFloor = first.Snapshot.Before.Exact.ToArray();
        }
        var selection = Did2RouteHistorySelection.Current([
            HistorySelector(subject, 1, BinaryPrimitives.ReadUInt64BigEndian(control.RightCursor.Span)),
            HistorySelector(subject, 2, BinaryPrimitives.ReadUInt64BigEndian(control.RightCursor.Span[40..]))]);
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject, selection, held, ct).ConfigureAwait(false);
        RequireRouteHistoryConsent(read);
        if (!read.Snapshot.FirstFault.IsAbsent || !FixedRoute(read.Snapshot.Before.Exact.Span, expectedFloor) ||
            !FixedRoute(read.Original(read.Snapshot.L).Span, announcement.Span))
            throw new CryptographicException("Current route changed its exact independently adopted native endpoint.");
        var c = FirstVerifiedHistoryDecision(read, 1, BinaryPrimitives.ReadUInt64BigEndian(control.RightCursor.Span));
        var p = FirstVerifiedHistoryDecision(read, 2, BinaryPrimitives.ReadUInt64BigEndian(control.RightCursor.Span[40..]));
        var facts = await RestoreRouteHistoryUnderLeaseAsync(read, c.Body.C, p.Body.P, own, peer, source, held, ct).ConfigureAwait(false);
        if (!FixedRoute(facts.Cursor.Span, control.RightCursor.Span) || !FixedRoute(facts.OriginalAnchorHash.Span, control.OriginalAnchorHash.Span))
            throw new CryptographicException("Current announcement changed its qualified historical endpoint.");
        var original = ApplicationCoreCodec.DecodeDmc2(read.Original(read.Snapshot.Anchor).Span).ParsedPayload switch
        {
            ContactHelloDmc2Payload hello => hello.MailboxRoute,
            ContactAcceptDmc2Payload accept => accept.MailboxRoute,
            _ => throw new CryptographicException("Current route lost its immutable relationship anchor.")
        };
        var peerConsent = subject == 2 ? await QualifyPagedPeerConsentUnderLeaseAsync(read, own, peer, source, held, ct).ConfigureAwait(false) : null;
        await opened.WithPairedSqlAsync(peerConsent is null ? read.Authored.PairedRead : PagedPeerConsentPairedRead(read, peerConsent),
            sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        return new(original, facts, announcement, SHA256.HashData(announcement.Span), read.Snapshot.Before.Exact.ToArray(), peerConsent);
    }
}
