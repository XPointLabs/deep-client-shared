using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private static ReadOnlyMemory<byte> RendezvousAnchor(QualifiedRouteHistoryRead read) =>
        ApplicationCoreCodec.DecodeDmc2(read.Original(read.Snapshot.Anchor).Span).ParsedPayload switch
        {
            ContactHelloDmc2Payload hello => hello.InboundXur1,
            ContactAcceptDmc2Payload accept => accept.InboundXur1,
            _ => throw new CryptographicException("Rendezvous continuation lost its native relationship anchor.")
        };

    private async Task<(ProtectedContactRendezvousContinuation State, byte[]? Exact)> ReadRendezvousContinuationUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, byte subject, ReadOnlyMemory<byte> original,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var raw = await storage.ReadOwnedAsync(ProtectedContactRendezvousContinuation.Slot(opened.Scope, subject), ct).ConfigureAwait(false);
        var exact = raw?.Use(bytes => bytes.ToArray());
        try { return (exact is null ? new() : ProtectedContactRendezvousContinuation.Decode(exact, opened.Scope, original.Span), exact); }
        catch { if (exact is not null) CryptographicOperations.ZeroMemory(exact); throw; }
    }

    private async Task CommitRendezvousContinuationUnderLeaseAsync(OwnedDid2MessagingStorage opened, byte subject,
        ReadOnlyMemory<byte> original, ProtectedContactRendezvousContinuation state, byte[]? previous,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var next = state.Encode(opened.Scope, original.Span);
        try
        {
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            if (previous is not null)
            {
                if (!previous.AsSpan().SequenceEqual(next) && !await storage.CompareExchangeAsync(
                    ProtectedContactRendezvousContinuation.Slot(opened.Scope, subject), previous, next, ct).ConfigureAwait(false))
                    throw new IOException("Rendezvous continuation changed during protected commit.");
                await RequireRendezvousContinuationReadbackAsync(opened, subject, next, ct).ConfigureAwait(false);
                return;
            }
            using var guard = await storage.ReadOwnedAsync(CurrentAccountSlot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Rendezvous continuation lost its current account guard.");
            var predecessor = guard.Use(bytes => bytes.ToArray());
            try
            {
                if (!await storage.CompareExchangeAndInsertAsync(CurrentAccountSlot, predecessor, predecessor,
                    [new(ProtectedContactRendezvousContinuation.Slot(opened.Scope, subject), next)], ct).ConfigureAwait(false))
                    throw new IOException("Rendezvous continuation enrollment changed its exact account guard.");
                await RequireRendezvousContinuationReadbackAsync(opened, subject, next, ct).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(predecessor); }
        }
        finally { CryptographicOperations.ZeroMemory(next); }
    }

    private async Task RequireRendezvousContinuationReadbackAsync(OwnedDid2MessagingStorage opened, byte subject,
        byte[] expected, CancellationToken ct)
    {
        using var raw = await storage.ReadOwnedAsync(ProtectedContactRendezvousContinuation.Slot(opened.Scope, subject), ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Committed rendezvous continuation disappeared.");
        if (!raw.Use(bytes => FixedRoute(bytes, expected)))
            throw new CryptographicException("Committed rendezvous continuation changed before release.");
    }

    private async Task<(ParsedDmc2 Message, Did2MessagingArchiveReference Reference)?> ReadLatestNativeRendezvousUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, byte subject, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var selector = new Did2RouteHistoryFactSelector(Did2MessagingArchiveFamily.RouteControl,
            Did2MessagingArchiveRouteFacts.LatestRendezvousSelector(subject));
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, subject,
            Did2RouteHistorySelection.Initial([selector]), held, ct).ConfigureAwait(false);
        var value = read.Snapshot.Facts.Single().Value;
        if (value is null) return null;
        var reference = Did2MessagingArchiveReference.Decode(value.Value.Span[..88], false);
        var message = ApplicationCoreCodec.DecodeDmc2(read.Original(reference).Span);
        if (reference.Direction != subject || message.ParsedPayload is not ContactRouteHistoryDmc2Payload { RendezvousSuccessors.Count: > 0 } page ||
            !FixedRoute(page.OriginalAnchorHash.Span, SHA256.HashData(read.Original(read.Snapshot.Anchor).Span)))
            throw new CryptographicException("Latest rendezvous observation changed its authenticated native anchor.");
        await opened.WithPairedSqlAsync(read.Authored.PairedRead,
            sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
        return (message, reference);
    }

    private async Task RequireOwnRendezvousNativeFloorUnderLeaseAsync(OwnedDid2MessagingStorage opened,
        ProtectedContactRendezvousContinuation state, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var latest = await ReadLatestNativeRendezvousUnderLeaseAsync(opened, 1, held, ct).ConfigureAwait(false);
        if (latest is null) return;
        var page = (ContactRouteHistoryDmc2Payload)latest.Value.Message.ParsedPayload;
        if (state.Successors.Count < page.RendezvousSuccessors.Count || !RendezvousPrefixesAgree(state.Successors, page.RendezvousSuccessors))
            throw new CryptographicException("Rendezvous continuation is missing or older than its native authored floor.");
    }

    private static ReadOnlyMemory<byte> RendezvousTip(ReadOnlyMemory<byte> original,
        IReadOnlyList<ReadOnlyMemory<byte>> successors) => successors.Count == 0 ? original : successors[^1];

    private async Task<bool> OwnRendezvousMaintenanceDueUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> announcement,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 1, Did2RouteHistorySelection.Initial(), held, ct).ConfigureAwait(false);
        RequireRouteHistoryConsent(read);
        var original = RendezvousAnchor(read);
        var (state, exact) = await ReadRendezvousContinuationUnderLeaseAsync(opened, 1, original, held, ct).ConfigureAwait(false);
        try
        {
            await RequireOwnRecordedRendezvousChainAsync(original, state.Successors, own, source, ct).ConfigureAwait(false);
            await RequireOwnRendezvousNativeFloorUnderLeaseAsync(opened, state, held, ct).ConfigureAwait(false);
            var publishedCount = announcement.IsEmpty ? 0 :
                (ApplicationCoreCodec.DecodeDmc2(announcement.Span).ParsedPayload as ContactRouteHistoryDmc2Payload)?.RendezvousSuccessors.Count ?? 0;
            if (state.Successors.Count > publishedCount) return true;
            var reading = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            return CanRenewRendezvous(current, RendezvousTip(original, state.Successors), own, reading);
        }
        finally { if (exact is not null) CryptographicOperations.ZeroMemory(exact); }
    }

    private static bool CanRenewRendezvous(VerifiedDeepIdV2CurrentAccount current, ReadOnlyMemory<byte> tip,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        Deep.Protocol.DeepExtension.PrivacyRouting.OnionMonotonicReading reading)
    {
        var record = ContactCodec.Decode("XUR1", tip.Span);
        var issued = BinaryPrimitives.ReadUInt64BigEndian(record.Field(11).Span);
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(record.Field(12).Span);
        var lower = checked(own.Proof.TrustedLowerUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample);
        var upper = checked(own.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample);
        var prospective = Math.Min(checked(lower + 86_400), Math.Min(own.Network.MaximumRecordExpiryUnixSeconds,
            current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate.ExpiresAtUnixSeconds));
        return upper >= ProactiveRefreshAt(issued, expiry) && prospective > expiry;
    }

    private static async Task RequireOwnRecordedRendezvousChainAsync(ReadOnlyMemory<byte> original,
        IReadOnlyList<ReadOnlyMemory<byte>> successors, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        if (successors.Count == 0) return;
        var tip = ContactCodec.Decode("XUR1", successors[^1].Span);
        await DeepIdV2ContactUpdateRendezvousVerifier.VerifyRecordedSuccessorChainAsync(original, original, successors,
            own.Proof, own.Network, own.Authority, BinaryPrimitives.ReadUInt64BigEndian(tip.Field(11).Span), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<ReadOnlyMemory<byte>>> EnsureOwnRendezvousContinuationUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, OwnedDid2MessagingStorage opened, QualifiedRouteHistoryRead read,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        RequireRouteHistoryConsent(read); var original = RendezvousAnchor(read);
        var (state, exact) = await ReadRendezvousContinuationUnderLeaseAsync(opened, 1, original, held, ct).ConfigureAwait(false);
        try
        {
            await RequireOwnRecordedRendezvousChainAsync(original, state.Successors, own, source, ct).ConfigureAwait(false);
            await RequireOwnRendezvousNativeFloorUnderLeaseAsync(opened, state, held, ct).ConfigureAwait(false);
            var tip = RendezvousTip(original, state.Successors);
            var reading = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            if (CanRenewRendezvous(current, tip, own, reading))
            {
                if (state.Successors.Count == ProtectedContactRendezvousContinuation.MaximumSuccessors)
                    throw new IOException("The signed rendezvous continuation reached its bounded horizon.");
                var issued = checked(own.Proof.TrustedLowerUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample);
                var expiry = Math.Min(checked(issued + 86_400), Math.Min(own.Network.MaximumRecordExpiryUnixSeconds,
                    current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate.ExpiresAtUnixSeconds));
                var next = await DeepIdV2ContactUpdateRendezvousAuthor.AuthorSuccessorAsync(tip, own.Proof, own.Network,
                    current.Verified.DeviceSecrets, issued, expiry, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                state.Successors.Add(next.ExactXur1.ToArray());
                await CommitRendezvousContinuationUnderLeaseAsync(opened, 1, original, state, exact, held, ct).ConfigureAwait(false);
            }
            return state.Successors;
        }
        finally { if (exact is not null) CryptographicOperations.ZeroMemory(exact); }
    }

    private static bool RendezvousPrefixesAgree(IReadOnlyList<ReadOnlyMemory<byte>> left,
        IReadOnlyList<ReadOnlyMemory<byte>> right)
    {
        for (var i = 0; i < Math.Min(left.Count, right.Count); i++)
            if (!FixedRoute(left[i].Span, right[i].Span)) return false;
        return true;
    }

    private async Task<ContactRouteHistoryDmc2Payload> RequireRecordedNativeRendezvousSourceUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> eventHash,
        ReadOnlyMemory<byte> original, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 2,
            Did2RouteHistorySelection.Custody(operation.Span), held, ct).ConfigureAwait(false);
        RequireRouteHistoryConsent(read);
        if (!FixedRoute(original.Span, RendezvousAnchor(read).Span))
            throw new CryptographicException("Rendezvous source changed its immutable native anchor.");
        var reference = read.Snapshot.SelectedOriginal.Reference;
        var exact = read.Original(reference);
        var message = ApplicationCoreCodec.DecodeDmc2(exact.Span);
        if (reference.Kind != 2 || reference.Direction != 2 ||
            !FixedRoute(SHA256.HashData(exact.Span), eventHash.Span) ||
            message.ParsedPayload is not ContactRouteHistoryDmc2Payload { RendezvousSuccessors.Count: > 0 } page ||
            !FixedRoute(message.SenderAccountId.Span, opened.Scope.RemoteAccount) ||
            !FixedRoute(message.SenderDeviceId.Span, opened.Scope.RemoteDevice) ||
            !FixedRoute(message.ConversationId.Span, opened.Scope.Conversation) ||
            !FixedRoute(page.RelationshipId.Span, opened.Scope.Relationship))
            throw new CryptographicException("Rendezvous head lost its exact authenticated native source.");
        if (!FixedRoute(page.OriginalAnchorHash.Span, SHA256.HashData(read.Original(read.Snapshot.Anchor).Span)))
            throw new CryptographicException("Rendezvous source names a different original native event.");
        await DeepIdV2ContactUpdateRendezvousVerifier.VerifyRecordedSuccessorChainAsync(original, original,
            page.RendezvousSuccessors, peer, own.Network, own.Authority, message.CreatedAtUnixMilliseconds / 1000,
            source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        await opened.WithPairedSqlAsync(read.Authored.PairedRead,
            sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
        return page;
    }

    private async Task RequirePeerRendezvousStateUnderLeaseAsync(OwnedDid2MessagingStorage opened,
        ProtectedContactRendezvousContinuation state, ReadOnlyMemory<byte> original,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        if (state.Successors.Count == 0)
        {
            if (state.SourceOperation.AsSpan().IndexOfAnyExcept((byte)0) >= 0 ||
                state.FaultOperation.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
                throw new CryptographicException("Rendezvous continuation has a source without an accepted chain.");
            return;
        }
        if (state.SourceOperation.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("Rendezvous accepted head has no authenticated native source.");
        var page = await RequireRecordedNativeRendezvousSourceUnderLeaseAsync(opened, state.SourceOperation,
            state.SourceEventHash, original, peer, own, source, held, ct).ConfigureAwait(false);
        if (page.RendezvousSuccessors.Count != state.Successors.Count ||
            !RendezvousPrefixesAgree(page.RendezvousSuccessors, state.Successors))
            throw new CryptographicException("Protected rendezvous head differs from its exact native source.");
        if (state.FaultOperation.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
        {
            var fault = await RequireRecordedNativeRendezvousSourceUnderLeaseAsync(opened, state.FaultOperation,
                state.FaultEventHash, original, peer, own, source, held, ct).ConfigureAwait(false);
            if (RendezvousPrefixesAgree(state.Successors, fault.RendezvousSuccessors))
                throw new CryptographicException("Rendezvous fork custody does not prove signed divergent continuations.");
        }
    }

    private async Task<bool> ReadNativeRendezvousForkUnderLeaseAsync(OwnedDid2MessagingStorage opened,
        ReadOnlyMemory<byte> original, int generations,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        for (var offset = 1; offset <= generations; offset += Did2RouteHistorySelection.MaximumFacts)
        {
            var selectors = Enumerable.Range(offset, Math.Min(Did2RouteHistorySelection.MaximumFacts, generations - offset + 1))
                .Select(generation => new Did2RouteHistoryFactSelector(Did2MessagingArchiveFamily.RouteControl,
                    Did2MessagingArchiveRouteFacts.RendezvousGenerationSelector(2, (ulong)generation))).ToArray();
            using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 2,
                Did2RouteHistorySelection.Initial(selectors), held, ct).ConfigureAwait(false);
            RequireRouteHistoryConsent(read);
            foreach (var fact in read.Snapshot.Facts)
            {
                if (fact.Value is not { } value)
                    throw new CryptographicException("Native rendezvous continuation lost a registered generation fact.");
                var second = Did2MessagingArchiveReference.Decode(value.Span.Slice(120, 88));
                if (second.IsAbsent) continue;
                var first = Did2MessagingArchiveReference.Decode(value.Span[..88], false);
                var firstMessage = ApplicationCoreCodec.DecodeDmc2(read.Original(first).Span);
                var secondMessage = ApplicationCoreCodec.DecodeDmc2(read.Original(second).Span);
                var left = await RequireRecordedNativeRendezvousSourceUnderLeaseAsync(opened, first.Operation.ToArray(),
                    SHA256.HashData(firstMessage.CanonicalBytes.Span), original, peer, own, source, held, ct).ConfigureAwait(false);
                var right = await RequireRecordedNativeRendezvousSourceUnderLeaseAsync(opened, second.Operation.ToArray(),
                    SHA256.HashData(secondMessage.CanonicalBytes.Span), original, peer, own, source, held, ct).ConfigureAwait(false);
                var generation = checked((int)BinaryPrimitives.ReadUInt64BigEndian(fact.Selector.Selector.Span[2..]));
                if (left.RendezvousSuccessors.Count < generation || right.RendezvousSuccessors.Count < generation ||
                    FixedRoute(left.RendezvousSuccessors[generation - 1].Span, right.RendezvousSuccessors[generation - 1].Span))
                    throw new CryptographicException("Native rendezvous fork fact lost its signed divergent source.");
                await opened.WithPairedSqlAsync(read.Authored.PairedRead,
                    sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
                return true;
            }
            await opened.WithPairedSqlAsync(read.Authored.PairedRead,
                sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
        }
        return false;
    }

    private async Task<bool> AdoptPeerRendezvousContinuationUnderLeaseAsync(OwnedDid2MessagingStorage opened,
        QualifiedRouteHistoryRead read, ParsedDmc2 message,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload { RendezvousSuccessors.Count: > 0 } page) return true;
        RequireRouteHistoryConsent(read); var original = RendezvousAnchor(read);
        if (!FixedRoute(page.OriginalAnchorHash.Span, SHA256.HashData(read.Original(read.Snapshot.Anchor).Span)) ||
            !FixedRoute(page.RelationshipId.Span, opened.Scope.Relationship) ||
            !FixedRoute(message.ConversationId.Span, opened.Scope.Conversation) ||
            !FixedRoute(message.SenderAccountId.Span, opened.Scope.RemoteAccount) ||
            !FixedRoute(message.SenderDeviceId.Span, opened.Scope.RemoteDevice)) return false;
        var (state, exact) = await ReadRendezvousContinuationUnderLeaseAsync(opened, 2, original, held, ct).ConfigureAwait(false);
        try
        {
            await RequirePeerRendezvousStateUnderLeaseAsync(opened, state, original, own, peer, source, held, ct).ConfigureAwait(false);
            var priorNative = await ReadLatestNativeRendezvousUnderLeaseAsync(opened, 2, held, ct).ConfigureAwait(false);
            if (await ReadNativeRendezvousForkUnderLeaseAsync(opened, original,
                Math.Max(state.Successors.Count, priorNative is null ? 0 :
                    ((ContactRouteHistoryDmc2Payload)priorNative.Value.Message.ParsedPayload).RendezvousSuccessors.Count),
                own, peer, source, held, ct).ConfigureAwait(false)) return false;
            if (state.FaultOperation.AsSpan().IndexOfAnyExcept((byte)0) >= 0) return false;
            // A thrown refusal alone is not fork evidence. Verify the entire
            // independently signed native input against the immutable anchor
            // before comparing it with a separately qualified accepted prefix.
            try
            {
                await DeepIdV2ContactUpdateRendezvousVerifier.VerifyRecordedSuccessorChainAsync(original, original,
                    page.RendezvousSuccessors, peer, own.Network, own.Authority, message.CreatedAtUnixMilliseconds / 1000,
                    source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            }
            catch (Exception error) when (error is CryptographicException or InvalidDataException or FormatException) { return false; }
            var reference = read.Snapshot.SelectedOriginal.Reference;
            if (reference.Kind != 2 || reference.Direction != 2)
                throw new CryptographicException("Rendezvous adoption requires the actual sealed native receive.");
            if (!RendezvousPrefixesAgree(state.Successors, page.RendezvousSuccessors))
            {
                reference.Operation.CopyTo(state.FaultOperation);
                SHA256.HashData(message.CanonicalBytes.Span, state.FaultEventHash);
                await CommitRendezvousContinuationUnderLeaseAsync(opened, 2, original, state, exact, held, ct).ConfigureAwait(false);
                return false;
            }
            if (page.RendezvousSuccessors.Count < state.Successors.Count) return true; // Exact historical prefixes never regress.
            try
            {
                _ = await DeepIdV2ContactUpdateRendezvousVerifier.VerifySuccessorChainAsync(original,
                    RendezvousTip(original, state.Successors), page.RendezvousSuccessors, peer, own.Network, own.Authority,
                    source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            }
            catch (Exception error) when (error is CryptographicException or InvalidDataException or FormatException) { return false; }
            state.Successors.Clear(); state.Successors.AddRange(page.RendezvousSuccessors.Select(value => (ReadOnlyMemory<byte>)value.ToArray()));
            reference.Operation.CopyTo(state.SourceOperation);
            SHA256.HashData(message.CanonicalBytes.Span, state.SourceEventHash);
            await CommitRendezvousContinuationUnderLeaseAsync(opened, 2, original, state, exact, held, ct).ConfigureAwait(false);
            return true;
        }
        finally { if (exact is not null) CryptographicOperations.ZeroMemory(exact); }
    }

    private async Task<(ReadOnlyMemory<byte> Tip, bool Faulted)> ReadPeerRendezvousTipUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> original,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var (state, exact) = await ReadRendezvousContinuationUnderLeaseAsync(opened, 2, original, held, ct).ConfigureAwait(false);
        try
        {
            await RequirePeerRendezvousStateUnderLeaseAsync(opened, state, original, own, peer, source, held, ct).ConfigureAwait(false);
            var latest = await ReadLatestNativeRendezvousUnderLeaseAsync(opened, 2, held, ct).ConfigureAwait(false);
            var latestPage = latest is null ? null : (ContactRouteHistoryDmc2Payload)latest.Value.Message.ParsedPayload;
            if (latestPage is null && state.Successors.Count > 0)
                throw new CryptographicException("Adopted rendezvous head lost its registered native observation.");
            if (latestPage is not null && state.Successors.Count < latestPage.RendezvousSuccessors.Count)
                throw new CryptographicException("Rendezvous head is missing or older than its authenticated native receive floor.");
            var nativeFork = await ReadNativeRendezvousForkUnderLeaseAsync(opened, original,
                Math.Max(state.Successors.Count, latestPage?.RendezvousSuccessors.Count ?? 0), own, peer, source, held, ct).ConfigureAwait(false);
            if (!nativeFork && latestPage is not null && !RendezvousPrefixesAgree(state.Successors, latestPage.RendezvousSuccessors))
            {
                // A native receive can survive a crash before auxiliary adoption.
                // Only replaying that exact ordinary receive can finish it; an
                // absent/rolled-back cache never resurrects genesis or a fork.
                throw new CryptographicException("Rendezvous head diverges from its authenticated native receive floor.");
            }
            return (RendezvousTip(original, state.Successors), nativeFork || state.FaultOperation.AsSpan().IndexOfAnyExcept((byte)0) >= 0);
        }
        finally { if (exact is not null) CryptographicOperations.ZeroMemory(exact); }
    }
}
