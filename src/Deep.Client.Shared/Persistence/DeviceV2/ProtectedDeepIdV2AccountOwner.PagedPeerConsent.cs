using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Immutable comparison facts for this held read only, never permission.
    // Each later consent query reacquires the actual snapshot and projection.
    private sealed class PagedPeerConsentFacts
    {
        internal readonly byte[] Scope, Floor, Archive, Consent, InitialHash, HelloHash, AcceptHash, AcceptRoot;
        internal readonly ulong ConsentOrdinal;
        internal readonly ReadOnlyMemory<byte> InboundXur1;
        internal PagedPeerConsentFacts(QualifiedRouteHistoryRead read, ContactHelloDmc2Payload hello, ContactAcceptDmc2Payload accepted)
        {
            var snapshot = read.Snapshot; var scope = snapshot.Scope;
            Scope = scope.Exact.ToArray(); Floor = snapshot.Before.Exact.ToArray(); Archive = snapshot.ArchiveRoot.Exact.ToArray();
            Consent = snapshot.Consent.Exact.ToArray(); ConsentOrdinal = snapshot.Consent.Ordinal;
            InitialHash = SHA256.HashData(snapshot.InitialSessionInit.Span); HelloHash = SHA256.HashData(snapshot.InitialHello.Span);
            AcceptHash = SHA256.HashData(read.Original(snapshot.Consent).Span);
            AcceptRoot = (read.Authored.Roots[ProtectedDid2ContactAcceptJournal.Slot] ??
                throw new InvalidDataException("Paged peer consent lost its protected acceptance root.")).ToArray();
            InboundXur1 = (scope.IsInitiator ? accepted.InboundXur1 : hello.InboundXur1).ToArray();
        }
        internal void RequireSame(QualifiedRouteHistoryRead read)
        {
            var snapshot = read.Snapshot;
            if (!FixedRoute(Scope, snapshot.Scope.Exact) || !FixedRoute(Floor, snapshot.Before.Exact.Span) ||
                !FixedRoute(Archive, snapshot.ArchiveRoot.Exact.Span) || !FixedRoute(Consent, snapshot.Consent.Exact.Span) ||
                !FixedRoute(InitialHash, SHA256.HashData(snapshot.InitialSessionInit.Span)) ||
                !FixedRoute(HelloHash, SHA256.HashData(snapshot.InitialHello.Span)) ||
                !FixedRoute(AcceptHash, SHA256.HashData(read.Original(snapshot.Consent).Span)) ||
                read.Authored.Roots[ProtectedDid2ContactAcceptJournal.Slot] is not { } actual || !FixedRoute(AcceptRoot, actual))
                throw new CryptographicException("Actual paged peer consent changed during its held verification.");
        }
    }

    private async Task<PagedPeerConsentFacts> QualifyPagedPeerConsentUnderLeaseAsync(QualifiedRouteHistoryRead read,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease); var snapshot = read.Snapshot; var scope = snapshot.Scope;
#if DEEP_TEST_INTERNALS
        Did2MessagingSqlJournal.NativeWork.PagedPeerConsentRead();
#endif
        var first = await source.RecheckEndpointPairUnderLeaseAsync(own, peer, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        AuthenticatedInitialDmc2Batch.RequireOwnedDid2SemanticScope(snapshot.InitialSessionInit.Span, snapshot.InitialHello.Span, scope);
        var hello = ApplicationCoreCodec.DecodeDmc2(snapshot.InitialHello.Span);
        var accepted = AuthenticatedContactAcceptDmc2.RequireOwnedDid2SemanticScope(read.Original(snapshot.Consent).Span, scope);
        var greeting = (ContactHelloDmc2Payload)hello.ParsedPayload;
        var acceptance = (ContactAcceptDmc2Payload)accepted.ParsedPayload;
        RequireRouteHistoryConsent(read);
        if (snapshot.Consent.Kind != 2 || snapshot.Consent.Direction != (scope.IsInitiator ? 2 : 1))
            throw new CryptographicException("Paged peer route lost its actual native consent role.");
        if (!scope.IsInitiator)
        {
            using var commands = ProtectedDid2ContactAcceptJournal.Decode(read.Authored.AcceptExact, scope.Network, scope.LocalAccount, scope.Instance);
            var winner = commands.FindScope(scope) ?? throw new CryptographicException("Paged peer route lost its local explicit acceptance winner.");
            if (!FixedRoute(winner.Operation, snapshot.Consent.Operation) || !FixedRoute(winner.HelloHash, SHA256.HashData(snapshot.InitialHello.Span)))
                throw new CryptographicException("Paged peer route changed its exact local acceptance winner.");
            winner.RequireExactAccept(read.Original(snapshot.Consent).Span);
        }
        await ApplicationCoreVerifier.RequireRetainedContactHelloEndpointBindingsAsync(hello,
            scope.IsInitiator ? own.Proof : peer, scope.IsInitiator ? peer : own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        await AuthenticatedInitialDmc2Batch.RequireRetainedMailboxRouteFactsAsync(greeting.MailboxRoute,
            scope.IsInitiator ? own.Proof : peer, own, source, held, ct).ConfigureAwait(false);
        await ApplicationCoreVerifier.RequireRetainedContactAcceptEndpointBindingsAsync(accepted, hello,
            scope.IsInitiator ? own.Proof : peer, scope.IsInitiator ? peer : own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        await AuthenticatedInitialDmc2Batch.RequireRetainedMailboxRouteFactsAsync(acceptance.MailboxRoute,
            scope.IsInitiator ? peer : own.Proof, own, source, held, ct).ConfigureAwait(false);
        var final = await source.RecheckEndpointPairUnderLeaseAsync(own, peer, held, ct).ConfigureAwait(false);
        if (!FixedRoute(first.BootId.Span, final.BootId.Span) || final.SampleSeconds < first.SampleSeconds)
            throw new CryptographicException("Paged peer consent crossed a clock discontinuity.");
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, final);
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        return new(read, greeting, acceptance);
    }

    private static Did2MessagingArchiveAuthoredRead PagedPeerConsentPairedRead(QualifiedRouteHistoryRead read, PagedPeerConsentFacts facts)
        => new(read.Authored.Roots, connection =>
        {
            read.Authored.PairedRead.Verify(connection);
            SqliteDeepMailboxStore.RequirePagedPeerAcceptanceProjection(connection, read.Snapshot.Scope, facts.AcceptHash);
        }, hasSources: true);

    private async Task<bool> RecheckPagedPeerConsentUnderLeaseAsync(OwnedDid2MessagingStorage opened, PagedPeerConsentFacts facts,
        ulong updateOrdinal, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        if (updateOrdinal <= facts.ConsentOrdinal) return false;
#if DEEP_TEST_INTERNALS
        Did2MessagingSqlJournal.NativeWork.PagedPeerConsentRead();
#endif
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 2, Did2RouteHistorySelection.Current(), held, ct).ConfigureAwait(false);
        facts.RequireSame(read);
        var reading = await source.RecheckEndpointPairUnderLeaseAsync(own, peer, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(opened.Scope, own.Proof, peer, reading);
        await opened.WithPairedSqlAsync(PagedPeerConsentPairedRead(read, facts),
            sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested(); return true;
    }
}
