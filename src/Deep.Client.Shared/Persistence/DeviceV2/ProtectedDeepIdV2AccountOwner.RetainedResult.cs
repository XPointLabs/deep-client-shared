using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Late packets reconcile an original closed acquisition only. The current
    // host verifies the real Retrieve issuer; old route admission is not revived.
    private async Task<VerifiedMailboxRetainedReadGrantV2> AcceptRetainedMailboxReadResultUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnRetainedPublication publication,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        ReadOnlyMemory<byte> exactXmc2, CancellationToken ct)
    {
        held.RequireActive(); ct.ThrowIfCancellationRequested();
        if (exactXmc2.Length is not (0 or 510)) throw new InvalidDataException("Late retained result exceeds its exact bound.");
        var scope = Convert.ToHexString(ProtectedDid2MailboxGrantJournal.Scope(publication.Route.ExactHash.Span,
            publication.Locator.Span, (byte)MailboxCapabilityDomain.Retrieve));
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? snapshot = null;
        try
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Original retained acquisition custody is absent.");
            snapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxGrantJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var response = ContactCodec.Decode("XMC2", exactXmc2.IsEmpty ?
                ProtectedDid2MailboxGrantJournal.Response(ProtectedDid2MailboxGrantJournal.RequireLateResultForResume(state, scope)).Span : exactXmc2.Span);
            var acquisition = Convert.ToHexString(response.Field(5).Span);
            if (!state.Entries.TryGetValue(acquisition, out var entry) ||
                !FixedRoute(entry.AsSpan(0, 32), Convert.FromHexString(scope)) ||
                !FixedRoute(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span, publication.Route.ExactBytes.Span))
                throw new CryptographicException("Late retained result has no exact owned acquisition in this route and role.");
            var request = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span);
            if (!FixedRoute(request.Field(4).Span, publication.Capability.Span))
                throw new CryptographicException("Late retained result differs from the actual private capability.");
            if (!ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(entry) && !ProtectedDid2MailboxGrantJournal.HasWinner(entry))
                throw new InvalidDataException("Pending acquisition must close under authenticated time before late settlement.");
            if (ProtectedDid2MailboxGrantJournal.HasWinner(entry) &&
                !FixedRoute(ProtectedDid2MailboxGrantJournal.Response(entry).Span, response.CanonicalBytes.Span))
                throw new CryptographicException("A retained winner is immutable.");
            var verified = await publication.Host.VerifyRetainedReadSuccessAsync(publication.Route.ExactBytes,
                ProtectedDid2MailboxGrantJournal.Request(entry), response.CanonicalBytes, ct).ConfigureAwait(false);
            await publication.RecheckAsync(ct).ConfigureAwait(false);
            if (ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(entry))
            {
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeLateResult);
#endif
                var next = ProtectedDid2MailboxGrantJournal.WithLateWinner(entry, verified.ExactXmc2.Span, networkId);
                state.Entries[acquisition] = next; CryptographicOperations.ZeroMemory(entry); entry = next;
                state.Revision = checked(state.Revision + 1);
                var adopted = await SaveMailboxGrantJournalAsync(state, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.AfterLateResult);
#endif
            }
            using var receivedRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Late retained result disappeared before adoption.");
            if (!receivedRoot.Use(bytes => FixedRoute(bytes, snapshot)))
                throw new CryptographicException("Late retained custody changed before adoption.");
            using var received = ProtectedDid2MailboxGrantJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var winner = received.Entries[acquisition];
            verified = await publication.Host.VerifyRetainedReadSuccessAsync(publication.Route.ExactBytes,
                ProtectedDid2MailboxGrantJournal.Request(winner), ProtectedDid2MailboxGrantJournal.Response(winner), ct).ConfigureAwait(false);
            await publication.RecheckAsync(ct).ConfigureAwait(false);
            if (ProtectedDid2MailboxGrantJournal.IsLateCandidate(winner))
            {
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeLateAdoption);
#endif
                ProtectedDid2MailboxGrantJournal.AdoptLateWinner(received, acquisition);
                received.Revision = checked(received.Revision + 1);
                var adopted = await SaveMailboxGrantJournalAsync(received, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.AfterLateAdoption);
#endif
            }
            if (!ProtectedDid2MailboxGrantJournal.IsLateAdopted(winner) && received.Selections[scope].Pending == acquisition)
                throw new InvalidDataException("Ordinary pending winner requires its original selection continuation.");
            await publication.RecheckAsync(ct).ConfigureAwait(false); await verified.EnsureCurrentAsync(ct).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, snapshot, ct).ConfigureAwait(false);
            using var installed = await OpenRetainedMailboxWinnerUnderLeaseAsync(current, held, publication,
                verified, winner, source, fresh, ct).ConfigureAwait(false);
            await publication.RecheckAsync(ct).ConfigureAwait(false); await verified.EnsureCurrentAsync(ct).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, snapshot, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return verified;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot);
        }
    }
}
