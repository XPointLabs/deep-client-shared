using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ReintroductionCapacity_ResolvedDestinationReusesFullFloorsWithoutAdmittingOrdinaryExpiryOrForeignAuthority()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        await fixture.CheckResolvedReintroductionCapacityAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckResolvedReintroductionCapacityAsync()
        {
            var (publisher, sender) = await PrepareRouteFaultPair(this);
            using (var announcement = await CreateOwnedRouteUpdate(publisher))
            {
                var expires = ApplicationCoreCodec.DecodeDmc2(announcement.ExactDmc2.Span).ExpiresAtUnixMilliseconds;
                using (var native = await SendOwnedRouteUpdate(publisher, announcement.OperationId))
                using (await ReceiveOwnedMessage(sender, native.ExactEnvelope.ToArray())) { }
                AdvanceControlClock(expires, past: true);
            }
            await RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1_000);
            var account = ReopenGrantReader(); var source = GrantReaderSource(account);
            var plan = await accounts.ReadOwnPermanentContactPlanAsync(); byte[] publication;
            using (var routes = await RouteState())
            {
                var entry = routes.Entries[Convert.ToHexString(plan.Intent.Span)];
                var request = ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span);
                publication = ContactPublicationAuthorityWireCodec.DecodeResponse(request, entry.Record(10).Span).ExactXpu1.ToArray();
            }
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var candidate = await account.ResolvePermanentContactAsync(address, source, new SyntheticPermanentRead(this, source, publication));
            var resolved = await source.VerifyPermanentContactAsync(candidate.Candidate, default);
            var pair = await source.VerifyForOwnMessagingAsync(account, sender, default, resolved.Own);
            var owner = GroupOwner(sender);
            await Assert.ThrowsAsync<CryptographicException>(() => account.RequireCurrentContactRouteAsync(new(sender), source));

            // Canonical ordinary input is not an owned route-control capability.
            var ordinary = ApplicationCoreCodec.AuthorDmc2(sender.Network, Bytes(32, 0x61), sender.Conversation,
                sender.LocalAccount, sender.LocalDevice, 3, checked(CurrentProofTime * 1000), 0,
                Dmc2Flags.None, [], ApplicationCoreCodec.CreateMessageCreatePayload("ordinary cannot use publication carriage"));
            var before = await Effects();
            await Assert.ThrowsAsync<CryptographicException>(() => owner.SendRouteControlMessagingAsync(1_000, pq,
                sender, Bytes(32, 0x62), ordinary.CanonicalBytes, pair.Own, pair.Peer, source, default, resolved));
            Assert.Equal(before, await Effects());

            var foreignOwn = await Source(accounts).VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var foreign = new DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority(foreignOwn, resolved.Contact);
            before = await Effects();
            await Assert.ThrowsAsync<CryptographicException>(() => owner.PrepareElectiveRouteAnnouncementAsync(1_000, pq,
                sender, pair.Own, pair.Peer, source, default, foreign));
            Assert.Equal(before, await Effects());

            // Full occupancy is disposable rejection metadata, not512 deliveries.
            // First prove a genuinely new current destination still cannot fit.
            var emptySendRoot = await FillFloors(null);
            before = await Effects();
            var ordinaryExpiry = await Assert.ThrowsAsync<CryptographicException>(() => account.QueueTextAsync(new(sender),
                "ordinary must retain its current peer route", source));
            Assert.Equal("DID2 route time coverage failed (XRA1; Expiry).", ordinaryExpiry.Message);
            await Assert.ThrowsAsync<IOException>(() => owner.PrepareElectiveRouteAnnouncementAsync(1_000, pq,
                sender, pair.Own, pair.Peer, source, default, resolved));
            Assert.Equal(before, await Effects());
            await RestoreSendRoot(emptySendRoot);

            // One real verified issuer result and its exact replay floor can be
            // reused at the same unchanged bound; no new namespace is invented.
            var issuer = new OwnedGrantTransport(this, ownerOnPrimary: false);
            var winner = await account.AcquirePermanentContactDepositGrantAsync(candidate, source, issuer);
            Assert.Equal(1, issuer.Calls);
            var previous = await FillFloors(winner); CryptographicOperations.ZeroMemory(previous);
            using var command = await owner.PrepareElectiveRouteAnnouncementAsync(1_000, pq, sender,
                pair.Own, pair.Peer, source, default, resolved);
            Assert.NotNull(command);
            var priorNative = await ReadMessagingFloor(sender);
            before = await Effects();
            await Assert.ThrowsAsync<CryptographicException>(() => owner.SendRouteControlMessagingAsync(1_000, pq,
                sender, command.OperationId, command.ExactDmc2, pair.Own, pair.Peer, source, default, foreign));
            Assert.Equal(before, await Effects());
            byte[] envelope;
            using (var native = await owner.SendRouteControlMessagingAsync(1_000, pq, sender, command.OperationId,
                command.ExactDmc2, pair.Own, pair.Peer, source, default, resolved)) envelope = native.ExactEnvelope.ToArray();
            var committed = await ReadMessagingFloor(sender);
            Assert.True(committed.Ordinal > priorNative.Ordinal); // Route-history decisions also advance the native journal.
            Assert.Equal(priorNative.RatchetGeneration + 1, committed.RatchetGeneration);
            using (var replay = await owner.SendRouteControlMessagingAsync(1_000, pq, sender, command.OperationId,
                command.ExactDmc2, pair.Own, pair.Peer, source, default, resolved)) Assert.Equal(envelope, replay.ExactEnvelope.ToArray());
            Assert.Equal(committed.Exact.ToArray(), (await ReadMessagingFloor(sender)).Exact.ToArray());
            Assert.Equal(1, issuer.Calls);
            await Assert.ThrowsAsync<CryptographicException>(() => account.RequireCurrentContactRouteAsync(new(sender), source));

            // Last: advancing the protected monotonic clock cannot be undone.
            // The same supplied authority must refuse both preparation/replay.
            before = await Effects(); Sample = checked(resolved.Own.Proof.FreshnessDeadlineMonotonicSeconds + 1);
            await Assert.ThrowsAsync<CryptographicException>(() => owner.PrepareDirectRouteUpdateAsync(1_000, pq,
                sender, command.OperationId, pair.Own, pair.Peer, source, default, resolved));
            await Assert.ThrowsAsync<CryptographicException>(() => owner.SendRouteControlMessagingAsync(1_000, pq,
                sender, command.OperationId, command.ExactDmc2, pair.Own, pair.Peer, source, default, resolved));
            Assert.Equal(before, await Effects()); Assert.Equal(1, issuer.Calls);
            foreach (var bytes in new[] { publication, emptySendRoot, envelope }) CryptographicOperations.ZeroMemory(bytes);

            async Task<byte[]> Effects()
            {
                var values = new List<byte[]> { (await ReadMessagingFloor(sender)).Exact.ToArray() };
                foreach (var slot in new[] { ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxSendJournal.Slot, ProtectedDid2MailboxGrantJournal.Slot })
                {
                    using var root = await NativeStorage(sender).ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                    values.Add(root.Use(bytes => SHA256.HashData(bytes)));
                }
                return values.SelectMany(bytes => bytes).ToArray();
            }
            async Task<byte[]> FillFloors(Deep.Protocol.ContactV2.VerifiedDeepIdV2MailboxGrant? grant)
            {
                using var root = await NativeStorage(sender).ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                var exact = root.Use(bytes => bytes.ToArray());
                using var state = ProtectedDid2MailboxSendJournal.Decode(exact, sender.Network, sender.LocalAccount, sender.Instance);
                Assert.Empty(state.Entries); Assert.Empty(state.Floors);
                if (grant is not null)
                {
                    var parsed = MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant.ExactGrant.Span);
                    state.EnrollScope(SHA256.HashData(grant.ExactGrant.Span),
                        MailboxCapabilityReplayStateMachine.ComputeScopeKey(parsed, MailboxAuthenticatedOperation.Store)); state.Revision++;
                }
                for (var index = state.Floors.Count; index < ProtectedDid2MailboxSendJournal.MaximumFloors; index++)
                { var hash = SHA256.HashData(BitConverter.GetBytes(index)); state.EnrollScope(hash, hash); state.Revision++; }
                var next = ProtectedDid2MailboxSendJournal.Encode(state, sender.Network, sender.LocalAccount, sender.Instance);
                try { Assert.True(await NativeStorage(sender).CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, exact, next)); }
                finally { CryptographicOperations.ZeroMemory(next); }
                return exact;
            }
            async Task RestoreSendRoot(byte[] exact)
            {
                using var root = await NativeStorage(sender).ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                var changed = root.Use(bytes => bytes.ToArray());
                try { Assert.True(await NativeStorage(sender).CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, changed, exact)); }
                finally { CryptographicOperations.ZeroMemory(changed); }
            }
        }
    }
}
