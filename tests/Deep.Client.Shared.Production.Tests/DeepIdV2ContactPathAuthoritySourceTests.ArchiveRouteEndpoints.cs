using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2IndexedArchive_ManyColdHistoricalRouteHeadsAfterRecordedRecoveryResolveOnlyQualifiedEndpoints()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RecoverNativeSenderPublicationAsync();
        byte[] latestClosure = [];
        var announcementCount = 0;
        ulong latestReceiveOrdinal = 0;
        for (var index = 0; index <= 24; index++)
        {
            if (index > 0)
            {
                // Preserve every owned publication. Stop before changing time
                // when the next genuine pending reservation cannot be admitted.
                using var publications = await fixture.RouteState();
                Assert.All(publications.Entries.Values, entry => Assert.Equal((byte)7, entry.Phase));
                var reserved = checked(ProtectedDid2ContactRouteJournal.HeaderBytes +
                    publications.Entries.Values.Sum(entry => checked(4 + entry.ReservedBytes)));
                Assert.InRange(reserved, ProtectedDid2ContactRouteJournal.HeaderBytes, ProtectedDid2ContactRouteJournal.MaximumBytes);
                if (publications.Entries.Count == ProtectedDid2ContactRouteJournal.MaximumIntents ||
                    checked(reserved + 4 + ProtectedDid2ContactRouteJournal.MaximumEntryBytes) > ProtectedDid2ContactRouteJournal.MaximumBytes)
                    break;
                await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 120);
            }
            using var command = await fixture.CreateOwnedRouteUpdate(sender);
            var payload = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ParsedPayload);
            Assert.Equal(DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement, payload.Mode);
            Assert.Equal(index == 0 ? 2 : 1, payload.Atoms.Count);
            Assert.Equal(index != 0, payload.Atoms[0].IsCompleted);
            Assert.True(payload.Atoms[^1].IsCompleted);
            Assert.Equal(checked((ulong)index + 1), BinaryPrimitives.ReadUInt64BigEndian(payload.RightCursor.Span));
            latestClosure = payload.Atoms[^1].ExactCompletedRoute.ToArray();
            Assert.Equal(checked((ulong)index + 2), BinaryPrimitives.ReadUInt64BigEndian(ContactRouteClosureCodec.Decode(latestClosure).Authorization.Field(3).Span));
            using (var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId))
            using (var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()))
            {
                Assert.Equal(3, received.RouteProcessing[0]);
                latestReceiveOrdinal = received.Ordinal;
            }
            announcementCount++;
            // Actual peer feedback keeps native Braid/frontier progress genuine;
            // the fixture never invents a ratchet or lowers its capacity limits.
            using (var reply = await fixture.CreateOwnedText(receiver, "route endpoint feedback " + index))
            using (var sent = await fixture.SendOwnedMessage(receiver, reply.OperationId, ApplicationCoreCodec.DecodeDmc2(reply.ExactDmc2.Span)))
            using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
            if (index % 6 == 0 || index == 24)
            {
                await fixture.ArchiveEntireEligibleSuffix(sender); await fixture.ArchiveEntireEligibleSuffix(receiver);
                fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage(); fixture.ColdReopenReceiverStoreStorage();
            }
        }
        Assert.InRange(announcementCount, 3, 25);
        foreach (var scope in new[] { sender, receiver })
        {
            var floor = await fixture.ReadMessagingFloor(scope);
            var archive = await fixture.ReadNativeArchive(scope);
            if (floor.Ordinal > archive.Basis.Ordinal) await fixture.ArchiveEntireEligibleSuffix(scope);
        }
        var receiverArchive = await fixture.ReadNativeArchive(receiver);
        Assert.True(receiverArchive.Basis.Ordinal >= latestReceiveOrdinal, "The selected latest route source was not archived.");
        Assert.True(receiverArchive.ArchiveCount >= checked((ulong)announcementCount));
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage(); fixture.ColdReopenReceiverStoreStorage();
        var application = await fixture.ReadArchiveEndpointConversation(receiver);
        using var applicationAccount = application.Account;
        _ = await applicationAccount.QueueTextAsync(application.Handle,
            "explicit cold admission before endpoint measurement", application.Source);
        byte[] operation;
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        {
            operation = (await applicationAccount.QueueTextAsync(application.Handle,
                "bounded restored indexed endpoint", application.Source)).ToArray();
            Assert.Equal(0, work.Audits); Assert.Equal(0, work.CipherScans); Assert.Equal(0, work.MetadataRows);
            Assert.InRange(work.Payloads, 1, 16); // Fixed selected originals across actual retained predecessors.
            Assert.InRange(work.SuffixRows, 0, 64);
        }
        var issuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var terminal = new OwnedStoreFixture(fixture, receiver, operation, null, ownerOnPrimary: false);
        _ = await fixture.SendNativeText(receiver, operation, "bounded restored indexed endpoint", issuer, terminal);
        var actual = await fixture.ReadAttemptOriginalRoute(receiver, operation);
        Assert.True(latestClosure.AsSpan().SequenceEqual(actual), "Restored endpoint selected an ancestor or caller-supplied route.");
        Assert.Equal(1, issuer.Calls); Assert.Equal(1, terminal.Calls);
    }

    private sealed partial class Fixture
    {
        internal Task<(DeepIdV2AccountService Account, DeepIdV2ContactPathAuthoritySource Source, DeepIdV2Conversation Handle)>
            ReadArchiveEndpointConversation(Did2MessagingSessionScope scope) => ReadApplicationConversation(scope);

        internal async Task ArchiveEntireEligibleSuffix(Did2MessagingSessionScope scope)
        {
            using var owned = await NativeStorage(scope).ReadOwnedAsync(Did2MessagingArchiveRoot.Slot(scope)) ?? throw new InvalidDataException();
            var archive = owned.Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
            var floor = await ReadMessagingFloor(scope); var count = checked((int)(floor.Ordinal - archive.Basis.Ordinal));
            Assert.InRange(count, 1, 32);
            await CompactActiveNativePrefix(scope, count);
        }
    }
}
