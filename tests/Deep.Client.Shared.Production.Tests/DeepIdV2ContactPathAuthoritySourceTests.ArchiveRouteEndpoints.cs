using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

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
        for (var index = 0; index <= 24; index++)
        {
            if (index > 0) await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 120);
            using var command = await fixture.CreateOwnedRouteUpdate(sender);
            var payload = Assert.IsType<ContactRouteUpdateDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ParsedPayload);
            Assert.Equal(index == 0, payload.RecoveryWitness is not null);
            Assert.Equal(checked((ulong)index + 1), payload.RouteGeneration);
            Assert.Equal(checked((ulong)index + 2), BinaryPrimitives.ReadUInt64BigEndian(payload.Authorization.Field(3).Span));
            latestClosure = payload.ExactRouteClosure.ToArray();
            using (var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId))
            using (var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()))
                Assert.Equal(1, received.RouteProcessing[0]);
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
        fixture.RetainNativeRuntimes();
        using (var warm = await fixture.CreateOwnedText(receiver, "explicit cold admission before endpoint measurement")) { }
        byte[] operation;
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        {
            operation = await fixture.QueueNativeText(receiver, "bounded restored indexed endpoint");
            Assert.Equal(0, work.Audits); Assert.Equal(0, work.CipherScans); Assert.Equal(0, work.MetadataRows);
            Assert.InRange(work.Payloads, 1, 16); // Fixed selected originals; not25 recursive predecessors.
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
