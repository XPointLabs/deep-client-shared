using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RendezvousContinuation_MissedSignedGenerationCatchesUpFromNativeGenesisWithoutAReset()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.SeedShortNativeRendezvousAsync(true, Bytes(32, 0x9a));
        var (sender, receiver) = await fixture.PrepareRouteHistoryPair();
        await fixture.SeedUnpublishedSignedRendezvousSuccessorAsync(sender);
        byte[] delayedPrefix;
        using (var delayed = await fixture.CreateOwnedRouteUpdate(sender))
        {
            Assert.Single(Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(delayed.ExactDmc2.Span).ParsedPayload).RendezvousSuccessors);
            using var native = await fixture.SendOwnedRouteUpdate(sender, delayed.OperationId);
            delayedPrefix = native.ExactEnvelope.ToArray();
        }
        fixture.ColdReopenCompactionStorage();
        fixture.AdvanceControlClockTo(1_198);
        Assert.Equal(0UL, (await fixture.ReadRendezvousHealthAsync(receiver)).UpdateGeneration);
        using var update = await fixture.CreateOwnedRouteUpdate(sender);
        var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(update.ExactDmc2.Span).ParsedPayload);
        Assert.Equal(2, page.RendezvousSuccessors.Count);
        using (var native = await fixture.SendOwnedRouteUpdate(sender, update.OperationId))
        using (var received = await fixture.ReceiveOwnedMessage(receiver, native.ExactEnvelope.ToArray())) Assert.Equal(3, received.RouteProcessing[0]);
        using (var delayed = await fixture.ReceiveOwnedMessage(receiver, delayedPrefix)) Assert.Equal(3, delayed.RouteProcessing[0]);
        Assert.Equal(2UL, (await fixture.ReadRendezvousHealthAsync(receiver)).UpdateGeneration);
        // A fresh native announcement can repeat the same signed head with a
        // different operation. Neither it nor a delayed older prefix regresses
        // the accepted generation or manufactures a fork.
        using (var repeat = await fixture.CreateOwnedRouteUpdate(sender))
        using (var native = await fixture.SendOwnedRouteUpdate(sender, repeat.OperationId))
        using (var received = await fixture.ReceiveOwnedMessage(receiver, native.ExactEnvelope.ToArray())) Assert.Equal(3, received.RouteProcessing[0]);
        await fixture.ArchiveEntireEligibleSuffix(receiver);
        fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        var health = await fixture.ReadRendezvousHealthAsync(receiver);
        Assert.Equal(2UL, health.UpdateGeneration); Assert.True(health.UpdateIntervalCoversNow);
        Assert.False(health.RouteFaultRetained);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RendezvousContinuation_IndependentlySignedNativeForkFencesDeliveryAfterEncryptedReopen()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.SeedShortNativeRendezvousAsync(true, Bytes(32, 0x9a));
        var (sender, receiver) = await fixture.PrepareRouteHistoryPair();
        using var withheld = await fixture.CreateOwnedText(sender, "disposable withheld branch text");
        using var branch = fixture.CaptureDisposableRouteSenderBranch();
        await fixture.SeedUnpublishedSignedRendezvousSuccessorAsync(sender);
        byte[] firstSuccessor;
        using (var first = await fixture.CreateOwnedRouteUpdate(sender))
        {
            firstSuccessor = Assert.Single(Assert.IsType<ContactRouteHistoryDmc2Payload>(
                ApplicationCoreCodec.DecodeDmc2(first.ExactDmc2.Span).ParsedPayload).RendezvousSuccessors).ToArray();
            using var native = await fixture.SendOwnedRouteUpdate(sender, first.OperationId);
            using var received = await fixture.ReceiveOwnedMessage(receiver, native.ExactEnvelope.ToArray());
        }
        using var honestBranch = fixture.CaptureDisposableRouteSenderBranch();
        fixture.RestoreDisposableRouteSenderBranch(branch);
        fixture.AdvanceControlClockTo(1_110);
        await fixture.SeedUnpublishedSignedRendezvousSuccessorAsync(sender);
        using (var native = await fixture.SendOwnedMessage(sender, withheld.OperationId,
            ApplicationCoreCodec.DecodeDmc2(withheld.ExactDmc2.Span))) { }
        // A different authored position isolates an XUR generation fork from
        // the independent existing native authored-position fault owner.
        using (var extra = await fixture.CreateOwnedText(sender, "disposable later branch position"))
        using (var native = await fixture.SendOwnedMessage(sender, extra.OperationId,
            ApplicationCoreCodec.DecodeDmc2(extra.ExactDmc2.Span))) { }
        byte[] forkEnvelope;
        using (var fork = await fixture.CreateOwnedRouteUpdate(sender))
        {
            var competing = Assert.Single(Assert.IsType<ContactRouteHistoryDmc2Payload>(
                ApplicationCoreCodec.DecodeDmc2(fork.ExactDmc2.Span).ParsedPayload).RendezvousSuccessors);
            Assert.False(competing.Span.SequenceEqual(firstSuccessor));
            using var native = await fixture.SendOwnedRouteUpdate(sender, fork.OperationId); forkEnvelope = native.ExactEnvelope.ToArray();
        }
        using (var received = await fixture.ReceiveOwnedMessage(receiver, forkEnvelope)) Assert.Equal(3, received.RouteProcessing[0]);
        var faulted = await fixture.ReadRendezvousHealthAsync(receiver);
        Assert.Equal(1UL, faulted.UpdateGeneration); Assert.True(faulted.RouteFaultRetained);
        // A newer, otherwise valid signed generation cannot erase evidence of
        // an older generation's native fork.
        fixture.RestoreDisposableRouteSenderBranch(honestBranch);
        fixture.AdvanceControlClockTo(1_198);
        foreach (var text in new[] { "honest branch withheld position one", "honest branch withheld position two" })
        {
            using var pending = await fixture.CreateOwnedText(sender, text);
            using var native = await fixture.SendOwnedMessage(sender, pending.OperationId, ApplicationCoreCodec.DecodeDmc2(pending.ExactDmc2.Span));
        }
        using (var newer = await fixture.CreateOwnedRouteUpdate(sender))
        {
            Assert.Equal(2, Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(newer.ExactDmc2.Span).ParsedPayload).RendezvousSuccessors.Count);
            using var native = await fixture.SendOwnedRouteUpdate(sender, newer.OperationId);
            using var received = await fixture.ReceiveOwnedMessage(receiver, native.ExactEnvelope.ToArray()); Assert.Equal(3, received.RouteProcessing[0]);
        }
        await fixture.ArchiveEntireEligibleSuffix(receiver);
        fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.RequireCurrentNativeRoute(receiver));
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, forkEnvelope)) Assert.Equal(3, replay.RouteProcessing[0]);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReadRendezvousHealthAsync(receiver));
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RendezvousContinuation_RealSignedBothDirectionsRenewBeforeExpiryAndKeepNativeHeadsAfterColdReopen()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        // Genuine short-lived signed genesis is selected before any native
        // Hello/Accept exists. No accepted source, clock or proof is rewritten.
        await fixture.SeedShortNativeRendezvousAsync(true, Bytes(32, 0x9a));
        await fixture.SeedShortNativeRendezvousAsync(false, Bytes(32, 0x9b));
        var (sender, receiver) = await fixture.PrepareRouteHistoryPair();
        fixture.AdvanceControlClockTo(1_180);
        foreach (var pair in new[] { (Sender: sender, Receiver: receiver), (Sender: receiver, Receiver: sender) })
        {
            Assert.Empty((await fixture.SelectHistoryRouteMaintenance(pair.Sender))!);
            using var update = await fixture.CreateOwnedRouteUpdate(pair.Sender);
            var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(update.ExactDmc2.Span).ParsedPayload);
            var successor = Assert.Single(page.RendezvousSuccessors);
            Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XUR1", successor.Span).Field(4).Span));
            Assert.Equal(update.OperationId.ToArray(), await fixture.SelectHistoryRouteMaintenance(pair.Sender));
            byte[] envelope;
            using (var native = await fixture.SendOwnedRouteUpdate(pair.Sender, update.OperationId)) envelope = native.ExactEnvelope.ToArray();
            using (var received = await fixture.ReceiveOwnedMessage(pair.Receiver, envelope)) Assert.Equal(3, received.RouteProcessing[0]);
            var store = new OwnedStoreFixture(fixture, pair.Sender, update.OperationId.ToArray(), envelope);
            _ = await fixture.DeliverNativeMessage(pair.Sender, update.OperationId.ToArray(),
                new OwnedGrantTransport(fixture, ownerOnPrimary: true), store);
        }
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage(); fixture.ColdReopenReceiverStoreStorage();
        foreach (var scope in new[] { sender, receiver })
        {
            var health = await fixture.ReadRendezvousHealthAsync(scope);
            Assert.True(health.UpdateIntervalCoversNow); Assert.Equal(1UL, health.UpdateGeneration);
            Assert.False(health.RouteFaultRetained);
            await fixture.RequireCurrentNativeRoute(scope);
        }
        await fixture.AssertRendezvousHeadDeletionAndRollbackRejectAsync(receiver);
    }

    private sealed partial class Fixture
    {
        internal async Task AssertRendezvousHeadDeletionAndRollbackRejectAsync(Did2MessagingSessionScope scope)
        {
            var secure = NativeStorage(scope); var slot = ProtectedContactRendezvousContinuation.Slot(scope, 2);
            using var raw = await secure.ReadOwnedAsync(slot);
            var winner = raw!.Use(bytes => bytes.ToArray());
            await secure.DeleteBatchAsync([slot]);
            await Assert.ThrowsAsync<CryptographicException>(() => ReadRendezvousHealthAsync(scope));
            var rollback = winner.AsSpan(0, 196).ToArray(); rollback[2] = 0; rollback[3] = 0; rollback.AsSpan(68).Clear();
            await secure.WriteBatchAsync([new(slot, rollback)]);
            await Assert.ThrowsAsync<CryptographicException>(() => ReadRendezvousHealthAsync(scope));
            Assert.True(await secure.CompareExchangeAsync(slot, rollback, winner));
            Assert.Equal(1UL, (await ReadRendezvousHealthAsync(scope)).UpdateGeneration);
        }

        internal async Task SeedUnpublishedSignedRendezvousSuccessorAsync(Did2MessagingSessionScope scope)
        {
            ReadOnlyMemory<byte> original = default;
            var floor = await ReadMessagingFloor(scope);
            await WithRouteReadSql(scope, (sql, _) =>
            {
                var initial = sql.ReadVerifiedActiveInitialEvents(floor);
                try { original = Assert.IsType<ContactHelloDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(initial.Hello).ParsedPayload).InboundXur1.ToArray(); }
                finally { CryptographicOperations.ZeroMemory(initial.SessionInit); CryptographicOperations.ZeroMemory(initial.Hello); }
            });
            var source = Source(); var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            using var current = (await SenderCompactionOwner().ReadCurrentAsync(1_000, pq, default))!;
            var signed = await DeepIdV2ContactUpdateRendezvousAuthor.AuthorSuccessorAsync(original, fresh.Proof,
                fresh.Network, current.Verified.DeviceSecrets, fresh.Proof.TrustedLowerUnixSeconds, 1_220, source.RendezvousTrustedTime);
            var state = new ProtectedContactRendezvousContinuation(); state.Successors.Add(signed.ExactXur1.ToArray());
            await storage.WriteBatchAsync([new(ProtectedContactRendezvousContinuation.Slot(scope, 1), state.Encode(scope, original.Span))]);
        }

        internal async Task SeedShortNativeRendezvousAsync(bool sender, byte[] intent)
        {
            var account = sender ? accounts : peerAccounts!; var secure = sender ? (IDeepSecureStorage)storage : peerStorage;
            var source = Source(account);
            var existing = await account.EnsureOwnContactRendezvousAsync(intent, source);
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(account, default);
            var folder = sender ? directory : Path.Combine(directory, "peer");
            var owner = new ProtectedDeepIdV2AccountOwner(secure,
                new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock")),
                Path.Combine(folder, "deep-store-v2-account.dsv2"), Network, 1);
            using var current = (await owner.ReadCurrentAsync(1_000, pq, default))!;
            var authored = await DeepIdV2ContactUpdateRendezvousAuthor.AuthorGenesisAsync(fresh.Proof, fresh.Network,
                current.Verified.DeviceSecrets, existing.Record.Field(8), existing.Record.Field(9),
                fresh.Proof.TrustedLowerUnixSeconds, 1_200, source.RendezvousTrustedTime);
            var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(secure, Network, current.AccountId, default);
            using var raw = await secure.ReadOwnedAsync(ProtectedContactRendezvousJournal.Slot);
            var previous = raw!.Use(bytes => bytes.ToArray()); byte[] next = [];
            try
            {
                using var journal = ProtectedContactRendezvousJournal.Decode(previous, Network, current.AccountId.Span, instance);
                authored.ExactXur1.Span.CopyTo(journal.Entries[Convert.ToHexString(intent)].AsSpan(64));
                next = ProtectedContactRendezvousJournal.Encode(journal, Network, current.AccountId.Span, instance);
                Assert.True(await secure.CompareExchangeAsync(ProtectedContactRendezvousJournal.Slot, previous, next));
            }
            finally { CryptographicOperations.ZeroMemory(instance); CryptographicOperations.ZeroMemory(previous); CryptographicOperations.ZeroMemory(next); }
        }

        internal Task<DeepIdV2ContactRouteHealth> ReadRendezvousHealthAsync(Did2MessagingSessionScope scope)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            return account.ReadContactRouteHealthAsync(new(scope), scope.IsInitiator ? Source(account) : GrantReaderSource(account));
        }
    }
}
