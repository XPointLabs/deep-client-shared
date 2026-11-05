using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PagedPeerConsent_BothRolesUseActualSnapshotWithoutInitialInboxHandoffsAndColdRead(bool initiator)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var pair = await fixture.PreparePagedConsentPair(initiator); var scope = pair.Observer;
        var floor = (await fixture.ReadMessagingFloor(scope)).Exact.ToArray();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(scope);
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        {
            await fixture.RequireCurrentNativeRoute(scope);
            Assert.True(work.PagedPeerConsentReads > 0); Assert.Equal(0, work.InitialHandoffs);
        }
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage(); fixture.ColdReopenReceiverStoreStorage();
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        {
            await fixture.RequireCurrentNativeRoute(scope);
            Assert.True(work.PagedPeerConsentReads > 0); Assert.Equal(0, work.InitialHandoffs);
        }
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(scope)).Exact.ToArray());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(scope));
    }

    [Theory]
    [InlineData("projection")] [InlineData("fork")] [InlineData("winner")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PagedPeerConsent_FinalSubjectTwoReadRejectsActualProjectionOrWinnerChangeAfterCapture(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var pair = await fixture.PreparePagedConsentPair(initiator: defect != "winner"); var scope = pair.Observer;
        await fixture.RequireCurrentNativeRoute(scope);
        var floor = (await fixture.ReadMessagingFloor(scope)).Exact.ToArray();
        var authored = await fixture.ReadAuthoredRootDigestAsync(scope.IsInitiator);
        byte[]? damagedApplication = null, damagedWinner = null;
        using var work = Did2MessagingSqlJournal.NativeWork.Measure();
        var hit = fixture.InjectPagedConsentClock(work, occurrence: 2, () =>
        {
            if (defect == "winner")
            {
                fixture.RemovePagedConsentWinner(scope).GetAwaiter().GetResult();
                using var raw = fixture.NativeStorage(scope).ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot).GetAwaiter().GetResult();
                damagedWinner = raw!.Use(bytes => bytes.ToArray());
            }
            else
            {
                damagedApplication = fixture.DamagePagedAcceptanceProjection(scope, defect == "fork").GetAwaiter().GetResult();
            }
        });
        try
        {
            var failure = await Record.ExceptionAsync(() => fixture.RequireCurrentNativeRoute(scope));
            Assert.True(hit()); Assert.IsAssignableFrom<CryptographicException>(failure);
            Assert.Equal(2, work.PagedPeerConsentReads); Assert.Equal(0, work.InitialHandoffs);
        }
        finally { fixture.ClearPagedConsentClock(); }
        // This mutation occurs in the final subject2 read after the current
        // verifier's callbacks, not merely before acquisition. No repair/effect.
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(scope)).Exact.ToArray());
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync(scope.IsInitiator));
        if (damagedApplication is not null) Assert.Equal(damagedApplication, await fixture.ReadCompleteOrdinaryApplicationProjection(scope));
        if (damagedWinner is not null)
        {
            using var raw = await fixture.NativeStorage(scope).ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot);
            Assert.Equal(damagedWinner, raw!.Use(bytes => bytes.ToArray()));
        }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PagedPeerConsent_DeferredConsentQueryRechecksActualFloorAndHeldFreshnessBeforeGrant(bool expireProof)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var pair = await fixture.PreparePagedConsentPair(initiator: true); var sender = pair.Observer;
        var predecessor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        using var command = await fixture.CreateOwnedRouteUpdate(sender); var operation = command.OperationId.ToArray(); byte[] envelope;
        using (var native = await fixture.SendOwnedRouteUpdate(sender, operation)) envelope = native.ExactEnvelope.ToArray();
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        Assert.NotEqual(predecessor, floor);
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        var authority = await fixture.Source().VerifyForOwnMessagingAsync(fixture.Accounts, sender, default);
        var deadline = Math.Max(authority.Own.Proof.FreshnessDeadlineMonotonicSeconds, authority.Peer.FreshnessDeadlineMonotonicSeconds);
        var issuer = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, operation, envelope);
        using var work = Did2MessagingSqlJournal.NativeWork.Measure();
        var hit = fixture.InjectPagedConsentClock(work, occurrence: 2, () =>
        {
            if (!expireProof)
                Assert.True(fixture.NativeStorage(sender).CompareExchangeAsync(sender.FloorSlot, floor, predecessor, default).GetAwaiter().GetResult());
        }, expireProof ? deadline : null);
        try
        {
            var failure = await Record.ExceptionAsync(() => fixture.DeliverAutomaticReintroducedRoute(fixture.ReopenAccount(), sender, operation, issuer, terminal));
            Assert.True(hit()); Assert.IsAssignableFrom<CryptographicException>(failure);
            Assert.Equal(2, work.PagedPeerConsentReads); Assert.Equal(0, work.InitialHandoffs);
        }
        finally { fixture.ClearPagedConsentClock(); }
        Assert.Equal(0, issuer.Calls); Assert.Equal(0, terminal.Calls);
        using var actualFloor = await fixture.NativeStorage(sender).ReadOwnedAsync(sender.FloorSlot);
        Assert.Equal(expireProof ? floor : predecessor, actualFloor!.Use(bytes => bytes.ToArray()));
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PagedPeerConsent_MalformedActualCount8CannotFallBackToInitialHandoffOrRepair()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var pair = await fixture.PreparePagedConsentPair(initiator: true); var scope = pair.Observer;
        var floor = (await fixture.ReadMessagingFloor(scope)).Exact.ToArray();
        await fixture.WithRouteReadSql(scope, (_, connection) =>
        {
            using var change = connection.CreateCommand();
            change.CommandText = "UPDATE events SET plaintext=zeroblob(length(plaintext)) WHERE operation=$operation AND direction=2;";
            change.Parameters.AddWithValue("$operation", pair.PeerOperation); Assert.Equal(1, change.ExecuteNonQuery());
        });
        using var work = Did2MessagingSqlJournal.NativeWork.Measure();
        var failure = await Record.ExceptionAsync(() => fixture.RequireCurrentNativeRoute(scope));
        Assert.True(failure is CryptographicException or InvalidDataException or FormatException);
        Assert.Equal(0, work.InitialHandoffs);
        using var actualFloor = await fixture.NativeStorage(scope).ReadOwnedAsync(scope.FloorSlot);
        Assert.Equal(floor, actualFloor!.Use(bytes => bytes.ToArray()));
        await fixture.WithRouteReadSql(scope, (_, connection) =>
        {
            using var read = connection.CreateCommand(); read.CommandText = "SELECT plaintext FROM events WHERE operation=$operation;";
            read.Parameters.AddWithValue("$operation", pair.PeerOperation);
            Assert.All((byte[])read.ExecuteScalar()!, value => Assert.Equal((byte)0, value));
        });
    }

    private sealed partial class Fixture
    {
        internal async Task<(Did2MessagingSessionScope Observer, byte[] PeerOperation)> PreparePagedConsentPair(bool initiator)
        {
            var (sender, receiver) = await PrepareRouteHistoryPair();
            var author = initiator ? receiver : sender; var observer = initiator ? sender : receiver;
            using var command = await CreateOwnedRouteUpdate(author); var operation = command.OperationId.ToArray();
            using var native = await SendOwnedRouteUpdate(author, operation);
            using (await ReceiveOwnedMessage(observer, native.ExactEnvelope.ToArray())) { }
            return (observer, operation);
        }

        internal Func<bool> InjectPagedConsentClock(Did2MessagingSqlJournal.NativeWork.Counts work, int occurrence,
            Action change, ulong? expiredSample = null)
        {
            var hit = false;
            thresholdClockOverride = token =>
            {
                token.ThrowIfCancellationRequested();
                if (!hit && work.PagedPeerConsentReads >= occurrence) { hit = true; change(); }
                return ValueTask.FromResult(new OnionMonotonicReading(Boot, hit && expiredSample is { } sample ? sample : checked(Sample + MailboxElapsedSeconds)));
            };
            return () => hit;
        }
        internal void ClearPagedConsentClock() => thresholdClockOverride = null;

        internal async Task<byte[]> DamagePagedAcceptanceProjection(Did2MessagingSessionScope scope, bool fork)
        {
            byte[] damaged = [];
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var change = connection.CreateCommand();
                change.CommandText = fork
                    ? "INSERT INTO authenticated_dmc2_inbox_forks(conversation_id,logical_message_id,author_device_id,incumbent_hash,conflicting_hash) SELECT conversation_id,logical_message_id,author_device_id,exact_dmc2_hash,zeroblob(32) FROM authenticated_dmc2_inbox WHERE conversation_id=$conversation AND content_kind=$kind;"
                    : "UPDATE authenticated_dmc2_inbox SET exact_dmc2=zeroblob(length(exact_dmc2)) WHERE conversation_id=$conversation AND content_kind=$kind;";
                change.Parameters.AddWithValue("$conversation", scope.Conversation.ToArray()); change.Parameters.AddWithValue("$kind", (int)Dmc2ContentKind.ContactAccept);
                Assert.Equal(1, change.ExecuteNonQuery());
                // The product owner already holds the account lease. Capture
                // the same complete digest on this mutation connection.
                damaged = SqliteDeepMailboxStore.ReadCompleteLocalSqlProjection(connection, scope.Hash, default);
            }, acquireOwnerLease: false);
            return damaged;
        }

        internal async Task RemovePagedConsentWinner(Did2MessagingSessionScope scope)
        {
            using var root = await NativeStorage(scope).ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot);
            var before = root!.Use(bytes => bytes.ToArray()); byte[] after = [];
            try
            {
                using var state = ProtectedDid2ContactAcceptJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                var winner = state.FindScope(scope); Assert.NotNull(winner);
                var name = Assert.Single(state.Entries, pair => ReferenceEquals(pair.Value, winner)).Key;
                Assert.True(state.Entries.Remove(name)); winner!.Dispose();
                state.Revision = state.Entries.Count == 0 ? 1 : checked(state.Revision + 1);
                after = ProtectedDid2ContactAcceptJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
                using (var changed = ProtectedDid2ContactAcceptJournal.Decode(after, scope.Network, scope.LocalAccount, scope.Instance))
                    Assert.Null(changed.FindScope(scope));
                Assert.True(await NativeStorage(scope).CompareExchangeAsync(ProtectedDid2ContactAcceptJournal.Slot, before, after, default));
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }
    }
}
