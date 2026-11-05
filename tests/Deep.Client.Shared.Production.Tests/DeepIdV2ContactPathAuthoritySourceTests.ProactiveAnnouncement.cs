using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteMaintenance_CurrentDueAnnouncementAdvancesOnlyUntilActualSignedCeilingAndKeepsPendingOriginal()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await fixture.PrepareRouteHistoryPair();
        using var first = await fixture.CreateOwnedRouteUpdate(sender);
        var firstMessage = ApplicationCoreCodec.DecodeDmc2(first.ExactDmc2.Span);
        byte[] firstEnvelope;
        using (var native = await fixture.SendOwnedRouteUpdate(sender, first.OperationId.ToArray()))
            firstEnvelope = native.ExactEnvelope.ToArray();
        var firstStore = new OwnedStoreFixture(fixture, sender, first.OperationId.ToArray(), firstEnvelope);
        _ = await fixture.DeliverNativeMessage(sender, first.OperationId.ToArray(),
            new OwnedGrantTransport(fixture, ownerOnPrimary: true), firstStore);
        Assert.Null(await fixture.SelectRouteMaintenance(sender));

        var firstDue = ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(
            firstMessage.CreatedAtUnixMilliseconds / 1000, firstMessage.ExpiresAtUnixMilliseconds / 1000);
        fixture.AdvanceControlClockTo(firstDue);
        var firstDueProof = (await fixture.Source().VerifyForOwnMessagingAsync(fixture.Accounts, sender, default)).Own.Proof;
        Assert.True(checked(firstDueProof.TrustedUpperUnixSeconds * 1000) < firstMessage.ExpiresAtUnixMilliseconds);
        var nativeBefore = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var authoredBefore = await fixture.ReadAuthoredRootDigestAsync();
        Assert.Empty((await fixture.SelectRouteMaintenance(sender))!);
        Assert.Equal(nativeBefore, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(authoredBefore, await fixture.ReadAuthoredRootDigestAsync());

        using var second = Assert.IsType<DirectTextOutboxEntry>(await fixture.CreateElectiveAnnouncement(sender));
        var secondMessage = ApplicationCoreCodec.DecodeDmc2(second.ExactDmc2.Span);
        var oldPage = Assert.IsType<ContactRouteHistoryDmc2Payload>(firstMessage.ParsedPayload);
        var newPage = Assert.IsType<ContactRouteHistoryDmc2Payload>(secondMessage.ParsedPayload);
        Assert.Equal(DeepIdV2ContactRouteHistoryMode.Announcement, newPage.Mode);
        Assert.Empty(newPage.Atoms);
        Assert.Equal(oldPage.RightCursor.ToArray(), newPage.RightCursor.ToArray());
        Assert.True(secondMessage.ExpiresAtUnixMilliseconds > firstMessage.ExpiresAtUnixMilliseconds);
        Assert.Equal(first.SenderSequence + 1, second.SenderSequence);
        Assert.Equal(second.OperationId.ToArray(), await fixture.SelectRouteMaintenance(sender));
        var pendingRoot = await fixture.ReadAuthoredRootDigestAsync();
        Assert.Null(await fixture.CreateElectiveAnnouncement(sender));
        Assert.Equal(pendingRoot, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(nativeBefore, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());

        byte[] secondEnvelope;
        using (var native = await fixture.SendOwnedRouteUpdate(sender, second.OperationId.ToArray()))
            secondEnvelope = native.ExactEnvelope.ToArray();
        var secondStore = new OwnedStoreFixture(fixture, sender, second.OperationId.ToArray(), secondEnvelope);
        _ = await fixture.DeliverNativeMessage(sender, second.OperationId.ToArray(),
            new OwnedGrantTransport(fixture, ownerOnPrimary: true), secondStore);
        // A stale positive scheduling hint cannot overtake this genuinely
        // completed newer L during selection's separate authoring lease.
        authoredBefore = await fixture.ReadAuthoredRootDigestAsync();
        Assert.Null(await fixture.CreateElectiveAnnouncement(sender));
        Assert.Equal(authoredBefore, await fixture.ReadAuthoredRootDigestAsync());
        var account = fixture.ReopenAccount();
        var proof = (await fixture.Source(account).VerifyForOwnMessagingAsync(account, sender, default)).Own;
        // The genuine fixture's signed ADH is now the limiting ceiling; no
        // further nonce renewal can extend this immutable signed head.
        Assert.Equal(checked(proof.Proof.NextProtectedLkg.Head.ValidUntil * 1000), secondMessage.ExpiresAtUnixMilliseconds);
        var secondDue = ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(
            secondMessage.CreatedAtUnixMilliseconds / 1000, secondMessage.ExpiresAtUnixMilliseconds / 1000);
        fixture.AdvanceControlClockTo(secondDue);
        var secondDueProof = (await fixture.Source(account).VerifyForOwnMessagingAsync(account, sender, default)).Own.Proof;
        Assert.True(checked(secondDueProof.TrustedUpperUnixSeconds * 1000) < secondMessage.ExpiresAtUnixMilliseconds);
        nativeBefore = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        authoredBefore = await fixture.ReadAuthoredRootDigestAsync();
        Assert.Null(await fixture.SelectRouteMaintenance(sender));
        Assert.Null(await fixture.SelectRouteMaintenance(sender));
        Assert.Null(await fixture.CreateElectiveAnnouncement(sender));
        Assert.Equal(nativeBefore, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(authoredBefore, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(1, firstStore.Calls); Assert.Equal(1, secondStore.Calls);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteMaintenance_ProactivePlanningRejectsAuthoredRootChangeAtActualClockCallback()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await fixture.PrepareRouteHistoryPair();
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
        byte[] envelope;
        using (var native = await fixture.SendOwnedRouteUpdate(sender, command.OperationId.ToArray()))
            envelope = native.ExactEnvelope.ToArray();
        var store = new OwnedStoreFixture(fixture, sender, command.OperationId.ToArray(), envelope);
        _ = await fixture.DeliverNativeMessage(sender, command.OperationId.ToArray(),
            new OwnedGrantTransport(fixture, ownerOnPrimary: true), store);
        fixture.AdvanceControlClockTo(ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(
            message.CreatedAtUnixMilliseconds / 1000, message.ExpiresAtUnixMilliseconds / 1000));
        var before = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var hit = fixture.MutateAuthoredRootDuringProactiveClock(sender);
        try
        {
            var failure = await Assert.ThrowsAsync<CryptographicException>(() => fixture.SelectRouteMaintenance(sender));
            Assert.True(hit());
            Assert.Equal("Announcement maintenance changed its authored root.", failure.Message);
        }
        finally { fixture.ClearProactiveClock(); }
        Assert.Equal(before, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(fixture.ProactiveChangedRootHash, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(1, store.Calls);
    }

    private sealed partial class Fixture
    {
        internal byte[] ProactiveChangedRootHash = [];

        internal Func<bool> MutateAuthoredRootDuringProactiveClock(Did2MessagingSessionScope scope)
        {
            var hit = false;
            thresholdClockOverride = _ =>
            {
                if (!hit && new StackTrace().GetFrames().Any(frame => frame.GetMethod()?.DeclaringType?.Name
                    .Contains("<ReadVerifiedContactRouteHistoryAnnouncementExpiryAsync>", StringComparison.Ordinal) == true))
                {
                    hit = true;
                    ChangeProactiveAuthoredRevision(scope).GetAwaiter().GetResult();
                }
                return ValueTask.FromResult(new Deep.Protocol.DeepExtension.PrivacyRouting.OnionMonotonicReading(Boot,
                    checked(Sample + MailboxElapsedSeconds)));
            };
            return () => hit;
        }

        private async Task ChangeProactiveAuthoredRevision(Did2MessagingSessionScope scope)
        {
            using var raw = await innerStorage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            var before = raw.Use(bytes => bytes.ToArray()); byte[] after = [];
            try
            {
                using (var state = ProtectedDid2DirectTextJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance))
                {
                    state.Revision = checked(state.Revision + 1);
                    after = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
                    using var roundTrip = ProtectedDid2DirectTextJournal.Decode(after, scope.Network, scope.LocalAccount, scope.Instance);
                    Assert.Equal(state.Revision, roundTrip.Revision);
                }
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, before, after, default));
                ProactiveChangedRootHash = SHA256.HashData(after);
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }

        internal void ClearProactiveClock() => thresholdClockOverride = null;

        internal Task<DirectTextOutboxEntry?> CreateElectiveAnnouncement(Did2MessagingSessionScope scope)
        {
            var account = ReopenAccount();
            return account.CreateOwnElectiveRouteAnnouncementAsync(scope, Source(account), default);
        }
    }
}
