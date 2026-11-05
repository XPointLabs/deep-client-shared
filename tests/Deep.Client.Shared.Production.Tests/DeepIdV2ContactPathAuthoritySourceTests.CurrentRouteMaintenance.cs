using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CurrentRoute_ReadOnlyAdmissionAndFreshRequestRejectExpiredActualAnnouncementBeforeAuthoring()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await fixture.PrepareRouteHistoryPair();
        using var announcement = await fixture.CreateOwnedRouteUpdate(sender);
        var message = ApplicationCoreCodec.DecodeDmc2(announcement.ExactDmc2.Span);
        var authorProof = (await fixture.Source().VerifyForOwnMessagingAsync(fixture.Accounts, sender, default)).Own;
        var originalDtt = AccountDirectoryDtt1Codec.Decode(authorProof.Proof.ExactDtt1.Span);
        // DTT's signed nonce-response issuance window is distinct from the
        // verified capability's ADH/revocation-freshness deadline.
        var nonceExpiry = originalDtt.ExpiresAt;
        Assert.True(message.ExpiresAtUnixMilliseconds > checked(nonceExpiry * 1000));
        Assert.True(message.ExpiresAtUnixMilliseconds > checked((authorProof.Proof.TrustedLowerUnixSeconds + 120) * 1000));
        Assert.True(message.ExpiresAtUnixMilliseconds <= checked((authorProof.Proof.TrustedLowerUnixSeconds + 3_600) * 1000));
        Assert.True(message.ExpiresAtUnixMilliseconds <= checked(authorProof.Proof.NextProtectedLkg.Head.ValidUntil * 1000));
        Assert.True(message.ExpiresAtUnixMilliseconds <= checked(authorProof.Network.MaximumRecordExpiryUnixSeconds * 1000));
        Assert.True(message.ExpiresAtUnixMilliseconds <= checked(await fixture.ActualInitialRouteExpiry(sender) * 1000));
        using (var native = await fixture.SendOwnedRouteUpdate(sender, announcement.OperationId.ToArray()))
        using (await fixture.ReceiveOwnedMessage(receiver, native.ExactEnvelope.ToArray())) { }
        await fixture.RequireCurrentNativeRoute(receiver);
        fixture.AdvanceControlClockTo(checked(nonceExpiry + 1));
        Assert.True(fixture.Sample < authorProof.Proof.FreshnessDeadlineMonotonicSeconds);
        var receiverAccount = fixture.ReopenGrantReader();
        var renewed = (await fixture.GrantReaderSource(receiverAccount).VerifyForOwnMessagingAsync(receiverAccount, receiver, default)).Peer;
        var renewedDtt = AccountDirectoryDtt1Codec.Decode(renewed.ExactDtt1.Span);
        Assert.NotEqual(originalDtt.ClientNonce.ToArray(), renewedDtt.ClientNonce.ToArray());
        Assert.True(renewedDtt.ExpiresAt > originalDtt.ExpiresAt);
        await fixture.RequireCurrentNativeRoute(receiver); // Fresh nonce proof, same immutable announcement.
        var senderAccount = fixture.ReopenAccount();
        using (var retained = await senderAccount.PrepareOwnDirectRouteUpdateAsync(sender, announcement.OperationId, fixture.Source(senderAccount), default))
            Assert.Equal(message.CanonicalBytes.ToArray(), retained.ExactDmc2.ToArray());
        var floor = (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
        var authored = await fixture.ReadAuthoredRootDigestAsync(own: false);
        await fixture.RequireCurrentNativeRoute(receiver);
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync(own: false));
        fixture.AdvanceControlClock(message.ExpiresAtUnixMilliseconds, past: true);
        var account = fixture.ReopenGrantReader(); var source = fixture.GrantReaderSource(account);
        var health = await account.ReadContactRouteHealthAsync(new(receiver), source);
        Assert.True(health.AdvertisementIntervalCoversNow); Assert.True(health.UpdateIntervalCoversNow);
        Assert.False(health.RouteFaultRetained); // Coarse original-XUR health cannot grant current count8 use.
        await Assert.ThrowsAsync<CryptographicException>(() => account.RequireCurrentContactRouteAsync(new(receiver), source));
        await Assert.ThrowsAsync<CryptographicException>(() => account.PrepareOwnRouteHistoryRequestForDispatchAsync(receiver, source, default));
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync(own: false));
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        // Receive's durable staging purpose remains available; retrying that
        // exact original does not silently author a replacement or grant Store.
        using var staged = await fixture.PrepareOwnedHistory(receiver); Assert.NotNull(staged);
        using var retry = await account.PrepareOwnRouteHistoryRequestForDispatchAsync(receiver, source, default);
        Assert.NotNull(retry); Assert.Equal(staged!.OperationId.ToArray(), retry!.OperationId.ToArray());
        Assert.Equal(staged.ExactDmc2.ToArray(), retry.ExactDmc2.ToArray());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteMaintenance_NeverAttemptedExpiredControlStopsOnlyAtTrustedLowerAndPreservesResponseUniqueness(bool response)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await fixture.PrepareRouteHistoryPair();
        byte[] requestOperation = [];
        if (response)
        {
            using var request = await fixture.PrepareOwnedHistory(receiver); Assert.NotNull(request);
            requestOperation = request!.OperationId.ToArray();
            using var native = await fixture.SendOwnedRouteUpdate(receiver, requestOperation);
            using (await fixture.ReceiveOwnedMessage(sender, native.ExactEnvelope.ToArray())) { }
        }
        using var command = await fixture.PrepareOwnedHistory(sender, requestOperation); Assert.NotNull(command);
        var operation = command!.OperationId.ToArray();
        var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
        var lifetime = message.ExpiresAtUnixMilliseconds - message.CreatedAtUnixMilliseconds;
        Assert.InRange(lifetime, 1UL, response ? 3_600_000UL : 120_000UL);
        using (await fixture.SendOwnedRouteUpdate(sender, operation)) { }
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var sends = await fixture.ReadSendRootForStoppedWork();
        var grants = await fixture.ReadControlGrantRoot();
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        using var before = await fixture.ReadAuthoredTextJournalAsync(sender);
        Assert.Equal(operation, await fixture.SelectRouteMaintenance(sender));
        fixture.AdvanceControlClock(message.ExpiresAtUnixMilliseconds, past: false);
        var pair = await fixture.Source().VerifyForOwnMessagingAsync(fixture.Accounts, sender, default);
        var expiry = Did2ControlWorkStop.ProvenExpirySecond(message.ExpiresAtUnixMilliseconds);
        Assert.True(pair.Own.Proof.TrustedLowerUnixSeconds < expiry);
        Assert.True(pair.Own.Proof.TrustedUpperUnixSeconds >= expiry);
        Assert.Equal(operation, await fixture.SelectRouteMaintenance(sender));
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
        fixture.AdvanceControlClock(message.ExpiresAtUnixMilliseconds, past: true);
        Assert.Null(await fixture.SelectRouteMaintenance(sender));
        using (var stopped = await fixture.ReadAuthoredTextJournalAsync(sender))
        {
            var actual = stopped.Entries[Convert.ToHexString(operation)];
            Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired, actual.StopReason);
            Assert.False(actual.Stored); Assert.False(actual.Pending);
            Assert.Equal(command.SenderSequence, actual.Sequence); Assert.Equal(SHA256.HashData(command.ExactDmc2.Span), actual.EventHash.ToArray());
            Assert.Equal(before.NextSequence(sender), stopped.NextSequence(sender));
            Assert.Equal(before.Entries.Count, stopped.Entries.Count); // Stop-only: no destructive retirement.
        }
        Assert.Equal(sends, await fixture.ReadSendRootForStoppedWork()); Assert.Equal(grants, await fixture.ReadControlGrantRoot());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        await Assert.ThrowsAsync<IOException>(() => fixture.SendOwnedRouteUpdate(sender, operation));
        using var next = await fixture.PrepareOwnedHistory(sender, requestOperation);
        if (response) Assert.Null(next); // Native-committed correlated response cannot be replaced.
        else { Assert.NotNull(next); Assert.NotEqual(operation, next!.OperationId.ToArray()); Assert.Equal(command.SenderSequence + 1, next.SenderSequence); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteMaintenance_NeverAttemptedStopRejectsActualPreparedTransportOrPublicEvidenceEvenWithoutSendRoot(bool evidence)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await fixture.PrepareRouteHistoryPair();
        using var command = await fixture.PrepareOwnedHistory(sender); Assert.NotNull(command);
        var operation = command!.OperationId.ToArray(); byte[] ciphertext;
        using (var native = await fixture.SendOwnedRouteUpdate(sender, operation)) ciphertext = native.ExactEnvelope.ToArray();
        var terminal = new OwnedStoreFixture(fixture, sender, operation, ciphertext) { LoseReply = true };
        var issuer = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        if (evidence)
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.DeliverNativeMessage(sender, operation, issuer, terminal));
        else
        {
            using var hook = Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterSql) throw new IOException("Retained actual Prepared SQL before send-root preparation."); });
            await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(sender, operation, issuer, terminal));
        }
        await fixture.RemoveControlSendEntryForDisposableNegative(sender, operation);
        if (!evidence)
            await fixture.WithAuthoredApplicationConnectionAsync(sender, connection =>
            {
                using var update = connection.CreateCommand();
                update.CommandText = "UPDATE transport_outbox_items SET account_scope=zeroblob(32) WHERE state=$prepared;";
                update.Parameters.AddWithValue("$prepared", (int)TransportOutboxState.Prepared);
                Assert.Equal(1, update.ExecuteNonQuery()); // Global absence includes another account scope and Prepared.
            });
        fixture.AdvanceControlClock(ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ExpiresAtUnixMilliseconds, past: true);
        var authored = await fixture.ReadAuthoredRootDigestAsync(); var sends = await fixture.ReadSendRootForStoppedWork();
        var grants = await fixture.ReadControlGrantRoot(); var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var error = await Assert.ThrowsAsync<CryptographicException>(() => fixture.SelectRouteMaintenance(sender));
        Assert.Equal(evidence ? "Never-attempted control has retained Store evidence." : "Never-attempted control has retained original transport custody.", error.Message);
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync()); Assert.Equal(sends, await fixture.ReadSendRootForStoppedWork());
        Assert.Equal(grants, await fixture.ReadControlGrantRoot()); Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(evidence ? 1 : 0, terminal.Calls);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteMaintenance_NeverAttemptedStopPostCasGuardConflictPropagatesWithoutCleanup()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await fixture.PrepareRouteHistoryPair();
        using var command = await fixture.PrepareOwnedHistory(sender); Assert.NotNull(command);
        var operation = command!.OperationId.ToArray(); using (await fixture.SendOwnedRouteUpdate(sender, operation)) { }
        fixture.AdvanceControlClock(ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ExpiresAtUnixMilliseconds, past: true);
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray(); var sends = await fixture.ReadSendRootForStoppedWork();
        var hit = false;
        using (Did2MailboxSendTestHooks.Push(point =>
        {
            if (point != Did2MailboxSendFailpoint.AfterWorkStopRoot) return;
            Assert.False(hit); hit = true;
            fixture.ChangeControlGrantRevision(sender).GetAwaiter().GetResult();
        }))
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.SelectRouteMaintenance(sender));
        Assert.True(hit);
        using var stopped = await fixture.ReadAuthoredTextJournalAsync(sender);
        var entry = stopped.Entries[Convert.ToHexString(operation)];
        Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired, entry.StopReason); Assert.False(entry.Stored);
        Assert.Empty(stopped.TerminalAudits);
        Assert.Equal(sends, await fixture.ReadSendRootForStoppedWork());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteMaintenance_SettledExpiredAnnouncementAllowsFreshSameEndpointButPendingOriginalAlwaysWins()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await fixture.PrepareRouteHistoryPair();
        using var first = await fixture.CreateOwnedRouteUpdate(sender); var operation = first.OperationId.ToArray(); byte[] envelope;
        using (var native = await fixture.SendOwnedRouteUpdate(sender, operation)) envelope = native.ExactEnvelope.ToArray();
        var terminal = new OwnedStoreFixture(fixture, sender, operation, envelope);
        _ = await fixture.DeliverNativeMessage(sender, operation, new OwnedGrantTransport(fixture, ownerOnPrimary: true), terminal);
        Assert.Null(await fixture.SelectRouteMaintenance(sender));
        fixture.AdvanceControlClock(ApplicationCoreCodec.DecodeDmc2(first.ExactDmc2.Span).ExpiresAtUnixMilliseconds, past: true);
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        Assert.Empty((await fixture.SelectRouteMaintenance(sender))!);
        using var second = await fixture.CreateOwnedRouteUpdate(sender);
        var oldPage = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(first.ExactDmc2.Span).ParsedPayload);
        var newPage = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(second.ExactDmc2.Span).ParsedPayload);
        Assert.Equal(DeepIdV2ContactRouteHistoryMode.Announcement, newPage.Mode);
        Assert.Equal(oldPage.RightCursor.ToArray(), newPage.RightCursor.ToArray());
        Assert.Equal(oldPage.ExactLeftXir1V2.ToArray(), newPage.ExactLeftXir1V2.ToArray()); Assert.Empty(newPage.Atoms);
        Assert.NotEqual(operation, second.OperationId.ToArray()); Assert.Equal(first.SenderSequence + 1, second.SenderSequence);
        Assert.Equal(second.OperationId.ToArray(), await fixture.SelectRouteMaintenance(sender));
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray()); Assert.Equal(1, terminal.Calls);
    }

    private sealed partial class Fixture
    {
        internal Task RequireCurrentNativeRoute(Did2MessagingSessionScope scope)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            return account.RequireCurrentContactRouteAsync(new(scope), scope.IsInitiator ? Source(account) : GrantReaderSource(account));
        }

        internal void AdvanceControlClock(ulong expiryMilliseconds, bool past)
        {
            var target = checked(Did2ControlWorkStop.ProvenExpirySecond(expiryMilliseconds) + (past ? 20UL : 0UL));
            AdvanceControlClockTo(target);
        }

        internal void AdvanceControlClockTo(ulong target)
        {
            Assert.True(target > CurrentProofTime);
            var delta = checked(target - CurrentProofTime); ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
        }

        internal async Task<ulong> ActualInitialRouteExpiry(Did2MessagingSessionScope scope)
        {
            var floor = await ReadMessagingFloor(scope); ulong expiry = 0;
            await WithRouteReadSql(scope, (sql, _) =>
            {
                var initial = sql.ReadVerifiedActiveInitialEvents(floor);
                try
                {
                    var original = Assert.IsType<ContactHelloDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(initial.Hello).ParsedPayload).MailboxRoute.Route;
                    expiry = new[] { (original.Authorization, 13), (original.Reachability, 17), (original.Route, 18),
                        (original.Successor, 11), (original.Selection, 9) }.Min(part => BinaryPrimitives.ReadUInt64BigEndian(part.Item1.Field(part.Item2).Span));
                }
                finally { CryptographicOperations.ZeroMemory(initial.SessionInit); CryptographicOperations.ZeroMemory(initial.Hello); }
            });
            return expiry;
        }

        internal async Task<byte[]> ReadControlGrantRoot()
        {
            using var raw = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            return raw.Use(bytes => bytes.ToArray());
        }

        internal async Task RemoveControlSendEntryForDisposableNegative(Did2MessagingSessionScope scope, byte[] operation)
        {
            var before = await ReadSendRootForStoppedWork(); byte[] after = [];
            try
            {
                using var state = ProtectedDid2MailboxSendJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                var entry = Assert.Single(state.Entries.Values, item => item.Operation.SequenceEqual(operation));
                Assert.True(state.Entries.Remove(entry.Name)); entry.Dispose(); state.Revision = checked(state.Revision + 1);
                after = ProtectedDid2MailboxSendJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
                using var decoded = ProtectedDid2MailboxSendJournal.Decode(after, scope.Network, scope.LocalAccount, scope.Instance);
                Assert.DoesNotContain(decoded.Entries.Values, item => item.Operation.SequenceEqual(operation));
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, before, after, default));
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }

        internal async Task ChangeControlGrantRevision(Did2MessagingSessionScope scope)
        {
            var before = await ReadControlGrantRoot(); byte[] after = [];
            try
            {
                using var state = ProtectedDid2MailboxGrantJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                state.Revision = checked(state.Revision + 1);
                after = ProtectedDid2MailboxGrantJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, before, after, default));
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }
    }
}
