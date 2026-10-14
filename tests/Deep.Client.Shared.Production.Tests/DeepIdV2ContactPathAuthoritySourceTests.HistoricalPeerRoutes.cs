using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2HistoricalPeerRoutes_OldAndUpdatedStoreKeepExactRoutesAcrossColdCleanup()
    {
        // Actual owned PQ/native sessions, qualified receive14, SQLCipher and
        // signed Store fixtures. Not socket or installed-device evidence.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.SeedShortPermanentProposalAsync(validitySeconds: 800);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x41));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x42)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        fixture.TrackMailboxDispatchClock();
        const string oldText = "original route before update";
        var oldOperation = await fixture.QueueNativeText(receiver, oldText);
        var oldIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var oldTerminal = new OwnedStoreFixture(fixture, receiver, oldOperation, null, ownerOnPrimary: false);
        var oldResult = await fixture.SendNativeText(receiver, oldOperation, oldText, oldIssuer, oldTerminal);
        var oldRoute = await fixture.ReadAttemptOriginalRoute(receiver, oldOperation);
        await fixture.RenewNativeSenderPublicationPastExpiryAsync();
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId))
        using (var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()))
            Assert.Equal(1, received.RouteProcessing[0]);
        fixture.ColdReopenReceiverStoreStorage();
        const string newText = "qualified successor route";
        var newOperation = await fixture.QueueNativeText(receiver, newText);
        var newIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var newTerminal = new OwnedStoreFixture(fixture, receiver, newOperation, null, ownerOnPrimary: false) { Cursor = 2 };
        var newResult = await fixture.SendNativeText(receiver, newOperation, newText, newIssuer, newTerminal);
        var newRoute = await fixture.ReadAttemptOriginalRoute(receiver, newOperation);
        Assert.NotEqual(oldRoute, newRoute);
        fixture.AdvanceSyntheticMailboxClockPast(newTerminal.DurableTimeForFixture);
        var native = (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray();
        await fixture.CompactHistoricalPeerRoutePrefix(receiver);
        fixture.ColdReopenReceiverStoreStorage();
        await CheckCachedResults();
        await CheckRouteSubstitution();
        // Actual per-attempt historical route joins must survive removal of
        // working sends, not merely use a current working route hash/cache.
        await fixture.CompactNativeOrdinaryOutbox(receiver, default);
        using (var sends = await fixture.ReadMailboxSends(own: false)) Assert.Empty(sends.Entries);
        fixture.ColdReopenReceiverStoreStorage();
        await CheckCachedResults();
        await CheckRouteSubstitution();
        Assert.Equal(oldRoute, await fixture.ReadAttemptOriginalRoute(receiver, oldOperation));
        Assert.Equal(newRoute, await fixture.ReadAttemptOriginalRoute(receiver, newOperation));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(2, (await fixture.ListOwnedMessages(receiver)).Count);
        foreach (var bytes in new[] { oldRoute, newRoute, native }) CryptographicOperations.ZeroMemory(bytes);

        async Task CheckCachedResults()
        {
            var unusedIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
            var oldCached = await fixture.SendNativeText(receiver, oldOperation, oldText, unusedIssuer, oldTerminal);
            var newCached = await fixture.SendNativeText(receiver, newOperation, newText, unusedIssuer, newTerminal);
            Assert.Equal(oldResult.Cursor, oldCached.Cursor); Assert.False(oldCached.IngressDispatched);
            Assert.Equal(newResult.Cursor, newCached.Cursor); Assert.False(newCached.IngressDispatched);
            Assert.Equal(0, unusedIssuer.Calls); Assert.Equal(1, oldTerminal.Calls); Assert.Equal(1, newTerminal.Calls);
            Assert.Equal(native, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        }

        async Task CheckRouteSubstitution()
        {
            foreach (var (operation, original, substituted, text, terminal) in new[]
            {
                (oldOperation, oldRoute, newRoute, oldText, oldTerminal),
                (newOperation, newRoute, oldRoute, newText, newTerminal)
            })
            {
                try
                {
                    await fixture.ReplaceAttemptOriginalRoute(receiver, operation, operation, substituted);
                    var sql = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
                    var roots = await fixture.ReadCompletedContactSendRetainedRoots(receiver);
                    await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendNativeText(receiver, operation, text,
                        new OwnedGrantTransport(fixture, ownerOnPrimary: false), terminal));
                    Assert.Equal(sql, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
                    Assert.Equal(roots, await fixture.ReadCompletedContactSendRetainedRoots(receiver));
                    Assert.Equal(native, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
                    Assert.Equal(1, terminal.Calls);
                    CryptographicOperations.ZeroMemory(sql); CryptographicOperations.ZeroMemory(roots);
                }
                finally { await fixture.ReplaceAttemptOriginalRoute(receiver, operation, operation, original); }
            }
        }
    }

    [Theory]
    [InlineData("BeforeSuccessorRoot")]
    [InlineData("AfterSuccessorRoot")]
    [InlineData("AfterSql")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2HistoricalPeerRoutes_ChangedRouteSuccessorColdResumesOriginalCiphertextAndDeadline(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.SeedShortPermanentProposalAsync(validitySeconds: 800);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x51));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x52)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        using var text = await fixture.CreateOwnedText(receiver, "same ciphertext across authenticated recipient route update");
        var operation = text.OperationId.ToArray();
        using var committed = await fixture.SendOwnedMessage(receiver, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var originalIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var originalTerminal = new OwnedStoreFixture(fixture, receiver, operation, committed.ExactEnvelope.ToArray(), ownerOnPrimary: false);
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterPreparedRoot) throw new IOException("Interrupted original prepared route attempt."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(receiver, operation, originalIssuer, originalTerminal));
        Assert.Equal(1, originalIssuer.Calls); Assert.Equal(0, originalTerminal.Calls);
        byte[] original;
        using (var sends = await fixture.ReadMailboxSends(own: false)) original = Assert.Single(sends.Entries).Value.Exact.ToArray();
        using var predecessor = ProtectedDid2MailboxSendJournal.Entry.Decode(original);
        await fixture.RenewNativeSenderPublicationPastExpiryAsync();
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId.ToArray()))
        using (var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()))
            Assert.Equal(1, received.RouteProcessing[0]);
        await fixture.CompactHistoricalPeerRoutePrefix(receiver);
        fixture.ColdReopenReceiverStoreStorage();
        var native = (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray();
        using var authoredBefore = await fixture.ReadAuthoredTextJournalAsync(receiver);
        var successorIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var terminal = new OwnedStoreFixture(fixture, receiver, operation, committed.ExactEnvelope.ToArray(), ownerOnPrimary: false);
        var hit = false; var failpoint = Enum.Parse<Did2MailboxSendFailpoint>(fault);
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == failpoint) { hit = true; throw new IOException("Interrupted changed-route successor handover."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(receiver, operation, successorIssuer, terminal));
        Assert.True(hit); Assert.Equal(1, successorIssuer.Calls); Assert.Equal(0, terminal.Calls);
        fixture.ColdReopenReceiverStoreStorage();
        var unusedIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var result = await fixture.DeliverNativeMessage(receiver, operation, unusedIssuer, terminal);
        Assert.NotNull(result.Cursor); Assert.Equal(0, unusedIssuer.Calls); Assert.Equal(1, terminal.Calls);
        ulong successfulAt;
        using (var authoredAfter = await fixture.ReadAuthoredTextJournalAsync(receiver))
        {
            var before = Assert.Single(authoredBefore.Entries).Value; var after = Assert.Single(authoredAfter.Entries).Value;
            Assert.False(before.Stored); Assert.True(after.Stored);
            Assert.Equal(before.Exact[..516].ToArray(), after.Exact[..516].ToArray());
            Assert.Equal(before.Exact[517..532].ToArray(), after.Exact[517..532].ToArray());
            Assert.Equal(before.Exact[540..].ToArray(), after.Exact[540..].ToArray());
            Assert.Equal(0UL, before.FirstSuccessfulStoreUpper);
            successfulAt = after.FirstSuccessfulStoreUpper;
            Assert.InRange(successfulAt, terminal.DurableTimeForFixture, checked(fixture.CurrentProofTime + 100));
            Assert.Equal(Assert.Single(authoredBefore.Floors).Value.NextSequence, Assert.Single(authoredAfter.Floors).Value.NextSequence);
        }
        using (var sends = await fixture.ReadMailboxSends(own: false))
        {
            var chain = sends.Chain(receiver.Hash, operation); Assert.Equal(2, chain.Count);
            var parent = chain[0]; var child = chain[1];
            Assert.True(parent.Closed); Assert.True(parent.HasSuccessor); Assert.True(child.Prepared); Assert.False(child.Closed);
            Assert.Equal(original[..296], parent.Exact[..296].ToArray());
            Assert.Equal(parent.Attempt.ToArray(), child.Predecessor.ToArray());
            Assert.Equal(child.Attempt.ToArray(), parent.Successor.ToArray());
            Assert.NotEqual(parent.RouteHash.ToArray(), child.RouteHash.ToArray());
            Assert.NotEqual(parent.GrantHash.ToArray(), child.GrantHash.ToArray());
            Assert.Equal(parent.EnvelopeHash.ToArray(), child.EnvelopeHash.ToArray());
            Assert.Equal(parent.Expires, child.Expires); Assert.Equal(parent.RetryUntil, child.RetryUntil);
            Assert.Equal(SHA256.HashData(await fixture.ReadAttemptOriginalRoute(receiver, operation)), child.RouteHash.ToArray());
            Assert.Equal(2UL, sends.MinimumCounter(parent.GrantHash)); Assert.Equal(2UL, sends.MinimumCounter(child.GrantHash));
        }
        fixture.AdvanceSyntheticMailboxClockPast(terminal.DurableTimeForFixture);
        fixture.ColdReopenReceiverStoreStorage();
        var cached = await fixture.DeliverNativeMessage(receiver, operation, unusedIssuer, terminal);
        Assert.Equal(result.Cursor, cached.Cursor); Assert.False(cached.IngressDispatched);
        using (var retried = await fixture.ReadAuthoredTextJournalAsync(receiver))
            Assert.Equal(successfulAt, Assert.Single(retried.Entries).Value.FirstSuccessfulStoreUpper);
        // A known child does not authorize deleting its unknown parent.
        var roots = await fixture.ReadCompletedContactSendRetainedRoots(receiver);
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
        await Assert.ThrowsAsync<IOException>(() => fixture.CompactNativeOrdinaryOutbox(receiver, default));
        Assert.Equal(roots, await fixture.ReadCompletedContactSendRetainedRoots(receiver));
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(0, originalTerminal.Calls); Assert.Equal(1, terminal.Calls); Assert.Equal(0, unusedIssuer.Calls);
        Assert.Single(await fixture.ListOwnedMessages(receiver));
        foreach (var bytes in new[] { original, native, roots, application }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData("BeforeSettlementSql")]
    [InlineData("AfterSettlementSql")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2HistoricalPeerRoutes_LateOriginalStoreClosesMixedRouteChainAndRetiresBothGrants(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        await fixture.SeedShortPermanentProposalAsync(validitySeconds: 800);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x81));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        var acceptOperation = Bytes(32, 0x82); byte[] acceptCipher;
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, acceptOperation))
        using (var sent = await fixture.SendOwnedMessage(receiver, acceptOperation, ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        { acceptCipher = sent.ExactEnvelope.ToArray(); using var received = await fixture.ReceiveOwnedMessage(sender, acceptCipher); }
        fixture.TrackMailboxDispatchClock();
        var originalIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false) { MaximumFixtureGrantLifetimeSeconds = 500 };
        var acceptanceTerminal = new OwnedStoreFixture(fixture, receiver, acceptOperation, acceptCipher, ownerOnPrimary: false);
        await fixture.DeliverNativeMessage(receiver, acceptOperation, originalIssuer, acceptanceTerminal);
        var acceptanceCase = new Fixture.CompletedContactSendCase(receiver, acceptOperation, [], originalIssuer, acceptanceTerminal,
            () => fixture.DeliverNativeMessage(receiver, acceptOperation, originalIssuer, acceptanceTerminal));
        using var text = await fixture.CreateOwnedText(receiver, "one message with original and updated route Stores");
        var operation = text.OperationId.ToArray();
        using var committed = await fixture.SendOwnedMessage(receiver, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var originalTerminal = new OwnedStoreFixture(fixture, receiver, operation, committed.ExactEnvelope.ToArray(), ownerOnPrimary: false)
            { Cursor = 2, LoseReply = true };
        var originalCase = new Fixture.CompletedContactSendCase(receiver, operation, [], originalIssuer, originalTerminal,
            () => fixture.DeliverNativeMessage(receiver, operation, originalIssuer, originalTerminal));
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(originalCase.Deliver);
        var reply = originalTerminal.CopyOriginalQuorumForFixture();
        var request = originalTerminal.ExactRequest!.ToArray();
        var oldRoute = await fixture.ReadAttemptOriginalRoute(receiver, operation, operation);
        Assert.Equal(1, originalIssuer.Calls); // Acceptance/text share one actual admitted grant.
        await fixture.RenewNativeSenderPublicationPastExpiryAsync();
        using (var update = await fixture.CreateOwnedRouteUpdate(sender))
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, update.OperationId.ToArray()))
        using (var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()))
            Assert.Equal(1, received.RouteProcessing[0]);
        await fixture.CompactHistoricalPeerRoutePrefix(receiver);
        fixture.ColdReopenReceiverStoreStorage();
        var native = (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray();
        var successorIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false) { MaximumFixtureGrantLifetimeSeconds = 120 };
        var successorTerminal = new OwnedStoreFixture(fixture, receiver, operation, committed.ExactEnvelope.ToArray(), ownerOnPrimary: false) { Cursor = 3 };
        var child = await fixture.DeliverNativeMessage(receiver, operation, successorIssuer, successorTerminal);
        Assert.NotNull(child.Cursor);
        fixture.AdvanceSyntheticMailboxClockPast(successorTerminal.DurableTimeForFixture);
        byte[] childAttempt;
        using (var sends = await fixture.ReadMailboxSends(own: false))
        {
            var chain = sends.Chain(receiver.Hash, operation); Assert.Equal(2, chain.Count);
            Assert.True(chain[0].Closed); Assert.True(chain[1].Prepared);
            Assert.NotEqual(chain[0].RouteHash.ToArray(), chain[1].RouteHash.ToArray());
            Assert.Equal(chain[0].EnvelopeHash.ToArray(), chain[1].EnvelopeHash.ToArray());
            Assert.Equal(chain[0].Expires, chain[1].Expires); Assert.Equal(chain[0].RetryUntil, chain[1].RetryUntil);
            childAttempt = chain[1].Attempt.ToArray();
        }
        var newRoute = await fixture.ReadAttemptOriginalRoute(receiver, operation, childAttempt);
        Assert.NotEqual(oldRoute, newRoute);
        // Both original attempts and signed Store replies already exist.
        // Renew through the genuine signed successor before the longer cold
        // settlement/retirement segment can outlive the original XNV1 window.
        // Original requests, policy ceilings and validation remain unchanged.
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        var pending = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
        var roots = await fixture.ReadCompletedContactSendRetainedRoots(receiver);
        await Assert.ThrowsAsync<IOException>(() => fixture.CompactNativeOrdinaryOutbox(receiver, default));
        Assert.Equal(pending, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        Assert.Equal(roots, await fixture.ReadCompletedContactSendRetainedRoots(receiver));
        var hit = false; var failpoint = Enum.Parse<Did2MailboxSendFailpoint>(fault);
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == failpoint) { hit = true; throw new IOException("Interrupted mixed-route original settlement."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.AdoptStoreSettlement(originalCase, reply));
        Assert.True(hit); Assert.Equal(roots, await fixture.ReadCompletedContactSendRetainedRoots(receiver));
        if (fault == "BeforeSettlementSql") Assert.Equal(pending, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        else Assert.NotEqual(pending, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        fixture.ColdReopenReceiverStoreStorage();
        var adopted = await fixture.AdoptStoreSettlement(originalCase, reply);
        var settled = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
        Assert.Equal(adopted.Cursor, (await fixture.AdoptStoreSettlement(originalCase, reply)).Cursor);
        Assert.Equal(settled, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        Assert.Equal(request, originalTerminal.ExactRequest);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        await fixture.CompactNativeOrdinaryOutbox(receiver, default);
        await fixture.RetireCompletedContactSend(acceptanceCase);
        using (var sends = await fixture.ReadMailboxSends(own: false)) Assert.Empty(sends.Entries);
        fixture.ColdReopenReceiverStoreStorage();
        var account = fixture.UsedDepositAccount(initial: false); var source = fixture.GrantReaderSource(account);
        byte[][] acquisitions;
        using (var grants = await fixture.ReadPeerGrantsAsync())
        { Assert.Equal(2, grants.Entries.Count); acquisitions = grants.Entries.Keys.Select(Convert.FromHexString).ToArray(); }
        foreach (var acquisition in acquisitions)
        {
            using (var exclusion = await account.OpenMailboxEpochExclusionAsync(acquisition, source))
                await exclusion.RetireIdleMailboxCounterFloorAsync();
            await account.RetireUsedDepositAcquisitionAsync(acquisition, source);
        }
        fixture.ColdReopenReceiverStoreStorage();
        using (var grants = await fixture.ReadPeerGrantsAsync()) { Assert.Empty(grants.Entries); Assert.Empty(grants.Selections); }
        var unusedIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var cached = await fixture.DeliverNativeMessage(receiver, operation, unusedIssuer, successorTerminal);
        Assert.Equal(adopted.Cursor, cached.Cursor); Assert.False(cached.IngressDispatched);
        Assert.Equal(oldRoute, await fixture.ReadAttemptOriginalRoute(receiver, operation, operation));
        Assert.Equal(newRoute, await fixture.ReadAttemptOriginalRoute(receiver, operation, childAttempt));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Single(await fixture.ListOwnedMessages(receiver));
        Assert.Equal(1, originalTerminal.Calls); Assert.Equal(1, successorTerminal.Calls); Assert.Equal(1, acceptanceTerminal.Calls);
        Assert.Equal(1, originalIssuer.Calls); Assert.Equal(1, successorIssuer.Calls); Assert.Equal(0, unusedIssuer.Calls);
        // Even after every original acquisition/working send was retired,
        // another genuine native-known route cannot replace this attempt's
        // captured route, nor can its integrity record be substituted.
        foreach (var changeRoute in new[] { true, false })
        {
            var originalMac = await fixture.ReadAttemptEvidenceCommitment(receiver, operation, operation);
            try
            {
                if (changeRoute) await fixture.ReplaceAttemptOriginalRoute(receiver, operation, operation, newRoute);
                else
                {
                    var changedMac = originalMac.ToArray(); changedMac[0] ^= 1;
                    try { await fixture.ReplaceAttemptEvidenceCommitment(receiver, operation, operation, changedMac); }
                    finally { CryptographicOperations.ZeroMemory(changedMac); }
                }
                var beforeSql = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
                var beforeRoots = await fixture.ReadCompletedContactSendRetainedRoots(receiver);
                try
                {
                    await Assert.ThrowsAsync<CryptographicException>(() =>
                        fixture.DeliverNativeMessage(receiver, operation, unusedIssuer, successorTerminal));
                    Assert.Equal(beforeSql, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
                    Assert.Equal(beforeRoots, await fixture.ReadCompletedContactSendRetainedRoots(receiver));
                    Assert.Equal(native, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
                    Assert.Equal(0, unusedIssuer.Calls); Assert.Equal(1, successorTerminal.Calls);
                }
                finally { CryptographicOperations.ZeroMemory(beforeSql); CryptographicOperations.ZeroMemory(beforeRoots); }
            }
            finally
            {
                await fixture.ReplaceAttemptOriginalRoute(receiver, operation, operation, oldRoute);
                await fixture.ReplaceAttemptEvidenceCommitment(receiver, operation, operation, originalMac);
                CryptographicOperations.ZeroMemory(originalMac);
            }
        }
        Assert.Equal(adopted.Cursor, (await fixture.DeliverNativeMessage(receiver, operation, unusedIssuer, successorTerminal)).Cursor);
        foreach (var bytes in acquisitions.Concat(new[] { acceptCipher, reply, request, oldRoute, newRoute, childAttempt, native, pending, roots, settled }))
            CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]> ReadAttemptEvidenceCommitment(Did2MessagingSessionScope scope, byte[] operation, byte[] attempt)
        {
            byte[] result = [];
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var read = connection.CreateCommand();
                read.CommandText = "SELECT evidence_commitment FROM mailbox_store_public_evidence WHERE scope_hash=$scope AND native_operation_id=$op AND attempt_id=$attempt;";
                read.Parameters.AddWithValue("$scope", scope.Hash.ToArray()); read.Parameters.AddWithValue("$op", operation); read.Parameters.AddWithValue("$attempt", attempt);
                using var rows = read.ExecuteReader(); Assert.True(rows.Read()); result = rows.GetFieldValue<byte[]>(0); Assert.False(rows.Read()); Assert.Equal(32, result.Length);
            });
            return result;
        }

        internal Task ReplaceAttemptEvidenceCommitment(Did2MessagingSessionScope scope, byte[] operation, byte[] attempt, byte[] commitment)
            => WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var write = connection.CreateCommand();
                write.CommandText = "UPDATE mailbox_store_public_evidence SET evidence_commitment=$mac WHERE scope_hash=$scope AND native_operation_id=$op AND attempt_id=$attempt;";
                write.Parameters.AddWithValue("$scope", scope.Hash.ToArray()); write.Parameters.AddWithValue("$op", operation); write.Parameters.AddWithValue("$attempt", attempt);
                write.Parameters.AddWithValue("$mac", commitment); Assert.Equal(1, write.ExecuteNonQuery());
            });

        internal async Task CompactHistoricalPeerRoutePrefix(Did2MessagingSessionScope scope)
        {
            var before = await ReadMessagingFloor(scope);
            await CompletedContactSendRecoveryOwner(scope.IsInitiator).CompactOwnedMessagingPrefixAsync(
                1_000, pq, scope, checked((int)before.Ordinal), default);
            var secure = scope.IsInitiator ? (Deep.Client.Shared.Persistence.IDeepSecureStorage)storage : peerStorage;
            var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(secure, scope, default);
            Assert.Equal(before.Ordinal, history.Basis.Ordinal);
            Assert.Equal(before.Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
        }

        internal Task ReplaceAttemptOriginalRoute(Did2MessagingSessionScope scope, byte[] operation, byte[] attempt, byte[] route)
            => WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var update = connection.CreateCommand();
                update.CommandText = "UPDATE mailbox_store_public_evidence SET original_route=$route WHERE scope_hash=$scope AND native_operation_id=$op AND attempt_id=$attempt;";
                update.Parameters.AddWithValue("$route", route); update.Parameters.AddWithValue("$scope", scope.Hash.ToArray());
                update.Parameters.AddWithValue("$op", operation); update.Parameters.AddWithValue("$attempt", attempt);
                Assert.Equal(1, update.ExecuteNonQuery());
            });

        internal async Task<byte[]> ReadAttemptOriginalRoute(Did2MessagingSessionScope scope, byte[] operation, byte[]? attempt = null)
        {
            byte[] result = [];
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var read = connection.CreateCommand();
                read.CommandText = "SELECT original_route FROM mailbox_store_public_evidence WHERE scope_hash=$scope AND native_operation_id=$op AND ($attempt IS NULL OR attempt_id=$attempt);";
                read.Parameters.AddWithValue("$scope", scope.Hash.ToArray()); read.Parameters.AddWithValue("$op", operation);
                read.Parameters.AddWithValue("$attempt", (object?)attempt ?? DBNull.Value);
                using var rows = read.ExecuteReader(); Assert.True(rows.Read());
                result = ((byte[])rows[0]).ToArray(); Assert.False(rows.Read());
            });
            return result;
        }
    }
}
