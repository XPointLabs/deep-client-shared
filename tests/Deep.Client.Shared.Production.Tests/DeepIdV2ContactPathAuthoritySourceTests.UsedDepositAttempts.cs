using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("initial", "AfterStage")] [InlineData("initial", "AfterHistoryAdopted")]
    [InlineData("accept", "AfterStage")] [InlineData("accept", "AfterHistoryAdopted")]
    [InlineData("ordinary", "AfterStage")] [InlineData("ordinary", "AfterHistoryAdopted")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2UsedDepositAttempts_AllOriginalAttemptsAuthenticateBeforeColdHolderRetirement(string kind, string fault)
    {
        // Real owned acquisition/linked send, native PQ and SQLCipher. Signed
        // in-process issuer/Store callbacks are not remote/device/AppAck proof.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareUsedDepositAttemptCase(kind);
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120; test.Transport.LoseReply = true;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        var originalIssuerCalls = test.Grants.Calls; // Ordinary work may reuse the actual initial holder.
        var reply = test.Transport.CopyOriginalQuorumForFixture();
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        using (var sends = await fixture.ReadMailboxSends(own: test.Scope.IsInitiator))
            fixture.AdvanceStoreSettlementClock(sends.Current(test.Scope.Hash, test.Operation)!.AdmissionUntil + 6);
        fixture.ColdReopenStoreSettlement(test.Scope);
        var childIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: test.Scope.IsInitiator)
            { MaximumFixtureGrantLifetimeSeconds = 120 };
        var child = new OwnedStoreFixture(fixture, test.Scope, test.Operation,
            test.Transport.StoredEnvelope!.Ciphertext.ToArray(), ownerOnPrimary: test.Scope.IsInitiator);
        Func<Task<ClientMailboxStoreResult>> deliverChild = () => kind == "initial"
            ? fixture.DeliverNativeInitial(test.Intent, childIssuer, child)
            : fixture.DeliverNativeMessage(test.Scope, test.Operation, childIssuer, child);
        var childStored = await deliverChild();
        fixture.AdvanceSyntheticMailboxClockPast(child.DurableTimeForFixture);
        byte[] childAttempt;
        using (var sends = await fixture.ReadMailboxSends(own: test.Scope.IsInitiator))
        {
            var chain = sends.Chain(test.Scope.Hash, test.Operation); Assert.Equal(2, chain.Count);
            childAttempt = chain[1].Attempt.ToArray(); Assert.NotEqual(test.Operation, childAttempt);
        }
        var originalStored = await fixture.AdoptStoreSettlement(test, reply);
        await fixture.CleanupSettledStoreCase(test, kind);
        fixture.ColdReopenStoreSettlement(test.Scope);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);

        var acquisitions = await fixture.ReadDepositAcquisitionChainForAttemptTest(test.Scope);
        Assert.True(acquisitions.Length >= 2);
        foreach (var acquisition in acquisitions)
        {
            var account = fixture.UsedDepositAccount(test.Scope.IsInitiator);
            var source = test.Scope.IsInitiator ? fixture.Source(account) : fixture.GrantReaderSource(account);
            using var exclusion = await account.OpenMailboxEpochExclusionAsync(acquisition, source);
            await exclusion.RetireIdleMailboxCounterFloorAsync();
        }
        using (var sends = await fixture.ReadMailboxSends(own: test.Scope.IsInitiator))
        { Assert.Empty(sends.Entries); Assert.Empty(sends.Floors); }
        var sql = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var roots = await fixture.ReadUsedDepositRetainedRoots(test.Scope);
        var sourceSql = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        try
        {
            for (var index = 0; index < acquisitions.Length; index++)
            {
                var account = fixture.UsedDepositAccount(test.Scope.IsInitiator);
                var source = test.Scope.IsInitiator ? fixture.Source(account) : fixture.GrantReaderSource(account);
                Func<Task> retire = () => account.RetireUsedDepositAcquisitionAsync(acquisitions[index], source);
                // A valid parent and a matching SQL grant cannot hide a corrupt
                // sibling, even after both protected send entries were compacted.
                await fixture.AssertSiblingStoreQuorumPinsHolderRetirement(test, childAttempt, retire);
                if (index == 0)
                {
                    var hit = false; var failpoint = Enum.Parse<Did2CompactionFailpoint>(fault);
                    using (Did2CompactionTestHooks.Push(point =>
                        { if (point == failpoint) { hit = true; throw new IOException("Interrupted all-attempt holder retirement."); } }))
                        await Assert.ThrowsAsync<IOException>(retire);
                    Assert.True(hit);
                    fixture.ColdReopenStoreSettlement(test.Scope);
                    await fixture.CompletedContactSendRecoveryOwner(test.Scope.IsInitiator).ResumeOwnedLocalCompactionAsync(default);
                }
                else await retire();
                fixture.ColdReopenStoreSettlement(test.Scope);
                Assert.Equal(sql, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
                Assert.Equal(roots, await fixture.ReadUsedDepositRetainedRoots(test.Scope));
                Assert.Equal(sourceSql, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
                Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            }
            using (var grants = await fixture.ReadPeerGrantsAsync(own: test.Scope.IsInitiator))
            { Assert.Empty(grants.Entries); Assert.Empty(grants.Selections); }
            var cached = await deliverChild();
            Assert.False(cached.IngressDispatched); Assert.Equal(originalStored.Cursor, cached.Cursor);
            Assert.NotNull(childStored.Cursor);
            Assert.Equal(1, test.Transport.Calls); Assert.Equal(originalIssuerCalls, test.Grants.Calls);
            Assert.Equal(1, child.Calls); Assert.Equal(1, childIssuer.Calls);
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        }
        finally
        {
            foreach (var bytes in acquisitions.Concat(new[] { reply, native, childAttempt, sql, roots, sourceSql }))
                CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private sealed partial class Fixture
    {
        internal async Task<CompletedContactSendCase> PrepareUsedDepositAttemptCase(string kind)
        {
            if (kind != "ordinary") return await PrepareCompletedContactSendCase(kind == "initial");
            // The complete native outgoing prefix includes DPH2. It MUST have
            // an actual original Store, not disappear through SQL absence.
            var initial = await PrepareCompletedContactSendCase(isInitial: true);
            initial.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
            await DeliverCompletedCaseWithExactRetry(initial);
            var dph = initial.Transport.StoredEnvelope!.Ciphertext.ToArray();
            try
            {
                using (var received = await CompleteReceiver(dph)) { }
                var receiver = await EnsureReceiverMessaging(dph);
                using (var accept = await PrepareOwnedContactAccept(receiver, Bytes(32, 0x72)))
                using (var sent = await SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
                using (var received = await ReceiveOwnedMessage(initial.Scope, sent.ExactEnvelope.ToArray())) { }
            }
            finally { CryptographicOperations.ZeroMemory(dph); }
            AdvanceSyntheticMailboxClockPast(initial.Transport.DurableTimeForFixture);
            await RetireCompletedContactSend(initial);
            using var text = await CreateOwnedText(initial.Scope, "same native event retains all original attempts");
            var operation = text.OperationId.ToArray();
            using var committed = await SendOwnedMessage(initial.Scope, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
            // Initial Store already started the same real elapsed clock. Never
            // reset it: the signed acceptance may be newer than the base time.
            var grants = new OwnedGrantTransport(this, ownerOnPrimary: true);
            var transport = new OwnedStoreFixture(this, initial.Scope, operation, committed.ExactEnvelope.ToArray());
            return new(initial.Scope, operation, [], grants, transport, () => DeliverNativeMessage(initial.Scope, operation, grants, transport));
        }

        internal async Task<byte[][]> ReadDepositAcquisitionChainForAttemptTest(Did2MessagingSessionScope scope)
        {
            // Selection on a disposable decoded copy, never writes real custody
            // or substitutes a deletion capability for the actual held owner.
            using var grants = await ReadPeerGrantsAsync(own: scope.IsInitiator);
            Assert.NotEmpty(grants.Selections);
            Assert.All(grants.Selections.Values, selection => Assert.Null(selection.Pending));
            var chain = new List<byte[]>();
            while (grants.Entries.Count != 0)
            {
                var eligible = grants.Entries.Keys.Where(name =>
                {
                    try { ProtectedDid2MailboxGrantJournal.RequireOldestAdoptedDeposit(grants, Convert.FromHexString(name)); return true; }
                    catch (IOException) { return false; }
                }).Order(StringComparer.Ordinal).ToArray();
                Assert.NotEmpty(eligible);
                var oldest = eligible[0]; // Oldest first independently in each real route scope.
                var acquisition = Convert.FromHexString(oldest); chain.Add(acquisition);
                var next = ProtectedDid2MailboxGrantJournal.RemoveOldestAdoptedDeposit(grants, acquisition,
                    scope.Network, scope.LocalAccount, scope.Instance);
                CryptographicOperations.ZeroMemory(next);
            }
            return chain.ToArray();
        }

        internal async Task AssertSiblingStoreQuorumPinsHolderRetirement(CompletedContactSendCase test,
            byte[] attempt, Func<Task> retire)
        {
            byte[] logical = [], original = [];
            await WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
            {
                using var read = connection.CreateCommand();
                read.CommandText = "SELECT e.logical_id,a.evidence FROM mailbox_store_public_evidence e JOIN transport_outbox_attempts a ON a.account_scope=e.account_scope AND a.logical_id=e.logical_id WHERE e.scope_hash=$scope AND e.attempt_id=$attempt AND a.state=$state;";
                read.Parameters.AddWithValue("$scope", test.Scope.Hash.ToArray()); read.Parameters.AddWithValue("$attempt", attempt);
                read.Parameters.AddWithValue("$state", (int)TransportOutboxAttemptState.Durable);
                using var rows = read.ExecuteReader(); Assert.True(rows.Read());
                logical = rows.GetFieldValue<byte[]>(0); original = rows.GetFieldValue<byte[]>(1); Assert.False(rows.Read());
            });
            async Task Replace(byte[] bytes) => await WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
            {
                using var update = connection.CreateCommand();
                update.CommandText = "UPDATE transport_outbox_attempts SET evidence=$evidence WHERE logical_id=$logical AND state=$state;";
                update.Parameters.AddWithValue("$evidence", bytes); update.Parameters.AddWithValue("$logical", logical);
                update.Parameters.AddWithValue("$state", (int)TransportOutboxAttemptState.Durable); Assert.Equal(1, update.ExecuteNonQuery());
            });
            var hostile = original.ToArray(); hostile[^1] ^= 1;
            var secure = CompletedContactSendStorage(test.Scope.IsInitiator);
            using var grant = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            var roots = await ReadUsedDepositRetainedRoots(test.Scope);
            try
            {
                await Replace(hostile);
                var sql = await ReadCompleteOrdinaryApplicationProjection(test.Scope);
                var error = await Assert.ThrowsAsync<MailboxReceiptException>(retire);
                Assert.Equal(MailboxReceiptError.UnexpectedStatement, error.Error);
                Assert.Equal(sql, await ReadCompleteOrdinaryApplicationProjection(test.Scope));
                Assert.Equal(roots, await ReadUsedDepositRetainedRoots(test.Scope));
                using var afterGrant = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                using var afterPlan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                Assert.Equal(grant.Use(bytes => bytes.ToArray()), afterGrant.Use(bytes => bytes.ToArray()));
                Assert.Equal(plan.Use(bytes => bytes.ToArray()), afterPlan.Use(bytes => bytes.ToArray()));
                CryptographicOperations.ZeroMemory(sql);
            }
            finally
            {
                await Replace(original);
                foreach (var bytes in new[] { logical, original, hostile, roots }) CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }
}
