using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("initial")] [InlineData("accept")] [InlineData("ordinary")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoreSettlement_DistinctIssuanceAndAssignmentAdoptsExactLateReplyWithoutRedispatch(string kind)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 1_200);
        var test = await fixture.PrepareStoreMonotonicityCase(kind);
        // Genuine signed same-epoch renewal, not a new logical assignment.
        await fixture.AdvanceNetworkAsync(expiry: 6_000);
        fixture.AdvanceStoreSettlementClock(1_100);
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
        test.Transport.BeforeReturnedReply = expiry => fixture.AdvanceStoreSettlementClock(expiry + 6);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var result = await test.Deliver();
        Assert.NotNull(result.Cursor); Assert.False(result.IngressDispatched);
        using (var grants = await fixture.ReadPeerGrantsAsync(own: test.Scope.IsInitiator))
        {
            var original = Assert.Single(grants.Entries).Value;
            var policy = ContactCodec.Decode("PMA2", ProtectedDid2MailboxGrantJournal.OriginalPolicy(original).Span);
            var route = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(original).Span);
            Assert.False(policy.CoreHash.Span.SequenceEqual(route.Projection.Field(4).Span[6..]));
        }
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        var originalRequest = test.Transport.ExactRequest!.ToArray();
        fixture.ColdReopenStoreSettlement(test.Scope);
        var repeated = await test.Deliver();
        Assert.Equal(result.Cursor, repeated.Cursor); Assert.False(repeated.IngressDispatched);
        Assert.Equal(originalRequest, test.Transport.ExactRequest);
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        CryptographicOperations.ZeroMemory(originalRequest); CryptographicOperations.ZeroMemory(native);
    }

    [Theory]
    [InlineData("initial")] [InlineData("accept")] [InlineData("ordinary")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoreSettlement_NormalReturnedLateReplyIsAdoptedWithoutAnotherDispatch(string kind)
    {
        // Genuine native PQ/SQLCipher/signatures and normal owned entry, with an
        // in-process Store callback delaying return beyond its signed grant.
        // Not socket/device E2E, remote durable persistence or application ACK.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var test = await fixture.PrepareStoreMonotonicityCase(kind);
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        test.Transport.BeforeReturnedReply = expiry => fixture.AdvanceStoreSettlementClock(expiry + 6);
        var result = await test.Deliver();
        Assert.NotNull(result.Cursor); Assert.False(result.IngressDispatched);
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        fixture.ColdReopenStoreSettlement(test.Scope);
        var cached = await test.Deliver();
        Assert.False(cached.IngressDispatched); Assert.Equal(result.Cursor, cached.Cursor);
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        await fixture.CleanupSettledStoreCase(test, kind);
        using var sends = await fixture.ReadMailboxSends(own: test.Scope.IsInitiator);
        Assert.Empty(sends.Entries); Assert.Single(sends.Floors);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        CryptographicOperations.ZeroMemory(native);
    }

    [Theory]
    [InlineData("initial", "BeforeSettlementSql")] [InlineData("initial", "AfterSettlementSql")]
    [InlineData("accept", "BeforeSettlementSql")] [InlineData("accept", "AfterSettlementSql")]
    [InlineData("ordinary", "BeforeSettlementSql")] [InlineData("ordinary", "AfterSettlementSql")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoreSettlement_LateOriginalReplyAndWholeKnownChainSurviveAtomicFaultAndColdReopen(string kind, string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var test = await fixture.PrepareStoreMonotonicityCase(kind);
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120; test.Transport.LoseReply = true;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        var reply = test.Transport.CopyOriginalQuorumForFixture();
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        byte[] parentRequest;
        using (var sends = await fixture.ReadMailboxSends(own: test.Scope.IsInitiator))
        {
            var parent = Assert.Single(sends.Entries).Value;
            fixture.AdvanceStoreSettlementClock(parent.AdmissionUntil + 6);
            parentRequest = test.Transport.ExactRequest!.ToArray();
        }
        fixture.ColdReopenStoreSettlement(test.Scope);
        var childIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: test.Scope.IsInitiator)
            { MaximumFixtureGrantLifetimeSeconds = 120 };
        var child = new OwnedStoreFixture(fixture, test.Scope, test.Operation, test.Transport.StoredEnvelope!.Ciphertext.ToArray());
        Func<Task<ClientMailboxStoreResult>> deliverChild = () => kind == "initial"
            ? fixture.DeliverNativeInitial(test.Intent, childIssuer, child)
            : fixture.DeliverNativeMessage(test.Scope, test.Operation, childIssuer, child);
        var childResult = await deliverChild(); Assert.NotNull(childResult.Cursor);
        fixture.AdvanceSyntheticMailboxClockPast(child.DurableTimeForFixture);
        using (var sends = await fixture.ReadMailboxSends(own: test.Scope.IsInitiator))
        {
            var chain = sends.Chain(test.Scope.Hash, test.Operation); Assert.Equal(2, chain.Count);
            Assert.True(chain[0].Closed); Assert.True(chain[1].Prepared);
            Assert.Equal(2UL, sends.MinimumCounter(chain[0].GrantHash));
            Assert.Equal(2UL, sends.MinimumCounter(chain[1].GrantHash));
        }
        var pending = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var retained = await fixture.ReadCompletedContactSendRetainedRoots(test.Scope);
        // The unchanged owner reports this precise IOException subtype for
        // unresolved public evidence; xUnit ThrowsAsync requires an exact type.
        await Assert.ThrowsAsync<ProtectedDeepIdV2AccountOwner.OutboxPrefixPinnedException>(() => fixture.CleanupSettledStoreCase(test, kind));
        Assert.Equal(pending, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        Assert.Equal(retained, await fixture.ReadCompletedContactSendRetainedRoots(test.Scope));

        // A valid child signature is still not evidence for the parent request.
        var hostile = reply.ToArray(); hostile[^1] ^= 1;
        foreach (var wrong in new[] { hostile, child.CopyOriginalQuorumForFixture() })
        {
            try
            {
                var error = await Assert.ThrowsAsync<MailboxReceiptException>(() => fixture.AdoptStoreSettlement(test, wrong));
                Assert.Equal(MailboxReceiptError.UnexpectedStatement, error.Error);
            }
            finally { CryptographicOperations.ZeroMemory(wrong); }
            Assert.Equal(pending, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(retained, await fixture.ReadCompletedContactSendRetainedRoots(test.Scope));
        }
        var hit = false; var failpoint = Enum.Parse<Did2MailboxSendFailpoint>(fault);
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == failpoint) { hit = true; throw new IOException("Interrupted original Store atomic settlement."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.AdoptStoreSettlement(test, reply));
        Assert.True(hit);
        if (fault == "BeforeSettlementSql") Assert.Equal(pending, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        else Assert.NotEqual(pending, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        Assert.Equal(retained, await fixture.ReadCompletedContactSendRetainedRoots(test.Scope));
        fixture.ColdReopenStoreSettlement(test.Scope);
        var adopted = await fixture.AdoptStoreSettlement(test, reply);
        Assert.False(adopted.IngressDispatched); Assert.NotNull(adopted.Cursor);
        var settled = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var repeated = await fixture.AdoptStoreSettlement(test, reply);
        Assert.Equal(adopted.Cursor, repeated.Cursor);
        Assert.Equal(settled, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        Assert.Equal(parentRequest, test.Transport.ExactRequest);
        if (kind == "initial") await fixture.AssertSiblingInitialEvidencePinsCleanup(test);
        await fixture.CleanupSettledStoreCase(test, kind);
        fixture.ColdReopenStoreSettlement(test.Scope);
        using (var sends = await fixture.ReadMailboxSends(own: test.Scope.IsInitiator))
        {
            Assert.Empty(sends.Entries); Assert.Equal(2, sends.Floors.Count);
            Assert.All(sends.Floors.Values, value => Assert.Equal(1UL, value.HighestCounter));
        }
        var cached = await deliverChild(); Assert.False(cached.IngressDispatched);
        Assert.Equal(adopted.Cursor, cached.Cursor);
        Assert.Equal(1, test.Grants.Calls); Assert.Equal(1, test.Transport.Calls);
        Assert.Equal(1, childIssuer.Calls); Assert.Equal(1, child.Calls);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        foreach (var bytes in new[] { reply, native, parentRequest, pending, retained, settled }) CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        internal void AdvanceStoreSettlementClock(ulong center)
        {
            var delta = checked(center - CurrentProofTime);
            ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
        }
        internal void ColdReopenStoreSettlement(Did2MessagingSessionScope scope)
        { if (scope.IsInitiator) ColdReopenCompactionStorage(); else ColdReopenReceiverStoreStorage(); }
        internal Task<ClientMailboxStoreResult> AdoptStoreSettlement(CompletedContactSendCase test, ReadOnlyMemory<byte> reply)
        {
            var account = test.Scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = test.Scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            return account.AdoptOwnOriginalMailboxStoreReplyAsync(test.Scope, test.Operation, test.Operation, test.Intent, reply, source);
        }
        internal Task CleanupSettledStoreCase(CompletedContactSendCase test, string kind) => kind == "ordinary"
            ? CompactNativeOrdinaryOutbox(test.Scope, default) : RetireCompletedContactSend(test);

        internal async Task AssertSiblingInitialEvidencePinsCleanup(CompletedContactSendCase test)
        {
            byte[] child = [], original = [];
            using (var sends = await ReadMailboxSends()) child = sends.Chain(test.Scope.Hash, test.Operation)[1].Attempt.ToArray();
            await WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
            {
                using var read = connection.CreateCommand();
                read.CommandText = "SELECT original_peer_adp FROM mailbox_store_public_evidence WHERE attempt_id=$attempt;";
                read.Parameters.AddWithValue("$attempt", child); original = ((byte[])read.ExecuteScalar()!).ToArray();
            });
            // Change an actual witness signature, not framing/revocation count.
            var signature = DeepIdV2Adp1Codec.Decode(original).Head.Witnesses[0].Signature.ToArray();
            var offset = original.AsSpan().IndexOf(signature);
            Assert.True(offset >= 0);
            var hostile = original.ToArray(); hostile[offset + signature.Length - 1] ^= 1;
            _ = DeepIdV2Adp1Codec.Decode(hostile); // Canonical proof shape still valid.
            async Task Replace(byte[] bytes) => await WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
            {
                using var update = connection.CreateCommand();
                update.CommandText = "UPDATE mailbox_store_public_evidence SET original_peer_adp=$adp WHERE attempt_id=$attempt;";
                update.Parameters.AddWithValue("$adp", bytes); update.Parameters.AddWithValue("$attempt", child);
                Assert.Equal(1, update.ExecuteNonQuery());
            });
            try
            {
                await Replace(hostile);
                var sql = await ReadCompleteOrdinaryApplicationProjection(test.Scope);
                var roots = await ReadCompletedContactSendRetainedRoots(test.Scope);
                // Original evidence has an independently protected commitment.
                // SQL substitution is rejected there, before witness parsing;
                // verifying a different proof cannot repair that commitment.
                await Assert.ThrowsAsync<CryptographicException>(() => RetireCompletedContactSend(test));
                Assert.Equal(sql, await ReadCompleteOrdinaryApplicationProjection(test.Scope));
                Assert.Equal(roots, await ReadCompletedContactSendRetainedRoots(test.Scope));
                CryptographicOperations.ZeroMemory(sql); CryptographicOperations.ZeroMemory(roots);
            }
            finally { await Replace(original); foreach (var bytes in new[] { child, original, hostile, signature }) CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}
