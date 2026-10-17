using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("BeforeSuccessorRoot")]
    [InlineData("AfterSuccessorRoot")]
    [InlineData("AfterSql")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public Task Did2ExpiredAttempt_CurrentGrantSuccessorColdResumesSameNativeCiphertext(string successorFault)
        => RunExpiredAttemptSuccessorAsync(successorFault, false);

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public Task Did2ExpiredAttempt_LostCommittedReplySuccessorHasDistinctTransportKeyAndSameEvent()
        => RunExpiredAttemptSuccessorAsync("AfterSql", true);

    private async Task RunExpiredAttemptSuccessorAsync(string successorFault, bool lostCommittedReply)
    {
        // Real PQ/SQLCipher owners and authenticated control-plane/Store proofs;
        // private transports are in process, not physical network/device E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x84));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x85)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        using var text = await fixture.CreateOwnedText(sender, "same ciphertext after closed admission");
        var operation = text.OperationId.ToArray();
        using var committed = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var oldIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var oldTransport = new OwnedStoreFixture(fixture, sender, operation, committed.ExactEnvelope.ToArray());
        if (lostCommittedReply)
        {
            oldTransport.LoseReply = true;
            await Assert.ThrowsAsync<Deep.Client.Shared.Services.ClientMailboxDispatchOutcomeUnknownException>(
                () => fixture.DeliverNativeMessage(sender, operation, oldIssuer, oldTransport));
        }
        else using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterPreparedRoot) throw new IOException("Interrupted original prepared attempt."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(sender, operation, oldIssuer, oldTransport));
        Assert.Equal(1, oldIssuer.Calls); Assert.Equal(lostCommittedReply ? 1 : 0, oldTransport.Calls);
        byte[] original;
        using (var sends = await fixture.ReadMailboxSends()) original = Assert.Single(sends.Entries).Value.Exact.ToArray();
        using var prior = ProtectedDid2MailboxSendJournal.Entry.Decode(original);
        var originalGrant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
            Deep.Protocol.ContactV1.ContactCodec.Decode("XMC2", oldIssuer.OriginalResponse.Span).Field(8).Span);
        Assert.Equal(originalGrant.ExpiresAtUnixSeconds, prior.AdmissionUntil);
        var nextCenter = checked(prior.AdmissionUntil + 6);
        // Advance the fixture's actual authenticated time, not admission or TTL.
        Assert.True(nextCenter + 5 < 6_000);
        fixture.Sample = checked(fixture.Sample + nextCenter - fixture.ProofTime);
        fixture.ProofTime = nextCenter;
        fixture.ColdReopenCompactionStorage();
        var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        using var authoredBefore = await fixture.ReadAuthoredTextJournalAsync(sender);
        var successorIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, committed.ExactEnvelope.ToArray());
        if (lostCommittedReply) transport.Cursor = 2;
        var failpoint = Enum.Parse<Did2MailboxSendFailpoint>(successorFault);
        var hit = false;
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == failpoint) { hit = true; throw new IOException("Interrupted successor handover."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(sender, operation, successorIssuer, transport));
        Assert.True(hit); Assert.Equal(1, successorIssuer.Calls); Assert.Equal(0, transport.Calls);
        fixture.ColdReopenCompactionStorage();
        var unusedIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var result = await fixture.DeliverNativeMessage(sender, operation, unusedIssuer, transport);
        Assert.NotNull(result.Cursor); Assert.Equal(0, unusedIssuer.Calls); Assert.Equal(1, transport.Calls);
        var childBody = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(
            MailboxAuthenticatedClientRequestCodec.Decode(transport.ExactRequest!).Binding.CanonicalRequest.Span);
        // Transport successors have new operation/cursor contexts. Reusing
        // only H(ciphertext) collides with a possibly committed predecessor's
        // native record. Semantic dedup remains the unchanged E2EE event.
        Assert.NotEqual(SHA256.HashData(committed.ExactEnvelope), childBody.DeduplicationDigest.ToArray());
        if (lostCommittedReply)
        {
            Assert.Equal(oldTransport.StoredEnvelope!.Ciphertext.ToArray(), childBody.Ciphertext.ToArray());
            Assert.NotEqual(oldTransport.StoredEnvelope.DeduplicationDigest.ToArray(), childBody.DeduplicationDigest.ToArray());
            Assert.NotEqual(oldTransport.StoredEnvelope.OperationId.ToArray(), childBody.OperationId.ToArray());
        }
        ulong successfulAt;
        using (var authoredAfter = await fixture.ReadAuthoredTextJournalAsync(sender))
        {
            // Exactly one allowed completion transition, not another authored
            // event/sequence. Stored also commits its first authenticated upper
            // time; every other field and independent floor remains exact.
            Assert.Equal(checked(authoredBefore.Revision + 1), authoredAfter.Revision);
            var before = Assert.Single(authoredBefore.Entries);
            var after = Assert.Single(authoredAfter.Entries);
            Assert.Equal(before.Key, after.Key); Assert.False(before.Value.Pending); Assert.False(before.Value.Stored);
            Assert.False(after.Value.Pending); Assert.True(after.Value.Stored);
            Assert.Equal(before.Value.Exact[..516].ToArray(), after.Value.Exact[..516].ToArray());
            Assert.Equal(before.Value.Exact[517..532].ToArray(), after.Value.Exact[517..532].ToArray());
            Assert.Equal(before.Value.Exact[540..].ToArray(), after.Value.Exact[540..].ToArray());
            Assert.Equal(0UL, before.Value.FirstSuccessfulStoreUpper);
            successfulAt = after.Value.FirstSuccessfulStoreUpper;
            Assert.InRange(successfulAt, transport.DurableTimeForFixture, checked(fixture.CurrentProofTime + 100));
            var floorBefore = Assert.Single(authoredBefore.Floors);
            var floorAfter = Assert.Single(authoredAfter.Floors);
            Assert.Equal(floorBefore.Key, floorAfter.Key);
            Assert.Equal(floorBefore.Value.Scope.Exact.ToArray(), floorAfter.Value.Scope.Exact.ToArray());
            Assert.Equal(floorBefore.Value.NextSequence, floorAfter.Value.NextSequence);
        }
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        using (var sends = await fixture.ReadMailboxSends())
        {
            var chain = sends.Chain(sender.Hash, operation);
            Assert.Equal(2, chain.Count);
            var parent = chain[0]; var child = chain[1];
            Assert.True(parent.Prepared); Assert.True(parent.Closed); Assert.True(parent.HasSuccessor);
            Assert.Equal(original[..296], parent.Exact[..296].ToArray());
            Assert.Equal(parent.Attempt.ToArray(), child.Predecessor.ToArray());
            Assert.Equal(child.Attempt.ToArray(), parent.Successor.ToArray());
            Assert.NotEqual(parent.Attempt.ToArray(), child.Attempt.ToArray());
            Assert.NotEqual(parent.MailboxOperation.ToArray(), child.MailboxOperation.ToArray());
            Assert.NotEqual(parent.GrantHash.ToArray(), child.GrantHash.ToArray());
            Assert.Equal(parent.EnvelopeHash.ToArray(), child.EnvelopeHash.ToArray());
            Assert.Equal(parent.Expires, child.Expires); Assert.Equal(parent.RetryUntil, child.RetryUntil);
            Assert.True(child.Created >= parent.ClosedAtLower); Assert.True(child.Prepared); Assert.False(child.Closed);
            Assert.Equal(2, sends.Floors.Count);
            Assert.Equal(2UL, sends.MinimumCounter(parent.GrantHash)); Assert.Equal(2UL, sends.MinimumCounter(child.GrantHash));
            Assert.Equal(SHA256.HashData(transport.ExactRequest!), child.MauHash.ToArray());
        }
        fixture.AdvanceSyntheticMailboxClockPast(transport.DurableTimeForFixture);
        fixture.ColdReopenCompactionStorage();
        var cached = await fixture.DeliverNativeMessage(sender, operation, unusedIssuer, transport);
        Assert.Equal(result.Cursor, cached.Cursor); Assert.False(cached.IngressDispatched);
        using (var retried = await fixture.ReadAuthoredTextJournalAsync(sender))
            Assert.Equal(successfulAt, Assert.Single(retried.Entries).Value.FirstSuccessfulStoreUpper);
        Assert.Equal(0, unusedIssuer.Calls); Assert.Equal(1, transport.Calls);
        // Actual known child + unknown parent remains a dependency, not a
        // deletion permission. This uses the genuine producer, not an injected
        // structural chain or synthetic success flag.
        byte[] sendsBefore;
        using (var sends = await fixture.ReadMailboxSends())
            sendsBefore = ProtectedDid2MailboxSendJournal.Encode(sends, sender.Network, sender.LocalAccount, sender.Instance);
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        await Assert.ThrowsAsync<IOException>(() => fixture.CompactNativeOrdinaryOutbox(sender, default));
        using (var sends = await fixture.ReadMailboxSends())
            Assert.Equal(sendsBefore, ProtectedDid2MailboxSendJournal.Encode(sends, sender.Network, sender.LocalAccount, sender.Instance));
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Single(await fixture.ListOwnedMessages(sender));
        foreach (var bytes in new[] { original, native, authored, sendsBefore, application }) CryptographicOperations.ZeroMemory(bytes);
    }
}
