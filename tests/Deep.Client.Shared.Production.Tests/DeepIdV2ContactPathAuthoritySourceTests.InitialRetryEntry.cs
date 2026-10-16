using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("draft", false)] [InlineData("unknown-claim", false)] [InlineData("completed-source", false)]
    [InlineData("draft", true)] [InlineData("unknown-claim", true)] [InlineData("completed-source", true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2InitialRetryEntry_ActualExpiryPrecedesPeerResolutionAndColdResumes(string stage, bool lostReply)
    {
        // Real PQ/SQLCipher/owned draft and cancellation state. In-process signed
        // services only; no physical delivery or arbitrary UI stop is proven.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        var intent = Bytes(32, 0xb6);
        var prepared = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: stage == "completed-source" ? null : stage);
        if (stage == "completed-source") using (var completed = await prepared.Complete(fixture.ReopenAccount())) { }
        var deadline = Did2ControlWorkStop.ProvenExpirySecond(prepared.Init.ExpiresAtUnixMilliseconds);
        await fixture.AdvanceInitialExpiryToLowerBoundary(deadline - 1);
        fixture.RejectContactRetryRecipient(initial: true);
        var grants = new OwnedGrantTransport(fixture); var transport = new RejectInitialDispatchFactory();
        var before = await fixture.ReadInitialStopGuardDigest();
        try
        {
            var overlap = await Record.ExceptionAsync(() => fixture.StartNativeContact(intent, grants, transport));
            Assert.NotNull(overlap); Assert.IsNotType<DeepIdV2ContactRetryExpiredException>(overlap);
            var afterOverlap = await fixture.ReadInitialStopGuardDigest();
            try { Assert.True(CryptographicOperations.FixedTimeEquals(before, afterOverlap)); }
            finally { CryptographicOperations.ZeroMemory(afterOverlap); }
            Assert.False(Assert.Single(await fixture.ReopenAccount().ListContactStartOperationsAsync()).IsStopped);
            var reads = fixture.RejectedContactRetryReadCalls; var proofs = fixture.RejectedContactRetryProofCalls;
            fixture.ProofTime++; fixture.Sample++;
            Assert.Equal(deadline, (await fixture.ReadPreSessionExpiryProof()).Lower);
            var hit = false;
            using (Did2MailboxSendTestHooks.Push(point =>
            {
                if (lostReply && point == Did2MailboxSendFailpoint.AfterWorkStopRoot)
                { hit = true; throw new IOException("Lost owned expiry entry reply."); }
            }))
            {
                if (lostReply) await Assert.ThrowsAsync<IOException>(() => fixture.StartNativeContact(intent, grants, transport));
                else await Assert.ThrowsAsync<DeepIdV2ContactRetryExpiredException>(() => fixture.StartNativeContact(intent, grants, transport));
            }
            Assert.Equal(lostReply, hit);
            fixture.ColdReopenCompactionStorage();
            await Assert.ThrowsAsync<DeepIdV2ContactRetryExpiredException>(() => fixture.StartNativeContact(intent, grants, transport));
            await fixture.AssertPreSessionCancelled(intent, reason: ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired);
            Assert.Equal(reads, fixture.RejectedContactRetryReadCalls); Assert.Equal(proofs, fixture.RejectedContactRetryProofCalls);
            Assert.Equal(0, grants.Calls); Assert.Equal(0, transport.Calls);
            var closed = Assert.Single(await fixture.ReopenAccount().ListContactStartOperationsAsync());
            Assert.Equal(intent, closed.LogicalIntent.ToArray()); Assert.True(closed.IsStopped);
            await Assert.ThrowsAsync<IOException>(() => fixture.BeginPreClaimAsync(intent));
        }
        finally { CryptographicOperations.ZeroMemory(before); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2InitialRetryEntry_AuthenticatedStoredResultWinsAfterApplicationExpiry()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(isInitial: true);
        var stored = await test.Deliver();
        var operation = Assert.Single(await fixture.ReopenAccount().ListContactStartOperationsAsync());
        await fixture.AdvanceInitialExpiryToLowerBoundary(Did2ControlWorkStop.ProvenExpirySecond(operation.ExpiresAtUnixMilliseconds));
        fixture.RejectContactRetryRecipient(initial: true);
        var grants = test.Grants.Calls; var forwards = test.Transport.Calls;
        var recovered = await fixture.StartNativeContact(test.Intent, test.Grants, test.Transport);
        Assert.Equal(stored.Cursor, recovered.StorageReceipt.Cursor);
        Assert.Equal(stored.Disposition, recovered.StorageReceipt.Disposition);
        Assert.Equal(stored.EntryRouterId.ToArray(), recovered.StorageReceipt.EntryRouterId.ToArray());
        Assert.False(recovered.StorageReceipt.IngressDispatched);
        Assert.False(Assert.Single(await fixture.ReopenAccount().ListContactStartOperationsAsync()).IsStopped);
        Assert.Equal(grants, test.Grants.Calls); Assert.Equal(forwards, test.Transport.Calls);
        Assert.Equal(0, fixture.RejectedContactRetryReadCalls); Assert.Equal(0, fixture.RejectedContactRetryProofCalls);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2InitialRetryEntry_ImportedUnknownUsesNativeStopAndColdRecovers(bool lostReply)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(isInitial: true);
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterPreparedRoot) throw new IOException("Interrupted original Initial."); }))
            await Assert.ThrowsAsync<IOException>(test.Deliver);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var source = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        using var retained = await fixture.ReadMailboxSends(own: true);
        var original = Assert.Single(retained.Entries).Value.Exact.ToArray();
        try
        {
            var operation = Assert.Single(await fixture.ReopenAccount().ListContactStartOperationsAsync());
            await fixture.AdvanceInitialExpiryToLowerBoundary(Did2ControlWorkStop.ProvenExpirySecond(operation.ExpiresAtUnixMilliseconds));
            fixture.RejectContactRetryRecipient(initial: true);
            var grants = test.Grants.Calls; var forwards = test.Transport.Calls; var hit = false;
            using (Did2MailboxSendTestHooks.Push(point =>
            {
                if (lostReply && point == Did2MailboxSendFailpoint.AfterWorkStopRoot)
                { hit = true; throw new IOException("Lost native Initial expiry reply."); }
            }))
            {
                if (lostReply) await Assert.ThrowsAsync<IOException>(() => fixture.StartNativeContact(test.Intent, test.Grants, test.Transport));
                else await Assert.ThrowsAsync<DeepIdV2ContactRetryExpiredException>(() => fixture.StartNativeContact(test.Intent, test.Grants, test.Transport));
            }
            Assert.Equal(lostReply, hit);
            fixture.ColdReopenCompactionStorage();
            await Assert.ThrowsAsync<DeepIdV2ContactRetryExpiredException>(() => fixture.StartNativeContact(test.Intent, test.Grants, test.Transport));
            await fixture.AssertControlStopMetadata(test, ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired);
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(source, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
            using var after = await fixture.ReadMailboxSends(own: true);
            Assert.Equal(original, Assert.Single(after.Entries).Value.Exact.ToArray());
            Assert.Equal(grants, test.Grants.Calls); Assert.Equal(forwards, test.Transport.Calls);
            Assert.Equal(0, fixture.RejectedContactRetryReadCalls); Assert.Equal(0, fixture.RejectedContactRetryProofCalls);
        }
        finally { foreach (var bytes in new[] { native, source, original }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
