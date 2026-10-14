using System.Net;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true, "none")] [InlineData(false, "none")]
    [InlineData(true, "BeforeClosureRoot")] [InlineData(false, "BeforeClosureRoot")]
    [InlineData(true, "AfterClosureRoot")] [InlineData(false, "AfterClosureRoot")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ContactRetryExpiry_OriginalUnknownClosesBeforeUnavailableRecipientAndColdResumes(bool initial, string fault)
    {
        // Real PQ/native/SQLCipher/owned grants; signed in-process services,
        // not device E2E. No prepared request is sent or reminted after expiry.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterPreparedRoot) throw new IOException("Interrupted original contact request."); }))
            await Assert.ThrowsAsync<IOException>(test.Deliver);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var source = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        byte[] original;
        using (var sends = await fixture.ReadMailboxSends(own: initial))
        {
            var entry = Assert.Single(sends.Entries).Value; original = entry.Exact.ToArray();
            var delta = checked(entry.RetryUntil + 6 - fixture.CurrentProofTime);
            fixture.Sample = checked(fixture.Sample + delta); fixture.ProofTime = checked(fixture.ProofTime + delta);
        }
        fixture.RejectContactRetryRecipient(initial);
        var calls = test.Grants.Calls;
        var hit = false;
        using (Did2MailboxSendTestHooks.Push(point =>
            {
                if (point.ToString() == fault)
                { hit = true; throw new IOException("Interrupted contact-only retry closure."); }
            }))
            await Assert.ThrowsAsync<IOException>(test.Deliver);
        Assert.Equal(fault != "none", hit);
        if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
        await Assert.ThrowsAsync<IOException>(test.Deliver);
        using (var sends = await fixture.ReadMailboxSends(own: initial))
        {
            var entry = Assert.Single(sends.Entries).Value;
            Assert.True(entry.Closed); Assert.True(entry.Prepared); Assert.False(entry.HasSuccessor);
            Assert.Equal(original[..296], entry.Exact[..296].ToArray());
            Assert.True(entry.ClosedAtLower >= entry.RetryUntil);
            Assert.Equal(2UL, sends.MinimumCounter(entry.GrantHash));
        }
        Assert.Equal(0, fixture.RejectedContactRetryProofCalls);
        Assert.Equal(0, fixture.RejectedContactRetryReadCalls);
        Assert.Equal(calls, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        Assert.Equal(source, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
        await fixture.AssertControlStopMetadata(test, ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired);
        foreach (var bytes in new[] { original, source, native }) CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        private byte[]? rejectedContactRetryLeaf;
        private bool rejectContactRetryRead;
        internal int RejectedContactRetryProofCalls { get; private set; }
        internal int RejectedContactRetryReadCalls { get; private set; }
        internal void RejectContactRetryRecipient(bool initial)
        {
            rejectedContactRetryLeaf = (initial ? peerCheckpoint! : checkpoint).Checkpoint.DirectoryLeafKey.ToArray();
            rejectContactRetryRead = true;
        }
        private bool RejectContactRetryProof(ReadOnlySpan<byte> leaf)
        {
            if (rejectedContactRetryLeaf is null || !leaf.SequenceEqual(rejectedContactRetryLeaf)) return false;
            RejectedContactRetryProofCalls++; return true;
        }
        internal void RequireContactRetryReadAvailable()
        {
            if (!rejectContactRetryRead) return;
            RejectedContactRetryReadCalls++;
            throw new IOException("Fixture recipient contact read is unavailable.");
        }
    }
}
