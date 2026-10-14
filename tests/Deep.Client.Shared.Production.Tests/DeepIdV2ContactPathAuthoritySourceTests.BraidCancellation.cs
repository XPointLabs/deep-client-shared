using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task OwnedBraidRecovery_CancellationBeforeAndAcrossEveryOwnedCommitHandoverPreservesExactRetry()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (alice, bob) = await PrepareRouteFaultPair(fixture);
        var counts = new[] { (await fixture.ListOwnedMessages(alice)).Count, (await fixture.ListOwnedMessages(bob)).Count };
        var aliceBefore = await fixture.ReadMessagingFloor(alice);
        var callbackHit = false;
        using (var cancelled = new CancellationTokenSource())
        using (Did2MessagingCommitTestHooks.Push(_ => callbackHit = true))
        {
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.SendOwnedBraid(alice, Bytes(32, 200), cancelled.Token));
        }
        Assert.False(callbackHit);
        Assert.Equal(aliceBefore.Exact.ToArray(), (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
        using var header = await fixture.SendOwnedBraid(alice, Bytes(32, 200));
        var bobBefore = await fixture.ReadMessagingFloor(bob);
        using (var cancelled = new CancellationTokenSource())
        using (Did2MessagingCommitTestHooks.Push(_ => callbackHit = true))
        {
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.ReceiveOwnedBraid(bob, header.ExactControl.ToArray(), cancelled.Token));
        }
        Assert.False(callbackHit);
        Assert.Equal(bobBefore.Exact.ToArray(), (await fixture.ReadMessagingFloor(bob)).Exact.ToArray());
        using (var received = await fixture.ReceiveOwnedBraid(bob, header.ExactControl.ToArray())) { }

        byte[] incoming = [];
        var covered = new HashSet<(bool Receive, Did2MessagingCommitFailpoint Point)>();
        try
        {
            // One actual four-flight exchange covers send AND receive at each
            // native commit handover, without six redundant account setups.
            foreach (var step in new[] {
                         (Scope: bob, Receive: false, Id: (byte)201, Point: Did2MessagingCommitFailpoint.AfterPending),
                         (Scope: alice, Receive: true, Id: (byte)201, Point: Did2MessagingCommitFailpoint.AfterPending),
                         (Scope: alice, Receive: false, Id: (byte)202, Point: Did2MessagingCommitFailpoint.AfterSql),
                         (Scope: bob, Receive: true, Id: (byte)202, Point: Did2MessagingCommitFailpoint.AfterSql),
                         (Scope: bob, Receive: false, Id: (byte)203, Point: Did2MessagingCommitFailpoint.AfterStable),
                         (Scope: alice, Receive: true, Id: (byte)203, Point: Did2MessagingCommitFailpoint.AfterStable) })
            {
                var before = await fixture.ReadMessagingFloor(step.Scope);
                byte[]? staged = null; var hit = false;
                Task<OwnedDid2BraidControlPersistedEvent> Invoke(CancellationToken ct) => step.Receive
                    ? fixture.ReceiveOwnedBraid(step.Scope, incoming, ct)
                    : fixture.SendOwnedBraid(step.Scope, Bytes(32, step.Id), ct);
                try
                {
                    using (var cancellation = new CancellationTokenSource())
                    using (Did2MessagingCommitTestHooks.PushAsync(async point =>
                    {
                        if (point == Did2MessagingCommitFailpoint.AfterPending)
                            staged = await fixture.ReadStagedBraidControlForTest(step.Scope);
                        if (point == step.Point) { hit = true; cancellation.Cancel(); }
                    }))
                        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                        { using var unexpectedlyReturned = await Invoke(cancellation.Token); });
                    Assert.True(hit); Assert.NotNull(staged);
                    Assert.True(covered.Add((step.Receive, step.Point)));
                    var interrupted = await fixture.ReadMessagingFloor(step.Scope);
                    Assert.Equal(step.Point == Did2MessagingCommitFailpoint.AfterStable ? (byte)1 : (byte)2, interrupted.Phase);
                    fixture.ColdReopenBraidStorage(step.Scope);
                    using var recovered = await Invoke(default);
                    Assert.Equal(staged, recovered.ExactControl.ToArray());
                    Assert.Equal(step.Receive ? 4 : 3, recovered.Direction);
                    var after = await fixture.ReadMessagingFloor(step.Scope);
                    Assert.Equal((byte)1, after.Phase); Assert.Equal(before.Ordinal + 1, after.Ordinal);
                    Assert.Equal(before.RatchetGeneration + 1, after.RatchetGeneration);
                    using var retry = await Invoke(default);
                    Assert.Equal(recovered.Ordinal, retry.Ordinal);
                    Assert.Equal(staged, retry.ExactControl.ToArray());
                    Assert.Equal(after.Exact.ToArray(), (await fixture.ReadMessagingFloor(step.Scope)).Exact.ToArray());
                    if (!step.Receive)
                    {
                        CryptographicOperations.ZeroMemory(incoming);
                        incoming = recovered.ExactControl.ToArray();
                    }
                }
                finally { if (staged is not null) CryptographicOperations.ZeroMemory(staged); }
            }
            Assert.Equal(6, covered.Count);
            foreach (var point in Enum.GetValues<Did2MessagingCommitFailpoint>())
            { Assert.Contains((false, point), covered); Assert.Contains((true, point), covered); }
            Assert.Equal(counts[0], (await fixture.ListOwnedMessages(alice)).Count);
            Assert.Equal(counts[1], (await fixture.ListOwnedMessages(bob)).Count);
            await SendBraidHistoryText(fixture, alice, bob, 210);
            await SendBraidHistoryText(fixture, bob, alice, 211);
        }
        finally { CryptographicOperations.ZeroMemory(incoming); }
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]> ReadStagedBraidControlForTest(Did2MessagingSessionScope scope)
        {
            // The test hook runs under the real account lease after the
            // protected write has completed. Read only the public staged frame;
            // never reacquire that lease, export TRS1 or author a replacement.
            var secure = scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage;
            var checkpoint = new Did2MessagingProtectedCheckpoint(secure, scope);
            var floor = await checkpoint.ReadAsync(default);
            using var pending = await checkpoint.ReadPendingAsync(floor, default);
            using var mutation = pending.Use(bytes => OwnedDid2MessagingMutation.RecoverProtectedPending(scope, floor, bytes));
            Assert.Equal((byte)5, mutation.Kind);
            return mutation.Envelope.ToArray();
        }
        internal void ColdReopenBraidStorage(Did2MessagingSessionScope scope)
        {
            if (scope.IsInitiator) Assert.IsType<CompactionDiskFixtureStorage>(innerStorage).Reopen();
            else Assert.IsType<CompactionDiskFixtureStorage>(peerStorage).Reopen();
        }
    }
}
