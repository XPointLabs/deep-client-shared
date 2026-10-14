using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task OwnedBraidRecovery_ExhaustedPeersRecoverWithColdSqlAndOriginalPendingData()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (alice, bob) = await PrepareRouteFaultPair(fixture);
        var pending = new List<(Did2MessagingSessionScope Recipient, byte[] Cipher)>();
        try
        {
            foreach (var (sender, recipient, start) in new[] { (alice, bob, (byte)1), (bob, alice, (byte)50) })
                for (var index = 0; index < 32; index++)
                {
                    using var draft = await fixture.CreateOwnedText(sender, "owned Braid pending " + index);
                    var op = draft.OperationId.ToArray();
                    try
                    {
                        using var sent = await fixture.SendOwnedMessage(sender, op, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
                        pending.Add((recipient, sent.ExactEnvelope.ToArray()));
                    }
                    catch (CryptographicException error) when
                        (error.Message == "A receive/send gap step omitted mandatory fresh PQ contribution.")
                    {
                        // A preexisting ContactAccept data send may already consume
                        // one of this endpoint's unchanged32 slots.
                        Assert.Equal(31, index); break;
                    }
                }
            Assert.Equal(63, pending.Count); // Plus the already committed ContactAccept: both data32 fences are exhausted.
            foreach (var scope in new[] { alice, bob })
            {
                var before = await fixture.ReadMessagingFloor(scope);
                using var blocked = await fixture.CreateOwnedText(scope, "must await genuine fresh PQ output");
                var op = blocked.OperationId.ToArray();
                var error = await Assert.ThrowsAnyAsync<CryptographicException>(() =>
                    fixture.SendOwnedMessage(scope, op, ApplicationCoreCodec.DecodeDmc2(blocked.ExactDmc2.Span)));
                Assert.Equal("A receive/send gap step omitted mandatory fresh PQ contribution.", error.Message);
                Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(scope)).Exact.ToArray());
            }
            var historyCounts = new[] { (await fixture.ListOwnedMessages(alice)).Count, (await fixture.ListOwnedMessages(bob)).Count };
            foreach (var (sender, recipient, id) in new[] { (alice, bob, (byte)200), (bob, alice, (byte)201),
                         (alice, bob, (byte)202), (bob, alice, (byte)203) })
            {
                using var sent = await fixture.SendOwnedBraid(sender, Bytes(32, id));
                Assert.Equal(3, sent.Direction);
                using var received = await fixture.ReceiveOwnedBraid(recipient, sent.ExactControl.ToArray());
                Assert.Equal(4, received.Direction);
                var floor = await fixture.ReadMessagingFloor(recipient);
                using var replay = await fixture.ReceiveOwnedBraid(recipient, sent.ExactControl.ToArray());
                Assert.Equal(floor.Exact.ToArray(), (await fixture.ReadMessagingFloor(recipient)).Exact.ToArray());
                var senderFloor = await fixture.ReadMessagingFloor(sender);
                using var retry = await fixture.SendOwnedBraid(sender, Bytes(32, id));
                Assert.True(sent.ExactControl.SequenceEqual(retry.ExactControl));
                Assert.Equal(senderFloor.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            }
            Assert.Equal(historyCounts[0], (await fixture.ListOwnedMessages(alice)).Count);
            Assert.Equal(historyCounts[1], (await fixture.ListOwnedMessages(bob)).Count);
            foreach (var (sender, recipient, id) in new[] { (alice, bob, (byte)210), (bob, alice, (byte)211) })
            {
                using var draft = await fixture.CreateOwnedText(sender, "owned fresh data after Braid recovery");
                var op = draft.OperationId.ToArray();
                using var sent = await fixture.SendOwnedMessage(sender, op, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
                using var received = await fixture.ReceiveOwnedMessage(recipient, sent.ExactEnvelope.ToArray());
            }
            foreach (var entry in pending)
            { using var received = await fixture.ReceiveOwnedMessage(entry.Recipient, entry.Cipher); }
        }
        finally { foreach (var entry in pending) CryptographicOperations.ZeroMemory(entry.Cipher); }
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(false, 1)]
    [InlineData(false, 2)]
    [InlineData(true, 0)]
    [InlineData(true, 1)]
    [InlineData(true, 2)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task OwnedBraidRecovery_CrashAtEveryCommitHandoverRetainsExactOperation(bool receive,
        int pointCode)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var point = (Did2MessagingCommitFailpoint)pointCode;
        var (alice, bob) = await PrepareRouteFaultPair(fixture);
        var op = Bytes(32, 200); byte[] exact = [];
        if (receive) { using var sent = await fixture.SendOwnedBraid(alice, op); exact = sent.ExactControl.ToArray(); }
        var scope = receive ? bob : alice; var before = await fixture.ReadMessagingFloor(scope); var hit = false;
        using (Did2MessagingCommitTestHooks.Push(current =>
            { if (current == point) { hit = true; throw new IOException("Injected owned Braid commit handover failure."); } }))
            await Assert.ThrowsAsync<IOException>(async () =>
            {
                using var row = receive ? await fixture.ReceiveOwnedBraid(scope, exact) : await fixture.SendOwnedBraid(scope, op);
            });
        Assert.True(hit);
        using var recovered = receive ? await fixture.ReceiveOwnedBraid(scope, exact) : await fixture.SendOwnedBraid(scope, op);
        var after = await fixture.ReadMessagingFloor(scope);
        Assert.Equal((byte)1, after.Phase); Assert.Equal(before.Ordinal + 1, after.Ordinal);
        Assert.Equal(before.RatchetGeneration + 1, after.RatchetGeneration);
        using var retry = receive ? await fixture.ReceiveOwnedBraid(scope, exact) : await fixture.SendOwnedBraid(scope, op);
        Assert.True(recovered.ExactControl.SequenceEqual(retry.ExactControl));
        Assert.Equal(after.Exact.ToArray(), (await fixture.ReadMessagingFloor(scope)).Exact.ToArray());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task OwnedBraidRecovery_ChangedReplayReflectionAndDataNamespaceCollisionsReject()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (alice, bob) = await PrepareRouteFaultPair(fixture); var op = Bytes(32, 200);
        using var sent = await fixture.SendOwnedBraid(alice, op);
        using var received = await fixture.ReceiveOwnedBraid(bob, sent.ExactControl.ToArray());
        var floor = await fixture.ReadMessagingFloor(bob); var aliceFloor = await fixture.ReadMessagingFloor(alice);
        var changed = sent.ExactControl.ToArray(); changed[^1] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReceiveOwnedBraid(bob, changed));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReceiveOwnedBraid(alice, sent.ExactControl.ToArray()));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendOwnedBraid(bob, op));
        await Assert.ThrowsAsync<IOException>(() => fixture.RetryOwnedText(alice, op, "data author must not reuse a control operation"));
        using var draft = await fixture.CreateOwnedText(alice, "data must not reuse a control operation");
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.SendOwnedMessage(alice, op, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span)));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendOwnedBraid(bob, Bytes(32, 0x92))); // Existing data ContactAccept operation.
        Assert.Equal(aliceFloor.Exact.ToArray(), (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
        Assert.Equal(floor.Exact.ToArray(), (await fixture.ReadMessagingFloor(bob)).Exact.ToArray());
    }

    private sealed partial class Fixture
    {
        private Func<Did2MessagingSessionScope, ReadOnlyMemory<byte>, CancellationToken, Task<OwnedDid2BraidControlPersistedEvent>>? sendOwnedBraidControl;
        private Func<Did2MessagingSessionScope, ReadOnlyMemory<byte>, CancellationToken, Task<OwnedDid2BraidControlPersistedEvent>>? receiveOwnedBraidControl;
        internal Task<OwnedDid2BraidControlPersistedEvent> SendOwnedBraid(Did2MessagingSessionScope scope,
            ReadOnlyMemory<byte> operation, CancellationToken ct = default) => sendOwnedBraidControl!(scope, operation, ct);
        internal Task<OwnedDid2BraidControlPersistedEvent> ReceiveOwnedBraid(Did2MessagingSessionScope scope,
            ReadOnlyMemory<byte> exact, CancellationToken ct = default) => receiveOwnedBraidControl!(scope, exact, ct);
    }
}
