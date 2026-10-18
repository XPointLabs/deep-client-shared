using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2Groups_OwnedBatchNativeReceiveColdHistoryAndReplayInBothDirections()
    {
        // Actual account/SQLCipher/native crypto with independently signed
        // fixture proofs. This is NOT socket transport, Store or ACK evidence.
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x91));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var alice = await fixture.EnsureSenderMessaging(init, hello);
        var bob = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(bob, Bytes(32, 0x92)))
        using (var sent = await fixture.SendOwnedMessage(bob, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(alice, sent.ExactEnvelope.ToArray())) { }
        var group = Convert.FromHexString(await fixture.Accounts.CreateGroupAsync("native group", fixture.Source()));
        await fixture.PrepareGroupAction(alice, "invite", group);
        await fixture.PrepareGroupAction(alice, "invite", group); // Resume retained invitation, never remint.
        await Transfer(alice, bob);
        Assert.Equal("Invited", Assert.Single(await fixture.AccountsForPeer().ListGroupsAsync()).State);
        var beforePrematureSend = await fixture.ReadMessagingFloor(bob);
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.PrepareGroupAction(bob, "send", group, "not a member yet"));
        Assert.Equal(SHA256.HashData(beforePrematureSend.Exact.Span), SHA256.HashData((await fixture.ReadMessagingFloor(bob)).Exact.Span));
        await fixture.PrepareGroupAction(bob, "accept", group); await Transfer(bob, alice);
        Assert.Equal("Accepted", Assert.Single(await fixture.Accounts.ListGroupsAsync()).State);
        await fixture.PrepareGroupAction(alice, "advance", group); await Transfer(alice, bob);
        Assert.Equal("Active", Assert.Single(await fixture.Accounts.ListGroupsAsync()).State);
        Assert.Equal("Active", Assert.Single(await fixture.AccountsForPeer().ListGroupsAsync()).State);
        await fixture.PrepareGroupAction(alice, "invite", group);
        await fixture.PrepareGroupAction(bob, "accept", group); // Exact original work survives activation.
        await fixture.PrepareGroupAction(alice, "send", group, "native A to B"); await Transfer(alice, bob);
        await fixture.PrepareGroupAction(bob, "send", group, "native B to A"); await Transfer(bob, alice);
        foreach (var account in new[] { fixture.ReopenAccount(), fixture.AccountsForPeer() })
        {
            var messages = await account.ListGroupMessagesAsync(group);
            Assert.Equal(2, messages.Count); Assert.Single(messages, item => item.IsLocalAuthor);
            Assert.Contains(messages, item => item.Text == "native A to B"); Assert.Contains(messages, item => item.Text == "native B to A");
        }

        async Task Transfer(Did2MessagingSessionScope sender, Did2MessagingSessionScope receiver)
        {
            var batch = await fixture.ReadGroupBatch(sender, group);
            try
            {
                foreach (var item in batch.Where(item => !item.NativeCommitted))
                {
                    Assert.True(item.Adopted); // Adopted command != committed native or Store.
                    if (ApplicationCoreCodec.DecodeDmc2(item.Event).ContentKind == Dmc2ContentKind.GroupApplicationMessage)
                    {
                        var changed = item.Event.ToArray(); changed[^1] ^= 1;
                        var before = await fixture.ReadMessagingFloor(sender);
                        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendOwnedMessage(sender, item.Operation, ApplicationCoreCodec.DecodeDmc2(changed)));
                        Assert.Equal(SHA256.HashData(before.Exact.Span), SHA256.HashData((await fixture.ReadMessagingFloor(sender)).Exact.Span));
                    }
                    using var native = await fixture.SendOwnedMessage(sender, item.Operation, ApplicationCoreCodec.DecodeDmc2(item.Event));
                    using (var received = await fixture.ReceiveOwnedMessage(receiver, native.ExactEnvelope.ToArray())) { }
                    using (var replay = await fixture.ReceiveOwnedMessage(receiver, native.ExactEnvelope.ToArray())) { }
                }
                var reopened = await fixture.ReadGroupBatch(sender, group);
                try
                {
                    Assert.All(reopened, item => Assert.True(item.NativeCommitted));
                    Assert.Equal(batch.Select(item => Convert.ToHexString(SHA256.HashData(item.Operation))), reopened.Select(item => Convert.ToHexString(SHA256.HashData(item.Operation))));
                    Assert.Equal(batch.Select(item => Convert.ToHexString(SHA256.HashData(item.Event))), reopened.Select(item => Convert.ToHexString(SHA256.HashData(item.Event))));
                }
                finally { Clear(reopened); }
            }
            finally { Clear(batch); }
        }
        static void Clear(IReadOnlyList<ProtectedDid2GroupJournal.Outgoing> batch)
        { foreach (var item in batch) foreach (var bytes in new[] { item.Group, item.Operation, item.Scope, item.Event }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private sealed partial class Fixture
    {
        private ProtectedDeepIdV2AccountOwner GroupOwner(Did2MessagingSessionScope scope)
        {
            var path = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            return new(scope.IsInitiator ? storage : peerStorage, new DeepIdV2AccountFileLease(Path.Combine(path, "deep-store-v2-account.lock")),
                Path.Combine(path, "deep-store-v2-account.dsv2"), Network, 1);
        }
        internal async Task PrepareGroupAction(Did2MessagingSessionScope scope, string action, byte[] group, string? text = null)
        {
            var account = scope.IsInitiator ? Accounts : peerAccounts!; var source = Source(account);
            var pair = await source.VerifyForOwnMessagingAsync(account, scope, default);
            using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            _ = await GroupOwner(scope).GroupActionAsync(1000, verifier, action, group, scope, text, pair.Own, pair.Peer, source, default);
        }
        internal async Task<IReadOnlyList<ProtectedDid2GroupJournal.Outgoing>> ReadGroupBatch(Did2MessagingSessionScope scope, byte[] group)
        {
            using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            return await GroupOwner(scope).ReadGroupBatchAsync(1000, verifier, group, scope, default);
        }
    }
}
