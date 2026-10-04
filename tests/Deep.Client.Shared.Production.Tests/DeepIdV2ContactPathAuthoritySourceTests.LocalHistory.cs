using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    private sealed partial class Fixture
    {
        // Runs after the actual two-account send/receive/ACK cycle. Every call
        // reopens the real account owner/SQLCipher; no manufactured UI handles.
        internal async Task VerifyOfflineNativeHistory(Did2MessagingSessionScope sender,
            Did2MessagingSessionScope receiver, string expectedText)
        {
            var sample = Sample;
            var reject = RejectProof;
            Sample += 1_000; RejectProof = true;
            var requests = ProofRequests;
            try
            {
                foreach (var scope in new[] { sender, receiver })
                {
                    var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
                    var snapshot = Assert.Single(await account.ListConversationsAsync());
                    Assert.Equal(scope.IsInitiator ? DeepIdV2ContactState.PeerAcceptanceRetained :
                        DeepIdV2ContactState.LocalAcceptanceRetained, snapshot.ContactState);
                    var message = Assert.Single(await account.ListMessagesAsync(snapshot.Conversation));
                    Assert.Equal(expectedText, message.Text);
                    Assert.Equal(scope.IsInitiator, message.IsLocalAuthor);
                    var foreign = scope.IsInitiator ? ReopenGrantReader() : ReopenAccount();
                    await Assert.ThrowsAsync<CryptographicException>(() => foreign.ListMessagesAsync(snapshot.Conversation));
                    using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => account.ListMessagesAsync(snapshot.Conversation, cancelled.Token));
                }
                Assert.Equal(requests, ProofRequests);
                // Missing protected peer custody is not treated as an empty
                // conversation and cannot be recreated by an offline reader.
                var slot = ProtectedDid2MessagingPeerBootstrap.Slot(receiver);
                using var retained = await peerStorage.ReadOwnedAsync(slot) ?? throw new InvalidOperationException();
                var bytes = retained.Use(value => value.ToArray());
                try
                {
                    var account = ReopenGrantReader();
                    var handle = Assert.Single(await account.ListConversationsAsync()).Conversation;
                    await peerStorage.DeleteBatchAsync([slot]);
                    await Assert.ThrowsAsync<InvalidDataException>(() => account.ListConversationsAsync());
                    await Assert.ThrowsAsync<InvalidDataException>(() => account.ListMessagesAsync(handle));
                    using var absent = await peerStorage.ReadOwnedAsync(slot); Assert.Null(absent);
                }
                finally
                {
                    await peerStorage.WriteBatchAsync([new DeepSecureStorageWrite(slot, bytes)]);
                    CryptographicOperations.ZeroMemory(bytes);
                }
                Assert.Equal(expectedText, Assert.Single(await ListNativeApplicationMessages(receiver)).Text);
                Assert.Equal(requests, ProofRequests);
            }
            finally { Sample = sample; RejectProof = reject; }
            // Local acceptance is only display metadata: send still requires
            // fresh independently authenticated authority, before transport.
            RejectProof = true;
            try
            {
                var grants = new OwnedGrantTransport(this, ownerOnPrimary: true);
                var terminal = new RejectInitialDispatchFactory();
                await Assert.ThrowsAnyAsync<IOException>(() => SendNativeText(sender, Bytes(32, 0xd1),
                    "must not send offline", grants, terminal));
                Assert.Equal(0, grants.Calls); Assert.Equal(0, terminal.Calls);
            }
            finally { RejectProof = reject; }
        }
    }
}
