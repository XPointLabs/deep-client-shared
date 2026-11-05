using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

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
                    var selected = await account.GetConversationAsync(snapshot.Conversation.ConversationId);
                    Assert.Equal(snapshot.ContactState, selected.ContactState);
                    Assert.Equal(snapshot.Conversation.Scope.Exact.ToArray(), selected.Conversation.Scope.Exact.ToArray());
                    await Assert.ThrowsAsync<InvalidOperationException>(() => account.GetConversationAsync(new string('0', 64)));
                    await Assert.ThrowsAsync<ArgumentException>(() => account.GetConversationAsync("not-a-conversation"));
                    using (var cancelledSelection = new CancellationTokenSource())
                    {
                        cancelledSelection.Cancel();
                        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => account.GetConversationAsync(
                            snapshot.Conversation.ConversationId, cancelledSelection.Token));
                    }
                    Assert.Equal(scope.IsInitiator ? DeepIdV2ContactState.PeerAcceptanceRetained :
                        DeepIdV2ContactState.LocalAcceptanceRetained, snapshot.ContactState);
                    var message = Assert.Single(await account.ListMessagesAsync(snapshot.Conversation));
                    Assert.Equal(expectedText, message.Text);
                    Assert.Equal(scope.IsInitiator, message.IsLocalAuthor);
                    Assert.Equal(message, Assert.Single(await account.ListRecentMessagesAsync(snapshot.Conversation, 1)));
                    Assert.Equal(message, Assert.Single(await account.ListRecentMessagesAsync(snapshot.Conversation.ConversationId, 1)));
                    await Assert.ThrowsAsync<InvalidOperationException>(() => account.ListRecentMessagesAsync(new string('0', 64), 1));
                    await Assert.ThrowsAsync<ArgumentException>(() => account.ListRecentMessagesAsync("not-a-conversation", 1));
                    await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => account.ListRecentMessagesAsync(snapshot.Conversation.ConversationId, 0));
                    await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => account.ListRecentMessagesAsync(snapshot.Conversation.ConversationId, 101));
                    if ((scope.IsInitiator ? innerStorage : peerStorage) is CompactionDiskFixtureStorage disk)
                        await VerifySelectedRecentReadWork(account, snapshot.Conversation.ConversationId, message, disk, scope.IsInitiator);
                    await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => account.ListRecentMessagesAsync(snapshot.Conversation, 0));
                    await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => account.ListRecentMessagesAsync(snapshot.Conversation, 101));
                    var foreign = scope.IsInitiator ? ReopenGrantReader() : ReopenAccount();
                    await Assert.ThrowsAsync<CryptographicException>(() => foreign.ListMessagesAsync(snapshot.Conversation));
                    await Assert.ThrowsAsync<CryptographicException>(() => foreign.ListRecentMessagesAsync(snapshot.Conversation, 1));
                    using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => account.ListMessagesAsync(snapshot.Conversation, cancelled.Token));
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => account.ListRecentMessagesAsync(snapshot.Conversation, 1, cancelled.Token));
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => account.ListRecentMessagesAsync(snapshot.Conversation.ConversationId, 1, cancelled.Token));
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
                    // An absent selector must not open this unrelated broken
                    // session; selecting that session must still fail closed.
                    await Assert.ThrowsAsync<InvalidOperationException>(() => account.GetConversationAsync(new string('0', 64)));
                    await Assert.ThrowsAsync<InvalidDataException>(() => account.ListConversationsAsync());
                    await Assert.ThrowsAsync<InvalidDataException>(() => account.GetConversationAsync(handle.ConversationId));
                    await Assert.ThrowsAsync<InvalidDataException>(() => account.ListMessagesAsync(handle));
                    await Assert.ThrowsAsync<InvalidDataException>(() => account.ListRecentMessagesAsync(handle, 1));
                    await Assert.ThrowsAsync<InvalidOperationException>(() => account.ListRecentMessagesAsync(new string('0', 64), 1));
                    await Assert.ThrowsAsync<InvalidDataException>(() => account.ListRecentMessagesAsync(handle.ConversationId, 1));
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
                await Assert.ThrowsAnyAsync<IOException>(() => QueueNativeText(sender, "must not send offline"));
                Assert.Equal(0, grants.Calls); Assert.Equal(0, terminal.Calls);
            }
            finally { RejectProof = reject; }
        }

        internal async Task VerifySelectedRecentConsentTampering(Did2MessagingSessionScope sender, Did2MessagingSessionScope receiver)
        {
            var proofRequests = ProofRequests;
            var receiverAccount = ReopenGrantReader();
            var receiverId = Convert.ToHexString(receiver.Conversation);
            var receiverFloor = (await ReadMessagingFloor(receiver)).Exact.ToArray();
            using var marker = await peerStorage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot) ?? throw new InvalidDataException();
            var originalMarker = marker.Use(bytes => bytes.ToArray());
            var emptyMarker = ProtectedDid2ContactAcceptJournal.Empty(receiver.Network, receiver.LocalAccount, receiver.Instance);
            try
            {
                Assert.True(await peerStorage.CompareExchangeAsync(ProtectedDid2ContactAcceptJournal.Slot, originalMarker, emptyMarker));
                await Assert.ThrowsAsync<InvalidOperationException>(() => receiverAccount.ListRecentMessagesAsync(new string('0', 64), 1));
                var selectedFailure = await Record.ExceptionAsync(() => receiverAccount.ListRecentMessagesAsync(receiverId, 1));
                Assert.True(selectedFailure is CryptographicException or InvalidDataException, selectedFailure?.GetType().Name ?? "No rejection");
                var previousFailure = await Record.ExceptionAsync(() => receiverAccount.GetConversationAsync(receiverId));
                Assert.True(previousFailure is CryptographicException or InvalidDataException, previousFailure?.GetType().Name ?? "No rejection");
                Assert.Equal(receiverFloor, (await ReadMessagingFloor(receiver)).Exact.ToArray());
            }
            finally
            {
                Assert.True(await peerStorage.CompareExchangeAsync(ProtectedDid2ContactAcceptJournal.Slot, emptyMarker, originalMarker));
                CryptographicOperations.ZeroMemory(receiverFloor); CryptographicOperations.ZeroMemory(originalMarker); CryptographicOperations.ZeroMemory(emptyMarker);
            }
            Assert.Equal(3, (await receiverAccount.ListRecentMessagesAsync(receiverId, 100)).Count);

            var senderAccount = ReopenAccount();
            var senderId = Convert.ToHexString(sender.Conversation);
            var senderFloor = (await ReadMessagingFloor(sender)).Exact.ToArray();
            byte[] logical = [], changed = Bytes(32, 0xa9);
            await WithOwnedApplicationConnectionAsync(true, Network, sender.LocalAccount.ToArray(), sql =>
            {
                using var query = sql.CreateCommand();
                query.CommandText = "SELECT logical_message_id FROM authenticated_dmc2_inbox WHERE conversation_id=$conversation AND author_device_id=$device AND content_kind=$kind;";
                query.Parameters.AddWithValue("$conversation", sender.Conversation.ToArray()); query.Parameters.AddWithValue("$device", sender.RemoteDevice.ToArray());
                query.Parameters.AddWithValue("$kind", (int)Dmc2ContentKind.ContactAccept);
                logical = Assert.IsType<byte[]>(query.ExecuteScalar()); Assert.Equal(32, logical.Length);
            });
            async Task ReplaceLogical(byte[] before, byte[] after)
            {
                await WithOwnedApplicationConnectionAsync(true, Network, sender.LocalAccount.ToArray(), sql =>
                {
                    using var update = sql.CreateCommand();
                    update.CommandText = "UPDATE authenticated_dmc2_inbox SET logical_message_id=$after WHERE conversation_id=$conversation AND author_device_id=$device AND logical_message_id=$before AND content_kind=$kind;";
                    update.Parameters.AddWithValue("$conversation", sender.Conversation.ToArray()); update.Parameters.AddWithValue("$device", sender.RemoteDevice.ToArray());
                    update.Parameters.AddWithValue("$kind", (int)Dmc2ContentKind.ContactAccept); update.Parameters.AddWithValue("$before", before); update.Parameters.AddWithValue("$after", after);
                    Assert.Equal(1, update.ExecuteNonQuery());
                });
            }
            await ReplaceLogical(logical, changed);
            try
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() => senderAccount.ListRecentMessagesAsync(new string('0', 64), 1));
                var selectedFailure = await Record.ExceptionAsync(() => senderAccount.ListRecentMessagesAsync(senderId, 1));
                Assert.True(selectedFailure is CryptographicException or InvalidDataException, selectedFailure?.GetType().Name ?? "No rejection");
                var previousFailure = await Record.ExceptionAsync(() => senderAccount.GetConversationAsync(senderId));
                Assert.True(previousFailure is CryptographicException or InvalidDataException, previousFailure?.GetType().Name ?? "No rejection");
                Assert.Equal(senderFloor, (await ReadMessagingFloor(sender)).Exact.ToArray());
            }
            finally
            {
                await ReplaceLogical(changed, logical);
                CryptographicOperations.ZeroMemory(senderFloor); CryptographicOperations.ZeroMemory(logical); CryptographicOperations.ZeroMemory(changed);
            }
            Assert.Equal(3, (await senderAccount.ListRecentMessagesAsync(senderId, 100)).Count);
            Assert.Equal(proofRequests, ProofRequests);
        }

        private static async Task VerifySelectedRecentReadWork(DeepIdV2AccountService account, string conversationId,
            DirectMessageCreateSnapshot expected, CompactionDiskFixtureStorage disk, bool initiator)
        {
            // Both paths are warm on the same encrypted synthetic profile.
            // Include the CLI's common GetCurrent gate in each API chain.
            // Count managed work; this is not a timing or delivery benchmark.
            Assert.NotNull(await account.GetCurrentAsync());
            _ = await account.ListRecentMessagesAsync(conversationId, 1);
            var before = disk.ReadWorkSnapshot();
            long baselineOpens;
            using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
            {
                Assert.NotNull(await account.GetCurrentAsync());
                var selected = await account.GetConversationAsync(conversationId);
                Assert.Equal(expected, Assert.Single(await account.ListRecentMessagesAsync(selected.Conversation, 1)));
                baselineOpens = work.Opens;
            }
            var baseline = disk.ReadWorkSnapshot();
            long selectedOpens;
            using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
            {
                Assert.NotNull(await account.GetCurrentAsync());
                Assert.Equal(expected, Assert.Single(await account.ListRecentMessagesAsync(conversationId, 1)));
                selectedOpens = work.Opens;
            }
            var selectedRead = disk.ReadWorkSnapshot();
            var baselineManifests = baseline.ManifestReads - before.ManifestReads;
            var selectedManifests = selectedRead.ManifestReads - baseline.ManifestReads;
            Assert.True(selectedOpens < baselineOpens);
            Assert.True(selectedManifests < baselineManifests);
            var artifactDirectory = Path.Combine(AppContext.BaseDirectory, "artifacts"); Directory.CreateDirectory(artifactDirectory);
            await File.WriteAllTextAsync(Path.Combine(artifactDirectory, "selected-recent-history-" + (initiator ? "sender" : "receiver") + ".json"),
                System.Text.Json.JsonSerializer.Serialize(new { baselineOpens, selectedOpens, baselineManifests, selectedManifests }));
        }
    }
}
