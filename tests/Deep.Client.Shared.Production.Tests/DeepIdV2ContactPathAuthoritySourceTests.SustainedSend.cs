using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public Task Did2SustainedSend_PublicSendCrosses512WithoutResetAndPreservesColdExactReplay() =>
        CheckSustainedSendAsync(ProtectedDid2MailboxSendJournal.MaximumEntries + 1);

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public Task Did2SustainedSend_ConnectedPendingUnknownAndRejectedRetryPreserveOneEffect() =>
        CheckSustainedSendAsync(Did2CompactionPlan.MaximumRows + 1);

    private static async Task CheckSustainedSendAsync(int sendsToComplete)
    {
        // Real owned commands, native ratchets, SQLCipher, signed grant/Store
        // evidence and automatic maintenance. In-process services, not devices.
        // This qualifies the send boundary, not128 distinct grant namespaces.
        await using var fixture = await Fixture.CreateAsync(withPeer: true,
            encryptedStorage: true, longMailboxWindow: true);
        static byte[] Operation(string purpose, int index) =>
            SHA256.HashData(Encoding.UTF8.GetBytes("S04/sustained-send/" + purpose + "/" + index));
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Operation("hello", 0));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Operation("accept", 0)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(),
            ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var handle = await fixture.ReadAutomaticMaintenanceConversation(sender);
        var feedback = 0;
        OwnedStoreFixture? first = null;
        byte[]? firstOperation = null;
        for (var index = 0; index < sendsToComplete; index++)
        {
            var operation = await fixture.QueueAutomaticMaintenanceText(handle, "sustained text " + index);
            var transport = new OwnedStoreFixture(fixture, sender, operation, null);
            // A new transport instance may issue an actual successor; it must
            // not return another request's cached grant if renewal is needed.
            var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
            if (index == sendsToComplete - 1)
                await fixture.CheckSustainedSendBoundaryAsync(handle, sender, receiver, operation,
                    "sustained text " + index, grants, transport);
            else
                _ = await fixture.SendAutomaticMaintenanceText(handle, operation, "sustained text " + index,
                    grants, transport);
            fixture.AdvanceSyntheticMailboxClockPast(transport.DurableTimeForFixture);
            Assert.Equal(index == sendsToComplete - 1 ? 2 : 1, transport.Calls);
            first ??= transport;
            firstOperation ??= operation.ToArray();
            using (var received = await fixture.ReceiveOwnedMessage(receiver,
                transport.StoredEnvelope!.Ciphertext.ToArray())) { }
            if ((index + 1) % 4 == 0)
            {
                using var reply = await fixture.CreateOwnedText(receiver, "sustained feedback " + feedback);
                var replyOperation = reply.OperationId.ToArray();
                using var sent = await fixture.SendOwnedMessage(receiver, replyOperation,
                    ApplicationCoreCodec.DecodeDmc2(reply.ExactDmc2.Span));
                using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
                feedback++;
            }
            if ((index + 1) % Did2CompactionPlan.MaximumRows != 0) continue;
            fixture.ColdReopenCompactionStorage();
            await fixture.AssertSenderCompactionIdle(sender);
            using var retained = await fixture.ReadMailboxSends();
            Assert.InRange(retained.Entries.Count, 1, Did2CompactionPlan.MaximumRows);
            Assert.InRange(retained.Floors.Count, 1, ProtectedDid2MailboxSendJournal.MaximumFloors);
        }
        fixture.ColdReopenCompactionStorage();
        await fixture.AssertSustainedSendHistory(sender, sendsToComplete, feedback);
        await fixture.AssertSustainedSendHistory(receiver, feedback, sendsToComplete);
        var beforeReplay = await fixture.ReadAutomaticMaintenanceFloorDigest(sender);
        var replayGrants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var cached = await fixture.SendAutomaticMaintenanceText(handle, firstOperation!,
            "sustained text 0", replayGrants, first!);
        Assert.False(cached.IngressDispatched);
        Assert.Equal(0, replayGrants.Calls);
        Assert.Equal(1, first!.Calls);
        Assert.Equal(beforeReplay, await fixture.ReadAutomaticMaintenanceFloorDigest(sender));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendAutomaticMaintenanceText(handle,
            firstOperation!, "changed compacted text", replayGrants, first));
        using (var received = await fixture.ReceiveOwnedMessage(receiver, first.StoredEnvelope!.Ciphertext.ToArray())) { }
        await fixture.AssertSustainedSendHistory(receiver, feedback, sendsToComplete);
        CryptographicOperations.ZeroMemory(beforeReplay);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckSustainedSendBoundaryAsync(DeepIdV2Conversation conversation,
            Did2MessagingSessionScope sender, Did2MessagingSessionScope receiver, byte[] operation,
            string text, OwnedGrantTransport grants, OwnedStoreFixture transport)
        {
            var before = await ReadAutomaticMaintenanceFloorDigest(sender);
            byte[] prepared = [];
            try
            {
                ColdReopenCompactionStorage();
                // A rejected changed-command retry cannot author or dispatch.
                // This is local rejection, not a fabricated remote terminal.
                await Assert.ThrowsAsync<CryptographicException>(() => SendAutomaticMaintenanceText(
                    conversation, operation, text + " changed", grants, transport));
                Assert.Equal(before, await ReadAutomaticMaintenanceFloorDigest(sender));
                Assert.Equal(0, grants.Calls); Assert.Equal(0, transport.Calls);
                var hit = false;
                using (Did2MailboxSendTestHooks.Push(point =>
                {
                    if (point != Did2MailboxSendFailpoint.BeforeDispatch) return;
                    hit = true; throw new IOException("Interrupted sustained send before ingress.");
                }))
                    await Assert.ThrowsAsync<IOException>(() => SendAutomaticMaintenanceText(
                        conversation, operation, text, grants, transport));
                Assert.True(hit); Assert.Equal(0, transport.Calls);
                prepared = await ReadAutomaticMaintenanceFloorDigest(sender);
                using (var sends = await ReadMailboxSends())
                    Assert.True(Assert.Single(sends.Entries.Values, entry => entry.Operation.SequenceEqual(operation)).Prepared);
                Assert.Equal(operation, Assert.Single(await ListNativePendingText()).LogicalOperation.ToArray());

                ColdReopenCompactionStorage();
                // Expire only the existing retry lease in the controlled signed
                // fixture clock. Neither request nor logical deadline is renewed.
                Sample += 40; ProofTime += 40;
                transport.LoseReply = true;
                await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() =>
                    SendAutomaticMaintenanceText(conversation, operation, text, grants, transport));
                Assert.Equal(1, transport.Calls);
                Assert.Equal(prepared, await ReadAutomaticMaintenanceFloorDigest(sender));
                using (var received = await ReceiveOwnedMessage(receiver,
                    transport.StoredEnvelope!.Ciphertext.ToArray())) { }
                ColdReopenCompactionStorage();
                await Assert.ThrowsAsync<ClientMailboxRetryLeaseException>(() =>
                    SendAutomaticMaintenanceText(conversation, operation, text, grants, transport));
                Assert.Equal(1, transport.Calls);
                Sample += 40; ProofTime += 40; transport.LoseReply = false;
                _ = await SendAutomaticMaintenanceText(conversation, operation, text, grants, transport);
                Assert.Equal(2, transport.Calls);
                Assert.Equal(prepared, await ReadAutomaticMaintenanceFloorDigest(sender));
                ColdReopenCompactionStorage();
                var cached = await SendAutomaticMaintenanceText(conversation, operation, text, grants, transport);
                Assert.False(cached.IngressDispatched); Assert.Equal(2, transport.Calls);
                Assert.Equal(prepared, await ReadAutomaticMaintenanceFloorDigest(sender));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(prepared);
            }
        }

        internal async Task AssertSustainedSendHistory(Did2MessagingSessionScope scope, int outgoing, int incoming)
        {
            // Public history/receipt APIs return at most100 items. Check that
            // real bounded projection too, but never mistake it for all rows.
            Assert.Equal(Math.Min(100, outgoing + incoming), (await ListOwnedMessages(scope)).Count);
            Assert.Equal(Math.Min(100, incoming), (await ListOwnedReceiptObligations(scope)).Count);
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var read = connection.CreateCommand();
                read.CommandText = "SELECT i.exact_dmc2,i.exact_dmc2_hash,i.author_account_id,f.incumbent_hash FROM authenticated_dmc2_inbox i LEFT JOIN authenticated_dmc2_inbox_forks f USING(conversation_id,logical_message_id,author_device_id) WHERE i.conversation_id=$conversation AND i.content_kind=$kind;";
                read.Parameters.AddWithValue("$conversation", scope.Conversation.ToArray());
                read.Parameters.AddWithValue("$kind", (int)Dmc2ContentKind.MessageCreate);
                var local = new HashSet<string>(StringComparer.Ordinal);
                var remote = new HashSet<string>(StringComparer.Ordinal);
                using (var rows = read.ExecuteReader())
                {
                    while (rows.Read())
                    {
                        Assert.True(rows.IsDBNull(3));
                        var exact = rows.GetFieldValue<byte[]>(0);
                        var digest = rows.GetFieldValue<byte[]>(1);
                        var author = rows.GetFieldValue<byte[]>(2);
                        try
                        {
                            Assert.True(CryptographicOperations.FixedTimeEquals(SHA256.HashData(exact), digest));
                            var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
                            Assert.True(parsed.ConversationId.Span.SequenceEqual(scope.Conversation));
                            Assert.True(parsed.SenderAccountId.Span.SequenceEqual(author));
                            var owned = author.AsSpan().SequenceEqual(scope.LocalAccount);
                            Assert.True(owned || author.AsSpan().SequenceEqual(scope.RemoteAccount));
                            Assert.True(parsed.SenderDeviceId.Span.SequenceEqual(owned ? scope.LocalDevice : scope.RemoteDevice));
                            var text = Assert.IsType<MessageCreateDmc2Payload>(parsed.ParsedPayload).Text;
                            Assert.True((owned ? local : remote).Add(text));
                            Assert.True(local.Count + remote.Count <= outgoing + incoming);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(exact);
                            CryptographicOperations.ZeroMemory(digest);
                            CryptographicOperations.ZeroMemory(author);
                        }
                    }
                }
                Assert.Equal(outgoing, local.Count);
                Assert.Equal(incoming, remote.Count);
                Assert.True(local.SetEquals(Enumerable.Range(0, outgoing).Select(index =>
                    (scope.IsInitiator ? "sustained text " : "sustained feedback ") + index)));
                Assert.True(remote.SetEquals(Enumerable.Range(0, incoming).Select(index =>
                    (scope.IsInitiator ? "sustained feedback " : "sustained text ") + index)));
                read.CommandText = "SELECT count(*) FROM direct_application_receipt_obligations WHERE conversation_id=$conversation;";
                Assert.Equal((long)incoming, read.ExecuteScalar());
                read.CommandText = "SELECT count(*) FROM direct_application_receipt_obligations r LEFT JOIN authenticated_dmc2_inbox i USING(conversation_id,logical_message_id,author_device_id) WHERE r.conversation_id=$conversation AND (i.exact_dmc2_hash IS NULL OR i.exact_dmc2_hash<>r.exact_dmc2_hash OR i.author_account_id<>r.author_account_id OR r.local_device_id<>$device);";
                read.Parameters.AddWithValue("$device", scope.LocalDevice.ToArray());
                Assert.Equal(0L, read.ExecuteScalar());
            });
        }
    }
}
