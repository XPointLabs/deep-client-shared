using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class DurableInboxRecoveryTests
{
    private const string AlicePhrase = "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed";
    private const string BobPhrase = "update vague zinger boxes ornament renting glass gained island nabbing afield calamity nabbing";
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-10T10:00:00Z");

    [Theory]
    [InlineData(InboxCrashPoint.BeforeStage)]
    [InlineData(InboxCrashPoint.AfterStage)]
    [InlineData(InboxCrashPoint.AfterPrepare)]
    public async Task E2eeInbox_RestartRecoversEveryRetrieveStageDecodeBoundary(InboxCrashPoint crashPoint)
    {
        var statePath = NewSqlitePath();
        var raw = new CursorRawTransport();
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        await SendEncryptedDirectAsync(raw, aliceIdentity, bobIdentity, "boundary-message");

        try
        {
            using (var store = new SqliteSessionStore(statePath))
            using (var receiver = new E2eeClientTransport(
                       raw,
                       _ => Task.FromResult<string?>(BobPhrase),
                       new FrozenClock(Now),
                       new FaultingInboxRepository(store, crashPoint),
                       new DirectP2pMailboxDeliveryPolicy()))
            {
                await Assert.ThrowsAsync<InjectedInboxCrashException>(() =>
                    receiver.ReceiveAsync(bobIdentity.SessionId));
            }

            using var restartedStore = new SqliteSessionStore(statePath);
            using var restarted = new E2eeClientTransport(
                raw,
                _ => Task.FromResult<string?>(BobPhrase),
                new FrozenClock(Now),
                restartedStore,
                new DirectP2pMailboxDeliveryPolicy());

            var recovered = Assert.Single(await restarted.ReceiveAsync(bobIdentity.SessionId));
            Assert.Equal("boundary-message", recovered.Id.Value);
            var scope = new DurableInboxScope(bobIdentity.SessionId, 0);
            Assert.Equal(raw.LastHashFor(bobIdentity.SessionId), await restartedStore.GetInboxCursorAsync(scope));
            Assert.Equal(1, await restartedStore.CountPendingInboxItemsAsync(scope));

            await restarted.AcknowledgeInboxItemAsync(bobIdentity.SessionId, recovered.ServerHash);
            Assert.Equal(0, await restartedStore.CountPendingInboxItemsAsync(scope));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task OfficialMailboxAck_RemoteSuccessBeforeLocalCrashRetriesIdempotently()
    {
        var raw = new CursorRawTransport();
        var official = new OpaqueAckTransport(raw);
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        await SendEncryptedDirectAsync(raw, aliceIdentity, bobIdentity, "remote-ack-boundary");
        var store = new InMemorySessionStore();
        using var receiver = new E2eeClientTransport(
            official,
            _ => Task.FromResult<string?>(BobPhrase),
            new FrozenClock(Now),
            new FaultingInboxRepository(store, InboxCrashPoint.BeforeAck),
            new DirectP2pMailboxDeliveryPolicy());

        var received = Assert.Single(await receiver.ReceiveAsync(bobIdentity.SessionId));
        await Assert.ThrowsAsync<InjectedInboxCrashException>(() =>
            receiver.AcknowledgeInboxItemAsync(bobIdentity.SessionId, received.ServerHash));
        Assert.Equal(1, official.RemoteAckCount);
        Assert.Equal(1, await store.CountPendingInboxItemsAsync(
            new DurableInboxScope(bobIdentity.SessionId, official.InboxNamespace)));

        await receiver.AcknowledgeInboxItemAsync(bobIdentity.SessionId, received.ServerHash);
        Assert.Equal(2, official.RemoteAckCount);
        Assert.Equal(0, await store.CountPendingInboxItemsAsync(
            new DurableInboxScope(bobIdentity.SessionId, official.InboxNamespace)));
    }

    [Fact]
    public async Task MessageService_RestartAfterDomainAppendBeforeAckIsIdempotent()
    {
        var statePath = NewSqlitePath();
        var raw = new CursorRawTransport();
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        await SendEncryptedDirectAsync(raw, aliceIdentity, bobIdentity, "domain-boundary");

        try
        {
            using (var store = new SqliteSessionStore(statePath))
            using (var receiver = new E2eeClientTransport(
                       raw,
                       _ => Task.FromResult<string?>(BobPhrase),
                       new FrozenClock(Now),
                       store,
                       new DirectP2pMailboxDeliveryPolicy()))
            {
                var faultingTransport = new FaultingAckTransport(receiver);
                var messages = CreateMessageService(store, faultingTransport);

                await Assert.ThrowsAsync<InjectedInboxCrashException>(() =>
                    messages.ReceiveAsync(bobIdentity.SessionId));

                Assert.NotNull(await store.GetAsync(MessageId.Parse("domain-boundary")));
                Assert.Equal(
                    [new PendingIncomingMessageNotification(
                        MessageId.Parse("domain-boundary"),
                        ConversationId.ForOneToOne(aliceIdentity.SessionId))],
                    await messages.ListPendingIncomingMessageNotificationIdsAsync(16));
                Assert.Equal(
                    1,
                    await store.CountPendingInboxItemsAsync(new DurableInboxScope(bobIdentity.SessionId, 0)));
            }

            using (var restartedStore = new SqliteSessionStore(statePath))
            using (var restartedTransport = new E2eeClientTransport(
                       raw,
                       _ => Task.FromResult<string?>(BobPhrase),
                       new FrozenClock(Now),
                       restartedStore,
                       new DirectP2pMailboxDeliveryPolicy()))
            {
                var messages = CreateMessageService(restartedStore, restartedTransport);
                Assert.Empty(await messages.ReceiveAsync(bobIdentity.SessionId));
                Assert.Equal(
                    0,
                    await restartedStore.CountPendingInboxItemsAsync(new DurableInboxScope(bobIdentity.SessionId, 0)));
                Assert.Single(await ToListAsync(
                    ((IMessageRepository)restartedStore).ListForConversationAsync(
                        ConversationId.ForOneToOne(aliceIdentity.SessionId))));
                Assert.Equal(
                    [new PendingIncomingMessageNotification(
                        MessageId.Parse("domain-boundary"),
                        ConversationId.ForOneToOne(aliceIdentity.SessionId))],
                    await messages.ListPendingIncomingMessageNotificationIdsAsync(16));
            }

            using var finalStore = new SqliteSessionStore(statePath);
            using var finalTransport = new E2eeClientTransport(
                raw,
                _ => Task.FromResult<string?>(BobPhrase),
                new FrozenClock(Now),
                finalStore,
                new DirectP2pMailboxDeliveryPolicy());
            var finalMessages = CreateMessageService(finalStore, finalTransport);
            Assert.Empty(await finalMessages.ReceiveAsync(bobIdentity.SessionId));
            Assert.Single(await ToListAsync(
                ((IMessageRepository)finalStore).ListForConversationAsync(
                    ConversationId.ForOneToOne(aliceIdentity.SessionId))));
            Assert.Equal(
                [new PendingIncomingMessageNotification(
                    MessageId.Parse("domain-boundary"),
                    ConversationId.ForOneToOne(aliceIdentity.SessionId))],
                await finalMessages.ListPendingIncomingMessageNotificationIdsAsync(16));

            await finalMessages.MarkIncomingMessageNotificationsPresentedAsync(
                [MessageId.Parse("domain-boundary")]);
            Assert.Empty(await finalMessages.ListPendingIncomingMessageNotificationIdsAsync(16));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task MalformedStagedEntryIsDiscardedWithoutBlockingFollowingMessage()
    {
        var raw = new CursorRawTransport();
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        raw.Enqueue(new InboundMessageEnvelope(
            MessageId.Parse("malformed-outer"),
            aliceIdentity.SessionId,
            bobIdentity.SessionId,
            "plaintext is not DPE1",
            [],
            Now,
            null,
            "wire-malformed"));
        await SendEncryptedDirectAsync(raw, aliceIdentity, bobIdentity, "valid-after-malformed");
        var store = new InMemorySessionStore();
        using var receiver = new E2eeClientTransport(
            raw,
            _ => Task.FromResult<string?>(BobPhrase),
            new FrozenClock(Now),
            store,
            new DirectP2pMailboxDeliveryPolicy());

        var received = Assert.Single(await receiver.ReceiveAsync(bobIdentity.SessionId));
        Assert.Equal("valid-after-malformed", received.Id.Value);
        await receiver.AcknowledgeInboxItemAsync(bobIdentity.SessionId, received.ServerHash);

        var scope = new DurableInboxScope(bobIdentity.SessionId, 0);
        Assert.Equal(0, await store.CountPendingInboxItemsAsync(scope));
        Assert.Equal(received.ServerHash, await store.GetInboxCursorAsync(scope));
        Assert.Empty(await receiver.ReceiveAsync(bobIdentity.SessionId));
    }

    [Fact]
    public async Task ReactionWaitsWithoutAckUntilTargetArrivesInFollowingRawBatch()
    {
        var raw = new CursorRawTransport { MaxEntriesPerRetrieve = 1 };
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        using (var sender = new E2eeClientTransport(
                   raw,
                   _ => Task.FromResult<string?>(AlicePhrase),
                   new FrozenClock(Now),
                   new InMemorySessionStore(),
                   new DirectP2pMailboxDeliveryPolicy()))
        {
            await sender.SendAsync(new OutboundMessageEnvelope(
                aliceIdentity.SessionId,
                bobIdentity.SessionId,
                string.Empty,
                [],
                Now,
                null,
                MessageId.Parse("reaction-before-target"),
                Reaction: new MessageReactionUpdate(
                    MessageId.Parse("late-target"),
                    "ok",
                    Remove: false)));
            await sender.SendAsync(new OutboundMessageEnvelope(
                aliceIdentity.SessionId,
                bobIdentity.SessionId,
                "late target body",
                [],
                Now.AddMilliseconds(1),
                null,
                MessageId.Parse("late-target")));
        }

        var store = new InMemorySessionStore();
        using var receiver = new E2eeClientTransport(
            raw,
            _ => Task.FromResult<string?>(BobPhrase),
            new FrozenClock(Now.AddSeconds(1)),
            store,
            new DirectP2pMailboxDeliveryPolicy());
        var messages = CreateMessageService(store, receiver);

        Assert.Empty(await messages.ReceiveAsync(bobIdentity.SessionId));
        Assert.Equal(1, await store.CountPendingInboxItemsAsync(
            new DurableInboxScope(bobIdentity.SessionId, 0)));

        var applied = await messages.ReceiveAsync(bobIdentity.SessionId);
        var target = await store.GetAsync(MessageId.Parse("late-target"));

        Assert.Equal(2, applied.Count);
        Assert.NotNull(target);
        Assert.Collection(target!.ReactionItems, reaction =>
        {
            Assert.Equal(aliceIdentity.SessionId, reaction.Reactor);
            Assert.Equal("ok", reaction.Emoji);
        });
        Assert.Equal(0, await store.CountPendingInboxItemsAsync(
            new DurableInboxScope(bobIdentity.SessionId, 0)));
    }

    private static MessageService CreateMessageService(
        ILocalSessionStore store,
        ISessionMessageTransport transport)
    {
        var groupSync = (IGroupSyncTransport)transport;
        var clock = new FrozenClock(Now);
        var conversations = new ConversationService(
            store,
            store,
            store,
            store,
            clock,
            ClientFeatureFlags.Defaults,
            groupSync);
        var network = new MessageNetworkRuntime(store, transport, groupSync, null);
        return new MessageService(conversations, store, store, store, clock, network);
    }

    private static async Task SendEncryptedDirectAsync(
        CursorRawTransport raw,
        SessionIdentityProvider sender,
        SessionIdentityProvider recipient,
        string messageId)
    {
        using var transport = new E2eeClientTransport(
            raw,
            _ => Task.FromResult<string?>(AlicePhrase),
            new FrozenClock(Now),
            new InMemorySessionStore(),
            new DirectP2pMailboxDeliveryPolicy());
        await transport.SendAsync(new OutboundMessageEnvelope(
            sender.SessionId,
            recipient.SessionId,
            "durable body",
            [],
            Now,
            null,
            MessageId.Parse(messageId)));
    }

    private static async Task<IReadOnlyList<T>> ToListAsync<T>(IAsyncEnumerable<T> source)
    {
        var result = new List<T>();
        await foreach (var item in source)
        {
            result.Add(item);
        }

        return result;
    }

    private static string NewSqlitePath() =>
        Path.Combine(Path.GetTempPath(), $"deep-client-inbox-recovery-{Guid.NewGuid():N}.db");

    private static void DeleteSqliteFiles(string statePath)
    {
        foreach (var path in new[] { statePath, statePath + "-wal", statePath + "-shm" })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    public enum InboxCrashPoint
    {
        BeforeStage,
        AfterStage,
        AfterPrepare,
        BeforeAck
    }

    private sealed class InjectedInboxCrashException : Exception;

    private sealed class FaultingInboxRepository(
        IDurableInboxRepository inner,
        InboxCrashPoint crashPoint) : IDurableInboxRepository
    {
        private int faulted;

        public Task<string?> GetInboxCursorAsync(DurableInboxScope scope, CancellationToken cancellationToken = default) =>
            inner.GetInboxCursorAsync(scope, cancellationToken);

        public async Task<DurableInboxStageResult> StageInboxBatchAsync(
            DurableInboxScope scope,
            string? expectedCursor,
            string? nextCursor,
            IReadOnlyList<DurableInboxWireEntry> entries,
            CancellationToken cancellationToken = default)
        {
            ThrowOnce(InboxCrashPoint.BeforeStage);
            var result = await inner.StageInboxBatchAsync(
                scope,
                expectedCursor,
                nextCursor,
                entries,
                cancellationToken);
            ThrowOnce(InboxCrashPoint.AfterStage);
            return result;
        }

        public Task<IReadOnlyList<DurableInboxItem>> ListStagedInboxItemsAsync(
            DurableInboxScope scope,
            int limit,
            CancellationToken cancellationToken = default) =>
            inner.ListStagedInboxItemsAsync(scope, limit, cancellationToken);

        public async Task<DurableInboxPrepareResult> PrepareInboxItemAsync(
            DurableInboxScope scope,
            string serverHash,
            DurableInboxDecodedMetadata decoded,
            CancellationToken cancellationToken = default)
        {
            var result = await inner.PrepareInboxItemAsync(scope, serverHash, decoded, cancellationToken);
            ThrowOnce(InboxCrashPoint.AfterPrepare);
            return result;
        }

        public Task<IReadOnlyList<DurableInboxItem>> ListDecodedInboxItemsAsync(
            DurableInboxScope scope,
            DurableInboxItemKind kind,
            string? routeKey,
            int limit,
            CancellationToken cancellationToken = default) =>
            inner.ListDecodedInboxItemsAsync(scope, kind, routeKey, limit, cancellationToken);

        public Task<DurableInboxAckResult> AcknowledgeInboxItemAsync(
            DurableInboxScope scope,
            string serverHash,
            CancellationToken cancellationToken = default)
        {
            ThrowOnce(InboxCrashPoint.BeforeAck);
            return inner.AcknowledgeInboxItemAsync(scope, serverHash, cancellationToken);
        }

        public Task DiscardInboxItemAsync(
            DurableInboxScope scope,
            string serverHash,
            CancellationToken cancellationToken = default) =>
            inner.DiscardInboxItemAsync(scope, serverHash, cancellationToken);

        public Task<int> CountPendingInboxItemsAsync(
            DurableInboxScope scope,
            CancellationToken cancellationToken = default) =>
            inner.CountPendingInboxItemsAsync(scope, cancellationToken);

        public Task<MessageReplayClaimResult> TryClaimAsync(
            SessionId sender,
            MessageId messageId,
            string envelopeDigest,
            DateTimeOffset protocolExpiresAt,
            CancellationToken cancellationToken = default) =>
            inner.TryClaimAsync(sender, messageId, envelopeDigest, protocolExpiresAt, cancellationToken);

        public Task<int> PruneExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default) =>
            inner.PruneExpiredAsync(now, cancellationToken);

        private void ThrowOnce(InboxCrashPoint point)
        {
            if (crashPoint == point && Interlocked.Exchange(ref faulted, 1) == 0)
            {
                throw new InjectedInboxCrashException();
            }
        }
    }

    private sealed class FaultingAckTransport(E2eeClientTransport inner) :
        ISessionMessageTransport,
        IGroupSyncTransport,
        IDurableInboxAcknowledger
    {
        private int faulted;

        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            inner.SendAsync(envelope, cancellationToken);

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            inner.ReceiveAsync(recipient, cancellationToken);

        public Task PublishGroupStateAsync(
            Group group,
            DateTimeOffset updatedAt,
            IEnumerable<SessionId>? recipients = null,
            CancellationToken cancellationToken = default) =>
            inner.PublishGroupStateAsync(group, updatedAt, recipients, cancellationToken);

        public Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
            SessionId member,
            CancellationToken cancellationToken = default) =>
            inner.ReceiveGroupStatesAsync(member, cancellationToken);

        public Task SendGroupMessageAsync(
            OutboundGroupMessageEnvelope envelope,
            CancellationToken cancellationToken = default) =>
            inner.SendGroupMessageAsync(envelope, cancellationToken);

        public Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
            ConversationId groupId,
            CancellationToken cancellationToken = default) =>
            inner.ReceiveGroupMessagesAsync(groupId, cancellationToken);

        public Task AcknowledgeInboxItemAsync(
            SessionId account,
            string serverHash,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref faulted, 1) == 0)
            {
                throw new InjectedInboxCrashException();
            }

            return inner.AcknowledgeInboxItemAsync(account, serverHash, cancellationToken);
        }
    }

    private sealed class CursorRawTransport :
        IDirectP2pSessionMessageTransport,
        IAuthenticatedInboxTransport
    {
        private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
        private readonly object gate = new();
        private readonly Dictionary<SessionId, List<InboundMessageEnvelope>> inboxes = [];
        private int nextHash;

        public int InboxNamespace => 0;

        public int MaxEntriesPerRetrieve { get; init; } = DurableInboxLimits.MaxBatchCount;

        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
        {
            var hash = $"wire-{Interlocked.Increment(ref nextHash)}";
            var inbound = new InboundMessageEnvelope(
                envelope.Id ?? MessageId.NewId(),
                envelope.Sender,
                envelope.Recipient,
                envelope.Body,
                envelope.Attachments,
                envelope.CreatedAt,
                envelope.ExpiresAt,
                hash,
                envelope.ReplyTo,
                envelope.Reaction);
            lock (gate)
            {
                AddCore(inbound);
            }

            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity,
            CancellationToken cancellationToken = default)
        {
            lock (gate)
            {
                return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>(
                    inboxes.GetValueOrDefault(identity.SessionId)?.ToArray() ?? []);
            }
        }

        public Task<AuthenticatedInboxBatch> RetrieveAuthenticatedAsync(
            SessionIdentityProvider identity,
            string? cursor,
            int limit,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                var values = inboxes.GetValueOrDefault(identity.SessionId) ?? [];
                var start = 0;
                if (cursor is not null)
                {
                    var cursorIndex = values.FindIndex(item =>
                        string.Equals(item.ServerHash, cursor, StringComparison.Ordinal));
                    start = cursorIndex < 0 ? values.Count : cursorIndex + 1;
                }

                var entries = values
                    .Skip(start)
                    .Take(Math.Min(limit, MaxEntriesPerRetrieve))
                    .Select(static envelope => DurableInboxWireEntry.Create(
                        envelope.ServerHash,
                        envelope.CreatedAt.ToUnixTimeMilliseconds(),
                        JsonSerializer.Serialize(envelope, JsonOptions)))
                    .ToArray();
                return Task.FromResult(new AuthenticatedInboxBatch(
                    entries,
                    entries.Length == 0 ? cursor : entries[^1].ServerHash));
            }
        }

        public void Enqueue(InboundMessageEnvelope envelope)
        {
            lock (gate)
            {
                AddCore(envelope);
            }
        }

        public string LastHashFor(SessionId recipient)
        {
            lock (gate)
            {
                return inboxes[recipient][^1].ServerHash;
            }
        }

        private void AddCore(InboundMessageEnvelope envelope)
        {
            if (!inboxes.TryGetValue(envelope.Recipient, out var inbox))
            {
                inbox = [];
                inboxes.Add(envelope.Recipient, inbox);
            }

            inbox.Add(envelope);
        }
    }

    private sealed class OpaqueAckTransport(CursorRawTransport inner) :
        IAuthenticatedOpaqueMailboxTransport,
        IAuthenticatedInboxTransport
    {
        private int remoteAckCount;
        public int RemoteAckCount => Volatile.Read(ref remoteAckCount);
        public int InboxNamespace => 0x4d32;

        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            inner.SendAsync(envelope, cancellationToken);
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient, CancellationToken cancellationToken = default) =>
            inner.ReceiveAsync(recipient, cancellationToken);
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity, CancellationToken cancellationToken = default) =>
            inner.ReceiveAuthenticatedAsync(identity, cancellationToken);
        public Task<AuthenticatedInboxBatch> RetrieveAuthenticatedAsync(
            SessionIdentityProvider identity, string? cursor, int limit,
            CancellationToken cancellationToken = default) =>
            inner.RetrieveAuthenticatedAsync(identity, cursor, limit, cancellationToken);
        public bool TryDecodeInboxEntry(
            DurableInboxWireEntry entry, SessionId recipient, out InboundMessageEnvelope envelope) =>
            ((IAuthenticatedInboxTransport)inner).TryDecodeInboxEntry(entry, recipient, out envelope);
        public Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>> PrepareScopedMailboxBatchAsync(
            IMailboxOperationSigner signer, IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task SendPreparedMailboxAuthenticatedAsync(
            IPreparedMailboxAuthenticatedSend preparedSend,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<OpaqueMailboxInboxPage> RetrieveOpaqueMailboxInboxAsync(
            IMailboxOperationSigner signer, OpaqueMailboxContinuation continuation,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task AcknowledgeOpaqueMailboxInboxAsync(
            IMailboxOperationSigner signer, string opaqueItemHandle,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref remoteAckCount);
            return Task.CompletedTask;
        }
    }
}
