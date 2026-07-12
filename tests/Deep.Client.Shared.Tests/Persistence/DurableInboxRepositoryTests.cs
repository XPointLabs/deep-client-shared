using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class DurableInboxRepositoryTests
{
    private const string DigestOne = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string DigestTwo = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private static readonly DateTimeOffset ExpiresAt = DateTimeOffset.Parse("2026-08-01T00:00:00Z");

    [Fact]
    public async Task Stores_StageCursorAndAckAreScopedBoundedAndIdempotent()
    {
        await ForEachStoreAsync(async store =>
        {
            var account = SessionId.CreateNew();
            var otherAccount = SessionId.CreateNew();
            var scope = new DurableInboxScope(account, 0);
            var otherNamespace = new DurableInboxScope(account, 10);
            var otherScope = new DurableInboxScope(otherAccount, 0);
            var entry = DurableInboxWireEntry.Create("storage-hash-1", 101, "wire-payload-1");

            var staged = await store.StageInboxBatchAsync(scope, null, entry.ServerHash, [entry]);
            var repeated = await store.StageInboxBatchAsync(scope, null, entry.ServerHash, [entry]);

            Assert.Equal(1, staged.StagedCount);
            Assert.Equal(0, staged.ExistingCount);
            Assert.Equal(0, repeated.StagedCount);
            Assert.Equal(1, repeated.ExistingCount);
            Assert.Equal(entry.ServerHash, await store.GetInboxCursorAsync(scope));
            Assert.Null(await store.GetInboxCursorAsync(otherNamespace));
            Assert.Null(await store.GetInboxCursorAsync(otherScope));
            Assert.Equal(1, await store.CountPendingInboxItemsAsync(scope));

            var metadata = Metadata(SessionId.CreateNew(), MessageId.NewId(), DigestOne);
            Assert.Equal(
                DurableInboxPrepareResult.Ready,
                await store.PrepareInboxItemAsync(scope, entry.ServerHash, metadata));
            Assert.Single(await store.ListDecodedInboxItemsAsync(
                scope,
                DurableInboxItemKind.DirectMessage,
                routeKey: null,
                limit: 10));

            Assert.Equal(
                DurableInboxAckResult.Applied,
                await store.AcknowledgeInboxItemAsync(scope, entry.ServerHash));
            Assert.Equal(0, await store.CountPendingInboxItemsAsync(scope));
            Assert.Equal(
                MessageReplayClaimResult.DuplicateSameDigest,
                await store.TryClaimAsync(
                    metadata.Sender,
                    metadata.MessageId,
                    metadata.EnvelopeDigest,
                    metadata.ProtocolExpiresAt));
        });
    }

    [Fact]
    public async Task Stores_RejectWireDigestCollisionWithoutAdvancingCursor()
    {
        await ForEachStoreAsync(async store =>
        {
            var scope = new DurableInboxScope(SessionId.CreateNew(), 0);
            var entry = DurableInboxWireEntry.Create("storage-hash-1", 101, "wire-payload-1");
            await store.StageInboxBatchAsync(scope, null, entry.ServerHash, [entry]);
            var collision = DurableInboxWireEntry.Create(entry.ServerHash, entry.StorageTimestamp, "changed-wire-payload");

            await Assert.ThrowsAsync<DurableInboxDigestMismatchException>(() =>
                store.StageInboxBatchAsync(scope, null, collision.ServerHash, [collision]));

            Assert.Equal(entry.ServerHash, await store.GetInboxCursorAsync(scope));
            var stored = Assert.Single(await store.ListStagedInboxItemsAsync(scope, 10));
            Assert.Equal(entry.WireDigest, stored.WireDigest);
        });
    }

    [Fact]
    public async Task Stores_PendingOwnerSuppressesSameDigestAndRejectsDifferentDigestWithoutClaimingEarly()
    {
        await ForEachStoreAsync(async store =>
        {
            var scope = new DurableInboxScope(SessionId.CreateNew(), 0);
            var entries = new[]
            {
                DurableInboxWireEntry.Create("storage-hash-1", 101, "wire-payload-1"),
                DurableInboxWireEntry.Create("storage-hash-2", 102, "wire-payload-2"),
                DurableInboxWireEntry.Create("storage-hash-3", 103, "wire-payload-3")
            };
            await store.StageInboxBatchAsync(scope, null, entries[^1].ServerHash, entries);
            var sender = SessionId.CreateNew();
            var messageId = MessageId.NewId();
            var accepted = Metadata(sender, messageId, DigestOne);

            Assert.Equal(
                DurableInboxPrepareResult.Ready,
                await store.PrepareInboxItemAsync(scope, entries[0].ServerHash, accepted));
            Assert.Equal(
                DurableInboxPrepareResult.DuplicateSameDigest,
                await store.PrepareInboxItemAsync(scope, entries[1].ServerHash, accepted));
            Assert.Equal(
                DurableInboxPrepareResult.RejectedDigestMismatch,
                await store.PrepareInboxItemAsync(
                    scope,
                    entries[2].ServerHash,
                    accepted with { EnvelopeDigest = DigestTwo }));

            Assert.Equal(1, await store.CountPendingInboxItemsAsync(scope));
            Assert.Equal(
                MessageReplayClaimResult.Accepted,
                await store.TryClaimAsync(sender, messageId, DigestOne, ExpiresAt));
            Assert.Single(await store.ListDecodedInboxItemsAsync(
                scope,
                DurableInboxItemKind.DirectMessage,
                routeKey: null,
                limit: 10));
            Assert.Equal(
                DurableInboxAckResult.DuplicateSameDigest,
                await store.AcknowledgeInboxItemAsync(scope, entries[0].ServerHash));
            Assert.Equal(0, await store.CountPendingInboxItemsAsync(scope));
        });
    }

    [Fact]
    public async Task Stores_RejectUnboundedBatch()
    {
        await ForEachStoreAsync(async store =>
        {
            var scope = new DurableInboxScope(SessionId.CreateNew(), 0);
            var entries = Enumerable.Range(0, DurableInboxLimits.MaxBatchCount + 1)
                .Select(index => DurableInboxWireEntry.Create($"hash-{index}", index, $"wire-{index}"))
                .ToArray();

            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
                store.StageInboxBatchAsync(scope, null, entries[^1].ServerHash, entries));
            Assert.Null(await store.GetInboxCursorAsync(scope));
        });
    }

    [Fact]
    public async Task Stores_BulkDiscardUnknownGroupRoutesWithoutTouchingKnownRoutes()
    {
        await ForEachStoreAsync(async store =>
        {
            var scope = new DurableInboxScope(SessionId.CreateNew(), 0);
            var sender = SessionId.CreateNew();
            var retainedRoute = ConversationId.CreateGroupV2().Value;
            var entries = Enumerable.Range(0, 302)
                .Select(index => DurableInboxWireEntry.Create($"group-hash-{index}", index, $"wire-{index}"))
                .ToArray();
            string? cursor = null;
            foreach (var batch in entries.Chunk(DurableInboxLimits.MaxBatchCount))
            {
                await store.StageInboxBatchAsync(scope, cursor, batch[^1].ServerHash, batch);
                cursor = batch[^1].ServerHash;
            }

            for (var index = 0; index < entries.Length; index++)
            {
                var routeKey = index is 17 or 299
                    ? retainedRoute
                    : ConversationId.CreateGroupV2().Value;
                var metadata = Metadata(sender, new MessageId($"group-message-{index}"), DigestOne) with
                {
                    Kind = DurableInboxItemKind.GroupMessage,
                    RouteKey = routeKey
                };
                Assert.Equal(
                    DurableInboxPrepareResult.Ready,
                    await store.PrepareInboxItemAsync(scope, entries[index].ServerHash, metadata));
            }

            var discarded = await store.DiscardDecodedInboxItemsOutsideRoutesAsync(
                scope,
                DurableInboxItemKind.GroupMessage,
                new HashSet<string>(StringComparer.Ordinal) { retainedRoute });

            Assert.Equal(300, discarded);
            Assert.Equal(2, await store.CountPendingInboxItemsAsync(scope));
            Assert.Equal(2, (await store.ListDecodedInboxItemsAsync(
                scope,
                DurableInboxItemKind.GroupMessage,
                retainedRoute,
                10)).Count);
        });
    }

    [Fact]
    public async Task UnknownGroupRoutesAtPendingLimit_DoNotStarveFollowingDirectMessage()
    {
        var store = new InMemorySessionStore();
        var scope = new DurableInboxScope(SessionId.CreateNew(), 0);
        var sender = SessionId.CreateNew();
        string? cursor = null;
        var index = 0;
        while (index < DurableInboxLimits.MaxPendingItemCount)
        {
            var batch = Enumerable.Range(index, DurableInboxLimits.MaxBatchCount)
                .Select(itemIndex => DurableInboxWireEntry.Create(
                    $"unknown-group-{itemIndex}",
                    itemIndex,
                    $"wire-{itemIndex}"))
                .ToArray();
            await store.StageInboxBatchAsync(scope, cursor, batch[^1].ServerHash, batch);
            foreach (var entry in batch)
            {
                var metadata = Metadata(sender, new MessageId($"unknown-message-{index++}"), DigestOne) with
                {
                    Kind = DurableInboxItemKind.GroupMessage,
                    RouteKey = ConversationId.CreateGroupV2().Value
                };
                await store.PrepareInboxItemAsync(scope, entry.ServerHash, metadata);
            }

            cursor = batch[^1].ServerHash;
        }

        var direct = DurableInboxWireEntry.Create("direct-after-flood", index + 1, "direct-wire");
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.StageInboxBatchAsync(scope, cursor, direct.ServerHash, [direct]));

        var discarded = await store.DiscardDecodedInboxItemsOutsideRoutesAsync(
            scope,
            DurableInboxItemKind.GroupMessage,
            new HashSet<string>(StringComparer.Ordinal));
        await store.StageInboxBatchAsync(scope, cursor, direct.ServerHash, [direct]);
        await store.PrepareInboxItemAsync(
            scope,
            direct.ServerHash,
            Metadata(sender, MessageId.NewId(), DigestTwo));

        Assert.Equal(DurableInboxLimits.MaxPendingItemCount, discarded);
        Assert.Equal(
            direct.ServerHash,
            Assert.Single(await store.ListDecodedInboxItemsAsync(
                scope,
                DurableInboxItemKind.DirectMessage,
                routeKey: null,
                limit: 1)).ServerHash);
    }

    [Fact]
    public async Task InMemoryStore_PersistsCursorAndDecodedItemAcrossRestart()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-inbox-{Guid.NewGuid():N}.json");
        try
        {
            var scope = new DurableInboxScope(SessionId.CreateNew(), -10);
            var entry = DurableInboxWireEntry.Create("storage-hash-1", 101, "wire-payload-1");
            var metadata = Metadata(SessionId.CreateNew(), MessageId.NewId(), DigestOne) with
            {
                Kind = DurableInboxItemKind.GroupMessage,
                RouteKey = ConversationId.CreateGroupV2().Value
            };
            var store = new InMemorySessionStore(statePath);
            await store.StageInboxBatchAsync(scope, null, entry.ServerHash, [entry]);
            await store.PrepareInboxItemAsync(scope, entry.ServerHash, metadata);

            var restarted = new InMemorySessionStore(statePath);

            Assert.Equal(entry.ServerHash, await restarted.GetInboxCursorAsync(scope));
            Assert.Single(await restarted.ListDecodedInboxItemsAsync(
                scope,
                DurableInboxItemKind.GroupMessage,
                metadata.RouteKey,
                10));
        }
        finally
        {
            File.Delete(statePath);
        }
    }

    [Fact]
    public async Task SqliteStore_PersistsCursorAndDecodedItemAcrossRestart()
    {
        var statePath = NewSqlitePath();
        try
        {
            var scope = new DurableInboxScope(SessionId.CreateNew(), 0);
            var entry = DurableInboxWireEntry.Create("storage-hash-1", 101, "wire-payload-1");
            var metadata = Metadata(SessionId.CreateNew(), MessageId.NewId(), DigestOne);
            using (var store = new SqliteSessionStore(statePath))
            {
                await store.StageInboxBatchAsync(scope, null, entry.ServerHash, [entry]);
                await store.PrepareInboxItemAsync(scope, entry.ServerHash, metadata);
            }

            using var restarted = new SqliteSessionStore(statePath);
            Assert.Equal(entry.ServerHash, await restarted.GetInboxCursorAsync(scope));
            Assert.Single(await restarted.ListDecodedInboxItemsAsync(
                scope,
                DurableInboxItemKind.DirectMessage,
                routeKey: null,
                limit: 10));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    private static DurableInboxDecodedMetadata Metadata(
        SessionId sender,
        MessageId messageId,
        string digest) =>
        new(
            DurableInboxItemKind.DirectMessage,
            ConversationId.ForOneToOne(sender).Value,
            sender,
            messageId,
            digest,
            ExpiresAt);

    private static async Task ForEachStoreAsync(Func<IDurableInboxRepository, Task> assertion)
    {
        await assertion(new InMemorySessionStore());

        var statePath = NewSqlitePath();
        try
        {
            using var store = new SqliteSessionStore(statePath);
            await assertion(store);
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    private static string NewSqlitePath() =>
        Path.Combine(Path.GetTempPath(), $"deep-client-inbox-{Guid.NewGuid():N}.db");

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
}
