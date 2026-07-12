using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class ReplayRepositoryTests
{
    private const string Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public async Task Stores_ClassifyFirstAndDuplicateReplayClaims()
    {
        await ForEachStoreAsync(async repository =>
        {
            var sender = SessionId.CreateNew();
            var messageId = MessageId.NewId();
            var expiresAt = DateTimeOffset.Parse("2026-08-01T00:00:00Z");

            Assert.Equal(
                MessageReplayClaimResult.Accepted,
                await repository.TryClaimAsync(sender, messageId, Digest, expiresAt));
            Assert.Equal(
                MessageReplayClaimResult.DuplicateSameDigest,
                await repository.TryClaimAsync(sender, messageId, Digest, expiresAt));
            Assert.Equal(
                MessageReplayClaimResult.RejectedDigestMismatch,
                await repository.TryClaimAsync(sender, messageId, new string('a', 64), expiresAt));
        });
    }

    [Fact]
    public async Task Stores_AllowExactlyOneConcurrentFirstClaim()
    {
        await ForEachStoreAsync(async repository =>
        {
            var sender = SessionId.CreateNew();
            var messageId = MessageId.NewId();
            var expiresAt = DateTimeOffset.Parse("2026-08-01T00:00:00Z");

            var results = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(_ => repository.TryClaimAsync(sender, messageId, Digest, expiresAt)));

            Assert.Equal(1, results.Count(result => result == MessageReplayClaimResult.Accepted));
            Assert.Equal(31, results.Count(result => result == MessageReplayClaimResult.DuplicateSameDigest));
        });
    }

    [Fact]
    public async Task SqliteStore_PersistsReplayClaimsAfterReopen()
    {
        var statePath = NewSqlitePath();
        try
        {
            var sender = SessionId.CreateNew();
            var messageId = MessageId.NewId();
            var expiresAt = DateTimeOffset.Parse("2026-08-01T00:00:00Z");

            using (var store = new SqliteSessionStore(statePath))
            {
                Assert.Equal(
                    MessageReplayClaimResult.Accepted,
                    await store.TryClaimAsync(sender, messageId, Digest, expiresAt));
            }

            using var reopened = new SqliteSessionStore(statePath);
            Assert.Equal(
                MessageReplayClaimResult.DuplicateSameDigest,
                await reopened.TryClaimAsync(sender, messageId, Digest, expiresAt));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task Stores_PruneExpiredReplayClaimsInBoundedBatches()
    {
        await ForEachStoreAsync(async repository =>
        {
            var sender = SessionId.CreateNew();
            var now = DateTimeOffset.Parse("2026-08-01T00:00:00Z");

            for (var index = 0; index < 257; index++)
            {
                Assert.Equal(
                    MessageReplayClaimResult.Accepted,
                    await repository.TryClaimAsync(
                        sender,
                        MessageId.Parse($"expired-{index}"),
                        Digest,
                        now.AddMinutes(1)));
            }

            Assert.Equal(256, await repository.PruneExpiredAsync(now.AddMinutes(2)));
            Assert.Equal(1, await repository.PruneExpiredAsync(now.AddMinutes(2)));
            Assert.Equal(
                MessageReplayClaimResult.Accepted,
                await repository.TryClaimAsync(sender, MessageId.Parse("expired-0"), Digest, now.AddMinutes(3)));
        });
    }

    [Fact]
    public async Task Stores_RejectInvalidReplayClaimInput()
    {
        await ForEachStoreAsync(async repository =>
        {
            var sender = SessionId.CreateNew();
            var messageId = MessageId.NewId();
            var expiresAt = DateTimeOffset.Parse("2026-08-01T00:00:00Z");

            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await repository.TryClaimAsync(sender, messageId, new string('A', 64), expiresAt));
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await repository.TryClaimAsync(sender, messageId, new string('a', 63), expiresAt));
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
                await repository.TryClaimAsync(sender, messageId, Digest, DateTimeOffset.UnixEpoch));
        });
    }

    private static async Task ForEachStoreAsync(Func<IMessageReplayRepository, Task> assertion)
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
        Path.Combine(Path.GetTempPath(), $"deep-client-replay-{Guid.NewGuid():N}.db");

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
