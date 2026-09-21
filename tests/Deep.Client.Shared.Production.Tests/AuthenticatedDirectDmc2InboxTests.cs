using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed class AuthenticatedDirectDmc2InboxTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExactCrossSessionReplayAndChangedBytesFork(bool sqlite)
    {
        using var fixture = new Fixture();
        using var store = Open(sqlite, fixture);
        var firstBytes = Event("first");
        var changedBytes = Event("changed");
        try
        {
            using var first = Handoff(firstBytes, 0x71);
            Assert.Equal(DirectDmc2InboxDisposition.Materialized,
                await Materialize(store, first));
            var read = await Read(store);
            Assert.Equal(firstBytes, read);
            CryptographicOperations.ZeroMemory(read!);

            using var crossSessionReplay = Handoff(firstBytes, 0x72);
            Assert.Equal(DirectDmc2InboxDisposition.ExactReplay,
                await Materialize(store, crossSessionReplay));
            var afterCallerClearedCopy = await Read(store);
            Assert.Equal(firstBytes, afterCallerClearedCopy);
            CryptographicOperations.ZeroMemory(afterCallerClearedCopy!);

            using var conflicting = Handoff(changedBytes, 0x73);
            Assert.Equal(DirectDmc2InboxDisposition.ForkLatched,
                await Materialize(store, conflicting));
            Assert.Equal(DirectDmc2InboxDisposition.ForkLatched,
                await Materialize(store, first));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await Read(store));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstBytes);
            CryptographicOperations.ZeroMemory(changedBytes);
        }
    }

    [Fact]
    public async Task SqliteMaterializationAndForkSurviveRestart()
    {
        using var fixture = new Fixture();
        var exact = Event("durable");
        var conflict = Event("different");
        try
        {
            using (var firstStore = Open(sqlite: true, fixture))
            using (var first = Handoff(exact, 0x74))
                Assert.Equal(DirectDmc2InboxDisposition.Materialized,
                    await Materialize(firstStore, first));

            using (var restarted = Open(sqlite: true, fixture))
            {
                var read = await Read(restarted);
                Assert.Equal(exact, read);
                CryptographicOperations.ZeroMemory(read!);
                using var changed = Handoff(conflict, 0x75);
                Assert.Equal(DirectDmc2InboxDisposition.ForkLatched,
                    await Materialize(restarted, changed));
            }
            using var forked = Open(sqlite: true, fixture);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await Read(forked));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact);
            CryptographicOperations.ZeroMemory(conflict);
        }
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    public async Task SqliteCrashIsPriorOrExactlyMaterialized(
        int crashPointValue, bool committed)
    {
        var crashPoint = (DirectDmc2InboxFaultPoint)crashPointValue;
        using var fixture = new Fixture();
        var exact = Event("crash");
        try
        {
            using (var firstStore = Open(sqlite: true, fixture))
            using (var handoff = Handoff(exact, 0x77))
            using (DirectDmc2InboxTestHooks.Push(point =>
                       { if (point == crashPoint)
                               throw new InvalidOperationException("Injected inbox crash."); }))
                await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                    await Materialize(firstStore, handoff));

            using var restarted = Open(sqlite: true, fixture);
            var recovered = await Read(restarted);
            Assert.Equal(committed, recovered is not null);
            if (recovered is not null)
            {
                Assert.Equal(exact, recovered);
                CryptographicOperations.ZeroMemory(recovered);
            }
            using var retry = Handoff(exact, 0x78);
            Assert.Equal(committed
                    ? DirectDmc2InboxDisposition.ExactReplay
                    : DirectDmc2InboxDisposition.Materialized,
                await Materialize(restarted, retry));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WrongAccountGenerationAndUnauthenticatedScopeReject(bool sqlite)
    {
        using var fixture = new Fixture();
        using var store = Open(sqlite, fixture);
        var exact = Event("scope");
        try
        {
            Assert.Throws<CryptographicException>(() => AuthenticatedDirectDmc2.CreateForTests(
                exact, Network, Local, 1, Conversation, Remote,
                Bytes(32, 0x99), Bytes(32, 0x76), Bytes(32, 0x86)));
            using var first = Handoff(exact, 0x76);
            Assert.Equal(DirectDmc2InboxDisposition.Materialized,
                await Materialize(store, first));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await Read(store, generation: 2));
            using var anotherGeneration = AuthenticatedDirectDmc2.CreateForTests(
                exact, Network, Local, 2, Conversation, Remote,
                AuthorDevice, Bytes(32, 0x80), Bytes(32, 0x90));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await Materialize(store, anotherGeneration));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Fact]
    public void MailboxOptionsClearOwnedKeyOnDispose()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var options = new SqliteDeepMailboxStoreOptions("unused.db", key);
        var observed = options.EncryptionKey;
        options.Dispose();
        Assert.True(observed.Span.IndexOfAnyExcept((byte)0) < 0);
        Assert.Throws<ObjectDisposedException>(() => _ = options.EncryptionKey);
        Assert.True(key.AsSpan().IndexOfAnyExcept((byte)0) >= 0);
        CryptographicOperations.ZeroMemory(key);
    }

    [Fact]
    public void EphemeralTypingCannotEnterDurableDirectHistory()
    {
        var exact = ApplicationCoreCodec.AuthorDmc2(
            Network, Logical, Conversation, Remote, AuthorDevice,
            1, 1_000, 2_000, Dmc2Flags.Silent, [],
            ApplicationCoreCodec.CreateTypingPayload(
                TypingOperation.Start, Bytes(32, 0xA1))).CanonicalBytes.ToArray();
        try
        {
            Assert.Throws<CryptographicException>(() => Handoff(exact, 0x81));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    private static readonly byte[] Network = Bytes(16, 0x11);
    private static readonly byte[] Local = Bytes(32, 0x21);
    private static readonly byte[] Remote = Bytes(32, 0x31);
    private static readonly byte[] AuthorDevice = Bytes(32, 0x41);
    private static readonly byte[] Conversation = Bytes(32, 0x51);
    private static readonly byte[] Logical = Bytes(32, 0x61);

    private static byte[] Event(string text) => ApplicationCoreCodec.AuthorDmc2(
        Network, Logical, Conversation, Remote, AuthorDevice,
        1, 1_000, 0, Dmc2Flags.None, [],
        ApplicationCoreCodec.CreateMessageCreatePayload(text)).CanonicalBytes.ToArray();

    private static AuthenticatedDirectDmc2 Handoff(byte[] exact, byte operation) =>
        AuthenticatedDirectDmc2.CreateForTests(
            exact, Network, Local, 1, Conversation, Remote, AuthorDevice,
            Bytes(32, operation), Bytes(32, unchecked((byte)(operation + 0x10))));

    private static IDisposable Open(bool sqlite, Fixture fixture) => sqlite
        ? new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key))
        : new InMemoryAuthenticatedDirectDmc2Inbox();

    private static Task<DirectDmc2InboxDisposition> Materialize(
        IDisposable store, AuthenticatedDirectDmc2 handoff) => store switch
        {
            SqliteDeepMailboxStore disk => disk.MaterializeDirectDmc2Async(handoff),
            InMemoryAuthenticatedDirectDmc2Inbox memory =>
                memory.MaterializeDirectDmc2Async(handoff),
            _ => throw new InvalidOperationException(),
        };

    private static Task<byte[]?> Read(IDisposable store, ulong generation = 1) =>
        store switch
        {
            SqliteDeepMailboxStore disk => disk.ReadDirectDmc2Async(
                Local, generation, Conversation, Logical, AuthorDevice),
            InMemoryAuthenticatedDirectDmc2Inbox memory =>
                memory.ReadDirectDmc2Async(
                    Local, generation, Conversation, Logical, AuthorDevice),
            _ => throw new InvalidOperationException(),
        };

    private static byte[] Bytes(int length, byte start) =>
        Enumerable.Range(0, length)
            .Select(index => unchecked((byte)(start + index))).ToArray();

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "deep-direct-inbox-" + Guid.NewGuid().ToString("N"));

        internal Fixture() => Directory.CreateDirectory(directory);
        internal string Path => System.IO.Path.Combine(directory, "mailbox.db");
        internal byte[] Key { get; } = RandomNumberGenerator.GetBytes(32);

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Key);
            Directory.Delete(directory, recursive: true);
        }
    }
}
