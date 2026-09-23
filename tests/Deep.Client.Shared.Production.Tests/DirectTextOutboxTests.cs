using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DirectTextOutboxTests
{
    private static readonly byte[] Network = Id(0x11, 16);
    private static readonly byte[] Account = Id(0x21);
    private static readonly byte[] Device = Id(0x31);
    private static readonly byte[] Conversation = Id(0x41);
    private static readonly byte[] OtherConversation = Id(0x42);
    private static readonly byte[] Recipient = Id(0x51);
    private static readonly byte[] RecipientDevice = Id(0x61);
    private static readonly DateTimeOffset Created =
        DateTimeOffset.FromUnixTimeMilliseconds(1_780_000_000_000);

    [Fact]
    public async Task AuthoredTextIsExactAfterRestartAndSequencesAdvancePerConversation()
    {
        using var fixture = new Fixture();
        byte[] firstLogical;
        byte[] firstExact;
        byte[] firstOperation;
        using (var store = fixture.Open())
        {
            using var first = await Stage(store, Conversation, "hello from Windows");
            using var second = await Stage(store, Conversation, "hello again");
            using var other = await Stage(store, OtherConversation, "other conversation");
            Assert.Equal<ulong>(3, first.SenderSequence);
            Assert.Equal<ulong>(4, second.SenderSequence);
            Assert.Equal<ulong>(3, other.SenderSequence);
            firstLogical = first.LogicalMessageId.ToArray();
            firstExact = first.ExactDmc2.ToArray();
            firstOperation = first.OperationId.ToArray();
            var parsed = ApplicationCoreCodec.DecodeDmc2(firstExact);
            Assert.Equal(Dmc2ContentKind.MessageCreate, parsed.ContentKind);
            Assert.Equal(firstExact, parsed.CanonicalBytes.ToArray());
        }
        using (var restarted = fixture.Open())
        using (var read = await restarted.ReadDirectTextAsync(
                   Network, Account, 1, Conversation, firstLogical,
                   Recipient, RecipientDevice))
        {
            Assert.NotNull(read);
            Assert.Equal(firstExact, read.ExactDmc2.ToArray());
            Assert.Equal(firstOperation, read.OperationId.ToArray());
            Assert.Equal<ulong>(3, read.SenderSequence);
        }
        var raw = File.ReadAllBytes(fixture.Path);
        Assert.False(Contains(raw, "hello from Windows"u8));
        CryptographicOperations.ZeroMemory(raw);
        CryptographicOperations.ZeroMemory(firstLogical);
        CryptographicOperations.ZeroMemory(firstExact);
        CryptographicOperations.ZeroMemory(firstOperation);
    }

    [Fact]
    public async Task ChangedAccountGenerationRecipientOrNetworkFailsClosed()
    {
        using var fixture = new Fixture();
        using var store = fixture.Open();
        using var staged = await Stage(store, Conversation, "private");
        var logical = staged.LogicalMessageId;
        await Assert.ThrowsAsync<CryptographicException>(() =>
            store.ReadDirectTextAsync(Network, Account, 2, Conversation,
                logical, Recipient, RecipientDevice));
        await Assert.ThrowsAsync<CryptographicException>(() =>
            store.ReadDirectTextAsync(Network, Account, 1, Conversation,
                logical, Id(0x52), RecipientDevice));
        await Assert.ThrowsAsync<CryptographicException>(() =>
            store.ReadDirectTextAsync(Id(0x12, 16), Account, 1, Conversation,
                logical, Recipient, RecipientDevice));
    }

    [Fact]
    public async Task InvalidTextDoesNotConsumeSequence()
    {
        using var fixture = new Fixture();
        using var store = fixture.Open();
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(() => Stage(store, Conversation, ""));
        using var first = await Stage(store, Conversation, "valid");
        Assert.Equal<ulong>(3, first.SenderSequence);
    }

    [Fact]
    public async Task DisposedEntryCannotReleasePlaintextAgain()
    {
        using var fixture = new Fixture();
        using var store = fixture.Open();
        var entry = await Stage(store, Conversation, "dispose me");
        entry.Dispose();
        Assert.Throws<ObjectDisposedException>(() => entry.ExactDmc2);
        Assert.Throws<ObjectDisposedException>(() => entry.OperationId);
        Assert.Throws<ObjectDisposedException>(() => entry.LogicalMessageId);
    }

    private static Task<DirectTextOutboxEntry> Stage(
        SqliteDeepMailboxStore store, byte[] conversation, string text) =>
        store.StageDirectTextAsync(Network, Account, 1, Device, conversation,
            Recipient, RecipientDevice, text, Created);

    private static bool Contains(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) =>
        haystack.IndexOf(needle) >= 0;

    private static byte[] Id(byte value, int count = 32) =>
        Enumerable.Repeat(value, count).ToArray();

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "deep-direct-text-" + Guid.NewGuid().ToString("N"));
        private readonly byte[] key = RandomNumberGenerator.GetBytes(32);

        internal Fixture() => Directory.CreateDirectory(directory);
        internal string Path => System.IO.Path.Combine(directory, "mailbox.db");
        internal SqliteDeepMailboxStore Open() => new(new(Path, key));

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(key);
            Directory.Delete(directory, recursive: true);
        }
    }
}
