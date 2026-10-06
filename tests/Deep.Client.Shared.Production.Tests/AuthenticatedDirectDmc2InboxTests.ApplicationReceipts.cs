using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class AuthenticatedDirectDmc2InboxTests
{
    // These are structural persistence fixtures, not authenticated device E2E.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ApplicationReceiptReplayCannotChangeItsRecipientDevice(bool sqlite)
    {
        using var fixture = new Fixture(); using var store = Open(sqlite, fixture);
        var exact = Event("recipient binding"); using var original = Handoff(exact, 0x81);
        Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, original));
        using var substituted = AuthenticatedDirectDmc2.CreateForTests(exact, Network, Local, 1, Bytes(32, 0x23),
            Conversation, Remote, AuthorDevice, Bytes(32, 0x82), Bytes(32, 0x92));
        await Assert.ThrowsAsync<CryptographicException>(() => Materialize(store, substituted));
        Assert.Equal(SHA256.HashData(exact), Assert.Single(await Receipts(store, ReceiptScope())).EventHash.ToArray());
        Assert.Equal(exact, await Read(store));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ApplicationReceiptReaderUsesItsBoundedSelection(bool sqlite)
    {
        using var fixture = new Fixture(); using var store = Open(sqlite, fixture);
        using var first = Handoff(Event("first"), 0x81);
        using var second = Handoff(Event("second", Bytes(32, 0x65), 4), 0x82);
        Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, first));
        Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, second));
        Assert.Equal(2, (await Receipts(store, ReceiptScope())).Count);
        Assert.Single(await Receipts(store, ReceiptScope(), 1));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ApplicationReceiptWorkIsIndependentIdempotentAndScopeBound(bool sqlite)
    {
        using var fixture = new Fixture();
        using var store = Open(sqlite, fixture);
        var exact = Event("receipt obligation"); using var handoff = Handoff(exact, 0x81);
        Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, handoff));
        var scope = ReceiptScope();
        var original = Assert.Single(await Receipts(store, scope));
        Assert.Equal(Logical, original.LogicalMessageId.ToArray());
        Assert.Equal(SHA256.HashData(exact), original.EventHash.ToArray());
        var observed = original.EventHash.ToArray(); observed[0] ^= 1;
        Assert.Equal(SHA256.HashData(exact), original.EventHash.ToArray());
        using var retry = Handoff(exact, 0x82);
        Assert.Equal(DirectDmc2InboxDisposition.ExactReplay, await Materialize(store, retry));
        Assert.Equal(original.EventHash.ToArray(), Assert.Single(await Receipts(store, scope)).EventHash.ToArray());
        var wrongDevice = scope.Exact.ToArray(); wrongDevice[92] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => Receipts(store, Did2MessagingSessionScope.RestoreMetadata(wrongDevice)));
        var wrongGeneration = scope.Exact.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(wrongGeneration.AsSpan(84), 2);
        await Assert.ThrowsAsync<CryptographicException>(() => Receipts(store, Did2MessagingSessionScope.RestoreMetadata(wrongGeneration)));
        var wrongNetwork = scope.Exact.ToArray(); wrongNetwork[4] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => Receipts(store, Did2MessagingSessionScope.RestoreMetadata(wrongNetwork)));
        foreach (var limit in new[] { 0, 101 })
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Receipts(store, scope, limit));
        if (sqlite)
        {
            using var reopened = Open(true, fixture);
            Assert.Equal(original.EventHash.ToArray(), Assert.Single(await Receipts(reopened, scope)).EventHash.ToArray());
        }
        CryptographicOperations.ZeroMemory(exact);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ApplicationReceiptWorkDoesNotAcknowledgeLocalHistoryOrReceipts(bool sqlite, bool receipt)
    {
        using var fixture = new Fixture(); using var store = Open(sqlite, fixture);
        var payload = receipt ? (Dmc2Payload)ApplicationCoreCodec.CreateReceiptReadPayload([new Dmc2LogicalMessageReference(Logical)])
            : ApplicationCoreCodec.CreateMessageCreatePayload("local author");
        var author = receipt ? Remote : Local; var device = receipt ? AuthorDevice : LocalDevice;
        var exact = ApplicationCoreCodec.AuthorDmc2(Network, Logical, Conversation, author, device,
            3, 1000, 0, Dmc2Flags.None, [], payload).CanonicalBytes.ToArray();
        using var handoff = AuthenticatedDirectDmc2.CreateForTests(exact, Network, Local, 1, LocalDevice,
            Conversation, author, device, Bytes(32, 0x81), Bytes(32, 0x91));
        Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, handoff));
        Assert.Empty(await Receipts(store, ReceiptScope()));
        Assert.Equal(DirectDmc2InboxDisposition.ExactReplay, await Materialize(store, handoff));
        Assert.Empty(await Receipts(store, ReceiptScope()));
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(3, false)]
    public async Task ApplicationReceiptCrashRetainsBothEffectsOrNeither(int point, bool committed)
    {
        using var fixture = new Fixture(); var exact = Event("atomic receipt");
        using (var store = Open(true, fixture))
        using (var handoff = Handoff(exact, 0x81))
        using (DirectDmc2InboxTestHooks.Push(observed => { if ((int)observed == point) throw new IOException("Injected receipt transaction crash."); }))
            await Assert.ThrowsAsync<IOException>(() => Materialize(store, handoff));
        using var reopened = Open(true, fixture);
        Assert.Equal(committed, (await Read(reopened)) is not null);
        Assert.Equal(committed ? 1 : 0, (await Receipts(reopened, ReceiptScope())).Count);
        using var retry = Handoff(exact, 0x82);
        Assert.Equal(committed ? DirectDmc2InboxDisposition.ExactReplay : DirectDmc2InboxDisposition.Materialized,
            await Materialize(reopened, retry));
        Assert.Single(await Receipts(reopened, ReceiptScope()));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public async Task ApplicationReceiptCancellationRollsBackEventAndDueWork(int point)
    {
        using var fixture = new Fixture(); using var cancelled = new CancellationTokenSource();
        using (var store = (SqliteDeepMailboxStore)Open(true, fixture))
        using (var handoff = Handoff(Event("cancelled receipt"), 0x81))
        using (DirectDmc2InboxTestHooks.Push(observed => { if ((int)observed == point) cancelled.Cancel(); }))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.MaterializeDirectDmc2Async(handoff, cancelled.Token));
        using var reopened = Open(true, fixture);
        Assert.Null(await Read(reopened)); Assert.Empty(await Receipts(reopened, ReceiptScope()));
    }

    [Theory]
    [InlineData("missing", "DELETE FROM direct_application_receipt_obligations;")]
    [InlineData("hash", "UPDATE direct_application_receipt_obligations SET exact_dmc2_hash=zeroblob(32);")]
    [InlineData("author", "UPDATE direct_application_receipt_obligations SET author_account_id=zeroblob(32);")]
    [InlineData("recipient", "UPDATE direct_application_receipt_obligations SET local_device_id=zeroblob(32);")]
    public async Task ApplicationReceiptMissingOrChangedWorkIsNeverRepaired(string caseId, string mutation)
    {
        Assert.False(string.IsNullOrWhiteSpace(caseId));
        using var fixture = new Fixture(); var exact = Event("retained receipt");
        using var store = (SqliteDeepMailboxStore)Open(true, fixture); using var handoff = Handoff(exact, 0x81);
        Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, handoff));
        using (var connection = new SqliteConnection($"Data Source={fixture.Path};Pooling=False"))
        {
            connection.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(connection, fixture.Key));
            using var change = connection.CreateCommand(); change.CommandText = mutation; Assert.Equal(1, change.ExecuteNonQuery());
        }
        var before = ReceiptDatabaseFacts(fixture);
        await Assert.ThrowsAsync<LocalStateResetRequiredException>(() => Materialize(store, handoff));
        using var options = new SqliteDeepMailboxStoreOptions(fixture.Path, fixture.Key);
        Assert.Throws<LocalStateResetRequiredException>(() => SqliteDeepMailboxStore.OpenExisting(options));
        Assert.Equal(before, ReceiptDatabaseFacts(fixture));
    }

    private static string ReceiptDatabaseFacts(Fixture fixture)
    {
        using var connection = new SqliteConnection($"Data Source={fixture.Path};Pooling=False");
        connection.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(connection, fixture.Key));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT (SELECT group_concat(hex(exact_dmc2)) FROM authenticated_dmc2_inbox),(SELECT group_concat(hex(conversation_id)||hex(logical_message_id)||hex(author_device_id)||hex(author_account_id)||hex(local_device_id)||hex(exact_dmc2_hash)) FROM direct_application_receipt_obligations);";
        using var reader = command.ExecuteReader(); Assert.True(reader.Read());
        return reader.GetString(0) + ":" + (reader.IsDBNull(1) ? "absent" : reader.GetString(1));
    }

    private static Task<IReadOnlyList<DirectApplicationReceiptObligation>> Receipts(IDisposable store,
        Did2MessagingSessionScope scope, int limit = 100) => store switch
    {
        SqliteDeepMailboxStore sql => sql.ListPendingDirectApplicationReceiptsAsync(scope, limit),
        InMemoryAuthenticatedDirectDmc2Inbox memory => memory.ListPendingDirectApplicationReceiptsAsync(scope, limit),
        _ => throw new InvalidOperationException(),
    };

    // Metadata-only fixture; RestoreMetadata grants no account/endpoint authority.
    private static Did2MessagingSessionScope ReceiptScope()
    {
        var exact = new byte[Did2MessagingSessionScope.Bytes]; exact[0] = 1; exact[1] = 2;
        Network.CopyTo(exact.AsSpan(4)); Local.CopyTo(exact.AsSpan(52)); LocalDevice.CopyTo(exact.AsSpan(92));
        Remote.CopyTo(exact.AsSpan(132)); AuthorDevice.CopyTo(exact.AsSpan(172)); Conversation.CopyTo(exact.AsSpan(244));
        foreach (var offset in new[] { 20, 212, 276, 308, 340, 372 }) Bytes(32, 0x71).CopyTo(exact.AsSpan(offset));
        foreach (var offset in new[] { 84, 124, 164, 204 }) BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(offset), 1);
        return Did2MessagingSessionScope.RestoreMetadata(exact);
    }
}
