using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// SQL facts only. These synthetic Stored roots grant no cleanup authority.
public sealed partial class Did2OwnedTextOutboxTests
{
    [Fact]
    public async Task CompactionReadCannotInitializeOwnerOrMaterializePending()
    {
        using var fixture = new SqlFixture(); using var options = new SqliteDeepMailboxStoreOptions(fixture.Path, fixture.Key);
        using var store = new SqliteDeepMailboxStore(options); var scope = Scope();
        using var empty = new ProtectedDid2DirectTextJournal.State();
        await Assert.ThrowsAsync<CryptographicException>(() => store.ReconcileOwnedTextOutboxAsync(empty,
            scope.LocalAccount.ToArray(), 1, scope, ReadOnlyMemory<byte>.Empty, default, requireStableReadOnly: true));
        using var pending = Pending(scope, B(32, 31), 3);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.ReconcileOwnedTextOutboxAsync(pending,
            scope.LocalAccount.ToArray(), 1, scope, ReadOnlyMemory<byte>.Empty, default, requireStableReadOnly: true));
        Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM authenticated_dmc2_inbox_owner;"));
        Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM direct_text_outbox;"));
        Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM direct_sender_sequences;"));
    }

    [Fact]
    public async Task CompactionVirtualSuccessorBindsEveryUnselectedCellWithoutWriting()
    {
        using var fixture = new SqlFixture(); using var options = new SqliteDeepMailboxStoreOptions(fixture.Path, fixture.Key);
        using var store = new SqliteDeepMailboxStore(options); var scope = Scope(); var first = B(32, 31); var second = B(32, 32);
        using var journal = Pending(scope, first, 3); using (await Mirror(store, journal, scope, first)) { } Stabilize(journal, first);
        journal.AddPending(Make(scope, second, 4)); using (await Mirror(store, journal, scope, second)) { } Stabilize(journal, second);
        journal.RetainStore(Convert.ToHexString(first)); var selected = new[] { journal.Entries[Convert.ToHexString(first)] };
        var effects = await store.CaptureOrdinaryOutboxEffectsAsync(scope, selected, default);
        var repeated = await store.CaptureOrdinaryOutboxEffectsAsync(scope, selected, default);
        Assert.Equal(effects.Before, repeated.Before); Assert.Equal(effects.After, repeated.After); Assert.NotEqual(effects.Before, effects.After);
        Assert.Equal(2L, fixture.Scalar("SELECT count(*) FROM direct_text_outbox;"));
        Assert.Equal(5L, fixture.Scalar("SELECT next_sequence FROM direct_sender_sequences;"));
        fixture.Execute("UPDATE direct_text_outbox SET recipient_device_id=zeroblob(32) WHERE sender_sequence=4;");
        var changedUnselected = await store.CaptureOrdinaryOutboxEffectsAsync(scope, selected, default);
        Assert.NotEqual(effects.Before, changedUnselected.Before); Assert.NotEqual(effects.After, changedUnselected.After);
        fixture.Execute("UPDATE direct_sender_sequences SET next_sequence=6;");
        var changedCounter = await store.CaptureOrdinaryOutboxEffectsAsync(scope, selected, default);
        Assert.NotEqual(changedUnselected.Before, changedCounter.Before); Assert.NotEqual(changedUnselected.After, changedCounter.After);
        Assert.Equal(2L, fixture.Scalar("SELECT count(*) FROM direct_text_outbox;"));
    }

    [Theory]
    [InlineData("missing-row", "DELETE FROM direct_text_outbox;")]
    [InlineData("changed-event", "UPDATE direct_text_outbox SET exact_dmc2=zeroblob(length(exact_dmc2));")]
    [InlineData("changed-recipient", "UPDATE direct_text_outbox SET recipient_account_id=zeroblob(32);")]
    [InlineData("oversized-event", "PRAGMA ignore_check_constraints=ON; UPDATE direct_text_outbox SET exact_dmc2=zeroblob(1048577);")]
    [InlineData("oversized-recipient", "PRAGMA ignore_check_constraints=ON; UPDATE direct_text_outbox SET recipient_account_id=zeroblob(1048577);")]
    public async Task CompactionCaptureRejectsMissingChangedOrOversizedSelectedRows(string caseId, string corrupt)
    {
        Assert.False(string.IsNullOrWhiteSpace(caseId));
        using var fixture = new SqlFixture(); using var options = new SqliteDeepMailboxStoreOptions(fixture.Path, fixture.Key);
        using var store = new SqliteDeepMailboxStore(options); var scope = Scope(); var op = B(32, 31);
        using var journal = Pending(scope, op, 3); using (await Mirror(store, journal, scope, op)) { } Stabilize(journal, op);
        journal.RetainStore(Convert.ToHexString(op)); var selected = new[] { journal.Entries[Convert.ToHexString(op)] };
        fixture.Execute(corrupt); var count = fixture.Scalar("SELECT count(*) FROM direct_text_outbox;");
        await Assert.ThrowsAsync<CryptographicException>(() => store.CaptureOrdinaryOutboxEffectsAsync(scope, selected, default));
        Assert.Equal(count, fixture.Scalar("SELECT count(*) FROM direct_text_outbox;"));
        Assert.Equal(4L, fixture.Scalar("SELECT next_sequence FROM direct_sender_sequences;"));
    }
}
