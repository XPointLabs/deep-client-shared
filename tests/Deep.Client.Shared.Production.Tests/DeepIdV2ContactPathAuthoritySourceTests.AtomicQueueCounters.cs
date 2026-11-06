using System.Diagnostics.Tracing;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2AtomicQueue_NativeCountersCoverSuccessFailureCancellationAndBorrowedOuterScopeAfterPrivateDisposal()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        using var observed = new AtomicQueueNativeCounterListener(fixture.CheckCounterObservationLease);
        _ = await fixture.QueueNativeText(sender, "observed atomic success");
        CheckOneRealOperation();

        using (Did2AtomicQueueTestHooks.Push(point =>
        { if (point == Did2AtomicQueueFailpoint.AfterProtectedCommit) throw new IOException("Observed atomic interruption."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.QueueNativeText(sender, "observed atomic failure"));
        CheckOneRealOperation();
        await FinishOriginal("observed atomic failure"); observed.Events.Clear();

        using (var cancelled = new CancellationTokenSource())
        {
            using (Did2AtomicQueueTestHooks.Push(point =>
            { if (point == Did2AtomicQueueFailpoint.AfterProtectedCommit) cancelled.Cancel(); }))
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.QueueAtomicCounterText(sender,
                    "observed atomic cancellation", cancelled.Token));
        }
        CheckOneRealOperation();
        await FinishOriginal("observed atomic cancellation"); observed.Events.Clear();

        using (var outer = Did2MessagingSqlJournal.NativeWork.Measure())
        {
            _ = await fixture.QueueNativeText(sender, "borrow the actual outer native scope");
            Assert.Empty(observed.Events); Assert.True(outer.Opens > 0);
            outer.Dispose(); ClientPersistenceTiming.PublishNativeCounts(outer);
            CheckOneRealOperation();
        }
        Assert.False(observed.PrivateLeaseObserved);

        void CheckOneRealOperation()
        {
            var counts = Assert.Single(observed.Events); Assert.Equal(9, counts.Length); Assert.True(counts[0] > 0);
            Assert.False(observed.PrivateLeaseObserved); observed.Events.Clear();
        }
        async Task FinishOriginal(string text)
        {
            var original = Assert.Single(await fixture.ListNativePendingText(), item => item.Text == text);
            var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
            var terminal = new OwnedStoreFixture(fixture, sender, original.LogicalOperation.ToArray(), null);
            _ = await fixture.SendNativeText(sender, original.LogicalOperation.ToArray(), text, grants, terminal);
        }
    }

    private sealed class AtomicQueueNativeCounterListener : EventListener
    {
        private static readonly AsyncLocal<AtomicQueueNativeCounterListener?> Current = new();
        private readonly Action checkPrivateLease;
        internal List<long[]> Events { get; } = [];
        internal bool PrivateLeaseObserved;
        internal AtomicQueueNativeCounterListener(Action checkPrivateLease)
        { this.checkPrivateLease = checkPrivateLease; Current.Value = this; }
        protected override void OnEventSourceCreated(EventSource source)
        { if (source.Name == "Deep-Client-Persistence") EnableEvents(source, EventLevel.Informational); }
        protected override void OnEventWritten(EventWrittenEventArgs value)
        {
            if (!ReferenceEquals(Current.Value, this) || value.EventSource.Name != "Deep-Client-Persistence" || value.EventId != 2) return;
            try { checkPrivateLease(); }
            catch { PrivateLeaseObserved = true; }
            if (value.Payload is { Count: 9 } payload && payload.All(item => item is long))
                Events.Add(payload.Cast<long>().ToArray());
        }
        public override void Dispose()
        { base.Dispose(); if (ReferenceEquals(Current.Value, this)) Current.Value = null; }
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]> QueueAtomicCounterText(Did2MessagingSessionScope scope, string text, CancellationToken ct)
        {
            var selected = await ReadApplicationConversation(scope);
            return (await selected.Account.QueueTextAsync(selected.Handle, text, selected.Source, ct)).ToArray();
        }
        internal void CheckCounterObservationLease()
        {
            var accountLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            using var held = accountLease.AcquireAsync(timeout.Token).GetAwaiter().GetResult();
            held.RequireOwner(accountLease);
        }
    }
}
