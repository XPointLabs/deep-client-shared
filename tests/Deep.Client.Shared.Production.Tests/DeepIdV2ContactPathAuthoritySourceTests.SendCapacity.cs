using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0, false)]
    [InlineData(3, false)]
    [InlineData(0, true)]
    [InlineData(3, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedText_TransportBackpressurePreservesAuthoredRatchetAndColdExactRetry(int fault, bool preparedDraft)
    {
        // Full occupancy is disposable rejection metadata, not evidence of
        // sustained512 delivery. Public Queue/Retry use real PQ accounts,
        // native ratchet, encrypted SQL and owned grant/receipt verification.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x81));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x82)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        const string text = "Backpressure precedes a new ratchet step";
        byte[] draft = [], operation = [];
        if (preparedDraft)
        {
            operation = await fixture.QueueNativeText(sender, text);
            using var retained = await fixture.RetryOwnedText(sender, operation, text);
            draft = retained.ExactDmc2.ToArray();
        }
        var authoredBefore = await fixture.ReadAuthoredRootDigestAsync();
        var sqlBefore = await fixture.ReadAuthoredApplicationDigestAsync(sender);
        var ratchetBefore = await fixture.ReadMessagingFloor(sender);
        var stagedOperation = preparedDraft ? operation : Bytes(32, 0x83);
        var originalRoot = await fixture.StageNewTextBackpressureAsync(sender, stagedOperation, fault);
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var blockedTransport = new OwnedStoreFixture(fixture, sender, stagedOperation, null);
        try
        {
            // Each public call reopens the account and its independently
            // verified sources; denial must not initialize or evict anything.
            for (var repeat = 0; repeat < 2; repeat++)
            {
                if (preparedDraft) await Assert.ThrowsAsync<IOException>(() => fixture.SendNativeText(sender, operation, text, grants, blockedTransport));
                else await Assert.ThrowsAsync<IOException>(() => fixture.QueueNativeText(sender, text));
            }
            Assert.Equal(0, grants.Calls); Assert.Equal(0, blockedTransport.Calls);
            Assert.Equal(authoredBefore, await fixture.ReadAuthoredRootDigestAsync());
            Assert.Equal(sqlBefore, await fixture.ReadAuthoredApplicationDigestAsync(sender));
            Assert.Equal(ratchetBefore.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            Assert.Equal(preparedDraft ? 1 : 0, (await fixture.ListNativePendingText()).Count);
            using (var retained = await fixture.ReadMailboxSends())
            {
                Assert.Equal(fault == 0 ? ProtectedDid2MailboxSendJournal.MaximumEntries : 0, retained.Entries.Count);
                Assert.Equal(ProtectedDid2MailboxSendJournal.MaximumFloors, retained.Floors.Count);
            }
            // Test-only restoration of the disposable capacity fixture, not
            // a product repair/retirement path or a raised working-set bound.
            await fixture.RestoreMailboxSendRoot(originalRoot);
            if (!preparedDraft) operation = await fixture.QueueNativeText(sender, text);
            var transport = preparedDraft ? blockedTransport : new OwnedStoreFixture(fixture, sender, operation, null);
            var stored = await fixture.SendNativeText(sender, operation, text, grants, transport);
            Assert.Equal(1UL, stored.Cursor); Assert.Equal(1, grants.Calls); Assert.Equal(1, transport.Calls);
            var committed = await fixture.ReadMessagingFloor(sender);
            Assert.Equal(ratchetBefore.Ordinal + 1, committed.Ordinal);
            // The dispatch installation clock advances conservatively with
            // elapsed work. Bring this synthetic signed proof source past its
            // own durable receipt before historical cached verification.
            fixture.AdvanceSyntheticMailboxClockPast(transport.DurableTimeForFixture);
            if (preparedDraft)
            {
                using var exact = await fixture.RetryOwnedText(sender, operation, text);
                Assert.Equal(draft, exact.ExactDmc2.ToArray());
            }
            var retry = await fixture.SendNativeText(sender, operation, text, grants, transport);
            Assert.Equal(stored.Cursor, retry.Cursor); Assert.Equal(stored.Disposition, retry.Disposition);
            Assert.Equal(stored.EntryRouterId.ToArray(), retry.EntryRouterId.ToArray());
            Assert.True(stored.IngressDispatched); Assert.False(retry.IngressDispatched);
            Assert.Equal(1, grants.Calls); Assert.Equal(1, transport.Calls);
            Assert.Equal(committed.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        }
        finally
        {
            foreach (var bytes in new[] { draft, authoredBefore, sqlBefore, originalRoot }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]> StageNewTextBackpressureAsync(Did2MessagingSessionScope scope, byte[] operation, int fault)
        {
            using var original = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
            var exact = original.Use(bytes => bytes.ToArray());
            try
            {
                _ = await StageRejectedMailboxSend(scope, operation, Bytes(64, 0x84), fault);
                return exact;
            }
            catch { CryptographicOperations.ZeroMemory(exact); throw; }
        }
    }
}
