using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2AuthoredFloor_ActualOwnerPendingSqlStableFaultsColdResumeWithoutSequenceReuse()
    {
        // Real account/consent/native ratchet/SQLCipher and independently signed
        // proofs. In-process proof source, not socket or physical-device E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x91));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x92)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var ratchetBefore = await fixture.ReadMessagingFloor(sender);
        var points = new[] { Did2TextOutboxFailpoint.AfterPending, Did2TextOutboxFailpoint.AfterSql, Did2TextOutboxFailpoint.AfterStable };
        for (var i = 0; i < points.Length; i++)
        {
            var op = Bytes(32, checked((byte)(0x93 + i))); var point = points[i];
            var interrupted = false;
            using (Did2TextOutboxTestHooks.Push(found =>
            {
                if (found != point) return;
                interrupted = true; throw new IOException("Injected owned authored-floor handover interruption.");
            }))
                await Assert.ThrowsAsync<IOException>(() => fixture.PrepareOwnedText(sender, op, "authored-floor recovery"));
            Assert.True(interrupted);
            byte[] retainedHash;
            using (var journal = await fixture.ReadAuthoredTextJournalAsync(sender))
            {
                var command = journal.Entries[Convert.ToHexString(op)];
                retainedHash = command.EventHash.ToArray();
                Assert.Equal(checked((ulong)i + 3), command.Sequence);
                Assert.Equal(point != Did2TextOutboxFailpoint.AfterStable, command.Pending);
                Assert.Equal(checked((ulong)i + 4), journal.NextSequence(sender));
                Assert.Single(journal.Floors);
            }
            // PrepareOwnedText constructs a new account/source on each call.
            using (var resumed = await fixture.PrepareOwnedText(sender, op, "authored-floor recovery"))
            {
                Assert.Equal(checked((ulong)i + 3), resumed.SenderSequence);
                Assert.Equal(retainedHash, SHA256.HashData(resumed.ExactDmc2.Span));
                using var retry = await fixture.PrepareOwnedText(sender, op, "authored-floor recovery");
                Assert.Equal(resumed.ExactDmc2.ToArray(), retry.ExactDmc2.ToArray());
            }
            using var stable = await fixture.ReadAuthoredTextJournalAsync(sender);
            Assert.Null(stable.Pending); Assert.Equal(checked((ulong)i + 4), stable.NextSequence(sender));
            Assert.Equal(ratchetBefore.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            CryptographicOperations.ZeroMemory(retainedHash);
        }
    }

    private sealed partial class Fixture
    {
        internal async Task<ProtectedDid2DirectTextJournal.State> ReadAuthoredTextJournalAsync(Did2MessagingSessionScope scope)
        {
            using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ??
                throw new InvalidDataException("Test observer lost the actual authored root.");
            return root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        }
    }
}
