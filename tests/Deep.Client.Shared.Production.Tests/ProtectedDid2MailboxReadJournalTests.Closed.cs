using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class ProtectedDid2MailboxReadJournalTests
{
    [Fact]
    public void EmptyClosedCollectionIsOneCanonicalGrammarWithoutASecondReader()
    {
        var expected = new byte[96]; expected[0] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(expected.AsSpan(4), 1);
        Network.CopyTo(expected, 12); Account.CopyTo(expected, 28); Instance.CopyTo(expected, 60);
        Assert.Equal(expected, ProtectedDid2MailboxReadJournal.Empty(Network, Account, Instance));
        using var read = ProtectedDid2MailboxReadJournal.Decode(expected, Network, Account, Instance);
        Assert.Empty(read.Closed); Assert.Null(read.Active);
    }

    [Fact]
    public void ClosedPendingFactsRoundtripWithoutResettingTraversalOrRevivingOriginalGrant()
    {
        using var state = ClosedPending(); Roundtrip(state);
        var closed = Assert.Single(state.Closed).Value;
        Assert.Equal(Grant, closed.Grant); Assert.Empty(closed.ExactMau);
        Assert.Equal(1_100UL, closed.ClosedAtLower); Assert.Single(state.Traversals);
        state.Active = ProtectedDid2MailboxReadJournal.Cycle.Begin(Grant, Scope, Route, 0, closed.RetrieveBody);
        state.Phase = 1; state.Revision++;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxReadJournal.Encode(state, Network, Account, Instance));
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    public void MalformedClosedFactsOrMissingTraversalCannotBecomeClosureAuthority(int defect)
    {
        using var state = ClosedPending(); var closed = Assert.Single(state.Closed).Value;
        switch (defect)
        {
            case 0: closed.Phase = 3; break;
            case 1: closed.ClosedAtLower--; break;
            case 2: closed.GrantExpiry = 0; break;
            case 3: closed.Counter = 1; break;
            case 4: closed.MauHash[0] = 1; break;
            case 5: closed.ExactMau = [1]; break;
            case 6: state.Traversals.Clear(); break;
            case 7: closed.Grant[0] ^= 1; break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxReadJournal.Encode(state, Network, Account, Instance));
    }

    [Theory]
    [InlineData("page")] [InlineData("capture-time")] [InlineData("ack-body")]
    [InlineData("ack-counter")] [InlineData("ack-hash")] [InlineData("ack-reply")]
    public void PageOrAckCannotBeDiscardedByTheUncapturedClosureBuilder(string field)
    {
        using var state = Pending();
        switch (field)
        {
            case "page": state.Active!.Page = [1]; break;
            case "capture-time": state.Active!.CapturedAt = 1; break;
            case "ack-body": state.Active!.AckBody = [1]; break;
            case "ack-counter": state.Active!.AckCounter = 1; break;
            case "ack-hash": state.Active!.AckMauHash[0] = 1; break;
            case "ack-reply": state.Active!.AckReply = [1]; break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxReadJournal.ClosedAttempt.Capture(state.Active!, 1, 1_100, 1_100, []));
    }

    [Fact]
    public void CompleteNewCycleReservationUsesTheExistingHardByteBound()
    {
        var maximumIdle = ProtectedDid2MailboxReadJournal.MaximumBytes - ProtectedDid2MailboxReadJournal.MaximumNewCycleGrowthBytes;
        Assert.True(maximumIdle >= ProtectedDid2MailboxReadJournal.HeaderBytes);
        Assert.Equal(348, ProtectedDid2MailboxReadJournal.MaximumNewCycleGrowthBytes - ProtectedDid2MailboxReadJournal.MaximumActiveCycleBytes);
        ProtectedDid2MailboxReadJournal.RequireRoomForNewCycle(maximumIdle);
        Assert.Throws<IOException>(() => ProtectedDid2MailboxReadJournal.RequireRoomForNewCycle(maximumIdle + 1));
        Assert.Equal(750_000, ProtectedDid2MailboxReadJournal.MaximumBytes);
        Assert.Equal(128, ProtectedDid2MailboxReadJournal.MaximumFloors);
    }

    private static ProtectedDid2MailboxReadJournal.State ClosedPending()
    {
        var state = Pending(); var cycle = state.Active!;
        state.Closed.Add(Convert.ToHexString(Grant), ProtectedDid2MailboxReadJournal.ClosedAttempt.Capture(cycle, 1, 1_100, 1_100, []));
        state.Active = null; state.Phase = 0; state.Revision++; cycle.Dispose(); return state;
    }
}
