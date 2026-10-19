using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class Did2OwnedTextOutboxTests
{
    [Fact]
    public void GroupSchedulingHintSkipsOnlyPreviouslyCompletedWorkWithoutMutatingOrReturningReceipts()
    {
        var scope = Scope(); var op = B(32, 0xd1); using var state = Pending(scope, op, 3);
        var item = new ProtectedDid2GroupJournal.Outgoing
        { Scope = scope.Exact.ToArray(), Operation = op, Event = state.Pending!.PendingDmc2.ToArray(), Adopted = true };
        Assert.False(ProtectedDeepIdV2AccountOwner.HasCompletedGroupDeliveryHint(item, state, scope));
        Stabilize(state, op);
        Assert.False(ProtectedDeepIdV2AccountOwner.HasCompletedGroupDeliveryHint(item, state, scope));
        state.RetainStore(Convert.ToHexString(op), 1500);
        var before = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.True(ProtectedDeepIdV2AccountOwner.HasCompletedGroupDeliveryHint(item, state, scope));
        Assert.Equal(before, ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance));
        item.Adopted = false;
        Assert.False(ProtectedDeepIdV2AccountOwner.HasCompletedGroupDeliveryHint(item, state, scope));
        item.Adopted = true;
        state.RetireSuccessfulCommands([state.Entries[Convert.ToHexString(op)]]);
        Assert.True(ProtectedDeepIdV2AccountOwner.HasCompletedGroupDeliveryHint(item, state, scope));
        state.ExpireAudit(Convert.ToHexString(op));
        Assert.False(ProtectedDeepIdV2AccountOwner.HasCompletedGroupDeliveryHint(item, state, scope));
    }

    [Theory]
    [InlineData(1)] [InlineData(2)]
    public void GroupSchedulingNeverTreatsStoppedAuditAsSuccessfulDelivery(int reason)
    {
        var scope = Scope(); var op = B(32, 0xd2); using var state = new ProtectedDid2DirectTextJournal.State();
        var raw = new byte[48]; op.CopyTo(raw, 0); BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(32), 1500); raw[40] = (byte)reason;
        state.TerminalAudits.Add(Convert.ToHexString(op), new(raw));
        var item = new ProtectedDid2GroupJournal.Outgoing { Scope = scope.Exact.ToArray(), Operation = op, Adopted = true };
        Assert.False(ProtectedDeepIdV2AccountOwner.HasCompletedGroupDeliveryHint(item, state, scope));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void GroupSchedulingRejectsChangedPayloadAndForeignAuthoredScope(bool foreign)
    {
        var scope = Scope(); var op = B(32, 0xd3); using var state = Pending(scope, op, 3);
        var item = new ProtectedDid2GroupJournal.Outgoing
        { Scope = scope.Exact.ToArray(), Operation = op, Event = state.Pending!.PendingDmc2.ToArray(), Adopted = true };
        Stabilize(state, op); state.RetainStore(Convert.ToHexString(op), 1500);
        if (foreign) { scope = Scope(false); item.Scope = scope.Exact.ToArray(); }
        else item.Event[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => ProtectedDeepIdV2AccountOwner.HasCompletedGroupDeliveryHint(item, state, scope));
    }

    [Theory]
    [InlineData(0)] [InlineData(4)] [InlineData(255)]
    public void TerminalAuditRejectsUnknownReasonsBeforeRetainingMetadata(int reason)
    {
        var raw = new byte[48]; B(32, 0xc3).CopyTo(raw, 0);
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(32), 1500); raw[40] = checked((byte)reason);
        Assert.Throws<InvalidDataException>(() => new ProtectedDid2DirectTextJournal.TerminalAudit(raw));
    }

    [Fact]
    public void SuccessfulCompactionKeepsOnlyRandomOperationAndFirstTimeWithoutResettingAuthoredFloor()
    {
        var scope = Scope(); var op = B(32, 0xc0); using var state = Pending(scope, op, 3); Stabilize(state, op);
        state.RetainStore(Convert.ToHexString(op), 1500);
        state.RetireSuccessfulCommands([state.Entries[Convert.ToHexString(op)]]);
        Assert.Empty(state.Entries); var audit = Assert.Single(state.TerminalAudits).Value;
        Assert.Equal(48, audit.Exact.Length); Assert.Equal(op, audit.Operation.ToArray()); Assert.Equal(1500UL, audit.TerminalAtUpper);
        Assert.Equal((byte)3, audit.Reason); Assert.Equal(new byte[7], audit.Exact[41..].ToArray()); Assert.Equal(4UL, state.NextSequence(scope));
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Equal(100 + ProtectedDid2DirectTextJournal.FloorBytes + 48, exact.Length);
        using var reopened = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Empty(reopened.Entries); Assert.Single(reopened.TerminalAudits); Assert.Equal(4UL, reopened.NextSequence(scope));
        var changed = exact.ToArray(); changed[^1] = 1;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode(changed, scope.Network, scope.LocalAccount, scope.Instance));
    }

    [Fact]
    public void FullSuccessfulAuditBudgetBackpressuresWithoutEvictionOrCounterReset()
    {
        // Structural budget coverage, not authority to synthesize or expire audits.
        var scope = Scope(); var count = ProtectedDid2DirectTextJournal.MaximumTerminalAudits;
        using var state = new ProtectedDid2DirectTextJournal.State { Revision = checked(1UL + 3UL * (ulong)count) };
        state.Floors.Add(ProtectedDid2DirectTextJournal.Position(scope), new(scope, checked(3UL + (ulong)count)));
        for (var index = 1; index <= count; index++)
        {
            var raw = new byte[48]; BinaryPrimitives.WriteInt32BigEndian(raw.AsSpan(28), index);
            BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(32), 1000);
            raw[40] = 3;
            var audit = new ProtectedDid2DirectTextJournal.TerminalAudit(raw);
            state.TerminalAudits.Add(Convert.ToHexString(audit.Operation), audit);
        }
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        using var reopened = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Throws<InvalidOperationException>(() => reopened.RequireCapacity(scope));
        Assert.Equal(count, reopened.TerminalAudits.Count);
        Assert.Equal(checked(3UL + (ulong)count), reopened.NextSequence(scope));
        Assert.Equal(exact, ProtectedDid2DirectTextJournal.Encode(reopened, scope.Network, scope.LocalAccount, scope.Instance));
        Assert.Equal(512, ProtectedDid2DirectTextJournal.MaximumEntries);
    }

    [Theory]
    [InlineData(0UL)] [InlineData(9223372036852183808UL)] [InlineData(ulong.MaxValue)]
    public void InvalidSuccessfulTimeCannotMutateOrForgeCompletion(ulong time)
    {
        var scope = Scope(); var op = B(32, 0xc1); using var state = Pending(scope, op, 3); Stabilize(state, op);
        var before = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Throws<InvalidDataException>(() => state.RetainStore(Convert.ToHexString(op), time));
        Assert.Equal(before, ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance));
    }

    [Fact]
    public void SuccessfulAuditHasNoPayloadAndCannotExistWithoutAuthoredFloor()
    {
        var scope = Scope(); var op = B(32, 0xc2); var raw = new byte[48]; op.CopyTo(raw, 0);
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(32), 1000);
        raw[40] = 3;
        using var state = new ProtectedDid2DirectTextJournal.State { Revision = 2 };
        state.TerminalAudits.Add(Convert.ToHexString(op), new(raw));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance));
        Assert.True(ProtectedDid2DirectTextJournal.MaximumBytes < 1_048_576);
        Assert.Equal(512, ProtectedDid2DirectTextJournal.MaximumEntries);
    }
}
