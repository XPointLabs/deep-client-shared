using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class Did2OwnedTextOutboxTests
{
    [Fact]
    public void ClosedMiddleWorkKeepsSparsePositionsAndIndependentFloorWithoutAllowingDuplicates()
    {
        // Codec-only shape; removal here is not a production deletion capability.
        var scope = Scope(); var first = B(32, 0xa1); var middle = B(32, 0xa2); var last = B(32, 0xa3);
        using var state = Pending(scope, first, 3); Stabilize(state, first);
        state.AddPending(Make(scope, middle, 4)); Stabilize(state, middle);
        state.StopWork(Convert.ToHexString(middle), ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, 1500);
        state.RetireWorkingPayload(Convert.ToHexString(middle));
        state.AddPending(Make(scope, last, 5)); Stabilize(state, last);
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        using var cold = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Equal(new ulong[] { 3, 5 }, cold.Entries.Values.Select(entry => entry.Sequence));
        Assert.Equal(6UL, cold.NextSequence(scope)); Assert.Single(cold.TerminalAudits);
        var duplicate = exact.ToArray();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(duplicate.AsSpan(
            ProtectedDid2DirectTextJournal.HeaderBytes + ProtectedDid2DirectTextJournal.FloorBytes +
            ProtectedDid2DirectTextJournal.PrefixBytes + 468), 3);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode(duplicate, scope.Network, scope.LocalAccount, scope.Instance));
        cold.Floors[ProtectedDid2DirectTextJournal.Position(scope)] = new(scope, 5);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Encode(cold, scope.Network, scope.LocalAccount, scope.Instance));
    }

    [Fact]
    public void ExpiredStoppedWorkMustReleaseWorkingCapacityWithoutResettingAuthoredFloor()
    {
        // Canonical local-state boundary, not a deletion capability or native
        // delivery claim. The owner's mixed-queue test exercises real cleanup.
        var scope = Scope();
        using var state = new ProtectedDid2DirectTextJournal.State();
        for (var index = 0; index < ProtectedDid2DirectTextJournal.MaximumEntries; index++)
        {
            var operation = SHA256.HashData(BitConverter.GetBytes(index));
            var name = Convert.ToHexString(operation);
            state.AddPending(Make(scope, operation, state.NextSequence(scope)));
            state.Stabilize(name);
            state.StopWork(name, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, 1500);
            state.RetireWorkingPayload(name);
            state.ExpireAudit(name);
        }
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        using var cold = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Equal(3UL + (ulong)ProtectedDid2DirectTextJournal.MaximumEntries, cold.NextSequence(scope));
        cold.RequireCapacity(scope);
        Assert.Equal(state.Revision, cold.Revision);
        Assert.Equal(exact, ProtectedDid2DirectTextJournal.Encode(cold, scope.Network, scope.LocalAccount, scope.Instance));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StoppedWorkAndVerifiedStoreAreIndependentMonotonicFacts(bool storeFirst)
    {
        var scope = Scope(); var op = B(32, 0xb7); var name = Convert.ToHexString(op);
        using var state = Pending(scope, op, 3); Stabilize(state, op);
        if (storeFirst)
        {
            state.RetainStore(name, 1000);
            Assert.Throws<InvalidOperationException>(() => state.StopWork(name, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, 1500));
        }
        else
        {
            state.StopWork(name, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, 1500);
            state.RetainStore(name, 1000);
        }
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        using var cold = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        var item = Assert.Single(cold.Entries).Value;
        Assert.True(item.Stored); Assert.Equal(!storeFirst, item.WorkStopped); Assert.False(item.Pending);
        Assert.Equal(storeFirst ? ProtectedDid2DirectTextJournal.WorkStopReason.Active : ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, item.StopReason);
        Assert.Equal(storeFirst ? 0UL : 1500UL, item.StoppedAtUpper);
        Assert.Equal(storeFirst ? 1000UL : 0UL, item.FirstSuccessfulStoreUpper);
        Assert.Equal(storeFirst ? 4UL : 5UL, cold.Revision); Assert.Equal(4UL, cold.NextSequence(scope));
        Assert.Throws<InvalidOperationException>(() => cold.StopWork(name, ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired, 2000));
        Assert.Equal(exact, ProtectedDid2DirectTextJournal.Encode(cold, scope.Network, scope.LocalAccount, scope.Instance));
    }

    [Theory]
    [InlineData(0UL)]
    [InlineData(9223372036852183808UL)]
    [InlineData(ulong.MaxValue)]
    public void InvalidStopTimeCannotMutateOriginalWork(ulong time)
    {
        var scope = Scope(); var op = B(32, 0xbc); using var state = Pending(scope, op, 3); Stabilize(state, op);
        var before = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Throws<InvalidDataException>(() => state.StopWork(Convert.ToHexString(op), ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, time));
        Assert.Equal(before, ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance));
    }

    [Fact]
    public async Task RetiredWorkingPayloadDoesNotRehydrateOrResetCounter()
    {
        var scope = Scope(); var op = B(32, 0xba); var name = Convert.ToHexString(op);
        using var fixture = new SqlFixture(); using var state = Pending(scope, op, 3);
        using (var store = new Deep.Client.Shared.Persistence.SqliteDeepMailboxStore(new(fixture.Path, fixture.Key)))
        {
            using var row = await Mirror(store, state, scope, op); Stabilize(state, op);
            state.StopWork(name, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, 1500);
            // Disposable SQL corruption probes the mirror only; the actual
            // owner's protected plan/deletion is covered by native tests.
            fixture.Execute("DELETE FROM direct_text_outbox;");
            await Assert.ThrowsAsync<CryptographicException>(() => Mirror(store, state, scope, op));
            state.RetireWorkingPayload(name);
            // A model marker without the independently authenticated SQL
            // audit must reject. This fixture does not authorize expiry;
            // actual protected producer/recovery is covered by native tests.
            await Assert.ThrowsAsync<CryptographicException>(() => Mirror(store, state, scope, op));
            state.ExpireAudit(name);
            Assert.Null(await Mirror(store, state, scope, op));
            Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM direct_text_outbox;"));
            Assert.Equal(4UL, state.NextSequence(scope));
            Assert.False(state.Entries.ContainsKey(name)); Assert.False(state.TerminalAudits.ContainsKey(name));
            Assert.Throws<KeyNotFoundException>(() => state.RetainStore(name, 1000));
        }
    }

    [Fact]
    public void ExpiredAuditDeletesMetadataWithoutRestoringWorkingCommandOrCounter()
    {
        var scope = Scope(); var op = B(32, 0xbe); var name = Convert.ToHexString(op);
        using var state = Pending(scope, op, 3); Stabilize(state, op);
        state.StopWork(name, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, 1500);
        Assert.Throws<InvalidOperationException>(() => state.ExpireAudit(name));
        state.RetireWorkingPayload(name);
        Assert.False(state.Entries.ContainsKey(name));
        var audit = state.TerminalAudits[name];
        Assert.Equal(48, audit.Exact.Length); Assert.Equal(op, audit.Operation.ToArray());
        Assert.Equal((byte)1, audit.Reason); Assert.Equal(1500UL, audit.TerminalAtUpper);
        state.ExpireAudit(name);
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        using var cold = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Empty(cold.Entries); Assert.Empty(cold.TerminalAudits);
        Assert.Equal(4UL, cold.NextSequence(scope)); Assert.Equal(6UL, cold.Revision);
        Assert.Throws<InvalidOperationException>(() => cold.ExpireAudit(name));
        Assert.Throws<KeyNotFoundException>(() => cold.StopWork(name, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, 2000));
        Assert.Equal(exact, ProtectedDid2DirectTextJournal.Encode(cold, scope.Network, scope.LocalAccount, scope.Instance));
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(2, true)]
    [InlineData(3, false)]
    [InlineData(255, false)]
    public void UnknownStopReasonsAndStoppedPendingPayloadReject(int reason, bool pending)
    {
        var scope = Scope(); var op = B(32, 0xb8); using var state = Pending(scope, op, 3);
        if (!pending) Stabilize(state, op);
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        var offset = ProtectedDid2DirectTextJournal.HeaderBytes + ProtectedDid2DirectTextJournal.FloorBytes;
        exact[offset + 518] = (byte)reason;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance));
    }
}
