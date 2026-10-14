using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ProtectedDid2MailboxSendJournalTests
{
    private static readonly byte[] Network = Bytes(16, 0x11), Account = Bytes(32, 0x12), Instance = Bytes(32, 0x13);
    [Fact]
    public void InitialStoreOperationHasItsClosedDomainAndRequiresActualIntentShape()
    {
        var intent = Bytes(32, 0x41);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Local/DID2/InitialMailboxIntent/1"u8); hash.AppendData([0]); hash.AppendData(intent);
        Assert.Equal(hash.GetHashAndReset(), ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent));
        Assert.NotEqual(intent, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent));
        Assert.Throws<ArgumentException>(() => ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(new byte[31]));
        Assert.Throws<ArgumentException>(() => ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(new byte[32]));
    }
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)]
    [InlineData(7)] [InlineData(8)] [InlineData(9)] [InlineData(10)]
    public void HeaderRejectsUnknownForeignOversizedOrNoncanonicalCustody(int fault)
    {
        var exact = ProtectedDid2MailboxSendJournal.Empty(Network, Account, Instance);
        switch (fault)
        {
            case 0: exact[0] = 1; break; // Retired MAU2 custody, even if empty.
            case 1: exact[1] = 1; break;
            case 2: BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), 513); break;
            case 3: exact[11] = 0; break;
            case 4: exact[12] ^= 1; break;
            case 5: exact[60] ^= 1; break;
            case 6: exact = [.. exact, 0]; break;
            case 7: exact[0] = 2; break; // Previous commitment has no independent replay floors.
            case 8: BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(92), 513); break;
            case 9: exact[94] = 1; break;
            case 10: exact[0] = 3; break; // Previous unlinked-attempt root, including empty.
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Decode(exact, Network, Account, Instance));
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public void EntryRejectsChangedKeyUnknownPhaseReservedMissingCounterOrInvalidLifetime(int fault)
    {
        using var pending = Pending(0x14);
        var exact = pending.Exact.ToArray();
        switch (fault)
        {
            case 0: exact[0] ^= 1; break;
            case 1: exact[296] = 3; break;
            case 2: exact[297] = 1; break;
            case 3: exact[296] = 2; break;
            case 4: exact[263] = 1; break;
            case 5: BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(216), 1059); break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Entry.Decode(exact));
    }

    [Fact]
    public void ExactRoundtripPreparedCounterFloorAndDuplicatePendingOrCounterRejection()
    {
        using var state = new ProtectedDid2MailboxSendJournal.State { Revision = 2 };
        state.EnrollScope(Bytes(32, 0x18), Bytes(32, 0x45));
        using var pending = Pending(0x14);
        var entry = ProtectedDid2MailboxSendJournal.Entry.Decode(pending.Exact);
        state.Entries.Add(entry.Name, entry);
        var bytes = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        using (var read = ProtectedDid2MailboxSendJournal.Decode(bytes, Network, Account, Instance))
        { Assert.False(Assert.Single(read.Entries).Value.Prepared); Assert.Equal(1UL, read.MinimumCounter(Bytes(32, 0x18))); }
        using var other = Pending(0x15);
        state.Revision++;
        state.Entries.Add(other.Name, ProtectedDid2MailboxSendJournal.Entry.Decode(other.Exact));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance));
        state.Entries[other.Name].Dispose(); state.Entries.Remove(other.Name);
        var prepared = entry.WithPrepared(Bytes(64, 0x20), 7);
        state.AdvanceCounter(entry.GrantHash, 7);
        state.Entries[entry.Name] = prepared; entry.Dispose();
        bytes = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        using (var read = ProtectedDid2MailboxSendJournal.Decode(bytes, Network, Account, Instance))
        { Assert.True(Assert.Single(read.Entries).Value.Prepared); Assert.Equal(8UL, read.MinimumCounter(Bytes(32, 0x18))); }
        var sameCounter = other.WithPrepared(Bytes(64, 0x21), 7);
        state.Entries.Add(sameCounter.Name, sameCounter);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance));
    }

    [Fact]
    public void WorkingEntryRemovalAndReopenCannotLowerIndependentFloor()
    {
        using var state = new ProtectedDid2MailboxSendJournal.State { Revision = 2 };
        using var pending = Pending(0x14);
        state.EnrollScope(pending.GrantHash, Bytes(32, 0x45));
        var prepared = pending.WithPrepared(Bytes(64, 0x20), 7);
        state.AdvanceCounter(pending.GrantHash, 7); state.Entries.Add(prepared.Name, prepared);
        prepared.Dispose(); state.Entries.Clear(); state.Revision++;
        // Structural cleanup fixture only: no public retirement permission or
        // compaction consumer is established by deleting this commitment.
        var exact = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        using var reopened = ProtectedDid2MailboxSendJournal.Decode(exact, Network, Account, Instance);
        Assert.Empty(reopened.Entries); Assert.Single(reopened.Floors);
        Assert.Equal(8UL, reopened.MinimumCounter(pending.GrantHash));
        Assert.Throws<CryptographicException>(() => reopened.AdvanceCounter(Bytes(32, 0x18), 7));
        Assert.Throws<InvalidDataException>(() => reopened.MinimumCounter(Bytes(32, 0x19)));
        reopened.AdvanceCounter(Bytes(32, 0x18), 8); reopened.Revision++;
        using var again = ProtectedDid2MailboxSendJournal.Decode(
            ProtectedDid2MailboxSendJournal.Encode(reopened, Network, Account, Instance), Network, Account, Instance);
        Assert.Equal(9UL, again.MinimumCounter(pending.GrantHash));
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public void FloorsRejectMissingChangedUnderReservedOrExhaustedCustody(int fault)
    {
        using var state = new ProtectedDid2MailboxSendJournal.State { Revision = 2 };
        using var pending = Pending(0x14);
        state.EnrollScope(pending.GrantHash, Bytes(32, 0x45)); state.AdvanceCounter(pending.GrantHash, 7);
        var entry = pending.WithPrepared(Bytes(64, 0x20), 7); state.Entries.Add(entry.Name, entry);
        var exact = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        switch (fault)
        {
            case 0: BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(92), 0); break;
            case 1: exact[ProtectedDid2MailboxSendJournal.HeaderBytes + 32] ^= 1; break;
            case 2: BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(ProtectedDid2MailboxSendJournal.HeaderBytes + 64), 6); break;
            case 3: BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(ProtectedDid2MailboxSendJournal.HeaderBytes + 64), ulong.MaxValue); break;
            case 4: exact.AsSpan(ProtectedDid2MailboxSendJournal.HeaderBytes, 32).Clear(); break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Decode(exact, Network, Account, Instance));
    }

    [Fact]
    public void NamespaceCannotRebindGrantAndFloorCapacityCannotEvictEarlierCounter()
    {
        using var state = new ProtectedDid2MailboxSendJournal.State();
        for (var index = 0; index < ProtectedDid2MailboxSendJournal.MaximumFloors; index++)
        {
            var identity = SHA256.HashData(BitConverter.GetBytes(index));
            state.EnrollScope(identity, identity); state.Revision++;
        }
        var first = SHA256.HashData(BitConverter.GetBytes(0)); state.AdvanceCounter(first, 7); state.Revision++;
        Assert.Throws<IOException>(() => state.EnrollScope(Bytes(32, 0x17), Bytes(32, 0x19)));
        Assert.Throws<CryptographicException>(() => state.EnrollScope(Bytes(32, 0x18), first));
        Assert.Throws<IOException>(() => state.EnrollScope(first, Bytes(32, 0x19)));
        Assert.Equal(8UL, state.MinimumCounter(first)); Assert.Empty(state.Entries);
        using var reopened = ProtectedDid2MailboxSendJournal.Decode(
            ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance), Network, Account, Instance);
        Assert.Equal(8UL, reopened.MinimumCounter(first)); Assert.Equal(ProtectedDid2MailboxSendJournal.MaximumFloors, reopened.Floors.Count);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void ClosedUnknownAndReciprocalSuccessorRoundtripPreserveOriginalRequestAndFloors(bool prepared)
    {
        // Pure codec/structural metadata. No authenticated clock, owner lease,
        // SQL settlement, issuer, retirement or delivery is established here.
        using var state = new ProtectedDid2MailboxSendJournal.State { Revision = 2 };
        using var pending = Pending(0x14);
        using var constrained = pending.WithAdmissionCeiling(1100);
        using var original = prepared ? constrained.WithPrepared(Bytes(64, 0x20), 7) :
            ProtectedDid2MailboxSendJournal.Entry.Decode(constrained.Exact);
        var closed = original.CloseUnknown(1100);
        state.EnrollScope(closed.GrantHash, Bytes(32, 0x45));
        if (prepared) state.AdvanceCounter(closed.GrantHash, 7);
        state.Entries.Add(closed.Name, closed);
        using var next = Successor(closed);
        state.EnrollScope(next.GrantHash, Bytes(32, 0x46)); state.Revision++;
        state.LinkSuccessor(closed, next);
        var encoded = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        using var reopened = ProtectedDid2MailboxSendJournal.Decode(encoded, Network, Account, Instance);
        var current = reopened.Current(original.ScopeHash, original.Operation)!;
        Assert.Equal(next.Exact.ToArray(), current.Exact.ToArray()); Assert.False(current.Closed); Assert.False(current.Prepared);
        var retained = reopened.Entries[original.Name];
        Assert.True(retained.Closed); Assert.Equal(prepared, retained.Prepared);
        Assert.Equal(original.Exact[..296].ToArray(), retained.Exact[..296].ToArray());
        Assert.Equal(original.Attempt.ToArray(), current.Predecessor.ToArray());
        Assert.Equal(next.Attempt.ToArray(), retained.Successor.ToArray());
        Assert.Equal(original.EnvelopeHash.ToArray(), current.EnvelopeHash.ToArray());
        Assert.Equal(original.RetryUntil, current.RetryUntil); Assert.Equal(original.Expires, current.Expires);
        Assert.Equal(prepared ? 8UL : 1UL, reopened.MinimumCounter(original.GrantHash));
        Assert.Equal(1UL, reopened.MinimumCounter(next.GrantHash));
        Assert.Throws<InvalidDataException>(() => retained.WithPrepared(Bytes(64, 0x21), 8));
        Assert.Throws<InvalidDataException>(() => reopened.LinkSuccessor(retained, next));
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    [InlineData(5)] [InlineData(6)] [InlineData(7)]
    public void SendChainsRejectMissingBrokenCrossMessageOrUnclosedLinks(int fault)
    {
        using var state = new ProtectedDid2MailboxSendJournal.State { Revision = 3 };
        using var pending = Pending(0x14);
        var closed = pending.WithAdmissionCeiling(1100);
        using (closed) state.Entries.Add(closed.Name, closed.CloseUnknown(1100));
        var parent = Assert.Single(state.Entries).Value;
        var parentName = parent.Name;
        state.EnrollScope(parent.GrantHash, Bytes(32, 0x45));
        using var next = Successor(parent); state.EnrollScope(next.GrantHash, Bytes(32, 0x46));
        state.LinkSuccessor(parent, next);
        var exact = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        var offset = ProtectedDid2MailboxSendJournal.HeaderBytes + 2 * ProtectedDid2MailboxSendJournal.FloorBytes;
        var firstIsParent = exact.AsSpan(offset, 32).SequenceEqual(Convert.FromHexString(parentName));
        // LinkSuccessor consumed its original parent; use immutable fixture IDs.
        var parentOffset = firstIsParent ? offset : offset + ProtectedDid2MailboxSendJournal.EntryBytes;
        var childOffset = firstIsParent ? offset + ProtectedDid2MailboxSendJournal.EntryBytes : offset;
        switch (fault)
        {
            case 0: exact.AsSpan(parentOffset + 368, 32).Clear(); break;
            case 1: exact[parentOffset + 368] ^= 1; break;
            case 2: exact[childOffset + 336] ^= 1; break;
            case 3: exact[childOffset + 64] ^= 1; break;
            case 4: exact[childOffset + 160] ^= 1; break;
            case 5: BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(childOffset + 400), 1199); break;
            case 6: BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(childOffset + 416), 3); break;
            case 7: exact[parentOffset + 296] = 1; exact.AsSpan(parentOffset + 408, 8).Clear(); break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Decode(exact, Network, Account, Instance));
    }

    [Fact]
    public void AdmissionAndSuccessorCannotExtendOriginalDeadlineOrBypassClosure()
    {
        using var pending = Pending(0x14);
        using var original = pending.WithAdmissionCeiling(1100);
        Assert.Throws<InvalidDataException>(() => original.WithAdmissionCeiling(1101));
        Assert.Throws<InvalidDataException>(() => original.CloseUnknown(1099));
        Assert.Throws<InvalidDataException>(() => Successor(original));
        using var closed = original.CloseUnknown(1100);
        Assert.Throws<InvalidDataException>(() => closed.CloseUnknown(1101));
        Assert.Throws<InvalidDataException>(() => Successor(closed, created: 1099));
        Assert.Throws<InvalidDataException>(() => Successor(closed, created: 1200));
        Assert.Throws<InvalidDataException>(() => Successor(closed, expiry: 1201));
        Assert.Throws<InvalidDataException>(() => Successor(closed, admission: 1100));
        Assert.Throws<InvalidDataException>(() => Successor(closed, admission: 1201));
        Assert.True(ProtectedDid2MailboxSendJournal.MaximumBytes < DeepSecureStorageRegistration.MaximumValueBytes);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void WholeChainSelectionAndCommitmentPreserveAllAttemptsAndIndependentFloors(bool preparedChild)
    {
        using var state = new ProtectedDid2MailboxSendJournal.State { Revision = 2 };
        using var pending = Pending(0x14);
        using var ceiling = pending.WithAdmissionCeiling(1100);
        using var prepared = ceiling.WithPrepared(Bytes(64, 0x20), 7);
        var parent = prepared.CloseUnknown(1100);
        var rootName = parent.Name; var scope = parent.ScopeHash.ToArray(); var native = parent.Operation.ToArray();
        state.EnrollScope(parent.GrantHash, Bytes(32, 0x45)); state.AdvanceCounter(parent.GrantHash, 7);
        state.Entries.Add(parent.Name, parent);
        var one = state.ChainCommitment(scope, native);
        Assert.Equal(SHA256.HashData(parent.Exact), one); // Single-record plan meaning is unchanged.
        using var next = Successor(parent); state.EnrollScope(next.GrantHash, Bytes(32, 0x46));
        state.LinkSuccessor(parent, next);
        if (preparedChild)
        {
            var child = state.Entries[next.Name];
            var adopted = child.WithPrepared(Bytes(64, 0x21), 1);
            state.Entries[child.Name] = adopted; child.Dispose(); state.AdvanceCounter(adopted.GrantHash, 1); state.Revision++;
        }
        using var unrelated = Pending(0x15);
        state.Entries.Add(unrelated.Name, ProtectedDid2MailboxSendJournal.Entry.Decode(unrelated.Exact)); state.Revision++;
        var before = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        var chain = state.Chain(scope, native);
        Assert.Equal(2, chain.Count); Assert.Equal(rootName, chain[0].Name); Assert.Equal(next.Name, chain[1].Name);
        using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            foreach (var entry in chain) hash.AppendData(entry.Exact);
            Assert.Equal(hash.GetHashAndReset(), state.ChainCommitment(scope, native));
        }
        Assert.NotEqual(one, state.ChainCommitment(scope, native));
        if (preparedChild) Assert.Equal(2, state.RequirePreparedChain(scope, native).Count);
        else Assert.Throws<IOException>(() => state.RequirePreparedChain(scope, native));
        Assert.Equal(before, ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance));
        Assert.Equal(8UL, state.MinimumCounter(chain[0].GrantHash));
        Assert.Equal(preparedChild ? 2UL : 1UL, state.MinimumCounter(chain[1].GrantHash));
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public void WholeChainSelectionRejectsMissingRootTailAndCounterFloorsWithoutMutation(int fault)
    {
        using var state = new ProtectedDid2MailboxSendJournal.State { Revision = 2 };
        using var pending = Pending(0x14); using var ceiling = pending.WithAdmissionCeiling(1100);
        using var prepared = ceiling.WithPrepared(Bytes(64, 0x20), 7);
        var parent = prepared.CloseUnknown(1100);
        var rootName = parent.Name; var scope = parent.ScopeHash.ToArray(); var native = parent.Operation.ToArray();
        state.EnrollScope(parent.GrantHash, Bytes(32, 0x45)); state.AdvanceCounter(parent.GrantHash, 7);
        state.Entries.Add(parent.Name, parent);
        using var next = Successor(parent); state.EnrollScope(next.GrantHash, Bytes(32, 0x46)); state.LinkSuccessor(parent, next);
        var child = state.Entries[next.Name]; var adopted = child.WithPrepared(Bytes(64, 0x21), 1);
        state.Entries[child.Name] = adopted; child.Dispose(); state.AdvanceCounter(adopted.GrantHash, 1);
        if (fault < 2)
        {
            var name = fault == 0 ? rootName : next.Name;
            state.Entries.Remove(name, out var removed); removed!.Dispose();
        }
        else
        {
            var pair = state.Floors.Single(item => item.Value.GrantHash.AsSpan().SequenceEqual(adopted.GrantHash));
            if (fault == 2) state.Floors[pair.Key] = pair.Value with { HighestCounter = 0 };
            else { state.Floors.Remove(pair.Key); CryptographicOperations.ZeroMemory(pair.Value.GrantHash); }
        }
        var records = state.Entries.Select(item => (item.Key, Bytes: item.Value.Exact.ToArray())).ToArray();
        var revision = state.Revision; var floors = state.Floors.Count;
        if (fault == 2) Assert.Throws<CryptographicException>(() => state.RequirePreparedChain(scope, native));
        else Assert.Throws<InvalidDataException>(() => state.RequirePreparedChain(scope, native));
        Assert.Equal(revision, state.Revision); Assert.Equal(floors, state.Floors.Count); Assert.Equal(records.Length, state.Entries.Count);
        foreach (var item in records) Assert.Equal(item.Bytes, state.Entries[item.Key].Exact.ToArray());
    }

    private static ProtectedDid2MailboxSendJournal.Entry Successor(ProtectedDid2MailboxSendJournal.Entry predecessor,
        ulong created = 1100, ulong expiry = 1200, ulong admission = 1150) => ProtectedDid2MailboxSendJournal.Entry.SuccessorOf(predecessor,
        Bytes(32, 0x25), Bytes(32, 0x28), Bytes(32, 0x29), new()
        {
            Epoch = 1, MailboxId = new(Bytes(32, 0x16)), PlacementId = new(Bytes(32, 0x17)),
            OperationId = Bytes(16, 0x25), DeduplicationDigest = SHA256.HashData(Bytes(64, 0x22)),
            CreatedAtUnixSeconds = created, ExpiresAtUnixSeconds = expiry, Ciphertext = Bytes(64, 0x22)
        }, admission);

    [Theory]
    [InlineData(1000UL, false)] [InlineData(1201UL, false)]
    [InlineData(1100UL, true)] [InlineData(1200UL, true)]
    public void OriginalApplicationRetryDeadlineCannotExtendOrRewriteObjectHorizon(ulong retryUntil, bool valid)
    {
        if (!valid)
        {
            Assert.Throws<InvalidDataException>(() => Pending(0x14, retryUntil)); return;
        }
        using var ordinary = Pending(0x14);
        using var constrained = Pending(0x14, retryUntil);
        Assert.Equal(ordinary.Exact[..400].ToArray(), constrained.Exact[..400].ToArray());
        Assert.Equal(ordinary.Expires, constrained.Expires);
        Assert.Equal(retryUntil, constrained.RetryUntil); Assert.Equal(retryUntil, constrained.AdmissionUntil);
        using var admitted = constrained.WithAdmissionCeiling(1050);
        using var closed = admitted.CloseUnknown(1050);
        using var child = Successor(closed, created: 1050, admission: 1090);
        Assert.Equal(retryUntil, child.RetryUntil); Assert.Equal(ordinary.Expires, child.Expires);
        Assert.Throws<InvalidDataException>(() => Successor(closed, created: retryUntil, admission: retryUntil));
        Assert.Throws<InvalidDataException>(() => constrained.WithAdmissionCeiling(retryUntil + 1));
    }

    private static ProtectedDid2MailboxSendJournal.Entry Pending(byte operation, ulong? retryUntil = null)
    {
        var exact = Bytes(Did2MessagingSessionScope.Bytes, 0x30); exact[0] = 1; exact[1] = 1; exact[2] = 0; exact[3] = 0;
        exact[132] = 0x31; exact[172] = 0x32;
        var scope = Did2MessagingSessionScope.RestoreMetadata(exact);
        return ProtectedDid2MailboxSendJournal.Entry.Pending(scope, Bytes(32, operation), Bytes(32, 0x18), Bytes(32, 0x19), new()
        {
            Epoch = 1, MailboxId = new(Bytes(32, 0x16)), PlacementId = new(Bytes(32, 0x17)),
            OperationId = Bytes(16, operation), DeduplicationDigest = System.Security.Cryptography.SHA256.HashData(Bytes(64, 0x22)),
            CreatedAtUnixSeconds = 1000, ExpiresAtUnixSeconds = 1200, Ciphertext = Bytes(64, 0x22)
        }, retryUntil);
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
}
