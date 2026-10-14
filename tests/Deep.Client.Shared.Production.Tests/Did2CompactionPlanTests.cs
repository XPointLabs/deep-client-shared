using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using static Deep.Client.Shared.Persistence.DeviceV2.Did2CompactionPlan;

namespace Deep.Client.Shared.Production.Tests;

// Metadata/recovery-shape fixtures only. No genuine owner, network authority,
// SQL cleanup, deletion capability or sustained delivery is asserted here.
public sealed class Did2CompactionPlanTests
{
    private static Root[] ContactPayloadRoots(bool initial = false) =>
    [
        Guard(RootKind.Ordinary, 10), Changed(RootKind.Send, 11, 21), Guard(RootKind.Grant, 12),
        Guard(RootKind.Read, 13), Guard(RootKind.SessionCatalog, 14), Guard(RootKind.Attachment, 15),
        Guard(RootKind.AccountRegistration, 16), Guard(RootKind.NativeFence, 17),
        initial ? Guard(RootKind.MailboxContactCustody, 18) : Changed(RootKind.ContactAccept, 18, 24),
        initial ? Changed(RootKind.ContactStart, 19, 24) : Guard(RootKind.MailboxContactCustody, 19)
    ];

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void ContactPayloadRecoveryRequiresBothOrderedSuccessorsAndIndependentCustody(bool initial)
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        var roots = ContactPayloadRoots(initial); var payloadIndex = initial ? 9 : 8; var guardIndex = initial ? 8 : 9;
        using var prepared = idle.Prepare(SqlTarget.ProtectedOnly, Bytes(32, 8), Bytes(32, 9), new byte[32], new byte[32],
            roots, [Rows(initial ? Disposition.InitialPayload : Disposition.ContactAcceptPayload)[0]]);
        var actual = Readbacks(roots);
        Assert.Equal(RecoveryStep.RecordSqlCommit, prepared.Plan.ObserveReadback(new byte[32], actual).Step);
        using var committed = prepared.Plan.WithSqlCommitted();
        actual[payloadIndex] = actual[payloadIndex] with { Digest = roots[payloadIndex].After };
        Assert.Throws<InvalidDataException>(() => committed.ObserveReadback(new byte[32], actual));
        actual[payloadIndex] = actual[payloadIndex] with { Digest = roots[payloadIndex].Before };
        foreach (var index in new[] { 1, payloadIndex })
        {
            Assert.Equal(new RecoveryObservation(RecoveryStep.AdoptRoot, index), committed.ObserveReadback(new byte[32], actual));
            using var successor = prepared.Successors.Use(bytes => committed.OwnSuccessor(index, bytes));
            Assert.True(successor.Use(bytes => bytes.SequenceEqual(roots[index].Successor.Span)));
            actual[index] = actual[index] with { Digest = roots[index].After };
        }
        Assert.Equal(RecoveryStep.ClearPlan, committed.ObserveReadback(new byte[32], actual).Step);
        actual[guardIndex] = actual[guardIndex] with { Digest = Bytes(32, 0x99) };
        Assert.Throws<InvalidDataException>(() => committed.ObserveReadback(new byte[32], actual));
    }

    [Theory]
    [InlineData("complete-state", false)] [InlineData("missing-custody", false)] [InlineData("missing-consent", false)]
    [InlineData("consent-guard", false)] [InlineData("send-guard", false)] [InlineData("changed-custody", false)]
    [InlineData("other-action", false)] [InlineData("extra-action", false)] [InlineData("sql-target", false)]
    [InlineData("complete-state", true)] [InlineData("missing-custody", true)] [InlineData("missing-consent", true)]
    [InlineData("consent-guard", true)] [InlineData("send-guard", true)] [InlineData("changed-custody", true)]
    [InlineData("other-action", true)] [InlineData("extra-action", true)] [InlineData("sql-target", true)]
    public void ContactPayloadRejectsBorrowedIncompleteOrChangedCustodyProfiles(string defect, bool initial)
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        var roots = ContactPayloadRoots(initial); var action = initial ? Disposition.InitialPayload : Disposition.ContactAcceptPayload;
        var rows = new[] { Rows(action)[0] }; var payloadIndex = initial ? 9 : 8; var guardIndex = initial ? 8 : 9;
        var target = SqlTarget.ProtectedOnly;
        switch (defect)
        {
            case "complete-state": roots[guardIndex] = Guard(RootKind.MailboxStoreState, 19); break;
            case "missing-custody": roots = roots.Where(root => root.Kind != RootKind.MailboxContactCustody).ToArray(); break;
            case "missing-consent": roots = roots.Where(root => root.Kind != (initial ? RootKind.ContactStart : RootKind.ContactAccept)).ToArray(); break;
            case "consent-guard": roots[payloadIndex] = Guard(initial ? RootKind.ContactStart : RootKind.ContactAccept, 18); break;
            case "send-guard": roots[1] = Guard(RootKind.Send, 11); break;
            case "changed-custody": roots[guardIndex] = Changed(RootKind.MailboxContactCustody, 19, 25); break;
            case "other-action": rows = [Rows(Disposition.ReplayScope)[0]]; break;
            case "extra-action": rows = Rows(action); break;
            case "sql-target": target = SqlTarget.Application; break;
        }
        Assert.Throws<InvalidDataException>(() => idle.Prepare(target, Bytes(32, 8), Bytes(32, 9),
            target == SqlTarget.ProtectedOnly ? new byte[32] : BeforeSql,
            target == SqlTarget.ProtectedOnly ? new byte[32] : AfterSql, roots, rows));
    }

    [Theory]
    [InlineData(false, (byte)Disposition.StoppedControlPayload)]
    [InlineData(true, (byte)Disposition.StoppedControlPayload)]
    [InlineData(false, (byte)Disposition.ExpiredControlAudit)]
    [InlineData(true, (byte)Disposition.ExpiredControlAudit)]
    public void StoppedControlAuditRequiresSqlThenOnePayloadSuccessorAndUnchangedSend(bool initial, byte actionValue)
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        var roots = ContactPayloadRoots(initial); roots[1] = Guard(RootKind.Send, 11);
        var row = Rows((Disposition)actionValue)[0]; var payloadIndex = initial ? 9 : 8;
        using var prepared = idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql, roots, [row]);
        var actual = Readbacks(roots);
        Assert.Equal(RecoveryStep.ApplySql, prepared.Plan.ObserveReadback(BeforeSql, actual).Step);
        Assert.Equal(RecoveryStep.RecordSqlCommit, prepared.Plan.ObserveReadback(AfterSql, actual).Step);
        using var committed = prepared.Plan.WithSqlCommitted();
        Assert.Equal(new RecoveryObservation(RecoveryStep.AdoptRoot, payloadIndex), committed.ObserveReadback(AfterSql, actual));
        actual[payloadIndex] = actual[payloadIndex] with { Digest = roots[payloadIndex].After };
        Assert.Equal(RecoveryStep.ClearPlan, committed.ObserveReadback(AfterSql, actual).Step);
        foreach (var defect in new[] { "changed-send", "payload-guard", "changed-custody", "missing-custody", "extra-row", "protected-only" })
        {
            var damaged = roots.ToArray(); var target = SqlTarget.Application; var rows = new[] { row };
            switch (defect)
            {
                case "changed-send": damaged[1] = Changed(RootKind.Send, 11, 21); break;
                case "payload-guard": damaged[payloadIndex] = Guard(damaged[payloadIndex].Kind, 24); break;
                case "changed-custody": damaged[initial ? 8 : 9] = Changed(RootKind.MailboxContactCustody, 25, 26); break;
                case "missing-custody": damaged = damaged.Where(root => root.Kind != RootKind.MailboxContactCustody).ToArray(); break;
                case "extra-row": rows = Rows((Disposition)actionValue); break;
                case "protected-only": target = SqlTarget.ProtectedOnly; break;
            }
            Assert.Throws<InvalidDataException>(() => idle.Prepare(target, Bytes(32, 8), Bytes(32, 9),
                target == SqlTarget.ProtectedOnly ? new byte[32] : BeforeSql,
                target == SqlTarget.ProtectedOnly ? new byte[32] : AfterSql, damaged, rows));
        }
    }

    [Theory]
    [InlineData((byte)Disposition.StoppedOutboxPayload)]
    [InlineData((byte)Disposition.ExpiredTerminalAudit)]
    public void StoppedPayloadPlanHasOneClosedApplicationProfile(byte actionValue)
    {
        var action = (Disposition)actionValue;
        using var idle = RegisteredEmpty(Network, Account, Instance);
        RootKind[] kinds = [RootKind.Ordinary, RootKind.Send, RootKind.Grant, RootKind.Read,
            RootKind.SessionCatalog, RootKind.MessagingFloor, RootKind.Attachment, RootKind.AccountRegistration,
            RootKind.MessagingHistoryCheckpoint, RootKind.MessagingPeerBootstrap];
        var roots = kinds.Select((kind, index) => index == 0 ? Changed(kind, 10, 20) : Guard(kind, checked((byte)(10 + index)))).ToArray();
        using var prepared = idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql,
            roots, Rows(action));
        Assert.Equal(10, prepared.Plan.RootCount); Assert.Equal(action, prepared.Plan.ReadRow(0).Action);
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Transport, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql,
            roots, Rows(action)));
        var altered = roots.ToArray(); altered[1] = Changed(RootKind.Send, 11, 21);
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql,
            altered, Rows(action)));
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql,
            roots, [Rows(Disposition.OutboxPayload)[0], Rows(action)[1]]));
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql,
            roots, [Rows(Disposition.StoppedOutboxPayload)[0], Rows(Disposition.ExpiredTerminalAudit)[1]]));
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql,
            roots, Rows((Disposition)7))); // Removed entry-based audit expiry is not another reader.
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
    private static readonly byte[] Network = Bytes(16, 1), Account = Bytes(32, 2), Instance = Bytes(32, 3);
    private static readonly byte[] BeforeSql = Bytes(32, 4), AfterSql = Bytes(32, 5);
    private static Root Changed(RootKind kind, byte selector, byte value)
    {
        var exact = Bytes(31, value);
        return new(kind, Bytes(32, selector), Bytes(32, 6), SHA256.HashData(exact), false, exact);
    }
    private static Root Guard(RootKind kind, byte selector) => new(kind, Bytes(32, selector), Bytes(32, 7), Bytes(32, 7), true, default);
    private static Root[] Roots() =>
    [
        Changed(RootKind.Ordinary, 10, 20), Changed(RootKind.Send, 11, 21), Changed(RootKind.Grant, 12, 22),
        Guard(RootKind.SessionCatalog, 13), Guard(RootKind.MessagingFloor, 14),
        Guard(RootKind.AccountRegistration, 15), Guard(RootKind.NativeFence, 16),
        Changed(RootKind.MessagingHistoryCheckpoint, 17, 23)
    ];
    private static Row[] Rows(Disposition action) => [new(action, Bytes(32, 30), Bytes(32, 40)), new(action, Bytes(32, 31), Bytes(32, 41))];
    private static Preparation Prepared(SqlTarget target = SqlTarget.Application)
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        var action = target == SqlTarget.Messaging ? Disposition.JournalPrefix :
            target == SqlTarget.ProtectedOnly ? Disposition.ReplayScope : Disposition.OutboxPayload;
        return idle.Prepare(target, Bytes(32, 8), Bytes(32, 9),
            target == SqlTarget.ProtectedOnly ? new byte[32] : BeforeSql,
            target == SqlTarget.ProtectedOnly ? new byte[32] : AfterSql, Roots(), Rows(action));
    }
    private static RootReadback[] Readbacks(Root[] roots, bool after = false) => roots.Select(root =>
        new RootReadback(root.Kind, root.Selector, after ? root.After : root.Before)).ToArray();

    private static Root[] RetainedPathRoots() =>
    [
        Guard(RootKind.Ordinary, 10), Guard(RootKind.Send, 11), Changed(RootKind.Grant, 12, 22),
        Changed(RootKind.Read, 13, 23), Guard(RootKind.SessionCatalog, 14), Guard(RootKind.Attachment, 15),
        Guard(RootKind.AccountRegistration, 16), Guard(RootKind.NativeFence, 17),
        Changed(RootKind.ContactPublication, 18, 24), Guard(RootKind.MailboxLocalCustody, 19)
    ];

    [Fact]
    public void RetainedPathRequiresJointSqlAndThreeOrderedRootAdoptions()
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        var roots = RetainedPathRoots();
        Row[] rows = [new(Disposition.ReplayScope, Bytes(32, 30), Bytes(32, 40)),
            new(Disposition.RetainedPath, Bytes(32, 31), Bytes(32, 41))];
        using var prepared = idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 31), BeforeSql, AfterSql, roots, rows);
        var actual = Readbacks(roots);
        Assert.Equal(RecoveryStep.ApplySql, prepared.Plan.ObserveReadback(BeforeSql, actual).Step);
        Assert.Equal(RecoveryStep.RecordSqlCommit, prepared.Plan.ObserveReadback(AfterSql, actual).Step);
        using var committed = prepared.Plan.WithSqlCommitted();
        using var reopened = Decode(committed.Exact.Span, Network, Account, Instance);
        foreach (var index in new[] { 2, 3, 8 })
        {
            Assert.Equal(new RecoveryObservation(RecoveryStep.AdoptRoot, index), reopened.ObserveReadback(AfterSql, actual));
            using var successor = prepared.Successors.Use(bytes => reopened.OwnSuccessor(index, bytes));
            Assert.True(successor.Use(bytes => bytes.SequenceEqual(roots[index].Successor.Span)));
            actual[index] = actual[index] with { Digest = roots[index].After };
        }
        Assert.Equal(RecoveryStep.ClearPlan, reopened.ObserveReadback(AfterSql, actual).Step);
        Assert.Throws<InvalidDataException>(() => reopened.ObserveReadback(BeforeSql, actual));
        actual[2] = actual[2] with { Digest = roots[2].Before };
        Assert.Throws<InvalidDataException>(() => reopened.ObserveReadback(AfterSql, actual));
    }

    [Theory]
    [InlineData("sql-less")] [InlineData("read-guard")] [InlineData("publication-guard")]
    [InlineData("missing-source")] [InlineData("extra-path")] [InlineData("unrelated-action")]
    [InlineData("unowned-roots")]
    public void RetainedPathRejectsIncompleteOrBorrowedCompactionProfiles(string defect)
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        var roots = RetainedPathRoots();
        var rows = new List<Row> { new(Disposition.ReplayScope, Bytes(32, 30), Bytes(32, 40)),
            new(Disposition.RetainedPath, Bytes(32, 31), Bytes(32, 41)) };
        var target = SqlTarget.Application;
        switch (defect)
        {
            case "sql-less": target = SqlTarget.ProtectedOnly; break;
            case "read-guard": roots[3] = Guard(RootKind.Read, 13); break;
            case "publication-guard": roots[8] = Guard(RootKind.ContactPublication, 18); break;
            case "missing-source": roots = roots[..^1]; break;
            case "extra-path": rows.Add(new(Disposition.RetainedPath, Bytes(32, 32), Bytes(32, 42))); break;
            case "unrelated-action": rows[0] = rows[0] with { Action = Disposition.Audit }; break;
            case "unowned-roots": rows[1] = rows[1] with { Action = Disposition.ReplayScope }; break;
        }
        Assert.Throws<InvalidDataException>(() => idle.Prepare(target, Bytes(32, 8), Bytes(32, 31),
            target == SqlTarget.ProtectedOnly ? new byte[32] : BeforeSql,
            target == SqlTarget.ProtectedOnly ? new byte[32] : AfterSql, roots, rows));
    }

    [Theory]
    [InlineData((byte)1)]
    [InlineData((byte)2)]
    [InlineData((byte)3)]
    [InlineData((byte)4)]
    public void ExactColdRecoveryObservesOnlyOriginalSqlCommittedSqlAndAdoptionPrefix(byte targetValue)
    {
        var target = (SqlTarget)targetValue;
        using var preparation = Prepared(target);
        using var pending = Decode(preparation.Plan.Exact.Span, Network, Account, Instance);
        preparation.Successors.Use(bytes => pending.ValidateSuccessors(bytes));
        var actual = Readbacks(Roots());
        if (target != SqlTarget.ProtectedOnly)
            Assert.Equal(new RecoveryObservation(RecoveryStep.ApplySql), pending.ObserveReadback(BeforeSql, actual));
        var sql = target == SqlTarget.ProtectedOnly ? new byte[32] : AfterSql;
        Assert.Equal(new RecoveryObservation(RecoveryStep.RecordSqlCommit), pending.ObserveReadback(sql, actual));
        using var committed = pending.WithSqlCommitted();
        using var reopened = Decode(committed.Exact.Span, Network, Account, Instance);
        var expected = Roots();
        while (true)
        {
            var observed = reopened.ObserveReadback(sql, actual);
            if (observed.Step == RecoveryStep.ClearPlan) break;
            Assert.Equal(RecoveryStep.AdoptRoot, observed.Step);
            var index = observed.RootIndex;
            using var successor = preparation.Successors.Use(bytes => reopened.OwnSuccessor(index, bytes));
            Assert.True(successor.Use(bytes => bytes.SequenceEqual(expected[index].Successor.Span)));
            actual[index] = actual[index] with { Digest = expected[index].After };
        }
        using var cleared = reopened.Cleared();
        Assert.Equal(4UL, cleared.Revision); Assert.Equal(0, cleared.Phase);
        Assert.Equal(HeaderBytes, cleared.Exact.Length);
        Assert.True(cleared.Exact.Span[96..].IndexOfAnyExcept((byte)0) < 0);
        Assert.Throws<InvalidDataException>(() => cleared.ObserveReadback(sql, actual));
        Assert.Throws<InvalidDataException>(() => pending.Cleared());
        Assert.Throws<InvalidDataException>(() => reopened.WithSqlCommitted());
    }

    [Theory]
    [InlineData("sql-third")]
    [InlineData("sql-rollback")]
    [InlineData("non-prefix")]
    [InlineData("guard")]
    [InlineData("root-third")]
    [InlineData("selector")]
    [InlineData("order")]
    [InlineData("missing")]
    [InlineData("premature-root")]
    public void MissingChangedMixedOrRolledBackReadbacksCannotAuthorizeRecovery(string defect)
    {
        using var preparation = Prepared(); using var committed = preparation.Plan.WithSqlCommitted();
        var actual = Readbacks(Roots()); var sql = AfterSql; var plan = committed;
        switch (defect)
        {
            case "sql-third": sql = Bytes(32, 0x99); break;
            case "sql-rollback": sql = BeforeSql; break;
            case "non-prefix": actual[1] = actual[1] with { Digest = Roots()[1].After }; break;
            case "guard": actual[3] = actual[3] with { Digest = Bytes(32, 0x99) }; break;
            case "root-third": actual[0] = actual[0] with { Digest = Bytes(32, 0x99) }; break;
            case "selector": actual[0] = actual[0] with { Selector = Bytes(32, 0x99) }; break;
            case "order": (actual[0], actual[1]) = (actual[1], actual[0]); break;
            case "missing": actual = actual[..^1]; break;
            case "premature-root": plan = preparation.Plan; actual[0] = actual[0] with { Digest = Roots()[0].After }; break;
        }
        Assert.Throws<InvalidDataException>(() => plan.ObserveReadback(sql, actual));
    }

    [Theory]
    [InlineData(0, 2)] [InlineData(1, 4)] [InlineData(2, 0)] [InlineData(2, 5)]
    [InlineData(3, 33)] [InlineData(4, 1)] [InlineData(5, 0)] [InlineData(6, 1)]
    [InlineData(261, 1)] [InlineData(260, 0)]
    public void UnknownVersionsPhasesCountsTargetsAndReservedBytesReject(int offset, int value)
    {
        using var preparation = Prepared(); var raw = preparation.Plan.Exact.ToArray(); raw[offset] = checked((byte)value);
        Assert.Throws<InvalidDataException>(() => Decode(raw, Network, Account, Instance));
    }

    [Theory]
    [InlineData(16, 16)] [InlineData(32, 32)] [InlineData(64, 32)]
    [InlineData(96, 32)] [InlineData(128, 32)] [InlineData(160, 32)] [InlineData(192, 32)] [InlineData(224, 32)]
    public void ForeignOwnerOrAbsentActiveCommitmentsReject(int offset, int count)
    {
        using var preparation = Prepared(); var raw = preparation.Plan.Exact.ToArray(); raw.AsSpan(offset, count).Clear();
        Assert.Throws<InvalidDataException>(() => Decode(raw, Network, Account, Instance));
    }

    [Fact]
    public void HostileRootRowLengthRevisionAndSuccessorCommitmentsRemainClosed()
    {
        using var preparation = Prepared(); var original = preparation.Plan.Exact.ToArray();
        void Reject(Action<byte[]> mutate)
        {
            var raw = original.ToArray(); mutate(raw);
            Assert.Throws<InvalidDataException>(() => Decode(raw, Network, Account, Instance));
        }
        Reject(raw => raw[HeaderBytes] = 13);
        Reject(raw => raw[HeaderBytes + 1] = 3);
        Reject(raw => raw[HeaderBytes + 2] = 1);
        Reject(raw => raw.AsSpan(HeaderBytes + 4, 32).Clear());
        Reject(raw => raw.AsSpan(HeaderBytes + 36, 32).Clear());
        Reject(raw => raw.AsSpan(HeaderBytes + 68, 32).Clear());
        Reject(raw => BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(HeaderBytes + 100), 0));
        var rowOffset = HeaderBytes + preparation.Plan.RootCount * RootBytes;
        Reject(raw => raw[rowOffset] = 0);
        Reject(raw => raw[rowOffset + 1] = 1);
        Reject(raw => raw.AsSpan(rowOffset + 8, 32).Clear());
        Reject(raw => raw.AsSpan(rowOffset + 40, 32).Clear());
        Reject(raw => BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), 0));
        Reject(raw => BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), 1));
        Assert.Throws<InvalidDataException>(() => Decode(original[..^1], Network, Account, Instance));
        Assert.Throws<InvalidDataException>(() => Decode(new byte[MaximumBytes + 1], Network, Account, Instance));
        // A shaped metadata digest is not sufficient: the retained successor
        // bundle must match each exact replacement before a consumer can use it.
        var changed = original.ToArray(); changed[HeaderBytes + 68] ^= 1;
        using var shaped = Decode(changed, Network, Account, Instance);
        Assert.Throws<InvalidDataException>(() => preparation.Successors.Use(bytes => { shaped.ValidateSuccessors(bytes); return 0; }));
    }

    [Fact]
    public void CanonicalRootsRowsAndDependencyKindsRejectAmbiguousSelections()
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        void Reject(Root[] roots, Row[] rows, SqlTarget target = SqlTarget.Application) => Assert.Throws<InvalidDataException>(() =>
            idle.Prepare(target, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql, roots, rows));
        var roots = Roots(); (roots[0], roots[1]) = (roots[1], roots[0]); Reject(roots, Rows(Disposition.OutboxPayload));
        roots = Roots(); roots[1] = roots[0]; Reject(roots, Rows(Disposition.OutboxPayload));
        roots = Roots(); roots[3] = Changed(RootKind.SessionCatalog, 13, 24); Reject(roots, Rows(Disposition.OutboxPayload));
        roots = Roots(); roots[5] = Changed(RootKind.AccountRegistration, 15, 24); Reject(roots, Rows(Disposition.OutboxPayload));
        roots = Roots(); roots[6] = Changed(RootKind.NativeFence, 16, 24); Reject(roots, Rows(Disposition.OutboxPayload));
        Reject(Roots().Where(root => root.Kind != RootKind.AccountRegistration).ToArray(), Rows(Disposition.OutboxPayload));
        Reject(Roots().Where(root => root.Kind != RootKind.NativeFence).ToArray(), Rows(Disposition.ReplayScope));
        Reject(Roots().Where(root => root.Kind != RootKind.MessagingHistoryCheckpoint).ToArray(), Rows(Disposition.JournalPrefix), SqlTarget.Messaging);
        var rows = Rows(Disposition.OutboxPayload); rows[1] = rows[0] with { Action = Disposition.Audit }; Reject(Roots(), rows);
        rows = Rows(Disposition.OutboxPayload); (rows[0], rows[1]) = (rows[1], rows[0]); Reject(Roots(), rows);
        Reject(Roots(), Rows((Disposition)5)); Reject(Roots(), Rows(Disposition.JournalPrefix));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PeerBootstrapDependencyIsAlwaysAnUnchangedGuard(bool changed)
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        var roots = Roots().Append(changed ? Changed(RootKind.MessagingPeerBootstrap, 18, 25) :
            Guard(RootKind.MessagingPeerBootstrap, 18)).ToArray();
        if (changed) Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Messaging,
            Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql, roots, Rows(Disposition.JournalPrefix)));
        else
        {
            using var prepared = idle.Prepare(SqlTarget.Messaging, Bytes(32, 8), Bytes(32, 9),
                BeforeSql, AfterSql, roots, Rows(Disposition.JournalPrefix));
            Assert.Equal(roots.Length, prepared.Plan.RootCount);
        }
    }

    [Fact]
    public void CompleteMailboxStateIsAUniqueUnchangedGuardAndChangedReadbackRejects()
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        var roots = Roots().Append(Guard(RootKind.MailboxStoreState, 19)).ToArray();
        using var prepared = idle.Prepare(SqlTarget.ProtectedOnly, Bytes(32, 8), Bytes(32, 9),
            new byte[32], new byte[32], roots, Rows(Disposition.ReplayScope));
        var readbacks = Readbacks(roots);
        Assert.Equal(RecoveryStep.RecordSqlCommit, prepared.Plan.ObserveReadback(new byte[32], readbacks).Step);
        readbacks[^1] = readbacks[^1] with { Digest = Bytes(32, 0x99) };
        Assert.Throws<InvalidDataException>(() => prepared.Plan.ObserveReadback(new byte[32], readbacks));
        roots[^1] = Changed(RootKind.MailboxStoreState, 19, 25);
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.ProtectedOnly, Bytes(32, 8), Bytes(32, 9),
            new byte[32], new byte[32], roots, Rows(Disposition.ReplayScope)));
        roots[^1] = Guard(RootKind.MailboxStoreState, 19);
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.ProtectedOnly, Bytes(32, 8), Bytes(32, 9),
            new byte[32], new byte[32], roots.Append(Guard(RootKind.MailboxStoreState, 20)).ToArray(), Rows(Disposition.ReplayScope)));
    }

    [Fact]
    public void CompletedContactSendAuditRequiresOneSendAndCompleteNativeSqlGuards()
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        Root[] roots = [Guard(RootKind.Ordinary, 10), Changed(RootKind.Send, 11, 21), Guard(RootKind.Grant, 12),
            Guard(RootKind.Read, 13), Guard(RootKind.SessionCatalog, 14), Guard(RootKind.Attachment, 15),
            Guard(RootKind.AccountRegistration, 16), Guard(RootKind.NativeFence, 17), Guard(RootKind.MailboxStoreState, 18)];
        var row = Rows(Disposition.Audit)[0];
        using var prepared = idle.Prepare(SqlTarget.ProtectedOnly, Bytes(32, 8), Bytes(32, 9), new byte[32], new byte[32], roots, [row]);
        Assert.Equal(RecoveryStep.RecordSqlCommit, prepared.Plan.ObserveReadback(new byte[32], Readbacks(roots)).Step);
        foreach (var required in new[] { RootKind.NativeFence, RootKind.MailboxStoreState })
            Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.ProtectedOnly, Bytes(32, 8), Bytes(32, 9),
                new byte[32], new byte[32], roots.Where(root => root.Kind != required).ToArray(), [row]));
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.ProtectedOnly, Bytes(32, 8), Bytes(32, 9),
            new byte[32], new byte[32], roots, Rows(Disposition.Audit)));
        roots[0] = Changed(RootKind.Ordinary, 10, 22);
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.ProtectedOnly, Bytes(32, 8), Bytes(32, 9),
            new byte[32], new byte[32], roots, [row]));
    }

    [Fact]
    public void DurableAbandonmentRequiresOnlyExactUnchangedPredecessorsAndCannotAcceptCommittedSql()
    {
        using var prepared = Prepared(); using var abandoning = prepared.Plan.WithAbandoningBeforeSql();
        Assert.Equal(3, abandoning.Phase); Assert.Equal(prepared.Plan.Revision + 1, abandoning.Revision);
        var roots = Roots().Select(root => new RootReadback(root.Kind, root.Selector, root.Before)).ToArray();
        Assert.Equal(RecoveryStep.ClearPlan, abandoning.ObserveReadback(BeforeSql, roots).Step);
        Assert.Throws<InvalidDataException>(() => abandoning.ObserveReadback(AfterSql, roots));
        roots[0] = roots[0] with { Digest = Roots()[0].After };
        Assert.Throws<InvalidDataException>(() => abandoning.ObserveReadback(BeforeSql, roots));
        using var cleared = abandoning.Cleared(); Assert.Equal(0, cleared.Phase); Assert.Equal(abandoning.Revision + 1, cleared.Revision);
        Assert.Throws<InvalidDataException>(() => abandoning.WithSqlCommitted());
        Assert.Throws<InvalidDataException>(() => abandoning.WithAbandoningBeforeSql());
    }

    [Fact]
    public void ExactSuccessorBytesAreOwnedBoundedAndCannotBeReconstructedFromDigests()
    {
        using var idle = RegisteredEmpty(Network, Account, Instance); var roots = Roots();
        var callerSuccessor = Bytes(31, 20); roots[0] = roots[0] with { Successor = callerSuccessor };
        using var preparation = idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql, roots, Rows(Disposition.OutboxPayload));
        var retained = preparation.Successors.Use(bytes => bytes.ToArray());
        callerSuccessor.AsSpan().Clear();
        Assert.Throws<InvalidDataException>(() => preparation.Plan.ValidateSuccessors([]));
        var changed = retained.ToArray(); changed[0] ^= 1;
        Assert.Throws<InvalidDataException>(() => preparation.Plan.ValidateSuccessors(changed));
        Assert.Throws<InvalidDataException>(() => preparation.Plan.ValidateSuccessors(retained[..^1]));
        using var actual = preparation.Plan.OwnSuccessor(0, retained);
        Assert.True(actual.Use(bytes => SHA256.HashData(bytes).AsSpan().SequenceEqual(roots[0].After.Span)));
        Assert.Throws<InvalidDataException>(() => preparation.Plan.OwnSuccessor(3, retained));
        roots[0] = roots[0] with { Successor = ReadOnlyMemory<byte>.Empty };
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql, roots, Rows(Disposition.OutboxPayload)));
        CryptographicOperations.ZeroMemory(retained); CryptographicOperations.ZeroMemory(changed);
    }

    [Fact]
    public void SuccessorPartAndRootBoundsRejectBeforeUnboundedAllocation()
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        Root Large(RootKind kind, byte selector, int length)
        {
            var exact = Bytes(length, selector);
            return new(kind, Bytes(32, selector), Bytes(32, 6), SHA256.HashData(exact), false, exact);
        }
        var first = Large(RootKind.Ordinary, 10, MaximumRootBytes);
        var second = Large(RootKind.Send, 11, MaximumRootBytes);
        using var maximum = idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql,
            [first, second, Guard(RootKind.AccountRegistration, 15)], Rows(Disposition.OutboxPayload));
        Assert.Equal(MaximumSuccessorBytes, maximum.Plan.SuccessorBytes); Assert.Equal(16, maximum.Plan.PartCount);
        maximum.Successors.Use(bytes => { maximum.Plan.ValidateSuccessors(bytes); return 0; });
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql,
            [first, second, Changed(RootKind.Grant, 12, 22), Guard(RootKind.AccountRegistration, 15)], Rows(Disposition.OutboxPayload)));
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql,
            [Large(RootKind.Ordinary, 10, MaximumRootBytes + 1), Guard(RootKind.AccountRegistration, 15)], Rows(Disposition.OutboxPayload)));
        var raw = maximum.Plan.Exact.ToArray(); BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(256), uint.MaxValue);
        Assert.Throws<InvalidDataException>(() => Decode(raw, Network, Account, Instance));
        raw = maximum.Plan.Exact.ToArray(); BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(HeaderBytes + 100), uint.MaxValue);
        Assert.Throws<InvalidDataException>(() => Decode(raw, Network, Account, Instance));
    }

    [Fact]
    public void CapacityRevisionAndDisposalCannotCreateAnUnboundedOrResetPlan()
    {
        using var idle = RegisteredEmpty(Network, Account, Instance);
        var roots = new List<Root> { Changed(RootKind.Ordinary, 10, 20) };
        for (byte i = 1; i <= 30; i++) roots.Add(Guard(RootKind.MessagingFloor, i));
        roots.Add(Guard(RootKind.AccountRegistration, 15));
        var rows = Enumerable.Range(1, MaximumRows).Select(i => new Row(Disposition.OutboxPayload, Bytes(32, checked((byte)i)), Bytes(32, 41))).ToArray();
        using var maximum = idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql, roots, rows);
        Assert.Equal(MaximumBytes, maximum.Plan.Exact.Length); Assert.Equal(1, maximum.Plan.PartCount);
        roots.Add(Guard(RootKind.NativeFence, 16));
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql, roots, rows));
        Assert.Throws<InvalidDataException>(() => idle.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql, Roots(), rows.Concat([rows[0]]).ToArray()));
        var exhaustedRaw = idle.Exact.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(exhaustedRaw.AsSpan(8), ulong.MaxValue);
        using var exhausted = Decode(exhaustedRaw, Network, Account, Instance);
        Assert.Throws<OverflowException>(() => exhausted.Prepare(SqlTarget.Application, Bytes(32, 8), Bytes(32, 9), BeforeSql, AfterSql, Roots(), Rows(Disposition.OutboxPayload)));
        var exhaustedPendingRaw = maximum.Plan.Exact.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(exhaustedPendingRaw.AsSpan(8), ulong.MaxValue);
        using var exhaustedPending = Decode(exhaustedPendingRaw, Network, Account, Instance);
        Assert.Throws<OverflowException>(() => exhaustedPending.WithSqlCommitted());
        using var committed = maximum.Plan.WithSqlCommitted(); var exhaustedCommittedRaw = committed.Exact.ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(exhaustedCommittedRaw.AsSpan(8), ulong.MaxValue);
        using var exhaustedCommitted = Decode(exhaustedCommittedRaw, Network, Account, Instance);
        Assert.Throws<OverflowException>(() => exhaustedCommitted.Cleared());
        maximum.Dispose(); Assert.Throws<ObjectDisposedException>(() => maximum.Plan.Exact);
        Assert.Throws<ObjectDisposedException>(() => maximum.Successors.Use(bytes => bytes.Length));
    }
}
