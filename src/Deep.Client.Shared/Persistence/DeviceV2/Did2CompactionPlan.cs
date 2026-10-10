using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Bounded private S01 plan metadata, not deletion or checkpoint
/// authority. No storage registration, SQL writer or runtime compactor is
/// installed here. The actual owner must independently verify dependency
/// closure and held fences before persisting or consuming this record.</summary>
internal sealed class Did2CompactionPlan : IDisposable
{
    internal const string Slot = "deep.store.v2.compaction-plan";
    internal const int HeaderBytes = 264, RootBytes = 104, RowBytes = 72;
    internal const int MaximumRoots = 32, MaximumRows = 32;
    internal const int MaximumBytes = HeaderBytes + MaximumRoots * RootBytes + MaximumRows * RowBytes;
    internal const int PartBytes = 128 * 1024, MaximumSuccessorBytes = 2 * 1024 * 1024, MaximumRootBytes = 1024 * 1024;
    internal enum SqlTarget : byte { Application = 1, Transport = 2, Messaging = 3, ProtectedOnly = 4 }
    internal enum RootKind : byte
    {
        Ordinary = 1, Send = 2, Grant = 3, Read = 4, SessionCatalog = 5,
        MessagingFloor = 6, Attachment = 7, AccountRegistration = 8,
        NativeFence = 9, MessagingHistoryCheckpoint = 10, MessagingPeerBootstrap = 11,
        MailboxStoreState = 12, ContactPublication = 13, MailboxLocalCustody = 14
    }
    internal enum Disposition : byte { OutboxPayload = 1, Audit = 2, JournalPrefix = 3, ReplayScope = 4, RetainedPath = 5 }
    internal enum RecoveryStep : byte { ApplySql = 1, RecordSqlCommit = 2, AdoptRoot = 3, ClearPlan = 4 }
    internal readonly record struct Root(RootKind Kind, ReadOnlyMemory<byte> Selector,
        ReadOnlyMemory<byte> Before, ReadOnlyMemory<byte> After, bool Guard, ReadOnlyMemory<byte> Successor);
    internal readonly record struct Row(Disposition Action, ReadOnlyMemory<byte> Selector, ReadOnlyMemory<byte> Commitment);
    internal readonly record struct RootReadback(RootKind Kind, ReadOnlyMemory<byte> Selector, ReadOnlyMemory<byte> Digest);
    internal readonly record struct RecoveryObservation(RecoveryStep Step, int RootIndex = -1);
    private byte[]? bytes;
    private Did2CompactionPlan(byte[] bytes) => this.bytes = bytes;
    private ReadOnlySpan<byte> Data => bytes ?? throw new ObjectDisposedException(nameof(Did2CompactionPlan));
    internal byte Phase => Data[1];
    internal ulong Revision => BinaryPrimitives.ReadUInt64BigEndian(Data[8..]);
    internal int RootCount => Data[3];
    internal int RowCount => BinaryPrimitives.ReadUInt16BigEndian(Data[4..]);
    internal int SuccessorBytes => checked((int)BinaryPrimitives.ReadUInt32BigEndian(Data[256..]));
    internal int PartCount => Data[260];
    internal SqlTarget Target => (SqlTarget)Data[2];
    internal ReadOnlySpan<byte> SqlSelector => Data.Slice(128, 32);
    internal ReadOnlySpan<byte> SqlBefore => Data.Slice(160, 32);
    internal ReadOnlySpan<byte> SqlAfter => Data.Slice(192, 32);
    internal ReadOnlySpan<byte> Nonce => Data.Slice(96, 32);
    internal Root ReadRoot(int index)
    {
        if (index < 0 || index >= RootCount) throw new ArgumentOutOfRangeException(nameof(index));
        var raw = Data.Slice(HeaderBytes + index * RootBytes, RootBytes);
        return new((RootKind)raw[0], raw.Slice(4, 32).ToArray(), raw.Slice(36, 32).ToArray(),
            raw.Slice(68, 32).ToArray(), raw[1] == 2, ReadOnlyMemory<byte>.Empty);
    }
    internal Row ReadRow(int index)
    {
        if (index < 0 || index >= RowCount) throw new ArgumentOutOfRangeException(nameof(index));
        var raw = Data.Slice(HeaderBytes + RootCount * RootBytes + index * RowBytes, RowBytes);
        return new((Disposition)raw[0], raw.Slice(8, 32).ToArray(), raw.Slice(40, 32).ToArray());
    }
    internal ReadOnlyMemory<byte> Exact => Data.ToArray();
    internal sealed class Preparation(Did2CompactionPlan plan, OwnedDeepSecret successors) : IDisposable
    {
        internal Did2CompactionPlan Plan { get; } = plan;
        internal OwnedDeepSecret Successors { get; } = successors;
        public void Dispose() { Plan.Dispose(); Successors.Dispose(); }
    }

    internal static Did2CompactionPlan RegisteredEmpty(ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var raw = new byte[HeaderBytes]; raw[0] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), 1);
        RequireOwner(network, account, instance);
        network.CopyTo(raw.AsSpan(16)); account.CopyTo(raw.AsSpan(32)); instance.CopyTo(raw.AsSpan(64));
        return Decode(raw, network, account, instance);
    }

    // This encodes a selection, not its authorization. In particular Guard
    // describes an unchanged root, never a serialized 'verified' permission.
    internal Preparation Prepare(SqlTarget target, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> sqlSelector, ReadOnlySpan<byte> sqlBefore, ReadOnlySpan<byte> sqlAfter,
        IReadOnlyList<Root> roots, IReadOnlyList<Row> rows)
    {
        ArgumentNullException.ThrowIfNull(roots); ArgumentNullException.ThrowIfNull(rows);
        if (Phase != 0 || roots.Count is < 1 or > MaximumRoots || rows.Count is < 1 or > MaximumRows)
            throw Bad();
        Require32(nonce); Require32(sqlSelector);
        if (target == SqlTarget.ProtectedOnly)
        { if (sqlBefore.Length != 32 || sqlAfter.Length != 32 || !Zero(sqlBefore) || !Zero(sqlAfter)) throw Bad(); }
        else { Require32(sqlBefore); Require32(sqlAfter); if (Fixed(sqlBefore, sqlAfter)) throw Bad(); }
        var nextRevision = checked(Revision + 1);
        var successorLength = 0;
        foreach (var root in roots)
        {
            if (root.Guard ? !root.Successor.IsEmpty : root.Successor.Length is < 1 or > MaximumRootBytes) throw Bad();
            successorLength = checked(successorLength + root.Successor.Length);
            if (successorLength > MaximumSuccessorBytes) throw Bad();
        }
        if (successorLength == 0) throw Bad();
        var raw = new byte[HeaderBytes + roots.Count * RootBytes + rows.Count * RowBytes];
        var successors = new byte[successorLength];
        Data[..96].CopyTo(raw); raw[1] = 1; raw[2] = (byte)target; raw[3] = checked((byte)roots.Count);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(4), checked((ushort)rows.Count));
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), nextRevision);
        nonce.CopyTo(raw.AsSpan(96)); sqlSelector.CopyTo(raw.AsSpan(128));
        sqlBefore.CopyTo(raw.AsSpan(160)); sqlAfter.CopyTo(raw.AsSpan(192));
        try
        {
            var successorOffset = 0;
            for (var i = 0; i < roots.Count; i++)
            {
                var root = roots[i]; Require32(root.Selector.Span); Require32(root.Before.Span); Require32(root.After.Span);
                var record = raw.AsSpan(HeaderBytes + i * RootBytes, RootBytes);
                record[0] = (byte)root.Kind; record[1] = root.Guard ? (byte)2 : (byte)1;
                root.Selector.Span.CopyTo(record[4..]); root.Before.Span.CopyTo(record[36..]); root.After.Span.CopyTo(record[68..]);
                BinaryPrimitives.WriteUInt32BigEndian(record[100..], checked((uint)root.Successor.Length));
                root.Successor.Span.CopyTo(successors.AsSpan(successorOffset)); successorOffset += root.Successor.Length;
            }
            for (var i = 0; i < rows.Count; i++)
            {
                var row = rows[i]; Require32(row.Selector.Span); Require32(row.Commitment.Span);
                var record = raw.AsSpan(HeaderBytes + roots.Count * RootBytes + i * RowBytes, RowBytes);
                record[0] = (byte)row.Action; row.Selector.Span.CopyTo(record[8..]); row.Commitment.Span.CopyTo(record[40..]);
            }
            SHA256.HashData(successors, raw.AsSpan(224, 32));
            BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(256), checked((uint)successors.Length));
            raw[260] = checked((byte)PartsFor(successors.Length));
            var plan = Decode(raw, Data.Slice(16, 16), Data.Slice(32, 32), Data.Slice(64, 32));
            try { plan.ValidateSuccessors(successors); return new(plan, new OwnedDeepSecret(successors)); }
            catch { plan.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(raw); CryptographicOperations.ZeroMemory(successors); }
    }

    internal static Did2CompactionPlan Decode(ReadOnlySpan<byte> raw, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireOwner(network, account, instance);
        if (raw.Length is < HeaderBytes or > MaximumBytes || raw[0] != 1 || raw[1] > 3 ||
            !Zero(raw.Slice(6, 2)) || !Zero(raw[261..HeaderBytes]) || !Fixed(raw.Slice(16, 16), network) ||
            !Fixed(raw.Slice(32, 32), account) || !Fixed(raw.Slice(64, 32), instance)) throw Bad();
        var revision = BinaryPrimitives.ReadUInt64BigEndian(raw[8..]);
        var roots = raw[3]; var rows = BinaryPrimitives.ReadUInt16BigEndian(raw[4..]);
        if (revision == 0 || roots > MaximumRoots || rows > MaximumRows ||
            raw.Length != HeaderBytes + roots * RootBytes + rows * RowBytes) throw Bad();
        if (raw[1] == 0)
        {
            if (raw[2] != 0 || roots != 0 || rows != 0 || !Zero(raw[96..])) throw Bad();
            return new(raw.ToArray());
        }
        if (revision < (raw[1] == 1 ? 2UL : 3UL) || raw[2] is < 1 or > 4 || roots == 0 || rows == 0) throw Bad();
        Require32(raw.Slice(96, 32)); Require32(raw.Slice(128, 32));
        Require32(raw.Slice(224, 32));
        var successorBytes = BinaryPrimitives.ReadUInt32BigEndian(raw[256..]);
        if (successorBytes is < 1 or > MaximumSuccessorBytes || raw[260] != PartsFor(checked((int)successorBytes))) throw Bad();
        if (raw[2] == (byte)SqlTarget.ProtectedOnly)
        { if (!Zero(raw.Slice(160, 64))) throw Bad(); }
        else
        { Require32(raw.Slice(160, 32)); Require32(raw.Slice(192, 32)); if (Fixed(raw.Slice(160, 32), raw.Slice(192, 32))) throw Bad(); }
        var changed = 0;
        var successorTotal = 0;
        var changedKinds = new HashSet<RootKind>(); var guards = new HashSet<RootKind>();
        var globalRoots = new HashSet<RootKind>();
        for (var i = 0; i < roots; i++)
        {
            var record = raw.Slice(HeaderBytes + i * RootBytes, RootBytes);
            if (record[0] is < 1 or > 14 || record[1] is not (1 or 2) || !Zero(record.Slice(2, 2))) throw Bad();
            if (record[0] is (byte)RootKind.SessionCatalog or (byte)RootKind.AccountRegistration or (byte)RootKind.NativeFence or (byte)RootKind.MessagingPeerBootstrap or (byte)RootKind.MailboxStoreState or (byte)RootKind.MailboxLocalCustody && record[1] != 2) throw Bad();
            if (record[0] is >= 1 and <= 5 or 7 or 8 or 12 or 13 or 14 && !globalRoots.Add((RootKind)record[0])) throw Bad();
            Require32(record.Slice(4, 32)); Require32(record.Slice(36, 32)); Require32(record.Slice(68, 32));
            if ((record[1] == 2) != Fixed(record.Slice(36, 32), record.Slice(68, 32))) throw Bad();
            var length = BinaryPrimitives.ReadUInt32BigEndian(record[100..]);
            if (record[1] == 2 ? length != 0 : length is < 1 or > MaximumRootBytes) throw Bad();
            successorTotal = checked(successorTotal + checked((int)length));
            if (successorTotal > MaximumSuccessorBytes) throw Bad();
            if (record[1] == 1) { changed++; changedKinds.Add((RootKind)record[0]); }
            else guards.Add((RootKind)record[0]);
            if (i != 0)
            {
                var prior = raw.Slice(HeaderBytes + (i - 1) * RootBytes, RootBytes);
                if (prior[0] > record[0] || prior[0] == record[0] && prior.Slice(4, 32).SequenceCompareTo(record.Slice(4, 32)) >= 0) throw Bad();
            }
        }
        if (changed == 0 || successorTotal != successorBytes) throw Bad();
        var selectors = new HashSet<string>(StringComparer.Ordinal);
        var actions = new HashSet<Disposition>();
        for (var i = 0; i < rows; i++)
        {
            var record = raw.Slice(HeaderBytes + roots * RootBytes + i * RowBytes, RowBytes);
            if (record[0] is < 1 or > 5 || !Zero(record.Slice(1, 7)) ||
                raw[2] == (byte)SqlTarget.Messaging && record[0] != (byte)Disposition.JournalPrefix ||
                raw[2] == (byte)SqlTarget.ProtectedOnly && record[0] is not ((byte)Disposition.ReplayScope or (byte)Disposition.Audit) ||
                raw[2] is (byte)SqlTarget.Application or (byte)SqlTarget.Transport && record[0] == (byte)Disposition.JournalPrefix) throw Bad();
            Require32(record.Slice(8, 32)); Require32(record.Slice(40, 32));
            actions.Add((Disposition)record[0]);
            if (!selectors.Add(Convert.ToHexString(record.Slice(8, 32)))) throw Bad();
            if (i != 0)
            {
                var prior = raw.Slice(HeaderBytes + roots * RootBytes + (i - 1) * RowBytes, RowBytes);
                if (prior[0] > record[0] || prior[0] == record[0] && prior.Slice(8, 32).SequenceCompareTo(record.Slice(8, 32)) >= 0) throw Bad();
            }
        }
        if (!guards.Contains(RootKind.AccountRegistration) ||
            actions.Contains(Disposition.ReplayScope) && !guards.Contains(RootKind.NativeFence) ||
            raw[2] == (byte)SqlTarget.ProtectedOnly && actions.Contains(Disposition.Audit) &&
                (rows != 1 || actions.Count != 1 || !changedKinds.Contains(RootKind.Send) || changedKinds.Count != 1 ||
                 !guards.Contains(RootKind.NativeFence) || !guards.Contains(RootKind.MailboxStoreState)) ||
            raw[2] == (byte)SqlTarget.Messaging && (!changedKinds.Contains(RootKind.MessagingHistoryCheckpoint) ||
                !guards.Contains(RootKind.MessagingFloor) || !guards.Contains(RootKind.SessionCatalog)) ||
            raw[2] == (byte)SqlTarget.Application && actions.Contains(Disposition.OutboxPayload) &&
                !changedKinds.Contains(RootKind.Ordinary) && !changedKinds.Contains(RootKind.Attachment) ||
            raw[2] == (byte)SqlTarget.Transport && actions.Contains(Disposition.OutboxPayload) &&
                !changedKinds.Contains(RootKind.Send) && !changedKinds.Contains(RootKind.Read) ||
            raw[2] == (byte)SqlTarget.ProtectedOnly && !changedKinds.Overlaps([RootKind.Grant, RootKind.Send, RootKind.Read])) throw Bad();
        // This action owns one closed joint SQL + grant/read/publication profile.
        // Other compaction profiles cannot borrow these roots or this action.
        var retainedPath = actions.Contains(Disposition.RetainedPath);
        if (retainedPath)
        {
            RootKind[] expected = [RootKind.Ordinary, RootKind.Send, RootKind.Grant, RootKind.Read,
                RootKind.SessionCatalog, RootKind.Attachment, RootKind.AccountRegistration,
                RootKind.NativeFence, RootKind.ContactPublication, RootKind.MailboxLocalCustody];
            if (raw[2] != (byte)SqlTarget.Application || roots != expected.Length || rows < 2 ||
                actions.Count != 2 || !actions.Contains(Disposition.ReplayScope)) throw Bad();
            for (var i = 0; i < roots; i++)
            {
                var record = raw.Slice(HeaderBytes + i * RootBytes, RootBytes);
                if (record[0] != (byte)expected[i] || record[1] != (i is 2 or 3 or 8 ? 1 : 2)) throw Bad();
            }
            for (var i = 0; i < rows; i++)
                if (raw[HeaderBytes + roots * RootBytes + i * RowBytes] !=
                    (byte)(i == rows - 1 ? Disposition.RetainedPath : Disposition.ReplayScope)) throw Bad();
        }
        else if (globalRoots.Contains(RootKind.ContactPublication) || globalRoots.Contains(RootKind.MailboxLocalCustody)) throw Bad();
        return new(raw.ToArray());
    }

    // Exact successor bytes are active protected custody, not audit metadata.
    // A digest alone cannot reconstruct a root after its source SQL was deleted.
    internal void ValidateSuccessors(ReadOnlySpan<byte> successors)
    {
        if (Phase == 0 || successors.Length != SuccessorBytes ||
            !Fixed(SHA256.HashData(successors), Data.Slice(224, 32))) throw Bad();
        var offset = 0;
        for (var i = 0; i < RootCount; i++)
        {
            var root = Data.Slice(HeaderBytes + i * RootBytes, RootBytes);
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(root[100..]));
            if (length != 0 && !Fixed(SHA256.HashData(successors.Slice(offset, length)), root.Slice(68, 32))) throw Bad();
            offset += length;
        }
        if (offset != successors.Length) throw Bad();
    }
    internal OwnedDeepSecret OwnSuccessor(int rootIndex, ReadOnlySpan<byte> successors)
    {
        ValidateSuccessors(successors);
        if (rootIndex < 0 || rootIndex >= RootCount) throw new ArgumentOutOfRangeException(nameof(rootIndex));
        var offset = 0;
        for (var i = 0; i <= rootIndex; i++)
        {
            var root = Data.Slice(HeaderBytes + i * RootBytes, RootBytes);
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(root[100..]));
            if (i == rootIndex) { if (length == 0) throw Bad(); return new(successors.Slice(offset, length)); }
            offset += length;
        }
        throw Bad();
    }

    // Observes structural exact states only. It does not open a database,
    // perform SQL/CAS, verify terminal evidence or authorize a returned step.
    internal RecoveryObservation ObserveReadback(ReadOnlySpan<byte> sqlDigest, IReadOnlyList<RootReadback> roots)
    {
        ArgumentNullException.ThrowIfNull(roots);
        if (Phase == 0 || roots.Count != RootCount || sqlDigest.Length != 32) throw Bad();
        var firstOriginal = -1;
        for (var i = 0; i < roots.Count; i++)
        {
            var expected = Data.Slice(HeaderBytes + i * RootBytes, RootBytes); var actual = roots[i];
            if ((byte)actual.Kind != expected[0] || !Fixed(actual.Selector.Span, expected.Slice(4, 32))) throw Bad();
            var before = Fixed(actual.Digest.Span, expected.Slice(36, 32));
            var after = Fixed(actual.Digest.Span, expected.Slice(68, 32));
            if (!before && !after || expected[1] == 2 && !before || Phase is 1 or 3 && !before) throw Bad();
            if (expected[1] == 2) continue;
            if (before) { if (firstOriginal < 0) firstOriginal = i; }
            else if (firstOriginal >= 0) throw Bad();
        }
        if (Phase == 3)
        {
            if (!Fixed(sqlDigest, Data.Slice(160, 32))) throw Bad();
            return new(RecoveryStep.ClearPlan);
        }
        if (Phase == 1)
        {
            if (Fixed(sqlDigest, Data.Slice(192, 32))) return new(RecoveryStep.RecordSqlCommit);
            if (Fixed(sqlDigest, Data.Slice(160, 32))) return new(RecoveryStep.ApplySql);
            throw Bad();
        }
        if (!Fixed(sqlDigest, Data.Slice(192, 32))) throw Bad();
        return firstOriginal < 0 ? new(RecoveryStep.ClearPlan) : new(RecoveryStep.AdoptRoot, firstOriginal);
    }

    // These are metadata phase encoders. Only a separately qualified held
    // owner may persist them after actual complete-effect read-back.
    internal Did2CompactionPlan WithSqlCommitted()
    {
        if (Phase != 1) throw Bad();
        var nextRevision = checked(Revision + 1);
        var raw = Data.ToArray(); raw[1] = 2;
        try
        {
            BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), nextRevision);
            return Decode(raw, Data.Slice(16, 16), Data.Slice(32, 32), Data.Slice(64, 32));
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }
    internal Did2CompactionPlan Cleared()
    {
        if (Phase is not (2 or 3)) throw Bad();
        var nextRevision = checked(Revision + 1);
        var raw = new byte[HeaderBytes]; Data[..96].CopyTo(raw); raw.AsSpan(1, 7).Clear();
        try
        {
            BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), nextRevision);
            return Decode(raw, Data.Slice(16, 16), Data.Slice(32, 32), Data.Slice(64, 32));
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }
    internal Did2CompactionPlan WithAbandoningBeforeSql()
    {
        if (Phase != 1) throw Bad();
        var raw = Data.ToArray(); raw[1] = 3;
        try
        {
            BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), checked(Revision + 1));
            return Decode(raw, Data.Slice(16, 16), Data.Slice(32, 32), Data.Slice(64, 32));
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }
    public void Dispose() { var raw = Interlocked.Exchange(ref bytes, null); if (raw is not null) CryptographicOperations.ZeroMemory(raw); }
    private static void RequireOwner(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { if (network.Length != 16 || Zero(network)) throw Bad(); Require32(account); Require32(instance); }
    private static void Require32(ReadOnlySpan<byte> value) { if (value.Length != 32 || Zero(value)) throw Bad(); }
    private static bool Zero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static int PartsFor(int count)
    { if (count is < 1 or > MaximumSuccessorBytes) throw Bad(); return (count + PartBytes - 1) / PartBytes; }
    private static InvalidDataException Bad() => new("Compaction plan/read-back is absent, foreign or noncanonical; no repair is permitted.");
}
