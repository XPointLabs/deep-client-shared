using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Persistence.GroupV1;

public enum GroupCommitDisposition
{
    Applied = 1,
    Idempotent = 2,
    NotFound = 3,
    StaleRevision = 4,
    Conflict = 5,
    ForkLatched = 6,
    InvalidTransition = 7,
}

public sealed record GroupCommitResult(GroupCommitDisposition Disposition, GroupHeadSnapshot? Head);

public interface IGroupStateStore
{
    GroupStoreScope Scope { get; }
    ValueTask<GroupHeadSnapshot?> ReadHeadAsync(GroupId32 groupId, CancellationToken cancellationToken = default);
    ValueTask<IReadOnlyList<GroupHeadSnapshot>> ReadHeadsAsync(CancellationToken cancellationToken = default);
    ValueTask<GroupHeadReadLease> AcquireHeadReadLeaseAsync(
        GroupId32 groupId,
        CancellationToken cancellationToken = default);
    ValueTask<GroupCommitResult> CommitVerifiedTransitionAsync(GroupTransitionCommitPlan plan,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Holds a stable, process- and database-wide view of one group head while a
/// dependent local transaction is materialized. The lease carries no network,
/// crypto, or transition authority.
/// </summary>
public sealed class GroupHeadReadLease : IDisposable, IAsyncDisposable
{
    private Action? release;

    internal GroupHeadReadLease(GroupHeadSnapshot? head, Action release)
    {
        Head = head?.Copy();
        this.release = release ?? throw new ArgumentNullException(nameof(release));
    }

    public GroupHeadSnapshot? Head { get; }

    internal GroupHeadSnapshot? DemandActiveHead()
    {
        if (Volatile.Read(ref release) is null)
            throw new ObjectDisposedException(nameof(GroupHeadReadLease));
        return Head?.Copy();
    }

    public void Dispose() => Interlocked.Exchange(ref release, null)?.Invoke();

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}

public sealed class GroupTransitionCommitPlan
{
    private readonly byte[] fingerprint;
    private readonly byte[] networkId;
    private readonly byte[] commitHash;
    private readonly byte[] packageHash;
    private readonly byte[] predecessorHash;
    private readonly byte[] canonicalCommit;
    private readonly byte[] canonicalPackage;
    private readonly byte[] exactVerifiedGcp1Sha256;
    private readonly GroupArtifactSnapshot[] artifacts;
    private readonly GroupChunkSnapshot[] chunks;
    private readonly GroupRecipientControlCursorSnapshot[] cursors;

    internal GroupTransitionCommitPlan(GroupStoreScope scope, GroupOperationId32 operationId,
        ulong? expectedRevision, VerifiedGroupTransition verifiedTransition, GroupCommitPackageRecord package,
        GroupId32 groupId, ReadOnlySpan<byte> networkId, ulong epoch, ReadOnlySpan<byte> commitHash,
        ReadOnlySpan<byte> packageHash, ReadOnlySpan<byte> predecessorHash, ushort memberCount, ushort deviceCount,
        IEnumerable<GroupArtifactSnapshot> artifacts, IEnumerable<GroupChunkSnapshot> chunks,
        IEnumerable<GroupRecipientControlCursorSnapshot> cursors)
    {
        if (!verifiedTransition.BindsExactGcp1(package.CanonicalBytes.Span))
            throw new ArgumentException("GCP1 bytes are not bound to the verified transition.", nameof(package));
        Scope = scope; OperationId = GroupOperationId32.FromBytes(operationId.Span);
        ExpectedRevision = expectedRevision; VerifiedTransition = verifiedTransition; Package = package;
        GroupId = GroupId32.FromBytes(groupId.Span); this.networkId = networkId.ToArray(); Epoch = epoch;
        this.commitHash = commitHash.ToArray(); this.packageHash = packageHash.ToArray();
        this.predecessorHash = predecessorHash.ToArray(); canonicalCommit = verifiedTransition.Commit.CanonicalBytes.ToArray();
        canonicalPackage = package.CanonicalBytes.ToArray(); MemberCount = memberCount; DeviceCount = deviceCount;
        exactVerifiedGcp1Sha256 = verifiedTransition.ExactVerifiedGcp1Sha256.ToArray();
        this.artifacts = artifacts.Select(static x => x.Copy()).ToArray();
        this.chunks = chunks.Select(static x => x.Copy()).ToArray();
        this.cursors = cursors.Select(static x => x.Copy()).ToArray();
        fingerprint = ComputeFingerprint();
    }

    public GroupStoreScope Scope { get; }
    public GroupOperationId32 OperationId { get; }
    public ulong? ExpectedRevision { get; }
    internal VerifiedGroupTransition VerifiedTransition { get; }
    internal GroupCommitPackageRecord Package { get; }
    internal GroupId32 GroupId { get; }
    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ulong Epoch { get; }
    internal ReadOnlySpan<byte> CommitHash => commitHash;
    internal ReadOnlySpan<byte> PackageHash => packageHash;
    internal ReadOnlySpan<byte> PredecessorHash => predecessorHash;
    internal ReadOnlySpan<byte> CanonicalCommit => canonicalCommit;
    internal ReadOnlySpan<byte> CanonicalPackage => canonicalPackage;
    internal ReadOnlySpan<byte> ExactVerifiedGcp1Sha256 => exactVerifiedGcp1Sha256;
    internal ushort MemberCount { get; }
    internal ushort DeviceCount { get; }
    internal IReadOnlyList<GroupArtifactSnapshot> Artifacts => artifacts;
    internal IReadOnlyList<GroupChunkSnapshot> Chunks => chunks;
    internal IReadOnlyList<GroupRecipientControlCursorSnapshot> Cursors => cursors;
    internal ReadOnlySpan<byte> Fingerprint => fingerprint;

    private byte[] ComputeFingerprint()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, Scope.AccountId.Bytes.Span);
        Span<byte> scalar = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(scalar, Scope.AccountGeneration); Append(hash, scalar);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, checked((ulong)Scope.StoreGeneration)); Append(hash, scalar);
        Append(hash, OperationId.Span); Append(hash, GroupId.Span);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, ExpectedRevision ?? 0); Append(hash, scalar);
        Append(hash, commitHash); Append(hash, packageHash); Append(hash, exactVerifiedGcp1Sha256);
        foreach (var chunk in chunks.OrderBy(static x => x.Index)) Append(hash, chunk.ExactCanonicalBytes.Span);
        foreach (var cursor in cursors.OrderBy(static x => Convert.ToHexString(x.Recipient.Bytes.Span), StringComparer.Ordinal))
        { Append(hash, cursor.Recipient.Bytes.Span); Append(hash, cursor.PackageHash.Span); BinaryPrimitives.WriteUInt32BigEndian(scalar, cursor.ChunkIndex); hash.AppendData(scalar[..4]); }
        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4]; BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length); hash.AppendData(value);
    }
}

internal sealed class GroupChunkSnapshot
{
    private readonly byte[] hash;
    private readonly byte[] canonical;
    internal GroupChunkSnapshot(uint index, uint count, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> canonical)
    { Index = index; Count = count; this.hash = hash.ToArray(); this.canonical = canonical.ToArray(); }
    internal uint Index { get; }
    internal uint Count { get; }
    internal ReadOnlyMemory<byte> Hash => hash.ToArray();
    internal ReadOnlyMemory<byte> ExactCanonicalBytes => canonical.ToArray();
    internal GroupChunkSnapshot Copy() => new(Index, Count, hash, canonical);
}
