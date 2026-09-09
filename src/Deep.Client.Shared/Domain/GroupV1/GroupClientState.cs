using System.Buffers.Binary;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Domain.GroupV1;

public sealed class GroupStoreScope : IEquatable<GroupStoreScope>
{
    public const int CurrentStoreGeneration = 1;

    public GroupStoreScope(DeepAccountId32 accountId, ulong accountGeneration, int storeGeneration)
    {
        AccountId = accountId ?? throw new ArgumentNullException(nameof(accountId));
        if (accountGeneration == 0) throw new ArgumentOutOfRangeException(nameof(accountGeneration));
        if (storeGeneration <= 0) throw new ArgumentOutOfRangeException(nameof(storeGeneration));
        AccountGeneration = accountGeneration;
        StoreGeneration = storeGeneration;
    }

    public DeepAccountId32 AccountId { get; }
    public ulong AccountGeneration { get; }
    public int StoreGeneration { get; }

    public static GroupStoreScope ForCurrentAccount(DeepAccountId32 accountId, ulong accountGeneration) =>
        new(accountId, accountGeneration, CurrentStoreGeneration);

    public bool Equals(GroupStoreScope? other) => other is not null
        && AccountId.Equals(other.AccountId)
        && AccountGeneration == other.AccountGeneration
        && StoreGeneration == other.StoreGeneration;
    public override bool Equals(object? obj) => Equals(obj as GroupStoreScope);
    public override int GetHashCode() => HashCode.Combine(AccountId, AccountGeneration, StoreGeneration);
    public override string ToString() => "[opaque-group-store-scope]";
}

public abstract class GroupBytes32 : IEquatable<GroupBytes32>
{
    private readonly byte[] bytes;
    protected GroupBytes32(ReadOnlySpan<byte> value, string parameter)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte value is required.", parameter);
        bytes = value.ToArray();
    }
    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();
    internal ReadOnlySpan<byte> Span => bytes;
    internal byte[] ToArray() => bytes.ToArray();
    public bool Equals(GroupBytes32? other) => other is not null
        && GetType() == other.GetType() && bytes.AsSpan().SequenceEqual(other.bytes);
    public override bool Equals(object? obj) => Equals(obj as GroupBytes32);
    public override int GetHashCode() => BinaryPrimitives.ReadInt32BigEndian(bytes);
    public override string ToString() => $"[{GetType().Name}]";
}

public sealed class GroupId32 : GroupBytes32
{
    private GroupId32(ReadOnlySpan<byte> value) : base(value, nameof(value)) { }
    public static GroupId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class GroupOperationId32 : GroupBytes32
{
    private GroupOperationId32(ReadOnlySpan<byte> value) : base(value, nameof(value)) { }
    public static GroupOperationId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class GroupRecipientKey32 : GroupBytes32
{
    private GroupRecipientKey32(ReadOnlySpan<byte> value) : base(value, nameof(value)) { }
    public static GroupRecipientKey32 FromOpaqueBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class GroupArtifactSnapshot
{
    private readonly byte[] hash;
    private readonly byte[] canonical;
    internal GroupArtifactSnapshot(string magic, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> canonical)
    {
        if (magic is not ("DGP1" or "GIV1" or "GIA1"))
            throw new ArgumentOutOfRangeException(nameof(magic));
        if (hash.Length != 32 || hash.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Artifact hash must be nonzero and 32 bytes.", nameof(hash));
        if (canonical.IsEmpty) throw new ArgumentException("Canonical artifact is required.", nameof(canonical));
        Magic = magic; this.hash = hash.ToArray(); this.canonical = canonical.ToArray();
    }
    public string Magic { get; }
    public ReadOnlyMemory<byte> Hash => hash.ToArray();
    public ReadOnlyMemory<byte> ExactCanonicalBytes => canonical.ToArray();
    internal GroupArtifactSnapshot Copy() => new(Magic, hash, canonical);
}

public sealed class GroupRecipientControlCursorSnapshot
{
    private readonly byte[] packageHash;
    internal GroupRecipientControlCursorSnapshot(GroupRecipientKey32 recipient, ReadOnlySpan<byte> packageHash,
        uint chunkIndex, uint chunkCount)
    {
        Recipient = GroupRecipientKey32.FromOpaqueBytes(recipient.Span);
        if (packageHash.Length != 32 || packageHash.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Package hash must be nonzero and 32 bytes.", nameof(packageHash));
        if (chunkCount == 0 || chunkIndex >= chunkCount)
            throw new ArgumentOutOfRangeException(nameof(chunkIndex));
        this.packageHash = packageHash.ToArray(); ChunkIndex = chunkIndex; ChunkCount = chunkCount;
    }
    public GroupRecipientKey32 Recipient { get; }
    public ReadOnlyMemory<byte> PackageHash => packageHash.ToArray();
    public uint ChunkIndex { get; }
    public uint ChunkCount { get; }
    internal GroupRecipientControlCursorSnapshot Copy() => new(Recipient, packageHash, ChunkIndex, ChunkCount);
}

public sealed class GroupHeadSnapshot
{
    private readonly byte[] networkId;
    private readonly byte[] commitHash;
    private readonly byte[] packageHash;
    private readonly byte[] predecessorHash;
    private readonly byte[] canonicalCommit;
    private readonly byte[] canonicalPackage;
    private readonly byte[] exactVerifiedGcp1Sha256;
    private readonly GroupArtifactSnapshot[] artifacts;
    private readonly GroupRecipientControlCursorSnapshot[] cursors;

    internal GroupHeadSnapshot(GroupId32 groupId, ReadOnlySpan<byte> networkId, ulong epoch, ulong revision,
        ReadOnlySpan<byte> commitHash, ReadOnlySpan<byte> packageHash, ReadOnlySpan<byte> predecessorHash,
        ReadOnlySpan<byte> canonicalCommit, ReadOnlySpan<byte> canonicalPackage,
        ReadOnlySpan<byte> exactVerifiedGcp1Sha256, ushort memberCount,
        ushort deviceCount, bool forkLatched, IEnumerable<GroupArtifactSnapshot> artifacts,
        IEnumerable<GroupRecipientControlCursorSnapshot> cursors)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Network ID must be nonzero and 16 bytes.", nameof(networkId));
        if (revision == 0 || memberCount is < 1 or > 100 || deviceCount is < 1 or > 500)
            throw new ArgumentOutOfRangeException(nameof(revision));
        ValidateHash(commitHash, nameof(commitHash)); ValidateHash(packageHash, nameof(packageHash));
        if (predecessorHash.Length != 32 || (epoch != 0 && predecessorHash.IndexOfAnyExcept((byte)0) < 0)
            || (epoch == 0 && predecessorHash.IndexOfAnyExcept((byte)0) >= 0))
            throw new ArgumentException("Predecessor hash does not match the epoch.", nameof(predecessorHash));
        if (canonicalCommit.IsEmpty || canonicalPackage.IsEmpty) throw new ArgumentException("Canonical group records are required.");
        ValidateHash(exactVerifiedGcp1Sha256, nameof(exactVerifiedGcp1Sha256));
        Span<byte> candidateGcp1Sha256 = stackalloc byte[32];
        System.Security.Cryptography.SHA256.HashData(canonicalPackage, candidateGcp1Sha256);
        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(exactVerifiedGcp1Sha256, candidateGcp1Sha256))
            throw new ArgumentException("Canonical GCP1 does not match its verifier-authoritative hash.", nameof(canonicalPackage));
        GroupId = GroupId32.FromBytes(groupId.Span); this.networkId = networkId.ToArray(); Epoch = epoch; Revision = revision;
        this.commitHash = commitHash.ToArray(); this.packageHash = packageHash.ToArray(); this.predecessorHash = predecessorHash.ToArray();
        this.canonicalCommit = canonicalCommit.ToArray(); this.canonicalPackage = canonicalPackage.ToArray();
        this.exactVerifiedGcp1Sha256 = exactVerifiedGcp1Sha256.ToArray();
        MemberCount = memberCount; DeviceCount = deviceCount; ForkLatched = forkLatched;
        this.artifacts = artifacts.Select(static x => x.Copy()).ToArray();
        this.cursors = cursors.Select(static x => x.Copy()).ToArray();
    }

    public GroupId32 GroupId { get; }
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong Epoch { get; }
    public ulong Revision { get; }
    public ReadOnlyMemory<byte> CommitHash => commitHash.ToArray();
    public ReadOnlyMemory<byte> PackageHash => packageHash.ToArray();
    public ReadOnlyMemory<byte> PredecessorHash => predecessorHash.ToArray();
    public ReadOnlyMemory<byte> ExactCanonicalCommit => canonicalCommit.ToArray();
    public ReadOnlyMemory<byte> ExactCanonicalPackage => canonicalPackage.ToArray();
    public ReadOnlyMemory<byte> ExactVerifiedGcp1Sha256 => exactVerifiedGcp1Sha256.ToArray();
    public ushort MemberCount { get; }
    public ushort DeviceCount { get; }
    public bool ForkLatched { get; }
    public IReadOnlyList<GroupArtifactSnapshot> Artifacts => Array.AsReadOnly(artifacts.Select(static x => x.Copy()).ToArray());
    public IReadOnlyList<GroupRecipientControlCursorSnapshot> ControlCursors => Array.AsReadOnly(cursors.Select(static x => x.Copy()).ToArray());
    internal GroupHeadSnapshot Copy() => new(GroupId, networkId, Epoch, Revision, commitHash, packageHash,
        predecessorHash, canonicalCommit, canonicalPackage, exactVerifiedGcp1Sha256, MemberCount, DeviceCount,
        ForkLatched, artifacts, cursors);

    private static void ValidateHash(ReadOnlySpan<byte> value, string parameter)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte hash is required.", parameter);
    }
}
