using System.Buffers.Binary;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Services.GroupV1;

/// <summary>Promotes only protocol-verified transitions and exact decoded GCP1/GCF1 records into durable client plans.</summary>
public sealed class GroupClientStateService
{
    private const int MaximumProposals = 64;

    public GroupTransitionCommitPlan PrepareVerifiedTransition(GroupStoreScope scope,
        GroupOperationId32 operationId, ulong? expectedRevision, VerifiedGroupTransition transition,
        GroupCommitPackageRecord package, IReadOnlyList<GroupCommitChunkRecord>? chunks = null,
        GroupRecipientKey32? recipient = null)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(operationId);
        ArgumentNullException.ThrowIfNull(transition); ArgumentNullException.ThrowIfNull(package);
        chunks ??= [];
        if (!transition.BindsExactGcp1(package.CanonicalBytes.Span))
            throw new ArgumentException("GCP1 is not the exact package promoted by the verified transition.", nameof(package));
        var commit = transition.Commit;
        var network = commit.Field(1).ToArray(); var group = GroupId32.FromBytes(commit.Field(2).Span);
        var epoch = U64(commit.Field(4).Span); var predecessor = commit.Field(5).ToArray();
        var commitHash = commit.ArtifactHash.ToArray(); var packageHash = package.ArtifactHash.ToArray();

        if (!package.Field(1).Span.SequenceEqual(network) || !package.Field(2).Span.SequenceEqual(group.Span)
            || U64(package.Field(3).Span) != epoch || !ReadLp32Exact(package.Field(4).Span).AsSpan().SequenceEqual(commit.CanonicalBytes.Span))
            throw new ArgumentException("GCP1 is not the exact package for the verified transition.", nameof(package));
        if ((transition.Predecessor is null) != (epoch == 0)
            || (transition.Predecessor is not null && !transition.Predecessor.ArtifactHash.Span.SequenceEqual(predecessor)))
            throw new ArgumentException("Verified transition predecessor is inconsistent.", nameof(transition));

        var memberCount = U16(commit.Field(11).Span);
        var deviceCount = CountVerifiedDevices(commit.Field(12).Span, memberCount);
        if (memberCount is < 1 or > 100 || deviceCount is < 1 or > 500)
            throw new ArgumentException("Verified commit exceeds the bounded GroupV1 profile.", nameof(transition));

        var artifacts = ReadPackageArtifacts(package, commit);
        if (artifacts.Count(static x => x.Magic == "DGP1") > MaximumProposals)
            throw new ArgumentException("Verified package exceeds the pending proposal bound.", nameof(package));
        var chunkRows = VerifyChunks(package, chunks);
        GroupRecipientControlCursorSnapshot[] cursors = [];
        if (recipient is not null)
        {
            if (chunkRows.Count == 0) throw new ArgumentException("A recipient cursor requires exact GCF1 output.", nameof(chunks));
            var last = chunkRows.MaxBy(static x => x.Index)!;
            cursors = [new GroupRecipientControlCursorSnapshot(recipient, packageHash, last.Index, last.Count)];
        }
        return new(scope, operationId, expectedRevision, transition, package, group, network, epoch,
            commitHash, packageHash, predecessor, memberCount, deviceCount, artifacts, chunkRows, cursors);
    }

    private static List<GroupArtifactSnapshot> ReadPackageArtifacts(GroupCommitPackageRecord package, GroupCommitRecord verifiedCommit)
    {
        var result = new List<GroupArtifactSnapshot>();
        var proposalCount = U16(package.Field(5).Span);
        if (proposalCount > MaximumProposals) throw new ArgumentException("GCP1 proposal count exceeds 64.", nameof(package));
        ReadLpRecords(package.Field(6).Span, proposalCount, "DGP1", result);
        if (proposalCount != U16(verifiedCommit.Field(9).Span)
            || !result.Where(static x => x.Magic == "DGP1").SelectMany(static x => x.Hash.ToArray()).ToArray()
                .AsSpan().SequenceEqual(verifiedCommit.Field(10).Span))
            throw new ArgumentException("GCP1 proposals are not cryptographically bound to the verified commit.", nameof(package));

        var expectedInvitationPairs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var proposal in result.Where(static x => x.Magic == "DGP1"))
        {
            var decoded = (GroupProposalRecord)GroupCodec.Decode("DGP1", proposal.ExactCanonicalBytes.Span);
            if (U16(decoded.Field(9).Span) != (ushort)GroupProposalAction.ActivateAcceptedInvite) continue;
            var payload = decoded.Field(10).Span;
            if (payload.Length != 287) throw new ArgumentException("Verified activation proposal payload is malformed.", nameof(package));
            expectedInvitationPairs.Add(Convert.ToHexString(payload[..76]));
        }

        var pairs = U16(package.Field(9).Span); var value = package.Field(10).Span; var at = 0;
        if (pairs != expectedInvitationPairs.Count) throw new ArgumentException("GCP1 invitation pair set is not exact.", nameof(package));
        for (var i = 0; i < pairs; i++)
        {
            Require(value, at, 38); var invitationReference = value.Slice(at, 38); at += 38;
            var invitation = TakeLp(value, ref at); Require(value, at, 38); var acceptanceReference = value.Slice(at, 38); at += 38;
            var acceptance = TakeLp(value, ref at);
            if (!expectedInvitationPairs.Remove(Convert.ToHexString([.. invitationReference.ToArray(), .. acceptanceReference.ToArray()])))
                throw new ArgumentException("GCP1 invitation pair is not referenced by a verified proposal.", nameof(package));
            AddExact("GIV1", invitation, invitationReference[6..], result);
            AddExact("GIA1", acceptance, acceptanceReference[6..], result);
        }
        if (at != value.Length || expectedInvitationPairs.Count != 0) throw new ArgumentException("GCP1 invitation list is not exact.", nameof(package));
        return result;
    }

    private static void ReadLpRecords(ReadOnlySpan<byte> value, ushort count, string magic, List<GroupArtifactSnapshot> output)
    {
        var at = 0;
        for (var i = 0; i < count; i++) { var bytes = TakeLp(value, ref at); var record = GroupCodec.Decode(magic, bytes); output.Add(new(magic, record.ArtifactHash.Span, record.CanonicalBytes.Span)); }
        if (at != value.Length) throw new ArgumentException("GCP1 embedded record list is not exact.");
    }

    private static void AddExact(string magic, ReadOnlySpan<byte> canonical, ReadOnlySpan<byte> expectedHash, List<GroupArtifactSnapshot> output)
    {
        var record = GroupCodec.Decode(magic, canonical);
        if (!record.ArtifactHash.Span.SequenceEqual(expectedHash)) throw new ArgumentException("GCP1 artifact reference mismatch.");
        output.Add(new(magic, expectedHash, record.CanonicalBytes.Span));
    }

    private static List<GroupChunkSnapshot> VerifyChunks(GroupCommitPackageRecord package, IReadOnlyList<GroupCommitChunkRecord> chunks)
    {
        if (chunks.Count == 0) return [];
        var assembler = GroupCodec.NewChunkAssembler(); var rows = new List<GroupChunkSnapshot>(chunks.Count);
        ReadOnlyMemory<byte> completed = default;
        foreach (var chunk in chunks.OrderBy(static x => U32(x.Field(4).Span)))
        {
            if (!chunk.Field(1).Span.SequenceEqual(package.ArtifactHash.Span) || !assembler.TryAdd(chunk, out completed))
                throw new ArgumentException("GCF1 sequence is conflicting or does not belong to GCP1.", nameof(chunks));
            rows.Add(new(U32(chunk.Field(4).Span), U32(chunk.Field(5).Span), chunk.Field(6).Span, chunk.CanonicalBytes.Span));
        }
        if (completed.IsEmpty || !completed.Span.SequenceEqual(package.CanonicalBytes.Span))
            throw new ArgumentException("GCF1 sequence is incomplete or reconstructs another package.", nameof(chunks));
        return rows;
    }

    private static ushort CountVerifiedDevices(ReadOnlySpan<byte> members, ushort expectedMembers)
    {
        var at = 0; var count = 0; var devices = 0;
        while (at < members.Length)
        {
            Require(members, at, 2); var length = U16(members[at..]); at += 2; Require(members, at, length);
            if (length < 220) throw new ArgumentException("Verified member table is malformed.");
            var deviceCount = members[at + 219];
            if (deviceCount is < 1 or > 5 || length != 220 + deviceCount * 70) throw new ArgumentException("Verified member table is malformed.");
            devices += deviceCount; count++; at += length;
        }
        if (count != expectedMembers || devices > 500) throw new ArgumentException("Verified member counts are inconsistent.");
        return checked((ushort)devices);
    }

    private static byte[] ReadLp32Exact(ReadOnlySpan<byte> value) { var at = 0; var result = TakeLp(value, ref at).ToArray(); if (at != value.Length) throw new ArgumentException("Non-exact LP32."); return result; }
    private static ReadOnlySpan<byte> TakeLp(ReadOnlySpan<byte> value, ref int at)
    { Require(value, at, 4); var n = U32(value[at..]); at += 4; if (n > int.MaxValue) throw new ArgumentException("LP32 is too large."); Require(value, at, (int)n); var result = value.Slice(at, (int)n); at += (int)n; return result; }
    private static void Require(ReadOnlySpan<byte> value, int at, int length) { if (at < 0 || length < 0 || length > value.Length - at) throw new ArgumentException("Truncated canonical GroupV1 field."); }
    private static ushort U16(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt16BigEndian(value);
    private static uint U32(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt32BigEndian(value);
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
}
