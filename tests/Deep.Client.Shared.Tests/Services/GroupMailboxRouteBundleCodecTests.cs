using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class GroupMailboxRouteBundleCodecTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-08-28T00:00:00Z");

    [Fact]
    public void EncodeDecode_RoundTripsCanonicalGmr1()
    {
        var group = CreateGroup(3);
        var bundle = CreateBundle(group);

        var encoded = GroupMailboxRouteBundleCodec.Encode(bundle);
        var decoded = GroupMailboxRouteBundleCodec.Decode(encoded);

        Assert.Equal("GMR1", System.Text.Encoding.ASCII.GetString(encoded, 0, 4));
        Assert.Equal(bundle.GroupId, decoded.GroupId);
        Assert.Equal(bundle.GroupRevision, decoded.GroupRevision);
        Assert.Equal(bundle.MembershipDigest, decoded.MembershipDigest);
        Assert.Equal(
            bundle.Invitations.Select(static invitation => invitation.Member),
            decoded.Invitations.Select(static invitation => invitation.Member));
        Assert.All(decoded.Invitations, invitation => Assert.Equal(585, invitation.CanonicalInvitation.Length));
        GroupMailboxRouteBundleCodec.ValidateForGroup(decoded, group);
    }

    [Fact]
    public void Decode_RejectsTrailingBytesAndNonCanonicalOrder()
    {
        var group = CreateGroup(2);
        var bundle = CreateBundle(group);
        var encoded = GroupMailboxRouteBundleCodec.Encode(bundle);

        Assert.Throws<E2eeProtocolException>(() =>
            GroupMailboxRouteBundleCodec.Decode([.. encoded, 0]));
        Assert.Throws<ArgumentException>(() => GroupMailboxRouteBundleCodec.Encode(
            bundle with { Invitations = bundle.Invitations.Reverse().ToArray() }));
        Assert.Throws<ArgumentException>(() => GroupMailboxRouteBundleCodec.Encode(
            bundle with { Invitations = [bundle.Invitations[0], bundle.Invitations[0]] }));
    }

    [Fact]
    public void ValidateForGroup_RejectsMissingExtraAndMismatchedMembership()
    {
        var group = CreateGroup(3);
        var bundle = CreateBundle(group);

        Assert.Throws<InvalidOperationException>(() =>
            GroupMailboxRouteBundleCodec.ValidateForGroup(
                bundle with { Invitations = bundle.Invitations.Take(bundle.Invitations.Count - 1).ToArray() },
                group));

        var replacement = Session('f');
        var extra = bundle.Invitations
            .Take(2)
            .Append(new GroupMemberMailboxInvitation(replacement, new byte[585]))
            .OrderBy(static invitation => invitation.Member.Value, StringComparer.Ordinal)
            .ToArray();
        Assert.Throws<InvalidOperationException>(() =>
            GroupMailboxRouteBundleCodec.ValidateForGroup(bundle with { Invitations = extra }, group));

        Assert.Throws<InvalidOperationException>(() =>
            GroupMailboxRouteBundleCodec.ValidateForGroup(
                bundle with { MembershipDigest = new byte[32] },
                group));
    }

    [Fact]
    public void Encode_EnforcesNinetySixMemberAndInvitationBounds()
    {
        var group = CreateGroup(GroupMailboxRouteBundleCodec.MaxInvitations);
        var bundle = CreateBundle(group);
        Assert.True(GroupMailboxRouteBundleCodec.Encode(bundle).Length < E2eeEnvelopeCodec.MaxPlaintextBytes);

        var tooMany = Enumerable.Range(0, GroupMailboxRouteBundleCodec.MaxInvitations + 1)
            .Select(index => new GroupMemberMailboxInvitation(
                SessionId.Parse("05" + index.ToString("x64")),
                new byte[585]))
            .ToArray();
        Assert.Throws<ArgumentException>(() => GroupMailboxRouteBundleCodec.Encode(
            bundle with { Invitations = tooMany }));
        Assert.Throws<ArgumentException>(() => GroupMailboxRouteBundleCodec.Encode(
            bundle with
            {
                Invitations =
                [
                    bundle.Invitations[0] with
                    {
                        CanonicalInvitation = new byte[GroupMailboxRouteBundleCodec.CanonicalInvitationBytes + 1]
                    }
                ]
            }));
    }

    [Fact]
    public void Dmc1GroupRoutes_RoundTripsWithoutChangingLegacyGroupStateShape()
    {
        var group = CreateGroup(2);
        var bundle = CreateBundle(group);
        var content = new E2eeContent(
            E2eeContentKind.GroupRoutes,
            new MessageId(new string('a', 64)),
            ConversationKind.GroupV2,
            group.Id,
            group.CreatedBy,
            group.Members[1].SessionId,
            Now,
            Now.AddHours(1),
            null,
            string.Empty,
            [],
            GroupRoutes: bundle);

        var decoded = E2eeContentCodec.Decode(E2eeContentCodec.Encode(content), Now);

        Assert.Equal(E2eeContentKind.GroupRoutes, decoded.Kind);
        Assert.NotNull(decoded.GroupRoutes);
        GroupMailboxRouteBundleCodec.ValidateForGroup(decoded.GroupRoutes!, group);
    }

    private static Group CreateGroup(int memberCount)
    {
        var members = Enumerable.Range(1, memberCount)
            .Select(index => new GroupMember(
                SessionId.Parse("05" + index.ToString("x64")),
                index == 1 ? GroupMemberRole.Admin : GroupMemberRole.Standard,
                Now))
            .ToArray();
        return new Group(
            ConversationId.Parse("03" + new string('a', 64)),
            "Routes",
            members[0].SessionId,
            Now,
            members,
            Revision: 7);
    }

    private static GroupMailboxRouteBundle CreateBundle(Group group) =>
        new(
            group.Id,
            group.Revision,
            E2eeContentCodec.ComputeGroupMembershipDigest(group),
            group.Members
                .Select(static member => new GroupMemberMailboxInvitation(
                    member.SessionId,
                    Enumerable.Repeat((byte)member.SessionId.Value[^1], 585).ToArray()))
                .OrderBy(static invitation => invitation.Member.Value, StringComparer.Ordinal)
                .ToArray());

    private static SessionId Session(char value) =>
        SessionId.Parse("05" + new string(value, 64));
}
