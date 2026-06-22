namespace Deep.Client.Shared.Domain;

public sealed record GroupMember(
    SessionId SessionId,
    GroupMemberRole Role,
    DateTimeOffset JoinedAt,
    bool IsPendingRemoval = false);

public sealed record Group(
    ConversationId Id,
    string Name,
    SessionId CreatedBy,
    DateTimeOffset CreatedAt,
    IReadOnlyList<GroupMember> Members,
    bool IsDestroyed = false,
    bool IsKicked = false)
{
    public bool HasAdmin(SessionId sessionId) =>
        Members.Any(member => member.SessionId == sessionId && member.Role == GroupMemberRole.Admin);

    public Group AddMember(GroupMember member)
    {
        var withoutExisting = Members.Where(existing => existing.SessionId != member.SessionId).ToArray();
        return this with { Members = [.. withoutExisting, member] };
    }
}
