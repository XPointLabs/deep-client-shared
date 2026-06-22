using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

public sealed class ConversationService(
    IConversationRepository conversations,
    IContactRepository contacts,
    IGroupRepository groups,
    ISettingsRepository settings,
    IClock clock,
    ClientFeatureFlags featureFlags,
    IGroupSyncTransport groupSync)
{
    public async Task<Conversation> GetOrCreateOneToOneAsync(
        SessionId counterpart,
        string? displayName = null,
        CancellationToken cancellationToken = default)
    {
        var id = ConversationId.ForOneToOne(counterpart);
        var existing = await conversations.GetAsync(id, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            return existing;
        }

        var now = clock.UtcNow;
        var contact = await contacts.GetAsync(counterpart, cancellationToken).ConfigureAwait(false)
            ?? Contact.Request(counterpart, displayName, now);

        if (!string.IsNullOrWhiteSpace(displayName) && contact.DisplayName != displayName)
        {
            contact = contact with { DisplayName = displayName, UpdatedAt = now };
        }

        var conversation = new Conversation(
            id,
            ConversationKind.OneToOne,
            contact.DisplayName ?? counterpart.Value,
            ConversationSettings.Default(ConversationKind.OneToOne),
            now,
            now);

        await contacts.UpsertAsync(contact, cancellationToken).ConfigureAwait(false);
        await conversations.UpsertAsync(conversation, cancellationToken).ConfigureAwait(false);
        return conversation;
    }

    public async Task<Group> CreateGroupScaffoldAsync(
        SessionId owner,
        string name,
        IEnumerable<SessionId> memberIds,
        CancellationToken cancellationToken = default)
    {
        if (!featureFlags.GroupsV2Enabled)
        {
            throw new FeatureDisabledException(nameof(featureFlags.GroupsV2Enabled));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var now = clock.UtcNow;
        var id = ConversationId.CreateGroupV2();
        var members = memberIds
            .Append(owner)
            .Distinct()
            .Select(member => new GroupMember(member, member == owner ? GroupMemberRole.Admin : GroupMemberRole.Standard, now))
            .ToArray();

        var group = new Group(id, name.Trim(), owner, now, members);
        await PersistGroupWithConversationAsync(group, cancellationToken, updatedAt: now).ConfigureAwait(false);
        return group;
    }

    public async Task<IReadOnlyList<Conversation>> ListAsync(CancellationToken cancellationToken = default)
    {
        var result = new List<Conversation>();
        await foreach (var conversation in conversations.ListAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(conversation);
        }

        return result;
    }

    public async Task<IReadOnlyList<Group>> ListGroupsAsync(CancellationToken cancellationToken = default)
    {
        var result = new List<Group>();
        await foreach (var group in groups.ListAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(group);
        }

        return result;
    }

    public Task<Group?> GetGroupAsync(ConversationId groupId, CancellationToken cancellationToken = default) =>
        groups.GetAsync(groupId, cancellationToken);

    public async Task<IReadOnlyList<Group>> ReceiveGroupUpdatesAsync(
        SessionId memberId,
        CancellationToken cancellationToken = default)
    {
        if (!featureFlags.GroupsV2Enabled)
        {
            return [];
        }

        var updates = await groupSync.ReceiveGroupStatesAsync(memberId, cancellationToken).ConfigureAwait(false);
        var applied = new List<Group>(updates.Count);

        foreach (var update in updates.OrderBy(static item => item.UpdatedAt))
        {
            var existing = await groups.GetAsync(update.Group.Id, cancellationToken).ConfigureAwait(false);
            var existingUpdatedAt = await GetGroupStateUpdatedAtAsync(update.Group.Id, cancellationToken).ConfigureAwait(false);
            if (existing is not null && existingUpdatedAt is not null && existingUpdatedAt >= update.UpdatedAt)
            {
                continue;
            }

            var isMember = update.Group.Members.Any(member => member.SessionId == memberId);
            var group = update.Group with { IsKicked = update.Group.IsKicked || !isMember };
            await PersistGroupWithConversationAsync(
                group,
                cancellationToken,
                publish: false,
                updatedAt: update.UpdatedAt).ConfigureAwait(false);
            applied.Add(group);
        }

        return applied;
    }

    public async Task<Group?> UpdateGroupNameAsync(
        ConversationId groupId,
        SessionId requestor,
        string newName,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newName);

        var group = await groups.GetAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || !group.HasAdmin(requestor) || group.IsDestroyed)
        {
            return null;
        }

        var updated = group with { Name = newName.Trim() };
        await PersistGroupWithConversationAsync(updated, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    public async Task<Group?> PromoteMemberAsync(
        ConversationId groupId,
        SessionId requestor,
        SessionId memberId,
        CancellationToken cancellationToken = default)
    {
        var group = await groups.GetAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || !group.HasAdmin(requestor) || group.IsDestroyed)
        {
            return null;
        }

        var member = group.Members.FirstOrDefault(item => item.SessionId == memberId);
        if (member == default)
        {
            return null;
        }

        var updated = group.AddMember(member with { Role = GroupMemberRole.Admin, IsPendingRemoval = false });
        await PersistGroupWithConversationAsync(updated, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    public async Task<Group?> DemoteMemberAsync(
        ConversationId groupId,
        SessionId requestor,
        SessionId memberId,
        CancellationToken cancellationToken = default)
    {
        var group = await groups.GetAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || !group.HasAdmin(requestor) || group.IsDestroyed)
        {
            return null;
        }

        var member = group.Members.FirstOrDefault(item => item.SessionId == memberId);
        if (member == default || member.Role != GroupMemberRole.Admin)
        {
            return null;
        }

        var adminCount = group.Members.Count(item => item.Role == GroupMemberRole.Admin);
        if (adminCount <= 1)
        {
            return null;
        }

        var updated = group.AddMember(member with { Role = GroupMemberRole.Standard, IsPendingRemoval = false });
        await PersistGroupWithConversationAsync(updated, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    public async Task<Group?> MarkMemberPendingRemovalAsync(
        ConversationId groupId,
        SessionId requestor,
        SessionId memberId,
        bool isPending,
        CancellationToken cancellationToken = default)
    {
        var group = await groups.GetAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || !group.HasAdmin(requestor) || group.IsDestroyed)
        {
            return null;
        }

        var member = group.Members.FirstOrDefault(item => item.SessionId == memberId);
        if (member == default)
        {
            return null;
        }

        var updated = group.AddMember(member with { IsPendingRemoval = isPending });
        await PersistGroupWithConversationAsync(updated, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    public async Task<Group?> AddMemberAsync(
        ConversationId groupId,
        SessionId requestor,
        SessionId memberId,
        CancellationToken cancellationToken = default)
    {
        var group = await groups.GetAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || !group.HasAdmin(requestor) || group.IsDestroyed)
        {
            return null;
        }

        if (group.Members.Any(item => item.SessionId == memberId))
        {
            return group;
        }

        var updated = group.AddMember(new GroupMember(memberId, GroupMemberRole.Standard, clock.UtcNow));
        await PersistGroupWithConversationAsync(updated, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    public async Task<Group?> RemoveMemberAsync(
        ConversationId groupId,
        SessionId requestor,
        SessionId memberId,
        CancellationToken cancellationToken = default)
    {
        var group = await groups.GetAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || !group.HasAdmin(requestor) || group.IsDestroyed)
        {
            return null;
        }

        if (memberId == group.CreatedBy)
        {
            return null;
        }

        var withoutMember = group.Members.Where(item => item.SessionId != memberId).ToArray();
        if (withoutMember.Length == group.Members.Count)
        {
            return group;
        }

        var normalizedMembers = EnsureAdminPresence(withoutMember, clock.UtcNow);
        var updated = group with
        {
            Members = normalizedMembers,
            IsDestroyed = normalizedMembers.Length == 0
        };

        var recipients = GroupStateRecipients(group);
        await PersistGroupWithConversationAsync(updated, cancellationToken, recipients: recipients).ConfigureAwait(false);
        return updated;
    }

    public async Task<Group?> LeaveGroupAsync(
        ConversationId groupId,
        SessionId memberId,
        CancellationToken cancellationToken = default)
    {
        var group = await groups.GetAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || group.IsDestroyed)
        {
            return null;
        }

        var withoutMember = group.Members.Where(item => item.SessionId != memberId).ToArray();
        if (withoutMember.Length == group.Members.Count)
        {
            return group;
        }

        var normalizedMembers = EnsureAdminPresence(withoutMember, clock.UtcNow);
        var updated = group with
        {
            Members = normalizedMembers,
            IsDestroyed = normalizedMembers.Length == 0,
            IsKicked = false
        };

        var recipients = GroupStateRecipients(group);
        await PersistGroupWithConversationAsync(updated, cancellationToken, recipients: recipients).ConfigureAwait(false);
        return updated;
    }

    public async Task<Group?> DestroyGroupAsync(
        ConversationId groupId,
        SessionId requestor,
        CancellationToken cancellationToken = default)
    {
        var group = await groups.GetAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || !group.HasAdmin(requestor))
        {
            return null;
        }

        var updated = group with { IsDestroyed = true };
        var recipients = GroupStateRecipients(group);
        await PersistGroupWithConversationAsync(updated, cancellationToken, recipients: recipients).ConfigureAwait(false);
        return updated;
    }

    private async Task PersistGroupWithConversationAsync(
        Group group,
        CancellationToken cancellationToken,
        bool publish = true,
        IEnumerable<SessionId>? recipients = null,
        DateTimeOffset? updatedAt = null)
    {
        await groups.UpsertAsync(group, cancellationToken).ConfigureAwait(false);

        var now = updatedAt ?? clock.UtcNow;
        var conversation = await conversations.GetAsync(group.Id, cancellationToken).ConfigureAwait(false)
            ?? new Conversation(
                group.Id,
                ConversationKind.GroupV2,
                group.Name,
                ConversationSettings.Default(ConversationKind.GroupV2),
                group.CreatedAt,
                now);

        conversation = conversation with
        {
            DisplayName = group.Name,
            UpdatedAt = now,
            IsHidden = group.IsDestroyed
        };

        await conversations.UpsertAsync(conversation, cancellationToken).ConfigureAwait(false);
        await settings.SetAsync(GroupStateUpdatedAtSettingKey(group.Id), now.ToString("O"), cancellationToken)
            .ConfigureAwait(false);

        if (publish)
        {
            await groupSync.PublishGroupStateAsync(group, now, recipients, cancellationToken).ConfigureAwait(false);
        }
    }

    private static GroupMember[] EnsureAdminPresence(IReadOnlyList<GroupMember> members, DateTimeOffset now)
    {
        if (members.Count == 0 || members.Any(item => item.Role == GroupMemberRole.Admin))
        {
            return members.ToArray();
        }

        var promoted = members[0] with { Role = GroupMemberRole.Admin, IsPendingRemoval = false, JoinedAt = members[0].JoinedAt == default ? now : members[0].JoinedAt };
        return [promoted, .. members.Skip(1)];
    }

    private async Task<DateTimeOffset?> GetGroupStateUpdatedAtAsync(
        ConversationId groupId,
        CancellationToken cancellationToken)
    {
        var raw = await settings.GetAsync<string>(GroupStateUpdatedAtSettingKey(groupId), cancellationToken)
            .ConfigureAwait(false);
        return DateTimeOffset.TryParse(raw, out var parsed) ? parsed : null;
    }

    private static string GroupStateUpdatedAtSettingKey(ConversationId groupId) =>
        $"sync.group-state-updated.{groupId.Value}";

    private static SessionId[] GroupStateRecipients(Group group) =>
        group.Members
            .Select(member => member.SessionId)
            .Append(group.CreatedBy)
            .Distinct()
            .ToArray();
}
