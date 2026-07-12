using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

public sealed class ConversationService(
    IConversationRepository conversations,
    IContactRepository contacts,
    IGroupRepository groups,
    IGroupStatePersistenceRepository groupStatePersistence,
    IClock clock,
    ClientFeatureFlags featureFlags,
    IGroupSyncTransport groupSync)
{
    private readonly SemaphoreSlim groupOutboxGate = new(1, 1);

    public async Task<Conversation> GetOrCreateOneToOneAsync(
        SessionId counterpart,
        string? displayName = null,
        bool approve = false,
        CancellationToken cancellationToken = default)
    {
        var id = ConversationId.ForOneToOne(counterpart);
        var existing = await conversations.GetAsync(id, cancellationToken).ConfigureAwait(false);
        var now = clock.UtcNow;
        var normalizedDisplayName = NormalizeDisplayName(counterpart, displayName);
        var contact = await contacts.GetAsync(counterpart, cancellationToken).ConfigureAwait(false)
            ?? Contact.Request(counterpart, normalizedDisplayName, now);
        var normalizedContactDisplayName = NormalizeDisplayName(counterpart, contact.DisplayName);

        if (!string.Equals(contact.DisplayName, normalizedContactDisplayName, StringComparison.Ordinal)
            || (!string.IsNullOrWhiteSpace(normalizedDisplayName) && contact.DisplayName != normalizedDisplayName)
            || (approve && !contact.IsApproved))
        {
            contact = contact with
            {
                DisplayName = string.IsNullOrWhiteSpace(normalizedDisplayName) ? normalizedContactDisplayName : normalizedDisplayName,
                IsApproved = contact.IsApproved || approve,
                IsTrusted = contact.IsTrusted || approve,
                UpdatedAt = now
            };
        }

        await contacts.UpsertAsync(contact, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            var desiredDisplayName = contact.DisplayName ?? counterpart.Value;
            var shouldPersistExisting = false;
            if (!string.Equals(existing.DisplayName, desiredDisplayName, StringComparison.Ordinal))
            {
                existing = existing with { DisplayName = desiredDisplayName };
                shouldPersistExisting = true;
            }

            if (existing.IsHidden)
            {
                existing = existing with { IsHidden = false, UpdatedAt = now };
                shouldPersistExisting = true;
            }

            if (shouldPersistExisting)
            {
                await conversations.UpsertAsync(existing, cancellationToken).ConfigureAwait(false);
            }

            return existing;
        }

        var conversation = new Conversation(
            id,
            ConversationKind.OneToOne,
            contact.DisplayName ?? counterpart.Value,
            ConversationSettings.Default(ConversationKind.OneToOne),
            now,
            now);

        await conversations.UpsertAsync(conversation, cancellationToken).ConfigureAwait(false);
        return conversation;
    }

    public Task<Contact?> GetContactAsync(SessionId contactId, CancellationToken cancellationToken = default) =>
        contacts.GetAsync(contactId, cancellationToken);

    public async Task<Contact> UpdateContactDisplayNameAsync(
        SessionId contactId,
        string? displayName,
        CancellationToken cancellationToken = default)
    {
        var normalizedDisplayName = string.IsNullOrWhiteSpace(displayName)
            ? null
            : displayName.Trim();
        normalizedDisplayName = NormalizeDisplayName(contactId, normalizedDisplayName);
        var now = clock.UtcNow;
        var contact = await contacts.GetAsync(contactId, cancellationToken).ConfigureAwait(false)
            ?? Contact.Request(contactId, normalizedDisplayName, now);
        var updated = contact with
        {
            DisplayName = normalizedDisplayName,
            UpdatedAt = now
        };
        await contacts.UpsertAsync(updated, cancellationToken).ConfigureAwait(false);

        var conversationId = ConversationId.ForOneToOne(contactId);
        var conversation = await conversations.GetAsync(conversationId, cancellationToken).ConfigureAwait(false);
        if (conversation is not null)
        {
            await conversations.UpsertAsync(
                conversation with { DisplayName = normalizedDisplayName ?? contactId.Value },
                cancellationToken).ConfigureAwait(false);
        }

        return updated;
    }

    public async Task SetConversationHiddenAsync(
        ConversationId conversationId,
        bool hidden,
        CancellationToken cancellationToken = default)
    {
        var conversation = await conversations.GetAsync(conversationId, cancellationToken).ConfigureAwait(false);
        if (conversation is null || conversation.IsHidden == hidden)
        {
            return;
        }

        await conversations.UpsertAsync(
            conversation with { IsHidden = hidden, UpdatedAt = clock.UtcNow },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<Contact> ApproveContactAsync(SessionId contactId, CancellationToken cancellationToken = default)
    {
        var contact = await contacts.GetAsync(contactId, cancellationToken).ConfigureAwait(false)
            ?? Contact.Request(contactId, null, clock.UtcNow);
        var updated = contact with
        {
            IsApproved = true,
            IsTrusted = true,
            IsBlocked = false,
            UpdatedAt = clock.UtcNow
        };
        await contacts.UpsertAsync(updated, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    public async Task<Contact> SetContactBlockedAsync(
        SessionId contactId,
        bool blocked,
        CancellationToken cancellationToken = default)
    {
        var contact = await contacts.GetAsync(contactId, cancellationToken).ConfigureAwait(false)
            ?? Contact.Request(contactId, null, clock.UtcNow);
        var updated = contact with { IsBlocked = blocked, UpdatedAt = clock.UtcNow };
        await contacts.UpsertAsync(updated, cancellationToken).ConfigureAwait(false);
        return updated;
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

        var group = new Group(id, name.Trim(), owner, now, members, Revision: 1);
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

        await TryFlushPendingGroupStatesAsync(cancellationToken).ConfigureAwait(false);

        var updates = await groupSync.ReceiveGroupStatesAsync(memberId, cancellationToken).ConfigureAwait(false);
        var applied = new List<Group>(updates.Count);

        foreach (var update in updates
                     .OrderBy(static item => item.Group.Revision)
                     .ThenBy(static item => item.UpdatedAt))
        {
            var existing = await groups.GetAsync(update.Group.Id, cancellationToken).ConfigureAwait(false);
            var shouldAcknowledge = true;
            if (TryValidateInboundGroupState(update, existing, memberId, out var group))
            {
                await PersistGroupWithConversationAsync(
                    group,
                    cancellationToken,
                    publish: false,
                    updatedAt: update.UpdatedAt).ConfigureAwait(false);
                applied.Add(group);
            }
            else if (TryResumePersistedInboundGroupState(update, existing, memberId, out group))
            {
                await PersistGroupWithConversationAsync(
                    group,
                    cancellationToken,
                    publish: false,
                    updatedAt: update.UpdatedAt).ConfigureAwait(false);
            }
            else if (ShouldDeferInboundGroupState(update, existing, memberId))
            {
                shouldAcknowledge = false;
            }

            if (shouldAcknowledge)
            {
                await AcknowledgeInboxItemAsync(groupSync, memberId, update.ServerHash, cancellationToken)
                    .ConfigureAwait(false);
            }
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

        var normalizedName = newName.Trim();
        if (string.Equals(group.Name, normalizedName, StringComparison.Ordinal))
        {
            return group;
        }

        var updated = WithNextRevision(group with { Name = normalizedName });
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

        if (member.Role == GroupMemberRole.Admin && !member.IsPendingRemoval)
        {
            return group;
        }

        var updated = WithNextRevision(
            group.AddMember(member with { Role = GroupMemberRole.Admin, IsPendingRemoval = false }));
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

        var updated = WithNextRevision(
            group.AddMember(member with { Role = GroupMemberRole.Standard, IsPendingRemoval = false }));
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

        if (member.IsPendingRemoval == isPending)
        {
            return group;
        }

        var updated = WithNextRevision(group.AddMember(member with { IsPendingRemoval = isPending }));
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

        var updated = WithNextRevision(
            group.AddMember(new GroupMember(memberId, GroupMemberRole.Standard, clock.UtcNow)));
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
        var updated = WithNextRevision(group with
        {
            Members = normalizedMembers,
            IsDestroyed = normalizedMembers.Length == 0
        });

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
        var updated = WithNextRevision(group with
        {
            Members = normalizedMembers,
            IsDestroyed = normalizedMembers.Length == 0,
            IsKicked = false
        });

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

        if (group.IsDestroyed)
        {
            return group;
        }

        var updated = WithNextRevision(group with { IsDestroyed = true });
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

        GroupStateOutboxItem? outboxItem = null;
        if (publish)
        {
            var targetRecipients = (recipients ?? GroupStateRecipients(group))
                .Append(group.CreatedBy)
                .Distinct()
                .ToArray();
            outboxItem = new GroupStateOutboxItem(
                GroupStateOperationId(group),
                group,
                now,
                targetRecipients);
        }

        await groupStatePersistence.PersistGroupStateAsync(
            group,
            conversation,
            now,
            outboxItem,
            cancellationToken).ConfigureAwait(false);

        if (publish)
        {
            await TryFlushPendingGroupStatesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<int> FlushPendingGroupStatesAsync(CancellationToken cancellationToken = default)
    {
        await groupOutboxGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var published = 0;
            while (true)
            {
                var pending = await groupStatePersistence.ListPendingGroupStatePublishesAsync(
                    GroupStateOutboxLimits.MaxPublishBatch,
                    cancellationToken).ConfigureAwait(false);
                if (pending.Count == 0)
                {
                    return published;
                }

                foreach (var item in pending)
                {
                    await groupSync.PublishGroupStateAsync(
                        item.Group,
                        item.UpdatedAt,
                        item.Recipients,
                        cancellationToken).ConfigureAwait(false);
                    await groupStatePersistence.AcknowledgeGroupStatePublishAsync(
                        item.OperationId,
                        cancellationToken).ConfigureAwait(false);
                    published++;
                }
            }
        }
        finally
        {
            groupOutboxGate.Release();
        }
    }

    private async Task TryFlushPendingGroupStatesAsync(CancellationToken cancellationToken)
    {
        try
        {
            await FlushPendingGroupStatesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // The committed outbox item remains durable and will be retried by the next sync cycle.
        }
    }

    private static string GroupStateOperationId(Group group) =>
        $"group-state:{group.Id.Value}:{group.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture)}";

    private static GroupMember[] EnsureAdminPresence(IReadOnlyList<GroupMember> members, DateTimeOffset now)
    {
        if (members.Count == 0 || members.Any(item => item.Role == GroupMemberRole.Admin))
        {
            return members.ToArray();
        }

        var promoted = members[0] with { Role = GroupMemberRole.Admin, IsPendingRemoval = false, JoinedAt = members[0].JoinedAt == default ? now : members[0].JoinedAt };
        return [promoted, .. members.Skip(1)];
    }

    private static Group WithNextRevision(Group group)
    {
        if (group.Revision < 1)
        {
            throw new InvalidOperationException("A group must have a valid revision before it can be mutated.");
        }

        return group with { Revision = checked(group.Revision + 1) };
    }

    private static bool TryValidateInboundGroupState(
        InboundGroupStateEnvelope update,
        Group? existing,
        SessionId recipient,
        out Group group)
    {
        group = default!;
        var candidate = update.Group;
        if (!HasValidGroupShape(candidate))
        {
            return false;
        }

        var includesRecipient = candidate.Members.Any(member => member.SessionId == recipient);
        if (existing is null)
        {
            if (candidate.Revision != 1
                || update.Sender != candidate.CreatedBy
                || !candidate.HasAdmin(candidate.CreatedBy)
                || !includesRecipient
                || candidate.IsDestroyed)
            {
                return false;
            }

            group = candidate with { IsKicked = false };
            return true;
        }

        if (existing.Revision < 1
            || existing.Revision == long.MaxValue
            || candidate.Revision != existing.Revision + 1
            || candidate.Id != existing.Id
            || candidate.CreatedBy != existing.CreatedBy
            || candidate.CreatedAt != existing.CreatedAt
            || existing.IsDestroyed
            || existing.IsKicked
            || !existing.HasAdmin(update.Sender))
        {
            return false;
        }

        var previouslyIncludedRecipient = existing.Members.Any(member => member.SessionId == recipient);
        if (!previouslyIncludedRecipient)
        {
            return false;
        }

        group = candidate with { IsKicked = !includesRecipient };
        return true;
    }

    private static bool TryResumePersistedInboundGroupState(
        InboundGroupStateEnvelope update,
        Group? existing,
        SessionId recipient,
        out Group group)
    {
        group = default!;
        if (existing is null || !HasValidGroupShape(update.Group) || existing.Revision != update.Group.Revision)
        {
            return false;
        }

        var candidate = update.Group with
        {
            IsKicked = !update.Group.Members.Any(member => member.SessionId == recipient)
        };
        if (candidate.Id != existing.Id
            || !string.Equals(candidate.Name, existing.Name, StringComparison.Ordinal)
            || candidate.CreatedBy != existing.CreatedBy
            || candidate.CreatedAt != existing.CreatedAt
            || candidate.IsDestroyed != existing.IsDestroyed
            || candidate.IsKicked != existing.IsKicked
            || !candidate.Members.SequenceEqual(existing.Members))
        {
            return false;
        }

        group = existing;
        return true;
    }

    private static bool ShouldDeferInboundGroupState(
        InboundGroupStateEnvelope update,
        Group? existing,
        SessionId recipient)
    {
        var candidate = update.Group;
        if (!HasValidGroupShape(candidate))
        {
            return false;
        }

        if (existing is null)
        {
            return candidate.Revision > 1
                && update.Sender == candidate.CreatedBy
                && candidate.HasAdmin(candidate.CreatedBy)
                && candidate.Members.Any(member => member.SessionId == recipient)
                && !candidate.IsDestroyed;
        }

        return existing.Revision is >= 1 and < long.MaxValue
            && candidate.Revision > existing.Revision + 1
            && candidate.Id == existing.Id
            && candidate.CreatedBy == existing.CreatedBy
            && candidate.CreatedAt == existing.CreatedAt
            && !existing.IsDestroyed
            && !existing.IsKicked
            && existing.HasAdmin(update.Sender)
            && existing.Members.Any(member => member.SessionId == recipient);
    }

    private static bool HasValidGroupShape(Group group)
    {
        if (group.Revision < 1
            || string.IsNullOrWhiteSpace(group.Id.Value)
            || string.IsNullOrWhiteSpace(group.Name)
            || string.IsNullOrWhiteSpace(group.CreatedBy.Value)
            || group.Members.Any(member =>
                string.IsNullOrWhiteSpace(member.SessionId.Value)
                || !Enum.IsDefined(member.Role))
            || group.Members.Select(member => member.SessionId).Distinct().Count() != group.Members.Count)
        {
            return false;
        }

        return group.IsDestroyed
            || (group.Members.Count > 0 && group.Members.Any(member => member.Role == GroupMemberRole.Admin));
    }

    private static Task AcknowledgeInboxItemAsync(
        object source,
        SessionId account,
        string serverHash,
        CancellationToken cancellationToken) =>
        source is IDurableInboxAcknowledger acknowledger
            ? acknowledger.AcknowledgeInboxItemAsync(account, serverHash, cancellationToken)
            : Task.CompletedTask;

    private static SessionId[] GroupStateRecipients(Group group) =>
        group.Members
            .Select(member => member.SessionId)
            .Append(group.CreatedBy)
            .Distinct()
            .ToArray();

    internal static string? NormalizeDisplayName(SessionId contactId, string? displayName)
    {
        var trimmed = displayName?.Trim();
        if (string.IsNullOrWhiteSpace(trimmed)
            || string.Equals(trimmed, contactId.Value, StringComparison.Ordinal)
            || (trimmed.Length == 11
                && trimmed.StartsWith("Deep ", StringComparison.Ordinal)
                && trimmed[5..].All(IsHex))
            || (trimmed.Length >= 48 && trimmed.All(static ch =>
                IsHex(ch))))
        {
            return null;
        }

        return trimmed;
    }

    private static bool IsHex(char ch) =>
        ch is >= '0' and <= '9'
        || ch is >= 'a' and <= 'f'
        || ch is >= 'A' and <= 'F';
}
