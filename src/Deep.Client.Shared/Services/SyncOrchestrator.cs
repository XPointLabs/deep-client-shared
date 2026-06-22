using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record SyncNamespace(
    int Id,
    string Name,
    int Priority,
    TimeSpan Ttl,
    int Order);

public sealed record SyncPlan(
    ConversationId? ConversationId,
    IReadOnlyList<SyncNamespace> Namespaces);

public interface ISyncCursorStore
{
    Task<string?> GetLastHashAsync(ConversationId? conversationId, int namespaceId, CancellationToken cancellationToken = default);

    Task SetLastHashAsync(ConversationId? conversationId, int namespaceId, string hash, CancellationToken cancellationToken = default);
}

public sealed class SyncOrchestrator
{
    public SyncPlan CreateUserConfigPlan() => new(
        null,
        Sort([
            new SyncNamespace(2, "UserConfig", 1, TimeSpan.FromDays(30), 10),
            new SyncNamespace(3, "UserContacts", 1, TimeSpan.FromDays(30), 20),
            new SyncNamespace(5, "UserGroups", 1, TimeSpan.FromDays(30), 30),
            new SyncNamespace(4, "ConvoInfoVolatile", 1, TimeSpan.FromDays(14), 40)
        ]));

    public SyncPlan CreateConversationPlan(Conversation conversation) =>
        conversation.Kind switch
        {
            ConversationKind.OneToOne => new SyncPlan(conversation.Id, Sort([
                new SyncNamespace(0, "DefaultMessages", 10, TimeSpan.FromDays(14), 10)
            ])),
            ConversationKind.GroupV2 => new SyncPlan(conversation.Id, Sort([
                new SyncNamespace(-11, "ClosedGroupRevokedRetrievableMessages", 10, TimeSpan.FromDays(14), 5),
                new SyncNamespace(11, "ClosedGroupMessages", 10, TimeSpan.FromDays(14), 10),
                new SyncNamespace(13, "ClosedGroupInfo", 1, TimeSpan.FromDays(30), 20),
                new SyncNamespace(14, "ClosedGroupMembers", 1, TimeSpan.FromDays(30), 30),
                new SyncNamespace(12, "ClosedGroupKeys", 1, TimeSpan.FromDays(30), 999)
            ])),
            ConversationKind.Community => new SyncPlan(conversation.Id, Sort([
                new SyncNamespace(0, "CommunityMessages", 10, TimeSpan.FromDays(14), 10)
            ])),
            _ => new SyncPlan(conversation.Id, [])
        };

    private static IReadOnlyList<SyncNamespace> Sort(IEnumerable<SyncNamespace> namespaces) =>
        namespaces.OrderBy(item => item.Order).ToArray();
}
