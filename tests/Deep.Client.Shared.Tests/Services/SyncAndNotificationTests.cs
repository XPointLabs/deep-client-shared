using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class SyncAndNotificationTests
{
    [Fact]
    public void GroupSyncPlanRequestsKeysLast()
    {
        var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
        var conversation = new Conversation(
            ConversationId.CreateGroupV2(),
            ConversationKind.GroupV2,
            "Group",
            ConversationSettings.Default(ConversationKind.GroupV2),
            now,
            now);

        var plan = new SyncOrchestrator().CreateConversationPlan(conversation);

        Assert.Equal("ClosedGroupKeys", plan.Namespaces.Last().Name);
    }

    [Fact]
    public void MutedConversationDoesNotCreateNotification()
    {
        var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
        var sender = SessionId.CreateNew();
        var conversation = new Conversation(
            ConversationId.ForOneToOne(sender),
            ConversationKind.OneToOne,
            "Alice",
            ConversationSettings.Default(ConversationKind.OneToOne) with { IsMuted = true },
            now,
            now);
        var message = new Message(MessageId.NewId(), conversation.Id, sender, SessionId.CreateNew(), "quiet", MessageDirection.Incoming, MessageDeliveryState.Delivered, now, []);

        var request = new NotificationPlanner().PlanIncomingMessage(
            conversation,
            message,
            new NotificationPreferences(ShowPreviews: true, PlaySound: true, ShowNotifications: true));

        Assert.Null(request);
    }
}
