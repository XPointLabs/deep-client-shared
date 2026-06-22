using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record NotificationPreferences(
    bool ShowPreviews,
    bool PlaySound,
    bool ShowNotifications);

public sealed record NotificationRequest(
    string Identifier,
    ConversationId ConversationId,
    string Title,
    string Body,
    bool PlaySound);

public interface INotificationScheduler
{
    Task ScheduleAsync(NotificationRequest request, CancellationToken cancellationToken = default);

    Task ClearConversationAsync(ConversationId conversationId, CancellationToken cancellationToken = default);
}

public sealed class NotificationPlanner
{
    public NotificationRequest? PlanIncomingMessage(
        Conversation conversation,
        Message message,
        NotificationPreferences preferences)
    {
        if (!preferences.ShowNotifications || conversation.Settings.IsMuted)
        {
            return null;
        }

        var body = preferences.ShowPreviews
            ? string.IsNullOrWhiteSpace(message.Body) && message.HasAttachments ? "Attachment" : message.Body
            : "New message";

        return new NotificationRequest(
            message.Id.Value,
            conversation.Id,
            conversation.DisplayName,
            body,
            preferences.PlaySound);
    }
}
