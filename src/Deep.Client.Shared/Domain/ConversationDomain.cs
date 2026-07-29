namespace Deep.Client.Shared.Domain;

public enum ConversationKind
{
    OneToOne = 0,
    GroupV2 = 1,
    Community = 3
}

public enum MessageDirection
{
    Incoming,
    Outgoing
}

public enum MessageDeliveryState
{
    Draft,
    Sending,
    Sent,
    Delivered,
    Read,
    Failed
}

public enum DisappearingMode
{
    Disabled,
    DeleteAfterRead,
    DeleteAfterSend
}

public enum GroupMemberRole
{
    Standard,
    Admin
}

public sealed record ReadReceiptSettings(bool SendReadReceipts, bool ShowReadReceipts)
{
    public static ReadReceiptSettings Default { get; } = new(SendReadReceipts: false, ShowReadReceipts: true);
}

public sealed record DisappearingMessageSettings(DisappearingMode Mode, TimeSpan? Duration)
{
    public static DisappearingMessageSettings Disabled { get; } = new(DisappearingMode.Disabled, null);

    public static DisappearingMessageSettings Create(ConversationKind kind, DisappearingMode mode, TimeSpan? duration)
    {
        if (kind == ConversationKind.Community)
        {
            return Disabled;
        }

        if (kind == ConversationKind.GroupV2 && mode == DisappearingMode.DeleteAfterRead)
        {
            mode = DisappearingMode.DeleteAfterSend;
        }

        if (mode == DisappearingMode.Disabled)
        {
            return Disabled;
        }

        if (duration is null || duration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(duration), "Disappearing messages require a positive duration.");
        }

        return new DisappearingMessageSettings(mode, duration);
    }
}

public sealed record ConversationSettings(
    DisappearingMessageSettings DisappearingMessages,
    ReadReceiptSettings ReadReceipts,
    bool IsMuted,
    bool IsPinned)
{
    public static ConversationSettings Default(ConversationKind kind) =>
        new(DisappearingMessageSettings.Create(kind, DisappearingMode.Disabled, null), ReadReceiptSettings.Default, IsMuted: false, IsPinned: false);
}

public sealed record Conversation(
    ConversationId Id,
    ConversationKind Kind,
    string DisplayName,
    ConversationSettings Settings,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    bool IsHidden = false)
{
    public bool SupportsDisappearingMessages => Kind is ConversationKind.OneToOne or ConversationKind.GroupV2;

    public bool SupportsReadReceipts => Kind == ConversationKind.OneToOne;

    public Conversation Touch(DateTimeOffset now) => this with { UpdatedAt = now };
}

public sealed record ConversationSummary(
    Conversation Conversation,
    Message? LastMessage,
    int UnreadCount);
