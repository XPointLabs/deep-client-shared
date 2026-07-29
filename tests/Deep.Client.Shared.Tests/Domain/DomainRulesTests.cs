using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Tests.Domain;

public sealed class DomainRulesTests
{
    [Fact]
    public void ConversationKindKeepsSupportedWireValuesAndLeavesLegacyValueInvalid()
    {
        Assert.Equal(0, (int)ConversationKind.OneToOne);
        Assert.Equal(1, (int)ConversationKind.GroupV2);
        Assert.Equal(3, (int)ConversationKind.Community);
        Assert.False(Enum.IsDefined((ConversationKind)2));
    }

    [Fact]
    public void GroupV2DisappearingMessagesForceDeleteAfterSend()
    {
        var settings = DisappearingMessageSettings.Create(
            ConversationKind.GroupV2,
            DisappearingMode.DeleteAfterRead,
            TimeSpan.FromHours(1));

        Assert.Equal(DisappearingMode.DeleteAfterSend, settings.Mode);
    }

    [Fact]
    public void CommunitiesDoNotEnableDisappearingMessages()
    {
        var settings = DisappearingMessageSettings.Create(
            ConversationKind.Community,
            DisappearingMode.DeleteAfterSend,
            TimeSpan.FromHours(1));

        Assert.Equal(DisappearingMode.Disabled, settings.Mode);
        Assert.Null(settings.Duration);
    }

    [Fact]
    public void NewSessionIdsUseSessionAccountPrefix()
    {
        var sessionId = SessionId.CreateNew();

        Assert.StartsWith("05", sessionId.Value);
        Assert.Equal(66, sessionId.Value.Length);
    }
}
