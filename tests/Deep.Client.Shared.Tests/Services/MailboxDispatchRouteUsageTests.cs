using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class MailboxDispatchRouteUsageTests
{
    [Fact]
    public void DurableUsage_OwnsExactVerifiedRouterId()
    {
        var routerId = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var usage = new MailboxDispatchRouteUsage(
            new MessageId("message-1"),
            ConversationId.ForOneToOne(Recipient),
            Recipient,
            Guid.NewGuid(),
            MailboxDispatchRouteOutcome.Durable,
            routerId);

        routerId[0] ^= 0xff;
        var returned = usage.EntryRouterId.ToArray();
        returned[1] ^= 0xff;

        Assert.Equal(Enumerable.Range(1, 32).Select(static value => (byte)value),
            usage.EntryRouterId.ToArray());
        Assert.True(typeof(MailboxDispatchRouteUsage).IsSealed);
        Assert.False(typeof(MailboxDispatchRouteUsage).IsAssignableTo(typeof(ICloneable)));
    }

    [Theory]
    [InlineData(MailboxDispatchRouteOutcome.Started)]
    [InlineData(MailboxDispatchRouteOutcome.NoDispatch)]
    [InlineData(MailboxDispatchRouteOutcome.Failed)]
    [InlineData(MailboxDispatchRouteOutcome.Canceled)]
    public void NonDurableUsage_CannotClaimStaleRouter(
        MailboxDispatchRouteOutcome outcome)
    {
        Assert.Throws<ArgumentException>(() => new MailboxDispatchRouteUsage(
            new MessageId("message-2"),
            ConversationId.ForOneToOne(Recipient),
            Recipient,
            Guid.NewGuid(),
            outcome,
            new byte[32]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void DurableUsage_RejectsMissingMalformedOrZeroRouter(int length)
    {
        Assert.Throws<ArgumentException>(() => new MailboxDispatchRouteUsage(
            new MessageId("message-3"),
            ConversationId.ForOneToOne(Recipient),
            Recipient,
            Guid.NewGuid(),
            MailboxDispatchRouteOutcome.Durable,
            new byte[length]));
    }

    private static SessionId Recipient { get; } = SessionId.Parse(
        "05b81aeb265f08c347b69f8b39ea28f80074534f858cbe1016a2de4e2dc213e71a");
}
