using Deep.Client.Shared.Domain.MessagingV1;

namespace Deep.Client.Shared.Tests.MessagingV1;

public sealed class MessagingBinaryValueTests
{
    [Fact]
    public void ValuesRejectWrongLengthAndZero()
    {
        Assert.Throws<ArgumentException>(() => SemanticMessageId32.FromBytes(new byte[31]));
        Assert.Throws<ArgumentException>(() => ConversationId32.FromBytes(new byte[32]));
        Assert.Throws<ArgumentException>(() => MessagingAccountId32.FromBytes(new byte[32]));
        Assert.Throws<ArgumentException>(() => MessagingDeviceId32.FromBytes(new byte[32]));
        Assert.Throws<ArgumentException>(() => TransportAttemptId16.FromBytes(new byte[16]));
        Assert.Throws<ArgumentException>(() => MessageEventHash32.FromBytes(new byte[32]));
        Assert.Throws<ArgumentException>(() => MessageMutationId32.FromBytes(new byte[32]));
        Assert.Throws<ArgumentException>(() => MessageStoreInstanceId32.FromBytes(new byte[32]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MessageStoreScope(
            MessagingV1Fixture.Account(), 0, MessageStoreInstanceId32.FromBytes(MessagingV1Fixture.Bytes(32, 1))));
    }

    [Fact]
    public void ValuesOwnInputsAndOutputsAndAreRedacted()
    {
        var input = MessagingV1Fixture.Bytes(32, 7);
        var value = SemanticMessageId32.FromBytes(input);
        input[0] = 99;
        var output = value.ToArray();
        output[0] = 88;

        Assert.Equal(7, value.ToArray()[0]);
        Assert.DoesNotContain(Convert.ToHexString(value.ToArray()), value.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void EqualityHashAndCrossTypeAreCanonical()
    {
        var bytes = MessagingV1Fixture.Bytes(32, 71);
        var first = SemanticMessageId32.FromBytes(bytes);
        var second = SemanticMessageId32.FromBytes(bytes);
        var differentKind = ConversationId32.FromBytes(bytes);

        Assert.Equal(first, second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
        Assert.False(first.Equals(differentKind));
        Assert.Throws<ArgumentException>(() => first.CompareTo(differentKind));
    }

    [Fact]
    public void SeedCanonicalizesTimeAndBoundsLifetime()
    {
        var withTicks = MessagingV1Fixture.CreatedAt.AddTicks(42);
        var seed = LogicalOutboxSeed.CreateOutbound(
            MessagingV1Fixture.Scope(), MessagingV1Fixture.Device(), MessagingV1Fixture.Conversation(),
            MessagingV1Fixture.Semantic(), MessagingV1Fixture.EventHash(),
            MessagingV1Fixture.Payload(), withTicks, withTicks.AddDays(1));

        Assert.Equal(0, seed.CreatedAt.Ticks % TimeSpan.TicksPerMillisecond);
        Assert.Throws<ArgumentOutOfRangeException>(() => LogicalOutboxSeed.CreateOutbound(
            MessagingV1Fixture.Scope(), MessagingV1Fixture.Device(), MessagingV1Fixture.Conversation(),
            MessagingV1Fixture.Semantic(), MessagingV1Fixture.EventHash(),
            MessagingV1Fixture.Payload(), withTicks, withTicks.AddDays(366)));
    }
}
