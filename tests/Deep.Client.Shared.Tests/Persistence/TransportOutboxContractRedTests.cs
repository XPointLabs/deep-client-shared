using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class TransportOutboxContractRedTests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-19T00:00:00Z");

    [Fact]
    public async Task PreparedItemRequiresExplicitRecipientAckBeforeDelivered()
    {
        ITransportOutboxRepository repository = new InMemorySessionStore();
        var prepared = TransportOutboxPreparedItem.Create(
            OutboxAccountScope.FromBytes(Bytes(32, 0x10)),
            OutboxLogicalId.FromBytes(Bytes(16, 0x20)),
            OutboxDedupMaterial.FromBytes(Bytes(32, 0x30)),
            Bytes(128, 0x40),
            Now,
            Now.AddHours(1),
            Now);

        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await repository.PrepareTransportOutboxAsync(prepared));

        var read = await repository.ReadTransportOutboxAsync(
            prepared.AccountScope,
            prepared.LogicalId);
        Assert.Equal(TransportOutboxReadResult.Found, read.Result);
        Assert.Equal(TransportOutboxState.Prepared, read.Item?.State);

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => repository.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Delivered(
                    prepared.AccountScope,
                    prepared.LogicalId,
                    expectedRevision: 1,
                    acknowledgement: null!,
                    OutboxTransitionReason.RecipientAcknowledged,
                    Now.AddMinutes(1))));
    }

    [Fact]
    public void OpaqueIdentifiersDoNotRenderTheirValue()
    {
        var logicalId = OutboxLogicalId.FromBytes(Bytes(16, 0x55));

        Assert.Equal("[opaque-outbox-logical-id]", logicalId.ToString());
        Assert.DoesNotContain("55", logicalId.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void OpaqueIdentifiersAndTransitionReasonsFailClosed()
    {
        Assert.Throws<ArgumentException>(
            () => OutboxLogicalId.FromBytes(new byte[TransportOutboxLimits.LogicalIdBytes]));
        Assert.Throws<ArgumentException>(
            () => TransportOutboxTransition.Durable(
                OutboxAccountScope.FromBytes(Bytes(32, 0x50)),
                OutboxLogicalId.FromBytes(Bytes(16, 0x51)),
                1,
                OutboxAttemptId.FromBytes(Bytes(16, 0x52)),
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.DispatchStarted,
                Now.AddMinutes(1),
                Bytes(16, 0x53)));
    }

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();
}
