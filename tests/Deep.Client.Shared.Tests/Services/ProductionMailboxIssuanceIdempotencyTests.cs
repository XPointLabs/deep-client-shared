using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ProductionMailboxIssuanceIdempotencyTests
{
    [Fact]
    public void LocalOwner_ExactVector_IsStable()
    {
        var actual = ProductionMailboxIssuanceIdempotency.Compute(
            Bytes(1), Bytes(2), Bytes(3), Bytes(4), Bytes(5),
            new byte[32], new byte[32], new byte[32],
            ProductionMailboxIssuanceIntent.LocalOwner,
            ProductionMailboxClientPlatform.Android,
            Bytes(6), Bytes(7), new byte[32]);

        Assert.Equal(
            "d707e99b4f0bc54d3769e3d4fb5f7803a84757dd532167f072f328c6f5486cf2",
            Convert.ToHexStringLower(actual));
    }

    [Fact]
    public void IntentAndRouteShape_AreFailClosed()
    {
        Assert.Throws<ArgumentException>(() =>
            ProductionMailboxIssuanceIdempotency.Compute(
                Bytes(1), Bytes(2), Bytes(3), Bytes(4), Bytes(5),
                Bytes(8), new byte[32], Bytes(9),
                ProductionMailboxIssuanceIntent.PeerDeposit,
                ProductionMailboxClientPlatform.Windows,
                Bytes(6), Bytes(7), new byte[32]));
        Assert.Throws<ArgumentException>(() =>
            ProductionMailboxIssuanceIdempotency.Compute(
                Bytes(1), Bytes(2), Bytes(3), Bytes(4), Bytes(5),
                Bytes(8), Bytes(9), Bytes(10),
                ProductionMailboxIssuanceIntent.LocalOwner,
                ProductionMailboxClientPlatform.Windows,
                Bytes(6), Bytes(7), new byte[32]));
    }

    private static byte[] Bytes(byte value) =>
        Enumerable.Repeat(value, 32).ToArray();
}
