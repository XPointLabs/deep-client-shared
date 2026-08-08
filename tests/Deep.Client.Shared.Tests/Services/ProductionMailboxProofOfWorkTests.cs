using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ProductionMailboxProofOfWorkTests
{
    [Fact]
    public async Task SolverProducesExactCanonicalProofAndIsDeterministic()
    {
        var id = Bytes(10, 16);
        var challenge = Bytes(30, 32);

        var first = await ProductionMailboxProofOfWork.SolveAsync(id, challenge, 12);
        var second = await ProductionMailboxProofOfWork.SolveAsync(id, challenge, 12);

        Assert.Equal(first, second);
        Assert.True(ProductionMailboxProofOfWork.Verify(
            id, challenge, first, 12));
    }

    [Fact]
    public async Task OversizedCostAndCancellationFailBeforeBatteryIntensiveWork()
    {
        var id = Bytes(10, 16);
        var challenge = Bytes(30, 32);
        Assert.Throws<InvalidDataException>(() =>
        {
            _ = ProductionMailboxProofOfWork.SolveAsync(
                id,
                challenge,
                ProductionMailboxProofOfWork.MaximumMobileLeadingZeroBits + 1);
        });

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ProductionMailboxProofOfWork.SolveAsync(
                id,
                challenge,
                ProductionMailboxProofOfWork.MaximumMobileLeadingZeroBits,
                cancellation.Token));
    }

    private static byte[] Bytes(byte seed, int length) =>
        Enumerable.Range(0, length)
            .Select(index => unchecked((byte)(seed + index)))
            .ToArray();
}
