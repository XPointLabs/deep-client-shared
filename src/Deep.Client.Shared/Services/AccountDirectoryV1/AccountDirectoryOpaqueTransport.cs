namespace Deep.Client.Shared.Services.AccountDirectoryV1;

/// <summary>
/// Carrier-neutral boundary. Implementations exchange only exact canonical XOQ1/XOR1 bytes;
/// this package does not know Registry HTTP endpoints and does not activate a network path.
/// </summary>
public interface IAccountDirectoryOpaqueTransport
{
    ValueTask<ReadOnlyMemory<byte>> ExchangeExactXoq1ForExactXor1Async(
        ReadOnlyMemory<byte> exactXoq1, CancellationToken cancellationToken);
}
