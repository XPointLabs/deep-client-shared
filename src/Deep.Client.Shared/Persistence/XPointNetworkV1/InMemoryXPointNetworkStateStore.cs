namespace Deep.Client.Shared.Persistence.XPointNetworkV1;

public sealed class InMemoryXPointNetworkStateStore : IXPointNetworkStateStore
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private XPointNetworkStateSnapshot? snapshot;

    public async ValueTask<XPointNetworkStateSnapshot?> ReadAsync(
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return XPointNetworkStateCloner.Clone(snapshot);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<XPointNetworkStoreWriteResult> CompareExchangeAsync(
        ulong? expectedRevision,
        XPointNetworkStateSnapshot replacement,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (snapshot?.Revision != expectedRevision)
                return new(
                    XPointNetworkStoreWriteDisposition.Conflict,
                    XPointNetworkStateCloner.Clone(snapshot));
            var requiredRevision = expectedRevision is null
                ? 1UL
                : checked(expectedRevision.Value + 1);
            if (replacement.Revision != requiredRevision)
                throw new InvalidOperationException(
                    "Replacement revision must be the next XPoint network CAS revision.");
            if (snapshot?.ForkLatched == true && !replacement.ForkLatched)
                throw new InvalidOperationException(
                    "A protected XPoint network fork latch cannot be cleared.");
            snapshot = XPointNetworkStateCloner.Clone(replacement);
            return new(
                XPointNetworkStoreWriteDisposition.Applied,
                XPointNetworkStateCloner.Clone(snapshot));
        }
        finally
        {
            gate.Release();
        }
    }
}
