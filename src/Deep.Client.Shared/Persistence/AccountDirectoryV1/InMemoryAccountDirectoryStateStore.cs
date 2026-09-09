using Deep.Client.Shared.Domain.AccountDirectoryV1;

namespace Deep.Client.Shared.Persistence.AccountDirectoryV1;

public sealed class InMemoryAccountDirectoryStateStore : IAccountDirectoryStateStore
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private AccountDirectoryStateSnapshot? snapshot;

    public async ValueTask<AccountDirectoryStateSnapshot?> ReadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return AccountDirectoryStateCloner.Clone(snapshot); }
        finally { gate.Release(); }
    }

    public async ValueTask<AccountDirectoryStoreWriteResult> CompareExchangeAsync(ulong? expectedRevision,
        AccountDirectoryStateSnapshot replacement, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var currentRevision = snapshot?.Revision;
            if (currentRevision != expectedRevision)
                return new(AccountDirectoryStoreWriteDisposition.Conflict, AccountDirectoryStateCloner.Clone(snapshot));
            var required = expectedRevision is null ? 1UL : checked(expectedRevision.Value + 1);
            if (replacement.Revision != required)
                throw new InvalidOperationException("Replacement revision must be the next CAS revision.");
            snapshot = AccountDirectoryStateCloner.Clone(replacement);
            return new(AccountDirectoryStoreWriteDisposition.Applied, AccountDirectoryStateCloner.Clone(snapshot));
        }
        finally { gate.Release(); }
    }
}
