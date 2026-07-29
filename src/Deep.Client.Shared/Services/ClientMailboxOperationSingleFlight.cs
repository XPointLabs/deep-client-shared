using System.Collections.Concurrent;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

internal static class ClientMailboxOperationSingleFlight
{
    private static readonly ConcurrentDictionary<string, Entry> Entries =
        new(StringComparer.Ordinal);

    public static async ValueTask<IAsyncDisposable> EnterAsync(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(logicalId);
        cancellationToken.ThrowIfCancellationRequested();
        var key = string.Concat(
            Convert.ToHexString(accountScope.Value),
            Convert.ToHexString(logicalId.Value));

        while (true)
        {
            var entry = Entries.GetOrAdd(key, static _ => new Entry());
            lock (entry.Sync)
            {
                if (entry.Retired)
                {
                    continue;
                }

                checked
                {
                    entry.References++;
                }
            }

            try
            {
                await entry.Gate.WaitAsync(cancellationToken)
                    .ConfigureAwait(false);
                return new Lease(key, entry);
            }
            catch
            {
                ReleaseReference(key, entry);
                throw;
            }
        }
    }

    private static void ReleaseReference(string key, Entry entry)
    {
        var dispose = false;
        lock (entry.Sync)
        {
            entry.References--;
            if (entry.References == 0)
            {
                entry.Retired = true;
                if (Entries.TryGetValue(key, out var current) &&
                    ReferenceEquals(current, entry))
                {
                    _ = Entries.TryRemove(key, out _);
                }
                dispose = true;
            }
        }

        if (dispose)
        {
            entry.Gate.Dispose();
        }
    }

    private sealed class Entry
    {
        public object Sync { get; } = new();
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public int References { get; set; }
        public bool Retired { get; set; }
    }

    private sealed class Lease(string key, Entry entry) : IAsyncDisposable
    {
        private int disposed;

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
            {
                entry.Gate.Release();
                ReleaseReference(key, entry);
            }

            return ValueTask.CompletedTask;
        }
    }
}
