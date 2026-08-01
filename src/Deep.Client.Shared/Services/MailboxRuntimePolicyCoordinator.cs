using System.Collections.Concurrent;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Process-wide publication/dispatch barrier keyed by canonical SQLite state and stable
/// mailbox authority.  Cross-process dispatch additionally reloads the committed SQLite
/// checkpoint before I/O and after the response; the node independently validates grants.
/// </summary>
internal interface IMailboxRuntimePolicyLease : IDisposable, IAsyncDisposable
{
}

internal sealed class MailboxRuntimeCommitActivation
{
    private readonly SqliteMailboxRevocationSource revocations;
    private readonly IMailboxRuntimePolicyLease publicationLease;
    private int activated;

    internal MailboxRuntimeCommitActivation(
        SqliteMailboxRevocationSource revocations,
        IMailboxRuntimePolicyLease publicationLease)
    {
        this.revocations = revocations ?? throw new ArgumentNullException(
            nameof(revocations));
        this.publicationLease = publicationLease ?? throw new ArgumentNullException(
            nameof(publicationLease));
    }

    internal void ActivateCommittedNoThrow()
    {
        if (Interlocked.Exchange(ref activated, 1) != 0) return;
        revocations.ActivateCommittedNoThrow();
        publicationLease.Dispose();
    }
}

internal sealed class MailboxRuntimePolicyCoordinator
{
    private static readonly ConcurrentDictionary<string, MailboxRuntimePolicyCoordinator>
        Coordinators = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim turnstile = new(1, 1);
    private readonly SemaphoreSlim readerMutex = new(1, 1);
    private readonly SemaphoreSlim resource = new(1, 1);
    private readonly string? registryKey;
    private int readers;

    private MailboxRuntimePolicyCoordinator(string? registryKey)
    {
        this.registryKey = registryKey;
    }

    internal static MailboxRuntimePolicyCoordinator For(
        string canonicalStateIdentity,
        ReadOnlySpan<byte> stableAuthorityId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalStateIdentity);
        if (stableAuthorityId.Length != 32 ||
            stableAuthorityId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Stable mailbox authority ID is invalid.",
                nameof(stableAuthorityId));
        var key = canonicalStateIdentity + ":" +
            Convert.ToHexString(stableAuthorityId);
        return Coordinators.GetOrAdd(key, static value => new(value));
    }

    internal static MailboxRuntimePolicyCoordinator Detached() => new(null);

    internal bool IsShared => registryKey is not null;

    internal bool Matches(string canonicalStateIdentity, ReadOnlySpan<byte> stableAuthorityId) =>
        IsShared && ReferenceEquals(this, For(canonicalStateIdentity, stableAuthorityId));

    public async ValueTask<IAsyncDisposable> AcquireDispatchAsync(
        CancellationToken cancellationToken = default)
    {
        await turnstile.WaitAsync(cancellationToken).ConfigureAwait(false);
        turnstile.Release();
        await readerMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (++readers == 1)
            {
                try
                {
                    await resource.WaitAsync(cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    readers--;
                    throw;
                }
            }
        }
        finally
        {
            readerMutex.Release();
        }
        return new PolicyLease(this, writer: false);
    }

    internal async ValueTask<IMailboxRuntimePolicyLease> AcquirePublicationAsync(
        CancellationToken cancellationToken = default)
    {
        await turnstile.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await resource.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            turnstile.Release();
            throw;
        }
        return new PolicyLease(this, writer: true);
    }

    private void ReleaseReader()
    {
        readerMutex.Wait();
        try
        {
            if (--readers == 0) resource.Release();
        }
        finally
        {
            readerMutex.Release();
        }
    }

    private sealed class PolicyLease(
        MailboxRuntimePolicyCoordinator owner,
        bool writer) : IMailboxRuntimePolicyLease
    {
        private int disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            if (writer)
            {
                owner.resource.Release();
                owner.turnstile.Release();
            }
            else
            {
                owner.ReleaseReader();
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
