using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

internal sealed class AccountGenerationMutationBarrier : IAccountGenerationLifecycle, IDisposable
{
    private readonly object gate = new();
    private CancellationTokenSource generationCancellation = new();
    private TaskCompletionSource? quiesced;
    private SessionId? account;
    private int activeMutations;
    private bool acceptingMutations = true;
    private bool disposed;

    public MutationLease Enter(CancellationToken cancellationToken = default)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!acceptingMutations)
            {
                throw new OperationCanceledException("The active account generation no longer accepts mutations.");
            }

            activeMutations++;
            return new MutationLease(this, generationCancellation.Token, cancellationToken);
        }
    }

    public async Task StopAsync(SessionId stoppedAccount, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CancellationTokenSource cancellation;
        Task waitForQuiescence;
        lock (gate)
        {
            if (!acceptingMutations || (account is not null && account != stoppedAccount))
            {
                return;
            }

            account ??= stoppedAccount;
            acceptingMutations = false;
            cancellation = generationCancellation;
            quiesced = activeMutations == 0
                ? null
                : new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            waitForQuiescence = quiesced?.Task ?? Task.CompletedTask;
        }

        cancellation.Cancel();
        await waitForQuiescence.ConfigureAwait(false);
    }

    public void Resume(SessionId resumedAccount)
    {
        CancellationTokenSource? previous = null;
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (acceptingMutations)
            {
                if (account is null)
                {
                    account = resumedAccount;
                    return;
                }

                if (account == resumedAccount)
                {
                    return;
                }

                throw new InvalidOperationException(
                    "A different account generation cannot resume before the active generation stops.");
            }

            if (activeMutations != 0)
            {
                throw new InvalidOperationException("An account generation cannot resume before its mutations quiesce.");
            }

            previous = generationCancellation;
            generationCancellation = new CancellationTokenSource();
            account = resumedAccount;
            acceptingMutations = true;
            quiesced = null;
        }

        previous.Dispose();
    }

    private void Exit()
    {
        TaskCompletionSource? completion = null;
        lock (gate)
        {
            activeMutations--;
            if (activeMutations == 0 && !acceptingMutations)
            {
                completion = quiesced;
                quiesced = null;
            }
        }

        completion?.TrySetResult();
    }

    public void Dispose()
    {
        CancellationTokenSource cancellation;
        lock (gate)
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            acceptingMutations = false;
            cancellation = generationCancellation;
        }

        cancellation.Cancel();
        cancellation.Dispose();
    }

    internal sealed class MutationLease : IDisposable
    {
        private readonly AccountGenerationMutationBarrier owner;
        private readonly CancellationTokenSource linkedCancellation;
        private int disposed;

        public MutationLease(
            AccountGenerationMutationBarrier owner,
            CancellationToken generationCancellation,
            CancellationToken callerCancellation)
        {
            this.owner = owner;
            linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                generationCancellation,
                callerCancellation);
        }

        public CancellationToken CancellationToken => linkedCancellation.Token;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }

            linkedCancellation.Dispose();
            owner.Exit();
        }
    }
}

internal sealed class CompositeAccountGenerationLifecycle(
    params IReadOnlyList<IAccountGenerationLifecycle> lifecycles) : IAccountGenerationLifecycle
{
    public async Task StopAsync(SessionId account, CancellationToken cancellationToken = default)
    {
        var stopped = new List<IAccountGenerationLifecycle>(lifecycles.Count);
        try
        {
            foreach (var lifecycle in lifecycles)
            {
                await lifecycle.StopAsync(account, cancellationToken).ConfigureAwait(false);
                stopped.Add(lifecycle);
            }
        }
        catch
        {
            for (var index = stopped.Count - 1; index >= 0; index--)
            {
                stopped[index].Resume(account);
            }

            throw;
        }
    }

    public void Resume(SessionId account)
    {
        foreach (var lifecycle in lifecycles)
        {
            lifecycle.Resume(account);
        }
    }
}
