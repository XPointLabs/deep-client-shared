namespace Deep.Client.Shared.Services;

// Retry only an already-owned operation, never queue/create/group action.
// Every attempt re-enters the real protected owner. A RetryLease exception is
// pre-dispatch; waiting is scheduling, not permission to waive that lease.
internal static class OwnedMailboxRecovery
{
    internal static async Task<T> RunAsync<T>(Func<Task<T>> attempt, Func<Task> resetUncaptured,
        Action resumed, Action waiting, CancellationToken ct,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        try { return await attempt().ConfigureAwait(false); }
        catch (ClientMailboxDispatchOutcomeUnknownException) when (!ct.IsCancellationRequested)
        {
            resumed();
            try
            {
                await resetUncaptured().ConfigureAwait(false);
                try { return await attempt().ConfigureAwait(false); }
                catch (ClientMailboxRetryLeaseException) when (!ct.IsCancellationRequested)
                {
                    waiting();
                    // The unchanged dispatch contract leases30s plus5s. The
                    // next owner still independently checks authenticated time.
                    await (delay ?? Task.Delay)(TimeSpan.FromSeconds(35), ct).ConfigureAwait(false);
                    await resetUncaptured().ConfigureAwait(false);
                    return await attempt().ConfigureAwait(false);
                }
            }
            catch (ClientMailboxDispatchOutcomeUnknownException) { throw; }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) when (error is IOException or System.Security.Cryptography.CryptographicException or
                InvalidOperationException or ArgumentException or Deep.Protocol.DeepExtension.PrivacyRouting.OnionBoundaryException)
            {
                throw new ClientMailboxDispatchOutcomeUnknownException(
                    "Owned mailbox recovery could not complete; original custody remains pending.", error);
            }
        }
    }
}
