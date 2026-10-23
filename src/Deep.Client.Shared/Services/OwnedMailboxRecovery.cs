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
        catch (System.Security.Cryptography.CryptographicException error) when (!ct.IsCancellationRequested &&
            error.GetType() == typeof(System.Security.Cryptography.CryptographicException) &&
            error.Data["Deep.MailboxGrant.Check"] is "RouteExpiry")
        {
            // A current signed closure may have a tighter ceiling than the
            // issuer's independently acquired closure. This denial is ONLY a
            // scheduling hint, not proof of a valid grant/signature or absence
            // of effects. Discard uncaptured public memo state, then re-enter
            // the SAME owned operation once with fresh independent evidence.
            // All strict result/route/expiry and captured-original guards run
            // again. A repeated denial propagates; no recursive retry/remint.
            resumed();
            await resetUncaptured().ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            return await attempt().ConfigureAwait(false);
        }
        catch (ClientMailboxDispatchOutcomeUnknownException) when (!ct.IsCancellationRequested)
        {
            resumed();
            try
            {
                await resetUncaptured().ConfigureAwait(false);
                try { return await attempt().ConfigureAwait(false); }
                catch (ClientMailboxRetryLeaseException lease) when (!ct.IsCancellationRequested)
                {
                    waiting();
                    // Wait only the adapter's remaining denial interval, bounded
                    // by the unchanged30s+5s contract, not another full35s after
                    // expensive recovery preparation. The next actual owner
                    // independently checks authenticated time and native custody.
                    await (delay ?? Task.Delay)(lease.SchedulingDelay, ct).ConfigureAwait(false);
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
