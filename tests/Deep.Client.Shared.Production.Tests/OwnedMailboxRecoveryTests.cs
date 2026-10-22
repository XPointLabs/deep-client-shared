using System.Security.Cryptography;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed class OwnedMailboxRecoveryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RouteCeilingDenialReentersOnlyTheOriginalOnceWithFreshUncapturedAuthority(bool repeated)
    {
        var calls = 0; var refreshes = 0; var resumes = 0; var waits = 0;
        var original = new object();
        var seen = new List<object>();
        Task<int> Attempt()
        {
            seen.Add(original); calls++;
            if (calls == 1 || repeated)
            {
                var error = new CryptographicException(); error.Data["Deep.MailboxGrant.Check"] = "RouteExpiry"; throw error;
            }
            Assert.Equal(1, refreshes); return Task.FromResult(7);
        }
        var result = OwnedMailboxRecovery.RunAsync(Attempt,
            () => { refreshes++; return Task.CompletedTask; }, () => resumes++, () => waits++, default);
        if (repeated) await Assert.ThrowsAsync<CryptographicException>(() => result);
        else Assert.Equal(7, await result);
        Assert.Equal(2, calls); Assert.Equal(1, refreshes); Assert.Equal(1, resumes); Assert.Equal(0, waits);
        Assert.All(seen, operation => Assert.Same(original, operation));
    }

    [Theory]
    [InlineData("Signature")]
    [InlineData("Issuer")]
    [InlineData("Generation")]
    [InlineData("Lifetime")]
    [InlineData("unsupported")]
    public async Task OtherGrantDenialsCannotScheduleAuthorityRefresh(string reason)
    {
        var calls = 0;
        var error = new CryptographicException(); error.Data["Deep.MailboxGrant.Check"] = reason;
        var actual = await Assert.ThrowsAsync<CryptographicException>(() => OwnedMailboxRecovery.RunAsync<int>(
            () => { calls++; throw error; }, () => throw new InvalidOperationException(),
            () => throw new InvalidOperationException(), () => throw new InvalidOperationException(), default));
        Assert.Same(error, actual); Assert.Equal(1, calls);
    }

    [Fact]
    public async Task CancellationDuringCeilingRefreshPreventsOriginalReentry()
    {
        using var cancellation = new CancellationTokenSource(); var calls = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => OwnedMailboxRecovery.RunAsync<int>(
            () => { calls++; var error = new CryptographicException(); error.Data["Deep.MailboxGrant.Check"] = "RouteExpiry"; throw error; },
            () => { cancellation.Cancel(); return Task.CompletedTask; }, () => { },
            () => throw new InvalidOperationException(), cancellation.Token));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task DerivedCryptoCannotScheduleCeilingRefresh()
    {
        var error = new DerivedCryptoException(); error.Data["Deep.MailboxGrant.Check"] = "RouteExpiry";
        var actual = await Assert.ThrowsAsync<DerivedCryptoException>(() => OwnedMailboxRecovery.RunAsync<int>(
            () => throw error, () => throw new InvalidOperationException(),
            () => throw new InvalidOperationException(), () => throw new InvalidOperationException(), default));
        Assert.Same(error, actual);
    }

    [Fact]
    public async Task FailedCeilingRefreshCannotReenterTheOriginal()
    {
        var calls = 0;
        await Assert.ThrowsAsync<IOException>(() => OwnedMailboxRecovery.RunAsync<int>(
            () => { calls++; var error = new CryptographicException(); error.Data["Deep.MailboxGrant.Check"] = "RouteExpiry"; throw error; },
            () => throw new IOException(), () => { }, () => throw new InvalidOperationException(), default));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task AlreadyCancelledCeilingDenialIsNotResumed()
    {
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        var error = new CryptographicException(); error.Data["Deep.MailboxGrant.Check"] = "RouteExpiry";
        var actual = await Assert.ThrowsAsync<CryptographicException>(() => OwnedMailboxRecovery.RunAsync<int>(
            () => throw error, () => throw new InvalidOperationException(),
            () => throw new InvalidOperationException(), () => throw new InvalidOperationException(), cancellation.Token));
        Assert.Same(error, actual);
    }

    private sealed class DerivedCryptoException : CryptographicException { }

    [Fact]
    public async Task SuccessDoesNotRefreshOrResume()
    {
        var effects = 0;
        Assert.Equal(7, await OwnedMailboxRecovery.RunAsync(() => Task.FromResult(7),
            () => { effects++; return Task.CompletedTask; }, () => effects++, () => effects++, default));
        Assert.Equal(0, effects);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnknownResumesOnlyTheOriginalAndWaitsForLeaseAtMostOnce(bool leased)
    {
        var calls = 0; var refresh = 0; var resumed = 0; var waits = 0; var delays = 0;
        var value = await OwnedMailboxRecovery.RunAsync(() =>
        {
            calls++;
            if (calls == 1) throw new ClientMailboxDispatchOutcomeUnknownException("Original pending.");
            if (leased && calls == 2) throw new ClientMailboxRetryLeaseException(DateTimeOffset.MaxValue);
            return Task.FromResult(7);
        }, () => { refresh++; return Task.CompletedTask; }, () => resumed++, () => waits++, default,
        (delay, ct) => { Assert.Equal(TimeSpan.FromSeconds(35), delay); ct.ThrowIfCancellationRequested(); delays++; return Task.CompletedTask; });
        Assert.Equal(7, value); Assert.Equal(leased ? 3 : 2, calls);
        Assert.Equal(leased ? 2 : 1, refresh); Assert.Equal(1, resumed);
        Assert.Equal(leased ? 1 : 0, waits); Assert.Equal(waits, delays);
    }

    [Fact]
    public async Task RepeatedUnknownStopsWithoutAnotherResume()
    {
        var calls = 0; var resumes = 0;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => OwnedMailboxRecovery.RunAsync<int>(
            () => { calls++; throw new ClientMailboxDispatchOutcomeUnknownException("Still pending."); },
            () => Task.CompletedTask, () => resumes++, () => throw new InvalidOperationException(), default));
        Assert.Equal(2, calls); Assert.Equal(1, resumes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SecurityOrOrdinaryIoFailureIsNeverRetried(bool security)
    {
        var calls = 0; var refresh = 0;
        var failure = await Record.ExceptionAsync(() => OwnedMailboxRecovery.RunAsync<int>(
            () => { calls++; if (security) throw new CryptographicException(); throw new IOException(); },
            () => { refresh++; return Task.CompletedTask; }, () => refresh++, () => refresh++, default));
        Assert.IsType(security ? typeof(CryptographicException) : typeof(IOException), failure);
        Assert.Equal(1, calls); Assert.Equal(0, refresh);
    }

    [Fact]
    public async Task FailedFreshAuthorityRetainsUnknownAndNeverFallsBack()
    {
        var calls = 0;
        var error = await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => OwnedMailboxRecovery.RunAsync<int>(
            () => { calls++; throw new ClientMailboxDispatchOutcomeUnknownException("Original pending."); },
            () => throw new CryptographicException(), () => { }, () => { }, default));
        Assert.IsType<CryptographicException>(error.InnerException); Assert.Equal(1, calls);
    }

    [Fact]
    public async Task CancellationDuringLeaseWaitPreventsAnotherAttempt()
    {
        using var cancellation = new CancellationTokenSource(); var calls = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => OwnedMailboxRecovery.RunAsync<int>(
            () => { calls++; if (calls == 1) throw new ClientMailboxDispatchOutcomeUnknownException("Pending."); throw new ClientMailboxRetryLeaseException(DateTimeOffset.MaxValue); },
            () => Task.CompletedTask, () => { }, () => { }, cancellation.Token,
            (_, ct) => { cancellation.Cancel(); ct.ThrowIfCancellationRequested(); return Task.CompletedTask; }));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task FreshAttemptSecurityDenialPreservesUnknownWithoutAnotherAttempt()
    {
        var calls = 0;
        var error = await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => OwnedMailboxRecovery.RunAsync<int>(
            () => { calls++; if (calls == 1) throw new ClientMailboxDispatchOutcomeUnknownException("Pending."); throw new CryptographicException(); },
            () => Task.CompletedTask, () => { }, () => throw new InvalidOperationException(), default));
        Assert.IsType<CryptographicException>(error.InnerException); Assert.Equal(2, calls);
    }

    [Fact]
    public async Task AlreadyCancelledUnknownIsNotResumed()
    {
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        var resumes = 0;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => OwnedMailboxRecovery.RunAsync<int>(
            () => throw new ClientMailboxDispatchOutcomeUnknownException("Pending."),
            () => throw new InvalidOperationException(), () => resumes++, () => resumes++, cancellation.Token));
        Assert.Equal(0, resumes);
    }
}
