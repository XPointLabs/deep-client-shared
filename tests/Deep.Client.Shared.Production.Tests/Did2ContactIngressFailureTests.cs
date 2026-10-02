using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2ContactIngressFailureTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ExactIngressRejectionPreservesCertaintyWithoutRetry(bool retryable)
    {
        var cause = new PrivacyIngressRejectedBeforeForwardException(retryable, "private endpoint");
        using var transport = new OneAttempt(cause);
        var result = await Assert.ThrowsAsync<ClientMailboxTransportException>(() =>
            DeepIdV2PublicationOnionTransport.ForwardOnceAsync(transport, new byte[] { 1 }, default));
        Assert.Equal(ClientMailboxTransportFailure.DependencyUnavailable, result.Failure);
        Assert.Equal(retryable, result.Retryable);
        Assert.Same(cause, result.InnerException);
        Assert.DoesNotContain("private", result.Message);
        Assert.Equal(1, transport.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GenericOrUnknownCompletionCannotBecomeBeforeForward(bool unknown)
    {
        IOException cause = unknown ? new ClientMailboxDispatchOutcomeUnknownException("private") : new IOException("private");
        using var transport = new OneAttempt(cause);
        var result = await Assert.ThrowsAsync(cause.GetType(), () =>
            DeepIdV2PublicationOnionTransport.ForwardOnceAsync(transport, new byte[] { 1 }, default));
        Assert.Same(cause, result);
        Assert.Equal(1, transport.Calls);
    }

    private sealed class OneAttempt(Exception cause) : IPrivacyManagedIngressTransport
    {
        internal int Calls { get; private set; }
        public Task<ReadOnlyMemory<byte>> ForwardAsync(ReadOnlyMemory<byte> frame, CancellationToken ct)
        { Calls++; return Task.FromException<ReadOnlyMemory<byte>>(cause); }
        public void Dispose() { }
    }
}
