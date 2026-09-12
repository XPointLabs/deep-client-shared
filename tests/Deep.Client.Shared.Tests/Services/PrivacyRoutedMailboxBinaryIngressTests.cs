using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Tests.Services;

public sealed class PrivacyRoutedMailboxBinaryIngressTests
{
    [Theory]
    [InlineData("http://entry.example/")]
    [InlineData("https://entry.example/path")]
    [InlineData("https://user@entry.example/")]
    public void RouteRejectsNonCanonicalProductionOrigin(string value)
    {
        Assert.Throws<ArgumentException>(() =>
            new PrivacyMailboxRoute(new Uri(value), new NeverPathProvider()));
    }

    [Fact]
    public void RouteAcceptsExplicitLoopbackCarrierAndBindsRouterIdentity()
    {
        var routerId = Enumerable.Repeat((byte)0x41, 32).ToArray();

        var route = new PrivacyMailboxRoute(
            new Uri("http://127.0.0.1:17891/"),
            new NeverPathProvider(),
            routerId);

        Assert.Equal("http://127.0.0.1:17891/", route.EntryOrigin.AbsoluteUri);
        Assert.Equal(routerId, route.ExpectedEntryRouterId.ToArray());
    }

    [Fact]
    public async Task MalformedMau2FailsBeforePathSelectionOrNetworkDispatch()
    {
        var provider = new NeverPathProvider();
        var transport = new NeverForwardTransport();
        var primary = new PrivacyMailboxRoute(new Uri("https://primary.example/"), provider);
        var fallback = new PrivacyMailboxRoute(new Uri("https://fallback.example/"), provider);
        using var ingress = new PrivacyRoutedMailboxBinaryIngress(
            primary,
            fallback,
            new NeverDecodePolicyProvider(),
            Codec(),
            transport,
            transport);

        var error = await Assert.ThrowsAsync<ClientMailboxTransportException>(() =>
            ingress.RetrieveAsync(ReadOnlyMemory<byte>.Empty));

        Assert.Equal(ClientMailboxTransportFailure.MalformedRequest, error.Failure);
        Assert.Equal(0, provider.CallCount);
        Assert.Equal(0, transport.CallCount);
    }

    [Fact]
    public async Task MalformedXiq1FailsBeforePathSelectionOrNetworkDispatch()
    {
        var provider = new NeverPathProvider();
        var transport = new NeverForwardTransport();
        var primary = new PrivacyMailboxRoute(new Uri("https://primary.example/"), provider);
        var fallback = new PrivacyMailboxRoute(new Uri("https://fallback.example/"), provider);
        using var resolver = new PrivacyRoutedContactResolverTransport(
            primary,
            fallback,
            Codec(),
            transport,
            transport);
        var request = new ContactResolverTransportRequest(
            "not-an-xiq1"u8,
            new ContactResolverTransportAttemptId32(Enumerable.Repeat((byte)0x5a, 32).ToArray()));

        var error = await Assert.ThrowsAsync<ContactResolverTransportException>(async () =>
            await resolver.SendXiq1Async(request));

        Assert.Equal(ContactResolverTransportFailureKind.Permanent, error.Failure);
        Assert.Equal(0, provider.CallCount);
        Assert.Equal(0, transport.CallCount);
    }

    private static PrivacyRoutingCodec Codec() => new(
        new OnionEntropyAuthority(new NeverEntropyLedger()),
        new OnionKeyAgreementAuthority(new NeverKeyVault()));

    private sealed class NeverPathProvider : IPrivacyMailboxPathProvider
    {
        public int CallCount { get; private set; }

        public ValueTask<PrivacyMailboxOnionAttempt> PrepareAsync(
            OnionOperation operation,
            ReadOnlyMemory<byte> exactCanonicalRequest,
            CancellationToken cancellationToken)
        {
            CallCount++;
            throw new InvalidOperationException("Malformed MAU2 must fail before path selection.");
        }
    }

    private sealed class NeverForwardTransport : IPrivacyManagedIngressTransport
    {
        public int CallCount { get; private set; }

        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> frame,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            throw new InvalidOperationException("Malformed MAU2 must fail before dispatch.");
        }

        public void Dispose()
        {
        }
    }

    private sealed class NeverEntropyLedger : IOnionEntropyUniquenessLedger
    {
        public ValueTask<OnionEntropyCommitOutcome> CommitAsync(
            OnionEntropyCommitmentBatch batch,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Malformed MAU2 must not consume entropy.");
    }

    private sealed class NeverKeyVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(
            OnionKeyHandle keyHandle,
            ReadOnlyMemory<byte> peerPublicKey,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Malformed MAU2 must not access private keys.");
    }

    private sealed class NeverDecodePolicyProvider : IMailboxClientDecodePolicyProvider
    {
        public MailboxClientDecodePolicy GetCurrent() =>
            throw new InvalidOperationException("Malformed MAU2 must not decode a response.");
    }
}
