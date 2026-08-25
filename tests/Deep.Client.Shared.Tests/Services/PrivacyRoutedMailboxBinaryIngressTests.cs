using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class PrivacyRoutedMailboxBinaryIngressTests
{
    [Fact]
    public async Task Success_UsesExactlyThreeHopsAndPreservesExactMau2()
    {
        using var fixture = new RouteFixture();
        var request = RetrieveRequest();
        var response = RetrieveResponse();
        var primary = new OpeningTransport(fixture.PrimaryKeys, response);
        var fallback = new OpeningTransport(fixture.FallbackKeys, response);
        using var ingress = fixture.Create(primary, fallback);

        var actual = await ingress.RetrieveAsync(request);

        Assert.Equal(response, actual.ToArray());
        Assert.Equal(request, Assert.Single(primary.ExitPayloads));
        Assert.Equal(PrivacyRoutingOperation.Retrieve, Assert.Single(primary.Operations));
        Assert.Empty(fallback.ExitPayloads);
    }

    [Fact]
    public async Task RetryableBeforeForward_UsesFreshDisjointFallback()
    {
        using var fixture = new RouteFixture();
        var request = RetrieveRequest();
        var response = RetrieveResponse();
        var primary = new RejectingTransport(retryable: true);
        var fallback = new OpeningTransport(fixture.FallbackKeys, response);
        using var ingress = fixture.Create(primary, fallback);

        var actual = await ingress.RetrieveAsync(request);

        Assert.Equal(response, actual.ToArray());
        Assert.Equal(1, primary.Attempts);
        Assert.Equal(request, Assert.Single(fallback.ExitPayloads));
    }

    [Fact]
    public async Task OutcomeUnknown_NeverUsesFallback()
    {
        using var fixture = new RouteFixture();
        var primary = new OutcomeUnknownTransport();
        var fallback = new OpeningTransport(fixture.FallbackKeys, RetrieveResponse());
        using var ingress = fixture.Create(primary, fallback);

        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Empty(fallback.ExitPayloads);
    }

    [Fact]
    public async Task UnauthenticatedReply_IsOutcomeUnknownAndDoesNotFallback()
    {
        using var fixture = new RouteFixture();
        var primary = new TamperedReplyTransport(fixture.PrimaryKeys);
        var fallback = new OpeningTransport(fixture.FallbackKeys, RetrieveResponse());
        using var ingress = fixture.Create(primary, fallback);

        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Empty(fallback.ExitPayloads);
    }

    [Fact]
    public async Task TerminalOutcomeUnknown_NeverUsesFallback()
    {
        using var fixture = new RouteFixture();
        var primary = new TerminalFailureTransport(
            fixture.PrimaryKeys,
            PrivacyRoutingFailureCode.OutcomeUnknown);
        var fallback = new OpeningTransport(fixture.FallbackKeys, RetrieveResponse());
        using var ingress = fixture.Create(primary, fallback);

        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Empty(fallback.ExitPayloads);
    }

    [Fact]
    public async Task DefiniteTerminalCapacityFailure_IsMappedWithoutFallback()
    {
        using var fixture = new RouteFixture();
        var primary = new TerminalFailureTransport(
            fixture.PrimaryKeys,
            PrivacyRoutingFailureCode.CapacityExceeded);
        var fallback = new OpeningTransport(fixture.FallbackKeys, RetrieveResponse());
        using var ingress = fixture.Create(primary, fallback);

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Equal(ClientMailboxTransportFailure.Throttled, exception.Failure);
        Assert.True(exception.Retryable);
        Assert.Empty(fallback.ExitPayloads);
    }

    [Fact]
    public void OverlappingFallbackRoute_IsRejected()
    {
        using var fixture = new RouteFixture();
        var overlapping = new PrivacyMailboxRoute(
            new Uri("https://fallback.example:443/"),
            [
                fixture.PrimaryRoute.Hops[2],
                fixture.FallbackRoute.Hops[1],
                fixture.FallbackRoute.Hops[2]
            ]);

        Assert.Throws<ArgumentException>(() => new PrivacyRoutedMailboxBinaryIngress(
            fixture.PrimaryRoute,
            overlapping,
            Policies(),
            new RejectingTransport(true),
            new RejectingTransport(true)));
    }

    [Fact]
    public async Task PreCancelledOperation_DoesNotSealOrDispatch()
    {
        using var fixture = new RouteFixture();
        var primary = new RejectingTransport(retryable: true);
        var fallback = new RejectingTransport(retryable: true);
        using var ingress = fixture.Create(primary, fallback);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ingress.RetrieveAsync(RetrieveRequest(), cancellation.Token));

        Assert.Equal(0, primary.Attempts);
        Assert.Equal(0, fallback.Attempts);
    }

    [Fact]
    public async Task NonCanonicalMau2_IsRejectedBeforeOuterDispatch()
    {
        using var fixture = new RouteFixture();
        var primary = new RejectingTransport(retryable: true);
        var fallback = new RejectingTransport(retryable: true);
        using var ingress = fixture.Create(primary, fallback);
        var malformed = RetrieveRequest().Concat(new byte[] { 0 }).ToArray();

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(malformed));

        Assert.Equal(ClientMailboxTransportFailure.MalformedRequest, exception.Failure);
        Assert.Equal(0, primary.Attempts);
        Assert.Equal(0, fallback.Attempts);
    }

    [Fact]
    public async Task FactoryOwnedIngress_UsesBoundNetworkHooksForPrimaryAndFallbackRoutes()
    {
        using var fixture = new RouteFixture();
        var connectedAuthorities = new List<string>();
        var factory = new HttpServiceTransportFactory(HttpServiceEndpointPolicy.Production)
            .BindNetwork(new HttpServiceNetworkHooks(
                ConnectCallback: (context, _) =>
                {
                    connectedAuthorities.Add(context.DnsEndPoint.Host);
                    return ValueTask.FromResult<Stream>(new MemoryStream());
                }));
        using var ingress = factory.CreatePrivacyRoutedMailboxIngress(
            fixture.PrimaryRoute,
            fixture.FallbackRoute,
            Policies(),
            new HttpServiceClientOptions(Timeout: TimeSpan.FromSeconds(2)),
            PrivacyRoutingLimits.MinimumPaddingBlockBytes);

        await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Equal(["primary.example", "fallback.example"], connectedAuthorities);
    }

    private static byte[] RetrieveRequest()
    {
        var operationId = Bytes(16, 0x11);
        var mailbox = new BlindedMailboxId(Bytes(32, 0x21));
        var placement = new BlindedPlacementId(Bytes(32, 0x41));
        var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7, operationId, mailbox, placement, 0, 10, []);
        return MailboxAuthenticatedClientRequestCodec.Encode(
            new MailboxAuthenticatedClientRequest
            {
                Binding = binding,
                Presentation = new MailboxAuthenticatedPresentation
                {
                    Operation = MailboxAuthenticatedOperation.Retrieve,
                    OperationId = operationId,
                    ReplayCounter = 1,
                    RequestDigest = binding.RequestDigest.ToArray(),
                    Grant = new MailboxAuthenticatedGrant
                    {
                        Domain = MailboxCapabilityDomain.Retrieve,
                        Lifecycle = MailboxCapabilityLifecycle.Active,
                        NetworkId = Bytes(16, 0x61),
                        Epoch = 7,
                        Generation = 107,
                        Serial = Bytes(16, 0x71),
                        NotBeforeUnixSeconds = 900,
                        ExpiresAtUnixSeconds = 1200,
                        OverlapUntilUnixSeconds = 0,
                        PlacementCommitment = MailboxPlacementCommitment.Compute(placement),
                        MembershipCommitment = Bytes(32, 0x81),
                        IssuerPublicKey = Bytes(32, 0x91),
                        HolderPublicKey = Bytes(32, 0xa1),
                        IssuerSignature = Bytes(64, 0xb1)
                    },
                    HolderSignature = Bytes(64, 0xc1)
                }
            });
    }

    private static byte[] RetrieveResponse() =>
        MailboxClientCodec.EncodeRetrievePage(new MailboxRetrievePage
        {
            Epoch = 7,
            OperationId = Bytes(16, 0x11),
            NextCursor = 0,
            HasMore = false,
            ContinuationToken = Array.Empty<byte>(),
            Items = []
        });

    private static IMailboxClientDecodePolicyProvider Policies() =>
        new TimeProviderMailboxClientDecodePolicyProvider(
            new MailboxEpochWindow
            {
                CurrentEpoch = 7,
                NextEpoch = 8,
                CurrentNotBeforeUnixSeconds = 900,
                NextNotBeforeUnixSeconds = 1100,
                CurrentExpiresAtUnixSeconds = 1120,
                NextExpiresAtUnixSeconds = 1200
            },
            new MailboxCapabilityDecodePolicy
            {
                CurrentBucket = 1050,
                MinimumGeneration = 7
            },
            new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1050)));

    private static byte[] Bytes(int count, byte start) => Enumerable.Range(0, count)
        .Select(index => unchecked((byte)(start + index))).ToArray();

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class RouteFixture : IDisposable
    {
        internal RouteFixture()
        {
            PrimaryKeys = KeyPairs(0x11);
            FallbackKeys = KeyPairs(0x71);
            PrimaryRoute = Route("primary", PrimaryKeys, 0x21);
            FallbackRoute = Route("fallback", FallbackKeys, 0x81);
        }

        internal KeyPair[] PrimaryKeys { get; }
        internal KeyPair[] FallbackKeys { get; }
        internal PrivacyMailboxRoute PrimaryRoute { get; }
        internal PrivacyMailboxRoute FallbackRoute { get; }

        internal PrivacyRoutedMailboxBinaryIngress Create(
            IPrivacyManagedIngressTransport primary,
            IPrivacyManagedIngressTransport fallback) => new(
                PrimaryRoute,
                FallbackRoute,
                Policies(),
                primary,
                fallback,
                PrivacyRoutingLimits.MinimumPaddingBlockBytes);

        public void Dispose()
        {
            foreach (var key in PrimaryKeys.Concat(FallbackKeys))
            {
                key.Dispose();
            }
        }

        private static PrivacyMailboxRoute Route(
            string host,
            IReadOnlyList<KeyPair> keys,
            byte seed) => new(
                new Uri($"https://{host}.example:443/"),
                keys.Select((key, index) => new PrivacyRoutingHop(
                    Bytes(32, checked((byte)(seed + index * 7))),
                    key.PublicKey)).ToArray());

        private static KeyPair[] KeyPairs(byte seed) =>
            Enumerable.Range(0, PrivacyRoutingLimits.RouteHopCount)
                .Select(index => PublicKeyBox.GenerateKeyPair(
                    Bytes(32, checked((byte)(seed + index * 13)))))
                .ToArray();
    }

    private sealed class OpeningTransport(
        IReadOnlyList<KeyPair> keys,
        byte[] response) : IPrivacyManagedIngressTransport
    {
        public List<byte[]> ExitPayloads { get; } = [];
        public List<PrivacyRoutingOperation> Operations { get; } = [];

        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var first = Assert.IsType<PrivacyRoutingRelayLayer>(
                PrivacyRoutingRequestCodec.Open(opaqueFrame.Span, keys[0].PrivateKey));
            var second = Assert.IsType<PrivacyRoutingRelayLayer>(
                PrivacyRoutingRequestCodec.Open(first.InnerFrame.Span, keys[1].PrivateKey));
            var exit = Assert.IsType<PrivacyRoutingExitLayer>(
                PrivacyRoutingRequestCodec.Open(second.InnerFrame.Span, keys[2].PrivateKey));
            ExitPayloads.Add(exit.Payload.ToArray());
            Operations.Add(exit.Operation);
            return Task.FromResult<ReadOnlyMemory<byte>>(
                PrivacyRoutingResponseCodec.Seal(
                    exit,
                    PrivacyRoutingResultCodec.Encode(
                        PrivacyRoutingTerminalResult.Success(exit.Operation, response)),
                    PrivacyRoutingLimits.MinimumPaddingBlockBytes));
        }

        public void Dispose()
        {
        }
    }

    private sealed class TamperedReplyTransport(
        IReadOnlyList<KeyPair> keys) : IPrivacyManagedIngressTransport
    {
        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var first = Assert.IsType<PrivacyRoutingRelayLayer>(
                PrivacyRoutingRequestCodec.Open(opaqueFrame.Span, keys[0].PrivateKey));
            var second = Assert.IsType<PrivacyRoutingRelayLayer>(
                PrivacyRoutingRequestCodec.Open(first.InnerFrame.Span, keys[1].PrivateKey));
            var exit = Assert.IsType<PrivacyRoutingExitLayer>(
                PrivacyRoutingRequestCodec.Open(second.InnerFrame.Span, keys[2].PrivateKey));
            var sealedReply = PrivacyRoutingResponseCodec.Seal(
                exit,
                PrivacyRoutingResultCodec.Encode(
                    PrivacyRoutingTerminalResult.Success(
                        exit.Operation,
                        RetrieveResponse())),
                PrivacyRoutingLimits.MinimumPaddingBlockBytes);
            sealedReply[^1] ^= 0x80;
            return Task.FromResult<ReadOnlyMemory<byte>>(sealedReply);
        }

        public void Dispose()
        {
        }
    }

    private sealed class TerminalFailureTransport(
        IReadOnlyList<KeyPair> keys,
        PrivacyRoutingFailureCode failureCode) : IPrivacyManagedIngressTransport
    {
        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var first = Assert.IsType<PrivacyRoutingRelayLayer>(
                PrivacyRoutingRequestCodec.Open(opaqueFrame.Span, keys[0].PrivateKey));
            var second = Assert.IsType<PrivacyRoutingRelayLayer>(
                PrivacyRoutingRequestCodec.Open(first.InnerFrame.Span, keys[1].PrivateKey));
            var exit = Assert.IsType<PrivacyRoutingExitLayer>(
                PrivacyRoutingRequestCodec.Open(second.InnerFrame.Span, keys[2].PrivateKey));
            var result = PrivacyRoutingResultCodec.Encode(
                PrivacyRoutingTerminalResult.Failure(exit.Operation, failureCode));
            return Task.FromResult<ReadOnlyMemory<byte>>(
                PrivacyRoutingResponseCodec.Seal(
                    exit,
                    result,
                    PrivacyRoutingLimits.MinimumPaddingBlockBytes));
        }

        public void Dispose()
        {
        }
    }

    private sealed class RejectingTransport(bool retryable) : IPrivacyManagedIngressTransport
    {
        public int Attempts { get; private set; }

        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Attempts++;
            return Task.FromException<ReadOnlyMemory<byte>>(
                new PrivacyIngressRejectedBeforeForwardException(
                    retryable,
                    "definite rejection"));
        }

        public void Dispose()
        {
        }
    }

    private sealed class OutcomeUnknownTransport : IPrivacyManagedIngressTransport
    {
        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken) =>
            Task.FromException<ReadOnlyMemory<byte>>(
                new ClientMailboxDispatchOutcomeUnknownException("unknown"));

        public void Dispose()
        {
        }
    }
}
