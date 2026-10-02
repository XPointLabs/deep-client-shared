using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using System.Runtime.CompilerServices;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2DirectoryProofClientTests
{
    [Fact]
    public async Task IgnoredTransportCancellationReturnsAndWipesLateResponseWithoutVerifyingIt()
    {
        var pending = new TaskCompletionSource<HttpServiceResponse>();
        using var cancel = new CancellationTokenSource();
        var bounded = DeepIdV2DirectoryProofClient.AwaitBoundedResponseAsync(pending.Task, cancel.Token);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => bounded.WaitAsync(TimeSpan.FromSeconds(2)));
        var body = new byte[] { 0x71, 0x72 };
        var response = new HttpServiceResponse(System.Net.HttpStatusCode.OK, body);
        pending.SetResult(response);
        // The registered cleanup continuation runs synchronously on SetResult.
        await pending.Task;
        Assert.All(body, value => Assert.Equal((byte)0, value));
        Assert.Throws<ObjectDisposedException>(() => _ = response.Body);
    }

    [Fact]
    public void RetryableProofFailureHasClosedBoundedSchedulingMetadata()
    {
        var failure = new DeepIdV2DirectoryProofUnavailableException(
            System.Net.HttpStatusCode.TooManyRequests, TimeSpan.FromSeconds(10));
        Assert.IsAssignableFrom<IOException>(failure);
        Assert.Equal(System.Net.HttpStatusCode.TooManyRequests, failure.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(10), failure.RetryAfter);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new DeepIdV2DirectoryProofUnavailableException(System.Net.HttpStatusCode.OK, null));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new DeepIdV2DirectoryProofUnavailableException(System.Net.HttpStatusCode.ServiceUnavailable,
                TimeSpan.FromMinutes(6)));
    }

    [Fact]
    public void TransportOptionsAreV2OnlyBoundedAndSingleEndpoint()
    {
        var options = DeepIdV2DirectoryProofClient.CreateTransportOptions(
            "https://registry.example/");

        Assert.Equal("https://registry.example/", options.BaseUrl);
        Assert.Equal([DeepIdV2DirectoryProofClient.EndpointPath],
            options.AllowedPostPaths);
        Assert.Equal(DeepIdV2DirectoryProofWireCodec.RequestMediaType,
            options.RequestMediaType);
        Assert.Equal(DeepIdV2DirectoryProofWireCodec.ResponseMediaType,
            options.ResponseMediaType);
        Assert.Equal(DeepIdV2DirectoryProofWireCodec.RequestLength,
            options.MaximumRequestBytes);
        Assert.Equal(DeepIdV2DirectoryProofWireCodec.MaximumResponseLength,
            options.MaximumResponseBytes);
        Assert.Equal(TimeSpan.FromSeconds(30), options.RequestTimeout);
        Assert.Null(options.RequestCharset);
        Assert.Null(options.ResponseCharset);
    }

    [Fact]
    public void TransportOptionsRejectUnboundedTimeoutAndMissingEndpoint()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DeepIdV2DirectoryProofClient.CreateTransportOptions(
                "https://registry.example/", TimeSpan.FromSeconds(31)));
        Assert.Throws<ArgumentException>(() =>
            DeepIdV2DirectoryProofClient.CreateTransportOptions(" "));
    }

    [Fact]
    public void ProofClientRequiresProtectedFloorStoreAtConstruction()
    {
        using var transport = new HttpServiceRequestTransport(
            new HttpClient(),
            DeepIdV2DirectoryProofClient.CreateTransportOptions(
                "https://registry.example/"),
            HttpServiceEndpointPolicy.Production);
        Assert.Throws<ArgumentNullException>(() =>
            new DeepIdV2DirectoryProofClient(transport, transport, new FixedClock(),
                new DenyingVerifier(), null!));
    }

    [Fact]
    public void FactoryOwnsProofTransportAndRejectsNonHttpsOrLongTimeout()
    {
        var factory = new HttpServiceTransportFactory(
            HttpServiceEndpointPolicy.Production);
        var clock = new FixedClock();
        var verifier = new DenyingVerifier();
        var floor = new UnusedFloor();

        using var proof = factory.CreateDeepIdV2DirectoryProofClient(
            "https://registry.example/", clock, verifier, floor);
        Assert.NotNull(proof);
        Assert.Throws<ArgumentException>(() =>
            factory.CreateDeepIdV2DirectoryProofClient(
                "http://registry.example/", clock, verifier, floor));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            factory.CreateDeepIdV2DirectoryProofClient(
                "https://registry.example/", clock, verifier, floor,
                requestTimeout: TimeSpan.FromSeconds(31)));
        Assert.Throws<ArgumentNullException>(() =>
            factory.CreateDeepIdV2DirectoryProofClient(
                "https://registry.example/", clock, verifier, null!));
    }

    [Theory]
    [InlineData((ushort)0, (ushort)2, "deploymentProfileId")]
    [InlineData((ushort)1, (ushort)1, "supportedReader")]
    public async Task InvalidV2ProfileRejectsBeforeProtectedFloorOrNetwork(
        ushort deploymentProfileId, ushort supportedReader,
        string expectedParameter)
    {
        using var transport = new HttpServiceRequestTransport(
            new HttpClient(),
            DeepIdV2DirectoryProofClient.CreateTransportOptions(
                "https://registry.example/"),
            HttpServiceEndpointPolicy.Production);
        using var proof = new DeepIdV2DirectoryProofClient(transport, transport,
            new FixedClock(), new DenyingVerifier(), new UnusedFloor());
        var did2 = DeepIdV2Codec.AuthorDid2(
            Enumerable.Repeat((byte)0x21, 32).ToArray(),
            Enumerable.Repeat((byte)0x31, 1952).ToArray(),
            Enumerable.Repeat((byte)0x41, 16).ToArray());
        var authority = (VerifiedXPointNetworkAuthority)
            RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedXPointNetworkAuthority));

        var error = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            async () => await proof.FetchByDid2Async(did2, authority,
                deploymentProfileId, supportedReader));
        Assert.Equal(expectedParameter, error.ParamName);
    }

    private sealed class UnusedFloor : IDeepIdV2DirectoryProtectedLkgStore
    {
        public ValueTask CommitCatchupAsync(VerifiedDeepIdV2DirectoryCatchup verified,
            CancellationToken cancellationToken) => throw new NotSupportedException("No network request is made.");
        public ValueTask<AccountDirectoryProtectedLkg> RestoreAsync(
            VerifiedXPointNetworkAuthority authority,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException("No network request is made.");

        public ValueTask CommitVerifiedAsync(
            AccountDirectoryProtectedLkg expectedHead,
            VerifiedDeepIdV2DirectoryFreshness verified,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException("No network request is made.");
    }

    private sealed class FixedClock : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new OnionMonotonicReading(
                Enumerable.Repeat((byte)0x41, 16).ToArray(), 5));
    }

    private sealed class DenyingVerifier : IDeepMlDsa65Verifier
    {
        public bool Verify(ReadOnlySpan<byte> publicKey1952,
            ReadOnlySpan<byte> message, ReadOnlySpan<byte> context,
            ReadOnlySpan<byte> signature3309) => false;
    }
}
