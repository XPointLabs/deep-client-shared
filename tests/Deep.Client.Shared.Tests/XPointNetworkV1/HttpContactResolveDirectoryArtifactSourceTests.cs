using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Tests.XPointNetworkV1;

public sealed class HttpContactResolveDirectoryArtifactSourceTests
{
    [Fact]
    public void Direct_directory_transport_is_not_a_public_host_composition_surface()
    {
        Assert.False(typeof(HttpContactResolveDirectoryArtifactSource).IsPublic);
        Assert.False(typeof(HttpContactResolveDirectoryOptions).IsPublic);
        Assert.DoesNotContain(
            typeof(HttpServiceTransportFactory).GetMethods(
                System.Reflection.BindingFlags.Instance |
                System.Reflection.BindingFlags.Public),
            static method => method.Name == "CreateContactResolveDirectoryArtifactSource");
    }

    [Fact]
    public void ConstructionIsFactoryOwnedAndDisposable()
    {
        Assert.Empty(typeof(HttpContactResolveDirectoryArtifactSource).GetConstructors(
            BindingFlags.Public | BindingFlags.Instance));
        Assert.True(typeof(IDisposable).IsAssignableFrom(
            typeof(HttpContactResolveDirectoryArtifactSource)));

        using var source = new HttpServiceTransportFactory(HttpServiceEndpointPolicy.Production)
            .CreateContactResolveDirectoryArtifactSource(
                new HttpContactResolveDirectoryOptions("https://directory.example/"),
                new SequenceClock(Reading(1)));
        Assert.NotNull(source);
    }

    [Fact]
    public async Task Success_PostsCleanBoundRequestAndReturnsUnverifiedArtifacts()
    {
        HttpContactResolveDirectoryRequest? observed = null;
        var package = HttpContactResolveDirectoryCodecTests.Artifacts(withForward: true);
        using var client = Client(async (request, cancellationToken) =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://directory.example/api/v1/directory/contact-resolve-packages",
                request.RequestUri!.AbsoluteUri);
            Assert.Equal(HttpContactResolveDirectoryCodec.RequestMediaType,
                request.Content!.Headers.ContentType!.MediaType);
            Assert.Contains(request.Headers.Accept, item =>
                item.MediaType == HttpContactResolveDirectoryCodec.ResponseMediaType);
            observed = HttpContactResolveDirectoryCodec.DecodeRequest(
                await request.Content.ReadAsByteArrayAsync(cancellationToken));
            return Response(HttpContactResolveDirectoryCodec.EncodeResponseForTest(
                observed.NetworkId, observed.Nonce, observed.BootId,
                observed.NonceCreatedAt, package));
        });
        var source = Source(client, new SequenceClock(
            Reading(10), Reading(12), Reading(13)));

        var result = await source.FetchCurrentAsync(Context(), default);

        Assert.NotNull(observed);
        Assert.Equal(B(16, 0x11), observed.NetworkId);
        Assert.Equal(32, observed.Nonce.Length);
        Assert.Contains(observed.Nonce, value => value != 0);
        Assert.Equal(B(16, 0x51), result.MonotonicRequestWindow.BootId.ToArray());
        Assert.Equal(10UL, result.MonotonicRequestWindow.NonceCreatedAt);
        Assert.Equal(12UL, result.MonotonicRequestWindow.ResponseReceivedAt);
        Assert.Equal(13UL, result.MonotonicRequestWindow.CurrentSample);
        Assert.Equal(package.ExactAdp1.ToArray(), result.ExactAdp1.ToArray());
        Assert.NotNull(result.ForwardCheckpoint);
    }

    [Fact]
    public async Task ConsecutiveRequests_UseFreshCryptographicNonces()
    {
        var nonces = new List<byte[]>();
        using var client = Client(async (request, cancellationToken) =>
        {
            var parsed = HttpContactResolveDirectoryCodec.DecodeRequest(
                await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            nonces.Add(parsed.Nonce);
            return Response(HttpContactResolveDirectoryCodec.EncodeResponseForTest(
                parsed.NetworkId, parsed.Nonce, parsed.BootId, parsed.NonceCreatedAt,
                HttpContactResolveDirectoryCodecTests.Artifacts()));
        });
        var source = Source(client, new SequenceClock(
            Reading(10), Reading(11), Reading(12),
            Reading(20), Reading(21), Reading(22)));

        await source.FetchCurrentAsync(Context(), default);
        await source.FetchCurrentAsync(Context(), default);

        Assert.Equal(2, nonces.Count);
        Assert.NotEqual(nonces[0], nonces[1]);
    }

    [Fact]
    public async Task TargetedCurrentValueRequest_UsesExactRegistryEndpointMediaAndBodyWithoutTrustProjection()
    {
        var lookupKey = B(32, 0x67);
        HttpTargetedCurrentValueDirectoryRequest? observed = null;
        using var client = Client(async (request, cancellationToken) =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://directory.example/api/v1/directory/current-values",
                request.RequestUri!.AbsoluteUri);
            Assert.Equal(HttpTargetedCurrentValueDirectoryCodec.RequestMediaType,
                request.Content!.Headers.ContentType!.MediaType);
            Assert.Empty(request.Content.Headers.ContentType.Parameters);
            Assert.Equal(HttpTargetedCurrentValueDirectoryCodec.RequestBytes,
                request.Content.Headers.ContentLength);
            Assert.Equal(HttpTargetedCurrentValueDirectoryCodec.ResponseMediaType,
                Assert.Single(request.Headers.Accept).MediaType);
            var body = await request.Content.ReadAsByteArrayAsync(cancellationToken);
            Assert.Equal(HttpTargetedCurrentValueDirectoryCodec.RequestBytes, body.Length);
            observed = HttpTargetedCurrentValueDirectoryCodec.DecodeRequest(
                body);
            return Response(
                HttpTargetedCurrentValueDirectoryCodec.EncodeResponseForTest(
                    observed.NetworkId,
                    observed.DirectoryLookupKey,
                    observed.Nonce,
                    observed.BootId,
                    observed.NonceCreatedAt,
                    HttpContactResolveDirectoryCodecTests.Artifacts()),
                mediaType: HttpTargetedCurrentValueDirectoryCodec.ResponseMediaType);
        });
        var source = Source(client, new SequenceClock(Reading(10), Reading(11), Reading(12)));
        var context = TargetedContext(lookupKey);

        var result = await source.FetchCurrentAsync(context, default);

        Assert.Equal(lookupKey, observed!.DirectoryLookupKey);
        Assert.Equal(lookupKey, result.QueriedDirectoryLeafKey.ToArray());
        Assert.Empty(result.ExactOrderedXvp1Chain);
        Assert.Empty(result.ExactActiveXnd1);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, "target-not-found")]
    [InlineData(HttpStatusCode.ServiceUnavailable, "directory-unavailable")]
    public async Task TargetedCurrentValueRequest_MapsNonEnumeratingStatusWithoutReadingBody(
        HttpStatusCode status,
        string expectedCode)
    {
        var content = new TrackingContent();
        content.Headers.ContentLength = 1;
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(status)
        {
            Content = content,
        }));
        var source = Source(client, new SequenceClock(Reading(10)));

        var error = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await source.FetchCurrentAsync(TargetedContext(B(32, 0x67)), default));

        Assert.Equal(expectedCode, error.Code);
        Assert.False(content.WasSerialized);
    }

    [Fact]
    public async Task TargetedCurrentValueRequest_RejectsWrongMediaAndRedirectedEndpoint()
    {
        using var wrongMediaClient = Client((_, _) => Task.FromResult(Response(
            new byte[] { 1 }, mediaType: HttpContactResolveDirectoryCodec.ResponseMediaType)));
        var wrongMediaSource = Source(wrongMediaClient, new SequenceClock(Reading(10)));
        var mediaError = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await wrongMediaSource.FetchCurrentAsync(TargetedContext(B(32, 0x67)), default));
        Assert.Equal("unexpected-media-type", mediaError.Code);

        using var redirectedClient = Client((_, _) =>
        {
            var response = Response(new byte[] { 1 }, mediaType:
                HttpTargetedCurrentValueDirectoryCodec.ResponseMediaType);
            response.RequestMessage = new HttpRequestMessage(
                HttpMethod.Post, "https://other.example/api/v1/directory/current-values");
            return Task.FromResult(response);
        });
        var redirectedSource = Source(redirectedClient, new SequenceClock(Reading(10)));
        var redirectError = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await redirectedSource.FetchCurrentAsync(TargetedContext(B(32, 0x67)), default));
        Assert.Equal("endpoint-changed", redirectError.Code);
    }

    [Fact]
    public async Task TargetedCurrentValueRequest_RejectsHostileResponseFraming()
    {
        using var client = Client(async (request, cancellationToken) =>
        {
            var parsed = HttpTargetedCurrentValueDirectoryCodec.DecodeRequest(
                await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            var encoded = HttpTargetedCurrentValueDirectoryCodec.EncodeResponseForTest(
                parsed.NetworkId, parsed.DirectoryLookupKey, parsed.Nonce, parsed.BootId,
                parsed.NonceCreatedAt, HttpContactResolveDirectoryCodecTests.Artifacts());
            encoded[4] ^= 0x01;
            return Response(encoded, mediaType: HttpTargetedCurrentValueDirectoryCodec.ResponseMediaType);
        });
        var source = Source(client, new SequenceClock(Reading(10), Reading(11), Reading(12)));

        var error = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await source.FetchCurrentAsync(TargetedContext(B(32, 0x67)), default));

        Assert.Equal("invalid-envelope", error.Code);
    }

    [Theory]
    [InlineData(HttpStatusCode.NoContent, HttpContactResolveDirectoryCodec.ResponseMediaType, "unexpected-status")]
    [InlineData(HttpStatusCode.NotFound, HttpContactResolveDirectoryCodec.ResponseMediaType, "unexpected-status")]
    [InlineData(HttpStatusCode.ServiceUnavailable, HttpContactResolveDirectoryCodec.ResponseMediaType, "unexpected-status")]
    [InlineData(HttpStatusCode.OK, "application/octet-stream", "unexpected-media-type")]
    public async Task WrongStatusOrMediaType_FailsClosed(
        HttpStatusCode status,
        string mediaType,
        string expectedCode)
    {
        using var client = Client((_, _) => Task.FromResult(Response(
            new byte[] { 1 }, status, mediaType)));
        var source = Source(client, new SequenceClock(Reading(10)));

        var error = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await source.FetchCurrentAsync(Context(), default));

        Assert.Equal(expectedCode, error.Code);
    }

    [Fact]
    public async Task MissingContentLength_FailsClosed()
    {
        using var client = Client((_, _) =>
        {
            var response = Response(new byte[] { 1 });
            response.Content.Headers.ContentLength = null;
            return Task.FromResult(response);
        });
        var source = Source(client, new SequenceClock(Reading(10)));

        var error = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await source.FetchCurrentAsync(Context(), default));

        Assert.Equal("content-length-required", error.Code);
    }

    [Fact]
    public async Task DeclaredOrAbsoluteOversize_FailsBeforeBodyRead()
    {
        var content = new TrackingContent();
        content.Headers.ContentLength = HttpContactResolveDirectoryCodec.AbsoluteMaximumEnvelopeBytes + 1L;
        content.Headers.ContentType = new MediaTypeHeaderValue(
            HttpContactResolveDirectoryCodec.ResponseMediaType);
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = content,
        }));
        var source = Source(client, new SequenceClock(Reading(10)));

        var error = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await source.FetchCurrentAsync(Context(), default));

        Assert.Equal("response-too-large", error.Code);
        Assert.False(content.WasSerialized);
    }

    [Fact]
    public async Task ConfiguredOversize_FailsBeforeBodyRead()
    {
        using var client = Client((_, _) => Task.FromResult(Response(new byte[513])));
        var source = Source(client, new SequenceClock(Reading(10)), maximumResponseBytes: 512);

        var error = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await source.FetchCurrentAsync(Context(), default));

        Assert.Equal("response-too-large", error.Code);
    }

    [Theory]
    [InlineData(true, "truncated-response")]
    [InlineData(false, "trailing-response")]
    public async Task ContentLengthMismatch_FailsClosed(bool truncated, string expectedCode)
    {
        using var client = Client(async (request, cancellationToken) =>
        {
            var parsed = HttpContactResolveDirectoryCodec.DecodeRequest(
                await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            var encoded = HttpContactResolveDirectoryCodec.EncodeResponseForTest(
                parsed.NetworkId, parsed.Nonce, parsed.BootId, parsed.NonceCreatedAt,
                HttpContactResolveDirectoryCodecTests.Artifacts());
            var response = Response(encoded);
            response.Content.Headers.ContentLength = truncated ? encoded.Length + 1 : encoded.Length - 1;
            return response;
        });
        var source = Source(client, new SequenceClock(Reading(10)));

        var error = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await source.FetchCurrentAsync(Context(), default));

        Assert.Equal(expectedCode, error.Code);
    }

    [Fact]
    public async Task MalformedEnvelope_FailsClosedWithoutAuthorityInterpretation()
    {
        using var client = Client(async (request, cancellationToken) =>
        {
            var parsed = HttpContactResolveDirectoryCodec.DecodeRequest(
                await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            var encoded = HttpContactResolveDirectoryCodec.EncodeResponseForTest(
                parsed.NetworkId, parsed.Nonce, parsed.BootId, parsed.NonceCreatedAt,
                HttpContactResolveDirectoryCodecTests.Artifacts());
            encoded[0] ^= 0xff;
            return Response(encoded);
        });
        var source = Source(client, new SequenceClock(Reading(10), Reading(11), Reading(12)));

        var error = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await source.FetchCurrentAsync(Context(), default));

        Assert.Equal("invalid-envelope", error.Code);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task WrongNonceOrNetwork_FailsClosed(bool wrongNonce)
    {
        using var client = Client(async (request, cancellationToken) =>
        {
            var parsed = HttpContactResolveDirectoryCodec.DecodeRequest(
                await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            return Response(HttpContactResolveDirectoryCodec.EncodeResponseForTest(
                wrongNonce ? parsed.NetworkId : B(16, 0x12),
                wrongNonce ? B(32, 0x42) : parsed.Nonce,
                parsed.BootId,
                parsed.NonceCreatedAt,
                HttpContactResolveDirectoryCodecTests.Artifacts()));
        });
        var source = Source(client, new SequenceClock(Reading(10), Reading(11), Reading(12)));

        var error = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await source.FetchCurrentAsync(Context(), default));

        Assert.Equal("invalid-envelope", error.Code);
    }

    [Fact]
    public async Task LocalBootChange_FailsClosed()
    {
        using var client = Client(async (request, cancellationToken) =>
        {
            var parsed = HttpContactResolveDirectoryCodec.DecodeRequest(
                await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            return Response(HttpContactResolveDirectoryCodec.EncodeResponseForTest(
                parsed.NetworkId, parsed.Nonce, parsed.BootId, parsed.NonceCreatedAt,
                HttpContactResolveDirectoryCodecTests.Artifacts()));
        });
        var source = Source(client, new SequenceClock(
            Reading(10),
            new OnionMonotonicReading(B(16, 0x52), 11),
            new OnionMonotonicReading(B(16, 0x52), 12)));

        var error = await Assert.ThrowsAsync<HttpContactResolveDirectoryException>(async () =>
            await source.FetchCurrentAsync(Context(), default));

        Assert.Equal("invalid-envelope", error.Code);
    }

    [Fact]
    public async Task Cancellation_IsPreserved()
    {
        using var client = Client(async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        });
        var source = Source(client, new SequenceClock(Reading(10)));
        using var cancellation = new CancellationTokenSource();
        cancellation.CancelAfter(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await source.FetchCurrentAsync(Context(), cancellation.Token));
    }

    private static HttpContactResolveDirectoryArtifactSource Source(
        HttpClient client,
        IOnionMonotonicClock clock,
        int maximumResponseBytes = HttpContactResolveDirectoryCodec.AbsoluteMaximumEnvelopeBytes) =>
        new(client, new HttpContactResolveDirectoryOptions(
            "https://directory.example/", maximumResponseBytes), clock);

    private static ContactResolveDirectoryFetchContext Context() =>
        new(B(16, 0x11), null, null);

    private static ContactResolveDirectoryFetchContext TargetedContext(byte[] lookupKey) =>
        new(B(16, 0x11),
            HttpContactResolveDirectoryCodecTests.DirectoryState(treeSize: 17, hashMarker: 0x31),
            null,
            lookupKey);

    private static OnionMonotonicReading Reading(ulong sample) =>
        new(B(16, 0x51), sample);

    private static HttpResponseMessage Response(
        byte[] bytes,
        HttpStatusCode status = HttpStatusCode.OK,
        string mediaType = HttpContactResolveDirectoryCodec.ResponseMediaType)
    {
        var response = new HttpResponseMessage(status)
        {
            Content = new ByteArrayContent(bytes),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        return response;
    }

    private static HttpClient Client(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> response) =>
        new(new Handler(response));

    private static byte[] B(int length, byte marker) =>
        HttpContactResolveDirectoryCodecTests.B(length, marker);

    private sealed class SequenceClock(params OnionMonotonicReading[] values) : IOnionMonotonicClock
    {
        private int index;

        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (index >= values.Length)
                throw new InvalidOperationException("The test monotonic clock was exhausted.");
            return ValueTask.FromResult(values[index++]);
        }
    }

    private sealed class Handler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> response)
        : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var result = await response(request, cancellationToken);
            result.RequestMessage ??= request;
            return result;
        }
    }

    private sealed class TrackingContent : HttpContent
    {
        internal bool WasSerialized { get; private set; }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            WasSerialized = true;
            return Task.CompletedTask;
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }
}
