using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Tests.Services;

public sealed class HttpClientMailboxBinaryIngressTests
{
    [Fact]
    public async Task Retrieve_sends_exact_mau2_to_only_native_route()
    {
        var request = RetrieveRequest();
        var response = RetrieveResponse();
        var handler = new RecordingHandler(message =>
        {
            Assert.Equal(MailboxWireHttpContract.RetrieveRoute,
                message.RequestUri!.AbsolutePath);
            Assert.Equal(MailboxWireHttpContract.Mau2ContentType,
                message.Content!.Headers.ContentType!.MediaType);
            Assert.Empty(message.Content.Headers.ContentType.Parameters);
            Assert.Empty(message.Content.Headers.ContentEncoding);
            Assert.Equal(request, message.Content.ReadAsByteArrayAsync()
                .GetAwaiter().GetResult());
            return Success(message, response);
        });
        var ingress = Create(handler);

        var actual = await ingress.RetrieveAsync(request);

        Assert.Equal(response, actual.ToArray());
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Retrieve_accepts_large_canonical_mrp1_without_truncation()
    {
        var response = RetrieveResponse(ciphertextBytes: 70 * 1024);
        Assert.True(response.Length > 64 * 1024);
        var ingress = Create(new RecordingHandler(
            request => Success(request, response)));

        var actual = await ingress.RetrieveAsync(RetrieveRequest());

        Assert.Equal(response, actual.ToArray());
    }

    [Theory]
    [InlineData("application/octet-stream")]
    [InlineData("application/vnd.deep.mailbox.mrp1; charset=utf-8")]
    public async Task Success_rejects_wrong_or_parameterized_media_type(
        string contentType)
    {
        var ingress = Create(new RecordingHandler(request =>
        {
            var response = Success(request, RetrieveResponse());
            response.Content.Headers.Remove("Content-Type");
            response.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
            return response;
        }));

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Equal(ClientMailboxTransportFailure.ProtocolViolation,
            exception.Failure);
        Assert.False(exception.Retryable);
    }

    [Fact]
    public async Task Success_rejects_truncated_mrp1()
    {
        var canonical = RetrieveResponse();
        var ingress = Create(new RecordingHandler(
            request => Success(request, canonical[..^1])));

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Equal(ClientMailboxTransportFailure.ProtocolViolation,
            exception.Failure);
        Assert.False(exception.Retryable);
    }

    [Fact]
    public async Task Entry_point_rejects_mau2_for_another_operation_before_network()
    {
        var handler = new RecordingHandler(
            _ => throw new InvalidOperationException("must not dispatch"));
        var ingress = Create(handler);

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.StoreAsync(RetrieveRequest()));

        Assert.Equal(ClientMailboxTransportFailure.MalformedRequest,
            exception.Failure);
        Assert.False(exception.Retryable);
        Assert.Equal(0, handler.Calls);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests,
        ClientMailboxTransportFailure.Throttled)]
    [InlineData(HttpStatusCode.ServiceUnavailable,
        ClientMailboxTransportFailure.DependencyUnavailable)]
    [InlineData(HttpStatusCode.GatewayTimeout,
        ClientMailboxTransportFailure.DeadlineExceeded)]
    public async Task Retryable_statuses_are_enum_classified(
        HttpStatusCode status,
        ClientMailboxTransportFailure expected)
    {
        var ingress = Create(new RecordingHandler(
            request => Empty(request, status)));

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Equal(expected, exception.Failure);
        Assert.True(exception.Retryable);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest,
        ClientMailboxTransportFailure.MalformedRequest)]
    [InlineData(HttpStatusCode.Unauthorized,
        ClientMailboxTransportFailure.AuthenticationRejected)]
    [InlineData(HttpStatusCode.Forbidden,
        ClientMailboxTransportFailure.AuthorizationRejected)]
    [InlineData(HttpStatusCode.Conflict,
        ClientMailboxTransportFailure.ConflictOrExpired)]
    [InlineData(HttpStatusCode.UnsupportedMediaType,
        ClientMailboxTransportFailure.UnsupportedMediaType)]
    public async Task Terminal_statuses_are_enum_classified(
        HttpStatusCode status,
        ClientMailboxTransportFailure expected)
    {
        var ingress = Create(new RecordingHandler(
            request => Empty(request, status)));

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Equal(expected, exception.Failure);
        Assert.False(exception.Retryable);
    }

    [Fact]
    public async Task Error_status_with_body_is_protocol_violation()
    {
        var ingress = Create(new RecordingHandler(request =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                RequestMessage = request,
                Content = new ByteArrayContent([1])
            };
            return response;
        }));

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Equal(ClientMailboxTransportFailure.ProtocolViolation,
            exception.Failure);
        Assert.False(exception.Retryable);
    }

    [Fact]
    public async Task Redirected_origin_is_rejected()
    {
        var ingress = Create(new RecordingHandler(request =>
        {
            var changed = new HttpRequestMessage(
                HttpMethod.Post,
                "https://redirected.invalid/api/client/mailbox/v2/retrieve");
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = changed,
                Content = Content(RetrieveResponse(),
                    MailboxWireHttpContract.Mrp1ContentType)
            };
        }));

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Equal(ClientMailboxTransportFailure.ProtocolViolation,
            exception.Failure);
        Assert.False(exception.Retryable);
    }

    [Fact]
    public async Task Owned_loopback_handler_does_not_follow_307_redirect()
    {
        var portProbe = new TcpListener(IPAddress.Loopback, 0);
        portProbe.Start();
        var port = ((IPEndPoint)portProbe.LocalEndpoint).Port;
        portProbe.Stop();
        var origin = new Uri($"http://127.0.0.1:{port}/");
        using var listener = new HttpListener();
        listener.Prefixes.Add(origin.AbsoluteUri);
        listener.Start();
        var requests = 0;
        var server = Task.Run(async () =>
        {
            var first = await listener.GetContextAsync();
            Interlocked.Increment(ref requests);
            first.Response.StatusCode = 307;
            first.Response.RedirectLocation =
                "/redirect-target";
            first.Response.ContentLength64 = 0;
            first.Response.Close();
            try
            {
                var second = await listener.GetContextAsync()
                    .WaitAsync(TimeSpan.FromSeconds(2));
                Interlocked.Increment(ref requests);
                second.Response.StatusCode = 503;
                second.Response.ContentLength64 = 0;
                second.Response.Close();
            }
            catch (TimeoutException)
            {
            }
        });
        using var ingress =
            HttpClientMailboxBinaryIngress.CreateLoopbackDevelopment(
                origin,
                Policy());

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));
        await server;

        Assert.Equal(ClientMailboxTransportFailure.ProtocolViolation,
            exception.Failure);
        Assert.Equal(1, requests);
    }

    [Fact]
    public void Public_factories_enforce_https_pins_or_explicit_loopback()
    {
        var pins = new ClientMailboxTlsSpkiPinSet(
            Bytes(SHA256.HashSizeInBytes, 0xd1));
        Assert.Throws<ArgumentException>(() =>
            HttpClientMailboxBinaryIngress.CreateProduction(
                new Uri("http://mailbox.example/"),
                Policy(),
                pins));
        Assert.Throws<ArgumentException>(() =>
            HttpClientMailboxBinaryIngress.CreateLoopbackDevelopment(
                new Uri("http://mailbox.example/"),
                Policy()));
        Assert.DoesNotContain(
            Convert.ToHexString(Bytes(SHA256.HashSizeInBytes, 0xd1)),
            pins.ToString(),
            StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Owned_deadline_maps_success_and_error_body_read_timeout(
        bool success)
    {
        var ingress = Create(
            new RecordingHandler(request =>
            {
                var response = new HttpResponseMessage(
                    success
                        ? HttpStatusCode.OK
                        : HttpStatusCode.ServiceUnavailable)
                {
                    RequestMessage = request,
                    Content = new StreamContent(new BlockingReadStream())
                };
                if (success)
                {
                    response.Content.Headers.ContentType =
                        new System.Net.Http.Headers.MediaTypeHeaderValue(
                            MailboxWireHttpContract.Mrp1ContentType);
                }
                return response;
            }),
            TimeSpan.FromMilliseconds(50));

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Equal(
            ClientMailboxTransportFailure.DeadlineExceeded,
            exception.Failure);
        Assert.True(exception.Retryable);
    }

    [Fact]
    public async Task Caller_cancellation_during_body_read_remains_raw()
    {
        var ingress = Create(
            new RecordingHandler(request =>
                new HttpResponseMessage(HttpStatusCode.OK)
                {
                    RequestMessage = request,
                    Content = BlockingContent()
                }),
            TimeSpan.FromSeconds(5));
        using var cancellation = new CancellationTokenSource(
            TimeSpan.FromMilliseconds(50));

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ingress.RetrieveAsync(
                RetrieveRequest(),
                cancellation.Token));

        Assert.IsNotType<ClientMailboxTransportException>(exception);
        Assert.True(cancellation.IsCancellationRequested);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task Post_header_network_failure_is_closed_and_retryable(
        bool success,
        bool httpRequestFailure)
    {
        var ingress = Create(new RecordingHandler(request =>
        {
            var response = new HttpResponseMessage(
                success
                    ? HttpStatusCode.OK
                    : HttpStatusCode.ServiceUnavailable)
            {
                RequestMessage = request,
                Content = new StreamContent(new ThrowingReadStream(
                    httpRequestFailure
                        ? new HttpRequestException("stream reset")
                        : new IOException("stream reset")))
            };
            if (success)
            {
                response.Content.Headers.ContentType =
                    new System.Net.Http.Headers.MediaTypeHeaderValue(
                        MailboxWireHttpContract.Mrp1ContentType);
            }
            return response;
        }));

        var exception = await Assert.ThrowsAsync<ClientMailboxTransportException>(
            () => ingress.RetrieveAsync(RetrieveRequest()));

        Assert.Equal(
            ClientMailboxTransportFailure.NetworkUnavailable,
            exception.Failure);
        Assert.True(exception.Retryable);
    }

    private static HttpClientMailboxBinaryIngress Create(
        HttpMessageHandler handler,
        TimeSpan? timeout = null)
    {
        var client = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://mailbox.test/")
        };
        var constructor = typeof(HttpClientMailboxBinaryIngress)
            .GetConstructor(
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                timeout is null
                    ? [typeof(HttpClient), typeof(MailboxClientDecodePolicy)]
                    :
                    [
                        typeof(HttpClient),
                        typeof(MailboxClientDecodePolicy),
                        typeof(TimeSpan?)
                    ],
                modifiers: null)!;
        return (HttpClientMailboxBinaryIngress)constructor.Invoke(
            timeout is null
                ? [client, Policy()]
                : [client, Policy(), timeout]);
    }

    private static HttpContent BlockingContent()
    {
        var content = new StreamContent(new BlockingReadStream());
        content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue(
                MailboxWireHttpContract.Mrp1ContentType);
        return content;
    }

    private static HttpResponseMessage Success(
        HttpRequestMessage request,
        byte[] body) =>
        new(HttpStatusCode.OK)
        {
            RequestMessage = request,
            Content = Content(body, MailboxWireHttpContract.Mrp1ContentType)
        };

    private static HttpResponseMessage Empty(
        HttpRequestMessage request,
        HttpStatusCode status) =>
        new(status)
        {
            RequestMessage = request,
            Content = new ByteArrayContent([])
        };

    private static ByteArrayContent Content(byte[] body, string contentType)
    {
        var content = new ByteArrayContent(body);
        content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
        return content;
    }

    private static byte[] RetrieveRequest()
    {
        var operationId = Bytes(16, 0x11);
        var mailbox = new BlindedMailboxId(Bytes(32, 0x21));
        var placement = new BlindedPlacementId(Bytes(32, 0x41));
        var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7,
            operationId,
            mailbox,
            placement,
            0,
            10,
            []);
        var grant = new MailboxAuthenticatedGrant
        {
            Domain = MailboxCapabilityDomain.Retrieve,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            NetworkId = Bytes(16, 0x61),
            Epoch = 7,
            Generation = 7,
            Serial = Bytes(16, 0x71),
            NotBeforeUnixSeconds = 900,
            ExpiresAtUnixSeconds = 1120,
            OverlapUntilUnixSeconds = 0,
            PlacementCommitment =
                MailboxPlacementCommitment.Compute(placement),
            MembershipCommitment = Bytes(32, 0x81),
            IssuerPublicKey = Bytes(32, 0x91),
            HolderPublicKey = Bytes(32, 0xa1),
            IssuerSignature = Bytes(64, 0xb1)
        };
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
                    Grant = grant,
                    HolderSignature = Bytes(64, 0xc1)
                }
            });
    }

    private static byte[] RetrieveResponse(int ciphertextBytes = 0)
    {
        IReadOnlyList<MailboxRetrievedEnvelope> items =
            ciphertextBytes == 0
                ? []
                :
                [
                    new MailboxRetrievedEnvelope
                    {
                        Cursor = 1,
                        Envelope = new MailboxEncryptedEnvelope
                        {
                            Epoch = 7,
                            MailboxId = new BlindedMailboxId(Bytes(32, 0x21)),
                            PlacementId = new BlindedPlacementId(Bytes(32, 0x41)),
                            OperationId = Bytes(16, 0x31),
                            DeduplicationDigest = Bytes(32, 0x51),
                            CreatedAtUnixSeconds = 1000,
                            ExpiresAtUnixSeconds = 1120,
                            Ciphertext = Bytes(ciphertextBytes, 0x61)
                        }
                    }
                ];
        return MailboxClientCodec.EncodeRetrievePage(new MailboxRetrievePage
        {
            Epoch = 7,
            OperationId = Bytes(16, 0x11),
            NextCursor = items.Count == 0 ? 0UL : 1UL,
            HasMore = false,
            ContinuationToken = Array.Empty<byte>(),
            Items = items
        });
    }

    private static MailboxClientDecodePolicy Policy() => new()
    {
        NowUnixSeconds = 1050,
        EpochWindow = new MailboxEpochWindow
        {
            CurrentEpoch = 7,
            NextEpoch = 8,
            CurrentNotBeforeUnixSeconds = 900,
            NextNotBeforeUnixSeconds = 1100,
            CurrentExpiresAtUnixSeconds = 1120,
            NextExpiresAtUnixSeconds = 1200
        },
        CapabilityPolicy = new MailboxCapabilityDecodePolicy
        {
            CurrentBucket = 1050,
            MinimumGeneration = 7
        }
    };

    private static byte[] Bytes(int count, byte start)
    {
        var bytes = new byte[count];
        for (var index = 0; index < count; index++)
        {
            bytes[index] = unchecked((byte)(start + index));
        }

        if (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            bytes[0] = 1;
        }

        return bytes;
    }

    private sealed class RecordingHandler(
        Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(respond(request));
        }
    }

    private sealed class BlockingReadStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    private sealed class ThrowingReadStream(Exception exception) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw exception;

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(exception);

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
