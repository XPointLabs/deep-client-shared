using System.Net;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class AvatarProfileTransportTests
{
    [Fact]
    public async Task HttpAvatarProfileTransport_UsesAvatarBackendContract()
    {
        using var identity = new SessionIdentityProvider(
            "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed");
        var sessionId = identity.SessionId;
        var avatarBytes = new byte[] { 0x89, 0x50, 0x4e, 0x47, 0x01 };
        var seenUpload = false;

        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            var expectedPath = $"/avatar/{sessionId.Value}";
            if (request.Method == HttpMethod.Put && request.RequestUri!.AbsolutePath == expectedPath)
            {
                seenUpload = true;
                Assert.Equal("image/png", request.Content!.Headers.ContentType?.MediaType);
                var uploaded = request.Content.ReadAsByteArrayAsync(cancellationToken).GetAwaiter().GetResult();
                Assert.Equal(avatarBytes, uploaded);
                var ed25519 = request.Headers.GetValues("X-Deep-Ed25519").Single();
                var timestamp = long.Parse(request.Headers.GetValues("X-Deep-Timestamp").Single());
                var nonce = request.Headers.GetValues("X-Deep-Nonce").Single();
                var digest = request.Headers.GetValues("X-Deep-Content-Sha256").Single();
                var signature = Convert.FromBase64String(request.Headers.GetValues("X-Deep-Signature").Single());
                Assert.Equal(sessionId.Value, request.Headers.GetValues("X-Deep-Session-Id").Single());
                Assert.Equal(Convert.ToHexString(SHA256.HashData(avatarBytes)).ToLowerInvariant(), digest);
                Assert.True(PublicKeyAuth.VerifyDetached(
                    signature,
                    AvatarProfileAuthentication.BuildUploadPayload(
                        expectedPath,
                        sessionId,
                        ed25519,
                        timestamp,
                        nonce,
                        digest),
                    Convert.FromHexString(ed25519)));

                return JsonResponse("""
                {
                  "sessionId": "SESSION_ID",
                  "fileId": "file-123",
                  "contentType": "image/png",
                  "size": 5,
                  "updated": 1780000000,
                  "expires": 1781814400
                }
                """.Replace("SESSION_ID", sessionId.Value, StringComparison.Ordinal));
            }

            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath == $"{expectedPath}/info")
            {
                return JsonResponse("""
                {
                  "sessionId": "SESSION_ID",
                  "fileId": "file-123",
                  "contentType": "image/png",
                  "size": 5,
                  "updated": 1780000000,
                  "expires": 1781814400
                }
                """.Replace("SESSION_ID", sessionId.Value, StringComparison.Ordinal));
            }

            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath == expectedPath)
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(avatarBytes)
                    {
                        Headers =
                        {
                            ContentType = new("image/png")
                        }
                    }
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }))
        {
            BaseAddress = new Uri("https://file.local/")
        };

        var transport = new HttpAvatarProfileTransport(
            client,
            new HttpAvatarProfileTransportOptions("https://file.local"),
            new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_780_000_000_000)));

        await using var uploadStream = new MemoryStream(avatarBytes);
        var uploadedMetadata = await transport.UploadAsync(identity, uploadStream, "image/png");
        var infoMetadata = await transport.TryGetInfoAsync(sessionId);
        var image = await transport.TryDownloadAsync(sessionId);

        Assert.True(seenUpload);
        Assert.Equal("file-123", uploadedMetadata.FileId);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1780000000), uploadedMetadata.UpdatedAt);
        Assert.Equal(uploadedMetadata, infoMetadata);
        Assert.NotNull(image);
        Assert.Equal("image/png", image.ContentType);
        Assert.Equal(avatarBytes, image.Content);
    }

    [Fact]
    public async Task ClientRuntime_CreateStubbed_DisablesAvatarProfilesByDefault()
    {
        var runtime = ClientRuntime.CreateStubbed();

        Assert.False(runtime.AvatarProfiles.IsEnabled);
        Assert.Null(await runtime.AvatarProfiles.TryGetInfoAsync(SessionId.CreateNew()));
    }

    [Fact]
    public async Task TryDownloadAsync_RejectsOversizedChunkedAvatar()
    {
        var sessionId = SessionId.CreateNew();
        using var client = new HttpClient(new FakeHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new UnknownLengthContent(new byte[1_025])
        }))
        {
            BaseAddress = new Uri("https://file.local/")
        };
        var transport = new HttpAvatarProfileTransport(
            client,
            new HttpAvatarProfileTransportOptions("https://file.local", MaxAvatarBytes: 1_024));

        await Assert.ThrowsAsync<HttpRequestException>(() => transport.TryDownloadAsync(sessionId));
    }

    private static HttpResponseMessage JsonResponse(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler;

        public FakeHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler)
        {
            this.handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(handler(request, cancellationToken));
    }

    private sealed class UnknownLengthContent(byte[] content) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(content).AsTask();

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
