using System.Net;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Services;

public sealed class AvatarProfileTransportTests
{
    [Fact]
    public async Task HttpAvatarProfileTransport_UsesAvatarBackendContract()
    {
        var sessionId = SessionId.CreateNew();
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
            BaseAddress = new Uri("http://file.local/")
        };

        var transport = new HttpAvatarProfileTransport(client, new HttpAvatarProfileTransportOptions("http://file.local"));

        await using var uploadStream = new MemoryStream(avatarBytes);
        var uploadedMetadata = await transport.UploadAsync(sessionId, uploadStream, "image/png");
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
}
