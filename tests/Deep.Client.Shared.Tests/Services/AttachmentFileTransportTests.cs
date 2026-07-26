using System.Net;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class AttachmentFileTransportTests
{
    [Fact]
    public async Task HttpAttachmentFileTransport_UploadsEncryptedPayloadAndDownloadsPlaintext()
    {
        var plain = Encoding.UTF8.GetBytes("attachment plaintext");
        byte[]? storedPayload = null;

        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath == "/file")
            {
                storedPayload = request.Content!.ReadAsByteArrayAsync(cancellationToken).GetAwaiter().GetResult();
                Assert.NotEqual(plain, storedPayload);
                Assert.True(storedPayload.Length > plain.Length);

                return JsonResponse("""{"id":"file-abc","expires":1781814400}""");
            }

            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath == "/file/file-abc")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(storedPayload!)
                    {
                        Headers =
                        {
                            ContentType = new("application/octet-stream")
                        }
                    }
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }))
        {
            BaseAddress = new Uri("https://file.local/")
        };

        var transport = new HttpAttachmentFileTransport(client, new HttpAttachmentFileTransportOptions("https://file.local"));
        await using var upload = new MemoryStream(plain);

        var metadata = await transport.UploadAsync(new AttachmentFileUpload("note.txt", "text/plain", upload));
        var download = await transport.DownloadAsync(metadata);

        Assert.True(metadata.IsUploaded);
        Assert.True(metadata.HasEncryptedPointer);
        Assert.Equal("file-abc", metadata.AttachmentId);
        Assert.Equal("note.txt", metadata.FileName);
        Assert.Equal("text/plain", metadata.ContentType);
        Assert.Equal(plain.Length, metadata.SizeBytes);
        Assert.False(metadata.IsDocument);
        Assert.Equal(new Uri("https://file.local/file/file-abc"), metadata.RemoteUri);
        Assert.Equal("note.txt", download.FileName);
        Assert.Equal("text/plain", download.ContentType);
        Assert.Equal(plain, download.Content);
    }

    [Fact]
    public async Task HttpAttachmentFileTransport_PreservesImageDocumentClassification()
    {
        using var client = new HttpClient(new FakeHandler((request, _) =>
            request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath == "/file"
                ? JsonResponse("""{"id":"file-image","expires":1781814400}""")
                : new HttpResponseMessage(HttpStatusCode.NotFound)))
        {
            BaseAddress = new Uri("https://file.local/")
        };

        var transport = new HttpAttachmentFileTransport(client, new HttpAttachmentFileTransportOptions("https://file.local"));
        await using var upload = new MemoryStream([1, 2, 3, 4]);

        var metadata = await transport.UploadAsync(new AttachmentFileUpload(
            "diagram.png",
            "image/png",
            upload,
            Width: 400,
            Height: 240,
            IsDocument: true));

        Assert.True(metadata.IsDocument);
        Assert.Equal(400, metadata.Width);
        Assert.Equal(240, metadata.Height);
        Assert.Equal("image/png", metadata.ContentType);
    }

    [Theory]
    [InlineData("https://other.local/file/file-abc")]
    [InlineData("http://file.local/file/file-abc")]
    [InlineData("https://user:password@file.local/file/file-abc")]
    [InlineData("https://file.local:22/file/file-abc")]
    [InlineData("https://file.local/admin/file-abc")]
    [InlineData("https://file.local/file/%66ile-abc")]
    public async Task HttpAttachmentFileTransport_RejectsUnsafeInboundRemoteUri(string remoteUri)
    {
        using var client = new HttpClient(new FakeHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(Encoding.UTF8.GetBytes("unexpected"))
            }))
        {
            BaseAddress = new Uri("https://file.local/")
        };
        var transport = new HttpAttachmentFileTransport(
            client,
            new HttpAttachmentFileTransportOptions("https://file.local"));
        var metadata = new AttachmentMetadata(
            "file-abc",
            "note.txt",
            "text/plain",
            10,
            new Uri(remoteUri));

        await Assert.ThrowsAsync<InvalidOperationException>(() => transport.DownloadAsync(metadata));
    }

    [Fact]
    public async Task HttpAttachmentFileTransport_AllowsLoopbackHttpForLocalTests()
    {
        var plain = Encoding.UTF8.GetBytes("loopback attachment");
        using var client = new HttpClient(new FakeHandler((request, _) =>
        {
            Assert.Equal("http://127.0.0.1:18082/file/file-abc", request.RequestUri?.ToString());
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(plain)
            };
        }))
        {
            BaseAddress = new Uri("http://127.0.0.1:18082/")
        };
        var transport = new HttpAttachmentFileTransport(
            client,
            new HttpAttachmentFileTransportOptions("http://127.0.0.1:18082"));
        var metadata = new AttachmentMetadata(
            "file-abc",
            "note.txt",
            "text/plain",
            plain.Length,
            new Uri("http://127.0.0.1:18082/file/file-abc"));

        var download = await transport.DownloadAsync(metadata);

        Assert.Equal(plain, download.Content);
    }

    [Fact]
    public async Task HttpAttachmentFileTransport_RoundTripsThroughLiveFileService_WhenConfigured()
    {
        var fileUrl = Environment.GetEnvironmentVariable("DEEP_FILE_URL");
        if (string.IsNullOrWhiteSpace(fileUrl))
        {
            return;
        }

        var plain = Encoding.UTF8.GetBytes($"live-file-{Guid.NewGuid():N}");
        var transport = new HttpAttachmentFileTransport(
            new HttpClient(),
            new HttpAttachmentFileTransportOptions(fileUrl));
        await using var upload = new MemoryStream(plain);

        var metadata = await transport.UploadAsync(new AttachmentFileUpload("live.txt", "text/plain", upload));
        var download = await transport.DownloadAsync(metadata);

        Assert.True(metadata.IsUploaded);
        Assert.True(metadata.HasEncryptedPointer);
        Assert.Equal(plain.Length, metadata.SizeBytes);
        Assert.Equal(plain, download.Content);
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
