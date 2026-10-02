using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed class AttachmentTransportCleanBreakTests
{
    [Fact]
    public void AssemblyCannotConstructTheRetiredFileProtocol()
    {
        var assembly = typeof(IAttachmentFileTransport).Assembly;
        Assert.Null(assembly.GetType("Deep.Client.Shared.Services.HttpAttachmentFileTransport"));
        Assert.Null(assembly.GetType("Deep.Client.Shared.Services.HttpAttachmentFileTransportOptions"));
        Assert.DoesNotContain(typeof(HttpServiceTransportFactory).GetMethods(), method => method.Name == "CreateAttachment");
    }

    [Fact]
    public async Task UncomposedTransportNeverTouchesCallerStreams()
    {
        using var stream = new UntouchableStream();
        var transport = new DisabledAttachmentFileTransport();
        var metadata = AttachmentMetadata.Local("photo.png", "image/png", 1);
        Assert.False(transport.IsEnabled);
        await Assert.ThrowsAsync<NotSupportedException>(() => transport.UploadAsync(new("photo.png", "image/png", stream)));
        await Assert.ThrowsAsync<NotSupportedException>(() => transport.DownloadAsync(metadata));
        await Assert.ThrowsAsync<NotSupportedException>(() => transport.DownloadToAsync(metadata, stream));
        Assert.Equal(0, stream.Touches);
    }

    private sealed class UntouchableStream : Stream
    {
        public int Touches { get; private set; }
        private Exception Touch() { Touches++; return new InvalidOperationException("An unavailable transport must not inspect streams."); }
        public override bool CanRead => throw Touch();
        public override bool CanSeek => throw Touch();
        public override bool CanWrite => throw Touch();
        public override long Length => throw Touch();
        public override long Position { get => throw Touch(); set => throw Touch(); }
        public override void Flush() => throw Touch();
        public override int Read(byte[] buffer, int offset, int count) => throw Touch();
        public override long Seek(long offset, SeekOrigin origin) => throw Touch();
        public override void SetLength(long value) => throw Touch();
        public override void Write(byte[] buffer, int offset, int count) => throw Touch();
    }
}
