using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

// UI file-I/O boundary only. DID2 blob custody and delivery must be composed
// explicitly; a file-service URL cannot authorize attachment transport.
public sealed record AttachmentFileUpload(
    string FileName,
    string ContentType,
    Stream Content,
    int? Width = null,
    int? Height = null,
    TimeSpan? Duration = null,
    bool IsDocument = false,
    AttachmentKind Kind = AttachmentKind.File);

public sealed record AttachmentFileDownload(string FileName, string ContentType, byte[] Content);
public sealed record AttachmentFileDownloadInfo(string FileName, string ContentType);

public interface IAttachmentFileTransport
{
    bool IsEnabled { get; }
    Task<AttachmentMetadata> UploadAsync(AttachmentFileUpload upload, CancellationToken cancellationToken = default);
    Task<AttachmentFileDownload> DownloadAsync(AttachmentMetadata metadata, CancellationToken cancellationToken = default);
    Task<AttachmentFileDownloadInfo> DownloadToAsync(
        AttachmentMetadata metadata, Stream destination, CancellationToken cancellationToken = default);
}

public sealed class DisabledAttachmentFileTransport : IAttachmentFileTransport
{
    private const string Reason = "DID2 encrypted blob transport is not composed yet.";
    public bool IsEnabled => false;
    public Task<AttachmentMetadata> UploadAsync(AttachmentFileUpload upload, CancellationToken cancellationToken = default) =>
        Task.FromException<AttachmentMetadata>(new NotSupportedException(Reason));
    public Task<AttachmentFileDownload> DownloadAsync(AttachmentMetadata metadata, CancellationToken cancellationToken = default) =>
        Task.FromException<AttachmentFileDownload>(new NotSupportedException(Reason));
    public Task<AttachmentFileDownloadInfo> DownloadToAsync(
        AttachmentMetadata metadata, Stream destination, CancellationToken cancellationToken = default) =>
        Task.FromException<AttachmentFileDownloadInfo>(new NotSupportedException(Reason));
}
