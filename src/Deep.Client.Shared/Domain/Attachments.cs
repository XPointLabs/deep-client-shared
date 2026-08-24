namespace Deep.Client.Shared.Domain;

public enum AttachmentKind : byte
{
    File = 0,
    VoiceMessage = 1
}

public sealed record AttachmentMetadata(
    string AttachmentId,
    string FileName,
    string ContentType,
    long SizeBytes,
    Uri? RemoteUri = null,
    string? EncryptionKeyBase64 = null,
    string? DigestBase64 = null,
    int? Width = null,
    int? Height = null,
    TimeSpan? Duration = null,
    bool IsDocument = false,
    AttachmentKind Kind = AttachmentKind.File)
{
    public bool IsUploaded => RemoteUri is not null;

    public bool HasEncryptedPointer => RemoteUri is not null && !string.IsNullOrWhiteSpace(EncryptionKeyBase64);

    public static AttachmentMetadata Local(
        string fileName,
        string contentType,
        long sizeBytes,
        int? width = null,
        int? height = null,
        TimeSpan? duration = null,
        bool isDocument = false,
        AttachmentKind kind = AttachmentKind.File) =>
        new(
            Guid.NewGuid().ToString("n"),
            fileName,
            contentType,
            sizeBytes,
            Width: width,
            Height: height,
            Duration: duration,
            IsDocument: isDocument,
            Kind: kind);
}
