namespace Deep.Client.Shared.Domain;

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
    TimeSpan? Duration = null)
{
    public bool IsUploaded => RemoteUri is not null;

    public bool HasEncryptedPointer => RemoteUri is not null && !string.IsNullOrWhiteSpace(EncryptionKeyBase64);

    public static AttachmentMetadata Local(string fileName, string contentType, long sizeBytes) =>
        new(Guid.NewGuid().ToString("n"), fileName, contentType, sizeBytes);
}
