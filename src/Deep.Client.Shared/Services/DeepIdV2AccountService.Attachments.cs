using Deep.Client.Shared.Services.AttachmentV1;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    internal async Task<OwnedDeepSecret> ReadOwnAttachmentPlaintextAsync(ReadOnlyMemory<byte> operation,
        CancellationToken cancellationToken)
    {
        using var asset = await ReadOwnAttachmentAsync(operation, cancellationToken).ConfigureAwait(false);
        return asset.MaterializePlaintext(cancellationToken);
    }

    internal async Task<OwnedAttachmentPreparation> ReadOwnAttachmentAsync(ReadOnlyMemory<byte> operation, CancellationToken cancellationToken)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadLocalAttachmentAsync(TrustedUnixSeconds(), verifier, operation, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<OwnedAttachmentPreparation> PrepareOwnAttachmentAsync(ReadOnlyMemory<byte> operation,
        Stream plaintext, long plaintextLength, string filename, string mediaType, ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        using var verifier = OpenVerifier();
        return await owner.PrepareLocalAttachmentAsync(TrustedUnixSeconds(), verifier, operation,
            plaintext, plaintextLength, filename, mediaType, expiresAtUnixSeconds, cancellationToken).ConfigureAwait(false);
    }
}
