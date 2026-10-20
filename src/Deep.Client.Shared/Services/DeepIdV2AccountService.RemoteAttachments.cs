using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.AttachmentV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.BlobV1;

namespace Deep.Client.Shared.Services;

public sealed record DeepIdV2PreparedAttachment(string Operation, string ObjectId, ulong Bytes, string PlaintextSha256, ulong ExpiresAtUnixSeconds);
public sealed record DeepIdV2AttachmentSnapshot(string LogicalId, string AuthorDeviceId, string ObjectId,
    string Filename, string MediaType, ulong Bytes, bool IsLocalAuthor, ulong ExpiresAtUnixSeconds);
public sealed record DeepIdV2DownloadedAttachment(string Filename, string MediaType, ulong Bytes, string PlaintextSha256);
public sealed record DeepIdV2AttachmentOperationSnapshot(string Operation, string ConversationId, string ObjectId, bool Stored, bool WorkStopped);

public sealed partial class DeepIdV2AccountService
{
    public async Task<IReadOnlyList<DeepIdV2AttachmentOperationSnapshot>> ListPendingAttachmentOperationsAsync(CancellationToken ct = default)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadPendingAttachmentOperationsAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<DeepIdV2AttachmentOperationSnapshot>> ListAttachmentOperationsAsync(CancellationToken ct = default)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadAttachmentOperationsAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false);
    }

    public async Task<ReadOnlyMemory<byte>> QueueAttachmentAsync(DeepIdV2Conversation conversation,
        ReadOnlyMemory<byte> assetOperation, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); source.RequireAccountOwner(this);
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        await RequireAttachmentConsentAsync(conversation, source, ct).ConfigureAwait(false);
        using var draft = await CreateOwnDirectAttachmentOfferAsync(conversation.Scope, assetOperation, source, ct).ConfigureAwait(false);
        return draft.OperationId.ToArray();
    }

    private async Task RequireAttachmentConsentAsync(DeepIdV2Conversation conversation, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var state = await ReadOwnContactAcceptanceAsync(conversation.Scope, source, ct).ConfigureAwait(false);
        if (conversation.IsInitiator ? state != Did2ContactAcceptanceState.PeerAcceptanceRetained : state != Did2ContactAcceptanceState.LocalAcceptanceRetained)
            throw new InvalidOperationException("An attachment requires retained explicit contact consent.");
    }

    public async Task<DeepIdV2PreparedAttachment> PrepareAttachmentAsync(ReadOnlyMemory<byte> operation, Stream plaintext,
        long length, string filename, string mediaType, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        source.RequireAccountOwner(this);
        using var verifier = OpenVerifier();
        using var existing = await owner.TryReadLocalAttachmentAsync(TrustedUnixSeconds(), verifier, operation, ct).ConfigureAwait(false);
        ulong expiry;
        if (existing is not null)
        {
            using var retained = existing.OwnManifest(); using var manifest = retained.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
            expiry = manifest.ExpiresAtUnixSeconds;
        }
        else
        {
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            expiry = checked(own.Proof.TrustedLowerUnixSeconds + BlobChunkCodec.MaximumRetentionSeconds);
        }
        using var asset = await PrepareOwnAttachmentAsync(operation, plaintext, length, filename, mediaType, expiry, ct).ConfigureAwait(false);
        using var exact = asset.OwnManifest(); using var parsed = exact.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
        return new(Convert.ToHexStringLower(operation.Span), Convert.ToHexStringLower(parsed.ObjectId.Span),
            parsed.TotalPlaintextBytes, Convert.ToHexStringLower(asset.PlaintextHash), parsed.ExpiresAtUnixSeconds);
    }

    public async Task<ClientMailboxStoreResult> SendAttachmentAsync(DeepIdV2Conversation conversation,
        ReadOnlyMemory<byte> assetOperation, ReadOnlyMemory<byte> offerOperation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); source.RequireAccountOwner(this);
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        await RequireAttachmentConsentAsync(conversation, source, ct).ConfigureAwait(false);
        using var asset = await ReadOwnAttachmentAsync(assetOperation, ct).ConfigureAwait(false);
        using var manifestBytes = asset.OwnManifest(); using var manifest = manifestBytes.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
        var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using (var verifier = OpenVerifier())
        {
            var retained = await owner.ReadRetainedDirectAttachmentStoreAsync(TrustedUnixSeconds(), verifier, conversation.Scope,
                offerOperation, manifest, own, source, ct).ConfigureAwait(false);
            if (retained is not null) return retained;
        }
        using var draft = await PrepareOwnDirectAttachmentOfferAsync(conversation.Scope, offerOperation, assetOperation, source, ct).ConfigureAwait(false);
        var custody = await OpenOwnOnionClientCustodyAsync(ct).ConfigureAwait(false);
        await new Did2BlobOnionTransport(source, custody).UploadAsync(asset, ct).ConfigureAwait(false);
        var exact = OwnedByteExports.TakeArray(draft.ExactDmc2);
        try
        {
            using var sent = await SendOwnMessagingAsync(conversation.Scope, offerOperation, exact, source, ct).ConfigureAwait(false);
            return await DeliverOwnMessagingAsync(conversation.Scope, offerOperation, source, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    public async Task<IReadOnlyList<DeepIdV2AttachmentSnapshot>> ListAttachmentsAsync(DeepIdV2Conversation conversation, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        return (await ListOwnMessagingAttachmentOffersAsync(conversation.Scope, ct).ConfigureAwait(false)).Select(item =>
            new DeepIdV2AttachmentSnapshot(Convert.ToHexStringLower(item.LogicalId.Span), Convert.ToHexStringLower(item.AuthorDeviceId.Span),
                Convert.ToHexStringLower(item.ObjectId.Span), item.Filename, item.MediaType, item.PlaintextBytes,
                item.IsLocalAuthor, item.ExpiresAtUnixSeconds)).ToArray();
    }

    public async Task<DeepIdV2DownloadedAttachment> DownloadAttachmentAsync(DeepIdV2Conversation conversation,
        ReadOnlyMemory<byte> logicalId, ReadOnlyMemory<byte> authorDeviceId, Stream destination,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite) throw new ArgumentException("Attachment destination must be writable.");
        source.RequireAccountOwner(this);
        _ = await source.VerifyForOwnMessagingAsync(this, conversation.Scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        using var exact = await owner.ReadReceivedAttachmentManifestAsync(TrustedUnixSeconds(), verifier, conversation.Scope, logicalId, authorDeviceId, ct).ConfigureAwait(false);
        using var manifest = exact.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
        var custody = await OpenOwnOnionClientCustodyAsync(ct).ConfigureAwait(false);
        var ciphertext = await new Did2BlobOnionTransport(source, custody).DownloadAsync(manifest, ct).ConfigureAwait(false);
        var plaintext = new byte[checked((int)manifest.TotalPlaintextBytes)];
        try
        {
            var at = 0;
            for (uint index = 0; index < manifest.ChunkCount; index++)
            {
                ct.ThrowIfCancellationRequested();
                var chunk = AttachmentChunkCipher.Decrypt(manifest, index, ciphertext[index]);
                try { chunk.CopyTo(plaintext, at); at = checked(at + chunk.Length); }
                finally { CryptographicOperations.ZeroMemory(chunk); }
            }
            if (at != plaintext.Length) throw new CryptographicException("Attachment object is incomplete.");
            var digest = Convert.ToHexStringLower(SHA256.HashData(plaintext));
            _ = await source.VerifyForOwnMessagingAsync(this, conversation.Scope, ct).ConfigureAwait(false);
            using var retained = await owner.ReadReceivedAttachmentManifestAsync(TrustedUnixSeconds(), verifier, conversation.Scope, logicalId, authorDeviceId, ct).ConfigureAwait(false);
            var original = exact.Use(bytes => bytes.ToArray());
            try { if (!retained.Use(bytes => CryptographicOperations.FixedTimeEquals(bytes, original))) throw new CryptographicException("Received attachment custody changed during download."); }
            finally { CryptographicOperations.ZeroMemory(original); }
            ct.ThrowIfCancellationRequested();
            // No byte reaches the caller until every commitment and AEAD tag,
            // complete geometry and current owned receive custody passed.
            await destination.WriteAsync(plaintext, ct).ConfigureAwait(false);
            return new(manifest.Filename, manifest.MediaType, manifest.TotalPlaintextBytes, digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            foreach (var chunk in ciphertext) CryptographicOperations.ZeroMemory(chunk);
        }
    }
}
