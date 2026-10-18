using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.BlobV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.AttachmentV1;

internal sealed class Did2BlobOnionTransport(DeepIdV2ContactPathAuthoritySource source, DeepIdV2OnionClientCustody custody)
{
    internal async Task UploadAsync(OwnedAttachmentPreparation asset, CancellationToken ct)
    {
        using var exact = asset.OwnManifest(); using var manifest = exact.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(custody.Owner, ct).ConfigureAwait(false);
        var replicas = OnionPathContextFactory.BlobNodeIds(fresh.Network, manifest.ObjectId).Take(2).ToArray();
        foreach (var replica in replicas)
            for (uint index = 0; index < manifest.ChunkCount; index++)
            {
                var ciphertext = asset.CopyCiphertext(index);
                try
                {
                    var response = await ExchangeAsync(manifest, BlobChunkOperation.Put, index, replica, ciphertext, ct).ConfigureAwait(false);
                    if (response.Status is not (BlobChunkStatus.Stored or BlobChunkStatus.ExactReplay)) throw new IOException("Blob upload has no authenticated durable result.");
                }
                finally { CryptographicOperations.ZeroMemory(ciphertext); }
            }
    }

    internal async Task<byte[][]> DownloadAsync(ParsedDam1 manifest, CancellationToken ct)
    {
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(custody.Owner, ct).ConfigureAwait(false);
        var nodes = OnionPathContextFactory.BlobNodeIds(fresh.Network, manifest.ObjectId);
        var chunks = new byte[manifest.ChunkCount][];
        try
        {
            for (uint index = 0; index < manifest.ChunkCount; index++)
            {
                foreach (var node in nodes)
                {
                    var result = await ExchangeAsync(manifest, BlobChunkOperation.Get, index, node, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
                    if (result.Status == BlobChunkStatus.Missing) continue;
                    if (result.Status != BlobChunkStatus.Chunk) throw new IOException("Blob download has no current authenticated chunk.");
                    chunks[index] = result.Ciphertext.ToArray(); break;
                }
                if (chunks[index] is null) throw new IOException("Blob ciphertext is missing from the bounded current cohort.");
            }
            return chunks;
        }
        catch { foreach (var chunk in chunks) if (chunk is not null) CryptographicOperations.ZeroMemory(chunk); throw; }
    }

    private async Task<BlobChunkResponse> ExchangeAsync(ParsedDam1 manifest, BlobChunkOperation operation,
        uint index, ReadOnlyMemory<byte> exit, ReadOnlyMemory<byte> ciphertext, CancellationToken ct)
    {
        source.RequireAccountOwner(custody.Owner);
        var exact = BlobChunkCodec.EncodeRequest(manifest, operation, index, ciphertext.Span);
        try
        {
            using var parsed = BlobChunkCodec.DecodeRequest(exact);
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(custody.Owner, ct).ConfigureAwait(false);
            var attempt = await new ContactResolvePrivacyPathProvider(source, custody.Guards).PrepareBlobAsync(fresh.Network, exact, exit, ct).ConfigureAwait(false);
            var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(custody.Entropy), new OnionKeyAgreementAuthority(new NoReceiveVault()));
            using var built = await codec.BuildAsync(attempt.Path, attempt.Request, ct).ConfigureAwait(false);
            using var transport = new PrivacyManagedIngressHttpTransport(OnionEntryTransportFactory.Create(attempt.Path));
            await source.RecheckOwnPreKeyAuthoringAsync(fresh, ct).ConfigureAwait(false);
            var reply = await DeepIdV2PublicationOnionTransport.ForwardOnceAsync(transport, built.Frame, ct).ConfigureAwait(false);
            var opened = await codec.OpenResponseAsync(reply, built.ReplyContext, ct).ConfigureAwait(false);
            if (opened.Result.Operation != OnionOperation.Blob || opened.Result.Kind != OnionTerminalResultKind.Success)
                throw new ClientMailboxDispatchOutcomeUnknownException("Blob transport has no authenticated successful terminal response.");
            await source.RecheckOwnPreKeyAuthoringAsync(fresh, ct).ConfigureAwait(false);
            return BlobChunkCodec.DecodeResponse(parsed, opened.Result.Body.Span);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
    private sealed class NoReceiveVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(OnionKeyHandle handle, ReadOnlyMemory<byte> peer, CancellationToken ct) =>
            ValueTask.FromException<byte[]>(new NotSupportedException("Client has no node receive-key custody."));
    }
}
