using Deep.Client.Shared.Services.AttachmentV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed class AttachmentObjectPreparationTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(262145)]
    public async Task OwnedExactChunksSurviveCopiesAndDecryptAcrossShortReads(int size)
    {
        var source = Enumerable.Range(0, size).Select(i => (byte)i).ToArray();
        using var input = new ShortInput(source);
        using var prepared = await AttachmentObjectPreparation.PrepareAsync(input, size, new byte[16],
            "photo.png", "image/png", 2_000_000_000, CancellationToken.None);
        Assert.Equal((size + 262143) / 262144, prepared.ChunkCount);
        using var manifestOwner = prepared.OwnManifest();
        var manifest = manifestOwner.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
        var offset = 0;
        for (uint index = 0; index < prepared.ChunkCount; index++)
        {
            var cipher = prepared.CopyCiphertext(index);
            var copy = prepared.CopyCiphertext(index); cipher[0] ^= 1;
            Assert.Equal(copy, prepared.CopyCiphertext(index));
            var plain = AttachmentChunkCipher.Decrypt(manifest, index, copy);
            Assert.Equal(source.AsSpan(offset, plain.Length).ToArray(), plain); offset += plain.Length;
        }
        Assert.Equal(size, offset);
        prepared.Dispose();
        Assert.Throws<ObjectDisposedException>(() => prepared.CopyCiphertext(0));
        Assert.Throws<ObjectDisposedException>(() => prepared.OwnManifest());
        // A separately owned manifest remains valid until its own disposal.
        Assert.Equal("photo.png", manifestOwner.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes).Filename));
    }

    [Fact]
    public async Task FreshPreparationDoesNotReencryptWithPreviousObjectScope()
    {
        using var a = await AttachmentObjectPreparation.PrepareAsync(new MemoryStream([1]), 1, new byte[16], "", "", 1, CancellationToken.None);
        using var b = await AttachmentObjectPreparation.PrepareAsync(new MemoryStream([2]), 1, new byte[16], "", "", 1, CancellationToken.None);
        using var am = a.OwnManifest(); using var bm = b.OwnManifest();
        Assert.NotEqual(am.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes).ObjectId.ToArray()),
            bm.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes).ObjectId.ToArray()));
        Assert.NotEqual(a.CopyCiphertext(0), b.CopyCiphertext(0));
    }

    [Fact]
    public async Task DeclaredLengthMetadataAndCancellationReject()
    {
        using var input = new MemoryStream([1]);
        Task<OwnedAttachmentPreparation> Prepare(long size, string name = "ok") =>
            AttachmentObjectPreparation.PrepareAsync(input, size, new byte[16], name, "image/png", 1, CancellationToken.None);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Prepare(0));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Prepare(26214401));
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(() => Prepare(1, "../file"));
        Assert.Equal(0, input.Position);
        await Assert.ThrowsAsync<EndOfStreamException>(() => Prepare(2));
        input.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => AttachmentObjectPreparation.PrepareAsync(
            new MemoryStream([1, 2]), 1, new byte[16], "", "", 1, CancellationToken.None));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AttachmentObjectPreparation.PrepareAsync(input,
            1, new byte[16], "", "", 1, cancelled.Token));
    }

    private sealed class ShortInput(byte[] input) : MemoryStream(input, false)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
            base.ReadAsync(buffer[..Math.Min(37, buffer.Length)], ct);
    }
}
