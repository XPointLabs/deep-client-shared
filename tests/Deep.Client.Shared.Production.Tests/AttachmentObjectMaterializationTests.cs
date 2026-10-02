using System.Security.Cryptography;
using Deep.Client.Shared.Services.AttachmentV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

// Real frozen chunk crypto and local owned custody, not BLOB/device evidence.
public sealed class AttachmentObjectMaterializationTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(262144)]
    [InlineData(262145)]
    [InlineData(26214400)]
    public async Task CompleteObjectMatchesOriginalIncludingMaximumSize(int size)
    {
        var source = new byte[size];
        for (var i = 0; i < source.Length; i++) source[i] = (byte)(i * 17);
        using var prepared = await Prepare(source);
        using var plaintext = prepared.MaterializePlaintext(default);
        Assert.Equal(size, plaintext.Length);
        Assert.True(plaintext.Use(bytes => bytes.SequenceEqual(source)));
        // Result ownership is independent of ciphertext/preparation ownership.
        prepared.Dispose();
        Assert.True(plaintext.Use(bytes => bytes.SequenceEqual(source)));
        plaintext.Dispose();
        Assert.Throws<ObjectDisposedException>(() => plaintext.Use(bytes => bytes.Length));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("reordered")]
    [InlineData("truncated")]
    [InlineData("corrupt-final")]
    public async Task IncompleteOrChangedCiphertextNeverReleasesPlaintext(string mutation)
    {
        using var original = await Prepare(new byte[262145]);
        using var exact = original.OwnManifest();
        var chunks = Enumerable.Range(0, original.ChunkCount).Select(i => original.CopyCiphertext((uint)i)).ToArray();
        switch (mutation)
        {
            case "missing": CryptographicOperations.ZeroMemory(chunks[^1]); chunks = chunks[..^1]; break;
            case "extra": chunks = [.. chunks, chunks[0].ToArray()]; break;
            case "reordered": Array.Reverse(chunks); break;
            case "truncated":
                var shortened = chunks[^1][..^1]; CryptographicOperations.ZeroMemory(chunks[^1]); chunks[^1] = shortened; break;
            case "corrupt-final": chunks[^1][0] ^= 1; break;
        }
        using var changed = exact.Use(bytes => new OwnedAttachmentPreparation(bytes, chunks, original.PlaintextHash));
        Assert.Throws<CryptographicException>(() => changed.MaterializePlaintext(default));
        // Reading never edits even a rejected adopted ciphertext scope.
        Assert.Equal(chunks[0], changed.CopyCiphertext(0));
    }

    [Fact]
    public async Task MatchingCiphertextHashesCannotBypassAeadOrProtectedPlaintextDigest()
    {
        using var original = await Prepare([1, 2, 3]);
        using var exact = original.OwnManifest();
        using var manifest = exact.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
        var wrongKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var altered = ApplicationCoreCodec.AuthorDam1(manifest.NetworkId.Span, manifest.ObjectId.Span,
                manifest.BlobCapability.Span, wrongKey, manifest.TotalPlaintextBytes, manifest.Chunks,
                manifest.ExpiresAtUnixSeconds, manifest.Filename, manifest.MediaType);
            // Same ciphertext/commitment, changed key: the actual AEAD must reject.
            using var badKey = new OwnedAttachmentPreparation(altered.CanonicalBytes.Span,
                [original.CopyCiphertext(0)], original.PlaintextHash);
            Assert.Throws<CryptographicException>(() => badKey.MaterializePlaintext(default));
            using var badDigest = exact.Use(bytes => new OwnedAttachmentPreparation(bytes,
                [original.CopyCiphertext(0)], new byte[32]));
            Assert.Throws<CryptographicException>(() => badDigest.MaterializePlaintext(default));
            using var shortDigest = exact.Use(bytes => new OwnedAttachmentPreparation(bytes,
                [original.CopyCiphertext(0)], new byte[31]));
            Assert.Throws<CryptographicException>(() => shortDigest.MaterializePlaintext(default));
        }
        finally { CryptographicOperations.ZeroMemory(wrongKey); }
    }

    [Fact]
    public async Task CancelledOrDisposedPreparationCannotReleaseContents()
    {
        using var prepared = await Prepare([1]);
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => prepared.MaterializePlaintext(cancellation.Token));
        using var valid = prepared.MaterializePlaintext(default);
        Assert.Equal(1, valid.Use(bytes => bytes.Length));
        prepared.Dispose();
        Assert.Throws<ObjectDisposedException>(() => prepared.MaterializePlaintext(default));
    }

    private static Task<OwnedAttachmentPreparation> Prepare(byte[] bytes) => AttachmentObjectPreparation.PrepareAsync(
        new MemoryStream(bytes, false), bytes.Length, new byte[16], "photo.png", "image/png", 2_000_000_000, default);
}
