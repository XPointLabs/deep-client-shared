using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2MailboxApplicationRetryDeadlineTests
{
    [Theory]
    [InlineData(0UL, ulong.MaxValue)]
    [InlineData(2000UL, 2UL)]
    [InlineData(2001UL, 2UL)]
    public void ReadingAnOwnedAttachmentDeadlineDisposesOnlyTheDecodedManifest(ulong expiry, ulong expected)
    {
        using var manifest = ApplicationCoreCodec.AuthorDam1(
            Bytes(16, 1), Bytes(32, 2), Bytes(32, 3), Bytes(32, 4), 1,
            new[] { new Dam1ChunkEntry(0, 17, Bytes(32, 5)) }, 2000, "owned.bin", "application/octet-stream");
        var record = ApplicationCoreCodec.AuthorDmc2(Bytes(16, 1), Bytes(32, 6), Bytes(32, 7),
            Bytes(32, 8), Bytes(32, 9), 3, 1000, expiry, Dmc2Flags.None, [],
            ApplicationCoreCodec.CreateAttachmentOfferPayload(manifest));
        using var decodedManifest = Assert.IsType<AttachmentOfferDmc2Payload>(record.ParsedPayload).Manifest;
        Assert.NotSame(manifest, decodedManifest);
        Assert.Equal(expected, ProtectedDeepIdV2AccountOwner.ApplicationRetryUntil(record));
        Assert.Throws<ObjectDisposedException>(() => { _ = decodedManifest.CanonicalBytes; });
        Assert.Throws<ObjectDisposedException>(() => { _ = record.CanonicalBytes; });
        Assert.Throws<ObjectDisposedException>(() => { _ = record.PayloadBytes; });
        var borrowed = OwnedByteExports.TakeArray(manifest.CanonicalBytes);
        try { Assert.True(borrowed.AsSpan().IndexOfAnyExcept((byte)0) >= 0); }
        finally { CryptographicOperations.ZeroMemory(borrowed); }
    }

    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
}
