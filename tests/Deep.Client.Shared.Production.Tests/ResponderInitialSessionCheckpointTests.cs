using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ResponderInitialSessionCheckpointTests
{
    private static readonly byte[] Instance = Enumerable.Repeat((byte)1, 32).ToArray();
    private static readonly byte[] Account = Enumerable.Repeat((byte)2, 32).ToArray();
    private static readonly byte[] Network = Enumerable.Repeat((byte)3, 16).ToArray();

    [Fact]
    public void ReceiverCheckpoint_StablePendingScopeAndExactHashHaveClosedBounds()
    {
        var empty = ResponderInitialSessionCheckpoint.Stable(Instance, Account, Network, 0, new byte[32]);
        Assert.Equal(192, empty.Length);
        using var stable = ResponderInitialSessionCheckpoint.Decode(empty, Instance, Account, Network);
        Assert.Equal((byte)1, stable.Phase); Assert.Equal(0UL, stable.Sequence); Assert.Empty(stable.Payload);
        // Codec-only opaque bytes: not a valid receiver record or completion.
        var metadata = new byte[168 + 426 + 1 + 1 + 1]; metadata[0] = 2;
        BinaryPrimitives.WriteUInt16BigEndian(metadata.AsSpan(4), 426);
        foreach (var offset in new[] { 8, 12, 16, 20 }) BinaryPrimitives.WriteUInt32BigEndian(metadata.AsSpan(offset), 1);
        SHA256.HashData(new byte[] { 7 }).CopyTo(metadata, 136);
        var payload = metadata.Concat(new byte[] { 7 }).ToArray();
        var pending = ResponderInitialSessionCheckpoint.Pending(Instance, Account, Network, stable, payload);
        using var decoded = ResponderInitialSessionCheckpoint.Decode(pending, Instance, Account, Network);
        Assert.Equal((byte)2, decoded.Phase); Assert.Equal(1UL, decoded.Sequence); Assert.Equal(payload, decoded.Payload);
        Assert.Equal(ResponderInitialSessionCheckpoint.RecordHash(Instance, Account, Network, 1, stable.Hash, metadata), decoded.Hash);
        var final = ResponderInitialSessionCheckpoint.Stable(Instance, Account, Network, 1, decoded.Hash);
        using var committed = ResponderInitialSessionCheckpoint.Decode(final, Instance, Account, Network);
        Assert.Empty(committed.Payload); Assert.Equal(decoded.Hash, committed.Hash);
        Assert.Throws<InvalidDataException>(() => DeepIdV2InitialContactSessionCommit.RestoreCustody(payload));
        foreach (var offset in new[] { 0, 1, 2, 3, 44, 76, 108, 140, 160 })
        {
            var altered = pending.ToArray(); altered[offset] ^= 0x80;
            Assert.Throws<CryptographicException>(() =>
            {
                using var rejected = ResponderInitialSessionCheckpoint.Decode(altered, Instance, Account, Network);
            });
        }
        foreach (var altered in new[] { pending[..^1], pending.Concat(new byte[] { 0 }).ToArray() })
            Assert.Throws<InvalidDataException>(() =>
            {
                using var rejected = ResponderInitialSessionCheckpoint.Decode(altered, Instance, Account, Network);
            });
        var unknownSequence = pending.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(unknownSequence.AsSpan(4), 129);
        Assert.Throws<InvalidDataException>(() =>
        {
            using var rejected = ResponderInitialSessionCheckpoint.Decode(unknownSequence, Instance, Account, Network);
        });
        Assert.Throws<InvalidDataException>(() => ResponderInitialSessionCheckpoint.Stable(Instance, Account, Network, 1, new byte[32]));
        Assert.Throws<InvalidDataException>(() => ResponderInitialSessionCheckpoint.Stable(Instance, Account, Network, 0, decoded.Hash));
        Assert.Throws<ArgumentException>(() => ResponderInitialSessionCheckpoint.Stable(new byte[32], Account, Network, 0, new byte[32]));
        using var full = ResponderInitialSessionCheckpoint.Decode(
            ResponderInitialSessionCheckpoint.Stable(Instance, Account, Network, 128, decoded.Hash), Instance, Account, Network);
        Assert.Throws<InvalidDataException>(() => ResponderInitialSessionCheckpoint.Pending(Instance, Account, Network, full, payload));
        Assert.Throws<InvalidDataException>(() => ResponderInitialSessionCheckpoint.Pending(Instance, Account, Network, decoded, payload));
        Assert.Throws<InvalidDataException>(() => ResponderInitialSessionCheckpoint.Pending(Instance, Account, Network, stable,
            new byte[DeepIdV2InitialContactSessionCommit.MaximumPayloadBytes + 1]));
        decoded.Dispose(); Assert.All(decoded.Payload, value => Assert.Equal((byte)0, value));
    }

    [Theory]
    [InlineData(Dpk2PrekeyKind.OneTime, 0, 0, false)]
    [InlineData(Dpk2PrekeyKind.OneTime, 0, 1, true)]
    [InlineData(Dpk2PrekeyKind.LastResort, 1, 0, false)]
    [InlineData(Dpk2PrekeyKind.LastResort, 1, 1, true)]
    [InlineData(Dpk2PrekeyKind.LastResort, 2, 1, false)]
    [InlineData(Dpk2PrekeyKind.LastResort, 2, 2, true)]
    [InlineData(Dpk2PrekeyKind.LastResort, 64, 63, false)]
    [InlineData(Dpk2PrekeyKind.LastResort, 64, 64, true)]
    public void ReceiverPreKeyConsumption_UsesExactSignedLimitNotWireMaximum(Dpk2PrekeyKind kind, int limit, int uses, bool exhausted)
    {
        Assert.Equal(exhausted, SqlitePreKeyV2InventoryStore.IsReceiverPreKeyExhausted(kind, checked((ushort)limit), uses));
    }

    [Theory]
    [InlineData(Dpk2PrekeyKind.OneTime, 0, 2)]
    [InlineData(Dpk2PrekeyKind.OneTime, 1, 1)]
    [InlineData(Dpk2PrekeyKind.LastResort, 0, 1)]
    [InlineData(Dpk2PrekeyKind.LastResort, 65, 1)]
    [InlineData(Dpk2PrekeyKind.LastResort, 1, 2)]
    [InlineData(Dpk2PrekeyKind.LastResort, 64, 65)]
    [InlineData(Dpk2PrekeyKind.LastResort, 64, -1)]
    [InlineData((Dpk2PrekeyKind)0, 1, 0)]
    public void ReceiverPreKeyConsumption_RejectsUnknownOrExceededLimits(Dpk2PrekeyKind kind, int limit, int uses)
    {
        Assert.Throws<CryptographicException>(() => SqlitePreKeyV2InventoryStore.IsReceiverPreKeyExhausted(kind, checked((ushort)limit), uses));
    }

    [Fact]
    public void ReceiverCustody_PublicSurfaceHasNoCallerConstructorOrPlaintextOrKeyExport()
    {
        var type = typeof(DeepIdV2InitialContactSessionCommit);
        Assert.Empty(type.GetConstructors());
        Assert.Equal(new[] { "ClaimOperationId", "ConversationId", "RelationshipId", "SessionId" },
            type.GetProperties().Select(property => property.Name).Order().ToArray());
        Assert.All(type.GetProperties(), property =>
        {
            Assert.Equal(typeof(ReadOnlyMemory<byte>), property.PropertyType);
            Assert.Null(property.SetMethod);
        });
    }

    [Fact]
    public void ReceiverDirectoryBinding_ChecksRemoteHashAtItsIndependentOffset()
    {
        // Binding helper only, not a valid TRS1 or authenticated session.
        var binding = new byte[252]; Account.CopyTo(binding, 12 + 136); Instance.CopyTo(binding, 12 + 208);
        MessagingCryptoV1Trs1.RequireLocalDirectoryBinding(binding, Account);
        MessagingCryptoV1Trs1.RequireRemoteDirectoryBinding(binding, Instance);
        Assert.Throws<CryptographicException>(() => MessagingCryptoV1Trs1.RequireRemoteDirectoryBinding(binding, Account));
        binding[12 + 208] ^= 1;
        Assert.Throws<CryptographicException>(() => MessagingCryptoV1Trs1.RequireRemoteDirectoryBinding(binding, Instance));
        Assert.Throws<FormatException>(() => MessagingCryptoV1Trs1.RequireRemoteDirectoryBinding(binding[..^1], Instance));
        Assert.Throws<ArgumentException>(() => MessagingCryptoV1Trs1.RequireRemoteDirectoryBinding(binding, new byte[32]));
    }
}
