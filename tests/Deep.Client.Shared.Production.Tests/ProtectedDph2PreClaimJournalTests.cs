using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Production.Tests;

// Structural ciphertext custody only: no synthetic current-account authority,
// DH operation, decryption, remote receipt or physical-delivery claim.
public sealed class ProtectedDph2PreClaimJournalTests
{
    private static readonly byte[] Network = Enumerable.Repeat((byte)1, 16).ToArray();
    private static readonly byte[] Account = Enumerable.Repeat((byte)2, 32).ToArray();
    private static readonly byte[] Instance = Enumerable.Repeat((byte)3, 32).ToArray();

    [Fact]
    public void EmptyAndExactCiphertextSnapshotsRoundTripWithDefensiveOwnership()
    {
        var empty = ProtectedDph2PreClaimJournal.Empty(Network, Account, Instance);
        var state = ProtectedDph2PreClaimJournal.Decode(empty, Network, Account, Instance);
        Assert.Equal(1UL, state.Revision); Assert.Empty(state.Claims);
        var intent = Enumerable.Repeat((byte)4, 32).ToArray();
        var blob = StructuralBlob(intent);
        state.Claims.Add(Convert.ToHexString(intent), blob);
        var encoded = ProtectedDph2PreClaimJournal.Encode(state with { Revision = 2 }, Network, Account, Instance);
        var reopened = ProtectedDph2PreClaimJournal.Decode(encoded, Network, Account, Instance);
        Assert.Equal(2UL, reopened.Revision);
        Assert.Equal(blob.CanonicalBytes.ToArray(), Assert.Single(reopened.Claims).Value.CanonicalBytes.ToArray());
        encoded[^1] ^= 1;
        Assert.Equal(blob.CanonicalBytes.ToArray(), Assert.Single(reopened.Claims).Value.CanonicalBytes.ToArray());
        Assert.Equal(ProtectedDph2PreClaimJournal.HeaderBytes + 32 + 2552, encoded.Length);
        Assert.True(ProtectedDph2PreClaimJournal.MaximumBytes < 1024 * 1024);
    }

    [Fact]
    public void UnknownShapeScopeRevisionAndHostileSizesRejectWithoutRepair()
    {
        var empty = ProtectedDph2PreClaimJournal.Empty(Network, Account, Instance);
        foreach (var offset in new[] { 0, 1, 2, 4, 11, 12, 28, 60 })
        {
            var changed = empty.ToArray(); changed[offset] ^= 1;
            if (offset is 2 or 4 or 11)
                Assert.Throws<InvalidDataException>(() => ProtectedDph2PreClaimJournal.Decode(changed, Network, Account, Instance));
            else
                Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
                    ProtectedDph2PreClaimJournal.Decode(changed, Network, Account, Instance));
        }
        foreach (var size in new[] { 0, 91, 93, ProtectedDph2PreClaimJournal.MaximumBytes + 1 })
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
                ProtectedDph2PreClaimJournal.Decode(new byte[size], Network, Account, Instance));
        Assert.Throws<ArgumentException>(() => ProtectedDph2PreClaimJournal.RequireIntent(new byte[32]));
        Assert.Throws<ArgumentException>(() => ProtectedDph2PreClaimJournal.RequireIntent(new byte[31]));
        Assert.Throws<InvalidDataException>(() => ProtectedDph2PreClaimJournal.Encode(new(2, new(StringComparer.Ordinal)),
            Network, Account, Instance));
    }

    [Fact]
    public void DuplicateUnsortedAndMalformedCiphertextRejectAndCapacityIsReserved()
    {
        var claims = new SortedDictionary<string, InitiatorDph2PreKeyClaimPersistenceBlob>(StringComparer.Ordinal);
        for (var index = 1; index <= ProtectedDph2PreClaimJournal.MaximumIntents; index++)
        {
            var intent = new byte[32]; BinaryPrimitives.WriteInt32BigEndian(intent.AsSpan(28), index);
            claims.Add(Convert.ToHexString(intent), StructuralBlob(intent));
        }
        var exact = ProtectedDph2PreClaimJournal.Encode(new(129, claims), Network, Account, Instance);
        Assert.Equal(ProtectedDph2PreClaimJournal.MaximumBytes, exact.Length);
        Assert.Equal(128, ProtectedDph2PreClaimJournal.Decode(exact, Network, Account, Instance).Claims.Count);
        var entryBytes = 32 + 2552; var header = ProtectedDph2PreClaimJournal.HeaderBytes;
        var duplicate = exact.ToArray(); duplicate.AsSpan(header, 32).CopyTo(duplicate.AsSpan(header + entryBytes, 32));
        Assert.Throws<InvalidDataException>(() => ProtectedDph2PreClaimJournal.Decode(duplicate, Network, Account, Instance));
        var unsorted = exact.ToArray();
        exact.AsSpan(header + entryBytes, entryBytes).CopyTo(unsorted.AsSpan(header, entryBytes));
        exact.AsSpan(header, entryBytes).CopyTo(unsorted.AsSpan(header + entryBytes, entryBytes));
        Assert.Throws<InvalidDataException>(() => ProtectedDph2PreClaimJournal.Decode(unsorted, Network, Account, Instance));
        var malformed = exact.ToArray(); malformed[header + 32] ^= 1;
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            ProtectedDph2PreClaimJournal.Decode(malformed, Network, Account, Instance));
        var another = Enumerable.Repeat((byte)255, 32).ToArray(); claims.Add(Convert.ToHexString(another), StructuralBlob(another));
        Assert.Throws<InvalidDataException>(() => ProtectedDph2PreClaimJournal.Encode(new(130, claims), Network, Account, Instance));
    }

    private static InitiatorDph2PreKeyClaimPersistenceBlob StructuralBlob(byte[] intent)
    {
        var bytes = Enumerable.Repeat((byte)7, 2552).ToArray();
        "IPK2"u8.CopyTo(bytes); bytes[4] = 1; bytes[5] = 1; bytes[6] = 0; bytes[7] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8, 4), 2552);
        Instance.CopyTo(bytes, 12); intent.CopyTo(bytes, 44); Network.CopyTo(bytes, 76); Account.CopyTo(bytes, 92);
        var did = DeepIdV2Codec.AuthorDid2(Enumerable.Repeat((byte)1, 32).ToArray(),
            Enumerable.Repeat((byte)2, 1952).ToArray(), Enumerable.Repeat((byte)3, 16).ToArray());
        did.CanonicalBytes.Span.CopyTo(bytes.AsSpan(236));
        return InitiatorDph2PreKeyClaimPersistenceBlob.Decode(bytes);
    }
}
