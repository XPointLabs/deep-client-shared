using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2InitialCancellationCodecTests
{
    private static byte[] B(int size, byte value) => Enumerable.Repeat(value, size).ToArray();

    [Theory]
    [InlineData("draft", 1)] [InlineData("draft", 2)] [InlineData("draft", 3)]
    [InlineData("preclaim", 1)] [InlineData("preclaim", 2)] [InlineData("retirement", 1)]
    public void RetiredLocalGenerationsRejectEvenEmptyState(string kind, byte generation)
    {
        var network = B(16, 1); var account = B(32, 2); var instance = B(32, 3);
        var raw = kind switch
        {
            "draft" => ProtectedDid2ContactStartJournal.Empty(network, account, instance),
            "preclaim" => ProtectedDph2PreClaimJournal.Empty(network, account, instance),
            _ => ProtectedInitialKeyRetirementJournal.Empty(network, account, instance)
        };
        raw[0] = generation;
        if (kind == "draft")
        {
            Assert.Throws<InvalidDataException>(() =>
            {
                using var decoded = ProtectedDid2ContactStartJournal.Decode(raw, network, account, instance);
            });
            return;
        }
        Assert.Throws<CryptographicException>(() =>
        {
            if (kind == "preclaim") _ = ProtectedDph2PreClaimJournal.Decode(raw, network, account, instance);
            else _ = ProtectedInitialKeyRetirementJournal.Decode(raw, network, account, instance);
        });
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void CancelledPreclaimIsStructurallyDistinctFromTransferAndNeverCarriesASeed(bool hadBlob)
    {
        var network = B(16, 1); var account = B(32, 2); var instance = B(32, 3); var intent = B(32, 4);
        var state = new ProtectedDph2PreClaimJournal.State(3, new(StringComparer.Ordinal));
        state.Cancelled.Add(Convert.ToHexString(intent), new(hadBlob ? B(32, 5) : new byte[32], B(32, 6)));
        var raw = ProtectedDph2PreClaimJournal.Encode(state, network, account, instance);
        var decoded = ProtectedDph2PreClaimJournal.Decode(raw, network, account, instance);
        Assert.Empty(decoded.Claims); Assert.Empty(decoded.Retired); Assert.Single(decoded.Cancelled);
        Assert.Equal(92 + 136, raw.Length);
        var scope = raw.ToArray(); scope[92 + 100] = 1;
        Assert.Throws<InvalidDataException>(() => ProtectedDph2PreClaimJournal.Decode(scope, network, account, instance));
        var payload = raw.ToArray(); BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(92 + 132), 1);
        Assert.Throws<InvalidDataException>(() => ProtectedDph2PreClaimJournal.Decode(payload, network, account, instance));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void CancellationManifestRejectsMixedSourceAbsenceAndCannotMasqueradeAsTransfer(bool hasSource)
    {
        var raw = new byte[ProtectedInitialKeyRetirementJournal.EntryBytes]; raw[0] = 3; raw[1] = 1;
        foreach (var offset in new[] { 4, 76, 172 }) B(32, (byte)(offset % 200 + 1)).CopyTo(raw, offset);
        if (hasSource)
        {
            BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(36), 1);
            foreach (var offset in new[] { 44, 108, 140, 204 }) B(32, 7).CopyTo(raw, offset);
        }
        var entry = new ProtectedInitialKeyRetirementJournal.Entry(raw); Assert.Equal(3, entry.Role);
        var mixed = raw.ToArray(); mixed[44] ^= 0x80;
        if (hasSource) mixed.AsSpan(44, 32).Clear();
        Assert.Throws<InvalidDataException>(() => new ProtectedInitialKeyRetirementJournal.Entry(mixed));
        raw[0] = 1;
        if (!hasSource) Assert.Throws<InvalidDataException>(() => new ProtectedInitialKeyRetirementJournal.Entry(raw));
        // With source, role1 still requires a real closed transfer at its writer;
        // parsing or changing a role byte never grants that authority.
    }
}
