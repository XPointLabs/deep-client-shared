using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

// Structural local metadata only; these fixtures mint no account/ACK authority.
public sealed class ProtectedDid2MailboxReadJournalTests
{
    private static readonly byte[] Network = Bytes(16, 1), Account = Bytes(32, 2), Instance = Bytes(32, 3),
        Grant = Bytes(32, 4), Scope = Bytes(32, 5), Route = Bytes(32, 6);

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    public void UnknownForeignCountsReservedRevisionAndTrailingBytesReject(int fault)
    {
        var exact = ProtectedDid2MailboxReadJournal.Empty(Network, Account, Instance);
        switch (fault)
        {
            case 0: exact[0] = 2; break;
            case 1: exact[1] = 7; break;
            case 2: BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), 129); break;
            case 3: BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(92), 129); break;
            case 4: exact[94] = 1; break;
            case 5: exact[11] = 0; break;
            case 6: exact[60] ^= 1; break;
            case 7: exact = [.. exact, 0]; break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxReadJournal.Decode(exact, Network, Account, Instance));
    }

    [Fact]
    public void PendingPreparedCapturedCommittedAndPendingAckRoundtripWithoutTrustFlags()
    {
        using var state = Pending();
        Roundtrip(state); Assert.Equal(1UL, state.MinimumCounter(Grant));
        var c = state.Active!; c.RetrieveCounter = 1; c.RetrieveMauHash = Bytes(32, 7);
        state.Counters.Add(Convert.ToHexString(Grant), 1); state.Phase = 2; state.Revision++; Roundtrip(state);
        Assert.Equal(2UL, state.MinimumCounter(Grant));
        var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(c.RetrieveBody);
        var cipher = Bytes(64, 8);
        var page = new MailboxRetrievePage
        {
            Epoch = 1, OperationId = request.OperationId, NextCursor = 1, HasMore = false, ContinuationToken = ReadOnlyMemory<byte>.Empty,
            Items = [new() { Cursor = 1, Envelope = new()
            {
                Epoch = 1, MailboxId = request.MailboxId, PlacementId = request.PlacementId, OperationId = Bytes(16, 9),
                Ciphertext = cipher, DeduplicationDigest = SHA256.HashData(cipher), CreatedAtUnixSeconds = 1000, ExpiresAtUnixSeconds = 1200
            } }]
        };
        c.Page = MailboxClientCodec.EncodeRetrievePage(page); c.CapturedAt = 1100;
        state.Phase = 3; state.Revision++; Roundtrip(state);
        state.Traversals[Convert.ToHexString(Scope)] = new(0, [], 1); state.Phase = 4; state.Revision++; Roundtrip(state);
        c.AckBody = MailboxAuthenticatedRequestTranscript.ForAck(1, c.AckOperation(), request.MailboxId, request.PlacementId, true, [],
            page.Items.Select(item => item.ToAcknowledgement()).ToArray()).CanonicalRequest.ToArray();
        state.Phase = 5; state.Revision++; Roundtrip(state);
        c.AckCounter = 2; c.AckMauHash = Bytes(32, 10); state.Counters[Convert.ToHexString(Grant)] = 2;
        state.Phase = 6; state.Revision++; Roundtrip(state); Assert.Equal(3UL, state.MinimumCounter(Grant));
        c.AckBody[^1] ^= 1;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxReadJournal.Encode(state, Network, Account, Instance));
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public void ChangedPhasePreparedCounterTraversalOrHostileBodyRejectsBeforeAdoption(int fault)
    {
        using var state = Pending();
        switch (fault)
        {
            case 0: state.Phase = 0; break;
            case 1: state.Phase = 2; break;
            case 2: state.Active!.RetrieveCounter = 1; break;
            case 3: state.Traversals[Convert.ToHexString(Scope)] = new(0, [], 1); break;
            case 4: state.Active!.Page = new byte[ProtectedDid2MailboxReadJournal.MaximumPageBytes + 1]; break;
            case 5: state.Active!.RetrieveBody = new byte[365]; break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxReadJournal.Encode(state, Network, Account, Instance));
    }

    [Fact]
    public void CounterAndTraversalFloorsAreRetainedWithClosedCapacityAndSortedIdentity()
    {
        using var state = new ProtectedDid2MailboxReadJournal.State { Revision = 257 };
        for (byte i = 1; i <= 128; i++)
        { var name = Convert.ToHexString(Bytes(32, i)); state.Counters.Add(name, i); state.Traversals.Add(name, new(0, [], i)); }
        Roundtrip(state);
        state.Counters.Add(Convert.ToHexString(Bytes(32, 129)), 1); state.Revision++;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxReadJournal.Encode(state, Network, Account, Instance));
    }

    private static ProtectedDid2MailboxReadJournal.State Pending()
    {
        var body = MailboxAuthenticatedRequestTranscript.ForRetrieve(1, Bytes(16, 11), new(Bytes(32, 12)), new(Bytes(32, 13)), 0, 8, []);
        var state = new ProtectedDid2MailboxReadJournal.State { Phase = 1, Revision = 2,
            Active = ProtectedDid2MailboxReadJournal.Cycle.Begin(Grant, Scope, Route, 0, body.CanonicalRequest.Span) };
        state.Traversals.Add(Convert.ToHexString(Scope), new(0, [], 0)); return state;
    }
    private static void Roundtrip(ProtectedDid2MailboxReadJournal.State state)
    {
        var exact = ProtectedDid2MailboxReadJournal.Encode(state, Network, Account, Instance);
        try
        {
            using var read = ProtectedDid2MailboxReadJournal.Decode(exact, Network, Account, Instance);
            Assert.Equal(state.Phase, read.Phase); Assert.Equal(state.Revision, read.Revision);
            Assert.Equal(exact, ProtectedDid2MailboxReadJournal.Encode(read, Network, Account, Instance));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
}
