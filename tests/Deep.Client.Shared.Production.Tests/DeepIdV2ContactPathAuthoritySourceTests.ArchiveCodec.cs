using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ArchiveCodec_ActualInitialHelloHeadsAndActiveBasisRoundTrip(bool initiator)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var pair = await fixture.PrepareActiveNativePair();
        var scope = initiator ? pair.Sender : pair.Receiver;
        await fixture.WithActiveNativeComparators(scope, (full, _, connection, _) =>
        {
            // Use an actual native import/activation prefix, not a synthesized
            // valid reducer. This does not install the index in this fixture.
            _ = full.VerifyTip();
            byte[] initial, hello, activation;
            using (var query = connection.CreateCommand())
            {
                query.CommandText = "SELECT metadata,hello FROM initial_events WHERE singleton=1;";
                using var row = query.ExecuteReader(); Assert.True(row.Read());
                initial = row.GetFieldValue<byte[]>(0); hello = row.GetFieldValue<byte[]>(1); Assert.False(row.Read());
            }
            using (var query = connection.CreateCommand())
            {
                query.CommandText = "SELECT metadata FROM journal WHERE ordinal=2;";
                activation = Assert.IsType<byte[]>(query.ExecuteScalar());
            }
            var imported = Did2MessagingFloor.FromJournalMetadata(scope, Did2MessagingFloor.Empty(scope), initial);
            var basis = Did2MessagingFloor.FromJournalMetadata(scope, imported, activation);
            Assert.Equal(2UL, basis.Ordinal); Assert.Equal(1, basis.Status);
            var parsed = ApplicationCoreCodec.DecodeDmc2(hello);
            var greeting = Assert.IsType<ContactHelloDmc2Payload>(parsed.ParsedPayload);
            Assert.Equal(2UL, parsed.SenderClientSequence);
            Assert.False(initial.AsSpan(268, 32).IndexOfAnyExcept((byte)0) < 0);
            var initialHash = SHA256.HashData(initial);
            var reference = Did2MessagingArchiveReference.Initial(initialHash);
            Assert.True(reference.Operation.IndexOfAnyExcept((byte)0) < 0);
            var raw = new byte[Did2MessagingArchiveReducer.Bytes]; raw[0] = 1;
            scope.Hash.CopyTo(raw.AsSpan(4)); basis.Exact.Span.CopyTo(raw.AsSpan(36)); initialHash.CopyTo(raw, 224);
            var head = initiator ? Did2MessagingArchiveReducer.ReferenceKind.OwnHead : Did2MessagingArchiveReducer.ReferenceKind.PeerHead;
            reference.Exact.Span.CopyTo(raw.AsSpan(256 + (int)head * Did2MessagingArchiveReference.Bytes));
            BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(initiator ? 880 : 888), parsed.SenderClientSequence);
            BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(896), (uint)greeting.Policy);
            var reducer = Did2MessagingArchiveReducer.Decode(raw, scope);
            var routeSelector = SHA256.HashData(greeting.MailboxRoute.Route.ExactBytes.Span);
            var value = new byte[136]; reference.Exact.Span.CopyTo(value);
            BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(128), parsed.SenderClientSequence);
            var routeLeaf = Did2MessagingArchivePatricia.Leaf(scope, Did2MessagingArchiveFamily.QualifiedPeerRoute, routeSelector, value);
            var root = Did2MessagingArchiveRoot.Create(scope, 1, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope),
                basis, 0, routeLeaf.Digest.Span, reducer.Digest.Span);
            reducer.RequireRoot(root);
            Assert.Equal(value, Did2MessagingArchivePatricia.VerifyProof(scope, root,
                Did2MessagingArchiveFamily.QualifiedPeerRoute, routeSelector, [routeLeaf.Exact]));
            var wrongSequence = raw.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(wrongSequence.AsSpan(initiator ? 880 : 888), 1);
            Assert.Throws<InvalidDataException>(() => Did2MessagingArchiveReducer.Decode(wrongSequence, scope));
            var wrongInitial = raw.ToArray(); wrongInitial[256 + (int)head * 88 + 56] ^= 1;
            Assert.Throws<InvalidDataException>(() => Did2MessagingArchiveReducer.Decode(wrongInitial, scope));
            var unjustifiedEpoch = raw.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(unjustifiedEpoch.AsSpan(872), 1);
            Assert.Throws<InvalidDataException>(() => Did2MessagingArchiveReducer.Decode(unjustifiedEpoch, scope));
            var emptyRoot = Did2MessagingArchiveRoot.Empty(scope);
            Assert.Throws<InvalidDataException>(() => reducer.RequireRoot(emptyRoot));
            var terminal = basis.Exact.ToArray(); terminal[2] = 2; terminal.AsSpan(84, 64).Clear();
            var terminalFloor = Did2MessagingFloor.Decode(terminal, scope);
            Assert.Throws<InvalidDataException>(() => Did2MessagingArchiveRoot.Create(scope, 1,
                Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope), terminalFloor, 0, routeLeaf.Digest.Span, reducer.Digest.Span));
        });
    }
}
