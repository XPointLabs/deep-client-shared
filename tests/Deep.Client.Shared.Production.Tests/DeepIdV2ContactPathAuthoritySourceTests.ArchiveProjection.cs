using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2IndexedArchive_ActualFourDirectionsAllSixFamiliesAndReducerEqualIndependentFullConstruction()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var pair = await fixture.PrepareArchiveEnrollmentPair(0);
        using (var sent = await fixture.SendOwnedBraid(pair.Sender, Bytes(32, 0xa8)))
        using (var received = await fixture.ReceiveOwnedBraid(pair.Receiver, sent.ExactControl.ToArray())) { }
        using (var sent = await fixture.SendOwnedBraid(pair.Receiver, Bytes(32, 0xa9)))
        using (var received = await fixture.ReceiveOwnedBraid(pair.Sender, sent.ExactControl.ToArray())) { }
        using var source = await fixture.StageActualLegacyArchiveInput([pair.Sender]);
        await fixture.EnrollArchiveAccount();
        await fixture.AssertArchiveAdoptedWithoutSourceMutation(source);
        await fixture.AssertArchiveIndependentProjection(pair.Sender);
        using (var command = await fixture.CreateOwnedText(pair.Receiver, "one actual incremental archived incoming event"))
        using (var sent = await fixture.SendOwnedMessage(pair.Receiver, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span)))
        using (var received = await fixture.ReceiveOwnedMessage(pair.Sender, sent.ExactEnvelope.ToArray())) { }
        await fixture.CompactActiveNativePrefix(pair.Sender, 1);
        fixture.ColdReopenCompactionStorage();
        await fixture.AssertArchiveIndependentProjection(pair.Sender);
    }

    private sealed partial class Fixture
    {
        private sealed record ReferenceArchiveRow(long RowId, ulong Ordinal, byte Direction, byte[] Operation,
            byte[] Metadata, byte[] Envelope, byte[]? Plaintext)
        {
            internal byte[] Ref()
            {
                var raw = new byte[88]; raw[0] = 2; raw[1] = Direction;
                BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), Ordinal);
                BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(16), checked((ulong)RowId));
                Operation.CopyTo(raw, 24); SHA256.HashData(Metadata).CopyTo(raw, 56); return raw;
            }
        }

        internal async Task AssertArchiveIndependentProjection(Did2MessagingSessionScope scope)
        {
            var rows = new List<ReferenceArchiveRow>(); byte[] initial = [], hello = [];
            await WithArchiveFixtureSql(scope, connection =>
            {
                using (var read = connection.CreateCommand())
                {
                    read.CommandText = "SELECT metadata,hello FROM initial_events WHERE singleton=1;";
                    using var row = read.ExecuteReader(); Assert.True(row.Read());
                    initial = row.GetFieldValue<byte[]>(0); hello = row.GetFieldValue<byte[]>(1);
                }
                using var events = connection.CreateCommand(); events.CommandText = "SELECT rowid,ordinal,direction,operation,metadata,envelope,plaintext FROM events ORDER BY ordinal;";
                using var all = events.ExecuteReader();
                while (all.Read()) rows.Add(new(all.GetInt64(0), checked((ulong)all.GetInt64(1)), checked((byte)all.GetInt64(2)),
                    all.GetFieldValue<byte[]>(3), all.GetFieldValue<byte[]>(4), all.GetFieldValue<byte[]>(5), all.IsDBNull(6) ? null : all.GetFieldValue<byte[]>(6)));
            });
            Assert.Equal(new byte[] { 1, 2, 3, 4 }, rows.Select(row => row.Direction).Distinct().Order().ToArray());
            using var rootBytes = await NativeStorage(scope).ReadOwnedAsync(Did2MessagingArchiveRoot.Slot(scope)) ?? throw new InvalidDataException();
            var root = rootBytes.Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
            var facts = new List<(Did2MessagingArchiveFamily Family, byte[] Selector, byte[] Value)>();
            var reducer = new byte[1136]; reducer[0] = 1; scope.Hash.CopyTo(reducer.AsSpan(4));
            root.Basis.Exact.Span.CopyTo(reducer.AsSpan(36)); SHA256.HashData(initial).CopyTo(reducer, 224);
            var initialRef = new byte[88]; initialRef[0] = 1; Put(8, 1, initialRef); Put(16, 1, initialRef); SHA256.HashData(initial).CopyTo(initialRef, 56);
            initialRef.CopyTo(reducer, 344); Put(880, 2, reducer);
            var greeting = Assert.IsType<ContactHelloDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(hello).ParsedPayload);
            BinaryPrimitives.WriteUInt32BigEndian(reducer.AsSpan(896), (uint)greeting.Policy);
            try
            {
                foreach (var row in rows)
                {
                    var reference = row.Ref(); var ordinal = new byte[8]; Put(0, row.Ordinal, ordinal);
                    facts.Add((Did2MessagingArchiveFamily.Operation, row.Operation, reference));
                    facts.Add((Did2MessagingArchiveFamily.Ordinal, ordinal, reference));
                    if (row.Direction != 2) continue;
                    var message = ApplicationCoreCodec.DecodeDmc2(row.Plaintext!); var eventHash = SHA256.HashData(row.Plaintext!);
                    facts.Add((Did2MessagingArchiveFamily.FirstIncomingEvent, eventHash, reference));
                    var position = new byte[40]; scope.Conversation.CopyTo(position); Put(32, message.SenderClientSequence, position);
                    var authored = new byte[240]; reference.CopyTo(authored, 0); eventHash.CopyTo(authored, 88);
                    facts.Add((Did2MessagingArchiveFamily.PeerAuthoredPosition, position, authored));
                    var attachment = new byte[64]; message.LogicalMessageId.Span.CopyTo(attachment); message.SenderDeviceId.Span.CopyTo(attachment.AsSpan(32));
                    var incoming = new byte[176]; reference.CopyTo(incoming, 0);
                    facts.Add((Did2MessagingArchiveFamily.IncomingAttachment, attachment, incoming));
                    var epoch = Dpe2Codec.Decode(row.Envelope).RatchetHeader.SckaSendingEpoch;
                    if (reducer.AsSpan(784, 88).IndexOfAnyExcept((byte)0) < 0 || epoch > BinaryPrimitives.ReadUInt64BigEndian(reducer.AsSpan(872)))
                    { reference.CopyTo(reducer, 784); Put(872, epoch, reducer); }
                    if (message.ParsedPayload is ContactAcceptDmc2Payload consent)
                    {
                        reference.CopyTo(reducer, 256); reference.CopyTo(reducer, 520);
                        Put(888, message.SenderClientSequence, reducer);
                        BinaryPrimitives.WriteUInt32BigEndian(reducer.AsSpan(900), (uint)consent.Policy);
                        var qualification = new byte[136]; reference.CopyTo(qualification, 0);
                        Put(88, row.Ordinal, qualification); Put(128, message.SenderClientSequence, qualification);
                        facts.Add((Did2MessagingArchiveFamily.QualifiedPeerRoute,
                            SHA256.HashData(consent.MailboxRoute.Route.ExactBytes.Span), qualification));
                    }
                }
                Assert.Equal(6, facts.Select(fact => fact.Family).Distinct().Count());
                var expected = Did2MessagingArchiveBuilderTests.IndependentReferenceForActualFacts(scope, facts);
                Assert.True(expected.Root.AsSpan().SequenceEqual(root.PatriciaHash), "Incremental native projection differs from independent sorted full construction.");
                var preimage = Encoding.UTF8.GetBytes("Deep/STORE-V2/archive-reducer").Concat(new byte[] { 0 })
                    .Concat(scope.Hash.ToArray()).Concat(reducer).ToArray();
                Assert.True(SHA256.HashData(preimage).AsSpan().SequenceEqual(root.SummaryHash), "Native reducer differs from independently derived initial/consent/head/epoch originals.");
                await WithArchiveFixtureSql(scope, connection =>
                {
                    foreach (var node in expected.Nodes)
                    {
                        using var read = connection.CreateCommand(); read.CommandText = "SELECT exact FROM archive_nodes WHERE hash=$hash;";
                        read.Parameters.AddWithValue("$hash", Convert.FromHexString(node.Key));
                        var exact = Assert.IsType<byte[]>(read.ExecuteScalar());
                        Assert.True(exact.AsSpan().SequenceEqual(node.Value), "A reachable immutable node differs from the independent exact tree.");
                    }
                });
                CryptographicOperations.ZeroMemory(preimage);
            }
            finally
            {
                foreach (var row in rows)
                    foreach (var bytes in new[] { row.Operation, row.Metadata, row.Envelope, row.Plaintext }) if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
                CryptographicOperations.ZeroMemory(initial); CryptographicOperations.ZeroMemory(hello); CryptographicOperations.ZeroMemory(reducer);
            }
            static void Put(int offset, ulong value, byte[] raw) => BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(offset), value);
        }
    }
}
