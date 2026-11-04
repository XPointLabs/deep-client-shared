using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryBounds_GenuineWorkingTransitionsDeduplicateBeforeSourcesAndColdCurrentRead()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        byte[] cursor = [];
        for (var generation = 1; generation <= 3; generation++)
        {
            await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1_000,
                successorAdvertisementLifetimeSeconds: 2_000, proactive: generation != 1);
            using var command = await fixture.CreateOwnedRouteUpdate(sender);
            var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ParsedPayload);
            cursor = page.RightCursor.ToArray(); Assert.Equal((ulong)generation, BinaryPrimitives.ReadUInt64BigEndian(cursor));
            using var native = await fixture.SendOwnedRouteUpdate(sender, command.OperationId);
            using var received = await fixture.ReceiveOwnedMessage(receiver, native.ExactEnvelope.ToArray());
            Assert.Equal(3, received.RouteProcessing[0]);
        }
        await fixture.AssertGenuineRouteSourceDeduplication(sender, cursor, requireWorking: true);
        await fixture.AssertBoundedCurrentPeerHealth(receiver);
        await fixture.ArchiveEntireEligibleSuffix(sender); await fixture.ArchiveEntireEligibleSuffix(receiver);
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage(); fixture.ColdReopenReceiverStoreStorage();
        await fixture.AssertGenuineRouteSourceDeduplication(sender, cursor, requireWorking: false);
        await fixture.AssertBoundedCurrentPeerHealth(receiver);
    }

    private sealed partial class Fixture
    {
        internal async Task AssertBoundedCurrentPeerHealth(Did2MessagingSessionScope scope)
        {
            var before = await ReadMessagingFloor(scope);
            var account = ReopenGrantReader(); var source = GrantReaderSource(account);
            var health = await account.ReadContactRouteHealthAsync(new(scope), source);
            Assert.False(health.RouteFaultRetained); Assert.True(health.AdvertisementIntervalCoversNow);
            Assert.Equal(before.Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
        }

        internal async Task AssertGenuineRouteSourceDeduplication(Did2MessagingSessionScope scope, byte[] cursor, bool requireWorking)
        {
            var floor = await ReadMessagingFloor(scope); var archive = await ReadNativeArchive(scope);
            var selectors = new[]
            {
                new Did2RouteHistoryFactSelector(Did2MessagingArchiveFamily.RouteHistory,
                    Did2MessagingArchiveRouteFacts.HistorySelector(1, 1, BinaryPrimitives.ReadUInt64BigEndian(cursor))),
                new Did2RouteHistoryFactSelector(Did2MessagingArchiveFamily.RouteHistory,
                    Did2MessagingArchiveRouteFacts.HistorySelector(1, 2, BinaryPrimitives.ReadUInt64BigEndian(cursor.AsSpan(40))))
            };
            await WithRouteReadSql(scope, (sql, connection) =>
            {
                var bodies = new List<Did2RouteHistoryDecision>();
                using (var query = connection.CreateCommand())
                {
                    query.CommandText = "SELECT decision FROM route_decisions WHERE ordinal>$basis ORDER BY ordinal;";
                    query.Parameters.AddWithValue("$basis", checked((long)archive.Basis.Ordinal));
                    using var rows = query.ExecuteReader();
                    while (rows.Read())
                    {
                        var body = Did2RouteHistoryDecision.Decode(rows.GetFieldValue<byte[]>(0), scope);
                        if (body.Subject == 1) bodies.Add(body);
                    }
                }
                Assert.Equal(requireWorking, bodies.Count != 0);
                var references = new HashSet<string>(StringComparer.Ordinal);
                Did2RouteHistoryDecision? previous = null;
                foreach (var body in bodies)
                {
                    var before = references.Count;
                    Add(body.C.Reference); Add(body.P.Reference);
                    Assert.InRange(references.Count - before, 0, previous is null ? 2 : 1);
                    if (previous is not null)
                    {
                        Assert.Contains(Convert.ToHexString(previous.C.Reference.Exact.Span), references);
                        Assert.Contains(Convert.ToHexString(previous.P.Reference.Exact.Span), references);
                        if (body.Action is Did2RouteHistoryDecision.ActionKind.Promotion or Did2RouteHistoryDecision.ActionKind.Conflict)
                            Assert.Equal(before, references.Count);
                    }
                    previous = body;
                }
                Assert.InRange(references.Count, 0, bodies.Count + 2);
                foreach (var selection in new[] { Did2RouteHistorySelection.Current(selectors), Did2RouteHistorySelection.Initial(selectors) })
                {
                    var sources = sql.ReadRouteHistoryAuthoredSources(floor, 1, selection);
                    try
                    {
                        Assert.NotEmpty(sources);
                        Assert.Equal(sources.Count, sources.Select(row => Convert.ToHexString(row.Reference.Exact.Span)).Distinct(StringComparer.Ordinal).Count());
                        Assert.InRange(sources.Count, 1, selection.MaximumAuthoredOriginals);
                        // After all actual native decisions enter the archive,
                        // endpoint C/P and P's immediate before-C suffice. The
                        // three-publication graph must not recursively expand.
                        if (!requireWorking && selection.IsCurrent) Assert.InRange(sources.Count, 1, 3);
                    }
                    finally { foreach (var source in sources) source.Dispose(); }
                }
                void Add(Did2MessagingArchiveReference reference)
                { if (!reference.IsAbsent) references.Add(Convert.ToHexString(reference.Exact.Span)); }
            });
            Assert.Equal(floor.Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
        }
    }
}
