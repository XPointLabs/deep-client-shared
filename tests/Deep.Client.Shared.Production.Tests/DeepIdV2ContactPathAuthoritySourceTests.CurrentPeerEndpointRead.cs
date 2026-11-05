using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CurrentPeerEndpointRead_ActualOldAndCompoundReadsMatchEverySourceWithFewerNativeOpens(bool initiator)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var pair = await fixture.PreparePagedConsentPair(initiator);
        var scope = pair.Observer;
        var floor = (await fixture.ReadMessagingFloor(scope)).Exact.ToArray();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(scope);
        await fixture.AssertCurrentPeerEndpointReadEquivalent(scope);
        await fixture.RequireCurrentNativeRoute(scope);
        await fixture.ArchiveEntireEligibleSuffix(scope);
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage(); fixture.ColdReopenReceiverStoreStorage();
        await fixture.AssertCurrentPeerEndpointReadEquivalent(scope);
        await fixture.RequireCurrentNativeRoute(scope);
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(scope)).Exact.ToArray());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(scope));
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CurrentPeerEndpointRead_LaterEvidenceKeepsActualAdoptedAnnouncementEndpoint()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        byte[] head;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            head = SHA256.HashData(command.ExactDmc2.Span);
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId);
            using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray());
        }
        using var gap = await fixture.PrepareFreshPagedHistoryGap(sender);
        using (await fixture.ReceiveOwnedMessage(receiver, gap.Prefixes[0])) { }
        var latest = (await fixture.ReadPagedNativeDecisionRows(receiver))[^1].Body;
        Assert.Equal(Did2RouteHistoryDecision.ActionKind.Evidence, latest.Action);
        await fixture.AssertCurrentPeerEndpointReadEquivalent(receiver, head);
    }

    [Theory]
    [InlineData("plaintext")] [InlineData("rowid")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CurrentPeerEndpointRead_ActualSourceSubstitutionAcrossAuthoredProviderRejectsWithoutRepair(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var pair = await fixture.PreparePagedConsentPair(initiator: true);
        var scope = pair.Observer;
        var floor = (await fixture.ReadMessagingFloor(scope)).Exact.ToArray();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(scope);
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        await fixture.AssertCurrentPeerEndpointSourceSubstitution(scope, pair.PeerOperation, defect);
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(scope)).Exact.ToArray());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(scope));
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
        await fixture.WithRouteReadSql(scope, (_, connection) =>
        {
            using var query = connection.CreateCommand();
            query.CommandText = defect == "plaintext"
                ? "SELECT plaintext FROM events WHERE operation=$operation;"
                : "SELECT rowid FROM events WHERE operation=$operation;";
            query.Parameters.AddWithValue("$operation", pair.PeerOperation);
            if (defect == "plaintext") Assert.All((byte[])query.ExecuteScalar()!, value => Assert.Equal((byte)0, value));
            else Assert.True(Convert.ToInt64(query.ExecuteScalar()) > 1000);
        });
    }

    private sealed class ObservedCurrentPeerRead(IDisposable owner, Did2RouteHistorySnapshot snapshot,
        Did2MessagingArchiveAuthoredRead paired, IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> events) : IDisposable
    {
        internal Did2RouteHistorySnapshot Snapshot { get; } = snapshot;
        internal Did2MessagingArchiveAuthoredRead Paired { get; } = paired;
        internal IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> Events { get; } = events;
        public void Dispose() => owner.Dispose();
    }

    private sealed partial class Fixture
    {
        internal async Task AssertCurrentPeerEndpointReadEquivalent(Did2MessagingSessionScope scope, byte[]? expectedHead = null)
        {
            await WithCurrentPeerEndpointOwner(scope, async (owner, opened, held) =>
            {
                byte[] baseline; long oldOpens;
                // Execute the former exact Current -> native L cursor -> Current
                // path on this same encrypted fixture, including its final join.
                using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
                {
                    using var first = await ObserveCurrentPeerRead(owner, "ReadRouteHistorySourcesUnderLeaseAsync",
                        opened, (byte)2, Did2RouteHistorySelection.Current(), held, CancellationToken.None);
                    var native = first.Snapshot.FindOriginal(first.Snapshot.L);
                    var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(native.Plaintext).ParsedPayload);
                    if (expectedHead is not null) Assert.Equal(expectedHead, SHA256.HashData(native.Plaintext));
                    var selection = Did2RouteHistorySelection.Current([
                        new(Did2MessagingArchiveFamily.RouteHistory, Did2MessagingArchiveRouteFacts.HistorySelector(2, 1, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span))),
                        new(Did2MessagingArchiveFamily.RouteHistory, Did2MessagingArchiveRouteFacts.HistorySelector(2, 2, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span[40..])))]);
                    using var old = await ObserveCurrentPeerRead(owner, "ReadRouteHistorySourcesUnderLeaseAsync",
                        opened, (byte)2, selection, held, CancellationToken.None);
                    Assert.Equal(first.Snapshot.Before.Exact.ToArray(), old.Snapshot.Before.Exact.ToArray());
                    Assert.Equal(first.Snapshot.L.Exact.ToArray(), old.Snapshot.L.Exact.ToArray());
                    baseline = old.Snapshot.Transcript.ToArray();
                    await opened.WithPairedSqlAsync(old.Paired,
                        sql => { sql.RequireRouteHistorySnapshot(old.Snapshot, old.Events); return true; }, default);
                    oldOpens = work.Opens;
                }
                using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
                {
                    using var actual = await ObserveCurrentPeerRead(owner, "ReadLiveRouteHistorySourcesUnderLeaseAsync",
                        opened, (byte)2, held, CancellationToken.None);
                    Assert.Equal(baseline, actual.Snapshot.Transcript.ToArray());
                    Assert.True(actual.Snapshot.Selection.IsCurrentPeerEndpoint); Assert.Equal(2, actual.Snapshot.Facts.Count);
                    await opened.WithPairedSqlAsync(actual.Paired,
                        sql => { sql.RequireRouteHistorySnapshot(actual.Snapshot, actual.Events); return true; }, default);
                    Console.WriteLine($"Current peer endpoint native opens: old={oldOpens}, compound={work.Opens}; exact source transcript equal.");
                    Assert.Equal(11, oldOpens); Assert.Equal(6, work.Opens);
                }
            });
        }

        internal async Task AssertCurrentPeerEndpointSourceSubstitution(Did2MessagingSessionScope scope, byte[] operation, string defect)
        {
            await WithCurrentPeerEndpointOwner(scope, async (owner, opened, held) =>
            {
                var hit = false;
                using var hook = Did2ContactRouteTestHooks.Push(point =>
                {
                    if (point != Did2ContactRouteFailpoint.AfterCurrentPeerEndpointSourceCapture || hit) return;
                    hit = true;
                    opened.WithSqlAsync(sql =>
                    {
                        using var change = ActualConnection(sql).CreateCommand();
                        change.CommandText = defect == "plaintext"
                            ? "UPDATE events SET plaintext=zeroblob(length(plaintext)) WHERE operation=$operation AND direction=2;"
                            : "UPDATE events SET rowid=rowid+1000 WHERE operation=$operation AND direction=2;";
                        change.Parameters.AddWithValue("$operation", operation); Assert.Equal(1, change.ExecuteNonQuery()); return true;
                    }, default).GetAwaiter().GetResult();
                });
                var failure = await Record.ExceptionAsync(async () =>
                {
                    using var rejected = await ObserveCurrentPeerRead(owner, "ReadLiveRouteHistorySourcesUnderLeaseAsync",
                        opened, (byte)2, held, CancellationToken.None);
                });
                Assert.True(hit); Assert.True(failure is CryptographicException or InvalidDataException or FormatException,
                    "Actual selected source substitution must reject outside a provider result: " + failure?.GetType().Name);
            });
        }

        private async Task WithCurrentPeerEndpointOwner(Did2MessagingSessionScope scope,
            Func<ProtectedDeepIdV2AccountOwner, OwnedDid2MessagingStorage, HeldDeepIdV2AccountLease, Task> inspect)
        {
            var folder = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var accountPath = Path.Combine(folder, "deep-store-v2-account.dsv2");
            var ownerLease = new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(NativeStorage(scope), ownerLease, accountPath, Network, 1);
            using var current = await owner.ReadCurrentAsync(CurrentProofTime, pq, default) ?? throw new InvalidDataException();
            using var held = await ownerLease.AcquireAsync(default);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOrdinaryMessagingUnderLeaseAsync(NativeStorage(scope), accountPath,
                current, scope, default);
            await inspect(owner, opened, held);
        }

        private static async Task<ObservedCurrentPeerRead> ObserveCurrentPeerRead(ProtectedDeepIdV2AccountOwner owner, string name, params object[] arguments)
        {
            var method = typeof(ProtectedDeepIdV2AccountOwner).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException("The actual current peer route owner boundary is absent.");
            var task = (Task)method.Invoke(owner, arguments)!; await task;
            var qualified = (IDisposable)(task.GetType().GetProperty("Result")!.GetValue(task) ?? throw new InvalidDataException());
            var type = qualified.GetType();
            var snapshot = (Did2RouteHistorySnapshot)type.GetProperty("Snapshot", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(qualified)!;
            var authored = type.GetProperty("Authored", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(qualified)!;
            var paired = (Did2MessagingArchiveAuthoredRead)authored.GetType().GetProperty("PairedRead", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(authored)!;
            var events = (IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>>)authored.GetType().GetProperty("Events", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(authored)!;
            return new(qualified, snapshot, paired, events);
        }
    }
}
