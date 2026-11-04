using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryClosureCapacity_ActualMaximumFactRolesAtLawfulSuffixRejoinAfterColdOpen()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        var facts = new List<Did2RouteHistoryFactSelector>(); byte[] selectedOperation = [];
        var distinctFacts = new HashSet<string>(StringComparer.Ordinal);
        byte selectedAtom = 0, conflictClass = 0;
        // These are six actual owned threshold/publication/native transitions,
        // not rows manufactured to make the conservative 71/95 sums distinct.
        // First three establish archived basis/first-verified sources; the next
        // three leave working decisions, endpoint C/P and before-C/P roles.
        for (var generation = 1; generation <= 7 && (generation <= 6 || facts.Count < 12); generation++)
        {
            await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300,
                successorAdvertisementLifetimeSeconds: 500, proactive: generation != 1);
            using var command = await fixture.CreateOwnedRouteUpdate(sender);
            var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ParsedPayload);
            selectedOperation = command.OperationId.ToArray(); selectedAtom = 1;
            conflictClass = page.Atoms[0].IsCompleted ? (byte)1 : (byte)2;
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId);
            using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray());
            Assert.Equal(3, received.RouteProcessing[0]);
            foreach (var fact in await fixture.ReadProducedRouteHistoryRoleFacts(sender, selectedOperation, page))
                if (facts.Count < 12 && distinctFacts.Add(Convert.ToHexString(fact.Selector.Span))) facts.Add(fact);
            if (generation == 3)
            {
                await fixture.ArchiveEntireEligibleSuffix(sender);
                await fixture.ArchiveEntireEligibleSuffix(receiver);
            }
        }
        Assert.Equal(12, facts.Count);
        Assert.Equal(12, facts.Select(value => Convert.ToHexString(value.Selector.Span)).Distinct(StringComparer.Ordinal).Count());
        await fixture.FillRouteHistoryLawfulActiveSuffix(sender, receiver);
        var selections = new (string Name, Did2RouteHistorySelection Selection)[]
        {
            ("ordinary-current", Did2RouteHistorySelection.Current(facts.TakeLast(2).ToArray())),
            ("catchup-twelve-facts", new(selectedOperation, selectedAtom, facts)),
            // This is actual source/application qualification for assessment of
            // a conflict candidate. It grants no conflict decision or authority;
            // all eight selected first-verified facts are genuine native data.
            ("conflict-eight-facts", Did2RouteHistorySelection.Conflict(selectedOperation, selectedAtom, conflictClass, facts.Take(8).ToArray()))
        };
        var before = await fixture.ReadMessagingFloor(sender);
        var observed = await fixture.ReadRouteHistoryClosureCapacity(sender, selections);
        Assert.Equal(new[] { 2, 12, 8 }, observed.Select(row => row.Facts));
        Assert.All(observed, row => Assert.InRange(row.Outgoing, 1, row.Ceiling));
        Assert.True(observed[1].Outgoing >= 6, "Twelve actual C/P facts did not retain the six independent outgoing publication originals.");
        Assert.True(observed[2].Outgoing >= 4, "Eight actual conflict fact purposes did not retain their four independent outgoing publication originals.");
        Assert.True(observed[1].WorkingOutgoing > 0);
        Assert.True(observed[1].ArchivedOutgoing > 0);
        // Production ordinary capacity is 63. Slot 64 is reserved for a
        // terminal latch, which changes Status to 2 and cannot enter this
        // Status1 route snapshot. Never fabricate active occupancy 64.
        await fixture.WithRouteReadSql(sender, (sql, connection) => Assert.Throws<InvalidOperationException>(() =>
        {
            using var rejected = sql.ReadVerifiedTransitionState(before, RandomNumberGenerator.GetBytes(32), [], out _);
        }));
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage(); fixture.ColdReopenReceiverStoreStorage();
        var reopened = await fixture.ReadRouteHistoryClosureCapacity(sender, selections);
        Assert.Equal(observed, reopened);
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
    }

    [Theory]
    [InlineData(71, 72)]
    [InlineData(95, 96)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryClosureCapacity_HostileOvercountRejectsAtActualOwnerBeforeProvidersOrEffects(int ceiling, int count)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, _) = await fixture.PrepareRouteHistoryPair();
        using (var command = await fixture.CreateOwnedText(sender, "actual outgoing source for hostile count boundary"))
        using (await fixture.SendOwnedMessage(sender, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span))) { }
        await fixture.RejectRouteHistoryOwnerOvercountBeforeEffects(sender, ceiling, count);
    }

    private sealed record RouteHistoryClosureCapacityObservation(string Purpose, int Ceiling, int Facts,
        int Outgoing, int ArchivedOutgoing, int WorkingOutgoing, int Decisions);

    private sealed partial class Fixture
    {
        internal async Task<IReadOnlyList<Did2RouteHistoryFactSelector>> ReadProducedRouteHistoryRoleFacts(
            Did2MessagingSessionScope scope, byte[] operation, ContactRouteHistoryDmc2Payload page)
        {
            var facts = new Dictionary<string, Did2RouteHistoryFactSelector>(StringComparer.Ordinal);
            await WithRouteReadSql(scope, (sql, connection) =>
            {
                _ = sql.VerifyTip();
                using var query = connection.CreateCommand();
                query.CommandText = "SELECT decision FROM route_decisions ORDER BY ordinal;";
                using var rows = query.ExecuteReader();
                while (rows.Read())
                {
                    var body = Did2RouteHistoryDecision.Decode(rows.GetFieldValue<byte[]>(0), scope);
                    if (body.Subject != 1 || body.Action != Did2RouteHistoryDecision.ActionKind.Evidence ||
                        !CryptographicOperations.FixedTimeEquals(body.Selected.Operation, operation)) continue;
                    foreach (var kind in new byte[] { 1, 2 })
                    {
                        var source = kind == 1 ? body.C : body.P;
                        if (source.Reference.Kind != 2 || source.AtomIndex == 0 ||
                            !CryptographicOperations.FixedTimeEquals(source.Reference.Operation, operation)) continue;
                        Assert.InRange(source.AtomIndex, (byte)1, checked((byte)page.Atoms.Count));
                        var atom = page.Atoms[source.AtomIndex - 1];
                        if (kind == 1) Assert.True(atom.IsCompleted);
                        var generation = kind == 1
                            ? BinaryPrimitives.ReadUInt64BigEndian(ContactRouteClosureCodec.Decode(atom.ExactCompletedRoute.Span).Reachability.Field(3).Span)
                            : BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", atom.ExactXra1.Span).Field(3).Span);
                        var selector = new Did2RouteHistoryFactSelector(Did2MessagingArchiveFamily.RouteHistory,
                            Did2MessagingArchiveRouteFacts.HistorySelector(1, kind, generation));
                        facts.TryAdd(Convert.ToHexString(selector.Selector.Span), selector);
                    }
                }
            });
            // Actual post-send Evidence, never page cursor values alone or an
            // unqualified original/Bootstrap anchor, supplies each selected key.
            Assert.NotEmpty(facts);
            return facts.Values.ToArray();
        }

        internal async Task FillRouteHistoryLawfulActiveSuffix(Did2MessagingSessionScope sender, Did2MessagingSessionScope receiver)
        {
            var turn = 0;
            while ((await ReadMessagingFloor(sender)).Ordinal - (await ReadNativeArchive(sender)).Basis.Ordinal < 63)
            {
                Assert.True(turn < 64, "Genuine suffix construction did not advance within its fixed budget.");
                // Real feedback first, then four authored originals for every
                // one incoming event, matching the sustained native send test's
                // lawful PQ refresh cadence. Do not freeze/reset Braid state to
                // pretend that an all-outgoing suffix is automatically valid.
                var scope = turn++ % 5 == 0 ? receiver : sender;
                using var command = await CreateOwnedText(scope, "lawful route source closure suffix feedback");
                using var sent = await SendOwnedMessage(scope, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span));
                using var received = await ReceiveOwnedMessage(scope.IsInitiator ? receiver : sender, sent.ExactEnvelope.ToArray());
            }
            Assert.Equal(63UL, (await ReadMessagingFloor(sender)).Ordinal - (await ReadNativeArchive(sender)).Basis.Ordinal);
        }

        internal async Task<RouteHistoryClosureCapacityObservation[]> ReadRouteHistoryClosureCapacity(Did2MessagingSessionScope scope,
            IReadOnlyList<(string Name, Did2RouteHistorySelection Selection)> selections)
        {
            var folder = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var accountPath = Path.Combine(folder, "deep-store-v2-account.dsv2");
            var ownerLease = new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(NativeStorage(scope), ownerLease, accountPath, Network, 1);
            // Use the moving signed fixture time after renewal; keep the
            // existing genuinely signed 6000s head/network window unchanged.
            Assert.InRange(CurrentProofTime, 1_000UL, 5_999UL);
            using var current = await owner.ReadCurrentAsync(CurrentProofTime, pq, default) ?? throw new InvalidDataException();
            using var held = await ownerLease.AcquireAsync(default);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOrdinaryMessagingUnderLeaseAsync(NativeStorage(scope), accountPath,
                current, scope, default);
            var method = typeof(ProtectedDeepIdV2AccountOwner).GetMethod("ReadRouteHistorySourcesUnderLeaseAsync", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException("The actual route-source owner boundary is absent.");
            var output = new List<RouteHistoryClosureCapacityObservation>();
            foreach (var selection in selections)
            {
                var task = (Task)method.Invoke(owner, [opened, (byte)1, selection.Selection, held, CancellationToken.None])!;
                await task;
                using var qualified = (IDisposable)(task.GetType().GetProperty("Result")!.GetValue(task) ?? throw new InvalidDataException());
                var type = qualified.GetType();
                var snapshot = (Did2RouteHistorySnapshot)type.GetProperty("Snapshot", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(qualified)!;
                var authored = type.GetProperty("Authored", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(qualified)!;
                var paired = (Did2MessagingArchiveAuthoredRead)authored.GetType().GetProperty("PairedRead", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(authored)!;
                var events = (IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>>)authored.GetType().GetProperty("Events", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(authored)!;
                var outgoing = snapshot.Originals.Where(row => row.Reference.Kind == 2 && row.Reference.Direction == 1).ToArray();
                Assert.Equal(outgoing.Length, outgoing.Select(row => Convert.ToHexString(row.Reference.Exact.Span)).Distinct(StringComparer.Ordinal).Count());
                Assert.Equal(outgoing.Length, events.Count);
                Assert.Equal(selection.Selection.Facts.Count, snapshot.Facts.Count);
                Assert.All(snapshot.Facts, fact => Assert.True(fact.Value.HasValue, "A maximum-role selector did not name an actual native first-verified fact."));
                foreach (var fact in snapshot.Facts)
                {
                    var verified = Did2MessagingArchiveReference.Decode(fact.Value!.Value.Span[..88], false);
                    Assert.Equal(3, verified.Kind);
                    var decision = snapshot.FindDecision(verified);
                    Assert.Equal(Did2RouteHistoryDecision.ActionKind.Evidence, decision.Body.Action);
                    var source = fact.Selector.Selector.Span[1] == 1 ? decision.Body.C : decision.Body.P;
                    Assert.Equal(2, source.Reference.Kind); Assert.True(source.AtomIndex > 0);
                }
                _ = await opened.WithPairedSqlAsync(paired, sql => { sql.RequireRouteHistorySnapshot(snapshot, events); return true; }, default);
                var result = new RouteHistoryClosureCapacityObservation(selection.Name, selection.Selection.MaximumAuthoredOriginals,
                    snapshot.Facts.Count, outgoing.Length, outgoing.Count(row => row.Reference.Ordinal <= snapshot.ArchiveRoot.Basis.Ordinal),
                    outgoing.Count(row => row.Reference.Ordinal > snapshot.ArchiveRoot.Basis.Ordinal), snapshot.Decisions.Count);
                output.Add(result);
                // Closed counts only: no native operation, identifier, selector,
                // key, plaintext or protected path is emitted as evidence.
                Console.WriteLine($"route-source-capacity purpose={result.Purpose} ceiling={result.Ceiling} facts={result.Facts} outgoing={result.Outgoing} archived={result.ArchivedOutgoing} working={result.WorkingOutgoing} decisions={result.Decisions}");
            }
            held.RequireOwner(ownerLease); return output.ToArray();
        }

        internal async Task RejectRouteHistoryOwnerOvercountBeforeEffects(Did2MessagingSessionScope scope, int ceiling, int count)
        {
            var before = await ReadMessagingFloor(scope);
            var application = await ReadCompleteOrdinaryApplicationProjection(scope);
            var obligations = (await ListOwnedReceiptObligations(scope)).Count;
            byte[] projection = [];
            IReadOnlyList<Did2MessagingArchiveOriginal>? sources = null;
            await WithRouteReadSql(scope, (sql, _) =>
            {
                projection = sql.ReadCompleteCompactionProjection();
                sources = sql.ReadRouteHistoryAuthoredSources(before, 1, Did2RouteHistorySelection.Initial());
            });
            try
            {
                var actualSources = sources ?? throw new InvalidDataException("Actual native source capture did not return its owned group.");
                Assert.NotEmpty(actualSources);
                // Deliberately hostile multiplicity of REAL captured originals.
                // This checks the entry count guard; it does not claim that 72
                // or 96 distinct originals form a valid/reachable authority graph.
                var hostile = Enumerable.Range(0, count).Select(index => actualSources[index % actualSources.Count]).ToArray();
                var folder = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
                var ownerLease = new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock"));
                var probe = new RouteHistoryCapacityProviderProbe(NativeStorage(scope));
                var owner = new ProtectedDeepIdV2AccountOwner(probe, ownerLease, Path.Combine(folder, "deep-store-v2-account.dsv2"), Network, 1);
                using (var held = await ownerLease.AcquireAsync(default))
                {
                    var method = typeof(ProtectedDeepIdV2AccountOwner).GetMethod("QualifyArchiveAuthoredAsync", BindingFlags.Instance | BindingFlags.NonPublic)
                        ?? throw new InvalidOperationException("The actual authored-source owner boundary is absent.");
                    var task = (Task)method.Invoke(owner, [scope, hostile, held, CancellationToken.None, ceiling])!;
                    var error = await Assert.ThrowsAsync<InvalidDataException>(() => task);
                    Assert.Equal("Authored qualification requires bounded outgoing actual originals.", error.Message);
                    Assert.Equal(0, probe.Calls); held.RequireOwner(ownerLease);
                }
                Assert.Equal(before.Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
                Assert.Equal(application, await ReadCompleteOrdinaryApplicationProjection(scope));
                Assert.Equal(obligations, (await ListOwnedReceiptObligations(scope)).Count);
                await WithRouteReadSql(scope, (sql, _) => Assert.Equal(projection, sql.ReadCompleteCompactionProjection()));
            }
            finally
            {
                if (sources is not null) foreach (var source in sources) source.Dispose();
                CryptographicOperations.ZeroMemory(application); CryptographicOperations.ZeroMemory(projection);
            }
        }
    }

    private sealed class RouteHistoryCapacityProviderProbe(IDeepSecureStorage inner) : IDeepSecureStorage, IDeepSecureStorageGuardedRead
    {
        internal int Calls;
        private Task<T> Count<T>(Func<Task<T>> call) { Calls++; return call(); }
        private Task Count(Func<Task> call) { Calls++; return call(); }
        public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken cancellationToken = default) => Count(() => inner.ReadOwnedAsync(slot, cancellationToken));
        public Task<OwnedDeepSecretBatch> ReadOwnedBatchAsync(IReadOnlyList<string> slots, CancellationToken cancellationToken = default) => Count(() => inner.ReadOwnedBatchAsync(slots, cancellationToken));
        Task<OwnedDeepSecretBatch> IDeepSecureStorageGuardedRead.ReadOwnedGuardedBatchAsync(DeepSecureStorageGuardedRead request, CancellationToken cancellationToken) => Count(() => inner.ReadOwnedGuardedBatchAsync(request.ReturnedSlots, request.Guards, cancellationToken));
        public Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken cancellationToken = default) => Count(() => inner.WriteBatchAsync(writes, cancellationToken));
        public Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, CancellationToken cancellationToken = default) => Count(() => inner.CompareExchangeAsync(slot, expected, replacement, cancellationToken));
        public Task<bool> CompareExchangeAndInsertAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, IReadOnlyList<DeepSecureStorageWrite> insertions, CancellationToken cancellationToken = default) => Count(() => inner.CompareExchangeAndInsertAsync(slot, expected, replacement, insertions, cancellationToken));
        public Task<bool> CompareAndDeleteAsync(string guardSlot, ReadOnlyMemory<byte> expected, IReadOnlyList<string> slots, CancellationToken cancellationToken = default) => Count(() => inner.CompareAndDeleteAsync(guardSlot, expected, slots, cancellationToken));
        public Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken cancellationToken = default) => Count(() => inner.DeleteBatchAsync(slots, cancellationToken));
        public Task PurgeStoreV1NamespaceAsync(CancellationToken cancellationToken = default) => Count(() => inner.PurgeStoreV1NamespaceAsync(cancellationToken));
        public Task PurgeStoreV2NamespaceAsync(CancellationToken cancellationToken = default) => Count(() => inner.PurgeStoreV2NamespaceAsync(cancellationToken));
    }
}
