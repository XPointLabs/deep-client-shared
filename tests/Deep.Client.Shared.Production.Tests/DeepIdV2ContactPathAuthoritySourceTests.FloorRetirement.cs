using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MailboxFloorRetirement_ActualCompletedAckKeepsSemanticCustodyAndLastRetainedRoute()
    {
        // Real Store/receive/ACK advances the fixture clock. Sign enough initial
        // authority for that work and a separate successor covering exclusion;
        // do not freeze time or bypass the exact XNV1 issuance interval check.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckCompletedAckFloorRetirementAsync();
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MailboxFloorRetirement_ChangedNativeSqlPinsTheSameColdRecoveryPlan()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckCompletedAckFloorRetirementAsync(nativeSqlFault: true);
    }

    [Theory]
    [InlineData(false, 0)] [InlineData(false, 1)] [InlineData(false, 2)] [InlineData(false, 3)] [InlineData(false, 4)]
    [InlineData(true, 0)] [InlineData(true, 1)] [InlineData(true, 2)] [InlineData(true, 3)] [InlineData(true, 4)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MailboxFloorRetirement_ColdRecoveryRemovesOnlyExcludedIdleCounter(bool deposit, int handover)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, shortMailboxAuthority: true);
        await fixture.CheckIdleFloorRetirementAsync(deposit, handover);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MailboxFloorRetirement_ActiveExactWorkPinsFloorWithoutStaging(bool deposit)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, shortMailboxAuthority: true);
        await fixture.CheckIdleFloorRetirementAsync(deposit, 0, active: true);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MailboxFloorRetirement_UncommittedExactPlanCanAbandon(bool deposit)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, shortMailboxAuthority: true);
        await fixture.CheckIdleFloorRetirementAsync(deposit, 0, abandon: true);
    }

    [Theory]
    [InlineData(false, 0)] [InlineData(false, 1)] [InlineData(false, 2)] [InlineData(false, 3)]
    [InlineData(true, 0)] [InlineData(true, 1)] [InlineData(true, 2)] [InlineData(true, 3)]
    [InlineData(false, 4)] [InlineData(true, 4)] [InlineData(false, 5)] [InlineData(true, 5)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MailboxFloorRetirement_ChangedGuardNativeFenceOrMissingPartRejectsRecovery(bool deposit, int fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, shortMailboxAuthority: true);
        await fixture.CheckIdleFloorRetirementAsync(deposit, 0, fault: fault);
    }

    [Theory]
    [InlineData(false, 0)] [InlineData(false, 1)] [InlineData(true, 0)] [InlineData(true, 1)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MailboxFloorRetirement_CancellationKeepsExactRecoveryOwner(bool deposit, int handover)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, shortMailboxAuthority: true);
        await fixture.CheckIdleFloorRetirementAsync(deposit, handover, cancel: true, abandon: handover == 0);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckCompletedAckFloorRetirementAsync(bool nativeSqlFault = false, bool retireSupersededHolder = false,
            bool retireClosedRenewal = false)
        {
            var intent = Bytes(32, 0xd1);
            var (complete, _, _, _, _) = await PrepareNativeHelloCompletion(intent, verifyDraftRecovery: false);
            byte[] initial;
            using (var committed = await complete(accounts)) initial = committed.ExactDph2.ToArray();
            TrackMailboxDispatchClock(); // Signed fixture sample advances with actual native dispatch time.
            var deposit = new OwnedGrantTransport(this, ownerOnPrimary: true);
            var store = new OwnedStoreFixture(this, null, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent), initial);
            try { _ = await StartNativeContact(intent, deposit, store); }
            catch (ClientMailboxDispatchOutcomeUnknownException)
            {
                // A slow durable Store may cross the existing 30s return fence.
                // Reconcile once through the public original-operation path;
                // do not resolve again, stretch time or reauthor the request.
                var original = store.ExactRequest?.ToArray() ?? throw new InvalidDataException();
                try
                {
                    _ = await ReplayInitialStartWithoutResolver(intent, deposit, store);
                    Assert.Equal(original, store.ExactRequest); Assert.Equal(1, deposit.Calls);
                }
                finally { CryptographicOperations.ZeroMemory(original); }
            }
            var retrieve = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: false);
            var terminal = new OwnedReadTerminal(this, initial) { RetainedEnvelope = store.StoredEnvelope };
            var received = await SynchronizeNativeReceiver(retrieve, terminal);
            Assert.Equal(1, received.ProcessedEnvelopes); Assert.Equal(1, received.DurableTombstones);
            var receiver = await ReceiveNativeMailboxInitial(initial);
            Assert.Equal(Did2ContactAcceptanceState.IncomingRequest, await ReadOwnedContactState(receiver));
            using (var read = await ReadPeerMailboxReads())
            { Assert.Equal(0, read.Phase); Assert.Null(read.Active); Assert.Equal(2UL, Assert.Single(read.Counters).Value); }
            if (retireClosedRenewal)
            {
                await CheckLinkedUnusedRetrieveRetirementAsync(own: false);
                Assert.Equal(Did2ContactAcceptanceState.IncomingRequest, await ReadOwnedContactState(receiver));
                return;
            }
            byte[] selector; ulong ceiling;
            using (var grants = await ReadPeerGrantsAsync())
            {
                var entry = Assert.Single(grants.Entries).Value;
                selector = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(entry));
                ceiling = ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry);
            }
            await AdvanceNetworkAsync(expiry: 6_000); AuthorSignedEpochAdvance();
            var nextTime = checked(ceiling + 5); Sample = checked(Sample + nextTime - ProofTime); ProofTime = nextTime;
            var pinnedSlots = new[] { ProtectedDid2MailboxGrantJournal.Slot, ProtectedDid2DirectTextJournal.Slot,
                ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot, ProtectedDid2MailboxSendJournal.Slot,
                receiver.FloorSlot, Did2MessagingHistoryCheckpoint.Slot(receiver), ProtectedDid2MessagingPeerBootstrap.Slot(receiver) };
            var hashes = new List<byte[]>();
            foreach (var slot in pinnedSlots)
            { using var raw = await peerStorage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); hashes.Add(raw.Use(bytes => SHA256.HashData(bytes))); }
            var reader = ReopenGrantReader();
            using (var exclusion = await reader.OpenMailboxEpochExclusionAsync(selector, GrantReaderSource(reader)))
            {
                var dependencies = await exclusion.CaptureRetirementDependenciesAsync();
                Assert.True(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.RetainedRetrievePath));
                Assert.True(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.UnresolvedReceiptOrObject));
                Assert.True(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.ReadTraversal));
                Assert.True(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.ReadFloor));
                Assert.False(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.ReadWork));
                if (nativeSqlFault)
                {
                    using (Did2CompactionTestHooks.Push(point =>
                    { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Injected native-state recovery handover."); }))
                        await Assert.ThrowsAsync<IOException>(() => exclusion.RetireIdleMailboxCounterFloorAsync());
                }
                else await exclusion.RetireIdleMailboxCounterFloorAsync();
            }
            Assert.IsType<CompactionDiskFixtureStorage>(peerStorage).Reopen();
            if (nativeSqlFault)
            {
                var accountDirectory = Path.Combine(directory, "peer");
                var lease = new DeepIdV2AccountFileLease(Path.Combine(accountDirectory, "deep-store-v2-account.lock"));
                async Task WithNative(Action<Microsoft.Data.Sqlite.SqliteConnection> change)
                {
                    using var held = await lease.AcquireAsync(default);
                    using var catalog = await new ProtectedDid2MessagingSessionCatalog(peerStorage, Network,
                        receiver.LocalAccount, receiver.Instance).ReadAsync(default);
                    using var sql = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(
                        Path.Combine(accountDirectory, "deep-store-v2-account.dsv2"), catalog, receiver, held, lease);
                    change(sql); held.RequireActive();
                }
                byte[] original = [];
                await WithNative(sql =>
                {
                    using var read = sql.CreateCommand(); read.CommandText = "SELECT envelope FROM initial_events;";
                    original = (byte[])read.ExecuteScalar()!;
                    using var change = sql.CreateCommand(); change.CommandText = "UPDATE initial_events SET envelope=$altered;";
                    var altered = original.ToArray(); altered[^1] ^= 1;
                    change.Parameters.AddWithValue("$altered", altered); Assert.Equal(1, change.ExecuteNonQuery());
                });
                try
                {
                    using var before = await peerStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    using var readBefore = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
                    var error = await Record.ExceptionAsync(() => PeerRetirementOwner().ResumeOwnedLocalCompactionAsync(default));
                    Assert.True(error is CryptographicException or InvalidDataException, error?.GetType().Name ?? "Unexpected successful recovery");
                    using var after = await peerStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    using var readAfter = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
                    Assert.Equal(before.Use(bytes => bytes.ToArray()), after.Use(bytes => bytes.ToArray()));
                    Assert.Equal(readBefore.Use(bytes => bytes.ToArray()), readAfter.Use(bytes => bytes.ToArray()));
                    await WithNative(sql =>
                    {
                        using var read = sql.CreateCommand(); read.CommandText = "SELECT envelope FROM initial_events;";
                        var altered = original.ToArray(); altered[^1] ^= 1; Assert.Equal(altered, (byte[])read.ExecuteScalar()!);
                        using var restore = sql.CreateCommand(); restore.CommandText = "UPDATE initial_events SET envelope=$original;";
                        restore.Parameters.AddWithValue("$original", original); Assert.Equal(1, restore.ExecuteNonQuery());
                    });
                    for (var index = 0; index < pinnedSlots.Length; index++)
                    { using var raw = await peerStorage.ReadOwnedAsync(pinnedSlots[index]) ?? throw new InvalidDataException(); Assert.Equal(hashes[index], raw.Use(bytes => SHA256.HashData(bytes))); }
                }
                finally { CryptographicOperations.ZeroMemory(original); }
            }
            await PeerRetirementOwner().ResumeOwnedLocalCompactionAsync(default);
            using (var read = await ReadPeerMailboxReads())
            { Assert.Equal(0, read.Phase); Assert.Empty(read.Counters); Assert.Single(read.Traversals); }
            reader = ReopenGrantReader();
            using (var exclusion = await reader.OpenMailboxEpochExclusionAsync(selector, GrantReaderSource(reader)))
            {
                var dependencies = await exclusion.CaptureRetirementDependenciesAsync();
                Assert.True(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.ReadTraversal));
                Assert.True(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.RetainedRetrievePath));
                Assert.False(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.ReadFloor));
                using var plan = await peerStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                await Assert.ThrowsAsync<IOException>(() => exclusion.RetireUnusedClosedDepositAcquisitionAsync());
                using var actualPlan = await peerStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                Assert.Equal(plan.Use(bytes => bytes.ToArray()), actualPlan.Use(bytes => bytes.ToArray()));
            }
            for (var index = 0; index < pinnedSlots.Length; index++)
            { using var raw = await peerStorage.ReadOwnedAsync(pinnedSlots[index]) ?? throw new InvalidDataException(); Assert.Equal(hashes[index], raw.Use(bytes => SHA256.HashData(bytes))); }
            // Durable local display survives exclusion; it does not renew the
            // expired Hello/rendezvous or mint current operation authority.
            var priorProofRequests = ProofRequests;
            var local = Assert.Single(await ReopenGrantReader().ListConversationsAsync());
            Assert.Equal(DeepIdV2ContactState.IncomingRequest, local.ContactState);
            Assert.Equal(receiver.Exact.ToArray(), local.Conversation.Scope.Exact.ToArray());
            Assert.Equal(priorProofRequests, ProofRequests);
            await Assert.ThrowsAsync<CryptographicException>(() => ReadOwnedContactState(receiver));
            Assert.Equal(1, retrieve.Calls); Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
            // Old grant cannot dispatch again after losing its floor; current
            // authority rejects it before any new Retrieve/ACK callback.
            await Assert.ThrowsAsync<CryptographicException>(() => SynchronizeNativeReceiver(retrieve, terminal));
            Assert.Equal(1, retrieve.Calls); Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
            if (retireSupersededHolder)
                await CheckSupersededRetrieveRetirementAsync(retrieve, own: false, selector);
            CryptographicOperations.ZeroMemory(initial); CryptographicOperations.ZeroMemory(selector);
        }

        internal async Task CheckIdleFloorRetirementAsync(bool deposit, int handover,
            bool active = false, bool abandon = false, int fault = -1, bool cancel = false)
        {
            var publication = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this) { ShorterSignedExpiry = 1_200 };
            var route = await EnsureRoute(publication.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold, new OwnedPublicationSource(this, route), replicas);
            var transport = new OwnedGrantTransport(this, selfRetrieve: !deposit);
            if (deposit)
            {
                var address = (await accounts.GetCurrentAsync())!.PermanentId;
                var reader = ReopenGrantReader(); var source = GrantReaderSource(reader);
                var resolved = await reader.ResolvePermanentContactAsync(address, source, new SyntheticPermanentRead(this, source, replicas.ExactPublication));
                _ = await reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport);
            }
            else
            {
                transport = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
                var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
                if (active)
                {
                    using (ClientMailboxRetrieveTestHooks.Push(point =>
                    { if (point == ClientMailboxRetrieveFailpoint.AfterPageCommit) throw new IOException("Injected captured-poll handover."); }))
                        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => SynchronizeNativeSender(transport, terminal));
                    using var captured = await ReadPeerMailboxReads(own: true);
                    Assert.Equal(3, captured.Phase); Assert.NotNull(captured.Active);
                }
                else
                {
                    var empty = await SynchronizeNativeSender(transport, terminal);
                    Assert.Equal(0, empty.ProcessedEnvelopes); Assert.Equal(1, terminal.RetrieveCalls);
                    using var completed = await ReadPeerMailboxReads(own: true);
                    Assert.Equal(0, completed.Phase); Assert.Null(completed.Active); Assert.Single(completed.Counters);
                }
            }
            var selectedStorage = deposit ? peerStorage : storage;
            var changedSlot = deposit ? ProtectedDid2MailboxSendJournal.Slot : ProtectedDid2MailboxReadJournal.Slot;
            byte[] acquisition, grantDigest; ulong ceiling;
            using (var grants = await ReadPeerGrantsAsync(own: !deposit))
            {
                var entry = Assert.Single(grants.Entries).Value;
                acquisition = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(entry));
                ceiling = ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry);
                var exactGrant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8);
                grantDigest = SHA256.HashData(exactGrant.Span);
                if (deposit)
                {
                    // Isolated protected-floor fixture for a signed known
                    // winner. No completed Store/remote non-delivery is claimed.
                    // A matching synthetic pending commitment must still pin it.
                    using var raw = await selectedStorage.ReadOwnedAsync(changedSlot) ?? throw new InvalidDataException();
                    var before = raw.Use(bytes => bytes.ToArray());
                    using var state = ProtectedDid2MailboxSendJournal.Decode(before, Network, before.AsSpan(28, 32), before.AsSpan(60, 32));
                    state.EnrollGrant(MailboxAuthenticatedCapabilityCodec.DecodeGrant(exactGrant.Span));
                    state.EnrollScope(Bytes(32, 0xe1), Bytes(32, 0xe2)); state.Revision += 2;
                    if (active)
                    {
                        var scopeBytes = Bytes(Did2MessagingSessionScope.Bytes, 0x30);
                        scopeBytes[0] = 1; scopeBytes[1] = 1; scopeBytes[2] = 0; scopeBytes[3] = 0;
                        scopeBytes[132] = 0x31; scopeBytes[172] = 0x32;
                        var scope = Did2MessagingSessionScope.RestoreMetadata(scopeBytes);
                        var pending = ProtectedDid2MailboxSendJournal.Entry.Pending(scope, Bytes(32, 0xe3), grantDigest, entry.AsSpan(64, 32), new()
                        {
                            Epoch = 1, MailboxId = new(Bytes(32, 0xe4)), PlacementId = new(Bytes(32, 0xe5)),
                            OperationId = Bytes(16, 0xe6), DeduplicationDigest = SHA256.HashData(Bytes(64, 0xe7)),
                            CreatedAtUnixSeconds = 1_000, ExpiresAtUnixSeconds = 1_200, Ciphertext = Bytes(64, 0xe7)
                        });
                        state.Entries.Add(pending.Name, pending); state.Revision++;
                    }
                    var after = ProtectedDid2MailboxSendJournal.Encode(state, Network, before.AsSpan(28, 32), before.AsSpan(60, 32));
                    try { Assert.True(await selectedStorage.CompareExchangeAsync(changedSlot, before, after)); }
                    finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
                }
            }
            await AdvanceNetworkAsync(); AuthorSignedEpochAdvance();
            var nextTime = checked(ceiling + 5); Sample = checked(Sample + nextTime - ProofTime); ProofTime = nextTime;
            var slots = new[] { ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxSendJournal.Slot,
                ProtectedDid2MailboxGrantJournal.Slot, ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot,
                ProtectedDid2AttachmentJournal.Slot, SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot };
            var originals = new Dictionary<string, byte[]>();
            foreach (var slot in slots)
            { using var raw = await selectedStorage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); originals.Add(slot, raw.Use(bytes => bytes.ToArray())); }
            try
            {
                var reader = deposit ? ReopenGrantReader() : ReopenAccount();
                var source = deposit ? GrantReaderSource(reader) : Source(reader);
                var points = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSqlRecorded,
                    Did2CompactionFailpoint.AfterHistoryAdopted, Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
                using var cancellation = new CancellationTokenSource();
                using (var exclusion = await reader.OpenMailboxEpochExclusionAsync(acquisition, source))
                {
                    var dependencies = await exclusion.CaptureRetirementDependenciesAsync();
                    Assert.True(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.UnresolvedReceiptOrObject));
                    if (!deposit) Assert.True(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.RetainedRetrievePath));
                    if (active)
                    {
                        using var planBefore = await selectedStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                        await Assert.ThrowsAsync<IOException>(() => exclusion.RetireIdleMailboxCounterFloorAsync());
                        using var planAfter = await selectedStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                        Assert.Equal(planBefore.Use(bytes => bytes.ToArray()), planAfter.Use(bytes => bytes.ToArray()));
                    }
                    else
                    {
                        using (Did2CompactionTestHooks.Push(point =>
                        { if (point != points[handover]) return; if (cancel) cancellation.Cancel(); else throw new IOException("Injected counter retirement handover."); }))
                        {
                            if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => exclusion.RetireIdleMailboxCounterFloorAsync(cancellation.Token));
                            else await Assert.ThrowsAsync<IOException>(() => exclusion.RetireIdleMailboxCounterFloorAsync());
                        }
                    }
                }
                if (active)
                {
                    foreach (var slot in slots)
                    { using var raw = await selectedStorage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); Assert.Equal(originals[slot], raw.Use(bytes => bytes.ToArray())); }
                    return;
                }
                if (deposit) Assert.IsType<CompactionDiskFixtureStorage>(peerStorage).Reopen();
                else ColdReopenCompactionStorage();
                var owner = deposit ? PeerRetirementOwner() : SenderCompactionOwner();
                if (fault is 4 or 5)
                {
                    using var rawPlan = await selectedStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    var exactPlan = rawPlan.Use(bytes => bytes.ToArray());
                    byte[]? counter = null;
                    var account = originals[ProtectedDid2MailboxGrantJournal.Slot].AsMemory(28, 32);
                    try
                    {
                        if (fault == 4)
                        {
                            // A valid, same-width SQL-only epoch value changes while
                            // every protected root and DNH2 remains byte-exact.
                            // Grant installation owns this row; replay counters need
                            // not exist before the first actual Store request.
                            await WithOwnedApplicationConnectionAsync(!deposit, Network, account, sql =>
                            {
                                using var read = sql.CreateCommand(); read.CommandText = "SELECT expires_at FROM mailbox_credential_epochs;";
                                counter = (byte[])read.ExecuteScalar()!; Assert.Equal(8, counter.Length);
                                using var change = sql.CreateCommand();
                                change.CommandText = "UPDATE mailbox_credential_epochs SET expires_at=$next;";
                                var altered = counter.ToArray(); altered[^1] ^= 1;
                                change.Parameters.AddWithValue("$next", altered); Assert.Equal(1, change.ExecuteNonQuery());
                            });
                        }
                        else
                        {
                            using var plan = Did2CompactionPlan.Decode(exactPlan, Network, account.Span, exactPlan.AsSpan(64, 32));
                            Assert.Equal(9, plan.RootCount);
                            var obsolete = new byte[exactPlan.Length - Did2CompactionPlan.RootBytes];
                            exactPlan.AsSpan(0, Did2CompactionPlan.HeaderBytes + 8 * Did2CompactionPlan.RootBytes).CopyTo(obsolete);
                            exactPlan.AsSpan(Did2CompactionPlan.HeaderBytes + 9 * Did2CompactionPlan.RootBytes).CopyTo(obsolete.AsSpan(Did2CompactionPlan.HeaderBytes + 8 * Did2CompactionPlan.RootBytes));
                            obsolete[3] = 8;
                            Assert.True(await selectedStorage.CompareExchangeAsync(Did2CompactionPlan.Slot, exactPlan, obsolete));
                        }
                        using var beforeRefusal = await selectedStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                        await Assert.ThrowsAsync<InvalidDataException>(() => owner.ResumeOwnedLocalCompactionAsync(default));
                        using var afterRefusal = await selectedStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                        Assert.Equal(beforeRefusal.Use(bytes => bytes.ToArray()), afterRefusal.Use(bytes => bytes.ToArray()));
                        foreach (var slot in slots)
                        { using var raw = await selectedStorage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); Assert.Equal(originals[slot], raw.Use(bytes => bytes.ToArray())); }
                        if (fault == 4)
                            await WithOwnedApplicationConnectionAsync(!deposit, Network, account, sql =>
                            {
                                using var read = sql.CreateCommand(); read.CommandText = "SELECT expires_at FROM mailbox_credential_epochs;";
                                var altered = counter!.ToArray(); altered[^1] ^= 1; Assert.Equal(altered, (byte[])read.ExecuteScalar()!);
                                using var restore = sql.CreateCommand(); restore.CommandText = "UPDATE mailbox_credential_epochs SET expires_at=$original;";
                                restore.Parameters.AddWithValue("$original", counter!); Assert.Equal(1, restore.ExecuteNonQuery());
                            });
                        else Assert.True(await selectedStorage.CompareExchangeAsync(Did2CompactionPlan.Slot,
                            afterRefusal.Use(bytes => bytes.ToArray()), exactPlan));
                        fault = -1; // Restored only this fixture's exact original state; finish the same plan.
                    }
                    finally { CryptographicOperations.ZeroMemory(exactPlan); if (counter is not null) CryptographicOperations.ZeroMemory(counter); }
                }
                if (fault >= 0)
                {
                    if (fault == 0) await selectedStorage.DeleteBatchAsync([ProtectedDid2CompactionPlan.PartSlot(0)]);
                    else if (fault == 1) await selectedStorage.DeleteBatchAsync([ProtectedDid2AttachmentJournal.Slot]);
                    else if (fault == 2)
                    {
                        using var sql = deposit ? await OpenPeerRetirementSqlAsync() : await OpenSqlAsync();
                        using var change = sql.CreateCommand(); change.CommandText = "DELETE FROM protected_lkg_root WHERE root_kind=3;";
                        Assert.Equal(1, change.ExecuteNonQuery());
                    }
                    else
                    {
                        var before = originals[ProtectedDid2MailboxGrantJournal.Slot];
                        using var grants = ProtectedDid2MailboxGrantJournal.Decode(before, Network, before.AsSpan(28, 32), before.AsSpan(60, 32));
                        grants.Revision++;
                        var after = ProtectedDid2MailboxGrantJournal.Encode(grants, Network, before.AsSpan(28, 32), before.AsSpan(60, 32));
                        try { Assert.True(await selectedStorage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, before, after)); }
                        finally { CryptographicOperations.ZeroMemory(after); }
                    }
                    using var protectedPlan = await selectedStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    await Assert.ThrowsAsync<InvalidDataException>(() => owner.ResumeOwnedLocalCompactionAsync(default));
                    using var afterPlan = await selectedStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    Assert.Equal(protectedPlan.Use(bytes => bytes.ToArray()), afterPlan.Use(bytes => bytes.ToArray()));
                    return;
                }
                if (abandon) await owner.AbandonUncommittedMailboxRetirementAsync(default);
                else
                {
                    if (handover is > 0 and < 4)
                        await Assert.ThrowsAsync<InvalidOperationException>(() => owner.AbandonUncommittedMailboxRetirementAsync(default));
                    await owner.ResumeOwnedLocalCompactionAsync(default);
                }
                foreach (var slot in slots.Where(slot => slot != changedSlot || abandon))
                { using var raw = await selectedStorage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); Assert.Equal(originals[slot], raw.Use(bytes => bytes.ToArray())); }
                if (!abandon)
                {
                    using var raw = await selectedStorage.ReadOwnedAsync(changedSlot) ?? throw new InvalidDataException();
                    var before = originals[changedSlot];
                    if (deposit)
                    {
                        using var after = raw.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, Network, before.AsSpan(28, 32), before.AsSpan(60, 32)));
                        Assert.Single(after.Floors); Assert.Equal(Bytes(32, 0xe1), Assert.Single(after.Floors).Value.GrantHash);
                        Assert.Empty(after.Entries); Assert.Equal(4UL, after.Revision);
                    }
                    else
                    {
                        using var after = raw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, Network, before.AsSpan(28, 32), before.AsSpan(60, 32)));
                        using var prior = ProtectedDid2MailboxReadJournal.Decode(before, Network, before.AsSpan(28, 32), before.AsSpan(60, 32));
                        Assert.Empty(after.Counters); Assert.Equal(0, after.Phase); Assert.Null(after.Active);
                        Assert.Equal(prior.Traversals.Keys, after.Traversals.Keys);
                        Assert.Equal(Assert.Single(prior.Traversals).Value.PollGeneration, Assert.Single(after.Traversals).Value.PollGeneration);
                        Assert.Equal(prior.Revision + 1, after.Revision);
                    }
                }
                using (var plan = await selectedStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException())
                    Assert.Equal(0, plan.Use(bytes => bytes[1]));
                for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
                    Assert.Null(await selectedStorage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index)));
                if (!abandon)
                {
                    var reopened = deposit ? ReopenGrantReader() : ReopenAccount();
                    var currentSource = deposit ? GrantReaderSource(reopened) : Source(reopened);
                    using var exclusion = await reopened.OpenMailboxEpochExclusionAsync(acquisition, currentSource);
                    if (deposit) await Assert.ThrowsAsync<CryptographicException>(() => exclusion.RetireIdleMailboxCounterFloorAsync());
                    else await Assert.ThrowsAsync<InvalidDataException>(() => exclusion.RetireIdleMailboxCounterFloorAsync());
                    using var unchanged = await selectedStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    Assert.Equal(0, unchanged.Use(bytes => bytes[1])); // Missing floor is not reminted or restaged.
                }
                Assert.Equal(1, transport.Calls); // Local recovery never reissues or dispatches.
            }
            finally
            {
                foreach (var bytes in originals.Values) CryptographicOperations.ZeroMemory(bytes);
                CryptographicOperations.ZeroMemory(acquisition); CryptographicOperations.ZeroMemory(grantDigest);
            }
        }
    }
}
