using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_ProtectedProviderEdgesClosePhysicalSourceAndColdRecoveryKeepsKeysDestroyed()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.CheckCancellationProviderPhysicalBoundary();
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_ActualProviderSubstitutionRejectsBeforeSourceDeleteAndColdExactRecovery(bool registration)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.CheckCancellationProviderSubstitution(registration);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_ElevenOtherCancelledScopesKeepGuardedSourceAuditAndMutationFences()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.CheckCancellationGuardedCapacity();
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_FinalStableRetirementRollbackRejectsWithoutRepairAndColdExactRestoreRecovers()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.CheckFinalCancellationRetirementRollback();
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_StoppedOrdinalZeroMissingEntireSourceRejectsWithoutReprovisioning()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.CheckStoppedCancellationMissingEntireSource();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckStoppedCancellationMissingEntireSource()
        {
            var intent = Bytes(32, 0xc7);
            _ = await PrepareNativeHelloCompletion(intent, preSessionCut: "draft");
            var stopped = false;
            using (Did2MailboxSendTestHooks.Push(point =>
            {
                if (point != Did2MailboxSendFailpoint.AfterWorkStopRoot) return;
                stopped = true; throw new IOException("Stopped ordinal-zero source boundary.");
            }))
                await Assert.ThrowsAsync<IOException>(() => CancelPreSessionInitial(intent));
            Assert.True(stopped);
            string[] custody = [SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot,
                SqliteDeepIdV2AccountGeneration.DeviceStateMarkerSlot, DeviceInitialSessionCheckpoint.Slot, ProtectedDid2ContactStartJournal.Slot];
            using (var actual = await storage.ReadOwnedBatchAsync(custody))
            {
                Assert.NotNull(actual[1]);
                var owner = (actual[0] ?? throw new InvalidDataException()).Use(bytes =>
                    (Account: bytes.Slice(24, 32).ToArray(), Instance: bytes.Slice(56, 32).ToArray(), Store: CancellationDeviceStoreId(bytes)));
                try
                {
                    using var checkpoint = (actual[2] ?? throw new InvalidDataException()).Use(bytes =>
                        DeviceInitialSessionCheckpoint.Decode(bytes, owner.Store, owner.Account, Network));
                    Assert.Equal(1, checkpoint.Phase); Assert.Equal(0UL, checkpoint.Sequence);
                    using var drafts = (actual[3] ?? throw new InvalidDataException()).Use(bytes =>
                        ProtectedDid2ContactStartJournal.Decode(bytes, Network, owner.Account, owner.Instance));
                    var selected = drafts.Entries[Convert.ToHexString(intent)];
                    Assert.True(selected.WorkStopped); Assert.Equal(2, selected.NativeStopMode);
                }
                finally { foreach (var bytes in new[] { owner.Account, owner.Instance, owner.Store }) CryptographicOperations.ZeroMemory(bytes); }
            }
            var sourcePath = SqliteDeepIdV2AccountGeneration.DeviceStatePath(Path.Combine(directory, "deep-store-v2-account.dsv2"));
            Assert.True(File.Exists(sourcePath));
            Assert.False(File.Exists(sourcePath + "-wal")); Assert.False(File.Exists(sourcePath + "-shm")); Assert.False(File.Exists(sourcePath + "-journal"));
            await storage.DeleteBatchAsync([custody[1], custody[2]]);
            File.Delete(sourcePath); // Only this test fixture's disposable source.
            string[] preserved = [ProtectedDid2ContactStartJournal.Slot, ProtectedDph2PreClaimJournal.Slot,
                ProtectedInitialKeyRetirementJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot];
            var before = new List<byte[]>();
            using (var actual = await storage.ReadOwnedBatchAsync(preserved))
                for (var index = 0; index < preserved.Length; index++) before.Add((actual[index] ?? throw new InvalidDataException()).Use(bytes => bytes.ToArray()));
            var writes = 0;
            var boundary = new CancellationProviderBoundaryStorage(storage, edge =>
            {
                if (!edge.After && edge.Operation is not ("read" or "read-batch" or "guarded-read")) writes++;
            });
            try
            {
                for (var attempt = 0; attempt < 2; attempt++)
                {
                    if (attempt != 0) ColdReopenCompactionStorage();
                    var account = new DeepIdV2AccountService(boundary, directory, Network, 1,
                        new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)), DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
                    var error = await Record.ExceptionAsync(() => account.CancelOwnInitialContactAsync(intent, Source(account)));
                    Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().Name ?? "Stopped cancellation reprovisioned its missing source.");
                    Assert.Equal(0, writes);
                    foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" }) Assert.False(File.Exists(sourcePath + suffix));
                    using (var absent = await storage.ReadOwnedBatchAsync([custody[1], custody[2]]))
                    { Assert.Null(absent[0]); Assert.Null(absent[1]); }
                    using var unchanged = await storage.ReadOwnedBatchAsync(preserved);
                    for (var index = 0; index < preserved.Length; index++) Assert.Equal(before[index], (unchanged[index] ?? throw new InvalidDataException()).Use(bytes => bytes.ToArray()));
                }
            }
            finally { foreach (var bytes in before) CryptographicOperations.ZeroMemory(bytes); }

            static byte[] CancellationDeviceStoreId(ReadOnlySpan<byte> record)
            {
                var domain = "Deep/STORE-V2/device-state-key"u8;
                var transcript = new byte[domain.Length + 80]; domain.CopyTo(transcript);
                record.Slice(8, 48).CopyTo(transcript.AsSpan(domain.Length)); record.Slice(56, 32).CopyTo(transcript.AsSpan(domain.Length + 48));
                try { return SHA256.HashData(transcript); }
                finally { CryptographicOperations.ZeroMemory(transcript); }
            }
        }

        internal async Task CheckFinalCancellationRetirementRollback()
        {
            var intent = Bytes(32, 0xc6);
            var prepared = await PrepareNativeHelloCompletion(intent);
            var scope = await RegisterEmptySenderForCancellation(intent, prepared.Init, prepared.Hello, prepared.Complete, initialize: true);
            byte[] stable = [], rollback = [];
            var hit = false;
            try
            {
                using (InitialKeyRetirementTestHooks.Push(point =>
                {
                    if (point != InitialKeyRetirementFailpoint.AfterStable || hit) return;
                    using var actual = storage.ReadOwnedAsync(ProtectedInitialKeyRetirementJournal.Slot).GetAwaiter().GetResult() ?? throw new InvalidDataException();
                    stable = actual.Use(bytes => bytes.ToArray());
                    var state = ProtectedInitialKeyRetirementJournal.Decode(stable, scope.Network, scope.LocalAccount, scope.Instance);
                    var entry = state.FindCancellation(intent) ?? throw new InvalidDataException();
                    Assert.Equal(2, entry.Phase);
                    var exact = entry.Exact.ToArray(); exact[1] = 1;
                    try { state.Entries[entry.Coordinate] = new ProtectedInitialKeyRetirementJournal.Entry(exact); }
                    finally { CryptographicOperations.ZeroMemory(exact); }
                    rollback = ProtectedInitialKeyRetirementJournal.Encode(state with { Revision = checked(state.Revision - 1) }, scope.Network, scope.LocalAccount, scope.Instance);
                    Assert.True(storage.CompareExchangeAsync(ProtectedInitialKeyRetirementJournal.Slot, stable, rollback).GetAwaiter().GetResult());
                    hit = true;
                }))
                    await Assert.ThrowsAsync<CryptographicException>(() => CancelPreSessionInitial(intent));
                Assert.True(hit, "The actual stable cancellation edge did not run.");
                using (var unchanged = await storage.ReadOwnedAsync(ProtectedInitialKeyRetirementJournal.Slot) ?? throw new InvalidDataException())
                    Assert.Equal(rollback, unchanged.Use(bytes => bytes.ToArray()));
                var rolled = ProtectedInitialKeyRetirementJournal.Decode(rollback, scope.Network, scope.LocalAccount, scope.Instance);
                using (var claimsRaw = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot) ?? throw new InvalidDataException())
                {
                    var claims = claimsRaw.Use(bytes => ProtectedDph2PreClaimJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                    Assert.True(claims.Cancelled.ContainsKey(Convert.ToHexString(intent)));
                    Assert.False(claims.Claims.ContainsKey(Convert.ToHexString(intent)));
                    rolled.RequirePreclaimState(claims);
                }
                await WithCompletedContactSourceSql(scope, sql =>
                {
                    using var read = sql.CreateCommand();
                    read.CommandText = "SELECT COUNT(*) FROM device_initial_state k JOIN device_initial_sessions s ON s.sequence=k.sequence WHERE s.logical_intent_id=$intent;";
                    read.Parameters.AddWithValue("$intent", intent);
                    Assert.Equal(0L, (long)(read.ExecuteScalar() ?? throw new InvalidDataException()));
                });
                Assert.Equal(Did2MessagingFloor.Empty(scope).Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
            }
            finally
            {
                if (hit) Assert.True(await storage.CompareExchangeAsync(ProtectedInitialKeyRetirementJournal.Slot, rollback, stable));
                CryptographicOperations.ZeroMemory(stable); CryptographicOperations.ZeroMemory(rollback);
            }
            ColdReopenCompactionStorage();
            var proofsBefore = ProofRequests;
            await SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
            Assert.Equal(proofsBefore, ProofRequests);
            await CancelPreSessionInitial(intent);
            await AssertPreSessionCancelled(intent);
            await Assert.ThrowsAsync<IOException>(() => BeginPreClaimAsync(intent));
        }

        internal async Task CheckCancellationGuardedCapacity()
        {
            var others = new List<Did2MessagingSessionScope>();
            for (var index = 0; index < 11; index++)
            {
                var intent = Bytes(32, checked((byte)(0xd0 + index)));
                var prepared = await PrepareNativeHelloCompletion(intent, oneTimeIndex: index);
                var scope = await RegisterEmptySenderForCancellation(intent, prepared.Init, prepared.Hello, prepared.Complete, initialize: true);
                await CancelPreSessionInitial(intent);
                others.Add(scope);
            }
            var selectedIntent = Bytes(32, 0xdb);
            var selectedPrepared = await PrepareNativeHelloCompletion(selectedIntent, oneTimeIndex: 11);
            var selected = await RegisterEmptySenderForCancellation(selectedIntent, selectedPrepared.Init, selectedPrepared.Hello, selectedPrepared.Complete, initialize: true);
            var otherRoots = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var scope in others)
                foreach (var slot in new[] { scope.FloorSlot, Did2MessagingHistoryCheckpoint.Slot(scope) })
                {
                    using var actual = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                    otherRoots.Add(slot, actual.Use(bytes => bytes.ToArray()));
                }
            var accountPath = Path.Combine(directory, "deep-store-v2-account.dsv2");
            var sourcePath = SqliteDeepIdV2AccountGeneration.DeviceStatePath(accountPath);
            var sourceBefore = await ReadCancellationSourceDiagnosticDigest(selected, selectedIntent);
            string? mutation = null; var mutationHit = false; var guardedInventories = 0;
            var boundary = new CancellationProviderBoundaryStorage(storage, edge =>
            {
                using var exclusive = new FileStream(sourcePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                if (edge.Operation != "guarded-read" || edge.After || edge.Guards is not { } guards ||
                    !otherRoots.All(pair => guards.TryGetValue(pair.Key, out var hash) && hash is not null &&
                        CryptographicOperations.FixedTimeEquals(hash, SHA256.HashData(pair.Value)))) return;
                guardedInventories++;
                if (mutation is null || mutationHit) return;
                mutationHit = true;
                var damaged = otherRoots[mutation].ToArray(); damaged[^1] ^= 1;
                try { Assert.True(storage.CompareExchangeAsync(mutation, otherRoots[mutation], damaged).GetAwaiter().GetResult()); }
                finally { CryptographicOperations.ZeroMemory(damaged); }
            });
            async Task Audit()
            {
                var accountLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
                var owner = new ProtectedDeepIdV2AccountOwner(boundary, accountLease, accountPath, Network, 1);
                using var current = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException();
                using var held = await accountLease.AcquireAsync(default);
                using var opened = await SqliteDeepIdV2AccountGeneration.OpenMessagingArchiveAuditUnderLeaseAsync(boundary,
                    accountPath, current, selected, default);
                Assert.Equal(Did2MessagingFloor.Empty(selected).Exact.ToArray(), (await opened.Custody.ReadCurrentFloorAsync(default)).Exact.ToArray());
            }
            try
            {
                await Audit();
                Assert.True(guardedInventories > 0, "The source audit did not atomically guard all eleven other cancelled scope floor/history pairs.");
                foreach (var slot in new[] { others[0].FloorSlot, Did2MessagingHistoryCheckpoint.Slot(others[^1]) })
                {
                    mutation = slot; mutationHit = false;
                    try
                    {
                        await Assert.ThrowsAsync<CryptographicException>(Audit);
                        Assert.True(mutationHit, "The actual other-scope guarded provider mutation did not run.");
                        var sourceAfter = await ReadCancellationSourceDiagnosticDigest(selected, selectedIntent);
                        try { Assert.Equal(sourceBefore, sourceAfter); }
                        finally { CryptographicOperations.ZeroMemory(sourceAfter); }
                        Assert.Equal(Did2MessagingFloor.Empty(selected).Exact.ToArray(), (await ReadMessagingFloor(selected)).Exact.ToArray());
                    }
                    finally
                    {
                        mutation = null;
                        if (mutationHit)
                        {
                            var damaged = otherRoots[slot].ToArray(); damaged[^1] ^= 1;
                            try { Assert.True(await storage.CompareExchangeAsync(slot, damaged, otherRoots[slot])); }
                            finally { CryptographicOperations.ZeroMemory(damaged); }
                        }
                    }
                }
                await Audit();
                var guardsBeforeCancellation = guardedInventories;
                var account = new DeepIdV2AccountService(boundary, directory, Network, 1,
                    new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)), DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
                await account.CancelOwnInitialContactAsync(selectedIntent, Source(account));
                Assert.True(guardedInventories > guardsBeforeCancellation, "Cancellation omitted the other cancelled scope guards.");
                ColdReopenCompactionStorage();
                var proofsBefore = ProofRequests;
                await SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
                Assert.Equal(proofsBefore, ProofRequests);
                await AssertPreSessionCancelled(selectedIntent);
                await Assert.ThrowsAsync<IOException>(() => BeginPreClaimAsync(selectedIntent));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sourceBefore);
                foreach (var bytes in otherRoots.Values) CryptographicOperations.ZeroMemory(bytes);
            }
        }

        internal async Task CheckCancellationProviderPhysicalBoundary()
        {
            var intent = Bytes(32, 0xc4);
            var prepared = await PrepareNativeHelloCompletion(intent);
            var scope = await RegisterEmptySenderForCancellation(intent, prepared.Init, prepared.Hello, prepared.Complete, initialize: true);
            var sourcePath = SqliteDeepIdV2AccountGeneration.DeviceStatePath(Path.Combine(directory, "deep-store-v2-account.dsv2"));
            var probes = 0; var observed = new HashSet<string>(StringComparer.Ordinal);
            var boundary = new CancellationProviderBoundaryStorage(storage, edge =>
            {
                using var exclusive = new FileStream(sourcePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                probes++;
                foreach (var slot in edge.Slots) observed.Add(slot);
            });
            var account = new DeepIdV2AccountService(boundary, directory, Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)), DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            var interrupted = false;
            using (InitialKeyRetirementTestHooks.Push(point =>
            {
                if (point != InitialKeyRetirementFailpoint.AfterPending) return;
                interrupted = true; throw new IOException("Cold cancellation provider-boundary checkpoint.");
            }))
                await Assert.ThrowsAsync<IOException>(() => account.CancelOwnInitialContactAsync(intent, Source(account)));
            Assert.True(interrupted);
            ColdReopenCompactionStorage();
            var proofsBefore = ProofRequests; var probesBefore = probes;
            var coldOwner = new ProtectedDeepIdV2AccountOwner(boundary,
                new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock")),
                Path.Combine(directory, "deep-store-v2-account.dsv2"), Network, 1);
            await coldOwner.ResumeOwnedLocalCompactionAsync(default);
            Assert.Equal(proofsBefore, ProofRequests);
            Assert.True(probes > probesBefore, "Cold local recovery bypassed the protected provider observer.");
            await account.CancelOwnInitialContactAsync(intent, Source(account));
            Assert.True(probes > 0);
            Assert.Contains(ProtectedDph2PreClaimJournal.Slot, observed);
            Assert.Contains(ProtectedInitialKeyRetirementJournal.Slot, observed);
            Assert.Contains(DeviceInitialSessionCheckpoint.Slot, observed);
            Assert.Equal(Did2MessagingFloor.Empty(scope).Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
            await AssertPreSessionCancelled(intent);
            await Assert.ThrowsAsync<IOException>(() => BeginPreClaimAsync(intent));
            Assert.Equal(Did2MessagingFloor.Empty(scope).Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
        }

        internal async Task CheckCancellationProviderSubstitution(bool registration)
        {
            var intent = Bytes(32, 0xc5);
            var prepared = await PrepareNativeHelloCompletion(intent);
            var scope = await RegisterEmptySenderForCancellation(intent, prepared.Init, prepared.Hello, prepared.Complete, initialize: true);
            var sourcePath = SqliteDeepIdV2AccountGeneration.DeviceStatePath(Path.Combine(directory, "deep-store-v2-account.dsv2"));
            var originalSource = await File.ReadAllBytesAsync(sourcePath);
            var sourceDigest = await ReadCancellationSourceDiagnosticDigest(scope, intent);
            using var actualRegistration = await storage.ReadOwnedAsync(SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot) ?? throw new InvalidDataException();
            var originalRegistration = actualRegistration.Use(bytes => bytes.ToArray());
            var damagedRegistration = originalRegistration.ToArray(); damagedRegistration[88] ^= 1;
            var damagedSource = originalSource.ToArray(); Assert.True(damagedSource.Length > 100); damagedSource[100] ^= 1;
            var hit = false; var exclusiveProbe = false;
            var boundary = new CancellationProviderBoundaryStorage(storage, edge =>
            {
                if (hit || !edge.After || edge.Operation != "cas" || edge.Slots.Length != 1 || edge.Slots[0] != ProtectedDph2PreClaimJournal.Slot) return;
                hit = true;
                using (var exclusive = new FileStream(sourcePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    exclusiveProbe = true;
                    if (!registration) { exclusive.Write(damagedSource); exclusive.Flush(true); }
                }
                if (registration)
                    Assert.True(storage.CompareExchangeAsync(SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot,
                        originalRegistration, damagedRegistration).GetAwaiter().GetResult());
            });
            var account = new DeepIdV2AccountService(boundary, directory, Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)), DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            try
            {
                var error = await Record.ExceptionAsync(() => account.CancelOwnInitialContactAsync(intent, Source(account)));
                Assert.True(hit, "The actual preclaim cancellation CAS callback did not run.");
                Assert.True(exclusiveProbe, "The source physical SQL handle crossed the protected preclaim CAS.");
                Assert.True(error is CryptographicException or InvalidDataException or SqliteException or Deep.Client.Shared.Persistence.DeviceV1.DeviceStateStoreOpenException,
                    "Cancellation accepted substituted source custody: " + (error?.GetType().Name ?? "none"));
                // Check before restoring disposable corruption: source deletion
                // must not have changed the actual damaged file.
                Assert.Equal(registration ? originalSource : damagedSource, await File.ReadAllBytesAsync(sourcePath));
                using var retirementRaw = await storage.ReadOwnedAsync(ProtectedInitialKeyRetirementJournal.Slot) ?? throw new InvalidDataException();
                var retirement = retirementRaw.Use(bytes => ProtectedInitialKeyRetirementJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                Assert.Equal(1, (retirement.FindCancellation(intent) ?? throw new InvalidDataException()).Phase);
                Assert.Equal(Did2MessagingFloor.Empty(scope).Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
            }
            finally
            {
                if (registration && hit)
                    Assert.True(await storage.CompareExchangeAsync(SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, damagedRegistration, originalRegistration));
                if (!registration && hit) await File.WriteAllBytesAsync(sourcePath, originalSource);
                foreach (var bytes in new[] { originalSource, damagedSource, originalRegistration, damagedRegistration }) CryptographicOperations.ZeroMemory(bytes);
            }
            var afterRefusal = await ReadCancellationSourceDiagnosticDigest(scope, intent);
            try { Assert.Equal(sourceDigest, afterRefusal); }
            finally { CryptographicOperations.ZeroMemory(sourceDigest); CryptographicOperations.ZeroMemory(afterRefusal); }
            ColdReopenCompactionStorage();
            var proofsBefore = ProofRequests;
            await SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
            Assert.Equal(proofsBefore, ProofRequests);
            await CancelPreSessionInitial(intent);
            await AssertPreSessionCancelled(intent);
            await Assert.ThrowsAsync<IOException>(() => BeginPreClaimAsync(intent));
            Assert.Equal(Did2MessagingFloor.Empty(scope).Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
        }
    }

    private sealed record CancellationProviderEdge(string Operation, string[] Slots, bool After,
        IReadOnlyDictionary<string, byte[]?>? Guards = null);

    // A forwarding observer around the real encrypted backend. It does not
    // replace results or grant authority; callbacks run at actual provider edges.
    private sealed class CancellationProviderBoundaryStorage(IDeepSecureStorage inner, Action<CancellationProviderEdge> observe) : IDeepSecureStorage, IDeepSecureStorageGuardedRead
    {
        private void Hit(string operation, IReadOnlyList<string> slots, bool after) => observe(new(operation, slots.ToArray(), after));
        async Task<OwnedDeepSecretBatch> IDeepSecureStorageGuardedRead.ReadOwnedGuardedBatchAsync(DeepSecureStorageGuardedRead request, CancellationToken ct)
        {
            var observedSlots = request.ReturnedSlots.Concat(request.Guards.Keys).Distinct(StringComparer.Ordinal).ToArray();
            observe(new("guarded-read", observedSlots, false, request.Guards));
            var result = await inner.ReadOwnedGuardedBatchAsync(request.ReturnedSlots, request.Guards, ct);
            try { observe(new("guarded-read", observedSlots, true, request.Guards)); return result; }
            catch { result.Dispose(); throw; }
        }
        public async Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken ct = default)
        {
            Hit("read", [slot], false); var result = await inner.ReadOwnedAsync(slot, ct);
            try { Hit("read", [slot], true); return result; } catch { result?.Dispose(); throw; }
        }
        public async Task<OwnedDeepSecretBatch> ReadOwnedBatchAsync(IReadOnlyList<string> slots, CancellationToken ct = default)
        {
            var captured = OwnedDeepSecretBatch.CaptureSlots(slots);
            Hit("read-batch", captured, false); var result = await inner.ReadOwnedBatchAsync(captured, ct);
            try { Hit("read-batch", captured, true); return result; } catch { result.Dispose(); throw; }
        }
        public async Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken ct = default)
        {
            var slots = writes.Select(write => write.Slot).ToArray();
            Hit("write", slots, false); await inner.WriteBatchAsync(writes, ct); Hit("write", slots, true);
        }
        public async Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, CancellationToken ct = default)
        {
            Hit("cas", [slot], false); var result = await inner.CompareExchangeAsync(slot, expected, replacement, ct); Hit("cas", [slot], true); return result;
        }
        public async Task<bool> CompareExchangeAndInsertAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement,
            IReadOnlyList<DeepSecureStorageWrite> insertions, CancellationToken ct = default)
        {
            var slots = new[] { slot }.Concat(insertions.Select(write => write.Slot)).ToArray();
            Hit("cas-insert", slots, false); var result = await inner.CompareExchangeAndInsertAsync(slot, expected, replacement, insertions, ct); Hit("cas-insert", slots, true); return result;
        }
        public async Task<bool> CompareAndDeleteAsync(string guardSlot, ReadOnlyMemory<byte> expected, IReadOnlyList<string> slots, CancellationToken ct = default)
        {
            var captured = new[] { guardSlot }.Concat(slots).ToArray();
            Hit("cas-delete", captured, false); var result = await inner.CompareAndDeleteAsync(guardSlot, expected, slots, ct); Hit("cas-delete", captured, true); return result;
        }
        public async Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken ct = default)
        { Hit("delete", slots, false); await inner.DeleteBatchAsync(slots, ct); Hit("delete", slots, true); }
        public async Task PurgeStoreV1NamespaceAsync(CancellationToken ct = default)
        { Hit("purge-v1", [], false); await inner.PurgeStoreV1NamespaceAsync(ct); Hit("purge-v1", [], true); }
        public async Task PurgeStoreV2NamespaceAsync(CancellationToken ct = default)
        { Hit("purge-v2", [], false); await inner.PurgeStoreV2NamespaceAsync(ct); Hit("purge-v2", [], true); }
    }
}
