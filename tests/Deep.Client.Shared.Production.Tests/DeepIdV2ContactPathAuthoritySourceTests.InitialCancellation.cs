using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("draft")] [InlineData("unknown-claim")] [InlineData("completed-source")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_ActualIntentRetiresKeysAndPayloadWithoutCreatingNativeWork(string stage)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xa9);
        var prepared = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: stage == "completed-source" ? null : stage);
        if (stage == "completed-source") using (var source = await prepared.Complete(fixture.ReopenAccount())) { }
        using var catalogBefore = await fixture.CompletedContactSendStorage(true).ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot) ?? throw new InvalidDataException();
        var exactCatalog = catalogBefore.Use(bytes => bytes.ToArray());
        await fixture.CancelPreSessionInitial(intent);
        for (var reopen = 0; reopen < 2; reopen++)
        {
            fixture.ColdReopenCompactionStorage();
            await fixture.CancelPreSessionInitial(intent);
            await fixture.AssertPreSessionCancelled(intent);
            using var after = await fixture.CompletedContactSendStorage(true).ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot) ?? throw new InvalidDataException();
            Assert.Equal(exactCatalog, after.Use(bytes => bytes.ToArray()));
            await Assert.ThrowsAsync<IOException>(() => fixture.BeginPreClaimAsync(intent));
        }
        CryptographicOperations.ZeroMemory(exactCatalog);
    }

    [Theory]
    [InlineData("AfterPending")] [InlineData("AfterPreclaim")] [InlineData("AfterSourceDelete")] [InlineData("AfterStable")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_KeyDeletionColdRecoversWithoutFreshProofOrReimport(string interruption)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xaa); var prepared = await fixture.PrepareNativeHelloCompletion(intent);
        using (var completed = await prepared.Complete(fixture.ReopenAccount())) { }
        var hit = false; var selected = Enum.Parse<InitialKeyRetirementFailpoint>(interruption);
        using (InitialKeyRetirementTestHooks.Push(point => { if (point == selected) { hit = true; throw new IOException("Interrupted pre-session key deletion."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CancelPreSessionInitial(intent));
        Assert.True(hit); fixture.ColdReopenCompactionStorage();
        var proofRequests = fixture.ProofRequests;
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        Assert.Equal(proofRequests, fixture.ProofRequests);
        await fixture.CancelPreSessionInitial(intent);
        await fixture.AssertPreSessionCancelled(intent);
    }

    [Theory]
    [InlineData("AfterStage")] [InlineData("AfterSql")] [InlineData("AfterSqlRecorded")]
    [InlineData("AfterHistoryAdopted")] [InlineData("AfterPartsDeleted")] [InlineData("AfterPlanCleared")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_PayloadAuditColdRecoversEveryHandoverWithoutNativeScope(string interruption)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xab); _ = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: "unknown-claim");
        var selected = Enum.Parse<Did2CompactionFailpoint>(interruption); var hit = false;
        using (Did2CompactionTestHooks.Push(point => { if (point == selected) { hit = true; throw new IOException("Interrupted pre-session payload cleanup."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CancelPreSessionInitial(intent));
        Assert.True(hit); fixture.ColdReopenCompactionStorage();
        var proofRequests = fixture.ProofRequests;
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        Assert.Equal(proofRequests, fixture.ProofRequests);
        await fixture.AssertPreSessionCancelled(intent);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_StopReplyLossAndTokenCancellationColdFinishWithoutNewClaim(bool cancel)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xac); _ = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: "unknown-claim");
        using var token = new CancellationTokenSource(); var hit = false;
        using (Did2MailboxSendTestHooks.Push(point =>
        {
            if (point != Did2MailboxSendFailpoint.AfterWorkStopRoot) return; hit = true;
            if (cancel) { token.Cancel(); token.Token.ThrowIfCancellationRequested(); }
            throw new IOException("Lost pre-session stop reply.");
        }))
        {
            if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.CancelPreSessionInitial(intent, token.Token));
            else await Assert.ThrowsAsync<IOException>(() => fixture.CancelPreSessionInitial(intent));
        }
        Assert.True(hit); fixture.ColdReopenCompactionStorage();
        var before = fixture.ProofRequests;
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        Assert.Equal(before, fixture.ProofRequests);
        await fixture.CancelPreSessionInitial(intent); await fixture.AssertPreSessionCancelled(intent);
        await Assert.ThrowsAsync<IOException>(() => fixture.BeginPreClaimAsync(intent));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_ActualReservedEmptyStoreNeverImportsAndCannotReimport(bool initializeSql)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xad); var prepared = await fixture.PrepareNativeHelloCompletion(intent);
        var scope = await fixture.RegisterEmptySenderForCancellation(intent, prepared.Init, prepared.Hello, prepared.Complete, initializeSql);
        await fixture.CancelPreSessionInitial(intent);
        fixture.ColdReopenCompactionStorage(); await fixture.CancelPreSessionInitial(intent);
        await fixture.AssertPreSessionCancelled(intent);
        Assert.Equal(Did2MessagingFloor.Empty(scope).Exact.ToArray(), (await fixture.ReadMessagingFloor(scope)).Exact.ToArray());
        await Assert.ThrowsAsync<IOException>(() => fixture.EnsureSenderMessaging(prepared.Init, prepared.Hello));
        Assert.Equal(Did2MessagingFloor.Empty(scope).Exact.ToArray(), (await fixture.ReadMessagingFloor(scope)).Exact.ToArray());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_IntentSelectorRecognizesActualNativeImportAndKeepsOriginalWork()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(true);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        await fixture.CancelPreSessionInitial(test.Intent);
        await fixture.AssertControlStopMetadata(test, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled);
        await fixture.AssertControlAuditFinal(test, expire: false);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        await fixture.AssertNoPreSessionCancellationOwner(test.Intent);
        Assert.Equal(0, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        CryptographicOperations.ZeroMemory(native);
    }

    [Theory]
    [InlineData("AfterAbandonRecorded")] [InlineData("AfterPartsDeleted")] [InlineData("AfterPlanCleared")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_UncommittedPayloadAbortDoesNotResurrectKeysOrReverseStop(string interruption)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xae); _ = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: "unknown-claim");
        using (Did2CompactionTestHooks.Push(point => { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Prepared pre-session payload plan."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CancelPreSessionInitial(intent));
        var selected = Enum.Parse<Did2CompactionFailpoint>(interruption); var hit = false;
        using (Did2CompactionTestHooks.Push(point => { if (point == selected) { hit = true; throw new IOException("Interrupted exact pre-session abort."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.SenderCompactionOwner().AbandonUncommittedControlAuditAsync(default));
        Assert.True(hit); fixture.ColdReopenCompactionStorage();
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        await fixture.AssertPreSessionStoppedWorkingAfterAbort(intent);
        await Assert.ThrowsAsync<IOException>(() => fixture.BeginPreClaimAsync(intent));
        await fixture.CancelPreSessionInitial(intent); await fixture.AssertPreSessionCancelled(intent);
    }

    [Theory]
    [InlineData("draft")] [InlineData("completed-source")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_AuditLowerDeadlineDoesNotExtendOrResurrectIntent(string stage)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var intent = Bytes(32, 0xaf); var prepared = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: stage == "draft" ? stage : null);
        if (stage == "completed-source") using (var completed = await prepared.Complete(fixture.ReopenAccount())) { }
        await fixture.CancelPreSessionInitial(intent);
        var before = await fixture.ReadPreSessionApplication(intent); var stopTime = await fixture.PreSessionStopTime(intent);
        var deadline = checked(stopTime + SqliteDeepMailboxStore.StoppedAuditSeconds);
        await fixture.AdvanceControlAuditToLowerBoundary(deadline - 1);
        await fixture.CancelPreSessionInitial(intent);
        Assert.Equal(before, await fixture.ReadPreSessionApplication(intent));
        Assert.Equal(stopTime, await fixture.PreSessionStopTime(intent));
        fixture.ProofTime++; fixture.Sample++;
        await fixture.CancelPreSessionInitial(intent);
        Assert.Equal(0UL, await fixture.PreSessionStopTime(intent));
        await fixture.AssertPreSessionCancelled(intent, auditExpired: true);
        var after = await fixture.ReadPreSessionApplication(intent);
        fixture.ColdReopenCompactionStorage(); await fixture.CancelPreSessionInitial(intent);
        Assert.Equal(after, await fixture.ReadPreSessionApplication(intent));
        await Assert.ThrowsAsync<IOException>(() => fixture.BeginPreClaimAsync(intent));
        foreach (var bytes in new[] { before, after }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData("draft")] [InlineData("preclaim")] [InlineData("keys")] [InlineData("catalog")] [InlineData("source-marker")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_MissingMandatoryCustodyRefusesWithoutStopOrRegeneration(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xb0); _ = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: "unknown-claim");
        var secure = fixture.CompletedContactSendStorage(true);
        var slot = defect switch
        {
            "draft" => ProtectedDid2ContactStartJournal.Slot,
            "preclaim" => ProtectedDph2PreClaimJournal.Slot,
            "keys" => ProtectedInitialKeyRetirementJournal.Slot,
            "catalog" => ProtectedDid2MessagingSessionCatalog.Slot,
            _ => SqliteDeepIdV2AccountGeneration.DeviceStateMarkerSlot
        };
        using var removed = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
        var original = removed.Use(bytes => bytes.ToArray());
        using var draftRaw = await secure.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException();
        var draft = draftRaw.Use(bytes => bytes.ToArray());
        await secure.DeleteBatchAsync([slot]); fixture.ColdReopenCompactionStorage();
        var error = await Record.ExceptionAsync(() => fixture.CancelPreSessionInitial(intent));
        Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().Name ?? "Unexpected successful cancellation");
        using var absent = await secure.ReadOwnedAsync(slot); Assert.Null(absent);
        if (defect != "draft")
        {
            using var unchanged = await secure.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException();
            Assert.Equal(draft, unchanged.Use(bytes => bytes.ToArray()));
        }
        // Exact disposable corruption restore only, never runtime repair.
        await secure.WriteBatchAsync([new(slot, original)]);
        await fixture.CancelPreSessionInitial(intent); await fixture.AssertPreSessionCancelled(intent);
        CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(draft);
    }

    [Theory]
    [InlineData("preclaim-resurrection")] [InlineData("keys-rollback")] [InlineData("draft-rollback")]
    [InlineData("source-keys-resurrection")] [InlineData("source-record")]
    [InlineData("audit-missing")] [InlineData("audit-mac")] [InlineData("audit-deadline")] [InlineData("audit-foreign")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionCancel_StableHostileCustodyNeverRepairsOrReactivates(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xb1); var prepared = await fixture.PrepareNativeHelloCompletion(intent);
        // This is a genuine registered pre-import store, not a manufactured scope.
        var scope = await fixture.RegisterEmptySenderForCancellation(intent, prepared.Init, prepared.Hello, prepared.Complete, initialize: true);
        var secure = fixture.CompletedContactSendStorage(true);
        var slots = new[] { ProtectedDph2PreClaimJournal.Slot, ProtectedInitialKeyRetirementJournal.Slot,
            ProtectedDid2ContactStartJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, Did2CompactionPlan.Slot };
        var before = new List<byte[]>(); var damagedRoots = new List<byte[]>();
        byte[] oldSourceKeys = [], sourceAfterDamage = [], applicationAfterDamage = [];
        try
        {
            foreach (var slot in slots)
            {
                using var raw = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                before.Add(raw.Use(bytes => bytes.ToArray()));
            }
            await fixture.WithCompletedContactSourceSql(scope, sql =>
            {
                using var read = sql.CreateCommand(); read.CommandText = "SELECT exact_state FROM device_initial_state;";
                oldSourceKeys = (byte[])(read.ExecuteScalar() ?? throw new InvalidDataException());
            });
            await fixture.CancelPreSessionInitial(intent); await fixture.AssertPreSessionCancelled(intent);
            var rolledSlot = defect switch
            {
                "preclaim-resurrection" => 0, "keys-rollback" => 1, "draft-rollback" => 2, _ => -1
            };
            if (rolledSlot >= 0)
            {
                using var current = await secure.ReadOwnedAsync(slots[rolledSlot]) ?? throw new InvalidDataException();
                Assert.True(await secure.CompareExchangeAsync(slots[rolledSlot], current.Use(bytes => bytes.ToArray()), before[rolledSlot]));
            }
            else if (defect.StartsWith("audit-", StringComparison.Ordinal))
                await fixture.DamageStoppedAudit(scope, defect[6..]);
            else
                await fixture.WithCompletedContactSourceSql(scope, sql =>
                {
                    using var edit = sql.CreateCommand();
                    edit.CommandText = defect == "source-keys-resurrection"
                        ? "INSERT INTO device_initial_state(sequence,exact_state) SELECT sequence,$keys FROM device_initial_sessions WHERE logical_intent_id=$intent;"
                        : "UPDATE device_initial_sessions SET record_hash=zeroblob(32) WHERE logical_intent_id=$intent;";
                    edit.Parameters.AddWithValue("$intent", intent);
                    if (defect == "source-keys-resurrection") edit.Parameters.AddWithValue("$keys", oldSourceKeys);
                    Assert.Equal(1, edit.ExecuteNonQuery());
                });
            foreach (var slot in slots)
            {
                using var raw = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                damagedRoots.Add(raw.Use(bytes => bytes.ToArray()));
            }
            sourceAfterDamage = await fixture.ReadCancellationSourceDiagnosticDigest(scope, intent);
            applicationAfterDamage = await fixture.ReadRawCompleteApplicationProjection(scope);
            fixture.ColdReopenCompactionStorage();
            var error = await Record.ExceptionAsync(() => fixture.CancelPreSessionInitial(intent));
            Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().Name ?? "Unexpected successful cancellation");
            for (var index = 0; index < slots.Length; index++)
            {
                using var raw = await secure.ReadOwnedAsync(slots[index]) ?? throw new InvalidDataException();
                Assert.Equal(damagedRoots[index], raw.Use(bytes => bytes.ToArray()));
            }
            var sourceAfterRefusal = await fixture.ReadCancellationSourceDiagnosticDigest(scope, intent);
            try { Assert.True(CryptographicOperations.FixedTimeEquals(sourceAfterDamage, sourceAfterRefusal)); }
            finally { CryptographicOperations.ZeroMemory(sourceAfterRefusal); }
            Assert.Equal(applicationAfterDamage, await fixture.ReadRawCompleteApplicationProjection(scope));
            Assert.Equal(Did2MessagingFloor.Empty(scope).Exact.ToArray(), (await fixture.ReadMessagingFloor(scope)).Exact.ToArray());
        }
        finally
        {
            foreach (var bytes in before.Concat(damagedRoots).Concat(new[] { oldSourceKeys, sourceAfterDamage, applicationAfterDamage }))
                CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]> ReadCancellationSourceDiagnosticDigest(Did2MessagingSessionScope scope, byte[] intent)
        {
            byte[] result = [];
            await WithCompletedContactSourceSql(scope, sql =>
            {
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                using var read = sql.CreateCommand();
                read.CommandText = "SELECT s.record_hash,s.payload,k.exact_state FROM device_initial_sessions s LEFT JOIN device_initial_state k ON k.sequence=s.sequence WHERE s.logical_intent_id=$intent;";
                read.Parameters.AddWithValue("$intent", intent); using var row = read.ExecuteReader();
                Assert.True(row.Read());
                for (var column = 0; column < 3; column++)
                {
                    hash.AppendData(new[] { row.IsDBNull(column) ? (byte)0 : (byte)1 });
                    if (row.IsDBNull(column)) continue;
                    var bytes = row.GetFieldValue<byte[]>(column);
                    try { hash.AppendData(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
                }
                Assert.False(row.Read()); result = hash.GetHashAndReset();
            });
            return result; // Damaged-state readback only; never deletion/import authority.
        }
        internal Task CancelPreSessionInitial(byte[] intent, CancellationToken ct = default)
        {
            var account = ReopenAccount(); return account.CancelOwnInitialContactAsync(intent, Source(account), ct);
        }
        internal async Task<Did2MessagingSessionScope> RegisterEmptySenderForCancellation(byte[] intent, ParsedDmc2 init, ParsedDmc2 hello,
            Func<Deep.Client.Shared.Services.DeepIdV2AccountService, Task<DeepIdV2InitialSessionCommit>> complete, bool initialize)
        {
            using var sender = await complete(accounts);
            using var receiver = await CompleteReceiver(sender.ExactDph2.ToArray());
            var seeds = await CreateMessagingSeeds(sender, receiver, init, hello);
            using var senderSeed = seeds.Sender; using var receiverSeed = seeds.Receiver;
            var heldLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await heldLease.AcquireAsync(default);
            var scope = Did2MessagingSessionScope.FromSeed(senderSeed);
            var catalog = new ProtectedDid2MessagingSessionCatalog(storage, scope.Network, scope.LocalAccount, scope.Instance);
            scope = await catalog.RegisterAsync(senderSeed, default);
            if (initialize)
                using (var opened = await SqliteDeepIdV2AccountGeneration.OpenRegisteredMessagingUnderLeaseAsync(storage,
                    Path.Combine(directory, "deep-store-v2-account.dsv2"), scope.Network.ToArray(), scope.LocalAccount.ToArray(), scope, default))
                    Assert.Equal(Did2MessagingFloor.Empty(scope).Exact.ToArray(), (await opened.Custody.ReconcileAsync(default)).Exact.ToArray());
            return scope;
        }
        internal async Task AssertNoPreSessionCancellationOwner(byte[] intent)
        {
            using var key = await storage.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidDataException();
            var account = key.Use(bytes => bytes.Slice(24, 32).ToArray());
            var keys = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, Network, account, default);
            Assert.Null(keys.FindCancellation(intent)); CryptographicOperations.ZeroMemory(account);
        }
        internal async Task AssertPreSessionStoppedWorkingAfterAbort(byte[] intent)
        {
            using var key = await storage.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidDataException();
            var account = key.Use(bytes => bytes.Slice(24, 32).ToArray()); var instance = key.Use(bytes => bytes.Slice(56, 32).ToArray());
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException();
            using var drafts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, Network, account, instance));
            var draft = drafts.Entries[Convert.ToHexString(intent)]; Assert.True(draft.WorkStopped); Assert.Equal(2, draft.NativeStopMode);
            Assert.False(draft.PayloadRetired); Assert.Equal(0, draft.AuditDisposition);
            var keys = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, Network, account, default);
            Assert.Equal(2, (keys.FindCancellation(intent) ?? throw new InvalidDataException()).Phase);
            foreach (var bytes in new[] { account, instance }) CryptographicOperations.ZeroMemory(bytes);
        }
        internal async Task AssertPreSessionCancelled(byte[] intent, bool auditExpired = false,
            ProtectedDid2DirectTextJournal.WorkStopReason reason = ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled)
        {
            using var key = await storage.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidDataException();
            var record = key.Use(bytes => bytes.ToArray()); var account = record.AsSpan(24, 32).ToArray(); var instance = record.AsSpan(56, 32).ToArray();
            try
            {
                using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException();
                using var starts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, Network, account, instance));
                var entry = starts.Entries[Convert.ToHexString(intent)];
                Assert.Equal(reason, entry.StopReason);
                Assert.True(entry.WorkStopped); Assert.True(entry.PayloadRetired); Assert.Equal(2, entry.NativeStopMode); Assert.Equal(auditExpired ? 2 : 1, entry.AuditDisposition);
                Assert.Equal(ProtectedDid2ContactStartJournal.PrefixBytes, entry.Exact.Length);
                using var claimsRaw = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot) ?? throw new InvalidDataException();
                var claims = claimsRaw.Use(bytes => ProtectedDph2PreClaimJournal.Decode(bytes, Network, account, instance));
                Assert.False(claims.Claims.ContainsKey(Convert.ToHexString(intent))); Assert.True(claims.Cancelled.ContainsKey(Convert.ToHexString(intent)));
                var keys = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, Network, account, default);
                var deleted = keys.FindCancellation(intent) ?? throw new InvalidDataException(); Assert.Equal(2, deleted.Phase); keys.RequirePreclaimState(claims);
                var heldLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
                using var held = await heldLease.AcquireAsync(default);
                using var source = await SqliteDeepIdV2AccountGeneration.OpenExistingCancellationSourceUnderLeaseAsync(storage,
                    Path.Combine(directory, "deep-store-v2-account.dsv2"), Network, account, instance, held, heldLease, default);
                if (await source.HasCompletedInitialSessionAsync(intent, default))
                    using (var metadata = await source.ReadMessagingSourceByIntentUnderLeaseAsync(intent, default)) Assert.False(metadata.HasInitialState);
                using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(storage,
                    Path.Combine(directory, "deep-store-v2-account.dsv2"), Network, account, instance, held, heldLease, default);
                using var ordinaryRaw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
                using var ordinary = ordinaryRaw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, Network, account, instance));
                await application.ValidateCompleteStoppedAuditsAsync(ordinary, default);
            }
            finally { foreach (var bytes in new[] { record, account, instance }) CryptographicOperations.ZeroMemory(bytes); }
        }
        internal async Task<ulong> PreSessionStopTime(byte[] intent)
        {
            using var key = await storage.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidDataException();
            var account = key.Use(bytes => bytes.Slice(24, 32).ToArray()); var instance = key.Use(bytes => bytes.Slice(56, 32).ToArray());
            try
            {
                using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException();
                using var state = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, Network, account, instance));
                return state.Entries[Convert.ToHexString(intent)].StoppedAtUpper;
            }
            finally { CryptographicOperations.ZeroMemory(account); CryptographicOperations.ZeroMemory(instance); }
        }
        internal async Task<byte[]> ReadPreSessionApplication(byte[] intent)
        {
            using var key = await storage.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidDataException();
            var account = key.Use(bytes => bytes.Slice(24, 32).ToArray()); var instance = key.Use(bytes => bytes.Slice(56, 32).ToArray());
            var operation = ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent); byte[] selector = [];
            try
            {
                var heldLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock")); using var held = await heldLease.AcquireAsync(default);
                using var app = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(storage,
                    Path.Combine(directory, "deep-store-v2-account.dsv2"), Network, account, instance, held, heldLease, default);
                selector = app.PreSessionControlAuditSelector(operation);
                return await app.ReadCompleteMailboxStateProjectionAsync(selector, default);
            }
            finally { foreach (var bytes in new[] { account, instance, operation, selector }) CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}
