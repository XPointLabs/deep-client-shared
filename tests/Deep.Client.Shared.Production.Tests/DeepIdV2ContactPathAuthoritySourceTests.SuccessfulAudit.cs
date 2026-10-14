using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false, "AfterStage")] [InlineData(false, "AfterSql")] [InlineData(false, "AfterSqlRecorded")]
    [InlineData(false, "AfterHistoryAdopted")] [InlineData(false, "AfterPartsDeleted")] [InlineData(false, "AfterPlanCleared")]
    [InlineData(true, "AfterStage")] [InlineData(true, "AfterSql")] [InlineData(true, "AfterSqlRecorded")]
    [InlineData(true, "AfterHistoryAdopted")] [InlineData(true, "AfterPartsDeleted")] [InlineData(true, "AfterPlanCleared")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2SuccessfulAudit_PayloadAndAuditExpiryColdRecoverWithoutNewTransport(bool expire, string interruption)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary"); await test.Deliver();
        var terminalTime = await fixture.ReadSuccessfulTerminalTime(test.Scope, test.Operation, compacted: false);
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        Assert.Equal(terminalTime, await fixture.ReadSuccessfulTerminalTime(test.Scope, test.Operation, compacted: false));
        fixture.AdvanceSyntheticMailboxClockPast(test.Transport.DurableTimeForFixture);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        if (expire)
        {
            await fixture.CompactNativeOrdinaryOutbox(test.Scope, default);
            Assert.Equal(terminalTime, await fixture.ReadSuccessfulTerminalTime(test.Scope, test.Operation, compacted: true));
            await fixture.AdvanceControlAuditToLowerBoundary(checked(terminalTime + SqliteDeepMailboxStore.StoppedAuditSeconds));
        }
        var hit = false; var selected = Enum.Parse<Did2CompactionFailpoint>(interruption);
        using (Did2CompactionTestHooks.Push(point =>
        {
            if (point == selected) { hit = true; throw new IOException("Interrupted successful-audit ownership handover."); }
        }))
            await Assert.ThrowsAsync<IOException>(() => expire ? fixture.ExpireSuccessfulAudits(test.Scope) : fixture.CompactNativeOrdinaryOutbox(test.Scope, default));
        Assert.True(hit); fixture.ColdReopenCompactionStorage();
        var requests = fixture.ProofRequests;
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        Assert.Equal(requests, fixture.ProofRequests);
        await fixture.AssertSuccessfulAudit(test.Scope, test.Operation, terminalTime, expire);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        var cached = await test.Deliver(); Assert.False(cached.IngressDispatched);
        await fixture.AssertSuccessfulAudit(test.Scope, test.Operation, terminalTime, expire);
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        CryptographicOperations.ZeroMemory(native);
    }

    [Theory]
    [InlineData(-1)] [InlineData(0)] [InlineData(1)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2SuccessfulAudit_AuthenticatedDeadlineEdgesPreserveOriginalStore(int offset)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        var stored = await test.Deliver();
        var terminal = await fixture.ReadSuccessfulTerminalTime(test.Scope, test.Operation, compacted: false);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        await fixture.CompactNativeOrdinaryOutbox(test.Scope, default);
        var lower = checked((ulong)(checked((long)(terminal + SqliteDeepMailboxStore.StoppedAuditSeconds)) + offset));
        await fixture.AdvanceControlAuditToLowerBoundary(lower);
        Assert.Equal(lower, await fixture.ReadSuccessfulAuditAuthenticatedLower());
        var before = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var root = await fixture.ReadAuthoredRootDigestAsync(own: true);
        var floor = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        try
        {
            await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
            Assert.Equal(before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(root, await fixture.ReadAuthoredRootDigestAsync(own: true));
            await fixture.ExpireSuccessfulAudits(test.Scope);
            await fixture.AssertSuccessfulAudit(test.Scope, test.Operation, terminal, expired: offset >= 0);
            if (offset < 0)
            {
                Assert.Equal(before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
                Assert.Equal(root, await fixture.ReadAuthoredRootDigestAsync(own: true));
            }
            fixture.ColdReopenCompactionStorage();
            await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
            var cached = await test.Deliver();
            Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
            await fixture.AssertSuccessfulAudit(test.Scope, test.Operation, terminal, expired: offset >= 0);
            Assert.Equal(floor, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            if (offset == 0)
                await fixture.AssertCompactedStoreRejectsChangedPublicEvidence(test.Scope, test.Deliver);
            Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        }
        finally { foreach (var bytes in new[] { before, root, floor }) CryptographicOperations.ZeroMemory(bytes); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2SuccessfulAudit_PrecommitAbortAndHostileRowsCannotEraseTerminalCustody()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary"); await test.Deliver();
        var terminal = await fixture.ReadSuccessfulTerminalTime(test.Scope, test.Operation, compacted: false);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        await fixture.CompactNativeOrdinaryOutbox(test.Scope, default);
        await fixture.AdvanceControlAuditToLowerBoundary(checked(terminal + SqliteDeepMailboxStore.StoppedAuditSeconds));
        var audit = await fixture.ReadOnlyControlAudit(test.Scope);
        var before = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var root = await fixture.ReadAuthoredRootDigestAsync(own: true);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        try
        {
            foreach (var column in new[] { "stopped_at", "expires_at" })
            {
                var rejected = await Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(() =>
                    fixture.WithAuthoredApplicationConnectionAsync(test.Scope, sql =>
                    {
                        using var write = sql.CreateCommand();
                        write.CommandText = "UPDATE stopped_work_audit SET " + column + "=" + column + "+1;";
                        write.ExecuteNonQuery();
                    }));
                Assert.Equal(19, rejected.SqliteErrorCode);
                Assert.Equal(before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            }
            for (var mutation = -1; mutation < audit.Length; mutation++)
            {
                var changed = audit.Select(value => value is byte[] bytes ? bytes.ToArray() : value).ToArray();
                if (mutation is 0 or 4) ((byte[])changed[mutation])[^1] ^= 1;
                else if (mutation == 1) changed[mutation] = 1L;
                else if (mutation >= 2)
                {
                    // Keep the SQL interval constraint valid, but do not forge
                    // its independent audit MAC or protected first timestamp.
                    var delta = mutation == 2 ? 1L : -1L;
                    changed[2] = checked((long)changed[2] + delta);
                    changed[3] = checked((long)changed[3] + delta);
                }
                await fixture.RestoreControlAuditFixture(test.Scope, mutation == -1 ? null : changed);
                var hostile = await fixture.ReadRawCompleteApplicationProjection(test.Scope);
                try
                {
                    var error = await Record.ExceptionAsync(() => fixture.ExpireSuccessfulAudits(test.Scope));
                    Assert.True(error is CryptographicException or InvalidDataException,
                        error?.ToString() ?? "Hostile successful audit was accepted.");
                    Assert.Equal(hostile, await fixture.ReadRawCompleteApplicationProjection(test.Scope));
                    Assert.Equal(root, await fixture.ReadAuthoredRootDigestAsync(own: true));
                }
                finally
                {
                    await fixture.RestoreControlAuditFixture(test.Scope, audit);
                    CryptographicOperations.ZeroMemory(hostile);
                    foreach (var bytes in changed.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
                }
            }
            foreach (var interruption in new[] { Did2CompactionFailpoint.AfterAbandonRecorded,
                Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared })
            {
                using (Did2CompactionTestHooks.Push(point =>
                    { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Prepared successful audit expiry."); }))
                    await Assert.ThrowsAsync<IOException>(() => fixture.ExpireSuccessfulAudits(test.Scope));
                fixture.ColdReopenCompactionStorage(); var hit = false;
                using (Did2CompactionTestHooks.Push(point =>
                    { if (point == interruption) { hit = true; throw new IOException("Interrupted successful audit abandon."); } }))
                    await Assert.ThrowsAsync<IOException>(() => fixture.SenderCompactionOwner().AbandonUncommittedOwnedOrdinaryOutboxAsync(default));
                Assert.True(hit); fixture.ColdReopenCompactionStorage();
                var requests = fixture.ProofRequests;
                await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
                await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
                Assert.Equal(requests, fixture.ProofRequests);
                Assert.Equal(before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
                Assert.Equal(root, await fixture.ReadAuthoredRootDigestAsync(own: true));
                await fixture.AssertSuccessfulAudit(test.Scope, test.Operation, terminal, expired: false);
            }
            await fixture.ExpireSuccessfulAudits(test.Scope);
            await fixture.AssertSuccessfulAudit(test.Scope, test.Operation, terminal, expired: true);
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.False((await test.Deliver()).IngressDispatched);
            Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        }
        finally
        {
            foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
            foreach (var bytes in new[] { before, root, native }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [Theory]
    [InlineData(true, false)] [InlineData(false, false)]
    [InlineData(true, true)] [InlineData(false, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2SuccessfulControlAudit_FirstSuccessAndEveryColdHandoverRemainMonotonic(bool initial, bool expire)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(initial); var stored = await test.Deliver();
        var first = await fixture.ReadSuccessfulControlTime(test);
        Assert.NotEqual(0UL, first);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        if (expire)
        {
            await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
            await fixture.AssertSuccessfulControlAudit(test, first, expired: false);
            await fixture.AdvanceControlAuditToLowerBoundary(checked(first + SqliteDeepMailboxStore.StoppedAuditSeconds));
        }
        var secure = fixture.CompletedContactSendStorage(initial);
        var slot = initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var original = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
        var before = original.Use(bytes => bytes.ToArray());
        var sql = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var audit = expire ? await fixture.ReadOnlyControlAudit(test.Scope) : null;
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        using var send = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        var sends = send.Use(bytes => bytes.ToArray());
        try
        {
            var points = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSql,
                Did2CompactionFailpoint.AfterSqlRecorded, Did2CompactionFailpoint.AfterHistoryAdopted,
                Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
            for (var index = 0; index < points.Length; index++)
            {
                if (index != 0)
                {
                    using var adopted = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                    Assert.True(await secure.CompareExchangeAsync(slot, adopted.Use(bytes => bytes.ToArray()), before));
                    await fixture.RestoreControlAuditFixture(test.Scope, audit);
                    Assert.Equal(sql, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
                }
                var hit = false;
                using (Did2CompactionTestHooks.Push(point =>
                    { if (point == points[index]) { hit = true; throw new IOException("Interrupted successful control audit."); } }))
                    await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
                Assert.True(hit);
                if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
                var requests = fixture.ProofRequests; var owner = fixture.CompletedContactSendRecoveryOwner(initial);
                await owner.ResumeOwnedLocalCompactionAsync(default); await owner.ResumeOwnedLocalCompactionAsync(default);
                Assert.Equal(requests, fixture.ProofRequests);
                await fixture.AssertSuccessfulControlAudit(test, first, expired: expire);
                var cached = await test.Deliver(); Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
                await fixture.AssertSuccessfulControlAudit(test, first, expired: expire);
                Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
                using var readback = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(sends, readback.Use(bytes => bytes.ToArray()));
                Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
            }
        }
        finally
        {
            foreach (var bytes in new[] { before, sql, native, sends }) CryptographicOperations.ZeroMemory(bytes);
            if (audit is not null) foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2SuccessfulControlAudit_DeadlineEdgesAndHostileRowsCannotRewriteFirstSuccess(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(initial); var stored = await test.Deliver();
        var first = await fixture.ReadSuccessfulControlTime(test);
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        await fixture.AssertSuccessfulControlAudit(test, first, expired: false);
        var audit = await fixture.ReadOnlyControlAudit(test.Scope);
        var deadline = checked(first + SqliteDeepMailboxStore.StoppedAuditSeconds);
        await fixture.AdvanceControlAuditToLowerBoundary(deadline - 1);
        Assert.Equal(deadline - 1, await fixture.ReadControlAuditAuthenticatedLower(test));
        var sqlBefore = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var secure = fixture.CompletedContactSendStorage(initial);
        var slot = initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var original = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
        var rootBefore = original.Use(bytes => bytes.ToArray());
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        try
        {
            // Missing/substituted/reason/time/MAC corruption is rejected even
            // before expiry, rather than silently repaired or extended.
            for (var mutation = -1; mutation < audit.Length; mutation++)
            {
                var changed = audit.Select(value => value is byte[] bytes ? bytes.ToArray() : value).ToArray();
                if (mutation is 0 or 4) ((byte[])changed[mutation])[^1] ^= 1;
                else if (mutation == 1) changed[mutation] = 1L;
                else if (mutation >= 2)
                {
                    var delta = mutation == 2 ? 1L : -1L;
                    changed[2] = checked((long)changed[2] + delta); changed[3] = checked((long)changed[3] + delta);
                }
                await fixture.RestoreControlAuditFixture(test.Scope, mutation == -1 ? null : changed);
                var hostile = await fixture.ReadRawCompleteApplicationProjection(test.Scope);
                try
                {
                    var error = await Record.ExceptionAsync(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
                    Assert.True(error is CryptographicException or InvalidDataException,
                        error?.ToString() ?? "Hostile successful control audit was accepted.");
                    Assert.Equal(hostile, await fixture.ReadRawCompleteApplicationProjection(test.Scope));
                    using var readback = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                    Assert.Equal(rootBefore, readback.Use(bytes => bytes.ToArray()));
                }
                finally
                {
                    await fixture.RestoreControlAuditFixture(test.Scope, audit);
                    CryptographicOperations.ZeroMemory(hostile);
                    foreach (var bytes in changed.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
                }
            }
            await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
            Assert.Equal(sqlBefore, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            using (var readback = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException())
                Assert.Equal(rootBefore, readback.Use(bytes => bytes.ToArray()));
            await fixture.AssertSuccessfulControlAudit(test, first, expired: false);
            fixture.AdvanceFrozenControlAuditOneSecond();
            Assert.Equal(deadline, await fixture.ReadControlAuditAuthenticatedLower(test));
            await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
            await fixture.AssertSuccessfulControlAudit(test, first, expired: true);
            var expired = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
            try
            {
                fixture.AdvanceFrozenControlAuditOneSecond();
                Assert.Equal(deadline + 1, await fixture.ReadControlAuditAuthenticatedLower(test));
                if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
                await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
                var cached = await test.Deliver(); Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
                await fixture.AssertSuccessfulControlAudit(test, first, expired: true);
                Assert.Equal(expired, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
                Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
                Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
            }
            finally { CryptographicOperations.ZeroMemory(expired); }
        }
        finally
        {
            foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
            foreach (var bytes in new[] { sqlBefore, rootBefore, native }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2SuccessfulControlAudit_PrecommitAbortColdRecoversWithoutReversingSuccess(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(initial); await test.Deliver();
        var first = await fixture.ReadSuccessfulControlTime(test);
        var secure = fixture.CompletedContactSendStorage(initial);
        var slot = initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        try
        {
            foreach (var expire in new[] { false, true })
            {
                if (expire)
                    await fixture.AdvanceControlAuditToLowerBoundary(checked(first + SqliteDeepMailboxStore.StoppedAuditSeconds));
                using var before = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                var rootBefore = before.Use(bytes => bytes.ToArray());
                var sqlBefore = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
                try
                {
                    foreach (var interruption in new[] { Did2CompactionFailpoint.AfterAbandonRecorded,
                        Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared })
                    {
                        using (Did2CompactionTestHooks.Push(point =>
                            { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Prepared successful control audit."); }))
                            await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
                        if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
                        var hit = false; var owner = fixture.CompletedContactSendRecoveryOwner(initial);
                        using (Did2CompactionTestHooks.Push(point =>
                            { if (point == interruption) { hit = true; throw new IOException("Interrupted successful control abandon."); } }))
                            await Assert.ThrowsAsync<IOException>(() => owner.AbandonUncommittedControlAuditAsync(default));
                        Assert.True(hit);
                        if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
                        owner = fixture.CompletedContactSendRecoveryOwner(initial); var requests = fixture.ProofRequests;
                        await owner.ResumeOwnedLocalCompactionAsync(default); await owner.ResumeOwnedLocalCompactionAsync(default);
                        Assert.Equal(requests, fixture.ProofRequests);
                        Assert.Equal(sqlBefore, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
                        using var readback = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                        Assert.Equal(rootBefore, readback.Use(bytes => bytes.ToArray()));
                        Assert.Equal(first, await fixture.ReadSuccessfulControlTime(test));
                    }
                }
                finally { CryptographicOperations.ZeroMemory(rootBefore); CryptographicOperations.ZeroMemory(sqlBefore); }
                await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
                await fixture.AssertSuccessfulControlAudit(test, first, expired: expire);
            }
            var cached = await test.Deliver(); Assert.False(cached.IngressDispatched);
            await fixture.AssertSuccessfulControlAudit(test, first, expired: true);
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        }
        finally { CryptographicOperations.ZeroMemory(native); }
    }

    private sealed partial class Fixture
    {
        internal void AdvanceFrozenControlAuditOneSecond()
        {
            Assert.Null(mailboxClockStarted);
            ProofTime = checked(ProofTime + 1); Sample = checked(Sample + 1);
        }
        internal async Task<ulong> ReadSuccessfulControlTime(CompletedContactSendCase test)
        {
            using var raw = await CompletedContactSendStorage(test.Scope.IsInitiator).ReadOwnedAsync(test.Scope.IsInitiator
                ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot) ?? throw new InvalidDataException();
            if (test.Scope.IsInitiator)
            {
                using var state = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
                var entry = state.Entries[Convert.ToHexString(test.Intent)]; Assert.False(entry.WorkStopped); Assert.True(entry.SuccessfullyStored);
                Assert.Equal(0UL, entry.StoppedAtUpper); return entry.FirstSuccessfulStoreUpper;
            }
            using var accepts = raw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
            var accept = accepts.FindScope(test.Scope)!; Assert.False(accept.WorkStopped); Assert.True(accept.SuccessfullyStored);
            Assert.Equal(0UL, accept.StoppedAtUpper); return accept.FirstSuccessfulStoreUpper;
        }
        internal async Task AssertSuccessfulControlAudit(CompletedContactSendCase test, ulong first, bool expired)
        {
            Assert.Equal(expired ? 0UL : first, await ReadSuccessfulControlTime(test));
            using var raw = await CompletedContactSendStorage(test.Scope.IsInitiator).ReadOwnedAsync(test.Scope.IsInitiator
                ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot) ?? throw new InvalidDataException();
            if (test.Scope.IsInitiator)
            {
                using var state = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
                var entry = state.Entries[Convert.ToHexString(test.Intent)]; Assert.True(entry.PayloadRetired); Assert.Equal(expired ? 2 : 1, entry.AuditDisposition);
                Assert.Equal(ProtectedDid2ContactStartJournal.PrefixBytes, entry.Exact.Length);
            }
            else
            {
                using var state = raw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
                var entry = state.FindScope(test.Scope)!; Assert.True(entry.PayloadRetired); Assert.Equal(expired ? 2 : 1, entry.AuditDisposition);
                Assert.Equal(ProtectedDid2ContactAcceptJournal.PrefixBytes, entry.Exact.Length);
            }
            if (expired)
                await WithAuthoredApplicationConnectionAsync(test.Scope, sql =>
                { using var read = sql.CreateCommand(); read.CommandText = "SELECT count(*) FROM stopped_work_audit;"; Assert.Equal(0L, read.ExecuteScalar()); });
            else
            {
                var audit = await ReadOnlyControlAudit(test.Scope); Assert.NotEqual(test.Operation, Assert.IsType<byte[]>(audit[0]));
                Assert.Equal(3L, audit[1]); Assert.Equal(checked((long)first), audit[2]);
                Assert.Equal(checked((long)(first + SqliteDeepMailboxStore.StoppedAuditSeconds)), audit[3]);
                Assert.Equal(32, Assert.IsType<byte[]>(audit[4]).Length);
                foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
            }
        }
        internal async Task<ulong> ReadSuccessfulAuditAuthenticatedLower()
        {
            var account = ReopenAccount();
            return (await Source(account).VerifyForOwnPreKeyAuthoringAsync(account, default)).Proof.TrustedLowerUnixSeconds;
        }
        internal Task ExpireSuccessfulAudits(Did2MessagingSessionScope scope)
        {
            var account = ReopenAccount(); return account.MaintainOwnSuccessfulOutboxAuditsAsync(scope, Source(account));
        }
        internal async Task<ulong> ReadSuccessfulTerminalTime(Did2MessagingSessionScope scope, byte[] operation, bool compacted)
        {
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            using var state = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var name = Convert.ToHexString(operation);
            return compacted ? state.TerminalAudits[name].TerminalAtUpper : state.Entries[name].FirstSuccessfulStoreUpper;
        }
        internal async Task AssertSuccessfulAudit(Did2MessagingSessionScope scope, byte[] operation, ulong terminalTime, bool expired)
        {
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            using var state = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var name = Convert.ToHexString(operation); Assert.False(state.Entries.ContainsKey(name));
            Assert.Equal(!expired, state.TerminalAudits.ContainsKey(name)); Assert.True(state.NextSequence(scope) > 3);
            await WithAuthoredApplicationConnectionAsync(scope, sql =>
            {
                using var read = sql.CreateCommand();
                read.CommandText = "SELECT reason,stopped_at,expires_at,length(authenticator) FROM stopped_work_audit WHERE operation_id=$op;";
                read.Parameters.AddWithValue("$op", operation); using var row = read.ExecuteReader();
                Assert.Equal(!expired, row.Read());
                if (!expired)
                {
                    Assert.Equal(3L, row.GetInt64(0)); Assert.Equal(checked((long)terminalTime), row.GetInt64(1));
                    Assert.Equal(checked((long)(terminalTime + SqliteDeepMailboxStore.StoppedAuditSeconds)), row.GetInt64(2));
                    Assert.Equal(32L, row.GetInt64(3)); Assert.False(row.Read());
                }
            });
            await ReadCompleteOrdinaryApplicationProjection(scope);
        }
    }
}
