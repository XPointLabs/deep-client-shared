using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ControlAudit_ActualStoppedCustodyProducesDeterministicReadOnlyVirtualSqlEffect(bool initial)
    {
        // Capturing a virtual effect is not actual payload/audit deletion.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterWorkStopRoot) throw new IOException("Stop committed before audit cleanup."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
        var before = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var effects = await fixture.CaptureStoppedControlAudit(test);
        Assert.True(before.AsSpan().SequenceEqual(effects.Before)); Assert.False(effects.Before.AsSpan().SequenceEqual(effects.After));
        var repeated = await fixture.CaptureStoppedControlAudit(test);
        Assert.True(effects.Before.AsSpan().SequenceEqual(repeated.Before)); Assert.True(effects.After.AsSpan().SequenceEqual(repeated.After));
        Assert.Equal(before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        await fixture.AssertControlStopMetadata(test, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, retired: false);
        Assert.Equal(0, test.Transport.Calls); Assert.Equal(0, test.Grants.Calls);
        foreach (var bytes in new[] { before, effects.Before, effects.After, repeated.Before, repeated.After }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(true, false)] [InlineData(false, false)]
    [InlineData(true, true)] [InlineData(false, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ControlAudit_JointCleanupAndExpiryColdRecoverEveryHandoverWithoutChangingUnknownWork(bool initial, bool expire)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        test.Transport.LoseReply = true;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterWorkStopRoot) throw new IOException("Stop before cleanup."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
        if (expire)
        {
            await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
            var audit = await fixture.ReadOnlyControlAudit(test.Scope);
            await fixture.AdvanceStoppedWorkToOriginalDeadline(checked((ulong)(long)audit[3]));
            foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
        }
        var secure = fixture.CompletedContactSendStorage(initial);
        var slot = initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var root = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
        var predecessor = root.Use(bytes => bytes.ToArray());
        var auditBefore = expire ? await fixture.ReadOnlyControlAudit(test.Scope) : null;
        var effects = await fixture.CaptureStoppedControlAudit(test, expire);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var source = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        using var sends = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        var sendBefore = sends.Use(bytes => bytes.ToArray());
        var points = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSql,
            Did2CompactionFailpoint.AfterSqlRecorded, Did2CompactionFailpoint.AfterHistoryAdopted,
            Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
        for (var index = 0; index < points.Length; index++)
        {
            if (index != 0)
            {
                // Restore only this disposable fixture's exact predecessor and
                // audit row to exercise all boundaries on the same real native work.
                using var adopted = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                Assert.True(await secure.CompareExchangeAsync(slot, adopted.Use(bytes => bytes.ToArray()), predecessor));
                await fixture.RestoreControlAuditFixture(test.Scope, auditBefore);
                Assert.Equal(effects.Before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            }
            using var cancellation = new CancellationTokenSource(); var hit = false;
            var cancel = index % 2 == 1;
            using (Did2CompactionTestHooks.Push(point =>
            {
                if (point != points[index]) return; hit = true;
                if (cancel) { cancellation.Cancel(); cancellation.Token.ThrowIfCancellationRequested(); }
                throw new IOException("Interrupted actual control audit transition.");
            }))
            {
                if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation, cancellation.Token));
                else await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
            }
            Assert.True(hit);
            if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
            var owner = fixture.CompletedContactSendRecoveryOwner(initial);
            if (index == 1)
                await Assert.ThrowsAsync<CryptographicException>(() => owner.AbandonUncommittedControlAuditAsync(default));
            if (index is 2 or 3)
                await Assert.ThrowsAsync<InvalidOperationException>(() => owner.AbandonUncommittedControlAuditAsync(default));
            await owner.ResumeOwnedLocalCompactionAsync(default); // Local recovery needs no renewed network authority.
            await owner.ResumeOwnedLocalCompactionAsync(default);
            await fixture.AssertControlAuditFinal(test, expire);
            Assert.Equal(effects.After, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(source, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
            using var sendAfter = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
            Assert.Equal(sendBefore, sendAfter.Use(bytes => bytes.ToArray()));
            Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
            using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            Assert.Equal(0, plan.Use(bytes => bytes[1]));
        }
        foreach (var bytes in new[] { predecessor, effects.Before, effects.After, native, source, sendBefore }) CryptographicOperations.ZeroMemory(bytes);
        if (auditBefore is not null) foreach (var bytes in auditBefore.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ControlAudit_UnchangedPreparedCleanupCanAbandonButStopCannotBeReversed(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        var before = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        using (Did2CompactionTestHooks.Push(point =>
            { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Prepared cleanup reply lost."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
        if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
        var owner = fixture.CompletedContactSendRecoveryOwner(initial);
        await owner.AbandonUncommittedControlAuditAsync(default);
        await fixture.AssertControlStopMetadata(test, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, retired: false);
        Assert.Equal(before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        await fixture.AssertControlAuditFinal(test, expire: false);
        Assert.Equal(0, test.Transport.Calls); Assert.Equal(0, test.Grants.Calls);
        CryptographicOperations.ZeroMemory(before);
    }

    [Theory]
    [InlineData(true, false)] [InlineData(false, false)]
    [InlineData(true, true)] [InlineData(false, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ControlAudit_PrecommitAbortColdRecoversEveryAbandonHandoverWithoutReversingStop(bool initial, bool expire)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        test.Transport.LoseReply = true;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterWorkStopRoot) throw new IOException("Stop before cleanup."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
        if (expire)
        {
            await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
            var audit = await fixture.ReadOnlyControlAudit(test.Scope);
            await fixture.AdvanceStoppedWorkToOriginalDeadline(checked((ulong)(long)audit[3]));
            foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
        }
        var sql = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var secure = fixture.CompletedContactSendStorage(initial);
        var slot = initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var command = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
        var exactCommand = command.Use(bytes => bytes.ToArray());
        using var sends = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        var exactSend = sends.Use(bytes => bytes.ToArray());
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var points = new[] { Did2CompactionFailpoint.AfterAbandonRecorded,
            Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
        foreach (var point in points)
        {
            using (Did2CompactionTestHooks.Push(actual =>
                { if (actual == Did2CompactionFailpoint.AfterStage) throw new IOException("Prepared audit plan."); }))
                await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
            var hit = false;
            using var cancellation = new CancellationTokenSource();
            using (Did2CompactionTestHooks.Push(actual =>
            {
                if (actual != point) return; hit = true;
                if (point == Did2CompactionFailpoint.AfterPartsDeleted)
                { cancellation.Cancel(); cancellation.Token.ThrowIfCancellationRequested(); }
                throw new IOException("Interrupted actual control abort.");
            }))
            {
                var owner = fixture.CompletedContactSendRecoveryOwner(initial);
                if (point == Did2CompactionFailpoint.AfterPartsDeleted)
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => owner.AbandonUncommittedControlAuditAsync(cancellation.Token));
                else await Assert.ThrowsAsync<IOException>(() => owner.AbandonUncommittedControlAuditAsync(default));
            }
            Assert.True(hit);
            if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
            await fixture.CompletedContactSendRecoveryOwner(initial).ResumeOwnedLocalCompactionAsync(default);
            await fixture.CompletedContactSendRecoveryOwner(initial).ResumeOwnedLocalCompactionAsync(default);
            using var current = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
            using var sendAfter = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
            using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            Assert.Equal(exactCommand, current.Use(bytes => bytes.ToArray())); Assert.Equal(exactSend, sendAfter.Use(bytes => bytes.ToArray()));
            Assert.Equal(sql, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(0, plan.Use(bytes => bytes[1]));
            for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
            {
                using var part = await secure.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index)); Assert.Null(part);
            }
        }
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        await fixture.AssertControlAuditFinal(test, expire);
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        foreach (var bytes in new[] { sql, exactCommand, exactSend, native }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ControlAudit_HostileRowsRejectWithoutRepairOrWorkReactivation(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        var audit = await fixture.ReadOnlyControlAudit(test.Scope);
        var secure = fixture.CompletedContactSendStorage(initial);
        var slot = initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var root = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
        var exact = root.Use(bytes => bytes.ToArray());
        foreach (var defect in new[] { "missing", "mac", "deadline", "foreign" })
        {
            await fixture.DamageStoppedAudit(test.Scope, defect);
            if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
            var damaged = await fixture.ReadRawCompleteApplicationProjection(test.Scope);
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
            Assert.Equal(damaged, await fixture.ReadRawCompleteApplicationProjection(test.Scope));
            using var after = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
            Assert.Equal(exact, after.Use(bytes => bytes.ToArray()));
            await fixture.RestoreControlAuditFixture(test.Scope, audit); // Disposable corruption fixture only.
            CryptographicOperations.ZeroMemory(damaged);
        }
        Assert.Equal(0, test.Transport.Calls); Assert.Equal(0, test.Grants.Calls);
        CryptographicOperations.ZeroMemory(exact);
        foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ControlAudit_AuthenticatedLowerDeadlineIsExactAndUpperCrossingCannotDelete(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        var audit = await fixture.ReadOnlyControlAudit(test.Scope);
        var deadline = checked((ulong)(long)audit[3]);
        await fixture.AdvanceControlAuditToLowerBoundary(deadline - 1);
        var before = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        Assert.Equal(deadline - 1, await fixture.ReadControlAuditAuthenticatedLower(test));
        if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        await fixture.AssertControlAuditFinal(test, expire: false);
        Assert.Equal(before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        Assert.Equal(audit, await fixture.ReadOnlyControlAudit(test.Scope)); // Neither time nor deadline extended.
        fixture.ProofTime++; fixture.Sample++;
        Assert.Equal(deadline, await fixture.ReadControlAuditAuthenticatedLower(test));
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        await fixture.AssertControlAuditFinal(test, expire: true);
        var after = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        fixture.ProofTime++; fixture.Sample++;
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        Assert.Equal(after, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        Assert.Equal(0, test.Transport.Calls); Assert.Equal(0, test.Grants.Calls);
        foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
        CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after);
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ControlAudit_HostileStagingCannotApplySqlAdoptPayloadOrAbandon(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        using (Did2CompactionTestHooks.Push(point =>
            { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Staging reply lost."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
        var secure = fixture.CompletedContactSendStorage(initial);
        using var part = await secure.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(0)) ?? throw new InvalidDataException();
        var exactPart = part.Use(bytes => bytes.ToArray());
        using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
        var exactPlan = plan.Use(bytes => bytes.ToArray());
        var slot = initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var command = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
        var exactCommand = command.Use(bytes => bytes.ToArray());
        var sql = await fixture.ReadRawCompleteApplicationProjection(test.Scope);
        foreach (var defect in new[] { "missing", "changed", "extra" })
        {
            if (defect == "missing") await secure.DeleteBatchAsync([ProtectedDid2CompactionPlan.PartSlot(0)]);
            if (defect == "changed")
            {
                var damaged = exactPart.ToArray(); damaged[^1] ^= 1;
                Assert.True(await secure.CompareExchangeAsync(ProtectedDid2CompactionPlan.PartSlot(0), exactPart, damaged));
                CryptographicOperations.ZeroMemory(damaged);
            }
            if (defect == "extra") await secure.WriteBatchAsync([new(ProtectedDid2CompactionPlan.PartSlot(1), exactPart)]);
            if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
            var owner = fixture.CompletedContactSendRecoveryOwner(initial);
            await Assert.ThrowsAsync<InvalidDataException>(() => owner.ResumeOwnedLocalCompactionAsync(default));
            await Assert.ThrowsAsync<InvalidDataException>(() => owner.AbandonUncommittedControlAuditAsync(default));
            using var planAfter = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            using var commandAfter = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
            Assert.Equal(exactPlan, planAfter.Use(bytes => bytes.ToArray())); Assert.Equal(exactCommand, commandAfter.Use(bytes => bytes.ToArray()));
            Assert.Equal(sql, await fixture.ReadRawCompleteApplicationProjection(test.Scope));
            if (defect == "extra") await secure.DeleteBatchAsync([ProtectedDid2CompactionPlan.PartSlot(1)]);
            else if (defect == "missing") await secure.WriteBatchAsync([new(ProtectedDid2CompactionPlan.PartSlot(0), exactPart)]);
            else
            {
                using var damaged = await secure.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(0)) ?? throw new InvalidDataException();
                Assert.True(await secure.CompareExchangeAsync(ProtectedDid2CompactionPlan.PartSlot(0), damaged.Use(bytes => bytes.ToArray()), exactPart));
            } // Exact disposable fixture restoration only, never runtime repair.
        }
        await fixture.CompletedContactSendRecoveryOwner(initial).ResumeOwnedLocalCompactionAsync(default);
        await fixture.AssertControlAuditFinal(test, expire: false);
        Assert.Equal(0, test.Transport.Calls); Assert.Equal(0, test.Grants.Calls);
        foreach (var bytes in new[] { exactPart, exactPlan, exactCommand, sql }) CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        internal async Task AdvanceControlAuditToLowerBoundary(ulong lower)
        {
            // Preserve elapsed authenticated time before freezing this test's
            // monotonic clock. Real signed proofs still define every boundary.
            var elapsed = MailboxElapsedSeconds;
            ProofTime = checked(ProofTime + elapsed); Sample = checked(Sample + elapsed); mailboxClockStarted = null;
            if (successor is null) await AdvanceOriginalStoreEpochForTestAsync(2_100);
            else Assert.NotNull(epochSuccessorPmt); // Reuse the actual already-authored successor, never mint it twice.
            var delta = checked(lower + 5 - CurrentProofTime);
            ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
            await AdvanceObjectHorizonAuthorityAsync();
        }

        internal async Task<ulong> ReadControlAuditAuthenticatedLower(CompletedContactSendCase test)
        {
            var account = test.Scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = test.Scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            return (await source.VerifyForOwnPreKeyAuthoringAsync(account, default)).Proof.TrustedLowerUnixSeconds;
        }

        internal async Task<object[]> ReadOnlyControlAudit(Did2MessagingSessionScope scope)
        {
            object[] result = [];
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var read = connection.CreateCommand(); read.CommandText = "SELECT * FROM stopped_work_audit;";
                using var rows = read.ExecuteReader(); Assert.True(rows.Read());
                result = new object[rows.FieldCount]; rows.GetValues(result); Assert.False(rows.Read());
            });
            Assert.Equal(5, result.Length); return result;
        }

        internal Task RestoreControlAuditFixture(Did2MessagingSessionScope scope, object[]? audit) =>
            WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var clear = connection.CreateCommand(); clear.CommandText = "DELETE FROM stopped_work_audit;"; clear.ExecuteNonQuery();
                if (audit is null) return;
                using var insert = connection.CreateCommand();
                insert.CommandText = "INSERT INTO stopped_work_audit VALUES($op,$reason,$stop,$expiry,$mac);";
                var names = new[] { "$op", "$reason", "$stop", "$expiry", "$mac" };
                for (var index = 0; index < names.Length; index++) insert.Parameters.AddWithValue(names[index], audit[index]);
                Assert.Equal(1, insert.ExecuteNonQuery());
            });

        internal async Task AssertControlAuditFinal(CompletedContactSendCase test, bool expire)
        {
            using var raw = await CompletedContactSendStorage(test.Scope.IsInitiator).ReadOwnedAsync(test.Scope.IsInitiator
                ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot) ?? throw new InvalidDataException();
            if (test.Scope.IsInitiator)
            {
                using var journal = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
                var entry = journal.Entries[Convert.ToHexString(test.Intent)];
                Assert.True(entry.WorkStopped); Assert.True(entry.PayloadRetired); Assert.Equal(expire ? 2 : 1, entry.AuditDisposition);
                Assert.Equal(ProtectedDid2ContactStartJournal.PrefixBytes, entry.Exact.Length);
                Assert.Equal(expire, entry.StoppedAtUpper == 0);
            }
            else
            {
                using var journal = raw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
                var entry = journal.FindScope(test.Scope) ?? throw new InvalidDataException();
                Assert.True(entry.WorkStopped); Assert.True(entry.PayloadRetired); Assert.Equal(expire ? 2 : 1, entry.AuditDisposition);
                Assert.Equal(ProtectedDid2ContactAcceptJournal.PrefixBytes, entry.Exact.Length);
                Assert.Equal(expire, entry.StoppedAtUpper == 0); Assert.Equal(1, entry.NativeStopMode);
            }
            if (expire)
                await WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
                {
                    using var read = connection.CreateCommand(); read.CommandText = "SELECT count(*) FROM stopped_work_audit;";
                    Assert.Equal(0L, read.ExecuteScalar());
                });
            else
            {
                var audit = await ReadOnlyControlAudit(test.Scope);
                Assert.NotEqual(test.Operation, Assert.IsType<byte[]>(audit[0]));
                Assert.Equal(1L, audit[1]); Assert.Equal((long)audit[2] + (long)SqliteDeepMailboxStore.StoppedAuditSeconds, (long)audit[3]);
                Assert.Equal(32, Assert.IsType<byte[]>(audit[4]).Length);
                foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
            }
        }

        internal async Task<(byte[] Before, byte[] After)> CaptureStoppedControlAudit(CompletedContactSendCase test, bool expire = false)
        {
            var scope = test.Scope;
            var accountDirectory = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var secure = CompletedContactSendStorage(scope.IsInitiator);
            var lease = new DeepIdV2AccountFileLease(Path.Combine(accountDirectory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            using var ordinaryRaw = await secure.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            using var ordinary = ordinaryRaw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(secure,
                Path.Combine(accountDirectory, "deep-store-v2-account.dsv2"), scope, held, lease, default);
            return await application.CaptureControlAuditEffectsAsync(scope, scope.IsInitiator ? (byte)1 : (byte)2,
                test.Operation, expire, ordinary, default);
        }

        internal async Task<byte[]> ReadRawCompleteApplicationProjection(Did2MessagingSessionScope scope)
        {
            byte[] result = [];
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
                result = SqliteDeepMailboxStore.ReadCompleteLocalSqlProjection(connection, scope.Hash, default));
            return result; // Diagnostic damaged-SQL readback only, never authority.
        }
    }
}
