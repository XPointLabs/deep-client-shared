using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedAudit_DueMaintenanceCannotBlockExactPendingAuthorRecovery()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        var audit = await fixture.ReadStoppedAuditRow(test.Scope, test.Operation);
        const string text = "Exact pending author before audit deadline";
        var hit = false;
        using (Did2TextOutboxTestHooks.Push(point =>
        { if (point == Did2TextOutboxFailpoint.AfterPending) { hit = true; throw new IOException("Interrupted actual pending author."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CreateOwnedText(test.Scope, text));
        Assert.True(hit);
        byte[] nextOperation;
        using (var actual = await fixture.ReadAuthoredTextJournalAsync(test.Scope))
            nextOperation = (actual.Pending ?? throw new InvalidDataException()).Operation.ToArray();
        var original = await fixture.ReadPendingAuthorForAudit(test.Scope, nextOperation);
        await fixture.AdvanceStoppedWorkToOriginalDeadline(checked((ulong)(long)audit[3]));
        fixture.ColdReopenCompactionStorage();
        using (var resumed = await fixture.RetryOwnedText(test.Scope, nextOperation, text))
            Assert.Equal(original, resumed.ExactDmc2.ToArray());
        Assert.Equal(audit, await fixture.ReadStoppedAuditRow(test.Scope, test.Operation));
        // The next ordinary entry point can now expire metadata, without
        // replacing the pending event or advancing its authored counter twice.
        using (var cached = await fixture.RetryOwnedText(test.Scope, nextOperation, text))
            Assert.Equal(original, cached.ExactDmc2.ToArray());
        await fixture.RequireExpiredStoppedAudit(test.Scope, test.Operation);
        Assert.Equal(0, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
        CryptographicOperations.ZeroMemory(original);
    }

    [Theory]
    [InlineData("AfterStage", false)] [InlineData("AfterSql", false)]
    [InlineData("AfterSqlRecorded", false)] [InlineData("AfterHistoryAdopted", false)]
    [InlineData("AfterPartsDeleted", false)] [InlineData("AfterPlanCleared", false)]
    [InlineData("AfterStage", true)] [InlineData("AfterSql", true)]
    [InlineData("AfterSqlRecorded", true)] [InlineData("AfterHistoryAdopted", true)]
    [InlineData("AfterPartsDeleted", true)] [InlineData("AfterPlanCleared", true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedAudit_ExpiredMetadataColdRecoversWithoutDeletingUnknownCustody(string interruption, bool cancel)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        test.Transport.LoseReply = true;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        var audit = await fixture.ReadStoppedAuditRow(test.Scope, test.Operation);
        Assert.Equal(5, audit.Length); Assert.Equal(test.Operation, audit[0]); Assert.Equal(1L, audit[1]);
        Assert.Equal((long)audit[2] + (long)SqliteDeepMailboxStore.StoppedAuditSeconds, (long)audit[3]);
        Assert.Equal(32, Assert.IsType<byte[]>(audit[4]).Length);
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        Assert.Equal(audit, await fixture.ReadStoppedAuditRow(test.Scope, test.Operation)); // No deadline extension.
        await fixture.AdvanceStoppedWorkToOriginalDeadline(checked((ulong)(long)audit[3]));
        var expectedSql = await fixture.ExpectedExpiredAuditSqlSuccessor(test.Scope, test.Operation);
        var originalSend = await fixture.ReadSendRootForStoppedWork();
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        using var cancellation = new CancellationTokenSource(); var hit = false;
        var selected = Enum.Parse<Did2CompactionFailpoint>(interruption);
        using (Did2CompactionTestHooks.Push(point =>
        {
            if (point != selected) return; hit = true;
            if (cancel) { cancellation.Cancel(); cancellation.Token.ThrowIfCancellationRequested(); }
            throw new IOException("Interrupted stopped audit expiry.");
        }))
        {
            if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation, cancellation.Token));
            else await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
        }
        Assert.True(hit);
        for (var reopen = 0; reopen < 2; reopen++)
        {
            fixture.ColdReopenCompactionStorage();
            await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
            await fixture.RequireExpiredStoppedAudit(test.Scope, test.Operation);
            Assert.Equal(expectedSql, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(originalSend, await fixture.ReadSendRootForStoppedWork());
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Single(await fixture.ListOwnedMessages(test.Scope)); Assert.Empty(await fixture.ListNativePendingText());
            Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        }
        foreach (var bytes in audit.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
        foreach (var bytes in new[] { expectedSql, originalSend, native }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData("missing")] [InlineData("mac")] [InlineData("deadline")] [InlineData("foreign")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedAudit_HostileSqlCannotAuthorizeOrRecreateAudit(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        await fixture.DamageStoppedAudit(test.Scope, defect);
        fixture.ColdReopenCompactionStorage();
        var before = await fixture.ReadRawCompleteApplicationProjection(test.Scope);
        var root = await fixture.ReadAuthoredRootDigestAsync();
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ListNativePendingText());
        Assert.Equal(before, await fixture.ReadRawCompleteApplicationProjection(test.Scope));
        Assert.Equal(root, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(0, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(root);
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]> ReadPendingAuthorForAudit(Did2MessagingSessionScope scope, byte[] operation)
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            using var journal = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var pending = journal.Entries[Convert.ToHexString(operation)]; Assert.True(pending.Pending);
            return pending.PendingDmc2.ToArray();
        }
        internal async Task<object[]> ReadStoppedAuditRow(Did2MessagingSessionScope scope, byte[] operation)
        {
            object[] result = [];
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var read = connection.CreateCommand(); read.CommandText = "SELECT * FROM stopped_work_audit WHERE operation_id=$op;";
                read.Parameters.AddWithValue("$op", operation); using var rows = read.ExecuteReader(); Assert.True(rows.Read());
                result = new object[rows.FieldCount]; rows.GetValues(result); Assert.False(rows.Read());
            });
            return result;
        }
        internal async Task<byte[]> ExpectedExpiredAuditSqlSuccessor(Did2MessagingSessionScope scope, byte[] operation)
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            using var journal = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var heldLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await heldLease.AcquireAsync(default);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(storage,
                Path.Combine(directory, "deep-store-v2-account.dsv2"), scope, held, heldLease, default);
            var effects = await application.CaptureTerminalAuditExpiryAsync(scope, journal,
                [journal.TerminalAudits[Convert.ToHexString(operation)]], default);
            CryptographicOperations.ZeroMemory(effects.Before); return effects.After;
        }
        internal async Task RequireExpiredStoppedAudit(Did2MessagingSessionScope scope, byte[] operation)
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            using var journal = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var name = Convert.ToHexString(operation);
            Assert.False(journal.Entries.ContainsKey(name)); Assert.False(journal.TerminalAudits.ContainsKey(name));
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var read = connection.CreateCommand(); read.CommandText = "SELECT count(*) FROM stopped_work_audit;";
                Assert.Equal(0L, read.ExecuteScalar());
            });
        }
        internal Task DamageStoppedAudit(Did2MessagingSessionScope scope, string defect) =>
            WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var edit = connection.CreateCommand();
                edit.CommandText = defect switch
                {
                    "missing" => "DELETE FROM stopped_work_audit;",
                    "mac" => "UPDATE stopped_work_audit SET authenticator=zeroblob(32);",
                    "deadline" => "UPDATE stopped_work_audit SET stopped_at=stopped_at+1,expires_at=expires_at+1;",
                    "foreign" => "UPDATE stopped_work_audit SET operation_id=randomblob(32);",
                    _ => throw new ArgumentOutOfRangeException(nameof(defect))
                };
                Assert.Equal(1, edit.ExecuteNonQuery());
            });
    }
}
