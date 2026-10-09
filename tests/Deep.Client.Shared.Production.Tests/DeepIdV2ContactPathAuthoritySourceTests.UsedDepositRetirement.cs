using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2UsedDepositRetirement_ColdHandoversPreserveLiveObjectsAndMissingSqlPins(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        var stored = await fixture.DeliverCompletedCaseWithExactRetry(test);
        var dispatches = test.Transport.Calls;
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        await fixture.RetireCompletedContactSend(test);
        var secure = fixture.CompletedContactSendStorage(initial);
        byte[] acquisition;
        using (var grants = await fixture.ReadPeerGrantsAsync(own: initial))
            acquisition = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(Assert.Single(grants.Entries).Value));
        var account = fixture.UsedDepositAccount(initial);
        var source = initial ? fixture.Source(account) : fixture.GrantReaderSource(account);
        using (var exclusion = await account.OpenMailboxEpochExclusionAsync(acquisition, source))
            await exclusion.RetireIdleMailboxCounterFloorAsync();
        using var original = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
        var originalGrant = original.Use(bytes => bytes.ToArray());
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var sourceSql = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        var retainedRoots = await fixture.ReadUsedDepositRetainedRoots(test.Scope);
        var envelope = test.Transport.StoredEnvelope ?? throw new InvalidDataException();
        Assert.Equal(30UL * 24 * 60 * 60, envelope.ExpiresAtUnixSeconds - envelope.CreatedAtUnixSeconds);
        Assert.True(envelope.ExpiresAtUnixSeconds > 2_100);

        // Actual native/source custody still exists after an application SQL
        // rollback. An empty evidence result cannot authorize holder deletion.
        var row = await fixture.RemoveOriginalStoreEvidenceForTest(test);
        try
        {
            using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            var missing = await Record.ExceptionAsync(() => account.RetireUsedDepositAcquisitionAsync(acquisition, source));
            Assert.True(missing is CryptographicException or InvalidDataException or IOException,
                missing?.GetType().Name ?? "Missing SQL unexpectedly authorized retirement");
            using var actual = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            using var actualPlan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            Assert.Equal(originalGrant, actual.Use(bytes => bytes.ToArray()));
            Assert.Equal(plan.Use(bytes => bytes.ToArray()), actualPlan.Use(bytes => bytes.ToArray()));
        }
        finally { await fixture.RestoreOriginalStoreEvidenceForTest(test, row); }
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));

        var points = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSqlRecorded,
            Did2CompactionFailpoint.AfterHistoryAdopted, Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
        for (var index = 0; index < points.Length; index++)
        {
            if (index != 0)
            {
                // Disposable fixture only: reinsert byte-exact original custody
                // for each handover of the same genuine one-time Store.
                using var retired = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                Assert.True(await secure.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot,
                    retired.Use(bytes => bytes.ToArray()), originalGrant));
            }
            account = fixture.UsedDepositAccount(initial);
            source = initial ? fixture.Source(account) : fixture.GrantReaderSource(account);
            using (Did2CompactionTestHooks.Push(point => { if (point == points[index]) throw new IOException("Injected used Deposit handover."); }))
                await Assert.ThrowsAsync<IOException>(() => account.RetireUsedDepositAcquisitionAsync(acquisition, source));
            if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
            var owner = fixture.CompletedContactSendRecoveryOwner(initial);
            if (index == 0)
            {
                var missingRow = await fixture.RemoveOriginalStoreEvidenceForTest(test);
                try
                {
                    using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    var fault = await Record.ExceptionAsync(() => owner.ResumeOwnedLocalCompactionAsync(default));
                    Assert.True(fault is CryptographicException or InvalidDataException, fault?.GetType().Name ?? "Changed SQL unexpectedly recovered");
                    using var actualPlan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    using var actualGrant = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    Assert.Equal(plan.Use(bytes => bytes.ToArray()), actualPlan.Use(bytes => bytes.ToArray()));
                    Assert.Equal(originalGrant, actualGrant.Use(bytes => bytes.ToArray()));
                }
                finally { await fixture.RestoreOriginalStoreEvidenceForTest(test, missingRow); }
            }
            await owner.ResumeOwnedLocalCompactionAsync(default);
            using (var grants = await fixture.ReadPeerGrantsAsync(own: initial))
            { Assert.Empty(grants.Entries); Assert.Empty(grants.Selections); }
            Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(sourceSql, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
            Assert.Equal(retainedRoots, await fixture.ReadUsedDepositRetainedRoots(test.Scope));
            var cached = await test.Deliver();
            Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
            Assert.Equal(stored.Disposition, cached.Disposition); Assert.Equal(dispatches, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
            using var completed = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            Assert.Equal(0, completed.Use(bytes => bytes[1]));
        }
        foreach (var bytes in new[] { acquisition, originalGrant }) CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        internal DeepIdV2AccountService UsedDepositAccount(bool initial) => initial ? ReopenAccount() : ReopenGrantReader();

        internal async Task<ClientMailboxStoreResult> DeliverCompletedCaseWithExactRetry(CompletedContactSendCase test)
        {
            try { return await test.Deliver(); }
            catch (ClientMailboxDispatchOutcomeUnknownException)
            {
                // No wider installation interval, clock freeze or reauthoring.
                // Exercise the ordinary exact retry with fresh current guards.
                var request = test.Transport.ExactRequest?.ToArray() ?? throw new InvalidDataException();
                try
                {
                    var result = await test.Deliver();
                    Assert.Equal(request, test.Transport.ExactRequest); Assert.Equal(1, test.Grants.Calls); return result;
                }
                finally { CryptographicOperations.ZeroMemory(request); }
            }
        }

        internal async Task<byte[]> ReadUsedDepositRetainedRoots(Did2MessagingSessionScope scope)
        {
            var secure = CompletedContactSendStorage(scope.IsInitiator);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var slot in new[] { ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxSendJournal.Slot,
                ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot,
                SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, ProtectedDid2ContactStartJournal.Slot,
                ProtectedDid2ContactAcceptJournal.Slot, ProtectedInitialKeyRetirementJournal.Slot, ProtectedDph2PreClaimJournal.Slot })
            { using var raw = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); raw.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; }); }
            return hash.GetHashAndReset();
        }

        private static readonly string[] StoreEvidenceColumns = ["scope_hash", "operation_id", "account_scope", "logical_id", "exact_pma", "exact_view",
            "first_descriptor", "second_descriptor", "original_dcr", "original_route", "original_peer_adp"];

        internal async Task<byte[][]> RemoveOriginalStoreEvidenceForTest(CompletedContactSendCase test)
        {
            byte[][] result = [];
            await WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
            {
                using (var read = connection.CreateCommand())
                {
                    read.CommandText = "SELECT " + string.Join(",", StoreEvidenceColumns) + " FROM mailbox_store_public_evidence WHERE scope_hash=$scope AND operation_id=$op;";
                    read.Parameters.AddWithValue("$scope", test.Scope.Hash.ToArray()); read.Parameters.AddWithValue("$op", test.Operation);
                    using var reader = read.ExecuteReader(); Assert.True(reader.Read());
                    result = StoreEvidenceColumns.Select((_, index) => reader.GetFieldValue<byte[]>(index)).ToArray(); Assert.False(reader.Read());
                }
                using var command = connection.CreateCommand();
                command.CommandText = "DELETE FROM mailbox_store_public_evidence WHERE scope_hash=$scope AND operation_id=$op;";
                command.Parameters.AddWithValue("$scope", test.Scope.Hash.ToArray()); command.Parameters.AddWithValue("$op", test.Operation);
                Assert.Equal(1, command.ExecuteNonQuery());
            });
            return result;
        }

        internal async Task RestoreOriginalStoreEvidenceForTest(CompletedContactSendCase test, byte[][] row)
        {
            try
            {
                await WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
                {
                    using var command = connection.CreateCommand();
                    command.CommandText = "INSERT INTO mailbox_store_public_evidence(" + string.Join(",", StoreEvidenceColumns) + ") VALUES(" +
                        string.Join(",", StoreEvidenceColumns.Select((_, index) => "$p" + index)) + ");";
                    for (var index = 0; index < row.Length; index++) command.Parameters.AddWithValue("$p" + index, row[index]);
                    Assert.Equal(1, command.ExecuteNonQuery());
                });
            }
            finally { foreach (var bytes in row) CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}
