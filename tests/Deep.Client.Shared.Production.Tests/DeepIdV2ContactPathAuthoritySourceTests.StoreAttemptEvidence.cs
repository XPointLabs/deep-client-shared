using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoreAttemptEvidence_CachedOwnerRejectsNativeRebindingAndUnlinkedSqlCandidates(bool initial)
    {
        // Actual two-account PQ/SQLCipher and signed Store. Only disposable
        // fixture SQL is corrupted/restored; this is not physical transport.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        var stored = await fixture.DeliverCompletedCaseWithExactRetry(test);
        var ingressCalls = test.Transport.Calls; var issuerCalls = test.Grants.Calls;
        var native = SHA256.HashData((await fixture.ReadMessagingFloor(test.Scope)).Exact.Span);
        var retained = await fixture.ReadCompletedContactSendRetainedRoots(test.Scope);
        var secure = fixture.CompletedContactSendStorage(initial);
        using var sendRoot = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        var sendDigest = sendRoot.Use(bytes => SHA256.HashData(bytes));
        object[] original = [];
        await fixture.WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
        {
            using var read = connection.CreateCommand();
            read.CommandText = "SELECT * FROM mailbox_store_public_evidence;";
            using var reader = read.ExecuteReader(); Assert.True(reader.Read());
            original = new object[reader.FieldCount]; reader.GetValues(original);
            Assert.Equal(13, original.Length); Assert.False(reader.Read());
        });
        try
        {
            foreach (var mutation in new[] { "native", "attempt", "append" })
            {
                await fixture.WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
                {
                    using var change = connection.CreateCommand();
                    if (mutation == "append")
                    {
                        // Canonical bounded public records cannot grant ownership
                        // of a second attempt absent from the protected chain.
                        change.CommandText = "INSERT INTO mailbox_store_public_evidence VALUES(" +
                            string.Join(",", Enumerable.Range(0, original.Length).Select(index => "$v" + index)) + ");";
                        for (var index = 0; index < original.Length; index++)
                            change.Parameters.AddWithValue("$v" + index, index == 2 ? Bytes(32, 0x59) :
                                index == 4 ? Bytes(16, 0x5a) : original[index]);
                    }
                    else
                    {
                        change.CommandText = "UPDATE mailbox_store_public_evidence SET " +
                            (mutation == "native" ? "native_operation_id" : "attempt_id") + "=$changed WHERE attempt_id=$op;";
                        change.Parameters.AddWithValue("$changed", Bytes(32, 0x59));
                        change.Parameters.AddWithValue("$op", original[2]);
                    }
                    Assert.Equal(1, change.ExecuteNonQuery());
                });
                var application = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
                try
                {
                    await Assert.ThrowsAsync<CryptographicException>(test.Deliver);
                    Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
                    Assert.Equal(native, SHA256.HashData((await fixture.ReadMessagingFloor(test.Scope)).Exact.Span));
                    Assert.Equal(retained, await fixture.ReadCompletedContactSendRetainedRoots(test.Scope));
                    using var actual = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                    Assert.Equal(sendDigest, actual.Use(bytes => SHA256.HashData(bytes)));
                    Assert.Equal(ingressCalls, test.Transport.Calls); Assert.Equal(issuerCalls, test.Grants.Calls);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(application);
                    await fixture.WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
                    {
                        using var tx = connection.BeginTransaction();
                        using var remove = connection.CreateCommand(); remove.Transaction = tx;
                        remove.CommandText = "DELETE FROM mailbox_store_public_evidence WHERE scope_hash=$scope;";
                        remove.Parameters.AddWithValue("$scope", original[0]); remove.ExecuteNonQuery();
                        using var restore = connection.CreateCommand(); restore.Transaction = tx;
                        restore.CommandText = "INSERT INTO mailbox_store_public_evidence VALUES(" +
                            string.Join(",", Enumerable.Range(0, original.Length).Select(index => "$v" + index)) + ");";
                        for (var index = 0; index < original.Length; index++) restore.Parameters.AddWithValue("$v" + index, original[index]);
                        Assert.Equal(1, restore.ExecuteNonQuery()); tx.Commit();
                    });
                }
            }
            if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
            var cached = await test.Deliver();
            Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
            Assert.Equal(stored.Disposition, cached.Disposition);
            Assert.Equal(ingressCalls, test.Transport.Calls); Assert.Equal(issuerCalls, test.Grants.Calls);
        }
        finally
        {
            foreach (var bytes in original.OfType<byte[]>().Concat([native, retained, sendDigest, test.Operation, test.Intent]))
                CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [Fact]
    public async Task Did2StoreAttemptEvidence_DistinctAttemptsKeepOriginalRecordsAndRejectNativeRebinding()
    {
        // Actual SQLCipher and canonical signed fixture records. These rows
        // alone are NOT verified Store, attempt-creation or dispatch authority.
        await using var fixture = await Fixture.CreateAsync();
        var plan = await fixture.Accounts.ReadOwnPermanentContactPlanAsync();
        using var threshold = new OwnedRouteThreshold(fixture);
        var route = await fixture.EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
        var replicas = await MailboxStoreReplicaEvidenceVerifier.CaptureAsync(route);
        var current = await fixture.Source().VerifyForOwnPreKeyAuthoringAsync(fixture.Accounts, default);
        var pma = current.MailboxAuthority.ExactPma2;
        // No empty original route or partial Initial package is accepted by
        // the current-only evidence row. Canonical routes remain metadata,
        // not native ownership or a signed Store result by themselves.
        Assert.Throws<ArgumentException>(() => new Did2StorePublicEvidence(Bytes(32, 0x44), Bytes(16, 0x45), pma, replicas));
        Assert.Throws<ArgumentException>(() => new Did2StorePublicEvidence(Bytes(32, 0x44), Bytes(16, 0x45), pma, replicas,
            originalDcr: new byte[1], originalRoute: route.ExactRouteClosure));
        Assert.Throws<ArgumentException>(() => new Did2StorePublicEvidence(Bytes(32, 0x44), Bytes(16, 0x45), pma, replicas,
            originalRoute: route.ExactRouteClosure, originalPeerAdp: new byte[1]));
        var malformed = route.ExactRouteClosure.ToArray(); malformed[0] ^= 1;
        Assert.Throws<ContactFormatException>(() => new Did2StorePublicEvidence(Bytes(32, 0x44), Bytes(16, 0x45), pma, replicas,
            originalRoute: malformed));
        CryptographicOperations.ZeroMemory(malformed);
        foreach (var length in new[] { 31, 33 })
            Assert.Throws<ArgumentException>(() => new Did2StorePublicEvidence(Bytes(32, 0x44), Bytes(16, 0x45), pma, replicas,
                originalRoute: route.ExactRouteClosure, evidenceCommitment: new byte[length]));
        var scopeBytes = Bytes(Did2MessagingSessionScope.Bytes, 0x30);
        scopeBytes[0] = scopeBytes[1] = 1; scopeBytes[2] = scopeBytes[3] = 0;
        scopeBytes[132] = 0x31; scopeBytes[172] = 0x32;
        var scope = Did2MessagingSessionScope.RestoreMetadata(scopeBytes);
        var native = Bytes(32, 0x41); var successor = Bytes(32, 0x42); var otherNative = Bytes(32, 0x43);
        var original = new Did2StorePublicEvidence(Bytes(32, 0x44), Bytes(16, 0x45), pma, replicas, originalRoute: route.ExactRouteClosure);
        var later = new Did2StorePublicEvidence(Bytes(32, 0x47), Bytes(16, 0x48), pma, replicas, originalRoute: route.ExactRouteClosure);
        var directory = Path.Combine(Path.GetTempPath(), "deep-store-attempt-evidence-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var key = RandomNumberGenerator.GetBytes(32);
        var options = new SqliteDeepMailboxStoreOptions(Path.Combine(directory, "probe.db"), key);
        try
        {
            using (var store = new SqliteDeepMailboxStore(options))
            {
                await store.RecordStorePublicEvidenceAsync(scope, native, native, original, default);
                await store.RecordStorePublicEvidenceAsync(scope, native, successor, later, default);
                await store.RecordStorePublicEvidenceAsync(scope, native, native, original, default);
                await Assert.ThrowsAsync<CryptographicException>(() =>
                    store.RecordStorePublicEvidenceAsync(scope, otherNative, native, original, default));
                await Assert.ThrowsAsync<CryptographicException>(() =>
                    store.RecordStorePublicEvidenceAsync(scope, native, native, later, default));
                await Assert.ThrowsAsync<CryptographicException>(() =>
                    store.RequireStorePublicEvidenceAsync(scope, otherNative, successor, default));
                await Assert.ThrowsAsync<ArgumentException>(() =>
                    store.RecordStorePublicEvidenceAsync(scope, native, new byte[32], original, default));
                await Assert.ThrowsAsync<SqliteException>(() =>
                    store.RecordStorePublicEvidenceAsync(scope, native, Bytes(32, 0x50), original, default));
                Assert.Null(await store.ReadDurableStorePublicEvidenceAsync(scope, native, successor, later.Logical, default));
            }
            using var reopened = SqliteDeepMailboxStore.OpenExisting(options);
            RequireSame(original, await reopened.RequireStorePublicEvidenceAsync(scope, native, native, default));
            RequireSame(later, await reopened.RequireStorePublicEvidenceAsync(scope, native, successor, default));
            var candidates = await reopened.ReadStoreAttemptCandidatesAsync(scope, native, default);
            try
            {
                Assert.Equal(2, candidates.Length);
                Assert.Equal(native, candidates[0]); Assert.Equal(successor, candidates[1]);
            }
            finally { foreach (var bytes in candidates) CryptographicOperations.ZeroMemory(bytes); }
            Assert.Empty(await reopened.ReadStoreAttemptCandidatesAsync(scope, otherNative, default));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(scopeBytes);
            Directory.Delete(directory, recursive: true);
        }

        static void RequireSame(Did2StorePublicEvidence expected, Did2StorePublicEvidence actual)
        {
            var before = expected.CopyRecords(); var after = actual.CopyRecords();
            try { Assert.Equal(before.Length, after.Length); for (var i = 0; i < before.Length; i++) Assert.Equal(before[i], after[i]); }
            finally { foreach (var bytes in before.Concat(after)) CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}
