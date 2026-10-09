using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CompletedContactSend_OriginalStoreColdHandoversKeepCountersAndAllOtherCustody(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        var stored = await test.Deliver();
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        var secure = fixture.CompletedContactSendStorage(initial);
        using var raw = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        var original = raw.Use(bytes => bytes.ToArray());
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var heldRoots = await fixture.ReadCompletedContactSendRetainedRoots(test.Scope);
        var sourceSql = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        var points = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSqlRecorded,
            Did2CompactionFailpoint.AfterHistoryAdopted, Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
        for (var index = 0; index < points.Length; index++)
        {
            if (index != 0)
            {
                // Reinsert only the exact completed disposable fixture entry
                // to exercise each boundary with the same one-time real Store.
                using var retired = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                Assert.True(await secure.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, retired.Use(bytes => bytes.ToArray()), original));
            }
            using (Did2CompactionTestHooks.Push(point => { if (point == points[index]) throw new IOException("Injected completed contact-send handover."); }))
                await Assert.ThrowsAsync<IOException>(() => fixture.RetireCompletedContactSend(test));
            if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
            var owner = fixture.CompletedContactSendRecoveryOwner(initial);
            if (index == 0)
            {
                using var planBefore = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                await fixture.WithCompletedContactSourceSql(test.Scope, sql =>
                {
                    using var mutate = sql.CreateCommand(); mutate.CommandText = "UPDATE device_store_meta SET account_generation=X'0000000000000002';";
                    Assert.Equal(1, mutate.ExecuteNonQuery());
                });
                var error = await Record.ExceptionAsync(() => owner.ResumeOwnedLocalCompactionAsync(default));
                Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().Name ?? "Unexpected successful recovery");
                using var planAfter = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                using var sendAfter = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(planBefore.Use(bytes => bytes.ToArray()), planAfter.Use(bytes => bytes.ToArray()));
                Assert.Equal(original, sendAfter.Use(bytes => bytes.ToArray()));
                await fixture.WithCompletedContactSourceSql(test.Scope, sql =>
                {
                    using var read = sql.CreateCommand(); read.CommandText = "SELECT account_generation FROM device_store_meta;";
                    Assert.Equal(new byte[] { 0, 0, 0, 0, 0, 0, 0, 2 }, (byte[])read.ExecuteScalar()!);
                    using var restore = sql.CreateCommand(); restore.CommandText = "UPDATE device_store_meta SET account_generation=X'0000000000000001';";
                    Assert.Equal(1, restore.ExecuteNonQuery());
                });
                if (!initial) await fixture.AssertCompletedContactResponderMutationPinsPlan(test, owner, original);
            }
            await owner.ResumeOwnedLocalCompactionAsync(default);
            using (var sends = await fixture.ReadMailboxSends(own: initial))
            { Assert.Empty(sends.Entries); Assert.Equal(1UL, Assert.Single(sends.Floors).Value.HighestCounter); }
            Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(heldRoots, await fixture.ReadCompletedContactSendRetainedRoots(test.Scope));
            Assert.Equal(sourceSql, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
            var cached = await test.Deliver();
            Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor); Assert.Equal(stored.Disposition, cached.Disposition);
            using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            Assert.Equal(0, plan.Use(bytes => bytes[1]));
        }
        await fixture.RetireCompletedContactSend(test); // Independently verified already-retired is idempotent.
        await fixture.AssertCompactedStoreRejectsChangedPublicEvidence(test.Scope, () => fixture.RetireCompletedContactSend(test));
        Assert.Equal(1, test.Grants.Calls); Assert.Equal(1, test.Transport.Calls);
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        foreach (var bytes in new[] { original, application, native, heldRoots, sourceSql, test.Operation, test.Intent }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CompletedContactSend_LostReplyPinsExactWorkWithoutStagingOrReissuing(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        test.Transport.LoseReply = true;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        var secure = fixture.CompletedContactSendStorage(initial);
        using var sendsBefore = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        using var planBefore = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        await Assert.ThrowsAsync<IOException>(() => fixture.RetireCompletedContactSend(test));
        using var sendsAfter = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        using var planAfter = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
        Assert.Equal(sendsBefore.Use(bytes => bytes.ToArray()), sendsAfter.Use(bytes => bytes.ToArray()));
        Assert.Equal(planBefore.Use(bytes => bytes.ToArray()), planAfter.Use(bytes => bytes.ToArray()));
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
    }

    private sealed partial class Fixture
    {
        internal IDeepSecureStorage CompletedContactSendStorage(bool own) => own ? storage : peerStorage;
        internal ProtectedDeepIdV2AccountOwner CompletedContactSendRecoveryOwner(bool own) => own ? SenderCompactionOwner() : PeerRetirementOwner();
        internal sealed record CompletedContactSendCase(Did2MessagingSessionScope Scope, byte[] Operation, byte[] Intent,
            OwnedGrantTransport Grants, OwnedStoreFixture Transport, Func<Task<ClientMailboxStoreResult>> Deliver);

        internal async Task<CompletedContactSendCase> PrepareCompletedContactSendCase(bool isInitial)
        {
            var intent = Bytes(32, 0x61);
            var (complete, hello, init, _, _) = await PrepareNativeHelloCompletion(intent);
            using var initial = await complete(accounts);
            if (!isInitial) using (var received = await CompleteReceiver(initial.ExactDph2.ToArray())) { }
            var sender = await EnsureSenderMessaging(init, hello);
            var scope = isInitial ? sender : await EnsureReceiverMessaging(initial.ExactDph2.ToArray());
            byte[] operation, envelope;
            if (isInitial) { operation = ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent); envelope = initial.ExactDph2.ToArray(); }
            else
            {
                using var accept = await PrepareOwnedContactAccept(scope, Bytes(32, 0x62)); operation = accept.Operation.ToArray();
                using var sent = await SendOwnedMessage(scope, operation, ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2));
                envelope = sent.ExactEnvelope.ToArray(); intent = [];
            }
            TrackMailboxDispatchClock();
            var grants = new OwnedGrantTransport(this, ownerOnPrimary: isInitial);
            var transport = new OwnedStoreFixture(this, isInitial ? null : scope, operation, envelope);
            return new(scope, operation, intent, grants, transport, () => isInitial ? DeliverNativeInitial(intent, grants, transport) : DeliverNativeMessage(scope, operation, grants, transport));
        }

        internal Task RetireCompletedContactSend(CompletedContactSendCase test)
        {
            var account = test.Scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = test.Scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            return account.RetireOwnCompletedContactMailboxSendAsync(test.Scope, test.Operation, test.Intent, source);
        }

        internal async Task<byte[]> ReadCompletedContactSendRetainedRoots(Did2MessagingSessionScope scope)
        {
            var secure = scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage;
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var slot in new[] { ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxGrantJournal.Slot,
                ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot,
                SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, ProtectedDid2ContactStartJournal.Slot,
                ProtectedDid2ContactAcceptJournal.Slot, ProtectedInitialKeyRetirementJournal.Slot, ProtectedDph2PreClaimJournal.Slot })
            { using var raw = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); raw.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; }); }
            return hash.GetHashAndReset();
        }

        internal async Task<byte[]> ReadCompletedContactSendSourceProjection(Did2MessagingSessionScope scope)
        {
            var accountDirectory = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var secure = scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage;
            var lease = new DeepIdV2AccountFileLease(Path.Combine(accountDirectory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            var path = Path.Combine(accountDirectory, "deep-store-v2-account.dsv2");
            var device = await SqliteDeepIdV2AccountGeneration.ReadExistingDeviceSourceProjectionUnderLeaseAsync(secure,
                path, scope.Network.ToArray(), scope.LocalAccount.ToArray(), scope.Instance.ToArray(), held, lease, default);
            var responder = await SqliteDeepIdV2AccountGeneration.ReadExistingPreKeySourceReadbackUnderLeaseAsync(secure,
                path, scope.Network.ToArray(), scope.LocalAccount.ToArray(), scope.Instance.ToArray(), held, lease, default);
            try
            {
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                hash.AppendData(device); hash.AppendData(responder); return hash.GetHashAndReset();
            }
            finally { CryptographicOperations.ZeroMemory(device); CryptographicOperations.ZeroMemory(responder); }
        }

        internal async Task AssertCompletedContactResponderMutationPinsPlan(CompletedContactSendCase test,
            ProtectedDeepIdV2AccountOwner owner, byte[] originalSend)
        {
            var path = Path.Combine(directory, "peer", "deep-store-v2-account.dsv2.prekeys.pkv2");
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "peer", "deep-store-v2-account.lock"));
            byte[] exactCiphertext;
            using (var held = await lease.AcquireAsync(default))
            {
                exactCiphertext = await File.ReadAllBytesAsync(path);
                await using var sql = await OpenPeerPreKeySqlAsync();
                using var mutate = sql.CreateCommand();
                mutate.CommandText = "UPDATE receiver_sessions SET record_hash=zeroblob(32);";
                Assert.Equal(1, mutate.ExecuteNonQuery());
            }
            try
            {
                using var planBefore = await peerStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                var error = await Record.ExceptionAsync(() => owner.ResumeOwnedLocalCompactionAsync(default));
                Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().Name ?? "Unexpected successful recovery");
                using var planAfter = await peerStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                using var sendAfter = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(planBefore.Use(bytes => bytes.ToArray()), planAfter.Use(bytes => bytes.ToArray()));
                Assert.Equal(originalSend, sendAfter.Use(bytes => bytes.ToArray()));
                using var held = await lease.AcquireAsync(default);
                await using (var sql = await OpenPeerPreKeySqlAsync())
                {
                    using var read = sql.CreateCommand(); read.CommandText = "SELECT record_hash FROM receiver_sessions;";
                    Assert.Equal(new byte[32], (byte[])read.ExecuteScalar()!);
                }
                // Disposable fixture only: restore exact ciphertext, not a
                // logical rewrite that would still change the guarded source.
                await File.WriteAllBytesAsync(path, exactCiphertext);
            }
            finally { CryptographicOperations.ZeroMemory(exactCiphertext); }
        }

        internal async Task WithCompletedContactSourceSql(Did2MessagingSessionScope scope, Action<SqliteConnection> change)
        {
            var accountDirectory = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var secure = scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage;
            using var held = await new DeepIdV2AccountFileLease(Path.Combine(accountDirectory, "deep-store-v2-account.lock")).AcquireAsync(default);
            using var raw = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(secure,
                scope.Network.ToArray(), scope.LocalAccount.ToArray(), default);
            var key = raw.Use(record =>
            {
                var domain = "Deep/STORE-V2/device-state-key"u8; var transcript = new byte[domain.Length + 80];
                domain.CopyTo(transcript); record.Slice(8, 48).CopyTo(transcript.AsSpan(domain.Length)); record.Slice(56, 32).CopyTo(transcript.AsSpan(domain.Length + 48));
                try { return HMACSHA256.HashData(record.Slice(88, 32), transcript); }
                finally { CryptographicOperations.ZeroMemory(transcript); }
            });
            try
            {
                using var sql = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = Path.Combine(accountDirectory, "deep-store-v2-account.dsv2.devices.dvs1"), Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
                sql.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(sql.Handle, key)); change(sql); held.RequireActive();
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        }
    }
}
