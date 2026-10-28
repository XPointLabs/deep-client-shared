using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("delete")]
    [InlineData("operation")]
    [InlineData("direction")]
    [InlineData("metadata")]
    [InlineData("route-marker")]
    [InlineData("type")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ActiveArchive_CompleteMapRejectsUnrelatedMutationAndFalseAbsence(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        var stable = await fixture.ReadMessagingFloor(sender);
        await fixture.CompactSenderPrefix(sender, checked((int)stable.Ordinal), default);
        await fixture.WithActiveNativeComparators(sender, (full, active, connection, floor) =>
        {
            using var change = connection.CreateCommand();
            change.CommandText = defect switch
            {
                "delete" => "DELETE FROM events WHERE direction=1;",
                "operation" => "UPDATE events SET operation=randomblob(32) WHERE direction=1;",
                "direction" => "PRAGMA ignore_check_constraints=ON; UPDATE events SET direction=2 WHERE direction=1;",
                "metadata" => "UPDATE events SET metadata=CAST(substr(metadata,1,300)||randomblob(32)||substr(metadata,333) AS BLOB) WHERE direction=1;",
                "route-marker" => "UPDATE events SET metadata=CAST(substr(metadata,1,608)||X'01'||substr(metadata,610) AS BLOB) WHERE direction=1;",
                "type" => "PRAGMA ignore_check_constraints=ON; UPDATE events SET metadata=CAST(metadata AS TEXT) WHERE direction=1;",
                _ => throw new InvalidOperationException()
            };
            Assert.Equal(1, change.ExecuteNonQuery());
            var absent = RandomNumberGenerator.GetBytes(32);
            Assert.ThrowsAny<Exception>(() => active.ReadVerifiedOperation(floor, absent));
            Assert.ThrowsAny<Exception>(() => active.VerifyOrdinaryState());
            Assert.ThrowsAny<Exception>(() => full.VerifyTip());
        });
        Assert.Equal(stable.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ActiveArchive_SemanticTimingIsExplicitAndEverySelectedConsumerStillRejects()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        var stable = await fixture.ReadMessagingFloor(sender);
        await fixture.CompactSenderPrefix(sender, checked((int)stable.Ordinal), default);
        await fixture.WithActiveNativeComparators(sender, (full, active, connection, floor) =>
        {
            var (operation, _, envelope) = ReadActiveOutgoing(connection);
            envelope[^1] ^= 1; // Validly reencrypted SQL substitution, canonical DPE2 shape.
            using (var change = connection.CreateCommand())
            { change.CommandText = "UPDATE events SET envelope=$value WHERE operation=$op;"; change.Parameters.AddWithValue("$value", envelope); change.Parameters.AddWithValue("$op", operation); Assert.Equal(1, change.ExecuteNonQuery()); }
            using var work = Did2MessagingSqlJournal.NativeWork.Measure();
            Assert.Equal(floor.Exact.ToArray(), active.VerifyOrdinaryState().Exact.ToArray());
            Assert.Equal(0, work.Payloads); Assert.True(work.CipherScans > 0);
            Assert.Null(active.ReadVerifiedOperation(floor, RandomNumberGenerator.GetBytes(32)));
            Assert.Throws<CryptographicException>(() => active.ReadVerifiedOperation(floor, operation));
            Assert.Throws<CryptographicException>(() => active.ReadVerifiedOperations(floor, [operation]));
            Assert.Throws<CryptographicException>(() => active.CreateVerifiedTransitionContext(floor, operation, envelope));
            Assert.Throws<CryptographicException>(() => full.VerifyTip());
            // These retained full consumers cannot silently adopt the cheaper
            // map-only semantics: arbitrary content class/Braid/source need them.
            Assert.Throws<CryptographicException>(() => active.ReadVerifiedOutgoingEvents(floor, default).GetEnumerator().MoveNext());
            Assert.Throws<CryptographicException>(() => active.ReadVerifiedIncomingEvents(floor, default).GetEnumerator().MoveNext());
            Assert.Throws<CryptographicException>(() => active.ReadVerifiedActiveInitialEvents(floor));
            Assert.Throws<CryptographicException>(() => active.OpenHistoricalRouteRead(floor));
            Assert.Throws<CryptographicException>(() => active.ReadVerifiedNativeEventDirection(floor, operation));
            Assert.Throws<CryptographicException>(() => active.ReadVerifiedBraidControl(floor, operation));
        });
        Assert.Equal(stable.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ActiveArchive_CapturedTupleRejectsSelfConsistentPostProofSubstitution()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        var stable = await fixture.ReadMessagingFloor(sender);
        await fixture.CompactSenderPrefix(sender, checked((int)stable.Ordinal), default);
        await fixture.CheckArchivePostProofTuple(sender);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ActiveArchive_RuntimeOwnerAuditsOnceAndClosedOwnerCannotReuseScheduling()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        fixture.RetainNativeRuntimes();
        using var work = Did2MessagingSqlJournal.NativeWork.Measure();
        using (var draft = await fixture.CreateOwnedText(sender, "first warm owner frame"))
        using (var sent = await fixture.SendOwnedMessage(sender, draft.OperationId, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span))) { }
        Assert.Equal(1, work.Audits);
        using (var draft = await fixture.CreateOwnedText(sender, "second warm owner frame"))
        using (var sent = await fixture.SendOwnedMessage(sender, draft.OperationId, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span))) { }
        Assert.Equal(1, work.Audits);
        fixture.CloseNativeRuntimes();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => fixture.CreateOwnedText(sender, "closed owner"));
        fixture.DropNativeRuntimes();
        using (var draft = await fixture.CreateOwnedText(sender, "new runtime is cold")) { }
        Assert.Equal(2, work.Audits);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ActiveArchive_WarmProjectionHistoryKeepsFullSelectedNativePayloadValidation()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        fixture.RetainNativeRuntimes();
        Assert.NotEmpty(await fixture.ListOwnedMessages(sender));
        var stable = await fixture.ReadMessagingFloor(sender);
        await fixture.CompactSenderPrefix(sender, checked((int)stable.Ordinal), default);
        await fixture.WithActiveNativeComparators(sender, (_, active, connection, floor) =>
        {
            var (operation, _, envelope) = ReadActiveOutgoing(connection); envelope[^1] ^= 1;
            using var changed = connection.CreateCommand();
            changed.CommandText = "UPDATE events SET envelope=$value WHERE operation=$op;";
            changed.Parameters.AddWithValue("$value", envelope); changed.Parameters.AddWithValue("$op", operation);
            Assert.Equal(1, changed.ExecuteNonQuery());
            Assert.Equal(floor.Exact.ToArray(), active.VerifyOrdinaryState().Exact.ToArray());
        });
        // The application projection is intact and the actual runtime is warm,
        // but its selected native original has a validly reencrypted mismatch.
        // Active-map success cannot authorize releasing that history projection.
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ListOwnedMessages(sender));
        Assert.Equal(stable.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
    }

    [Theory]
    [InlineData("envelope")]
    [InlineData("plaintext")]
    [InlineData("metadata")]
    [InlineData("operation")]
    [InlineData("ratchet")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ActiveArchive_ActualLateRowBoundsRejectBeforePayloadAllocation(string column)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        var stable = await fixture.ReadMessagingFloor(sender);
        await fixture.CompactSenderPrefix(sender, checked((int)stable.Ordinal), default);
        await fixture.CheckArchivePostProofBounds(sender, column);
    }

    [Theory]
    [InlineData("history-missing")]
    [InlineData("history-changed")]
    [InlineData("registration-missing")]
    [InlineData("catalog-changed")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ActiveArchive_FinalSourceCallbackMustRejoinActualProtectedRoots(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (sender, receiver) = await fixture.PrepareActiveNativePair();
        await fixture.CompactActiveNativePrefix(receiver, checked((int)(await fixture.ReadMessagingFloor(receiver)).Ordinal));
        using var draft = await fixture.CreateOwnedText(sender, "late callback protected root guard");
        using var sent = await fixture.SendOwnedMessage(sender, draft.OperationId, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
        var secure = fixture.NativeStorage(receiver);
        var slot = defect.StartsWith("history", StringComparison.Ordinal) ? Did2MessagingHistoryCheckpoint.Slot(receiver) :
            defect == "registration-missing" ? SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot : ProtectedDid2MessagingSessionCatalog.Slot;
        using var original = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
        var originalBytes = original.Use(bytes => bytes.ToArray());
        var reachedCallback = false;
        var mutationApplied = false;
        using var observations = new DeliveryEventListener();
        using (DirectDmc2InboxTestHooks.Push(point =>
        {
            if (point != DirectDmc2InboxFaultPoint.AfterCommit) return;
            fixture.afterNativeClockRead = () =>
            {
                reachedCallback = true;
                if (defect.EndsWith("missing", StringComparison.Ordinal))
                {
                    secure.DeleteBatchAsync([slot]).GetAwaiter().GetResult();
                    using var missing = secure.ReadOwnedAsync(slot).GetAwaiter().GetResult(); Assert.Null(missing);
                }
                else
                {
                    var changed = originalBytes.ToArray(); changed[defect == "history-changed" ? 264 : changed.Length - 1] ^= 1;
                    Assert.True(secure.CompareExchangeAsync(slot, originalBytes, changed).GetAwaiter().GetResult());
                    CryptographicOperations.ZeroMemory(changed);
                }
                mutationApplied = true;
            };
        }))
        {
            var failure = await Record.ExceptionAsync(() => fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()));
            Assert.True(failure is InvalidDataException or CryptographicException, failure?.GetType().Name ?? "No rejection");
        }
        Assert.True(reachedCallback); Assert.True(mutationApplied); Assert.Empty(observations.Events);
        using (var current = await secure.ReadOwnedAsync(slot))
        {
            if (current is null) await secure.WriteBatchAsync([new(slot, originalBytes)]);
            else Assert.True(await secure.CompareExchangeAsync(slot, current.Use(bytes => bytes.ToArray()), originalBytes));
        }
        CryptographicOperations.ZeroMemory(originalBytes);
        using (var exactRetry = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray())) { }
        Assert.Empty(observations.Events); // Already materialized receive is never observed as new on retry.
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ActiveArchive_RealFreshTransitionTriggersOneBoundedBatchAndWarmRetryRecoversIt()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, receiver) = await fixture.PrepareActiveNativePair();
        fixture.RetainNativeRuntimes();
        byte[]? earliestOperation = null, earliestExact = null, earliestDmc = null;
        // Real bidirectional crypto maintains the Braid. No fabricated ordinal,
        // occupancy, compaction capability or lowered production threshold.
        while ((await fixture.ReadMessagingFloor(sender)).Ordinal - (await fixture.ReadNativeArchive(sender)).Basis.Ordinal < 62)
        {
            foreach (var scope in new[] { sender, receiver })
            {
                using var draft = await fixture.CreateOwnedText(scope, "native threshold feedback");
                using var sent = await fixture.SendOwnedMessage(scope, draft.OperationId, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
                if (scope.IsInitiator && earliestOperation is null)
                { earliestOperation = draft.OperationId.ToArray(); earliestDmc = draft.ExactDmc2.ToArray(); earliestExact = sent.ExactEnvelope.ToArray(); }
                using var received = await fixture.ReceiveOwnedMessage(scope.IsInitiator ? receiver : sender, sent.ExactEnvelope.ToArray());
            }
        }
        using (var softLimit = await fixture.CreateOwnedText(sender, "exact indexed soft-limit transition"))
        using (var sent = await fixture.SendOwnedMessage(sender, softLimit.OperationId, ApplicationCoreCodec.DecodeDmc2(softLimit.ExactDmc2.Span)))
        using (var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray())) { }
        var before = await fixture.ReadMessagingFloor(sender);
        var historyBefore = await fixture.ReadNativeHistory(sender);
        var archiveBefore = await fixture.ReadNativeArchive(sender);
        Assert.Equal(63UL, before.Ordinal - archiveBefore.Basis.Ordinal);
        Assert.Equal(0UL, historyBefore.HistoryCount);
        using var next = await fixture.CreateOwnedText(sender, "threshold owned transition");
        // Exact replay and malformed receive must not stage maintenance.
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        using (var original = await fixture.SendOwnedMessage(sender, earliestOperation!, ApplicationCoreCodec.DecodeDmc2(earliestDmc!)))
        { Assert.Equal(earliestExact, original.ExactEnvelope.ToArray()); Assert.Equal(0, work.MaintenanceBatches); }
        using (var peerDraft = await fixture.CreateOwnedText(receiver, "bad receive must not checkpoint"))
        using (var peerSend = await fixture.SendOwnedMessage(receiver, peerDraft.OperationId, ApplicationCoreCodec.DecodeDmc2(peerDraft.ExactDmc2.Span)))
        {
            var malformed = peerSend.ExactEnvelope.ToArray(); malformed[^1] ^= 1;
            using var work = Did2MessagingSqlJournal.NativeWork.Measure();
            var rejected = await Assert.ThrowsAnyAsync<CryptographicException>(() => fixture.ReceiveOwnedMessage(sender, malformed));
            Assert.Equal("Deep.Protocol.MessagingCrypto.MessagingCryptoException", rejected.GetType().FullName);
            Assert.IsType<CryptographicException>(rejected.InnerException);
            Assert.Equal(0, work.MaintenanceBatches);
            Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        }
        var hit = false;
        using (Did2CompactionTestHooks.Push(point => { if (point == Did2CompactionFailpoint.AfterStage) { hit = true; throw new IOException("Threshold batch interrupted."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.SendOwnedMessage(sender, next.OperationId, ApplicationCoreCodec.DecodeDmc2(next.ExactDmc2.Span)));
        Assert.True(hit); Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        using (var sent = await fixture.SendOwnedMessage(sender, next.OperationId, ApplicationCoreCodec.DecodeDmc2(next.ExactDmc2.Span)))
        {
            Assert.Equal(1, work.MaintenanceBatches); // Original pending batch completed; no second selection.
            using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray());
        }
        var after = await fixture.ReadNativeArchive(sender);
        Assert.Equal(archiveBefore.Basis.Ordinal + 32, after.Basis.Ordinal);
        Assert.True(after.ArchiveCount > 0); Assert.Equal(before.Ordinal + 1, (await fixture.ReadMessagingFloor(sender)).Ordinal);
        var immutableSource = await fixture.ReadNativeHistory(sender);
        Assert.True(historyBefore.Exact.Span.SequenceEqual(immutableSource.Exact.Span), "Indexed maintenance changed immutable source history.");
        using (var original = await fixture.SendOwnedMessage(sender, earliestOperation!, ApplicationCoreCodec.DecodeDmc2(earliestDmc!)))
            Assert.Equal(earliestExact, original.ExactEnvelope.ToArray());
        await fixture.AssertSenderCompactionIdle(sender);
        Assert.NotEmpty(await fixture.ListOwnedReceiptObligations(sender)); // Receipt originals are not retired by native checkpointing.
    }

    private static (byte[] Operation, byte[] Metadata, byte[] Envelope) ReadActiveOutgoing(SqliteConnection connection)
    {
        using var command = connection.CreateCommand(); command.CommandText = "SELECT operation,metadata,envelope FROM events WHERE direction=1 ORDER BY ordinal LIMIT 1;";
        using var row = command.ExecuteReader(); Assert.True(row.Read());
        return (row.GetFieldValue<byte[]>(0), row.GetFieldValue<byte[]>(1), row.GetFieldValue<byte[]>(2));
    }

    private sealed partial class Fixture
    {
        internal Action? afterNativeClockRead;
        private bool retainNativeRuntime;
        private readonly Dictionary<bool, (DeepIdV2AccountService Account, DeepIdV2ContactPathAuthoritySource Source)> nativeRuntimes = [];
        internal void RetainNativeRuntimes() => retainNativeRuntime = true;
        internal void CloseNativeRuntimes() { foreach (var runtime in nativeRuntimes.Values) runtime.Account.Dispose(); }
        internal void DropNativeRuntimes() { CloseNativeRuntimes(); nativeRuntimes.Clear(); }
        internal Task<Did2MessagingHistoryCheckpoint> ReadNativeHistory(Did2MessagingSessionScope scope) =>
            Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage, scope, default);
        internal async Task<Did2MessagingArchiveRoot> ReadNativeArchive(Did2MessagingSessionScope scope)
        {
            using var value = await NativeStorage(scope).ReadOwnedAsync(Did2MessagingArchiveRoot.Slot(scope)) ?? throw new InvalidDataException();
            return value.Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
        }
        internal IDeepSecureStorage NativeStorage(Did2MessagingSessionScope scope) => scope.IsInitiator ? storage : peerStorage;
        internal Task CompactActiveNativePrefix(Did2MessagingSessionScope scope, int rows)
        {
            var privateDirectory = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var nativeOwner = new ProtectedDeepIdV2AccountOwner(NativeStorage(scope),
                new DeepIdV2AccountFileLease(Path.Combine(privateDirectory, "deep-store-v2-account.lock")),
                Path.Combine(privateDirectory, "deep-store-v2-account.dsv2"), Network, 1);
            return nativeOwner.CompactOwnedMessagingPrefixAsync(1_000, pq, scope, rows, default);
        }

        internal async Task<(Did2MessagingSessionScope Sender, Did2MessagingSessionScope Receiver)> PrepareActiveNativePair()
        {
            var (complete, hello, init, _, _) = await PrepareNativeHelloCompletion(Bytes(32, 0xe1));
            using var initial = await complete(Accounts);
            using (var received = await CompleteReceiver(initial.ExactDph2.ToArray())) { }
            var sender = await EnsureSenderMessaging(init, hello);
            var receiver = await EnsureReceiverMessaging(initial.ExactDph2.ToArray());
            using (var accept = await PrepareOwnedContactAccept(receiver, Bytes(32, 0xe2)))
            using (var sent = await SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
            using (var received = await ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
            using (var draft = await CreateOwnedText(sender, "initial outgoing native archive"))
            using (var sent = await SendOwnedMessage(sender, draft.OperationId, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span)))
            using (var received = await ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray())) { }
            return (sender, receiver);
        }

        internal async Task WithActiveNativeComparators(Did2MessagingSessionScope scope,
            Action<Did2MessagingSqlJournal, Did2MessagingSqlJournal, SqliteConnection, Did2MessagingFloor> inspect)
        {
            var history = await ReadNativeHistory(scope); var floor = await ReadMessagingFloor(scope);
            using var root = await NativeStorage(scope).ReadOwnedAsync(Did2MessagingArchiveRoot.Slot(scope)) ?? throw new InvalidDataException();
            var archive = root.Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
            await WithRouteReadSql(scope, (full, connection) =>
                inspect(full, Did2MessagingSqlJournal.ForOrdinaryRuntime(connection, scope, history, archive), connection, floor));
        }
    }
}
