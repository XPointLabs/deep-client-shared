using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_RetiredAttachmentOfferPreservesIndependentHistoryAndNextAuthor()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        var assetOperation = Bytes(32, 0xa9);
        var content = System.Text.Encoding.UTF8.GetBytes("Retained attachment history after sender cancellation");
        using var asset = await fixture.PrepareOwnedAsset(sender, assetOperation, content, "retained.txt", "text/plain", 1400);
        using var offer = await fixture.CreateOwnedAttachmentOffer(sender, assetOperation);
        var offerOperation = offer.OperationId.ToArray();
        var message = Deep.Protocol.ApplicationCore.ApplicationCoreCodec.DecodeDmc2(offer.ExactDmc2.Span);
        using var manifest = Assert.IsType<Deep.Protocol.ApplicationCore.AttachmentOfferDmc2Payload>(message.ParsedPayload).Manifest;
        byte[] ciphertext;
        using (var sent = await fixture.SendOwnedMessage(sender, offerOperation, message)) ciphertext = sent.ExactEnvelope.ToArray();
        using var expected = await fixture.ExpectedStoppedPayloadSqlSuccessor(sender, offerOperation);
        using var capture = expected.Observe();
        var before = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        await fixture.CancelNativeMessagingWork(sender, offerOperation);
        fixture.ColdReopenCompactionStorage();
        Assert.Equal(expected.After, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(before, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        await fixture.RequireRetiredStoppedPayload(sender, offerOperation);
        using (var received = await fixture.ReceiveOwnedMessage(receiver, ciphertext))
        using (var authenticated = received.OwnAuthenticatedDmc2())
        {
            var parsed = authenticated.Use(bytes => Deep.Protocol.ApplicationCore.ApplicationCoreCodec.DecodeDmc2(bytes));
            using var retainedManifest = Assert.IsType<Deep.Protocol.ApplicationCore.AttachmentOfferDmc2Payload>(parsed.ParsedPayload).Manifest;
            Assert.Equal(manifest.CanonicalBytes.ToArray(), retainedManifest.CanonicalBytes.ToArray());
            var chunk = asset.CopyCiphertext(0);
            var opened = Deep.Protocol.ApplicationCore.AttachmentChunkCipher.Decrypt(retainedManifest, 0, chunk);
            try { Assert.Equal(content, opened); }
            finally { CryptographicOperations.ZeroMemory(chunk); CryptographicOperations.ZeroMemory(opened); }
        }
        using var next = await fixture.CreateOwnedText(sender, "Independent next author after cancelled offer");
        var nextOperation = next.OperationId.ToArray();
        Assert.Equal(offer.SenderSequence + 1, next.SenderSequence);
        using var nextSend = await fixture.SendOwnedMessage(sender, nextOperation,
            Deep.Protocol.ApplicationCore.ApplicationCoreCodec.DecodeDmc2(next.ExactDmc2.Span));
        using var nextReceived = await fixture.ReceiveOwnedMessage(receiver, nextSend.ExactEnvelope.ToArray());
        foreach (var value in new[] { content, ciphertext, before }) CryptographicOperations.ZeroMemory(value);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_CachedOriginalStoreCompletesInterruptedMarkerAfterPayloadRetirement()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary"); var hit = false;
        using (Did2MailboxSendTestHooks.Push(point =>
        { if (point == Did2MailboxSendFailpoint.BeforeOrdinaryCompletion) { hit = true; throw new IOException("Interrupted actual Store marker."); } }))
        {
            var outcome = await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
            Assert.IsType<IOException>(outcome.InnerException);
        }
        Assert.True(hit);
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        fixture.ColdReopenCompactionStorage();
        var cached = await test.Deliver(); Assert.False(cached.IngressDispatched);
        fixture.ColdReopenCompactionStorage();
        var replay = await test.Deliver(); Assert.Equal(cached.Cursor, replay.Cursor); Assert.False(replay.IngressDispatched);
        await fixture.RequireRetiredStoppedPayload(test.Scope, test.Operation);
        Assert.Equal(1, test.Grants.Calls); Assert.Equal(1, test.Transport.Calls);
    }
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_RetiredRouteControlKeepsActualAdvertisedHistoryForSuccessor()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1000, successorAdvertisementLifetimeSeconds: 2000);
        byte[] operation, first;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            operation = command.OperationId.ToArray();
            using var sent = await fixture.SendOwnedRouteUpdate(sender, operation);
            first = sent.ExactEnvelope.ToArray();
        }
        var before = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        using var sql = await fixture.ExpectedStoppedPayloadSqlSuccessor(sender, operation);
        using var capture = sql.Observe();
        await fixture.CancelNativeMessagingWork(sender, operation);
        fixture.ColdReopenCompactionStorage();
        await fixture.RequireRetiredStoppedPayload(sender, operation);
        Assert.Equal(before, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(sql.After, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        // Cancellation is not recall: the exact already-authored control can
        // independently authenticate at the peer, without sender re-dispatch.
        using (var received = await fixture.ReceiveOwnedMessage(receiver, first)) Assert.Equal(1, received.RouteProcessing[0]);
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1000, proactive: true);
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            var successor = command.OperationId.ToArray();
            var control = Assert.IsType<Deep.Protocol.ApplicationCore.ContactRouteUpdateDmc2Payload>(
                Deep.Protocol.ApplicationCore.ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ParsedPayload);
            Assert.Equal(2UL, control.RouteGeneration);
            using var sent = await fixture.SendOwnedRouteUpdate(sender, successor);
            using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray());
            Assert.Equal(1, received.RouteProcessing[0]);
        }
        foreach (var value in new[] { first, before }) CryptographicOperations.ZeroMemory(value);
    }
    [Theory]
    [InlineData("AfterStage", false)] [InlineData("AfterSql", false)]
    [InlineData("AfterSqlRecorded", false)] [InlineData("AfterHistoryAdopted", false)]
    [InlineData("AfterPartsDeleted", false)] [InlineData("AfterPlanCleared", false)]
    [InlineData("AfterStage", true)] [InlineData("AfterSql", true)]
    [InlineData("AfterSqlRecorded", true)] [InlineData("AfterHistoryAdopted", true)]
    [InlineData("AfterPartsDeleted", true)] [InlineData("AfterPlanCleared", true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_PayloadCleanupColdRecoversExactSqlAndPreservesUnknown(string interruption, bool cancel)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        test.Transport.LoseReply = true;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        using var expectedSql = await fixture.ExpectedStoppedPayloadSqlSuccessor(test.Scope, test.Operation);
        using var capture = expectedSql.Observe();
        var originalSend = await fixture.ReadSendRootForStoppedWork();
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        using var cancellation = new CancellationTokenSource(); var hit = false;
        var selected = Enum.Parse<Did2CompactionFailpoint>(interruption);
        using (Did2CompactionTestHooks.Push(point =>
        {
            if (point != selected) return; hit = true;
            if (cancel) { cancellation.Cancel(); cancellation.Token.ThrowIfCancellationRequested(); }
            throw new IOException("Interrupted stopped working-copy cleanup.");
        }))
        {
            if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation, cancellation.Token));
            else await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
        }
        Assert.True(hit);
        for (var reopen = 0; reopen < 2; reopen++)
        {
            fixture.ColdReopenCompactionStorage();
            // Ordinary entry point must recover committed cleanup, not a
            // privileged fixture-only recovery callback or SQL repair.
            await Assert.ThrowsAsync<IOException>(test.Deliver);
            Assert.Equal(expectedSql.After, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(originalSend, await fixture.ReadSendRootForStoppedWork());
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Single(await fixture.ListOwnedMessages(test.Scope)); Assert.Empty(await fixture.ListNativePendingText());
            Assert.Equal(1, test.Grants.Calls); Assert.Equal(1, test.Transport.Calls);
            await fixture.RequireRetiredStoppedPayload(test.Scope, test.Operation);
        }
        foreach (var value in new[] { originalSend, native }) CryptographicOperations.ZeroMemory(value);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_DeletedWorkingCopyCannotReappearEvenWithExactOriginalBytes()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        var original = await fixture.CaptureOrdinaryWorkingRow(test.Scope, test.Operation);
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        await fixture.RestoreOrdinaryWorkingRow(test.Scope, original); // Disposable rollback, never runtime repair.
        fixture.ColdReopenCompactionStorage();
        var before = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ListNativePendingText());
        Assert.Equal(before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        Assert.Equal(0, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        foreach (var value in original.OfType<byte[]>()) CryptographicOperations.ZeroMemory(value);
        CryptographicOperations.ZeroMemory(before);
    }
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_ChangedRetryDeadlineRejectsBeforeClosureOrStop()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        using (Did2MailboxSendTestHooks.Push(point =>
        { if (point == Did2MailboxSendFailpoint.AfterPreparedRoot) throw new IOException("Retained exact prepared work."); }))
            await Assert.ThrowsAsync<IOException>(test.Deliver);
        await fixture.ChangeRetryDeadlineForDisposableStopTest(test.Scope);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        var damaged = await fixture.ReadSendRootForStoppedWork();
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        for (var reopen = 0; reopen < 2; reopen++)
        {
            fixture.ColdReopenCompactionStorage();
            await Assert.ThrowsAsync<CryptographicException>(test.Deliver);
            Assert.Equal(damaged, await fixture.ReadSendRootForStoppedWork());
            Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
            Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.Active,
                await fixture.ReadStoppedWorkReason(test.Scope, test.Operation));
        }
        Assert.Equal(1, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        foreach (var bytes in new[] { damaged, authored }) CryptographicOperations.ZeroMemory(bytes);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_OriginalDeadlineStopsBeforeExpiredPeerRefresh(bool interruptAfterClosure)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        using (Did2MailboxSendTestHooks.Push(point =>
        { if (point == Did2MailboxSendFailpoint.AfterPreparedRoot) throw new IOException("Retained exact prepared work."); }))
            await Assert.ThrowsAsync<IOException>(test.Deliver);
        ulong deadline;
        using (var original = await fixture.ReadMailboxSends()) deadline = Assert.Single(original.Entries).Value.RetryUntil;
        await fixture.AdvanceStoppedWorkToOriginalDeadline(deadline);
        var hit = false;
        if (interruptAfterClosure)
        {
            using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterClosureRoot) { hit = true; throw new IOException("Interrupted original closure before stop."); } }))
                await Assert.ThrowsAsync<IOException>(test.Deliver);
            Assert.True(hit);
            Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.Active,
                await fixture.ReadStoppedWorkReason(test.Scope, test.Operation));
            fixture.ColdReopenCompactionStorage();
        }
        await Assert.ThrowsAsync<IOException>(test.Deliver);
        Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired,
            await fixture.ReadStoppedWorkReason(test.Scope, test.Operation));
        using (var closed = await fixture.ReadMailboxSends())
        {
            var retained = Assert.Single(closed.Entries).Value;
            Assert.True(retained.Closed); Assert.True(retained.Prepared); Assert.False(retained.HasSuccessor);
            Assert.True(retained.ClosedAtLower >= deadline); Assert.Equal(deadline, retained.RetryUntil);
        }
        var before = await fixture.ReadAuthoredRootDigestAsync();
        fixture.ColdReopenCompactionStorage();
        await Assert.ThrowsAsync<IOException>(test.Deliver);
        Assert.Equal(before, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(1, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        Assert.Empty(await fixture.ListNativePendingText());
        Assert.Single(await fixture.ListOwnedMessages(test.Scope));
        CryptographicOperations.ZeroMemory(before);
    }
    [Theory]
    [InlineData("NoAttempt")]
    [InlineData("BeforeSql")]
    [InlineData("AfterSql")]
    [InlineData("AfterPreparedRoot")]
    [InlineData("Unknown")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_CancelRetainsOriginalCustodyAndColdForbidsDispatch(string preparation)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        if (preparation == "Unknown")
        {
            test.Transport.LoseReply = true;
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        }
        else if (preparation != "NoAttempt")
        {
            var fault = Enum.Parse<Did2MailboxSendFailpoint>(preparation);
            var hit = false;
            using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == fault) { hit = true; throw new IOException("Interrupted actual original request preparation."); } }))
                await Assert.ThrowsAsync<IOException>(test.Deliver);
            Assert.True(hit);
        }
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        using var application = await fixture.ExpectedStoppedPayloadSqlSuccessor(test.Scope, test.Operation);
        using var capture = application.Observe();
        var sends = await fixture.ReadSendRootForStoppedWork();
        var grants = test.Grants.Calls; var dispatches = test.Transport.Calls;
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        var stopped = await fixture.ReadAuthoredRootDigestAsync();
        for (var reopen = 0; reopen < 2; reopen++)
        {
            fixture.ColdReopenCompactionStorage();
            await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
            await Assert.ThrowsAsync<IOException>(test.Deliver);
            Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled,
                await fixture.ReadStoppedWorkReason(test.Scope, test.Operation));
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(application.After, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(sends, await fixture.ReadSendRootForStoppedWork());
            Assert.Equal(stopped, await fixture.ReadAuthoredRootDigestAsync());
            Assert.Equal(grants, test.Grants.Calls); Assert.Equal(dispatches, test.Transport.Calls);
            Assert.Empty(await fixture.ListNativePendingText());
            Assert.Single(await fixture.ListOwnedMessages(test.Scope));
        }
        foreach (var bytes in new[] { native, sends, stopped }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData("BeforeWorkStopRoot", false)]
    [InlineData("AfterWorkStopRoot", false)]
    [InlineData("BeforeWorkStopRoot", true)]
    [InlineData("AfterWorkStopRoot", true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_CrashAndCancellationResumeOneLocalStop(string interruption, bool cancel)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        var fault = Enum.Parse<Did2MailboxSendFailpoint>(interruption); var hit = false;
        using var cancellation = new CancellationTokenSource();
        using (Did2MailboxSendTestHooks.Push(point =>
        {
            if (point != fault) return;
            hit = true;
            if (cancel) { cancellation.Cancel(); cancellation.Token.ThrowIfCancellationRequested(); }
            throw new IOException("Interrupted actual owned work stop.");
        }))
        {
            if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                fixture.CancelNativeMessagingWork(test.Scope, test.Operation, cancellation.Token));
            else await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
        }
        Assert.True(hit);
        Assert.Equal(fault == Did2MailboxSendFailpoint.AfterWorkStopRoot
            ? ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled : ProtectedDid2DirectTextJournal.WorkStopReason.Active,
            await fixture.ReadStoppedWorkReason(test.Scope, test.Operation));
        fixture.ColdReopenCompactionStorage();
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        var once = await fixture.ReadAuthoredRootDigestAsync();
        fixture.ColdReopenCompactionStorage();
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        await Assert.ThrowsAsync<IOException>(test.Deliver);
        Assert.Equal(once, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(0, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        CryptographicOperations.ZeroMemory(once);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_CancelCannotDowngradeOriginalStoreOrTransportDelivered(bool repositoryDelivered)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        var stored = await test.Deliver();
        if (repositoryDelivered) await fixture.AdvanceStoreRepositoryStateForContractTest(test.Scope, test.Operation);
        // Delivered here is the existing opaque storage-contract fixture, NOT
        // an authenticated application AppAck/device delivery qualification.
        var before = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var successfulAt = await fixture.ReadSuccessfulTerminalTime(test.Scope, test.Operation, compacted: false);
        try
        {
            Assert.True(successfulAt > 0);
            using var capture = Did2MailboxSendTestHooks.Push(point =>
            {
                if (point is Did2MailboxSendFailpoint.BeforeWorkStopRoot or Did2MailboxSendFailpoint.AfterWorkStopRoot)
                    throw new InvalidDataException("A successful Store must not enter a later stop transition.");
            });
            for (var retry = 0; retry < 2; retry++)
            {
                await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
                fixture.ColdReopenCompactionStorage();
                var retained = await test.Deliver();
                Assert.False(retained.IngressDispatched); Assert.Equal(stored.Cursor, retained.Cursor);
                Assert.Equal(before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
                Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
                Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
                Assert.Equal(successfulAt, await fixture.ReadSuccessfulTerminalTime(test.Scope, test.Operation, compacted: false));
                Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.Active,
                    await fixture.ReadStoppedWorkReason(test.Scope, test.Operation));
            }
            Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        }
        finally { foreach (var bytes in new[] { before, authored, native }) CryptographicOperations.ZeroMemory(bytes); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoppedWork_OriginalLateQuorumAdoptsStoreWithoutResumingCancelledSend()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        test.Transport.LoseReply = true;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        var reply = test.Transport.CopyOriginalQuorumForFixture();
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        fixture.ColdReopenCompactionStorage();
        var account = fixture.ReopenAccount(); var source = fixture.Source(account);
        var adopted = await account.AdoptOwnOriginalMailboxStoreReplyAsync(test.Scope, test.Operation,
            test.Operation, ReadOnlyMemory<byte>.Empty, reply, source);
        Assert.False(adopted.IngressDispatched);
        Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled,
            await fixture.ReadStoppedWorkReason(test.Scope, test.Operation));
        var retained = await test.Deliver();
        Assert.False(retained.IngressDispatched); Assert.Equal(adopted.Cursor, retained.Cursor);
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        CryptographicOperations.ZeroMemory(reply);
    }

    private sealed partial class Fixture
    {
        internal async Task RequireRetiredStoppedPayload(Did2MessagingSessionScope scope, byte[] operation)
        {
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidOperationException();
            using var state = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var name = Convert.ToHexString(operation);
            Assert.False(state.Entries.ContainsKey(name));
            var audit = state.TerminalAudits[name];
            Assert.Contains(audit.Reason, new byte[] { 1, 2 });
            Assert.InRange(audit.TerminalAtUpper, 1UL, CurrentProofTime + 100UL);
        }
        // Read-only complete SQL effects, not staging/deletion permission. The
        // owner must independently commit actual stop custody before cleanup.
        internal async Task<StoppedSqlExpectation> ExpectedStoppedPayloadSqlSuccessor(Did2MessagingSessionScope scope, byte[] operation)
        {
            var accountDirectory = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var secure = scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage;
            var heldLease = new DeepIdV2AccountFileLease(Path.Combine(accountDirectory, "deep-store-v2-account.lock"));
            using var held = await heldLease.AcquireAsync(default);
            var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(secure,
                Path.Combine(accountDirectory, "deep-store-v2-account.dsv2"), scope, held, heldLease, default);
            try
            {
                var before = await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, default);
                return new(application, secure, scope, operation, before);
            }
            catch { application.Dispose(); throw; }
        }

        // Observe the actual protected stop before cleanup starts. The expected
        // SQL successor is independently calculated from unchanged SQL facts
        // and its real final authenticated time, never copied from the plan,
        // predicted UTC, a frozen clock or a fake caller-owned stop timestamp.
        internal sealed class StoppedSqlExpectation(SqliteDeepMailboxStore application, IDeepSecureStorage secure,
            Did2MessagingSessionScope scope, byte[] operation, byte[] before) : IDisposable
        {
            private byte[] after = [];
            internal byte[] After => after.Length == 32 ? after : throw new InvalidDataException("Actual stop observation was not captured.");
            // Install in the calling test's execution context, not in the
            // asynchronous factory's child AsyncLocal context.
            internal IDisposable Observe() => Did2MailboxSendTestHooks.Push(point =>
            {
                if (point != Did2MailboxSendFailpoint.AfterWorkStopRoot) return;
                using var raw = secure.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot).GetAwaiter().GetResult() ?? throw new InvalidDataException();
                using var state = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                var stopped = state.Entries[Convert.ToHexString(operation)];
                Assert.True(stopped.WorkStopped); Assert.False(state.TerminalAudits.ContainsKey(Convert.ToHexString(operation)));
                Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, stopped.StopReason);
                var effects = application.CaptureOrdinaryOutboxEffectsAsync(scope, [stopped], default,
                    Did2CompactionPlan.Disposition.StoppedOutboxPayload).GetAwaiter().GetResult();
                try { Assert.Equal(before, effects.Before); Assert.Empty(after); after = effects.After; }
                finally { CryptographicOperations.ZeroMemory(effects.Before); }
            });
            public void Dispose()
            { application.Dispose(); CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }
        internal async Task ChangeRetryDeadlineForDisposableStopTest(Did2MessagingSessionScope scope)
        {
            using var raw = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidOperationException();
            var snapshot = raw.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxSendJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
            var original = Assert.Single(state.Entries).Value; var record = original.Exact.ToArray();
            // Remain structurally canonical while violating the independent
            // application deadline. An arbitrary earlier value can violate
            // admission <= retry and never reach the actual owner rejection.
            BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(400), original.AdmissionUntil);
            state.Entries[original.Name] = ProtectedDid2MailboxSendJournal.Entry.Decode(record); original.Dispose();
            var damaged = ProtectedDid2MailboxSendJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
            // Only this disposable corruption fixture, never a runtime repair.
            Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, damaged, default));
            foreach (var bytes in new[] { snapshot, record, damaged }) CryptographicOperations.ZeroMemory(bytes);
        }
        internal async Task AdvanceStoppedWorkToOriginalDeadline(ulong deadline)
        {
            await AdvanceOriginalStoreEpochForTestAsync(2_100);
            var delta = checked(deadline + 20 - CurrentProofTime);
            ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
            await AdvanceObjectHorizonAuthorityAsync();
        }
        internal Task CancelNativeMessagingWork(Did2MessagingSessionScope scope, byte[] operation, CancellationToken ct = default)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            return account.CancelOwnMessagingWorkAsync(scope, operation, source, ct);
        }
        internal async Task<byte[]> ReadSendRootForStoppedWork()
        {
            using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidOperationException();
            return root.Use(bytes => bytes.ToArray());
        }
        internal async Task<ProtectedDid2DirectTextJournal.WorkStopReason> ReadStoppedWorkReason(Did2MessagingSessionScope scope, byte[] operation)
        {
            using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidOperationException();
            using var journal = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var name = Convert.ToHexString(operation);
            if (journal.Entries.TryGetValue(name, out var command)) return command.StopReason;
            if (journal.TerminalAudits.TryGetValue(name, out var audit))
                return audit.Reason == 3 ? ProtectedDid2DirectTextJournal.WorkStopReason.Active :
                    (ProtectedDid2DirectTextJournal.WorkStopReason)audit.Reason;
            throw new IOException("No retained terminal disposition exists.");
        }
    }
}
