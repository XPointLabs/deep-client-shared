using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteReintroduction_AutomaticRecoveryKeepsExactPreparedOriginalWithoutAnotherNativeSend()
    {
        // Genuine signed in-process services, owned grants, SQLCipher and native
        // custody. This is not a socket, deployed-node or physical-device claim.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        fixture.TrackMailboxDispatchClock();
        await fixture.RenewNativeSenderPublicationPastExpiryAsync();
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        var operation = command.OperationId.ToArray(); byte[] ciphertext;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, operation)) ciphertext = sent.ExactEnvelope.ToArray();
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        using var authoredBefore = await fixture.ReadAuthoredTextJournalAsync(sender);
        var account = fixture.ReopenAccount(); var caller = operation.ToArray();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, operation, ciphertext) { LoseReply = true };
        byte[] originalMau = [];
        terminal.OnLostReply = () =>
        {
            originalMau = terminal.ExactRequest!.ToArray();
            var grant = MailboxAuthenticatedClientRequestCodec.Decode(originalMau).Presentation.Grant;
            Assert.True(checked(fixture.CurrentProofTime + 45) < grant.ExpiresAtUnixSeconds);
            caller.AsSpan().Clear(); fixture.Sample += 40; fixture.ProofTime += 40;
            terminal.LoseReply = false;
        };
        var result = await fixture.DeliverAutomaticReintroducedRoute(account, sender, caller, grants, terminal);
        Assert.NotNull(result.Cursor); Assert.NotNull(result.Disposition);
        Assert.Equal(2, terminal.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(originalMau, terminal.ExactRequest); // Includes body, grant, counter, nonce and operation.
        Assert.All(caller, value => Assert.Equal((byte)0, value));
        Assert.Equal(1, account.ExactStoreResumes); Assert.Equal(0, account.ExactRecoveryLeaseWaits);
        using (var sends = await fixture.ReadMailboxSends())
        {
            var attempt = Assert.Single(sends.Entries.Values, entry => entry.Operation.SequenceEqual(operation));
            Assert.False(attempt.HasPredecessor); Assert.False(attempt.HasSuccessor); Assert.True(attempt.Prepared);
            Assert.Equal(SHA256.HashData(originalMau), attempt.MauHash.ToArray());
            Assert.Equal(1UL, attempt.Counter);
        }
        using (var authoredAfter = await fixture.ReadAuthoredTextJournalAsync(sender))
        {
            Assert.Equal(authoredBefore.NextSequence(sender), authoredAfter.NextSequence(sender));
            Assert.Equal(authoredBefore.Entries.Count, authoredAfter.Entries.Count);
            Assert.Equal(authoredBefore.Entries[Convert.ToHexString(operation)].EventHash.ToArray(),
                authoredAfter.Entries[Convert.ToHexString(operation)].EventHash.ToArray());
        }
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        foreach (var bytes in new[] { operation, ciphertext, floor, caller, originalMau }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteReintroduction_AutomaticRecoveryStopsExpiredOriginalBeforeFreshRecipientOrDispatch()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        fixture.TrackMailboxDispatchClock();
        await fixture.RenewNativeSenderPublicationPastExpiryAsync();
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        var operation = command.OperationId.ToArray(); byte[] ciphertext;
        var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
        var deadline = message.ExpiresAtUnixMilliseconds / 1_000;
        Assert.True(deadline > fixture.CurrentProofTime);
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, operation)) ciphertext = sent.ExactEnvelope.ToArray();
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var account = fixture.ReopenAccount(); var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, operation, ciphertext) { LoseReply = true };
        byte[] originalMau = [];
        terminal.OnLostReply = () =>
        {
            originalMau = terminal.ExactRequest!.ToArray();
            var delta = checked(deadline + 20 - fixture.CurrentProofTime);
            fixture.Sample = checked(fixture.Sample + delta); fixture.ProofTime = checked(fixture.ProofTime + delta);
            fixture.RejectContactRetryRecipient(initial: true);
        };
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() =>
            fixture.DeliverAutomaticReintroducedRoute(account, sender, operation, grants, terminal));
        Assert.Equal(1, terminal.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(originalMau, terminal.ExactRequest);
        Assert.Equal(0, fixture.RejectedContactRetryProofCalls); Assert.Equal(0, fixture.RejectedContactRetryReadCalls);
        Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired,
            await fixture.ReadStoppedWorkReason(sender, operation));
        using (var sends = await fixture.ReadMailboxSends())
        {
            var attempt = Assert.Single(sends.Entries.Values, entry => entry.Operation.SequenceEqual(operation));
            Assert.True(attempt.Closed); Assert.True(attempt.Prepared); Assert.False(attempt.HasSuccessor);
            Assert.Equal(deadline, attempt.RetryUntil); Assert.True(attempt.ClosedAtLower >= deadline);
            Assert.Equal(SHA256.HashData(originalMau), attempt.MauHash.ToArray());
        }
        Assert.Equal(1, account.ExactStoreResumes); Assert.Equal(0, account.ExactRecoveryLeaseWaits);
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        foreach (var bytes in new[] { operation, ciphertext, floor, originalMau }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteMaintenance_ExpiredOriginalRequiresExactStopAndPreservesControlReplacementRules(bool response, bool changedDeadline)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await fixture.PrepareRouteHistoryPair();
        fixture.TrackMailboxDispatchClock();
        byte[] requestOperation = [];
        if (response)
        {
            using var request = await fixture.PrepareOwnedHistory(receiver); Assert.NotNull(request);
            requestOperation = request!.OperationId.ToArray();
            using var sent = await fixture.SendOwnedRouteUpdate(receiver, requestOperation);
            using (await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        }
        using var command = await fixture.PrepareOwnedHistory(sender, requestOperation); Assert.NotNull(command);
        var operation = command!.OperationId.ToArray();
        var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
        var control = Assert.IsType<ContactRouteHistoryDmc2Payload>(message.ParsedPayload);
        Assert.Equal(!response, control.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest);
        var deadline = message.ExpiresAtUnixMilliseconds / 1_000;
        byte[] ciphertext;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, operation)) ciphertext = sent.ExactEnvelope.ToArray();
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        using var authoredBefore = await fixture.ReadAuthoredTextJournalAsync(sender);
        // No attempt is not expiry evidence, even for a retained native control.
        Assert.Equal(operation, await fixture.SelectRouteMaintenance(sender));
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, operation, ciphertext) { LoseReply = true };
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() =>
            fixture.DeliverNativeMessage(sender, operation, grants, terminal));
        var originalMau = terminal.ExactRequest!.ToArray();
        var authoredActive = await fixture.ReadAuthoredRootDigestAsync();
        var sendActive = await fixture.ReadSendRootForStoppedWork();
        Assert.Equal(operation, await fixture.SelectRouteMaintenance(sender)); // Unexpired uncertainty remains the original.
        Assert.Equal(authoredActive, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(sendActive, await fixture.ReadSendRootForStoppedWork());
        var delta = checked(deadline + 20 - fixture.CurrentProofTime);
        fixture.Sample = checked(fixture.Sample + delta); fixture.ProofTime = checked(fixture.ProofTime + delta);
        if (changedDeadline)
        {
            await fixture.ChangeRouteMaintenanceRetryDeadlineForDisposableTest(sender, operation);
            var damaged = await fixture.ReadSendRootForStoppedWork();
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.SelectRouteMaintenance(sender));
            Assert.Equal(damaged, await fixture.ReadSendRootForStoppedWork());
            Assert.Equal(authoredActive, await fixture.ReadAuthoredRootDigestAsync());
            Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.Active, await fixture.ReadStoppedWorkReason(sender, operation));
            CryptographicOperations.ZeroMemory(damaged);
        }
        else
        {
            Assert.Null(await fixture.SelectRouteMaintenance(sender)); // Completed stop, never a fabricated Store success.
            Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired, await fixture.ReadStoppedWorkReason(sender, operation));
            using (var sends = await fixture.ReadMailboxSends())
            {
                var attempt = Assert.Single(sends.Entries.Values, entry => entry.Operation.SequenceEqual(operation));
                Assert.True(attempt.Closed); Assert.True(attempt.Prepared); Assert.False(attempt.HasSuccessor);
                Assert.Equal(deadline, attempt.RetryUntil); Assert.True(attempt.ClosedAtLower >= deadline);
                Assert.Equal(SHA256.HashData(originalMau), attempt.MauHash.ToArray());
            }
            await fixture.RequireRetiredStoppedPayload(sender, operation);
            Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            using var authoredStopped = await fixture.ReadAuthoredTextJournalAsync(sender);
            Assert.Equal(authoredBefore.NextSequence(sender), authoredStopped.NextSequence(sender));
            using var next = await fixture.PrepareOwnedHistory(sender, requestOperation);
            if (response)
            {
                // Native F8 tag3 keeps this exact response unique after expiry/stop.
                Assert.Null(next);
                using var unchanged = await fixture.ReadAuthoredTextJournalAsync(sender);
                Assert.Equal(authoredStopped.NextSequence(sender), unchanged.NextSequence(sender));
                Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            }
            else
            {
                Assert.NotNull(next);
                Assert.NotEqual(operation, next!.OperationId.ToArray());
                Assert.Equal(command.SenderSequence + 1, next.SenderSequence);
                var fresh = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(next.ExactDmc2.Span).ParsedPayload);
                Assert.Equal(control.LeftCursor.ToArray(), fresh.LeftCursor.ToArray());
                Assert.Equal(DeepIdV2ContactRouteHistoryMode.HistoryRequest, fresh.Mode);
                using var sent = await fixture.SendOwnedRouteUpdate(sender, next.OperationId.ToArray());
                using (await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray())) { }
            }
        }
        Assert.Equal(1, terminal.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(originalMau, terminal.ExactRequest);
        if (changedDeadline) Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        foreach (var bytes in new[] { requestOperation, operation, ciphertext, floor, originalMau, authoredActive, sendActive })
            CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteMaintenance_CompletedExpiryStopPreservesGenuinePendingControlAndCounter()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await fixture.PrepareRouteHistoryPair();
        fixture.TrackMailboxDispatchClock();
        using var request = await fixture.PrepareOwnedHistory(sender); Assert.NotNull(request);
        var operation = request!.OperationId.ToArray();
        var deadline = ApplicationCoreCodec.DecodeDmc2(request.ExactDmc2.Span).ExpiresAtUnixMilliseconds / 1_000;
        byte[] ciphertext;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, operation)) ciphertext = sent.ExactEnvelope.ToArray();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, operation, ciphertext) { LoseReply = true };
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() =>
            fixture.DeliverNativeMessage(sender, operation, grants, terminal));
        var originalMau = terminal.ExactRequest!.ToArray();
        var hit = false;
        using (Did2TextOutboxTestHooks.Push(point =>
        {
            if (point != Did2TextOutboxFailpoint.AfterPending) return;
            hit = true; throw new IOException("Retained genuine pending route control.");
        }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CreateOwnedRouteUpdate(sender));
        Assert.True(hit);
        using var before = await fixture.ReadAuthoredTextJournalAsync(sender);
        var pending = before.Pending ?? throw new InvalidDataException("The real author did not retain its pending control.");
        Assert.Equal(Dmc2ContentKind.ContactRouteUpdate, pending.Kind);
        Assert.Equal(sender.Exact.ToArray(), pending.Scope.Exact.ToArray());
        var pendingExact = pending.Exact.ToArray(); var pendingOperation = pending.Operation.ToArray();
        var nextSequence = before.NextSequence(sender);
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var delta = checked(deadline + 20 - fixture.CurrentProofTime);
        fixture.Sample = checked(fixture.Sample + delta); fixture.ProofTime = checked(fixture.ProofTime + delta);
        Assert.Null(await fixture.SelectRouteMaintenance(sender));
        using (var after = await fixture.ReadAuthoredTextJournalAsync(sender))
        {
            Assert.NotNull(after.Pending); Assert.Equal(pendingExact, after.Pending!.Exact.ToArray());
            Assert.Equal(nextSequence, after.NextSequence(sender));
            var stopped = after.Entries[Convert.ToHexString(operation)];
            Assert.True(stopped.WorkStopped); Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired, stopped.StopReason);
            Assert.Equal(request.SenderSequence, stopped.Sequence);
            Assert.Equal(SHA256.HashData(request.ExactDmc2.Span), stopped.EventHash.ToArray());
        }
        // The next scheduling call selects that exact pending original. It
        // neither resumes the stopped request nor manufactures another control.
        Assert.Equal(pendingOperation, await fixture.SelectRouteMaintenance(sender));
        using (var unchanged = await fixture.ReadAuthoredTextJournalAsync(sender))
        {
            Assert.Equal(pendingExact, unchanged.Pending!.Exact.ToArray());
            Assert.Equal(nextSequence, unchanged.NextSequence(sender));
        }
        using (var sends = await fixture.ReadMailboxSends())
        {
            var original = Assert.Single(sends.Entries.Values, entry => entry.Operation.SequenceEqual(operation));
            Assert.True(original.Closed); Assert.True(original.Prepared); Assert.False(original.HasSuccessor);
            Assert.Equal(SHA256.HashData(originalMau), original.MauHash.ToArray());
        }
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(1, grants.Calls); Assert.Equal(1, terminal.Calls); Assert.Equal(originalMau, terminal.ExactRequest);
        foreach (var bytes in new[] { operation, ciphertext, originalMau, pendingExact, pendingOperation, floor })
            CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        internal async Task ChangeRouteMaintenanceRetryDeadlineForDisposableTest(Did2MessagingSessionScope scope, byte[] operation)
        {
            using var raw = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidOperationException();
            var snapshot = raw.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxSendJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
            var original = Assert.Single(state.Entries.Values, entry => entry.Operation.SequenceEqual(operation));
            var record = original.Exact.ToArray(); var retry = checked(original.RetryUntil - 1);
            Assert.True(retry > original.Created);
            BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(400), retry);
            BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(424), Math.Min(original.AdmissionUntil, retry));
            Assert.NotEqual(original.Exact.ToArray(), record);
            using (var canonical = ProtectedDid2MailboxSendJournal.Entry.Decode(record)) Assert.Equal(record, canonical.Exact.ToArray());
            state.Entries[original.Name] = ProtectedDid2MailboxSendJournal.Entry.Decode(record); original.Dispose();
            var damaged = ProtectedDid2MailboxSendJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
            Assert.NotEqual(snapshot, damaged);
            using (var canonical = ProtectedDid2MailboxSendJournal.Decode(damaged, scope.Network, scope.LocalAccount, scope.Instance))
                Assert.Equal(damaged, ProtectedDid2MailboxSendJournal.Encode(canonical, scope.Network, scope.LocalAccount, scope.Instance));
            Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, damaged, default));
            foreach (var bytes in new[] { snapshot, record, damaged }) CryptographicOperations.ZeroMemory(bytes);
        }

        internal async Task<ClientMailboxStoreResult> DeliverAutomaticReintroducedRoute(DeepIdV2AccountService account,
            Did2MessagingSessionScope scope, byte[] operation, IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport)
        {
            var source = Source(account);
            var read = new SyntheticPermanentRead(this, source, nativeMessagingPublication);
            var address = nativeMessagingContact!.Candidate.Address;
            var contact = await account.ResolvePermanentContactAsync(address, source, read);
            var resolved = await source.VerifyPermanentContactAsync(contact.Candidate, default);
            return await account.DeliverOwnRouteReintroductionWithRecoveryAsync(scope, operation, address,
                resolved, source, grants, transport, default, read);
        }
    }
}
