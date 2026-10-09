using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StorePublicEvidence_InitialStoreKeepsOriginalRecipientAfterColdEpochRollover(bool interruptBeforeIngress, bool loseReply)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var intent = Bytes(32, 0xc1);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(intent);
        using var initial = await complete(fixture.Accounts);
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        fixture.TrackMailboxDispatchClock();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, null, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent), initial.ExactDph2.ToArray());
        if (loseReply)
        {
            transport.LoseReply = true;
            await Assert.ThrowsAsync<Deep.Client.Shared.Services.ClientMailboxDispatchOutcomeUnknownException>(
                () => fixture.DeliverNativeInitial(intent, grants, transport));
            Assert.Equal(1, transport.Calls); transport.LoseReply = false;
        }
        var expectedIngress = loseReply ? 2 : 1;
        if (interruptBeforeIngress)
        {
            using (Did2MailboxSendTestHooks.Push(point =>
            {
                if (point == Did2MailboxSendFailpoint.BeforeDispatch) throw new IOException("Injected initial public-evidence interruption before ingress.");
            }))
                await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeInitial(intent, grants, transport));
            Assert.Equal(0, transport.Calls);
        }
        var stored = await fixture.DeliverNativeInitial(intent, grants, transport);
        Assert.True(stored.IngressDispatched); Assert.Equal(expectedIngress, transport.Calls); Assert.Equal(1, grants.Calls);
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var controls = await fixture.ReadRetainedContactStoreRoots(sender);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        fixture.ColdReopenCompactionStorage();
        var retained = await fixture.DeliverNativeInitial(intent, grants, transport);
        Assert.False(retained.IngressDispatched); Assert.Equal(stored.Cursor, retained.Cursor); Assert.Equal(stored.Disposition, retained.Disposition);
        var started = await fixture.ReplayInitialStartWithoutResolver(intent, grants, transport);
        Assert.False(started.StorageReceipt.IngressDispatched); Assert.Equal(sender.Exact.ToArray(), started.Conversation.Scope.Exact.ToArray());
        Assert.Equal(stored.Cursor, started.StorageReceipt.Cursor);
        Assert.Equal(expectedIngress, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(controls, await fixture.ReadRetainedContactStoreRoots(sender));
        await fixture.AssertCompactedStoreRejectsChangedPublicEvidence(sender,
            () => fixture.DeliverNativeInitial(intent, grants, transport));
        if (!interruptBeforeIngress && !loseReply)
            await fixture.AssertInitialStartRejectsMissingDraft(sender, intent, grants, transport);
        Assert.Equal(expectedIngress, transport.Calls); Assert.Equal(1, grants.Calls);
        foreach (var bytes in new[] { intent, application, native, controls }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StorePublicEvidence_InitialUnknownMissingEvidenceCannotResolveOrReconstruct()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var intent = Bytes(32, 0xc3);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(intent);
        using var initial = await complete(fixture.Accounts);
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var operation = ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent);
        fixture.TrackMailboxDispatchClock();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, null, operation, initial.ExactDph2.ToArray()) { LoseReply = true };
        await Assert.ThrowsAsync<Deep.Client.Shared.Services.ClientMailboxDispatchOutcomeUnknownException>(
            () => fixture.DeliverNativeInitial(intent, grants, transport));
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        await fixture.DeleteContactStoreEvidenceDuringOwnerCallback(sender, operation);
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var controls = await fixture.ReadRetainedContactStoreRoots(sender);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeInitial(intent, grants, transport));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReplayInitialStartWithoutResolver(intent, grants, transport));
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(controls, await fixture.ReadRetainedContactStoreRoots(sender));
        foreach (var bytes in new[] { intent, operation, application, native, controls }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StorePublicEvidence_InitialStoreLostEvidenceAfterIngressCannotReturnOrRepairSuccess()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var intent = Bytes(32, 0xc2);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(intent);
        using var initial = await complete(fixture.Accounts);
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var operation = ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent);
        fixture.TrackMailboxDispatchClock();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, null, operation, initial.ExactDph2.ToArray());
        var removed = false;
        using (Did2MailboxSendTestHooks.Push(point =>
        {
            if (point != Did2MailboxSendFailpoint.BeforeOrdinaryCompletion) return;
            fixture.DeleteContactStoreEvidenceDuringOwnerCallback(sender, operation).GetAwaiter().GetResult(); removed = true;
        }))
            await Assert.ThrowsAsync<Deep.Client.Shared.Services.ClientMailboxDispatchOutcomeUnknownException>(
                () => fixture.DeliverNativeInitial(intent, grants, transport));
        Assert.True(removed); Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var controls = await fixture.ReadRetainedContactStoreRoots(sender);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeInitial(intent, grants, transport));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReplayInitialStartWithoutResolver(intent, grants, transport));
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(controls, await fixture.ReadRetainedContactStoreRoots(sender));
        foreach (var bytes in new[] { intent, operation, application, native, controls }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StorePublicEvidence_ContactAcceptLostEvidenceAfterIngressCannotReturnOrRepairSuccess()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xb1));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        _ = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xb2));
        var operation = accept.Operation.ToArray();
        using var sent = await fixture.SendOwnedMessage(receiver, operation, ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2));
        fixture.TrackMailboxDispatchClock();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var transport = new OwnedStoreFixture(fixture, receiver, operation, sent.ExactEnvelope.ToArray());
        var removed = false;
        using (Did2MailboxSendTestHooks.Push(point =>
        {
            if (point != Did2MailboxSendFailpoint.BeforeOrdinaryCompletion) return;
            fixture.DeleteContactStoreEvidenceDuringOwnerCallback(receiver, operation).GetAwaiter().GetResult();
            removed = true;
        }))
            await Assert.ThrowsAsync<Deep.Client.Shared.Services.ClientMailboxDispatchOutcomeUnknownException>(
                () => fixture.DeliverNativeMessage(receiver, operation, grants, transport));
        Assert.True(removed); Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
        var native = (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray();
        var controls = await fixture.ReadRetainedContactStoreRoots(receiver);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeMessage(receiver, operation, grants, transport));
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(controls, await fixture.ReadRetainedContactStoreRoots(receiver));
        foreach (var bytes in new[] { operation, application, native, controls }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StorePublicEvidence_ContactAcceptKeepsOriginalOutcomeAfterColdEpochRollover(bool interruptBeforeIngress)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xa1));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        _ = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xa2));
        var operation = accept.Operation.ToArray();
        using var sent = await fixture.SendOwnedMessage(receiver, operation, ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2));
        fixture.TrackMailboxDispatchClock();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var transport = new OwnedStoreFixture(fixture, receiver, operation, sent.ExactEnvelope.ToArray());
        if (interruptBeforeIngress)
        {
            using (Did2MailboxSendTestHooks.Push(point =>
            {
                if (point == Did2MailboxSendFailpoint.BeforeDispatch) throw new IOException("Injected interruption after original public evidence, before ingress.");
            }))
                await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(receiver, operation, grants, transport));
            Assert.Equal(0, transport.Calls);
            // Public evidence alone is not a Store success. The exact prepared
            // request must still reach ingress once on the subsequent attempt.
        }
        var stored = await fixture.DeliverNativeMessage(receiver, operation, grants, transport);
        Assert.True(stored.IngressDispatched); Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        var authored = await fixture.ReadAuthoredRootDigestAsync(own: false);
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
        var native = (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray();
        var controls = await fixture.ReadRetainedContactStoreRoots(receiver);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        fixture.ColdReopenReceiverStoreStorage();
        var retained = await fixture.DeliverNativeMessage(receiver, operation, grants, transport);
        Assert.False(retained.IngressDispatched); Assert.Equal(stored.Cursor, retained.Cursor);
        Assert.Equal(stored.Disposition, retained.Disposition);
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync(own: false));
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(controls, await fixture.ReadRetainedContactStoreRoots(receiver));
        await fixture.AssertCompactedStoreRejectsChangedPublicEvidence(receiver,
            () => fixture.DeliverNativeMessage(receiver, operation, grants, transport));
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        foreach (var bytes in new[] { operation, authored, application, native, controls }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StorePublicEvidence_StoredWorkingCommandSurvivesOriginalPolicyAndEpochExpiry()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xd1));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xd2)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var operation = Bytes(32, 0xd3);
        using var text = await fixture.PrepareOwnedText(sender, operation, "completed Store is not renewed admission");
        using var committed = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, committed.ExactEnvelope.ToArray());
        var stored = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
        Assert.True(stored.IngressDispatched);
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        using (var sends = await fixture.ReadMailboxSends())
        { Assert.Single(sends.Entries); Assert.Single(sends.Floors); }

        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        fixture.ColdReopenCompactionStorage();
        var retained = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
        Assert.False(retained.IngressDispatched); Assert.Equal(stored.Cursor, retained.Cursor);
        Assert.Equal(stored.Disposition, retained.Disposition);
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        using (var sends = await fixture.ReadMailboxSends())
        { Assert.Single(sends.Entries); Assert.Single(sends.Floors); }
        Assert.Empty(await fixture.ListNativePendingText());
        // Missing public evidence must not be repaired from retained private
        // grant/send custody or the independently current replacement policy.
        await fixture.AssertCompactedStoreRejectsChangedPublicEvidence(sender,
            () => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        foreach (var bytes in new[] { authored, application, native }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(false)] // Cancel after durable completion; fresh read may recover the original outcome.
    [InlineData(true)] // Expire actual directory freshness; do not rewind time or invent a fresh head.
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxSend_LostOwnContextAfterCompletionCannotReturnSuccess(bool expire)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xe1));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xe2)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var operation = Bytes(32, 0xe3);
        using var text = await fixture.PrepareOwnedText(sender, operation, "completion keeps facts, not expired authority");
        using var committed = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        // Signed receipts use the advancing dispatch clock. The independently
        // sampled authority clock must advance too; a frozen sample would put
        // that same accepted receipt in the future on a subsequent local read.
        fixture.TrackMailboxDispatchClock();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, committed.ExactEnvelope.ToArray());
        var reached = false;
        using var cancelled = new CancellationTokenSource();
        using (Did2MailboxSendTestHooks.Push(point =>
        {
            if (point != Did2MailboxSendFailpoint.AfterOrdinaryCompletion) return;
            reached = true;
            // DTT1 response freshness and a cached directory head's revocation
            // window are distinct. Cross the actual maximum cached TTL, not
            // an arbitrary delta that may still be valid under the signed head.
            if (expire) fixture.Sample = checked(fixture.Sample + AccountDirectoryCurrentProofVerifier.RevocationFreshnessTtlSeconds);
            else cancelled.Cancel();
        }))
            await Assert.ThrowsAsync<Deep.Client.Shared.Services.ClientMailboxDispatchOutcomeUnknownException>(
                () => fixture.DeliverNativeMessage(sender, operation, grants, transport, cancelled.Token));
        Assert.True(reached); Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Empty(await fixture.ListNativePendingText());
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        // Local history remains available without acquiring network authority.
        Assert.Single(await fixture.ListOwnedMessages(sender));
        if (!expire)
        {
            var retained = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
            Assert.False(retained.IngressDispatched); Assert.Equal(1UL, retained.Cursor);
        }
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        foreach (var bytes in new[] { authored, application }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxSend_SlowPreparationCannotRewindTheDispatchClock()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xb1));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xb2)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var operation = Bytes(32, 0xb3);
        using var text = await fixture.PrepareOwnedText(sender, operation, "one monotonic owned preparation/dispatch clock");
        using var committed = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, committed.ExactEnvelope.ToArray());
        // Force the real preparation's conservative clock two whole seconds
        // past a newly minted dispatch clock. No time/grant/retry guard changes.
        using (Did2MailboxSendTestHooks.Push(point => { if (point == Did2MailboxSendFailpoint.BeforeSql) Thread.Sleep(2_100); }))
        {
            var stored = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
            Assert.True(stored.IngressDispatched); Assert.Equal(1UL, stored.Cursor);
        }
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Empty(await fixture.ListNativePendingText());
    }

    [Fact]
    public async Task Did2StorePublicEvidence_ActualSignedPairIsImmutableAndRejectsKeyViewSubstitution()
    {
        await using var fixture = await Fixture.CreateAsync();
        var plan = await fixture.Accounts.ReadOwnPermanentContactPlanAsync();
        using var threshold = new OwnedRouteThreshold(fixture);
        var route = await fixture.EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
        var captured = await MailboxStoreReplicaEvidenceVerifier.CaptureAsync(route);
        var records = new[] { captured.ExactXnv1.ToArray(), captured.ExactFirstXnd1.ToArray(), captured.ExactSecondXnd1.ToArray() };
        var evidence = new MailboxStoreReplicaEvidence(records[0], records[1], records[2]);
        foreach (var bytes in records) bytes[^1] ^= 1;
        var verified = MailboxStoreReplicaEvidenceVerifier.Verify(route.Network, route.NetworkAuthority, route.Route, evidence);
        Assert.Equal(route.Route.Selection.Field(6).ToArray()[..32], verified.FirstNodeId.ToArray());
        Assert.Equal(route.Route.Selection.Field(6).ToArray()[32..], verified.SecondNodeId.ToArray());
        Assert.Equal(route.Network.ResolveNodeIdentityPublicKey(verified.FirstNodeId).ToArray(), verified.FirstReceiptPublicKey.ToArray());
        var expected = verified.FirstReceiptPublicKey.ToArray();
        Assert.True(MemoryMarshal.TryGetArray(verified.FirstReceiptPublicKey, out var returned)); returned.Array![returned.Offset] ^= 1;
        Assert.Equal(expected, verified.FirstReceiptPublicKey.ToArray());
        Assert.True(MemoryMarshal.TryGetArray(evidence.ExactXnv1, out var returnedView)); returnedView.Array![returnedView.Offset + returnedView.Count - 1] ^= 1;
        Assert.Equal(captured.ExactXnv1.ToArray(), evidence.ExactXnv1.ToArray());
        foreach (var index in Enumerable.Range(0, 3))
        {
            var changed = new[] { captured.ExactXnv1.ToArray(), captured.ExactFirstXnd1.ToArray(), captured.ExactSecondXnd1.ToArray() };
            changed[index][^1] ^= 1;
            var hostile = new MailboxStoreReplicaEvidence(changed[0], changed[1], changed[2]);
            Assert.Throws<CryptographicException>(() => { _ = MailboxStoreReplicaEvidenceVerifier.Verify(route.Network, route.NetworkAuthority, route.Route, hostile); });
        }
        var reordered = new MailboxStoreReplicaEvidence(captured.ExactXnv1, captured.ExactSecondXnd1, captured.ExactFirstXnd1);
        Assert.Throws<CryptographicException>(() => { _ = MailboxStoreReplicaEvidenceVerifier.Verify(route.Network, route.NetworkAuthority, route.Route, reordered); });
        var duplicate = new MailboxStoreReplicaEvidence(captured.ExactXnv1, captured.ExactFirstXnd1, captured.ExactFirstXnd1);
        Assert.Throws<CryptographicException>(() => { _ = MailboxStoreReplicaEvidenceVerifier.Verify(route.Network, route.NetworkAuthority, route.Route, duplicate); });
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => MailboxStoreReplicaEvidenceVerifier.CaptureAsync(route, cancelled.Token).AsTask());
        foreach (var bytes in records.Append(expected)) CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        internal async Task AssertInitialStartRejectsMissingDraft(Did2MessagingSessionScope scope, byte[] intent,
            IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport)
        {
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            byte[] original = [], missing = [];
            try
            {
                using (var held = await lease.AcquireAsync(default))
                {
                    using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException();
                    original = root.Use(bytes => bytes.ToArray());
                    using var drafts = ProtectedDid2ContactStartJournal.Decode(original, scope.Network, scope.LocalAccount, scope.Instance);
                    Assert.True(drafts.Entries.Remove(Convert.ToHexString(intent), out var removed)); removed!.Dispose();
                    missing = ProtectedDid2ContactStartJournal.Encode(drafts, scope.Network, scope.LocalAccount, scope.Instance);
                    Assert.True(await storage.CompareExchangeAsync(ProtectedDid2ContactStartJournal.Slot, original, missing)); held.RequireActive();
                }
                var application = await ReadCompleteOrdinaryApplicationProjection(scope);
                try
                {
                    await Assert.ThrowsAsync<CryptographicException>(() => ReplayInitialStartWithoutResolver(intent, grants, transport));
                    Assert.Equal(application, await ReadCompleteOrdinaryApplicationProjection(scope));
                    using var unchanged = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException();
                    Assert.True(unchanged.Use(bytes => Did2MessagingSessionScope.Fixed(bytes, missing)));
                }
                finally { CryptographicOperations.ZeroMemory(application); }
            }
            finally
            {
                if (missing.Length != 0)
                {
                    using var held = await lease.AcquireAsync(default);
                    Assert.True(await storage.CompareExchangeAsync(ProtectedDid2ContactStartJournal.Slot, missing, original)); held.RequireActive();
                }
                CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(missing);
            }
        }

        internal async Task<Deep.Client.Shared.Services.DeepIdV2ContactStartResult> ReplayInitialStartWithoutResolver(byte[] intent,
            IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport)
        {
            var account = ReopenAccount(); var source = Source(account);
            var forbidden = new ClaimOnion(null, []);
            try { return await account.StartContactAsync(nativeMessagingContact!.Candidate.Address, intent, source,
                forbidden, forbidden, grants, transport); }
            finally { Assert.Equal(0, forbidden.Calls); }
        }

        internal Task DeleteContactStoreEvidenceDuringOwnerCallback(Did2MessagingSessionScope scope, byte[] operation) =>
            WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var delete = connection.CreateCommand();
                delete.CommandText = "DELETE FROM mailbox_store_public_evidence WHERE scope_hash=$scope AND operation_id=$op;";
                delete.Parameters.AddWithValue("$scope", scope.Hash.ToArray()); delete.Parameters.AddWithValue("$op", operation);
                Assert.Equal(1, delete.ExecuteNonQuery());
            }, acquireOwnerLease: false);

        internal void ColdReopenReceiverStoreStorage() => Assert.IsType<CompactionDiskFixtureStorage>(peerStorage).Reopen();

        internal async Task<byte[]> ReadRetainedContactStoreRoots(Did2MessagingSessionScope scope)
        {
            var secure = scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage;
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var slot in new[] { ProtectedDid2ContactAcceptJournal.Slot, ProtectedDid2MailboxSendJournal.Slot, ProtectedDid2MailboxGrantJournal.Slot })
            {
                using var root = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException("Fixture Store control root absent.");
                digest.AppendData(root.Use(bytes => SHA256.HashData(bytes)));
            }
            return digest.GetHashAndReset();
        }

        internal async Task AdvanceOriginalStoreEpochForTestAsync(ulong unixSeconds)
        {
            await AdvanceNetworkAsync(expiry: 6_000);
            AuthorSignedEpochAdvance();
            Sample = checked(Sample + unixSeconds - ProofTime);
            ProofTime = unixSeconds; // Original PMA2 expired; a genuinely signed higher epoch is current.
        }
    }
}
