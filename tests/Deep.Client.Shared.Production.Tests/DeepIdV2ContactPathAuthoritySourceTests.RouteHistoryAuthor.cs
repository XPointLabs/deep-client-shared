using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryAuthor_Mode4UsesExactOrdinaryPendingRecovery(int boundary)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, _) = await fixture.PrepareRouteHistoryPair();
        using (Did2TextOutboxTestHooks.Push(hit => { if ((int)hit == boundary) throw new IOException("Interrupted actual route-history authored boundary."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.PrepareOwnedHistory(sender));
        byte[] operation, eventHash;
        using (var raw = await fixture.NativeStorage(sender).ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot))
        using (var journal = raw!.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, sender.Network, sender.LocalAccount, sender.Instance)))
        {
            var entry = Assert.Single(journal.Entries).Value;
            operation = entry.Operation.ToArray(); eventHash = entry.EventHash.ToArray();
        }
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage();
        using var recovered = await fixture.PrepareOwnedHistory(sender);
        Assert.NotNull(recovered); Assert.Equal(operation, recovered!.OperationId.ToArray());
        Assert.Equal(eventHash, SHA256.HashData(recovered.ExactDmc2.Span));
        var message = ApplicationCoreCodec.DecodeDmc2(recovered.ExactDmc2.Span);
        var request = Assert.IsType<ContactRouteHistoryDmc2Payload>(message.ParsedPayload);
        Assert.Equal(DeepIdV2ContactRouteHistoryMode.HistoryRequest, request.Mode);
        Assert.Empty(request.Atoms); Assert.Equal(request.LeftCursor.ToArray(), request.RightCursor.ToArray());
        Assert.InRange(message.ExpiresAtUnixMilliseconds - message.CreatedAtUnixMilliseconds, 1UL, 120_000UL);
        using var exactRetry = await fixture.PrepareOwnedHistory(sender);
        Assert.NotNull(exactRetry); Assert.Equal(recovered.ExactDmc2.ToArray(), exactRetry!.ExactDmc2.ToArray());
        Assert.Equal(operation, await fixture.SelectRouteMaintenance(sender));
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryAuthor_StoreAndOrdinaryRetirementDoNotRemintUnchangedRequest()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await fixture.PrepareRouteHistoryPair();
        using var request = await fixture.PrepareOwnedHistory(sender); Assert.NotNull(request);
        var operation = request!.OperationId.ToArray(); byte[] envelope;
        using (var native = await fixture.SendOwnedRouteUpdate(sender, operation)) envelope = native.ExactEnvelope.ToArray();
        var terminal = new OwnedStoreFixture(fixture, sender, operation, envelope);
        _ = await fixture.DeliverNativeMessage(sender, operation, new OwnedGrantTransport(fixture, ownerOnPrimary: true), terminal);
        Assert.Null(await fixture.PrepareOwnedHistory(sender));
        await fixture.CompactNativeOrdinaryOutbox(sender, default);
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage();
        var before = await fixture.ReadMessagingFloor(sender);
        Assert.Null(await fixture.PrepareOwnedHistory(sender));
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(1, terminal.Calls);
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryAuthor_ServiceReceiveStagesOneCorrelatedResponseAndMaintenanceResumesIt(bool initiatorRequests)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, receiver) = await fixture.PrepareRouteHistoryPair();
        var requester = initiatorRequests ? sender : receiver; var responder = initiatorRequests ? receiver : sender;
        using var request = await fixture.PrepareOwnedHistory(requester); Assert.NotNull(request);
        var requestExact = request!.ExactDmc2.ToArray(); var requestOperation = request.OperationId.ToArray(); byte[] envelope;
        using (var native = await fixture.SendOwnedRouteUpdate(requester, requestOperation)) envelope = native.ExactEnvelope.ToArray();
        using (await fixture.ReceiveOwnedMessage(responder, envelope)) { }
        using var response = await fixture.PrepareOwnedHistory(responder, requestOperation); Assert.NotNull(response);
        var payload = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(response!.ExactDmc2.Span).ParsedPayload);
        DeepIdV2ContactRouteUpdateVerifier.RequireHistoryResponseCorrelation(payload, requestExact);
        Assert.NotEqual(DeepIdV2ContactRouteHistoryMode.HistoryRequest, payload.Mode);
        var operation = response.OperationId.ToArray();
        Assert.Equal(operation, await fixture.SelectHistoryRouteMaintenance(responder));
        var before = await fixture.ReadMessagingFloor(responder);
        using (await fixture.ReceiveOwnedMessage(responder, envelope)) { }
        using var retry = await fixture.PrepareOwnedHistory(responder, requestOperation);
        Assert.NotNull(retry); Assert.Equal(response.ExactDmc2.ToArray(), retry!.ExactDmc2.ToArray());
        Assert.Equal(operation, retry.OperationId.ToArray());
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(responder)).Exact.ToArray());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryAuthor_CompletedPreNativeStopAndRetirementPermitNewResponseWithoutResurrection()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, receiver) = await fixture.PrepareRouteHistoryPair();
        using var request = await fixture.PrepareOwnedHistory(sender); Assert.NotNull(request);
        var requestOperation = request!.OperationId.ToArray(); byte[] envelope;
        using (var native = await fixture.SendOwnedRouteUpdate(sender, requestOperation)) envelope = native.ExactEnvelope.ToArray();
        using (Did2TextOutboxTestHooks.Push(point =>
            { if (point == Did2TextOutboxFailpoint.AfterStable) throw new IOException("Response draft retained before native encryption."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.ReceiveOwnedMessage(receiver, envelope));
        using var stopped = await fixture.PrepareOwnedHistory(receiver, requestOperation); Assert.NotNull(stopped);
        var stoppedOperation = stopped!.OperationId.ToArray(); var before = await fixture.ReadMessagingFloor(receiver);
        await fixture.CancelNativeMessagingWork(receiver, stoppedOperation);
        await fixture.RequireRetiredStoppedPayload(receiver, stoppedOperation);
        fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        using var replacement = await fixture.PrepareOwnedHistory(receiver, requestOperation); Assert.NotNull(replacement);
        Assert.NotEqual(stoppedOperation, replacement!.OperationId.ToArray());
        Assert.NotEqual(stopped.LogicalMessageId.ToArray(), replacement.LogicalMessageId.ToArray());
        Assert.Equal(stopped.SenderSequence + 1, replacement.SenderSequence);
        var payload = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(replacement.ExactDmc2.Span).ParsedPayload);
        DeepIdV2ContactRouteUpdateVerifier.RequireHistoryResponseCorrelation(payload, request.ExactDmc2.Span);
        await Assert.ThrowsAsync<IOException>(() => fixture.SendOwnedRouteUpdate(receiver, stoppedOperation));
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
    }

    private sealed partial class Fixture
    {
        internal async Task<(Did2MessagingSessionScope Sender, Did2MessagingSessionScope Receiver)> PrepareRouteHistoryPair()
        {
            var (complete, hello, init, _, _) = await PrepareNativeHelloCompletion(Bytes(32, 0x9a));
            using var initial = await complete(Accounts);
            using (await CompleteReceiver(initial.ExactDph2.ToArray())) { }
            var sender = await EnsureSenderMessaging(init, hello); var receiver = await EnsureReceiverMessaging(initial.ExactDph2.ToArray());
            using (var accept = await PrepareOwnedContactAccept(receiver, Bytes(32, 0x9b)))
            using (var native = await SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
            using (await ReceiveOwnedMessage(sender, native.ExactEnvelope.ToArray())) { }
            return (sender, receiver);
        }

        internal Task<DirectTextOutboxEntry?> PrepareOwnedHistory(Did2MessagingSessionScope scope, ReadOnlyMemory<byte> requestOperation = default)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            return account.PrepareOwnRouteHistoryCommandAsync(scope, !requestOperation.IsEmpty, requestOperation, source, default);
        }

        internal async Task<byte[]?> SelectHistoryRouteMaintenance(Did2MessagingSessionScope scope)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            var pair = await source.VerifyForOwnMessagingAsync(account, scope, default);
            var folder = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var owner = new ProtectedDeepIdV2AccountOwner(NativeStorage(scope),
                new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock")),
                Path.Combine(folder, "deep-store-v2-account.dsv2"), Network, 1);
            return await owner.SelectOwnRouteMaintenanceAsync(1_000, pq, scope, pair.Own, pair.Peer, source, default);
        }
    }
}
