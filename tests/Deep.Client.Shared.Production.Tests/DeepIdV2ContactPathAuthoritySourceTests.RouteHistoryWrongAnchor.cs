using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryPaged_ActualWrongAnchorRetainsOriginalWithoutAppAckOrEligibility(int mode)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver, accepted) = await fixture.PrepareWrongAnchorPair();
        byte[] correct;
        if (mode == 4)
        {
            using var request = await fixture.PrepareOwnedHistory(sender); Assert.NotNull(request);
            correct = request!.ExactDmc2.ToArray();
        }
        else
        {
            await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
            using var command = await fixture.CreateOwnedRouteUpdate(sender); correct = command.ExactDmc2.ToArray();
        }
        var original = ApplicationCoreCodec.DecodeDmc2(correct);
        var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(original.ParsedPayload);
        var payload = page.CanonicalBytes.ToArray(); payload[74] = checked((byte)mode);
        if (mode == 2)
        {
            payload = payload[..DeepIdV2ContactRouteHistoryCodec.HeaderBytes]; payload[75] = 0;
            page.RightCursor.Span.CopyTo(payload.AsSpan(80));
            page.Atoms.Last(atom => atom.IsCompleted).ExactCompletedXir1V2.Span.CopyTo(payload.AsSpan(304));
        }
        var otherAnchor = mode == 4 ? await fixture.ActualInitialHelloHash(sender) : SHA256.HashData(accepted);
        otherAnchor.CopyTo(payload, 40);
        var hostile = Fixture.ReplaceHostileControlPayload(original, payload);
        Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(hostile).ParsedPayload);
        var envelope = await fixture.EmitHostileNativeRoute(sender, hostile);
        var before = await fixture.ReadMessagingFloor(receiver);
        var appBefore = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReceivePagedOwnerOnly(receiver, envelope));
        var retained = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(before.Ordinal + 1, retained.Ordinal); Assert.Equal(before.RatchetGeneration + 1, retained.RatchetGeneration);
        Assert.Equal(before.Status, retained.Status);
        Assert.Equal(appBefore, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        var grants = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var terminal = new OwnedReadTerminal(fixture, envelope);
        // A genuine Retrieve prepares its transport request and captures the
        // encrypted page before semantic receive. Baseline that completed
        // transport work separately from the rejected application handoff.
        await fixture.CaptureWrongAnchorMailboxPage(receiver, grants, terminal, envelope);
        Assert.Equal(retained.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        var capturedApp = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
        Assert.Equal(1, terminal.RetrieveCalls);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
        Assert.Equal(1, terminal.RetrieveCalls);
        Assert.Equal(0, terminal.AckCalls);
        Assert.Equal(capturedApp, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        await fixture.ArchiveEntireEligibleSuffix(receiver);
        await fixture.RequireWrongAnchorArchiveReplay(receiver, envelope, hostile, accepted);
        Assert.Equal(capturedApp, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReceivePagedOwnerOnly(receiver, envelope));
        Assert.Equal(retained.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(capturedApp, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
    }

    private sealed partial class Fixture
    {
        internal static byte[] ReplaceHostileControlPayload(ParsedDmc2 original, byte[] payload) => ReplaceControlPayload(original, payload);
        internal async Task CaptureWrongAnchorMailboxPage(Did2MessagingSessionScope scope,
            OwnedGrantTransport grants, OwnedReadTerminal terminal, byte[] envelope)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(account, default);
            using var captured = await PagedOwner(scope).RetrieveOwnMailboxAsync(CurrentProofTime, pq, source, own, grants, terminal, default);
            Assert.Equal(envelope, Assert.Single(captured.ReadPage().Items).Envelope.Ciphertext.ToArray());
            using var read = await ReadPeerMailboxReads(own: scope.IsInitiator);
            Assert.Equal(4, read.Phase);
        }
        internal async Task<(Did2MessagingSessionScope Sender, Did2MessagingSessionScope Receiver, byte[] Accept)> PrepareWrongAnchorPair()
        {
            await SeedShortPermanentProposalAsync(validitySeconds: 800);
            var (complete, hello, init, _, _) = await PrepareNativeHelloCompletion(Bytes(32, 0xe8));
            using var initial = await complete(Accounts);
            using (await CompleteReceiver(initial.ExactDph2.ToArray())) { }
            var sender = await EnsureSenderMessaging(init, hello); var receiver = await EnsureReceiverMessaging(initial.ExactDph2.ToArray());
            using var accept = await PrepareOwnedContactAccept(receiver, Bytes(32, 0xe9));
            using (var native = await SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
            using (await ReceiveOwnedMessage(sender, native.ExactEnvelope.ToArray())) { }
            TrackMailboxDispatchClock(); return (sender, receiver, accept.ExactDmc2.ToArray());
        }
        internal async Task<byte[]> ActualInitialHelloHash(Did2MessagingSessionScope scope)
        {
            byte[] result = []; var floor = await ReadMessagingFloor(scope);
            await WithRouteReadSql(scope, (sql, _) =>
            {
                var initial = sql.ReadVerifiedActiveInitialEvents(floor);
                try { result = SHA256.HashData(initial.Hello); }
                finally { CryptographicOperations.ZeroMemory(initial.SessionInit); CryptographicOperations.ZeroMemory(initial.Hello); }
            });
            return result;
        }

        // A malicious peer uses real disposable TRS/crypto and commits its real
        // native plan. It deliberately bypasses its own application author
        // facade; no fabricated receiver qualification or permission is used.
        internal async Task<byte[]> EmitHostileNativeRoute(Did2MessagingSessionScope scope, byte[] exact)
        {
            var folder = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var accountLease = new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock"));
            using var held = await accountLease.AcquireAsync(default);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenRegisteredMessagingUnderLeaseAsync(NativeStorage(scope),
                Path.Combine(folder, "deep-store-v2-account.dsv2"), scope.Network.ToArray(), scope.LocalAccount.ToArray(), scope, default);
            var floor = await opened.Custody.ReconcileAsync(default); var operation = RandomNumberGenerator.GetBytes(32);
            var captured = await opened.WithSqlAsync(sql =>
            {
                var state = sql.ReadVerifiedTransitionState(floor, operation, [], out var context); return (State: state, Context: context);
            }, default);
            using var state = captured.State;
            using var prepared = state.Use(bytes => ExactDpe2DurableTransactionProducer.PrepareSend(bytes, captured.Context, exact, scope.Network, operation));
            state.Dispose();
            using var sent = await prepared.CommitAsync(new HostileNativeRouteAuthority(opened, scope, floor, SHA256.HashData(exact)));
            return sent.TakeExactEnvelope();
        }

        internal async Task RequireWrongAnchorArchiveReplay(Did2MessagingSessionScope scope, byte[] envelope, byte[] exact, byte[] accepted)
        {
            var operation = Deep.Protocol.MessagingWire.Dpe2Codec.Decode(envelope).OperationId;
            var archive = await Did2MessagingArchiveRoot.ReadRegisteredAsync(NativeStorage(scope), scope, default);
            await WithActiveNativeComparators(scope, (full, active, connection, floor) =>
            {
                full.BindOpenedFloor(floor); active.BindOpenedFloor(floor);
                using var selected = active.ReadVerifiedOperation(floor, operation.Span); Assert.NotNull(selected);
                Assert.Equal(3, selected!.RouteProcessing[0]);
                using var payload = selected.OwnAuthenticatedDmc2(); Assert.True(payload.Use(bytes => bytes.SequenceEqual(exact)));
                var authored = new Dictionary<ulong, ReadOnlyMemory<byte>>();
                foreach (var outgoing in full.ReadVerifiedOutgoingEvents(floor, default))
                {
                    using (outgoing) { Assert.Equal(SHA256.HashData(accepted), outgoing.EventHash.ToArray()); authored.Add(outgoing.Ordinal, accepted); }
                }
                var replay = full.VerifyArchiveReplayBatch(archive, Did2MessagingArchiveReducer.Empty(scope), 0, 0, authored);
                Assert.True(replay.Complete);
                var tree = full.VerifyCompleteArchiveTree(archive);
                full.RequireFinalArchiveAudit(archive, replay.Reducer, replay.Count, replay.Families, tree);
                Assert.Equal(0UL, tree[6]); Assert.Equal(0UL, tree[7]);
            });
        }
    }

    private sealed class HostileNativeRouteAuthority(OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        Did2MessagingFloor floor, byte[] eventHash) : IExactDpe2DurableTransactionAuthority
    {
        public async ValueTask<ExactDpe2DurableCommitReceipt> CommitAsync(ExactDpe2DurablePersistencePlan plan,
            ExactDpe2DurableCommitCompletion completion, CancellationToken cancellationToken = default)
        {
            using var mutation = OwnedDid2MessagingMutation.Ratchet(scope, floor, plan, eventHash);
            _ = await opened.Custody.CommitOwnedAsync(mutation, cancellationToken);
            return completion.Complete(ExactDpe2DurableCommitDisposition.Committed);
        }
    }
}
