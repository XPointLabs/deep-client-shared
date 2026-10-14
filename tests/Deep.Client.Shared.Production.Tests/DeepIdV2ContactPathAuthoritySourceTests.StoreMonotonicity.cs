using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("initial")] [InlineData("accept")] [InlineData("ordinary")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoreMonotonicity_AdvancedSqlStatePreservesIndependentStoreAcrossColdExpiryAndCleanup(string kind)
    {
        // Real PQ/native/SQLCipher/signature Store producer and owner consumers.
        // Delivered is ONLY a repository-contract input here, not an authenticated
        // application-ACK producer or physical recipient-delivery qualification.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareStoreMonotonicityCase(kind);
        var stored = await test.Deliver();
        Assert.True(stored.IngressDispatched);
        fixture.AdvanceSyntheticMailboxClockPast(test.Transport.DurableTimeForFixture);
        await fixture.AdvanceStoreRepositoryStateForContractTest(test.Scope, test.Operation);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var roots = await fixture.ReadRetainedContactStoreRoots(test.Scope);
        try
        {
            await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
            if (test.Scope.IsInitiator) fixture.ColdReopenCompactionStorage();
            else fixture.ColdReopenReceiverStoreStorage();
            var cached = await test.Deliver();
            Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
            Assert.Equal(stored.Disposition, cached.Disposition);
            Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(roots, await fixture.ReadRetainedContactStoreRoots(test.Scope));

            // A higher SQL state still cannot substitute for original signatures,
            // public key/view custody or the independent coordinator statement.
            await fixture.AssertCompactedStoreRejectsChangedPublicEvidence(test.Scope, test.Deliver);
            await fixture.AssertCompactedStoreRejectsMissingOrChangedCoordinatorStatement(test.Scope, test.Deliver);
            Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(roots, await fixture.ReadRetainedContactStoreRoots(test.Scope));

            if (kind == "ordinary") await fixture.CompactNativeOrdinaryOutbox(test.Scope, default);
            else await fixture.RetireCompletedContactSend(test);
            if (test.Scope.IsInitiator) fixture.ColdReopenCompactionStorage();
            else fixture.ColdReopenReceiverStoreStorage();
            var afterCleanup = await test.Deliver();
            Assert.False(afterCleanup.IngressDispatched); Assert.Equal(stored.Cursor, afterCleanup.Cursor);
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(1, test.Grants.Calls); Assert.Equal(1, test.Transport.Calls);
            using var sends = await fixture.ReadMailboxSends(own: test.Scope.IsInitiator);
            Assert.Empty(sends.Entries); Assert.Single(sends.Floors);
        }
        finally { foreach (var bytes in new[] { native, application, roots }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private sealed partial class Fixture
    {
        internal async Task<CompletedContactSendCase> PrepareStoreMonotonicityCase(string kind)
        {
            if (kind != "ordinary") return await PrepareCompletedContactSendCase(kind == "initial");
            var (complete, hello, init, _, _) = await PrepareNativeHelloCompletion(Bytes(32, 0x51));
            using var initial = await complete(Accounts);
            using (var received = await CompleteReceiver(initial.ExactDph2.ToArray())) { }
            var sender = await EnsureSenderMessaging(init, hello);
            var receiver = await EnsureReceiverMessaging(initial.ExactDph2.ToArray());
            using (var accept = await PrepareOwnedContactAccept(receiver, Bytes(32, 0x52)))
            using (var sent = await SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
            using (var received = await ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
            using var text = await CreateOwnedText(sender, "Store remains an independent monotonic fact");
            var operation = text.OperationId.ToArray();
            using var committed = await SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
            TrackMailboxDispatchClock();
            var grants = new OwnedGrantTransport(this, ownerOnPrimary: true);
            var transport = new OwnedStoreFixture(this, sender, operation, committed.ExactEnvelope.ToArray());
            return new(sender, operation, [], grants, transport, () => DeliverNativeMessage(sender, operation, grants, transport));
        }

        internal async Task AdvanceStoreRepositoryStateForContractTest(Did2MessagingSessionScope scope, byte[] operation)
        {
            var accountDirectory = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var secure = scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage;
            var lease = new DeepIdV2AccountFileLease(Path.Combine(accountDirectory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(secure,
                Path.Combine(accountDirectory, "deep-store-v2-account.dsv2"), scope, held, lease, default);
            var evidence = await application.RequireStorePublicEvidenceAsync(scope, operation, operation, default);
            var account = OutboxAccountScope.FromBytes(evidence.AccountScope.Span);
            var logical = OutboxLogicalId.FromBytes(evidence.Logical.Span);
            var read = await application.ReadTransportOutboxAsync(account, logical, default);
            Assert.Equal(TransportOutboxReadResult.Found, read.Result);
            var before = Assert.IsType<TransportOutboxItemSnapshot>(read.Item);
            Assert.Equal(TransportOutboxState.Durable, before.State);
            var quorum = Assert.Single(before.Attempts).GetEvidenceCopy();
            var exact = before.GetCiphertextBundleCopy();
            try
            {
                // Deliberately opaque input accepted by the storage contract.
                // The historical Store reader must not authenticate or project
                // recipient delivery from this byte, or use it instead of quorum.
                var acknowledgement = RecipientDeviceAcknowledgement.Create(logical, before.DedupMaterial,
                    new byte[] { 1 }, before.TransitionedAt);
                Assert.Equal(TransportOutboxCommitResult.Applied, await application.ApplyTransportOutboxTransitionAsync(
                    TransportOutboxTransition.Delivered(account, logical, before.Revision, acknowledgement,
                        OutboxTransitionReason.RecipientAcknowledged, before.TransitionedAt), default));
                var advanced = (await application.ReadTransportOutboxAsync(account, logical, default)).Item!;
                Assert.Equal(TransportOutboxState.Delivered, advanced.State);
                Assert.Equal(exact, advanced.GetCiphertextBundleCopy());
                Assert.Equal(quorum, Assert.Single(advanced.Attempts).GetEvidenceCopy());
                held.RequireActive();
            }
            finally { CryptographicOperations.ZeroMemory(quorum); CryptographicOperations.ZeroMemory(exact); }
        }
    }
}
