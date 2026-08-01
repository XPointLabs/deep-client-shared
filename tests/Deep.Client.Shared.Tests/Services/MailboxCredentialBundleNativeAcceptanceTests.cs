using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Tests.Services;

public sealed partial class MailboxCredentialBundleImporterTests
{
    [Fact]
    public async Task NativeComposition_RejectsAuthorityImportedFromAnotherDatabase()
    {
        using var firstFixture = Fixture.Create();
        using var secondFixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        var clock = new MutableTimeProvider(Now);
        using var firstStore = new SqliteSessionStore(firstFixture.DatabasePath);
        using var secondStore = new SqliteSessionStore(secondFixture.DatabasePath);
        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            firstStore,
            identity,
            firstFixture.AndroidOptions with { TimeProvider = clock },
            MailboxInfrastructureOwnership.UserManaged);

        Assert.Throws<InvalidOperationException>(() =>
            new NativeMau2MailboxTransport(
                ClientFeatureFlags.Defaults with
                {
                    ClientMailboxAdapterEnabled = true
                },
                imported.Activation,
                new ScriptedRetrieveIngress(clock),
                secondStore,
                new PinnedClientMailboxReceiptVerifier(
                    new SodiumClientMailboxReceiptCrypto()),
                imported.DecodePolicies,
                imported.Authority,
                _ => imported.SelfSelector,
                timeProvider: clock));
    }

    [Fact]
    public async Task ImportedNativePreparedDispatch_WaitsForItsPublicationCoordinator()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        var clock = new MutableTimeProvider(Now);
        using var store = new SqliteSessionStore(fixture.DatabasePath);
        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            store,
            identity,
            fixture.AndroidOptions with { TimeProvider = clock },
            MailboxInfrastructureOwnership.UserManaged);
        var ingress = new ScriptedRetrieveIngress(clock);
        using var transport = new NativeMau2MailboxTransport(
            ClientFeatureFlags.Defaults with { ClientMailboxAdapterEnabled = true },
            imported.Activation,
            ingress,
            store,
            new PinnedClientMailboxReceiptVerifier(
                new SodiumClientMailboxReceiptCrypto()),
            imported.DecodePolicies,
            imported.Authority,
            sessionId => sessionId == imported.LocalSessionId
                ? imported.SelfSelector
                : throw new InvalidOperationException(
                    "The acceptance transport has no selector for another identity."),
            timeProvider: clock);
        IReadOnlyList<IPreparedMailboxAuthenticatedSend> prepared;
        using (var signer = new AcceptanceMailboxSigner(identity))
        {
            prepared = await transport.PrepareScopedMailboxBatchAsync(
                signer,
                [
                    new MailboxAuthenticatedSendTarget(
                        new OutboundMessageEnvelope(
                            identity.SessionId,
                            fixture.BobSessionId,
                            Dpe1(Bytes(64, 0xc2)),
                            [],
                            Now,
                            Now.AddMinutes(5),
                            new MessageId("publication-coordinator-barrier")),
                        imported.PeerSelector,
                        imported.Authority)
                ]);
        }

        var coordinator = MailboxRuntimePolicyCoordinator.For(
            store.CanonicalStateIdentity,
            imported.PeerSelector.IssuerContext.Span);
        using var publication = await coordinator.AcquirePublicationAsync();
        var dispatch = transport.SendPreparedMailboxAuthenticatedAsync(
            Assert.Single(prepared));
        var early = await Task.WhenAny(
            ingress.StoreEntered.Task,
            Task.Delay(TimeSpan.FromMilliseconds(250)));
        Assert.NotSame(ingress.StoreEntered.Task, early);
        Assert.Equal(0, ingress.StoreCalls);
        Assert.False(dispatch.IsCompleted);

        publication.Dispose();
        await ingress.StoreEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<InvalidOperationException>(() => dispatch);
        Assert.Equal(1, ingress.StoreCalls);
    }

    [Fact]
    public async Task ImportedSqliteCredentials_DriveNativeRetrieve_AndExpiredRevocationsBlockBeforeIngress()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        var clock = new MutableTimeProvider(Now);
        var options = fixture.AndroidOptions with { TimeProvider = clock };
        using var store = new SqliteSessionStore(fixture.DatabasePath);

        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            store,
            identity,
            options,
            MailboxInfrastructureOwnership.UserManaged);
        var ingress = new ScriptedRetrieveIngress(clock);
        using var transport = new NativeMau2MailboxTransport(
            ClientFeatureFlags.Defaults with { ClientMailboxAdapterEnabled = true },
            imported.Activation,
            ingress,
            store,
            new PinnedClientMailboxReceiptVerifier(
                new SodiumClientMailboxReceiptCrypto()),
            imported.DecodePolicies,
            imported.Authority,
            sessionId => sessionId == imported.LocalSessionId
                ? imported.SelfSelector
                : throw new InvalidOperationException(
                    "The acceptance transport has no selector for another identity."),
            timeProvider: clock);

        var first = await transport.RetrieveAuthenticatedAsync(
            identity,
            cursor: null,
            limit: 1);

        var entry = Assert.Single(first.Entries);
        Assert.Equal(1, ingress.RetrieveCalls);
        Assert.NotNull(ingress.LastCanonicalRequest);
        Assert.True(transport.TryDecodeInboxEntry(
            entry,
            imported.LocalSessionId,
            out var envelope));
        Assert.StartsWith("dpe1:", envelope.Body, StringComparison.Ordinal);
        using (var signer = new AcceptanceMailboxSigner(identity))
        {
            await transport.AcknowledgeOpaqueMailboxInboxAsync(
                signer,
                entry.ServerHash);
        }
        Assert.Equal(1, ingress.AcknowledgeCalls);
        IReadOnlyList<IPreparedMailboxAuthenticatedSend> prepared;
        using (var signer = new AcceptanceMailboxSigner(identity))
        {
            prepared = await transport.PrepareScopedMailboxBatchAsync(
                signer,
                [
                    new MailboxAuthenticatedSendTarget(
                        new OutboundMessageEnvelope(
                            identity.SessionId,
                            fixture.BobSessionId,
                            Dpe1(Bytes(64, 0xc1)),
                            [],
                            Now,
                            Now.AddMinutes(5),
                            new MessageId("acceptance-expired-revocations")),
                        imported.PeerSelector,
                        imported.Authority)
                ]);
        }
        var preparedSend = Assert.Single(prepared);
        Assert.Equal((ulong)Now.ToUnixTimeSeconds(),
            imported.DecodePolicies.GetCurrent().NowUnixSeconds);

        clock.Set(Now.AddMinutes(21));
        Assert.Equal((ulong)Now.AddMinutes(21).ToUnixTimeSeconds(),
            imported.DecodePolicies.GetCurrent().NowUnixSeconds);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            transport.RetrieveAuthenticatedAsync(
                identity,
                cursor: null,
                limit: 1));
        Assert.Equal(1, ingress.RetrieveCalls);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            transport.SendPreparedMailboxAuthenticatedAsync(preparedSend));
        Assert.Equal(0, ingress.StoreCalls);
    }

    [Fact]
    public async Task NativeBatch_WithMissingFinalCredential_PersistsAndDispatchesNothing()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        var clock = new MutableTimeProvider(Now);
        var options = fixture.AndroidOptions with { TimeProvider = clock };
        using var store = new SqliteSessionStore(fixture.DatabasePath);
        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            store,
            identity,
            options,
            MailboxInfrastructureOwnership.UserManaged);
        var ingress = new ScriptedRetrieveIngress(clock);
        using var transport = new NativeMau2MailboxTransport(
            ClientFeatureFlags.Defaults with { ClientMailboxAdapterEnabled = true },
            imported.Activation,
            ingress,
            store,
            new PinnedClientMailboxReceiptVerifier(
                new SodiumClientMailboxReceiptCrypto()),
            imported.DecodePolicies,
            imported.Authority,
            sessionId => sessionId == imported.LocalSessionId
                ? imported.SelfSelector
                : throw new InvalidOperationException(
                    "The acceptance transport has no selector for another identity."),
            timeProvider: clock);
        var missing = new MailboxCredentialSelector(
            imported.PeerSelector.AccountScope,
            MailboxCredentialScopeKind.Peer,
            Bytes(32, 0xe1),
            imported.PeerSelector.IssuerContext.Span);
        var valid = Target(imported.PeerSelector, 0xd1, "batch-valid");
        var invalid = Target(missing, 0xd2, "batch-missing-credential");

        using var signer = new AcceptanceMailboxSigner(identity);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            transport.PrepareScopedMailboxBatchAsync(signer, [valid, invalid]));

        Assert.Equal(0, ingress.StoreCalls);
        Assert.Equal(0, CountRows(fixture.DatabasePath, "mailbox_prepared_batches"));
        Assert.Equal(0, CountRows(fixture.DatabasePath, "mailbox_prepared_batch_targets"));
        Assert.Equal(0, CountRows(fixture.DatabasePath, "mailbox_replay_counters"));
        Assert.Equal(0, CountRows(fixture.DatabasePath, "transport_outbox_items"));

        MailboxAuthenticatedSendTarget Target(
            MailboxCredentialSelector selector,
            byte fill,
            string id) => new(
            new OutboundMessageEnvelope(
                identity.SessionId,
                fixture.BobSessionId,
                Dpe1(Bytes(64, fill)),
                [],
                Now,
                Now.AddMinutes(5),
                new MessageId(id)),
            selector,
            imported.Authority);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ImportedNative_RejectsPoisonedMeo1_AndE2eeContinuesToValidEntry(
        int tamperMode)
    {
        using var fixture = Fixture.Create();
        using var localIdentity = new SessionIdentityProvider(AlicePhrase);
        using var remoteIdentity = new SessionIdentityProvider(BobPhrase);
        var clock = new MutableTimeProvider(Now);
        using var store = new SqliteSessionStore(fixture.DatabasePath);
        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            store,
            localIdentity,
            fixture.AndroidOptions with { TimeProvider = clock },
            MailboxInfrastructureOwnership.UserManaged);
        var innerDpe1 = remoteIdentity.CreateEnvelopeCodec().EncryptContent(
            new E2eeContent(
                E2eeContentKind.Message,
                new MessageId("meo1-valid-following"),
                ConversationKind.OneToOne,
                ConversationId.ForOneToOne(localIdentity.SessionId),
                remoteIdentity.SessionId,
                localIdentity.SessionId,
                Now,
                Now.AddDays(1),
                null,
                "valid after poisoned MEO1",
                []),
            localIdentity.SessionId);
        var ingress = new ScriptedRetrieveIngress(clock, innerDpe1);
        using var native = new NativeMau2MailboxTransport(
            ClientFeatureFlags.Defaults with { ClientMailboxAdapterEnabled = true },
            imported.Activation,
            ingress,
            store,
            new PinnedClientMailboxReceiptVerifier(
                new SodiumClientMailboxReceiptCrypto()),
            imported.DecodePolicies,
            imported.Authority,
            sessionId => sessionId == imported.LocalSessionId
                ? imported.SelfSelector
                : throw new InvalidOperationException(
                    "The acceptance transport has no selector for another identity."),
            timeProvider: clock);
        var canonical = Assert.Single((await native.RetrieveAuthenticatedAsync(
            localIdentity,
            cursor: null,
            limit: 1)).Entries);
        var poisoned = DurableInboxWireEntry.CreateBounded(
            canonical.ServerHash,
            canonical.StorageTimestamp,
            TamperMeo1(canonical.WirePayload, tamperMode));
        var validFollowing = DurableInboxWireEntry.CreateBounded(
            WithCursor(canonical.ServerHash, 2),
            checked(canonical.StorageTimestamp + 1),
            canonical.WirePayload);

        Assert.False(native.TryDecodeInboxEntry(
            poisoned,
            localIdentity.SessionId,
            out _));

        var batchTransport = new InjectedBatchNativeTransport(
            native,
            [poisoned, validFollowing]);
        using var e2ee = new E2eeClientTransport(
            batchTransport,
            _ => Task.FromResult<string?>(AlicePhrase),
            new FrozenClock(Now),
            store,
            new DirectP2pMailboxDeliveryPolicy());
        var message = Assert.Single(
            await e2ee.ReceiveAsync(localIdentity.SessionId));
        Assert.Equal(remoteIdentity.SessionId, message.Sender);
        Assert.Equal("valid after poisoned MEO1", message.Body);
        Assert.Equal(validFollowing.ServerHash, message.ServerHash);
        Assert.Equal(1, batchTransport.RetrieveCalls);
    }

    private static string TamperMeo1(string wirePayload, int tamperMode)
    {
        var meo1 = Convert.FromBase64String(wirePayload);
        switch (tamperMode)
        {
            case 0:
                meo1[0] ^= 1;
                break;
            case 1:
                meo1[5] = 1;
                break;
            case 2:
                meo1[96] ^= 1;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(tamperMode));
        }
        return Convert.ToBase64String(meo1);
    }

    private static string WithCursor(string itemHandle, ulong cursor)
    {
        var digestSeparator = itemHandle.LastIndexOf(':');
        Assert.True(digestSeparator > 0);
        return $"mau2-item-v1:{cursor:x16}:{itemHandle[(digestSeparator + 1)..]}";
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task E2eeOverNative_TrustsAuthenticatedInnerSender_NotSyntheticOuterMetadata(
        int tamperMode)
    {
        using var fixture = Fixture.Create();
        using var localIdentity = new SessionIdentityProvider(AlicePhrase);
        using var remoteIdentity = new SessionIdentityProvider(BobPhrase);
        var clock = new MutableTimeProvider(Now);
        var options = fixture.AndroidOptions with { TimeProvider = clock };
        using var store = new SqliteSessionStore(fixture.DatabasePath);
        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            store,
            localIdentity,
            options,
            MailboxInfrastructureOwnership.UserManaged);
        var innerDpe1 = remoteIdentity.CreateEnvelopeCodec().EncryptContent(
            new E2eeContent(
                E2eeContentKind.Message,
                new MessageId("native-inner-authenticity"),
                ConversationKind.OneToOne,
                ConversationId.ForOneToOne(localIdentity.SessionId),
                remoteIdentity.SessionId,
                localIdentity.SessionId,
                Now,
                Now.AddDays(1),
                null,
                "authenticated inner sender",
                []),
            localIdentity.SessionId);
        if (tamperMode == 1)
        {
            // DPE1 fixed header starts with 8 bytes before its signed sender Session ID.
            innerDpe1[9] ^= 1;
        }
        else if (tamperMode == 2)
        {
            // The detached Ed25519 signature is the final fixed-width DPE1 field.
            innerDpe1[^1] ^= 1;
        }

        var ingress = new ScriptedRetrieveIngress(clock, innerDpe1);
        using var native = new NativeMau2MailboxTransport(
            ClientFeatureFlags.Defaults with { ClientMailboxAdapterEnabled = true },
            imported.Activation,
            ingress,
            store,
            new PinnedClientMailboxReceiptVerifier(
                new SodiumClientMailboxReceiptCrypto()),
            imported.DecodePolicies,
            imported.Authority,
            sessionId => sessionId == imported.LocalSessionId
                ? imported.SelfSelector
                : throw new InvalidOperationException(
                    "The acceptance transport has no selector for another identity."),
            timeProvider: clock);
        using var e2ee = new E2eeClientTransport(
            native,
            _ => Task.FromResult<string?>(AlicePhrase),
            new FrozenClock(Now),
            store,
            new DirectP2pMailboxDeliveryPolicy());

        var received = await e2ee.ReceiveAsync(localIdentity.SessionId);

        if (tamperMode == 0)
        {
            var message = Assert.Single(received);
            Assert.Equal(remoteIdentity.SessionId, message.Sender);
            Assert.Equal(localIdentity.SessionId, message.Recipient);
            Assert.Equal("authenticated inner sender", message.Body);
            Assert.NotEqual(localIdentity.SessionId, message.Sender);
        }
        else
        {
            Assert.Empty(received);
        }
        Assert.Equal(1, ingress.RetrieveCalls);
    }

    [Fact]
    public async Task NativeExternalCursor_SurvivesRestart_WhileInternalContinuationStaysPrivate()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        var clock = new MutableTimeProvider(Now);
        var options = fixture.AndroidOptions with { TimeProvider = clock };
        var ingress = new ScriptedCursorIngress(clock);
        ImportedMailboxRuntimeMaterial imported;
        string externalCursor;

        using (var store = new SqliteSessionStore(fixture.DatabasePath))
        {
            imported = await MailboxCredentialBundleImporter.ImportAsync(
                store,
                identity,
                options,
                MailboxInfrastructureOwnership.UserManaged);
            using var native = Native(store);
            var first = await native.RetrieveAuthenticatedAsync(
                identity,
                cursor: null,
                limit: 1);
            var entry = Assert.Single(first.Entries);
            externalCursor = Assert.IsType<string>(first.NextCursor);
            Assert.Equal(entry.ServerHash, externalCursor);
            using var signer = new AcceptanceMailboxSigner(identity);
            await native.AcknowledgeOpaqueMailboxInboxAsync(
                signer,
                entry.ServerHash);
            Assert.Equal(1, ingress.AcknowledgeCalls);
        }

        using (var reopened = new SqliteSessionStore(fixture.DatabasePath))
        using (var native = Native(reopened))
        {
            await Assert.ThrowsAsync<ArgumentException>(() =>
                native.RetrieveAuthenticatedAsync(
                    identity,
                    externalCursor + "00",
                    limit: 1));
            Assert.Equal(1, ingress.RetrieveCalls);

            var terminal = await native.RetrieveAuthenticatedAsync(
                identity,
                externalCursor,
                limit: 1);
            Assert.Empty(terminal.Entries);
            Assert.Equal(externalCursor, terminal.NextCursor);
        }

        Assert.Equal(2, ingress.RetrieveCalls);
        Assert.Equal(1, ingress.AcknowledgeCalls);
        Assert.Equal(0UL, ingress.Requests[0].AfterCursor);
        Assert.Empty(ingress.Requests[0].ContinuationToken.ToArray());
        Assert.Equal(1UL, ingress.Requests[1].AfterCursor);
        Assert.Equal(ScriptedCursorIngress.Token,
            ingress.Requests[1].ContinuationToken.ToArray());

        NativeMau2MailboxTransport Native(SqliteSessionStore store) => new(
            ClientFeatureFlags.Defaults with { ClientMailboxAdapterEnabled = true },
            imported.Activation,
            ingress,
            store,
            new PinnedClientMailboxReceiptVerifier(
                new SodiumClientMailboxReceiptCrypto()),
            imported.DecodePolicies,
            imported.Authority,
            sessionId => sessionId == imported.LocalSessionId
                ? imported.SelfSelector
                : throw new InvalidOperationException(
                    "The acceptance transport has no selector for another identity."),
            timeProvider: clock);
    }

    [Fact]
    public async Task E2eeGenericCursor_SurvivesNativeAckAndFullRestart_WithoutReplay()
    {
        using var fixture = Fixture.Create();
        using var localIdentity = new SessionIdentityProvider(AlicePhrase);
        using var remoteIdentity = new SessionIdentityProvider(BobPhrase);
        var clock = new MutableTimeProvider(Now);
        var innerDpe1 = remoteIdentity.CreateEnvelopeCodec().EncryptContent(
            new E2eeContent(
                E2eeContentKind.Message,
                new MessageId("generic-cursor-restart"),
                ConversationKind.OneToOne,
                ConversationId.ForOneToOne(localIdentity.SessionId),
                remoteIdentity.SessionId,
                localIdentity.SessionId,
                Now,
                Now.AddDays(1),
                null,
                "one delivery across restart",
                []),
            localIdentity.SessionId);
        var ingress = new ScriptedCursorIngress(clock, innerDpe1);
        ImportedMailboxRuntimeMaterial imported;
        string externalCursor;

        using (var store = new SqliteSessionStore(fixture.DatabasePath))
        {
            imported = await MailboxCredentialBundleImporter.ImportAsync(
                store,
                localIdentity,
                fixture.AndroidOptions with { TimeProvider = clock },
                MailboxInfrastructureOwnership.UserManaged);
            using var native = Native(store);
            using var e2ee = E2ee(native, store);
            var message = Assert.Single(
                await e2ee.ReceiveAsync(localIdentity.SessionId));
            Assert.Equal(remoteIdentity.SessionId, message.Sender);
            Assert.Equal("one delivery across restart", message.Body);
            externalCursor = message.ServerHash;

            await e2ee.AcknowledgeInboxItemAsync(
                localIdentity.SessionId,
                message.ServerHash);
            Assert.Equal(1, ingress.AcknowledgeCalls);
        }

        using (var reopened = new SqliteSessionStore(fixture.DatabasePath))
        using (var native = Native(reopened))
        using (var e2ee = E2ee(native, reopened))
        {
            Assert.Empty(await e2ee.ReceiveAsync(localIdentity.SessionId));
        }

        Assert.Equal(2, ingress.RetrieveCalls);
        Assert.Equal(1, ingress.AcknowledgeCalls);
        Assert.Equal(1UL, ingress.Requests[1].AfterCursor);
        Assert.Equal(ScriptedCursorIngress.Token,
            ingress.Requests[1].ContinuationToken.ToArray());
        Assert.Equal(externalCursor,
            await ReadExternalCursorAsync());

        NativeMau2MailboxTransport Native(SqliteSessionStore store) => new(
            ClientFeatureFlags.Defaults with { ClientMailboxAdapterEnabled = true },
            imported.Activation,
            ingress,
            store,
            new PinnedClientMailboxReceiptVerifier(
                new SodiumClientMailboxReceiptCrypto()),
            imported.DecodePolicies,
            imported.Authority,
            sessionId => sessionId == imported.LocalSessionId
                ? imported.SelfSelector
                : throw new InvalidOperationException(
                    "The acceptance transport has no selector for another identity."),
            timeProvider: clock);

        E2eeClientTransport E2ee(
            NativeMau2MailboxTransport native,
            SqliteSessionStore store) => new(
            native,
            _ => Task.FromResult<string?>(AlicePhrase),
            new FrozenClock(Now),
            store,
            new DirectP2pMailboxDeliveryPolicy());

        async Task<string?> ReadExternalCursorAsync()
        {
            using var reopened = new SqliteSessionStore(fixture.DatabasePath);
            return await reopened.GetInboxCursorAsync(
                new DurableInboxScope(localIdentity.SessionId,
                    unchecked((int)0x4d415532)));
        }
    }

    private static string Dpe1(ReadOnlySpan<byte> bytes) =>
        E2eeClientTransport.WireBodyPrefix + Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class ScriptedRetrieveIngress(
        TimeProvider timeProvider,
        byte[]? responseCiphertext = null) :
        IClientMailboxBinaryIngress
    {
        private static readonly byte[] FirstReplicaId = Bytes(32, 0x51);
        private static readonly byte[] SecondReplicaId = Bytes(32, 0x52);
        private static readonly byte[] FirstReplicaSeed = Bytes(32, 0x61);
        private static readonly byte[] SecondReplicaSeed = Bytes(32, 0x62);
        private readonly SodiumMailboxPeerReplicationCrypto receiptCrypto = new();
        private MailboxEncryptedEnvelope? retrievedEnvelope;

        public int RetrieveCalls { get; private set; }
        public int AcknowledgeCalls { get; private set; }
        public int StoreCalls { get; private set; }
        public TaskCompletionSource StoreEntered { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        public byte[]? LastCanonicalRequest { get; private set; }

        public Task<ReadOnlyMemory<byte>> StoreAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default)
        {
            StoreCalls++;
            StoreEntered.TrySetResult();
            return Task.FromException<ReadOnlyMemory<byte>>(
                new InvalidOperationException(
                    "Expired revocations must prevent the acceptance lane from storing."));
        }

        public Task<ReadOnlyMemory<byte>> RetrieveAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RetrieveCalls++;
            LastCanonicalRequest = canonicalMau2.ToArray();
            var authenticated = MailboxAuthenticatedClientRequestCodec.Decode(
                canonicalMau2.Span);
            Assert.Equal(
                MailboxAuthenticatedOperation.Retrieve,
                authenticated.Binding.Operation);
            Assert.Equal(
                MailboxAuthenticatedOperation.Retrieve,
                authenticated.Presentation.Operation);
            Assert.Equal(
                canonicalMau2.ToArray(),
                MailboxAuthenticatedClientRequestCodec.Encode(authenticated));
            var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
                authenticated.Binding.CanonicalRequest.Span);
            var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
            var ciphertext = responseCiphertext?.ToArray() ?? Enumerable.Range(0, 64)
                .Select(index => checked((byte)(0x20 + index)))
                .ToArray();
            var envelope = new MailboxEncryptedEnvelope
            {
                Epoch = request.Epoch,
                MailboxId = request.MailboxId,
                PlacementId = request.PlacementId,
                OperationId = Enumerable.Repeat((byte)0xa1, 16).ToArray(),
                DeduplicationDigest = SHA256.HashData(ciphertext),
                CreatedAtUnixSeconds = now,
                ExpiresAtUnixSeconds = checked(now + 300),
                Ciphertext = ciphertext
            };
            retrievedEnvelope = envelope;
            var response = MailboxClientCodec.EncodeRetrievePage(
                new MailboxRetrievePage
                {
                    Epoch = request.Epoch,
                    OperationId = request.OperationId.ToArray(),
                    NextCursor = 1,
                    HasMore = false,
                    ContinuationToken = ReadOnlyMemory<byte>.Empty,
                    Items =
                    [
                        new MailboxRetrievedEnvelope
                        {
                            Cursor = 1,
                            Envelope = envelope
                        }
                    ]
                });
            return Task.FromResult<ReadOnlyMemory<byte>>(response);
        }

        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AcknowledgeCalls++;
            var authenticated = MailboxAuthenticatedClientRequestCodec.Decode(
                canonicalMau2.Span);
            Assert.Equal(MailboxAuthenticatedOperation.Ack,
                authenticated.Binding.Operation);
            Assert.Equal(MailboxAuthenticatedOperation.Ack,
                authenticated.Presentation.Operation);
            Assert.Equal(canonicalMau2.ToArray(),
                MailboxAuthenticatedClientRequestCodec.Encode(authenticated));
            var request = MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                authenticated.Binding.CanonicalRequest.Span);
            var acknowledgement = Assert.Single(request.Acknowledgements);
            var envelope = retrievedEnvelope ?? throw new InvalidOperationException(
                "ACK was dispatched before the scripted retrieve response.");
            Assert.Equal(1UL, acknowledgement.Cursor);
            Assert.Equal(envelope.DeduplicationDigest.ToArray(),
                acknowledgement.EnvelopeDigest.ToArray());

            var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
            var first = TombstoneReplica(
                FirstReplicaId,
                FirstReplicaSeed,
                request,
                acknowledgement,
                authenticated.Presentation.Grant.MembershipCommitment.Span,
                envelope.ExpiresAtUnixSeconds,
                now);
            var second = TombstoneReplica(
                SecondReplicaId,
                SecondReplicaSeed,
                request,
                acknowledgement,
                authenticated.Presentation.Grant.MembershipCommitment.Span,
                envelope.ExpiresAtUnixSeconds,
                now);
            var unsigned = new MailboxDurableQuorumReceiptV3
            {
                CoordinatorId = FirstReplicaId,
                CoordinatorSequence = 1,
                FirstReplica = first,
                SecondReplica = second,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            var quorum = MailboxReceiptV3Codec.EncodeDurableQuorum(
                receiptCrypto.SignQuorumResponse(unsigned, FirstReplicaSeed));
            var response = MailboxAggregateAckCodec.EncodeMqr3(
                new MailboxAggregateAckResponse
                {
                    Epoch = request.Epoch,
                    OperationId = request.OperationId.ToArray(),
                    TombstoneQuorums = [quorum]
                });
            return Task.FromResult<ReadOnlyMemory<byte>>(response);
        }

        private MailboxReplicaReceiptV2 TombstoneReplica(
            byte[] replicaId,
            byte[] replicaSeed,
            MailboxAuthenticatedAckBody request,
            MailboxAcknowledgement acknowledgement,
            ReadOnlySpan<byte> membershipCommitment,
            ulong expiresAtUnixSeconds,
            ulong nowUnixSeconds) => receiptCrypto.SignReplicaResponse(
            new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = MailboxReplicaDisposition.Tombstone,
                ReplicaId = replicaId,
                OperationId = request.OperationId.ToArray(),
                Epoch = request.Epoch,
                Cursor = acknowledgement.Cursor,
                AcceptedAtUnixSeconds = nowUnixSeconds,
                DurableAtUnixSeconds = nowUnixSeconds,
                ExpiresAtUnixSeconds = expiresAtUnixSeconds,
                BlindedMailboxId = request.MailboxId.Bytes,
                PlacementCommitment = MailboxPlacementCommitment.Compute(
                    request.PlacementId),
                MembershipCommitment = membershipCommitment.ToArray(),
                EnvelopeDigest = acknowledgement.EnvelopeDigest.ToArray(),
                Signature = ReadOnlyMemory<byte>.Empty
            },
            replicaSeed);
    }

    private sealed class InjectedBatchNativeTransport(
        NativeMau2MailboxTransport inner,
        IReadOnlyList<DurableInboxWireEntry> entries) :
        IAuthenticatedOpaqueMailboxTransport,
        IAuthenticatedInboxTransport
    {
        public int InboxNamespace => inner.InboxNamespace;
        public int RetrieveCalls { get; private set; }

        public Task SendAsync(
            OutboundMessageEnvelope envelope,
            CancellationToken cancellationToken = default) =>
            inner.SendAsync(envelope, cancellationToken);

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            inner.ReceiveAsync(recipient, cancellationToken);

        public Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>
            PrepareScopedMailboxBatchAsync(
            IMailboxOperationSigner signer,
            IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
            CancellationToken cancellationToken = default) =>
            inner.PrepareScopedMailboxBatchAsync(signer, targets, cancellationToken);

        public Task SendPreparedMailboxAuthenticatedAsync(
            IPreparedMailboxAuthenticatedSend preparedSend,
            CancellationToken cancellationToken = default) =>
            inner.SendPreparedMailboxAuthenticatedAsync(preparedSend, cancellationToken);

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity,
            CancellationToken cancellationToken = default) =>
            Task.FromException<IReadOnlyList<InboundMessageEnvelope>>(
                new InvalidOperationException(
                    "Injected acceptance batch requires cursor retrieval."));

        public Task<AuthenticatedInboxBatch> RetrieveAuthenticatedAsync(
            SessionIdentityProvider identity,
            string? cursor,
            int limit,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RetrieveCalls++;
            if (RetrieveCalls != 1)
                return Task.FromResult(new AuthenticatedInboxBatch([], cursor));
            Assert.Null(cursor);
            Assert.True(limit >= entries.Count);
            return Task.FromResult(new AuthenticatedInboxBatch(
                entries,
                entries[^1].ServerHash));
        }

        public bool TryDecodeInboxEntry(
            DurableInboxWireEntry entry,
            SessionId recipient,
            out InboundMessageEnvelope envelope) =>
            inner.TryDecodeInboxEntry(entry, recipient, out envelope);

        public Task<OpaqueMailboxInboxPage> RetrieveOpaqueMailboxInboxAsync(
            IMailboxOperationSigner signer,
            OpaqueMailboxContinuation continuation,
            CancellationToken cancellationToken = default) =>
            inner.RetrieveOpaqueMailboxInboxAsync(
                signer, continuation, cancellationToken);

        public Task AcknowledgeOpaqueMailboxInboxAsync(
            IMailboxOperationSigner signer,
            string opaqueItemHandle,
            CancellationToken cancellationToken = default) =>
            inner.AcknowledgeOpaqueMailboxInboxAsync(
                signer, opaqueItemHandle, cancellationToken);
    }

    private sealed class ScriptedCursorIngress(
        TimeProvider timeProvider,
        byte[]? responseCiphertext = null) :
        IClientMailboxBinaryIngress
    {
        public static readonly byte[] Token = Bytes(32, 0x73);
        private readonly List<MailboxAuthenticatedRetrieveBody> requests = [];
        private readonly SodiumMailboxPeerReplicationCrypto receiptCrypto = new();
        private MailboxEncryptedEnvelope? retrievedEnvelope;

        public int RetrieveCalls => requests.Count;
        public int AcknowledgeCalls { get; private set; }
        public IReadOnlyList<MailboxAuthenticatedRetrieveBody> Requests => requests;

        public Task<ReadOnlyMemory<byte>> StoreAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default) =>
            Task.FromException<ReadOnlyMemory<byte>>(
                new InvalidOperationException("Cursor acceptance does not store."));

        public Task<ReadOnlyMemory<byte>> RetrieveAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var authenticated = MailboxAuthenticatedClientRequestCodec.Decode(
                canonicalMau2.Span);
            Assert.Equal(canonicalMau2.ToArray(),
                MailboxAuthenticatedClientRequestCodec.Encode(authenticated));
            var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
                authenticated.Binding.CanonicalRequest.Span);
            requests.Add(request);
            if (requests.Count == 1)
            {
                Assert.Equal(0UL, request.AfterCursor);
                Assert.Empty(request.ContinuationToken.ToArray());
                var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
                var ciphertext = responseCiphertext?.ToArray() ?? Bytes(64, 0x83);
                var envelope = new MailboxEncryptedEnvelope
                {
                    Epoch = request.Epoch,
                    MailboxId = request.MailboxId,
                    PlacementId = request.PlacementId,
                    OperationId = Bytes(16, 0x84),
                    DeduplicationDigest = SHA256.HashData(ciphertext),
                    CreatedAtUnixSeconds = now,
                    ExpiresAtUnixSeconds = checked(now + 300),
                    Ciphertext = ciphertext
                };
                retrievedEnvelope = envelope;
                return Page(new MailboxRetrievePage
                {
                    Epoch = request.Epoch,
                    OperationId = request.OperationId.ToArray(),
                    NextCursor = 1,
                    HasMore = true,
                    ContinuationToken = Token,
                    Items = [new MailboxRetrievedEnvelope { Cursor = 1, Envelope = envelope }]
                });
            }

            Assert.Equal(1UL, request.AfterCursor);
            Assert.Equal(Token, request.ContinuationToken.ToArray());
            return Page(new MailboxRetrievePage
            {
                Epoch = request.Epoch,
                OperationId = request.OperationId.ToArray(),
                NextCursor = 0,
                HasMore = false,
                ContinuationToken = ReadOnlyMemory<byte>.Empty,
                Items = []
            });
        }

        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AcknowledgeCalls++;
            var authenticated = MailboxAuthenticatedClientRequestCodec.Decode(
                canonicalMau2.Span);
            Assert.Equal(MailboxAuthenticatedOperation.Ack,
                authenticated.Binding.Operation);
            Assert.Equal(canonicalMau2.ToArray(),
                MailboxAuthenticatedClientRequestCodec.Encode(authenticated));
            var request = MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                authenticated.Binding.CanonicalRequest.Span);
            var acknowledgement = Assert.Single(request.Acknowledgements);
            var envelope = retrievedEnvelope ?? throw new InvalidOperationException(
                "Cursor ACK was dispatched before retrieve.");
            Assert.Equal(1UL, acknowledgement.Cursor);
            Assert.Equal(envelope.DeduplicationDigest.ToArray(),
                acknowledgement.EnvelopeDigest.ToArray());
            var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
            var first = Tombstone(
                Bytes(32, 0x51), Bytes(32, 0x61), request, acknowledgement,
                authenticated.Presentation.Grant.MembershipCommitment.Span,
                envelope.ExpiresAtUnixSeconds, now);
            var second = Tombstone(
                Bytes(32, 0x52), Bytes(32, 0x62), request, acknowledgement,
                authenticated.Presentation.Grant.MembershipCommitment.Span,
                envelope.ExpiresAtUnixSeconds, now);
            var unsigned = new MailboxDurableQuorumReceiptV3
            {
                CoordinatorId = Bytes(32, 0x51),
                CoordinatorSequence = 1,
                FirstReplica = first,
                SecondReplica = second,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            var quorum = MailboxReceiptV3Codec.EncodeDurableQuorum(
                receiptCrypto.SignQuorumResponse(unsigned, Bytes(32, 0x61)));
            return Task.FromResult<ReadOnlyMemory<byte>>(
                MailboxAggregateAckCodec.EncodeMqr3(
                    new MailboxAggregateAckResponse
                    {
                        Epoch = request.Epoch,
                        OperationId = request.OperationId.ToArray(),
                        TombstoneQuorums = [quorum]
                    }));
        }

        private MailboxReplicaReceiptV2 Tombstone(
            byte[] replicaId,
            byte[] replicaSeed,
            MailboxAuthenticatedAckBody request,
            MailboxAcknowledgement acknowledgement,
            ReadOnlySpan<byte> membershipCommitment,
            ulong expiresAtUnixSeconds,
            ulong nowUnixSeconds) => receiptCrypto.SignReplicaResponse(
            new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = MailboxReplicaDisposition.Tombstone,
                ReplicaId = replicaId,
                OperationId = request.OperationId.ToArray(),
                Epoch = request.Epoch,
                Cursor = acknowledgement.Cursor,
                AcceptedAtUnixSeconds = nowUnixSeconds,
                DurableAtUnixSeconds = nowUnixSeconds,
                ExpiresAtUnixSeconds = expiresAtUnixSeconds,
                BlindedMailboxId = request.MailboxId.Bytes,
                PlacementCommitment = MailboxPlacementCommitment.Compute(
                    request.PlacementId),
                MembershipCommitment = membershipCommitment.ToArray(),
                EnvelopeDigest = acknowledgement.EnvelopeDigest.ToArray(),
                Signature = ReadOnlyMemory<byte>.Empty
            },
            replicaSeed);

        private static Task<ReadOnlyMemory<byte>> Page(MailboxRetrievePage page) =>
            Task.FromResult<ReadOnlyMemory<byte>>(
                MailboxClientCodec.EncodeRetrievePage(page));
    }

    private sealed class AcceptanceMailboxSigner(SessionIdentityProvider identity) :
        IMailboxOperationSigner,
        IDisposable
    {
        private int disposed;

        public SessionId SessionId => identity.SessionId;

        public byte[] GetEd25519PublicKey()
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            return identity.GetEd25519PublicKey();
        }

        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> canonicalPresentationSigningBytes)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            var domain = operation switch
            {
                MailboxAuthenticatedOperation.Store => "DEEP-MCP2-STR\0\0\0"u8,
                MailboxAuthenticatedOperation.Retrieve => "DEEP-MCP2-GET\0\0\0"u8,
                MailboxAuthenticatedOperation.Ack => "DEEP-MCP2-ACK\0\0\0"u8,
                _ => throw new ArgumentOutOfRangeException(nameof(operation))
            };
            if (!canonicalPresentationSigningBytes.StartsWith(domain))
                throw new InvalidOperationException(
                    "Acceptance signer received a noncanonical MCP2 domain.");
            return identity.SignDetached(canonicalPresentationSigningBytes);
        }

        public void Dispose() => Interlocked.Exchange(ref disposed, 1);
    }
}
