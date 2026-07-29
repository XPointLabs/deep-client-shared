using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ClientMailboxAdapterTests
{
    [Fact]
    public void Activation_IsDisabledByDefaultAndRedactsIssuerMaterial()
    {
        Assert.False(ClientFeatureFlags.Defaults.ClientMailboxAdapterEnabled);
        Assert.False(ClientFeatureFlags.ReleaseDefaults.ClientMailboxAdapterEnabled);
        var issuer = Range(0x20, 32);
        var activation = new ClientMailboxActivation(
            enabled: false,
            issuer,
            route: null,
            ingressConfigured: false);

        Assert.DoesNotContain(Convert.ToHexString(issuer), activation.ToString());
        Assert.Contains("[configured]", activation.ToString());
    }

    [Fact]
    public async Task Store_PersistsAcceptedThenDurable_IsRestartIdempotentAndNeverDelivered()
    {
        var fixture = new ReceiptFixture();
        var ingress = new SequenceIngress(
            new ClientMailboxStoreIngressResult(
                ClientMailboxIngressState.Accepted,
                fixture.AcceptedReceipt()),
            new ClientMailboxStoreIngressResult(
                ClientMailboxIngressState.Durable,
                fixture.Quorum()));
        var outbox = new InMemorySessionStore();
        var adapter = fixture.Adapter(ingress, outbox);
        var scope = ClientMailboxScope.FromBytes(Range(0x01, 32));
        var outboxScope = OutboxAccountScope.FromBytes(Range(0x02, 32));

        var accepted = await adapter.StoreAsync(
            scope,
            outboxScope,
            fixture.StoreRequest());
        Assert.Equal(ClientMailboxIngressState.Accepted, accepted.State);
        var afterAccepted = await outbox.ReadTransportOutboxAsync(
            outboxScope,
            OutboxLogicalId.FromBytes(fixture.OperationId));
        Assert.Equal(TransportOutboxState.Accepted, afterAccepted.Item!.State);

        var durable = await adapter.StoreAsync(
            scope,
            outboxScope,
            fixture.StoreRequest());
        Assert.Equal(ClientMailboxIngressState.Durable, durable.State);
        var afterDurable = await outbox.ReadTransportOutboxAsync(
            outboxScope,
            OutboxLogicalId.FromBytes(fixture.OperationId));
        Assert.Equal(TransportOutboxState.Durable, afterDurable.Item!.State);
        Assert.NotEqual(TransportOutboxState.Delivered, afterDurable.Item.State);

        var restarted = fixture.Adapter(ingress, outbox);
        var idempotent = await restarted.StoreAsync(
            scope,
            outboxScope,
            fixture.StoreRequest());
        Assert.Equal(ClientMailboxIngressState.Durable, idempotent.State);
        Assert.Equal(42UL, idempotent.Cursor);
        Assert.Equal(MailboxReplicaDisposition.Stored, idempotent.Disposition);
        Assert.Equal(2, ingress.StoreCalls);
        Assert.All(ingress.StoreRequests, request =>
            Assert.Equal("MST1"u8.ToArray(), request[..4]));
    }

    [Fact]
    public async Task RetrieveAndAck_UseCanonicalMrp1Mar1AndAckIsRestartIdempotent()
    {
        var fixture = new ReceiptFixture();
        var state = new InMemoryClientMailboxStateRepository();
        var page = fixture.RetrievePage();
        var ack = fixture.AckRequest(page.Items[0].ToAcknowledgement());
        var mar1 = MailboxAggregateAckCodec.EncodeMqr3(
            new MailboxAggregateAckResponse
            {
                Epoch = ack.Epoch,
                OperationId = ack.OperationId,
                TombstoneQuorums =
                [
                    fixture.Quorum(
                        disposition: MailboxReplicaDisposition.Tombstone)
                ]
            });
        var ingress = new RetrieveAckIngress(
            MailboxClientCodec.EncodeRetrievePage(page),
            mar1);
        var adapter = fixture.Adapter(ingress, new InMemorySessionStore(), state);
        var scope = ClientMailboxScope.FromBytes(Range(0x03, 32));

        var retrieved = await adapter.RetrieveAsync(
            scope,
            fixture.RetrieveRequest());
        Assert.Single(retrieved.NewItems);
        Assert.Equal(42UL, retrieved.AfterCursor);

        var acknowledged = await adapter.AcknowledgeAsync(scope, ack);
        Assert.False(acknowledged.Idempotent);
        Assert.Equal(1, acknowledged.DurableTombstones);
        var replay = await adapter.AcknowledgeAsync(scope, ack);
        Assert.True(replay.Idempotent);
        Assert.Equal(1, ingress.AckCalls);
        Assert.Equal("MRT1"u8.ToArray(), ingress.RetrieveRequest![..4]);
        Assert.Equal("MAK1"u8.ToArray(), ingress.AckRequest![..4]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReceiveState_MergesR2SuppressesDuplicatesAndCommitsOnlyAckPrefix(
        bool sqlite)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-client-mailbox-{Guid.NewGuid():N}.db");
        IClientMailboxStateRepository repository = sqlite
            ? new SqliteClientMailboxStateRepository(path)
            : new InMemoryClientMailboxStateRepository();
        try
        {
            var scope = ClientMailboxScope.FromBytes(Range(0x10, 32));
            var page = Page(1, 2);
            var first = await repository.MergeRetrievePageAsync(scope, page);
            Assert.Equal(2UL, first.AfterCursor);
            Assert.Equal(2, first.NewItems.Count);

            var retry = await repository.MergeRetrievePageAsync(scope, page);
            Assert.Empty(retry.NewItems);
            var firstAck = new[] { page.Items[0].ToAcknowledgement() };
            var secondAck = new[] { page.Items[1].ToAcknowledgement() };
            Assert.Equal(
                ClientMailboxAckState.Conflict,
                await repository.CheckAcknowledgementsAsync(scope, secondAck));
            Assert.Equal(
                ClientMailboxAckState.Pending,
                await repository.CommitAcknowledgementsAsync(scope, firstAck));
            Assert.Equal(
                ClientMailboxAckState.AlreadyCommitted,
                await repository.CheckAcknowledgementsAsync(scope, firstAck));

            if (repository is IDisposable disposable)
            {
                disposable.Dispose();
            }
            if (sqlite)
            {
                repository = new SqliteClientMailboxStateRepository(path);
                Assert.Equal(2UL, await repository.ReadAfterCursorAsync(scope));
                Assert.Equal(
                    ClientMailboxAckState.AlreadyCommitted,
                    await repository.CheckAcknowledgementsAsync(scope, firstAck));
                Assert.Equal(
                    ClientMailboxAckState.Pending,
                    await repository.CheckAcknowledgementsAsync(scope, secondAck));
            }
        }
        finally
        {
            (repository as IDisposable)?.Dispose();
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task SqliteState_LazilyMigratesV1BinaryWithoutJsonOrRawIdentity()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-client-mailbox-migration-{Guid.NewGuid():N}.db");
        var scope = ClientMailboxScope.FromBytes(Range(0x31, 32));
        var digest = Range(0x71, 32);
        var v1 = new byte[56];
        "CMS1"u8.CopyTo(v1);
        BinaryPrimitives.WriteUInt64BigEndian(v1.AsSpan(4, 8), 7);
        BinaryPrimitives.WriteUInt32BigEndian(v1.AsSpan(12, 4), 1);
        BinaryPrimitives.WriteUInt64BigEndian(v1.AsSpan(16, 8), 7);
        digest.CopyTo(v1, 24);

        try
        {
            using (var repository = new SqliteClientMailboxStateRepository(path))
            {
                repository.InsertVersionOneStateForTests(scope, v1);
                Assert.Equal(7UL, await repository.ReadAfterCursorAsync(scope));
                var acknowledgement = new MailboxAcknowledgement
                {
                    Cursor = 7,
                    EnvelopeDigest = digest
                };
                Assert.Equal(
                    ClientMailboxAckState.Pending,
                    await repository.CommitAcknowledgementsAsync(
                        scope,
                        [acknowledgement]));
            }

            await using var connection = new SqliteConnection(
                new SqliteConnectionStringBuilder
                {
                    DataSource = path,
                    Pooling = false
                }.ToString());
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText =
                "SELECT state_blob FROM client_mailbox_state WHERE scope = $scope;";
            command.Parameters.Add("$scope", SqliteType.Blob).Value = scope.ToArray();
            var stateBytes = Assert.IsType<byte[]>(await command.ExecuteScalarAsync());
            Assert.Equal("CMS2"u8.ToArray(), stateBytes[..4]);
            Assert.DoesNotContain("alice@example.test"u8.ToArray(), stateBytes);
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void PinnedVerifier_RejectsForgedSingleReplicaAndReplicaEquivocation()
    {
        var fixture = new ReceiptFixture();
        var verifier = new PinnedClientMailboxReceiptVerifier(fixture.Crypto);
        var canonical = fixture.Quorum();
        var verified = verifier.VerifyDurable(canonical, fixture.Expectation());
        Assert.Equal(42UL, verified.Cursor);

        var forged = canonical.ToArray();
        forged[^1] ^= 1;
        Assert.Throws<MailboxReceiptException>(() =>
            verifier.VerifyDurable(forged, fixture.Expectation()));

        var single = fixture.Quorum(secondUsesFirstIdentity: true);
        Assert.Throws<MailboxReceiptException>(() =>
            verifier.VerifyDurable(single, fixture.Expectation()));

        var equivocation = fixture.Quorum(secondCursor: 43);
        Assert.Throws<MailboxReceiptException>(() =>
            verifier.VerifyDurable(equivocation, fixture.Expectation()));
    }

    [Fact]
    public void PinnedVerifier_RejectsCoordinatorSequenceEquivocation()
    {
        var fixture = new ReceiptFixture();
        var verifier = new PinnedClientMailboxReceiptVerifier(fixture.Crypto);
        _ = verifier.VerifyDurable(fixture.Quorum(), fixture.Expectation());

        var second = fixture.Quorum(cursor: 43, coordinatorSequence: 42);
        Assert.Throws<MailboxReceiptException>(() =>
            verifier.VerifyDurable(
                second,
                fixture.Expectation(cursor: 43)));
    }

    [Fact]
    public void Mqr3CannotBeDowngradedToLegacyMqr2()
    {
        var fixture = new ReceiptFixture();
        var mqr3 = fixture.Quorum();
        _ = MailboxReceiptV3Codec.DecodeDurableQuorum(mqr3);
        Assert.Throws<MailboxReceiptException>(() =>
            MailboxReceiptV2Codec.DecodeDurableQuorum(mqr3));
    }

    private static MailboxRetrievePage Page(params ulong[] cursors)
    {
        var items = cursors.Select(cursor => new MailboxRetrievedEnvelope
        {
            Cursor = cursor,
            Envelope = new MailboxEncryptedEnvelope
            {
                Epoch = 7,
                MailboxId = new BlindedMailboxId(Range(0x90, 32)),
                PlacementId = new BlindedPlacementId(Range(0xb0, 32)),
                OperationId = Range(checked((int)cursor + 1), 16),
                DeduplicationDigest = SHA256.HashData(UInt64Bytes(cursor)),
                CreatedAtUnixSeconds = 1000,
                ExpiresAtUnixSeconds = 1120,
                Ciphertext = Range(0x01, 64)
            }
        }).ToArray();
        return new MailboxRetrievePage
        {
            Epoch = 7,
            OperationId = Range(0x50, 16),
            NextCursor = cursors[^1],
            HasMore = false,
            ContinuationToken = ReadOnlyMemory<byte>.Empty,
            Items = items
        };
    }

    private static byte[] UInt64Bytes(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length)
            .Select(static value => unchecked((byte)value))
            .ToArray();

    private static void DeleteSqliteFiles(string path)
    {
        foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
        {
            if (File.Exists(candidate))
            {
                File.Delete(candidate);
            }
        }
    }

    private sealed class ReceiptFixture
    {
        private readonly byte[] firstSeed = Range(0x10, 32);
        private readonly byte[] secondSeed = Range(0x50, 32);
        private readonly byte[] firstId = Range(0x20, 32);
        private readonly byte[] secondId = Range(0x60, 32);
        private readonly byte[] membership = Range(0x80, 32);
        private readonly BlindedMailboxId mailboxId =
            new(Range(0xc0, 32));
        private readonly BlindedPlacementId placementId =
            new(Range(0xa0, 32));
        private readonly byte[] operationId = Range(0x70, 16);
        private readonly byte[] envelopeDigest = Range(0xe0, 32);

        public ReceiptFixture()
        {
            Crypto = new SodiumMailboxPeerReplicationCrypto();
            Route = new ClientMailboxPinnedRoute(
                placementId,
                membership,
                firstId,
                Crypto.GetPublicKey(firstSeed),
                secondId,
                Crypto.GetPublicKey(secondSeed));
        }

        public SodiumMailboxPeerReplicationCrypto Crypto { get; }
        public ClientMailboxPinnedRoute Route { get; }
        public byte[] OperationId => operationId.ToArray();

        public MailboxStoreRequest StoreRequest() => new()
        {
            Epoch = 7,
            OperationId = operationId,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            DepositCapability = new MailboxCapabilityPresentation
            {
                DomainValue = new RotatingDepositCapability(Range(0x30, 32)),
                Lifecycle = MailboxCapabilityLifecycle.Active,
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                Generation = 7,
                NotBeforeBucket = 900,
                ExpiresAtBucket = 1200,
                OverlapUntilBucket = 0,
                ReplayCounter = 1,
                IdempotencyKey = operationId
            },
            Envelope = new MailboxEncryptedEnvelope
            {
                Epoch = 7,
                MailboxId = mailboxId,
                PlacementId = placementId,
                OperationId = operationId,
                DeduplicationDigest = envelopeDigest,
                CreatedAtUnixSeconds = 1000,
                ExpiresAtUnixSeconds = 1120,
                Ciphertext = Range(0x01, 64)
            }
        };

        public byte[] AcceptedReceipt()
        {
            var durable = Replica(firstId, firstSeed, 42);
            return MailboxReceiptV2Codec.EncodeReplica(
                Crypto.SignReplicaResponse(
                    durable with
                    {
                        Status = MailboxReceiptStatus.Accepted,
                        DurableAtUnixSeconds = 0,
                        Signature = ReadOnlyMemory<byte>.Empty
                    },
                    firstSeed));
        }

        public ClientMailboxAdapter Adapter(
            IClientMailboxBinaryIngress ingress,
            ITransportOutboxRepository outbox,
            IClientMailboxStateRepository? state = null) =>
            new(
                ClientFeatureFlags.Defaults with
                {
                    ClientMailboxAdapterEnabled = true
                },
                new ClientMailboxActivation(
                    enabled: true,
                    Range(0x11, 32),
                    Route,
                    ingressConfigured: true),
                ingress,
                outbox,
                state ?? new InMemoryClientMailboxStateRepository(),
                new PinnedClientMailboxReceiptVerifier(Crypto),
                new MailboxClientDecodePolicy
                {
                    NowUnixSeconds = 1050,
                    EpochWindow = new MailboxEpochWindow
                    {
                        CurrentEpoch = 7,
                        NextEpoch = 8,
                        CurrentNotBeforeUnixSeconds = 900,
                        NextNotBeforeUnixSeconds = 1100,
                        CurrentExpiresAtUnixSeconds = 1120,
                        NextExpiresAtUnixSeconds = 1200
                    },
                    CapabilityPolicy = new MailboxCapabilityDecodePolicy
                    {
                        CurrentBucket = 1050,
                        MinimumGeneration = 7
                    }
                },
                new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1050)));

        public MailboxRetrieveRequest RetrieveRequest() => new()
        {
            Epoch = 7,
            OperationId = operationId,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            RetrieveCapability = RetrieveCapability(),
            MailboxId = mailboxId,
            PlacementId = placementId,
            AfterCursor = 0,
            MaximumItems = 10,
            ContinuationToken = ReadOnlyMemory<byte>.Empty
        };

        public MailboxRetrievePage RetrievePage() => new()
        {
            Epoch = 7,
            OperationId = operationId,
            NextCursor = 42,
            HasMore = false,
            ContinuationToken = ReadOnlyMemory<byte>.Empty,
            Items =
            [
                new MailboxRetrievedEnvelope
                {
                    Cursor = 42,
                    Envelope = StoreRequest().Envelope
                }
            ]
        };

        public MailboxAckRequest AckRequest(
            MailboxAcknowledgement acknowledgement) => new()
            {
                Epoch = 7,
                OperationId = operationId,
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                RetrieveCapability = RetrieveCapability(),
                MailboxId = mailboxId,
                PlacementId = placementId,
                IsFinalPage = true,
                ContinuationToken = ReadOnlyMemory<byte>.Empty,
                Acknowledgements = [acknowledgement]
            };

        private static MailboxCapabilityPresentation RetrieveCapability() =>
            new()
            {
                DomainValue = new RotatingRetrieveCapability(Range(0x40, 32)),
                Lifecycle = MailboxCapabilityLifecycle.Active,
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                Generation = 7,
                NotBeforeBucket = 900,
                ExpiresAtBucket = 1200,
                OverlapUntilBucket = 0,
                ReplayCounter = 2,
                IdempotencyKey = Range(0x70, 16)
            };

        public ClientMailboxReceiptExpectation Expectation(ulong cursor = 42) =>
            new()
            {
                Epoch = 7,
                OperationId = operationId,
                MailboxId = mailboxId,
                Route = Route,
                EnvelopeDigest = envelopeDigest,
                ExpiresAtUnixSeconds = 1120,
                AllowedDispositions =
                    new HashSet<MailboxReplicaDisposition>
                    {
                        MailboxReplicaDisposition.Stored
                    },
                Cursor = cursor
            };

        public byte[] Quorum(
            ulong cursor = 42,
            ulong coordinatorSequence = 42,
            ulong? secondCursor = null,
            bool secondUsesFirstIdentity = false,
            MailboxReplicaDisposition disposition =
                MailboxReplicaDisposition.Stored)
        {
            var first = Replica(firstId, firstSeed, cursor, disposition);
            var second = Replica(
                secondUsesFirstIdentity ? firstId : secondId,
                secondUsesFirstIdentity ? firstSeed : secondSeed,
                secondCursor ?? cursor,
                disposition);
            var unsigned = new MailboxDurableQuorumReceiptV3
            {
                CoordinatorId = firstId,
                CoordinatorSequence = coordinatorSequence,
                FirstReplica = first,
                SecondReplica = second,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            return MailboxReceiptV3Codec.EncodeDurableQuorum(
                Crypto.SignQuorumResponse(unsigned, firstSeed));
        }

        private MailboxReplicaReceiptV2 Replica(
            byte[] replicaId,
            byte[] seed,
            ulong cursor,
            MailboxReplicaDisposition disposition =
                MailboxReplicaDisposition.Stored)
        {
            var unsigned = new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = disposition,
                ReplicaId = replicaId,
                OperationId = operationId,
                Epoch = 7,
                Cursor = cursor,
                AcceptedAtUnixSeconds = 1050,
                DurableAtUnixSeconds = 1051,
                ExpiresAtUnixSeconds = 1120,
                BlindedMailboxId = mailboxId.Bytes,
                PlacementCommitment =
                    MailboxPlacementCommitment.Compute(placementId),
                MembershipCommitment = membership,
                EnvelopeDigest = envelopeDigest,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            return Crypto.SignReplicaResponse(unsigned, seed);
        }
    }

    private sealed class SequenceIngress(
        params ClientMailboxStoreIngressResult[] responses)
        : IClientMailboxBinaryIngress
    {
        private int index;
        public int StoreCalls { get; private set; }
        public List<byte[]> StoreRequests { get; } = [];

        public Task<ClientMailboxStoreIngressResult> StoreAsync(
            ReadOnlyMemory<byte> canonicalMst1,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StoreCalls++;
            StoreRequests.Add(canonicalMst1.ToArray());
            return Task.FromResult(responses[index++]);
        }

        public Task<ReadOnlyMemory<byte>> RetrieveAsync(
            ReadOnlyMemory<byte> canonicalMrt1,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
            ReadOnlyMemory<byte> canonicalMak1,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class RetrieveAckIngress(
        ReadOnlyMemory<byte> retrieveResponse,
        ReadOnlyMemory<byte> ackResponse)
        : IClientMailboxBinaryIngress
    {
        public byte[]? RetrieveRequest { get; private set; }
        public byte[]? AckRequest { get; private set; }
        public int AckCalls { get; private set; }

        public Task<ClientMailboxStoreIngressResult> StoreAsync(
            ReadOnlyMemory<byte> canonicalMst1,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ReadOnlyMemory<byte>> RetrieveAsync(
            ReadOnlyMemory<byte> canonicalMrt1,
            CancellationToken cancellationToken = default)
        {
            RetrieveRequest = canonicalMrt1.ToArray();
            return Task.FromResult(retrieveResponse);
        }

        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
            ReadOnlyMemory<byte> canonicalMak1,
            CancellationToken cancellationToken = default)
        {
            AckCalls++;
            AckRequest = canonicalMak1.ToArray();
            return Task.FromResult(ackResponse);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
