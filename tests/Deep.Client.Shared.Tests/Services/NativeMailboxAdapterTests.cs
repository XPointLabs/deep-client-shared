using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class NativeMailboxAdapterTests
{
    [Fact]
    public async Task Concurrent_first_store_is_single_flight_for_counter_frame_and_network()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var outbox = new InMemorySessionStore();
        var ingress = new CoordinatedStoreIngress(
            canonical => fixture.StoreQuorum(canonical));
        var envelope = fixture.StoreEnvelope(0x30);
        var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x20));
        var adapter = fixture.Adapter(state, outbox, ingress);

        var first = adapter.StoreAsync(
            scope,
            fixture.Signer,
            envelope);
        await ingress.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        using var cancellation = new CancellationTokenSource();
        var cancelledWaiter = adapter.StoreAsync(
            scope,
            fixture.Signer,
            envelope,
            cancellation.Token);
        await Task.Delay(25);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => cancelledWaiter);
        Assert.Single(ingress.Requests);
        var second = adapter.StoreAsync(
            scope,
            fixture.Signer,
            envelope);
        await Task.Delay(50);
        Assert.Single(ingress.Requests);

        ingress.Release.TrySetResult();
        var results = await Task.WhenAll(first, second);

        Assert.All(results, result => Assert.Equal(42UL, result.Cursor));
        var sent = Assert.Single(ingress.Requests);
        Assert.Equal(
            1UL,
            MailboxAuthenticatedClientRequestCodec.Decode(sent)
                .Presentation.ReplayCounter);
        var persisted = await outbox.ReadTransportOutboxAsync(
            scope,
            OutboxLogicalId.FromBytes(envelope.OperationId.Span));
        Assert.Equal(TransportOutboxState.Durable, persisted.Item!.State);
        Assert.Single(persisted.Item.Attempts);
    }

    [Fact]
    public async Task Persisted_retry_lease_blocks_second_repository_instance()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-native-mailbox-{Guid.NewGuid():N}.db");
        try
        {
            using var firstOutbox = new SqliteSessionStore(path);
            using var secondOutbox = new SqliteSessionStore(path);
            var firstIngress = new ScriptedIngress
            {
                Store = (_, _) => throw new ClientMailboxTransportException(
                    ClientMailboxTransportFailure.DependencyUnavailable,
                    true,
                    "unavailable")
            };
            var secondIngress = new ScriptedIngress
            {
                Store = (canonical, _) => fixture.StoreQuorum(canonical)
            };
            var envelope = fixture.StoreEnvelope(0x33);
            var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x29));

            await Assert.ThrowsAsync<ClientMailboxTransportException>(() =>
                fixture.Adapter(state, firstOutbox, firstIngress).StoreAsync(
                    scope,
                    fixture.Signer,
                    envelope));
            var exception =
                await Assert.ThrowsAsync<ClientMailboxRetryLeaseException>(() =>
                    fixture.Adapter(
                        state,
                        secondOutbox,
                        secondIngress).StoreAsync(
                            scope,
                            fixture.Signer,
                            envelope));

            Assert.Empty(secondIngress.StoreRequests);
            var persisted = await secondOutbox.ReadTransportOutboxAsync(
                scope,
                OutboxLogicalId.FromBytes(envelope.OperationId.Span));
            Assert.Equal(persisted.Item!.NotBefore, exception.RetryNotBefore);
            Assert.True(
                persisted.Item.NotBefore - persisted.Item.TransitionedAt >=
                TimeSpan.FromSeconds(
                    MailboxWireHttpContract.Store.RequestTimeoutSeconds + 5));
        }
        finally
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                File.Delete(path + suffix);
            }
        }
    }

    [Fact]
    public async Task Store_restart_retries_byte_identical_mau2_without_burning_counter()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var outbox = new InMemorySessionStore();
        var ingress = new ScriptedIngress
        {
            Store = (canonical, call) =>
                call == 1
                    ? throw new ClientMailboxTransportException(
                        ClientMailboxTransportFailure.DependencyUnavailable,
                        true,
                        "unavailable")
                    : fixture.StoreQuorum(canonical)
        };
        var envelope = fixture.StoreEnvelope(0x31);
        var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x22));

        await Assert.ThrowsAsync<ClientMailboxTransportException>(() =>
            fixture.Adapter(state, outbox, ingress).StoreAsync(
                scope,
                fixture.Signer,
                envelope));

        var restarted = state.RestartInstallationForTests();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Adapter(restarted, outbox, ingress).StoreAsync(
                scope,
                fixture.OtherSigner,
                envelope));
        Assert.Single(ingress.StoreRequests);
        var leased = await Assert.ThrowsAsync<ClientMailboxRetryLeaseException>(
            () => fixture.Adapter(restarted, outbox, ingress).StoreAsync(
                scope,
                fixture.Signer,
                envelope));
        Assert.Single(ingress.StoreRequests);
        fixture.Clock.Set(leased.RetryNotBefore);
        var result = await fixture.Adapter(restarted, outbox, ingress).StoreAsync(
            scope,
            fixture.Signer,
            envelope);

        Assert.Equal(42UL, result.Cursor);
        Assert.Equal(2, ingress.StoreRequests.Count);
        Assert.Equal(ingress.StoreRequests[0], ingress.StoreRequests[1]);
        var first = MailboxAuthenticatedClientRequestCodec.Decode(
            ingress.StoreRequests[0]);
        var second = MailboxAuthenticatedClientRequestCodec.Decode(
            ingress.StoreRequests[1]);
        Assert.Equal(1UL, first.Presentation.ReplayCounter);
        Assert.Equal(first.Presentation.ReplayCounter,
            second.Presentation.ReplayCounter);

        var nextEnvelope = fixture.StoreEnvelope(0x41);
        ingress.Store = (canonical, _) => fixture.StoreQuorum(canonical);
        await fixture.Adapter(restarted, outbox, ingress).StoreAsync(
            scope,
            fixture.Signer,
            nextEnvelope);
        Assert.Equal(
            2UL,
            MailboxAuthenticatedClientRequestCodec.Decode(
                ingress.StoreRequests[^1]).Presentation.ReplayCounter);
    }

    [Fact]
    public async Task Store_rejects_wrong_mqr3_binding_before_durable_outbox()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var outbox = new InMemorySessionStore();
        var ingress = new ScriptedIngress
        {
            Store = (canonical, _) => fixture.StoreQuorum(
                canonical,
                operationIdOverride: Bytes(16, 0xee))
        };
        var envelope = fixture.StoreEnvelope(0x32);
        var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x23));

        await Assert.ThrowsAsync<MailboxReceiptException>(() =>
            fixture.Adapter(state, outbox, ingress).StoreAsync(
                scope,
                fixture.Signer,
                envelope));

        var persisted = await outbox.ReadTransportOutboxAsync(
            scope,
            OutboxLogicalId.FromBytes(envelope.OperationId.Span));
        Assert.Equal(TransportOutboxState.Attempted, persisted.Item!.State);
    }

    [Fact]
    public async Task Retrieve_commits_large_exact_mrp1_before_durable_success()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var outbox = new InMemorySessionStore();
        var operationId = Bytes(16, 0x51);
        var page = fixture.RetrievePage(operationId, 70 * 1024);
        var canonicalPage = MailboxClientCodec.EncodeRetrievePage(page);
        Assert.True(canonicalPage.Length > 64 * 1024);
        var ingress = new ScriptedIngress
        {
            Retrieve = (_, _) => canonicalPage
        };
        var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x24));

        var result = await fixture.Adapter(state, outbox, ingress).RetrieveAsync(
            scope,
            fixture.Signer,
            fixture.OwnMailboxId,
            7,
            operationId,
            10);

        Assert.Single(result.NewItems);
        Assert.Equal(70 * 1024, result.NewItems[0].Envelope.Ciphertext.Length);
        var sent = Assert.Single(ingress.RetrieveRequests);
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(sent);
        Assert.Equal(MailboxAuthenticatedOperation.Retrieve,
            decoded.Binding.Operation);
        Assert.Equal("MBR2",
            System.Text.Encoding.ASCII.GetString(
                decoded.Binding.CanonicalRequest.Span[..4]));
        var persisted = await outbox.ReadTransportOutboxAsync(
            scope,
            OutboxLogicalId.FromBytes(operationId));
        Assert.Equal(TransportOutboxState.Durable, persisted.Item!.State);
        Assert.Single(await state.ReadDurableInboxAsync(fixture.Scope));
    }

    [Fact]
    public async Task Retrieve_crash_after_state_commit_recovers_same_nonfinal_mau2()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var commit = 0;
        var outbox = new InMemorySessionStore(
            statePath: null,
            point =>
            {
                if (point == TransportOutboxCommitFaultPoint.BeforeDurableCommit &&
                    Interlocked.Increment(ref commit) == 3)
                {
                    throw new IOException("crash-after-mailbox-state");
                }
            });
        var operationId = Bytes(16, 0x53);
        var token = Bytes(32, 0x54);
        var page = fixture.RetrievePage(
            operationId,
            64,
            hasMore: true,
            continuationToken: token);
        var canonicalPage = MailboxClientCodec.EncodeRetrievePage(page);
        var ingress = new ScriptedIngress
        {
            Retrieve = (_, _) => canonicalPage
        };
        var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x26));

        await Assert.ThrowsAsync<IOException>(() =>
            fixture.Adapter(state, outbox, ingress).RetrieveAsync(
                scope,
                fixture.Signer,
                fixture.OwnMailboxId,
                7,
                operationId,
                10));
        Assert.Equal(42UL,
            (await state.ReadTraversalAsync(fixture.Scope)).AfterCursor);

        fixture.Clock.Set((await outbox.ReadTransportOutboxAsync(
            scope,
            OutboxLogicalId.FromBytes(operationId))).Item!.NotBefore);
        var result = await fixture.Adapter(state, outbox, ingress)
            .RetrieveAsync(
                scope,
                fixture.Signer,
                fixture.OwnMailboxId,
                7,
                operationId,
                10);

        Assert.Equal(42UL, result.AfterCursor);
        Assert.Equal(token, result.ContinuationToken.ToArray());
        Assert.Equal(2, ingress.RetrieveRequests.Count);
        Assert.Equal(
            ingress.RetrieveRequests[0],
            ingress.RetrieveRequests[1]);
        Assert.Equal(
            1UL,
            MailboxAuthenticatedClientRequestCodec.Decode(
                ingress.RetrieveRequests[1]).Presentation.ReplayCounter);
        var persisted = await outbox.ReadTransportOutboxAsync(
            scope,
            OutboxLogicalId.FromBytes(operationId));
        Assert.Equal(TransportOutboxState.Durable, persisted.Item!.State);
        var evidence = persisted.Item.Attempts
            .Single(attempt =>
                attempt.State == TransportOutboxAttemptState.Durable)
            .GetEvidenceCopy();
        Assert.Equal(
            "MRSO",
            System.Text.Encoding.ASCII.GetString(evidence[..4]));
        Assert.Equal(
            SHA256.HashData(canonicalPage),
            evidence[32..64]);
        var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
            MailboxAuthenticatedClientRequestCodec.Decode(
                ingress.RetrieveRequests[0]).Binding.CanonicalRequest.Span);
        var summary =
            ClientMailboxRetrieveOutcomeSummary.DecodeAndValidate(
                evidence,
                request);
        Assert.Equal(42UL, summary.ResultAfterCursor);
        Assert.Equal(token, summary.ContinuationToken.ToArray());
    }

    [Fact]
    public async Task Retrieve_retry_returns_exact_operation_summary_not_mutable_traversal()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var outbox = new InMemorySessionStore();
        var firstOperation = Bytes(16, 0x55);
        var secondOperation = Bytes(16, 0x56);
        var firstToken = Bytes(32, 0x57);
        var secondToken = Bytes(32, 0x58);
        var ingress = new ScriptedIngress
        {
            Retrieve = (_, call) => MailboxClientCodec.EncodeRetrievePage(
                call == 1
                    ? fixture.RetrievePage(
                        firstOperation,
                        64,
                        hasMore: true,
                        continuationToken: firstToken,
                        cursor: 42)
                    : fixture.RetrievePage(
                        secondOperation,
                        64,
                        hasMore: true,
                        continuationToken: secondToken,
                        cursor: 84,
                        envelopeMarker: 0x75))
        };
        var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x2a));
        var adapter = fixture.Adapter(state, outbox, ingress);

        var first = await adapter.RetrieveAsync(
            scope,
            fixture.Signer,
            fixture.OwnMailboxId,
            7,
            firstOperation,
            10);
        var second = await adapter.RetrieveAsync(
            scope,
            fixture.Signer,
            fixture.OwnMailboxId,
            7,
            secondOperation,
            10);
        var retriedFirst = await adapter.RetrieveAsync(
            scope,
            fixture.Signer,
            fixture.OwnMailboxId,
            7,
            firstOperation,
            10);

        Assert.Equal(42UL, first.AfterCursor);
        Assert.Equal(84UL, second.AfterCursor);
        Assert.Equal(42UL, retriedFirst.AfterCursor);
        Assert.True(retriedFirst.HasMore);
        Assert.Equal(firstToken, retriedFirst.ContinuationToken.ToArray());
        Assert.Empty(retriedFirst.NewItems);
        Assert.Equal(2, ingress.RetrieveRequests.Count);
    }

    [Fact]
    public void Retrieve_summary_rejects_malformed_and_equivocated_evidence()
    {
        var fixture = new Fixture();
        var operationId = Bytes(16, 0x59);
        var page = fixture.RetrievePage(
            operationId,
            64,
            hasMore: true,
            continuationToken: Bytes(32, 0x5a));
        var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7,
            operationId,
            fixture.OwnMailboxId,
            fixture.Route.PlacementId,
            0,
            10,
            []);
        var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
            binding.CanonicalRequest.Span);
        var canonical = MailboxClientCodec.EncodeRetrievePage(page);
        var evidence = ClientMailboxRetrieveOutcomeSummary.Encode(
            request,
            page,
            canonical);

        var malformed = evidence.ToArray();
        malformed[4] = 2;
        Assert.Throws<InvalidDataException>(() =>
            ClientMailboxRetrieveOutcomeSummary.DecodeAndValidate(
                malformed,
                request));
        var equivocated = evidence.ToArray();
        equivocated[64 + 7] = 1;
        Assert.Throws<InvalidDataException>(() =>
            ClientMailboxRetrieveOutcomeSummary.DecodeAndValidate(
                equivocated,
                request));
    }

    [Fact]
    public async Task Native_recovery_fails_closed_on_multiple_success_history()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var durableOutbox = new InMemorySessionStore();
        var operationId = Bytes(16, 0x5b);
        var page = fixture.RetrievePage(operationId, 64);
        var ingress = new ScriptedIngress
        {
            Retrieve = (_, _) => MailboxClientCodec.EncodeRetrievePage(page)
        };
        var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x2b));
        await fixture.Adapter(state, durableOutbox, ingress).RetrieveAsync(
            scope,
            fixture.Signer,
            fixture.OwnMailboxId,
            7,
            operationId,
            10);
        var tampered = new ReadTamperingOutbox(
            durableOutbox,
            snapshot =>
            {
                var attempts = snapshot.Attempts.ToList();
                var evidence = attempts.Single(
                    attempt =>
                        attempt.State == TransportOutboxAttemptState.Durable)
                    .GetEvidenceCopy();
                attempts.Add(new TransportOutboxAttemptSnapshot(
                    OutboxAttemptId.FromBytes(Bytes(16, 0xdc)),
                    TransportOutboxAttemptState.Accepted,
                    OutboxTransitionSource.Adapter,
                    OutboxTransitionReason.AdapterAccepted,
                    snapshot.TransitionedAt,
                    evidence));
                return Clone(snapshot, attempts);
            });

        await Assert.ThrowsAsync<TransportOutboxCorruptException>(() =>
            fixture.Adapter(state, tampered, ingress).RetrieveAsync(
                scope,
                fixture.Signer,
                fixture.OwnMailboxId,
                7,
                operationId,
                10));

        Assert.Single(ingress.RetrieveRequests);
    }

    [Fact]
    public async Task Ack_wrong_mar1_then_retry_reuses_exact_mau2_and_counter()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var outbox = new InMemorySessionStore();
        var page = fixture.RetrievePage(Bytes(16, 0x52), 64);
        await state.CommitRetrievePageAsync(
            fixture.Scope,
            new ClientMailboxTraversal(0, []),
            page);
        var acknowledgement = page.Items[0].ToAcknowledgement();
        var ackOperationId = Bytes(16, 0x61);
        var ingress = new ScriptedIngress
        {
            Ack = (canonical, call) => fixture.AckResponse(
                canonical,
                operationIdOverride:
                    call == 1 ? Bytes(16, 0xef) : null)
        };
        var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x25));
        var adapter = fixture.Adapter(state, outbox, ingress);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            adapter.AcknowledgeAsync(
                scope,
                fixture.Signer,
                fixture.OwnMailboxId,
                7,
                ackOperationId,
                true,
                ReadOnlyMemory<byte>.Empty,
                [acknowledgement]));
        Assert.Equal(
            ClientMailboxAckState.Pending,
            await state.CheckAcknowledgementsAsync(
                fixture.Scope,
                [acknowledgement]));

        fixture.Clock.Set((await outbox.ReadTransportOutboxAsync(
            scope,
            OutboxLogicalId.FromBytes(ackOperationId))).Item!.NotBefore);
        var result = await fixture.Adapter(state, outbox, ingress)
            .AcknowledgeAsync(
                scope,
                fixture.Signer,
                fixture.OwnMailboxId,
                7,
                ackOperationId,
                true,
                ReadOnlyMemory<byte>.Empty,
                [acknowledgement]);

        Assert.False(result.Idempotent);
        Assert.Equal(2, ingress.AckRequests.Count);
        Assert.Equal(ingress.AckRequests[0], ingress.AckRequests[1]);
        Assert.Equal(
            1UL,
            MailboxAuthenticatedClientRequestCodec.Decode(
                ingress.AckRequests[0]).Presentation.ReplayCounter);
        Assert.Equal(
            ClientMailboxAckState.AlreadyCommitted,
            await state.CheckAcknowledgementsAsync(
                fixture.Scope,
                [acknowledgement]));
    }

    [Fact]
    public async Task Ack_crash_after_state_commit_resends_and_persists_exact_mar1()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var commit = 0;
        var outbox = new InMemorySessionStore(
            statePath: null,
            point =>
            {
                if (point == TransportOutboxCommitFaultPoint.BeforeDurableCommit &&
                    Interlocked.Increment(ref commit) == 3)
                {
                    throw new IOException("crash-after-ack-state");
                }
            });
        var page = fixture.RetrievePage(Bytes(16, 0x62), 64);
        await state.CommitRetrievePageAsync(
            fixture.Scope,
            new ClientMailboxTraversal(0, []),
            page);
        var acknowledgement = page.Items[0].ToAcknowledgement();
        var operationId = Bytes(16, 0x63);
        var ingress = new ScriptedIngress
        {
            Ack = (canonical, _) => fixture.AckResponse(canonical)
        };
        var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x27));

        await Assert.ThrowsAsync<IOException>(() =>
            fixture.Adapter(state, outbox, ingress).AcknowledgeAsync(
                scope,
                fixture.Signer,
                fixture.OwnMailboxId,
                7,
                operationId,
                true,
                ReadOnlyMemory<byte>.Empty,
                [acknowledgement]));
        Assert.Equal(
            ClientMailboxAckState.AlreadyCommitted,
            await state.CheckAcknowledgementsAsync(
                fixture.Scope,
                [acknowledgement]));

        fixture.Clock.Set((await outbox.ReadTransportOutboxAsync(
            scope,
            OutboxLogicalId.FromBytes(operationId))).Item!.NotBefore);
        var result = await fixture.Adapter(state, outbox, ingress)
            .AcknowledgeAsync(
                scope,
                fixture.Signer,
                fixture.OwnMailboxId,
                7,
                operationId,
                true,
                ReadOnlyMemory<byte>.Empty,
                [acknowledgement]);

        Assert.True(result.Idempotent);
        Assert.Equal(2, ingress.AckRequests.Count);
        Assert.Equal(ingress.AckRequests[0], ingress.AckRequests[1]);
        var persisted = await outbox.ReadTransportOutboxAsync(
            scope,
            OutboxLogicalId.FromBytes(operationId));
        Assert.Equal(TransportOutboxState.Durable, persisted.Item!.State);
        var evidence = persisted.Item.Attempts
            .Single(attempt =>
                attempt.State == TransportOutboxAttemptState.Durable)
            .GetEvidenceCopy();
        Assert.Equal("MCO1",
            System.Text.Encoding.ASCII.GetString(evidence[..4]));
        Assert.Equal(
            SHA256.HashData(fixture.AckResponse(
                ingress.AckRequests[1])),
            evidence[8..]);
    }

    [Fact]
    public async Task Ack_crash_recovery_rejects_equivocated_receipt_expiry()
    {
        var fixture = new Fixture();
        var state = await fixture.StateAsync();
        var commit = 0;
        var outbox = new InMemorySessionStore(
            statePath: null,
            point =>
            {
                if (point == TransportOutboxCommitFaultPoint.BeforeDurableCommit &&
                    Interlocked.Increment(ref commit) == 3)
                {
                    throw new IOException("crash-after-ack-state");
                }
            });
        var page = fixture.RetrievePage(Bytes(16, 0x64), 64);
        await state.CommitRetrievePageAsync(
            fixture.Scope,
            new ClientMailboxTraversal(0, []),
            page);
        var acknowledgement = page.Items[0].ToAcknowledgement();
        var operationId = Bytes(16, 0x65);
        var ingress = new ScriptedIngress
        {
            Ack = (canonical, call) => fixture.AckResponse(
                canonical,
                expiresAtOverride: call == 1 ? null : 1130)
        };
        var scope = OutboxAccountScope.FromBytes(Bytes(32, 0x28));

        await Assert.ThrowsAsync<IOException>(() =>
            fixture.Adapter(state, outbox, ingress).AcknowledgeAsync(
                scope,
                fixture.Signer,
                fixture.OwnMailboxId,
                7,
                operationId,
                true,
                ReadOnlyMemory<byte>.Empty,
                [acknowledgement]));

        fixture.Clock.Set((await outbox.ReadTransportOutboxAsync(
            scope,
            OutboxLogicalId.FromBytes(operationId))).Item!.NotBefore);
        await Assert.ThrowsAsync<MailboxReceiptException>(() =>
            fixture.Adapter(state, outbox, ingress).AcknowledgeAsync(
                scope,
                fixture.Signer,
                fixture.OwnMailboxId,
                7,
                operationId,
                true,
                ReadOnlyMemory<byte>.Empty,
                [acknowledgement]));

        Assert.Equal(2, ingress.AckRequests.Count);
        Assert.Equal(ingress.AckRequests[0], ingress.AckRequests[1]);
        Assert.Equal(
            ClientMailboxAckState.AlreadyCommitted,
            await state.CheckAcknowledgementsAsync(
                fixture.Scope,
                [acknowledgement]));
        var persisted = await outbox.ReadTransportOutboxAsync(
            scope,
            OutboxLogicalId.FromBytes(operationId));
        Assert.Equal(TransportOutboxState.Attempted, persisted.Item!.State);
    }

    private sealed class Fixture
    {
        private readonly byte[] issuerSeed = Bytes(32, 0x01);
        private readonly byte[] holderSeed = Bytes(32, 0x21);
        private readonly byte[] firstSeed = Bytes(32, 0x41);
        private readonly byte[] secondSeed = Bytes(32, 0x61);
        private readonly byte[] firstId = Bytes(32, 0x81);
        private readonly byte[] secondId = Bytes(32, 0xa1);
        private readonly byte[] membership = Bytes(32, 0xc1);
        private readonly byte[] issuerContext = Bytes(32, 0xe1);
        private readonly BlindedPlacementId placementId =
            new(Bytes(32, 0x71));
        private readonly SodiumMailboxPeerReplicationCrypto receiptCrypto =
            new();
        private readonly MailboxCredentialGeneration credentials;
        private readonly MailboxCredentialImportPolicy importPolicy;

        public Fixture()
        {
            var capabilityCrypto = new SodiumMailboxCapabilityCrypto();
            var issuerKey = capabilityCrypto.GetPublicKey(issuerSeed);
            var holderKey = capabilityCrypto.GetPublicKey(holderSeed);
            var current = new MailboxCredentialEpoch(
                7,
                900,
                1200,
                membership,
                placementId.Bytes.Span,
                MailboxPlacementCommitment.Compute(placementId));
            var nextPlacement = new BlindedPlacementId(Bytes(32, 0x72));
            var next = new MailboxCredentialEpoch(
                8,
                1100,
                1400,
                Bytes(32, 0xc2),
                nextPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(nextPlacement));
            credentials = new MailboxCredentialGeneration(
                Bytes(32, 0x11),
                Bytes(32, 0x12),
                Bytes(16, 0x13),
                issuerKey,
                holderKey,
                OwnMailboxId.Bytes.Span,
                PeerMailboxId.Bytes.Span,
                current,
                next,
                Set(MailboxCapabilityDomain.Retrieve, 0x31, current, next),
                Set(MailboxCapabilityDomain.Deposit, 0x41, current, next),
                Set(MailboxCapabilityDomain.Deposit, 0x51, current, next),
                new MailboxCredentialReplicaPair(
                    firstId,
                    receiptCrypto.GetPublicKey(firstSeed),
                    secondId,
                    receiptCrypto.GetPublicKey(secondSeed)));
            importPolicy = new MailboxCredentialImportPolicy(
                credentials.Generation,
                credentials.ManifestHash,
                credentials.NetworkId,
                issuerKey,
                holderKey,
                credentials.Replicas,
                new NoRevocations(),
                1050);
            Signer = new OperationSigner(holderSeed, holderKey);
            var otherSeed = Bytes(32, 0x19);
            OtherSigner = new OperationSigner(
                otherSeed,
                capabilityCrypto.GetPublicKey(otherSeed));
            Route = new ClientMailboxPinnedRoute(
                placementId,
                membership,
                firstId,
                receiptCrypto.GetPublicKey(firstSeed),
                secondId,
                receiptCrypto.GetPublicKey(secondSeed));
        }

        public BlindedMailboxId OwnMailboxId { get; } =
            new(Bytes(32, 0x31));

        public BlindedMailboxId PeerMailboxId { get; } =
            new(Bytes(32, 0x51));

        public ClientMailboxPinnedRoute Route { get; }

        public OperationSigner Signer { get; }

        public OperationSigner OtherSigner { get; }

        public MutableTimeProvider Clock { get; } = new(1050);

        public ClientMailboxScope Scope =>
            ClientMailboxScope.Derive(issuerContext, OwnMailboxId, 7);

        public async Task<InMemoryClientMailboxStateRepository> StateAsync()
        {
            var state = new InMemoryClientMailboxStateRepository();
            await state.ImportCredentialGenerationAsync(
                credentials,
                importPolicy);
            return state;
        }

        public ClientMailboxAdapter Adapter(
            InMemoryClientMailboxStateRepository state,
            ITransportOutboxRepository outbox,
            IClientMailboxBinaryIngress ingress) =>
            new(
                ClientFeatureFlags.Defaults with
                {
                    ClientMailboxAdapterEnabled = true
                },
                new ClientMailboxActivation(
                    true,
                    issuerContext,
                    Route,
                    true),
                ingress,
                outbox,
                state,
                new PinnedClientMailboxReceiptVerifier(receiptCrypto),
                new MailboxAuthenticatedRequestFactory(
                    state,
                    new NoRevocations(),
                    Clock),
                Policy(),
                Clock);

        public MailboxEncryptedEnvelope StoreEnvelope(byte value) => new()
        {
            Epoch = 7,
            MailboxId = PeerMailboxId,
            PlacementId = placementId,
            OperationId = Bytes(16, value),
            DeduplicationDigest = Bytes(32, unchecked((byte)(value + 1))),
            CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1120,
            Ciphertext = Bytes(64, unchecked((byte)(value + 2)))
        };

        public MailboxRetrievePage RetrievePage(
            byte[] operationId,
            int ciphertextBytes,
            bool hasMore = false,
            byte[]? continuationToken = null,
            ulong cursor = 42,
            byte envelopeMarker = 0x71) =>
            new()
            {
                Epoch = 7,
                OperationId = operationId,
                NextCursor = cursor,
                HasMore = hasMore,
                ContinuationToken = continuationToken ??
                    Array.Empty<byte>(),
                Items =
                [
                    new MailboxRetrievedEnvelope
                    {
                        Cursor = cursor,
                        Envelope = new MailboxEncryptedEnvelope
                        {
                            Epoch = 7,
                            MailboxId = OwnMailboxId,
                            PlacementId = placementId,
                            OperationId = Bytes(16, envelopeMarker),
                            DeduplicationDigest = Bytes(
                                32,
                                unchecked((byte)(envelopeMarker + 1))),
                            CreatedAtUnixSeconds = 1000,
                            ExpiresAtUnixSeconds = 1120,
                            Ciphertext = Bytes(
                                ciphertextBytes,
                                unchecked((byte)(envelopeMarker + 2)))
                        }
                    }
                ]
            };

        public byte[] StoreQuorum(
            ReadOnlyMemory<byte> canonicalMau2,
            byte[]? operationIdOverride = null)
        {
            var request = MailboxAuthenticatedClientRequestCodec.Decode(
                canonicalMau2.Span);
            var envelope =
                MailboxAuthenticatedRequestTranscript.DecodeStoreBody(
                    request.Binding.CanonicalRequest.Span);
            return Quorum(
                operationIdOverride ?? envelope.OperationId.ToArray(),
                envelope.MailboxId,
                envelope.DeduplicationDigest.ToArray(),
                envelope.ExpiresAtUnixSeconds,
                42,
                MailboxReplicaDisposition.Stored,
                envelope.OperationId.Span[0]);
        }

        public byte[] AckResponse(
            ReadOnlyMemory<byte> canonicalMau2,
            byte[]? operationIdOverride = null,
            ulong? expiresAtOverride = null)
        {
            var request = MailboxAuthenticatedClientRequestCodec.Decode(
                canonicalMau2.Span);
            var ack = MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                request.Binding.CanonicalRequest.Span);
            return MailboxAggregateAckCodec.EncodeMqr3(
                new MailboxAggregateAckResponse
                {
                    Epoch = ack.Epoch,
                    OperationId =
                        operationIdOverride ?? ack.OperationId.ToArray(),
                    TombstoneQuorums = ack.Acknowledgements
                        .Select((value, index) =>
                            (ReadOnlyMemory<byte>)Quorum(
                                ack.OperationId.ToArray(),
                                ack.MailboxId,
                                value.EnvelopeDigest.ToArray(),
                                expiresAtOverride ?? 1120,
                                value.Cursor,
                                MailboxReplicaDisposition.Tombstone,
                                checked((ulong)(10 + index))))
                        .ToArray()
                });
        }

        private byte[] Quorum(
            byte[] operationId,
            BlindedMailboxId mailboxId,
            byte[] digest,
            ulong expiresAt,
            ulong cursor,
            MailboxReplicaDisposition disposition,
            ulong sequence)
        {
            var first = Replica(
                firstId,
                firstSeed,
                operationId,
                mailboxId,
                digest,
                expiresAt,
                cursor,
                disposition);
            var second = Replica(
                secondId,
                secondSeed,
                operationId,
                mailboxId,
                digest,
                expiresAt,
                cursor,
                disposition);
            return MailboxReceiptV3Codec.EncodeDurableQuorum(
                receiptCrypto.SignQuorumResponse(
                    new MailboxDurableQuorumReceiptV3
                    {
                        CoordinatorId = firstId,
                        CoordinatorSequence = sequence,
                        FirstReplica = first,
                        SecondReplica = second,
                        Signature = ReadOnlyMemory<byte>.Empty
                    },
                    firstSeed));
        }

        private MailboxReplicaReceiptV2 Replica(
            byte[] replicaId,
            byte[] seed,
            byte[] operationId,
            BlindedMailboxId mailboxId,
            byte[] digest,
            ulong expiresAt,
            ulong cursor,
            MailboxReplicaDisposition disposition) =>
            receiptCrypto.SignReplicaResponse(
                new MailboxReplicaReceiptV2
                {
                    Status = MailboxReceiptStatus.Durable,
                    Disposition = disposition,
                    ReplicaId = replicaId,
                    OperationId = operationId,
                    Epoch = 7,
                    Cursor = cursor,
                    AcceptedAtUnixSeconds = 1050,
                    DurableAtUnixSeconds = 1051,
                    ExpiresAtUnixSeconds = expiresAt,
                    BlindedMailboxId = mailboxId.Bytes,
                    PlacementCommitment =
                        MailboxPlacementCommitment.Compute(placementId),
                    MembershipCommitment = membership,
                    EnvelopeDigest = digest,
                    Signature = ReadOnlyMemory<byte>.Empty
                },
                seed);

        private MailboxCredentialGrantSet Set(
            MailboxCapabilityDomain domain,
            byte serial,
            MailboxCredentialEpoch current,
            MailboxCredentialEpoch next) =>
            new(
                Grant(domain, serial, current),
                Grant(domain, unchecked((byte)(serial + 1)), next));

        private byte[] Grant(
            MailboxCapabilityDomain domain,
            byte serial,
            MailboxCredentialEpoch epoch)
        {
            var crypto = new SodiumMailboxCapabilityCrypto();
            var grant = new MailboxAuthenticatedGrant
            {
                Domain = domain,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = Bytes(16, 0x13),
                Epoch = epoch.Epoch,
                Generation = epoch.Epoch,
                Serial = Bytes(16, serial),
                NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
                ExpiresAtUnixSeconds = epoch.ExpiresAtUnixSeconds,
                OverlapUntilUnixSeconds = 0,
                PlacementCommitment = epoch.PlacementCommitment.ToArray(),
                MembershipCommitment = epoch.MembershipCommitment.ToArray(),
                IssuerPublicKey = crypto.GetPublicKey(issuerSeed),
                HolderPublicKey = crypto.GetPublicKey(holderSeed),
                IssuerSignature = new byte[64]
            };
            return MailboxAuthenticatedCapabilityCodec.EncodeGrant(
                crypto.SignGrant(grant, issuerSeed));
        }
    }

    private sealed class ScriptedIngress : IClientMailboxBinaryIngress
    {
        public Func<ReadOnlyMemory<byte>, int, byte[]>? Store { get; set; }
        public Func<ReadOnlyMemory<byte>, int, byte[]>? Retrieve { get; set; }
        public Func<ReadOnlyMemory<byte>, int, byte[]>? Ack { get; set; }
        public List<byte[]> StoreRequests { get; } = [];
        public List<byte[]> RetrieveRequests { get; } = [];
        public List<byte[]> AckRequests { get; } = [];

        public Task<ReadOnlyMemory<byte>> StoreAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default)
        {
            StoreRequests.Add(canonicalMau2.ToArray());
            return Task.FromResult<ReadOnlyMemory<byte>>(
                Store!(canonicalMau2, StoreRequests.Count));
        }

        public Task<ReadOnlyMemory<byte>> RetrieveAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default)
        {
            RetrieveRequests.Add(canonicalMau2.ToArray());
            return Task.FromResult<ReadOnlyMemory<byte>>(
                Retrieve!(canonicalMau2, RetrieveRequests.Count));
        }

        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default)
        {
            AckRequests.Add(canonicalMau2.ToArray());
            return Task.FromResult<ReadOnlyMemory<byte>>(
                Ack!(canonicalMau2, AckRequests.Count));
        }
    }

    private sealed class CoordinatedStoreIngress(
        Func<ReadOnlyMemory<byte>, byte[]> respond)
        : IClientMailboxBinaryIngress
    {
        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public List<byte[]> Requests { get; } = [];

        public async Task<ReadOnlyMemory<byte>> StoreAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(canonicalMau2.ToArray());
            Entered.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return respond(canonicalMau2);
        }

        public Task<ReadOnlyMemory<byte>> RetrieveAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class ReadTamperingOutbox(
        ITransportOutboxRepository inner,
        Func<TransportOutboxItemSnapshot, TransportOutboxItemSnapshot> tamper)
        : ITransportOutboxRepository
    {
        public Task<TransportOutboxCommitResult> PrepareTransportOutboxAsync(
            TransportOutboxPreparedItem item,
            CancellationToken cancellationToken = default) =>
            inner.PrepareTransportOutboxAsync(item, cancellationToken);

        public async Task<TransportOutboxReadSnapshot> ReadTransportOutboxAsync(
            OutboxAccountScope accountScope,
            OutboxLogicalId logicalId,
            CancellationToken cancellationToken = default)
        {
            var read = await inner.ReadTransportOutboxAsync(
                accountScope,
                logicalId,
                cancellationToken);
            return read is
                { Result: TransportOutboxReadResult.Found, Item: not null }
                ? new TransportOutboxReadSnapshot(
                    TransportOutboxReadResult.Found,
                    tamper(read.Item))
                : read;
        }

        public Task<TransportOutboxCommitResult>
            ApplyTransportOutboxTransitionAsync(
                OutboxAccountScope accountScope,
                TransportOutboxTransition transition,
                CancellationToken cancellationToken = default) =>
            inner.ApplyTransportOutboxTransitionAsync(
                accountScope,
                transition,
                cancellationToken);

        public Task<IReadOnlyList<TransportOutboxItemSnapshot>>
            ListReadyTransportOutboxAsync(
                OutboxAccountScope accountScope,
                DateTimeOffset now,
                int limit,
                CancellationToken cancellationToken = default) =>
            inner.ListReadyTransportOutboxAsync(
                accountScope,
                now,
                limit,
                cancellationToken);

        public Task<int> ExpireDueTransportOutboxAsync(
            OutboxAccountScope accountScope,
            DateTimeOffset now,
            int limit,
            CancellationToken cancellationToken = default) =>
            inner.ExpireDueTransportOutboxAsync(
                accountScope,
                now,
                limit,
                cancellationToken);

        public Task PurgeTransportOutboxScopeAsync(
            OutboxAccountScope accountScope,
            CancellationToken cancellationToken = default) =>
            inner.PurgeTransportOutboxScopeAsync(
                accountScope,
                cancellationToken);
    }

    private static TransportOutboxItemSnapshot Clone(
        TransportOutboxItemSnapshot snapshot,
        IReadOnlyList<TransportOutboxAttemptSnapshot> attempts) =>
        new(
            snapshot.AccountScope,
            snapshot.LogicalId,
            snapshot.DedupMaterial,
            snapshot.GetCiphertextBundleCopy(),
            snapshot.CreatedAt,
            snapshot.ExpiresAt,
            snapshot.NotBefore,
            snapshot.State,
            snapshot.Revision,
            snapshot.Source,
            snapshot.Reason,
            snapshot.TransitionedAt,
            attempts,
            snapshot.GetAcknowledgementEvidenceCopy());

    private sealed class OperationSigner(
        byte[] seed,
        byte[] publicKey) : IMailboxOperationSigner
    {
        public SessionId SessionId =>
            SessionId.Parse("05" + new string('a', 64));

        public byte[] GetEd25519PublicKey() => publicKey.ToArray();

        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> canonicalPresentationSigningBytes) =>
            PublicKeyAuth.SignDetached(
                canonicalPresentationSigningBytes.ToArray(),
                PublicKeyAuth.GenerateKeyPair(seed).PrivateKey);
    }

    private sealed class NoRevocations : IMailboxCapabilityRevocationSource
    {
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }

    private sealed class MutableTimeProvider(long seconds) : TimeProvider
    {
        private DateTimeOffset now =
            DateTimeOffset.FromUnixTimeSeconds(seconds);

        public override DateTimeOffset GetUtcNow() =>
            now;

        public void Set(DateTimeOffset value) => now = value;
    }

    private static MailboxClientDecodePolicy Policy() => new()
    {
        NowUnixSeconds = 1050,
        EpochWindow = new MailboxEpochWindow
        {
            CurrentEpoch = 7,
            NextEpoch = 8,
            CurrentNotBeforeUnixSeconds = 900,
            NextNotBeforeUnixSeconds = 1100,
            CurrentExpiresAtUnixSeconds = 1200,
            NextExpiresAtUnixSeconds = 1400
        },
        CapabilityPolicy = new MailboxCapabilityDecodePolicy
        {
            CurrentBucket = 1050,
            MinimumGeneration = 7
        }
    };

    private static byte[] Bytes(int count, byte start)
    {
        var value = new byte[count];
        for (var index = 0; index < count; index++)
        {
            value[index] = unchecked((byte)(start + index));
        }
        if (value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            value[0] = 1;
        }
        return value;
    }
}
