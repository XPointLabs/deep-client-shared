using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;
using Sodium;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class ScopedMailboxRepositoryConformanceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Multi_scope_import_exact_retry_and_conflict_are_aligned(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialBatchAsync(
            [fixture.Self, fixture.Peer], fixture.Authority);
        await fixture.Repository.InstallScopedCredentialBatchAsync(
            [fixture.Self, fixture.Peer], fixture.Authority);
        Assert.Equal(2, fixture.CredentialCount());

        var changed = fixture.Peer with
        {
            Generation = Bytes(32, 0xe1)
        };
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Repository.InstallScopedCredentialBatchAsync(
                [fixture.Self, changed], fixture.Authority));
        Assert.Equal(2, fixture.CredentialCount());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pair_rotation_is_atomic_monotonic_and_exactly_idempotent(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialBatchAsync(
            [fixture.Self, fixture.Peer], fixture.Authority);
        fixture.Clock.Set(1150);
        var rotatedSelf = fixture.Rotate(fixture.Self, 0x91);
        var rotatedPeer = fixture.Rotate(fixture.Peer, 0xa1);
        var badPlacement = new BlindedPlacementId(Bytes(32, 0xf1));
        var badPeer = rotatedPeer with
        {
            Current = new MailboxCredentialEpoch(
                rotatedPeer.Current.Epoch,
                rotatedPeer.Current.NotBeforeUnixSeconds,
                rotatedPeer.Current.ExpiresAtUnixSeconds,
                rotatedPeer.Current.MembershipCommitment.Span,
                badPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(badPlacement))
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Repository.RotateScopedCredentialBatchAsync(
                [rotatedSelf, badPeer], fixture.Authority));
        Assert.Equal(7UL, (await fixture.Repository.ReadScopedMailboxRouteAsync(
            fixture.SelfSelector, fixture.Authority)).Epoch);

        await fixture.Repository.RotateScopedCredentialBatchAsync(
            [rotatedSelf, rotatedPeer], fixture.Authority);
        await fixture.Repository.RotateScopedCredentialBatchAsync(
            [rotatedSelf, rotatedPeer], fixture.Authority);
        Assert.Equal(8UL, (await fixture.Repository.ReadScopedMailboxRouteAsync(
            fixture.SelfSelector, fixture.Authority)).Epoch);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Repository.RotateScopedCredentialBatchAsync(
                [fixture.Self, fixture.Peer], fixture.Authority));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Prepare_fault_rolls_back_batch_counter_and_outbox(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        fixture.ThrowBeforePreparePublish = true;

        await Assert.ThrowsAsync<InjectedFaultException>(() =>
            fixture.PrepareAsync(fixture.SelfTarget(0x91)));

        Assert.Equal(0, fixture.BatchCount());
        Assert.Equal(0, fixture.OutboxCount());
        Assert.Empty(fixture.NextCounters());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Prepare_after_publish_fault_reports_unknown_but_keeps_atomic_state(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        fixture.ThrowAfterPreparePublish = true;

        await Assert.ThrowsAsync<TransportOutboxCommitOutcomeUnknownException>(
            () => fixture.PrepareAsync(fixture.SelfTarget(0x92)));

        Assert.Equal(1, fixture.BatchCount());
        Assert.Equal(1, fixture.OutboxCount());
        Assert.Equal([2UL], fixture.NextCounters());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancelled_prepare_publishes_no_batch_counter_or_outbox(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            fixture.PrepareAsync(
                fixture.SelfTarget(0x93), cancellation.Token));

        Assert.Equal(0, fixture.BatchCount());
        Assert.Equal(0, fixture.OutboxCount());
        Assert.Empty(fixture.NextCounters());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Concurrent_prepare_allocates_unique_counters_without_reuse(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        var tasks = Enumerable.Range(0, 16)
            .Select(index => fixture.PrepareAsync(
                fixture.SelfTarget(checked((byte)(0xa0 + index)))))
            .ToArray();
        var batches = await Task.WhenAll(tasks);
        var counters = batches
            .Select(batch => MailboxAuthenticatedClientRequestCodec.Decode(
                batch.Frames.Single().GetCanonicalMau2Copy())
                .Presentation.ReplayCounter)
            .Order()
            .ToArray();

        Assert.Equal(
            Enumerable.Range(1, 16).Select(static value => (ulong)value),
            counters);
        Assert.Equal(16, fixture.BatchCount());
        Assert.Equal(16, fixture.OutboxCount());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Counter_exhaustion_is_atomic_and_epoch_switch_restarts_namespace(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        _ = await fixture.PrepareAsync(fixture.SelfTarget(0xb1));
        fixture.SetAllNextCounters(ulong.MaxValue);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.PrepareAsync(fixture.SelfTarget(0xb2)));
        Assert.Equal(1, fixture.BatchCount());
        Assert.Equal(1, fixture.OutboxCount());

        fixture.Clock.Set(1150);
        await fixture.Repository.SwitchScopedCredentialEpochAsync(
            fixture.SelfSelector, 8, fixture.Authority);
        var route = await fixture.Repository.ReadScopedMailboxRouteAsync(
            fixture.SelfSelector, fixture.Authority);
        Assert.Equal(8UL, route.Epoch);
        Assert.Equal(
            fixture.Self.NextReplicas.FirstId.ToArray(),
            route.Replicas.FirstId.ToArray());
        Assert.Equal(
            fixture.Self.NextReplicas.SecondId.ToArray(),
            route.Replicas.SecondId.ToArray());
        var next = await fixture.PrepareAsync(
            fixture.SelfTarget(0xb3, nextEpoch: true));
        Assert.Equal(
            1UL,
            MailboxAuthenticatedClientRequestCodec.Decode(
                next.Frames.Single().GetCanonicalMau2Copy())
                .Presentation.ReplayCounter);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Prepared_retry_cannot_rebind_to_rotated_epoch_or_replica_pair(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        var currentRoute = await fixture.Repository.ReadScopedMailboxRouteAsync(
            fixture.SelfSelector, fixture.Authority);
        Assert.Equal(
            fixture.Self.CurrentReplicas.FirstId.ToArray(),
            currentRoute.Replicas.FirstId.ToArray());
        var target = fixture.SelfTarget(0xb4);
        _ = await fixture.PrepareAsync(target);

        fixture.Clock.Set(1150);
        await fixture.Repository.SwitchScopedCredentialEpochAsync(
            fixture.SelfSelector, fixture.Self.Next.Epoch, fixture.Authority);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.ResumeAsync(target));
        Assert.Equal(1, fixture.BatchCount());
        Assert.Equal(1, fixture.OutboxCount());
        Assert.Equal([2UL], fixture.NextCounters());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Exact_resume_and_corrupt_target_rejection_are_aligned(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        var target = fixture.SelfTarget(0xc1);
        Assert.Null(await fixture.ResumeAsync(target));
        var first = await fixture.PrepareAsync(target);
        Assert.Equal([2UL], fixture.NextCounters());
        Assert.Equal(1, fixture.BatchCount());
        Assert.Equal(1, fixture.OutboxCount());
        fixture.Clock.Set(1051);
        var resumed = Assert.IsType<ScopedMailboxPreparedBatch>(
            await fixture.ResumeAsync(target));
        Assert.Equal(
            first.Frames.Single().GetCanonicalMau2Copy(),
            resumed.Frames.Single().GetCanonicalMau2Copy());
        Assert.Equal([2UL], fixture.NextCounters());
        Assert.Equal(1, fixture.BatchCount());
        Assert.Equal(1, fixture.OutboxCount());

        fixture.DeletePreparedTargets(Bytes(16, 0xc1));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.ResumeAsync(target));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Semantic_operation_cannot_rebind_its_durable_fan_out(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        var semantic = Bytes(16, 0xd0);
        var originalTarget = fixture.SelfTarget(0xd1);
        var changedTarget = fixture.SelfTarget(0xd2);
        var original = fixture.BatchRequest(originalTarget, semantic);
        var changed = fixture.BatchRequest(changedTarget, semantic);

        _ = await fixture.Repository.PrepareScopedMailboxBatchAsync(
            original, fixture.Signer, fixture.Authority);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Repository.TryResumeScopedMailboxBatchAsync(
                new ScopedMailboxResumeBatchRequest(
                    changed.AccountScope,
                    changed.ParentOperationId,
                    changed.SemanticOperationId,
                    changed.Selectors),
                fixture.Signer,
                fixture.Authority));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Repository.PrepareScopedMailboxBatchAsync(
                changed, fixture.Signer, fixture.Authority));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Repository.PrepareScopedMailboxBatchAsync(
                original with { SemanticOperationId = Bytes(16, 0xd3) },
                fixture.Signer,
                fixture.Authority));

        Assert.Equal(1, fixture.BatchCount());
        Assert.Equal(1, fixture.OutboxCount());
        Assert.Equal([2UL], fixture.NextCounters());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Same_scope_batch_orders_by_stable_wire_id_not_random_operation_id(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        var first = fixture.SelfTarget(0xe2);
        var second = fixture.SelfTarget(0xe1);
        var selectors = new[]
        {
            new ScopedMailboxBatchSelector(
                fixture.SelfSelector,
                new MessageId("wire-a"),
                first.Binding.Operation),
            new ScopedMailboxBatchSelector(
                fixture.SelfSelector,
                new MessageId("wire-b"),
                second.Binding.Operation)
        };
        var request = new ScopedMailboxPrepareBatchRequest(
            fixture.Account,
            Bytes(16, 0xe3),
            Bytes(16, 0xe4),
            selectors,
            [first, second],
            DateTimeOffset.FromUnixTimeSeconds(fixture.Clock.Seconds));

        var prepared = await fixture.Repository.PrepareScopedMailboxBatchAsync(
            request, fixture.Signer, fixture.Authority);
        Assert.Equal(2, prepared.Frames.Count);
        Assert.Equal([3UL], fixture.NextCounters());

        await Assert.ThrowsAsync<ArgumentException>(() =>
            fixture.Repository.PrepareScopedMailboxBatchAsync(
                request with
                {
                    Selectors = selectors.Reverse().ToArray(),
                    Targets = new[] { second, first }
                },
                fixture.Signer,
                fixture.Authority));
        Assert.Equal(1, fixture.BatchCount());
        Assert.Equal(2, fixture.OutboxCount());
        Assert.Equal([3UL], fixture.NextCounters());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Live_revocation_and_expiry_reject_dispatch_for_all_roles(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        fixture.Revocations.Revoked = true;
        foreach (var operation in new[]
                 {
                     MailboxAuthenticatedOperation.Store,
                     MailboxAuthenticatedOperation.Retrieve,
                     MailboxAuthenticatedOperation.Ack
                 })
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                fixture.Repository.RevalidateScopedMailboxDispatchAsync(
                    fixture.SelfSelector,
                    operation,
                    fixture.Authority));
        }

        fixture.Revocations.Revoked = false;
        fixture.Clock.Set(1500);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Repository.RevalidateScopedMailboxDispatchAsync(
                fixture.SelfSelector,
                MailboxAuthenticatedOperation.Store,
                fixture.Authority));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Epoch_switch_requires_exact_persisted_authority_and_keeps_exact_import_retry(
        bool inMemory)
    {
        using var fixture = new Fixture(inMemory);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        fixture.Clock.Set(1150);
        var wrongPolicy = fixture.AuthorityWithMinimumGeneration(2);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Repository.SwitchScopedCredentialEpochAsync(
                fixture.SelfSelector, 8, wrongPolicy));
        Assert.Equal(
            7UL,
            (await fixture.Repository.ReadScopedMailboxRouteAsync(
                fixture.SelfSelector, fixture.Authority)).Epoch);

        await fixture.Repository.SwitchScopedCredentialEpochAsync(
            fixture.SelfSelector, 8, fixture.Authority);
        await fixture.Repository.InstallScopedCredentialAsync(
            fixture.Self, fixture.Authority);
        Assert.Equal(
            8UL,
            (await fixture.Repository.ReadScopedMailboxRouteAsync(
                fixture.SelfSelector, fixture.Authority)).Epoch);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly byte[] issuerSeed = Bytes(32, 0x01);
        private readonly byte[] holderSeed = Bytes(32, 0x21);
        private readonly SodiumMailboxCapabilityCrypto crypto = new();
        private readonly InMemoryScopedMailboxCredentialRepository? memory;
        private readonly SqliteSessionStore? sqlite;

        public Fixture(bool inMemory)
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"deep-scoped-conformance-{Guid.NewGuid():N}.db");
            Clock = new MutableTimeProvider(1050);
            Revocations = new MutableRevocations();
            Account = OutboxAccountScope.FromBytes(Bytes(32, 0x11));
            var issuerContext = Bytes(32, 0x12);
            SelfSelector = new MailboxCredentialSelector(
                Account,
                MailboxCredentialScopeKind.Self,
                Bytes(32, 0x13),
                issuerContext);
            PeerSelector = new MailboxCredentialSelector(
                Account,
                MailboxCredentialScopeKind.Peer,
                Bytes(32, 0x14),
                issuerContext);
            IssuerPublicKey = crypto.GetPublicKey(issuerSeed);
            Authority = new VerifiedOfficialMailboxAuthority(
                Bytes(16, 0x15),
                1,
                [
                    Issuer(IssuerPublicKey, MailboxCapabilityDomain.Deposit),
                    Issuer(IssuerPublicKey, MailboxCapabilityDomain.Retrieve)
                ],
                true,
                static () => true,
                Revocations,
                Clock);
            Signer = new OperationSigner(
                holderSeed,
                crypto.GetPublicKey(holderSeed));
            Self = Generation(SelfSelector, 0x31, peer: false);
            Peer = Generation(PeerSelector, 0x41, peer: true);
            if (inMemory)
            {
                memory = new InMemoryScopedMailboxCredentialRepository(point =>
                {
                    if (ThrowBeforePreparePublish &&
                        point == InMemoryScopedMailboxFaultPoint
                            .PrepareBeforePublish)
                    {
                        throw new InjectedFaultException();
                    }
                    if (ThrowAfterPreparePublish &&
                        point == InMemoryScopedMailboxFaultPoint
                            .PrepareAfterPublish)
                    {
                        throw new InjectedFaultException();
                    }
                });
                Repository = memory;
            }
            else
            {
                sqlite = new SqliteSessionStore(
                    new SqliteSessionStoreOptions(Path),
                    point =>
                    {
                        if (ThrowBeforePreparePublish &&
                            point == ClientMailboxCommitFaultPoint.BeforeCommit)
                        {
                            throw new InjectedFaultException();
                        }
                        if (ThrowAfterPreparePublish &&
                            point == ClientMailboxCommitFaultPoint.AfterCommit)
                        {
                            throw new InjectedFaultException();
                        }
                    });
                Repository = sqlite;
            }
        }

        public string Path { get; }
        public IScopedMailboxCredentialRepository Repository { get; }
        public OutboxAccountScope Account { get; }
        public MailboxCredentialSelector SelfSelector { get; }
        public MailboxCredentialSelector PeerSelector { get; }
        public VerifiedOfficialMailboxAuthority Authority { get; }
        public byte[] IssuerPublicKey { get; }
        public MutableTimeProvider Clock { get; }
        public MutableRevocations Revocations { get; }
        public OperationSigner Signer { get; }
        public ScopedMailboxCredentialGeneration Self { get; }
        public ScopedMailboxCredentialGeneration Peer { get; }
        public bool ThrowBeforePreparePublish { get; set; }
        public bool ThrowAfterPreparePublish { get; set; }

        public ScopedMailboxCredentialGeneration Rotate(
            ScopedMailboxCredentialGeneration prior,
            byte marker)
        {
            var nextPlacement = new BlindedPlacementId(Bytes(32, marker));
            var next = new MailboxCredentialEpoch(
                prior.Next.Epoch + 1,
                1300,
                1700,
                Bytes(32, checked((byte)(marker + 1))),
                nextPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(nextPlacement));
            var retrieve = prior.Retrieve is null ? null :
                new MailboxCredentialGrantSet(
                    prior.Retrieve.NextGrant.Span,
                    Grant(MailboxCapabilityDomain.Retrieve,
                        checked((byte)(marker + 2)), next));
            return new ScopedMailboxCredentialGeneration(
                prior.Selector,
                SHA256.HashData([marker, (byte)9]),
                prior.HolderPublicKey,
                prior.MailboxId,
                prior.Next,
                next,
                retrieve,
                new MailboxCredentialGrantSet(
                    prior.Deposit!.NextGrant.Span,
                    Grant(MailboxCapabilityDomain.Deposit,
                        checked((byte)(marker + 3)), next)),
                prior.NextReplicas,
                new MailboxCredentialReplicaPair(
                    Bytes(32, checked((byte)(marker + 4))),
                    Bytes(32, checked((byte)(marker + 5))),
                    Bytes(32, checked((byte)(marker + 6))),
                    Bytes(32, checked((byte)(marker + 7)))));
        }

        public VerifiedOfficialMailboxAuthority AuthorityWithMinimumGeneration(
            ulong minimumGeneration) => new(
            Authority.NetworkId,
            minimumGeneration,
            Authority.TrustedIssuers,
            true,
            static () => true,
            Revocations,
            Clock);

        public ScopedMailboxBatchTarget SelfTarget(
            byte operation,
            bool nextEpoch = false)
        {
            var epoch = nextEpoch ? Self.Next : Self.Current;
            return new ScopedMailboxBatchTarget(
                SelfSelector,
                MailboxAuthenticatedRequestTranscript.ForRetrieve(
                    epoch.Epoch,
                    Bytes(16, operation),
                    new BlindedMailboxId(Self.MailboxId.Span),
                    new BlindedPlacementId(epoch.PlacementId.Span),
                    0,
                    25,
                    []));
        }

        public Task<ScopedMailboxPreparedBatch> PrepareAsync(
            ScopedMailboxBatchTarget target,
            CancellationToken cancellationToken = default) =>
            Repository.PrepareScopedMailboxBatchAsync(
                BatchRequest(target, target.Binding.OperationId),
                Signer,
                Authority,
                cancellationToken);

        public ScopedMailboxPrepareBatchRequest BatchRequest(
            ScopedMailboxBatchTarget target,
            ReadOnlyMemory<byte> semanticOperationId) => new(
            Account,
            target.Binding.OperationId,
            semanticOperationId,
            [new ScopedMailboxBatchSelector(
                target.Selector,
                new MessageId(Convert.ToHexString(target.Binding.OperationId.Span)),
                target.Binding.Operation)],
            [target],
            DateTimeOffset.FromUnixTimeSeconds(Clock.Seconds));

        public Task<ScopedMailboxPreparedBatch?> ResumeAsync(
            ScopedMailboxBatchTarget target,
            CancellationToken cancellationToken = default) =>
            Repository.TryResumeScopedMailboxBatchAsync(
                new ScopedMailboxResumeBatchRequest(
                    Account,
                    target.Binding.OperationId,
                    target.Binding.OperationId,
                    [new ScopedMailboxBatchSelector(
                        target.Selector,
                        new MessageId(Convert.ToHexString(target.Binding.OperationId.Span)),
                        target.Binding.Operation)]),
                Signer,
                Authority,
                cancellationToken);

        public int CredentialCount() => memory is not null
            ? memory.CredentialCountForTests()
            : Count("mailbox_credential_scopes");
        public int BatchCount() => memory is not null
            ? memory.PreparedBatchCountForTests()
            : Count("mailbox_prepared_batches");
        public int OutboxCount() => memory is not null
            ? memory.EquivalentOutboxCountForTests()
            : Count("transport_outbox_items");
        public IReadOnlyList<ulong> NextCounters() => memory is not null
            ? memory.NextCountersForTests()
            : ReadSqliteCounters();

        public void SetAllNextCounters(ulong value)
        {
            if (memory is not null)
            {
                memory.SetAllNextCountersForTests(value);
                return;
            }
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText =
                "UPDATE mailbox_replay_counters SET next_counter=$value;";
            command.Parameters.Add("$value", SqliteType.Blob).Value = U64(value);
            command.ExecuteNonQuery();
        }

        public void DeletePreparedTargets(byte[] parent)
        {
            if (memory is not null)
            {
                memory.DeletePreparedTargetsForTests(Account, parent);
                return;
            }
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                DELETE FROM mailbox_prepared_batch_targets
                WHERE account_scope=$account AND parent_operation_id=$parent;
                """;
            command.Parameters.Add("$account", SqliteType.Blob).Value =
                Account.ToArray();
            command.Parameters.Add("$parent", SqliteType.Blob).Value = parent;
            command.ExecuteNonQuery();
        }

        private ScopedMailboxCredentialGeneration Generation(
            MailboxCredentialSelector selector,
            byte marker,
            bool peer)
        {
            var currentPlacement = new BlindedPlacementId(Bytes(32, marker));
            var nextPlacement = new BlindedPlacementId(
                Bytes(32, checked((byte)(marker + 1))));
            var current = new MailboxCredentialEpoch(
                7,
                900,
                1200,
                Bytes(32, checked((byte)(marker + 2))),
                currentPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(currentPlacement));
            var next = new MailboxCredentialEpoch(
                8,
                1100,
                1400,
                Bytes(32, checked((byte)(marker + 3))),
                nextPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(nextPlacement));
            var serial = checked((byte)(marker + 0x40));
            return new ScopedMailboxCredentialGeneration(
                selector,
                SHA256.HashData([marker, (byte)1]),
                crypto.GetPublicKey(holderSeed),
                SHA256.HashData([marker, (byte)2]),
                current,
                next,
                peer ? null : new MailboxCredentialGrantSet(
                    Grant(MailboxCapabilityDomain.Retrieve, serial, current),
                    Grant(MailboxCapabilityDomain.Retrieve,
                        checked((byte)(serial + 1)), next)),
                new MailboxCredentialGrantSet(
                    Grant(MailboxCapabilityDomain.Deposit,
                        checked((byte)(serial + 2)), current),
                    Grant(MailboxCapabilityDomain.Deposit,
                        checked((byte)(serial + 3)), next)),
                new MailboxCredentialReplicaPair(
                    Bytes(32, 0xd1),
                    Bytes(32, 0xd2),
                    Bytes(32, 0xd3),
                    Bytes(32, 0xd4)),
                new MailboxCredentialReplicaPair(
                    Bytes(32, 0xe1),
                    Bytes(32, 0xe2),
                    Bytes(32, 0xe3),
                    Bytes(32, 0xe4)));
        }

        private byte[] Grant(
            MailboxCapabilityDomain domain,
            byte serial,
            MailboxCredentialEpoch epoch)
        {
            var unsigned = new MailboxAuthenticatedGrant
            {
                Domain = domain,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = Authority.NetworkId,
                Epoch = epoch.Epoch,
                Generation = epoch.Epoch,
                Serial = Bytes(16, serial),
                NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
                ExpiresAtUnixSeconds = epoch.ExpiresAtUnixSeconds,
                OverlapUntilUnixSeconds = 0,
                PlacementCommitment = epoch.PlacementCommitment,
                MembershipCommitment = epoch.MembershipCommitment,
                IssuerPublicKey = IssuerPublicKey,
                HolderPublicKey = crypto.GetPublicKey(holderSeed),
                IssuerSignature = new byte[64]
            };
            return MailboxAuthenticatedCapabilityCodec.EncodeGrant(
                crypto.SignGrant(unsigned, issuerSeed));
        }

        private static MailboxCapabilityIssuerAuthority Issuer(
            ReadOnlyMemory<byte> publicKey,
            MailboxCapabilityDomain domain) => new()
            {
                PublicKey = publicKey.ToArray(),
                Domain = domain,
                AllowedLifecycle = MailboxCapabilityLifecycle.Active,
                MinimumGeneration = 1,
                MaximumGeneration = ulong.MaxValue,
                ValidFromUnixSeconds = 1,
                ValidUntilUnixSeconds = ulong.MaxValue
            };

        private int Count(string table)
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT count(*) FROM {table};";
            return Convert.ToInt32(command.ExecuteScalar());
        }

        private IReadOnlyList<ulong> ReadSqliteCounters()
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText =
                "SELECT next_counter FROM mailbox_replay_counters ORDER BY scope_id,epoch,grant_digest;";
            using var reader = command.ExecuteReader();
            var values = new List<ulong>();
            while (reader.Read())
            {
                values.Add(BinaryPrimitives.ReadUInt64BigEndian(
                    (byte[])reader.GetValue(0)));
            }
            return values;
        }

        private SqliteConnection Open()
        {
            var connection = new SqliteConnection(
                $"Data Source={Path};Pooling=False");
            connection.Open();
            return connection;
        }

        public void Dispose()
        {
            sqlite?.Dispose();
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { Path, Path + "-wal", Path + "-shm" })
            {
                if (File.Exists(candidate))
                {
                    File.Delete(candidate);
                }
            }
        }
    }

    private sealed class OperationSigner(byte[] seed, byte[] publicKey) :
        IMailboxOperationSigner
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

    private sealed class MutableRevocations :
        IFreshMailboxCapabilityRevocationSource
    {
        public void ValidateFreshness() { }
        public bool Revoked { get; set; }
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => Revoked;
    }

    private sealed class MutableTimeProvider(long seconds) : TimeProvider
    {
        public long Seconds { get; private set; } = seconds;
        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.FromUnixTimeSeconds(Seconds);
        public void Set(long value) => Seconds = value;
    }

    private sealed class InjectedFaultException : Exception;

    private static byte[] U64(ulong value)
    {
        var encoded = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        return encoded;
    }

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
