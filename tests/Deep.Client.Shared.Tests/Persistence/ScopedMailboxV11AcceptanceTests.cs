using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;
using Sodium;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class ScopedMailboxV11AcceptanceTests
{
    [Fact]
    public async Task Atomic_import_survives_restart_with_exact_scoped_routes()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialBatchAsync(
            [fixture.Self, fixture.Peer, fixture.Group], fixture.Authority);

        using var restarted = fixture.Restart();
        var self = await restarted.ReadScopedMailboxRouteAsync(
            fixture.SelfSelector, fixture.Authority);
        var peer = await restarted.ReadScopedMailboxRouteAsync(
            fixture.PeerSelector, fixture.Authority);
        var group = await restarted.ReadScopedMailboxRouteAsync(
            fixture.GroupSelector, fixture.Authority);

        Assert.Equal(fixture.Self.MailboxId.ToArray(), self.MailboxId.Bytes.ToArray());
        Assert.Equal(fixture.Peer.MailboxId.ToArray(), peer.MailboxId.Bytes.ToArray());
        Assert.Equal(fixture.Group.MailboxId.ToArray(), group.MailboxId.Bytes.ToArray());
        Assert.Equal(fixture.GroupSelector.GroupMembershipCommitment.ToArray(),
            group.MembershipCommitment.ToArray());
    }

    [Fact]
    public async Task Exact_import_retry_is_idempotent_and_material_retry_is_not()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialBatchAsync(
            [fixture.Self, fixture.Peer], fixture.Authority);
        await fixture.Store.InstallScopedCredentialBatchAsync(
            [fixture.Self, fixture.Peer], fixture.Authority);

        var changed = fixture.CreateGeneration(
            fixture.PeerSelector, MailboxCredentialScopeKind.Peer, 0x42,
            generationOverride: Bytes(32, 0xe1));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.InstallScopedCredentialBatchAsync([changed], fixture.Authority));
        Assert.Equal(2, fixture.Count("mailbox_credential_scopes"));
    }

    [Fact]
    public async Task Failure_on_last_import_target_rolls_back_every_prior_target()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Peer, fixture.Authority);
        var changedPeer = fixture.CreateGeneration(
            fixture.PeerSelector, MailboxCredentialScopeKind.Peer, 0x42,
            generationOverride: Bytes(32, 0xe2));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.InstallScopedCredentialBatchAsync(
                [fixture.Self, changedPeer], fixture.Authority));

        Assert.Equal(1, fixture.Count("mailbox_credential_scopes"));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.ReadScopedMailboxRouteAsync(
                fixture.SelfSelector, fixture.Authority));
    }

    [Fact]
    public async Task Reused_mailbox_material_across_scopes_conflicts_whole_import()
    {
        using var fixture = new Fixture();
        var peerWithSelfMailbox = fixture.CreateGeneration(
            fixture.PeerSelector, MailboxCredentialScopeKind.Peer, 0x42,
            mailboxOverride: fixture.Self.MailboxId.ToArray());

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialBatchAsync(
                [fixture.Self, peerWithSelfMailbox], fixture.Authority));

        Assert.Equal(0, fixture.Count("mailbox_credential_scopes"));
    }

    [Fact]
    public async Task Wrong_holder_rejects_import_without_partial_scope()
    {
        using var fixture = new Fixture();
        var wrong = fixture.Self with { HolderPublicKey = Bytes(32, 0xf1) };
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialAsync(wrong, fixture.Authority));
        Assert.Equal(0, fixture.Count("mailbox_credential_scopes"));
    }

    [Fact]
    public async Task Revoked_grant_rejects_import_without_partial_scope()
    {
        using var fixture = new Fixture();
        fixture.Revocations.Revoked = true;
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority));
        Assert.Equal(0, fixture.Count("mailbox_credential_scopes"));
    }

    [Fact]
    public async Task Factory_emits_canonical_verifiable_mau2()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        var factory = new MailboxAuthenticatedRequestFactory(
            fixture.Store, fixture.Authority);

        var frame = await factory.CreateRetrieveAsync(
            fixture.Account, fixture.SelfSelector, fixture.Signer,
            Bytes(16, 0x81), 0, 25, ReadOnlyMemory<byte>.Empty);
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(
            frame.GetCanonicalMau2Copy());

        Assert.Equal(MailboxAuthenticatedOperation.Retrieve, decoded.Binding.Operation);
        Assert.Equal(1UL, decoded.Presentation.ReplayCounter);
        Assert.Equal(fixture.Signer.GetEd25519PublicKey(),
            decoded.Presentation.Grant.HolderPublicKey.ToArray());
    }

    [Fact]
    public async Task Live_revocation_rejects_prepare_without_counter_burn()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        var factory = new MailboxAuthenticatedRequestFactory(
            fixture.Store, fixture.Authority);
        fixture.Revocations.Revoked = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            factory.CreateRetrieveAsync(
                fixture.Account, fixture.SelfSelector, fixture.Signer,
                Bytes(16, 0x82), 0, 25, ReadOnlyMemory<byte>.Empty));

        fixture.Revocations.Revoked = false;
        var valid = await factory.CreateRetrieveAsync(
            fixture.Account, fixture.SelfSelector, fixture.Signer,
            Bytes(16, 0x83), 0, 25, ReadOnlyMemory<byte>.Empty);
        Assert.Equal(1UL, Counter(valid));
    }

    [Fact]
    public async Task Invalid_route_binding_does_not_burn_counter()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        var wrong = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7, Bytes(16, 0x84), new BlindedMailboxId(Bytes(32, 0xf2)),
            new BlindedPlacementId(fixture.Self.Current.PlacementId.Span), 0, 10, []);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.PrepareAsync(
                Bytes(16, 0x84),
                [new ScopedMailboxBatchTarget(fixture.SelfSelector, wrong)]));

        var valid = await fixture.PrepareRetrieveAsync(
            fixture.SelfSelector, fixture.Self, 0x85);
        Assert.Equal(1UL, Counter(valid.Frames.Single()));
    }

    [Fact]
    public async Task Sqlite_restart_allocates_next_counter_without_reuse()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        var first = await fixture.PrepareRetrieveAsync(
            fixture.SelfSelector, fixture.Self, 0x86);

        using var restarted = fixture.Restart();
        var second = await fixture.PrepareRetrieveAsync(
            restarted, fixture.SelfSelector, fixture.Self, 0x87);

        Assert.Equal(1UL, Counter(first.Frames.Single()));
        Assert.Equal(2UL, Counter(second.Frames.Single()));
    }

    [Fact]
    public async Task Two_sqlite_instances_allocate_distinct_monotonic_counters()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        using var second = fixture.Restart();

        var operations = Enumerable.Range(0, 12).Select(index =>
            fixture.PrepareRetrieveAsync(
                (index & 1) == 0 ? fixture.Store : second,
                fixture.SelfSelector, fixture.Self,
                checked((byte)(0x90 + index))));
        var counters = (await Task.WhenAll(operations))
            .Select(result => Counter(result.Frames.Single()))
            .Order()
            .ToArray();

        Assert.Equal(Enumerable.Range(1, 12).Select(value => (ulong)value), counters);
    }

    [Fact]
    public async Task Atomic_multi_target_batch_allocates_and_persists_every_target_once()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialBatchAsync(
            [fixture.Self, fixture.Peer, fixture.Group], fixture.Authority);
        var targets = new[]
        {
            fixture.RetrieveTarget(fixture.SelfSelector, fixture.Self, 0xa1),
            fixture.StoreTarget(fixture.PeerSelector, fixture.Peer, 0xa2),
            fixture.StoreTarget(fixture.GroupSelector, fixture.Group, 0xa3)
        }.OrderBy(target => Convert.ToHexString(target.Selector.ScopeId.Span))
         .ThenBy(target => Convert.ToHexString(target.Binding.OperationId.Span))
         .ToArray();

        var prepared = await fixture.PrepareAsync(Bytes(16, 0xaa), targets);
        Assert.Equal(3, prepared.Frames.Count);
        Assert.All(prepared.Frames, frame => Assert.Equal(1UL, Counter(frame)));
        Assert.Equal(3, fixture.Count("transport_outbox_items"));

        var resumed = await fixture.PrepareAsync(Bytes(16, 0xaa), targets);
        Assert.Equal(prepared.Frames.Select(frame => frame.GetCanonicalMau2Copy()),
            resumed.Frames.Select(frame => frame.GetCanonicalMau2Copy()));
        Assert.Equal(3, fixture.Count("transport_outbox_items"));
    }

    [Fact]
    public async Task Failure_on_last_prepare_target_leaves_zero_batch_outbox_and_counters()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialBatchAsync(
            [fixture.Self, fixture.Peer], fixture.Authority);
        var valid = fixture.RetrieveTarget(fixture.SelfSelector, fixture.Self, 0xb1);
        var invalidBinding = MailboxAuthenticatedRequestTranscript.ForStore(
            fixture.Envelope(fixture.Peer, 0xb2) with
            {
                MailboxId = new BlindedMailboxId(Bytes(32, 0xf3))
            });
        var targets = new[]
        {
            valid,
            new ScopedMailboxBatchTarget(fixture.PeerSelector, invalidBinding)
        }.OrderBy(target => Convert.ToHexString(target.Selector.ScopeId.Span))
         .ThenBy(target => Convert.ToHexString(target.Binding.OperationId.Span))
         .ToArray();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.PrepareAsync(Bytes(16, 0xbb), targets));

        Assert.Equal(0, fixture.Count("mailbox_prepared_batches"));
        Assert.Equal(0, fixture.Count("transport_outbox_items"));
        Assert.Equal(0, fixture.Count("mailbox_replay_counters"));
    }

    [Fact]
    public async Task Conflicting_parent_plan_is_rejected_without_counter_burn()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        var parent = Bytes(16, 0xbc);
        var first = fixture.RetrieveTarget(fixture.SelfSelector, fixture.Self, 0xbd);
        await fixture.PrepareAsync(parent, [first]);
        var changed = fixture.RetrieveTarget(fixture.SelfSelector, fixture.Self, 0xbe);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.PrepareAsync(parent, [changed]));

        Assert.Equal(1, fixture.Count("mailbox_replay_counters"));
        Assert.Equal(1, fixture.Count("transport_outbox_items"));
    }

    [Fact]
    public async Task Counter_exhaustion_fails_before_outbox_mutation()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        _ = await fixture.PrepareRetrieveAsync(fixture.SelfSelector, fixture.Self, 0xc1);
        fixture.SetAllCounters(ulong.MaxValue);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.PrepareRetrieveAsync(fixture.SelfSelector, fixture.Self, 0xc2));

        Assert.Equal(1, fixture.Count("transport_outbox_items"));
    }

    [Fact]
    public async Task Epoch_switch_revalidates_authority_and_starts_next_grant_counter()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        var current = await fixture.PrepareRetrieveAsync(
            fixture.SelfSelector, fixture.Self, 0xc3);
        fixture.Clock.SetUnixSeconds(1150);
        await fixture.Store.SwitchScopedCredentialEpochAsync(
            fixture.SelfSelector, 8, fixture.Authority);
        var next = fixture.Self with { Current = fixture.Self.Next };
        var preparedNext = await fixture.PrepareRetrieveAsync(
            fixture.SelfSelector, next, 0xc4);

        Assert.Equal(1UL, Counter(current.Frames.Single()));
        Assert.Equal(1UL, Counter(preparedNext.Frames.Single()));
        Assert.Equal(8UL,
            MailboxAuthenticatedClientRequestCodec.Decode(
                preparedNext.Frames.Single().GetCanonicalMau2Copy())
                .Presentation.Grant.Epoch);
    }

    [Fact]
    public async Task Wrong_network_authority_rejects_import_without_mutation()
    {
        using var fixture = new Fixture();
        var wrong = fixture.CreateAuthority(
            Bytes(16, 0xf4), fixture.IssuerPublicKey);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialAsync(fixture.Self, wrong));
        Assert.Equal(0, fixture.Count("mailbox_credential_scopes"));
    }

    [Fact]
    public async Task Wrong_issuer_authority_rejects_import_without_mutation()
    {
        using var fixture = new Fixture();
        var wrong = fixture.CreateAuthority(
            fixture.Authority.NetworkId.ToArray(), Bytes(32, 0xf5));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialAsync(fixture.Self, wrong));
        Assert.Equal(0, fixture.Count("mailbox_credential_scopes"));
    }

    [Fact]
    public void Replica_pair_rejects_zero_and_duplicate_ids()
    {
        Assert.Throws<ArgumentException>(() => new MailboxCredentialReplicaPair(
            new byte[32], Bytes(32, 1), Bytes(32, 2), Bytes(32, 3)));
        Assert.Throws<ArgumentException>(() => new MailboxCredentialReplicaPair(
            Bytes(32, 4), Bytes(32, 5), Bytes(32, 4), Bytes(32, 6)));
    }

    [Fact]
    public async Task Batch_rejects_duplicate_and_noncanonical_targets_without_mutation()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        var target = fixture.RetrieveTarget(fixture.SelfSelector, fixture.Self, 0xd1);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            fixture.PrepareAsync(Bytes(16, 0xd2), [target, target]));

        Assert.Equal(0, fixture.Count("mailbox_replay_counters"));
        Assert.Equal(0, fixture.Count("transport_outbox_items"));
    }

    [Fact]
    public async Task Outbox_operation_conflict_rolls_back_new_counter()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        var first = await fixture.PrepareRetrieveAsync(
            fixture.SelfSelector, fixture.Self, 0xd3);
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(
            first.Frames.Single().GetCanonicalMau2Copy());
        var conflict = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7, decoded.Binding.OperationId.Span,
            new BlindedMailboxId(fixture.Self.MailboxId.Span),
            new BlindedPlacementId(fixture.Self.Current.PlacementId.Span),
            1, 10, []);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.PrepareAsync(Bytes(16, 0xd4),
                [new ScopedMailboxBatchTarget(fixture.SelfSelector, conflict)]));

        Assert.Equal(1, fixture.Count("transport_outbox_items"));
        Assert.Equal(2UL, fixture.ReadNextCounters().Single());
    }

    [Fact]
    public async Task Route_read_rejects_expired_authority_dynamically()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(fixture.Self, fixture.Authority);
        fixture.Clock.SetUnixSeconds(1201);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.ReadScopedMailboxRouteAsync(
                fixture.SelfSelector, fixture.Authority));
    }

    private static ulong Counter(MailboxAuthenticatedRequestFrame frame) =>
        MailboxAuthenticatedClientRequestCodec.Decode(frame.GetCanonicalMau2Copy())
            .Presentation.ReplayCounter;

    private sealed class Fixture : IDisposable
    {
        private readonly byte[] issuerSeed = Bytes(32, 0x01);
        private readonly byte[] holderSeed = Bytes(32, 0x21);
        private readonly byte[] firstSeed = Bytes(32, 0x41);
        private readonly byte[] secondSeed = Bytes(32, 0x61);
        private readonly SodiumMailboxCapabilityCrypto capabilityCrypto = new();
        private readonly SodiumMailboxPeerReplicationCrypto replicaCrypto = new();

        public Fixture()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
                $"deep-scoped-v11-{Guid.NewGuid():N}.db");
            Clock = new MutableTimeProvider(1050);
            Revocations = new MutableRevocations();
            Account = OutboxAccountScope.FromBytes(Bytes(32, 0x10));
            var issuerContext = Bytes(32, 0x30);
            SelfSelector = new MailboxCredentialSelector(
                Account, MailboxCredentialScopeKind.Self,
                Bytes(32, 0x31), issuerContext);
            PeerSelector = new MailboxCredentialSelector(
                Account, MailboxCredentialScopeKind.Peer,
                Bytes(32, 0x32), issuerContext);
            GroupSelector = new MailboxCredentialSelector(
                Account, MailboxCredentialScopeKind.Group,
                Bytes(32, 0x33), issuerContext, Bytes(32, 0x73));
            IssuerPublicKey = capabilityCrypto.GetPublicKey(issuerSeed);
            Authority = CreateAuthority(Bytes(16, 0x13), IssuerPublicKey);
            Signer = new OperationSigner(holderSeed,
                capabilityCrypto.GetPublicKey(holderSeed));
            Self = CreateGeneration(SelfSelector, MailboxCredentialScopeKind.Self, 0x41);
            Peer = CreateGeneration(PeerSelector, MailboxCredentialScopeKind.Peer, 0x42);
            Group = CreateGeneration(GroupSelector, MailboxCredentialScopeKind.Group, 0x43);
            Store = new SqliteSessionStore(Path);
        }

        public string Path { get; }
        public SqliteSessionStore Store { get; }
        public OutboxAccountScope Account { get; }
        public MailboxCredentialSelector SelfSelector { get; }
        public MailboxCredentialSelector PeerSelector { get; }
        public MailboxCredentialSelector GroupSelector { get; }
        public VerifiedOfficialMailboxAuthority Authority { get; }
        public byte[] IssuerPublicKey { get; }
        public MutableTimeProvider Clock { get; }
        public MutableRevocations Revocations { get; }
        public OperationSigner Signer { get; }
        public ScopedMailboxCredentialGeneration Self { get; }
        public ScopedMailboxCredentialGeneration Peer { get; }
        public ScopedMailboxCredentialGeneration Group { get; }

        public SqliteSessionStore Restart() => new(Path);

        public VerifiedOfficialMailboxAuthority CreateAuthority(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> issuerPublicKey) => new(
            networkId,
            1,
            [
                Issuer(issuerPublicKey, MailboxCapabilityDomain.Deposit),
                Issuer(issuerPublicKey, MailboxCapabilityDomain.Retrieve)
            ],
            true,
            static () => true,
            Revocations,
            Clock);

        public ScopedMailboxCredentialGeneration CreateGeneration(
            MailboxCredentialSelector selector,
            MailboxCredentialScopeKind kind,
            byte marker,
            byte[]? generationOverride = null,
            byte[]? mailboxOverride = null)
        {
            var membership = kind == MailboxCredentialScopeKind.Group
                ? selector.GroupMembershipCommitment.ToArray()
                : Bytes(32, checked((byte)(marker + 0x20)));
            var currentPlacement = new BlindedPlacementId(Bytes(32, marker));
            var nextPlacement = new BlindedPlacementId(Bytes(32, checked((byte)(marker + 1))));
            var current = new MailboxCredentialEpoch(
                7, 900, 1200, membership, currentPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(currentPlacement));
            var nextMembership = kind == MailboxCredentialScopeKind.Group
                ? membership
                : Bytes(32, checked((byte)(marker + 0x21)));
            var next = new MailboxCredentialEpoch(
                8, 1100, 1400, nextMembership, nextPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(nextPlacement));
            var serialBase = checked((byte)((marker - 0x40) * 4));
            var retrieve = kind == MailboxCredentialScopeKind.Peer
                ? null
                : Set(MailboxCapabilityDomain.Retrieve,
                    serialBase, current, next);
            var deposit = Set(MailboxCapabilityDomain.Deposit,
                checked((byte)(serialBase + 2)), current, next);
            return new ScopedMailboxCredentialGeneration(
                selector,
                generationOverride ?? Material(marker, 1),
                capabilityCrypto.GetPublicKey(holderSeed),
                mailboxOverride ?? Material(marker, 2),
                current,
                next,
                retrieve,
                deposit,
                new MailboxCredentialReplicaPair(
                    Bytes(32, 0x81), replicaCrypto.GetPublicKey(firstSeed),
                    Bytes(32, 0xa1), replicaCrypto.GetPublicKey(secondSeed)));
        }

        public ScopedMailboxBatchTarget RetrieveTarget(
            MailboxCredentialSelector selector,
            ScopedMailboxCredentialGeneration generation,
            byte operation) => new(
                selector,
                MailboxAuthenticatedRequestTranscript.ForRetrieve(
                    generation.Current.Epoch, Bytes(16, operation),
                    new BlindedMailboxId(generation.MailboxId.Span),
                    new BlindedPlacementId(generation.Current.PlacementId.Span),
                    0, 25, []));

        public ScopedMailboxBatchTarget StoreTarget(
            MailboxCredentialSelector selector,
            ScopedMailboxCredentialGeneration generation,
            byte operation) => new(
                selector,
                MailboxAuthenticatedRequestTranscript.ForStore(
                    Envelope(generation, operation)));

        public MailboxEncryptedEnvelope Envelope(
            ScopedMailboxCredentialGeneration generation,
            byte operation) => new()
            {
                Epoch = generation.Current.Epoch,
                MailboxId = new BlindedMailboxId(generation.MailboxId.Span),
                PlacementId = new BlindedPlacementId(generation.Current.PlacementId.Span),
                OperationId = Bytes(16, operation),
                DeduplicationDigest = Bytes(32, checked((byte)(operation + 1))),
                CreatedAtUnixSeconds = 1000,
                ExpiresAtUnixSeconds = 1120,
                Ciphertext = Bytes(64, checked((byte)(operation + 2)))
            };

        public Task<ScopedMailboxPreparedBatch> PrepareRetrieveAsync(
            MailboxCredentialSelector selector,
            ScopedMailboxCredentialGeneration generation,
            byte operation) => PrepareRetrieveAsync(
                Store, selector, generation, operation);

        public Task<ScopedMailboxPreparedBatch> PrepareRetrieveAsync(
            SqliteSessionStore store,
            MailboxCredentialSelector selector,
            ScopedMailboxCredentialGeneration generation,
            byte operation) => PrepareAsync(
                store, Bytes(16, operation),
                [RetrieveTarget(selector, generation, operation)]);

        public Task<ScopedMailboxPreparedBatch> PrepareAsync(
            byte[] parentOperationId,
            IReadOnlyList<ScopedMailboxBatchTarget> targets) =>
            PrepareAsync(Store, parentOperationId, targets);

        private Task<ScopedMailboxPreparedBatch> PrepareAsync(
            SqliteSessionStore store,
            byte[] parentOperationId,
            IReadOnlyList<ScopedMailboxBatchTarget> targets) =>
            store.PrepareScopedMailboxBatchAsync(
                new ScopedMailboxPrepareBatchRequest(
                    Account, parentOperationId, targets,
                    DateTimeOffset.FromUnixTimeSeconds(Clock.GetUtcNow().ToUnixTimeSeconds())),
                Signer, Authority);

        public int Count(string table)
        {
            using var connection = new SqliteConnection($"Data Source={Path};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT count(*) FROM {table};";
            return Convert.ToInt32(command.ExecuteScalar());
        }

        public IReadOnlyList<ulong> ReadNextCounters()
        {
            using var connection = new SqliteConnection($"Data Source={Path};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT next_counter FROM mailbox_replay_counters;";
            using var reader = command.ExecuteReader();
            var values = new List<ulong>();
            while (reader.Read())
                values.Add(BinaryPrimitives.ReadUInt64BigEndian((byte[])reader.GetValue(0)));
            return values;
        }

        public void SetAllCounters(ulong value)
        {
            var encoded = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
            using var connection = new SqliteConnection($"Data Source={Path};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE mailbox_replay_counters SET next_counter=$counter;";
            command.Parameters.Add("$counter", SqliteType.Blob).Value = encoded;
            command.ExecuteNonQuery();
        }

        private MailboxCredentialGrantSet Set(
            MailboxCapabilityDomain domain,
            byte serial,
            MailboxCredentialEpoch current,
            MailboxCredentialEpoch next) => new(
                Grant(domain, serial, current),
                Grant(domain, checked((byte)(serial + 1)), next));

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
                HolderPublicKey = capabilityCrypto.GetPublicKey(holderSeed),
                IssuerSignature = new byte[64]
            };
            return MailboxAuthenticatedCapabilityCodec.EncodeGrant(
                capabilityCrypto.SignGrant(unsigned, issuerSeed));
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

        public void Dispose()
        {
            Store.Dispose();
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { Path, Path + "-wal", Path + "-shm" })
                if (File.Exists(candidate)) File.Delete(candidate);
        }
    }

    private sealed class OperationSigner(byte[] seed, byte[] publicKey) :
        IMailboxOperationSigner
    {
        public SessionId SessionId => SessionId.Parse("05" + new string('a', 64));
        public byte[] GetEd25519PublicKey() => publicKey.ToArray();
        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> canonicalPresentationSigningBytes) =>
            PublicKeyAuth.SignDetached(
                canonicalPresentationSigningBytes.ToArray(),
                PublicKeyAuth.GenerateKeyPair(seed).PrivateKey);
    }

    private sealed class MutableRevocations : IFreshMailboxCapabilityRevocationSource
    {
        public void ValidateFreshness() { }
        public bool Revoked { get; set; }
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => Revoked;
    }

    private sealed class MutableTimeProvider(long seconds) : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(seconds);
        public override DateTimeOffset GetUtcNow() => now;
        public void SetUnixSeconds(long value) =>
            now = DateTimeOffset.FromUnixTimeSeconds(value);
    }

    private static byte[] Bytes(int count, byte start)
    {
        var value = new byte[count];
        for (var index = 0; index < count; index++)
            value[index] = unchecked((byte)(start + index));
        if (value.AsSpan().IndexOfAnyExcept((byte)0) < 0) value[0] = 1;
        return value;
    }

    private static byte[] Material(byte marker, byte domain) =>
        SHA256.HashData([domain, marker]);
}
