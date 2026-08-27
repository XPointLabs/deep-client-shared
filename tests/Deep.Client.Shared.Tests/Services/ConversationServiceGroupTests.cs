using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ConversationServiceGroupTests
{
    private static readonly DateTimeOffset CreatedAt = DateTimeOffset.Parse("2026-06-01T00:00:00Z");

    [Fact]
    public async Task LocalGroupMutations_IncrementAndPublishExactlyOnce()
    {
        var transport = new RecordingGroupSyncTransport();
        var runtime = CreateRuntime(transport);
        var owner = Session('1');
        var bob = Session('2');
        var charlie = Session('3');

        var group = await runtime.Conversations.CreateGroupScaffoldAsync(owner, "Original", [bob]);
        Assert.Equal(1, group.Revision);

        group = (await runtime.Conversations.UpdateGroupNameAsync(group.Id, owner, "Renamed"))!;
        Assert.Equal(2, group.Revision);
        group = (await runtime.Conversations.AddMemberAsync(group.Id, owner, charlie))!;
        Assert.Equal(3, group.Revision);
        group = (await runtime.Conversations.PromoteMemberAsync(group.Id, owner, bob))!;
        Assert.Equal(4, group.Revision);
        group = (await runtime.Conversations.DemoteMemberAsync(group.Id, owner, bob))!;
        Assert.Equal(5, group.Revision);
        group = (await runtime.Conversations.MarkMemberPendingRemovalAsync(group.Id, owner, bob, true))!;
        Assert.Equal(6, group.Revision);
        group = (await runtime.Conversations.MarkMemberPendingRemovalAsync(group.Id, owner, bob, false))!;
        Assert.Equal(7, group.Revision);
        group = (await runtime.Conversations.RemoveMemberAsync(group.Id, owner, charlie))!;
        Assert.Equal(8, group.Revision);
        group = (await runtime.Conversations.LeaveGroupAsync(group.Id, bob))!;
        Assert.Equal(9, group.Revision);
        group = (await runtime.Conversations.DestroyGroupAsync(group.Id, owner))!;
        Assert.Equal(10, group.Revision);

        Assert.Equal(Enumerable.Range(1, 10).Select(static revision => (long)revision),
            transport.Published.Select(static group => group.Revision));
        Assert.Equal(group, await runtime.Conversations.GetGroupAsync(group.Id));
    }

    [Fact]
    public async Task GroupStateOutbox_SurvivesRestartAndRetriesExactlyOnce()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-group-outbox-{Guid.NewGuid():N}.db");
        var transport = new RecordingGroupSyncTransport { FailuresRemaining = 1 };
        var owner = Session('1');
        var member = Session('2');
        ConversationId groupId;

        try
        {
            var initialStore = new SqliteSessionStore(statePath);
            using (var runtime = new ClientRuntime(
                       initialStore,
                       Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
                       new FrozenClock(CreatedAt),
                       new StubSessionBackend(),
                       transport))
            {
                var group = await runtime.Conversations.CreateGroupScaffoldAsync(owner, "Durable outbox", [member]);
                groupId = group.Id;

                var persistedGroup = await runtime.Conversations.GetGroupAsync(group.Id);
                Assert.Equal(group.Id, persistedGroup?.Id);
                Assert.Equal(group.Revision, persistedGroup?.Revision);
                Assert.Equal(group.Members, persistedGroup?.Members);
                Assert.NotNull(await ((IConversationRepository)initialStore).GetAsync(group.Id));
                Assert.Single(await initialStore.ListPendingGroupStatePublishesAsync(GroupStateOutboxLimits.MaxPublishBatch));
                Assert.Empty(transport.Published);
            }

            var restartedStore = new SqliteSessionStore(statePath);
            using (var runtime = new ClientRuntime(
                       restartedStore,
                       Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
                       new FrozenClock(CreatedAt),
                       new StubSessionBackend(),
                       transport))
            {
                Assert.Equal(1, await runtime.Conversations.FlushPendingGroupStatesAsync());
                Assert.Empty(await restartedStore.ListPendingGroupStatePublishesAsync(GroupStateOutboxLimits.MaxPublishBatch));
                Assert.Equal(1, Assert.Single(transport.Published).Revision);
                Assert.Equal(groupId, transport.Published[0].Id);
            }
        }
        finally
        {
            foreach (var path in new[] { statePath, statePath + "-wal", statePath + "-shm" })
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
        }
    }

    [Fact]
    public async Task RemoveMemberPublishesFinalRevisionToRemovedMember()
    {
        var transport = new RecordingGroupSyncTransport();
        var runtime = CreateRuntime(transport);
        var owner = Session('1');
        var member = Session('2');
        var group = await runtime.Conversations.CreateGroupScaffoldAsync(owner, "Removal", [member]);

        await runtime.Conversations.RemoveMemberAsync(group.Id, owner, member);

        Assert.Contains(member, transport.PublishedRecipients[^1]);
    }

    [Fact]
    public async Task AccountPurgeRemovesPendingGroupStateOutbox()
    {
        var store = new InMemorySessionStore();
        var transport = new RecordingGroupSyncTransport { FailuresRemaining = 1 };
        using var runtime = new ClientRuntime(
            store,
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            new FrozenClock(CreatedAt),
            new StubSessionBackend(),
            transport);

        await runtime.Conversations.CreateGroupScaffoldAsync(Session('1'), "Purge", [Session('2')]);
        Assert.Single(await store.ListPendingGroupStatePublishesAsync(GroupStateOutboxLimits.MaxPublishBatch));

        await store.PurgeAccountDataAsync();

        Assert.Empty(await store.ListPendingGroupStatePublishesAsync(GroupStateOutboxLimits.MaxPublishBatch));
    }

    [Fact]
    public void GroupAddMember_DoesNotChangeRevision()
    {
        var owner = Session('1');
        var group = GroupState(owner, Session('2'), revision: 7);

        var updated = group.AddMember(new GroupMember(Session('3'), GroupMemberRole.Standard, CreatedAt));

        Assert.Equal(7, updated.Revision);
    }

    [Fact]
    public async Task ReceiveGroupUpdates_AppliesGenesisAndNextRevisionBeforeOlderTimestamp()
    {
        var transport = new RecordingGroupSyncTransport();
        var runtime = CreateRuntime(transport);
        var owner = Session('1');
        var recipient = Session('2');
        var genesis = GroupState(owner, recipient, revision: 1);
        var update = genesis with { Name = "Revision two", Revision = 2 };
        transport.Incoming =
        [
            Envelope(update, owner, CreatedAt),
            Envelope(genesis, owner, CreatedAt.AddMinutes(1))
        ];

        var applied = await runtime.Conversations.ReceiveGroupUpdatesAsync(recipient);

        Assert.Equal([1L, 2L], applied.Select(static group => group.Revision));
        var persisted = await runtime.Conversations.GetGroupAsync(genesis.Id);
        Assert.Equal(2, persisted?.Revision);
        Assert.Equal("Revision two", persisted?.Name);
    }

    [Fact]
    public async Task ReceiveGroupUpdates_RejectsGenesisWithoutCreatorAuthenticationOrAdminMembership()
    {
        var transport = new RecordingGroupSyncTransport();
        var runtime = CreateRuntime(transport);
        var owner = Session('1');
        var recipient = Session('2');
        var attacker = Session('3');
        var genesis = GroupState(owner, recipient, revision: 1);
        var creatorIsStandard = genesis with
        {
            Members =
            [
                new GroupMember(owner, GroupMemberRole.Standard, CreatedAt),
                new GroupMember(recipient, GroupMemberRole.Admin, CreatedAt)
            ]
        };
        transport.Incoming =
        [
            Envelope(genesis, attacker, CreatedAt),
            Envelope(creatorIsStandard, owner, CreatedAt.AddSeconds(1))
        ];

        var applied = await runtime.Conversations.ReceiveGroupUpdatesAsync(recipient);

        Assert.Empty(applied);
        Assert.Null(await runtime.Conversations.GetGroupAsync(genesis.Id));
    }

    [Fact]
    public async Task ReceiveGroupUpdates_RejectsSenderPromotedOnlyByUntrustedUpdate()
    {
        var transport = new RecordingGroupSyncTransport();
        var runtime = CreateRuntime(transport);
        var owner = Session('1');
        var recipient = Session('2');
        var existing = GroupState(owner, recipient, revision: 1);
        await StoreGroupAsync(runtime, existing);
        var unauthorized = existing with
        {
            Name = "Unauthorized",
            Members = existing.Members
                .Select(member => member.SessionId == recipient
                    ? member with { Role = GroupMemberRole.Admin }
                    : member)
                .ToArray(),
            Revision = 2
        };
        transport.Incoming = [Envelope(unauthorized, recipient, CreatedAt.AddMinutes(1))];

        var applied = await runtime.Conversations.ReceiveGroupUpdatesAsync(recipient);

        Assert.Empty(applied);
        Assert.Equal(existing, await runtime.Conversations.GetGroupAsync(existing.Id));
    }

    [Theory]
    [InlineData(1L)]
    [InlineData(3L)]
    public async Task ReceiveGroupUpdates_RejectsRollbackAndGap(long revision)
    {
        var transport = new RecordingGroupSyncTransport();
        var runtime = CreateRuntime(transport);
        var owner = Session('1');
        var recipient = Session('2');
        var existing = GroupState(owner, recipient, revision: 1);
        await StoreGroupAsync(runtime, existing);
        transport.Incoming =
        [
            Envelope(existing with { Name = "Rejected", Revision = revision }, owner, CreatedAt.AddMinutes(1))
        ];

        var applied = await runtime.Conversations.ReceiveGroupUpdatesAsync(recipient);

        Assert.Empty(applied);
        Assert.Equal(existing, await runtime.Conversations.GetGroupAsync(existing.Id));
    }

    [Fact]
    public async Task ReceiveGroupUpdates_RejectsChangedCreatorAndCreationTime()
    {
        var transport = new RecordingGroupSyncTransport();
        var runtime = CreateRuntime(transport);
        var owner = Session('1');
        var recipient = Session('2');
        var attacker = Session('3');
        var existing = GroupState(owner, recipient, revision: 1);
        await StoreGroupAsync(runtime, existing);
        transport.Incoming =
        [
            Envelope(existing with { CreatedBy = attacker, Revision = 2 }, owner, CreatedAt.AddMinutes(1)),
            Envelope(existing with { CreatedAt = CreatedAt.AddDays(1), Revision = 2 }, owner, CreatedAt.AddMinutes(2))
        ];

        var applied = await runtime.Conversations.ReceiveGroupUpdatesAsync(recipient);

        Assert.Empty(applied);
        Assert.Equal(existing, await runtime.Conversations.GetGroupAsync(existing.Id));
    }

    [Fact]
    public async Task ReceiveGroupUpdates_AcceptsRemovalAndRejectsRecipientResurrection()
    {
        var transport = new RecordingGroupSyncTransport();
        var runtime = CreateRuntime(transport);
        var owner = Session('1');
        var recipient = Session('2');
        var existing = GroupState(owner, recipient, revision: 1);
        await StoreGroupAsync(runtime, existing);
        var removed = existing with
        {
            Members = existing.Members.Where(member => member.SessionId != recipient).ToArray(),
            Revision = 2
        };
        var resurrected = existing with { Name = "Resurrected", Revision = 3 };
        transport.Incoming =
        [
            Envelope(resurrected, owner, CreatedAt.AddMinutes(2)),
            Envelope(removed, owner, CreatedAt.AddMinutes(1))
        ];

        var applied = await runtime.Conversations.ReceiveGroupUpdatesAsync(recipient);

        var kicked = Assert.Single(applied);
        Assert.Equal(2, kicked.Revision);
        Assert.True(kicked.IsKicked);
        var persisted = await runtime.Conversations.GetGroupAsync(existing.Id);
        Assert.Equal(2, persisted?.Revision);
        Assert.True(persisted?.IsKicked);
        Assert.DoesNotContain(persisted!.Members, member => member.SessionId == recipient);
    }

    [Fact]
    public async Task LocalMutation_CapturesImmutableRoutesBeforePersistenceAndPublishesStateThenRoutes()
    {
        var transport = new RecordingGroupSyncTransport();
        var exchange = new RecordingGroupMailboxRouteExchange();
        var runtime = CreateRuntime(transport, exchange);
        var owner = Session('1');
        var member = Session('2');

        var group = await runtime.Conversations.CreateGroupScaffoldAsync(owner, "Routed", [member]);

        var captured = Assert.Single(exchange.Captured);
        var published = Assert.Single(transport.PublishedRoutes);
        Assert.Equal(group.Id, published.GroupId);
        Assert.Equal(["state:1", "routes:1"], transport.PublishOrder);
        Assert.NotSame(captured, published);
        Assert.NotSame(captured.MembershipDigest, published.MembershipDigest);
        GroupMailboxRouteBundleCodec.ValidateForGroup(published, group);
    }

    [Fact]
    public async Task LocalMutation_WithoutCompleteRoutesFailsBeforePersistence()
    {
        var transport = new RecordingGroupSyncTransport();
        var exchange = new RecordingGroupMailboxRouteExchange { ReturnMissingBundle = true };
        var runtime = CreateRuntime(transport, exchange);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            runtime.Conversations.CreateGroupScaffoldAsync(Session('1'), "Blocked", [Session('2')]));

        Assert.Empty(await runtime.Conversations.ListGroupsAsync());
        Assert.Empty(transport.Published);
    }

    [Fact]
    public async Task ReceiveGroupRoutes_ImportsAllThirdMemberRoutesWithoutCreatingDirectContacts()
    {
        var transport = new RecordingGroupSyncTransport();
        var exchange = new RecordingGroupMailboxRouteExchange();
        var runtime = CreateRuntime(transport, exchange);
        var owner = Session('1');
        var recipient = Session('2');
        var third = Session('3');
        var group = GroupState(owner, recipient, revision: 1) with
        {
            Members =
            [
                new GroupMember(owner, GroupMemberRole.Admin, CreatedAt),
                new GroupMember(recipient, GroupMemberRole.Standard, CreatedAt),
                new GroupMember(third, GroupMemberRole.Standard, CreatedAt)
            ]
        };
        transport.Incoming = [Envelope(group, owner, CreatedAt)];
        transport.IncomingRoutes = [RouteEnvelope(group, owner, "routes-third")];

        var applied = await runtime.Conversations.ReceiveGroupUpdatesAsync(recipient);

        Assert.Single(applied);
        var imported = Assert.Single(exchange.Imported);
        Assert.Equal(new[] { owner, recipient, third }.OrderBy(static id => id.Value),
            imported.Bundle.Invitations.Select(static invitation => invitation.Member));
        Assert.Null(await runtime.Conversations.GetContactAsync(owner));
        Assert.Null(await runtime.Conversations.GetContactAsync(third));
        Assert.Contains("routes-third", transport.AcknowledgedHashes);
    }

    [Fact]
    public async Task ReceiveGroupRoutes_UnauthorizedSenderIsDiscardedBeforeImport()
    {
        var transport = new RecordingGroupSyncTransport();
        var exchange = new RecordingGroupMailboxRouteExchange();
        var runtime = CreateRuntime(transport, exchange);
        var owner = Session('1');
        var recipient = Session('2');
        var attacker = Session('3');
        var group = GroupState(owner, recipient, revision: 1);
        await StoreGroupAsync(runtime, group);
        transport.IncomingRoutes = [RouteEnvelope(group, attacker, "routes-attacker")];

        await runtime.Conversations.ReceiveGroupUpdatesAsync(recipient);

        Assert.Empty(exchange.Imported);
        Assert.Contains("routes-attacker", transport.AcknowledgedHashes);
    }

    [Fact]
    public async Task ReceiveGroupRoutes_TransientImportFailureRetriesAndAcknowledgesOnlyAfterSuccess()
    {
        var transport = new RecordingGroupSyncTransport();
        var exchange = new RecordingGroupMailboxRouteExchange { ImportFailuresRemaining = 1 };
        var runtime = CreateRuntime(transport, exchange);
        var owner = Session('1');
        var recipient = Session('2');
        var group = GroupState(owner, recipient, revision: 1);
        await StoreGroupAsync(runtime, group);
        transport.IncomingRoutes = [RouteEnvelope(group, owner, "routes-retry")];

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            runtime.Conversations.ReceiveGroupUpdatesAsync(recipient));
        Assert.DoesNotContain("routes-retry", transport.AcknowledgedHashes);

        await runtime.Conversations.ReceiveGroupUpdatesAsync(recipient);

        Assert.Single(exchange.Imported);
        Assert.Contains("routes-retry", transport.AcknowledgedHashes);
    }

    [Fact]
    public async Task GroupOutbox_RetriesLegacyStateBeforeRouteBundleAndKeepsStableBundle()
    {
        var store = new InMemorySessionStore();
        var transport = new RecordingGroupSyncTransport { RouteFailuresRemaining = 1 };
        var exchange = new RecordingGroupMailboxRouteExchange();
        using var runtime = new ClientRuntime(
            store,
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            new FrozenClock(CreatedAt),
            new StubSessionBackend(),
            transport,
            groupMailboxRoutes: exchange);

        var group = await runtime.Conversations.CreateGroupScaffoldAsync(Session('1'), "Retry", [Session('2')]);
        var pending = Assert.Single(await store.ListPendingGroupStatePublishesAsync(GroupStateOutboxLimits.MaxPublishBatch));
        var stableBytes = GroupMailboxRouteBundleCodec.Encode(pending.RouteBundle!);

        Assert.Equal(1, await runtime.Conversations.FlushPendingGroupStatesAsync());

        Assert.Equal(["state:1", "routes:1", "state:1", "routes:1"], transport.PublishOrder);
        Assert.Equal(stableBytes, GroupMailboxRouteBundleCodec.Encode(transport.PublishedRoutes[^1]));
        Assert.Empty(await store.ListPendingGroupStatePublishesAsync(GroupStateOutboxLimits.MaxPublishBatch));
        Assert.Equal(group.Id, transport.PublishedRoutes[^1].GroupId);
    }

    [Fact]
    public async Task GroupRouteBundleOutbox_SurvivesSqliteRestartByteForByte()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-group-routes-{Guid.NewGuid():N}.db");
        var owner = Session('1');
        var member = Session('2');
        var failingTransport = new RecordingGroupSyncTransport { RouteFailuresRemaining = 1 };
        byte[] expected;

        try
        {
            using (var runtime = new ClientRuntime(
                       new SqliteSessionStore(statePath),
                       Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
                       new FrozenClock(CreatedAt),
                       new StubSessionBackend(),
                       failingTransport,
                       groupMailboxRoutes: new RecordingGroupMailboxRouteExchange()))
            {
                await runtime.Conversations.CreateGroupScaffoldAsync(owner, "Restart routes", [member]);
                var pending = Assert.Single(await ((IGroupStatePersistenceRepository)runtime.Store)
                    .ListPendingGroupStatePublishesAsync(GroupStateOutboxLimits.MaxPublishBatch));
                expected = GroupMailboxRouteBundleCodec.Encode(pending.RouteBundle!);
            }

            var resumedTransport = new RecordingGroupSyncTransport();
            using var resumed = new ClientRuntime(
                new SqliteSessionStore(statePath),
                Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
                new FrozenClock(CreatedAt),
                new StubSessionBackend(),
                resumedTransport);

            Assert.Equal(1, await resumed.Conversations.FlushPendingGroupStatesAsync());
            Assert.Equal(expected, GroupMailboxRouteBundleCodec.Encode(Assert.Single(resumedTransport.PublishedRoutes)));
        }
        finally
        {
            foreach (var path in new[] { statePath, statePath + "-wal", statePath + "-shm" })
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
        }
    }

    private static ClientRuntime CreateRuntime(
        RecordingGroupSyncTransport transport,
        IGroupMailboxRouteExchange? exchange = null) =>
        ClientRuntime.CreateStubbed(
            clock: new FrozenClock(CreatedAt),
            groupSyncTransport: transport,
            groupMailboxRoutes: exchange);

    private static Task StoreGroupAsync(ClientRuntime runtime, Group group) =>
        ((IGroupRepository)runtime.Store).UpsertAsync(group);

    private static Group GroupState(SessionId owner, SessionId recipient, long revision) =>
        new(
            ConversationId.Parse("03" + new string('a', 64)),
            "Trusted group",
            owner,
            CreatedAt,
            [
                new GroupMember(owner, GroupMemberRole.Admin, CreatedAt),
                new GroupMember(recipient, GroupMemberRole.Standard, CreatedAt)
            ],
            Revision: revision);

    private static InboundGroupStateEnvelope Envelope(
        Group group,
        SessionId sender,
        DateTimeOffset updatedAt) =>
        new(group, updatedAt, $"hash-{group.Revision}-{updatedAt.Ticks}", sender);

    private static InboundGroupMailboxRouteEnvelope RouteEnvelope(
        Group group,
        SessionId sender,
        string serverHash) =>
        new(
            RecordingGroupMailboxRouteExchange.CreateBundle(group),
            sender,
            CreatedAt,
            CreatedAt.AddHours(1),
            serverHash);

    private static SessionId Session(char value) =>
        SessionId.Parse("05" + new string(value, 64));

    private sealed class RecordingGroupSyncTransport :
        IGroupSyncTransport,
        IGroupMailboxRouteSyncTransport,
        IDurableInboxAcknowledger
    {
        public List<Group> Published { get; } = [];

        public List<IReadOnlyList<SessionId>> PublishedRecipients { get; } = [];

        public int FailuresRemaining { get; set; }

        public int RouteFailuresRemaining { get; set; }

        public List<GroupMailboxRouteBundle> PublishedRoutes { get; } = [];

        public List<string> PublishOrder { get; } = [];

        public List<string> AcknowledgedHashes { get; } = [];

        public IReadOnlyList<InboundGroupStateEnvelope> Incoming { get; set; } = [];

        public IReadOnlyList<InboundGroupMailboxRouteEnvelope> IncomingRoutes { get; set; } = [];

        public Task PublishGroupStateAsync(
            Group group,
            DateTimeOffset updatedAt,
            IEnumerable<SessionId>? recipients = null,
            CancellationToken cancellationToken = default)
        {
            if (FailuresRemaining > 0)
            {
                FailuresRemaining--;
                throw new HttpRequestException("injected publish failure");
            }

            Published.Add(group);
            PublishedRecipients.Add(recipients?.ToArray() ?? []);
            PublishOrder.Add($"state:{group.Revision}");
            return Task.CompletedTask;
        }

        public Task PublishGroupMailboxRoutesAsync(
            GroupMailboxRouteBundle bundle,
            DateTimeOffset updatedAt,
            IEnumerable<SessionId> recipients,
            CancellationToken cancellationToken = default)
        {
            PublishOrder.Add($"routes:{bundle.GroupRevision}");
            if (RouteFailuresRemaining > 0)
            {
                RouteFailuresRemaining--;
                throw new HttpRequestException("injected route publish failure");
            }

            PublishedRoutes.Add(bundle);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<InboundGroupMailboxRouteEnvelope>> ReceiveGroupMailboxRoutesAsync(
            SessionId member,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(IncomingRoutes);

        public Task AcknowledgeInboxItemAsync(
            SessionId account,
            string serverHash,
            CancellationToken cancellationToken = default)
        {
            AcknowledgedHashes.Add(serverHash);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
            SessionId member,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Incoming);

        public Task SendGroupMessageAsync(
            OutboundGroupMessageEnvelope envelope,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
            ConversationId groupId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundGroupMessageEnvelope>>([]);
    }

    private sealed class RecordingGroupMailboxRouteExchange : IGroupMailboxRouteExchange
    {
        public List<GroupMailboxRouteBundle> Captured { get; } = [];

        public List<(SessionId Account, Group Group, GroupMailboxRouteBundle Bundle)> Imported { get; } = [];

        public bool ReturnMissingBundle { get; set; }

        public int ImportFailuresRemaining { get; set; }

        public Task<GroupMailboxRouteBundle?> CaptureForPublishAsync(
            Group group,
            CancellationToken cancellationToken = default)
        {
            if (ReturnMissingBundle)
            {
                return Task.FromResult<GroupMailboxRouteBundle?>(null);
            }

            var bundle = CreateBundle(group);
            Captured.Add(bundle);
            return Task.FromResult<GroupMailboxRouteBundle?>(bundle);
        }

        public Task ImportReceivedAsync(
            SessionId localAccount,
            Group group,
            GroupMailboxRouteBundle bundle,
            CancellationToken cancellationToken = default)
        {
            if (ImportFailuresRemaining > 0)
            {
                ImportFailuresRemaining--;
                throw new HttpRequestException("injected route import failure");
            }

            Imported.Add((localAccount, group, bundle));
            return Task.CompletedTask;
        }

        public static GroupMailboxRouteBundle CreateBundle(Group group) =>
            new(
                group.Id,
                group.Revision,
                E2eeContentCodec.ComputeGroupMembershipDigest(group),
                group.Members
                    .Select(static member => new GroupMemberMailboxInvitation(
                        member.SessionId,
                        Enumerable.Repeat((byte)member.SessionId.Value[^1], 585).ToArray()))
                    .OrderBy(static invitation => invitation.Member.Value, StringComparer.Ordinal)
                    .ToArray());
    }
}
