using System.Buffers.Binary;
using System.Reflection;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class ContactRelationshipStateMachineTests
{
    private static readonly byte[] Network = Bytes(16, 0x21);
    private static readonly DateTimeOffset Started = DateTimeOffset.FromUnixTimeSeconds(1_910_000_000);

    [Fact]
    public async Task HappyPathConflictsAndVerifiedRepairsFollowNormativeGraph()
    {
        var scope = Scope();
        var store = new InMemoryContactStateStore(scope);
        var (service, head) = await CreateBundleAsync(store, scope, 1);

        Assert.Equal(ContactRelationshipState.BundleVerified, head.State);
        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.RequestQueued, 2);
        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.RemoteStoreAccepted, 3);
        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.RequestMaterialized, 4);
        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.PeerAccepted, 5);
        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.Activated, 6);
        Assert.Equal(ContactRelationshipState.Active, head.State);

        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.IdentityConflict, 7);
        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.ConflictRepaired, 8);
        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.DirectoryConflict, 9);
        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.ConflictRepaired, 10);
        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.RouteStale, 11);

        var invalidRepair = await service.ApplyVerifiedTransitionAsync(
            Transition(scope, head, VerifiedContactTransitionKind.ConflictRepaired, 12),
            head.Revision, Mutation(12), Started.AddMinutes(12));
        Assert.Equal(ContactRelationshipCommitDisposition.InvalidTransition, invalidRepair.Disposition);
        Assert.Equal(ContactRelationshipState.RouteStale, invalidRepair.Relationship!.State);
    }

    [Theory]
    [InlineData(VerifiedContactTransitionKind.Rejected, ContactRelationshipState.Rejected)]
    [InlineData(VerifiedContactTransitionKind.Expired, ContactRelationshipState.Expired)]
    public async Task PendingRequestCanTerminateOnlyOnVerifiedEvidence(
        VerifiedContactTransitionKind kind,
        ContactRelationshipState expected)
    {
        var scope = Scope();
        var store = new InMemoryContactStateStore(scope);
        var (service, head) = await CreateBundleAsync(store, scope, (int)kind + 20);
        head = await MoveAsync(service, scope, head, VerifiedContactTransitionKind.RequestQueued, 40);

        var terminal = await MoveAsync(service, scope, head, kind, 41);
        Assert.Equal(expected, terminal.State);
        var impossible = await service.BlockAsync(terminal.RelationshipId, terminal.Revision,
            Mutation(42), Started.AddHours(1));
        Assert.Equal(ContactRelationshipCommitDisposition.InvalidTransition, impossible.Disposition);
    }

    [Theory]
    [InlineData(false, ContactRelationshipState.Blocked)]
    [InlineData(true, ContactRelationshipState.Deleted)]
    public async Task LocalBlockAndDeleteFenceNonterminalStateWithoutEvidence(
        bool delete,
        ContactRelationshipState expected)
    {
        var scope = Scope();
        var store = new InMemoryContactStateStore(scope);
        var (service, head) = await CreateBundleAsync(store, scope, delete ? 61 : 60);

        var result = delete
            ? await service.DeleteAsync(head.RelationshipId, head.Revision, Mutation(62), Started.AddMinutes(2))
            : await service.BlockAsync(head.RelationshipId, head.Revision, Mutation(62), Started.AddMinutes(2));

        Assert.Equal(ContactRelationshipCommitDisposition.Applied, result.Disposition);
        Assert.Equal(expected, result.Relationship!.State);
    }

    [Fact]
    public async Task BundleRequiresPendingOriginAndOnlyThenPersistsExactVerifiedIdentity()
    {
        var scope = Scope();
        var store = new InMemoryContactStateStore(scope);
        var service = new ContactRelationshipService(store);
        var address = ImportedDid(70);
        var verification = Verification(scope, address, 70);
        var evidence = verification.Evidence;

        var absent = await service.RecordBundleVerifiedAsync(verification, Mutation(70), Started);
        Assert.Equal(ContactRelationshipCommitDisposition.NotFound, absent.Disposition);
        Assert.Empty(await store.ReadRelationshipsAsync());
        Assert.Null(await store.ReadVerifiedPeerPackageAsync(evidence.RelationshipId));

        await store.PutPendingAddressAsync(new PendingContactAddress(address, Started));
        var applied = await service.RecordBundleVerifiedAsync(verification, Mutation(70), Started);
        Assert.Equal(ContactRelationshipCommitDisposition.Applied, applied.Disposition);
        Assert.Equal(Bytes(32, 0xB0), applied.Relationship!.RemoteAccountId.ToArray());
        Assert.Equal(evidence.RelationshipId, applied.Relationship.RelationshipId);
        Assert.Equal(evidence.ConversationId, applied.Relationship.ConversationId);
        foreach (var kind in Enum.GetValues<ContactVerifiedArtifactKind>())
            Assert.Equal(evidence.ArtifactHashes[kind], applied.Relationship.ArtifactHashes[kind]);
        var package = await store.ReadVerifiedPeerPackageAsync(evidence.RelationshipId);
        Assert.NotNull(package);
        Assert.Equal(verification.RecoveryPackage.PackageHash.ToArray(), package.PackageHash.ToArray());
        Assert.Equal(evidence.ConversationId, package.ConversationId);
        Assert.Equal(evidence.RemoteAccountId, package.RemoteAccountId);
    }

    [Fact]
    public async Task VerifiedPeerPackageReplayIsIdempotentAndForkConflictsWithoutReplacement()
    {
        var scope = Scope();
        var store = new InMemoryContactStateStore(scope);
        var address = ImportedDid(75);
        await store.PutPendingAddressAsync(new PendingContactAddress(address, Started));
        var service = new ContactRelationshipService(store);
        var operation = Mutation(75);
        var accepted = Verification(scope, address, 75);

        var first = await service.RecordBundleVerifiedAsync(accepted, operation, Started);
        var replay = await service.RecordBundleVerifiedAsync(accepted, operation, Started);
        var fork = await service.RecordBundleVerifiedAsync(
            Verification(scope, address, 75, packageMarker: 76), operation, Started);

        Assert.Equal(ContactRelationshipCommitDisposition.Applied, first.Disposition);
        Assert.Equal(ContactRelationshipCommitDisposition.Idempotent, replay.Disposition);
        Assert.Equal(ContactRelationshipCommitDisposition.Conflict, fork.Disposition);
        var stored = await store.ReadVerifiedPeerPackageAsync(accepted.Evidence.RelationshipId);
        Assert.NotNull(stored);
        Assert.Equal(accepted.RecoveryPackage.PackageHash.ToArray(), stored.PackageHash.ToArray());
    }

    [Fact]
    public async Task SqlCipherVerifiedPeerPackageForkAndOlderOperationCannotReplaceCommittedBytes()
    {
        using var fixture = StoreFixture.Create();
        using var store = new SqliteContactStateStore(fixture.Options);
        var scope = fixture.Options.Scope;
        var address = ImportedDid(77);
        await store.PutPendingAddressAsync(new PendingContactAddress(address, Started));
        var service = new ContactRelationshipService(store);
        var accepted = Verification(scope, address, 77);
        var original = await service.RecordBundleVerifiedAsync(accepted, Mutation(77), Started);

        var sameOperationFork = await service.RecordBundleVerifiedAsync(
            Verification(scope, address, 77, packageMarker: 78), Mutation(77), Started);
        var olderOperationFork = await service.RecordBundleVerifiedAsync(
            Verification(scope, address, 77, packageMarker: 76), Mutation(76), Started.AddSeconds(-1));

        Assert.Equal(ContactRelationshipCommitDisposition.Applied, original.Disposition);
        Assert.Equal(ContactRelationshipCommitDisposition.Conflict, sameOperationFork.Disposition);
        Assert.Equal(ContactRelationshipCommitDisposition.Conflict, olderOperationFork.Disposition);
        var stored = await store.ReadVerifiedPeerPackageAsync(accepted.Evidence.RelationshipId);
        Assert.NotNull(stored);
        Assert.Equal(accepted.RecoveryPackage.PackageHash.ToArray(), stored.PackageHash.ToArray());
    }

    [Fact]
    public async Task ExactReplayIsIdempotentAndConflictingReplayFailsClosed()
    {
        var scope = Scope();
        var store = new InMemoryContactStateStore(scope);
        var (service, head) = await CreateBundleAsync(store, scope, 80);
        var evidence = Transition(scope, head, VerifiedContactTransitionKind.RequestQueued, 81);
        var operation = Mutation(81);
        var first = await service.ApplyVerifiedTransitionAsync(evidence, head.Revision, operation,
            Started.AddMinutes(1));
        var replay = await service.ApplyVerifiedTransitionAsync(evidence, head.Revision, operation,
            Started.AddMinutes(1));
        var conflict = await service.ApplyVerifiedTransitionAsync(
            Transition(scope, head, VerifiedContactTransitionKind.Expired, 82),
            head.Revision, operation, Started.AddMinutes(1));

        Assert.Equal(ContactRelationshipCommitDisposition.Applied, first.Disposition);
        Assert.Equal(ContactRelationshipCommitDisposition.Idempotent, replay.Disposition);
        Assert.Equal(first.CommittedRevision, replay.CommittedRevision);
        Assert.Equal(ContactRelationshipCommitDisposition.Conflict, conflict.Disposition);
        Assert.Equal(ContactRelationshipState.RequestQueued,
            (await store.ReadRelationshipAsync(head.RelationshipId))!.State);
    }

    [Fact]
    public async Task SqlCipherRestartPreservesExactHeadHashesAndScope()
    {
        using var fixture = StoreFixture.Create();
        ContactRelationshipSnapshot expected;
        using (var store = new SqliteContactStateStore(fixture.Options))
        {
            var (_, bundle) = await CreateBundleAsync(store, fixture.Options.Scope, 90);
            expected = await MoveAsync(new ContactRelationshipService(store), fixture.Options.Scope,
                bundle, VerifiedContactTransitionKind.RequestQueued, 91);
        }

        using var reopened = new SqliteContactStateStore(fixture.Options);
        var actual = await reopened.ReadRelationshipAsync(expected.RelationshipId);

        Assert.NotNull(actual);
        Assert.Equal(expected.State, actual.State);
        Assert.Equal(expected.Revision, actual.Revision);
        Assert.Equal(expected.RemoteAccountId, actual.RemoteAccountId);
        Assert.Equal(expected.ConversationId, actual.ConversationId);
        Assert.Equal(expected.ExactCanonicalAddress.ToArray(), actual.ExactCanonicalAddress.ToArray());
        foreach (var kind in Enum.GetValues<ContactVerifiedArtifactKind>())
            Assert.Equal(expected.ArtifactHashes[kind], actual.ArtifactHashes[kind]);
        var package = await reopened.ReadVerifiedPeerPackageAsync(expected.RelationshipId);
        Assert.NotNull(package);
        Assert.Equal(expected.ConversationId, package.ConversationId);
        Assert.Equal(expected.RemoteAccountId, package.RemoteAccountId);
        Assert.Equal(ContactVerifiedPeerPackageEvidence.CurrentVersion, package.Version);
        Assert.Single(package.Devices);
    }

    [Fact]
    public async Task ConcurrentSqlCipherCasAllowsOneWinnerAndExactReplay()
    {
        using var fixture = StoreFixture.Create();
        using var storeA = new SqliteContactStateStore(fixture.Options);
        using var storeB = new SqliteContactStateStore(fixture.Options);
        var (_, head) = await CreateBundleAsync(storeA, fixture.Options.Scope, 100);
        var serviceA = new ContactRelationshipService(storeA);
        var serviceB = new ContactRelationshipService(storeB);
        var evidenceA = Transition(fixture.Options.Scope, head, VerifiedContactTransitionKind.RequestQueued, 101);
        var evidenceB = Transition(fixture.Options.Scope, head, VerifiedContactTransitionKind.RequestQueued, 102);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var first = Task.Run(async () => { await start.Task; return await serviceA.ApplyVerifiedTransitionAsync(
            evidenceA, head.Revision, Mutation(101), Started.AddMinutes(1)); });
        var second = Task.Run(async () => { await start.Task; return await serviceB.ApplyVerifiedTransitionAsync(
            evidenceB, head.Revision, Mutation(102), Started.AddMinutes(1)); });
        start.TrySetResult();
        var results = await Task.WhenAll(first, second);

        Assert.Single(results, result => result.Disposition == ContactRelationshipCommitDisposition.Applied);
        Assert.Single(results, result => result.Disposition == ContactRelationshipCommitDisposition.StaleRevision);
        var winner = results.Single(result => result.Disposition == ContactRelationshipCommitDisposition.Applied);
        var replayEvidence = winner == results[0] ? evidenceA : evidenceB;
        var replayOperation = winner == results[0] ? Mutation(101) : Mutation(102);
        var replay = await serviceA.ApplyVerifiedTransitionAsync(replayEvidence, head.Revision,
            replayOperation, Started.AddMinutes(1));
        Assert.Equal(ContactRelationshipCommitDisposition.Idempotent, replay.Disposition);
    }

    [Fact]
    public async Task EvidenceIsScopeBoundAndCapabilitiesHaveNoPublicConstructors()
    {
        var scopeA = Scope(0x71);
        var scopeB = Scope(0x72);
        var store = new InMemoryContactStateStore(scopeB);
        var address = ImportedDid(110);
        await store.PutPendingAddressAsync(new PendingContactAddress(address, Started));

        await Assert.ThrowsAsync<ArgumentException>(() => new ContactRelationshipService(store)
            .RecordBundleVerifiedAsync(Verification(scopeA, address, 110), Mutation(110), Started).AsTask());
        Assert.Empty(await store.ReadRelationshipsAsync());
        Assert.Empty(typeof(VerifiedContactBundleEvidence).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(VerifiedContactTransitionEvidence).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(ContactVerifiedPeerPackageEvidence).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(ContactResolverTrustedVerificationResult).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public async Task RelationshipCapacityIsBoundedAtTenThousand()
    {
        var scope = Scope();
        var store = new InMemoryContactStateStore(scope);
        var service = new ContactRelationshipService(store);
        var address = ImportedDid(120);
        await store.PutPendingAddressAsync(new PendingContactAddress(address, Started));

        for (var index = 1; index <= InMemoryContactStateStore.DefaultMaximumPendingAddresses; index++)
        {
            var result = await service.RecordBundleVerifiedAsync(Verification(scope, address, index),
                Mutation(index), Started);
            Assert.Equal(ContactRelationshipCommitDisposition.Applied, result.Disposition);
        }
        var full = await service.RecordBundleVerifiedAsync(Verification(scope, address, 20_000),
            Mutation(20_000), Started);

        Assert.Equal(ContactRelationshipCommitDisposition.CapacityExceeded, full.Disposition);
        Assert.Equal(10_000, (await store.ReadRelationshipsAsync()).Count);
    }

    [Fact]
    public async Task CancellationDoesNotMutateRelationshipState()
    {
        var scope = Scope();
        var store = new InMemoryContactStateStore(scope);
        var (service, head) = await CreateBundleAsync(store, scope, 130);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.ApplyVerifiedTransitionAsync(
            Transition(scope, head, VerifiedContactTransitionKind.RequestQueued, 131), head.Revision,
            Mutation(131), Started.AddMinutes(1), cancelled.Token).AsTask());
        Assert.Equal(ContactRelationshipState.BundleVerified,
            (await store.ReadRelationshipAsync(head.RelationshipId))!.State);
    }

    [Fact]
    public async Task CorruptRelationshipAndOperationRowsFailDuringOpen()
    {
        using var fixture = StoreFixture.Create();
        ContactRelationshipId32 relationshipId;
        using (var store = new SqliteContactStateStore(fixture.Options))
        {
            var (_, head) = await CreateBundleAsync(store, fixture.Options.Scope, 140);
            relationshipId = head.RelationshipId;
        }
        using (var database = OpenEncrypted(fixture.Options))
            Execute(database, "PRAGMA ignore_check_constraints=ON; UPDATE contact_relationships SET state=99; PRAGMA ignore_check_constraints=OFF;");

        var stateFailure = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteContactStateStore(fixture.Options));
        Assert.Equal(ContactStateStoreOpenFailure.Corrupt, stateFailure.Reason);

        fixture.ResetDatabaseFiles();
        using (var store = new SqliteContactStateStore(fixture.Options))
        {
            var (_, head) = await CreateBundleAsync(store, fixture.Options.Scope, 141);
            relationshipId = head.RelationshipId;
        }
        using (var database = OpenEncrypted(fixture.Options))
            Execute(database, "PRAGMA ignore_check_constraints=ON; UPDATE contact_relationship_operations SET committed_revision=x'0000000000000010'; PRAGMA ignore_check_constraints=OFF;");

        var operationFailure = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteContactStateStore(fixture.Options));
        Assert.Equal(ContactStateStoreOpenFailure.Corrupt, operationFailure.Reason);

        fixture.ResetDatabaseFiles();
        using (var store = new SqliteContactStateStore(fixture.Options))
        {
            var (_, head) = await CreateBundleAsync(store, fixture.Options.Scope, 142);
            relationshipId = head.RelationshipId;
        }
        using (var database = OpenEncrypted(fixture.Options))
            Execute(database, "UPDATE contact_verified_peer_packages SET exact_dcr1=x'99';");

        var packageFailure = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteContactStateStore(fixture.Options));
        Assert.Equal(ContactStateStoreOpenFailure.Corrupt, packageFailure.Reason);
        Assert.NotNull(relationshipId);
    }

    private static async Task<(ContactRelationshipService Service, ContactRelationshipSnapshot Head)> CreateBundleAsync(
        IContactStateStore store,
        ContactStoreScope scope,
        int marker)
    {
        var address = ImportedDid(marker);
        await store.PutPendingAddressAsync(new PendingContactAddress(address, Started));
        var service = new ContactRelationshipService(store);
        var result = await service.RecordBundleVerifiedAsync(Verification(scope, address, marker),
            Mutation(marker), Started);
        Assert.Equal(ContactRelationshipCommitDisposition.Applied, result.Disposition);
        return (service, result.Relationship!);
    }

    private static async Task<ContactRelationshipSnapshot> MoveAsync(
        ContactRelationshipService service,
        ContactStoreScope scope,
        ContactRelationshipSnapshot head,
        VerifiedContactTransitionKind kind,
        int marker)
    {
        var result = await service.ApplyVerifiedTransitionAsync(Transition(scope, head, kind, marker),
            head.Revision, Mutation(marker), Started.AddMinutes(marker));
        Assert.Equal(ContactRelationshipCommitDisposition.Applied, result.Disposition);
        return result.Relationship!;
    }

    private static VerifiedContactBundleEvidence Bundle(
        ContactStoreScope scope,
        ImportedContactAddress address,
        int marker) => ContactTrustedVerifierBoundary.BundleVerified(scope, address,
            Bytes(32, 0xB0), Relationship(marker), ArtifactHashes(marker), Hash(marker + 10_000));

    private static ContactResolverTrustedVerificationResult Verification(
        ContactStoreScope scope,
        ImportedContactAddress address,
        int marker,
        int? packageMarker = null)
    {
        var bytesMarker = packageMarker ?? marker;
        var evidence = Bundle(scope, address, marker);
        var package = new ContactVerifiedPeerPackageEvidence(
            scope,
            evidence.RelationshipId,
            evidence.ConversationId,
            evidence.RemoteAccountId,
            address.Kind,
            address.NetworkId.Span,
            address.CanonicalBytes.Span,
            Hash(bytesMarker + 50_000),
            Hash(bytesMarker + 50_001),
            [0x44],
            [0x45],
            [0x46],
            [new ContactVerifiedPeerDeviceEvidence(Hash(bytesMarker + 50_002), Bytes(776, 0x47))],
            [0x48]);
        return new ContactResolverTrustedVerificationResult(evidence, package);
    }

    private static VerifiedContactTransitionEvidence Transition(
        ContactStoreScope scope,
        ContactRelationshipSnapshot head,
        VerifiedContactTransitionKind kind,
        int marker) => ContactTrustedVerifierBoundary.TransitionVerified(scope,
            head.RelationshipId, kind, Hash(marker + 20_000));

    private static IReadOnlyDictionary<ContactVerifiedArtifactKind, ReadOnlyMemory<byte>> ArtifactHashes(int marker) =>
        Enum.GetValues<ContactVerifiedArtifactKind>().ToDictionary(kind => kind,
            kind => (ReadOnlyMemory<byte>)Hash(marker * 100 + (int)kind));

    private static ImportedContactAddress ImportedDid(int marker)
    {
        var key = Hash(marker);
        var capability = Hash(marker + 1)[..16];
        var did = ApplicationCoreCodec.AuthorDid1(key, capability);
        return new ImportedContactAddress(ContactAddressKind.PermanentDeepId, Network,
            did.CanonicalBytes.Span, did.Text, null);
    }

    private static ContactRelationshipId32 Relationship(int marker) =>
        ContactRelationshipId32.FromBytes(Hash(marker + 30_000));
    private static ContactMutationId32 Mutation(int marker) =>
        ContactMutationId32.FromBytes(Hash(marker + 40_000));
    private static byte[] Hash(int marker)
    {
        var value = Bytes(32, 0x41);
        BinaryPrimitives.WriteInt32BigEndian(value.AsSpan(28), marker);
        return System.Security.Cryptography.SHA256.HashData(value);
    }

    private static ContactStoreScope Scope(byte marker = 0x71) =>
        ContactStoreScope.ForCurrentAccount(DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Network), 1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Bytes(32, marker))).AccountId);

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

    private static SqliteConnection OpenEncrypted(SqliteContactStateStoreOptions options)
    {
        SQLitePCL.Batteries_V2.Init();
        var database = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = options.StatePath,
            Pooling = false,
        }.ToString());
        database.Open();
        var key = new byte[32];
        options.CopyEncryptionKeyTo(key);
        try
        {
            Assert.Equal(SQLitePCL.raw.SQLITE_OK,
                SQLitePCL.raw.sqlite3_key(database.Handle, key));
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
        }
        return database;
    }

    private static void Execute(SqliteConnection database, string sql)
    {
        using var command = database.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private sealed class StoreFixture : IDisposable
    {
        private StoreFixture(string directory)
        {
            Directory = directory;
            Path = System.IO.Path.Combine(directory, "contacts.db");
            Options = new SqliteContactStateStoreOptions(Path, Bytes(32, 0xE1), Scope());
        }

        internal string Directory { get; }
        internal string Path { get; }
        internal SqliteContactStateStoreOptions Options { get; }
        internal static StoreFixture Create()
        {
            var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
                "deep-contact-01c-" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(directory);
            return new(directory);
        }

        internal void ResetDatabaseFiles()
        {
            SqliteConnection.ClearAllPools();
            foreach (var file in new[] { Path, Path + "-wal", Path + "-shm" })
                if (File.Exists(file)) File.Delete(file);
        }

        public void Dispose()
        {
            Options.Dispose();
            SqliteConnection.ClearAllPools();
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }
    }
}
