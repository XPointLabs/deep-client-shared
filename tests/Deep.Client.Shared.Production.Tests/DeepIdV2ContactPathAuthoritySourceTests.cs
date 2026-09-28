using System.Net;
using System.Buffers.Binary;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task InitialInventory_UsesRealCurrentClosureAndPreservesExactRetryAfterReopen()
    {
        // The approved whole ML-KEM asset is currently validated on Windows.
        // This fixture is native/SQL evidence, not physical-device evidence.
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var staged = await fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
        Assert.Equal(1, fixture.ProofRequests);
        fixture.VerifyInventory(staged, (await source.VerifyForOwnPreKeyAuthoringAsync(
            fixture.Accounts, default)).Proof);
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
        Assert.Equal(32, publication.OneTimeMembers.Count);
        var service = DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span);
        var placement = await source.GetCurrentForPublicationAsync(Fixture.Network, service.Field(2));
        Assert.Equal(placement.Placement.PlacementHash.ToArray(), publication.PlacementHash.ToArray());
        Assert.True(await fixture.Accounts.HasOwnStagedPreKeyInventoryAsync());
        Assert.Null(await fixture.Accounts.ReadOwnPreKeyCommitPairAsync());
        await AssertRealOnionCustodyAsync(fixture, source, staged, publication, placement);
        fixture.RejectProof = true;
        var before = fixture.ProofRequests;
        var retry = await fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
        var reopened = fixture.ReopenAccount();
        var afterRestart = await reopened.EnsureOwnInitialPreKeyInventoryAsync(fixture.Source(reopened));
        Assert.Equal(staged.ExactXpp1.ToArray(), retry.ExactXpp1.ToArray());
        Assert.Equal(staged.ExactXpp1.ToArray(), afterRestart.ExactXpp1.ToArray());
        Assert.Equal(staged.ExactXps1.ToArray(), afterRestart.ExactXps1.ToArray());
        Assert.Equal(before, fixture.ProofRequests); // Stored retry is not fresh authority.
        await Assert.ThrowsAnyAsync<IOException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, service.Field(2)));
    }

    private static async Task AssertRealOnionCustodyAsync(Fixture fixture,
        DeepIdV2ContactPathAuthoritySource source, StagedDeepIdV2PreKeyPublication staged,
        ParsedXpp1V2 publication, ContactResolvePathAuthority authority)
    {
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var fragments = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(staged.ExactXpp1.Span,
            authority.Placement.ViewHash.Span, staged.ExactDid2.Span, staged.ExactDca1.Span, staged.ExactXps1.Span);
        var request = ContactResolveCanonicalPathRequest.FromDid2BoundedPublication(
            DeepIdV2BoundedPreKeyPublicationCodec.Decode(fragments[0]), publication.Manifest.Field(2).Span,
            Math.Min(BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(15).Span),
                authority.Placement.ValidUntilUnixSeconds));
        var paths = new ContactResolvePrivacyPathProvider(source, custody.Guards);
        var ledger = new CapturingEntropyLedger(custody.Entropy);
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(ledger),
            new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
        foreach (var exit in authority.Placement.RankedReplicaNodeIds)
        {
            var prepared = await paths.PrepareExactAsync(OnionOperation.ContactResolve, request, exit, default);
            var entry = OnionEntryTransportFactory.Create(prepared.Attempt.Path);
            entry.EnsureCurrent();
            using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, default);
            Assert.False(built.Frame.IsEmpty);
            Assert.NotNull(ledger.LastBatch);
            Assert.Equal(OnionEntropyCommitOutcome.Duplicate,
                await custody.Entropy.CommitAsync(ledger.LastBatch!, default));
        }
        var reopened = await fixture.ReopenAccount().OpenOwnOnionClientCustodyAsync();
        Assert.Equal(OnionEntropyCommitOutcome.Duplicate,
            await reopened.Entropy.CommitAsync(ledger.LastBatch!, default));
        Assert.Equal(EntryGuardStateCodec.Encode((await custody.Guards.ReadAsync(default))!),
            EntryGuardStateCodec.Encode((await reopened.Guards.ReadAsync(default))!));
        // A frame was sealed locally; no network send, XIC1 or device claim.
    }

    private sealed class CapturingEntropyLedger(IOnionEntropyUniquenessLedger inner) : IOnionEntropyUniquenessLedger
    {
        internal OnionEntropyCommitmentBatch? LastBatch { get; private set; }
        public async ValueTask<OnionEntropyCommitOutcome> CommitAsync(OnionEntropyCommitmentBatch batch, CancellationToken ct)
        {
            var result = await inner.CommitAsync(batch, ct);
            if (result == OnionEntropyCommitOutcome.Committed) LastBatch = batch;
            return result;
        }
    }

    private sealed class RejectClientReceiveVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(OnionKeyHandle keyHandle,
            ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct) =>
            throw new InvalidOperationException("The client must never ask for an XNode receive key.");
    }

    [Fact]
    public async Task InitialInventory_MissingProofCancellationAndWrongOwnerDoNotStage()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source, cancelled.Token));
        Assert.Equal(0, fixture.ProofRequests);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            fixture.ReopenAccount().EnsureOwnInitialPreKeyInventoryAsync(source));
        Assert.Equal(0, fixture.ProofRequests);
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(() =>
            fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source));
        Assert.Equal(1, fixture.ProofRequests);
        Assert.Null(await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync());
    }

    [Fact]
    public async Task OwnAuthoringAuthority_RejectsExpiredClockAndChangedNetworkCustody()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var authoring = await source.VerifyForOwnPreKeyAuthoringAsync(fixture.Accounts, default);
        fixture.Sample = authoring.Proof.FreshnessDeadlineMonotonicSeconds;
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.RecheckOwnPreKeyAuthoringAsync(authoring, default));
        fixture.Sample = 100;
        var floor = (await fixture.NetworkStore.ReadAsync(default))!;
        await fixture.NetworkStore.CompareExchangeAsync(floor.Revision,
            new(floor.Revision + 1, floor.ProtectedLkg, true), default);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.RecheckOwnPreKeyAuthoringAsync(authoring, default));
        Assert.Null(await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync());
    }

    [Fact]
    public async Task RealDid2AccountAndSignedNetwork_VerifyThenMintRechecksProofAndRehydratesExactFloor()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var network = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        network.EnsureCurrent();
        Assert.NotNull(await fixture.NetworkStore.ReadAsync(default));
        Assert.Equal(1, fixture.ProofRequests);
        var first = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.True(first.Placement.Binds(ContactServiceRequestKind.PublishPreKeyInventory, Fixture.Service));
        Assert.NotNull(await fixture.NetworkStore.ReadAsync(default));
        var second = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(first.Placement.PlacementHash.ToArray(), second.Placement.PlacementHash.ToArray());
        Assert.Equal(3, fixture.ProofRequests);
        var reopened = fixture.Source();
        var restoredNetwork = await reopened.VerifyCurrentNetworkAsync(Fixture.Network);
        restoredNetwork.EnsureCurrent();
        Assert.Equal(XPointNetworkProtectedLkgCodec.Encode(
                Assert.IsType<XPointNetworkProtectedLkg>(network.ProtectedLkg)),
            XPointNetworkProtectedLkgCodec.Encode(
                Assert.IsType<XPointNetworkProtectedLkg>(restoredNetwork.ProtectedLkg)));
        var restored = await reopened.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(first.Placement.PlacementHash.ToArray(), restored.Placement.PlacementHash.ToArray());
        Assert.Equal(5, fixture.ProofRequests);
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task MissingFreshProof_CannotReusePreviouslyMintedNetworkAuthority()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        _ = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal(2, fixture.ProofRequests);
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
        fixture.RejectProof = false;
        _ = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(3, fixture.ProofRequests);
    }

    [Fact]
    public async Task AlteredSignedNodeClosure_DoesNotInitializeNetworkCustody()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.AlterNode = true;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Null(await fixture.NetworkStore.ReadAsync(default));
    }

    [Fact]
    public async Task UnrelatedNetworkAndProtectedFork_RejectBeforeFetchingAnyProof()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.GetCurrentForPublicationAsync(Bytes(16, 0x22), Fixture.Service));
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.VerifyCurrentNetworkAsync(Bytes(16, 0x22)));
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, new byte[32]));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network, cancelled.Token));
        Assert.Equal(0, fixture.ProofRequests);
        _ = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        var current = (await fixture.NetworkStore.ReadAsync(default))!;
        await fixture.NetworkStore.CompareExchangeAsync(current.Revision,
            new(current.Revision + 1, current.ProtectedLkg, true), default);
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service));
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal(1, fixture.ProofRequests);
    }

    [Fact]
    public void RawNetworkClosureOwnsCopiesAndRejectsOversizedListsBeforeCopying()
    {
        var value = new byte[] { 1 };
        ReadOnlyMemory<byte>[] one = [value];
        var closure = new DeepIdV2NetworkClosureArtifacts(one, one, one, one, one, one, one);
        value[0] = 2;
        Assert.Equal((byte)1, closure.ExactOrderedXnv1Chain[0].Span[0]);
        Assert.True(MemoryMarshal.TryGetArray(closure.ExactOrderedXnv1Chain[0], out var exported));
        exported.Array![exported.Offset] = 3;
        Assert.Equal((byte)1, closure.ExactOrderedXnv1Chain[0].Span[0]);
        var tooMany = Enumerable.Repeat<ReadOnlyMemory<byte>>(value, 4097).ToArray();
        Assert.Throws<ArgumentException>(() =>
            new DeepIdV2NetworkClosureArtifacts(one, one, one, tooMany, tooMany, one, one));
        Assert.Throws<ArgumentException>(() =>
            new DeepIdV2NetworkClosureArtifacts(one, one, one, [value, value], one, one, one));
    }

    [Fact]
    public void AccountPublisherRequiresDid2OnlyAuthoritySource()
    {
        var method = typeof(DeepIdV2AccountService).GetMethod(
            nameof(DeepIdV2AccountService.PublishOwnStagedPreKeyInventoryAsync))!;
        Assert.Equal(typeof(DeepIdV2ContactPathAuthoritySource), method.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(DeepIdV2OnionClientCustody), method.GetParameters()[1].ParameterType);
        Assert.Empty(typeof(DeepIdV2OnionClientCustody).GetConstructors());
    }

    [Fact]
    public async Task OnionGuardCustody_PreservesCasAfterReopenAndRejectsSqlRollbackAndForeignOwner()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        Assert.Null(await custody.Guards.ReadAsync(default));
        var first = Guard(1);
        Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
            (await custody.Guards.CompareExchangeAsync(null, first, default)).Disposition);
        Assert.Equal(EntryGuardStoreWriteDisposition.Conflict,
            (await custody.Guards.CompareExchangeAsync(null, first, default)).Disposition);
        var reopenedAccount = fixture.ReopenAccount();
        var reopened = await reopenedAccount.OpenOwnOnionClientCustodyAsync();
        Assert.Equal(EntryGuardStateCodec.Encode(first),
            EntryGuardStateCodec.Encode((await reopened.Guards.ReadAsync(default))!));
        await Assert.ThrowsAsync<ArgumentException>(() => reopenedAccount.PublishOwnStagedPreKeyInventoryAsync(
            fixture.Source(reopenedAccount), custody));
        Assert.Equal(0, fixture.ProofRequests);
        var second = Guard(2);
        Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
            (await reopened.Guards.CompareExchangeAsync(1, second, default)).Disposition);
        await using (var connection = await fixture.OpenSqlAsync())
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE protected_lkg_root SET revision=1,payload=$payload WHERE root_kind=4;";
            command.Parameters.AddWithValue("$payload", EntryGuardStateCodec.Encode(first));
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        await Assert.ThrowsAsync<CryptographicException>(async () => await reopened.Guards.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => reopenedAccount.OpenOwnOnionClientCustodyAsync());
        await fixture.ResetAccountAsync();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await custody.Guards.ReadAsync(default));
    }

    [Fact]
    public async Task OnionGuardMarkerBeforeSqlCrash_RejectsReadAndReopenWithoutEmittingAuthority()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        fixture.FailAfterNextOnionMarker();
        await Assert.ThrowsAsync<IOException>(async () =>
            await custody.Guards.CompareExchangeAsync(null, Guard(1), default));
        await Assert.ThrowsAsync<CryptographicException>(async () => await custody.Guards.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.Accounts.OpenOwnOnionClientCustodyAsync());
        Assert.Equal(0, fixture.ProofRequests);
    }

    private static EntryGuardState Guard(ulong revision) => new(revision, Fixture.Network,
        1, Bytes(32, 0x21), Bytes(32, 0x22), Bytes(32, 0x23), [Bytes(32, 0x23)]);

    [Fact]
    public async Task AccountNetworkFloor_RejectsSqlRollbackCorruptionDeletionAndRepin()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        var initial = (await fixture.NetworkStore.ReadAsync(default))!;
        Assert.Equal(XPointNetworkStoreWriteDisposition.Conflict,
            (await fixture.NetworkStore.CompareExchangeAsync(null, initial, default)).Disposition);
        await using var connection = await fixture.OpenSqlAsync();
        byte[] Payload()
        {
            using var read = connection.CreateCommand();
            read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=3;";
            return Assert.IsType<byte[]>(read.ExecuteScalar());
        }
        void Replace(long revision, byte[] payload)
        {
            using var write = connection.CreateCommand();
            write.CommandText = "UPDATE protected_lkg_root SET revision=$revision,payload=$payload WHERE root_kind=3;";
            write.Parameters.AddWithValue("$revision", revision);
            write.Parameters.AddWithValue("$payload", payload);
            Assert.Equal(1, write.ExecuteNonQuery());
        }
        var oldPayload = Payload();
        var latched = new XPointNetworkStateSnapshot(2, initial.ProtectedLkg, true);
        Assert.Equal(XPointNetworkStoreWriteDisposition.Applied,
            (await fixture.NetworkStore.CompareExchangeAsync(1, latched, default)).Disposition);
        var currentPayload = Payload();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await fixture.NetworkStore.CompareExchangeAsync(2, new(3, initial.ProtectedLkg, false), default));
        var reopened = await fixture.ReopenNetworkStoreAsync();
        Assert.True((await reopened.ReadAsync(default))!.ForkLatched);
        Replace(1, oldPayload);
        await Assert.ThrowsAsync<CryptographicException>(async () => await reopened.ReadAsync(default));
        Replace(2, currentPayload);
        Assert.True((await reopened.ReadAsync(default))!.ForkLatched);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync(changedPin: true));
        Replace(2, [1]);
        await Assert.ThrowsAsync<InvalidDataException>(async () => await reopened.ReadAsync(default));
        using (var delete = connection.CreateCommand())
        {
            delete.CommandText = "DELETE FROM protected_lkg_root WHERE root_kind=3;";
            Assert.Equal(1, delete.ExecuteNonQuery());
        }
        await Assert.ThrowsAsync<CryptographicException>(async () => await reopened.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
        await connection.DisposeAsync();
        await fixture.ResetAccountAsync();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await reopened.ReadAsync(default));
    }

    [Fact]
    public async Task NetworkMarkerCommittedBeforeSqlCrash_RejectsEmptyFloorAndReopen()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.FailAfterNextNetworkMarker();
        await Assert.ThrowsAsync<IOException>(async () =>
            await fixture.Source().GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service));
        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
    }

    /// <summary>Real account-owned SQLCipher DID2 state and native ML-DSA;
    /// signed public network ceremony and nonce-bound HTTP proof bytes. The
    /// HTTP/secure-storage adapters are in-memory; directory and network
    /// floors use real SQLCipher. This is not TLS, ONION or device evidence.</summary>
    private sealed class Fixture : HttpMessageHandler, IAsyncDisposable,
        IOnionMonotonicClock
    {
        internal static readonly byte[] Network = Bytes(16, 0x11);
        internal static readonly byte[] Service = Bytes(32, 0x35);
        private static readonly byte[] Boot = Bytes(16, 0xf3);
        private readonly string directory = Path.Combine(Path.GetTempPath(),
            "deep-did2-path-" + Guid.NewGuid().ToString("N"));
        private readonly InMemoryDeepSecureStorage innerStorage = new();
        private readonly NetworkMarkerFaultStorage storage;
        private readonly Signer root = new(0x20);
        private readonly Signer[] witnesses = [new(0x30), new(0x31), new(0x32)];
        private readonly Signer[] nodes = [new(0x70), new(0x71), new(0x72)];
        private readonly IDeepMlDsa65VerifierLease pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        private VerifiedXPointNetworkBootstrap bootstrap = null!;
        private AuthoredXPointNetworkOperationalGenesis operational = null!;
        private AuthoredAccountDirectoryHeadMutation genesis = null!;
        private AuthoredAccountDirectoryHeadMutation head = null!;
        private VerifiedAdc1V2 checkpoint = null!;
        private DeepIdV2AccountService accounts = null!;
        private DeepIdV2DirectoryProofClient proofs = null!;
        private HttpClient http = null!;
        private HttpDeepIdV2NetworkClosureArtifactSource closure = null!;
        internal IXPointNetworkStateStore NetworkStore { get; private set; } = null!;
        internal int ProofRequests { get; private set; }
        internal bool RejectProof { get; set; }
        internal bool AlterNode { get; set; }
        internal ulong Sample { get; set; } = 100;
        internal DeepIdV2AccountService Accounts => accounts;
        internal DeepIdV2AccountService ReopenAccount() => new(storage, directory, Network, 1,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
            DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);

        internal void VerifyInventory(StagedDeepIdV2PreKeyPublication staged,
            VerifiedDeepIdV2DirectoryFreshness fresh)
        {
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span),
                checkpoint.Binding, checkpoint.Directory);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh, dca, Boot, Sample);
            DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(checkpoint.Binding.DeepId,
                staged.ExactXps1.Span, authorization,
                DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span), Boot, Sample);
        }

        private Fixture() => storage = new(innerStorage);
        internal void FailAfterNextNetworkMarker() => storage.FailAfterNetworkMarker = true;
        internal void FailAfterNextOnionMarker() => storage.FailAfterOnionMarker = true;
        internal Task ResetAccountAsync() => accounts.ResetExplicitlyAsync();

        internal async Task<IXPointNetworkStateStore> ReopenNetworkStoreAsync(bool changedPin = false)
        {
            var reopened = new DeepIdV2AccountService(storage, directory, Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            var pin = changedPin ? new XPointNetworkGenesisPin(Network, Bytes(32, 0x55)) : bootstrap.GenesisPin;
            return await reopened.OpenNetworkLkgStoreAsync(pin);
        }

        internal async Task<SqliteConnection> OpenSqlAsync()
        {
            using var record = await storage.ReadOwnedAsync("deep.store.v2.sql-generation");
            var key = record!.Use(value => value.Slice(88, 32).ToArray());
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = Path.Combine(directory, "deep-store-v2-account.dsv2"),
              Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
            try
            {
                connection.Open();
                Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(connection.Handle, key));
                return connection;
            }
            catch { connection.Dispose(); throw; }
            finally { CryptographicOperations.ZeroMemory(key); }
        }

        internal static async Task<Fixture> CreateAsync()
        {
            var fixture = new Fixture();
            try { await fixture.InitializeAsync(); return fixture; }
            catch { await fixture.DisposeAsync(); throw; }
        }

        private async Task InitializeAsync()
        {
            Directory.CreateDirectory(directory);
            accounts = new(storage, directory, Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            await accounts.CreateAsync("DID2 path test");
            bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                new(Bytes(32, 0x12), Network,
                    [new(root.RootKeyId.Span, 0, root.Ed25519PublicKey.Span, root.CustodyDomainHash.Span)], 1,
                    witnesses.Select(w => new XPointNetworkBootstrapWitnessKey(w.SignerId.Span, 0,
                        w.Ed25519PublicKey.Span, w.FailureDomainHash.Span)).ToArray(), 2,
                    [new(Bytes(32, 0x60), Bytes(32, 0x61), 1, "time1.invalid", 4460, Bytes(32, 0x62), 5),
                     new(Bytes(32, 0x63), Bytes(32, 0x64), 1, "time2.invalid", 4460, Bytes(32, 0x65), 5)],
                    5, 10, 900, 900, 10_000, 900, 9_000, 1, 1), [root]);
            var descriptors = nodes.Select((signer, index) => new XPointNetworkOperationalNode(signer,
                Bytes(32, (byte)(0x80 + index)), Bytes(32, (byte)(0x90 + index)),
                Bytes(32, (byte)(0xa0 + index)), Bytes(32, (byte)(0xb0 + index)),
                (uint)(64_500 + index), 840, Bytes(32, (byte)(0xc0 + index)),
                IPAddress.Parse($"192.0.2.{index + 1}"), 443,
                Bytes(32, (byte)(0xd0 + index)), Bytes(32, (byte)(0xd8 + index)),
                ScalarMult.Base(Bytes(32, (byte)(0xe0 + index))),
                ScalarMult.Base(Bytes(32, (byte)(0xe8 + index))),
                Enumerable.Range(0, 5).Select(role => (ReadOnlyMemory<byte>)
                    PublicKey((byte)(0x10 + index * 5 + role))).ToArray())).ToArray();
            operational = await XPointNetworkOperationalGenesisAuthor.AuthorAsync(new(
                Bytes(32, 0x12), bootstrap, [root], witnesses, descriptors, Bytes(32, 0xf1),
                Bytes(32, 0xf4), Bytes(32, 0xf5), Bytes(32, 0xf6), PublicKey(0x31), PublicKey(0x32),
                990, 1_000, 1_500, Bytes(32, 0xf2), Boot, 100, 100, 100, 1_100, 5));
            var admission = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(
                await accounts.PrepareGenesisAdmissionAsync()).Admission;
            checkpoint = DeepIdV2GenesisAdmissionVerifier.Verify(admission, 1_000, 1, 2, pq);
            genesis = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
                bootstrap.Authority, 990, 1_500, witnesses);
            head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority,
                genesis.ProtectedHead, new([], [], [checkpoint], 990, 1_500, 2), witnesses);
            var floor = await accounts.OpenDirectoryLkgStoreAsync(bootstrap.Authority,
                genesis.ExactAdh1, genesis.CoreHash);
            NetworkStore = await accounts.OpenNetworkLkgStoreAsync(bootstrap.GenesisPin);
            http = new(this, disposeHandler: false);
            var transport = new HttpServiceRequestTransport(http,
                DeepIdV2DirectoryProofClient.CreateTransportOptions("https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            proofs = new(transport, this, pq, floor);
            closure = new(new HttpServiceRequestTransport(new HttpClient(this, disposeHandler: false),
                HttpDeepIdV2NetworkClosureArtifactSource.CreateTransportOptions("https://registry.example/"),
                HttpServiceEndpointPolicy.Production));
        }

        internal DeepIdV2ContactPathAuthoritySource Source(DeepIdV2AccountService? account = null) =>
            new(bootstrap.GenesisPin, account ?? accounts, proofs, closure, NetworkStore, this);

        private DeepIdV2NetworkClosureArtifacts PublicClosure()
        {
            var descriptors = operational.ExactXnd1.Select(value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
            if (AlterNode) { var bytes = descriptors[0].ToArray(); bytes[^1] ^= 1; descriptors[0] = bytes; }
            return new DeepIdV2NetworkClosureArtifacts(
                [bootstrap.ExactXna1], [bootstrap.ExactDts1], [operational.ExactXvp1],
                [operational.ExactXnv1], [operational.ExactXnh1], descriptors, [operational.ExactPmt2]);
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == HttpDeepIdV2NetworkClosureArtifactSource.EndpointPath)
            {
                var network = XPointNetworkClosureWireCodec.DecodeRequest(
                    await request.Content!.ReadAsByteArrayAsync(cancellationToken));
                Assert.Equal(Network, network);
                var raw = PublicClosure();
                var encoded = XPointNetworkClosureWireCodec.EncodeResponse(network,
                    raw.ExactXna1AuthorityChain, raw.ExactDts1PolicyChain,
                    raw.ExactOrderedXvp1Chain, raw.ExactOrderedXnv1Chain,
                    raw.ExactOrderedXnh1Chain, raw.ExactActiveXnd1, raw.ExactOrderedPmt2Chain);
                var distributed = new HttpResponseMessage(HttpStatusCode.OK)
                { RequestMessage = request, Content = new ByteArrayContent(encoded) };
                distributed.Content.Headers.ContentType = new(XPointNetworkClosureWireCodec.ResponseMediaType);
                return distributed;
            }
            ProofRequests++;
            if (RejectProof) return new(HttpStatusCode.ServiceUnavailable) { RequestMessage = request };
            var query = DeepIdV2DirectoryProofWireCodec.DecodeRequest(
                await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            var floor = query.Lookup.MinimumAdhGeneration switch
            {
                0 => genesis.ProtectedHead,
                1 => head.ProtectedHead,
                _ => throw new CryptographicException("Unknown test directory floor.")
            };
            var material = DeepIdV2DirectoryProofMaterialAuthor.Create(head.ProtectedHead,
                head.ExactAllTransitions, [checkpoint], query.DirectoryLeafKey.Span, floor);
            var issued = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(bootstrap.Authority,
                new(Network, query.Nonce.Span, query.BootId.Span, query.ClientMonotonicSendSample,
                    head.ExactAdh1.Span, operational.ExactXnv1.Span, 1_100, 5, 1_100, 1_130,
                    AccountDirectoryDtt1IssuanceEpoch.Derive(bootstrap.Authority, 1_100, 5), 2),
                material, witnesses, 1, pq, cancellationToken);
            var body = DeepIdV2DirectoryProofWireCodec.EncodeResponse(query, issued);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            { RequestMessage = request, Content = new ByteArrayContent(body) };
            response.Content.Headers.ContentType = new(DeepIdV2DirectoryProofWireCodec.ResponseMediaType);
            response.Headers.CacheControl = new() { NoStore = true };
            return response;
        }

        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(Boot, Sample));
        }

        public ValueTask DisposeAsync()
        {
            closure?.Dispose(); proofs?.Dispose(); http?.Dispose(); pq.Dispose(); innerStorage.Dispose();
            foreach (var signer in witnesses.Concat(nodes).Append(root)) signer.Dispose();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
            Dispose(); return ValueTask.CompletedTask;
        }
    }

    private sealed class NetworkMarkerFaultStorage(IDeepSecureStorage inner) : IDeepSecureStorage
    {
        internal bool FailAfterNetworkMarker { get; set; }
        internal bool FailAfterOnionMarker { get; set; }
        public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken ct = default) => inner.ReadOwnedAsync(slot, ct);
        public async Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken ct = default)
        {
            await inner.WriteBatchAsync(writes, ct);
            if (FailAfterOnionMarker && writes.Any(write => write.Slot.Contains(".onion-custody.", StringComparison.Ordinal)))
            {
                FailAfterOnionMarker = false;
                throw new IOException("Injected stop after ONION marker, before SQL commit.");
            }
            if (FailAfterNetworkMarker && writes.Any(write => write.Slot.Contains(".network-lkg-floor.", StringComparison.Ordinal)))
            {
                FailAfterNetworkMarker = false;
                throw new IOException("Injected stop after network marker, before SQL commit.");
            }
        }
        public Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken ct = default) => inner.DeleteBatchAsync(slots, ct);
        public Task PurgeStoreV1NamespaceAsync(CancellationToken ct = default) => inner.PurgeStoreV1NamespaceAsync(ct);
        public Task PurgeStoreV2NamespaceAsync(CancellationToken ct = default) => inner.PurgeStoreV2NamespaceAsync(ct);
    }

    private sealed class Signer : IDisposable, IXPointNetworkBootstrapRootSigner,
        IXPointNetworkWitnessSigner, IAccountDirectoryAdh1WitnessSigner
    {
        private readonly byte marker;
        private readonly KeyPair key;
        internal Signer(byte marker)
        {
            this.marker = marker;
            var seed = Bytes(32, marker);
            try { key = PublicKeyAuth.GenerateKeyPair(seed); }
            finally { CryptographicOperations.ZeroMemory(seed); }
        }
        public ReadOnlyMemory<byte> RootKeyId => Bytes(32, marker);
        public ReadOnlyMemory<byte> SignerId => marker >= 0x70 ? key.PublicKey : RootKeyId;
        public ReadOnlyMemory<byte> WitnessId => SignerId;
        public ulong KeyGeneration => 0;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, (byte)(marker + 0x40));
        public ReadOnlyMemory<byte> FailureDomainHash => CustodyDomainHash;
        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request,
            Memory<byte> signature64, CancellationToken ct) => Sign(request.SigningInput, signature64, ct);
        public ValueTask<int> SignAsync(XPointNetworkOperationalSigningRequest request,
            Memory<byte> signature64, CancellationToken ct) => Sign(request.SigningInput, signature64, ct);
        private ValueTask<int> Sign(ReadOnlyMemory<byte> input, Memory<byte> destination, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey).CopyTo(destination);
            return ValueTask.FromResult(64);
        }
        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(ReadOnlyMemory<byte> input, CancellationToken ct) => Witness(input, ct);
        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(ReadOnlyMemory<byte> input, CancellationToken ct) => Witness(input, ct);
        private ValueTask<ReadOnlyMemory<byte>> Witness(ReadOnlyMemory<byte> input, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey));
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
    private static byte[] PublicKey(byte marker)
    {
        var seed = Bytes(32, marker); var pair = PublicKeyAuth.GenerateKeyPair(seed);
        try { return pair.PublicKey.ToArray(); }
        finally { CryptographicOperations.ZeroMemory(seed); CryptographicOperations.ZeroMemory(pair.PrivateKey); }
    }
}
