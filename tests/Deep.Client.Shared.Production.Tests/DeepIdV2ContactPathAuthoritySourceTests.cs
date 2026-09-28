using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task RealDid2AccountAndSignedNetwork_MintRechecksProofAndRehydratesExactFloor()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var first = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.True(first.Placement.Binds(ContactServiceRequestKind.PublishPreKeyInventory, Fixture.Service));
        Assert.NotNull(await fixture.NetworkStore.ReadAsync(default));
        var second = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(first.Placement.PlacementHash.ToArray(), second.Placement.PlacementHash.ToArray());
        Assert.Equal(2, fixture.ProofRequests);
        var reopened = fixture.Source();
        var restored = await reopened.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(first.Placement.PlacementHash.ToArray(), restored.Placement.PlacementHash.ToArray());
        Assert.Equal(3, fixture.ProofRequests);
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task MissingFreshProof_CannotReusePreviouslyMintedNetworkAuthority()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        _ = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service));
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
            await fixture.Source().GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service));
        Assert.Null(await fixture.NetworkStore.ReadAsync(default));
    }

    [Fact]
    public async Task UnrelatedNetworkAndProtectedFork_RejectBeforeFetchingAnyProof()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.GetCurrentForPublicationAsync(Bytes(16, 0x22), Fixture.Service));
        Assert.Equal(0, fixture.ProofRequests);
        _ = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        var current = (await fixture.NetworkStore.ReadAsync(default))!;
        await fixture.NetworkStore.CompareExchangeAsync(current.Revision,
            new(current.Revision + 1, current.ProtectedLkg, true), default);
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service));
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
    }

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
        IDeepIdV2NetworkClosureArtifactSource, IOnionMonotonicClock
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
        internal IXPointNetworkStateStore NetworkStore { get; private set; } = null!;
        internal int ProofRequests { get; private set; }
        internal bool RejectProof { get; set; }
        internal bool AlterNode { get; set; }

        private Fixture() => storage = new(innerStorage);
        internal void FailAfterNextNetworkMarker() => storage.FailAfterNetworkMarker = true;
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
        }

        internal DeepIdV2ContactPathAuthoritySource Source() =>
            new(bootstrap.GenesisPin, accounts, proofs, this, NetworkStore, this);

        public ValueTask<DeepIdV2NetworkClosureArtifacts> FetchCurrentAsync(ReadOnlyMemory<byte> networkId,
            XPointNetworkProtectedLkg? protectedFloor, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var descriptors = operational.ExactXnd1.Select(value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
            if (AlterNode) { var bytes = descriptors[0].ToArray(); bytes[^1] ^= 1; descriptors[0] = bytes; }
            return ValueTask.FromResult(new DeepIdV2NetworkClosureArtifacts(
                [bootstrap.ExactXna1], [bootstrap.ExactDts1], [operational.ExactXvp1],
                [operational.ExactXnv1], [operational.ExactXnh1], descriptors, [operational.ExactPmt2]));
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
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
            return ValueTask.FromResult(new OnionMonotonicReading(Boot, 100));
        }

        public ValueTask DisposeAsync()
        {
            proofs?.Dispose(); http?.Dispose(); pq.Dispose(); innerStorage.Dispose();
            foreach (var signer in witnesses.Concat(nodes).Append(root)) signer.Dispose();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
            Dispose(); return ValueTask.CompletedTask;
        }
    }

    private sealed class NetworkMarkerFaultStorage(IDeepSecureStorage inner) : IDeepSecureStorage
    {
        internal bool FailAfterNetworkMarker { get; set; }
        public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken ct = default) => inner.ReadOwnedAsync(slot, ct);
        public async Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken ct = default)
        {
            await inner.WriteBatchAsync(writes, ct);
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
