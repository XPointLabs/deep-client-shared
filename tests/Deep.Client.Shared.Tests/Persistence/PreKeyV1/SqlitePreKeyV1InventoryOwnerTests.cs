using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.PreKeyV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using System.Reflection;

namespace Deep.Client.Shared.Tests.Persistence.PreKeyV1;

[Collection("SQLite global pool isolation")]
[Trait("RequiresApprovedMlKemRuntime", "true")]
public sealed class SqlitePreKeyV1InventoryOwnerTests
{
    [Fact]
    public async Task AtomicInventorySurvivesRestartAndVerifiedClaimKeysExactDurableSecret()
    {
        using var fixture = new Fixture();
        using var batch = fixture.Batch(epoch: 1);
        await using (var owner = fixture.Open())
        {
            var capabilities = batch.Capabilities(owner);
            var staged = await owner.StageInventoryAsync(batch.Request, capabilities);
            Assert.Equal(PreKeyV1InventoryStageDisposition.Staged, staged.Disposition);
            Assert.All(capabilities, static capability => Assert.True(capability.IsClearedForTesting));
        }

        await using var restarted = fixture.Open(allowCreate: false);
        var durable = await restarted.ReadPublicationAsync(1);
        Assert.NotNull(durable);
        Assert.Equal(batch.Request.ExactPublicationRequest.ToArray(), durable!.ExactPublicationRequest.ToArray());
        Assert.Equal(batch.Request.ExactXpi1.ToArray(), durable.ExactXpi1.ToArray());

        var selected = batch.OneTime[0];
        var claim = fixture.Claim(selected, operationMarker: 0x71);
        var reserved = await restarted.ReserveAndRestoreForTestsAsync(claim);
        Assert.Equal(PreKeyV1ClaimDisposition.Reserved, reserved.Disposition);
        Assert.True(reserved.SecretCallbackInvoked);
    }

    [Theory]
    [InlineData((int)PreKeyV1StoreFailpoint.AfterInventorySecretsBeforePublication)]
    [InlineData((int)PreKeyV1StoreFailpoint.BeforeInventoryCommit)]
    public async Task CrashBeforeInventoryCommitRollsBackSecretsAndPublication(int failpointValue)
    {
        using var fixture = new Fixture();
        using (var batch = fixture.Batch(epoch: 1))
        await using (var owner = fixture.Open())
        using (PreKeyV1StoreTestHooks.Push(point =>
                   { if (point == (PreKeyV1StoreFailpoint)failpointValue) throw new PreKeyV1InjectedCrashException(point); }))
        {
            await Assert.ThrowsAsync<PreKeyV1InjectedCrashException>(async () =>
                await owner.StageInventoryAsync(batch.Request, batch.Capabilities(owner)));
        }

        await using var restarted = fixture.Open(allowCreate: false);
        Assert.Null(await restarted.ReadPublicationAsync(1));
        using var retry = fixture.Batch(epoch: 1);
        var result = await restarted.StageInventoryAsync(retry.Request, retry.Capabilities(restarted));
        Assert.Equal(PreKeyV1InventoryStageDisposition.Staged, result.Disposition);
    }

    [Fact]
    public async Task CrashAfterCommitRecoversExactRequestAndReplayDoesNotDuplicateInventory()
    {
        using var fixture = new Fixture();
        using var batch = fixture.Batch(epoch: 1);
        await using (var owner = fixture.Open())
        using (PreKeyV1StoreTestHooks.Push(point =>
                   { if (point == PreKeyV1StoreFailpoint.AfterInventoryCommit) throw new PreKeyV1InjectedCrashException(point); }))
        {
            await Assert.ThrowsAsync<PreKeyV1InjectedCrashException>(async () =>
                await owner.StageInventoryAsync(batch.Request, batch.Capabilities(owner)));
        }

        await using var restarted = fixture.Open(allowCreate: false);
        var durable = await restarted.ReadPublicationAsync(1);
        Assert.NotNull(durable);
        Assert.Equal(batch.Request.ExactPublicationRequest.ToArray(), durable!.ExactPublicationRequest.ToArray());
        Assert.Equal(batch.Request.ExactPublicationRequest.ToArray(), durable.ExactPublicationRequest.ToArray());
    }

    [Fact]
    public async Task EpochRollbackLatchesForkAcrossRestart()
    {
        using var fixture = new Fixture();
        using var genesis = fixture.Batch(epoch: 1);
        using var current = fixture.Batch(epoch: 2, predecessor: genesis.Request.Xpi1Hash.Span);
        await using (var owner = fixture.Open())
        {
            Assert.Equal(PreKeyV1InventoryStageDisposition.Staged,
                (await owner.StageInventoryAsync(genesis.Request, genesis.Capabilities(owner))).Disposition);
            Assert.Equal(PreKeyV1InventoryStageDisposition.Staged,
                (await owner.StageInventoryAsync(current.Request, current.Capabilities(owner))).Disposition);
            using var rollback = fixture.Batch(epoch: 1, variant: 1);
            var rejected = await owner.StageInventoryAsync(
                rollback.Request, rollback.Capabilities(owner));
            Assert.Equal(PreKeyV1InventoryStageDisposition.ForkLatched, rejected.Disposition);
            Assert.True(rejected.ForkLatched);
        }

        await using var restarted = fixture.Open(allowCreate: false);
        using var successor = fixture.Batch(epoch: 3, predecessor: current.Request.Xpi1Hash.Span);
        var blocked = await restarted.StageInventoryAsync(
            successor.Request, successor.Capabilities(restarted));
        Assert.Equal(PreKeyV1InventoryStageDisposition.AlreadyForkLatched, blocked.Disposition);
    }

    [Fact]
    public void ProductionSurfaceUsesProtocolCapabilitiesAndHasNoPublicRawSecretOrProviderSeam()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot(), "src", "Deep.Client.Shared", "Services", "ContactV1",
            "ProductionPreKeyV1InventoryOwner.cs"));
        Assert.Contains("authority.AuthorOneTime", source, StringComparison.Ordinal);
        Assert.Contains("authority.AuthorLastResort", source, StringComparison.Ordinal);
        Assert.Contains("store.SealAuthored", source, StringComparison.Ordinal);
        Assert.Contains("Xpi1Codec.Encode", source, StringComparison.Ordinal);
        Assert.Contains("Xpp1Codec.Encode", source, StringComparison.Ordinal);
        Assert.DoesNotContain("SessionId", source, StringComparison.Ordinal);
        Assert.DoesNotContain("private key", source, StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(typeof(IPreKeyV1InventoryOwner).GetMethods()
            .SelectMany(static method => method.GetParameters()),
            static parameter => parameter.ParameterType == typeof(byte[]) ||
                typeof(Delegate).IsAssignableFrom(parameter.ParameterType));
        Assert.DoesNotContain(
            typeof(Deep.Client.Shared.Services.DeepAccountService)
                .GetMethod("OpenCurrentDpk2AuthoringAuthorityAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
                .GetParameters(),
            static parameter => parameter.ParameterType == typeof(byte[]) ||
                typeof(Delegate).IsAssignableFrom(parameter.ParameterType));
        Assert.DoesNotContain(
            typeof(Deep.Protocol.MessagingCrypto.Dpk2PreKeySecretCapability)
                .GetMethods(BindingFlags.Instance | BindingFlags.Public),
            static method => method.ReturnType == typeof(byte[]));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly OpaquePreKeyV1AuthoringFixture authoring;
        private readonly string directory = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "deep-prekey-inventory", Guid.NewGuid().ToString("N"));
        private readonly byte[] key = Bytes(32, 0x11);
        internal readonly byte[] Network;
        internal readonly byte[] Account;
        internal readonly byte[] Device;
        internal readonly byte[] DpdHash;
        internal readonly byte[] DmdHash;
        internal readonly byte[] DpdReference;

        internal Fixture()
        {
            authoring = OpaquePreKeyV1AuthoringFixture.CreateAsync().GetAwaiter().GetResult();
            Directory.CreateDirectory(directory);
            Network = authoring.NetworkId.ToArray();
            Account = authoring.AccountId.ToArray();
            Device = authoring.DeviceId.ToArray();
            DpdHash = authoring.Dpd1Hash.ToArray();
            DpdReference = authoring.Dpd1Reference.ToArray();
            DmdHash = authoring.CurrentDirectory.Head.Record.RecordHash.ToArray();
        }

        private string Path => System.IO.Path.Combine(directory, "prekeys.db");
        internal PreKeyV1StoreScope Scope => new(
            Network, Account, 1, Device, authoring.DeviceGeneration, DpdReference, DpdHash, 13);

        internal SqlitePreKeyV1SecretOwner Open(bool allowCreate = true)
        {
            using var options = new PreKeyV1StoreOptions(Path, key, Scope, allowCreate);
            return new SqlitePreKeyV1SecretOwner(options);
        }

        internal Batch Batch(ulong epoch, ReadOnlySpan<byte> predecessor = default, byte variant = 0)
        {
            var predecessorHash = predecessor.IsEmpty ? new byte[32] : predecessor.ToArray();
            var oneTime = Enumerable.Range(0, 32)
                .Select(_ => Material(Dpk2PrekeyKind.OneTime, epoch))
                .OrderBy(static value => value.Record.OneTimeX25519PrekeyId.ToArray(), ByteArrayOrder.Instance)
                .ToArray();
            var last = Material(Dpk2PrekeyKind.LastResort, epoch, reuseLimit: 2);
            var hashes = oneTime.Select(static value => value.Hash.ToArray()).ToArray();
            var root = ProductionPreKeyV1InventoryOwner.ComputeInventoryMerkleRoot(hashes);
            try
            {
                var fields = new Xpi1UnsignedFields(
                    Network, Bytes(32, 0x81), Device, DpdReference,
                    oneTime[0].Record.PrekeyServiceGeneration,
                    Reference("XPS1", Bytes(32, 0x82)), epoch, predecessorHash,
                    32, root, last.Hash, DmdHash,
                    Reference("DRS1", Bytes(32, 0x83)),
                    oneTime[0].Record.NotBefore,
                    oneTime[0].Record.ExpiresAt);
                var exactXpi1 = Xpi1Codec.Encode(fields, Bytes(64, 0x84 + variant));
                var manifest = Xpi1Codec.Decode(exactXpi1);
                var operation = Bytes(32, checked((byte)(0x90 + epoch + variant)));
                var exactXpp1 = Xpp1Codec.Encode(
                    Network, operation, Bytes(32, 0x91 + variant), manifest,
                    oneTime.Select(static value => (ReadOnlyMemory<byte>)value.Exact).ToArray(),
                    last.Exact);
                var xpiHash = Xpi1Codec.ComputeHash(exactXpi1);
                var request = new PreKeyV1PublicationRequest(
                    epoch, oneTime[0].Record.PrekeyServiceGeneration,
                    operation, predecessorHash,
                    oneTime[0].Record.DeviceDirectoryGeneration, DmdHash,
                    xpiHash, exactXpi1, exactXpp1);
                CryptographicOperations.ZeroMemory(exactXpi1);
                CryptographicOperations.ZeroMemory(exactXpp1);
                CryptographicOperations.ZeroMemory(xpiHash);
                CryptographicOperations.ZeroMemory(operation);
                return new Batch(request, oneTime, last);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(predecessorHash);
                CryptographicOperations.ZeroMemory(root);
                foreach (var hash in hashes) CryptographicOperations.ZeroMemory(hash);
            }
        }

        internal PreKeyV1ClaimCapability Claim(Material selected, byte operationMarker) =>
            PreKeyV1ClaimCapability.CreateForTests(
                Dpk2PrekeyKind.OneTime, 0,
                Bytes(32, operationMarker), Bytes(32, operationMarker + 1), selected.Hash,
                Bytes(32, operationMarker + 2), Bytes(32, operationMarker + 3),
                selected.Record.OneTimeX25519PrekeyId.Span, selected.Record.MlKemPrekeyId.Span);

        private Material Material(Dpk2PrekeyKind kind, ulong epoch, ushort reuseLimit = 0)
        {
            var offering = authoring.Author(kind, epoch, reuseLimit);
            return new Material(
                offering,
                offering.Record,
                offering.ExactDpk2.ToArray(),
                offering.ExactDpk2Hash.ToArray());
        }

        public void Dispose()
        {
            authoring.Dispose();
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(Network);
            CryptographicOperations.ZeroMemory(Account);
            CryptographicOperations.ZeroMemory(Device);
            CryptographicOperations.ZeroMemory(DpdHash);
            CryptographicOperations.ZeroMemory(DmdHash);
            CryptographicOperations.ZeroMemory(DpdReference);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class Batch(
        PreKeyV1PublicationRequest request,
        Material[] oneTime,
        Material lastResort) : IDisposable
    {
        internal PreKeyV1PublicationRequest Request { get; } = request;
        internal Material[] OneTime { get; } = oneTime;
        internal Material LastResort { get; } = lastResort;

        internal IReadOnlyList<PreKeyV1ProvisioningCapability> Capabilities(
            SqlitePreKeyV1SecretOwner owner) =>
            OneTime.Append(LastResort)
                .Select(value => owner.SealAuthored(value.Offering))
                .ToArray();

        public void Dispose()
        {
            foreach (var value in OneTime) value.Dispose();
            LastResort.Dispose();
        }
    }

    private sealed class Material(
        AuthoredDpk2Offering offering,
        Dpk2Record record,
        byte[] exact,
        byte[] hash) : IDisposable
    {
        internal AuthoredDpk2Offering Offering { get; } = offering;
        internal Dpk2Record Record { get; } = record;
        internal byte[] Exact { get; } = exact;
        internal byte[] Hash { get; } = hash;
        public void Dispose()
        {
            Offering.Dispose();
            CryptographicOperations.ZeroMemory(Exact);
            CryptographicOperations.ZeroMemory(Hash);
        }
    }

    private sealed class ByteArrayOrder : IComparer<byte[]>
    {
        internal static ByteArrayOrder Instance { get; } = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private static byte[] Bytes(int length, int marker)
    {
        var value = new byte[length];
        for (var index = 0; index < value.Length; index++)
            value[index] = unchecked((byte)(marker + index * 17 + 1));
        return value;
    }

    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Deep.Client.Shared.slnx")))
                return current.FullName;
            current = current.Parent;
        }
        throw new DirectoryNotFoundException("deep-client-shared root was not found.");
    }
}
