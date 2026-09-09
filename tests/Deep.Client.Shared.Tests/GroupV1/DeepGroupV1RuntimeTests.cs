using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Client.Shared.Services.GroupV1;
using Deep.Protocol.GroupV1;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.GroupV1;

public sealed class DeepGroupV1RuntimeTests : IDisposable
{
    private readonly string directory = Path.Combine(
        Path.GetTempPath(), "deep-group-runtime-" + Guid.NewGuid().ToString("N"));
    private readonly byte[] key = Bytes(32, 0xc1);

    public DeepGroupV1RuntimeTests() => Directory.CreateDirectory(directory);

    [Fact]
    public async Task VerifiedTransitionAppliesReadsAndSurvivesStoreRestart()
    {
        var account = Account(0x71);
        var device = Device(0x31);
        var scope = GroupStoreScope.ForCurrentAccount(account.AccountId, account.AccountGeneration);
        var authored = Genesis();
        var groupId = GroupId32.FromBytes(authored.Transition.Commit.Field(2).Span);

        using (var options = Options(scope))
        using (var store = new SqliteGroupStateStore(options))
        {
            IDeepGroupV1Runtime runtime = new DeepGroupV1Runtime(
                account.AccountId, device, new BoundSigner(device), store);
            var applied = await runtime.ApplyVerifiedTransitionAsync(Operation(1), null, authored);

            Assert.Equal(GroupCommitDisposition.Applied, applied.Disposition);
            Assert.Equal((ulong)1, applied.Head!.Revision);
            var read = await runtime.ReadAsync(groupId);
            Assert.NotNull(read);
            Assert.Equal(authored.Package.CanonicalBytes.ToArray(), read!.ExactCanonicalPackage.ToArray());

            var replay = await runtime.ApplyVerifiedTransitionAsync(Operation(1), null, authored);
            Assert.Equal(GroupCommitDisposition.Idempotent, replay.Disposition);
        }

        using var reopenedOptions = Options(scope, allowCreate: false);
        using var reopenedStore = new SqliteGroupStateStore(reopenedOptions);
        var reopenedRuntime = new DeepGroupV1Runtime(
            account.AccountId, device, new BoundSigner(device), reopenedStore);
        var restored = Assert.Single(await reopenedRuntime.ReadAllAsync());
        Assert.Equal(groupId, restored.GroupId);
        Assert.Equal((ulong)1, restored.Revision);
        Assert.Equal(authored.Transition.ExactVerifiedGcp1Sha256.ToArray(),
            restored.ExactVerifiedGcp1Sha256.ToArray());
    }

    [Fact]
    public async Task ChangedPackageRejectsBeforeAnyStoreMutation()
    {
        var account = Account(0x72);
        var device = Device(0x32);
        var scope = GroupStoreScope.ForCurrentAccount(account.AccountId, account.AccountGeneration);
        var authored = Genesis();
        var changedPackage = Assert.IsType<GroupCommitPackageRecord>(Record(
            "GCP1",
            Enumerable.Range(1, 11)
                .Select(tag => tag == 11 ? new byte[] { 1 } : authored.Package.Field(tag).ToArray())
                .ToArray()));
        var substituted = Authored(changedPackage, authored.Transition);

        using var options = Options(scope);
        using var store = new SqliteGroupStateStore(options);
        var runtime = new DeepGroupV1Runtime(
            account.AccountId, device, new BoundSigner(device), store);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            runtime.ApplyVerifiedTransitionAsync(Operation(2), null, substituted).AsTask());
        Assert.Empty(await runtime.ReadAllAsync());
    }

    [Fact]
    public void CompositionRejectsForeignAccountStoreAndForeignDeviceCustody()
    {
        var account = Account(0x73);
        var foreignAccount = Account(0x74);
        var device = Device(0x33);
        var foreignDevice = Device(0x34);
        var scope = GroupStoreScope.ForCurrentAccount(account.AccountId, account.AccountGeneration);

        using var options = Options(scope);
        using var store = new SqliteGroupStateStore(options);
        Assert.Throws<ArgumentException>(() => new DeepGroupV1Runtime(
            foreignAccount.AccountId, device, new BoundSigner(device), store));
        Assert.Throws<ArgumentException>(() => new DeepGroupV1Runtime(
            account.AccountId, device, new BoundSigner(foreignDevice), store));
    }

    [Fact]
    public void PublicRuntimeBoundaryIsTypedAndLegacyFree()
    {
        var boundaryTypes = new[]
        {
            typeof(IDeepGroupV1Runtime),
            typeof(DeepGroupV1Runtime),
            typeof(IDeepGroupControlTransport),
            typeof(DeepGroupV1TransitionResult),
        };
        foreach (var type in boundaryTypes)
        {
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance |
                                                    BindingFlags.DeclaredOnly))
            {
                AssertLegacyFree(method.ReturnType);
                foreach (var parameter in method.GetParameters())
                    AssertLegacyFree(parameter.ParameterType);
            }
        }

        Assert.Equal(typeof(DeepAccountId32),
            typeof(IDeepGroupV1Runtime).GetProperty(nameof(IDeepGroupV1Runtime.AccountId))!.PropertyType);
        Assert.Equal(typeof(DeviceId32),
            typeof(IDeepGroupV1Runtime).GetProperty(nameof(IDeepGroupV1Runtime.DeviceId))!.PropertyType);
        Assert.Empty(typeof(VerifiedGroupControlResult).GetConstructors());
        Assert.Empty(typeof(VerifiedAuthoredGroupTransition).GetConstructors());
    }

    [Fact]
    public void RuntimeSourceUsesProductionAuthorsAndContainsNoLegacyAliasesOrCallerTrustFlags()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "Deep.Client.Shared",
            "Services", "GroupV1", "DeepGroupV1Runtime.cs"));

        Assert.Contains("GroupProductionAuthor.AuthorGenesisAsync", source, StringComparison.Ordinal);
        Assert.Contains("GroupProductionAuthor.AuthorInvitationAsync", source, StringComparison.Ordinal);
        Assert.Contains("GroupProductionAuthor.AuthorMembershipCommitAsync", source, StringComparison.Ordinal);
        Assert.Contains("GroupProductionAuthor.AuthorMembershipChangeCommitAsync", source, StringComparison.Ordinal);
        Assert.Contains("GroupControlProductionClient.AuthorWrite", source, StringComparison.Ordinal);
        Assert.Contains("GroupControlProductionClient.AuthorQuery", source, StringComparison.Ordinal);
        Assert.Contains("GroupControlProductionClient.VerifyResult", source, StringComparison.Ordinal);
        Assert.Contains("stateService.PrepareVerifiedTransition", source, StringComparison.Ordinal);
        Assert.DoesNotContain("SessionId", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ConversationId", source, StringComparison.Ordinal);
        Assert.DoesNotContain("\"05", source, StringComparison.Ordinal);
        Assert.DoesNotContain("isTrusted", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("trustNetwork", source, StringComparison.OrdinalIgnoreCase);
    }

    private SqliteGroupStateStoreOptions Options(GroupStoreScope scope, bool allowCreate = true) =>
        new(Path.Combine(directory, "groups.dgv1"), key, scope, allowCreate);

    private static DeepAccountIdentityCapability Account(byte marker) =>
        DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Bytes(16, 0x11)),
            1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Bytes(32, marker)));

    private static DeviceId32 Device(byte marker)
    {
        using var persisted = OwnedPersistedDeviceIdentitySecrets.TakeOwnership(
            Bytes(32, marker),
            Bytes(32, unchecked((byte)(marker + 1))),
            Bytes(32, unchecked((byte)(marker + 2))),
            Bytes(32, unchecked((byte)(marker + 3))));
        using var restored = OwnedGenesisDeviceSecrets.RestoreFromPersistedOwnedSecrets(persisted);
        return restored.DeviceId;
    }

    private static VerifiedAuthoredGroupTransition Genesis()
    {
        var commit = (GroupCommitRecord)Record("DGC1",
        [
            Bytes(16, 1), Bytes(32, 20), U16(1), U64(0), new byte[32],
            Bytes(32, 2), Bytes(32, 3), Ref("DPD1", 4), U16(0), Array.Empty<byte>(),
            U16(1), Member(Bytes(32, 2), Bytes(32, 3)), Encoding.UTF8.GetBytes("runtime"),
            new byte[] { 0 }, U32(60), U64(1), Bytes(64, 30),
        ]);
        var package = (GroupCommitPackageRecord)Record("GCP1",
        [
            commit.Field(1).ToArray(), commit.Field(2).ToArray(), commit.Field(4).ToArray(),
            Lp(commit.CanonicalBytes.Span), U16(0), Array.Empty<byte>(), U32(0),
            Array.Empty<byte>(), U16(0), Array.Empty<byte>(), Array.Empty<byte>(),
        ]);
        return Authored(package, Verified(commit, package));
    }

    private static VerifiedAuthoredGroupTransition Authored(
        GroupCommitPackageRecord package,
        VerifiedGroupTransition transition) =>
        (VerifiedAuthoredGroupTransition)Activator.CreateInstance(
            typeof(VerifiedAuthoredGroupTransition),
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            args: [package, transition],
            culture: null)!;

    private static VerifiedGroupTransition Verified(
        GroupCommitRecord commit,
        GroupCommitPackageRecord package)
    {
        var implementation = typeof(VerifiedGroupTransition).Assembly.GetType(
            "Deep.Protocol.GroupV1.GroupCodec+VerifiedGroupTransitionImpl", throwOnError: true)!;
        var transition = (VerifiedGroupTransition)System.Runtime.CompilerServices.RuntimeHelpers
            .GetUninitializedObject(implementation);
        var capability = typeof(VerifiedGroupTransition);
        capability.GetField("<Commit>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(transition, commit);
        capability.GetField("<Predecessor>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(transition, null);
        capability.GetField("exactVerifiedGcp1Sha256", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(transition, SHA256.HashData(package.CanonicalBytes.Span));
        return transition;
    }

    private static GroupRecord Record(string magic, IReadOnlyList<byte[]> fields)
    {
        var length = 12 + fields.Sum(field => 8 + field.Length);
        var bytes = new byte[length];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count));
        var at = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(at), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(at + 4), checked((uint)fields[index].Length));
            at += 8;
            fields[index].CopyTo(bytes, at);
            at += fields[index].Length;
        }
        return GroupCodec.Decode(magic, bytes);
    }

    private static byte[] Member(byte[] account, byte[] device)
    {
        var body = Join(account, new byte[] { 1 }, Ref("ADC1", 21), Ref("ADH1", 22),
            Bytes(32, 23), U64(1), Bytes(32, 24), Ref("DRS1", 25), new byte[] { 1 },
            device, Ref("DPD1", 4));
        return Join(U16(checked((ushort)body.Length)), body);
    }

    private static void AssertLegacyFree(Type type)
    {
        var display = type.ToString();
        Assert.DoesNotContain("SessionId", display, StringComparison.Ordinal);
        Assert.DoesNotContain("ConversationId", display, StringComparison.Ordinal);
        if (type.IsGenericType)
            foreach (var argument in type.GetGenericArguments())
                AssertLegacyFree(argument);
    }

    private static string RepositoryRoot()
    {
        for (var current = new DirectoryInfo(AppContext.BaseDirectory);
             current is not null;
             current = current.Parent)
        {
            if (File.Exists(Path.Combine(current.FullName, "Deep.Client.Shared.slnx")))
                return current.FullName;
        }
        throw new DirectoryNotFoundException("deep-client-shared repository root was not found.");
    }

    private static GroupOperationId32 Operation(int value) =>
        GroupOperationId32.FromBytes(SHA256.HashData(BitConverter.GetBytes(value)));
    private static byte[] Ref(string magic, byte marker) => Ref(magic, Bytes(32, marker));
    private static byte[] Ref(string magic, ReadOnlySpan<byte> hash)
    {
        var value = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        value[5] = 1;
        hash.CopyTo(value.AsSpan(6));
        return value;
    }
    private static byte[] Lp(ReadOnlySpan<byte> value) => Join(U32(checked((uint)value.Length)), value.ToArray());
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] Bytes(int length, byte marker) => Enumerable.Repeat(marker, length).ToArray();
    private static byte[] Join(params byte[][] values) => values.SelectMany(static value => value).ToArray();

    private sealed class BoundSigner(DeviceId32 deviceId) : IGroupDeviceCustodySigner
    {
        public ReadOnlyMemory<byte> DeviceId => deviceId.Bytes;
        public ReadOnlyMemory<byte> Ed25519PublicKey => Bytes(32, 0x91);
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, 0x92);
        public ValueTask<int> SignAsync(
            GroupDeviceSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<int>(new InvalidOperationException("This state-only fixture never signs."));
    }

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
