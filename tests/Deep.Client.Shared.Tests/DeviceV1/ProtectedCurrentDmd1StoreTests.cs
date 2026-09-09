using System.Reflection;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.DeviceV1;

public sealed class ProtectedCurrentDmd1StoreTests
{
    public static IEnumerable<object[]> Stores() => DeviceStateStoreContractTests.Stores();

    [Theory, MemberData(nameof(Stores))]
    public async Task CurrentLkg_RejectsStaleOmittedWrongGenerationAndForkedAuthority(
        DeviceStateStoreContractTests.StoreKind kind)
    {
        using var fixture = kind.Open();
        var first = Evidence(1, null, [Device(0x20, 1, 0x50, 0x70), Device(0x21, 4, 0x51, 0x71)]);
        Assert.Equal(ProtectedCurrentDmd1CommitDisposition.Applied,
            (await Commit(fixture.Store, 0x80, first)).Disposition);

        var granted = await Authorize(fixture.Store, 0x90, first,
            Binding(first, 0x20, 1, 0x50, 0x70));
        Assert.Equal(ProtectedDeviceAgreementDisposition.Granted, granted.Disposition);
        var authorization = Assert.IsType<ProtectedDeviceAgreementAuthorization>(granted.Authorization);
        var use = authorization.ClaimOnce();
        var bindingBytes = use.OperationBinding;
        Assert.Throws<InvalidOperationException>(() => authorization.ClaimOnce());
        use.Dispose();
        authorization.Dispose();

        var second = Evidence(2, first.DirectoryHash.Span, [Device(0x20, 1, 0x50, 0x70)]);
        Assert.Equal(ProtectedCurrentDmd1CommitDisposition.Applied,
            (await Commit(fixture.Store, 0x81, second)).Disposition);
        Assert.Equal(ProtectedCurrentDmd1CommitDisposition.Stale,
            (await Commit(fixture.Store, 0x82, first)).Disposition);
        Assert.Equal(ProtectedDeviceAgreementDisposition.Stale,
            (await Authorize(fixture.Store, 0x91, first,
                Binding(first, 0x21, 4, 0x51, 0x71))).Disposition);
        Assert.Equal(ProtectedDeviceAgreementDisposition.RevokedOrSuperseded,
            (await Authorize(fixture.Store, 0x92, second,
                Binding(second, 0x21, 4, 0x51, 0x71))).Disposition);
        Assert.Equal(ProtectedDeviceAgreementDisposition.RevokedOrSuperseded,
            (await Authorize(fixture.Store, 0x93, second,
                Binding(second, 0x20, 2, 0x50, 0x70))).Disposition);
        Assert.Equal(ProtectedDeviceAgreementDisposition.RevokedOrSuperseded,
            (await Authorize(fixture.Store, 0x94, second,
                Binding(second, 0x20, 1, 0x52, 0x70))).Disposition);
        Assert.Equal(ProtectedDeviceAgreementDisposition.RevokedOrSuperseded,
            (await Authorize(fixture.Store, 0x95, second,
                Binding(second, 0x20, 1, 0x50, 0x70, networkMarker: 0x19))).Disposition);
        Assert.Equal(ProtectedDeviceAgreementDisposition.RevokedOrSuperseded,
            (await Authorize(fixture.Store, 0x96, second,
                Binding(second, 0x20, 1, 0x50, 0x72))).Disposition);

        var fork = Evidence(2, first.DirectoryHash.Span, [Device(0x20, 1, 0x53, 0x73)]);
        Assert.Equal(ProtectedCurrentDmd1CommitDisposition.ForkLatched,
            (await Commit(fixture.Store, 0x83, fork)).Disposition);
        Assert.Equal(ProtectedDeviceAgreementDisposition.ForkLatched,
            (await Authorize(fixture.Store, 0x97, second,
                Binding(second, 0x20, 1, 0x50, 0x70))).Disposition);

        Assert.All(bindingBytes, static value => Assert.Equal(0, value));
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task SameOperation_IsGrantedOnceUnderConcurrency(
        DeviceStateStoreContractTests.StoreKind kind)
    {
        using var fixture = kind.Open();
        var current = Evidence(1, null, [Device(0x20, 7, 0x50, 0x70)]);
        await Commit(fixture.Store, 0x80, current);
        var binding = Binding(current, 0x20, 7, 0x50, 0x70);

        var attempts = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ =>
            Authorize(fixture.Store, 0x90, current, binding).AsTask()));

        Assert.Single(attempts, static value =>
            value.Disposition == ProtectedDeviceAgreementDisposition.Granted);
        Assert.Equal(23, attempts.Count(static value =>
            value.Disposition == ProtectedDeviceAgreementDisposition.AlreadyConsumed));
        foreach (var token in attempts.Select(static value => value.Authorization).OfType<IDisposable>())
            token.Dispose();
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task LocallyRevokedDevice_RemainsDeniedAfterExactSuccessorBecomesCurrent(
        DeviceStateStoreContractTests.StoreKind kind)
    {
        using var fixture = kind.Open();
        var first = Evidence(1, null, [Device(0x20, 1, 0x50, 0x70), Device(0x21, 4, 0x51, 0x71)]);
        await Commit(fixture.Store, 0x80, first);
        var current = Assert.IsType<DeviceAccountStateSnapshot>((await fixture.Store.ReadAsync(
            DeviceV1Fixture.Account(), 1, CancellationToken.None)).Snapshot);
        var second = Evidence(2, first.DirectoryHash.Span, [Device(0x20, 1, 0x50, 0x70)]);
        var saga = DeviceV1Fixture.Operation(0x89);
        var intent = DeviceV1Fixture.RevokeIntent(
            current.Directory, DeviceV1Fixture.Device(0x21), second.DirectoryFacts);
        var prepared = await fixture.Store.CommitAsync(DeviceTransactionPlan.PrepareRevocation(
            current, DeviceV1Fixture.Operation(0x81), saga, intent), CancellationToken.None);
        var floor = await fixture.Store.CommitAsync(DeviceTransactionPlan.CommitRevocationFloor(
            prepared.Snapshot!, DeviceV1Fixture.Operation(0x82), saga), CancellationToken.None);
        Assert.True(floor.Snapshot!.IsLocallyRevoked(DeviceV1Fixture.Device(0x21)));
        Assert.Equal(ProtectedCurrentDmd1CommitDisposition.Applied,
            (await Commit(fixture.Store, 0x83, second)).Disposition);

        Assert.Equal(ProtectedDeviceAgreementDisposition.RevokedOrSuperseded,
            (await Authorize(fixture.Store, 0x90, second,
                Binding(second, 0x21, 4, 0x51, 0x71))).Disposition);
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task InitiallyForkedVerifiedLineage_LatchesBeforeAnyLeaseAndCannotRecover(
        DeviceStateStoreContractTests.StoreKind kind)
    {
        using var fixture = kind.Open();
        var forked = Evidence(1, null, [Device(0x20, 1, 0x50, 0x70)], forkLatched: true);
        Assert.Equal(ProtectedCurrentDmd1CommitDisposition.ForkLatched,
            (await Commit(fixture.Store, 0x80, forked)).Disposition);
        Assert.Equal(ProtectedDeviceAgreementDisposition.ForkLatched,
            (await Authorize(fixture.Store, 0x90, forked,
                Binding(forked, 0x20, 1, 0x50, 0x70))).Disposition);

        var clean = Evidence(1, null, [Device(0x20, 1, 0x50, 0x70)]);
        Assert.Equal(ProtectedCurrentDmd1CommitDisposition.ForkLatched,
            (await Commit(fixture.Store, 0x81, clean)).Disposition);
    }

    [Fact]
    public async Task SqlCipherRestart_PreservesExactLkgAndOperationBurn_AndRejectsWrongKey()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-protected-dmd1-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "device.db");
        var options = DeviceStateStoreContractTests.StoreFixture.Options(path);
        var current = Evidence(1, null, [Device(0x20, 3, 0x50, 0x70)]);
        var binding = Binding(current, 0x20, 3, 0x50, 0x70);
        try
        {
            using (var store = new SqliteDeviceStateStore(options))
            {
                await Commit(store, 0x80, current);
                var granted = await Authorize(store, 0x90, current, binding);
                Assert.Equal(ProtectedDeviceAgreementDisposition.Granted, granted.Disposition);
                granted.Authorization!.Dispose();
            }

            using (var reopened = new SqliteDeviceStateStore(options))
            {
                Assert.Equal(ProtectedDeviceAgreementDisposition.AlreadyConsumed,
                    (await Authorize(reopened, 0x90, current, binding)).Disposition);
                var next = await Authorize(reopened, 0x91, current, binding);
                Assert.Equal(ProtectedDeviceAgreementDisposition.Granted, next.Disposition);
                next.Authorization!.Dispose();
            }

            var wrongKey = Assert.Throws<DeviceStateStoreOpenException>(() =>
                new SqliteDeviceStateStore(
                    DeviceStateStoreContractTests.StoreFixture.Options(path, keyMarker: 0xE1)));
            Assert.Equal(DeviceStateStoreOpenFailure.UnreadableOrWrongKey, wrongKey.Reason);
        }
        finally
        {
            SqliteDeviceStateStoreTests.DeleteDirectory(directory);
        }
    }

    [Fact]
    public async Task SqlCipherCrashBeforeAuthorizationCommit_DoesNotBurnOperation()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-protected-dmd1-crash-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "device.db");
        var options = DeviceStateStoreContractTests.StoreFixture.Options(path);
        var current = Evidence(1, null, [Device(0x20, 3, 0x50, 0x70)]);
        var binding = Binding(current, 0x20, 3, 0x50, 0x70);
        try
        {
            using (var store = new SqliteDeviceStateStore(options))
            {
                await Commit(store, 0x80, current);
                using var hook = DeviceStateStoreTestHooks.Push(point =>
                {
                    if (point == DeviceStateStoreFailpoint.BeforeAgreementAuthorizationCommit)
                        throw new DeviceStateStoreInjectedCrashException(point);
                });
                await Assert.ThrowsAsync<DeviceStateStoreInjectedCrashException>(() =>
                    Authorize(store, 0x90, current, binding).AsTask());
            }

            using var reopened = new SqliteDeviceStateStore(options);
            var retry = await Authorize(reopened, 0x90, current, binding);
            Assert.Equal(ProtectedDeviceAgreementDisposition.Granted, retry.Disposition);
            retry.Authorization!.Dispose();
        }
        finally
        {
            SqliteDeviceStateStoreTests.DeleteDirectory(directory);
        }
    }

    [Fact]
    public void Authorization_IsOpaqueOneUseAndZeroizesOperationMaterial()
    {
        var current = Evidence(1, null, [Device(0x20, 1, 0x50, 0x70)]);
        var token = new ProtectedDeviceAgreementAuthorization(
            DeviceV1Fixture.Operation(0x90), current,
            Binding(current, 0x20, 1, 0x50, 0x70),
            LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
            DeviceV1Fixture.Bytes(32, 0xA0), DeviceV1Fixture.Bytes(32, 0xB0));
        var operation = Assert.IsType<byte[]>(typeof(ProtectedDeviceAgreementAuthorization)
            .GetField("operationBinding", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(token));
        var peer = Assert.IsType<byte[]>(typeof(ProtectedDeviceAgreementAuthorization)
            .GetField("peerPublicKey", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(token));

        token.Dispose();

        Assert.All(operation, static value => Assert.Equal(0, value));
        Assert.All(peer, static value => Assert.Equal(0, value));
        Assert.Throws<InvalidOperationException>(() => token.ClaimOnce());
        Assert.Empty(typeof(ProtectedDeviceAgreementAuthorization)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(typeof(ProtectedDeviceAgreementAuthorization)
                .GetMethods(BindingFlags.Public | BindingFlags.Instance),
            static method => method.Name.Contains("Agree", StringComparison.OrdinalIgnoreCase) ||
                method.Name.Contains("Export", StringComparison.OrdinalIgnoreCase) ||
                method.Name.Contains("Claim", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PublicStoreBoundary_AcceptsOnlyVerifiedProtocolAuthorities()
    {
        var methods = typeof(IProtectedCurrentDmd1Store).GetMethods();
        var authorize = Assert.Single(methods,
            static method => method.Name == nameof(IProtectedCurrentDmd1Store.AuthorizeDeviceAgreementAsync));
        Assert.Contains(authorize.GetParameters(),
            static parameter => parameter.ParameterType == typeof(Dmd1LineageState));
        Assert.Contains(authorize.GetParameters(),
            static parameter => parameter.ParameterType == typeof(LocalDeviceX25519AgreementAuthority));
        Assert.DoesNotContain(methods.SelectMany(static method => method.GetParameters()),
            static parameter => parameter.ParameterType == typeof(bool) ||
                parameter.ParameterType == typeof(byte[]) ||
                parameter.Name!.Contains("mac", StringComparison.OrdinalIgnoreCase) ||
                parameter.Name.Contains("private", StringComparison.OrdinalIgnoreCase) ||
                parameter.Name.Contains("current", StringComparison.OrdinalIgnoreCase) &&
                    parameter.ParameterType != typeof(Dmd1LineageState));
        Assert.True(typeof(CurrentDmd1Evidence).IsNotPublic);
        Assert.All(typeof(ProtectedDeviceAgreementAuthorization).GetConstructors(),
            static constructor => Assert.False(constructor.IsPublic));
    }

    private static ValueTask<ProtectedCurrentDmd1CommitResult> Commit(
        IDeviceStateStore store,
        byte operation,
        CurrentDmd1Evidence evidence) => store switch
        {
            SqliteDeviceStateStore sqlite => sqlite.CommitCurrentDmd1ForTestingAsync(
                DeviceV1Fixture.Operation(operation), evidence, CancellationToken.None),
            InMemoryDeviceStateStore memory => memory.CommitCurrentDmd1ForTestingAsync(
                DeviceV1Fixture.Operation(operation), evidence, CancellationToken.None),
            _ => throw new NotSupportedException()
        };

    private static ValueTask<ProtectedDeviceAgreementAuthorizationResult> Authorize(
        IDeviceStateStore store,
        byte operation,
        CurrentDmd1Evidence evidence,
        LocalDeviceAgreementBinding binding) => store switch
        {
            SqliteDeviceStateStore sqlite => sqlite.AuthorizeDeviceAgreementForTestingAsync(
                DeviceV1Fixture.Operation(operation), evidence, binding,
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                DeviceV1Fixture.Bytes(32, 0xA0), DeviceV1Fixture.Bytes(32, 0xB0),
                CancellationToken.None),
            InMemoryDeviceStateStore memory => memory.AuthorizeDeviceAgreementForTestingAsync(
                DeviceV1Fixture.Operation(operation), evidence, binding,
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                DeviceV1Fixture.Bytes(32, 0xA0), DeviceV1Fixture.Bytes(32, 0xB0),
                CancellationToken.None),
            _ => throw new NotSupportedException()
        };

    private static LocalDeviceAgreementBinding Binding(
        CurrentDmd1Evidence evidence,
        byte device,
        ulong deviceGeneration,
        byte dpd,
        byte key,
        byte networkMarker = 0x11) =>
        LocalDeviceAgreementBinding.ForTesting(
            DeviceV1Fixture.Bytes(16, networkMarker), evidence.AccountId.Span,
            evidence.AccountGeneration, DeviceV1Fixture.Bytes(32, device),
            deviceGeneration, DeviceV1Fixture.Bytes(32, dpd), DeviceV1Fixture.Bytes(32, key));

    private static CurrentDmd1DeviceEvidence Device(
        byte id,
        ulong generation,
        byte dpd,
        byte key) => new(DeviceV1Fixture.Bytes(32, id), generation,
            DeviceV1Fixture.Bytes(32, dpd), DeviceV1Fixture.Bytes(32, key));

    private static CurrentDmd1Evidence Evidence(
        ulong generation,
        ReadOnlySpan<byte> predecessor,
        IReadOnlyList<CurrentDmd1DeviceEvidence> devices,
        bool forkLatched = false)
    {
        var network = DeviceV1Fixture.Bytes(16, 0x11);
        var account = DeviceV1Fixture.Account().ToArray();
        var drsHash = DeviceV1Fixture.Bytes(32, checked((byte)(0x60 + generation)));
        var dpa = ApplicationCoreCodec.CreateArtifactReference(
            (ushort)ArtifactType.Dpa1, 644, DeviceV1Fixture.Bytes(32, 0x40));
        var drs = ApplicationCoreCodec.CreateArtifactReference(
            (ushort)ArtifactType.Drs1, 356, drsHash);
        var entries = devices.Select(static value => new DeviceDirectoryEntry(
            value.DeviceId.Span,
            ApplicationCoreCodec.CreateArtifactReference(
                (ushort)ArtifactType.Dpd1, 776, value.Dpd1Hash.Span))).ToArray();
        var parsed = ApplicationCoreCodec.AuthorDmd1(
            network, account, 1, dpa, drs, generation,
            predecessor.IsEmpty ? new byte[32] : predecessor,
            entries, 100 + generation, DeviceV1Fixture.Bytes(64, 0x30));
        return CurrentDmd1Evidence.ForTesting(
            forkLatched, parsed.CanonicalBytes.Span, network, account, 1, generation,
            parsed.RecordHash.Span, parsed.PredecessorDmd1Hash.Span, generation,
            drsHash, devices);
    }
}
