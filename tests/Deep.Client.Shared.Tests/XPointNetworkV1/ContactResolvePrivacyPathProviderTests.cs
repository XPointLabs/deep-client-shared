using System.Collections;
using System.Reflection;
using System.Runtime.CompilerServices;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.XPointNetworkV1;

public sealed class ContactResolvePrivacyPathProviderTests
{
    [Fact]
    public async Task RestartAndSameView_KeepPrimaryGuardStable()
    {
        var network = Network(7, [1, 2, 3, 4]);
        var placement = Placement(network, 0x71, [4, 3]);
        var request = Xiq(network, placement, 0x71);
        var store = new InMemoryProtectedEntryGuardStore();

        var first = await Provider(network, placement, store).PrepareAsync(
            OnionOperation.ContactResolve, request, default);
        var persisted = Assert.IsType<EntryGuardState>(await store.ReadAsync(default));
        var second = await Provider(network, placement, store).PrepareAsync(
            OnionOperation.ContactResolve, request, default);
        var afterRestart = Assert.IsType<EntryGuardState>(await store.ReadAsync(default));

        Assert.Equal(first.EntryRouterId.ToArray(), second.EntryRouterId.ToArray());
        Assert.Equal(persisted.PrimaryNodeId.ToArray(), afterRestart.PrimaryNodeId.ToArray());
        Assert.Equal(1UL, afterRestart.Revision);
    }

    [Fact]
    public async Task ViewAdvance_ReplacesRevokedPrimaryButRetainsSalt()
    {
        var oldNetwork = Network(7, [1, 2, 3, 4]);
        var oldPlacement = Placement(oldNetwork, 0x71, [4, 3]);
        var store = new InMemoryProtectedEntryGuardStore();
        await Provider(oldNetwork, oldPlacement, store).PrepareAsync(
            OnionOperation.ContactResolve, Xiq(oldNetwork, oldPlacement, 0x71), default);
        var old = Assert.IsType<EntryGuardState>(await store.ReadAsync(default));

        var revoked = old.PrimaryNodeId.Span[0];
        var survivors = new byte[] { 1, 2, 3, 4 }.Where(marker => marker != revoked).Append((byte)5).ToArray();
        var currentNetwork = Network(8, survivors);
        var currentPlacement = Placement(currentNetwork, 0x72, [survivors[^1], survivors[^2]]);
        await Provider(currentNetwork, currentPlacement, store).PrepareAsync(
            OnionOperation.ContactResolve, Xiq(currentNetwork, currentPlacement, 0x72), default);
        var current = Assert.IsType<EntryGuardState>(await store.ReadAsync(default));

        Assert.Equal(2UL, current.Revision);
        Assert.Equal(8UL, current.ViewGeneration);
        Assert.Equal(old.LocalSalt.ToArray(), current.LocalSalt.ToArray());
        Assert.NotEqual(old.PrimaryNodeId.ToArray(), current.PrimaryNodeId.ToArray());
        Assert.DoesNotContain(current.ConfirmedGuardNodeIds, id => id.Span[0] == revoked);
    }

    [Fact]
    public async Task ExitEqualToOneGuard_UsesAValidDistinctPermutation()
    {
        var network = Network(7, [1, 2, 3]);
        var store = new InMemoryProtectedEntryGuardStore();
        var viewHash = OnionPathCandidateSnapshotFactory.Create(network).ViewHash;
        var state = new EntryGuardState(
            1, network.NetworkId.Span, 7, viewHash.Span, B(32, 0x51), B(32, 1),
            new ReadOnlyMemory<byte>[] { B(32, 1), B(32, 2), B(32, 3) });
        await store.CompareExchangeAsync(null, state, default);
        var placement = Placement(network, 0x71, [1]);

        var attempt = await Provider(network, placement, store).PrepareAsync(
            OnionOperation.ContactResolve, Xiq(network, placement, 0x71), default);

        Assert.NotEqual(B(32, 0x21), attempt.EntryRouterId.ToArray());
    }

    [Fact]
    public async Task CrossPlacementAndInsufficientDiversity_FailClosed()
    {
        var network = Network(7, [1, 2, 3]);
        var placement = Placement(network, 0x71, [3]);
        var cross = Xiq(network, placement, 0x72, placementHashMarker: 0x7F);
        var crossError = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await Provider(network, placement, new InMemoryProtectedEntryGuardStore()).PrepareAsync(
                OnionOperation.ContactResolve, cross, default));
        Assert.Equal("placement-request-mismatch", crossError.Code);

        var tooSmall = Network(7, [1, 2]);
        var smallPlacement = Placement(tooSmall, 0x73, [2]);
        var diversityError = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await Provider(tooSmall, smallPlacement, new InMemoryProtectedEntryGuardStore()).PrepareAsync(
                OnionOperation.ContactResolve, Xiq(tooSmall, smallPlacement, 0x73), default));
        Assert.Equal("path-diversity-insufficient", diversityError.Code);
    }

    [Fact]
    public async Task DuplicateHiddenKeys_FailAtProtocolFactory()
    {
        var network = Network(7, [1, 2, 3], duplicateKey: true);
        var placement = Placement(network, 0x71, [3]);
        var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await Provider(network, placement, new InMemoryProtectedEntryGuardStore()).PrepareAsync(
                OnionOperation.ContactResolve, Xiq(network, placement, 0x71), default));
        Assert.Equal("path-diversity-insufficient", error.Code);
    }

    [Fact]
    public async Task RoleSeparatedNodes_UseTheirOwnCapacityInsteadOfMailboxCapacity()
    {
        var network = Network(7, [1, 2, 3, 4], roleSeparated: true);
        var placement = Placement(network, 0x71, [3, 4]);

        var attempt = await Provider(
                network, placement, new InMemoryProtectedEntryGuardStore())
            .PrepareAsync(
                OnionOperation.ContactResolve,
                Xiq(network, placement, 0x71),
                default);

        Assert.Equal(B(32, 1), attempt.EntryRouterId.ToArray());
    }

    [Fact]
    public async Task Xpk1UsesClaimPreKeyServiceCapabilityPlacement()
    {
        var network = Network(7, [1, 2, 3, 4]);
        var serviceCapability = B(32, 0x74);
        var placement = CreatePlacement(
            network,
            ContactServiceRequestKind.ClaimPreKey,
            ContactServiceClass.PreKeyClaim,
            network.ProtectedLkg!.ViewCoreReference.Slice(6, 32).Span,
            B(32, 0x75),
            serviceCapability,
            7,
            100,
            new[] { B(32, 4), B(32, 3) });
        var exactXpk1 = Xpk1Codec.Encode(
            network.NetworkId.Span,
            B(32, 0x61),
            placement.ViewHash.Span,
            placement.PlacementHash.Span,
            1,
            2,
            serviceCapability,
            B(32, 0x76),
            B(32, 0x77),
            B(32, 0x78),
            B(32, 0x79));

        var attempt = await Provider(
                network, placement, new InMemoryProtectedEntryGuardStore())
            .PrepareAsync(OnionOperation.ContactResolve, exactXpk1, default);

        Assert.Equal(OnionOperation.ContactResolve, attempt.Request.Operation);
        Assert.Equal(exactXpk1, attempt.Request.CanonicalBytes.ToArray());
    }

    private static ContactResolvePrivacyPathProvider Provider(
        VerifiedOnionNetworkContext network,
        VerifiedContactServicePlacement placement,
        IProtectedEntryGuardStore store) => new(
            new Source(network, placement), store, () => B(32, 0x51));

    private static byte[] Xiq(
        VerifiedOnionNetworkContext network,
        VerifiedContactServicePlacement placement,
        byte locatorMarker,
        byte? placementHashMarker = null) => Xiq1Codec.Encode(
            network.NetworkId.Span, B(32, 0x61), placement.ViewHash.Span,
            placementHashMarker.HasValue ? B(32, placementHashMarker.Value) : placement.PlacementHash.Span,
            1, 2, B(32, locatorMarker), 0, Xiq1AntiSpamTokenType.None,
            ReadOnlySpan<byte>.Empty, ContactServicePaddingClass.Bytes4096);

    private static VerifiedContactServicePlacement Placement(
        VerifiedOnionNetworkContext network,
        byte marker,
        byte[] replicas) => CreatePlacement(
            network, ContactServiceRequestKind.ResolveInvite, ContactServiceClass.InviteResolver,
            network.ProtectedLkg!.ViewCoreReference.Slice(6, 32).Span,
            B(32, (byte)(marker + 1)), B(32, marker), 7, 100,
            replicas.Select(value => B(32, value)));

    private static VerifiedOnionNetworkContext Network(
        ulong viewGeneration,
        byte[] nodeMarkers,
        bool duplicateKey = false,
        bool roleSeparated = false)
    {
        var network = CreateNetwork(B(16, 0x11));
        Set(network, "<TrustedTime>k__BackingField", CreateLease(
            TimeProvider.System, TimeSpan.FromMinutes(10), B(32, 0x19)));
        Set(network, "<ProtectedLkg>k__BackingField", new XPointNetworkProtectedLkg(
            B(16, 0x11), Reference("XNH1", 0x31), checked(viewGeneration + 1), B(32, 0x32),
            Reference("XNV1", (byte)(0x70 + viewGeneration)), viewGeneration, Reference("XNA1", 0x33)));
        var closureType = typeof(VerifiedOnionNetworkContext).Assembly.GetType(
            "Deep.Protocol.XPointNetworkV1.VerifiedOnionNetworkClosure", throwOnError: true)!;
        Set(network, "<Closure>k__BackingField", RuntimeHelpers.GetUninitializedObject(closureType));

        var nodeType = typeof(VerifiedOnionNetworkContext).Assembly.GetType(
            "Deep.Protocol.DeepExtension.PrivacyRouting.VerifiedNetworkNode", throwOnError: true)!;
        var dictionary = (IDictionary)typeof(VerifiedOnionNetworkContext)
            .GetField("_nodes", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(network)!;
        for (var index = 0; index < nodeMarkers.Length; index++)
        {
            var marker = nodeMarkers[index];
            var roleMask = roleSeparated
                ? index switch { 0 => (ushort)0x0001, 1 => (ushort)0x0002, _ => (ushort)0x0004 }
                : (ushort)0x0007;
            var node = Activator.CreateInstance(
                nodeType,
                BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public,
                binder: null,
                args:
                [
                    B(32, marker), B(32, (byte)(marker + 0x20)), B(32, (byte)(marker + 0x40)),
                    B(32, (byte)(marker + 0x60)), B(32, (byte)(marker + 0x70)),
                    (byte)1, (byte)4, new byte[] { 127, 0, 0, marker }, (ushort)(4400 + marker),
                    B(32, (byte)(marker + 0x50)), roleMask,
                    (roleMask & 0x0001) != 0 ? 65_536U : 0U,
                    (roleMask & 0x0002) != 0 ? 65_536UL : 0UL,
                    (roleMask & 0x0004) != 0 ? 65_536UL : 0UL,
                    1UL,
                    B(32, duplicateKey ? (byte)0x55 : (byte)(marker + 0x10)),
                    B(32, (byte)(marker + 0x30)), B(32, (byte)(marker + 0x50))
                ],
                culture: null)!;
            dictionary.Add(Convert.ToHexString(B(32, marker)), node);
        }
        return network;
    }

    private static void Set(object target, string field, object value) =>
        target.GetType().GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(target, value);

    private static byte[] Reference(string magic, byte marker)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        value[5] = 1;
        value.AsSpan(6).Fill(marker);
        return value;
    }

    private static byte[] B(int length, byte marker) => Enumerable.Repeat(marker, length).ToArray();

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedOnionNetworkContext CreateNetwork(ReadOnlySpan<byte> networkId);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern OnionTrustedTimeLease CreateLease(
        TimeProvider timeProvider,
        TimeSpan lifetime,
        ReadOnlySpan<byte> bootId);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedContactServicePlacement CreatePlacement(
        VerifiedOnionNetworkContext network,
        ContactServiceRequestKind requestKind,
        ContactServiceClass serviceClass,
        ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash,
        ReadOnlySpan<byte> shardKey,
        ulong selectionEpoch,
        ulong validUntilUnixSeconds,
        IEnumerable<byte[]> rankedReplicaNodeIds);

    private sealed class Source(
        VerifiedOnionNetworkContext network,
        VerifiedContactServicePlacement placement) : IContactResolvePathAuthoritySource
    {
        public ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
            Xiq1Request request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new ContactResolvePathAuthority(network, placement));

        public ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
            ContactResolveCanonicalPathRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new ContactResolvePathAuthority(network, placement));
    }
}
