using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Domain.AccountDirectoryV1;
using Deep.Client.Shared.Persistence.AccountDirectoryV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services.AccountDirectoryV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.XPointNetworkV1;

public sealed class ProductionContactResolvePathAuthoritySourceTests
{
    [Fact]
    public async Task CanonicalSource_DerivesExactPlacementAndCommitsProtectedLkg()
    {
        var network = Network(0);
        var request = Request(network, locator: 0x61);
        var directory = await ReadyDirectoryAsync();
        var networkStore = new InMemoryXPointNetworkStateStore();
        var fetch = new ArtifactSource(Artifacts());
        var source = Source(network, fetch, directory, networkStore);

        var authority = await source.GetCurrentAsync(request, default);

        Assert.Same(network, authority.Network);
        Assert.Same(network, authority.Placement.Network);
        Assert.True(authority.Placement.Binds(ContactServiceRequestKind.ResolveInvite, request.LocatorHash));
        Assert.Equal(request.ViewHash.ToArray(), authority.Placement.ViewHash.ToArray());
        Assert.Equal(request.PlacementHash.ToArray(), authority.Placement.PlacementHash.ToArray());
        Assert.Equal(1, fetch.Calls);
        Assert.Equal(B(16, 0x11), fetch.Contexts[0].ExpectedNetworkId.ToArray());
        Assert.Null(fetch.Contexts[0].ProtectedNetworkLkg);
        var persisted = Assert.IsType<XPointNetworkStateSnapshot>(await networkStore.ReadAsync(default));
        Assert.Equal(0UL, persisted.ProtectedLkg.ViewGeneration);
        Assert.False(persisted.ForkLatched);
    }

    [Fact]
    public async Task LiveVerifiedSuccessor_AdvancesProtectedLkgWithoutCallerAuthority()
    {
        var first = Network(0);
        var successor = Network(1, prior: first.ProtectedLkg);
        var verifier = new SequenceVerifier(first, successor);
        var directory = await ReadyDirectoryAsync();
        var networkStore = new InMemoryXPointNetworkStateStore();
        var fetch = new ArtifactSource(Artifacts());
        var source = new ProductionContactResolvePathAuthoritySource(
            Pin(), fetch, directory, networkStore, verifier);

        await source.GetCurrentAsync(Request(first, 0x61), default);
        await source.GetCurrentAsync(Request(successor, 0x61), default);

        Assert.Null(verifier.PreviousArguments[0]);
        Assert.Same(first, verifier.PreviousArguments[1]);
        Assert.Null(fetch.Contexts[0].ProtectedNetworkLkg);
        Assert.Equal(0UL, fetch.Contexts[1].ProtectedNetworkLkg!.ViewGeneration);
        var persisted = Assert.IsType<XPointNetworkStateSnapshot>(await networkStore.ReadAsync(default));
        Assert.Equal(1UL, persisted.ProtectedLkg.ViewGeneration);
        Assert.Equal(2UL, persisted.Revision);
    }

    [Fact]
    public async Task FreshPermanentDid_MintsPlacementContextBeforeAnyXiq1Exists()
    {
        var scope = ContactStoreScope.ForCurrentAccount(CreateAccountId(B(32, 0x22)));
        var contactStore = new InMemoryContactStateStore(scope);
        var did = ApplicationCoreCodec.AuthorDid1(B(32, 0x23), B(16, 0x24));
        var pending = (await new ContactAddressImportService(contactStore, B(16, 0x11))
            .ImportAsync(did.Text)).PendingAddress;
        var network = Network(0);
        var fetch = new ArtifactSource(Artifacts());
        var source = Source(network, fetch, await ReadyDirectoryAsync(), new InMemoryXPointNetworkStateStore());

        var context = await source.MintPlacementContextAsync(scope, pending, default);

        var locator = ContactCodecHash.OneTimeOrPermanentLocator(pending.Address);
        var exactXiq1 = Xiq1Codec.Encode(
            pending.Address.NetworkId.Span,
            B(32, 0x25),
            context.ViewHashSpan,
            context.PlacementHashSpan,
            1_900_000_000,
            1_900_000_060,
            locator,
            0,
            Xiq1AntiSpamTokenType.None,
            ReadOnlySpan<byte>.Empty,
            ContactServicePaddingClass.Bytes4096);
        var transportAuthority = await source.GetCurrentAsync(
            Xiq1Codec.Decode(exactXiq1), default);

        Assert.Equal(ContactAddressKind.PermanentDeepId, context.PendingAddress.Address.Kind);
        Assert.Same(scope, context.Scope);
        Assert.Equal(pending.Address.CanonicalBytes.ToArray(), context.PendingAddress.Address.CanonicalBytes.ToArray());
        Assert.Equal(network.ProtectedLkg!.ViewCoreReference.Slice(6, 32).ToArray(), context.ViewHashSpan.ToArray());
        Assert.Same(network, transportAuthority.Network);
        Assert.Equal(context.PlacementHashSpan.ToArray(), transportAuthority.Placement.PlacementHash.ToArray());
        Assert.Equal(2, fetch.Calls);
        CryptographicOperations.ZeroMemory(locator);
    }

    [Fact]
    public void PublicConstruction_HasNoVerifiedCapabilityInjectionSeam()
    {
        var constructor = Assert.Single(typeof(ProductionContactResolvePathAuthoritySource)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));

        Assert.DoesNotContain(constructor.GetParameters(), parameter =>
            parameter.ParameterType == typeof(VerifiedOnionNetworkContext)
            || parameter.ParameterType == typeof(VerifiedContactServicePlacement)
            || parameter.ParameterType == typeof(ICanonicalContactResolveAuthorityVerifier));
    }

    [Fact]
    public async Task WrongNetwork_IsRejectedBeforeDirectoryFetch()
    {
        var network = Network(0, networkMarker: 0x12);
        var fetch = new ArtifactSource(Artifacts());
        var source = Source(network, fetch, await ReadyDirectoryAsync(), new InMemoryXPointNetworkStateStore(),
            pinNetworkMarker: 0x11);

        var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await source.GetCurrentAsync(Request(network, 0x61), default));

        Assert.Equal("request-network-mismatch", error.Code);
        Assert.Equal(0, fetch.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task WrongViewOrPlacement_FailsBeforeTransportAuthorityReturn(bool wrongView)
    {
        var network = Network(0);
        var valid = Request(network, 0x61);
        var exact = Xiq1Codec.Encode(
            valid.NetworkId.Span,
            valid.OperationId.Span,
            wrongView ? B(32, 0x7a) : valid.ViewHash.Span,
            wrongView ? valid.PlacementHash.Span : B(32, 0x7b),
            valid.IssuedAtUnixSeconds,
            valid.ExpiresAtUnixSeconds,
            valid.LocatorHash.Span,
            valid.RequestedGeneration,
            valid.AntiSpamTokenType,
            ReadOnlySpan<byte>.Empty,
            valid.ResponsePaddingClass);
        var networkStore = new InMemoryXPointNetworkStateStore();
        var source = Source(network, new ArtifactSource(Artifacts()), await ReadyDirectoryAsync(), networkStore);

        var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await source.GetCurrentAsync(Xiq1Codec.Decode(exact), default));

        Assert.Equal("request-placement-mismatch", error.Code);
        var protectedState = Assert.IsType<XPointNetworkStateSnapshot>(await networkStore.ReadAsync(default));
        Assert.Equal(0UL, protectedState.ProtectedLkg.ViewGeneration);
    }

    [Fact]
    public async Task StaleVerifiedContext_IsRejectedAgainstProtectedLkg()
    {
        var protectedNetwork = Network(1);
        var stale = Network(0);
        var networkStore = new InMemoryXPointNetworkStateStore();
        await networkStore.CompareExchangeAsync(null,
            new XPointNetworkStateSnapshot(1, protectedNetwork.ProtectedLkg!, false), default);
        var source = Source(stale, new ArtifactSource(Artifacts()), await ReadyDirectoryAsync(), networkStore);

        var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await source.GetCurrentAsync(Request(stale, 0x61), default));

        Assert.Equal("network-rollback", error.Code);
        var persisted = Assert.IsType<XPointNetworkStateSnapshot>(await networkStore.ReadAsync(default));
        Assert.Equal(1UL, persisted.ProtectedLkg.ViewGeneration);
    }

    [Fact]
    public async Task ProtectedNetworkForkLatch_RejectsBeforeFetch()
    {
        var network = Network(0);
        var store = new InMemoryXPointNetworkStateStore();
        await store.CompareExchangeAsync(null,
            new XPointNetworkStateSnapshot(1, network.ProtectedLkg!, true), default);
        var fetch = new ArtifactSource(Artifacts());
        var source = Source(network, fetch, await ReadyDirectoryAsync(), store);

        var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await source.GetCurrentAsync(Request(network, 0x61), default));

        Assert.Equal("network-fork-latched", error.Code);
        Assert.Equal(0, fetch.Calls);
    }

    [Fact]
    public async Task ExactSignedSuccessorFork_IsPersistentlyLatched()
    {
        var network = Network(0);
        var store = new InMemoryXPointNetworkStateStore();
        await store.CompareExchangeAsync(null,
            new XPointNetworkStateSnapshot(1, network.ProtectedLkg!, false), default);
        var source = new ProductionContactResolvePathAuthoritySource(
            Pin(), new ArtifactSource(Artifacts()), await ReadyDirectoryAsync(), store,
            new ThrowingVerifier(CreateOnionException(
                "network-fork", "conflicting signed successor", null)));

        var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await source.GetCurrentAsync(Request(network, 0x61), default));

        Assert.Equal("network-fork-latched", error.Code);
        var persisted = Assert.IsType<XPointNetworkStateSnapshot>(await store.ReadAsync(default));
        Assert.True(persisted.ForkLatched);
        Assert.Equal(2UL, persisted.Revision);
    }

    [Fact]
    public async Task ProtectedDirectoryForkLatch_RejectsBeforeFetch()
    {
        var network = Network(0);
        var directory = new InMemoryAccountDirectoryStateStore();
        await directory.CompareExchangeAsync(null,
            new AccountDirectoryStateSnapshot(1, null, true, []), default);
        var fetch = new ArtifactSource(Artifacts());
        var source = Source(network, fetch, directory, new InMemoryXPointNetworkStateStore());

        var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await source.GetCurrentAsync(Request(network, 0x61), default));

        Assert.Equal("directory-fork-latched", error.Code);
        Assert.Equal(0, fetch.Calls);
    }

    [Fact]
    public async Task OneTimeClaimPath_ForwardsExactLookupAndSelectsCurrentValueVerifier()
    {
        var network = Network(0);
        var request = Request(network, 0x61);
        var fetch = new ArtifactSource(Artifacts());
        var verifier = new ClaimRecordingVerifier();
        var source = new ProductionContactResolvePathAuthoritySource(
            Pin(), fetch, await ReadyDirectoryAsync(), new InMemoryXPointNetworkStateStore(), verifier);
        var lookup = B(32, 0x6a);

        var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await ((IContactResolveClaimPathAuthoritySource)source)
                .GetCurrentForOneTimeClaimAsync(request, lookup, default));

        Assert.Equal("claim-verifier-observed", error.Code);
        Assert.Equal(1, verifier.ClaimCalls);
        Assert.Equal(0, verifier.PlacementCalls);
        Assert.Equal(lookup, Assert.Single(fetch.Contexts).RequiredDirectoryLookupKey.ToArray());
    }

    [Fact]
    public async Task PermanentPath_DerivesExactDidLeafAndSelectsCurrentValueVerifier()
    {
        var network = Network(0);
        var did = ApplicationCoreCodec.AuthorDid1(B(32, 0x63), B(16, 0x64));
        var locator = ContactCodecHash.OneTimeOrPermanentLocator(
            new ImportedContactAddress(
                ContactAddressKind.PermanentDeepId,
                B(16, 0x11),
                did.CanonicalBytes.Span,
                did.Text,
                expiresAtUnixSeconds: null));
        try
        {
            var request = Request(network, locator[0]);
            var requestBytes = Xiq1Codec.Encode(
                request.NetworkId.Span,
                request.OperationId.Span,
                request.ViewHash.Span,
                request.PlacementHash.Span,
                request.IssuedAtUnixSeconds,
                request.ExpiresAtUnixSeconds,
                locator,
                request.RequestedGeneration,
                request.AntiSpamTokenType,
                request.AntiSpamToken.Span,
                request.ResponsePaddingClass);
            request = Xiq1Codec.Decode(requestBytes);
            var fetch = new ArtifactSource(Artifacts());
            var verifier = new ClaimRecordingVerifier();
            var source = new ProductionContactResolvePathAuthoritySource(
                Pin(), fetch, await ReadyDirectoryAsync(),
                new InMemoryXPointNetworkStateStore(), verifier);

            var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
                await ((IContactResolvePermanentPathAuthoritySource)source)
                    .GetCurrentForPermanentResolveAsync(request, did, default));

            Assert.Equal("claim-verifier-observed", error.Code);
            Assert.Equal(1, verifier.ClaimCalls);
            Assert.Equal(0, verifier.PlacementCalls);
            Assert.Equal(
                PermanentDirectoryLeaf(B(16, 0x11), did.CanonicalBytes.Span),
                Assert.Single(fetch.Contexts).RequiredDirectoryLookupKey.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(locator);
        }
    }

    [Fact]
    public async Task PersistedLkgWithoutLivePredecessorOrForwardCheckpoint_FailsClosedPrecisely()
    {
        var directory = await ReadyDirectoryAsync();
        var verifier = new ProtocolCanonicalContactResolveAuthorityVerifier(
            new AccountDirectoryClient(directory),
            new OnionTrustedTimeAuthority(new FixedClock()),
            supportedDirectoryReader: 1);
        var protectedNetwork = Network(3);
        var state = new XPointNetworkStateSnapshot(1, protectedNetwork.ProtectedLkg!, false);

        var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await verifier.VerifyAsync(Pin(), Artifacts(), state, null, default));

        Assert.Equal("network-predecessor-capability-unavailable", error.Code);
    }

    [Fact]
    public void ArtifactPackage_IsBoundedAndDefensivelyCopied()
    {
        var mutable = new byte[] { 0x21 };
        var package = Artifacts(mutable);
        mutable[0] = 0x00;
        var escaped = package.ExactOrderedXnv1Chain[0].ToArray();
        escaped[0] = 0x00;

        Assert.Equal(0x21, package.ExactOrderedXnv1Chain[0].Span[0]);
        Assert.Throws<ArgumentException>(() => Artifacts(
            Enumerable.Range(0, ContactResolveDirectoryArtifacts.MaximumChainArtifacts + 1)
                .Select(_ => (ReadOnlyMemory<byte>)new byte[] { 1 }).ToArray()));
        Assert.Throws<ArgumentException>(() => new ContactResolveDirectoryArtifacts(
            [new byte[] { 1 }],
            [new byte[] { 1 }, new byte[] { 2 }],
            new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 },
            B(32, 1), B(32, 2), Window(),
            [new byte[] { 1 }], [new byte[] { 1 }], [new byte[] { 1 }],
            [new byte[] { 1 }], [new byte[] { 1 }]));
    }

    private static ProductionContactResolvePathAuthoritySource Source(
        VerifiedOnionNetworkContext network,
        ArtifactSource artifacts,
        IAccountDirectoryStateStore directory,
        IXPointNetworkStateStore networkStore,
        byte pinNetworkMarker = 0x11) => new(
            Pin(pinNetworkMarker), artifacts, directory, networkStore,
            new FixedVerifier(network));

    private static async Task<InMemoryAccountDirectoryStateStore> ReadyDirectoryAsync()
    {
        var store = new InMemoryAccountDirectoryStateStore();
        await store.CompareExchangeAsync(null,
            new AccountDirectoryStateSnapshot(1, null, false, []), default);
        return store;
    }

    private static ContactResolveDirectoryArtifacts Artifacts(
        byte[]? xnv = null) => new(
            [new byte[] { 1 }], [new byte[] { 2 }],
            new byte[] { 3 }, new byte[] { 4 }, new byte[] { 5 },
            B(32, 6), B(32, 7), Window(),
            [new byte[] { 8 }], [xnv ?? new byte[] { 9 }], [new byte[] { 10 }],
            [new byte[] { 11 }], [new byte[] { 12 }]);

    private static ContactResolveDirectoryArtifacts Artifacts(
        IReadOnlyList<ReadOnlyMemory<byte>> xnv) => new(
            [new byte[] { 1 }], [new byte[] { 2 }],
            new byte[] { 3 }, new byte[] { 4 }, new byte[] { 5 },
            B(32, 6), B(32, 7), Window(),
            [new byte[] { 8 }], xnv,
            Enumerable.Range(0, xnv.Count).Select(_ => (ReadOnlyMemory<byte>)new byte[] { 10 }).ToArray(),
            [new byte[] { 11 }], [new byte[] { 12 }]);

    private static AccountDirectoryMonotonicRequestWindow Window() => new(B(16, 0x31), 1, 2, 3);

    private static XPointNetworkGenesisPin Pin(byte networkMarker = 0x11) =>
        new(B(16, networkMarker), B(32, 0x41));

    private static Xiq1Request Request(VerifiedOnionNetworkContext network, byte locator)
    {
        var placement = ContactServicePlacementFactory.Create(
            network, ContactServiceRequestKind.ResolveInvite, B(32, locator));
        return Xiq1Codec.Decode(Xiq1Codec.Encode(
            network.NetworkId.Span, B(32, 0x51), placement.ViewHash.Span,
            placement.PlacementHash.Span, 10, 100, B(32, locator), 0,
            Xiq1AntiSpamTokenType.None, ReadOnlySpan<byte>.Empty,
            ContactServicePaddingClass.Bytes4096));
    }

    private static VerifiedOnionNetworkContext Network(
        ulong generation,
        byte networkMarker = 0x11,
        XPointNetworkProtectedLkg? prior = null)
    {
        var networkId = B(16, networkMarker);
        var context = CreateNetwork(networkId);
        Set(context, "<TrustedTime>k__BackingField", CreateLease(
            TimeProvider.System, TimeSpan.FromMinutes(10), B(32, 0x19)));
        var lkg = new XPointNetworkProtectedLkg(
            networkId,
            Reference("XNH1", (byte)(0x20 + generation)),
            checked(generation + 1),
            B(32, (byte)(0x30 + generation)),
            Reference("XNV1", (byte)(0x40 + generation)),
            generation,
            Reference("XNA1", 0x50));
        Set(context, "<ProtectedLkg>k__BackingField", lkg);
        if (prior is not null)
            Set(context, "<PriorProtectedLkg>k__BackingField", prior);

        var closureType = typeof(VerifiedOnionNetworkContext).Assembly.GetType(
            "Deep.Protocol.XPointNetworkV1.VerifiedOnionNetworkClosure", throwOnError: true)!;
        var closure = RuntimeHelpers.GetUninitializedObject(closureType);
        Set(closure, "<NetworkId>k__BackingField", networkId);
        Set(closure, "<ViewCoreHash>k__BackingField", lkg.ViewCoreReference.Slice(6, 32).ToArray());
        Set(closure, "<ViewCoreReference>k__BackingField", lkg.ViewCoreReference.ToArray());
        Set(closure, "<PmtArtifactReference>k__BackingField", Reference("PMT2", 0x61));
        Set(closure, "<PmtNodeIds>k__BackingField", new[] { B(32, 0x71), B(32, 0x72) });
        Set(closure, "<SelectionEpoch>k__BackingField", 7UL);
        Set(closure, "<ReplicaCount>k__BackingField", (byte)2);
        Set(closure, "<HardUpperUnixSeconds>k__BackingField", 2_000_000_000UL);
        Set(context, "<Closure>k__BackingField", closure);
        return context;
    }

    private static void Set(object target, string field, object? value) =>
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

    private static byte[] PermanentDirectoryLeaf(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> exactDid1)
    {
        var preimage = new byte[networkId.Length + exactDid1.Length];
        networkId.CopyTo(preimage);
        exactDid1.CopyTo(preimage.AsSpan(networkId.Length));
        var lookup = DomainHash("Deep/AccountDirectory/V1/lookup", preimage);
        try
        {
            return DomainHash("Deep/AccountDirectory/V1/leaf", lookup);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preimage);
            CryptographicOperations.ZeroMemory(lookup);
        }
    }

    private static byte[] DomainHash(string domain, ReadOnlySpan<byte> payload)
    {
        var label = System.Text.Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[label.Length + 5 + payload.Length];
        label.CopyTo(preimage, 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
            preimage.AsSpan(label.Length + 1), checked((uint)payload.Length));
        payload.CopyTo(preimage.AsSpan(label.Length + 5));
        return SHA256.HashData(preimage);
    }

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedOnionNetworkContext CreateNetwork(ReadOnlySpan<byte> networkId);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern DeepAccountId32 CreateAccountId(ReadOnlySpan<byte> value);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern OnionTrustedTimeLease CreateLease(
        TimeProvider timeProvider,
        TimeSpan lifetime,
        ReadOnlySpan<byte> bootId);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern OnionBoundaryException CreateOnionException(
        string code,
        string message,
        Exception? inner);

    private sealed class ArtifactSource(ContactResolveDirectoryArtifacts package)
        : IContactResolveDirectoryArtifactSource
    {
        public int Calls { get; private set; }
        public List<ContactResolveDirectoryFetchContext> Contexts { get; } = [];

        public ValueTask<ContactResolveDirectoryArtifacts> FetchCurrentAsync(
            ContactResolveDirectoryFetchContext context,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            Contexts.Add(context);
            return ValueTask.FromResult(package);
        }
    }

    private sealed class FixedVerifier(VerifiedOnionNetworkContext network)
        : ICanonicalContactResolveAuthorityVerifier
    {
        public ValueTask<VerifiedOnionNetworkContext> VerifyAsync(
            XPointNetworkGenesisPin genesisPin,
            ContactResolveDirectoryArtifacts artifacts,
            XPointNetworkStateSnapshot? protectedNetworkState,
            VerifiedOnionNetworkContext? livePrevious,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(network);
        }
    }

    private sealed class ThrowingVerifier(Exception exception)
        : ICanonicalContactResolveAuthorityVerifier
    {
        public ValueTask<VerifiedOnionNetworkContext> VerifyAsync(
            XPointNetworkGenesisPin genesisPin,
            ContactResolveDirectoryArtifacts artifacts,
            XPointNetworkStateSnapshot? protectedNetworkState,
            VerifiedOnionNetworkContext? livePrevious,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<VerifiedOnionNetworkContext>(exception);
    }

    private sealed class SequenceVerifier(params VerifiedOnionNetworkContext[] values)
        : ICanonicalContactResolveAuthorityVerifier
    {
        private int index;
        public List<VerifiedOnionNetworkContext?> PreviousArguments { get; } = [];

        public ValueTask<VerifiedOnionNetworkContext> VerifyAsync(
            XPointNetworkGenesisPin genesisPin,
            ContactResolveDirectoryArtifacts artifacts,
            XPointNetworkStateSnapshot? protectedNetworkState,
            VerifiedOnionNetworkContext? livePrevious,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PreviousArguments.Add(livePrevious);
            return ValueTask.FromResult(values[index++]);
        }
    }

    private sealed class ClaimRecordingVerifier : ICanonicalContactResolveAuthorityVerifier
    {
        public int PlacementCalls { get; private set; }
        public int ClaimCalls { get; private set; }

        public ValueTask<VerifiedOnionNetworkContext> VerifyAsync(
            XPointNetworkGenesisPin genesisPin,
            ContactResolveDirectoryArtifacts artifacts,
            XPointNetworkStateSnapshot? protectedNetworkState,
            VerifiedOnionNetworkContext? livePrevious,
            CancellationToken cancellationToken)
        {
            PlacementCalls++;
            return ValueTask.FromException<VerifiedOnionNetworkContext>(
                new Xunit.Sdk.XunitException("The one-time path selected the placement-only verifier."));
        }

        public ValueTask<CanonicalContactResolveAuthority> VerifyCurrentValueAsync(
            XPointNetworkGenesisPin genesisPin,
            ContactResolveDirectoryArtifacts artifacts,
            XPointNetworkStateSnapshot? protectedNetworkState,
            VerifiedOnionNetworkContext? livePrevious,
            CancellationToken cancellationToken)
        {
            ClaimCalls++;
            return ValueTask.FromException<CanonicalContactResolveAuthority>(
                new ContactResolvePathException("claim-verifier-observed", "expected test stop"));
        }
    }

    private sealed class FixedClock : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(new OnionMonotonicReading(B(16, 0x31), 3));
    }
}
