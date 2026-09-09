using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class PermanentContactResolverCapabilitySourceTests
{
    [Fact]
    public async Task ExactPermanentResult_ComposesOneCapabilitySetWithoutClaimReceipt()
    {
        var fixture = await Fixture.CreateAsync();
        var verifier = new RecordingPermanentVerifier();
        var source = new ProductionContactResolverVerifiedCapabilitySource(fixture.Path, verifier);

        var result = await source.VerifyAsync(fixture.Input);

        Assert.Same(verifier.Bundle, result.Bundle);
        Assert.Same(verifier.Route, result.Route);
        Assert.Same(fixture.Placement, result.Placement);
        Assert.Null(result.ClaimReceipt);
        Assert.Equal(1, fixture.Path.PermanentCalls);
        Assert.Equal(0, fixture.Path.PlacementOnlyCalls);
        Assert.Equal(1, verifier.Calls);
        Assert.Equal(fixture.Input.Address.CanonicalBytes.ToArray(),
            verifier.LastDid!.CanonicalBytes.ToArray());
        Assert.Same(fixture.Path.Authority, verifier.LastPath);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task WrongNetworkOrLocator_FailsBeforePermanentAuthority(
        bool wrongNetwork)
    {
        var fixture = await Fixture.CreateAsync();
        var request = fixture.Input.Request;
        var changedRequest = Xiq1Codec.Decode(Xiq1Codec.Encode(
            wrongNetwork ? Bytes(16, 0x91) : request.NetworkId.Span,
            request.OperationId.Span,
            request.ViewHash.Span,
            request.PlacementHash.Span,
            request.IssuedAtUnixSeconds,
            request.ExpiresAtUnixSeconds,
            wrongNetwork ? request.LocatorHash.Span : Bytes(32, 0x92),
            request.RequestedGeneration,
            request.AntiSpamTokenType,
            request.AntiSpamToken.Span,
            request.ResponsePaddingClass));
        var changedInput = new ContactResolverVerificationInput(
            fixture.Input.Address, changedRequest, fixture.Input.Result);
        var verifier = new RecordingPermanentVerifier();
        var source = new ProductionContactResolverVerifiedCapabilitySource(fixture.Path, verifier);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.VerifyAsync(changedInput));

        Assert.Equal(0, fixture.Path.PermanentCalls);
        Assert.Equal(0, verifier.Calls);
    }

    [Theory]
    [InlineData("permanent replica signature rejected")]
    [InlineData("permanent directory freshness stale")]
    public async Task SignatureOrStaleProtocolFailure_FailsClosed(string message)
    {
        var fixture = await Fixture.CreateAsync();
        var verifier = new RecordingPermanentVerifier(new CryptographicException(message));
        var source = new ProductionContactResolverVerifiedCapabilitySource(fixture.Path, verifier);

        var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.VerifyAsync(fixture.Input));

        Assert.Equal(message, error.Message);
        Assert.Equal(1, fixture.Path.PermanentCalls);
        Assert.Equal(1, verifier.Calls);
    }

    [Fact]
    public async Task ProtectedForkFromCurrentPath_FailsBeforeProtocolVerification()
    {
        var fixture = await Fixture.CreateAsync();
        fixture.Path.Failure = new ContactResolvePathException(
            "directory-fork-latched", "protected directory fork");
        var verifier = new RecordingPermanentVerifier();
        var source = new ProductionContactResolverVerifiedCapabilitySource(fixture.Path, verifier);

        var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
            await source.VerifyAsync(fixture.Input));

        Assert.Equal("directory-fork-latched", error.Code);
        Assert.Equal(1, fixture.Path.PermanentCalls);
        Assert.Equal(0, verifier.Calls);
    }

    [Fact]
    public async Task IndependentlyVerifiedRouteFailure_DoesNotReturnIdentityOnlySet()
    {
        var fixture = await Fixture.CreateAsync();
        var verifier = new RecordingPermanentVerifier(
            new CryptographicException("independent route closure rejected"));
        var source = new ProductionContactResolverVerifiedCapabilitySource(fixture.Path, verifier);

        var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.VerifyAsync(fixture.Input));

        Assert.Equal("independent route closure rejected", error.Message);
        Assert.Equal(1, verifier.Calls);
    }

    [Fact]
    public async Task CancellationStopsBeforePathAndProtocolCapabilities()
    {
        var fixture = await Fixture.CreateAsync();
        var verifier = new RecordingPermanentVerifier();
        var source = new ProductionContactResolverVerifiedCapabilitySource(fixture.Path, verifier);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await source.VerifyAsync(fixture.Input, cancellation.Token));

        Assert.Equal(0, fixture.Path.PermanentCalls);
        Assert.Equal(0, verifier.Calls);
    }

    [Fact]
    public void PublicSurfaceHasNoPermanentVerifierKeyBooleanOrCapabilityInjection()
    {
        var constructor = Assert.Single(typeof(ProductionContactResolverVerifiedCapabilitySource)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Equal(typeof(IContactResolvePathAuthoritySource),
            Assert.Single(constructor.GetParameters()).ParameterType);
        Assert.False(typeof(IPermanentContactResolverCapabilityVerifier).IsPublic);
        Assert.Empty(typeof(PermanentContactResolverCapabilities)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(VerifiedPermanentContactResolveClosure).GetConstructors());
        Assert.DoesNotContain(typeof(ProductionContactResolverVerifiedCapabilitySource)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .SelectMany(static method => method.GetParameters()), static parameter =>
                parameter.ParameterType == typeof(bool)
                || parameter.Name?.Contains("key", StringComparison.OrdinalIgnoreCase) == true
                || parameter.Name?.Contains("receipt", StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public async Task PublicProductionConstructorUsesTheProtocolPermanentVerifierAdapter()
    {
        var fixture = await Fixture.CreateAsync();
        var source = new ProductionContactResolverVerifiedCapabilitySource(fixture.Path);
        var field = typeof(ProductionContactResolverVerifiedCapabilitySource).GetField(
            "permanentVerifier", BindingFlags.Instance | BindingFlags.NonPublic);

        Assert.NotNull(field);
        Assert.Same(ProtocolPermanentContactResolverCapabilityVerifier.Instance,
            field.GetValue(source));
        Assert.Empty(typeof(ProtocolPermanentContactResolverCapabilityVerifier)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    private sealed class Fixture
    {
        private Fixture()
        {
        }

        internal ContactResolverVerificationInput Input { get; private init; } = null!;
        internal RecordingPermanentPath Path { get; private init; } = null!;
        internal VerifiedContactServicePlacement Placement { get; private init; } = null!;

        internal static async Task<Fixture> CreateAsync()
        {
            var addressNetwork = Bytes(16, 0x11);
            var network = LiveNetwork(addressNetwork);
            var did = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x81), Bytes(16, 0x82));
            var store = new InMemoryContactStateStore(
                ContactResolverClientOrchestrationTests.Scope());
            var address = (await new ContactAddressImportService(store, addressNetwork)
                .ImportAsync(did.Text)).PendingAddress.Address;
            var locator = ContactCodecHash.OneTimeOrPermanentLocator(address);
            try
            {
                var placement = ContactServicePlacementFactory.Create(
                    network, ContactServiceRequestKind.ResolveInvite, locator);
                var requestBytes = Xiq1Codec.Encode(
                    addressNetwork,
                    Bytes(32, 0x83),
                    placement.ViewHash.Span,
                    placement.PlacementHash.Span,
                    10,
                    100,
                    locator,
                    0,
                    Xiq1AntiSpamTokenType.None,
                    ReadOnlySpan<byte>.Empty,
                    ContactServicePaddingClass.Bytes16384);
                var request = Xiq1Codec.Decode(requestBytes);
                var route = ContactResolverClientOrchestrationTests.RouteClosure();
                var protectedObject = Bytes(40, 0x88);
                var receipts = PermanentReceipts();
                var resultBytes = Xis1Codec.Encode(
                    requestBytes,
                    Xis1Status.Success,
                    ContactServiceMutationOutcome.None,
                    50,
                    0,
                    ContactServicePaddingClass.Bytes16384,
                    [U64(0), U64(190), SHA256.HashData(protectedObject), protectedObject,
                     SHA256.HashData(route), route, receipts]);
                var input = new ContactResolverVerificationInput(
                    address, request, Xis1Codec.Decode(resultBytes, requestBytes));
                var permanentAuthority = new ContactResolveCurrentValuePathAuthority(
                    Uninitialized<VerifiedXPointNetworkAuthority>(),
                    Uninitialized<VerifiedAccountDirectoryFreshness>(),
                    network,
                    placement,
                    Bytes(1, 1),
                    Bytes(1, 2),
                    Bytes(1, 3),
                    Bytes(16, 4),
                    5,
                    new OnionTrustedTimeAuthority(new FixedClock()));
                return new Fixture
                {
                    Input = input,
                    Path = new RecordingPermanentPath(permanentAuthority),
                    Placement = placement,
                };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(locator);
            }
        }
    }

    private sealed class RecordingPermanentPath(ContactResolveCurrentValuePathAuthority authority) :
        IContactResolvePathAuthoritySource,
        IContactResolvePermanentPathAuthoritySource
    {
        internal ContactResolveCurrentValuePathAuthority Authority { get; } = authority;
        internal Exception? Failure { get; set; }
        internal int PermanentCalls { get; private set; }
        internal int PlacementOnlyCalls { get; private set; }

        public ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
            Xiq1Request request,
            CancellationToken cancellationToken)
        {
            PlacementOnlyCalls++;
            return ValueTask.FromException<ContactResolvePathAuthority>(
                new Xunit.Sdk.XunitException("Permanent resolution used the placement-only authority."));
        }

        public ValueTask<ContactResolveCurrentValuePathAuthority> GetCurrentForPermanentResolveAsync(
            Xiq1Request request,
            ParsedDid1 permanentDeepId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PermanentCalls++;
            return Failure is null
                ? ValueTask.FromResult(Authority)
                : ValueTask.FromException<ContactResolveCurrentValuePathAuthority>(Failure);
        }
    }

    private sealed class RecordingPermanentVerifier(Exception? failure = null) :
        IPermanentContactResolverCapabilityVerifier
    {
        internal VerifiedContactBundleClosure Bundle { get; } =
            Uninitialized<VerifiedContactBundleClosure>();
        internal VerifiedContactRouteClosure Route { get; } =
            Uninitialized<VerifiedContactRouteClosure>();
        internal int Calls { get; private set; }
        internal ParsedDid1? LastDid { get; private set; }
        internal ContactResolveCurrentValuePathAuthority? LastPath { get; private set; }

        public ValueTask<PermanentContactResolverCapabilities> VerifyAsync(
            ContactResolverVerificationInput input,
            ParsedDid1 permanentDeepId,
            ContactResolveCurrentValuePathAuthority path,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            LastDid = permanentDeepId;
            LastPath = path;
            return failure is null
                ? ValueTask.FromResult(new PermanentContactResolverCapabilities(Bundle, Route))
                : ValueTask.FromException<PermanentContactResolverCapabilities>(failure);
        }
    }

    private static VerifiedOnionNetworkContext LiveNetwork(ReadOnlySpan<byte> networkId)
    {
        var context = CreateNetwork(networkId);
        Set(context, "<TrustedTime>k__BackingField", CreateLease(
            TimeProvider.System, TimeSpan.FromMinutes(10), Bytes(32, 0x19)));
        var lkg = new XPointNetworkProtectedLkg(
            networkId.ToArray(),
            Reference("XNH1", 0x20),
            1,
            Bytes(32, 0x30),
            Reference("XNV1", 0x40),
            0,
            Reference("XNA1", 0x50));
        Set(context, "<ProtectedLkg>k__BackingField", lkg);
        var closureType = typeof(VerifiedOnionNetworkContext).Assembly.GetType(
            "Deep.Protocol.XPointNetworkV1.VerifiedOnionNetworkClosure", throwOnError: true)!;
        var closure = RuntimeHelpers.GetUninitializedObject(closureType);
        Set(closure, "<NetworkId>k__BackingField", networkId.ToArray());
        Set(closure, "<ViewCoreHash>k__BackingField", lkg.ViewCoreReference.Slice(6, 32).ToArray());
        Set(closure, "<ViewCoreReference>k__BackingField", lkg.ViewCoreReference.ToArray());
        Set(closure, "<PmtArtifactReference>k__BackingField", Reference("PMT2", 0x61));
        Set(closure, "<PmtNodeIds>k__BackingField", new[] { Bytes(32, 0x71), Bytes(32, 0x72) });
        Set(closure, "<SelectionEpoch>k__BackingField", 7UL);
        Set(closure, "<ReplicaCount>k__BackingField", (byte)2);
        Set(closure, "<HardUpperUnixSeconds>k__BackingField", 2_000_000_000UL);
        Set(context, "<Closure>k__BackingField", closure);
        return context;
    }

    private static void Set(object target, string field, object? value) =>
        target.GetType().GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(target, value);

    private static byte[] Reference(string magic, byte marker)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        value[5] = 1;
        value.AsSpan(6).Fill(marker);
        return value;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] PermanentReceipts()
    {
        var receipts = new byte[193];
        receipts[0] = 2;
        Bytes(32, 0x11).CopyTo(receipts, 1);
        Bytes(64, 0x31).CopyTo(receipts, 33);
        Bytes(32, 0x22).CopyTo(receipts, 97);
        Bytes(64, 0x41).CopyTo(receipts, 129);
        return receipts;
    }

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();

    private static T Uninitialized<T>() where T : class =>
        (T)RuntimeHelpers.GetUninitializedObject(typeof(T));

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedOnionNetworkContext CreateNetwork(ReadOnlySpan<byte> networkId);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern OnionTrustedTimeLease CreateLease(
        TimeProvider timeProvider,
        TimeSpan lifetime,
        ReadOnlySpan<byte> bootId);

    private sealed class FixedClock : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(new OnionMonotonicReading(Bytes(16, 0x41), 5));
    }
}
