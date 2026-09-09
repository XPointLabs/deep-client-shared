using System.Buffers.Binary;
using System.Collections;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.GroupV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.GroupV1;

public sealed class PrivacyRoutedGroupControlTransportTests
{
    [Theory]
    [InlineData("http://entry.example/")]
    [InlineData("https://entry.example/path")]
    [InlineData("https://user@entry.example/")]
    public void IngressRouteRejectsNonCanonicalProductionOrigin(string value)
    {
        Assert.Throws<ArgumentException>(() =>
            new GroupControlIngressRoute(new Uri(value), Bytes(32, 0x21)));
    }

    [Fact]
    public async Task HttpFactoryCreatesOwnedCapabilityBoundTransport()
    {
        var fixture = Fixture.Create();
        var provider = fixture.Provider(await fixture.GuardStoreAsync());
        var codec = new PrivacyRoutingCodec(
            new OnionEntropyAuthority(new NeverEntropyLedger()),
            new OnionKeyAgreementAuthority(new NeverKeyVault()));

        using var transport = new HttpServiceTransportFactory(HttpServiceEndpointPolicy.Production)
            .CreatePrivacyRoutedGroupControlTransport(
                fixture.PrimaryRoute,
                fixture.FallbackRoute,
                provider,
                codec);

        Assert.IsAssignableFrom<IDeepGroupControlTransport>(transport);
    }

    [Fact]
    public async Task PathProviderUsesProtectedPrimaryAndFallbackGuardsOnly()
    {
        var fixture = Fixture.Create();
        var store = await fixture.GuardStoreAsync();
        var provider = fixture.Provider(store);

        var primary = await ((IGroupControlPrivacyPathProvider)provider).PrepareAsync(
            fixture.Request,
            fixture.PrimaryRoute,
            PrivacyMailboxRouteSelection.Primary,
            default);
        var fallback = await ((IGroupControlPrivacyPathProvider)provider).PrepareAsync(
            fixture.Request,
            fixture.FallbackRoute,
            PrivacyMailboxRouteSelection.Fallback,
            default);

        Assert.Equal(OnionOperation.GroupControl, primary.Request.Operation);
        Assert.Equal(OnionOperation.GroupControl, fallback.Request.Operation);
        Assert.Equal(fixture.PrimaryRoute.EntryRouterId.ToArray(), primary.EntryRouterId.ToArray());
        Assert.Equal(fixture.FallbackRoute.EntryRouterId.ToArray(), fallback.EntryRouterId.ToArray());
        Assert.Equal(fixture.Request.CanonicalBytes.ToArray(), primary.Request.CanonicalBytes.ToArray());
    }

    [Fact]
    public async Task PathProviderRejectsWrongRouteAndCrossNetworkRequestBeforeDispatch()
    {
        var fixture = Fixture.Create();
        var provider = fixture.Provider(await fixture.GuardStoreAsync());
        var wrongRoute = new GroupControlIngressRoute(
            new Uri("https://wrong.example/"),
            Bytes(32, 0x03));

        var wrongRouteError = await Assert.ThrowsAsync<GroupControlPathException>(async () =>
            await ((IGroupControlPrivacyPathProvider)provider).PrepareAsync(
                fixture.Request,
                wrongRoute,
                PrivacyMailboxRouteSelection.Primary,
                default));
        Assert.Equal("route-binding-unavailable", wrongRouteError.Code);

        var other = Fixture.Create(networkMarker: 0x19);
        var crossNetworkError = await Assert.ThrowsAsync<GroupControlPathException>(async () =>
            await ((IGroupControlPrivacyPathProvider)provider).PrepareAsync(
                other.Request,
                fixture.PrimaryRoute,
                PrivacyMailboxRouteSelection.Primary,
                default));
        Assert.Equal("request-placement-mismatch", crossNetworkError.Code);
    }

    [Fact]
    public async Task ExactQueryAndReplayReturnOnlyRequestBoundCanonicalGss1()
    {
        var fixture = Fixture.Create();
        var body = fixture.QueryResult();
        var codec = new FakeCodec(body);
        var ingress = new CountingIngress();
        using var transport = fixture.Transport(codec, ingress, new NeverIngress());

        var first = await transport.ExecuteAsync(fixture.Request);
        var replay = await transport.ExecuteAsync(fixture.Request);

        Assert.Equal(body, first.ToArray());
        Assert.Equal(body, replay.ToArray());
        Assert.Equal(2, ingress.CallCount);
        Assert.Equal(2, codec.OpenCount);
    }

    [Fact]
    public async Task WrongTerminalOperationOrOperationIdFailsClosed()
    {
        var fixture = Fixture.Create();
        var wrongOperationCodec = new FakeCodec(
            fixture.QueryResult(),
            OnionOperation.ContactResolve);
        using (var wrongOperation = fixture.Transport(
                   wrongOperationCodec,
                   new CountingIngress(),
                   new NeverIngress()))
        {
            var error = await Assert.ThrowsAsync<GroupControlTransportException>(async () =>
                await wrongOperation.ExecuteAsync(fixture.Request));
            Assert.Equal(GroupControlTransportFailure.ProtocolViolation, error.Failure);
        }

        var changedOperation = fixture.QueryResult();
        changedOperation[FieldOffset(changedOperation, 2)] ^= 0x80;
        using var wrongId = fixture.Transport(
            new FakeCodec(changedOperation),
            new CountingIngress(),
            new NeverIngress());
        var wrongIdError = await Assert.ThrowsAsync<GroupControlTransportException>(async () =>
            await wrongId.ExecuteAsync(fixture.Request));
        Assert.Equal(GroupControlTransportFailure.ProtocolViolation, wrongIdError.Failure);
    }

    [Fact]
    public async Task RetryableBeforeForwardRejectUsesOnlyVerifiedFallbackIngress()
    {
        var fixture = Fixture.Create();
        var fallback = new CountingIngress();
        var observer = new SelectionObserver();
        using var transport = fixture.Transport(
            new FakeCodec(fixture.QueryResult()),
            new BeforeForwardIngress(retryable: true),
            fallback,
            observer);

        var result = await transport.ExecuteAsync(fixture.Request);

        Assert.Equal(fixture.QueryResult(), result.ToArray());
        Assert.Equal(1, fallback.CallCount);
        Assert.Equal(PrivacyMailboxRouteSelection.Fallback, observer.Selection);
        Assert.Equal(fixture.FallbackRoute.EntryRouterId.ToArray(), observer.EntryRouterId);
    }

    [Fact]
    public async Task AfterForwardFailureNeverFallsBackToAnotherOrDirectEndpoint()
    {
        var fixture = Fixture.Create();
        var fallback = new CountingIngress();
        using var transport = fixture.Transport(
            new FakeCodec(fixture.QueryResult()),
            new UnknownIngress(),
            fallback);

        var error = await Assert.ThrowsAsync<GroupControlTransportException>(async () =>
            await transport.ExecuteAsync(fixture.Request));

        Assert.Equal(GroupControlTransportFailure.OutcomeUnknown, error.Failure);
        Assert.Equal(0, fallback.CallCount);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(OnionLimits.MaximumGroupControlResponseBytes + 1)]
    public async Task HostileTerminalLengthFailsBeforeResultPromotion(int length)
    {
        var fixture = Fixture.Create();
        using var transport = fixture.Transport(
            new FakeCodec(new byte[length]),
            new CountingIngress(),
            new NeverIngress());

        var error = await Assert.ThrowsAsync<GroupControlTransportException>(async () =>
            await transport.ExecuteAsync(fixture.Request));

        Assert.Equal(GroupControlTransportFailure.ProtocolViolation, error.Failure);
    }

    [Theory]
    [InlineData(true, ManagedIngressH2Contract.OpaqueMediaType)]
    [InlineData(false, "application/octet-stream")]
    public async Task RedirectOrWrongFramingIsOutcomeUnknownWithoutFallback(
        bool redirect,
        string mediaType)
    {
        var fixture = Fixture.Create();
        using var httpIngress = HttpIngress(request =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Version = HttpVersion.Version20,
                RequestMessage = redirect
                    ? new HttpRequestMessage(HttpMethod.Post, "https://other.example/xpoint/v1/frame")
                    : request,
                Content = new ByteArrayContent(Bytes(64, 0x5a)),
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
            response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            return response;
        });
        var fallback = new CountingIngress();
        using var transport = fixture.Transport(
            new FakeCodec(fixture.QueryResult()),
            httpIngress,
            fallback);

        var error = await Assert.ThrowsAsync<GroupControlTransportException>(async () =>
            await transport.ExecuteAsync(fixture.Request));

        Assert.Equal(GroupControlTransportFailure.OutcomeUnknown, error.Failure);
        Assert.Equal(0, fallback.CallCount);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(63)]
    [InlineData(65)]
    public async Task MissingOrMismatchedContentLengthIsOutcomeUnknownWithoutFallback(
        long declaredLength)
    {
        var fixture = Fixture.Create();
        using var httpIngress = HttpIngress(request =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Version = HttpVersion.Version20,
                RequestMessage = request,
                Content = new ByteArrayContent(Bytes(64, 0x5a)),
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue(
                ManagedIngressH2Contract.OpaqueMediaType);
            response.Content.Headers.ContentLength = declaredLength < 0
                ? null
                : declaredLength;
            response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            return response;
        });
        var fallback = new CountingIngress();
        using var transport = fixture.Transport(
            new FakeCodec(fixture.QueryResult()),
            httpIngress,
            fallback);

        var error = await Assert.ThrowsAsync<GroupControlTransportException>(async () =>
            await transport.ExecuteAsync(fixture.Request));

        Assert.Equal(GroupControlTransportFailure.OutcomeUnknown, error.Failure);
        Assert.Equal(0, fallback.CallCount);
    }

    [Fact]
    public void FactoryAndPublicBoundaryAreLegacyAndTrustFlagFree()
    {
        var root = RepositoryRoot();
        var files = new[]
        {
            Path.Combine(root, "src", "Deep.Client.Shared", "Services", "GroupV1",
                "PrivacyRoutedGroupControlTransport.cs"),
            Path.Combine(root, "src", "Deep.Client.Shared", "Services", "GroupV1",
                "GroupControlPrivacyPathProvider.cs"),
        };
        var source = string.Join("\n", files.Select(File.ReadAllText));

        Assert.Contains("OnionOperation.GroupControl", source, StringComparison.Ordinal);
        Assert.Contains("OnionPathContextFactory.CreateGroupControl", source, StringComparison.Ordinal);
        Assert.Contains("GroupControlProductionClient.VerifyResult", source, StringComparison.Ordinal);
        Assert.DoesNotContain("SessionId", source, StringComparison.Ordinal);
        Assert.DoesNotContain("isTrusted", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("trustNetwork", source, StringComparison.OrdinalIgnoreCase);

        using var handler = HttpServiceTransportFactory.CreateHttpHandler(
            options: null,
            networkHooks: null);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
    }

    private static PrivacyManagedIngressHttpTransport HttpIngress(
        Func<HttpRequestMessage, HttpResponseMessage> response)
    {
        var client = new HttpClient(new Handler(response))
        {
            BaseAddress = new Uri("https://primary.example/"),
        };
        return new PrivacyManagedIngressHttpTransport(client);
    }

    private static string RepositoryRoot()
    {
        for (var current = new DirectoryInfo(AppContext.BaseDirectory);
             current is not null;
             current = current.Parent)
        {
            if (File.Exists(Path.Combine(current.FullName, "Deep.Client.Shared.slnx")))
            {
                return current.FullName;
            }
        }

        throw new DirectoryNotFoundException("deep-client-shared repository root was not found.");
    }

    private static int FieldOffset(ReadOnlySpan<byte> record, ushort tag)
    {
        var offset = 12;
        for (var index = 0;
             index < BinaryPrimitives.ReadUInt16BigEndian(record[8..10]);
             index++)
        {
            var current = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(record.Slice(offset + 4, 4)));
            offset += 8;
            if (current == tag)
            {
                return offset;
            }

            offset += length;
        }

        throw new InvalidOperationException("Record field was not found.");
    }

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();

    private sealed class Fixture
    {
        private Fixture()
        {
        }

        internal required VerifiedOnionNetworkContext Network { get; init; }
        internal required VerifiedGroupControlPlacement Placement { get; init; }
        internal required VerifiedGroupControlQueryRequest Request { get; init; }
        internal required GroupControlIngressRoute PrimaryRoute { get; init; }
        internal required GroupControlIngressRoute FallbackRoute { get; init; }
        internal required ReadOnlyMemory<byte> ViewHash { get; init; }

        internal static Fixture Create(byte networkMarker = 0x11)
        {
            var networkId = Bytes(16, networkMarker);
            var viewHash = Bytes(32, 0x75);
            var network = CreateNetwork(networkId);
            Set(network, "<TrustedTime>k__BackingField", CreateLease(
                TimeProvider.System,
                TimeSpan.FromMinutes(10),
                Bytes(32, 0x19)));
            Set(network, "<ProtectedLkg>k__BackingField", new XPointNetworkProtectedLkg(
                networkId,
                Reference("XNH1", Bytes(32, 0x73)),
                2,
                Bytes(32, 0x74),
                Reference("XNV1", viewHash),
                1,
                Reference("XNA1", Bytes(32, 0x76))));
            var closureType = typeof(VerifiedOnionNetworkContext).Assembly.GetType(
                "Deep.Protocol.XPointNetworkV1.VerifiedOnionNetworkClosure",
                throwOnError: true)!;
            Set(network, "<Closure>k__BackingField", RuntimeHelpers.GetUninitializedObject(closureType));
            var dictionary = (IDictionary)typeof(VerifiedOnionNetworkContext)
                .GetField("_nodes", BindingFlags.Instance | BindingFlags.NonPublic)!
                .GetValue(network)!;
            for (byte marker = 1; marker <= 5; marker++)
            {
                dictionary.Add(Convert.ToHexString(Bytes(32, marker)), Node(marker));
            }

            var gsr = (GroupControlRendezvousRecord)GroupCodec.Decode("GSR1", GroupRecord(
                "GSR1",
                null,
                [
                    networkId,
                    Bytes(32, 0x20),
                    Bytes(32, 0x30),
                    U64(0),
                    new byte[32],
                    Reference("PMT2", Bytes(32, 0x71)),
                    viewHash,
                    Bytes(32, 0x66),
                    Bytes(32, 0x61),
                    Bytes(32, 0x62),
                    Reference("DPD1", Bytes(32, 0x63)),
                    U64(10),
                    U64(100),
                    Bytes(64, 0x64),
                ]));
            var owner = (VerifiedContactBundleClosure)RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedContactBundleClosure));
            var rendezvous = (VerifiedGroupControlRendezvous)Activator.CreateInstance(
                typeof(VerifiedGroupControlRendezvous),
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                args: [gsr, owner],
                culture: null)!;
            var placement = CreatePlacement(
                network,
                rendezvous,
                viewHash,
                Bytes(32, 0x66),
                [Bytes(32, 4), Bytes(32, 5)]);

            var group = Group(networkId);
            var query = (GroupControlQueryRecord)GroupCodec.Decode("GSQ1", GroupRecord(
                "GSQ1",
                [1, 2, 3, 4, 5, 6, 16, 17, 18, 19, 20],
                [
                    networkId,
                    Bytes(32, 0x41),
                    viewHash,
                    placement.PlacementHash,
                    U64(20),
                    U64(40),
                    gsr.Field(2),
                    gsr.ArtifactHash,
                    U64(0),
                    U16(64),
                    U16(4),
                ]));
            var terminal = OnionTerminalPayloadVerifierV1.VerifyRequest(
                network,
                OnionOperation.GroupControl,
                query.CanonicalBytes);
            var request = (VerifiedGroupControlQueryRequest)Activator.CreateInstance(
                typeof(VerifiedGroupControlQueryRequest),
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                args: [group, placement, query, terminal],
                culture: null)!;

            return new Fixture
            {
                Network = network,
                Placement = placement,
                Request = request,
                ViewHash = viewHash,
                PrimaryRoute = new GroupControlIngressRoute(
                    new Uri("https://primary.example/"),
                    Bytes(32, 0x01)),
                FallbackRoute = new GroupControlIngressRoute(
                    new Uri("https://fallback.example/"),
                    Bytes(32, 0x02)),
            };
        }

        internal GroupControlPrivacyPathProvider Provider(IProtectedEntryGuardStore store) =>
            new(Network, store, () => Bytes(32, 0x51));

        internal async Task<IProtectedEntryGuardStore> GuardStoreAsync()
        {
            var store = new InMemoryProtectedEntryGuardStore();
            var state = new EntryGuardState(
                1,
                Network.NetworkId.Span,
                1,
                ViewHash.Span,
                Bytes(32, 0x51),
                Bytes(32, 1),
                new ReadOnlyMemory<byte>[]
                {
                    Bytes(32, 1),
                    Bytes(32, 2),
                    Bytes(32, 3),
                });
            await store.CompareExchangeAsync(null, state, default);
            return store;
        }

        internal PrivacyRoutedGroupControlTransport Transport(
            IGroupControlPrivacyCodec codec,
            IPrivacyManagedIngressTransport primary,
            IPrivacyManagedIngressTransport fallback,
            IPrivacyMailboxRouteSelectionObserver? observer = null) =>
            new(
                PrimaryRoute,
                FallbackRoute,
                Provider(GuardStoreAsync().GetAwaiter().GetResult()),
                codec,
                primary,
                fallback,
                observer);

        internal byte[] QueryResult()
        {
            var body = Bytes(64, 0x91);
            var bodyHash = SHA256.HashData(body);
            var events = Join(U64(1), new byte[32], bodyHash, U64(30), Lp32(body));
            return GroupRecord(
                "GSS1",
                [1, 2, 3, 4, 5, 6, 7, 8, 16, 17, 18, 19, 20],
                [
                    Request.Record.Field(1),
                    Request.Record.Field(2),
                    RequestHash(Request.CanonicalBytes.Span),
                    U16((ushort)GroupControlResultStatus.Events),
                    new byte[] { 0 },
                    U64(30),
                    U32(0),
                    U16(4),
                    new byte[] { 2 },
                    U16(1),
                    events,
                    U64(1),
                    new byte[] { 0 },
                ]);
        }

        private static VerifiedGroupTransition Group(byte[] networkId)
        {
            var commit = (GroupCommitRecord)GroupCodec.Decode("DGC1", GroupRecord(
                "DGC1",
                null,
                [
                    networkId,
                    Bytes(32, 0x20),
                    U16(1),
                    U64(0),
                    new byte[32],
                    Bytes(32, 0x30),
                    Bytes(32, 0x31),
                    Reference("DPD1", Bytes(32, 0x32)),
                    U16(0),
                    Array.Empty<byte>(),
                    U16(1),
                    Member(Bytes(32, 0x30), Bytes(32, 0x31)),
                    Encoding.UTF8.GetBytes("group-control"),
                    new byte[] { 0 },
                    U32(60),
                    U64(1),
                    Bytes(64, 0x33),
                ]));
            var implementation = typeof(VerifiedGroupTransition).Assembly.GetType(
                "Deep.Protocol.GroupV1.GroupCodec+VerifiedGroupTransitionImpl",
                throwOnError: true)!;
            var transition = (VerifiedGroupTransition)RuntimeHelpers.GetUninitializedObject(implementation);
            var type = typeof(VerifiedGroupTransition);
            type.GetField("<Commit>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(transition, commit);
            type.GetField("<Predecessor>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(transition, null);
            type.GetField("exactVerifiedGcp1Sha256", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(transition, Bytes(32, 0x34));
            return transition;
        }

        private static byte[] Member(byte[] account, byte[] device)
        {
            var body = Join(
                account,
                new byte[] { 1 },
                Reference("ADC1", Bytes(32, 0x21)),
                Reference("ADH1", Bytes(32, 0x22)),
                Bytes(32, 0x23),
                U64(1),
                Bytes(32, 0x24),
                Reference("DRS1", Bytes(32, 0x25)),
                new byte[] { 1 },
                device,
                Reference("DPD1", Bytes(32, 0x32)));
            return Join(U16(checked((ushort)body.Length)), body);
        }
    }

    private sealed class FakeCodec(
        ReadOnlyMemory<byte> body,
        OnionOperation operation = OnionOperation.GroupControl) : IGroupControlPrivacyCodec
    {
        public int OpenCount { get; private set; }

        public ValueTask<IGroupControlPrivacyBuiltRequest> BuildAsync(
            VerifiedOnionPathContext path,
            VerifiedCanonicalOnionRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(OnionOperation.GroupControl, request.Operation);
            return ValueTask.FromResult<IGroupControlPrivacyBuiltRequest>(new FakeBuiltRequest());
        }

        public ValueTask<GroupControlPrivacyOpenedResponse> OpenResponseAsync(
            ReadOnlyMemory<byte> frame,
            IGroupControlPrivacyBuiltRequest builtRequest,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            OpenCount++;
            return ValueTask.FromResult(new GroupControlPrivacyOpenedResponse(
                operation,
                OnionTerminalResultKind.Success,
                null,
                body));
        }
    }

    private sealed class FakeBuiltRequest : IGroupControlPrivacyBuiltRequest
    {
        public ReadOnlyMemory<byte> Frame => Bytes(64, 0x51);
        public void Dispose()
        {
        }
    }

    private sealed class CountingIngress : IPrivacyManagedIngressTransport
    {
        public int CallCount { get; private set; }

        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return Task.FromResult<ReadOnlyMemory<byte>>(Bytes(64, 0x52));
        }

        public void Dispose()
        {
        }
    }

    private sealed class BeforeForwardIngress(bool retryable) : IPrivacyManagedIngressTransport
    {
        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken) =>
            Task.FromException<ReadOnlyMemory<byte>>(
                new PrivacyIngressRejectedBeforeForwardException(
                    retryable,
                    "before-forward"));

        public void Dispose()
        {
        }
    }

    private sealed class UnknownIngress : IPrivacyManagedIngressTransport
    {
        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken) =>
            Task.FromException<ReadOnlyMemory<byte>>(new IOException("after-forward"));

        public void Dispose()
        {
        }
    }

    private sealed class NeverIngress : IPrivacyManagedIngressTransport
    {
        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Fallback ingress must not be used.");

        public void Dispose()
        {
        }
    }

    private sealed class SelectionObserver : IPrivacyMailboxRouteSelectionObserver
    {
        public PrivacyMailboxRouteSelection? Selection { get; private set; }
        public byte[]? EntryRouterId { get; private set; }

        public void Observe(
            PrivacyMailboxRouteSelection selection,
            ReadOnlyMemory<byte> entryRouterId)
        {
            Selection = selection;
            EntryRouterId = entryRouterId.ToArray();
        }
    }

    private sealed class Handler(
        Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(HttpVersion.Version20, request.Version);
            Assert.Equal(HttpVersionPolicy.RequestVersionExact, request.VersionPolicy);
            Assert.Equal(ManagedIngressH2Contract.FramePath, request.RequestUri!.AbsolutePath);
            return Task.FromResult(response(request));
        }
    }

    private sealed class NeverEntropyLedger : IOnionEntropyUniquenessLedger
    {
        public ValueTask<OnionEntropyCommitOutcome> CommitAsync(
            OnionEntropyCommitmentBatch batch,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Factory creation must not consume ONION entropy.");
    }

    private sealed class NeverKeyVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(
            OnionKeyHandle keyHandle,
            ReadOnlyMemory<byte> peerPublicKey,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Factory creation must not access ONION private keys.");
    }

    private static object Node(byte marker)
    {
        var nodeType = typeof(VerifiedOnionNetworkContext).Assembly.GetType(
            "Deep.Protocol.DeepExtension.PrivacyRouting.VerifiedNetworkNode",
            throwOnError: true)!;
        return Activator.CreateInstance(
            nodeType,
            BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public,
            binder: null,
            args:
            [
                Bytes(32, marker),
                Bytes(32, checked((byte)(marker + 0x20))),
                Bytes(32, checked((byte)(marker + 0x40))),
                Bytes(32, checked((byte)(marker + 0x60))),
                Bytes(32, checked((byte)(marker + 0x70))),
                (byte)1,
                (byte)4,
                Ipv4(checked((byte)(marker + 10))),
                checked((ushort)(4400 + marker)),
                Bytes(32, checked((byte)(marker + 0x50))),
                (ushort)0x0007,
                65_536U,
                65_536UL,
                65_536UL,
                1UL,
                Bytes(32, checked((byte)(marker + 0x10))),
                Bytes(32, checked((byte)(marker + 0x30))),
                Bytes(32, checked((byte)(marker + 0x50))),
            ],
            culture: null)!;
    }

    private static void Set(object target, string field, object value) =>
        target.GetType().GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(target, value);

    private static byte[] GroupRecord(
        string magic,
        IReadOnlyList<int>? tags,
        IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        tags ??= Enumerable.Range(1, fields.Count).ToArray();
        var bytes = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)tags[index]));
            BinaryPrimitives.WriteUInt32BigEndian(
                bytes.AsSpan(offset + 4),
                checked((uint)fields[index].Length));
            offset += 8;
            fields[index].Span.CopyTo(bytes.AsSpan(offset));
            offset += fields[index].Length;
        }

        return bytes;
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var value = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        hash.CopyTo(value.AsSpan(6));
        return value;
    }

    private static byte[] RequestHash(ReadOnlySpan<byte> request)
    {
        var label = Encoding.ASCII.GetBytes("Deep/ContactResolver/V1/request");
        var preimage = new byte[label.Length + 5 + request.Length];
        label.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            preimage.AsSpan(label.Length + 1),
            checked((uint)request.Length));
        request.CopyTo(preimage.AsSpan(label.Length + 5));
        try
        {
            return SHA256.HashData(preimage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preimage);
        }
    }

    private static byte[] Lp32(ReadOnlySpan<byte> value)
    {
        var output = new byte[4 + value.Length];
        BinaryPrimitives.WriteUInt32BigEndian(output, checked((uint)value.Length));
        value.CopyTo(output.AsSpan(4));
        return output;
    }

    private static byte[] Join(params byte[][] values) =>
        values.SelectMany(static value => value).ToArray();

    private static byte[] Ipv4(byte value)
    {
        var output = new byte[16];
        output.AsSpan(0, 4).Fill(value);
        return output;
    }

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U32(uint value)
    {
        var output = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedOnionNetworkContext CreateNetwork(ReadOnlySpan<byte> networkId);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern OnionTrustedTimeLease CreateLease(
        TimeProvider timeProvider,
        TimeSpan lifetime,
        ReadOnlySpan<byte> bootId);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedGroupControlPlacement CreatePlacement(
        VerifiedOnionNetworkContext network,
        VerifiedGroupControlRendezvous rendezvous,
        ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash,
        IReadOnlyList<byte[]> replicaNodeIds);
}
