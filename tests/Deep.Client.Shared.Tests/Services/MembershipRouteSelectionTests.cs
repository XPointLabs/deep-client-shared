using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.MembershipRoutes;

namespace Deep.Client.Shared.Tests.Services;

public sealed class MembershipRouteSelectionTests
{
    private static readonly DateTimeOffset TrustNow = DateTimeOffset.FromUnixTimeSeconds(1010);

    [Fact]
    public void XNodeRpcClient_RetainsBinaryCompatibleFourArgumentConstructor()
    {
        var constructor = typeof(XNodeRpcClient).GetConstructor(
            [
                typeof(HttpClient),
                typeof(XNodeRpcClientOptions),
                typeof(TimeProvider),
                typeof(IMembershipRouteCatalogProvider)
            ]);

        Assert.NotNull(constructor);
        Assert.Equal(4, constructor.GetParameters().Length);
        Assert.NotNull(typeof(XNodeRpcClient).GetConstructor(
            [
                typeof(HttpClient),
                typeof(XNodeRpcClientOptions),
                typeof(TimeProvider),
                typeof(IMembershipRouteCatalogProvider),
                typeof(ITransportRouteEvidenceObserver)
            ]));
    }

    [Fact]
    public void Selector_ProducesExactDisjointThreeHopRoutesFromSixMembers()
    {
        var catalog = Catalog();
        var first = MembershipRouteSelector.Select(catalog, Enumerable.Repeat((byte)1, 32).ToArray());
        var excluded = first
            .Select(static item => Convert.ToHexStringLower(item.Descriptor.RouterId.Span))
            .ToHashSet(StringComparer.Ordinal);
        var second = MembershipRouteSelector.Select(
            catalog,
            Enumerable.Repeat((byte)2, 32).ToArray(),
            excluded);

        Assert.Equal(3, first.Count);
        Assert.Equal(3, second.Count);
        Assert.Empty(first.Select(Id).Intersect(second.Select(Id), StringComparer.Ordinal));
    }

    [Fact]
    public void Selector_PreservesIngressCoreStorageRoleSeparation()
    {
        var source = Catalog();
        var members = source.Members.Select((member, index) => member with
        {
            Descriptor = member.Descriptor with
            {
                Roles = index switch
                {
                    < 2 => MembershipRouteRole.Ingress,
                    < 4 => MembershipRouteRole.Core,
                    _ => MembershipRouteRole.Storage
                },
                Capabilities = MembershipRouteCapability.SessionRpc |
                               MembershipRouteCapability.OnionV1 |
                               (index >= 4
                                   ? MembershipRouteCapability.Storage
                                   : MembershipRouteCapability.None)
            }
        }).ToArray();
        var selected = MembershipRouteSelector.Select(
            source with { Members = members },
            Enumerable.Repeat((byte)3, 32).ToArray());

        Assert.True(selected[0].Descriptor.Roles.HasFlag(MembershipRouteRole.Ingress));
        Assert.True(selected[1].Descriptor.Roles.HasFlag(MembershipRouteRole.Core));
        Assert.True(selected[2].Descriptor.Roles.HasFlag(MembershipRouteRole.Storage));
    }

    [Fact]
    public void Selector_FailsClosedWhenFewerThanThreeViableMembersRemain()
    {
        var catalog = Catalog();
        var excluded = catalog.Members
            .Take(4)
            .Select(Id)
            .ToHashSet(StringComparer.Ordinal);

        var exception = Assert.Throws<MembershipRouteCatalogException>(() =>
            MembershipRouteSelector.Select(
                catalog,
                Enumerable.Repeat((byte)4, 32).ToArray(),
                excluded));

        Assert.Contains("No exact", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MembershipStore_DispatchesDirectlyWithoutRouteOrExclusionDisclosure()
    {
        var requests = new List<string>();
        var evidence = new RecordingRouteEvidenceObserver();
        using var client = new HttpClient(new ThrowingHandler(async (request, cancellationToken) =>
        {
            requests.Add(await request.Content!.ReadAsStringAsync(cancellationToken));
            throw new HttpRequestException("response lost");
        }));
        var catalog = Catalog();
        var routerIds = catalog.Members.Select(Id).ToArray();
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                [new PinnedRouterEndpoint("http://bootstrap.invalid/", routerIds[0])],
                TrustedRouterIds: routerIds,
                RequireMembershipRouteSelection: true),
            timeProvider: null,
            membershipRouteCatalogProvider: new StaticCatalogProvider(catalog),
            routeEvidenceObserver: evidence);

        await Assert.ThrowsAsync<StorageDispatchOutcomeUnknownException>(
            () => router.PostStorageAsync(
                "storage_store",
                new { placement_key = "opaque" },
                "mailbox-target-that-must-not-leak"));

        var request = Assert.Single(requests);
        Assert.Contains("\"method\":\"onion_request\"", request, StringComparison.Ordinal);
        Assert.DoesNotContain("storage_route", request, StringComparison.Ordinal);
        Assert.DoesNotContain("excludedRouterIds", request, StringComparison.Ordinal);
        Assert.DoesNotContain("mailbox-target-that-must-not-leak", request, StringComparison.Ordinal);
        Assert.Equal(
            [
                TransportRouteEvidenceEvent.Selected,
                TransportRouteEvidenceEvent.OutcomeUnknown
            ],
            evidence.Events.Select(static item => item.Event));
        Assert.DoesNotContain(
            "mailbox-target-that-must-not-leak",
            JsonSerializer.Serialize(evidence.Events),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task RouteEvidence_ConcurrentCallsHaveIndependentImmutableCorrelations()
    {
        const int callCount = 8;
        var dispatchCount = 0;
        var evidence = new ConcurrentRouteEvidenceObserver();
        using var client = new HttpClient(new ThrowingHandler((request, cancellationToken) =>
        {
            Interlocked.Increment(ref dispatchCount);
            return Task.FromException<HttpResponseMessage>(
                new HttpRequestException("response lost"));
        }));
        var catalog = Catalog();
        var routerIds = catalog.Members.Select(Id).ToArray();
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                [new PinnedRouterEndpoint("http://bootstrap.invalid/", routerIds[0])],
                TrustedRouterIds: routerIds,
                RequireMembershipRouteSelection: true),
            timeProvider: null,
            membershipRouteCatalogProvider: new StaticCatalogProvider(catalog),
            routeEvidenceObserver: evidence);

        await Task.WhenAll(Enumerable.Range(0, callCount).Select(async _ =>
            await Assert.ThrowsAsync<StorageDispatchOutcomeUnknownException>(() =>
                router.PostStorageAsync(
                    "storage_store",
                    new { placement_key = "opaque" },
                    "same-private-target"))));

        Assert.Equal(callCount, dispatchCount);
        var snapshots = evidence.Events.ToArray();
        Assert.Equal(callCount * 2, snapshots.Length);
        var correlations = snapshots.GroupBy(static item => item.CorrelationId).ToArray();
        Assert.Equal(callCount, correlations.Length);
        Assert.All(correlations, group =>
        {
            Assert.Matches("^[0-9a-f]{32}$", group.Key);
            Assert.Equal(2, group.Count());
            Assert.Equal(
                [
                    TransportRouteEvidenceEvent.Selected,
                    TransportRouteEvidenceEvent.OutcomeUnknown
                ],
                group.Select(static item => item.Event));
            Assert.All(group, static item => Assert.Equal(1, item.Attempt));
        });
        var firstRouters = Assert.IsAssignableFrom<IList<string>>(snapshots[0].RouterIdDigests);
        Assert.Throws<NotSupportedException>(() => firstRouters[0] = new string('0', 64));
        Assert.DoesNotContain(
            "same-private-target",
            JsonSerializer.Serialize(snapshots),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task RouteEvidence_ThrowingObserverCannotAlterTransportSemantics()
    {
        var dispatchCount = 0;
        using var client = new HttpClient(new ThrowingHandler((request, cancellationToken) =>
        {
            Interlocked.Increment(ref dispatchCount);
            return Task.FromException<HttpResponseMessage>(
                new HttpRequestException("response lost"));
        }));
        var catalog = Catalog();
        var routerIds = catalog.Members.Select(Id).ToArray();
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                [new PinnedRouterEndpoint("http://bootstrap.invalid/", routerIds[0])],
                TrustedRouterIds: routerIds,
                RequireMembershipRouteSelection: true),
            timeProvider: null,
            membershipRouteCatalogProvider: new StaticCatalogProvider(catalog),
            routeEvidenceObserver: new ThrowingRouteEvidenceObserver());

        await Assert.ThrowsAsync<StorageDispatchOutcomeUnknownException>(() =>
            router.PostStorageAsync(
                "storage_store",
                new { placement_key = "opaque" },
                "private-target"));

        Assert.Equal(1, dispatchCount);
    }

    [Fact]
    public void RequiredMembershipMode_FailsClosedWithoutProvider()
    {
        var routerId = Id(Catalog().Members[0]);
        var exception = Assert.Throws<ArgumentException>(() => new XNodeRpcClient(
            new HttpClient(),
            new XNodeRpcClientOptions(
                [new PinnedRouterEndpoint("http://bootstrap.invalid/", routerId)],
                TrustedRouterIds: Catalog().Members.Take(3).Select(Id).ToArray(),
                RequireMembershipRouteSelection: true)));

        Assert.Contains("no verified catalog provider", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifiedProvider_UsesCachedLkgOnlyForDirectoryOutage()
    {
        var fixture = SignedArtifact();
        var store = new InMemorySessionStore();
        var verifier = new MembershipTrustServiceTests.FixtureMembershipVerifier();
        var trust = new MembershipTrustService(
            store,
            verifier,
            new FrozenClock(TrustNow),
            MembershipTrustOptions.DormantDefaults with
            {
                Enabled = true,
                AllowedClockSkew = TimeSpan.FromSeconds(30),
                ClockRollbackTolerance = TimeSpan.FromSeconds(30)
            });
        var sourceState = new SwitchingArtifactHandler(fixture.Artifact);
        var source = DevLocalHttpSource(sourceState);
        var cache = new InMemoryMembershipRouteArtifactCache();
        var provider = new VerifiedMembershipRouteCatalogProvider(
            trust,
            store,
            fixture.Bootstrap,
            source,
            cache,
            new FrozenTimeProvider(TrustNow),
            MembershipRouteEndpointPolicy.DevLocalHttp);

        var fresh = await provider.GetCatalogAsync();
        sourceState.Unavailable = true;
        var cached = await provider.GetCatalogAsync();

        Assert.Equal(6, fresh.Members.Count);
        Assert.Equal(fresh.CanonicalMembershipHash, cached.CanonicalMembershipHash);
    }

    [Fact]
    public async Task VerifiedProvider_DoesNotMaskMalformedRemoteArtifactWithCachedLkg()
    {
        var fixture = SignedArtifact();
        var store = new InMemorySessionStore();
        var verifier = new MembershipTrustServiceTests.FixtureMembershipVerifier();
        var sourceState = new SwitchingArtifactHandler(fixture.Artifact);
        var providerSource = DevLocalHttpSource(sourceState);
        var provider = new VerifiedMembershipRouteCatalogProvider(
            new MembershipTrustService(
                store,
                verifier,
                new FrozenClock(TrustNow),
                MembershipTrustOptions.DormantDefaults with
                {
                    Enabled = true,
                    AllowedClockSkew = TimeSpan.FromSeconds(30),
                    ClockRollbackTolerance = TimeSpan.FromSeconds(30)
                }),
            store,
            fixture.Bootstrap,
            providerSource,
            new InMemoryMembershipRouteArtifactCache(),
            new FrozenTimeProvider(TrustNow),
            MembershipRouteEndpointPolicy.DevLocalHttp);

        _ = await provider.GetCatalogAsync();
        sourceState.Artifact = "{ \"version\": \"unsigned\" }"u8.ToArray();

        await Assert.ThrowsAsync<MembershipRouteCatalogException>(
            () => provider.GetCatalogAsync());
    }

    [Fact]
    public void DevBootstrap_RequiresExactWholeArtifactPin()
    {
        var fixture = SignedArtifact();

        Assert.Throws<MembershipRouteCatalogException>(() =>
            DevLocalMembershipTrustBootstrap.CreateProfile(
                fixture.Artifact,
                new DevLocalMembershipTrustBootstrapOptions(null)));
        Assert.Throws<MembershipRouteCatalogException>(() =>
            DevLocalMembershipTrustBootstrap.CreateProfile(
                fixture.Artifact,
                fixture.Bootstrap with
                {
                    ExpectedArtifactSha256 = new string('0', 64)
                }));
        Assert.Throws<MembershipRouteCatalogException>(() =>
            DevLocalMembershipTrustBootstrap.CreateProfile(
                fixture.Artifact,
                fixture.Bootstrap with
                {
                    ExpectedArtifactSha256 =
                        fixture.Bootstrap.ExpectedArtifactSha256!.ToUpperInvariant()
                }));
    }

    [Fact]
    public void DevBootstrap_DerivesExactArtifactScopedProfileKey()
    {
        var fixture = SignedArtifact();
        var profile = DevLocalMembershipTrustBootstrap.CreateProfile(
            fixture.Artifact,
            fixture.Bootstrap);

        Assert.Equal(
            $"{DevLocalMembershipTrustBootstrap.OpaqueProfileKeyBase}:{fixture.Bootstrap.ExpectedArtifactSha256}",
            profile.OpaqueProfileKey);
        Assert.Equal(
            DevLocalMembershipTrustBootstrap.OpaqueProfileKeyBase.Length + 65,
            profile.OpaqueProfileKey.Length);
        Assert.True(
            profile.OpaqueProfileKey.Length <= MembershipTrustRecord.MaximumProfileKeyLength);
    }

    [Theory]
    [InlineData("")]
    [InlineData("install:deep-survival-dev-v1")]
    [InlineData("install:deep-survival-dev-v2:")]
    [InlineData("install:self-hosted:deep-survival-dev-v2")]
    public void DevBootstrap_RejectsMalformedOrUnpinnedProfileBase(string profileBase)
    {
        var fixture = SignedArtifact();

        Assert.Throws<MembershipRouteCatalogException>(() =>
            DevLocalMembershipTrustBootstrap.CreateProfile(
                fixture.Artifact,
                fixture.Bootstrap with { ExpectedOpaqueProfileKey = profileBase }));
    }

    [Fact]
    public async Task DevBootstrap_DifferentArtifactPinsIsolatePersistedAuthority()
    {
        var first = SignedArtifact(static index => $"http://10.0.0.{index}/");
        var second = SignedArtifact(static index => $"http://10.0.1.{index}/");
        var firstProfile = DevLocalMembershipTrustBootstrap.CreateProfile(
            first.Artifact,
            first.Bootstrap);
        var secondProfile = DevLocalMembershipTrustBootstrap.CreateProfile(
            second.Artifact,
            second.Bootstrap);
        var store = new InMemorySessionStore();

        var firstProvider = new VerifiedMembershipRouteCatalogProvider(
            TrustService(store),
            store,
            first.Bootstrap,
            DevLocalHttpSource(new SwitchingArtifactHandler(first.Artifact)),
            new InMemoryMembershipRouteArtifactCache(),
            new FrozenTimeProvider(TrustNow),
            MembershipRouteEndpointPolicy.DevLocalHttp);
        var secondProvider = new VerifiedMembershipRouteCatalogProvider(
            TrustService(store),
            store,
            second.Bootstrap,
            DevLocalHttpSource(new SwitchingArtifactHandler(second.Artifact)),
            new InMemoryMembershipRouteArtifactCache(),
            new FrozenTimeProvider(TrustNow),
            MembershipRouteEndpointPolicy.DevLocalHttp);

        _ = await firstProvider.GetCatalogAsync();
        _ = await secondProvider.GetCatalogAsync();
        var firstAuthority = await store.ReadMembershipTrustAsync(
            firstProfile.OpaqueProfileKey,
            MembershipTrustDomain.Authority);
        var secondAuthority = await store.ReadMembershipTrustAsync(
            secondProfile.OpaqueProfileKey,
            MembershipTrustDomain.Authority);

        Assert.NotEqual(firstProfile.OpaqueProfileKey, secondProfile.OpaqueProfileKey);
        Assert.Equal(MembershipTrustReadResult.Found, firstAuthority.Result);
        Assert.Equal(MembershipTrustReadResult.Found, secondAuthority.Result);
        Assert.Equal(firstProfile.OpaqueProfileKey, firstAuthority.Head!.OpaqueProfileKey);
        Assert.Equal(secondProfile.OpaqueProfileKey, secondAuthority.Head!.OpaqueProfileKey);
    }

    [Fact]
    public void DevBootstrap_RejectsExtraOrPrivateFields()
    {
        var fixture = SignedArtifact();
        var root = JsonNode.Parse(fixture.Artifact)!.AsObject();
        root["trustBootstrap"]!.AsObject()["privateKey"] = "must-not-be-accepted";
        var mutated = JsonSerializer.SerializeToUtf8Bytes(
            root,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Throws<MembershipRouteCatalogException>(() =>
            DevLocalMembershipTrustBootstrap.CreateProfile(
                mutated,
                BootstrapFor(mutated)));
    }

    [Theory]
    [InlineData("expectedNetworkId")]
    [InlineData("signedDelegation")]
    public void DevBootstrap_RejectsNonCanonicalBase64(string propertyName)
    {
        var fixture = SignedArtifact();
        var root = JsonNode.Parse(fixture.Artifact)!.AsObject();
        var trust = root["trustBootstrap"]!.AsObject();
        trust[propertyName] = trust[propertyName]!.GetValue<string>() + "\n";
        var mutated = JsonSerializer.SerializeToUtf8Bytes(
            root,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Throws<MembershipRouteCatalogException>(() =>
            DevLocalMembershipTrustBootstrap.CreateProfile(
                mutated,
                BootstrapFor(mutated)));
    }

    [Theory]
    [InlineData("version", "deep-membership-trust-bootstrap-v3")]
    [InlineData("scope", "PRODUCTION")]
    [InlineData("opaqueProfileKey", "install:other-profile")]
    public void DevBootstrap_RejectsUnpinnedFraming(
        string propertyName,
        string value)
    {
        var fixture = SignedArtifact();
        var root = JsonNode.Parse(fixture.Artifact)!.AsObject();
        root["trustBootstrap"]!.AsObject()[propertyName] = value;
        var mutated = JsonSerializer.SerializeToUtf8Bytes(
            root,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Throws<MembershipRouteCatalogException>(() =>
            DevLocalMembershipTrustBootstrap.CreateProfile(
                mutated,
                BootstrapFor(mutated)));
    }

    [Fact]
    public void DevBootstrap_RejectsMalformedUtf8()
    {
        var malformed = new byte[] { (byte)'{', (byte)'"', 0xff, (byte)'"', (byte)'}' };

        Assert.Throws<MembershipRouteCatalogException>(() =>
            DevLocalMembershipTrustBootstrap.CreateProfile(
                malformed,
                BootstrapFor(malformed)));
    }

    [Theory]
    [InlineData("http://203.0.113.10/api/network/membership-route-catalog")]
    [InlineData("http://example.invalid/api/network/membership-route-catalog")]
    [InlineData("http://localhost/api/network/membership-route-catalog")]
    [InlineData("http://0.0.0.0/api/network/membership-route-catalog")]
    [InlineData("http://[::1]/api/network/membership-route-catalog")]
    public void DevHttpCatalog_RejectsRemoteOrNonIpv4Urls(string value)
    {
        Assert.Throws<ArgumentException>(() =>
            HttpMembershipRouteArtifactSource.FromCatalogUrls(
                new HttpClient(),
                [new Uri(value)],
                MembershipRouteEndpointPolicy.DevLocalHttp));
    }

    [Theory]
    [InlineData("http://127.0.0.1/api/network/membership-route-catalog")]
    [InlineData("http://10.20.30.40/api/network/membership-route-catalog")]
    [InlineData("http://172.31.255.254/api/network/membership-route-catalog")]
    [InlineData("http://192.168.50.7/api/network/membership-route-catalog")]
    [InlineData("http://169.254.10.20/api/network/membership-route-catalog")]
    public void DevHttpCatalog_AcceptsExplicitLocalIpv4Ranges(string value)
    {
        Assert.NotNull(HttpMembershipRouteArtifactSource.FromCatalogUrls(
            new HttpClient(),
            [new Uri(value)],
            MembershipRouteEndpointPolicy.DevLocalHttp));
    }

    [Theory]
    [InlineData("https://user:password@registry.example/api/network/membership-route-catalog")]
    [InlineData("https://registry.example/api/network/membership-route-catalog?mirror=1")]
    [InlineData("https://registry.example/api/network/membership-route-catalog#fragment")]
    public void CatalogUrls_RejectCredentialsQueryAndFragment(string value)
    {
        Assert.Throws<ArgumentException>(() =>
            HttpMembershipRouteArtifactSource.FromCatalogUrls(
                new HttpClient(),
                [new Uri(value)]));
    }

    [Fact]
    public async Task DevHttpCatalog_RequiresExplicitPolicyAndExactPath()
    {
        var requests = new List<Uri>();
        using var client = new HttpClient(new ThrowingHandler((request, _) =>
        {
            requests.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent("{}"u8.ToArray())
            });
        }));
        var url = new Uri("http://192.168.50.7/api/network/membership-route-catalog");

        Assert.Throws<ArgumentException>(() =>
            HttpMembershipRouteArtifactSource.FromCatalogUrls(client, [url]));
        Assert.Throws<ArgumentException>(() =>
            HttpMembershipRouteArtifactSource.FromCatalogUrls(
                client,
                [new Uri("http://192.168.50.7/not-the-catalog")],
                MembershipRouteEndpointPolicy.DevLocalHttp));
        Assert.NotNull(HttpMembershipRouteArtifactSource.FromCatalogUrls(
            client,
            [new Uri("https://registry.example/api/network/membership-route-catalog")]));

        var source = HttpMembershipRouteArtifactSource.FromCatalogUrls(
            client,
            [url],
            MembershipRouteEndpointPolicy.DevLocalHttp);
        _ = await source.FetchAsync();

        Assert.Equal(url, Assert.Single(requests));
    }

    [Fact]
    public void DevBootstrapProvider_RequiresExplicitDevLocalPolicy()
    {
        var fixture = SignedArtifact();
        var store = new InMemorySessionStore();
        var source = DevLocalHttpSource(new SwitchingArtifactHandler(fixture.Artifact));

        Assert.Throws<ArgumentException>(() => new VerifiedMembershipRouteCatalogProvider(
            TrustService(store),
            store,
            fixture.Bootstrap,
            source,
            new InMemoryMembershipRouteArtifactCache()));
        Assert.Throws<ArgumentException>(() => new VerifiedMembershipRouteCatalogProvider(
            TrustService(store),
            store,
            fixture.Bootstrap,
            source,
            new InMemoryMembershipRouteArtifactCache(),
            endpointPolicy: MembershipRouteEndpointPolicy.Production));
        Assert.Throws<ArgumentException>(() => new VerifiedMembershipRouteCatalogProvider(
            TrustService(store),
            store,
            fixture.Bootstrap,
            source,
            new InMemoryMembershipRouteArtifactCache(),
            endpointPolicy: new MembershipRouteEndpointPolicy
            {
                AllowDevLocalHttp = true
            }));
    }

    [Theory]
    [InlineData("https://127.0.0.1/api/network/membership-route-catalog")]
    [InlineData("https://registry.example/api/network/membership-route-catalog")]
    [InlineData("http://127.0.0.1:80/api/network/membership-route-catalog")]
    [InlineData("http://127.1/api/network/membership-route-catalog")]
    public void DevBootstrapProvider_RejectsHttpsOrNoncanonicalCatalogSources(string value)
    {
        var fixture = SignedArtifact();
        var store = new InMemorySessionStore();
        var source = HttpMembershipRouteArtifactSource.FromCatalogUrls(
            new HttpClient(),
            [new Uri(value)],
            MembershipRouteEndpointPolicy.DevLocalHttp);

        Assert.Throws<ArgumentException>(() => new VerifiedMembershipRouteCatalogProvider(
            TrustService(store),
            store,
            fixture.Bootstrap,
            source,
            new InMemoryMembershipRouteArtifactCache(),
            endpointPolicy: MembershipRouteEndpointPolicy.DevLocalHttp));
    }

    [Fact]
    public void DevBootstrapProvider_RejectsArbitraryArtifactSource()
    {
        var fixture = SignedArtifact();
        var store = new InMemorySessionStore();

        Assert.Throws<ArgumentException>(() => new VerifiedMembershipRouteCatalogProvider(
            TrustService(store),
            store,
            fixture.Bootstrap,
            new SwitchingArtifactSource(fixture.Artifact),
            new InMemoryMembershipRouteArtifactCache(),
            endpointPolicy: MembershipRouteEndpointPolicy.DevLocalHttp));
    }

    [Fact]
    public async Task DevBootstrapProvider_RejectsRedirectAwayFromExactLocalCatalogUrl()
    {
        var fixture = SignedArtifact();
        var store = new InMemorySessionStore();
        using var client = new HttpClient(new ThrowingHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(fixture.Artifact),
                RequestMessage = new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://public.example/api/network/membership-route-catalog")
            })));
        var source = HttpMembershipRouteArtifactSource.FromCatalogUrls(
            client,
            [new Uri("http://127.0.0.1/api/network/membership-route-catalog")],
            MembershipRouteEndpointPolicy.DevLocalHttp);
        var provider = new VerifiedMembershipRouteCatalogProvider(
            TrustService(store),
            store,
            fixture.Bootstrap,
            source,
            new InMemoryMembershipRouteArtifactCache(),
            endpointPolicy: MembershipRouteEndpointPolicy.DevLocalHttp);

        await Assert.ThrowsAsync<MembershipRouteDirectoryUnavailableException>(
            () => provider.GetCatalogAsync());
    }

    [Fact]
    public async Task VerifiedProvider_AcceptsHttpsProductionCatalogAndAllSixQuorumMembers()
    {
        var fixture = SignedArtifact(static index => $"https://node-{index}.example/");
        var store = new InMemorySessionStore();
        var provider = ProductionProvider(
            fixture,
            store,
            MembershipRouteEndpointPolicy.Production);

        var catalog = await provider.GetCatalogAsync();
        var first = MembershipRouteSelector.Select(
            catalog,
            Enumerable.Repeat((byte)11, 32).ToArray());
        var excluded = first.Select(Id).ToHashSet(StringComparer.Ordinal);
        var second = MembershipRouteSelector.Select(
            catalog,
            Enumerable.Repeat((byte)12, 32).ToArray(),
            excluded);

        Assert.Equal(6, catalog.Members.Count);
        Assert.Equal(3, first.Count);
        Assert.Equal(3, second.Count);
        Assert.Empty(first.Select(Id).Intersect(second.Select(Id), StringComparer.Ordinal));
    }

    [Fact]
    public async Task VerifiedProvider_RejectsEquivalentDefaultPortOrigins()
    {
        var fixture = SignedArtifact(index => index switch
        {
            1 => "https://duplicate.example/",
            2 => "https://duplicate.example:443",
            _ => $"https://node-{index}.example/"
        });
        var store = new InMemorySessionStore();
        var provider = ProductionProvider(
            fixture,
            store,
            MembershipRouteEndpointPolicy.Production);

        await Assert.ThrowsAsync<MembershipRouteCatalogException>(
            () => provider.GetCatalogAsync());
    }

    [Fact]
    public void MembershipRoutePackage_IsExactLocalPinnedArtifact()
    {
        var root = P14A2PackageAndStaticGateTests.RepositoryRoot();
        var package = Path.Combine(
            root,
            "vendor",
            "production-2eb8b1e",
            "packages",
            "Deep.Protocol.MembershipRoutes.0.4.0-production.2eb8b1e.nupkg");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "vendor", "production-2eb8b1e", "package-manifest.json")));
        var packageEntry = Assert.Single(
            manifest.RootElement.GetProperty("packages").EnumerateArray(),
            entry => entry.GetProperty("id").GetString() ==
                "Deep.Protocol.MembershipRoutes");
        var expectedHash = packageEntry.GetProperty("sha256").GetString();

        Assert.Equal(175_350, new FileInfo(package).Length);
        Assert.Equal(
            expectedHash,
            Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(package))));
        Assert.Equal(
            "2eb8b1eb4605216b239f63d1ad8e587a28918134",
            manifest.RootElement.GetProperty("sourceCommit").GetString());

        foreach (var relative in new[]
                 {
                     Path.Combine("src", "Deep.Client.Shared", "packages.lock.json"),
                     Path.Combine("tests", "Deep.Client.Shared.Tests", "packages.lock.json")
                 })
        {
            using var locked = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, relative)));
            var dependency = locked.RootElement.GetProperty("dependencies").GetProperty("net10.0")
                .GetProperty("Deep.Protocol.MembershipRoutes");
            Assert.Equal(
                "0.4.0-production.2eb8b1e",
                dependency.GetProperty("resolved").GetString());
            Assert.Equal(
                "/b9lgdmor/rVftS9Y9ZsnRdZZo9eRt5dbXE40YoJBZd2E4jMcucqyMArEb+dG7DDcpfutRU6aE4gNO0LQTmLOA==",
                dependency.GetProperty("contentHash").GetString());
        }
    }

    private static MembershipRouteCatalogSnapshot Catalog()
    {
        var members = Enumerable.Range(1, 6)
            .Select(index => new MembershipRouteCatalogMember(
                new MembershipRouteDescriptor
                {
                    RouterId = Bytes(index),
                    Ed25519PublicKey = Bytes(index),
                    X25519PublicKey = Bytes(index + 64),
                    RpcEndpoint = $"http://10.0.0.{index}/",
                    Roles = MembershipRouteRole.Ingress |
                            MembershipRouteRole.Core |
                            MembershipRouteRole.Storage,
                    Capabilities = MembershipRouteCapability.SessionRpc |
                                   MembershipRouteCapability.OnionV1 |
                                   MembershipRouteCapability.Storage,
                    Epoch = 10,
                    ValidFromUnixSeconds = 1_700_000_000,
                    ValidUntilUnixSeconds = 1_900_000_000
                },
                new MembershipRouteInclusionProof
                {
                    LeafIndex = checked((uint)(index - 1)),
                    MemberCount = 6,
                    SiblingHashes = []
                }))
            .ToArray();
        return new MembershipRouteCatalogSnapshot(
            10,
            DateTimeOffset.FromUnixTimeSeconds(1_900_000_000),
            members,
            SHA256.HashData("membership"u8))
        {
            EndpointPolicy = MembershipRouteEndpointPolicy.DevLocalHttp
        };
    }

    private static (
        byte[] Artifact,
        MembershipTrustProfile Profile,
        DevLocalMembershipTrustBootstrapOptions Bootstrap) SignedArtifact(
            Func<int, string>? endpoint = null)
    {
        endpoint ??= static index => $"http://10.0.0.{index}/";
        var membershipTemplate = MembershipContractCodec.DecodeSignedMembership(
            MembershipTrustServiceTests.Vector("deep-extension/membership/v1/signed-membership"));
        var delegation = MembershipContractCodec.DecodeSignedDelegation(
            MembershipTrustServiceTests.Vector("deep-extension/membership/v1/signed-delegation"));
        var genesisBytes = MembershipTrustServiceTests.Vector(
            "deep-extension/membership/v1/network-genesis");
        var genesis = MembershipContractCodec.DecodeGenesis(genesisBytes);
        var descriptors = Enumerable.Range(1, 6).Select(index => new MembershipRouteDescriptor
        {
            RouterId = Bytes(index),
            Ed25519PublicKey = Bytes(index),
            X25519PublicKey = Bytes(index + 64),
            RpcEndpoint = endpoint(index),
            Roles = MembershipRouteRole.Ingress |
                    MembershipRouteRole.Core |
                    MembershipRouteRole.Storage,
            Capabilities = MembershipRouteCapability.SessionRpc |
                           MembershipRouteCapability.OnionV1 |
                           MembershipRouteCapability.Storage,
            Epoch = delegation.Sequence + 1,
            ValidFromUnixSeconds = membershipTemplate.Statement.ValidFromUnixSeconds,
            ValidUntilUnixSeconds = membershipTemplate.Statement.ValidUntilUnixSeconds
        }).ToArray();
        var statement = membershipTemplate.Statement with
        {
            Sequence = delegation.Sequence + 1,
            PreviousHash = MembershipContractHash.Sha256(
                MembershipContractCodec.GetDelegationSigningBytes(delegation)),
            MemberCount = checked((uint)descriptors.Length),
            MerkleRoot = MembershipRouteDescriptorCodec.ComputeRoot(descriptors)
        };
        var verifier = new MembershipTrustServiceTests.FixtureMembershipVerifier();
        var signingBytes = MembershipContractCodec.GetMembershipSigningBytes(statement);
        var signed = new SignedMembershipCommitment
        {
            Statement = statement,
            Signatures = delegation.OnlineSigners.Take(2).Select(signer => new MembershipSignature
            {
                SignerId = signer.SignerId.ToArray(),
                Domain = MembershipSignatureDomain.Membership,
                Signature = verifier.Sign(
                    signer.SignerId.Span,
                    signer.PublicKey.Span,
                    MembershipSignatureDomain.Membership,
                    signingBytes)
            }).ToArray()
        };
        var proofs = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
        var profile = new MembershipTrustProfile(
            DevLocalMembershipTrustBootstrap.OpaqueProfileKeyBase,
            genesisBytes,
            genesis.NetworkId.ToArray(),
            MembershipContractHash.Sha256(genesisBytes),
            MembershipTrustServiceTests.Vector("deep-extension/membership/v1/signed-delegation"),
            new MembershipTrustAnchor(delegation.Sequence, statement.PreviousHash.ToArray()),
            new MembershipTrustAnchor(delegation.Sequence, statement.PreviousHash.ToArray()));
        var artifact = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = "deep-membership-route-catalog-v1",
            trustBootstrap = new
            {
                version = DevLocalMembershipTrustBootstrap.Version,
                scope = DevLocalMembershipTrustBootstrap.Scope,
                opaqueProfileKey = profile.OpaqueProfileKey,
                canonicalGenesis = Convert.ToBase64String(profile.CanonicalGenesis),
                expectedNetworkId = Convert.ToBase64String(profile.ExpectedNetworkId),
                expectedCanonicalGenesisSha256 =
                    Convert.ToBase64String(profile.ExpectedCanonicalGenesisSha256),
                signedDelegation = Convert.ToBase64String(profile.SignedDelegation),
                bridgeAnchor = new
                {
                    sequence = profile.BridgeAnchor!.Sequence,
                    canonicalHash = Convert.ToBase64String(profile.BridgeAnchor.CanonicalHash)
                },
                membershipAnchor = new
                {
                    sequence = profile.MembershipAnchor!.Sequence,
                    canonicalHash = Convert.ToBase64String(profile.MembershipAnchor.CanonicalHash)
                }
            },
            signedMembership = Convert.ToBase64String(
                MembershipContractCodec.EncodeSignedMembership(signed)),
            members = descriptors.Select((descriptor, index) => new
            {
                leaf = Convert.ToBase64String(MembershipRouteDescriptorCodec.Encode(descriptor)),
                leafIndex = proofs[index].LeafIndex,
                memberCount = proofs[index].MemberCount,
                siblingHashes = proofs[index].SiblingHashes.Select(
                    static value => Convert.ToBase64String(value.Span)).ToArray()
            }).ToArray()
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return (artifact, profile, BootstrapFor(artifact, profile.OpaqueProfileKey));
    }

    private static DevLocalMembershipTrustBootstrapOptions BootstrapFor(
        byte[] artifact,
        string profileKey = DevLocalMembershipTrustBootstrap.OpaqueProfileKeyBase) =>
        new(Convert.ToHexStringLower(SHA256.HashData(artifact)), profileKey);

    private static VerifiedMembershipRouteCatalogProvider ProductionProvider(
        (
            byte[] Artifact,
            MembershipTrustProfile Profile,
            DevLocalMembershipTrustBootstrapOptions Bootstrap) fixture,
        InMemorySessionStore store,
        MembershipRouteEndpointPolicy endpointPolicy) =>
        new(
            TrustService(store),
            store,
            fixture.Profile,
            new SwitchingArtifactSource(RemoveTrustBootstrap(fixture.Artifact)),
            new InMemoryMembershipRouteArtifactCache(),
            new FrozenTimeProvider(TrustNow),
            endpointPolicy);

    private static MembershipTrustService TrustService(InMemorySessionStore store) =>
        new(
            store,
            new MembershipTrustServiceTests.FixtureMembershipVerifier(),
            new FrozenClock(TrustNow),
            MembershipTrustOptions.DormantDefaults with
            {
                Enabled = true,
                AllowedClockSkew = TimeSpan.FromSeconds(30),
                ClockRollbackTolerance = TimeSpan.FromSeconds(30)
            });

    private static HttpMembershipRouteArtifactSource DevLocalHttpSource(
        SwitchingArtifactHandler handler) =>
        HttpMembershipRouteArtifactSource.FromCatalogUrls(
            new HttpClient(handler),
            [new Uri("http://127.0.0.1/api/network/membership-route-catalog")],
            MembershipRouteEndpointPolicy.DevLocalHttp);

    private static byte[] RemoveTrustBootstrap(byte[] artifact)
    {
        var root = JsonNode.Parse(artifact)!.AsObject();
        Assert.True(root.Remove("trustBootstrap"));
        return JsonSerializer.SerializeToUtf8Bytes(
            root,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
    }

    private static string Id(MembershipRouteCatalogMember member) =>
        Convert.ToHexStringLower(member.Descriptor.RouterId.Span);

    private static byte[] Bytes(int start) =>
        Enumerable.Range(start, MembershipRouteDescriptorCodec.KeyLength)
            .Select(static value => checked((byte)value))
            .ToArray();

    private sealed class StaticCatalogProvider(MembershipRouteCatalogSnapshot catalog)
        : IMembershipRouteCatalogProvider
    {
        public Task<MembershipRouteCatalogSnapshot> GetCatalogAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(catalog);
        }
    }

    private sealed class RecordingRouteEvidenceObserver : ITransportRouteEvidenceObserver
    {
        public List<TransportRouteEvidence> Events { get; } = [];

        public void Observe(TransportRouteEvidence evidence) => Events.Add(evidence);
    }

    private sealed class ConcurrentRouteEvidenceObserver : ITransportRouteEvidenceObserver
    {
        public ConcurrentQueue<TransportRouteEvidence> Events { get; } = new();

        public void Observe(TransportRouteEvidence evidence) => Events.Enqueue(evidence);
    }

    private sealed class ThrowingRouteEvidenceObserver : ITransportRouteEvidenceObserver
    {
        public void Observe(TransportRouteEvidence evidence) =>
            throw new InvalidOperationException("observer failure");
    }

    private sealed class ThrowingHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => handler(request, cancellationToken);
    }

    private sealed class SwitchingArtifactSource(byte[] artifact) : IMembershipRouteArtifactSource
    {
        public byte[] Artifact { get; set; } = artifact;
        public bool Unavailable { get; set; }

        public Task<byte[]> FetchAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Unavailable)
                throw new MembershipRouteDirectoryUnavailableException("fixture outage");
            return Task.FromResult(Artifact.ToArray());
        }
    }

    private sealed class SwitchingArtifactHandler(byte[] artifact) : HttpMessageHandler
    {
        public byte[] Artifact { get; set; } = artifact;
        public bool Unavailable { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Unavailable)
                throw new HttpRequestException("fixture outage");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(Artifact.ToArray()),
                RequestMessage = request
            });
        }
    }

    private sealed class FrozenTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
