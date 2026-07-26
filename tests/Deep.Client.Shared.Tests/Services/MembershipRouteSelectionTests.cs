using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
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
    public async Task MembershipStore_DispatchesDirectlyWithoutRouteOrExclusionDisclosure()
    {
        var requests = new List<string>();
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
            membershipRouteCatalogProvider: new StaticCatalogProvider(catalog));

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
        var source = new SwitchingArtifactSource(fixture.Artifact);
        var cache = new InMemoryMembershipRouteArtifactCache();
        var provider = new VerifiedMembershipRouteCatalogProvider(
            trust,
            store,
            fixture.Profile,
            source,
            cache,
            new FrozenTimeProvider(TrustNow));

        var fresh = await provider.GetCatalogAsync();
        source.Unavailable = true;
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
        var providerSource = new SwitchingArtifactSource(fixture.Artifact);
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
            fixture.Profile,
            providerSource,
            new InMemoryMembershipRouteArtifactCache(),
            new FrozenTimeProvider(TrustNow));

        _ = await provider.GetCatalogAsync();
        providerSource.Artifact = "{ \"version\": \"unsigned\" }"u8.ToArray();

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
            "p15",
            "packages",
            "Deep.Protocol.MembershipRoutes.0.1.0-p15.local.nupkg");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "vendor", "p15", "package-manifest.json")));
        var expectedHash = manifest.RootElement.GetProperty("packageSha256").GetString();

        Assert.Equal(12_064, new FileInfo(package).Length);
        Assert.Equal(
            expectedHash,
            Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(package))));
        Assert.Equal(
            "f224a96d3208c8f85989375b56d322191e71f4e5",
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
            Assert.Equal("0.1.0-p15.local", dependency.GetProperty("resolved").GetString());
            Assert.Equal(
                "ejxZx+b4Um6rd8NrUdUhPKdPYSxYPmkOVa6G/RsAjnHuwEfce7IZXTt5tu5LbSAmM5QfM2gH0vNt35wDwvLKiQ==",
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
                    RpcEndpoint = $"http://node-{index}.invalid/",
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
            SHA256.HashData("membership"u8));
    }

    private static (byte[] Artifact, MembershipTrustProfile Profile) SignedArtifact()
    {
        var membershipTemplate = MembershipContractCodec.DecodeSignedMembership(
            MembershipTrustServiceTests.Vector("deep-extension/membership/v1/signed-membership"));
        var delegation = MembershipContractCodec.DecodeSignedDelegation(
            MembershipTrustServiceTests.Vector("deep-extension/membership/v1/signed-delegation"));
        var bridge = MembershipContractCodec.DecodeSignedBridge(
            MembershipTrustServiceTests.Vector("deep-extension/membership/v1/signed-bridge"));
        var genesisBytes = MembershipTrustServiceTests.Vector(
            "deep-extension/membership/v1/network-genesis");
        var genesis = MembershipContractCodec.DecodeGenesis(genesisBytes);
        var descriptors = Enumerable.Range(1, 6).Select(index => new MembershipRouteDescriptor
        {
            RouterId = Bytes(index),
            Ed25519PublicKey = Bytes(index),
            X25519PublicKey = Bytes(index + 64),
            RpcEndpoint = $"http://node-{index}.invalid/",
            Roles = MembershipRouteRole.Ingress |
                    MembershipRouteRole.Core |
                    MembershipRouteRole.Storage,
            Capabilities = MembershipRouteCapability.SessionRpc |
                           MembershipRouteCapability.OnionV1 |
                           MembershipRouteCapability.Storage,
            Epoch = membershipTemplate.Statement.Sequence,
            ValidFromUnixSeconds = membershipTemplate.Statement.ValidFromUnixSeconds,
            ValidUntilUnixSeconds = membershipTemplate.Statement.ValidUntilUnixSeconds
        }).ToArray();
        var statement = membershipTemplate.Statement with
        {
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
        var artifact = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = "deep-membership-route-catalog-v1",
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
        var profile = new MembershipTrustProfile(
            "install:membership-route-test",
            genesisBytes,
            genesis.NetworkId.ToArray(),
            MembershipContractHash.Sha256(genesisBytes),
            MembershipTrustServiceTests.Vector("deep-extension/membership/v1/signed-delegation"),
            new MembershipTrustAnchor(
                bridge.Statement.Sequence - 1,
                bridge.Statement.PreviousHash.ToArray()),
            new MembershipTrustAnchor(
                statement.Sequence - 1,
                statement.PreviousHash.ToArray()));
        return (artifact, profile);
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

    private sealed class FrozenTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
