using System.Security.Cryptography;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Client.Shared.Tests.Services;

public sealed class MembershipTrustServiceTests
{
    private static readonly DateTimeOffset FixtureNow = DateTimeOffset.FromUnixTimeSeconds(1010);

    [Fact]
    public async Task DisabledAndMissingVerifier_FailClosedWithoutLegacyEligibility()
    {
        var profile = FixtureProfile();
        var disabled = new MembershipTrustService(
            new InMemorySessionStore(),
            new FixtureMembershipVerifier(),
            new FrozenClock(FixtureNow),
            MembershipTrustOptions.DormantDefaults);
        var disabledStatus = await disabled.InitializeAsync(profile);
        Assert.Equal(MembershipTrustState.Disabled, disabledStatus.State);
        Assert.False(disabledStatus.LegacyRollbackEligible);

        var enabledWithoutVerifier = new MembershipTrustService(
            new InMemorySessionStore(),
            verifier: null,
            new FrozenClock(FixtureNow),
            EnabledOptions());
        var missingVerifier = await enabledWithoutVerifier.InitializeAsync(profile);
        Assert.Equal(MembershipTrustState.VerifierUnavailable, missingVerifier.State);
        Assert.False(missingVerifier.LegacyRollbackEligible);
    }

    [Fact]
    public async Task CanonicalFixtureBootstrapAndIndependentContentTracks_AreHealthy()
    {
        var store = new InMemorySessionStore();
        var service = Service(store);
        var profile = FixtureProfile();

        Assert.Equal(MembershipTrustState.Healthy, (await service.InitializeAsync(profile)).State);
        Assert.Equal(
            MembershipTrustState.Healthy,
            (await service.ApplyMembershipAsync(profile, Vector("deep-extension/membership/v1/signed-membership"))).State);
        Assert.Equal(
            MembershipTrustState.Healthy,
            (await service.ApplyBridgeAsync(profile, Vector("deep-extension/membership/v1/signed-bridge"))).State);

        var authority = await store.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority);
        var bridge = await store.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Bridge);
        var membership = await store.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Membership);

        Assert.Equal(2UL, authority.Head!.Sequence);
        Assert.Equal(7UL, bridge.Head!.Sequence);
        Assert.Equal(7UL, membership.Head!.Sequence);
        Assert.NotEqual(bridge.Head.PayloadDigestHex, membership.Head.PayloadDigestHex);
    }

    [Theory]
    [InlineData("deep-extension/membership/v1/signed-membership", MembershipTrustState.Corrupt)]
    [InlineData("deep-extension/membership/v1/signed-bridge", MembershipTrustState.Corrupt)]
    public async Task TruncatedOrTrailingCanonicalEnvelope_FailsClosed(
        string vectorId,
        MembershipTrustState expected)
    {
        var profile = FixtureProfile();
        var service = Service(new InMemorySessionStore());
        _ = await service.InitializeAsync(profile);
        var canonical = Vector(vectorId);

        var truncated = canonical[..^1];
        var trailing = canonical.Concat(new byte[] { 0 }).ToArray();
        var first = vectorId.EndsWith("membership", StringComparison.Ordinal)
            ? await service.ApplyMembershipAsync(profile, truncated)
            : await service.ApplyBridgeAsync(profile, truncated);
        var second = vectorId.EndsWith("membership", StringComparison.Ordinal)
            ? await service.ApplyMembershipAsync(profile, trailing)
            : await service.ApplyBridgeAsync(profile, trailing);

        Assert.Equal(expected, first.State);
        Assert.Equal(expected, second.State);
        Assert.False(first.LegacyRollbackEligible);
        Assert.False(second.LegacyRollbackEligible);
    }

    [Fact]
    public async Task BadDomainOneSignerWrongNetworkAndProtocol_FailClosed()
    {
        var verifier = new FixtureMembershipVerifier();
        var profile = FixtureProfile();
        var service = Service(new InMemorySessionStore(), verifier);
        _ = await service.InitializeAsync(profile);

        var canonical = Vector("deep-extension/membership/v1/signed-membership");
        var signed = MembershipContractCodec.DecodeSignedMembership(canonical);
        var oneSigner = signed with { Signatures = [signed.Signatures[0]] };
        var oneSignerStatus = await service.ApplyMembershipAsync(
            profile,
            MembershipContractCodec.EncodeSignedMembership(oneSigner));
        Assert.Equal(MembershipTrustState.ProtocolUnsupported, oneSignerStatus.State);

        var invalidSignatureBytes = signed.Signatures[0].Signature.ToArray();
        invalidSignatureBytes[0] ^= 0xff;
        var badSignature = signed with
        {
            Signatures =
            [
                signed.Signatures[0] with { Signature = invalidSignatureBytes },
                signed.Signatures[1]
            ]
        };
        var invalidSignatureStatus = await service.ApplyMembershipAsync(
            profile,
            MembershipContractCodec.EncodeSignedMembership(badSignature));
        Assert.Equal(MembershipTrustState.ProtocolUnsupported, invalidSignatureStatus.State);

        var wrongDomain = ResignMembership(
            signed.Statement,
            signed.Signatures,
            MembershipSignatureDomain.Bridge,
            verifier);
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.EncodeSignedMembership(wrongDomain));

        var wrongNetworkStatement = signed.Statement with
        {
            NetworkId = Enumerable.Repeat((byte)0x42, MembershipLimits.NetworkIdLength).ToArray()
        };
        var wrongNetwork = ResignMembership(
            wrongNetworkStatement,
            signed.Signatures,
            MembershipSignatureDomain.Membership,
            verifier);
        Assert.Equal(
            MembershipTrustState.ProtocolUnsupported,
            (await service.ApplyMembershipAsync(
                profile,
                MembershipContractCodec.EncodeSignedMembership(wrongNetwork))).State);

        var wrongProtocolStatement = signed.Statement with { MinimumProtocol = 9, MaximumProtocol = 10 };
        var wrongProtocol = ResignMembership(
            wrongProtocolStatement,
            signed.Signatures,
            MembershipSignatureDomain.Membership,
            verifier);
        Assert.Equal(
            MembershipTrustState.ProtocolUnsupported,
            (await service.ApplyMembershipAsync(
                profile,
                MembershipContractCodec.EncodeSignedMembership(wrongProtocol))).State);
    }

    [Fact]
    public async Task SameSequenceDifferentValidCandidate_PersistsForkAndNeverChoosesByArrival()
    {
        var verifier = new FixtureMembershipVerifier();
        var store = new InMemorySessionStore();
        var profile = FixtureProfile();
        var service = Service(store, verifier);
        _ = await service.InitializeAsync(profile);

        var firstBytes = Vector("deep-extension/membership/v1/signed-membership");
        Assert.Equal(
            MembershipTrustState.Healthy,
            (await service.ApplyMembershipAsync(profile, firstBytes)).State);
        var first = MembershipContractCodec.DecodeSignedMembership(firstBytes);
        var alternateStatement = first.Statement with
        {
            MemberCount = first.Statement.MemberCount + 1,
            MerkleRoot = SHA256.HashData(first.Statement.MerkleRoot.Span)
        };
        var alternate = ResignMembership(
            alternateStatement,
            first.Signatures,
            MembershipSignatureDomain.Membership,
            verifier);

        var fork = await service.ApplyMembershipAsync(
            profile,
            MembershipContractCodec.EncodeSignedMembership(alternate));
        Assert.Equal(MembershipTrustState.ForkDetected, fork.State);
        Assert.False(fork.Usable);
        Assert.False(fork.LegacyRollbackEligible);

        var afterRestart = Service(store, verifier);
        Assert.Equal(
            MembershipTrustState.ForkDetected,
            (await afterRestart.EvaluateAsync(profile)).State);
    }

    [Fact]
    public async Task ClockRollbackAndRevocation_AreBlocking()
    {
        var clock = new MutableClock(FixtureNow);
        var store = new InMemorySessionStore();
        var profile = FixtureProfile();
        var service = new MembershipTrustService(store, new FixtureMembershipVerifier(), clock, EnabledOptions());
        _ = await service.InitializeAsync(profile);

        clock.UtcNow = FixtureNow.AddMinutes(-10);
        var rollback = await service.EvaluateAsync(profile);
        Assert.Equal(MembershipTrustState.ClockRollback, rollback.State);
        Assert.False(rollback.LegacyRollbackEligible);

        clock.UtcNow = FixtureNow;
        var revoked = await service.ApplyRevocationAsync(
            profile,
            Vector("deep-extension/membership/v1/signed-revocation"));
        Assert.Equal(MembershipTrustState.Revoked, revoked.State);
        Assert.False(revoked.Usable);
    }

    [Fact]
    public async Task SelfHostedGenesis_RequiresExactIndependentPinsAndSignatures()
    {
        var verifier = new FixtureMembershipVerifier();
        var service = Service(new InMemorySessionStore(), verifier);
        var genesisBytes = Vector("deep-extension/membership/v1/network-genesis");
        var genesis = MembershipContractCodec.DecodeGenesis(genesisBytes);
        var signatures = genesis.OfflineRoots.Take(3).Select(root => new MembershipSignature
        {
            SignerId = root.SignerId.ToArray(),
            Domain = MembershipSignatureDomain.Genesis,
            Signature = verifier.Sign(
                root.SignerId.Span,
                root.PublicKey.Span,
                MembershipSignatureDomain.Genesis,
                genesisBytes)
        }).ToArray();

        var imported = await service.ImportSelfHostedGenesisAsync(new SelfHostedGenesisImport(
            OpaqueProfileKey: "install:self-hosted:test",
            CanonicalGenesis: genesisBytes,
            ExpectedNetworkId: genesis.NetworkId.ToArray(),
            ExpectedCanonicalGenesisSha256: MembershipContractHash.Sha256(genesisBytes),
            CanonicalSignatures: EncodeGenesisSignatures(signatures)));
        Assert.Equal(MembershipTrustState.MissingBootstrap, imported.State);

        var wrongPin = await service.ImportSelfHostedGenesisAsync(new SelfHostedGenesisImport(
            OpaqueProfileKey: "install:self-hosted:isolated",
            CanonicalGenesis: genesisBytes,
            ExpectedNetworkId: Enumerable.Repeat((byte)1, MembershipLimits.NetworkIdLength).ToArray(),
            ExpectedCanonicalGenesisSha256: MembershipContractHash.Sha256(genesisBytes),
            CanonicalSignatures: EncodeGenesisSignatures(signatures)));
        Assert.Equal(MembershipTrustState.ProtocolUnsupported, wrongPin.State);
        Assert.False(wrongPin.LegacyRollbackEligible);
    }

    [Fact]
    public async Task ExistingState_RejectsDelegationAndAnchorSubstitution()
    {
        var verifier = new FixtureMembershipVerifier();
        var store = new InMemorySessionStore();
        var profile = FixtureProfile();
        var service = Service(store, verifier);
        Assert.Equal(MembershipTrustState.Healthy, (await service.InitializeAsync(profile)).State);

        var substitutedDelegation = CreateDelegation(
            profile,
            verifier,
            sequence: 2,
            previousHash: MembershipContractHash.Sha256(profile.CanonicalGenesis),
            keyOffset: 7);
        var delegationSubstitution = profile with { SignedDelegation = substitutedDelegation };
        Assert.NotEqual(
            MembershipTrustState.Healthy,
            (await service.InitializeAsync(delegationSubstitution)).State);
        Assert.NotEqual(
            MembershipTrustState.Healthy,
            (await service.EvaluateAsync(delegationSubstitution)).State);

        var anchorSubstitution = profile with
        {
            MembershipAnchor = profile.MembershipAnchor! with
            {
                CanonicalHash = Enumerable.Repeat((byte)0x66, MembershipLimits.HashLength).ToArray()
            }
        };
        Assert.NotEqual(
            MembershipTrustState.Healthy,
            (await service.InitializeAsync(anchorSubstitution)).State);
        Assert.NotEqual(
            MembershipTrustState.Healthy,
            (await service.EvaluateAsync(anchorSubstitution)).State);
    }

    [Fact]
    public async Task RootSignedDelegation_RotatesFromHealthyAndAfterRevocation()
    {
        var verifier = new FixtureMembershipVerifier();
        var profile = FixtureProfile();

        var healthyStore = new InMemorySessionStore();
        var healthyService = Service(healthyStore, verifier);
        _ = await healthyService.InitializeAsync(profile);
        var authority = (await healthyStore.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority)).Head!;
        var rotation = CreateDelegation(
            profile,
            verifier,
            sequence: 3,
            previousHash: authority.CanonicalHash,
            keyOffset: 9);
        Assert.Equal(
            MembershipTrustState.Healthy,
            (await healthyService.ApplyDelegationAsync(profile, rotation)).State);

        var revokedStore = new InMemorySessionStore();
        var revokedService = Service(revokedStore, verifier);
        _ = await revokedService.InitializeAsync(profile);
        Assert.Equal(
            MembershipTrustState.Revoked,
            (await revokedService.ApplyRevocationAsync(
                profile,
                Vector("deep-extension/membership/v1/signed-revocation"))).State);
        var revokedHead = (await revokedStore.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority)).Head!;
        var recovery = CreateDelegation(
            profile,
            verifier,
            sequence: 4,
            previousHash: revokedHead.CanonicalHash,
            keyOffset: 11);
        Assert.Equal(
            MembershipTrustState.Healthy,
            (await revokedService.ApplyDelegationAsync(profile, recovery)).State);
        Assert.Equal(
            4UL,
            (await revokedStore.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                MembershipTrustDomain.Authority)).Head!.Sequence);
    }

    [Fact]
    public async Task RotatedAuthority_SurvivesOriginalBootstrapExpiryAndRestart()
    {
        var verifier = new FixtureMembershipVerifier();
        var clock = new MutableClock(FixtureNow);
        var store = new InMemorySessionStore();
        var profile = FixtureProfile();
        var service = new MembershipTrustService(store, verifier, clock, EnabledOptions());
        _ = await service.InitializeAsync(profile);
        var head = (await store.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority)).Head!;
        var rotation = CreateDelegation(
            profile,
            verifier,
            sequence: 3,
            previousHash: head.CanonicalHash,
            keyOffset: 13,
            validUntil: 3000);
        Assert.Equal(
            MembershipTrustState.Healthy,
            (await service.ApplyDelegationAsync(profile, rotation)).State);

        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1500);
        var restarted = new MembershipTrustService(
            store,
            verifier,
            clock,
            EnabledOptions());
        Assert.Equal(
            MembershipTrustState.Healthy,
            (await restarted.InitializeAsync(profile)).State);
        var successor = CreateDelegation(
            profile,
            verifier,
            sequence: 4,
            previousHash: (await store.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                MembershipTrustDomain.Authority)).Head!.CanonicalHash,
            keyOffset: 15,
            validFrom: 1400,
            validUntil: 3200);
        Assert.Equal(
            MembershipTrustState.Healthy,
            (await restarted.ApplyDelegationAsync(profile, successor)).State);
    }

    [Fact]
    public async Task AuthorityDelegationEquivocation_PersistsForkAcrossRestart()
    {
        var verifier = new FixtureMembershipVerifier();
        var store = new InMemorySessionStore();
        var profile = FixtureProfile();
        var service = Service(store, verifier);
        _ = await service.InitializeAsync(profile);
        var predecessor = (await store.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority)).Head!;
        var first = CreateDelegation(
            profile, verifier, 3, predecessor.CanonicalHash, 17);
        var second = CreateDelegation(
            profile, verifier, 3, predecessor.CanonicalHash, 19);
        Assert.Equal(MembershipTrustState.Healthy, (await service.ApplyDelegationAsync(profile, first)).State);
        Assert.Equal(MembershipTrustState.ForkDetected, (await service.ApplyDelegationAsync(profile, second)).State);
        Assert.Equal(
            MembershipTrustState.ForkDetected,
            (await Service(store, verifier).InitializeAsync(profile)).State);
    }

    [Fact]
    public async Task AuthorityDelegationRevocationEquivocation_PersistsForkAcrossRestart()
    {
        var verifier = new FixtureMembershipVerifier();
        var store = new InMemorySessionStore();
        var profile = FixtureProfile();
        var service = Service(store, verifier);
        _ = await service.InitializeAsync(profile);
        var predecessor = (await store.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority)).Head!;
        var delegation = CreateDelegation(
            profile, verifier, 3, predecessor.CanonicalHash, 21);

        Assert.Equal(
            MembershipTrustState.Healthy,
            (await service.ApplyDelegationAsync(profile, delegation)).State);
        Assert.Equal(
            MembershipTrustState.ForkDetected,
            (await service.ApplyRevocationAsync(
                profile,
                Vector("deep-extension/membership/v1/signed-revocation"))).State);
        Assert.Equal(
            MembershipTrustState.ForkDetected,
            (await Service(store, verifier).InitializeAsync(profile)).State);
    }

    [Fact]
    public async Task ConcurrentAuthorityDelegationAndRevocation_PersistFork()
    {
        var verifier = new FixtureMembershipVerifier();
        var store = new InMemorySessionStore();
        var profile = FixtureProfile();
        var service = Service(store, verifier);
        _ = await service.InitializeAsync(profile);
        var predecessor = (await store.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority)).Head!;
        var delegation = CreateDelegation(
            profile, verifier, 3, predecessor.CanonicalHash, 25);

        var results = await Task.WhenAll(
            service.ApplyDelegationAsync(profile, delegation),
            service.ApplyRevocationAsync(
                profile,
                Vector("deep-extension/membership/v1/signed-revocation")));

        Assert.Contains(results, status => status.State == MembershipTrustState.ForkDetected);
        Assert.Equal(
            MembershipTrustState.ForkDetected,
            (await Service(store, verifier).InitializeAsync(profile)).State);
    }

    [Fact]
    public async Task RevokedThenRotatedAuthority_RestartsAfterOriginalExpiry()
    {
        var verifier = new FixtureMembershipVerifier();
        var clock = new MutableClock(FixtureNow);
        var store = new InMemorySessionStore();
        var profile = FixtureProfile();
        var service = new MembershipTrustService(store, verifier, clock, EnabledOptions());
        _ = await service.InitializeAsync(profile);
        Assert.Equal(
            MembershipTrustState.Revoked,
            (await service.ApplyRevocationAsync(
                profile,
                Vector("deep-extension/membership/v1/signed-revocation"))).State);
        var revoked = (await store.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority)).Head!;
        Assert.Equal(
            MembershipTrustState.Healthy,
            (await service.ApplyDelegationAsync(
                profile,
                CreateDelegation(
                    profile,
                    verifier,
                    4,
                    revoked.CanonicalHash,
                    27,
                    validFrom: 1000,
                    validUntil: 3000))).State);

        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1500);
        Assert.Equal(
            MembershipTrustState.Healthy,
            (await new MembershipTrustService(
                store,
                verifier,
                clock,
                EnabledOptions()).InitializeAsync(profile)).State);
    }

    [Fact]
    public async Task RestartCryptographicallyRevalidatesPersistedAuthorityAndContent()
    {
        var verifier = new FixtureMembershipVerifier();
        var store = new InMemorySessionStore();
        var profile = FixtureProfile();
        var service = Service(store, verifier);
        _ = await service.InitializeAsync(profile);
        _ = await service.ApplyMembershipAsync(
            profile,
            Vector("deep-extension/membership/v1/signed-membership"));
        var authority = (await store.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority)).Head!;
        _ = await service.ApplyDelegationAsync(
            profile,
            CreateDelegation(profile, verifier, 3, authority.CanonicalHash, 23));

        var restarted = new MembershipTrustService(
            store,
            new RejectingMembershipVerifier(),
            new FrozenClock(FixtureNow),
            EnabledOptions());
        Assert.Equal(
            MembershipTrustState.ProtocolUnsupported,
            (await restarted.InitializeAsync(profile)).State);
    }

    [Fact]
    public async Task PublicOperation_ReadsClockExactlyOnce()
    {
        var clock = new CountingClock(FixtureNow);
        var profile = FixtureProfile();
        var service = new MembershipTrustService(
            new InMemorySessionStore(),
            new FixtureMembershipVerifier(),
            clock,
            EnabledOptions());

        _ = await service.InitializeAsync(profile);

        Assert.Equal(1, clock.ReadCount);
    }

    [Fact]
    public void SelfHostedImportBoundary_IsRawCanonicalAndNamespaceSeparated()
    {
        var properties = typeof(SelfHostedGenesisImport).GetProperties();
        Assert.DoesNotContain(
            properties,
            property => property.PropertyType.Namespace == typeof(MembershipSignature).Namespace ||
                        property.PropertyType.GenericTypeArguments.Any(
                            argument => argument.Namespace == typeof(MembershipSignature).Namespace));
        Assert.Contains(properties, property =>
            property.Name == "CanonicalSignatures" && property.PropertyType == typeof(byte[]));
    }

    [Fact]
    public void PublicApplyBoundary_HasNoTrustedP04ModelParameters()
    {
        var methods = typeof(MembershipTrustService).GetMethods()
            .Where(method => method.Name.StartsWith("Apply", StringComparison.Ordinal));

        Assert.All(methods, method => Assert.DoesNotContain(
            method.GetParameters(),
            parameter => parameter.ParameterType.Namespace == typeof(NetworkGenesis).Namespace));
    }

    private static MembershipTrustService Service(
        IMembershipTrustRepository repository,
        FixtureMembershipVerifier? verifier = null) =>
        new(repository, verifier ?? new FixtureMembershipVerifier(), new FrozenClock(FixtureNow), EnabledOptions());

    private static MembershipTrustOptions EnabledOptions() =>
        MembershipTrustOptions.DormantDefaults with
        {
            Enabled = true,
            AllowedClockSkew = TimeSpan.FromSeconds(30),
            ClockRollbackTolerance = TimeSpan.FromSeconds(30)
        };

    private static MembershipTrustProfile FixtureProfile()
    {
        var genesis = Vector("deep-extension/membership/v1/network-genesis");
        var membership = MembershipContractCodec.DecodeSignedMembership(
            Vector("deep-extension/membership/v1/signed-membership"));
        var bridge = MembershipContractCodec.DecodeSignedBridge(
            Vector("deep-extension/membership/v1/signed-bridge"));
        return new MembershipTrustProfile(
            OpaqueProfileKey: "install:default",
            CanonicalGenesis: genesis,
            ExpectedNetworkId: MembershipContractCodec.DecodeGenesis(genesis).NetworkId.ToArray(),
            ExpectedCanonicalGenesisSha256: MembershipContractHash.Sha256(genesis),
            SignedDelegation: Vector("deep-extension/membership/v1/signed-delegation"),
            BridgeAnchor: new MembershipTrustAnchor(
                bridge.Statement.Sequence - 1,
                bridge.Statement.PreviousHash.ToArray()),
            MembershipAnchor: new MembershipTrustAnchor(
                membership.Statement.Sequence - 1,
                membership.Statement.PreviousHash.ToArray()));
    }

    private static SignedMembershipCommitment ResignMembership(
        NodeMembershipCommitment statement,
        IReadOnlyList<MembershipSignature> signerTemplates,
        MembershipSignatureDomain domain,
        FixtureMembershipVerifier verifier)
    {
        var delegation = MembershipContractCodec.DecodeSignedDelegation(
            Vector("deep-extension/membership/v1/signed-delegation"));
        var bytes = MembershipContractCodec.GetMembershipSigningBytes(statement);
        return new SignedMembershipCommitment
        {
            Statement = statement,
            Signatures = signerTemplates.Take(2).Select((signature, index) =>
            {
                var signer = delegation.OnlineSigners[index];
                return new MembershipSignature
                {
                    SignerId = signer.SignerId.ToArray(),
                    Domain = domain,
                    Signature = verifier.Sign(
                        signer.SignerId.Span,
                        signer.PublicKey.Span,
                        domain,
                        bytes)
                };
            }).ToArray()
        };
    }

    private static byte[] CreateDelegation(
        MembershipTrustProfile profile,
        FixtureMembershipVerifier verifier,
        ulong sequence,
        byte[] previousHash,
        int keyOffset,
        ulong validFrom = 900,
        ulong validUntil = 1300)
    {
        var genesis = MembershipContractCodec.DecodeGenesis(profile.CanonicalGenesis);
        var template = MembershipContractCodec.DecodeSignedDelegation(profile.SignedDelegation);
        var candidate = template with
        {
            Sequence = sequence,
            PreviousHash = previousHash.ToArray(),
            ValidFromUnixSeconds = validFrom,
            ValidUntilUnixSeconds = validUntil,
            OnlineSigners = template.OnlineSigners.Select((signer, index) => signer with
            {
                SignerId = Enumerable.Range(0, MembershipLimits.SignerIdLength)
                    .Select(value => (byte)(0xa0 + keyOffset + index + value)).ToArray(),
                PublicKey = Enumerable.Range(0, MembershipLimits.PublicKeyLength)
                    .Select(value => (byte)(0x20 + keyOffset + index + value)).ToArray()
            }).ToArray(),
            Signatures = []
        };
        var signingBytes = MembershipContractCodec.GetDelegationSigningBytes(candidate);
        candidate = candidate with
        {
            Signatures = genesis.OfflineRoots.Take(3).Select(root => new MembershipSignature
            {
                SignerId = root.SignerId.ToArray(),
                Domain = MembershipSignatureDomain.OfflineDelegation,
                Signature = verifier.Sign(
                    root.SignerId.Span,
                    root.PublicKey.Span,
                    MembershipSignatureDomain.OfflineDelegation,
                    signingBytes)
            }).ToArray()
        };
        return MembershipContractCodec.EncodeSignedDelegation(candidate);
    }

    private static byte[] EncodeGenesisSignatures(
        IReadOnlyCollection<MembershipSignature> signatures)
    {
        using var stream = new MemoryStream();
        stream.Write("DSIG"u8);
        Span<byte> header = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(header, 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(
            header[2..],
            checked((ushort)signatures.Count));
        stream.Write(header);
        var length = new byte[2];
        foreach (var signature in signatures.OrderBy(
                     static item => Convert.ToHexString(item.SignerId.Span),
                     StringComparer.Ordinal))
        {
            stream.Write(signature.SignerId.Span);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(
                length,
                checked((ushort)signature.Signature.Length));
            stream.Write(length);
            stream.Write(signature.Signature.Span);
        }
        return stream.ToArray();
    }

    internal static byte[] Vector(string id)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "p04-membership-contract-v1.json");
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var hex = document.RootElement.GetProperty("vectors")
            .EnumerateArray()
            .Single(item => item.GetProperty("id").GetString() == id)
            .GetProperty("hex")
            .GetString();
        return Convert.FromHexString(hex!);
    }

    internal sealed class FixtureMembershipVerifier : IMembershipSignatureVerifier
    {
        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) =>
            signature.SequenceEqual(SignFramed(signerId, publicKey, signingBytes));

        public byte[] Sign(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> canonicalStatement) =>
            SignFramed(
                signerId,
                publicKey,
                MembershipSigningDomains.Frame(domain, canonicalStatement));

        private static byte[] SignFramed(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> signingBytes)
        {
            var framed = new byte[signerId.Length + publicKey.Length + signingBytes.Length];
            signerId.CopyTo(framed);
            publicKey.CopyTo(framed.AsSpan(signerId.Length));
            signingBytes.CopyTo(framed.AsSpan(signerId.Length + publicKey.Length));
            return SHA256.HashData(framed);
        }
    }

    private sealed class RejectingMembershipVerifier : IMembershipSignatureVerifier
    {
        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) => false;
    }

    private sealed class CountingClock(DateTimeOffset now) : IClock
    {
        public int ReadCount { get; private set; }

        public DateTimeOffset UtcNow
        {
            get
            {
                ReadCount++;
                return now;
            }
        }
    }

    private sealed class MutableClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = now;
    }
}
