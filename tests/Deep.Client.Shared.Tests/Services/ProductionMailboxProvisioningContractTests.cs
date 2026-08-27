using System.Security.Cryptography;
using System.Reflection;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ProductionMailboxProvisioningContractTests
{
    internal const ulong Now = 2_100_000_000;

    [Fact]
    public async Task ExactSignedChain_VerifiesCommitsReplaysAndRejectsTamper()
    {
        var fixture = CreateSignedFixture();
        var store = new MemoryStore();

        var verified = await ProductionMailboxControlPlaneVerifier.VerifyAsync(
            fixture.Artifacts,
            fixture.BuildAnchor,
            store,
            fixture.ClientIdentity,
            MailboxInfrastructureOwnership.OfficialManaged,
            fixture.CurrentPlacement,
            fixture.NextPlacement,
            new FixedTimeProvider(Now));

        Assert.Equal(7UL, verified.Authority.Authority.AuthorityGeneration);
        Assert.Equal(3UL, verified.Topology.CommittedTopologyGeneration);
        Assert.Equal(9UL, verified.CurrentSelection.Proof.Epoch);
        Assert.Equal(10UL, verified.NextSelection.Proof.Epoch);
        Assert.Equal(1UL, verified.StateToCommit.Revision);

        await ProductionMailboxControlPlaneVerifier.CommitAsync(verified, store);
        var replay = await ProductionMailboxControlPlaneVerifier.VerifyAsync(
            fixture.Artifacts,
            fixture.BuildAnchor,
            store,
            fixture.ClientIdentity,
            MailboxInfrastructureOwnership.OfficialManaged,
            fixture.CurrentPlacement,
            fixture.NextPlacement,
            new FixedTimeProvider(Now));
        await ProductionMailboxControlPlaneVerifier.CommitAsync(replay, store);
        Assert.Equal(1, store.Writes);

        var tampered = fixture.Artifacts.CanonicalNextSelection.ToArray();
        tampered[^1] ^= 1;
        await Assert.ThrowsAsync<ProductionMailboxTopologyException>(() =>
            ProductionMailboxControlPlaneVerifier.VerifyAsync(
                fixture.Artifacts with { CanonicalNextSelection = tampered },
                fixture.BuildAnchor,
                store,
                fixture.ClientIdentity,
                MailboxInfrastructureOwnership.OfficialManaged,
                fixture.CurrentPlacement,
                fixture.NextPlacement,
                new FixedTimeProvider(Now)));
    }

    [Fact]
    public void TrustStateCodec_RoundTripsExactCoupledState_AndRejectsTamper()
    {
        var previous = Anchor(1, 4, 7, 0x11);
        var current = Anchor(2, 5, 8, 0x22);
        var state = new ProductionMailboxTrustState(9, previous, previous, current);

        var encoded = ProductionMailboxTrustStateCodec.Encode(state);
        var decoded = ProductionMailboxTrustStateCodec.Decode(encoded);

        Assert.Equal(ProductionMailboxTrustStateCodec.EncodedLength, encoded.Length);
        Assert.Equal(state.Revision, decoded.Revision);
        Assert.Equal(current.AuthorityGeneration, decoded.Current.AuthorityGeneration);
        Assert.Equal(current.TopologyHash.ToArray(), decoded.Current.TopologyHash.ToArray());

        encoded[4] = 2;
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxTrustStateCodec.Decode(encoded));
    }

    [Fact]
    public void VerifiedCapability_HasNoPublicForgeOrMutationSurface()
    {
        var type = typeof(VerifiedProductionMailboxControlPlane);
        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(type.GetProperties(BindingFlags.Public | BindingFlags.Instance),
            static property => property.SetMethod is not null);
        Assert.DoesNotContain(type.GetMethods(BindingFlags.NonPublic | BindingFlags.Instance),
            method => method.DeclaringType == type &&
                method.Name.Contains("Clone", StringComparison.Ordinal));
        Assert.Null(type.GetProperty("StateToCommit", BindingFlags.Public | BindingFlags.Instance));
        Assert.Null(type.GetProperty("ExpectedStateRevision", BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public async Task VerificationUsesOneOwnedSnapshotAcrossStoreAndClockCallbacks()
    {
        var fixture = CreateSignedFixture();
        var authority = fixture.Artifacts.CanonicalAuthority.ToArray();
        var revocations = fixture.Artifacts.CanonicalRevocationSnapshot.ToArray();
        var topology = fixture.Artifacts.CanonicalTopology.ToArray();
        var current = fixture.Artifacts.CanonicalCurrentSelection.ToArray();
        var next = fixture.Artifacts.CanonicalNextSelection.ToArray();
        var buildMrX = fixture.BuildAnchor.MrXPublicKeySha256.ToArray();
        var signer = fixture.ClientIdentity.SigningCertificateSha256.ToArray();
        var artifacts = new ProductionMailboxControlPlaneArtifacts(
            authority, revocations, topology, current, next);
        var build = fixture.BuildAnchor with { MrXPublicKeySha256 = buildMrX };
        var identity = fixture.ClientIdentity with { SigningCertificateSha256 = signer };
        var store = new CallbackReadStore(() =>
        {
            authority[0] ^= 0xff;
            buildMrX[0] ^= 0xff;
            signer[0] ^= 0xff;
        });
        var clock = new CallbackTimeProvider(Now, () =>
        {
            revocations[0] ^= 0xff;
            topology[0] ^= 0xff;
            current[0] ^= 0xff;
            next[0] ^= 0xff;
        });

        var verified = await ProductionMailboxControlPlaneVerifier.VerifyAsync(
            artifacts, build, store, identity,
            MailboxInfrastructureOwnership.OfficialManaged,
            fixture.CurrentPlacement, fixture.NextPlacement, clock);

        Assert.Equal(7UL, verified.Authority.Authority.AuthorityGeneration);
        Assert.Equal(1, store.Reads);
    }

    [Fact]
    public async Task PersistedAndCommitStateAreDeepFrozenAcrossExternalMutation()
    {
        var fixture = CreateSignedFixture();
        var store = new MemoryStore();
        var first = await ProductionMailboxControlPlaneVerifier.VerifyAsync(
            fixture.Artifacts, fixture.BuildAnchor, store, fixture.ClientIdentity,
            MailboxInfrastructureOwnership.OfficialManaged,
            fixture.CurrentPlacement, fixture.NextPlacement, new FixedTimeProvider(Now));
        await ProductionMailboxControlPlaneVerifier.CommitAsync(first, store);
        var persisted = (await store.ReadAsync())!;
        var expectedAuthorityHash = persisted.Current.AuthorityHash.ToArray();
        var replay = await ProductionMailboxControlPlaneVerifier.VerifyAsync(
            fixture.Artifacts, fixture.BuildAnchor, store, fixture.ClientIdentity,
            MailboxInfrastructureOwnership.OfficialManaged,
            fixture.CurrentPlacement, fixture.NextPlacement,
            new CallbackTimeProvider(Now, () => Flip(persisted.Current.AuthorityHash)));
        Assert.Equal(expectedAuthorityHash, replay.StateToCommit.Current.AuthorityHash.ToArray());

        var blocking = new BlockingCommitStore();
        var candidate = await ProductionMailboxControlPlaneVerifier.VerifyAsync(
            fixture.Artifacts, fixture.BuildAnchor, blocking, fixture.ClientIdentity,
            MailboxInfrastructureOwnership.OfficialManaged,
            fixture.CurrentPlacement, fixture.NextPlacement, new FixedTimeProvider(Now));
        var expectedCandidateHash = candidate.StateToCommit.Current.AuthorityHash.ToArray();
        Flip(fixture.Artifacts.CanonicalAuthority);
        Flip(fixture.BuildAnchor.AuthorityHash);
        var exposedCopy = candidate.StateToCommit;
        var commit = ProductionMailboxControlPlaneVerifier.CommitAsync(candidate, blocking);
        await blocking.Entered;
        Flip(exposedCopy.Current.AuthorityHash);
        blocking.Release();
        await commit;
        Assert.Equal(expectedCandidateHash,
            (await blocking.ReadAsync())!.Current.AuthorityHash.ToArray());
    }

    [Fact]
    public async Task OversizedArtifactFailsBeforeStoreCallbackOrLargeClone()
    {
        var fixture = CreateSignedFixture();
        var oversized = new byte[8 * 1024 * 1024];
        var artifacts = fixture.Artifacts with { CanonicalAuthority = oversized };
        var store = new CallbackReadStore(() => throw new Xunit.Sdk.XunitException(
            "State store must not be reached."));
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var verification = ProductionMailboxControlPlaneVerifier.VerifyAsync(
            artifacts, fixture.BuildAnchor, store, fixture.ClientIdentity,
            MailboxInfrastructureOwnership.OfficialManaged,
            fixture.CurrentPlacement, fixture.NextPlacement,
            new FixedTimeProvider(Now));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
        _ = await Assert.ThrowsAsync<InvalidDataException>(() => verification);
        Assert.InRange(allocated, 0, 1_000_000);
        Assert.Equal(0, store.Reads);
    }

    [Fact]
    public async Task OversizedBuildAnchorAndClientIdentityFailBeforeStoreOrClock()
    {
        var fixture = CreateSignedFixture();
        var oversized = new byte[8 * 1024 * 1024];
        var clockCalls = 0;
        var clock = new CallbackTimeProvider(Now, () => clockCalls++);

        foreach (var invalid in new[]
        {
            (Build: fixture.BuildAnchor with { MrXPublicKeySha256 = oversized },
                Identity: fixture.ClientIdentity),
            (Build: fixture.BuildAnchor,
                Identity: fixture.ClientIdentity with { BuildArtifactSha256 = oversized })
        })
        {
            var store = new CallbackReadStore(() => throw new Xunit.Sdk.XunitException(
                "State store must not be reached."));
            var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
            var verification = ProductionMailboxControlPlaneVerifier.VerifyAsync(
                fixture.Artifacts, invalid.Build, store, invalid.Identity,
                MailboxInfrastructureOwnership.OfficialManaged,
                fixture.CurrentPlacement, fixture.NextPlacement, clock);
            var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
            _ = await Assert.ThrowsAsync<InvalidDataException>(() => verification);
            Assert.InRange(allocated, 0, 1_000_000);
            Assert.Equal(0, store.Reads);
        }
        Assert.Equal(0, clockCalls);
    }

    [Fact]
    public async Task OversizedPersistedStateFailsAfterOneReadBeforeClockOrLargeClone()
    {
        var fixture = CreateSignedFixture();
        var oversized = new byte[8 * 1024 * 1024];
        var hostile = new ProductionMailboxTrustState(
            1,
            fixture.BuildAnchor with { TopologyHash = oversized },
            fixture.BuildAnchor,
            fixture.BuildAnchor);
        var store = new ReturningStore(hostile);
        var clockCalls = 0;
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var verification = ProductionMailboxControlPlaneVerifier.VerifyAsync(
            fixture.Artifacts, fixture.BuildAnchor, store, fixture.ClientIdentity,
            MailboxInfrastructureOwnership.OfficialManaged,
            fixture.CurrentPlacement, fixture.NextPlacement,
            new CallbackTimeProvider(Now, () => clockCalls++));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;

        _ = await Assert.ThrowsAsync<InvalidDataException>(() => verification);
        Assert.InRange(allocated, 0, 1_000_000);
        Assert.Equal(1, store.Reads);
        Assert.Equal(0, clockCalls);
    }

    [Fact]
    public void NewerBuildFloorCanAdvanceOlderPersistedState_WithoutRequiringExactRoot()
    {
        var originalRoot = Anchor(1, 1, 1, 0x11);
        var oldCurrent = Anchor(2, 2, 2, 0x22);
        var persisted = new ProductionMailboxTrustState(
            7, originalRoot, originalRoot, oldCurrent);
        var newerBuild = Anchor(4, 4, 5, 0x44);

        var authority = ProductionMailboxControlPlaneVerifier
            .SelectAuthorityPredecessor(
                5, Fill(32, 0x55), newerBuild, persisted);
        var topology = ProductionMailboxControlPlaneVerifier
            .SelectTopologyPredecessor(
                6, Fill(32, 0x58), newerBuild, persisted);

        Assert.Same(newerBuild, authority);
        Assert.Same(newerBuild, topology);
    }

    [Fact]
    public void EqualGenerationBuildForkIsRejected()
    {
        var root = Anchor(1, 1, 1, 0x11);
        var persistedCurrent = Anchor(3, 3, 4, 0x33);
        var persisted = new ProductionMailboxTrustState(
            5, root, Anchor(2, 2, 3, 0x22), persistedCurrent);
        var conflictingBuild = Anchor(3, 3, 4, 0x66);

        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxControlPlaneVerifier.SelectAuthorityPredecessor(
                4, Fill(32, 0x77), conflictingBuild, persisted));
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxControlPlaneVerifier.SelectTopologyPredecessor(
                5, Fill(32, 0x78), conflictingBuild, persisted));
    }

    [Fact]
    public void CoupledPredecessorPreservesIndependentAuthorityAndTopologyLineage()
    {
        var trustDomain = Anchor(1, 1, 1, 0x11);
        var authorityPredecessor = Anchor(7, 9, 50, 0x31);
        var topologyPredecessor = Anchor(4, 5, 12, 0x51);

        var combined = ProductionMailboxControlPlaneVerifier.CombinePredecessors(
            trustDomain, authorityPredecessor, topologyPredecessor);

        Assert.Equal(7UL, combined.AuthorityGeneration);
        Assert.Equal(9UL, combined.RevocationGeneration);
        Assert.Equal(
            authorityPredecessor.AuthorityHash.ToArray(),
            combined.AuthorityHash.ToArray());
        Assert.Equal(12UL, combined.TopologyGeneration);
        Assert.Equal(
            topologyPredecessor.TopologyHash.ToArray(),
            combined.TopologyHash.ToArray());
        Assert.Equal(
            trustDomain.MrXPublicKeySha256.ToArray(),
            combined.MrXPublicKeySha256.ToArray());
    }

    private static ProductionMailboxTrustAnchor Anchor(
        ulong authority,
        ulong revocation,
        ulong topology,
        byte marker) => new(
            Fill(32, 0x41), Fill(16, 0x42), authority, Fill(32, marker), revocation,
            Fill(32, (byte)(marker + 1)), Fill(32, (byte)(marker + 2)), topology,
            Fill(32, (byte)(marker + 3)));

    private static byte[] Fill(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private static void Flip(ReadOnlyMemory<byte> value)
    {
        Assert.True(MemoryMarshal.TryGetArray(value, out var segment));
        segment.Array![segment.Offset] ^= 0xff;
    }

    internal static SignedFixture CreateSignedFixture(bool sharedPlacement = false)
    {
        var issuer = PublicKeyAuth.GenerateKeyPair(Bytes(30, 32));
        var mrX = PublicKeyAuth.GenerateKeyPair(Bytes(60, 32));
        var currentDescriptors = Descriptors(9, Now - 100, Now + 1_000, 0x10);
        var nextDescriptors = Descriptors(10, Now - 50, Now + 2_000, 0x50);
        var currentRoot = MembershipRouteDescriptorCodec.ComputeRoot(currentDescriptors);
        var nextRoot = MembershipRouteDescriptorCodec.ComputeRoot(nextDescriptors);
        var draftAuthority = new ProductionMailboxAuthority
        {
            DevelopmentOnly = false,
            Environment = ProductionMailboxAuthorityEnvironment.Production,
            Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
            Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
            EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
            NetworkId = Bytes(1, 16),
            AuthorityGeneration = 7,
            PreviousAuthorityHash = Bytes(2, 32),
            MailboxIssuerEd25519PublicKey = issuer.PublicKey,
            MrXApprovalEd25519PublicKey = mrX.PublicKey,
            Coordinator = Endpoint("https://coord.example.net/", 4),
            NodeIngress = Endpoint("https://ingress.example.net/mau2/", 6),
            CurrentEpoch = AuthorityEpoch(9, 70, currentRoot, Bytes(8, 32), Now - 100, Now + 1_000),
            NextEpoch = AuthorityEpoch(10, 71, nextRoot, Bytes(10, 32), Now - 50, Now + 2_000),
            Revocation = new ProductionMailboxAuthorityRevocation
            {
                SnapshotHash = Bytes(12, 32),
                HeadHash = Bytes(13, 32),
                PreviousHeadHash = Bytes(22, 32),
                Generation = 6,
                IssuedAtUnixSeconds = Now - 20,
                ExpiresAtUnixSeconds = Now + 500
            },
            MrXApproval = new ProductionMailboxAuthorityApproval
            {
                AuthorityPayloadHash = Bytes(14, 32),
                AllowedAndroidSigningCertificateSha256 = [Bytes(15, 32)],
                AllowedWindowsSigningCertificateSha256 = [Bytes(16, 32)],
                AndroidReleaseBuildArtifactSha256 = [Bytes(17, 32)],
                WindowsReleaseBuildArtifactSha256 = [Bytes(18, 32)],
                RolloutNotBeforeUnixSeconds = Now - 30,
                RolloutNotAfterUnixSeconds = Now + 500
            },
            Signature = new byte[64]
        };
        var unsignedRevocations = new ProductionMailboxRevocationSnapshot
        {
            NetworkId = draftAuthority.NetworkId,
            AuthorityGeneration = draftAuthority.AuthorityGeneration,
            AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(draftAuthority),
            RevocationGeneration = draftAuthority.Revocation.Generation,
            RevocationHeadHash = draftAuthority.Revocation.HeadHash,
            PreviousRevocationHeadHash = draftAuthority.Revocation.PreviousHeadHash,
            IssuedAtUnixSeconds = draftAuthority.Revocation.IssuedAtUnixSeconds,
            ExpiresAtUnixSeconds = draftAuthority.Revocation.ExpiresAtUnixSeconds,
            RevokedGrantSerials = [],
            IssuerSignature = new byte[64]
        };
        var revocations = unsignedRevocations with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedRevocations),
                issuer.PrivateKey)
        };
        var revocationBytes = ProductionMailboxRevocationSnapshotCodec.Encode(revocations);
        var authority = SignAuthority(draftAuthority with
        {
            Revocation = draftAuthority.Revocation with
            {
                SnapshotHash = SHA256.HashData(revocationBytes)
            }
        }, mrX.PrivateKey);
        var authorityBytes = ProductionMailboxAuthorityCodec.Encode(authority);
        var topology = SignTopology(new ProductionMailboxTopologySnapshot
        {
            NetworkId = authority.NetworkId,
            AuthorityGeneration = authority.AuthorityGeneration,
            CanonicalAuthorityHash = SHA256.HashData(authorityBytes),
            TopologyGeneration = 3,
            PreviousTopologyHash = Bytes(90, 32),
            IssuedAtUnixSeconds = Now - 10,
            ExpiresAtUnixSeconds = Now + 100,
            CurrentEpoch = TopologyEpoch(authority.CurrentEpoch, currentDescriptors),
            NextEpoch = TopologyEpoch(authority.NextEpoch, nextDescriptors),
            IssuerSignature = new byte[64]
        }, issuer.PrivateKey);
        var topologyBytes = ProductionMailboxTopologyCodec.Encode(topology);
        var currentPlacement = new BlindedPlacementId(Bytes(201, 32));
        var nextPlacement = sharedPlacement
            ? new BlindedPlacementId(currentPlacement.Bytes.Span)
            : new BlindedPlacementId(Bytes(211, 32));
        var currentSelection = SignSelection(
            authority, topology, currentDescriptors, topology.CurrentEpoch,
            currentPlacement, issuer.PrivateKey);
        var nextSelection = SignSelection(
            authority, topology, nextDescriptors, topology.NextEpoch,
            nextPlacement, issuer.PrivateKey);
        var artifacts = new ProductionMailboxControlPlaneArtifacts(
            authorityBytes,
            revocationBytes,
            topologyBytes,
            ProductionMailboxTopologyCodec.EncodeSelection(currentSelection),
            ProductionMailboxTopologyCodec.EncodeSelection(nextSelection));
        var buildAnchor = new ProductionMailboxTrustAnchor(
            SHA256.HashData(mrX.PublicKey),
            authority.NetworkId,
            6,
            authority.PreviousAuthorityHash,
            5,
            authority.Revocation.PreviousHeadHash,
            Bytes(23, 32),
            2,
            topology.PreviousTopologyHash);
        var clientIdentity = new ProductionMailboxClientApprovalIdentity(
            MailboxClientPlatform.Android,
            ProductionMailboxControlPlaneVerifier.AndroidApplicationIdentity,
            Bytes(15, 32),
            Bytes(17, 32));
        return new SignedFixture(
            artifacts, buildAnchor, clientIdentity, currentPlacement, nextPlacement,
            issuer.PrivateKey, mrX.PrivateKey);
    }

    internal static SignedFixture CreateRotatedSignedFixture(
        SignedFixture previous,
        ulong generationSteps)
    {
        if (generationSteps == 0) throw new ArgumentOutOfRangeException(nameof(generationSteps));
        var oldAuthority = ProductionMailboxAuthorityCodec.Decode(
            previous.Artifacts.CanonicalAuthority.Span);
        var oldTopology = ProductionMailboxTopologyCodec.Decode(
            previous.Artifacts.CanonicalTopology.Span);
        var issuer = PublicKeyAuth.GenerateKeyPair(previous.IssuerPrivateKey[..32]);
        var mrX = PublicKeyAuth.GenerateKeyPair(previous.MrXPrivateKey[..32]);
        var currentEpochNumber = checked(oldTopology.NextEpoch.Epoch + generationSteps - 1);
        var nextEpochNumber = checked(currentEpochNumber + 1);
        var currentGeneration = checked(oldTopology.NextEpoch.Generation + generationSteps - 1);
        var nextGeneration = checked(currentGeneration + 1);
        var currentSeed = generationSteps == 1 ? 0x50 : 0x90;
        var nextSeed = currentSeed + 0x40;
        var currentNotBefore = generationSteps == 1
            ? oldAuthority.NextEpoch.NotBeforeUnixSeconds
            : Now - 50;
        var currentNotAfter = generationSteps == 1
            ? oldAuthority.NextEpoch.NotAfterUnixSeconds
            : Now + 400;
        var nextNotBefore = Now - 25;
        var nextNotAfter = generationSteps == 1 ? Now + 2_500 : Now + 450;
        var currentDescriptors = Descriptors(
            currentEpochNumber, currentNotBefore, currentNotAfter, currentSeed);
        var nextDescriptors = Descriptors(
            nextEpochNumber, nextNotBefore, nextNotAfter, nextSeed);
        var currentRoot = MembershipRouteDescriptorCodec.ComputeRoot(currentDescriptors);
        var nextRoot = MembershipRouteDescriptorCodec.ComputeRoot(nextDescriptors);
        var draftAuthority = oldAuthority with
        {
            AuthorityGeneration = checked(oldAuthority.AuthorityGeneration + generationSteps),
            PreviousAuthorityHash = generationSteps == 1
                ? SHA256.HashData(previous.Artifacts.CanonicalAuthority.Span)
                : Bytes(0xa1, 32),
            CurrentEpoch = AuthorityEpoch(
                currentEpochNumber, currentGeneration, currentRoot,
                generationSteps == 1
                    ? oldAuthority.NextEpoch.TopologyPlacementCommitment.ToArray()
                    : Bytes(0xa2, 32),
                currentNotBefore, currentNotAfter),
            NextEpoch = AuthorityEpoch(
                nextEpochNumber, nextGeneration, nextRoot, Bytes(0xa3, 32),
                nextNotBefore, nextNotAfter),
            Revocation = oldAuthority.Revocation with
            {
                SnapshotHash = Bytes(0xa4, 32),
                HeadHash = Bytes(0xa5, 32),
                PreviousHeadHash = generationSteps == 1
                    ? oldAuthority.Revocation.HeadHash
                    : Bytes(0xa6, 32),
                Generation = checked(oldAuthority.Revocation.Generation + generationSteps),
                IssuedAtUnixSeconds = Now - 10,
                ExpiresAtUnixSeconds = generationSteps == 1
                    ? Now + 2_500
                    : Now + 1_000
            },
            MrXApproval = oldAuthority.MrXApproval with
            {
                RolloutNotBeforeUnixSeconds = Now - 20,
                RolloutNotAfterUnixSeconds = generationSteps == 1
                    ? Now + 2_500
                    : Now + 400
            },
            Signature = new byte[64]
        };
        draftAuthority = SignAuthority(draftAuthority, mrX.PrivateKey);
        var unsignedRevocations = new ProductionMailboxRevocationSnapshot
        {
            NetworkId = draftAuthority.NetworkId,
            AuthorityGeneration = draftAuthority.AuthorityGeneration,
            AuthorityBindingHash =
                ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(
                    draftAuthority),
            RevocationGeneration = draftAuthority.Revocation.Generation,
            RevocationHeadHash = draftAuthority.Revocation.HeadHash,
            PreviousRevocationHeadHash = draftAuthority.Revocation.PreviousHeadHash,
            IssuedAtUnixSeconds = draftAuthority.Revocation.IssuedAtUnixSeconds,
            ExpiresAtUnixSeconds = draftAuthority.Revocation.ExpiresAtUnixSeconds,
            RevokedGrantSerials = [],
            IssuerSignature = new byte[64]
        };
        var revocations = unsignedRevocations with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedRevocations),
                issuer.PrivateKey)
        };
        var revocationBytes = ProductionMailboxRevocationSnapshotCodec.Encode(revocations);
        var authority = SignAuthority(draftAuthority with
        {
            Revocation = draftAuthority.Revocation with
            {
                SnapshotHash = SHA256.HashData(revocationBytes)
            }
        }, mrX.PrivateKey);
        var authorityBytes = ProductionMailboxAuthorityCodec.Encode(authority);
        var topology = SignTopology(new ProductionMailboxTopologySnapshot
        {
            NetworkId = authority.NetworkId,
            AuthorityGeneration = authority.AuthorityGeneration,
            CanonicalAuthorityHash = SHA256.HashData(authorityBytes),
            TopologyGeneration = checked(oldTopology.TopologyGeneration + generationSteps),
            PreviousTopologyHash = generationSteps == 1
                ? SHA256.HashData(previous.Artifacts.CanonicalTopology.Span)
                : Bytes(0xa7, 32),
            IssuedAtUnixSeconds = Now - 5,
            ExpiresAtUnixSeconds = Now + 400,
            CurrentEpoch = TopologyEpoch(authority.CurrentEpoch, currentDescriptors),
            NextEpoch = TopologyEpoch(authority.NextEpoch, nextDescriptors),
            IssuerSignature = new byte[64]
        }, issuer.PrivateKey);
        var topologyBytes = ProductionMailboxTopologyCodec.Encode(topology);
        var placement = new BlindedPlacementId(previous.CurrentPlacement.Bytes.Span);
        var currentSelection = SignSelection(
            authority, topology, currentDescriptors, topology.CurrentEpoch,
            placement, issuer.PrivateKey);
        var nextSelection = SignSelection(
            authority, topology, nextDescriptors, topology.NextEpoch,
            placement, issuer.PrivateKey);
        return new SignedFixture(
            new ProductionMailboxControlPlaneArtifacts(
                authorityBytes,
                revocationBytes,
                topologyBytes,
                ProductionMailboxTopologyCodec.EncodeSelection(currentSelection),
                ProductionMailboxTopologyCodec.EncodeSelection(nextSelection)),
            previous.BuildAnchor,
            previous.ClientIdentity,
            placement,
            placement,
            issuer.PrivateKey,
            mrX.PrivateKey);
    }

    private static ProductionMailboxSelectionProof SignSelection(
        ProductionMailboxAuthority authority,
        ProductionMailboxTopologySnapshot topology,
        MembershipRouteDescriptor[] descriptors,
        ProductionMailboxTopologyEpoch epoch,
        BlindedPlacementId placement,
        byte[] issuerPrivateKey)
    {
        var selectionCommitment = ProductionMailboxReplicaSelection
            .ComputeSelectionInputCommitment(placement);
        var selected = ProductionMailboxReplicaSelection.Select(
            topology.NetworkId.Span,
            epoch,
            selectionCommitment);
        var proofs = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
        var replicas = selected.Select(id =>
        {
            var index = Array.FindIndex(
                descriptors,
                descriptor => descriptor.RouterId.Span.SequenceEqual(id.Span));
            Assert.True(index >= 0);
            var descriptor = descriptors[index];
            var membershipProof = new MailboxReplicaMembershipProof
            {
                ReplicaId = descriptor.RouterId,
                SigningPublicKey = descriptor.Ed25519PublicKey,
                Epoch = descriptor.Epoch,
                MembershipCommitment = epoch.MembershipCommitment,
                CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(
                    descriptor, proofs[index])
            };
            return new ProductionMailboxSelectionReplica
            {
                ReplicaId = descriptor.RouterId,
                CanonicalMIP1Proof = MailboxPeerReplicationCodec.EncodeMembershipProof(
                    membershipProof)
            };
        }).ToArray();
        var unsigned = new ProductionMailboxSelectionProof
        {
            Algorithm = ProductionMailboxSelectionAlgorithm.RendezvousSha256V2,
            NetworkId = topology.NetworkId,
            AuthorityGeneration = topology.AuthorityGeneration,
            CanonicalAuthorityHash = topology.CanonicalAuthorityHash,
            TopologyGeneration = topology.TopologyGeneration,
            CanonicalTopologyHash = SHA256.HashData(
                ProductionMailboxTopologyCodec.Encode(topology)),
            Epoch = epoch.Epoch,
            Generation = epoch.Generation,
            MembershipCommitment = epoch.MembershipCommitment,
            TopologyPlacementCommitment = epoch.TopologyPlacementCommitment,
            MailboxPlacementCommitment = MailboxPlacementCommitment.Compute(placement),
            SelectionInputCommitment = selectionCommitment,
            IssuedAtUnixSeconds = Now - 5,
            ExpiresAtUnixSeconds = Now + 50,
            Replicas = replicas,
            IssuerSignature = new byte[64]
        };
        return unsigned with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxTopologyCodec.GetSelectionSigningBytes(unsigned),
                issuerPrivateKey)
        };
    }

    private static MembershipRouteDescriptor[] Descriptors(
        ulong epoch, ulong from, ulong until, int seed) =>
    [
        Descriptor(seed, epoch, from, until),
        Descriptor(seed + 0x10, epoch, from, until),
        Descriptor(seed + 0x20, epoch, from, until)
    ];

    private static MembershipRouteDescriptor Descriptor(
        int seed, ulong epoch, ulong from, ulong until) => new()
    {
        RouterId = Range(seed, 32),
        Ed25519PublicKey = Range(seed + 32, 32),
        X25519PublicKey = Range(seed + 64, 32),
        RpcEndpoint = $"https://route-{seed}.example.net/",
        Roles = MembershipRouteRole.Storage,
        Capabilities = MembershipRouteCapability.Storage,
        Epoch = epoch,
        ValidFromUnixSeconds = from,
        ValidUntilUnixSeconds = until
    };

    private static ProductionMailboxTopologyEpoch TopologyEpoch(
        ProductionMailboxAuthorityEpoch authorityEpoch,
        MembershipRouteDescriptor[] descriptors) => new()
    {
        Epoch = authorityEpoch.Epoch,
        Generation = authorityEpoch.Generation,
        MembershipCommitment = authorityEpoch.MembershipCommitment,
        TopologyPlacementCommitment = authorityEpoch.TopologyPlacementCommitment,
        NotBeforeUnixSeconds = authorityEpoch.NotBeforeUnixSeconds,
        NotAfterUnixSeconds = authorityEpoch.NotAfterUnixSeconds,
        Nodes = descriptors.Select((descriptor, index) => new ProductionMailboxTopologyNode
        {
            NodeId = descriptor.RouterId,
            HttpsEndpoint = $"https://node-{authorityEpoch.Epoch}-{index + 1}.example.net/",
            CurrentSpkiSha256 = Bytes((byte)(100 + index * 2), 32),
            NextSpkiSha256 = Bytes((byte)(101 + index * 2), 32)
        }).ToArray()
    };

    private static ProductionMailboxAuthorityEpoch AuthorityEpoch(
        ulong epoch,
        ulong generation,
        byte[] membership,
        byte[] placement,
        ulong from,
        ulong until) => new()
    {
        Epoch = epoch,
        Generation = generation,
        MembershipCommitment = membership,
        TopologyPlacementCommitment = placement,
        NotBeforeUnixSeconds = from,
        NotAfterUnixSeconds = until
    };

    private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
    {
        Uri = uri,
        CurrentSpkiSha256 = Bytes(seed, 32),
        NextSpkiSha256 = Bytes((byte)(seed + 1), 32)
    };

    private static ProductionMailboxAuthority SignAuthority(
        ProductionMailboxAuthority authority, byte[] key)
    {
        var bound = authority with
        {
            MrXApproval = authority.MrXApproval with
            {
                AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(authority)
            },
            Signature = new byte[64]
        };
        return bound with
        {
            Signature = PublicKeyAuth.SignDetached(
                ProductionMailboxAuthorityCodec.GetSigningBytes(bound), key)
        };
    }

    private static ProductionMailboxTopologySnapshot SignTopology(
        ProductionMailboxTopologySnapshot topology, byte[] key)
    {
        var unsigned = topology with { IssuerSignature = new byte[64] };
        return unsigned with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxTopologyCodec.GetSigningBytes(unsigned), key)
        };
    }

    private static byte[] Bytes(byte seed, int length) =>
        Enumerable.Range(0, length)
            .Select(index => unchecked((byte)(seed + index)))
            .ToArray();

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length)
            .Select(index => unchecked((byte)index))
            .ToArray();

    internal sealed record SignedFixture(
        ProductionMailboxControlPlaneArtifacts Artifacts,
        ProductionMailboxTrustAnchor BuildAnchor,
        ProductionMailboxClientApprovalIdentity ClientIdentity,
        BlindedPlacementId CurrentPlacement,
        BlindedPlacementId NextPlacement,
        byte[] IssuerPrivateKey,
        byte[] MrXPrivateKey);

    private sealed class FixedTimeProvider(ulong now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.FromUnixTimeSeconds(checked((long)now));
    }

    private sealed class CallbackTimeProvider(ulong now, Action callback) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            callback();
            return DateTimeOffset.FromUnixTimeSeconds(checked((long)now));
        }
    }

    private sealed class CallbackReadStore(Action callback) : IProductionMailboxTrustStateStore
    {
        public int Reads { get; private set; }

        public Task<ProductionMailboxTrustState?> ReadAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Reads++;
            callback();
            return Task.FromResult<ProductionMailboxTrustState?>(null);
        }

        public Task CommitAsync(
            ulong expectedRevision,
            ProductionMailboxTrustState replacement,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class ReturningStore(ProductionMailboxTrustState value) :
        IProductionMailboxTrustStateStore
    {
        public int Reads { get; private set; }

        public Task<ProductionMailboxTrustState?> ReadAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Reads++;
            return Task.FromResult<ProductionMailboxTrustState?>(value);
        }

        public Task CommitAsync(
            ulong expectedRevision,
            ProductionMailboxTrustState replacement,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class BlockingCommitStore : IProductionMailboxTrustStateStore
    {
        private readonly TaskCompletionSource entered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource release = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private ProductionMailboxTrustState? state;

        public Task Entered => entered.Task;

        public Task<ProductionMailboxTrustState?> ReadAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(state);
        }

        public async Task CommitAsync(
            ulong expectedRevision,
            ProductionMailboxTrustState replacement,
            CancellationToken cancellationToken = default)
        {
            if ((state?.Revision ?? 0) != expectedRevision)
                throw new InvalidOperationException("concurrent-update");
            entered.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
            state = replacement;
        }

        public void Release() => release.TrySetResult();
    }

    private sealed class MemoryStore : IProductionMailboxTrustStateStore
    {
        private readonly object gate = new();
        private ProductionMailboxTrustState? state;
        public int Writes { get; private set; }

        public Task<ProductionMailboxTrustState?> ReadAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate) return Task.FromResult(state);
        }

        public Task CommitAsync(
            ulong expectedRevision,
            ProductionMailboxTrustState replacement,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                if ((state?.Revision ?? 0) != expectedRevision)
                    throw new InvalidOperationException("concurrent-update");
                state = replacement; Writes++;
            }
            return Task.CompletedTask;
        }
    }
}
