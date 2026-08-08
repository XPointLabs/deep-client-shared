using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Client.Shared.Services;

public sealed record ProductionMailboxControlPlaneArtifacts(
    ReadOnlyMemory<byte> CanonicalAuthority,
    ReadOnlyMemory<byte> CanonicalRevocationSnapshot,
    ReadOnlyMemory<byte> CanonicalTopology,
    ReadOnlyMemory<byte> CanonicalCurrentSelection,
    ReadOnlyMemory<byte> CanonicalNextSelection);

public sealed record ProductionMailboxClientApprovalIdentity(
    MailboxClientPlatform Platform,
    string ApplicationIdentity,
    ReadOnlyMemory<byte> SigningCertificateSha256,
    ReadOnlyMemory<byte> BuildArtifactSha256);

/// <summary>
/// Compile-time trust floor. It is deliberately the state immediately before the first
/// PMA1/PMT1 accepted by this binary, so a downloaded artifact can never bootstrap its own trust.
/// </summary>
public sealed record ProductionMailboxTrustAnchor(
    ReadOnlyMemory<byte> MrXPublicKeySha256,
    ReadOnlyMemory<byte> NetworkId,
    ulong AuthorityGeneration,
    ReadOnlyMemory<byte> AuthorityHash,
    ulong RevocationGeneration,
    ReadOnlyMemory<byte> RevocationHeadHash,
    ReadOnlyMemory<byte> RevocationSnapshotHash,
    ulong TopologyGeneration,
    ReadOnlyMemory<byte> TopologyHash);

public sealed record ProductionMailboxTrustState(
    ulong Revision,
    ProductionMailboxTrustAnchor Root,
    ProductionMailboxTrustAnchor Previous,
    ProductionMailboxTrustAnchor Current);

/// <summary>Fixed-order coupled LKG encoding; no optional/legacy fields.</summary>
public static class ProductionMailboxTrustStateCodec
{
    public const int EncodedLength = 616;
    private static ReadOnlySpan<byte> Magic => "PML1"u8;

    public static byte[] Encode(ProductionMailboxTrustState value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Revision == 0) throw new InvalidDataException("Production LKG revision is invalid.");
        Validate(value.Root); Validate(value.Previous); Validate(value.Current);
        var output = new byte[EncodedLength];
        Magic.CopyTo(output); output[4] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), value.Revision);
        WriteAnchor(output.AsSpan(16, 200), value.Root);
        WriteAnchor(output.AsSpan(216, 200), value.Previous);
        WriteAnchor(output.AsSpan(416, 200), value.Current);
        return output;
    }

    public static ProductionMailboxTrustState Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedLength || !encoded[..4].SequenceEqual(Magic) ||
            encoded[4] != 1 || encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Production LKG framing is invalid.");
        var revision = BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]);
        if (revision == 0) throw new InvalidDataException("Production LKG revision is invalid.");
        return new ProductionMailboxTrustState(
            revision,
            ReadAnchor(encoded.Slice(16, 200)),
            ReadAnchor(encoded.Slice(216, 200)),
            ReadAnchor(encoded.Slice(416, 200)));
    }

    private static void WriteAnchor(Span<byte> target, ProductionMailboxTrustAnchor value)
    {
        value.MrXPublicKeySha256.Span.CopyTo(target);
        value.NetworkId.Span.CopyTo(target[32..]);
        BinaryPrimitives.WriteUInt64BigEndian(target[48..], value.AuthorityGeneration);
        value.AuthorityHash.Span.CopyTo(target[56..]);
        BinaryPrimitives.WriteUInt64BigEndian(target[88..], value.RevocationGeneration);
        value.RevocationHeadHash.Span.CopyTo(target[96..]);
        value.RevocationSnapshotHash.Span.CopyTo(target[128..]);
        BinaryPrimitives.WriteUInt64BigEndian(target[160..], value.TopologyGeneration);
        value.TopologyHash.Span.CopyTo(target[168..]);
    }

    private static ProductionMailboxTrustAnchor ReadAnchor(ReadOnlySpan<byte> source)
    {
        var value = new ProductionMailboxTrustAnchor(
            source[..32].ToArray(),
            source.Slice(32, 16).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(source[48..]),
            source.Slice(56, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(source[88..]),
            source.Slice(96, 32).ToArray(),
            source.Slice(128, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(source[160..]),
            source.Slice(168, 32).ToArray());
        Validate(value);
        return value;
    }

    private static void Validate(ProductionMailboxTrustAnchor value)
    {
        static bool Hash(ReadOnlySpan<byte> bytes) => bytes.Length == 32 && bytes.IndexOfAnyExcept((byte)0) >= 0;
        if (!Hash(value.MrXPublicKeySha256.Span) || value.NetworkId.Length != 16 ||
            value.NetworkId.Span.IndexOfAnyExcept((byte)0) < 0 || value.AuthorityGeneration == 0 ||
            !Hash(value.AuthorityHash.Span) || value.RevocationGeneration == 0 ||
            !Hash(value.RevocationHeadHash.Span) || !Hash(value.RevocationSnapshotHash.Span) ||
            value.TopologyGeneration == 0 || !Hash(value.TopologyHash.Span))
            throw new InvalidDataException("Production LKG anchor is incomplete.");
    }
}

public interface IProductionMailboxTrustStateStore
{
    Task<ProductionMailboxTrustState?> ReadAsync(CancellationToken cancellationToken = default);

    /// <summary>Atomic compare/exchange; an unexpected revision must fail, never overwrite.</summary>
    Task CommitAsync(
        ulong expectedRevision,
        ProductionMailboxTrustState replacement,
        CancellationToken cancellationToken = default);
}

public sealed class VerifiedProductionMailboxControlPlane
{
    private readonly ProductionMailboxTrustState stateToCommit;

    internal VerifiedProductionMailboxControlPlane(
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        VerifiedProductionMailboxTopology topology,
        VerifiedProductionMailboxSelection currentSelection,
        VerifiedProductionMailboxSelection nextSelection,
        ProductionMailboxTrustState stateToCommit,
        ulong expectedStateRevision)
    {
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        Revocations = revocations ?? throw new ArgumentNullException(nameof(revocations));
        Topology = topology ?? throw new ArgumentNullException(nameof(topology));
        CurrentSelection = currentSelection ?? throw new ArgumentNullException(nameof(currentSelection));
        NextSelection = nextSelection ?? throw new ArgumentNullException(nameof(nextSelection));
        this.stateToCommit = ProductionMailboxControlPlaneVerifier.FreezeState(stateToCommit);
        ExpectedStateRevision = expectedStateRevision;
    }

    public VerifiedProductionMailboxAuthority Authority { get; }
    public VerifiedProductionMailboxRevocationSnapshot Revocations { get; }
    public VerifiedProductionMailboxTopology Topology { get; }
    public VerifiedProductionMailboxSelection CurrentSelection { get; }
    public VerifiedProductionMailboxSelection NextSelection { get; }

    internal ulong ExpectedStateRevision { get; }
    internal ProductionMailboxTrustState StateToCommit =>
        ProductionMailboxControlPlaneVerifier.FreezeState(stateToCommit);
    internal ProductionMailboxTrustState SnapshotStateToCommit() =>
        ProductionMailboxControlPlaneVerifier.FreezeState(stateToCommit);
}

/// <summary>
/// Verify-only PMA1 -> PMR1 -> PMT1 -> caller-bound PMS1 production chain. This type owns no
/// signer, private key, network fallback, or development fixture path.
/// </summary>
public static class ProductionMailboxControlPlaneVerifier
{
    public const string AndroidApplicationIdentity = "network.xpoint.deep";
    public const string WindowsApplicationIdentity = "Deep.Client.Maui.exe";

    public static async Task<VerifiedProductionMailboxControlPlane> VerifyAsync(
        ProductionMailboxControlPlaneArtifacts artifacts,
        ProductionMailboxTrustAnchor buildAnchor,
        IProductionMailboxTrustStateStore stateStore,
        ProductionMailboxClientApprovalIdentity clientIdentity,
        MailboxInfrastructureOwnership expectedOwnership,
        BlindedPlacementId currentPlacement,
        BlindedPlacementId nextPlacement,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        ArgumentNullException.ThrowIfNull(buildAnchor);
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(clientIdentity);
        ArgumentNullException.ThrowIfNull(currentPlacement);
        ArgumentNullException.ThrowIfNull(nextPlacement);
        PreflightArtifactLengths(artifacts);
        var frozenArtifacts = new ProductionMailboxControlPlaneArtifacts(
            artifacts.CanonicalAuthority.ToArray(),
            artifacts.CanonicalRevocationSnapshot.ToArray(),
            artifacts.CanonicalTopology.ToArray(),
            artifacts.CanonicalCurrentSelection.ToArray(),
            artifacts.CanonicalNextSelection.ToArray());
        PreflightArtifacts(frozenArtifacts);
        var frozenBuildAnchor = FreezeAnchor(buildAnchor);
        var frozenClientIdentity = FreezeIdentity(clientIdentity);
        var frozenCurrentPlacement = new BlindedPlacementId(currentPlacement.Bytes.Span);
        var frozenNextPlacement = new BlindedPlacementId(nextPlacement.Bytes.Span);
        ValidateAnchor(frozenBuildAnchor);
        ValidateIdentity(frozenClientIdentity);
        if (expectedOwnership is not (MailboxInfrastructureOwnership.OfficialManaged or
            MailboxInfrastructureOwnership.UserManaged))
            throw new InvalidDataException("Production MAU2 ownership is invalid.");

        cancellationToken.ThrowIfCancellationRequested();
        var persistedSource = await stateStore.ReadAsync(cancellationToken).ConfigureAwait(false);
        var persisted = persistedSource is null ? null : FreezeState(persistedSource);
        if (persisted is not null)
        {
            if (persisted.Revision == 0)
                throw new InvalidDataException("Production mailbox state revision is invalid.");
            ValidateAnchor(persisted.Root);
            ValidateAnchor(persisted.Previous);
            ValidateAnchor(persisted.Current);
            ValidateTrustDomain(persisted.Root, frozenBuildAnchor);
            ValidateTrustDomain(persisted.Previous, frozenBuildAnchor);
            ValidateTrustDomain(persisted.Current, frozenBuildAnchor);
        }

        var authorityBytes = frozenArtifacts.CanonicalAuthority.ToArray();
        var authorityCandidate = ProductionMailboxAuthorityCodec.Decode(authorityBytes);
        var authorityHash = SHA256.HashData(authorityBytes);
        var predecessor = SelectAuthorityPredecessor(
            authorityCandidate.AuthorityGeneration, authorityHash, frozenBuildAnchor, persisted);
        var nowSeconds = PositiveUnixTime(timeProvider ?? TimeProvider.System);
        var verifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(
            authorityCandidate,
            new ProductionMailboxAuthorityVerificationContext
            {
                PinnedMrXPublicKeySha256 = frozenBuildAnchor.MrXPublicKeySha256.ToArray(),
                ExpectedNetworkId = frozenBuildAnchor.NetworkId.ToArray(),
                LastCommittedGeneration = predecessor.AuthorityGeneration,
                LastCommittedAuthorityHash = predecessor.AuthorityHash.ToArray(),
                LastCommittedRevocationGeneration = predecessor.RevocationGeneration,
                LastCommittedRevocationHeadHash = predecessor.RevocationHeadHash.ToArray(),
                LastCommittedRevocationSnapshotHash = predecessor.RevocationSnapshotHash.ToArray(),
                NowUnixSeconds = nowSeconds,
                ClockSkewSeconds = ProductionMailboxAuthorityConstants.MaximumClockSkewSeconds
            },
            new SodiumProductionMailboxAuthoritySignatureVerifier());
        VerifyOwnership(verifiedAuthority.Authority, expectedOwnership);
        VerifyApproval(verifiedAuthority.Authority.MrXApproval, frozenClientIdentity);

        var revocations = ProductionMailboxRevocationSnapshotVerifier.Verify(
            frozenArtifacts.CanonicalRevocationSnapshot.Span,
            verifiedAuthority,
            nowSeconds,
            ProductionMailboxAuthorityConstants.MaximumClockSkewSeconds,
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());

        var topologyBytes = frozenArtifacts.CanonicalTopology.ToArray();
        var topologyCandidate = ProductionMailboxTopologyCodec.Decode(topologyBytes);
        var topologyHash = SHA256.HashData(topologyBytes);
        var topologyPredecessor = SelectTopologyPredecessor(
            topologyCandidate.TopologyGeneration, topologyHash, frozenBuildAnchor, persisted);
        var topology = ProductionMailboxTopologyVerifier.Verify(
            topologyBytes,
            verifiedAuthority,
            new ProductionMailboxTopologyVerificationContext
            {
                LastCommittedTopologyGeneration = topologyPredecessor.TopologyGeneration,
                LastCommittedTopologyHash = topologyPredecessor.TopologyHash.ToArray(),
                NowUnixSeconds = nowSeconds,
                ClockSkewSeconds = ProductionMailboxTopologyConstants.MaximumClockSkewSeconds
            },
            new SodiumProductionMailboxTopologySignatureVerifier());

        var authority = verifiedAuthority.Authority;
        var current = VerifySelection(
            frozenArtifacts.CanonicalCurrentSelection, frozenCurrentPlacement, authority.CurrentEpoch.Epoch,
            verifiedAuthority, topology, nowSeconds);
        var next = VerifySelection(
            frozenArtifacts.CanonicalNextSelection, frozenNextPlacement, authority.NextEpoch.Epoch,
            verifiedAuthority, topology, nowSeconds);
        var candidateAnchor = new ProductionMailboxTrustAnchor(
            frozenBuildAnchor.MrXPublicKeySha256.ToArray(),
            authority.NetworkId.ToArray(),
            authority.AuthorityGeneration,
            verifiedAuthority.CanonicalAuthorityHash.ToArray(),
            authority.Revocation.Generation,
            authority.Revocation.HeadHash.ToArray(),
            authority.Revocation.SnapshotHash.ToArray(),
            topology.CommittedTopologyGeneration,
            topology.CanonicalTopologyHash.ToArray());
        var coupledPredecessor = CombinePredecessors(
            frozenBuildAnchor, predecessor, topologyPredecessor);
        var expectedRevision = persisted?.Revision ?? 0;
        var state = persisted is null || !AnchorEquals(persisted.Current, candidateAnchor)
            ? new ProductionMailboxTrustState(
                checked(expectedRevision + 1),
                persisted?.Root ?? frozenBuildAnchor,
                coupledPredecessor,
                candidateAnchor)
            : persisted;
        return new VerifiedProductionMailboxControlPlane(
            verifiedAuthority, revocations, topology, current, next, state, expectedRevision);
    }

    public static Task CommitAsync(
        VerifiedProductionMailboxControlPlane verified,
        IProductionMailboxTrustStateStore stateStore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verified);
        ArgumentNullException.ThrowIfNull(stateStore);
        var replacement = verified.SnapshotStateToCommit();
        ValidateCommitState(replacement, verified.ExpectedStateRevision);
        if (replacement.Revision == verified.ExpectedStateRevision)
            return Task.CompletedTask;
        return stateStore.CommitAsync(
            verified.ExpectedStateRevision, replacement, cancellationToken);
    }

    private static VerifiedProductionMailboxSelection VerifySelection(
        ReadOnlyMemory<byte> encoded,
        BlindedPlacementId placement,
        ulong expectedEpoch,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxTopology topology,
        ulong now)
    {
        var selection = ProductionMailboxSelectionVerifier.Verify(
            encoded.Span, authority, topology, placement, now,
            ProductionMailboxTopologyConstants.MaximumClockSkewSeconds,
            new SodiumProductionMailboxTopologySignatureVerifier());
        if (selection.Proof.Epoch != expectedEpoch)
            throw new InvalidDataException("PMS1 is bound to the wrong authority epoch.");
        return selection;
    }

    private static void VerifyOwnership(
        ProductionMailboxAuthority authority,
        MailboxInfrastructureOwnership expected)
    {
        var actual = authority.Ownership switch
        {
            ProductionMailboxAuthorityOwnership.OfficialManaged =>
                MailboxInfrastructureOwnership.OfficialManaged,
            ProductionMailboxAuthorityOwnership.UserManaged =>
                MailboxInfrastructureOwnership.UserManaged,
            _ => throw new InvalidDataException("PMA1 ownership is unsupported.")
        };
        if (actual != expected)
            throw new InvalidDataException("PMA1 ownership does not match the selected mode.");
    }

    private static void VerifyApproval(
        ProductionMailboxAuthorityApproval approval,
        ProductionMailboxClientApprovalIdentity identity)
    {
        var expectedApplication = identity.Platform switch
        {
            MailboxClientPlatform.Android => AndroidApplicationIdentity,
            MailboxClientPlatform.Windows => WindowsApplicationIdentity,
            _ => throw new InvalidDataException("Production client platform is unsupported.")
        };
        if (!string.Equals(identity.ApplicationIdentity, expectedApplication, StringComparison.Ordinal))
            throw new InvalidDataException("Production application identity is not approved.");
        var signers = identity.Platform == MailboxClientPlatform.Android
            ? approval.AllowedAndroidSigningCertificateSha256
            : approval.AllowedWindowsSigningCertificateSha256;
        var artifacts = identity.Platform == MailboxClientPlatform.Android
            ? approval.AndroidReleaseBuildArtifactSha256
            : approval.WindowsReleaseBuildArtifactSha256;
        if (!ContainsHash(signers, identity.SigningCertificateSha256.Span) ||
            !ContainsHash(artifacts, identity.BuildArtifactSha256.Span))
            throw new InvalidDataException("Production client signer or build artifact is not approved by Mr. X.");
    }

    internal static ProductionMailboxTrustAnchor SelectAuthorityPredecessor(
        ulong generation,
        ReadOnlySpan<byte> candidateHash,
        ProductionMailboxTrustAnchor build,
        ProductionMailboxTrustState? persisted)
    {
        if (persisted is null ||
            build.AuthorityGeneration > persisted.Current.AuthorityGeneration)
        {
            if (generation != checked(build.AuthorityGeneration + 1))
                throw new InvalidDataException("PMA1 does not succeed the build-pinned authority.");
            return build;
        }
        if (build.AuthorityGeneration == persisted.Current.AuthorityGeneration &&
            !AuthorityComponentEquals(build, persisted.Current))
            throw new InvalidDataException("PMA1 persisted state conflicts with the build trust floor.");
        if (generation == persisted.Current.AuthorityGeneration &&
            Fixed(candidateHash, persisted.Current.AuthorityHash.Span) &&
            build.AuthorityGeneration <= persisted.Current.AuthorityGeneration)
            return persisted.Previous;
        if (generation == checked(persisted.Current.AuthorityGeneration + 1))
            return persisted.Current;
        throw new InvalidDataException("PMA1 is a rollback, fork, or generation gap.");
    }

    internal static ProductionMailboxTrustAnchor SelectTopologyPredecessor(
        ulong generation,
        ReadOnlySpan<byte> candidateHash,
        ProductionMailboxTrustAnchor build,
        ProductionMailboxTrustState? persisted)
    {
        if (persisted is null ||
            build.TopologyGeneration > persisted.Current.TopologyGeneration)
        {
            if (generation != checked(build.TopologyGeneration + 1))
                throw new InvalidDataException("PMT1 does not succeed the build-pinned topology.");
            return build;
        }
        if (build.TopologyGeneration == persisted.Current.TopologyGeneration &&
            !TopologyComponentEquals(build, persisted.Current))
            throw new InvalidDataException("PMT1 persisted state conflicts with the build trust floor.");
        if (generation == persisted.Current.TopologyGeneration &&
            Fixed(candidateHash, persisted.Current.TopologyHash.Span) &&
            build.TopologyGeneration <= persisted.Current.TopologyGeneration)
            return persisted.Previous;
        if (generation == checked(persisted.Current.TopologyGeneration + 1))
            return persisted.Current;
        throw new InvalidDataException("PMT1 is a rollback, fork, or generation gap.");
    }

    internal static ProductionMailboxTrustAnchor CombinePredecessors(
        ProductionMailboxTrustAnchor trustDomain,
        ProductionMailboxTrustAnchor authority,
        ProductionMailboxTrustAnchor topology) => new(
            trustDomain.MrXPublicKeySha256.ToArray(),
            trustDomain.NetworkId.ToArray(),
            authority.AuthorityGeneration,
            authority.AuthorityHash.ToArray(),
            authority.RevocationGeneration,
            authority.RevocationHeadHash.ToArray(),
            authority.RevocationSnapshotHash.ToArray(),
            topology.TopologyGeneration,
            topology.TopologyHash.ToArray());

    internal static ProductionMailboxTrustState FreezeState(ProductionMailboxTrustState value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Revision == 0)
            throw new InvalidDataException("Production mailbox state revision is invalid.");
        ValidateAnchor(value.Root);
        ValidateAnchor(value.Previous);
        ValidateAnchor(value.Current);
        var frozen = new ProductionMailboxTrustState(
            value.Revision,
            FreezeAnchor(value.Root),
            FreezeAnchor(value.Previous),
            FreezeAnchor(value.Current));
        return frozen;
    }

    private static ProductionMailboxTrustAnchor FreezeAnchor(ProductionMailboxTrustAnchor value)
    {
        ValidateAnchor(value);
        var frozen = new ProductionMailboxTrustAnchor(
            value.MrXPublicKeySha256.ToArray(), value.NetworkId.ToArray(),
            value.AuthorityGeneration, value.AuthorityHash.ToArray(),
            value.RevocationGeneration, value.RevocationHeadHash.ToArray(),
            value.RevocationSnapshotHash.ToArray(), value.TopologyGeneration,
            value.TopologyHash.ToArray());
        ValidateAnchor(frozen);
        return frozen;
    }

    private static ProductionMailboxClientApprovalIdentity FreezeIdentity(
        ProductionMailboxClientApprovalIdentity value)
    {
        ValidateIdentity(value);
        var frozen = new ProductionMailboxClientApprovalIdentity(
            value.Platform, value.ApplicationIdentity,
            value.SigningCertificateSha256.ToArray(),
            value.BuildArtifactSha256.ToArray());
        ValidateIdentity(frozen);
        return frozen;
    }

    private static void PreflightArtifacts(ProductionMailboxControlPlaneArtifacts value)
    {
        PreflightAuthority(value.CanonicalAuthority.Span);
        PreflightRevocations(value.CanonicalRevocationSnapshot.Span);
        PreflightTopology(value.CanonicalTopology.Span);
        PreflightSelection(value.CanonicalCurrentSelection.Span, "current PMS1");
        PreflightSelection(value.CanonicalNextSelection.Span, "next PMS1");
    }

    private static void PreflightArtifactLengths(ProductionMailboxControlPlaneArtifacts value)
    {
        RequireLength(value.CanonicalAuthority.Length, 821,
            ProductionMailboxAuthorityConstants.MaximumArtifactBytes, "PMA1");
        RequireLength(value.CanonicalRevocationSnapshot.Length,
            ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials,
            ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes, "PMR1");
        RequireLength(value.CanonicalTopology.Length, 780,
            ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes, "PMT1");
        RequireLength(value.CanonicalCurrentSelection.Length, 410,
            ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes, "current PMS1");
        RequireLength(value.CanonicalNextSelection.Length, 410,
            ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes, "next PMS1");
    }

    private static void RequireLength(int length, int minimum, int maximum, string label)
    {
        if (length < minimum || length > maximum)
            throw new InvalidDataException($"{label} length is outside strict bounds.");
    }

    private static void PreflightAuthority(ReadOnlySpan<byte> value)
    {
        if (value.Length is < 821 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes)
            throw new InvalidDataException("PMA1 length is outside strict bounds.");
        var offset = 133;
        for (var endpoint = 0; endpoint < 2; endpoint++)
        {
            Require(value, offset, 1, "PMA1");
            var length = value[offset++];
            if (length == 0) throw new InvalidDataException("PMA1 endpoint length is invalid.");
            Skip(value, ref offset, checked(length + 64), "PMA1");
        }
        Skip(value, ref offset, 192 + 120 + 32, "PMA1");
        for (var list = 0; list < 4; list++)
        {
            Require(value, offset, 1, "PMA1");
            var count = value[offset++];
            if (count is < 1 or > ProductionMailboxAuthorityConstants.MaximumHashesPerPlatform)
                throw new InvalidDataException("PMA1 approval count is outside strict bounds.");
            Skip(value, ref offset, checked(count * 32), "PMA1");
        }
        Skip(value, ref offset, 16 + 64, "PMA1");
        RequireEnd(value, offset, "PMA1");
    }

    private static void PreflightRevocations(ReadOnlySpan<byte> value)
    {
        if (value.Length is < ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials
            or > ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes)
            throw new InvalidDataException("PMR1 length is outside strict bounds.");
        const int countOffset = 152;
        var count = BinaryPrimitives.ReadUInt16LittleEndian(value.Slice(countOffset, 2));
        var expected = checked(ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials +
            count * ProductionMailboxRevocationSnapshotConstants.RevokedGrantSerialBytes);
        if (count > ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials ||
            value.Length != expected)
            throw new InvalidDataException("PMR1 length does not match its bounded count.");
    }

    private static void PreflightTopology(ReadOnlySpan<byte> value)
    {
        if (value.Length is < 780 or > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes)
            throw new InvalidDataException("PMT1 length is outside strict bounds.");
        var offset = 120;
        for (var epoch = 0; epoch < 2; epoch++)
        {
            Skip(value, ref offset, 96, "PMT1");
            var count = ReadUInt16BigEndian(value, ref offset, "PMT1");
            Skip(value, ref offset, 2, "PMT1");
            if (count is < 2 or > ProductionMailboxTopologyConstants.MaximumNodesPerEpoch)
                throw new InvalidDataException("PMT1 node count is outside strict bounds.");
            for (var node = 0; node < count; node++)
            {
                Skip(value, ref offset, 32, "PMT1");
                var endpointLength = ReadUInt16BigEndian(value, ref offset, "PMT1");
                if (endpointLength is < 1 or > ProductionMailboxTopologyConstants.MaximumEndpointBytes)
                    throw new InvalidDataException("PMT1 endpoint length is outside strict bounds.");
                Skip(value, ref offset, checked(endpointLength + 64), "PMT1");
            }
        }
        Skip(value, ref offset, 64, "PMT1");
        RequireEnd(value, offset, "PMT1");
    }

    private static void PreflightSelection(ReadOnlySpan<byte> value, string label)
    {
        if (value.Length is < 410 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes)
            throw new InvalidDataException($"{label} length is outside strict bounds.");
        var offset = 268;
        Require(value, offset, 1, label);
        var count = value[offset++];
        Skip(value, ref offset, 3, label);
        if (count != ProductionMailboxTopologyConstants.ReplicaCount)
            throw new InvalidDataException($"{label} replica count is invalid.");
        for (var replica = 0; replica < count; replica++)
        {
            Skip(value, ref offset, 32, label);
            var proofLength = ReadUInt16BigEndian(value, ref offset, label);
            Skip(value, ref offset, 2, label);
            if (proofLength == 0)
                throw new InvalidDataException($"{label} proof length is invalid.");
            Skip(value, ref offset, proofLength, label);
        }
        Skip(value, ref offset, 64, label);
        RequireEnd(value, offset, label);
    }

    private static ushort ReadUInt16BigEndian(
        ReadOnlySpan<byte> value, ref int offset, string label)
    {
        Require(value, offset, 2, label);
        var result = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(offset, 2));
        offset += 2;
        return result;
    }

    private static void Skip(ReadOnlySpan<byte> value, ref int offset, int count, string label)
    {
        Require(value, offset, count, label);
        offset = checked(offset + count);
    }

    private static void Require(ReadOnlySpan<byte> value, int offset, int count, string label)
    {
        if (offset < 0 || count < 0 || offset > value.Length - count)
            throw new InvalidDataException($"{label} is truncated.");
    }

    private static void RequireEnd(ReadOnlySpan<byte> value, int offset, string label)
    {
        if (offset != value.Length)
            throw new InvalidDataException($"{label} length does not match its bounded counts.");
    }

    private static void ValidateCommitState(
        ProductionMailboxTrustState value, ulong expectedRevision)
    {
        ValidateAnchor(value.Root);
        ValidateAnchor(value.Previous);
        ValidateAnchor(value.Current);
        ValidateTrustDomain(value.Previous, value.Root);
        ValidateTrustDomain(value.Current, value.Root);
        if (value.Revision != expectedRevision &&
            (expectedRevision == ulong.MaxValue || value.Revision != expectedRevision + 1))
            throw new InvalidDataException("Production mailbox commit revision is invalid.");
    }

    private static ulong PositiveUnixTime(TimeProvider provider)
    {
        var value = provider.GetUtcNow().ToUnixTimeSeconds();
        if (value <= 0) throw new InvalidDataException("Production verification clock is invalid.");
        return checked((ulong)value);
    }

    private static void ValidateIdentity(ProductionMailboxClientApprovalIdentity value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var expectedApplication = value.Platform switch
        {
            MailboxClientPlatform.Android => AndroidApplicationIdentity,
            MailboxClientPlatform.Windows => WindowsApplicationIdentity,
            _ => null
        };
        if (expectedApplication is null ||
            !string.Equals(value.ApplicationIdentity, expectedApplication, StringComparison.Ordinal) ||
            !NonzeroHash(value.SigningCertificateSha256.Span) ||
            !NonzeroHash(value.BuildArtifactSha256.Span))
            throw new InvalidDataException("Production client approval identity is incomplete.");
    }

    private static void ValidateAnchor(ProductionMailboxTrustAnchor value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!NonzeroHash(value.MrXPublicKeySha256.Span) || value.NetworkId.Length != 16 ||
            value.NetworkId.Span.IndexOfAnyExcept((byte)0) < 0 || value.AuthorityGeneration == 0 ||
            !NonzeroHash(value.AuthorityHash.Span) || value.RevocationGeneration == 0 ||
            !NonzeroHash(value.RevocationHeadHash.Span) ||
            !NonzeroHash(value.RevocationSnapshotHash.Span) || value.TopologyGeneration == 0 ||
            !NonzeroHash(value.TopologyHash.Span))
            throw new InvalidDataException("Production mailbox trust anchor is incomplete.");
    }

    private static void ValidateTrustDomain(
        ProductionMailboxTrustAnchor persisted,
        ProductionMailboxTrustAnchor build)
    {
        if (!Fixed(persisted.MrXPublicKeySha256.Span,
                build.MrXPublicKeySha256.Span) ||
            !Fixed(persisted.NetworkId.Span, build.NetworkId.Span))
            throw new InvalidDataException(
                "Production mailbox state belongs to another trust domain.");
    }

    private static bool AuthorityComponentEquals(
        ProductionMailboxTrustAnchor left,
        ProductionMailboxTrustAnchor right) =>
        left.AuthorityGeneration == right.AuthorityGeneration &&
        left.RevocationGeneration == right.RevocationGeneration &&
        Fixed(left.AuthorityHash.Span, right.AuthorityHash.Span) &&
        Fixed(left.RevocationHeadHash.Span, right.RevocationHeadHash.Span) &&
        Fixed(left.RevocationSnapshotHash.Span,
            right.RevocationSnapshotHash.Span);

    private static bool TopologyComponentEquals(
        ProductionMailboxTrustAnchor left,
        ProductionMailboxTrustAnchor right) =>
        left.TopologyGeneration == right.TopologyGeneration &&
        Fixed(left.TopologyHash.Span, right.TopologyHash.Span);

    private static bool AnchorEquals(ProductionMailboxTrustAnchor left, ProductionMailboxTrustAnchor right) =>
        left.AuthorityGeneration == right.AuthorityGeneration &&
        left.RevocationGeneration == right.RevocationGeneration &&
        left.TopologyGeneration == right.TopologyGeneration &&
        Fixed(left.MrXPublicKeySha256.Span, right.MrXPublicKeySha256.Span) &&
        Fixed(left.NetworkId.Span, right.NetworkId.Span) &&
        Fixed(left.AuthorityHash.Span, right.AuthorityHash.Span) &&
        Fixed(left.RevocationHeadHash.Span, right.RevocationHeadHash.Span) &&
        Fixed(left.RevocationSnapshotHash.Span, right.RevocationSnapshotHash.Span) &&
        Fixed(left.TopologyHash.Span, right.TopologyHash.Span);

    private static bool ContainsHash(
        IReadOnlyList<ReadOnlyMemory<byte>> candidates,
        ReadOnlySpan<byte> expected)
    {
        if (!NonzeroHash(expected)) return false;
        foreach (var candidate in candidates)
            if (Fixed(candidate.Span, expected)) return true;
        return false;
    }

    private static bool NonzeroHash(ReadOnlySpan<byte> value) =>
        value.Length == 32 && value.IndexOfAnyExcept((byte)0) >= 0;

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
