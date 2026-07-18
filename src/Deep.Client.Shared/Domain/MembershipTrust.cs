using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Client.Shared.Domain;

public enum MembershipTrustDomain
{
    Authority = 1,
    Bridge = 2,
    Membership = 3
}

public enum MembershipTrustState
{
    Disabled = 0,
    MissingBootstrap = 1,
    VerifierUnavailable = 2,
    Healthy = 3,
    DegradedStale = 4,
    Expired = 5,
    NotYetValid = 6,
    ProtocolUnsupported = 7,
    Revoked = 8,
    ClockRollback = 9,
    ForkDetected = 10,
    Corrupt = 11
}

public enum MembershipTrustEvent
{
    None = 0,
    BootstrapRequired = 1,
    VerificationRejected = 2,
    StateAccepted = 3,
    StateUnchanged = 4,
    EquivocationObserved = 5,
    LocalStateRejected = 6
}

public sealed record MembershipTrustAnchor(
    ulong Sequence,
    byte[] CanonicalHash);

public sealed record MembershipTrustProfile(
    string OpaqueProfileKey,
    byte[] CanonicalGenesis,
    byte[] ExpectedNetworkId,
    byte[] ExpectedCanonicalGenesisSha256,
    byte[] SignedDelegation,
    MembershipTrustAnchor? BridgeAnchor,
    MembershipTrustAnchor? MembershipAnchor);

public sealed record SelfHostedGenesisImport(
    string OpaqueProfileKey,
    byte[] CanonicalGenesis,
    byte[] ExpectedNetworkId,
    byte[] ExpectedCanonicalGenesisSha256,
    IReadOnlyList<MembershipSignature> Signatures);

public sealed record MembershipTrustOptions
{
    public bool Enabled { get; init; }

    public bool LegacyEmbeddedBootstrapRollbackAllowed { get; init; }

    public ushort ClientProtocol { get; init; } = 2;

    public TimeSpan AllowedClockSkew { get; init; } = TimeSpan.Zero;

    public TimeSpan ClockRollbackTolerance { get; init; } = TimeSpan.Zero;

    public TimeSpan StaleGrace { get; init; } = TimeSpan.Zero;

    public int MaximumEnvelopeBytes { get; init; } = 128 * 1024;

    public static MembershipTrustOptions DormantDefaults { get; } = new();
}

public sealed record MembershipTrustStatus(
    MembershipTrustState State,
    MembershipTrustEvent Event,
    bool Usable,
    bool LegacyRollbackEligible)
{
    public static MembershipTrustStatus For(
        MembershipTrustState state,
        MembershipTrustEvent @event = MembershipTrustEvent.None) =>
        new(
            state,
            @event,
            state == MembershipTrustState.Healthy,
            LegacyRollbackEligible: false);
}

public sealed record MembershipTrustRecord
{
    public const int SchemaVersion = 1;
    public const int MaximumProfileKeyLength = 128;
    public const int MaximumEnvelopeLength = 128 * 1024;

    public required int Version { get; init; }

    public required string OpaqueProfileKey { get; init; }

    public required MembershipTrustDomain Domain { get; init; }

    public required ulong Revision { get; init; }

    public required ulong Sequence { get; init; }

    public required ulong PreviousSequence { get; init; }

    public required byte[] PreviousCanonicalHash { get; init; }

    public required byte[] CanonicalEnvelope { get; init; }

    public required byte[] PayloadDigest { get; init; }

    public required byte[] CanonicalHash { get; init; }

    public required MembershipTrustState State { get; init; }

    public required DateTimeOffset ObservedAt { get; init; }

    public required DateTimeOffset ValidFrom { get; init; }

    public required DateTimeOffset ValidUntil { get; init; }

    public string PayloadDigestHex => Convert.ToHexStringLower(PayloadDigest);

    public static MembershipTrustRecord Create(
        string opaqueProfileKey,
        MembershipTrustDomain domain,
        ulong revision,
        ulong sequence,
        ulong previousSequence,
        byte[] previousCanonicalHash,
        byte[] canonicalEnvelope,
        MembershipTrustState state,
        DateTimeOffset observedAt,
        DateTimeOffset validUntil,
        DateTimeOffset? validFrom = null,
        byte[]? canonicalHash = null)
    {
        ArgumentNullException.ThrowIfNull(previousCanonicalHash);
        ArgumentNullException.ThrowIfNull(canonicalEnvelope);
        var record = new MembershipTrustRecord
        {
            Version = SchemaVersion,
            OpaqueProfileKey = opaqueProfileKey,
            Domain = domain,
            Revision = revision,
            Sequence = sequence,
            PreviousSequence = previousSequence,
            PreviousCanonicalHash = previousCanonicalHash.ToArray(),
            CanonicalEnvelope = canonicalEnvelope.ToArray(),
            PayloadDigest = SHA256.HashData(canonicalEnvelope),
            CanonicalHash = (canonicalHash ?? SHA256.HashData(canonicalEnvelope)).ToArray(),
            State = state,
            ObservedAt = observedAt,
            ValidFrom = validFrom ?? DateTimeOffset.UnixEpoch,
            ValidUntil = validUntil
        };
        Validate(record);
        return record;
    }

    public static void Validate(MembershipTrustRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.Version != SchemaVersion ||
            string.IsNullOrWhiteSpace(record.OpaqueProfileKey) ||
            record.OpaqueProfileKey.Length > MaximumProfileKeyLength ||
            !Enum.IsDefined(record.Domain) ||
            record.Revision == 0 ||
            record.Revision > long.MaxValue ||
            record.Sequence == 0 ||
            record.Sequence > long.MaxValue ||
            record.PreviousSequence > long.MaxValue ||
            record.PreviousSequence >= record.Sequence ||
            record.PreviousCanonicalHash is null ||
            record.PreviousCanonicalHash.Length != MembershipLimits.HashLength ||
            record.CanonicalEnvelope is null ||
            record.CanonicalEnvelope.Length is <= 0 or > MaximumEnvelopeLength ||
            record.PayloadDigest is null ||
            record.PayloadDigest.Length != MembershipLimits.HashLength ||
            !SHA256.HashData(record.CanonicalEnvelope).AsSpan().SequenceEqual(record.PayloadDigest) ||
            record.CanonicalHash is null ||
            record.CanonicalHash.Length != MembershipLimits.HashLength ||
            !Enum.IsDefined(record.State) ||
            record.ObservedAt < DateTimeOffset.UnixEpoch ||
            record.ValidFrom > record.ValidUntil)
        {
            throw new InvalidDataException("Membership trust state is invalid.");
        }
    }
}
