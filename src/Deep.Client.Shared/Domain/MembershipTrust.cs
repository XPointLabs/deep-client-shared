using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Client.Shared.Domain;

public enum MembershipTrustDomain
{
    Authority = 1,
    Bridge = 2,
    Membership = 3
}

public enum MembershipTrustArtifactKind
{
    Anchor = 1,
    Delegation = 2,
    Revocation = 3,
    Bridge = 4,
    Membership = 5,
    SelfHostedGenesis = 6
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
    byte[] CanonicalSignatures);

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

    public required MembershipTrustArtifactKind ArtifactKind { get; init; }

    public required ulong Revision { get; init; }

    public required ulong Sequence { get; init; }

    public required ulong PreviousSequence { get; init; }

    public required byte[] PreviousCanonicalHash { get; init; }

    public required byte[] CanonicalEnvelope { get; init; }

    public required byte[] PayloadDigest { get; init; }

    public required byte[] CanonicalHash { get; init; }

    public required byte[] ProfileBindingHash { get; init; }

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
        byte[]? canonicalHash = null,
        byte[]? profileBindingHash = null,
        MembershipTrustArtifactKind? artifactKind = null)
    {
        ArgumentNullException.ThrowIfNull(previousCanonicalHash);
        ArgumentNullException.ThrowIfNull(canonicalEnvelope);
        var record = new MembershipTrustRecord
        {
            Version = SchemaVersion,
            OpaqueProfileKey = opaqueProfileKey,
            Domain = domain,
            ArtifactKind = artifactKind ?? domain switch
            {
                MembershipTrustDomain.Authority => MembershipTrustArtifactKind.Delegation,
                MembershipTrustDomain.Bridge => MembershipTrustArtifactKind.Bridge,
                MembershipTrustDomain.Membership => MembershipTrustArtifactKind.Membership,
                _ => throw new ArgumentOutOfRangeException(nameof(domain))
            },
            Revision = revision,
            Sequence = sequence,
            PreviousSequence = previousSequence,
            PreviousCanonicalHash = previousCanonicalHash.ToArray(),
            CanonicalEnvelope = canonicalEnvelope.ToArray(),
            PayloadDigest = [],
            CanonicalHash = (canonicalHash ?? SHA256.HashData(canonicalEnvelope)).ToArray(),
            ProfileBindingHash = (profileBindingHash ??
                SHA256.HashData(Encoding.UTF8.GetBytes(opaqueProfileKey))).ToArray(),
            State = state,
            ObservedAt = observedAt,
            ValidFrom = validFrom ?? DateTimeOffset.UnixEpoch,
            ValidUntil = validUntil
        };
        record = record with { PayloadDigest = ComputePayloadDigest(record) };
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
            !Enum.IsDefined(record.ArtifactKind) ||
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
            !ComputePayloadDigest(record).AsSpan().SequenceEqual(record.PayloadDigest) ||
            record.CanonicalHash is null ||
            record.CanonicalHash.Length != MembershipLimits.HashLength ||
            record.ProfileBindingHash is null ||
            record.ProfileBindingHash.Length != MembershipLimits.HashLength ||
            !Enum.IsDefined(record.State) ||
            record.ObservedAt < DateTimeOffset.UnixEpoch ||
            record.ValidFrom > record.ValidUntil)
        {
            throw new InvalidDataException("Membership trust state is invalid.");
        }
    }

    public static byte[] ComputePayloadDigest(MembershipTrustRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "deep.membership-trust-record/v1"u8);
        AppendInt32(hash, record.Version);
        var profile = Encoding.UTF8.GetBytes(record.OpaqueProfileKey ?? string.Empty);
        AppendUInt32(hash, checked((uint)profile.Length));
        Append(hash, profile);
        AppendInt32(hash, (int)record.Domain);
        AppendInt32(hash, (int)record.ArtifactKind);
        AppendUInt64(hash, record.Revision);
        AppendUInt64(hash, record.Sequence);
        AppendUInt64(hash, record.PreviousSequence);
        AppendFixed(hash, record.PreviousCanonicalHash);
        AppendUInt32(hash, checked((uint)(record.CanonicalEnvelope?.Length ?? 0)));
        Append(hash, record.CanonicalEnvelope ?? []);
        AppendFixed(hash, record.CanonicalHash);
        AppendFixed(hash, record.ProfileBindingHash);
        AppendInt32(hash, (int)record.State);
        AppendInt64(hash, record.ObservedAt.ToUnixTimeSeconds());
        AppendInt64(hash, record.ValidFrom.ToUnixTimeSeconds());
        AppendInt64(hash, record.ValidUntil.ToUnixTimeSeconds());
        return hash.GetHashAndReset();
    }

    private static void AppendFixed(IncrementalHash hash, byte[]? value)
    {
        AppendUInt32(hash, checked((uint)(value?.Length ?? 0)));
        Append(hash, value ?? []);
    }

    private static void AppendInt32(IncrementalHash hash, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private static void AppendUInt32(IncrementalHash hash, uint value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private static void AppendInt64(IncrementalHash hash, long value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private static void AppendUInt64(IncrementalHash hash, ulong value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value) =>
        hash.AppendData(value);
}

public sealed record MembershipTrustClockRecord
{
    public const int SchemaVersion = 1;

    public required int Version { get; init; }

    public required string OpaqueProfileKey { get; init; }

    public required ulong Revision { get; init; }

    public required DateTimeOffset ObservedAt { get; init; }

    public required byte[] Digest { get; init; }

    public static MembershipTrustClockRecord Create(
        string opaqueProfileKey,
        ulong revision,
        DateTimeOffset observedAt)
    {
        var record = new MembershipTrustClockRecord
        {
            Version = SchemaVersion,
            OpaqueProfileKey = opaqueProfileKey,
            Revision = revision,
            ObservedAt = observedAt,
            Digest = []
        };
        record = record with { Digest = ComputeDigest(record) };
        Validate(record);
        return record;
    }

    public static void Validate(MembershipTrustClockRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.Version != SchemaVersion ||
            string.IsNullOrWhiteSpace(record.OpaqueProfileKey) ||
            record.OpaqueProfileKey.Length > MembershipTrustRecord.MaximumProfileKeyLength ||
            record.Revision == 0 ||
            record.Revision > long.MaxValue ||
            record.ObservedAt < DateTimeOffset.UnixEpoch ||
            record.Digest is null ||
            record.Digest.Length != MembershipLimits.HashLength ||
            !ComputeDigest(record).AsSpan().SequenceEqual(record.Digest))
        {
            throw new InvalidDataException("Membership trust clock is invalid.");
        }
    }

    public static byte[] ComputeDigest(MembershipTrustClockRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("deep.membership-trust-clock/v1"u8);
        var profile = Encoding.UTF8.GetBytes(record.OpaqueProfileKey ?? string.Empty);
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, checked((ulong)profile.Length));
        hash.AppendData(bytes);
        hash.AppendData(profile);
        BinaryPrimitives.WriteUInt64BigEndian(bytes, record.Revision);
        hash.AppendData(bytes);
        BinaryPrimitives.WriteInt64BigEndian(bytes, record.ObservedAt.ToUnixTimeSeconds());
        hash.AppendData(bytes);
        return hash.GetHashAndReset();
    }
}
