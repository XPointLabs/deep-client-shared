using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;

namespace Deep.Client.Shared.Persistence.ContactV1;

/// <summary>
/// Bounded, byte-only recovery evidence for a verified contact. Reading this
/// object does not grant identity, directory, route, or messaging authority;
/// every authority consumer must decode the exact transcript and run the
/// trusted ContactV1 verifier again.
/// </summary>
public sealed class ContactVerifiedPeerPackageEvidence
{
    public const ushort CurrentVersion = 1;
    internal const int MaximumTranscriptBytes = 131_072;
    internal const int MaximumArtifactBytes = 65_535;
    internal const int MaximumDevices = 16;

    private readonly byte[] networkId;
    private readonly byte[] exactCanonicalAddress;
    private readonly byte[] exactXiq1;
    private readonly byte[] exactXis1;
    private readonly byte[] exactDcr1;
    private readonly byte[] exactDcb1;
    private readonly byte[] exactDmd1;
    private readonly ContactVerifiedPeerDeviceEvidence[] devices;
    private readonly byte[] exactRouteClosure;
    private readonly byte[] packageHash;

    internal ContactVerifiedPeerPackageEvidence(
        ContactStoreScope scope,
        ContactRelationshipId32 relationshipId,
        ContactConversationId32 conversationId,
        ContactAccountId32 remoteAccountId,
        ContactAddressKind addressKind,
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> exactCanonicalAddress,
        ReadOnlySpan<byte> exactXiq1,
        ReadOnlySpan<byte> exactXis1,
        ReadOnlySpan<byte> exactDcr1,
        ReadOnlySpan<byte> exactDcb1,
        ReadOnlySpan<byte> exactDmd1,
        IReadOnlyList<ContactVerifiedPeerDeviceEvidence> devices,
        ReadOnlySpan<byte> exactRouteClosure,
        ReadOnlySpan<byte> expectedPackageHash = default,
        bool requireCanonicalVerification = false)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        RelationshipId = relationshipId ?? throw new ArgumentNullException(nameof(relationshipId));
        ConversationId = conversationId ?? throw new ArgumentNullException(nameof(conversationId));
        RemoteAccountId = remoteAccountId ?? throw new ArgumentNullException(nameof(remoteAccountId));
        ArgumentNullException.ThrowIfNull(devices);
        if (!Enum.IsDefined(addressKind)) throw new FormatException("Verified-peer address kind is invalid.");
        if (networkId16.Length != 16 || networkId16.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("Verified-peer network ID is invalid.");
        RequireBounded(exactCanonicalAddress, 1, 225, nameof(exactCanonicalAddress));
        RequireBounded(exactXiq1, 1, MaximumArtifactBytes, nameof(exactXiq1));
        RequireBounded(exactXis1, 1, MaximumTranscriptBytes, nameof(exactXis1));
        RequireBounded(exactDcr1, 1, MaximumArtifactBytes, nameof(exactDcr1));
        RequireBounded(exactDcb1, 1, MaximumArtifactBytes, nameof(exactDcb1));
        RequireBounded(exactDmd1, 1, MaximumArtifactBytes, nameof(exactDmd1));
        RequireBounded(exactRouteClosure, 1, MaximumArtifactBytes, nameof(exactRouteClosure));
        if (devices.Count is < 1 or > MaximumDevices)
            throw new FormatException("Verified-peer device directory count is invalid.");

        AddressKind = addressKind;
        networkId = networkId16.ToArray();
        this.exactCanonicalAddress = exactCanonicalAddress.ToArray();
        this.exactXiq1 = exactXiq1.ToArray();
        this.exactXis1 = exactXis1.ToArray();
        this.exactDcr1 = exactDcr1.ToArray();
        this.exactDcb1 = exactDcb1.ToArray();
        this.exactDmd1 = exactDmd1.ToArray();
        this.devices = devices.Select(static value => value.Copy()).ToArray();
        if (this.devices.Select(static value => Convert.ToHexString(value.DeviceId.Span))
            .Distinct(StringComparer.Ordinal).Count() != this.devices.Length)
            throw new FormatException("Verified-peer device IDs must be unique.");
        this.exactRouteClosure = exactRouteClosure.ToArray();

        if (requireCanonicalVerification) ValidateCanonicalCorrelations();
        packageHash = ComputeHash();
        if (!expectedPackageHash.IsEmpty &&
            (expectedPackageHash.Length != 32 ||
             !CryptographicOperations.FixedTimeEquals(packageHash, expectedPackageHash)))
            throw new FormatException("Verified-peer package hash is invalid.");
    }

    public ushort Version => CurrentVersion;
    public ContactStoreScope Scope { get; }
    public ContactRelationshipId32 RelationshipId { get; }
    public ContactConversationId32 ConversationId { get; }
    public ContactAccountId32 RemoteAccountId { get; }
    public ContactAddressKind AddressKind { get; }
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> ExactCanonicalAddress => exactCanonicalAddress.ToArray();
    public ReadOnlyMemory<byte> ExactXiq1 => exactXiq1.ToArray();
    public ReadOnlyMemory<byte> ExactXis1 => exactXis1.ToArray();
    public ReadOnlyMemory<byte> ExactDcr1 => exactDcr1.ToArray();
    public ReadOnlyMemory<byte> ExactDcb1 => exactDcb1.ToArray();
    public ReadOnlyMemory<byte> ExactDmd1 => exactDmd1.ToArray();
    public IReadOnlyList<ContactVerifiedPeerDeviceEvidence> Devices =>
        Array.AsReadOnly(devices.Select(static value => value.Copy()).ToArray());
    public ReadOnlyMemory<byte> ExactRouteClosure => exactRouteClosure.ToArray();
    public ReadOnlyMemory<byte> PackageHash => packageHash.ToArray();

    internal ContactVerifiedPeerPackageEvidence Copy() => new(
        Scope, RelationshipId, ConversationId, RemoteAccountId, AddressKind,
        networkId, exactCanonicalAddress, exactXiq1, exactXis1, exactDcr1,
        exactDcb1, exactDmd1, devices, exactRouteClosure, packageHash);

    private void ValidateCanonicalCorrelations()
    {
        ContactStatePersistenceValidation.ValidateLookup(AddressKind, exactCanonicalAddress);
        var request = Xiq1Codec.Decode(exactXiq1);
        var result = Xis1Codec.Decode(exactXis1, exactXiq1);
        if (result.Status != Xis1Status.Success ||
            !request.NetworkId.Span.SequenceEqual(networkId) ||
            !result.NetworkId.Span.SequenceEqual(networkId))
            throw new FormatException("Verified-peer transcript is not a successful resolve for its network.");
        var oneTime = AddressKind == ContactAddressKind.OneTimeInvitation;
        if (oneTime != (result.MutationOutcome == ContactServiceMutationOutcome.DurablyCommitted) ||
            (oneTime && (result.Field(22).Length != sizeof(ulong) || result.Field(23).Length != 193)) ||
            (!oneTime && (result.MutationOutcome != ContactServiceMutationOutcome.None ||
                          result.Field(22).Length != 193 || !result.Field(23).IsEmpty)))
            throw new FormatException("Verified-peer transcript has the wrong consumable-address shape.");
        var dcr = ContactCodec.Decode("DCR1", exactDcr1);
        var dcb = ContactCodec.Decode("DCB1", exactDcb1);
        var dmd = ApplicationCoreCodec.DecodeDmd1(exactDmd1);
        if (!dcr.Field(1).Span.SequenceEqual(networkId) ||
            !dcr.Field(2).Span.SequenceEqual(exactDcb1) ||
            !dcb.Field(1).Span.SequenceEqual(networkId) ||
            !dcb.Field(5).Span.SequenceEqual(exactDmd1) ||
            !dmd.NetworkId.Span.SequenceEqual(networkId) ||
            !dmd.DeepAccountId.Span.SequenceEqual(RemoteAccountId.Span) ||
            !result.Field(21).Span.SequenceEqual(exactRouteClosure))
            throw new FormatException("Verified-peer canonical artifacts are not byte-correlated.");
        if (dmd.ActiveDevices.Count != devices.Length)
            throw new FormatException("Verified-peer device directory is incomplete.");
        for (var index = 0; index < devices.Length; index++)
        {
            var entry = dmd.ActiveDevices[index];
            var device = devices[index];
            var certificate = IdentityCodec.DecodeDeviceCertificate(device.ExactDpd1.Span);
            if (!entry.DeviceId.Span.SequenceEqual(device.DeviceId.Span) ||
                !entry.Dpd1Reference.CanonicalHash.Span.SequenceEqual(device.Dpd1Hash.Span) ||
                !certificate.DeviceId.Span.SequenceEqual(device.DeviceId.Span) ||
                !certificate.NetworkId.Span.SequenceEqual(networkId) ||
                !certificate.AccountHash.Span.SequenceEqual(RemoteAccountId.Span))
                throw new FormatException("Verified-peer device artifact differs from DMD1.");
        }
    }

    private byte[] ComputeHash()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.ASCII.GetBytes("Deep/Client/ContactV1/verified-peer-package/v1"));
        AppendU16(hash, CurrentVersion);
        Append(hash, Scope.AccountId.Bytes.Span);
        AppendU64(hash, checked((ulong)Scope.StoreGeneration));
        Append(hash, RelationshipId.Span);
        Append(hash, ConversationId.Span);
        Append(hash, RemoteAccountId.Span);
        hash.AppendData([(byte)AddressKind]);
        Append(hash, networkId);
        Append(hash, exactCanonicalAddress);
        Append(hash, exactXiq1);
        Append(hash, exactXis1);
        Append(hash, exactDcr1);
        Append(hash, exactDcb1);
        Append(hash, exactDmd1);
        AppendU16(hash, checked((ushort)devices.Length));
        foreach (var device in devices)
        {
            Append(hash, device.DeviceId.Span);
            Append(hash, device.ExactDpd1.Span);
        }
        Append(hash, exactRouteClosure);
        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static void AppendU16(IncrementalHash hash, ushort value)
    {
        Span<byte> encoded = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
        hash.AppendData(encoded);
    }

    private static void AppendU64(IncrementalHash hash, ulong value)
    {
        Span<byte> encoded = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        hash.AppendData(encoded);
    }

    private static void RequireBounded(ReadOnlySpan<byte> value, int minimum, int maximum, string name)
    {
        if (value.Length < minimum || value.Length > maximum)
            throw new FormatException($"Verified-peer {name} length is outside its sealed bound.");
    }
}

public sealed class ContactVerifiedPeerDeviceEvidence
{
    private readonly byte[] deviceId;
    private readonly byte[] exactDpd1;
    private readonly byte[] dpd1Hash;

    internal ContactVerifiedPeerDeviceEvidence(
        ReadOnlySpan<byte> deviceId32,
        ReadOnlySpan<byte> exactDpd1)
    {
        if (deviceId32.Length != 32 || deviceId32.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("Verified-peer device ID is invalid.");
        if (exactDpd1.Length != 776)
            throw new FormatException("Verified-peer DPD1 length is invalid.");
        deviceId = deviceId32.ToArray();
        this.exactDpd1 = exactDpd1.ToArray();
        dpd1Hash = SHA256.HashData(exactDpd1);
    }

    public ReadOnlyMemory<byte> DeviceId => deviceId.ToArray();
    public ReadOnlyMemory<byte> ExactDpd1 => exactDpd1.ToArray();
    public ReadOnlyMemory<byte> Dpd1Hash => dpd1Hash.ToArray();

    internal ContactVerifiedPeerDeviceEvidence Copy() => new(deviceId, exactDpd1);
}
