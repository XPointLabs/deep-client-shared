using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity.DeviceV1;

namespace Deep.Client.Shared.Domain.DeviceV1;

public sealed class VerifiedActiveDeviceFacts : IEquatable<VerifiedActiveDeviceFacts>, IComparable<VerifiedActiveDeviceFacts>
{
    internal VerifiedActiveDeviceFacts(DeviceIdentifier32 deviceId, DeviceCertificateHash32 certificateHash)
    {
        DeviceId = DeviceIdentifier32.FromBytes(deviceId.Span);
        CertificateHash = DeviceCertificateHash32.FromBytes(certificateHash.Span);
    }
    public DeviceIdentifier32 DeviceId { get; }
    public DeviceCertificateHash32 CertificateHash { get; }
    public bool Equals(VerifiedActiveDeviceFacts? other) => other is not null && DeviceId.Equals(other.DeviceId) && CertificateHash.Equals(other.CertificateHash);
    public override bool Equals(object? obj) => Equals(obj as VerifiedActiveDeviceFacts);
    public override int GetHashCode() => HashCode.Combine(DeviceId, CertificateHash);
    public int CompareTo(VerifiedActiveDeviceFacts? other) { ArgumentNullException.ThrowIfNull(other); return DeviceId.CompareTo(other.DeviceId); }
    public override string ToString() => "[verified-active-device]";
}

public sealed class VerifiedDeviceDirectoryFacts
{
    private readonly byte[] predecessorHash;
    private readonly VerifiedActiveDeviceFacts[] activeDevices;
    private VerifiedDeviceDirectoryFacts(DeviceAccountId32 accountId, ulong accountGeneration,
        ulong directoryGeneration, DeviceDirectoryHash32 directoryHash, byte[] predecessorHash,
        ulong revocationRevision, DeviceRevocationHash32 revocationHash,
        IEnumerable<VerifiedActiveDeviceFacts> activeDevices)
    {
        ArgumentNullException.ThrowIfNull(predecessorHash);
        if (accountGeneration == 0 || directoryGeneration == 0 || predecessorHash.Length != 32)
            throw new ArgumentException("Verified DMD1 generation or predecessor facts are malformed.");
        AccountId = DeviceAccountId32.FromBytes(accountId.Span); AccountGeneration = accountGeneration;
        DirectoryGeneration = directoryGeneration; DirectoryHash = DeviceDirectoryHash32.FromBytes(directoryHash.Span);
        this.predecessorHash = predecessorHash.ToArray(); RevocationRevision = revocationRevision;
        RevocationHash = DeviceRevocationHash32.FromBytes(revocationHash.Span);
        this.activeDevices = activeDevices.Select(static value => new VerifiedActiveDeviceFacts(value.DeviceId, value.CertificateHash)).OrderBy(static value => value).ToArray();
        if (this.activeDevices.Length is < 1 or > 16 || this.activeDevices.Select(static value => value.DeviceId).Distinct().Count() != this.activeDevices.Length)
            throw new ArgumentException("Verified DMD1 facts require one through sixteen unique active devices.", nameof(activeDevices));
    }
    public DeviceAccountId32 AccountId { get; } public ulong AccountGeneration { get; }
    public ulong DirectoryGeneration { get; } public DeviceDirectoryHash32 DirectoryHash { get; }
    public ReadOnlyMemory<byte> PredecessorHash => predecessorHash.ToArray(); public ulong RevocationRevision { get; }
    public DeviceRevocationHash32 RevocationHash { get; }
    public IReadOnlyList<VerifiedActiveDeviceFacts> ActiveDevices => Array.AsReadOnly(activeDevices.Select(static value => new VerifiedActiveDeviceFacts(value.DeviceId, value.CertificateHash)).ToArray());
    internal ReadOnlySpan<byte> PredecessorSpan => predecessorHash;
    public bool Contains(DeviceIdentifier32 deviceId) { ArgumentNullException.ThrowIfNull(deviceId); return activeDevices.Any(value => value.DeviceId.Equals(deviceId)); }

    public static VerifiedDeviceDirectoryFacts FromVerified(VerifiedDmd1 verified)
    {
        ArgumentNullException.ThrowIfNull(verified); var record = verified.Record;
        var byId = verified.Identity.ActiveDevices.ToDictionary(static value => Convert.ToHexString(value.Certificate.DeviceId.Span), StringComparer.Ordinal);
        var active = record.ActiveDevices.Select(entry => {
            if (!byId.TryGetValue(Convert.ToHexString(entry.DeviceId.Span), out var device)) throw new InvalidOperationException("Verified DMD1 closure is missing an active DPD1 capability.");
            return new VerifiedActiveDeviceFacts(DeviceIdentifier32.FromBytes(entry.DeviceId.Span), DeviceCertificateHash32.FromBytes(device.Certificate.CanonicalHash.Span));
        }).ToArray();
        return RestorePersisted(DeviceAccountId32.FromBytes(record.DeepAccountId.Span), record.AccountGeneration,
            record.DirectoryGeneration, DeviceDirectoryHash32.FromBytes(record.RecordHash.Span), record.PredecessorDmd1Hash.ToArray(),
            verified.Identity.Revocations.Snapshot.Revision, DeviceRevocationHash32.FromBytes(verified.Identity.Revocations.Snapshot.CanonicalHash.Span), active);
    }
    internal static VerifiedDeviceDirectoryFacts RestorePersisted(DeviceAccountId32 accountId, ulong accountGeneration,
        ulong directoryGeneration, DeviceDirectoryHash32 directoryHash, byte[] predecessorHash,
        ulong revocationRevision, DeviceRevocationHash32 revocationHash, IEnumerable<VerifiedActiveDeviceFacts> activeDevices) =>
        new(accountId, accountGeneration, directoryGeneration, directoryHash, predecessorHash, revocationRevision, revocationHash, activeDevices);
}

public sealed class VerifiedEnrollmentDeviceFacts
{
    private VerifiedEnrollmentDeviceFacts(DeviceAccountId32 accountId, ulong accountGeneration, ulong revocationRevision,
        DeviceRevocationHash32 revocationHash, DeviceIdentifier32 deviceId, DeviceCertificateHash32 certificateHash)
    { AccountId = DeviceAccountId32.FromBytes(accountId.Span); AccountGeneration = accountGeneration; RevocationRevision = revocationRevision;
      RevocationHash = DeviceRevocationHash32.FromBytes(revocationHash.Span); DeviceId = DeviceIdentifier32.FromBytes(deviceId.Span); CertificateHash = DeviceCertificateHash32.FromBytes(certificateHash.Span); }
    public DeviceAccountId32 AccountId { get; } public ulong AccountGeneration { get; } public ulong RevocationRevision { get; }
    public DeviceRevocationHash32 RevocationHash { get; } public DeviceIdentifier32 DeviceId { get; } public DeviceCertificateHash32 CertificateHash { get; }
    public static VerifiedEnrollmentDeviceFacts FromVerified(VerifiedDevice verified)
    { ArgumentNullException.ThrowIfNull(verified); return RestorePersisted(DeviceAccountId32.FromBytes(verified.Certificate.AccountHash.Span), verified.Certificate.AccountGeneration,
        verified.Revocations.Snapshot.Revision, DeviceRevocationHash32.FromBytes(verified.Revocations.Snapshot.CanonicalHash.Span),
        DeviceIdentifier32.FromBytes(verified.Certificate.DeviceId.Span), DeviceCertificateHash32.FromBytes(verified.Certificate.CanonicalHash.Span)); }
    internal static VerifiedEnrollmentDeviceFacts RestorePersisted(DeviceAccountId32 accountId, ulong accountGeneration,
        ulong revocationRevision, DeviceRevocationHash32 revocationHash, DeviceIdentifier32 deviceId, DeviceCertificateHash32 certificateHash) =>
        new(accountId, accountGeneration, revocationRevision, revocationHash, deviceId, certificateHash);
}

public sealed class DeviceLocalRevocationFloorEntry : IEquatable<DeviceLocalRevocationFloorEntry>
{
    private readonly byte[] revokedDpdReference;
    internal DeviceLocalRevocationFloorEntry(DeviceAccountId32 accountId, ulong accountGeneration, DeviceIdentifier32 deviceId,
        byte[] revokedDpdReference, ulong priorDrsRevision, DeviceRevocationHash32 priorDrsHash,
        ulong successorDrsRevision, DeviceRevocationHash32 successorDrsHash, DeviceOperationId32 sagaOperationId)
    {
        if (revokedDpdReference.Length != ArtifactReference.Length
            || System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(revokedDpdReference) != (ushort)ArtifactType.Dpd1
            || System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(revokedDpdReference.AsSpan(2)) == 0
            || revokedDpdReference.AsSpan(6).IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Revoked DPD1 reference is malformed.", nameof(revokedDpdReference));
        AccountId = DeviceAccountId32.FromBytes(accountId.Span); AccountGeneration = accountGeneration; DeviceId = DeviceIdentifier32.FromBytes(deviceId.Span);
        this.revokedDpdReference = revokedDpdReference.ToArray(); PriorDrsRevision = priorDrsRevision; PriorDrsHash = DeviceRevocationHash32.FromBytes(priorDrsHash.Span);
        SuccessorDrsRevision = successorDrsRevision; SuccessorDrsHash = DeviceRevocationHash32.FromBytes(successorDrsHash.Span); SagaOperationId = DeviceOperationId32.FromBytes(sagaOperationId.Span);
    }
    public DeviceAccountId32 AccountId { get; } public ulong AccountGeneration { get; } public DeviceIdentifier32 DeviceId { get; }
    public ReadOnlyMemory<byte> RevokedDpdReference => revokedDpdReference.ToArray(); public ulong PriorDrsRevision { get; }
    public DeviceRevocationHash32 PriorDrsHash { get; } public ulong SuccessorDrsRevision { get; }
    public DeviceRevocationHash32 SuccessorDrsHash { get; } public DeviceOperationId32 SagaOperationId { get; }
    internal static DeviceLocalRevocationFloorEntry FromVerified(VerifiedDeviceRevocationSuccessor verified, DeviceOperationId32 sagaOperationId) =>
        new(DeviceAccountId32.FromBytes(verified.AccountId.Span), verified.AccountGeneration, DeviceIdentifier32.FromBytes(verified.RevokedDeviceId.Span),
            ReferenceBytes(verified.RevokedDpdReference), verified.PriorDrsRevision, DeviceRevocationHash32.FromBytes(verified.PriorDrsHash.Span),
            verified.SuccessorDrsRevision, DeviceRevocationHash32.FromBytes(verified.SuccessorDrsHash.Span), sagaOperationId);
    public bool Equals(DeviceLocalRevocationFloorEntry? other) => other is not null && AccountId.Equals(other.AccountId) && AccountGeneration == other.AccountGeneration && DeviceId.Equals(other.DeviceId) && SuccessorDrsHash.Equals(other.SuccessorDrsHash);
    public override bool Equals(object? obj) => Equals(obj as DeviceLocalRevocationFloorEntry);
    public override int GetHashCode() => HashCode.Combine(AccountId, AccountGeneration, DeviceId, SuccessorDrsHash);
    private static byte[] ReferenceBytes(ArtifactReference reference)
    { var bytes = new byte[ArtifactReference.Length]; System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort)reference.Type);
      System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(2), reference.CanonicalLength); reference.CanonicalHash.Span.CopyTo(bytes.AsSpan(6)); return bytes; }
}
