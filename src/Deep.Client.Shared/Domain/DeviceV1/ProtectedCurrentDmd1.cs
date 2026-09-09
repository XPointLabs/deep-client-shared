using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Domain.DeviceV1;

public enum ProtectedCurrentDmd1CommitDisposition
{
    Applied = 1,
    ExactReplay = 2,
    Stale = 3,
    InvalidLineage = 4,
    ForkLatched = 5,
    Conflict = 6
}

public enum ProtectedDeviceAgreementDisposition
{
    Granted = 1,
    AlreadyConsumed = 2,
    MissingCurrentDmd1 = 3,
    Stale = 4,
    RevokedOrSuperseded = 5,
    ForkLatched = 6,
    Conflict = 7
}

public sealed class ProtectedCurrentDmd1CommitResult
{
    internal ProtectedCurrentDmd1CommitResult(
        ProtectedCurrentDmd1CommitDisposition disposition,
        ulong directoryGeneration,
        ReadOnlySpan<byte> directoryHash)
    {
        Disposition = disposition;
        DirectoryGeneration = directoryGeneration;
        DirectoryHash = directoryHash.ToArray();
    }

    public ProtectedCurrentDmd1CommitDisposition Disposition { get; }
    public ulong DirectoryGeneration { get; }
    public ReadOnlyMemory<byte> DirectoryHash { get; }
}

public sealed class ProtectedDeviceAgreementAuthorizationResult
{
    internal ProtectedDeviceAgreementAuthorizationResult(
        ProtectedDeviceAgreementDisposition disposition,
        ProtectedDeviceAgreementAuthorization? authorization = null)
    {
        Disposition = disposition;
        Authorization = authorization;
    }

    public ProtectedDeviceAgreementDisposition Disposition { get; }
    public ProtectedDeviceAgreementAuthorization? Authorization { get; }
}

/// <summary>
/// A store-issued, operation-scoped and one-use handoff. It intentionally does
/// not expose an agreement operation. The internal custody bridge is the sole
/// consumer and can only exchange it for an equally scoped Protocol lease.
/// </summary>
public sealed class ProtectedDeviceAgreementAuthorization : IDisposable
{
    private byte[]? operationBinding;
    private byte[]? peerPublicKey;
    private int claimed;

    internal ProtectedDeviceAgreementAuthorization(
        DeviceOperationId32 operationId,
        CurrentDmd1Evidence evidence,
        LocalDeviceAgreementBinding device,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlySpan<byte> operationBinding,
        ReadOnlySpan<byte> peerPublicKey)
    {
        OperationId = DeviceOperationId32.FromBytes(operationId.Span);
        NetworkId = evidence.NetworkId.ToArray();
        AccountId = evidence.AccountId.ToArray();
        AccountGeneration = evidence.AccountGeneration;
        DirectoryGeneration = evidence.DirectoryGeneration;
        DirectoryHash = evidence.DirectoryHash.ToArray();
        DeviceId = device.DeviceId.ToArray();
        DeviceGeneration = device.DeviceGeneration;
        ExactDpd1Hash = device.ExactDpd1Hash.ToArray();
        Purpose = purpose;
        this.operationBinding = operationBinding.ToArray();
        this.peerPublicKey = peerPublicKey.ToArray();
    }

    internal DeviceOperationId32 OperationId { get; }
    internal ReadOnlyMemory<byte> NetworkId { get; }
    internal ReadOnlyMemory<byte> AccountId { get; }
    internal ulong AccountGeneration { get; }
    internal ulong DirectoryGeneration { get; }
    internal ReadOnlyMemory<byte> DirectoryHash { get; }
    internal ReadOnlyMemory<byte> DeviceId { get; }
    internal ulong DeviceGeneration { get; }
    internal ReadOnlyMemory<byte> ExactDpd1Hash { get; }
    internal LocalDeviceX25519AgreementPurpose Purpose { get; }

    internal ProtectedDeviceAgreementUse ClaimOnce()
    {
        if (Interlocked.Exchange(ref claimed, 1) != 0)
            throw new InvalidOperationException("The protected device-agreement authorization was already consumed.");
        var operation = Interlocked.Exchange(ref operationBinding, null);
        var peer = Interlocked.Exchange(ref peerPublicKey, null);
        if (operation is null || peer is null)
        {
            Zero(operation);
            Zero(peer);
            throw new ObjectDisposedException(nameof(ProtectedDeviceAgreementAuthorization));
        }
        return new ProtectedDeviceAgreementUse(Purpose, operation, peer);
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref claimed, 1);
        Zero(Interlocked.Exchange(ref operationBinding, null));
        Zero(Interlocked.Exchange(ref peerPublicKey, null));
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
            CryptographicOperations.ZeroMemory(value);
    }
}

internal sealed class ProtectedDeviceAgreementUse : IDisposable
{
    internal ProtectedDeviceAgreementUse(
        LocalDeviceX25519AgreementPurpose purpose,
        byte[] operationBinding,
        byte[] peerPublicKey)
    {
        Purpose = purpose;
        OperationBinding = operationBinding;
        PeerPublicKey = peerPublicKey;
    }

    internal LocalDeviceX25519AgreementPurpose Purpose { get; }
    internal byte[] OperationBinding { get; }
    internal byte[] PeerPublicKey { get; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(OperationBinding);
        CryptographicOperations.ZeroMemory(PeerPublicKey);
    }
}

internal sealed class LocalDeviceAgreementBinding
{
    private LocalDeviceAgreementBinding(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> exactDpd1Hash,
        ReadOnlySpan<byte> agreementPublicKey)
    {
        NetworkId = networkId.ToArray();
        AccountId = accountId.ToArray();
        AccountGeneration = accountGeneration;
        DeviceId = deviceId.ToArray();
        DeviceGeneration = deviceGeneration;
        ExactDpd1Hash = exactDpd1Hash.ToArray();
        AgreementPublicKey = agreementPublicKey.ToArray();
    }

    internal ReadOnlyMemory<byte> NetworkId { get; }
    internal ReadOnlyMemory<byte> AccountId { get; }
    internal ulong AccountGeneration { get; }
    internal ReadOnlyMemory<byte> DeviceId { get; }
    internal ulong DeviceGeneration { get; }
    internal ReadOnlyMemory<byte> ExactDpd1Hash { get; }
    internal ReadOnlyMemory<byte> AgreementPublicKey { get; }

    internal static LocalDeviceAgreementBinding FromAuthority(
        LocalDeviceX25519AgreementAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        return new LocalDeviceAgreementBinding(
            authority.NetworkId.Span,
            authority.AccountId.Span,
            authority.AccountGeneration,
            authority.DeviceId.Span,
            authority.DeviceGeneration,
            authority.ExactDpd1Hash.Span,
            authority.AgreementPublicKey.Span);
    }

#if DEEP_TEST_INTERNALS
    internal static LocalDeviceAgreementBinding ForTesting(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> exactDpd1Hash,
        ReadOnlySpan<byte> agreementPublicKey) =>
        new(networkId, accountId, accountGeneration, deviceId, deviceGeneration,
            exactDpd1Hash, agreementPublicKey);
#endif
}

internal sealed class CurrentDmd1Evidence
{
    private readonly byte[] canonical;
    private readonly byte[] networkId;
    private readonly byte[] accountId;
    private readonly byte[] directoryHash;
    private readonly byte[] predecessorHash;
    private readonly byte[] drsHash;
    private readonly CurrentDmd1DeviceEvidence[] devices;

    private CurrentDmd1Evidence(
        bool forkLatched,
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ulong directoryGeneration,
        ReadOnlySpan<byte> directoryHash,
        ReadOnlySpan<byte> predecessorHash,
        ulong drsRevision,
        ReadOnlySpan<byte> drsHash,
        IEnumerable<CurrentDmd1DeviceEvidence> devices)
    {
        ForkLatched = forkLatched;
        this.canonical = canonical.ToArray();
        this.networkId = networkId.ToArray();
        this.accountId = accountId.ToArray();
        AccountGeneration = accountGeneration;
        DirectoryGeneration = directoryGeneration;
        this.directoryHash = directoryHash.ToArray();
        this.predecessorHash = predecessorHash.ToArray();
        DrsRevision = drsRevision;
        this.drsHash = drsHash.ToArray();
        this.devices = devices.OrderBy(static value => Convert.ToHexString(value.DeviceId.Span), StringComparer.Ordinal).ToArray();
        ValidateShape();
    }

    internal bool ForkLatched { get; }
    internal ReadOnlyMemory<byte> Canonical => canonical;
    internal ReadOnlyMemory<byte> NetworkId => networkId;
    internal ReadOnlyMemory<byte> AccountId => accountId;
    internal ulong AccountGeneration { get; }
    internal ulong DirectoryGeneration { get; }
    internal ReadOnlyMemory<byte> DirectoryHash => directoryHash;
    internal ReadOnlyMemory<byte> PredecessorHash => predecessorHash;
    internal ulong DrsRevision { get; }
    internal ReadOnlyMemory<byte> DrsHash => drsHash;
    internal IReadOnlyList<CurrentDmd1DeviceEvidence> Devices => devices;

    internal VerifiedDeviceDirectoryFacts DirectoryFacts =>
        VerifiedDeviceDirectoryFacts.RestorePersisted(
            DeviceAccountId32.FromBytes(accountId),
            AccountGeneration,
            DirectoryGeneration,
            DeviceDirectoryHash32.FromBytes(directoryHash),
            predecessorHash.ToArray(),
            DrsRevision,
            DeviceRevocationHash32.FromBytes(drsHash),
            devices.Select(static value => new VerifiedActiveDeviceFacts(
                DeviceIdentifier32.FromBytes(value.DeviceId.Span),
                DeviceCertificateHash32.FromBytes(value.Dpd1Hash.Span))));

    internal static CurrentDmd1Evidence FromVerified(Dmd1LineageState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var verified = state.Head;
        var record = verified.Record;
        var byId = verified.Identity.ActiveDevices.ToDictionary(
            static value => Convert.ToHexString(value.Certificate.DeviceId.Span),
            StringComparer.Ordinal);
        var devices = record.ActiveDevices.Select(entry =>
        {
            if (!byId.TryGetValue(Convert.ToHexString(entry.DeviceId.Span), out var device) ||
                !entry.Dpd1Reference.CanonicalHash.Span.SequenceEqual(device.Certificate.CanonicalHash.Span))
                throw new InvalidOperationException("Verified DMD1 lost its exact active DPD1 closure.");
            return new CurrentDmd1DeviceEvidence(
                entry.DeviceId.Span,
                device.Certificate.DeviceGeneration,
                device.Certificate.CanonicalHash.Span,
                device.Certificate.DeviceX25519PublicKey.Span);
        });
        return new CurrentDmd1Evidence(
            state.ForkLatched,
            record.CanonicalBytes.Span,
            record.NetworkId.Span,
            record.DeepAccountId.Span,
            record.AccountGeneration,
            record.DirectoryGeneration,
            record.RecordHash.Span,
            record.PredecessorDmd1Hash.Span,
            verified.Identity.Revocations.Snapshot.Revision,
            record.Drs1Reference.CanonicalHash.Span,
            devices);
    }

    internal static CurrentDmd1Evidence RestoreProtected(
        bool forkLatched,
        ReadOnlySpan<byte> canonical,
        ulong drsRevision)
    {
        var record = ApplicationCoreCodec.DecodeDmd1(canonical);
        return new CurrentDmd1Evidence(
            forkLatched,
            record.CanonicalBytes.Span,
            record.NetworkId.Span,
            record.DeepAccountId.Span,
            record.AccountGeneration,
            record.DirectoryGeneration,
            record.RecordHash.Span,
            record.PredecessorDmd1Hash.Span,
            drsRevision,
            record.Drs1Reference.CanonicalHash.Span,
            record.ActiveDevices.Select(static entry => new CurrentDmd1DeviceEvidence(
                entry.DeviceId.Span, 0, entry.Dpd1Reference.CanonicalHash.Span, new byte[32])));
    }

#if DEEP_TEST_INTERNALS
    internal static CurrentDmd1Evidence ForTesting(
        bool forkLatched,
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ulong directoryGeneration,
        ReadOnlySpan<byte> directoryHash,
        ReadOnlySpan<byte> predecessorHash,
        ulong drsRevision,
        ReadOnlySpan<byte> drsHash,
        IEnumerable<CurrentDmd1DeviceEvidence> devices) =>
        new(forkLatched, canonical, networkId, accountId, accountGeneration,
            directoryGeneration, directoryHash, predecessorHash, drsRevision,
            drsHash, devices);
#endif

    internal bool ExactEquals(CurrentDmd1Evidence other) =>
        DirectoryGeneration == other.DirectoryGeneration &&
        AccountGeneration == other.AccountGeneration &&
        canonical.AsSpan().SequenceEqual(other.canonical) &&
        directoryHash.AsSpan().SequenceEqual(other.directoryHash) &&
        accountId.AsSpan().SequenceEqual(other.accountId);

    internal bool Matches(LocalDeviceAgreementBinding device) =>
        networkId.AsSpan().SequenceEqual(device.NetworkId.Span) &&
        accountId.AsSpan().SequenceEqual(device.AccountId.Span) &&
        AccountGeneration == device.AccountGeneration &&
        devices.Any(value =>
            value.DeviceId.Span.SequenceEqual(device.DeviceId.Span) &&
            value.DeviceGeneration == device.DeviceGeneration &&
            value.Dpd1Hash.Span.SequenceEqual(device.ExactDpd1Hash.Span) &&
            value.AgreementPublicKey.Span.SequenceEqual(device.AgreementPublicKey.Span));

    private void ValidateShape()
    {
        if (canonical.Length is < 426 or > 1476 || networkId.Length != 16 ||
            accountId.Length != 32 || AccountGeneration == 0 || DirectoryGeneration == 0 ||
            directoryHash.Length != 32 || directoryHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            predecessorHash.Length != 32 || drsHash.Length != 32 ||
            drsHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 || devices.Length is < 1 or > 16 ||
            devices.Select(static value => Convert.ToHexString(value.DeviceId.Span)).Distinct(StringComparer.Ordinal).Count() != devices.Length)
            throw new InvalidDataException("Protected current-DMD1 evidence is malformed.");
    }
}

internal sealed class CurrentDmd1DeviceEvidence
{
    internal CurrentDmd1DeviceEvidence(
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> dpd1Hash,
        ReadOnlySpan<byte> agreementPublicKey)
    {
        if (deviceId.Length != 32 || deviceId.IndexOfAnyExcept((byte)0) < 0 ||
            dpd1Hash.Length != 32 || dpd1Hash.IndexOfAnyExcept((byte)0) < 0 ||
            agreementPublicKey.Length != 32 ||
            (deviceGeneration == 0) != (agreementPublicKey.IndexOfAnyExcept((byte)0) < 0))
            throw new InvalidDataException("Protected DMD1 device evidence is malformed.");
        DeviceId = deviceId.ToArray();
        DeviceGeneration = deviceGeneration;
        Dpd1Hash = dpd1Hash.ToArray();
        AgreementPublicKey = agreementPublicKey.ToArray();
    }

    internal ReadOnlyMemory<byte> DeviceId { get; }
    internal ulong DeviceGeneration { get; }
    internal ReadOnlyMemory<byte> Dpd1Hash { get; }
    internal ReadOnlyMemory<byte> AgreementPublicKey { get; }
}
