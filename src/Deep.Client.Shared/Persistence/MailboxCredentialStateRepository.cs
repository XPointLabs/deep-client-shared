using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence;

/// <summary>Strict, binary credential input for one atomically pinned mailbox generation.
/// The caller is responsible for reading the provisioner's generation pointer and manifest;
/// this runtime deliberately has no JSON or compatibility import path.</summary>
public sealed class MailboxCredentialGeneration
{
    private readonly byte[] generation, manifestHash, networkId, issuerPublicKey, holderPublicKey, ownMailboxId, peerMailboxId;
    public MailboxCredentialGeneration(
        ReadOnlySpan<byte> generation,
        ReadOnlySpan<byte> manifestHash,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> issuerPublicKey,
        ReadOnlySpan<byte> holderPublicKey,
        ReadOnlySpan<byte> ownMailboxId,
        ReadOnlySpan<byte> peerMailboxId,
        MailboxCredentialEpoch current,
        MailboxCredentialEpoch next,
        MailboxCredentialGrantSet ownRetrieve,
        MailboxCredentialGrantSet ownDeposit,
        MailboxCredentialGrantSet peerDeposit,
        MailboxCredentialReplicaPair replicas)
    {
        this.generation = CopyFixed(generation, 32, nameof(generation));
        this.manifestHash = CopyFixed(manifestHash, 32, nameof(manifestHash));
        this.networkId = CopyFixed(networkId, 16, nameof(networkId));
        this.issuerPublicKey = CopyFixed(issuerPublicKey, 32, nameof(issuerPublicKey));
        this.holderPublicKey = CopyFixed(holderPublicKey, 32, nameof(holderPublicKey));
        this.ownMailboxId = CopyFixed(ownMailboxId, 32, nameof(ownMailboxId));
        this.peerMailboxId = CopyFixed(peerMailboxId, 32, nameof(peerMailboxId));
        Current = current ?? throw new ArgumentNullException(nameof(current));
        Next = next ?? throw new ArgumentNullException(nameof(next));
        OwnRetrieve = ownRetrieve ?? throw new ArgumentNullException(nameof(ownRetrieve));
        OwnDeposit = ownDeposit ?? throw new ArgumentNullException(nameof(ownDeposit));
        PeerDeposit = peerDeposit ?? throw new ArgumentNullException(nameof(peerDeposit));
        Replicas = replicas ?? throw new ArgumentNullException(nameof(replicas));
    }

    public ReadOnlyMemory<byte> Generation => generation.ToArray();
    public ReadOnlyMemory<byte> ManifestHash => manifestHash.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> IssuerPublicKey => issuerPublicKey.ToArray();
    public ReadOnlyMemory<byte> HolderPublicKey => holderPublicKey.ToArray();
    public ReadOnlyMemory<byte> OwnMailboxId => ownMailboxId.ToArray();
    public ReadOnlyMemory<byte> PeerMailboxId => peerMailboxId.ToArray();
    public MailboxCredentialEpoch Current { get; }
    public MailboxCredentialEpoch Next { get; }
    public MailboxCredentialGrantSet OwnRetrieve { get; }
    public MailboxCredentialGrantSet OwnDeposit { get; }
    public MailboxCredentialGrantSet PeerDeposit { get; }
    public MailboxCredentialReplicaPair Replicas { get; }

    internal MailboxCredentialGeneration Clone() => new(
        Generation.Span, ManifestHash.Span, NetworkId.Span, IssuerPublicKey.Span,
        HolderPublicKey.Span, OwnMailboxId.Span, PeerMailboxId.Span, Current.Clone(),
        Next.Clone(), OwnRetrieve.Clone(), OwnDeposit.Clone(), PeerDeposit.Clone(), Replicas.Clone());

    private static byte[] CopyFixed(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Mailbox credential field is invalid.", name);
        return value.ToArray();
    }
}

public sealed class MailboxCredentialEpoch
{
    private readonly byte[] membershipCommitment, placementId, placementCommitment;
    public MailboxCredentialEpoch(ulong epoch, ulong notBeforeUnixSeconds,
        ulong expiresAtUnixSeconds, ReadOnlySpan<byte> membershipCommitment,
        ReadOnlySpan<byte> placementId, ReadOnlySpan<byte> placementCommitment)
    {
        if (epoch == 0 || notBeforeUnixSeconds >= expiresAtUnixSeconds)
            throw new ArgumentException("Mailbox credential epoch is invalid.");
        Epoch = epoch;
        NotBeforeUnixSeconds = notBeforeUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        this.membershipCommitment = Copy(membershipCommitment);
        this.placementId = Copy(placementId);
        this.placementCommitment = Copy(placementCommitment);
    }
    public ulong Epoch { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> MembershipCommitment => membershipCommitment.ToArray();
    public ReadOnlyMemory<byte> PlacementId => placementId.ToArray();
    public ReadOnlyMemory<byte> PlacementCommitment => placementCommitment.ToArray();
    internal MailboxCredentialEpoch Clone() => new(Epoch, NotBeforeUnixSeconds,
        ExpiresAtUnixSeconds, MembershipCommitment.Span, PlacementId.Span, PlacementCommitment.Span);
    private static byte[] Copy(ReadOnlySpan<byte> value)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Mailbox credential epoch binding is invalid.");
        return value.ToArray();
    }
}

public sealed class MailboxCredentialGrantSet
{
    private readonly byte[] currentGrant, nextGrant;
    public MailboxCredentialGrantSet(ReadOnlySpan<byte> currentGrant, ReadOnlySpan<byte> nextGrant)
    {
        this.currentGrant = Copy(currentGrant);
        this.nextGrant = Copy(nextGrant);
    }
    public ReadOnlyMemory<byte> CurrentGrant => currentGrant.ToArray();
    public ReadOnlyMemory<byte> NextGrant => nextGrant.ToArray();
    internal MailboxCredentialGrantSet Clone() => new(CurrentGrant.Span, NextGrant.Span);
    private static byte[] Copy(ReadOnlySpan<byte> value)
    {
        if (value.Length != MailboxAuthenticatedCapabilityLimits.GrantLength)
            throw new ArgumentException("Mailbox grant has an invalid length.");
        return value.ToArray();
    }
}

public sealed class MailboxCredentialReplicaPair
{
    private readonly byte[] firstId, firstSigningKey, secondId, secondSigningKey;
    public MailboxCredentialReplicaPair(ReadOnlySpan<byte> firstId, ReadOnlySpan<byte> firstSigningKey,
        ReadOnlySpan<byte> secondId, ReadOnlySpan<byte> secondSigningKey)
    {
        this.firstId = Copy(firstId); this.firstSigningKey = Copy(firstSigningKey);
        this.secondId = Copy(secondId); this.secondSigningKey = Copy(secondSigningKey);
        if (CryptographicOperations.FixedTimeEquals(this.firstId, this.secondId))
            throw new ArgumentException("Mailbox replica pair must be distinct.");
    }
    public ReadOnlyMemory<byte> FirstId => firstId.ToArray();
    public ReadOnlyMemory<byte> FirstSigningKey => firstSigningKey.ToArray();
    public ReadOnlyMemory<byte> SecondId => secondId.ToArray();
    public ReadOnlyMemory<byte> SecondSigningKey => secondSigningKey.ToArray();
    internal MailboxCredentialReplicaPair Clone() => new(FirstId.Span, FirstSigningKey.Span,
        SecondId.Span, SecondSigningKey.Span);
    private static byte[] Copy(ReadOnlySpan<byte> value)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Mailbox replica binding is invalid.");
        return value.ToArray();
    }
}

public enum MailboxCredentialGrantKind { OwnRetrieve = 1, OwnDeposit = 2, PeerDeposit = 3 }

public sealed record MailboxCredentialImportPolicy(
    ReadOnlyMemory<byte> Generation,
    ReadOnlyMemory<byte> ManifestHash,
    ReadOnlyMemory<byte> NetworkId,
    ReadOnlyMemory<byte> IssuerPublicKey,
    ReadOnlyMemory<byte> HolderPublicKey,
    MailboxCredentialReplicaPair Replicas,
    IMailboxCapabilityRevocationSource Revocations,
    ulong NowUnixSeconds)
{
    public override string ToString() => "[mailbox-credential-import-policy]";
}

public sealed class MailboxCredentialGrantLease
{
    private readonly byte[] canonicalGrant;
    internal MailboxCredentialGrantLease(MailboxCredentialGrantKind kind, ulong epoch,
        ulong replayCounter, ReadOnlySpan<byte> canonicalGrant)
    {
        Kind = kind; Epoch = epoch; ReplayCounter = replayCounter;
        this.canonicalGrant = canonicalGrant.ToArray();
    }
    public MailboxCredentialGrantKind Kind { get; }
    public ulong Epoch { get; }
    public ulong ReplayCounter { get; }
    public ReadOnlyMemory<byte> CanonicalGrant => canonicalGrant.ToArray();
}

public interface IClientMailboxCredentialStateRepository
{
    Task ImportCredentialGenerationAsync(MailboxCredentialGeneration generation,
        MailboxCredentialImportPolicy policy, CancellationToken cancellationToken = default);
    Task<MailboxCredentialGeneration> ReadCredentialGenerationAsync(CancellationToken cancellationToken = default);
    Task<ulong> ReadActiveCredentialEpochAsync(CancellationToken cancellationToken = default);
    Task SwitchCredentialEpochAsync(ulong epoch, ulong nowUnixSeconds, CancellationToken cancellationToken = default);
    Task<MailboxCredentialGrantLease> AllocateReplayCounterAsync(MailboxCredentialGrantKind kind,
        ulong nowUnixSeconds, CancellationToken cancellationToken = default);
}

internal sealed class MailboxCredentialStoredState
{
    public required MailboxCredentialGeneration Generation { get; init; }
    public required ulong ActiveEpoch { get; set; }
    public Dictionary<string, ulong> NextCounters { get; } = new(StringComparer.Ordinal);

    public MailboxCredentialStoredState Clone()
    {
        var clone = new MailboxCredentialStoredState { Generation = Generation.Clone(), ActiveEpoch = ActiveEpoch };
        foreach (var (key, value) in NextCounters) clone.NextCounters.Add(key, value);
        return clone;
    }
}

internal static class MailboxCredentialStateMachine
{
    public static MailboxCredentialStoredState Import(MailboxCredentialGeneration generation,
        MailboxCredentialImportPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(generation);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(policy.Replicas);
        ArgumentNullException.ThrowIfNull(policy.Revocations);
        if (policy.NowUnixSeconds == 0 || !Same(generation.Generation.Span, policy.Generation.Span, 32) ||
            !Same(generation.ManifestHash.Span, policy.ManifestHash.Span, 32) ||
            !Same(generation.NetworkId.Span, policy.NetworkId.Span, 16) ||
            !Same(generation.IssuerPublicKey.Span, policy.IssuerPublicKey.Span, 32) ||
            !Same(generation.HolderPublicKey.Span, policy.HolderPublicKey.Span, 32) ||
            !SamePair(generation.Replicas, policy.Replicas) ||
            generation.Next.Epoch != generation.Current.Epoch + 1 ||
            generation.Current.NotBeforeUnixSeconds >= generation.Next.NotBeforeUnixSeconds ||
            generation.Next.NotBeforeUnixSeconds > generation.Current.ExpiresAtUnixSeconds ||
            generation.Current.ExpiresAtUnixSeconds >= generation.Next.ExpiresAtUnixSeconds ||
            !Same(generation.Current.PlacementCommitment.Span,
                MailboxPlacementCommitment.Compute(new BlindedPlacementId(generation.Current.PlacementId.Span)), 32) ||
            !Same(generation.Next.PlacementCommitment.Span,
                MailboxPlacementCommitment.Compute(new BlindedPlacementId(generation.Next.PlacementId.Span)), 32))
            throw Invalid();

        var crypto = new SodiumMailboxCapabilityCrypto();
        var serials = new HashSet<string>(StringComparer.Ordinal);
        ValidateSet(generation.OwnRetrieve, MailboxCredentialGrantKind.OwnRetrieve,
            MailboxCapabilityDomain.Retrieve, generation, crypto, policy.Revocations, policy.NowUnixSeconds, serials);
        ValidateSet(generation.OwnDeposit, MailboxCredentialGrantKind.OwnDeposit,
            MailboxCapabilityDomain.Deposit, generation, crypto, policy.Revocations, policy.NowUnixSeconds, serials);
        ValidateSet(generation.PeerDeposit, MailboxCredentialGrantKind.PeerDeposit,
            MailboxCapabilityDomain.Deposit, generation, crypto, policy.Revocations, policy.NowUnixSeconds, serials);
        return new MailboxCredentialStoredState { Generation = generation.Clone(), ActiveEpoch = generation.Current.Epoch };
    }

    public static MailboxCredentialGrantLease Allocate(MailboxCredentialStoredState state,
        MailboxCredentialGrantKind kind, ulong now)
    {
        ArgumentNullException.ThrowIfNull(state);
        var epoch = Epoch(state.Generation, state.ActiveEpoch);
        if (now < epoch.NotBeforeUnixSeconds || now > epoch.ExpiresAtUnixSeconds)
            throw new InvalidOperationException("Mailbox credential is not active.");
        var grant = Grant(state.Generation, kind, state.ActiveEpoch);
        var decoded = MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant.Span);
        if (decoded.ExpiresAtUnixSeconds < now)
            throw new InvalidOperationException("Mailbox credential is not active.");
        var key = Convert.ToHexString(SHA256.HashData(grant.Span));
        var counter = state.NextCounters.TryGetValue(key, out var value) ? value : 1;
        if (counter == 0 || counter == ulong.MaxValue)
            throw new InvalidOperationException("Mailbox replay counter is exhausted.");
        state.NextCounters[key] = checked(counter + 1);
        return new MailboxCredentialGrantLease(kind, state.ActiveEpoch, counter, grant.Span);
    }

    public static void Switch(MailboxCredentialStoredState state, ulong epoch, ulong now)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (epoch != state.Generation.Next.Epoch || state.ActiveEpoch != state.Generation.Current.Epoch)
            throw new InvalidOperationException("Mailbox epoch switch is not authorized.");
        var target = Epoch(state.Generation, epoch);
        if (now < target.NotBeforeUnixSeconds || now > target.ExpiresAtUnixSeconds)
            throw new InvalidOperationException("Mailbox epoch is not active.");
        state.ActiveEpoch = epoch;
    }

    public static MailboxCredentialGeneration Read(MailboxCredentialStoredState state) => state.Generation.Clone();

    private static void ValidateSet(MailboxCredentialGrantSet set, MailboxCredentialGrantKind kind,
        MailboxCapabilityDomain domain, MailboxCredentialGeneration generation,
        IMailboxAuthenticatedCapabilityCrypto crypto, IMailboxCapabilityRevocationSource revoked, ulong now,
        ISet<string> serials)
    {
        ValidateGrant(set.CurrentGrant.Span, kind, domain, generation, generation.Current, crypto, revoked, now, serials);
        ValidateGrant(set.NextGrant.Span, kind, domain, generation, generation.Next, crypto, revoked, now, serials);
    }

    private static void ValidateGrant(ReadOnlySpan<byte> encoded, MailboxCredentialGrantKind kind,
        MailboxCapabilityDomain domain, MailboxCredentialGeneration generation, MailboxCredentialEpoch epoch,
        IMailboxAuthenticatedCapabilityCrypto crypto, IMailboxCapabilityRevocationSource revoked, ulong now,
        ISet<string> serials)
    {
        MailboxAuthenticatedGrant grant;
        try { grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(encoded); }
        catch (Exception exception) when (exception is ArgumentException or MailboxAuthenticatedCapabilityException)
        { throw Invalid(); }
        if (!Same(encoded, MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant), MailboxAuthenticatedCapabilityLimits.GrantLength) ||
            grant.Domain != domain || grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
            grant.Epoch != epoch.Epoch || grant.Generation != epoch.Epoch ||
            grant.NotBeforeUnixSeconds != epoch.NotBeforeUnixSeconds || grant.ExpiresAtUnixSeconds != epoch.ExpiresAtUnixSeconds ||
            grant.OverlapUntilUnixSeconds != 0 || now > grant.ExpiresAtUnixSeconds || !Same(grant.NetworkId.Span, generation.NetworkId.Span, 16) ||
            !Same(grant.IssuerPublicKey.Span, generation.IssuerPublicKey.Span, 32) ||
            !Same(grant.HolderPublicKey.Span, generation.HolderPublicKey.Span, 32) ||
            !Same(grant.PlacementCommitment.Span, epoch.PlacementCommitment.Span, 32) ||
            !Same(grant.MembershipCommitment.Span, epoch.MembershipCommitment.Span, 32) ||
            !crypto.VerifyIssuer(grant.IssuerPublicKey.Span,
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), grant.IssuerSignature.Span) ||
            revoked.IsRevoked(new MailboxCapabilityRevocationQuery { IssuerPublicKey = grant.IssuerPublicKey.ToArray(),
                Serial = grant.Serial.ToArray(), Domain = grant.Domain, Generation = grant.Generation,
                Epoch = grant.Epoch, MembershipCommitment = grant.MembershipCommitment.ToArray() }) ||
            !serials.Add(Convert.ToHexString(grant.Serial.Span)))
            throw Invalid();
    }

    private static MailboxCredentialEpoch Epoch(MailboxCredentialGeneration generation, ulong epoch) =>
        epoch == generation.Current.Epoch ? generation.Current : epoch == generation.Next.Epoch ? generation.Next : throw Invalid();
    private static ReadOnlyMemory<byte> Grant(MailboxCredentialGeneration generation, MailboxCredentialGrantKind kind, ulong epoch)
    {
        var set = kind switch { MailboxCredentialGrantKind.OwnRetrieve => generation.OwnRetrieve,
            MailboxCredentialGrantKind.OwnDeposit => generation.OwnDeposit,
            MailboxCredentialGrantKind.PeerDeposit => generation.PeerDeposit, _ => throw Invalid() };
        return epoch == generation.Current.Epoch ? set.CurrentGrant : epoch == generation.Next.Epoch ? set.NextGrant : throw Invalid();
    }
    private static bool SamePair(MailboxCredentialReplicaPair a, MailboxCredentialReplicaPair b) =>
        Same(a.FirstId.Span, b.FirstId.Span, 32) && Same(a.FirstSigningKey.Span, b.FirstSigningKey.Span, 32) &&
        Same(a.SecondId.Span, b.SecondId.Span, 32) && Same(a.SecondSigningKey.Span, b.SecondSigningKey.Span, 32);
    private static bool Same(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, int length) =>
        a.Length == length && b.Length == length && CryptographicOperations.FixedTimeEquals(a, b);
    private static InvalidDataException Invalid() => new("Mailbox credential generation is invalid.");
}

internal static class MailboxCredentialBinaryCodec
{
    private const int Length = 2216;
    public static byte[] Encode(MailboxCredentialGeneration value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var bytes = new byte[Length]; var offset = 0;
        Copy("MCB1"u8); bytes[offset++] = 1; offset += 3;
        Copy(value.Generation.Span); Copy(value.ManifestHash.Span); Copy(value.NetworkId.Span);
        Copy(value.IssuerPublicKey.Span); Copy(value.HolderPublicKey.Span); Copy(value.OwnMailboxId.Span); Copy(value.PeerMailboxId.Span);
        Epoch(value.Current); Epoch(value.Next);
        Grants(value.OwnRetrieve); Grants(value.OwnDeposit); Grants(value.PeerDeposit);
        Copy(value.Replicas.FirstId.Span); Copy(value.Replicas.FirstSigningKey.Span);
        Copy(value.Replicas.SecondId.Span); Copy(value.Replicas.SecondSigningKey.Span);
        if (offset != bytes.Length) throw new InvalidOperationException("Mailbox credential encoding length is invalid.");
        return bytes;
        void Copy(ReadOnlySpan<byte> source) { source.CopyTo(bytes.AsSpan(offset)); offset += source.Length; }
        void U64(ulong number) { System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset, 8), number); offset += 8; }
        void Epoch(MailboxCredentialEpoch epoch) { U64(epoch.Epoch); U64(epoch.NotBeforeUnixSeconds); U64(epoch.ExpiresAtUnixSeconds); Copy(epoch.MembershipCommitment.Span); Copy(epoch.PlacementId.Span); Copy(epoch.PlacementCommitment.Span); }
        void Grants(MailboxCredentialGrantSet set) { Copy(set.CurrentGrant.Span); Copy(set.NextGrant.Span); }
    }
    public static MailboxCredentialGeneration Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length || !bytes[..4].SequenceEqual("MCB1"u8) || bytes[4] != 1 || bytes.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Mailbox credential state is invalid.");
        var payload = bytes.ToArray();
        var offset = 8;
        var generation = Take(32); var manifest = Take(32); var network = Take(16); var issuer = Take(32); var holder = Take(32); var own = Take(32); var peer = Take(32);
        var current = Epoch(); var next = Epoch(); var ownRetrieve = Grants(); var ownDeposit = Grants(); var peerDeposit = Grants();
        var replicas = new MailboxCredentialReplicaPair(Take(32), Take(32), Take(32), Take(32));
        if (offset != payload.Length) throw new InvalidDataException("Mailbox credential state is invalid.");
        return new MailboxCredentialGeneration(generation, manifest, network, issuer, holder, own, peer, current, next, ownRetrieve, ownDeposit, peerDeposit, replicas);
        byte[] Take(int count) { var value = payload.AsSpan(offset, count).ToArray(); offset += count; return value; }
        ulong U64() { var value = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(payload.AsSpan(offset, 8)); offset += 8; return value; }
        MailboxCredentialEpoch Epoch() => new(U64(), U64(), U64(), Take(32), Take(32), Take(32));
        MailboxCredentialGrantSet Grants() => new(Take(MailboxAuthenticatedCapabilityLimits.GrantLength), Take(MailboxAuthenticatedCapabilityLimits.GrantLength));
    }
}
