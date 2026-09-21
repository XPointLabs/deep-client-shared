using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence;

/// <summary>One time-bounded, cryptographically bound epoch in a scoped mailbox grant.</summary>
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
        if (currentGrant.Length != MailboxAuthenticatedCapabilityLimits.GrantLength ||
            nextGrant.Length != MailboxAuthenticatedCapabilityLimits.GrantLength)
            throw new ArgumentException("Mailbox grant has an invalid length.");
        this.currentGrant = currentGrant.ToArray();
        this.nextGrant = nextGrant.ToArray();
    }
    public ReadOnlyMemory<byte> CurrentGrant => currentGrant.ToArray();
    public ReadOnlyMemory<byte> NextGrant => nextGrant.ToArray();
}

/// <summary>
/// The clean ContactV1 grant shape. XMG1/XMC1 intentionally returns only the
/// authenticated current epoch; a client must reacquire on epoch rollover and
/// must never invent an unsigned next grant.
/// </summary>
public sealed class CurrentMailboxCredentialGrants
{
    private readonly byte[]? retrieveGrant;
    private readonly byte[]? depositGrant;

    public CurrentMailboxCredentialGrants(
        ReadOnlySpan<byte> retrieveGrant = default,
        ReadOnlySpan<byte> depositGrant = default)
    {
        if (retrieveGrant.IsEmpty == depositGrant.IsEmpty)
            throw new ArgumentException(
                "Exactly one current mailbox grant role is required.");
        if (!retrieveGrant.IsEmpty &&
            retrieveGrant.Length != MailboxAuthenticatedCapabilityLimits.GrantLength ||
            !depositGrant.IsEmpty &&
            depositGrant.Length != MailboxAuthenticatedCapabilityLimits.GrantLength)
            throw new ArgumentException("A current mailbox grant has an invalid length.");
        this.retrieveGrant = retrieveGrant.IsEmpty ? null : retrieveGrant.ToArray();
        this.depositGrant = depositGrant.IsEmpty ? null : depositGrant.ToArray();
    }

    public ReadOnlyMemory<byte> RetrieveGrant =>
        retrieveGrant?.ToArray() ?? ReadOnlyMemory<byte>.Empty;
    public ReadOnlyMemory<byte> DepositGrant =>
        depositGrant?.ToArray() ?? ReadOnlyMemory<byte>.Empty;
}

public sealed class MailboxCredentialReplicaPair
{
    private readonly byte[] firstId, firstSigningKey, secondId, secondSigningKey;
    public MailboxCredentialReplicaPair(ReadOnlySpan<byte> firstId, ReadOnlySpan<byte> firstSigningKey,
        ReadOnlySpan<byte> secondId, ReadOnlySpan<byte> secondSigningKey)
    {
        this.firstId = Copy(firstId); this.firstSigningKey = Copy(firstSigningKey);
        this.secondId = Copy(secondId); this.secondSigningKey = Copy(secondSigningKey);
        if (CryptographicOperations.FixedTimeEquals(this.firstId, this.secondId) ||
            CryptographicOperations.FixedTimeEquals(
                this.firstSigningKey, this.secondSigningKey))
            throw new ArgumentException("Mailbox replica pair must be distinct.");
    }
    public ReadOnlyMemory<byte> FirstId => firstId.ToArray();
    public ReadOnlyMemory<byte> FirstSigningKey => firstSigningKey.ToArray();
    public ReadOnlyMemory<byte> SecondId => secondId.ToArray();
    public ReadOnlyMemory<byte> SecondSigningKey => secondSigningKey.ToArray();
    private static byte[] Copy(ReadOnlySpan<byte> value)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Mailbox replica binding is invalid.");
        return value.ToArray();
    }
}
