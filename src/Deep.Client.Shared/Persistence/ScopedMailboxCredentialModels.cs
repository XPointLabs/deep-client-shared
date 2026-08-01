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
