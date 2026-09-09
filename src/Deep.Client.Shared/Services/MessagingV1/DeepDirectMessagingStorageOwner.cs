using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.PreKeyV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Services.MessagingV1;

/// <summary>
/// Opaque account-scoped owner for the durable direct-messaging graph. The host
/// supplies only verifier-minted local-device capabilities; SQLCipher stores,
/// pre-key secret owners, ratchet state, and persistence keys never cross this
/// boundary.
/// </summary>
public sealed class DeepDirectMessagingStorageFacade : IAsyncDisposable
{
    private readonly DeepDirectMessagingLocalAuthorityBinding authority;
    private DeepDirectMessagingStorageOwner? owner;

    private DeepDirectMessagingStorageFacade(
        DeepDirectMessagingLocalAuthorityBinding authority,
        DeepDirectMessagingStorageOwner owner)
    {
        this.authority = authority;
        this.owner = owner;
    }

    public static async Task<DeepDirectMessagingStorageFacade> OpenAsync(
        string appDataDirectory,
        DeepAccountService accountService,
        LocalDeviceX25519AgreementAuthority localAgreementAuthority,
        VerifiedDeviceRelative verifiedDevice,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountService);
        var identity = await accountService.GetLocalIdentityAsync(cancellationToken)
            .ConfigureAwait(false) ?? throw new CryptographicException(
                "Direct-message storage requires a current local account identity.");
        var authority = DeepDirectMessagingLocalAuthorityBinding.FromVerified(
            localAgreementAuthority,
            verifiedDevice);
        var owner = await DeepDirectMessagingStorageOwner.OpenAsync(
                appDataDirectory,
                accountService.SecureStorageForOwnedComposition,
                accountService,
                identity,
                authority,
                cancellationToken)
            .ConfigureAwait(false);
        return new DeepDirectMessagingStorageFacade(authority, owner);
    }

    public bool IsBoundTo(
        LocalDeviceX25519AgreementAuthority localAgreementAuthority,
        VerifiedDeviceRelative verifiedDevice)
    {
        ObjectDisposedException.ThrowIf(owner is null, this);
        var requested = DeepDirectMessagingLocalAuthorityBinding.FromVerified(
            localAgreementAuthority,
            verifiedDevice);
        return authority.Matches(requested);
    }

    public static void DeleteAccountState(string appDataDirectory) =>
        DeepDirectMessagingStorageOwner.DeleteState(appDataDirectory);

    public async ValueTask DisposeAsync()
    {
        var current = Interlocked.Exchange(ref owner, null);
        if (current is not null)
        {
            await current.DisposeAsync().ConfigureAwait(false);
        }
    }
}

/// <summary>
/// Byte-only projection of a verifier-minted local-device authority. It never
/// retains the authority because that capability owns the device agreement key.
/// </summary>
internal sealed class DeepDirectMessagingLocalAuthorityBinding
{
    private readonly byte[] networkId;
    private readonly byte[] accountId;
    private readonly byte[] deviceId;
    private readonly byte[] exactDpd1Hash;
    private readonly VerifiedDeviceRelative? verifiedDevice;

    private DeepDirectMessagingLocalAuthorityBinding(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> exactDpd1Hash,
        VerifiedDeviceRelative? verifiedDevice)
    {
        RequireIdentifier(networkId, 16, nameof(networkId));
        RequireIdentifier(accountId, 32, nameof(accountId));
        RequireIdentifier(deviceId, 32, nameof(deviceId));
        RequireIdentifier(exactDpd1Hash, 32, nameof(exactDpd1Hash));
        if (accountGeneration == 0 || deviceGeneration == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(accountGeneration),
                "Local account and device generations must be nonzero.");
        }

        this.networkId = networkId.ToArray();
        this.accountId = accountId.ToArray();
        this.deviceId = deviceId.ToArray();
        this.exactDpd1Hash = exactDpd1Hash.ToArray();
        this.verifiedDevice = verifiedDevice;
        AccountGeneration = accountGeneration;
        DeviceGeneration = deviceGeneration;
    }

    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> AccountId => accountId;
    internal ulong AccountGeneration { get; }
    internal ReadOnlySpan<byte> DeviceId => deviceId;
    internal ulong DeviceGeneration { get; }
    internal ReadOnlySpan<byte> ExactDpd1Hash => exactDpd1Hash;
    internal VerifiedDeviceRelative? VerifiedDevice => verifiedDevice;

    internal static DeepDirectMessagingLocalAuthorityBinding FromVerified(
        LocalDeviceX25519AgreementAuthority authority,
        VerifiedDeviceRelative verifiedDevice)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(verifiedDevice);
        var certificate = verifiedDevice.Certificate;
        if (!Fixed(authority.NetworkId.Span, certificate.NetworkId.Span) ||
            !Fixed(authority.AccountId.Span, certificate.AccountHash.Span) ||
            authority.AccountGeneration != certificate.AccountGeneration ||
            !Fixed(authority.DeviceId.Span, certificate.DeviceId.Span) ||
            authority.DeviceGeneration != certificate.DeviceGeneration ||
            !Fixed(authority.ExactDpd1Hash.Span, certificate.CanonicalHash.Span) ||
            !Fixed(authority.AgreementPublicKey.Span,
                certificate.DeviceX25519PublicKey.Span))
        {
            throw new CryptographicException(
                "The verified local device differs from the device-agreement authority.");
        }
        return new DeepDirectMessagingLocalAuthorityBinding(
            authority.NetworkId.Span,
            authority.AccountId.Span,
            authority.AccountGeneration,
            authority.DeviceId.Span,
            authority.DeviceGeneration,
            authority.ExactDpd1Hash.Span,
            verifiedDevice);
    }

#if DEEP_TEST_INTERNALS
    internal static DeepDirectMessagingLocalAuthorityBinding CreateForTests(
        DeepLocalIdentitySnapshot identity,
        ReadOnlySpan<byte> exactDpd1Hash) => new(
            identity.NetworkId.Span,
            identity.Account.AccountIdentity.AccountId.Bytes.Span,
            identity.Account.AccountIdentity.AccountGeneration,
            identity.Device.DeviceId.Bytes.Span,
            identity.Device.DeviceGeneration,
            exactDpd1Hash,
            verifiedDevice: null);

    internal static DeepDirectMessagingLocalAuthorityBinding CreateForTests(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> exactDpd1Hash) => new(
            networkId,
            accountId,
            accountGeneration,
            deviceId,
            deviceGeneration,
            exactDpd1Hash,
            verifiedDevice: null);
#endif

    internal bool Matches(DeepLocalIdentitySnapshot identity) =>
        identity.Account.AccountIdentity.AccountGeneration == AccountGeneration &&
        identity.Device.DeviceGeneration == DeviceGeneration &&
        Fixed(identity.NetworkId.Span, networkId) &&
        Fixed(identity.Account.AccountIdentity.AccountId.Bytes.Span, accountId) &&
        Fixed(identity.Device.DeviceId.Bytes.Span, deviceId);

    internal bool Matches(DeepDirectMessagingLocalAuthorityBinding other) =>
        other.AccountGeneration == AccountGeneration &&
        other.DeviceGeneration == DeviceGeneration &&
        Fixed(other.NetworkId, networkId) &&
        Fixed(other.AccountId, accountId) &&
        Fixed(other.DeviceId, deviceId) &&
        Fixed(other.ExactDpd1Hash, exactDpd1Hash);

    private static void RequireIdentifier(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} must be exactly {length} nonzero bytes.", name);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// One verified remote device and exact DPH2 session identifier. Production
/// construction requires a live ContactResolver capability; raw identifiers are
/// accepted only by the test-only factory.
/// </summary>
internal sealed class DeepDirectMessagingVerifiedSessionBinding
{
    private readonly byte[] networkId;
    private readonly byte[] remoteAccountId;
    private readonly byte[] remoteDeviceId;
    private readonly byte[] conversationId;
    private readonly byte[] exactDph2Id;

    private DeepDirectMessagingVerifiedSessionBinding(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> remoteAccountId,
        ulong remoteAccountGeneration,
        ReadOnlySpan<byte> remoteDeviceId,
        ulong remoteDeviceGeneration,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> exactDph2Id)
    {
        RequireIdentifier(networkId, 16, nameof(networkId));
        RequireIdentifier(remoteAccountId, 32, nameof(remoteAccountId));
        RequireIdentifier(remoteDeviceId, 32, nameof(remoteDeviceId));
        RequireIdentifier(conversationId, 32, nameof(conversationId));
        RequireIdentifier(exactDph2Id, 32, nameof(exactDph2Id));
        if (remoteAccountGeneration == 0 || remoteDeviceGeneration == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(remoteAccountGeneration),
                "Remote account and device generations must be nonzero.");
        }

        this.networkId = networkId.ToArray();
        this.remoteAccountId = remoteAccountId.ToArray();
        this.remoteDeviceId = remoteDeviceId.ToArray();
        this.conversationId = conversationId.ToArray();
        this.exactDph2Id = exactDph2Id.ToArray();
        RemoteAccountGeneration = remoteAccountGeneration;
        RemoteDeviceGeneration = remoteDeviceGeneration;
    }

    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> RemoteAccountId => remoteAccountId;
    internal ulong RemoteAccountGeneration { get; }
    internal ReadOnlySpan<byte> RemoteDeviceId => remoteDeviceId;
    internal ulong RemoteDeviceGeneration { get; }
    internal ReadOnlySpan<byte> ConversationId => conversationId;
    internal ReadOnlySpan<byte> ExactDph2Id => exactDph2Id;

    internal static DeepDirectMessagingVerifiedSessionBinding FromVerified(
        ContactResolverVerifiedCapabilitySet verifiedContact,
        ContactConversationId32 conversationId,
        ReadOnlySpan<byte> remoteDeviceId,
        ReadOnlySpan<byte> exactDph2Id)
    {
        ArgumentNullException.ThrowIfNull(verifiedContact);
        ArgumentNullException.ThrowIfNull(conversationId);
        RequireIdentifier(remoteDeviceId, 32, nameof(remoteDeviceId));
        RequireIdentifier(exactDph2Id, 32, nameof(exactDph2Id));

        var directory = verifiedContact.Bundle.Directory;
        var record = directory.Record;
        var selectedDeviceId = remoteDeviceId.ToArray();
        var entry = record.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.DeviceId.Span, selectedDeviceId));
        var verifiedDevice = directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, selectedDeviceId));
        if (entry is null || verifiedDevice is null ||
            entry.Dpd1Reference.TypeCode != (ushort)ArtifactType.Dpd1 ||
            entry.Dpd1Reference.CanonicalLength != 776 ||
            !Fixed(entry.Dpd1Reference.CanonicalHash.Span,
                verifiedDevice.Certificate.CanonicalHash.Span) ||
            !Fixed(verifiedDevice.Certificate.NetworkId.Span, record.NetworkId.Span) ||
            !Fixed(verifiedDevice.Certificate.AccountHash.Span, record.DeepAccountId.Span) ||
            verifiedDevice.Certificate.AccountGeneration != record.AccountGeneration)
        {
            throw new CryptographicException(
                "The selected direct-message peer is not an active device in the verified contact closure.");
        }

        return new DeepDirectMessagingVerifiedSessionBinding(
            record.NetworkId.Span,
            record.DeepAccountId.Span,
            record.AccountGeneration,
            selectedDeviceId,
            verifiedDevice.Certificate.DeviceGeneration,
            conversationId.Span,
            exactDph2Id);
    }

    internal static DeepDirectMessagingVerifiedSessionBinding FromInitiatorScope(
        InitiatorInitialSessionVerifiedScope verifiedScope,
        ReadOnlySpan<byte> exactDph2Id)
    {
        ArgumentNullException.ThrowIfNull(verifiedScope);
        return new DeepDirectMessagingVerifiedSessionBinding(
            verifiedScope.NetworkId,
            verifiedScope.RemoteAccountId,
            verifiedScope.RemoteAccountGeneration,
            verifiedScope.RemoteDeviceId,
            verifiedScope.RemoteDeviceGeneration,
            verifiedScope.ConversationId,
            exactDph2Id);
    }

#if DEEP_TEST_INTERNALS
    internal static DeepDirectMessagingVerifiedSessionBinding CreateForTests(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> remoteAccountId,
        ulong remoteAccountGeneration,
        ReadOnlySpan<byte> remoteDeviceId,
        ulong remoteDeviceGeneration,
        ContactConversationId32 conversationId,
        ReadOnlySpan<byte> exactDph2Id) => new(
            networkId,
            remoteAccountId,
            remoteAccountGeneration,
            remoteDeviceId,
            remoteDeviceGeneration,
            conversationId.Span,
            exactDph2Id);
#endif

    internal byte[] ComputeCatalogKey(
        DeepDirectMessagingLocalAuthorityBinding localAuthority)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Client/DirectMessaging/session-catalog-key/v1\0"u8);
        Append(hash, localAuthority.NetworkId);
        Append(hash, localAuthority.AccountId);
        Append(hash, U64(localAuthority.AccountGeneration));
        Append(hash, localAuthority.DeviceId);
        Append(hash, U64(localAuthority.DeviceGeneration));
        Append(hash, remoteAccountId);
        Append(hash, U64(RemoteAccountGeneration));
        Append(hash, remoteDeviceId);
        Append(hash, U64(RemoteDeviceGeneration));
        Append(hash, conversationId);
        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static void RequireIdentifier(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} must be exactly {length} nonzero bytes.", name);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class DeepDirectMessagingSessionCatalogEntry
{
    private readonly byte[] remoteAccountId;
    private readonly byte[] remoteDeviceId;
    private readonly byte[] conversationId;
    private readonly byte[] exactDph2Id;

    internal DeepDirectMessagingSessionCatalogEntry(
        ReadOnlySpan<byte> remoteAccountId,
        ulong remoteAccountGeneration,
        ReadOnlySpan<byte> remoteDeviceId,
        ulong remoteDeviceGeneration,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> exactDph2Id)
    {
        this.remoteAccountId = remoteAccountId.ToArray();
        this.remoteDeviceId = remoteDeviceId.ToArray();
        this.conversationId = conversationId.ToArray();
        this.exactDph2Id = exactDph2Id.ToArray();
        RemoteAccountGeneration = remoteAccountGeneration;
        RemoteDeviceGeneration = remoteDeviceGeneration;
    }

    internal ReadOnlyMemory<byte> RemoteAccountId => remoteAccountId.ToArray();
    internal ulong RemoteAccountGeneration { get; }
    internal ReadOnlyMemory<byte> RemoteDeviceId => remoteDeviceId.ToArray();
    internal ulong RemoteDeviceGeneration { get; }
    internal ContactConversationId32 ConversationId => ContactConversationId32.FromBytes(conversationId);
    internal ReadOnlyMemory<byte> ExactDph2Id => exactDph2Id.ToArray();
}

internal sealed record DeepDirectMessagingSessionStoreBinding(
    DeepDirectMessagingSessionCatalogEntry CatalogEntry,
    SqliteMessagingCryptoV1Store Store);

internal sealed class DeepDirectMessagingInventoryPublication
{
    private readonly byte[] operationId;
    private readonly byte[] predecessorXpi1Hash;
    private readonly byte[] currentDmd1Hash;
    private readonly byte[] xpi1Hash;
    private readonly byte[] exactXpi1;
    private readonly byte[] exactXpp1;

    internal DeepDirectMessagingInventoryPublication(
        PreKeyV1InventoryStageResult staged)
    {
        ArgumentNullException.ThrowIfNull(staged);
        var publication = staged.Publication ?? throw new CryptographicException(
            "The durable DPK2 inventory result contains no publication request.");
        if (staged.ForkLatched ||
            staged.Disposition is PreKeyV1InventoryStageDisposition.ForkLatched or
                PreKeyV1InventoryStageDisposition.AlreadyForkLatched)
        {
            throw new CryptographicException(
                "The DPK2 inventory lineage is fork-latched and cannot be published.");
        }
        IsExactReplay = staged.Disposition == PreKeyV1InventoryStageDisposition.ExactReplay;
        InventoryEpoch = publication.InventoryEpoch;
        ServiceGeneration = publication.ServiceGeneration;
        CurrentDmd1Generation = publication.CurrentDmd1Generation;
        operationId = publication.OperationId.ToArray();
        predecessorXpi1Hash = publication.PredecessorXpi1Hash.ToArray();
        currentDmd1Hash = publication.CurrentDmd1Hash.ToArray();
        xpi1Hash = publication.Xpi1Hash.ToArray();
        exactXpi1 = publication.ExactXpi1.ToArray();
        exactXpp1 = publication.ExactPublicationRequest.ToArray();
    }

    internal bool IsExactReplay { get; }
    internal ulong InventoryEpoch { get; }
    internal ulong ServiceGeneration { get; }
    internal ulong CurrentDmd1Generation { get; }
    internal ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    internal ReadOnlyMemory<byte> PredecessorXpi1Hash => predecessorXpi1Hash.ToArray();
    internal ReadOnlyMemory<byte> CurrentDmd1Hash => currentDmd1Hash.ToArray();
    internal ReadOnlyMemory<byte> Xpi1Hash => xpi1Hash.ToArray();
    internal ReadOnlyMemory<byte> ExactXpi1 => exactXpi1.ToArray();
    internal ReadOnlyMemory<byte> ExactPublicationRequest => exactXpp1.ToArray();
}

/// <summary>
/// One-use Protocol DPH2 preparation plus the verifier-minted contact/device
/// scope needed by the later privacy-routed XPK1 adapter. It owns all ephemeral
/// initiator material until completion or disposal.
/// </summary>
internal sealed class DeepDirectMessagingInitiatorClaimPreparation : IDisposable
{
    private readonly object ownerToken;
    private readonly byte[] networkId;
    private readonly byte[] operationId;
    private readonly byte[] responderAccountId;
    private readonly byte[] responderDeviceId;
    private readonly byte[] senderEphemeralCommitment;
    private readonly byte[] exactDpk2;
    private readonly byte[] exactDpk2Hash;
    private InitiatorDph2ClaimPreparation? preparation;
    private int disposed;

    internal DeepDirectMessagingInitiatorClaimPreparation(
        object ownerToken,
        ContactResolverReverifiedPeerAuthority verifiedPeer,
        VerifiedDpk2Offering verifiedOffering,
        InitiatorInitialSessionVerifiedScope verifiedScope,
        InitiatorDph2ClaimPreparation preparation)
    {
        this.ownerToken = ownerToken ?? throw new ArgumentNullException(nameof(ownerToken));
        VerifiedPeer = verifiedPeer ?? throw new ArgumentNullException(nameof(verifiedPeer));
        VerifiedOffering = verifiedOffering ?? throw new ArgumentNullException(nameof(verifiedOffering));
        VerifiedScope = verifiedScope ?? throw new ArgumentNullException(nameof(verifiedScope));
        this.preparation = preparation ?? throw new ArgumentNullException(nameof(preparation));
        networkId = preparation.NetworkId.ToArray();
        operationId = preparation.ClaimOperationId.ToArray();
        responderAccountId = preparation.ResponderAccountId.ToArray();
        responderDeviceId = preparation.ResponderDeviceId.ToArray();
        senderEphemeralCommitment = preparation.SenderEphemeralCommitment.ToArray();
        exactDpk2 = verifiedOffering.ExactBytes.ToArray();
        exactDpk2Hash = verifiedOffering.ExactHash.ToArray();
    }

    internal ContactResolverReverifiedPeerAuthority VerifiedPeer { get; }
    internal VerifiedDpk2Offering VerifiedOffering { get; }
    internal InitiatorInitialSessionVerifiedScope VerifiedScope { get; }
    internal ReadOnlyMemory<byte> NetworkId => Copy(networkId);
    internal ReadOnlyMemory<byte> ClaimOperationId => Copy(operationId);
    internal ReadOnlyMemory<byte> ResponderAccountId => Copy(responderAccountId);
    internal ReadOnlyMemory<byte> ResponderDeviceId => Copy(responderDeviceId);
    internal ReadOnlyMemory<byte> SenderEphemeralCommitment => Copy(senderEphemeralCommitment);
    internal ReadOnlyMemory<byte> ExactDpk2 => Copy(exactDpk2);
    internal ReadOnlyMemory<byte> ExactDpk2Hash => Copy(exactDpk2Hash);

    internal InitiatorInitialSessionCommitCapability Complete(
        object expectedOwnerToken,
        VerifiedXpc1PreKeyClaimReceipt verifiedClaim,
        ReadOnlySpan<byte> exactSessionInitDmc2,
        ReadOnlySpan<byte> exactFirstApplicationDmc2)
    {
        ArgumentNullException.ThrowIfNull(verifiedClaim);
        if (!ReferenceEquals(ownerToken, expectedOwnerToken))
        {
            throw new CryptographicException(
                "The DPH2 preparation belongs to another direct-message owner.");
        }
        var owned = Interlocked.Exchange(ref preparation, null) ??
            throw new ObjectDisposedException(nameof(DeepDirectMessagingInitiatorClaimPreparation));
        try
        {
            return owned.Complete(
                verifiedClaim,
                exactSessionInitDmc2,
                exactFirstApplicationDmc2);
        }
        finally
        {
            owned.Dispose();
            DisposePublicValues();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }
        Interlocked.Exchange(ref preparation, null)?.Dispose();
        DisposePublicValues();
    }

    private void DisposePublicValues()
    {
        CryptographicOperations.ZeroMemory(networkId);
        CryptographicOperations.ZeroMemory(operationId);
        CryptographicOperations.ZeroMemory(responderAccountId);
        CryptographicOperations.ZeroMemory(responderDeviceId);
        CryptographicOperations.ZeroMemory(senderEphemeralCommitment);
        CryptographicOperations.ZeroMemory(exactDpk2);
        CryptographicOperations.ZeroMemory(exactDpk2Hash);
        Interlocked.Exchange(ref disposed, 1);
    }

    private byte[] Copy(byte[] value)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return value.ToArray();
    }
}

internal sealed class DeepDirectMessagingInitiatorCommitResult : IDisposable
{
    private readonly byte[] stateCommitment;
    private readonly byte[] journalHead;
    private byte[]? exactDph2;
    private byte[]? claimOperationId;
    private byte[]? fullReplayHash;

    internal DeepDirectMessagingInitiatorCommitResult(
        MessagingCryptoV1CommitResult commit,
        InitiatorInitialSessionDispatchEnvelope dispatch)
    {
        ArgumentNullException.ThrowIfNull(commit);
        ArgumentNullException.ThrowIfNull(dispatch);
        Disposition = commit.Disposition;
        StateGeneration = commit.StateGeneration;
        JournalGeneration = commit.JournalGeneration;
        ForkLatched = commit.ForkLatched;
        TerminallyLatched = commit.TerminallyLatched;
        stateCommitment = commit.StateCommitment.ToArray();
        journalHead = commit.JournalHead.ToArray();
        exactDph2 = dispatch.ExactDph2.ToArray();
        claimOperationId = dispatch.OperationId.ToArray();
        fullReplayHash = dispatch.ReplayHash.ToArray();
    }

    internal MessagingCryptoV1CommitDisposition Disposition { get; }
    internal ulong StateGeneration { get; }
    internal ReadOnlyMemory<byte> StateCommitment => stateCommitment.ToArray();
    internal ulong JournalGeneration { get; }
    internal ReadOnlyMemory<byte> JournalHead => journalHead.ToArray();
    internal bool ForkLatched { get; }
    internal bool TerminallyLatched { get; }
    internal ReadOnlyMemory<byte> ExactDph2 => Value(exactDph2).ToArray();
    internal ReadOnlyMemory<byte> ClaimOperationId => Value(claimOperationId).ToArray();
    internal ReadOnlyMemory<byte> FullReplayHash => Value(fullReplayHash).ToArray();

    public void Dispose()
    {
        Zero(Interlocked.Exchange(ref exactDph2, null));
        Zero(Interlocked.Exchange(ref claimOperationId, null));
        Zero(Interlocked.Exchange(ref fullReplayHash, null));
        CryptographicOperations.ZeroMemory(stateCommitment);
        CryptographicOperations.ZeroMemory(journalHead);
    }

    private static byte[] Value(byte[]? value) =>
        value ?? throw new ObjectDisposedException(nameof(DeepDirectMessagingInitiatorCommitResult));
    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}

/// <summary>
/// Account-owned storage graph for the clean-break direct-message path. It owns
/// one device-wide DPK2 secret store and one independently keyed DPE2 ratchet
/// store per verified contact/device/session tuple. It performs no network I/O.
/// </summary>
internal sealed class DeepDirectMessagingStorageOwner : IAsyncDisposable
{
    private const string PreKeyPath = "deep-store-v1/direct-prekeys.dpk2";
    private const string CatalogPath = "deep-store-v1/direct-sessions.dsc1";
    private const string SessionsDirectory = "deep-store-v1/direct-sessions";
    private const string PreKeySlotSuffix = ".direct-prekey-v1-key";
    private const string CatalogSlotSuffix = ".direct-session-catalog-key";
    private const string SessionSlotSuffix = ".direct-session-key.";
    private readonly string appDataDirectory;
    private readonly IDeepSecureStorage secureStorage;
    private readonly DeepAccountService accountService;
    private readonly DeepLocalIdentitySnapshot identity;
    private readonly DeepDirectMessagingLocalAuthorityBinding localAuthority;
    private readonly SqlitePreKeyV1SecretOwner preKeyOwner;
    private readonly ProductionPreKeyV1InventoryOwner? inventoryOwner;
    private readonly DeepDirectMessagingSessionCatalog catalog;
    private readonly object ownerToken = new();
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Dictionary<string, DeepDirectMessagingSessionStoreBinding> sessions =
        new(StringComparer.Ordinal);
    private int disposed;

    private DeepDirectMessagingStorageOwner(
        string appDataDirectory,
        IDeepSecureStorage secureStorage,
        DeepAccountService accountService,
        DeepLocalIdentitySnapshot identity,
        DeepDirectMessagingLocalAuthorityBinding localAuthority,
        SqlitePreKeyV1SecretOwner preKeyOwner,
        ProductionPreKeyV1InventoryOwner? inventoryOwner,
        DeepDirectMessagingSessionCatalog catalog)
    {
        this.appDataDirectory = appDataDirectory;
        this.secureStorage = secureStorage;
        this.accountService = accountService;
        this.identity = identity;
        this.localAuthority = localAuthority;
        this.preKeyOwner = preKeyOwner;
        this.inventoryOwner = inventoryOwner;
        this.catalog = catalog;
    }

    internal SqlitePreKeyV1SecretOwner PreKeyOwner => preKeyOwner;
    internal bool IsCatalogKeyZeroedForTesting => catalog.IsKeyZeroedForTesting;
    internal bool IsPreKeyOwnerKeyZeroedForTesting => preKeyOwner.IsKeyZeroedForTesting;
    internal bool HasProductionInventoryOwner => inventoryOwner is not null;

    internal static async Task<DeepDirectMessagingStorageOwner> OpenAsync(
        string appDataDirectory,
        IDeepSecureStorage secureStorage,
        DeepAccountService accountService,
        DeepLocalIdentitySnapshot identity,
        DeepDirectMessagingLocalAuthorityBinding localAuthority,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appDataDirectory);
        ArgumentNullException.ThrowIfNull(secureStorage);
        ArgumentNullException.ThrowIfNull(accountService);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(localAuthority);
        cancellationToken.ThrowIfCancellationRequested();
        if (!localAuthority.Matches(identity))
        {
            throw new CryptographicException(
                "The verified local messaging authority belongs to another account or device generation.");
        }

        var root = Path.GetFullPath(appDataDirectory);
        var preKeyPath = Path.Combine(root, PreKeyPath);
        var catalogPath = Path.Combine(root, CatalogPath);
        var preKeySlot = ScopedSlot(
            identity.SecureSlots.MessageStoreInstanceId,
            PreKeySlotSuffix,
            "direct pre-key owner");
        var catalogSlot = ScopedSlot(
            identity.SecureSlots.MessageStoreInstanceId,
            CatalogSlotSuffix,
            "direct session catalog");
        byte[]? preKeyKey = null;
        byte[]? catalogKey = null;
        var createdSlots = new List<string>(2);
        SqlitePreKeyV1SecretOwner? openedPreKeys = null;
        ProductionPreKeyV1InventoryOwner? openedInventory = null;
        DeepDirectMessagingSessionCatalog? openedCatalog = null;
        try
        {
            preKeyKey = await ReadKeyAsync(
                    secureStorage, preKeySlot, "direct pre-key", cancellationToken)
                .ConfigureAwait(false);
            catalogKey = await ReadKeyAsync(
                    secureStorage, catalogSlot, "direct session catalog", cancellationToken)
                .ConfigureAwait(false);
            if (preKeyKey is null && SqliteFamilyExists(preKeyPath))
            {
                throw ResetRequired(
                    "The direct pre-key database exists without its protected SQLCipher key.");
            }
            if (catalogKey is null && SqliteFamilyExists(catalogPath))
            {
                throw ResetRequired(
                    "The direct session catalog exists without its protected SQLCipher key.");
            }

            var writes = new List<DeepSecureStorageWrite>(2);
            if (preKeyKey is null)
            {
                preKeyKey = CreateNonzeroKey();
                writes.Add(new DeepSecureStorageWrite(preKeySlot, preKeyKey));
                createdSlots.Add(preKeySlot);
            }
            if (catalogKey is null)
            {
                do
                {
                    if (catalogKey is not null)
                    {
                        CryptographicOperations.ZeroMemory(catalogKey);
                    }
                    catalogKey = CreateNonzeroKey();
                }
                while (CryptographicOperations.FixedTimeEquals(preKeyKey, catalogKey));
                writes.Add(new DeepSecureStorageWrite(catalogSlot, catalogKey));
                createdSlots.Add(catalogSlot);
            }
            if (CryptographicOperations.FixedTimeEquals(preKeyKey, catalogKey))
            {
                throw ResetRequired(
                    "The direct pre-key and session-catalog SQLCipher keys are not distinct.");
            }
            if (writes.Count != 0)
            {
                await secureStorage.WriteBatchAsync(writes, cancellationToken)
                    .ConfigureAwait(false);
            }

            var dpd1Reference = CreateDpd1Reference(localAuthority.ExactDpd1Hash);
            try
            {
                var preKeyScope = new PreKeyV1StoreScope(
                    localAuthority.NetworkId,
                    localAuthority.AccountId,
                    localAuthority.AccountGeneration,
                    localAuthority.DeviceId,
                    localAuthority.DeviceGeneration,
                    dpd1Reference,
                    localAuthority.ExactDpd1Hash,
                    checked((ulong)identity.StoreGeneration));
                using var preKeyOptions = new PreKeyV1StoreOptions(
                    preKeyPath,
                    preKeyKey,
                    preKeyScope);
                openedPreKeys = new SqlitePreKeyV1SecretOwner(preKeyOptions);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dpd1Reference);
            }

            if (localAuthority.VerifiedDevice is { } verifiedDevice)
            {
                openedInventory = await ProductionPreKeyV1InventoryOwner.CreateAsync(
                        openedPreKeys,
                        accountService,
                        identity,
                        verifiedDevice,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            var storeInstanceId = await ReadStoreInstanceIdAsync(
                    secureStorage,
                    identity.SecureSlots.MessageStoreInstanceId,
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                openedCatalog = new DeepDirectMessagingSessionCatalog(
                    catalogPath,
                    catalogKey,
                    new DeepDirectMessagingCatalogScope(
                        localAuthority,
                        checked((ulong)identity.StoreGeneration),
                        storeInstanceId));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(storeInstanceId);
            }

            var result = new DeepDirectMessagingStorageOwner(
                root,
                secureStorage,
                accountService,
                identity,
                localAuthority,
                openedPreKeys,
                openedInventory,
                openedCatalog);
            openedPreKeys = null;
            openedInventory = null;
            openedCatalog = null;
            return result;
        }
        catch (Exception exception)
        {
            openedInventory?.Dispose();
            openedInventory = null;
            if (openedPreKeys is not null)
            {
                await openedPreKeys.DisposeAsync().ConfigureAwait(false);
                openedPreKeys = null;
            }
            openedCatalog?.Dispose();
            openedCatalog = null;
            if (createdSlots.Count != 0)
            {
                await secureStorage.DeleteBatchAsync(createdSlots, CancellationToken.None)
                    .ConfigureAwait(false);
                if (createdSlots.Contains(preKeySlot, StringComparer.Ordinal))
                {
                    DeleteSqliteFamily(preKeyPath);
                }
                if (createdSlots.Contains(catalogSlot, StringComparer.Ordinal))
                {
                    DeleteSqliteFamily(catalogPath);
                }
            }
            if (exception is PreKeyV1StoreOpenException)
            {
                throw ResetRequired(
                    "The protected direct pre-key store cannot be opened.",
                    exception);
            }
            throw;
        }
        finally
        {
            openedInventory?.Dispose();
            if (openedPreKeys is not null)
            {
                await openedPreKeys.DisposeAsync().ConfigureAwait(false);
            }
            openedCatalog?.Dispose();
            Zero(preKeyKey);
            Zero(catalogKey);
        }
    }

    internal bool MatchesAuthority(DeepDirectMessagingLocalAuthorityBinding authority) =>
        localAuthority.Matches(authority);

    internal async ValueTask<DeepDirectMessagingInventoryPublication?>
        EnsureInventoryAsync(
            PreKeyV1InventoryAuthoringContext? authoringContext,
            CancellationToken cancellationToken = default)
    {
        if (authoringContext is null)
        {
            return null;
        }
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var owner = inventoryOwner ?? throw new CryptographicException(
                "DPK2 inventory requires a current verified local DPD1/DMD1 authority.");
            var staged = await owner.EnsureInventoryAsync(authoringContext, cancellationToken)
                .ConfigureAwait(false);
            return new DeepDirectMessagingInventoryPublication(staged);
        }
        finally
        {
            gate.Release();
        }
    }

    internal async ValueTask<DeepDirectMessagingInitiatorClaimPreparation?>
        TryPrepareInitiatorClaimAsync(
            ContactResolverReverifiedPeerAuthority? verifiedPeer,
            VerifiedDpk2Offering? verifiedOffering,
            LocalDeviceX25519AgreementLease? deviceAgreementLease,
            int maximumMessagesWithoutPqInjection,
            CancellationToken cancellationToken = default)
    {
        if (verifiedPeer is null || verifiedOffering is null || deviceAgreementLease is null)
        {
            deviceAgreementLease?.Dispose();
            return null;
        }
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
        {
            deviceAgreementLease.Dispose();
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        }

        var gateHeld = false;
        var transferred = false;
        InitiatorDph2ClaimPreparation? prepared = null;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            gateHeld = true;
            ThrowIfDisposed();
            var scope = InitiatorInitialSessionVerifiedScope.FromReverifiedPeer(
                verifiedPeer,
                verifiedOffering.ResponderDeviceId.Span);
            RequireLocalInitiatorLease(deviceAgreementLease);
            RequireVerifiedOfferingMatchesScope(verifiedOffering, verifiedPeer, scope);
            var factory = new ManagedInitiatorInitialSessionFactory(
                maximumMessagesWithoutPqInjection);
            prepared = factory.PrepareClaim(verifiedOffering, deviceAgreementLease);
            transferred = true;
            var result = new DeepDirectMessagingInitiatorClaimPreparation(
                ownerToken,
                verifiedPeer,
                verifiedOffering,
                scope,
                prepared);
            prepared = null;
            return result;
        }
        finally
        {
            prepared?.Dispose();
            if (!transferred)
            {
                deviceAgreementLease.Dispose();
            }
            if (gateHeld)
            {
                gate.Release();
            }
        }
    }

    internal async ValueTask<DeepDirectMessagingInitiatorCommitResult?>
        TryCommitInitiatorSessionAsync(
            DeepDirectMessagingInitiatorClaimPreparation? preparedClaim,
            VerifiedXpc1PreKeyClaimReceipt? verifiedClaim,
            ReadOnlyMemory<byte> exactSessionInitDmc2,
            ReadOnlyMemory<byte> exactFirstApplicationDmc2 = default,
            CancellationToken cancellationToken = default)
    {
        if (preparedClaim is null || verifiedClaim is null)
        {
            preparedClaim?.Dispose();
            return null;
        }
        InitiatorInitialSessionCommitCapability? capability = null;
        byte[]? exactDph2Id = null;
        try
        {
            ThrowIfDisposed();
            capability = preparedClaim.Complete(
                ownerToken,
                verifiedClaim,
                exactSessionInitDmc2.Span,
                exactFirstApplicationDmc2.Span);
            exactDph2Id = capability.SessionId.ToArray();
            var session = DeepDirectMessagingVerifiedSessionBinding.FromInitiatorScope(
                preparedClaim.VerifiedScope,
                exactDph2Id);
            var opened = await TryOpenSessionAsync(
                    session,
                    createIfMissing: true,
                    cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "The verified initiator DPH2 session store was not opened.");

            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                var catalogKey = session.ComputeCatalogKey(localAuthority);
                try
                {
                    var keyText = Convert.ToHexStringLower(catalogKey);
                    if (!sessions.TryGetValue(keyText, out var current) ||
                        !ReferenceEquals(current.Store, opened.Store))
                    {
                        throw new CryptographicException(
                            "The initiator session store lost its account-owner binding.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(catalogKey);
                }

                var adapter = new ManagedInitiatorInitialSessionSqliteAdapter(
                    opened.Store,
                    preparedClaim.VerifiedScope);
                var committed = await adapter.CommitAsync(capability, cancellationToken)
                    .ConfigureAwait(false);
                capability = null;
                using var dispatch = await adapter.ReadPendingDispatchAsync(cancellationToken)
                    .ConfigureAwait(false) ?? throw new CryptographicException(
                    "The committed initiator TRS1 has no exact durable DPH2 dispatch.");
                return new DeepDirectMessagingInitiatorCommitResult(committed, dispatch);
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            capability?.Dispose();
            preparedClaim.Dispose();
            Zero(exactDph2Id);
        }
    }

    internal async ValueTask<PreKeyV1InitialSessionSagaResult?>
        TryCommitResponderSessionAsync(
            DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
            VerifiedContactBundleEvidence? relationship,
            VerifiedXpc1PreKeyClaimReceipt? verifiedClaim,
            VerifiedDph2Initiation? verifiedInitiation,
            int maximumMessagesWithoutPqInjection,
            CancellationToken cancellationToken = default)
    {
        if (verifiedSession is null || relationship is null ||
            verifiedClaim is null || verifiedInitiation is null)
        {
            return null;
        }
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        }
        RequireResponderSessionBinding(
            verifiedSession,
            relationship,
            verifiedInitiation);
        var opened = await TryOpenSessionAsync(
                verifiedSession,
                createIfMissing: true,
                cancellationToken)
            .ConfigureAwait(false) ?? throw new CryptographicException(
                "The verified responder DPH2 session store was not opened.");

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var coordinator = new ContactInitialSessionCoordinator(
                preKeyOwner,
                opened.Store,
                relationship,
                accountService,
                identity,
                maximumMessagesWithoutPqInjection);
            return await coordinator.CommitAsync(
                    verifiedClaim,
                    verifiedInitiation,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    internal async ValueTask<DeepDirectMessagingSessionStoreBinding?> TryOpenSessionAsync(
        DeepDirectMessagingVerifiedSessionBinding? verifiedSession,
        bool createIfMissing,
        CancellationToken cancellationToken = default)
    {
        if (verifiedSession is null)
        {
            return null;
        }
        if (!CryptographicOperations.FixedTimeEquals(
                verifiedSession.NetworkId,
                localAuthority.NetworkId))
        {
            throw new CryptographicException(
                "The verified direct-message peer belongs to another network.");
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var catalogKey = verifiedSession.ComputeCatalogKey(localAuthority);
            try
            {
                var keyText = Convert.ToHexStringLower(catalogKey);
                if (sessions.TryGetValue(keyText, out var existing))
                {
                    RequireExactSession(existing.CatalogEntry, verifiedSession);
                    return existing;
                }

                var row = catalog.Read(catalogKey);
                var inserted = false;
                if (row is null)
                {
                    if (!createIfMissing)
                    {
                        return null;
                    }
                    row = CreatePendingRow(catalogKey, verifiedSession);
                    catalog.InsertPending(row);
                    inserted = true;
                }
                RequireExactSession(row, verifiedSession);

                var statePath = Path.Combine(appDataDirectory, row.RelativePath);
                byte[]? sessionKey = await ReadKeyAsync(
                        secureStorage,
                        row.KeySlot,
                        "direct message session",
                        cancellationToken)
                    .ConfigureAwait(false);
                var databaseExisted = SqliteFamilyExists(statePath);
                var createdKey = sessionKey is null;
                if (createdKey && row.State == DirectSessionCatalogState.Active)
                {
                    throw ResetRequired(
                        "An active direct-message session exists without its protected SQLCipher key.");
                }
                if (createdKey && databaseExisted)
                {
                    throw ResetRequired(
                        "The direct-message session database exists without its protected SQLCipher key.");
                }

                sessionKey ??= CreateNonzeroKey();
                SqliteMessagingCryptoV1Store? opened = null;
                try
                {
                    if (createdKey)
                    {
                        await secureStorage.WriteBatchAsync(
                                [new DeepSecureStorageWrite(row.KeySlot, sessionKey)],
                                cancellationToken)
                            .ConfigureAwait(false);
                    }

                    var scope = new MessagingCryptoV1StoreScope(
                        localAuthority.AccountId,
                        localAuthority.AccountGeneration,
                        localAuthority.DeviceId,
                        localAuthority.DeviceGeneration,
                        verifiedSession.ConversationId,
                        verifiedSession.ExactDph2Id,
                        checked((ulong)identity.StoreGeneration));
                    using var options = new MessagingCryptoV1StoreOptions(
                        statePath,
                        sessionKey,
                        scope);
                    opened = new SqliteMessagingCryptoV1Store(options);
                    catalog.Activate(catalogKey);
                    var entry = row.ToEntry();
                    var binding = new DeepDirectMessagingSessionStoreBinding(entry, opened);
                    sessions.Add(keyText, binding);
                    opened = null;
                    return binding;
                }
                catch (Exception exception)
                {
                    if (opened is not null)
                    {
                        await opened.DisposeAsync().ConfigureAwait(false);
                        opened = null;
                    }
                    if (inserted && createdKey && !databaseExisted)
                    {
                        await secureStorage.DeleteBatchAsync([row.KeySlot], CancellationToken.None)
                            .ConfigureAwait(false);
                        catalog.RemovePending(catalogKey);
                        DeleteSqliteFamily(statePath);
                    }
                    if (exception is MessagingCryptoV1StoreOpenException)
                    {
                        throw ResetRequired(
                            "The protected direct-message session store cannot be opened.",
                            exception);
                    }
                    throw;
                }
                finally
                {
                    if (opened is not null)
                    {
                        await opened.DisposeAsync().ConfigureAwait(false);
                    }
                    Zero(sessionKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(catalogKey);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    internal async ValueTask<IReadOnlyList<DeepDirectMessagingSessionCatalogEntry>>
        ReadCatalogAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return catalog.ReadAll().Select(static row => row.ToEntry()).ToArray();
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            foreach (var binding in sessions.Values)
            {
                await binding.Store.DisposeAsync().ConfigureAwait(false);
            }
            sessions.Clear();
            catalog.Dispose();
            inventoryOwner?.Dispose();
            await preKeyOwner.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    internal static void DeleteState(string appDataDirectory)
    {
        var root = Path.GetFullPath(appDataDirectory);
        DeleteSqliteFamily(Path.Combine(root, PreKeyPath));
        DeleteSqliteFamily(Path.Combine(root, CatalogPath));
        var sessionDirectory = Path.Combine(root, SessionsDirectory);
        if (!Directory.Exists(sessionDirectory))
        {
            return;
        }
        foreach (var file in Directory.GetFiles(sessionDirectory))
        {
            File.Delete(file);
        }
        Directory.Delete(sessionDirectory, recursive: false);
    }

    private DirectSessionCatalogRow CreatePendingRow(
        ReadOnlySpan<byte> catalogKey,
        DeepDirectMessagingVerifiedSessionBinding session)
    {
        var keyText = Convert.ToHexStringLower(catalogKey);
        var relativePath = SessionsDirectory.Replace('/', Path.DirectorySeparatorChar) +
                           Path.DirectorySeparatorChar + keyText + ".mcr1";
        var keySlot = ScopedSlot(
            identity.SecureSlots.MessageStoreInstanceId,
            SessionSlotSuffix + keyText,
            "direct message session");
        return new DirectSessionCatalogRow(
            catalogKey.ToArray(),
            session.RemoteAccountId.ToArray(),
            session.RemoteAccountGeneration,
            session.RemoteDeviceId.ToArray(),
            session.RemoteDeviceGeneration,
            session.ConversationId.ToArray(),
            session.ExactDph2Id.ToArray(),
            keySlot,
            relativePath,
            DirectSessionCatalogState.Pending);
    }

    private static void RequireExactSession(
        DeepDirectMessagingSessionCatalogEntry entry,
        DeepDirectMessagingVerifiedSessionBinding expected)
    {
        if (entry.RemoteAccountGeneration != expected.RemoteAccountGeneration ||
            entry.RemoteDeviceGeneration != expected.RemoteDeviceGeneration ||
            !Fixed(entry.RemoteAccountId.Span, expected.RemoteAccountId) ||
            !Fixed(entry.RemoteDeviceId.Span, expected.RemoteDeviceId) ||
            !Fixed(entry.ConversationId.Span, expected.ConversationId) ||
            !Fixed(entry.ExactDph2Id.Span, expected.ExactDph2Id))
        {
            throw new CryptographicException(
                "The verified direct-message session conflicts with its durable catalog entry.");
        }
    }

    private static void RequireExactSession(
        DirectSessionCatalogRow row,
        DeepDirectMessagingVerifiedSessionBinding expected) =>
        RequireExactSession(row.ToEntry(), expected);

    private void RequireLocalInitiatorLease(
        LocalDeviceX25519AgreementLease lease)
    {
        if (lease.Purpose != LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1 ||
            lease.AccountGeneration != localAuthority.AccountGeneration ||
            lease.DeviceGeneration != localAuthority.DeviceGeneration ||
            !Fixed(lease.NetworkId.Span, localAuthority.NetworkId) ||
            !Fixed(lease.AccountId.Span, localAuthority.AccountId) ||
            !Fixed(lease.DeviceId.Span, localAuthority.DeviceId) ||
            !Fixed(lease.ExactDpd1Hash.Span, localAuthority.ExactDpd1Hash))
        {
            throw new CryptographicException(
                "The protected DPH2 initiator lease is outside the local account/device authority.");
        }
    }

    private void RequireVerifiedOfferingMatchesScope(
        VerifiedDpk2Offering offering,
        ContactResolverReverifiedPeerAuthority peer,
        InitiatorInitialSessionVerifiedScope scope)
    {
        var exact = offering.ExactBytes.ToArray();
        byte[]? canonical = null;
        byte[]? expectedDpd1Reference = null;
        byte[]? exactHash = null;
        try
        {
            var record = Dpk2Codec.Decode(exact);
            canonical = Dpk2Codec.Encode(record);
            exactHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record);
            var directory = peer.Bundle.Directory;
            var directoryRecord = directory.Record;
            var selected = directory.Identity.ActiveDevices.SingleOrDefault(device =>
                Fixed(device.Certificate.DeviceId.Span, scope.RemoteDeviceId));
            if (selected is null)
            {
                throw new CryptographicException(
                    "The verified DPK2 responder is absent from the current contact closure.");
            }
            expectedDpd1Reference = CreateDpd1Reference(
                selected.Certificate.CanonicalHash.Span);
            if (!Fixed(scope.NetworkId, localAuthority.NetworkId) ||
                !Fixed(scope.LocalAccountId, localAuthority.AccountId) ||
                !Fixed(record.NetworkId.Span, scope.NetworkId) ||
                !Fixed(record.ResponderAccountId.Span, scope.RemoteAccountId) ||
                !Fixed(record.ResponderDeviceId.Span, scope.RemoteDeviceId) ||
                record.ResponderDeviceGeneration != scope.RemoteDeviceGeneration ||
                !Fixed(record.ResponderDpd1Ref.Span, expectedDpd1Reference) ||
                record.DeviceDirectoryGeneration != scope.RemoteDirectoryGeneration ||
                !Fixed(record.DeviceDirectoryHeadHash.Span,
                    directoryRecord.RecordHash.Span) ||
                !Fixed(canonical, exact) ||
                !Fixed(exactHash, offering.ExactHash.Span))
            {
                throw new CryptographicException(
                    "The verified DPK2 offering differs from the current contact/device closure.");
            }
        }
        finally
        {
            Zero(exact);
            Zero(canonical);
            Zero(expectedDpd1Reference);
            Zero(exactHash);
        }
    }

    private void RequireResponderSessionBinding(
        DeepDirectMessagingVerifiedSessionBinding session,
        VerifiedContactBundleEvidence relationship,
        VerifiedDph2Initiation initiation)
    {
        var exact = initiation.ExactBytes.ToArray();
        byte[]? canonical = null;
        try
        {
            var record = Dph2Codec.Decode(exact);
            canonical = Dph2Codec.Encode(record);
            if (!Fixed(session.NetworkId, localAuthority.NetworkId) ||
                !Fixed(relationship.Address.NetworkId.Span, localAuthority.NetworkId) ||
                !Fixed(relationship.Scope.AccountId.Bytes.Span, localAuthority.AccountId) ||
                !Fixed(relationship.RemoteAccountId.Span, session.RemoteAccountId) ||
                !Fixed(relationship.ConversationId.Span, session.ConversationId) ||
                !Fixed(record.NetworkId.Span, localAuthority.NetworkId) ||
                !Fixed(record.InitiatorAccountId.Span, session.RemoteAccountId) ||
                !Fixed(record.InitiatorDeviceId.Span, session.RemoteDeviceId) ||
                record.InitiatorDeviceGeneration != session.RemoteDeviceGeneration ||
                !Fixed(record.ResponderAccountId.Span, localAuthority.AccountId) ||
                !Fixed(record.ResponderDeviceId.Span, localAuthority.DeviceId) ||
                record.ResponderDeviceGeneration != localAuthority.DeviceGeneration ||
                !Fixed(record.SessionId.Span, session.ExactDph2Id) ||
                !Fixed(canonical, exact))
            {
                throw new CryptographicException(
                    "The verified responder DPH2 differs from the contact/session owner scope.");
            }
        }
        finally
        {
            Zero(exact);
            Zero(canonical);
        }
    }

    private static async Task<byte[]?> ReadKeyAsync(
        IDeepSecureStorage secureStorage,
        string slot,
        string purpose,
        CancellationToken cancellationToken)
    {
        using var stored = await secureStorage.ReadOwnedAsync(slot, cancellationToken)
            .ConfigureAwait(false);
        if (stored is null)
        {
            return null;
        }
        if (stored.Length != 32)
        {
            throw ResetRequired($"The {purpose} SQLCipher key is invalid.");
        }
        var result = new byte[32];
        stored.CopyTo(result);
        if (result.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            CryptographicOperations.ZeroMemory(result);
            throw ResetRequired($"The {purpose} SQLCipher key is invalid.");
        }
        return result;
    }

    private static async Task<byte[]> ReadStoreInstanceIdAsync(
        IDeepSecureStorage secureStorage,
        string slot,
        CancellationToken cancellationToken)
    {
        var value = await ReadKeyAsync(
                secureStorage,
                slot,
                "message-store instance",
                cancellationToken)
            .ConfigureAwait(false);
        return value ?? throw ResetRequired("The message-store instance ID is missing.");
    }

    private static byte[] CreateDpd1Reference(ReadOnlySpan<byte> dpd1Hash)
    {
        if (dpd1Hash.Length != 32 || dpd1Hash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The exact DPD1 hash must be 32 nonzero bytes.",
                nameof(dpd1Hash));
        }
        var result = new byte[38];
        "DPD1"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        dpd1Hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private static string ScopedSlot(
        string messageStoreInstanceSlot,
        string suffix,
        string purpose)
    {
        const string sourceSuffix = ".message-store-instance";
        if (!messageStoreInstanceSlot.StartsWith("deep.store.v1.", StringComparison.Ordinal) ||
            !messageStoreInstanceSlot.EndsWith(sourceSuffix, StringComparison.Ordinal) ||
            suffix.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw ResetRequired($"The {purpose} secure-storage scope is invalid.");
        }
        return messageStoreInstanceSlot[..^sourceSuffix.Length] + suffix;
    }

    private static byte[] CreateNonzeroKey()
    {
        while (true)
        {
            var key = RandomNumberGenerator.GetBytes(32);
            if (key.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
            {
                return key;
            }
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private static LocalStateResetRequiredException ResetRequired(
        string message,
        Exception? inner = null) => new(
            inner is PreKeyV1StoreOpenException { Reason: PreKeyV1StoreOpenFailure.UnreadableOrWrongKey } or
                MessagingCryptoV1StoreOpenException { Reason: MessagingCryptoV1StoreOpenFailure.UnreadableOrWrongKey }
                ? LocalStateResetRequiredReason.UnreadableOrWrongKey
                : LocalStateResetRequiredReason.InvalidCurrentSchema,
            message,
            inner);

    private static bool SqliteFamilyExists(string statePath) =>
        File.Exists(statePath) || File.Exists(statePath + "-wal") ||
        File.Exists(statePath + "-shm") || File.Exists(statePath + "-journal");

    private static void DeleteSqliteFamily(string statePath)
    {
        foreach (var path in new[]
                 {
                     statePath,
                     statePath + "-wal",
                     statePath + "-shm",
                     statePath + "-journal"
                 })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
}

internal sealed class DeepDirectMessagingCatalogScope
{
    private readonly byte[] networkId;
    private readonly byte[] localAccountId;
    private readonly byte[] localDeviceId;
    private readonly byte[] storeInstanceId;

    internal DeepDirectMessagingCatalogScope(
        DeepDirectMessagingLocalAuthorityBinding authority,
        ulong databaseGeneration,
        ReadOnlySpan<byte> storeInstanceId)
    {
        networkId = authority.NetworkId.ToArray();
        localAccountId = authority.AccountId.ToArray();
        localDeviceId = authority.DeviceId.ToArray();
        this.storeInstanceId = storeInstanceId.ToArray();
        AccountGeneration = authority.AccountGeneration;
        DeviceGeneration = authority.DeviceGeneration;
        DatabaseGeneration = databaseGeneration;
    }

    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> LocalAccountId => localAccountId;
    internal ulong AccountGeneration { get; }
    internal ReadOnlySpan<byte> LocalDeviceId => localDeviceId;
    internal ulong DeviceGeneration { get; }
    internal ulong DatabaseGeneration { get; }
    internal ReadOnlySpan<byte> StoreInstanceId => storeInstanceId;
}

internal enum DirectSessionCatalogState
{
    Pending = 1,
    Active = 2,
}

internal sealed record DirectSessionCatalogRow(
    byte[] CatalogKey,
    byte[] RemoteAccountId,
    ulong RemoteAccountGeneration,
    byte[] RemoteDeviceId,
    ulong RemoteDeviceGeneration,
    byte[] ConversationId,
    byte[] ExactDph2Id,
    string KeySlot,
    string RelativePath,
    DirectSessionCatalogState State)
{
    internal DeepDirectMessagingSessionCatalogEntry ToEntry() => new(
        RemoteAccountId,
        RemoteAccountGeneration,
        RemoteDeviceId,
        RemoteDeviceGeneration,
        ConversationId,
        ExactDph2Id);
}

/// <summary>
/// Encrypted, generation-bound index. It stores no ratchet or pre-key secret;
/// every session database has a separate protected SQLCipher key.
/// </summary>
internal sealed class DeepDirectMessagingSessionCatalog : IDisposable
{
    private const int ApplicationId = 0x44534331; // DSC1
    private const int SchemaGeneration = 1;
    private const int MaximumSessions = 4096;
    private const string SchemaDdl = """
        CREATE TABLE direct_session_catalog_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),database_generation BLOB NOT NULL CHECK(length(database_generation)=8),network_id BLOB NOT NULL CHECK(length(network_id)=16),local_account_id BLOB NOT NULL CHECK(length(local_account_id)=32),account_generation BLOB NOT NULL CHECK(length(account_generation)=8),local_device_id BLOB NOT NULL CHECK(length(local_device_id)=32),device_generation BLOB NOT NULL CHECK(length(device_generation)=8),store_instance_id BLOB NOT NULL CHECK(length(store_instance_id)=32));
        CREATE TABLE direct_sessions(catalog_key BLOB PRIMARY KEY CHECK(length(catalog_key)=32),remote_account_id BLOB NOT NULL CHECK(length(remote_account_id)=32),remote_account_generation BLOB NOT NULL CHECK(length(remote_account_generation)=8),remote_device_id BLOB NOT NULL CHECK(length(remote_device_id)=32),remote_device_generation BLOB NOT NULL CHECK(length(remote_device_generation)=8),conversation_id BLOB NOT NULL CHECK(length(conversation_id)=32),dph2_id BLOB NOT NULL UNIQUE CHECK(length(dph2_id)=32),key_slot TEXT NOT NULL UNIQUE CHECK(length(key_slot) BETWEEN 1 AND 192),relative_path TEXT NOT NULL UNIQUE CHECK(length(relative_path) BETWEEN 1 AND 192),state INTEGER NOT NULL CHECK(state IN(1,2)),UNIQUE(remote_account_id,remote_account_generation,remote_device_id,remote_device_generation,conversation_id));
        """;
    private static readonly byte[] ExpectedSchemaFingerprint = HashSchema(
        ExpectedSchemaObjects());
    private readonly byte[] key;
    private readonly string statePath;
    private readonly string connectionString;
    private readonly DeepDirectMessagingCatalogScope scope;
    private SqliteConnection? connection;
    private int disposed;

    static DeepDirectMessagingSessionCatalog() => SQLitePCL.Batteries_V2.Init();

    internal DeepDirectMessagingSessionCatalog(
        string statePath,
        ReadOnlySpan<byte> encryptionKey,
        DeepDirectMessagingCatalogScope scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        if (encryptionKey.Length != 32 || encryptionKey.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A nonzero 32-byte direct session catalog key is required.",
                nameof(encryptionKey));
        }
        this.statePath = Path.GetFullPath(statePath);
        this.scope = scope ?? throw new ArgumentNullException(nameof(scope));
        key = encryptionKey.ToArray();
        var exists = File.Exists(this.statePath);
        if (exists && new FileInfo(this.statePath).Length == 0)
        {
            CryptographicOperations.ZeroMemory(key);
            throw ResetRequired("The direct session catalog is empty.");
        }
        var directory = Path.GetDirectoryName(this.statePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = this.statePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();
        try
        {
            using var opened = Open();
            if (exists)
            {
                Validate(opened);
            }
            else
            {
                Create(opened);
            }
            ValidateEncryptedHeader();
            connection = Open();
        }
        catch (LocalStateResetRequiredException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        catch (SqliteException exception)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.UnreadableOrWrongKey,
                "The protected direct session catalog is unreadable or corrupt.",
                exception);
        }
        catch (Exception exception) when (exception is FormatException or
            InvalidOperationException or OverflowException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw ResetRequired("The protected direct session catalog is corrupt.", exception);
        }
    }

    internal bool IsKeyZeroedForTesting => key.All(static value => value == 0);

    internal DirectSessionCatalogRow? Read(ReadOnlySpan<byte> catalogKey)
    {
        ThrowIfDisposed();
        using var command = GetConnection().CreateCommand();
        command.CommandText = """
            SELECT remote_account_id,remote_account_generation,remote_device_id,
                   remote_device_generation,conversation_id,dph2_id,key_slot,
                   relative_path,state
            FROM direct_sessions WHERE catalog_key=$key;
            """;
        Add(command, "$key", catalogKey.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }
        var result = ReadRow(reader, catalogKey.ToArray());
        if (reader.Read())
        {
            throw ResetRequired("The direct session catalog contains duplicate keys.");
        }
        return result;
    }

    internal IReadOnlyList<DirectSessionCatalogRow> ReadAll()
    {
        ThrowIfDisposed();
        return ReadAll(GetConnection());
    }

    private IReadOnlyList<DirectSessionCatalogRow> ReadAll(SqliteConnection database)
    {
        using var command = database.CreateCommand();
        command.CommandText = """
            SELECT catalog_key,remote_account_id,remote_account_generation,
                   remote_device_id,remote_device_generation,conversation_id,
                   dph2_id,key_slot,relative_path,state
            FROM direct_sessions ORDER BY catalog_key;
            """;
        using var reader = command.ExecuteReader();
        var result = new List<DirectSessionCatalogRow>();
        while (reader.Read())
        {
            var keyBytes = FixedColumn(reader, 0, 32, "catalog key");
            result.Add(ReadRow(reader, keyBytes, offset: 1));
            if (result.Count > MaximumSessions)
            {
                throw ResetRequired("The direct session catalog exceeds its sealed capacity.");
            }
        }
        return result;
    }

    internal void InsertPending(DirectSessionCatalogRow row)
    {
        ThrowIfDisposed();
        if (row.State != DirectSessionCatalogState.Pending)
        {
            throw new ArgumentException("A new direct session must be pending.", nameof(row));
        }
        var database = GetConnection();
        using var transaction = database.BeginTransaction();
        if (ScalarLong(database, transaction, "SELECT count(*) FROM direct_sessions;") >=
            MaximumSessions)
        {
            throw new InvalidOperationException("The direct session catalog is full.");
        }
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO direct_sessions(
                catalog_key,remote_account_id,remote_account_generation,
                remote_device_id,remote_device_generation,conversation_id,
                dph2_id,key_slot,relative_path,state)
            VALUES($catalog,$account,$accountGeneration,$device,$deviceGeneration,
                $conversation,$dph2,$slot,$path,1);
            """;
        Add(command, "$catalog", row.CatalogKey);
        Add(command, "$account", row.RemoteAccountId);
        Add(command, "$accountGeneration", U64(row.RemoteAccountGeneration));
        Add(command, "$device", row.RemoteDeviceId);
        Add(command, "$deviceGeneration", U64(row.RemoteDeviceGeneration));
        Add(command, "$conversation", row.ConversationId);
        Add(command, "$dph2", row.ExactDph2Id);
        Add(command, "$slot", row.KeySlot);
        Add(command, "$path", row.RelativePath.Replace('\\', '/'));
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    internal void Activate(ReadOnlySpan<byte> catalogKey)
    {
        ThrowIfDisposed();
        using var command = GetConnection().CreateCommand();
        command.CommandText =
            "UPDATE direct_sessions SET state=2 WHERE catalog_key=$key AND state IN(1,2);";
        Add(command, "$key", catalogKey.ToArray());
        if (command.ExecuteNonQuery() != 1)
        {
            throw ResetRequired("The pending direct session catalog entry disappeared.");
        }
    }

    internal void RemovePending(ReadOnlySpan<byte> catalogKey)
    {
        ThrowIfDisposed();
        using var command = GetConnection().CreateCommand();
        command.CommandText =
            "DELETE FROM direct_sessions WHERE catalog_key=$key AND state=1;";
        Add(command, "$key", catalogKey.ToArray());
        command.ExecuteNonQuery();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }
        connection?.Dispose();
        connection = null;
        CryptographicOperations.ZeroMemory(key);
    }

    private void Create(SqliteConnection database)
    {
        Execute(database, null,
            $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        Execute(database, null, SchemaDdl);
        using var command = database.CreateCommand();
        command.CommandText = """
            INSERT INTO direct_session_catalog_meta VALUES(
                1,$database,$network,$account,$accountGeneration,$device,
                $deviceGeneration,$instance);
            """;
        Add(command, "$database", U64(scope.DatabaseGeneration));
        Add(command, "$network", scope.NetworkId.ToArray());
        Add(command, "$account", scope.LocalAccountId.ToArray());
        Add(command, "$accountGeneration", U64(scope.AccountGeneration));
        Add(command, "$device", scope.LocalDeviceId.ToArray());
        Add(command, "$deviceGeneration", U64(scope.DeviceGeneration));
        Add(command, "$instance", scope.StoreInstanceId.ToArray());
        command.ExecuteNonQuery();
        Execute(database, null, "PRAGMA wal_checkpoint(FULL);");
        Validate(database);
    }

    private void Validate(SqliteConnection database)
    {
        if (ScalarLong(database, null, "PRAGMA application_id;") != ApplicationId)
        {
            throw ResetRequired("Unexpected direct session catalog application ID.");
        }
        if (ScalarLong(database, null, "PRAGMA user_version;") != SchemaGeneration)
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.UnsupportedVersion,
                "The direct session catalog generation is unsupported.");
        }
        ValidateCipher(database);
        if (!string.Equals(
                Convert.ToString(Scalar(database, null, "PRAGMA quick_check;"),
                    CultureInfo.InvariantCulture),
                "ok",
                StringComparison.OrdinalIgnoreCase))
        {
            throw ResetRequired("The direct session catalog quick check failed.");
        }

        var actualSchema = HashSchema(ReadSchemaObjects(database));
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(ExpectedSchemaFingerprint, actualSchema))
            {
                throw ResetRequired(
                    "The direct session catalog DDL differs from its sealed schema.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualSchema);
        }

        using (var command = database.CreateCommand())
        {
            command.CommandText = """
                SELECT database_generation,network_id,local_account_id,
                       account_generation,local_device_id,device_generation,
                       store_instance_id
                FROM direct_session_catalog_meta WHERE singleton=1;
                """;
            using var reader = command.ExecuteReader();
            if (!reader.Read() ||
                !FixedColumn(reader, 0, U64(scope.DatabaseGeneration)) ||
                !FixedColumn(reader, 1, scope.NetworkId) ||
                !FixedColumn(reader, 2, scope.LocalAccountId) ||
                !FixedColumn(reader, 3, U64(scope.AccountGeneration)) ||
                !FixedColumn(reader, 4, scope.LocalDeviceId) ||
                !FixedColumn(reader, 5, U64(scope.DeviceGeneration)) ||
                !FixedColumn(reader, 6, scope.StoreInstanceId) || reader.Read())
            {
                throw ResetRequired(
                    "The direct session catalog belongs to another account, device, or store generation.");
            }
        }

        _ = ReadAll(database);
    }

    private DirectSessionCatalogRow ReadRow(
        SqliteDataReader reader,
        byte[] catalogKey,
        int offset = 0)
    {
        var account = FixedColumn(reader, offset, 32, "remote account ID");
        var accountGeneration = ReadU64(
            FixedColumn(reader, offset + 1, 8, "remote account generation"));
        var device = FixedColumn(reader, offset + 2, 32, "remote device ID");
        var deviceGeneration = ReadU64(
            FixedColumn(reader, offset + 3, 8, "remote device generation"));
        var conversation = FixedColumn(reader, offset + 4, 32, "conversation ID");
        var session = FixedColumn(reader, offset + 5, 32, "session ID");
        var keySlot = reader.GetString(offset + 6);
        var relativePath = reader.GetString(offset + 7);
        var stateValue = reader.GetInt32(offset + 8);
        if (accountGeneration == 0 || deviceGeneration == 0 ||
            stateValue is not (1 or 2) ||
            !Regex.IsMatch(
                keySlot,
                "^deep\\.store\\.v1\\.[0-9a-f]{32}\\.direct-session-key\\.[0-9a-f]{64}$",
                RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(
                relativePath,
                "^deep-store-v1/direct-sessions/[0-9a-f]{64}\\.mcr1$",
                RegexOptions.CultureInvariant))
        {
            throw ResetRequired("A direct session catalog row is malformed.");
        }

        var expectedPathTail = Convert.ToHexStringLower(catalogKey);
        if (!keySlot.EndsWith(expectedPathTail, StringComparison.Ordinal) ||
            !relativePath.EndsWith(expectedPathTail + ".mcr1", StringComparison.Ordinal))
        {
            throw ResetRequired(
                "A direct session catalog row is not bound to its canonical key.");
        }
        return new DirectSessionCatalogRow(
            catalogKey,
            account,
            accountGeneration,
            device,
            deviceGeneration,
            conversation,
            session,
            keySlot,
            relativePath.Replace('/', Path.DirectorySeparatorChar),
            (DirectSessionCatalogState)stateValue);
    }

    private SqliteConnection Open()
    {
        var database = new SqliteConnection(connectionString);
        try
        {
            database.Open();
            var result = SQLitePCL.raw.sqlite3_key(database.Handle, key);
            if (result != SQLitePCL.raw.SQLITE_OK)
            {
                throw new SqliteException(
                    "SQLCipher rejected the direct session catalog key.",
                    result);
            }
            Execute(database, null,
                "PRAGMA cipher_memory_security=ON; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;");
            return database;
        }
        catch (SqliteException exception)
        {
            database.Dispose();
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.UnreadableOrWrongKey,
                "The protected direct session catalog cannot be opened.",
                exception);
        }
        catch
        {
            database.Dispose();
            throw;
        }
    }

    private static void ValidateCipher(SqliteConnection database)
    {
        if (Scalar(database, null, "PRAGMA cipher_version;") is not string version ||
            !version.StartsWith("4.", StringComparison.Ordinal))
        {
            throw ResetRequired("SQLCipher v4 is unavailable for the direct session catalog.");
        }
        using var command = database.CreateCommand();
        command.CommandText = "PRAGMA cipher_integrity_check;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (!string.Equals(reader.GetString(0), "ok", StringComparison.OrdinalIgnoreCase))
            {
                throw ResetRequired("The direct session catalog cipher integrity check failed.");
            }
        }
    }

    private void ValidateEncryptedHeader()
    {
        using var stream = new FileStream(
            statePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        Span<byte> header = stackalloc byte[16];
        if (stream.Read(header) != header.Length || header.SequenceEqual("SQLite format 3\0"u8))
        {
            throw ResetRequired(
                "The direct session catalog is truncated or has a plaintext SQLite header.");
        }
    }

    private SqliteConnection GetConnection() => connection ??
        throw new ObjectDisposedException(nameof(DeepDirectMessagingSessionCatalog));

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

    private static byte[] FixedColumn(
        SqliteDataReader reader,
        int ordinal,
        int length,
        string purpose)
    {
        if (reader[ordinal] is not byte[] value || value.Length != length ||
            value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            throw ResetRequired($"The direct session catalog {purpose} is invalid.");
        }
        return value;
    }

    private static bool FixedColumn(
        SqliteDataReader reader,
        int ordinal,
        ReadOnlySpan<byte> expected) =>
        reader[ordinal] is byte[] value && value.Length == expected.Length &&
        CryptographicOperations.FixedTimeEquals(value, expected);

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static ulong ReadU64(ReadOnlySpan<byte> value) =>
        value.Length == 8
            ? BinaryPrimitives.ReadUInt64BigEndian(value)
            : throw ResetRequired("A direct session catalog generation is invalid.");

    private static void Add(SqliteCommand command, string name, object value) =>
        command.Parameters.AddWithValue(name, value);

    private static object? Scalar(
        SqliteConnection database,
        SqliteTransaction? transaction,
        string sql)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static long ScalarLong(
        SqliteConnection database,
        SqliteTransaction? transaction,
        string sql) => Convert.ToInt64(
            Scalar(database, transaction, sql),
            CultureInfo.InvariantCulture);

    private static void Execute(
        SqliteConnection database,
        SqliteTransaction? transaction,
        string sql)
    {
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static string[] ExpectedSchemaObjects() => SchemaDdl
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(static statement =>
        {
            var match = Regex.Match(
                statement,
                "^CREATE\\s+TABLE\\s+([a-z0-9_]+)",
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (!match.Success)
            {
                throw new InvalidOperationException(
                    "The sealed direct session catalog schema is malformed.");
            }
            return $"table|{match.Groups[1].Value}|{match.Groups[1].Value}|{NormalizeSql(statement)}";
        })
        .OrderBy(static value => value, StringComparer.Ordinal)
        .ToArray();

    private static string[] ReadSchemaObjects(SqliteConnection database)
    {
        using var command = database.CreateCommand();
        command.CommandText = """
            SELECT type,name,tbl_name,sql FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name;
            """;
        using var reader = command.ExecuteReader();
        var result = new List<string>();
        while (reader.Read())
        {
            if (reader.IsDBNull(3))
            {
                throw ResetRequired("The direct session catalog has an unsealed schema object.");
            }
            result.Add(
                $"{reader.GetString(0)}|{reader.GetString(1)}|{reader.GetString(2)}|" +
                NormalizeSql(reader.GetString(3)));
        }
        return result.ToArray();
    }

    private static string NormalizeSql(string sql) => Regex.Replace(
        sql.Trim().TrimEnd(';'),
        "\\s+",
        " ",
        RegexOptions.CultureInvariant).ToLowerInvariant();

    private static byte[] HashSchema(IEnumerable<string> objects)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        foreach (var item in objects)
        {
            var bytes = Encoding.UTF8.GetBytes(item);
            try
            {
                BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
                hash.AppendData(length);
                hash.AppendData(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        return hash.GetHashAndReset();
    }

    private static LocalStateResetRequiredException ResetRequired(
        string message,
        Exception? inner = null) => new(
            LocalStateResetRequiredReason.InvalidCurrentSchema,
            message,
            inner);
}
