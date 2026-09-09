using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.MessagingCryptoV1;

/// <summary>
/// Verifier-minted contact/device scope for one initiator-side DPH2 session.
/// The production factory accepts no raw authority material or trust decision.
/// </summary>
internal sealed class InitiatorInitialSessionVerifiedScope
{
    private readonly byte[] networkId;
    private readonly byte[] localAccountId;
    private readonly byte[] relationshipId;
    private readonly byte[] conversationId;
    private readonly byte[] contactEvidenceHash;
    private readonly byte[] peerPackageHash;
    private readonly byte[] remoteAccountId;
    private readonly byte[] remoteDeviceId;

    private InitiatorInitialSessionVerifiedScope(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> localAccountId,
        int contactStoreGeneration,
        ReadOnlySpan<byte> relationshipId,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> contactEvidenceHash,
        ReadOnlySpan<byte> peerPackageHash,
        ReadOnlySpan<byte> remoteAccountId,
        ulong remoteAccountGeneration,
        ulong remoteDirectoryGeneration,
        ReadOnlySpan<byte> remoteDeviceId,
        ulong remoteDeviceGeneration)
    {
        Require(networkId, 16, nameof(networkId));
        Require(localAccountId, 32, nameof(localAccountId));
        Require(relationshipId, 32, nameof(relationshipId));
        Require(conversationId, 32, nameof(conversationId));
        Require(contactEvidenceHash, 32, nameof(contactEvidenceHash));
        Require(peerPackageHash, 32, nameof(peerPackageHash));
        Require(remoteAccountId, 32, nameof(remoteAccountId));
        Require(remoteDeviceId, 32, nameof(remoteDeviceId));
        if (contactStoreGeneration <= 0 || remoteAccountGeneration == 0 ||
            remoteDirectoryGeneration == 0 || remoteDeviceGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(contactStoreGeneration),
                "Contact, account, directory, and device generations must be nonzero.");

        this.networkId = networkId.ToArray();
        this.localAccountId = localAccountId.ToArray();
        ContactStoreGeneration = contactStoreGeneration;
        this.relationshipId = relationshipId.ToArray();
        this.conversationId = conversationId.ToArray();
        this.contactEvidenceHash = contactEvidenceHash.ToArray();
        this.peerPackageHash = peerPackageHash.ToArray();
        this.remoteAccountId = remoteAccountId.ToArray();
        RemoteAccountGeneration = remoteAccountGeneration;
        RemoteDirectoryGeneration = remoteDirectoryGeneration;
        this.remoteDeviceId = remoteDeviceId.ToArray();
        RemoteDeviceGeneration = remoteDeviceGeneration;
    }

    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> LocalAccountId => localAccountId;
    internal int ContactStoreGeneration { get; }
    internal ReadOnlySpan<byte> RelationshipId => relationshipId;
    internal ReadOnlySpan<byte> ConversationId => conversationId;
    internal ReadOnlySpan<byte> ContactEvidenceHash => contactEvidenceHash;
    internal ReadOnlySpan<byte> PeerPackageHash => peerPackageHash;
    internal ReadOnlySpan<byte> RemoteAccountId => remoteAccountId;
    internal ulong RemoteAccountGeneration { get; }
    internal ulong RemoteDirectoryGeneration { get; }
    internal ReadOnlySpan<byte> RemoteDeviceId => remoteDeviceId;
    internal ulong RemoteDeviceGeneration { get; }

    internal static InitiatorInitialSessionVerifiedScope FromReverifiedPeer(
        ContactResolverReverifiedPeerAuthority peer,
        ReadOnlySpan<byte> remoteDeviceId)
    {
        ArgumentNullException.ThrowIfNull(peer);
        Require(remoteDeviceId, 32, nameof(remoteDeviceId));
        var selectedDeviceId = remoteDeviceId.ToArray();
        var directory = peer.Bundle.Directory;
        var record = directory.Record;
        var selected = directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, selectedDeviceId));
        var entry = record.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.DeviceId.Span, selectedDeviceId));
        if (selected is null || entry is null ||
            entry.Dpd1Reference.TypeCode != (ushort)ArtifactType.Dpd1 ||
            entry.Dpd1Reference.CanonicalLength != 776 ||
            !Fixed(entry.Dpd1Reference.CanonicalHash.Span,
                selected.Certificate.CanonicalHash.Span) ||
            !Fixed(selected.Certificate.NetworkId.Span, record.NetworkId.Span) ||
            !Fixed(selected.Certificate.AccountHash.Span, record.DeepAccountId.Span) ||
            selected.Certificate.AccountGeneration != record.AccountGeneration)
            throw new CryptographicException(
                "The requested DPH2 recipient is not an active device in the reverified contact closure.");

        return new InitiatorInitialSessionVerifiedScope(
            record.NetworkId.Span,
            peer.Evidence.Scope.AccountId.Bytes.Span,
            peer.Evidence.Scope.StoreGeneration,
            peer.Evidence.RelationshipId.Span,
            peer.Evidence.ConversationId.Span,
            peer.Evidence.EvidenceHash.Span,
            peer.PackageHash.Span,
            record.DeepAccountId.Span,
            record.AccountGeneration,
            record.DirectoryGeneration,
            selectedDeviceId,
            selected.Certificate.DeviceGeneration);
    }

#if DEEP_TEST_INTERNALS
    internal static InitiatorInitialSessionVerifiedScope CreateForTests(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> localAccountId,
        int contactStoreGeneration,
        ReadOnlySpan<byte> relationshipId,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> contactEvidenceHash,
        ReadOnlySpan<byte> peerPackageHash,
        ReadOnlySpan<byte> remoteAccountId,
        ulong remoteAccountGeneration,
        ulong remoteDirectoryGeneration,
        ReadOnlySpan<byte> remoteDeviceId,
        ulong remoteDeviceGeneration) => new(
            networkId, localAccountId, contactStoreGeneration, relationshipId,
            conversationId, contactEvidenceHash, peerPackageHash, remoteAccountId,
            remoteAccountGeneration, remoteDirectoryGeneration, remoteDeviceId,
            remoteDeviceGeneration);
#endif

    private static void Require(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} nonzero bytes.", name);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Narrow friend boundary used by the platform-owned store catalog. The exact
/// Protocol capability is consumed once and no key/provider surface crosses it.
/// </summary>
internal sealed class ManagedInitiatorInitialSessionSqliteAdapter
{
    private readonly SqliteMessagingCryptoV1Store store;
    private readonly InitiatorInitialSessionVerifiedScope verifiedScope;

    internal ManagedInitiatorInitialSessionSqliteAdapter(
        SqliteMessagingCryptoV1Store store,
        InitiatorInitialSessionVerifiedScope verifiedScope)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.verifiedScope = verifiedScope ?? throw new ArgumentNullException(nameof(verifiedScope));
        store.RequireInitiatorScope(verifiedScope);
    }

    internal async ValueTask<MessagingCryptoV1CommitResult> CommitAsync(
        InitiatorInitialSessionCommitCapability capability,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(capability);
        cancellationToken.ThrowIfCancellationRequested();
        using var snapshot = InitiatorInitialSessionProtocolSnapshot.Capture(
            capability, verifiedScope, store);
        // Once the one-shot Protocol capability has transferred DPH2/TRS1, an
        // advisory caller cancellation cannot safely abandon the claimed
        // remote pre-key. Finish the bounded local SQLCipher transaction.
        return await store.CommitInitiatorInitialSessionAsync(snapshot, CancellationToken.None)
            .ConfigureAwait(false);
    }

#if DEEP_TEST_INTERNALS
    internal ValueTask<MessagingCryptoV1CommitResult> CommitForTestsAsync(
        InitiatorInitialSessionProtocolSnapshot snapshot,
        CancellationToken cancellationToken = default) =>
        store.CommitInitiatorInitialSessionAsync(snapshot, cancellationToken);
#endif

    internal ValueTask<InitiatorInitialSessionDispatchEnvelope?> ReadPendingDispatchAsync(
        CancellationToken cancellationToken = default) =>
        store.ReadInitiatorInitialSessionDispatchAsync(verifiedScope, cancellationToken);
}

/// <summary>
/// Owned, short-lived copy of an unforgeable Protocol DPH2/TRS1 capability.
/// </summary>
internal sealed class InitiatorInitialSessionProtocolSnapshot : IDisposable
{
    private readonly List<byte[]> owned = [];
    private int disposed;

    private InitiatorInitialSessionProtocolSnapshot(
        ReadOnlySpan<byte> exactDph2,
        ReadOnlySpan<byte> exactTrs1,
        ReadOnlySpan<byte> expectedSessionId,
        ReadOnlySpan<byte> expectedOperationId,
        ReadOnlySpan<byte> expectedReplayHash,
        ReadOnlySpan<byte> expectedClaimBinding,
        InitiatorInitialSessionVerifiedScope verifiedScope,
        SqliteMessagingCryptoV1Store store)
    {
        try
        {
            ExactDph2 = Copy(exactDph2);
            ExactTrs1 = Copy(exactTrs1);
            SessionId = Copy(expectedSessionId);
            ClaimOperationId = Copy(expectedOperationId);
            FullDph2ReplayHash = Copy(expectedReplayHash);
            ClaimBinding = Copy(expectedClaimBinding);
            NetworkId = Copy(verifiedScope.NetworkId);
            LocalAccountId = Copy(verifiedScope.LocalAccountId);
            ContactStoreGeneration = verifiedScope.ContactStoreGeneration;
            RelationshipId = Copy(verifiedScope.RelationshipId);
            ConversationId = Copy(verifiedScope.ConversationId);
            ContactEvidenceHash = Copy(verifiedScope.ContactEvidenceHash);
            PeerPackageHash = Copy(verifiedScope.PeerPackageHash);
            RemoteAccountId = Copy(verifiedScope.RemoteAccountId);
            RemoteAccountGeneration = verifiedScope.RemoteAccountGeneration;
            RemoteDirectoryGeneration = verifiedScope.RemoteDirectoryGeneration;
            RemoteDeviceId = Copy(verifiedScope.RemoteDeviceId);
            RemoteDeviceGeneration = verifiedScope.RemoteDeviceGeneration;
            Validate(store);
        }
        catch
        {
            foreach (var value in owned) CryptographicOperations.ZeroMemory(value);
            throw;
        }
    }

    internal byte[] ExactDph2 { get; }
    internal byte[] ExactTrs1 { get; }
    internal byte[] SessionId { get; }
    internal byte[] ClaimOperationId { get; }
    internal byte[] FullDph2ReplayHash { get; }
    internal byte[] ClaimBinding { get; }
    internal byte[] NetworkId { get; }
    internal byte[] LocalAccountId { get; }
    internal int ContactStoreGeneration { get; }
    internal byte[] RelationshipId { get; }
    internal byte[] ConversationId { get; }
    internal byte[] ContactEvidenceHash { get; }
    internal byte[] PeerPackageHash { get; }
    internal byte[] RemoteAccountId { get; }
    internal ulong RemoteAccountGeneration { get; }
    internal ulong RemoteDirectoryGeneration { get; }
    internal byte[] RemoteDeviceId { get; }
    internal ulong RemoteDeviceGeneration { get; }

    internal static InitiatorInitialSessionProtocolSnapshot Capture(
        InitiatorInitialSessionCommitCapability capability,
        InitiatorInitialSessionVerifiedScope verifiedScope,
        SqliteMessagingCryptoV1Store store)
    {
        var sessionId = capability.SessionId.ToArray();
        var operationId = capability.ClaimOperationId.ToArray();
        var replayHash = capability.FullDph2ReplayHash.ToArray();
        var claimBinding = capability.ClaimBinding.ToArray();
        try
        {
            using var payload = capability.ConsumeForAtomicStore();
            return new InitiatorInitialSessionProtocolSnapshot(
                payload.ExactDph2.Span,
                payload.ExactTrs1.Span,
                sessionId,
                operationId,
                replayHash,
                claimBinding,
                verifiedScope,
                store);
        }
        finally
        {
            Zero(sessionId, operationId, replayHash, claimBinding);
        }
    }

#if DEEP_TEST_INTERNALS
    internal static InitiatorInitialSessionProtocolSnapshot CreateForTests(
        ReadOnlySpan<byte> exactDph2,
        ReadOnlySpan<byte> exactTrs1,
        InitiatorInitialSessionVerifiedScope verifiedScope,
        SqliteMessagingCryptoV1Store store)
    {
        var record = Dph2Codec.Decode(exactDph2);
        var replay = MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(record);
        var claim = MessagingWireCryptographicInputs.ComputeDph2ClaimBinding(record);
        try
        {
            return new InitiatorInitialSessionProtocolSnapshot(
                exactDph2, exactTrs1, record.SessionId.Span,
                record.ClaimOperationId.Span, replay, claim, verifiedScope, store);
        }
        finally { Zero(replay, claim); }
    }
#endif

    internal bool IsClearedForTesting => owned.All(static value =>
        value.AsSpan().IndexOfAnyExcept((byte)0) < 0);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var value in owned) CryptographicOperations.ZeroMemory(value);
    }

    private void Validate(SqliteMessagingCryptoV1Store store)
    {
        var record = Dph2Codec.Decode(ExactDph2);
        store.RequireInitiatorDph2Values(
            record.InitiatorAccountId.Span,
            record.InitiatorDeviceId.Span,
            record.InitiatorDeviceGeneration,
            ConversationId,
            SessionId);
        MessagingCryptoV1Trs1.RequireResponderContactBinding(
            ExactTrs1, RemoteDeviceId, RemoteDeviceGeneration);
        var canonical = Dph2Codec.Encode(record);
        var replay = MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(record);
        var claim = MessagingWireCryptographicInputs.ComputeDph2ClaimBinding(record);
        try
        {
            if (!Fixed(canonical, ExactDph2) ||
                !Fixed(record.SessionId.Span, SessionId) ||
                !Fixed(record.ClaimOperationId.Span, ClaimOperationId) ||
                !Fixed(replay, FullDph2ReplayHash) ||
                !Fixed(claim, ClaimBinding) ||
                !Fixed(record.NetworkId.Span, NetworkId) ||
                !Fixed(record.InitiatorAccountId.Span, LocalAccountId) ||
                !Fixed(record.ResponderAccountId.Span, RemoteAccountId) ||
                !Fixed(record.ResponderDeviceId.Span, RemoteDeviceId) ||
                record.ResponderDeviceGeneration != RemoteDeviceGeneration)
                throw new CryptographicException(
                    "The Protocol DPH2 capability is outside the verified contact/session scope.");
        }
        finally { Zero(canonical, replay, claim); }
    }

    private byte[] Copy(ReadOnlySpan<byte> source)
    {
        var result = source.ToArray();
        owned.Add(result);
        return result;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Zero(params byte[][] values)
    {
        foreach (var value in values) CryptographicOperations.ZeroMemory(value);
    }
}

/// <summary>
/// Durable exact DPH2 waiting for the separate privacy-routed network dispatch.
/// </summary>
internal sealed class InitiatorInitialSessionDispatchEnvelope : IDisposable
{
    private byte[]? exactDph2;
    private byte[]? operationId;
    private byte[]? sessionId;
    private byte[]? replayHash;

    internal InitiatorInitialSessionDispatchEnvelope(
        ReadOnlySpan<byte> exactDph2,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> replayHash)
    {
        this.exactDph2 = exactDph2.ToArray();
        this.operationId = operationId.ToArray();
        this.sessionId = sessionId.ToArray();
        this.replayHash = replayHash.ToArray();
    }

    internal ReadOnlyMemory<byte> ExactDph2 => Value(exactDph2).ToArray();
    internal ReadOnlyMemory<byte> OperationId => Value(operationId).ToArray();
    internal ReadOnlyMemory<byte> SessionId => Value(sessionId).ToArray();
    internal ReadOnlyMemory<byte> ReplayHash => Value(replayHash).ToArray();

    public void Dispose()
    {
        Zero(Interlocked.Exchange(ref exactDph2, null));
        Zero(Interlocked.Exchange(ref operationId, null));
        Zero(Interlocked.Exchange(ref sessionId, null));
        Zero(Interlocked.Exchange(ref replayHash, null));
    }

    private static byte[] Value(byte[]? value) =>
        value ?? throw new ObjectDisposedException(nameof(InitiatorInitialSessionDispatchEnvelope));

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}
