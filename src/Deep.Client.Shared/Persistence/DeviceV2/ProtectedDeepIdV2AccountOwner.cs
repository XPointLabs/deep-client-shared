using System.Buffers.Binary;
using Deep.Client.Shared.Domain;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// Isolated protected-state owner for one offline DID2 account. This is not
/// the SQL/MAUI account owner. All create/read/reset operations share a
/// process-independent lease; an interrupted unpublished creation is never
/// silently resumed or promoted to an account.
/// </summary>
internal sealed class ProtectedDeepIdV2AccountOwner
{
    private const string CreationIntentSlot = "deep.store.v2.creation-intent";
    private readonly IDeepSecureStorage storage;
    private readonly DeepIdV2AccountFileLease lease;
    private readonly byte[] networkId;
    private readonly ushort deploymentProfileId;

    internal ProtectedDeepIdV2AccountOwner(IDeepSecureStorage storage,
        DeepIdV2AccountFileLease lease, ReadOnlySpan<byte> networkId,
        ushort deploymentProfileId)
    {
        this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
        this.lease = lease ?? throw new ArgumentNullException(nameof(lease));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0 ||
            deploymentProfileId == 0)
            throw new ArgumentException("A nonzero DID2 network/profile is required.");
        this.networkId = networkId.ToArray();
        this.deploymentProfileId = deploymentProfileId;
    }

    internal async ValueTask<VerifiedDeepIdV2CurrentAccount?> ReadCurrentAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier mlDsa65,
        CancellationToken cancellationToken)
    {
        using var held = await lease.AcquireAsync(cancellationToken)
            .ConfigureAwait(false);
        var current = await Index().ReadVerifiedAsync(trustedUnixSeconds,
            mlDsa65, cancellationToken).ConfigureAwait(false);
        if (current is not null) return current;
        if (await HasCreationIntentAsync(cancellationToken).ConfigureAwait(false))
            throw new DeepIdV2CreationInterruptedException();
        return null;
    }

    internal async ValueTask<VerifiedDeepIdV2CurrentAccount> CreateFreshAsync(
        string displayName, ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier mlDsa65, CancellationToken cancellationToken)
    {
        var normalized = DeepDisplayName.Normalize(displayName,
            nameof(displayName));
        using var held = await lease.AcquireAsync(cancellationToken)
            .ConfigureAwait(false);
        using var current = await Index().ReadVerifiedAsync(trustedUnixSeconds,
            mlDsa65, cancellationToken).ConfigureAwait(false);
        if (current is not null)
            throw new InvalidOperationException("A DID2 current account already exists.");
        if (await HasCreationIntentAsync(cancellationToken).ConfigureAwait(false))
            throw new DeepIdV2CreationInterruptedException();

        var marker = new byte[24];
        "DCI2"u8.CopyTo(marker);
        BinaryPrimitives.WriteUInt16BigEndian(marker.AsSpan(4), 2);
        BinaryPrimitives.WriteUInt16BigEndian(marker.AsSpan(6),
            deploymentProfileId);
        networkId.CopyTo(marker, 8);
        await storage.WriteBatchAsync(
            [new DeepSecureStorageWrite(CreationIntentSlot, marker)],
            cancellationToken).ConfigureAwait(false);

        using var created = await new DeepIdV2OfflineGenesisIssuer(storage,
            networkId, deploymentProfileId).CreateAsync(trustedUnixSeconds,
            mlDsa65, cancellationToken).ConfigureAwait(false);
        return await Index().PublishVerifiedAsync(normalized,
            created.AccountId, trustedUnixSeconds, mlDsa65,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Called only after an explicit account reset decision. This erases all
    /// local V2 account state, including a valid current account if present.
    /// It never touches the V1 namespace.
    /// </summary>
    internal async ValueTask ResetExplicitlyAsync(
        CancellationToken cancellationToken)
    {
        using var held = await lease.AcquireAsync(cancellationToken)
            .ConfigureAwait(false);
        await storage.PurgeStoreV2NamespaceAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private ProtectedDeepIdV2CurrentAccountIndex Index() =>
        new(storage, networkId, deploymentProfileId);

    private async ValueTask<bool> HasCreationIntentAsync(
        CancellationToken cancellationToken)
    {
        using var owned = await storage.ReadOwnedAsync(CreationIntentSlot,
            cancellationToken).ConfigureAwait(false);
        if (owned is null) return false;
        if (owned.Length != 24 || !owned.Use(value =>
                value[..4].SequenceEqual("DCI2"u8) &&
                BinaryPrimitives.ReadUInt16BigEndian(value[4..]) == 2 &&
                BinaryPrimitives.ReadUInt16BigEndian(value[6..]) ==
                    deploymentProfileId &&
                value[8..].SequenceEqual(networkId)))
            throw new InvalidDataException("The V2 creation-intent marker is malformed.");
        return true;
    }
}

internal sealed class DeepIdV2CreationInterruptedException() :
    InvalidOperationException(
        "An unpublished DID2 account creation was interrupted; explicit local V2 reset is required.");
