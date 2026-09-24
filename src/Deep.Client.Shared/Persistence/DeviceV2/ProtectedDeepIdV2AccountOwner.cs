using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// Isolated protected-state owner for one offline DID2 account. This is not
/// the SQL/MAUI account owner. All create/read/reset operations share a
/// process-independent lease. Only a fully verified durable genesis winner
/// may be resumed and promoted after an interrupted index publication.
/// </summary>
internal sealed class ProtectedDeepIdV2AccountOwner
{
    private const string CreationIntentSlot = "deep.store.v2.creation-intent";
    private const string CreationCandidateSlot = "deep.store.v2.creation-candidate";
    private const string CurrentAccountSlot = "deep.store.v2.current-account";
    private const int IntentHeaderLength = 26;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly IDeepSecureStorage storage;
    private readonly DeepIdV2AccountFileLease lease;
    private readonly string sqlStatePath;
    private readonly byte[] networkId;
    private readonly ushort deploymentProfileId;

    internal ProtectedDeepIdV2AccountOwner(IDeepSecureStorage storage,
        DeepIdV2AccountFileLease lease, string sqlStatePath,
        ReadOnlySpan<byte> networkId,
        ushort deploymentProfileId)
    {
        this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
        this.lease = lease ?? throw new ArgumentNullException(nameof(lease));
        ArgumentException.ThrowIfNullOrWhiteSpace(sqlStatePath);
        this.sqlStatePath = Path.GetFullPath(sqlStatePath);
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
        return await ReadCurrentUnderLeaseAsync(trustedUnixSeconds,
            mlDsa65, cancellationToken).ConfigureAwait(false);
    }

    internal async ValueTask<IDeepIdV2DirectoryProtectedLkgStore>
        OpenDirectoryLkgStoreAsync(ulong trustedUnixSeconds,
            IDeepMlDsa65Verifier mlDsa65,
            VerifiedXPointNetworkAuthority authority,
            ReadOnlyMemory<byte> exactGenesisAdh1,
            ReadOnlyMemory<byte> protectedGenesisCoreHash,
            CancellationToken cancellationToken)
    {
        using var held = await lease.AcquireAsync(cancellationToken)
            .ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(
            trustedUnixSeconds, mlDsa65, cancellationToken)
            .ConfigureAwait(false);
        return await SqliteDeepIdV2AccountGeneration.OpenDirectoryLkgStoreAsync(
            storage, lease, sqlStatePath, current, authority,
            exactGenesisAdh1, protectedGenesisCoreHash, cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask<VerifiedDeepIdV2CurrentAccount> CreateFreshAsync(
        string displayName, ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier mlDsa65, CancellationToken cancellationToken)
    {
        var normalized = DeepDisplayName.Normalize(displayName,
            nameof(displayName));
        using var held = await lease.AcquireAsync(cancellationToken)
            .ConfigureAwait(false);
        using var current = await ReadCurrentUnderLeaseAsync(trustedUnixSeconds,
            mlDsa65, cancellationToken).ConfigureAwait(false);
        if (current is not null)
            throw new InvalidOperationException("A DID2 current account already exists.");

        using var phrase = DeepRecoveryV1.Generate();
        using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase, networkId, 1);
        var candidateAccountId = recovery.AccountIdentity.AccountId.Bytes.ToArray();
        await WriteCreationCandidateAsync(normalized, candidateAccountId,
            cancellationToken).ConfigureAwait(false);

        using var created = await new DeepIdV2OfflineGenesisIssuer(storage,
            networkId, deploymentProfileId).CreateAsync(phrase,
            trustedUnixSeconds, mlDsa65, cancellationToken)
            .ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(
                candidateAccountId, created.AccountId.Span))
            throw new CryptographicException(
                "The DID2 issuer returned a different candidate account ID.");
        await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlStatePath,
            storage, networkId, created.AccountId, normalized, created.Verified,
            allowCreate: true, cancellationToken).ConfigureAwait(false);
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
        using var current = await storage.ReadOwnedAsync(CurrentAccountSlot,
            cancellationToken).ConfigureAwait(false);
        if (current is null)
        {
            var candidate = await ReadCandidateAccountIdAsync(cancellationToken)
                .ConfigureAwait(false);
            if (candidate is not null && await new
                ProtectedDeepIdV2GenesisContactStore(storage, networkId,
                    candidate).ReadUntrustedAsync(cancellationToken)
                    .ConfigureAwait(false) is not null)
                throw new InvalidOperationException(
                    "An unpublished durable DID2/DAB2 winner must be recovered before reset.");
        }
        SqliteDeepIdV2AccountGeneration.DeleteArtifactsAfterExplicitReset(
            sqlStatePath);
        await storage.PurgeStoreV2NamespaceAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask<VerifiedDeepRecoveryPhrase?>
        ReadRetainedRecoveryPhraseAsync(ulong trustedUnixSeconds,
            IDeepMlDsa65Verifier mlDsa65, CancellationToken cancellationToken)
    {
        using var held = await lease.AcquireAsync(cancellationToken)
            .ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(
            trustedUnixSeconds, mlDsa65, cancellationToken)
            .ConfigureAwait(false);
        return await PhraseStore(current.AccountId.Span)
            .ReadVerifiedAsync(cancellationToken).ConfigureAwait(false);
    }

    internal async ValueTask DeleteRetainedRecoveryPhraseAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier mlDsa65,
        CancellationToken cancellationToken)
    {
        using var held = await lease.AcquireAsync(cancellationToken)
            .ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(
            trustedUnixSeconds, mlDsa65, cancellationToken)
            .ConfigureAwait(false);
        await PhraseStore(current.AccountId.Span)
            .DeleteAfterVerifiedBootstrapAsync(trustedUnixSeconds,
                deploymentProfileId, mlDsa65, cancellationToken)
            .ConfigureAwait(false);
    }

    private ProtectedDeepIdV2CurrentAccountIndex Index() =>
        new(storage, networkId, deploymentProfileId);

    private ProtectedDeepIdV2RecoveryPhraseStore PhraseStore(
        ReadOnlySpan<byte> accountId) => new(storage, networkId, accountId);

    private async ValueTask<VerifiedDeepIdV2CurrentAccount?>
        ReadCurrentUnderLeaseAsync(ulong trustedUnixSeconds,
            IDeepMlDsa65Verifier mlDsa65, CancellationToken cancellationToken)
    {
        var current = await Index().ReadVerifiedAsync(trustedUnixSeconds,
            mlDsa65, cancellationToken).ConfigureAwait(false);
        if (current is not null)
        {
            try
            {
                await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlStatePath,
                    storage, networkId, current.AccountId, current.DisplayName,
                    current.Verified, allowCreate: false, cancellationToken)
                    .ConfigureAwait(false);
                return current;
            }
            catch
            {
                current.Dispose();
                throw;
            }
        }
        var name = await ReadCreationIntentAsync(cancellationToken)
            .ConfigureAwait(false);
        var candidate = await ReadCandidateAccountIdAsync(cancellationToken)
            .ConfigureAwait(false);
        if (name is null)
        {
            if (candidate is not null)
                throw new InvalidDataException(
                    "The DID2 creation candidate has no intent.");
            return null;
        }
        if (candidate is null)
            throw new DeepIdV2CreationInterruptedException();
        var publicWinner = await new ProtectedDeepIdV2GenesisContactStore(
            storage, networkId, candidate).ReadUntrustedAsync(
            cancellationToken).ConfigureAwait(false);
        if (publicWinner is null)
            throw new DeepIdV2CreationInterruptedException();
        using var retained = await PhraseStore(candidate).ReadVerifiedAsync(
            cancellationToken).ConfigureAwait(false)
            ?? throw new CryptographicException(
                "An unpublished durable DID2 winner has no retained recovery phrase.");
        using var completed = await new ProtectedDeepIdV2GenesisBootstrap(
            storage, networkId, candidate).ReadVerifiedAsync(
            trustedUnixSeconds, deploymentProfileId, mlDsa65,
            cancellationToken).ConfigureAwait(false)
            ?? throw new CryptographicException(
                "An unpublished DID2 winner has incomplete bootstrap state.");
        var restoredAddress = DeepIdV2Root.DerivePermanentIdV2(retained);
        if (!restoredAddress.MatchesExactCredential(
                completed.PublicEvidence.Binding.DeepId))
            throw new CryptographicException(
                "The retained phrase does not restore the exact DID2 resolver capability.");
        await new ProtectedDeepIdV2ResolverCapabilityStore(storage,
            networkId, candidate).WriteVerifiedAsync(
            completed.PublicEvidence.Binding.DeepId,
            restoredAddress.ResolverReadCapability,
            cancellationToken).ConfigureAwait(false);
        await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlStatePath,
            storage, networkId, candidate, name, completed,
            allowCreate: true, cancellationToken).ConfigureAwait(false);
        return await Index().PublishVerifiedAsync(name, candidate,
            trustedUnixSeconds, mlDsa65, cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask<VerifiedDeepIdV2CurrentAccount>
        RequireCurrentUnderLeaseAsync(ulong trustedUnixSeconds,
            IDeepMlDsa65Verifier mlDsa65, CancellationToken cancellationToken) =>
        await ReadCurrentUnderLeaseAsync(trustedUnixSeconds, mlDsa65,
            cancellationToken).ConfigureAwait(false)
        ?? throw new InvalidOperationException("No current DID2 account exists.");

    private async ValueTask WriteCreationCandidateAsync(string normalizedName,
        ReadOnlyMemory<byte> candidateAccountId, CancellationToken cancellationToken)
    {
        var name = StrictUtf8.GetBytes(normalizedName);
        var intent = new byte[IntentHeaderLength + name.Length];
        var candidate = new byte[56];
        try
        {
            "DCI2"u8.CopyTo(intent);
            BinaryPrimitives.WriteUInt16BigEndian(intent.AsSpan(4), 2);
            BinaryPrimitives.WriteUInt16BigEndian(intent.AsSpan(6),
                deploymentProfileId);
            networkId.CopyTo(intent, 8);
            BinaryPrimitives.WriteUInt16BigEndian(intent.AsSpan(24),
                checked((ushort)name.Length));
            name.CopyTo(intent, IntentHeaderLength);
            "DCC2"u8.CopyTo(candidate);
            BinaryPrimitives.WriteUInt16BigEndian(candidate.AsSpan(4), 2);
            networkId.CopyTo(candidate, 8);
            candidateAccountId.Span.CopyTo(candidate.AsSpan(24));
            await storage.WriteBatchAsync(
                [new DeepSecureStorageWrite(CreationIntentSlot, intent),
                 new DeepSecureStorageWrite(CreationCandidateSlot, candidate)],
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(intent);
            CryptographicOperations.ZeroMemory(candidate);
        }
    }

    private async ValueTask<string?> ReadCreationIntentAsync(
        CancellationToken cancellationToken)
    {
        using var owned = await storage.ReadOwnedAsync(CreationIntentSlot,
            cancellationToken).ConfigureAwait(false);
        if (owned is null) return null;
        if (owned.Length is < IntentHeaderLength + 1 or > IntentHeaderLength +
            DeepDisplayName.MaxUtf8Bytes)
            throw new InvalidDataException("The V2 creation-intent marker has a hostile size.");
        return owned.Use(value =>
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(value[24..]);
            if (!value[..4].SequenceEqual("DCI2"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(value[4..]) != 2 ||
                BinaryPrimitives.ReadUInt16BigEndian(value[6..]) !=
                    deploymentProfileId ||
                !value.Slice(8, 16).SequenceEqual(networkId) ||
                length != value.Length - IntentHeaderLength)
                throw new InvalidDataException(
                    "The V2 creation-intent marker is malformed.");
            var name = StrictUtf8.GetString(value[IntentHeaderLength..]);
            if (DeepDisplayName.Normalize(name, nameof(name)) != name)
                throw new InvalidDataException(
                    "The V2 creation-intent name is not canonical.");
            return name;
        });
    }

    private async ValueTask<byte[]?> ReadCandidateAccountIdAsync(
        CancellationToken cancellationToken)
    {
        using var owned = await storage.ReadOwnedAsync(CreationCandidateSlot,
            cancellationToken).ConfigureAwait(false);
        if (owned is null) return null;
        if (owned.Length != 56)
            throw new InvalidDataException("The V2 creation candidate has a hostile size.");
        return owned.Use(value =>
        {
            if (!value[..4].SequenceEqual("DCC2"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(value[4..]) != 2 ||
                value.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
                !value.Slice(8, 16).SequenceEqual(networkId) ||
                value[24..].IndexOfAnyExcept((byte)0) < 0)
                throw new InvalidDataException(
                    "The V2 creation candidate is malformed.");
            return value[24..].ToArray();
        });
    }
}

internal sealed class DeepIdV2CreationInterruptedException() :
    InvalidOperationException(
        "An unpublished DID2 account creation was interrupted; explicit local V2 reset is required.");
