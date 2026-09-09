using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence;

public static class DeepAccountStoreContract
{
    public const int CurrentStoreGeneration = 1;
    public const ulong CurrentAccountGeneration = 1;
    public const int NetworkIdSize = 16;
    public const int KeyMaterialSize = 32;
    public const string DatabaseGenerationSlot = "deep.store.v1.database-generation";
    public const string DatabaseAccountManifestSlot = "deep.store.v1.database-account-manifest";
    public const string PendingAccountSlot = "deep.store.v1.pending-account";
}

public enum DeepAccountCommitFaultPoint
{
    BeforeTransaction = 1,
    AfterAccount = 2,
    AfterDevice = 3,
    BeforeCommit = 4,
    AfterCommit = 5
}

public interface IDeepAccountStore : IAsyncDisposable
{
    ValueTask<DeepAccountMutationLease> AcquireMutationLeaseAsync(
        CancellationToken cancellationToken = default);

    Task<DeepAccountIdentityCapability?> ReadAccountIdentityAsync(
        CancellationToken cancellationToken = default);

    Task<DeepLocalIdentitySnapshot?> ReadAsync(
        LocalDeviceIdentityIntent? localDeviceIdentity,
        CancellationToken cancellationToken = default);

    Task CreateAsync(
        DeepAccountReconciledMutationCapability mutationCapability,
        DeepLocalIdentitySnapshot identity,
        DeepAccountCreationOperation operation,
        ReadOnlyMemory<byte> immutableIdentityCommitment,
        CancellationToken cancellationToken = default);

    Task<DeepAccountCreationOperation?> ReadCreationOperationAsync(
        CancellationToken cancellationToken = default);

    Task UpdateProfileAsync(
        DeepAccountReconciledMutationCapability mutationCapability,
        DeepPermanentIdV1 account,
        DeepLocalProfile profile,
        CancellationToken cancellationToken = default);

    Task ClearLocalAccountAsync(
        DeepAccountReconciledMutationCapability mutationCapability,
        CancellationToken cancellationToken = default);

    DeepSecureStorageSlots GetGenerationSecureStorageSlots();
}

public sealed class DeepAccountMutationLease : IAsyncDisposable
{
    private readonly object owner;
    private readonly SemaphoreSlim useGate = new(1, 1);
    private Func<ValueTask>? releaseAction;

    internal DeepAccountMutationLease(object owner, Func<ValueTask> release)
    {
        this.owner = owner ?? throw new ArgumentNullException(nameof(owner));
        releaseAction = release ?? throw new ArgumentNullException(nameof(release));
    }

    internal async ValueTask<IAsyncDisposable> EnterAsync(
        object expectedOwner,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expectedOwner);
        await useGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (!ReferenceEquals(owner, expectedOwner) || Volatile.Read(ref releaseAction) is null)
        {
            useGate.Release();
            throw new InvalidOperationException(
                "An active mutation lease issued by this exact account store is required.");
        }
        return new DeepAccountMutationUse(() => useGate.Release());
    }

    public async ValueTask DisposeAsync()
    {
        await useGate.WaitAsync().ConfigureAwait(false);
        try
        {
            var release = Interlocked.Exchange(ref releaseAction, null);
            if (release is not null)
            {
                await release().ConfigureAwait(false);
            }
        }
        finally
        {
            useGate.Release();
        }
    }

    private sealed class DeepAccountMutationUse(Action release) : IAsyncDisposable
    {
        private Action? releaseAction = release;

        public ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref releaseAction, null)?.Invoke();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>
/// Proves that the exact account receipt, immutable identity commitment, secure
/// inventory and pending journal were reconciled while the underlying mutation
/// lease was held. Only the account service can mint this capability.
/// </summary>
public sealed class DeepAccountReconciledMutationCapability
{
    private readonly DeepAccountMutationLease mutationLease;
    private readonly DeepAccountCreationOperation? expectedOperation;
    private readonly byte[]? expectedImmutableIdentityCommitment;

    internal DeepAccountReconciledMutationCapability(
        DeepAccountMutationLease mutationLease,
        DeepAccountCreationOperation? expectedOperation,
        ReadOnlySpan<byte> expectedImmutableIdentityCommitment)
    {
        this.mutationLease = mutationLease ?? throw new ArgumentNullException(nameof(mutationLease));
        this.expectedOperation = expectedOperation;
        if (expectedOperation is null)
        {
            if (!expectedImmutableIdentityCommitment.IsEmpty)
            {
                throw new ArgumentException(
                    "An empty reconciled store cannot carry an identity commitment.",
                    nameof(expectedImmutableIdentityCommitment));
            }
        }
        else
        {
            DeepAccountImmutableIdentityHash.Validate(
                expectedImmutableIdentityCommitment,
                nameof(expectedImmutableIdentityCommitment));
            this.expectedImmutableIdentityCommitment = expectedImmutableIdentityCommitment.ToArray();
        }
    }

    internal DeepAccountCreationOperation? ExpectedOperation => expectedOperation;

    internal ReadOnlySpan<byte> ExpectedImmutableIdentityCommitment =>
        expectedImmutableIdentityCommitment;

    internal ValueTask<IAsyncDisposable> EnterAsync(
        object expectedOwner,
        CancellationToken cancellationToken) =>
        mutationLease.EnterAsync(expectedOwner, cancellationToken);
}

public sealed class DeepAccountCreationOperation
{
    public const int ValueSize = 32;

    private readonly byte[] operationId;
    private readonly byte[] initialSnapshotHash;

    private DeepAccountCreationOperation(
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> initialSnapshotHash)
    {
        Validate(operationId, nameof(operationId));
        Validate(initialSnapshotHash, nameof(initialSnapshotHash));
        this.operationId = operationId.ToArray();
        this.initialSnapshotHash = initialSnapshotHash.ToArray();
    }

    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();

    public ReadOnlyMemory<byte> InitialSnapshotHash => initialSnapshotHash.ToArray();

    public static DeepAccountCreationOperation Create(DeepLocalIdentitySnapshot identity)
    {
        DeepAccountStoreValidation.Validate(identity);
        var operationId = RandomNumberGenerator.GetBytes(ValueSize);
        var initialSnapshotHash = DeepAccountInitialSnapshotHash.Compute(identity);
        try
        {
            return new DeepAccountCreationOperation(operationId, initialSnapshotHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(operationId);
            CryptographicOperations.ZeroMemory(initialSnapshotHash);
        }
    }

    internal static DeepAccountCreationOperation FromPersisted(
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> initialSnapshotHash) => new(operationId, initialSnapshotHash);

    public bool Matches(DeepAccountCreationOperation other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return CryptographicOperations.FixedTimeEquals(operationId, other.operationId)
            && CryptographicOperations.FixedTimeEquals(
                initialSnapshotHash,
                other.initialSnapshotHash);
    }

    public bool MatchesIdentity(DeepLocalIdentitySnapshot identity)
    {
        var actual = DeepAccountInitialSnapshotHash.Compute(identity);
        try
        {
            return CryptographicOperations.FixedTimeEquals(initialSnapshotHash, actual);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static void Validate(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != ValueSize || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} must contain exactly {ValueSize} nonzero bytes.", name);
        }
    }
}

internal static class DeepAccountInitialSnapshotHash
{
    private static readonly byte[] Domain = "Deep/Store/V1/account-creation"u8.ToArray();

    internal static byte[] Compute(DeepLocalIdentitySnapshot identity)
    {
        DeepAccountStoreValidation.Validate(identity);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, Domain);
        AppendInt32(hash, identity.StoreGeneration);
        Append(hash, identity.NetworkId.Span);
        Append(hash, Encoding.UTF8.GetBytes(identity.Account.PermanentId.CanonicalText));
        Append(hash, identity.Account.AccountIdentity.AccountId.Bytes.Span);
        AppendUInt64(hash, identity.Account.AccountIdentity.AccountGeneration);
        Append(hash, identity.Account.AccountIdentity.AccountSigningPublicKey.Bytes.Span);

        // The creation receipt commits only the immutable genesis/account state.
        // Mutable profile, activation, current-device pointer, and secure-storage
        // slot names are deliberately excluded so the receipt remains verifiable
        // after legitimate local updates.
        Append(hash, identity.Device.DeviceId.Bytes.Span);
        AppendUInt64(hash, identity.Device.DeviceGeneration);
        Append(hash, identity.Device.RevocationHandle.Bytes.Span);
        Append(hash, identity.Device.SigningPublicKey.Span);
        Append(hash, identity.Device.AgreementPublicKey.Span);
        Append(hash, identity.Device.PrekeyPublicKey.Span);
        AppendInt64(hash, identity.Device.CreatedAt.ToUnixTimeMilliseconds());
        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static void AppendInt32(IncrementalHash hash, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        Append(hash, bytes);
    }

    private static void AppendInt64(IncrementalHash hash, long value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(bytes, value);
        Append(hash, bytes);
    }

    private static void AppendUInt64(IncrementalHash hash, ulong value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        Append(hash, bytes);
    }
}

internal static class DeepAccountImmutableIdentityHash
{
    internal const int Size = 32;
    private static readonly byte[] Domain = "Deep/Store/V1/immutable-identity"u8.ToArray();

    internal static byte[] Compute(DeepLocalIdentitySnapshot identity)
    {
        DeepAccountStoreValidation.Validate(identity);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, Domain);
        AppendInt32(hash, identity.StoreGeneration);
        Append(hash, identity.NetworkId.Span);
        Append(hash, Encoding.UTF8.GetBytes(identity.Account.PermanentId.CanonicalText));
        Append(hash, identity.Account.AccountIdentity.AccountId.Bytes.Span);
        AppendUInt64(hash, identity.Account.AccountIdentity.AccountGeneration);
        Append(hash, identity.Account.AccountIdentity.AccountSigningPublicKey.Bytes.Span);

        // This is the immutable genesis device identity. A future current-device
        // pointer is mutable directory state and must be stored separately rather
        // than changing this commitment.
        Append(hash, identity.Device.DeviceId.Bytes.Span);
        AppendUInt64(hash, identity.Device.DeviceGeneration);
        Append(hash, identity.Device.RevocationHandle.Bytes.Span);
        Append(hash, identity.Device.SigningPublicKey.Span);
        Append(hash, identity.Device.AgreementPublicKey.Span);
        Append(hash, identity.Device.PrekeyPublicKey.Span);
        AppendInt64(hash, identity.Device.CreatedAt.ToUnixTimeMilliseconds());
        return hash.GetHashAndReset();
    }

    internal static void Validate(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != Size || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} must contain exactly {Size} nonzero bytes.", name);
        }
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static void AppendInt32(IncrementalHash hash, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        Append(hash, bytes);
    }

    private static void AppendInt64(IncrementalHash hash, long value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(bytes, value);
        Append(hash, bytes);
    }

    private static void AppendUInt64(IncrementalHash hash, ulong value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        Append(hash, bytes);
    }
}

public sealed class DeepAccountAlreadyExistsException() :
    InvalidOperationException("A local Deep account already exists. Reset local state before creating or restoring another account.");

public sealed class DeepAccountCreationOutcomeUnknownException(Exception creationFailure, Exception reconciliationFailure) :
    InvalidOperationException(
        "The local account commit outcome could not be reconciled. Secure material was preserved for the next startup reconciliation.",
        new AggregateException(creationFailure, reconciliationFailure));

internal static class DeepAccountStoreValidation
{
    internal static void ValidateProfile(DeepLocalProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        string normalized;
        try
        {
            normalized = DeepDisplayName.Normalize(profile.DisplayName, nameof(profile));
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException(
                "Profile display name is not canonical or contains unsafe Unicode.",
                nameof(profile),
                exception);
        }
        if (!string.Equals(normalized, profile.DisplayName, StringComparison.Ordinal))
        {
            throw new ArgumentException("Profile display name must be canonical NFC.", nameof(profile));
        }
    }

    internal static void Validate(DeepLocalIdentitySnapshot identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (identity.StoreGeneration != DeepAccountStoreContract.CurrentStoreGeneration)
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.UnsupportedVersion,
                $"Local account generation {identity.StoreGeneration} is unsupported; generation {DeepAccountStoreContract.CurrentStoreGeneration} is required. Reset local data before retrying.");
        }

        if (identity.Account is null
            || identity.Device is null
            || identity.Profile is null
            || identity.SecureSlots is null
            || identity.Account.PermanentId is null
            || identity.Account.AccountIdentity is null
            || identity.Account.CurrentDeviceId is null
            || identity.Device.Identity is null
            || identity.Device.DeviceId is null)
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "Local Deep account state contains missing required values.");
        }

        if (identity.Account.AccountIdentity.AccountGeneration != DeepAccountStoreContract.CurrentAccountGeneration
            || identity.NetworkId.Length != DeepAccountStoreContract.NetworkIdSize
            || !identity.Account.AccountIdentity.NetworkId.Matches(identity.NetworkId.Span)
            || !identity.Device.Identity.AccountIdentity.Equals(identity.Account.AccountIdentity)
            || !identity.Account.CurrentDeviceId.Equals(identity.Device.DeviceId)
            || identity.Device.DeviceGeneration != 1
            || !string.Equals(identity.Account.DisplayName, identity.Profile.DisplayName, StringComparison.Ordinal)
            || identity.Account.DisplayName is null
            || !DeepDisplayName.IsCanonical(identity.Account.DisplayName)
            || identity.Account.ActivationState is not (
                DeepAccountActivationState.ActiveLocal or
                DeepAccountActivationState.RestorePendingActivation)
            || identity.Device.SigningPublicKey.Length != DeepAccountStoreContract.KeyMaterialSize
            || identity.Device.AgreementPublicKey.Length != DeepAccountStoreContract.KeyMaterialSize
            || identity.Device.PrekeyPublicKey.Length != DeepAccountStoreContract.KeyMaterialSize)
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "Local Deep account state is inconsistent and must be reset.");
        }

        DeepSecureStorageSlots.Validate(identity.SecureSlots);
        ValidateProfile(identity.Profile);
    }
}
