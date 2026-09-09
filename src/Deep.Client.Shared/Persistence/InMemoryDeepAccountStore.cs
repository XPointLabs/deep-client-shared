using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence;

public sealed class InMemoryDeepAccountStore : IDeepAccountStore
{
    private static readonly SemaphoreSlim MutationGate = new(1, 1);
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly object mutationOwner = new();
    private readonly Action<DeepAccountCommitFaultPoint>? faultInjector;
    private DeepLocalIdentitySnapshot? identity;
    private DeepAccountCreationOperation? creationOperation;
    private byte[]? immutableIdentityCommitment;
    private readonly DeepSecureStorageSlots generationSecureSlots;
    private int disposed;

    public InMemoryDeepAccountStore()
    {
        generationSecureSlots = CreateGenerationSecureSlots();
    }

    internal InMemoryDeepAccountStore(Action<DeepAccountCommitFaultPoint>? faultInjector)
    {
        this.faultInjector = faultInjector;
        generationSecureSlots = CreateGenerationSecureSlots();
    }

    public async ValueTask<DeepAccountMutationLease> AcquireMutationLeaseAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await MutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (Volatile.Read(ref disposed) != 0)
        {
            MutationGate.Release();
            ThrowIfDisposed();
        }
        return new DeepAccountMutationLease(mutationOwner, () =>
        {
            MutationGate.Release();
            return ValueTask.CompletedTask;
        });
    }

    public async Task<DeepAccountIdentityCapability?> ReadAccountIdentityAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (identity is null)
            {
                return null;
            }

            DeepAccountStoreValidation.Validate(identity);
            if (creationOperation is null || !creationOperation.MatchesIdentity(identity))
            {
                throw new LocalStateResetRequiredException(
                    LocalStateResetRequiredReason.InvalidCurrentSchema,
                    "The in-memory account creation receipt does not match immutable genesis state.");
            }
            VerifyImmutableIdentity(identity, immutableIdentityCommitment);
            return identity.Account.AccountIdentity;
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<DeepLocalIdentitySnapshot?> ReadAsync(
        LocalDeviceIdentityIntent? localDeviceIdentity,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (identity is null)
            {
                return null;
            }

            if (localDeviceIdentity is null
                || !identity.Device.Identity.Equals(localDeviceIdentity))
            {
                throw new LocalStateResetRequiredException(
                    LocalStateResetRequiredReason.InvalidCurrentSchema,
                    "The supplied owned local-device intent does not match persisted state.");
            }

            DeepAccountStoreValidation.Validate(identity);
            if (creationOperation is null || !creationOperation.MatchesIdentity(identity))
            {
                throw new LocalStateResetRequiredException(
                    LocalStateResetRequiredReason.InvalidCurrentSchema,
                    "The in-memory account creation receipt does not match immutable genesis state.");
            }
            VerifyImmutableIdentity(identity, immutableIdentityCommitment);
            return Clone(identity, localDeviceIdentity);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task CreateAsync(
        DeepAccountReconciledMutationCapability mutationCapability,
        DeepLocalIdentitySnapshot value,
        DeepAccountCreationOperation operation,
        ReadOnlyMemory<byte> immutableCommitment,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(mutationCapability);
        await using var mutationUse = await mutationCapability
            .EnterAsync(mutationOwner, cancellationToken)
            .ConfigureAwait(false);
        DeepAccountStoreValidation.Validate(value);
        ArgumentNullException.ThrowIfNull(operation);
        if (!operation.MatchesIdentity(value))
        {
            throw new ArgumentException("Creation operation does not match the identity snapshot.", nameof(operation));
        }
        DeepAccountImmutableIdentityHash.Validate(immutableCommitment.Span, nameof(immutableCommitment));
        var computedImmutable = DeepAccountImmutableIdentityHash.Compute(value);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(computedImmutable, immutableCommitment.Span))
            {
                throw new ArgumentException(
                    "Immutable identity commitment does not match the identity snapshot.",
                    nameof(immutableCommitment));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedImmutable);
        }
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            faultInjector?.Invoke(DeepAccountCommitFaultPoint.BeforeTransaction);
            if (identity is not null)
            {
                throw new DeepAccountAlreadyExistsException();
            }
            ValidateExpectedState(mutationCapability);

            var candidate = Clone(value);
            var candidateOperation = Clone(operation);
            var candidateImmutableCommitment = immutableCommitment.ToArray();
            faultInjector?.Invoke(DeepAccountCommitFaultPoint.AfterAccount);
            faultInjector?.Invoke(DeepAccountCommitFaultPoint.AfterDevice);
            cancellationToken.ThrowIfCancellationRequested();
            faultInjector?.Invoke(DeepAccountCommitFaultPoint.BeforeCommit);
            identity = candidate;
            creationOperation = candidateOperation;
            immutableIdentityCommitment = candidateImmutableCommitment;
            faultInjector?.Invoke(DeepAccountCommitFaultPoint.AfterCommit);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<DeepAccountCreationOperation?> ReadCreationOperationAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return creationOperation is null ? null : Clone(creationOperation);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task UpdateProfileAsync(
        DeepAccountReconciledMutationCapability mutationCapability,
        DeepPermanentIdV1 account,
        DeepLocalProfile profile,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(mutationCapability);
        await using var mutationUse = await mutationCapability
            .EnterAsync(mutationOwner, cancellationToken)
            .ConfigureAwait(false);
        DeepAccountStoreValidation.ValidateProfile(profile);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            ValidateExpectedState(mutationCapability);
            var current = identity ?? throw new InvalidOperationException("No local Deep account exists.");
            if (current.Account.PermanentId != account)
            {
                throw new InvalidOperationException("Profile account does not match the local Deep account.");
            }

            var updated = current with
            {
                Account = current.Account with { DisplayName = profile.DisplayName },
                Profile = profile
            };
            DeepAccountStoreValidation.Validate(updated);
            identity = Clone(updated);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task ClearLocalAccountAsync(
        DeepAccountReconciledMutationCapability mutationCapability,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(mutationCapability);
        await using var mutationUse = await mutationCapability
            .EnterAsync(mutationOwner, cancellationToken)
            .ConfigureAwait(false);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            ValidateExpectedState(mutationCapability);
            identity = null;
            creationOperation = null;
            if (immutableIdentityCommitment is not null)
            {
                CryptographicOperations.ZeroMemory(immutableIdentityCommitment);
                immutableIdentityCommitment = null;
            }
        }
        finally
        {
            gate.Release();
        }
    }

    public DeepSecureStorageSlots GetGenerationSecureStorageSlots()
    {
        ThrowIfDisposed();
        return generationSecureSlots;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
        {
            await gate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (immutableIdentityCommitment is not null)
                {
                    CryptographicOperations.ZeroMemory(immutableIdentityCommitment);
                    immutableIdentityCommitment = null;
                }
            }
            finally
            {
                gate.Release();
                gate.Dispose();
            }
        }
    }

    private static DeepLocalIdentitySnapshot Clone(
        DeepLocalIdentitySnapshot value,
        LocalDeviceIdentityIntent? localDeviceIdentity = null) =>
        value with
        {
            NetworkId = value.NetworkId.ToArray(),
            Device = new DeepDevice(
                localDeviceIdentity ?? value.Device.Identity,
                value.Device.PrekeyPublicKey.Span,
                value.Device.CreatedAt)
        };

    private static DeepAccountCreationOperation Clone(DeepAccountCreationOperation value) =>
        DeepAccountCreationOperation.FromPersisted(
            value.OperationId.Span,
            value.InitialSnapshotHash.Span);

    private void ValidateExpectedState(DeepAccountReconciledMutationCapability capability)
    {
        if (capability.ExpectedOperation is null)
        {
            if (identity is not null || creationOperation is not null || immutableIdentityCommitment is not null)
            {
                throw new InvalidOperationException("The reconciled empty-store capability is stale.");
            }
            return;
        }

        if (creationOperation is null
            || !creationOperation.Matches(capability.ExpectedOperation)
            || immutableIdentityCommitment is null
            || !CryptographicOperations.FixedTimeEquals(
                immutableIdentityCommitment,
                capability.ExpectedImmutableIdentityCommitment))
        {
            throw new InvalidOperationException("The reconciled mutation capability is stale.");
        }
    }

    private static void VerifyImmutableIdentity(
        DeepLocalIdentitySnapshot value,
        byte[]? expectedCommitment)
    {
        if (expectedCommitment is null)
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "The in-memory account is missing its immutable identity commitment.");
        }
        var actual = DeepAccountImmutableIdentityHash.Compute(value);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expectedCommitment, actual))
            {
                throw new LocalStateResetRequiredException(
                    LocalStateResetRequiredReason.InvalidCurrentSchema,
                    "The in-memory account immutable identity commitment does not match current state.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static DeepSecureStorageSlots CreateGenerationSecureSlots()
    {
        var generationId = RandomNumberGenerator.GetBytes(DeepAccountStoreContract.KeyMaterialSize);
        try
        {
            return DeepSecureStorageSlots.CreateForGeneration(generationId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(generationId);
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed != 0, this);
}
