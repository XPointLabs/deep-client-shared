using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepAccountService
{
    internal async Task<MessageStoreScope> GetMessageStoreScopeAsync(
        DeepLocalIdentitySnapshot expectedIdentity,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        cancellationToken.ThrowIfCancellationRequested();

        await ProcessMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var mutationLease = await store
                .AcquireMutationLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            var reconciled = await RecoverPendingSecureStorageAsync(
                    mutationLease,
                    cancellationToken)
                .ConfigureAwait(false);
            var current = reconciled.Identity
                ?? throw new InvalidOperationException("No local Deep account exists.");
            EnsureExpectedDeviceSnapshot(current, expectedIdentity);

            var expectedInstanceId = reconciled.MessageStoreInstanceId
                ?? throw ResetRequired("The reconciled account has no message-store instance ID.");
            using var storedInstanceId = await secureStorage
                .ReadOwnedAsync(current.SecureSlots.MessageStoreInstanceId, cancellationToken)
                .ConfigureAwait(false)
                ?? throw ResetRequired("The message-store instance secure-storage slot is missing.");

            MessageStoreInstanceId32? instanceId = null;
            if (storedInstanceId.Length != DeepAccountStoreContract.KeyMaterialSize)
            {
                throw ResetRequired("The message-store instance secure-storage slot is invalid.");
            }
            storedInstanceId.Use(value =>
            {
                if (!CryptographicOperations.FixedTimeEquals(value, expectedInstanceId.Span))
                {
                    throw ResetRequired("The message-store instance secure-storage slot is invalid.");
                }
                instanceId = MessageStoreInstanceId32.FromBytes(value);
            });

            return new MessageStoreScope(
                MessagingAccountId32.FromBytes(
                    current.Account.AccountIdentity.AccountId.Bytes.Span),
                checked((ulong)DeepAccountStoreContract.CurrentStoreGeneration),
                instanceId!);
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }
}
