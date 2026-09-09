using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Sodium;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Receives a byref-like view over one service-owned secret for a synchronous
/// internal operation. The underlying owned read is disposed when it returns.
/// </summary>
internal delegate TResult DeepDeviceSecretScopeFunc<TResult>(
    DeepDeviceSecretScope secret,
    CancellationToken cancellationToken);

/// <summary>
/// Provides callback-only access to one owned device secret. As a ref struct it
/// cannot be boxed, retained in an object, or carried across an async boundary.
/// </summary>
internal readonly ref struct DeepDeviceSecretScope
{
    private readonly ReadOnlySpan<byte> secret;

    internal DeepDeviceSecretScope(ReadOnlySpan<byte> secret) => this.secret = secret;

    internal void Use(DeepSecretAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        action(secret);
    }
}

/// <summary>
/// Short-lived, non-public owner of the current device agreement scalar.  It
/// can only combine that scalar with the signed pre-key selected by the
/// device-wide PreKeyV1 store; the scalar is never returned to its caller.
/// </summary>
internal sealed class DeepResponderIdentitySecretLease : IDisposable
{
    private byte[]? agreementPrivateScalar;
    private readonly int maximumMessagesWithoutPqInjection;

    internal DeepResponderIdentitySecretLease(
        ReadOnlySpan<byte> agreementPrivateScalar,
        int maximumMessagesWithoutPqInjection)
    {
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        this.agreementPrivateScalar = agreementPrivateScalar.ToArray();
        this.maximumMessagesWithoutPqInjection = maximumMessagesWithoutPqInjection;
    }

    internal ManagedResponderInitialSessionFactory OpenFactory()
    {
        var agreement = Volatile.Read(ref agreementPrivateScalar) ??
            throw new ObjectDisposedException(nameof(DeepResponderIdentitySecretLease));
        return new ManagedResponderInitialSessionFactory(
            agreement,
            maximumMessagesWithoutPqInjection);
    }

    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref agreementPrivateScalar, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

public sealed partial class DeepAccountService
{
    internal async Task<Dpk2AuthoringAuthority> OpenCurrentDpk2AuthoringAuthorityAsync(
        DeepLocalIdentitySnapshot expectedIdentity,
        VerifiedDeviceRelative verifiedDevice,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        ArgumentNullException.ThrowIfNull(verifiedDevice);
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
            var current = reconciled.Identity ??
                throw new InvalidOperationException("No local Deep account exists.");
            EnsureExpectedDeviceSnapshot(current, expectedIdentity);
            await ValidateCurrentDeviceIdSlotAsync(current, cancellationToken)
                .ConfigureAwait(false);

            byte[]? signing = new byte[DeepAccountStoreContract.KeyMaterialSize];
            byte[]? agreement = new byte[DeepAccountStoreContract.KeyMaterialSize];
            byte[]? deviceId = new byte[DeepAccountStoreContract.KeyMaterialSize];
            byte[]? revocation = new byte[DeepAccountStoreContract.KeyMaterialSize];
            try
            {
                await CopyExactSecureValueAsync(current.SecureSlots.DeviceSigningKey, signing, cancellationToken)
                    .ConfigureAwait(false);
                await CopyExactSecureValueAsync(current.SecureSlots.DeviceAgreementKey, agreement, cancellationToken)
                    .ConfigureAwait(false);
                await CopyExactSecureValueAsync(current.SecureSlots.DeviceId, deviceId, cancellationToken)
                    .ConfigureAwait(false);
                await CopyExactSecureValueAsync(current.SecureSlots.DeviceRevocationHandle, revocation, cancellationToken)
                    .ConfigureAwait(false);
                using var persisted = OwnedPersistedDeviceIdentitySecrets.TakeOwnership(
                    signing, agreement, deviceId, revocation);
                signing = agreement = deviceId = revocation = null;
                using var restored = OwnedGenesisDeviceSecrets.RestoreFromPersistedOwnedSecrets(persisted);
                return restored.CreateDpk2AuthoringAuthority(verifiedDevice);
            }
            catch (Exception exception) when (exception is ArgumentException or CryptographicException)
            {
                throw ResetRequired(
                    "The verified device or protected local-device identity cannot open DPK2 authoring authority.",
                    exception);
            }
            finally
            {
                Zero(signing); Zero(agreement); Zero(deviceId); Zero(revocation);
            }
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }

    internal async Task<DeepResponderIdentitySecretLease>
        OpenCurrentResponderIdentitySecretLeaseAsync(
            DeepLocalIdentitySnapshot expectedIdentity,
            int maximumMessagesWithoutPqInjection,
            CancellationToken cancellationToken = default)
    {
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        return await UseCurrentDeviceAgreementKeyAsync(
                expectedIdentity,
                (secret, token) =>
                {
                    DeepResponderIdentitySecretLease? result = null;
                    secret.Use(value => result = new DeepResponderIdentitySecretLease(
                        value,
                        maximumMessagesWithoutPqInjection));
                    token.ThrowIfCancellationRequested();
                    return result!;
                },
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal Task<byte[]> SignWithCurrentDeviceAsync(
        DeepLocalIdentitySnapshot expectedIdentity,
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default) =>
        UseCurrentDeviceSecretAsync(
            expectedIdentity,
            DeviceSecretRole.Signing,
            (secret, token) => SignDetached(secret, message, token),
            cancellationToken);

    internal Task<TResult> UseCurrentDeviceAgreementKeyAsync<TResult>(
        DeepLocalIdentitySnapshot expectedIdentity,
        DeepDeviceSecretScopeFunc<TResult> operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return UseCurrentDeviceSecretAsync(
            expectedIdentity,
            DeviceSecretRole.Agreement,
            (owned, token) =>
            {
                TResult result = default!;
                owned.Use(secret => result = operation(new DeepDeviceSecretScope(secret), token));
                return result;
            },
            cancellationToken);
    }

    internal Task<TResult> UseCurrentDevicePrekeyAsync<TResult>(
        DeepLocalIdentitySnapshot expectedIdentity,
        DeepDeviceSecretScopeFunc<TResult> operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return UseCurrentDeviceSecretAsync(
            expectedIdentity,
            DeviceSecretRole.Prekey,
            (owned, token) =>
            {
                TResult result = default!;
                owned.Use(secret => result = operation(new DeepDeviceSecretScope(secret), token));
                return result;
            },
            cancellationToken);
    }

    private async Task<TResult> UseCurrentDeviceSecretAsync<TResult>(
        DeepLocalIdentitySnapshot expectedIdentity,
        DeviceSecretRole role,
        Func<OwnedDeepSecret, CancellationToken, TResult> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        ArgumentNullException.ThrowIfNull(operation);
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
            await ValidateCurrentDeviceIdSlotAsync(current, cancellationToken)
                .ConfigureAwait(false);

            string slot;
            ReadOnlyMemory<byte> expectedPublicKey;
            PublicKeyMatcher matcher;
            switch (role)
            {
                case DeviceSecretRole.Signing:
                    slot = current.SecureSlots.DeviceSigningKey;
                    expectedPublicKey = current.Device.SigningPublicKey;
                    matcher = MatchEd25519PublicKey;
                    break;
                case DeviceSecretRole.Agreement:
                    slot = current.SecureSlots.DeviceAgreementKey;
                    expectedPublicKey = current.Device.AgreementPublicKey;
                    matcher = MatchX25519PublicKey;
                    break;
                case DeviceSecretRole.Prekey:
                    slot = current.SecureSlots.DevicePrekey;
                    expectedPublicKey = current.Device.PrekeyPublicKey;
                    matcher = MatchX25519PublicKey;
                    break;
                default:
                    throw new InvalidOperationException("Unknown local-device secret role.");
            }

            using var owned = await secureStorage.ReadOwnedAsync(slot, cancellationToken)
                .ConfigureAwait(false)
                ?? throw ResetRequired("A required local-device secret slot is missing.");
            ValidateSecretMatchesPublicKey(owned, expectedPublicKey, matcher);
            cancellationToken.ThrowIfCancellationRequested();
            return operation(owned, cancellationToken);
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }

    private async Task ValidateCurrentDeviceIdSlotAsync(
        DeepLocalIdentitySnapshot current,
        CancellationToken cancellationToken)
    {
        using var deviceId = await secureStorage
            .ReadOwnedAsync(current.SecureSlots.DeviceId, cancellationToken)
            .ConfigureAwait(false)
            ?? throw ResetRequired("The current-device ID secure-storage slot is missing.");
        if (deviceId.Length != DeviceId32.Size
            || !deviceId.Use(value => current.Device.DeviceId.Matches(value))
            || !current.Account.CurrentDeviceId.Equals(current.Device.DeviceId))
        {
            throw ResetRequired("The current-device ID does not match the reconciled public snapshot.");
        }
    }

    private static void EnsureExpectedDeviceSnapshot(
        DeepLocalIdentitySnapshot current,
        DeepLocalIdentitySnapshot expected)
    {
        if (current.StoreGeneration != expected.StoreGeneration
            || !CryptographicOperations.FixedTimeEquals(current.NetworkId.Span, expected.NetworkId.Span)
            || !current.Account.PermanentId.Equals(expected.Account.PermanentId)
            || !current.Account.AccountIdentity.Equals(expected.Account.AccountIdentity)
            || !current.Account.CurrentDeviceId.Equals(expected.Account.CurrentDeviceId)
            || !current.Device.DeviceId.Equals(expected.Device.DeviceId)
            || current.Device.DeviceGeneration != expected.Device.DeviceGeneration
            || !CryptographicOperations.FixedTimeEquals(
                current.Device.SigningPublicKey.Span,
                expected.Device.SigningPublicKey.Span)
            || !CryptographicOperations.FixedTimeEquals(
                current.Device.AgreementPublicKey.Span,
                expected.Device.AgreementPublicKey.Span)
            || !CryptographicOperations.FixedTimeEquals(
                current.Device.PrekeyPublicKey.Span,
                expected.Device.PrekeyPublicKey.Span)
            || !current.SecureSlots.Equals(expected.SecureSlots))
        {
            throw new InvalidOperationException(
                "The expected local-device snapshot does not match the current reconciled identity.");
        }
    }

    private static void ValidateSecretMatchesPublicKey(
        OwnedDeepSecret secret,
        ReadOnlyMemory<byte> expectedPublicKey,
        PublicKeyMatcher matcher)
    {
        try
        {
            if (secret.Length != DeepAccountStoreContract.KeyMaterialSize
                || !secret.Use(value => matcher(value, expectedPublicKey)))
            {
                throw ResetRequired(
                    "A local-device secret does not match its reconciled public key.");
            }
        }
        catch (ArgumentException exception)
        {
            throw ResetRequired("A local-device secret contains an invalid value.", exception);
        }
    }

    private static bool MatchEd25519PublicKey(
        ReadOnlySpan<byte> secret,
        ReadOnlyMemory<byte> expected) =>
        DeepIdentityCrypto.Ed25519PublicKeyMatchesSeed(secret, expected.Span);

    private static bool MatchX25519PublicKey(
        ReadOnlySpan<byte> secret,
        ReadOnlyMemory<byte> expected) =>
        DeepIdentityCrypto.X25519PublicKeyMatchesPrivateScalar(secret, expected.Span);

    private static byte[] SignDetached(
        OwnedDeepSecret secret,
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken)
    {
        byte[]? seed = null;
        byte[]? messageCopy = null;
        byte[]? signature = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            secret.Use(value => seed = value.ToArray());
            messageCopy = message.ToArray();
            using var keyPair = PublicKeyAuth.GenerateKeyPair(seed!);
            try
            {
                signature = PublicKeyAuth.SignDetached(messageCopy, keyPair.PrivateKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyPair.PrivateKey);
            }
            cancellationToken.ThrowIfCancellationRequested();
            var result = signature;
            signature = null;
            return result;
        }
        finally
        {
            Zero(seed);
            Zero(messageCopy);
            Zero(signature);
        }
    }

    private enum DeviceSecretRole
    {
        Signing = 1,
        Agreement = 2,
        Prekey = 3
    }
}
