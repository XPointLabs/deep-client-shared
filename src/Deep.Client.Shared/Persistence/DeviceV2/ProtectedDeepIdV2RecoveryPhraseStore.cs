using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// V2-only account-scoped custody of the canonical 24-word recovery phrase.
/// Explicit deletion is gated on a fresh verified public-and-device bootstrap.
/// </summary>
internal sealed class ProtectedDeepIdV2RecoveryPhraseStore
{
    private const int HeaderLength = 56;
    private readonly IDeepSecureStorage storage;
    private readonly string slot;
    private readonly string deletedSlot;
    private readonly byte[] networkId;
    private readonly byte[] accountId;

    internal ProtectedDeepIdV2RecoveryPhraseStore(IDeepSecureStorage storage,
        ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> accountId)
    {
        this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0 ||
            accountId.Length != 32 || accountId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero V2 network/account scope is required.");
        this.networkId = networkId.ToArray();
        this.accountId = accountId.ToArray();
        Span<byte> scope = stackalloc byte[48];
        networkId.CopyTo(scope);
        accountId.CopyTo(scope[16..]);
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(scope, digest);
        var prefix = "deep.store.v2." + Convert.ToHexStringLower(digest);
        slot = prefix + ".recovery-phrase";
        deletedSlot = prefix + ".recovery-phrase-deleted";
        CryptographicOperations.ZeroMemory(scope);
        CryptographicOperations.ZeroMemory(digest);
    }

    internal async ValueTask WriteVerifiedAsync(VerifiedDeepRecoveryPhrase phrase,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(phrase);
        using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase, networkId, 1);
        if (!Fixed(recovery.AccountIdentity.AccountId.Bytes.Span, accountId))
            throw new CryptographicException(
                "The retained V2 recovery phrase derives a different account.");
        if (await IsDeletedAsync(cancellationToken).ConfigureAwait(false))
            throw new CryptographicException(
                "The V2 recovery phrase was permanently deleted locally.");
        var length = phrase.CanonicalUtf8Length;
        var encoded = new byte[HeaderLength + length];
        try
        {
            "DRP2"u8.CopyTo(encoded);
            BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(4), 2);
            BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(6),
                checked((ushort)length));
            networkId.CopyTo(encoded, 8);
            accountId.CopyTo(encoded, 24);
            if (phrase.WriteCanonicalUtf8(encoded.AsSpan(HeaderLength)) != length)
                throw new CryptographicException(
                    "The V2 phrase changed during protected persistence.");
            using var current = await storage.ReadOwnedAsync(slot,
                cancellationToken).ConfigureAwait(false);
            if (current is not null)
            {
                if (current.Length != encoded.Length ||
                    !current.Use(value => Fixed(value, encoded)))
                    throw new CryptographicException(
                        "The retained V2 recovery phrase differs from the winner.");
            }
            else try
            {
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(slot, encoded)],
                    cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                using var raced = await storage.ReadOwnedAsync(slot,
                    CancellationToken.None).ConfigureAwait(false);
                if (raced is null || raced.Length != encoded.Length ||
                    !raced.Use(value => Fixed(value, encoded)))
                    throw;
            }
            if (await IsDeletedAsync(CancellationToken.None).ConfigureAwait(false))
            {
                await storage.DeleteBatchAsync([slot], CancellationToken.None)
                    .ConfigureAwait(false);
                throw new CryptographicException(
                    "The V2 recovery phrase was concurrently deleted.");
            }
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    internal async ValueTask<VerifiedDeepRecoveryPhrase?> ReadVerifiedAsync(
        CancellationToken cancellationToken)
    {
        if (await IsDeletedAsync(cancellationToken).ConfigureAwait(false))
        {
            await storage.DeleteBatchAsync([slot], cancellationToken)
                .ConfigureAwait(false);
            return null;
        }
        using var owned = await storage.ReadOwnedAsync(slot,
            cancellationToken).ConfigureAwait(false);
        if (owned is null) return null;
        if (owned.Length is < HeaderLength + 1 or > HeaderLength +
            DeepRecoveryV1.MaxCanonicalUtf8Length)
            throw new InvalidDataException("The protected V2 phrase has a hostile size.");
        var encoded = new byte[owned.Length];
        owned.CopyTo(encoded);
        try
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(6));
            if (!encoded.AsSpan(0, 4).SequenceEqual("DRP2"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(4)) != 2 ||
                length != encoded.Length - HeaderLength ||
                !Fixed(encoded.AsSpan(8, 16), networkId) ||
                !Fixed(encoded.AsSpan(24, 32), accountId))
                throw new InvalidDataException(
                    "The protected V2 phrase has a different scope or version.");
            var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(
                encoded.AsSpan(HeaderLength, length));
            try
            {
                using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
                    phrase, networkId, 1);
                if (!Fixed(recovery.AccountIdentity.AccountId.Bytes.Span, accountId))
                    throw new CryptographicException(
                        "The protected V2 phrase derives a different account.");
                if (await IsDeletedAsync(cancellationToken).ConfigureAwait(false))
                {
                    phrase.Dispose();
                    await storage.DeleteBatchAsync([slot], cancellationToken)
                        .ConfigureAwait(false);
                    return null;
                }
                return phrase;
            }
            catch
            {
                phrase.Dispose();
                throw;
            }
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    internal async ValueTask DeleteAfterVerifiedBootstrapAsync(
        ulong trustedUnixSeconds, ushort deploymentProfileId,
        IDeepMlDsa65Verifier mlDsa65, CancellationToken cancellationToken)
    {
        using var completed = await new ProtectedDeepIdV2GenesisBootstrap(
            storage, networkId, accountId).ReadVerifiedAsync(trustedUnixSeconds,
            deploymentProfileId, mlDsa65, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new CryptographicException(
                "The V2 phrase cannot be deleted before verified bootstrap.");
        if (!await IsDeletedAsync(cancellationToken).ConfigureAwait(false))
        {
            var marker = new byte[56];
            try
            {
                "DRD2"u8.CopyTo(marker);
                BinaryPrimitives.WriteUInt16BigEndian(marker.AsSpan(4), 2);
                networkId.CopyTo(marker, 8);
                accountId.CopyTo(marker, 24);
                try
                {
                    await storage.WriteBatchAsync(
                        [new DeepSecureStorageWrite(deletedSlot, marker)],
                        cancellationToken).ConfigureAwait(false);
                }
                catch (InvalidOperationException)
                {
                    if (!await IsDeletedAsync(CancellationToken.None)
                            .ConfigureAwait(false))
                        throw;
                }
            }
            finally { CryptographicOperations.ZeroMemory(marker); }
        }
        await storage.DeleteBatchAsync([slot], cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask<bool> IsDeletedAsync(CancellationToken cancellationToken)
    {
        using var owned = await storage.ReadOwnedAsync(deletedSlot,
            cancellationToken).ConfigureAwait(false);
        if (owned is null) return false;
        if (owned.Length != 56 || !owned.Use(value =>
                value[..4].SequenceEqual("DRD2"u8) &&
                BinaryPrimitives.ReadUInt16BigEndian(value[4..]) == 2 &&
                value.Slice(6, 2).IndexOfAnyExcept((byte)0) < 0 &&
                Fixed(value.Slice(8, 16), networkId) &&
                Fixed(value.Slice(24, 32), accountId)))
            throw new CryptographicException(
                "The V2 phrase-deletion marker is malformed.");
        return true;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
