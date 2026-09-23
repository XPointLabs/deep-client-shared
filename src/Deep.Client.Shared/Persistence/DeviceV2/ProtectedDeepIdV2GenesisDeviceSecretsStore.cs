using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// Add-only V2 custody for one genesis device secret tuple. The four values
/// never leave the secure-storage boundary except as protocol-owned secrets.
/// This namespace has no V1 reader or fallback.
/// </summary>
internal sealed class ProtectedDeepIdV2GenesisDeviceSecretsStore
{
    private const int HeaderLength = 56;
    private const int RecordLength = HeaderLength + 128;
    private readonly IDeepSecureStorage storage;
    private readonly string slot;
    private readonly byte[] networkId;
    private readonly byte[] accountId;

    internal ProtectedDeepIdV2GenesisDeviceSecretsStore(
        IDeepSecureStorage storage, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId)
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
        slot = "deep.store.v2." + Convert.ToHexStringLower(digest) +
            ".genesis-device-secrets";
        CryptographicOperations.ZeroMemory(scope);
        CryptographicOperations.ZeroMemory(digest);
    }

    internal async ValueTask WriteVerifiedAsync(
        OwnedGenesisDeviceSecrets secrets, VerifiedDevice device,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(device);
        if (!Matches(device, secrets))
            throw new CryptographicException(
                "The V2 device secrets do not match the verified DPD1.");
        var encoded = new byte[RecordLength];
        try
        {
            "DGS2"u8.CopyTo(encoded);
            BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(4), 2);
            networkId.CopyTo(encoded, 8);
            accountId.CopyTo(encoded, 24);
            using (var copy = secrets.ExportOwnedPersistenceCopy())
                copy.CopyTo(encoded.AsSpan(56, 32), encoded.AsSpan(88, 32),
                    encoded.AsSpan(120, 32), encoded.AsSpan(152, 32));
            using var current = await storage.ReadOwnedAsync(slot,
                cancellationToken).ConfigureAwait(false);
            if (current is not null)
            {
                if (current.Length != encoded.Length ||
                    !current.Use(value => Fixed(value, encoded)))
                    throw new CryptographicException(
                        "The protected V2 device-secret winner differs.");
                return;
            }
            try
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
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    internal async ValueTask<OwnedGenesisDeviceSecrets?> ReadVerifiedAsync(
        VerifiedDevice device, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (!MatchesScope(device))
            throw new CryptographicException(
                "The verified DPD1 is outside the V2 device-secret scope.");
        using var owned = await storage.ReadOwnedAsync(slot,
            cancellationToken).ConfigureAwait(false);
        if (owned is null) return null;
        if (owned.Length != RecordLength)
            throw new InvalidDataException("The V2 device-secret record has a hostile size.");
        var encoded = new byte[RecordLength];
        owned.CopyTo(encoded);
        try
        {
            if (!encoded.AsSpan(0, 4).SequenceEqual("DGS2"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(4)) != 2 ||
                encoded.AsSpan(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
                !Fixed(encoded.AsSpan(8, 16), networkId) ||
                !Fixed(encoded.AsSpan(24, 32), accountId))
                throw new InvalidDataException(
                    "The V2 device-secret record has a different scope or version.");
            using var payload = OwnedPersistedDeviceIdentitySecrets.TakeOwnership(
                encoded.AsSpan(56, 32).ToArray(),
                encoded.AsSpan(88, 32).ToArray(),
                encoded.AsSpan(120, 32).ToArray(),
                encoded.AsSpan(152, 32).ToArray());
            var restored = OwnedGenesisDeviceSecrets.RestoreFromPersistedOwnedSecrets(
                payload);
            if (Matches(device, restored)) return restored;
            restored.Dispose();
            throw new CryptographicException(
                "The restored V2 device secrets do not match verified DPD1.");
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    internal async ValueTask<bool> HasRecordAsync(CancellationToken cancellationToken)
    {
        using var owned = await storage.ReadOwnedAsync(slot,
            cancellationToken).ConfigureAwait(false);
        return owned is not null;
    }

    private bool Matches(VerifiedDevice device,
        OwnedGenesisDeviceSecrets secrets) =>
        MatchesScope(device) &&
        Fixed(device.Certificate.DeviceId.Span, secrets.DeviceId.Bytes.Span) &&
        Fixed(device.Certificate.DeviceEd25519PublicKey.Span,
            secrets.SigningPublicKey.Bytes.Span) &&
        Fixed(device.Certificate.DeviceX25519PublicKey.Span,
            secrets.AgreementPublicKey.Bytes.Span) &&
        Fixed(device.Certificate.RevocationHandle.Span,
            secrets.RevocationHandle.Bytes.Span);

    private bool MatchesScope(VerifiedDevice device) =>
        Fixed(device.Certificate.NetworkId.Span, networkId) &&
        Fixed(device.Certificate.AccountHash.Span, accountId);

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
