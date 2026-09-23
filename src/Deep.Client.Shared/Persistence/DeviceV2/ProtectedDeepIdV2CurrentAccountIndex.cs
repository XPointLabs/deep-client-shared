using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// Add-only V2 current-account pointer. It is published only after verified
/// genesis bootstrap and grants no account authority without a fresh read-back.
/// </summary>
internal sealed class ProtectedDeepIdV2CurrentAccountIndex
{
    private const string Slot = "deep.store.v2.current-account";
    private const int HeaderLength = 56;
    private const int MaximumNameBytes = 256;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly IDeepSecureStorage storage;
    private readonly byte[] networkId;
    private readonly ushort deploymentProfileId;

    internal ProtectedDeepIdV2CurrentAccountIndex(IDeepSecureStorage storage,
        ReadOnlySpan<byte> networkId, ushort deploymentProfileId)
    {
        this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0 ||
            deploymentProfileId == 0)
            throw new ArgumentException("A nonzero DID2 network/profile is required.");
        this.networkId = networkId.ToArray();
        this.deploymentProfileId = deploymentProfileId;
    }

    internal async ValueTask<VerifiedDeepIdV2CurrentAccount> PublishVerifiedAsync(
        string displayName, ReadOnlyMemory<byte> accountId,
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier mlDsa65,
        CancellationToken cancellationToken)
    {
        var normalized = NormalizeName(displayName);
        if (accountId.Length != 32 ||
            accountId.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero DID2 account ID is required.",
                nameof(accountId));
        using var complete = await new ProtectedDeepIdV2GenesisBootstrap(
            storage, networkId, accountId.Span).ReadVerifiedAsync(
            trustedUnixSeconds, deploymentProfileId, mlDsa65,
            cancellationToken).ConfigureAwait(false)
            ?? throw new CryptographicException(
                "A partial DID2 genesis cannot become the current account.");
        var name = StrictUtf8.GetBytes(normalized);
        var encoded = new byte[HeaderLength + name.Length];
        try
        {
            "DIX2"u8.CopyTo(encoded);
            BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(4), 2);
            BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(6),
                checked((ushort)name.Length));
            networkId.CopyTo(encoded, 8);
            accountId.Span.CopyTo(encoded.AsSpan(24));
            name.CopyTo(encoded, HeaderLength);
            using var current = await storage.ReadOwnedAsync(Slot,
                cancellationToken).ConfigureAwait(false);
            if (current is not null)
            {
                if (current.Length != encoded.Length ||
                    !current.Use(value => Fixed(value, encoded)))
                    throw new CryptographicException(
                        "A different DID2 current-account index already exists.");
            }
            else try
            {
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(Slot, encoded)],
                    cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                using var raced = await storage.ReadOwnedAsync(Slot,
                    CancellationToken.None).ConfigureAwait(false);
                if (raced is null || raced.Length != encoded.Length ||
                    !raced.Use(value => Fixed(value, encoded)))
                    throw;
            }
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
        return await ReadVerifiedAsync(trustedUnixSeconds, mlDsa65,
            cancellationToken).ConfigureAwait(false)
            ?? throw new CryptographicException(
                "The DID2 account index did not survive verified read-back.");
    }

    internal async ValueTask<VerifiedDeepIdV2CurrentAccount?> ReadVerifiedAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier mlDsa65,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(mlDsa65);
        using var owned = await storage.ReadOwnedAsync(Slot,
            cancellationToken).ConfigureAwait(false);
        if (owned is null) return null;
        if (owned.Length is < HeaderLength + 1 or > HeaderLength + MaximumNameBytes)
            throw new InvalidDataException("The DID2 current-account index has a hostile size.");
        var encoded = new byte[owned.Length];
        owned.CopyTo(encoded);
        try
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(6));
            if (!encoded.AsSpan(0, 4).SequenceEqual("DIX2"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(4)) != 2 ||
                length != encoded.Length - HeaderLength ||
                !Fixed(encoded.AsSpan(8, 16), networkId))
                throw new InvalidDataException(
                    "The DID2 current-account index has a different scope or version.");
            var accountId = encoded.AsSpan(24, 32).ToArray();
            var name = StrictUtf8.GetString(encoded, HeaderLength, length);
            if (NormalizeName(name) != name)
                throw new InvalidDataException(
                    "The DID2 current-account name is not canonical.");
            var complete = await new ProtectedDeepIdV2GenesisBootstrap(
                storage, networkId, accountId).ReadVerifiedAsync(
                trustedUnixSeconds, deploymentProfileId, mlDsa65,
                cancellationToken).ConfigureAwait(false)
                ?? throw new CryptographicException(
                    "The DID2 account index points to partial genesis state.");
            return new(name, accountId, complete);
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    private static string NormalizeName(string displayName)
    {
        ArgumentNullException.ThrowIfNull(displayName);
        var normalized = displayName.Trim().Normalize(NormalizationForm.FormC);
        if (normalized.Length is < 1 or > 64 ||
            normalized.Any(char.IsControl) ||
            StrictUtf8.GetByteCount(normalized) > MaximumNameBytes)
            throw new ArgumentException("The DID2 display name is invalid.",
                nameof(displayName));
        return normalized;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class VerifiedDeepIdV2CurrentAccount(
    string displayName, ReadOnlySpan<byte> accountId,
    VerifiedDeepIdV2LocalGenesis verified) : IDisposable
{
    private readonly byte[] accountId = accountId.ToArray();
    internal string DisplayName { get; } = displayName;
    internal ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    internal VerifiedDeepIdV2LocalGenesis Verified { get; } = verified;

    public void Dispose() => Verified.Dispose();
}
