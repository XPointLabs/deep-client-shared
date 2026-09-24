using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// One add-only STORE-V2 capability, scoped to the exact public DID2 root.
/// The capability is never copied into DGA1, DPQ2 or a public credential.
/// </summary>
internal sealed class ProtectedDeepIdV2ResolverCapabilityStore
{
    private const string Slot = "deep.store.v2.resolver-read-capability";
    private const int RecordLength = 100;
    private readonly IDeepSecureStorage storage;
    private readonly byte[] networkId;
    private readonly byte[] accountId;

    internal ProtectedDeepIdV2ResolverCapabilityStore(
        IDeepSecureStorage storage, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId)
    {
        this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
        if (networkId.Length != 16 || accountId.Length != 32 ||
            networkId.IndexOfAnyExcept((byte)0) < 0 ||
            accountId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The DID2 capability scope is invalid.");
        this.networkId = networkId.ToArray();
        this.accountId = accountId.ToArray();
    }

    internal async ValueTask WriteVerifiedAsync(
        ParsedDid2 did, ReadOnlyMemory<byte> capability,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(did);
        if (!did.MatchesResolverReadCapability(capability.Span))
            throw new CryptographicException(
                "The resolver capability does not match the exact DID2 commitment.");
        var encoded = new byte[RecordLength];
        try
        {
            "DRC2"u8.CopyTo(encoded);
            networkId.CopyTo(encoded, 4);
            accountId.CopyTo(encoded, 20);
            did.RecordHash.Span.CopyTo(encoded.AsSpan(52));
            capability.Span.CopyTo(encoded.AsSpan(84));
            using var existing = await storage.ReadOwnedAsync(Slot,
                cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                if (existing.Length != RecordLength ||
                    !existing.Use(value => Fixed(value, encoded)))
                    throw new CryptographicException(
                        "The protected DID2 resolver capability changed.");
                return;
            }
            try
            {
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(Slot, encoded)],
                    cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                using var raced = await storage.ReadOwnedAsync(Slot,
                    CancellationToken.None).ConfigureAwait(false);
                if (raced is null || raced.Length != RecordLength ||
                    !raced.Use(value => Fixed(value, encoded)))
                    throw;
            }
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    internal async ValueTask<DeepPermanentIdV2> ReadVerifiedAsync(
        ParsedDid2 did, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(did);
        using var owned = await storage.ReadOwnedAsync(Slot,
            cancellationToken).ConfigureAwait(false) ??
            throw new CryptographicException(
                "The protected DID2 resolver capability is absent.");
        if (owned.Length != RecordLength)
            throw new InvalidDataException(
                "The protected DID2 resolver capability has a hostile size.");
        return owned.Use(value =>
        {
            if (!value[..4].SequenceEqual("DRC2"u8) ||
                !Fixed(value.Slice(4, 16), networkId) ||
                !Fixed(value.Slice(20, 32), accountId) ||
                !Fixed(value.Slice(52, 32), did.RecordHash.Span) ||
                !did.MatchesResolverReadCapability(value.Slice(84, 16)))
                throw new CryptographicException(
                    "The protected resolver capability does not match DID2.");
            return DeepPermanentIdV2.FromCredential(did,
                value.Slice(84, 16));
        });
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
