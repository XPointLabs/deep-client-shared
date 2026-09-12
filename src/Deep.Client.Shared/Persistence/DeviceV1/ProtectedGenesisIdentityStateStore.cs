using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV1;

/// <summary>
/// Add-only protected storage for the exact signed genesis identity closure.
/// DXP1 owns DPD1 recovery separately; this store seals DPA1/DRS1 before device
/// issuance and DMD1 only after the verifier-minted device is available.
/// </summary>
internal sealed class ProtectedGenesisIdentityStateStore
{
    private const int MaximumArtifactBytes = 16 * 1024;
    private static readonly byte[] AccountMagic = "DGA1"u8.ToArray();
    private static readonly byte[] DirectoryMagic = "DGD1"u8.ToArray();
    private readonly IDeepSecureStorage storage;
    private readonly string accountSlot;
    private readonly string directorySlot;

    internal ProtectedGenesisIdentityStateStore(
        IDeepSecureStorage storage,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId)
    {
        this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0 ||
            accountId.Length != 32 || accountId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero network/account scope is required.");
        Span<byte> scope = stackalloc byte[48];
        networkId.CopyTo(scope);
        accountId.CopyTo(scope[16..]);
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(scope, digest);
        var prefix = "deep.store.v1." + Convert.ToHexStringLower(digest) + ".genesis";
        accountSlot = prefix + ".account";
        directorySlot = prefix + ".directory";
        CryptographicOperations.ZeroMemory(scope);
        CryptographicOperations.ZeroMemory(digest);
    }

    internal async Task<ProtectedGenesisAccountEvidence?> ReadAccountAsync(
        CancellationToken cancellationToken)
    {
        var encoded = await ReadAsync(accountSlot, cancellationToken).ConfigureAwait(false);
        if (encoded is null) return null;
        try
        {
            return DecodeAccount(encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    internal async Task WriteAccountAsync(
        ReadOnlyMemory<byte> canonicalDpa1,
        ReadOnlyMemory<byte> canonicalDrs1,
        CancellationToken cancellationToken)
    {
        var encoded = EncodeAccount(canonicalDpa1.Span, canonicalDrs1.Span);
        try
        {
            await WriteImmutableAsync(accountSlot, encoded, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    internal async Task<byte[]?> ReadDirectoryAsync(CancellationToken cancellationToken)
    {
        var encoded = await ReadAsync(directorySlot, cancellationToken).ConfigureAwait(false);
        if (encoded is null) return null;
        try
        {
            return DecodeDirectory(encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    internal async Task WriteDirectoryAsync(
        ReadOnlyMemory<byte> canonicalDmd1,
        CancellationToken cancellationToken)
    {
        var encoded = EncodeDirectory(canonicalDmd1.Span);
        try
        {
            await WriteImmutableAsync(directorySlot, encoded, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    internal async Task<bool> IsCompleteAsync(CancellationToken cancellationToken)
    {
        using var account = await storage.ReadOwnedAsync(accountSlot, cancellationToken)
            .ConfigureAwait(false);
        if (account is null) return false;
        using var directory = await storage.ReadOwnedAsync(directorySlot, cancellationToken)
            .ConfigureAwait(false);
        return directory is not null;
    }

    private async Task WriteImmutableAsync(
        string slot,
        byte[] encoded,
        CancellationToken cancellationToken)
    {
        var existing = await ReadAsync(slot, cancellationToken).ConfigureAwait(false);
        try
        {
            if (existing is not null)
            {
                if (!CryptographicOperations.FixedTimeEquals(existing, encoded))
                    throw new CryptographicException(
                        "Protected genesis evidence conflicts with the durable winner.");
                return;
            }
            try
            {
                await storage.WriteBatchAsync(
                        [new DeepSecureStorageWrite(slot, encoded)],
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                existing = await ReadAsync(slot, CancellationToken.None).ConfigureAwait(false);
                if (existing is null ||
                    !CryptographicOperations.FixedTimeEquals(existing, encoded))
                    throw;
            }
        }
        finally
        {
            if (existing is not null) CryptographicOperations.ZeroMemory(existing);
        }
    }

    private async Task<byte[]?> ReadAsync(string slot, CancellationToken cancellationToken)
    {
        using var owned = await storage.ReadOwnedAsync(slot, cancellationToken)
            .ConfigureAwait(false);
        if (owned is null) return null;
        var result = new byte[owned.Length];
        owned.CopyTo(result);
        return result;
    }

    private static byte[] EncodeAccount(ReadOnlySpan<byte> dpa, ReadOnlySpan<byte> drs)
    {
        RequireArtifact(dpa, nameof(dpa));
        RequireArtifact(drs, nameof(drs));
        var result = new byte[16 + dpa.Length + drs.Length];
        AccountMagic.CopyTo(result, 0);
        result[4] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), checked((uint)dpa.Length));
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(12), checked((uint)drs.Length));
        dpa.CopyTo(result.AsSpan(16));
        drs.CopyTo(result.AsSpan(16 + dpa.Length));
        return result;
    }

    private static ProtectedGenesisAccountEvidence DecodeAccount(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < 18 || !encoded[..4].SequenceEqual(AccountMagic) ||
            encoded[4] != 1 || encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Protected genesis account evidence is malformed.");
        var dpaLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded[8..]));
        var drsLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded[12..]));
        if (dpaLength is < 1 or > MaximumArtifactBytes ||
            drsLength is < 1 or > MaximumArtifactBytes ||
            encoded.Length != 16 + dpaLength + drsLength)
            throw new InvalidDataException("Protected genesis account evidence has a hostile size.");
        return new ProtectedGenesisAccountEvidence(
            encoded.Slice(16, dpaLength),
            encoded.Slice(16 + dpaLength, drsLength));
    }

    private static byte[] EncodeDirectory(ReadOnlySpan<byte> dmd)
    {
        RequireArtifact(dmd, nameof(dmd));
        var result = new byte[12 + dmd.Length];
        DirectoryMagic.CopyTo(result, 0);
        result[4] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), checked((uint)dmd.Length));
        dmd.CopyTo(result.AsSpan(12));
        return result;
    }

    private static byte[] DecodeDirectory(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < 13 || !encoded[..4].SequenceEqual(DirectoryMagic) ||
            encoded[4] != 1 || encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Protected genesis directory evidence is malformed.");
        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded[8..]));
        if (length is < 1 or > MaximumArtifactBytes || encoded.Length != 12 + length)
            throw new InvalidDataException("Protected genesis directory evidence has a hostile size.");
        return encoded[12..].ToArray();
    }

    private static void RequireArtifact(ReadOnlySpan<byte> value, string parameterName)
    {
        if (value.Length is < 1 or > MaximumArtifactBytes ||
            value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero bounded canonical artifact is required.", parameterName);
    }
}

internal sealed class ProtectedGenesisAccountEvidence
{
    private readonly byte[] dpa;
    private readonly byte[] drs;

    internal ProtectedGenesisAccountEvidence(ReadOnlySpan<byte> dpa, ReadOnlySpan<byte> drs)
    {
        this.dpa = dpa.ToArray();
        this.drs = drs.ToArray();
    }

    internal ReadOnlyMemory<byte> CanonicalDpa1 => dpa.ToArray();
    internal ReadOnlyMemory<byte> CanonicalDrs1 => drs.ToArray();
}
