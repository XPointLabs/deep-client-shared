using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.ContactV1;
using Sodium;

namespace Deep.Client.Shared.Services.MessagingV1;

/// <summary>
/// Retains the recipient's XRA1 metadata-sealing key before publication and
/// reopens it only for the same verified, current local reachability record.
/// Losing the protected key cannot be repaired by silently generating another.
/// </summary>
internal sealed class ReachabilityMetadataSealingKeyAuthority
{
    private static ReadOnlySpan<byte> SlotDomain =>
        "Deep/Client/ContactV1/metadata-sealing-slot/v1"u8;
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private readonly IDeepSecureStorage secureStorage;

    internal ReachabilityMetadataSealingKeyAuthority(IDeepSecureStorage secureStorage) =>
        this.secureStorage = secureStorage ?? throw new ArgumentNullException(nameof(secureStorage));

    internal ValueTask<MetadataSealingPublicBinding> OpenOrCreateForAuthoringAsync(
        DeepLocalIdentitySnapshot identity,
        VerifiedContactRouteProposalAuthority proposal,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(proposal);
        if (identity.Device is null ||
            !Fixed(proposal.NetworkId.Span, identity.NetworkId.Span) ||
            !Fixed(proposal.RecipientDeviceId.Span,
                identity.Device.DeviceId.Bytes.Span) ||
            !Fixed(proposal.RecipientDevicePublicKey.Span,
                identity.Device.SigningPublicKey.Span))
            throw new CryptographicException(
                "The verified XRA1 proposal belongs to another local device.");
        return OpenOrCreateForPmt2ReferenceAsync(
            identity, proposal.Pmt2ArtifactReference, cancellationToken);
    }

#if DEEP_TEST_INTERNALS
    internal ValueTask<MetadataSealingPublicBinding> OpenOrCreateForTestsAsync(
        DeepLocalIdentitySnapshot identity,
        ReadOnlyMemory<byte> exactPmt2Reference,
        CancellationToken cancellationToken = default) =>
        OpenOrCreateForPmt2ReferenceAsync(identity, exactPmt2Reference, cancellationToken);
#endif

    private async ValueTask<MetadataSealingPublicBinding> OpenOrCreateForPmt2ReferenceAsync(
        DeepLocalIdentitySnapshot identity,
        ReadOnlyMemory<byte> exactPmt2Reference,
        CancellationToken cancellationToken = default)
    {
        var slot = Slot(identity, exactPmt2Reference.Span);
        await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var stored = await ReadAsync(slot, cancellationToken).ConfigureAwait(false);
            if (stored is null)
            {
                stored = new byte[64];
                RandomNumberGenerator.Fill(stored.AsSpan(0, 32));
                RandomNumberGenerator.Fill(stored.AsSpan(32, 32));
                try
                {
                    await secureStorage.WriteBatchAsync(
                        [new DeepSecureStorageWrite(slot, stored)], cancellationToken)
                        .ConfigureAwait(false);
                }
                catch
                {
                    CryptographicOperations.ZeroMemory(stored);
                    throw;
                }
            }
            try
            {
                return PublicBinding(stored);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stored);
            }
        }
        finally
        {
            Gate.Release();
        }
    }

    internal async ValueTask<ManagedMessagingDao1OpenAuthority> OpenForCurrentRouteAsync(
        DeepLocalIdentitySnapshot identity,
        VerifiedContactRouteClosure currentRoute,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(currentRoute);
        return await OpenForCurrentAuthorizationAsync(
            identity, currentRoute.Authorization, cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask<ManagedMessagingDao1OpenAuthority> OpenForCurrentRouteAsync(
        DeepLocalIdentitySnapshot identity,
        ParsedContactRouteClosure currentRoute,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(currentRoute);
        return await OpenForCurrentAuthorizationAsync(
            identity, currentRoute.Authorization, cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask<ManagedMessagingDao1OpenAuthority>
        OpenForCurrentAuthorizationAsync(
            DeepLocalIdentitySnapshot identity,
            ContactRecord xra1,
            CancellationToken cancellationToken)
    {
        if (!StringComparer.Ordinal.Equals(xra1.Magic, "XRA1") ||
            !Fixed(xra1.Field(1).Span, identity.NetworkId.Span) ||
            !Fixed(xra1.Field(14).Span, identity.Device.DeviceId.Bytes.Span))
            throw new CryptographicException(
                "The verified XRA1 is not for the current local network and device.");

        var slot = Slot(identity, xra1.Field(5).Span);
        await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var stored = await ReadAsync(slot, cancellationToken).ConfigureAwait(false) ??
                throw new CryptographicException(
                    "The current published XRA1 has no protected metadata-sealing private key.");
            try
            {
                var binding = PublicBinding(stored);
                if (!Fixed(binding.KeyId.Span, xra1.Field(10).Span) ||
                    !Fixed(binding.X25519PublicKey.Span, xra1.Field(11).Span))
                    throw new CryptographicException(
                        "The protected metadata-sealing key differs from the current published XRA1.");
                return new ManagedMessagingDao1OpenAuthority(
                    identity.NetworkId.Span, binding.KeyId.Span,
                    binding.X25519PublicKey.Span, stored.AsSpan(32, 32));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stored);
            }
        }
        finally
        {
            Gate.Release();
        }
    }

    private async Task<byte[]?> ReadAsync(string slot, CancellationToken cancellationToken)
    {
        using var secret = await secureStorage.ReadOwnedAsync(slot, cancellationToken)
            .ConfigureAwait(false);
        if (secret is null) return null;
        if (secret.Length != 64)
            throw new CryptographicException("The protected metadata-sealing key is malformed.");
        var result = new byte[64];
        secret.CopyTo(result);
        if (result.AsSpan(0, 32).IndexOfAnyExcept((byte)0) < 0 ||
            result.AsSpan(32, 32).IndexOfAnyExcept((byte)0) < 0)
        {
            CryptographicOperations.ZeroMemory(result);
            throw new CryptographicException("The protected metadata-sealing key is zero.");
        }
        return result;
    }

    private static MetadataSealingPublicBinding PublicBinding(ReadOnlySpan<byte> stored)
    {
        var scalar = stored.Slice(32, 32).ToArray();
        try
        {
            var publicKey = ScalarMult.Base(scalar);
            try
            {
                if (publicKey.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                    throw new CryptographicException("The metadata-sealing public key is zero.");
                return new MetadataSealingPublicBinding(stored[..32], publicKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scalar);
        }
    }

    private static string Slot(
        DeepLocalIdentitySnapshot identity,
        ReadOnlySpan<byte> exactPmt2Reference)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (identity.StoreGeneration <= 0 || identity.Device is null ||
            exactPmt2Reference.Length != 38 ||
            exactPmt2Reference.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A current local device and exact PMT2 reference are required.");
        if (!identity.Account.AccountIdentity.NetworkId.Matches(identity.NetworkId.Span) ||
            !Fixed(identity.Account.CurrentDeviceId.Bytes.Span,
                identity.Device.DeviceId.Bytes.Span))
            throw new CryptographicException(
                "The metadata-sealing key owner requires the current local account and device.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(SlotDomain);
        hash.AppendData(identity.NetworkId.Span);
        hash.AppendData(identity.Account.AccountIdentity.AccountId.Bytes.Span);
        Span<byte> integer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(integer,
            identity.Account.AccountIdentity.AccountGeneration);
        hash.AppendData(integer);
        hash.AppendData(identity.Device.DeviceId.Bytes.Span);
        BinaryPrimitives.WriteUInt64BigEndian(integer, identity.Device.DeviceGeneration);
        hash.AppendData(integer);
        BinaryPrimitives.WriteInt64BigEndian(integer, identity.StoreGeneration);
        hash.AppendData(integer);
        hash.AppendData(exactPmt2Reference);
        var digest = hash.GetHashAndReset();
        try
        {
            return "deep.store.v1.metadata-sealing." + Convert.ToHexStringLower(digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
            CryptographicOperations.ZeroMemory(integer);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class MetadataSealingPublicBinding
{
    private readonly byte[] keyId;
    private readonly byte[] publicKey;

    internal MetadataSealingPublicBinding(ReadOnlySpan<byte> keyId, ReadOnlySpan<byte> publicKey)
    {
        this.keyId = keyId.ToArray();
        this.publicKey = publicKey.ToArray();
    }

    internal ReadOnlyMemory<byte> KeyId => keyId.ToArray();
    internal ReadOnlyMemory<byte> X25519PublicKey => publicKey.ToArray();
}
