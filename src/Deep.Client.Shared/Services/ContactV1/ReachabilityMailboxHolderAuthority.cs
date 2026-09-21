using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Client.Shared.Services.ContactV1;

/// <summary>
/// Owns random mailbox holder keys in the current Deep account secure-storage
/// namespace. A key is scoped to one account generation, locator, exact
/// reachability route and grant role; no account/device/recovery key is reused.
/// </summary>
public sealed class ReachabilityMailboxHolderAuthority
{
    private static ReadOnlySpan<byte> SlotDomain =>
        "Deep/Client/ContactV1/mailbox-holder-slot/v1"u8;
    private static readonly SemaphoreSlim MutationGate = new(1, 1);
    private readonly IDeepSecureStorage secureStorage;

    public ReachabilityMailboxHolderAuthority(IDeepSecureStorage secureStorage)
    {
        this.secureStorage = secureStorage ??
            throw new ArgumentNullException(nameof(secureStorage));
    }

    public async ValueTask<ReachabilityMailboxHolderSigner> OpenOrCreateAsync(
        DeepLocalIdentitySnapshot identity,
        VerifiedContactRouteClosure route,
        ReadOnlyMemory<byte> locatorHash,
        MailboxCapabilityDomain domain,
        CancellationToken cancellationToken = default)
    {
        var binding = BoundScope.Create(identity, route, locatorHash, domain);
        await MutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var stored = await secureStorage.ReadOwnedAsync(
                    binding.Slot,
                    cancellationToken)
                .ConfigureAwait(false);
            byte[] seed;
            if (stored is null)
            {
                seed = RandomNumberGenerator.GetBytes(32);
                try
                {
                    await secureStorage.WriteBatchAsync(
                            [new DeepSecureStorageWrite(binding.Slot, seed)],
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                catch
                {
                    CryptographicOperations.ZeroMemory(seed);
                    throw;
                }
            }
            else
            {
                if (stored.Length != 32)
                    throw new CryptographicException(
                        "The protected reachability mailbox holder seed is malformed.");
                seed = new byte[32];
                stored.CopyTo(seed);
            }
            try
            {
                return new ReachabilityMailboxHolderSigner(binding, seed);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
            }
        }
        finally
        {
            MutationGate.Release();
        }
    }

    public async Task DeleteAsync(
        DeepLocalIdentitySnapshot identity,
        VerifiedContactRouteClosure route,
        ReadOnlyMemory<byte> locatorHash,
        MailboxCapabilityDomain domain,
        CancellationToken cancellationToken = default)
    {
        var binding = BoundScope.Create(identity, route, locatorHash, domain);
        await MutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await secureStorage.DeleteBatchAsync([binding.Slot], cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            MutationGate.Release();
        }
    }

    internal sealed class BoundScope
    {
        private BoundScope(
            string slot,
            ReadOnlySpan<byte> networkId,
            ReadOnlySpan<byte> locatorHash,
            ReadOnlySpan<byte> pmt2Reference,
            ReadOnlySpan<byte> pms2Hash,
            MailboxCapabilityDomain domain)
        {
            Slot = slot;
            NetworkId = networkId.ToArray();
            LocatorHash = locatorHash.ToArray();
            Pmt2Reference = pmt2Reference.ToArray();
            Pms2Hash = pms2Hash.ToArray();
            Domain = domain;
        }

        internal string Slot { get; }
        internal byte[] NetworkId { get; }
        internal byte[] LocatorHash { get; }
        internal byte[] Pmt2Reference { get; }
        internal byte[] Pms2Hash { get; }
        internal MailboxCapabilityDomain Domain { get; }

        internal static BoundScope Create(
            DeepLocalIdentitySnapshot identity,
            VerifiedContactRouteClosure route,
            ReadOnlyMemory<byte> locatorHash,
            MailboxCapabilityDomain domain)
        {
            ArgumentNullException.ThrowIfNull(identity);
            ArgumentNullException.ThrowIfNull(route);
            if (domain is not (
                MailboxCapabilityDomain.Deposit or
                MailboxCapabilityDomain.Retrieve))
                throw new ArgumentOutOfRangeException(nameof(domain));
            if (locatorHash.Length != 32 ||
                locatorHash.Span.IndexOfAnyExcept((byte)0) < 0)
                throw new ArgumentException(
                    "A non-zero 32-byte ContactResolve locator is required.",
                    nameof(locatorHash));
            var network = route.Reachability.Field(1);
            if (!identity.Account.AccountIdentity.NetworkId.Matches(network.Span))
                throw new CryptographicException(
                    "The reachability route belongs to another Deep network.");
            var pmt2Reference = ContactCodec.ArtifactReference(
                "PMT2", route.Projection).CanonicalBytes;
            var pms2Hash = route.Selection.ArtifactHash;
            var accountId = identity.Account.AccountIdentity.AccountId.Bytes;
            var generation = identity.Account.AccountIdentity.AccountGeneration;
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData(SlotDomain);
            hash.AppendData(network.Span);
            hash.AppendData(accountId.Span);
            Span<byte> scalar = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(scalar, generation);
            hash.AppendData(scalar);
            hash.AppendData(locatorHash.Span);
            hash.AppendData(route.Reachability.ArtifactHash.Span);
            hash.AppendData([(byte)domain]);
            var digest = hash.GetHashAndReset();
            try
            {
                return new BoundScope(
                    "deep.store.v1.mailbox-holder." +
                        Convert.ToHexStringLower(digest),
                    network.Span,
                    locatorHash.Span,
                    pmt2Reference.Span,
                    pms2Hash.Span,
                    domain);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(digest);
            }
        }
    }

    public sealed class ReachabilityMailboxHolderSigner :
        IReachabilityMailboxHolderSigner,
        IMailboxOperationSigner,
        IDisposable
    {
        private static ReadOnlySpan<byte> Xmg1Domain =>
            "Deep/ContactResolver/V1/XMG1"u8;
        private static readonly int[] Xmg1ProjectionLengths =
            [16, 32, 32, 32, 32, 1, 38, 32, 8, 8, 32];
        private readonly BoundScope binding;
        private byte[]? seed;
        private readonly byte[] publicKey;

        internal ReachabilityMailboxHolderSigner(
            BoundScope binding,
            ReadOnlySpan<byte> seed)
        {
            this.binding = binding;
            this.seed = seed.ToArray();
            var seedCopy = seed.ToArray();
            try
            {
                var pair = PublicKeyAuth.GenerateKeyPair(seedCopy);
                publicKey = pair.PublicKey.ToArray();
                CryptographicOperations.ZeroMemory(pair.PrivateKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seedCopy);
            }
        }

        public ReadOnlyMemory<byte> Ed25519PublicKey => publicKey.ToArray();

        public byte[] GetEd25519PublicKey()
        {
            ObjectDisposedException.ThrowIf(seed is null, this);
            return publicKey.ToArray();
        }

        public async ValueTask<int> SignMailboxGrantRequestAsync(
            ReadOnlyMemory<byte> exactSigningInput,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (signature64.Length < 64)
                throw new ArgumentException(
                    "The XMG1 signature destination is too short.",
                    nameof(signature64));
            ValidateXmg1SigningInput(exactSigningInput.Span);
            var signature = Sign(exactSigningInput.Span);
            try
            {
                signature.CopyTo(signature64);
                await Task.CompletedTask.ConfigureAwait(false);
                return signature.Length;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }

        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> canonicalPresentationSigningBytes)
        {
            ValidateMcp2SigningInput(operation, canonicalPresentationSigningBytes);
            return Sign(canonicalPresentationSigningBytes);
        }

        public void Dispose()
        {
            var current = Interlocked.Exchange(ref seed, null);
            if (current is not null)
                CryptographicOperations.ZeroMemory(current);
        }

        private byte[] Sign(ReadOnlySpan<byte> input)
        {
            var current = Volatile.Read(ref seed) ??
                throw new ObjectDisposedException(nameof(ReachabilityMailboxHolderSigner));
            var seedCopy = current.ToArray();
            try
            {
                var pair = PublicKeyAuth.GenerateKeyPair(seedCopy);
                try
                {
                    return PublicKeyAuth.SignDetached(input.ToArray(), pair.PrivateKey);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pair.PrivateKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seedCopy);
            }
        }

        private void ValidateMcp2SigningInput(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> input)
        {
            var tag = operation switch
            {
                MailboxAuthenticatedOperation.Store => "DEEP-MCP2-STR\0\0\0"u8,
                MailboxAuthenticatedOperation.Retrieve => "DEEP-MCP2-GET\0\0\0"u8,
                MailboxAuthenticatedOperation.Ack => "DEEP-MCP2-ACK\0\0\0"u8,
                _ => throw new ArgumentOutOfRangeException(nameof(operation)),
            };
            const int unsignedPresentationLength =
                MailboxAuthenticatedCapabilityLimits.PresentationLength -
                MailboxAuthenticatedCapabilityLimits.SignatureLength;
            if (input.Length != tag.Length + unsignedPresentationLength ||
                !CryptographicOperations.FixedTimeEquals(input[..tag.Length], tag))
                throw new CryptographicException(
                    "The holder key accepts only exact domain-separated MCP2 signing input.");

            var unsigned = input[tag.Length..];
            if (!unsigned[..4].SequenceEqual("MCP2"u8) ||
                unsigned[4] != 2 ||
                unsigned[5] != (byte)operation ||
                unsigned.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
                BinaryPrimitives.ReadUInt16BigEndian(unsigned.Slice(64, 2)) !=
                    MailboxAuthenticatedCapabilityLimits.GrantLength ||
                unsigned.Slice(66, 6).IndexOfAnyExcept((byte)0) >= 0)
                throw new CryptographicException(
                    "The MCP2 signing input is not canonical.");

            MailboxAuthenticatedGrant grant;
            try
            {
                grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                    unsigned.Slice(
                        72,
                        MailboxAuthenticatedCapabilityLimits.GrantLength));
            }
            catch (MailboxAuthenticatedCapabilityException exception)
            {
                throw new CryptographicException(
                    "The MCP2 signing input contains an invalid MCG2 grant.",
                    exception);
            }
            var expectedDomain = operation == MailboxAuthenticatedOperation.Store
                ? MailboxCapabilityDomain.Deposit
                : MailboxCapabilityDomain.Retrieve;
            if (binding.Domain != expectedDomain ||
                grant.Domain != expectedDomain ||
                !Fixed(grant.NetworkId.Span, binding.NetworkId) ||
                !Fixed(grant.HolderPublicKey.Span, publicKey))
                throw new CryptographicException(
                    "The MCP2 grant differs from the protected reachability holder scope.");
        }

        private void ValidateXmg1SigningInput(ReadOnlySpan<byte> input)
        {
            var header = Xmg1Domain.Length + 7;
            if (input.Length <= header ||
                !input[..Xmg1Domain.Length].SequenceEqual(Xmg1Domain) ||
                input[Xmg1Domain.Length] != 0 ||
                BinaryPrimitives.ReadUInt16BigEndian(
                    input.Slice(Xmg1Domain.Length + 1, 2)) != 0x0201)
                throw new CryptographicException(
                    "The holder key accepts only exact XMG1 signature input.");
            var projectionLength = BinaryPrimitives.ReadUInt32BigEndian(
                input.Slice(Xmg1Domain.Length + 3, 4));
            if (projectionLength != input.Length - header)
                throw new CryptographicException(
                    "The XMG1 signature projection length is invalid.");
            var projection = input[header..];
            if (projection.Length < 12 ||
                !projection[..4].SequenceEqual("XMG1"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(projection.Slice(4, 2)) != 1 ||
                BinaryPrimitives.ReadUInt16BigEndian(projection.Slice(6, 2)) != 0x0201 ||
                BinaryPrimitives.ReadUInt16BigEndian(projection.Slice(8, 2)) !=
                    Xmg1ProjectionLengths.Length ||
                BinaryPrimitives.ReadUInt16BigEndian(projection.Slice(10, 2)) != 0)
                throw new CryptographicException(
                    "The XMG1 signature projection header is not canonical.");
            var offset = 12;
            for (var index = 0; index < Xmg1ProjectionLengths.Length; index++)
            {
                if (projection.Length - offset < 8 ||
                    BinaryPrimitives.ReadUInt16BigEndian(projection[offset..]) != index + 1 ||
                    BinaryPrimitives.ReadUInt16BigEndian(projection[(offset + 2)..]) != 0 ||
                    BinaryPrimitives.ReadUInt32BigEndian(projection[(offset + 4)..]) !=
                        Xmg1ProjectionLengths[index])
                    throw new CryptographicException(
                        "The XMG1 signature projection is not canonical.");
                offset += 8;
                var field = projection.Slice(offset, Xmg1ProjectionLengths[index]);
                if (index == 0 && !Fixed(field, binding.NetworkId) ||
                    index == 2 && !Fixed(field, binding.LocatorHash) ||
                    index == 4 && !Fixed(field, publicKey) ||
                    index == 5 && field[0] != (byte)binding.Domain ||
                    index == 6 && !Fixed(field, binding.Pmt2Reference) ||
                    index == 7 && !Fixed(field, binding.Pms2Hash))
                    throw new CryptographicException(
                        "The XMG1 signature projection differs from the protected reachability scope.");
                offset += field.Length;
            }
            if (offset != projection.Length)
                throw new CryptographicException(
                    "The XMG1 signature projection has trailing bytes.");
        }

        private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
            left.Length == right.Length &&
            CryptographicOperations.FixedTimeEquals(left, right);
    }
}
