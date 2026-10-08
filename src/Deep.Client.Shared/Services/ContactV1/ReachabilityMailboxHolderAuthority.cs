using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Client.Shared.Services.ContactV1;

/// <summary>Narrow DID2 route-bound holder signer. No public key creation,
/// seed/storage access or legacy identity owner; durable account custody must
/// be supplied by the account owner before this internal factory is used.</summary>
public static class ReachabilityMailboxHolderAuthority
{
    // Internal signer scope, not a proof of publication or an installation
    // capability. The actual held account owner supplies the original records
    // and its private protected-root/current-source continuation.
    internal static ReachabilityMailboxHolderSigner OpenRetainedRead(
        ParsedContactRouteClosure route, ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash, ReadOnlyMemory<byte> ownerCapability,
        ReadOnlySpan<byte> retainedSeed, Func<CancellationToken, Task> recheck)
    {
        ArgumentNullException.ThrowIfNull(recheck);
        if (retainedSeed.Length != 32 || retainedSeed.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("An exact nonzero retained holder seed is required.");
        var binding = BoundScope.CreateRetainedRead(route, networkId, locatorHash, ownerCapability, recheck);
        try { return new(binding, retainedSeed); }
        catch { binding.Dispose(); throw; }
    }

    internal static ReachabilityMailboxHolderSigner OpenRetained(
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> roleCapability, MailboxCapabilityDomain domain,
        ReadOnlySpan<byte> retainedSeed)
    {
        ArgumentNullException.ThrowIfNull(route);
        if (retainedSeed.Length != 32 || retainedSeed.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("An exact nonzero retained holder seed is required.");
        var binding = BoundScope.Create(route, locatorHash, roleCapability, domain);
        try { return new(binding, retainedSeed); }
        catch { binding.Dispose(); throw; }
    }

    internal sealed class BoundScope : IDisposable
    {
        private BoundScope(VerifiedDeepIdV2ContactRouteClosure route,
            ReadOnlySpan<byte> locator, ReadOnlySpan<byte> capability, MailboxCapabilityDomain domain)
            : this(route.Route, route.Network.NetworkId, locator, capability, domain,
                token => route.EnsureCurrentAsync(token).AsTask())
        { }

        private BoundScope(ParsedContactRouteClosure route, ReadOnlyMemory<byte> network,
            ReadOnlySpan<byte> locator, ReadOnlySpan<byte> capability, MailboxCapabilityDomain domain,
            Func<CancellationToken, Task> recheck)
        {
            Recheck = recheck;
            NetworkId = network.ToArray();
            LocatorHash = locator.ToArray(); RoleCapability = capability.ToArray();
            Pmt2Reference = ContactCodec.ArtifactReference("PMT2", route.Projection).CanonicalBytes.ToArray();
            Pms2Hash = route.Selection.ArtifactHash.ToArray();
            ExactRouteHash = route.ExactHash.ToArray();
            SelectionInput = route.Selection.Field(3).ToArray();
            PlacementCommitment = MailboxPlacementCommitment.Compute(new BlindedPlacementId(route.Reachability.Field(10).Span));
            Epoch = BinaryPrimitives.ReadUInt64BigEndian(route.Selection.Field(4).Span);
            Domain = domain;
        }
        internal Func<CancellationToken, Task> Recheck { get; }
        internal byte[] NetworkId { get; }
        internal byte[] LocatorHash { get; }
        internal byte[] RoleCapability { get; }
        internal byte[] Pmt2Reference { get; }
        internal byte[] Pms2Hash { get; }
        internal byte[] ExactRouteHash { get; }
        internal byte[] SelectionInput { get; }
        internal byte[] PlacementCommitment { get; }
        internal ulong Epoch { get; }
        internal MailboxCapabilityDomain Domain { get; }
        internal static BoundScope CreateRetainedRead(ParsedContactRouteClosure route, ReadOnlyMemory<byte> network,
            ReadOnlyMemory<byte> locator, ReadOnlyMemory<byte> capability, Func<CancellationToken, Task> recheck)
        {
            ArgumentNullException.ThrowIfNull(route);
            route = ContactRouteClosureCodec.Decode(route.ExactBytes.Span);
            if (network.Length != 16 || !CryptographicOperations.FixedTimeEquals(network.Span, route.Reachability.Field(1).Span) ||
                locator.Length != 32 || locator.Span.IndexOfAnyExcept((byte)0) < 0 ||
                capability.Length != 32 || capability.Span.IndexOfAnyExcept((byte)0) < 0 ||
                CryptographicOperations.FixedTimeEquals(capability.Span, route.Reachability.Field(10).Span))
                throw new CryptographicException("Retained holder requires its exact original private Retrieve scope.");
            return new(route, network, locator.Span, capability.Span, MailboxCapabilityDomain.Retrieve, recheck);
        }
        internal static BoundScope Create(VerifiedDeepIdV2ContactRouteClosure route,
            ReadOnlyMemory<byte> locator, ReadOnlyMemory<byte> capability, MailboxCapabilityDomain domain)
        {
            if (domain is not (MailboxCapabilityDomain.Deposit or MailboxCapabilityDomain.Retrieve))
                throw new ArgumentOutOfRangeException(nameof(domain));
            if (locator.Length != 32 || locator.Span.IndexOfAnyExcept((byte)0) < 0 ||
                capability.Length != 32 || capability.Span.IndexOfAnyExcept((byte)0) < 0)
                throw new ArgumentException("Exact nonzero holder locator/capability scope is required.");
            var deposit = route.Route.Reachability.Field(10);
            var matchesDeposit = CryptographicOperations.FixedTimeEquals(capability.Span, deposit.Span);
            if (domain == MailboxCapabilityDomain.Deposit && !matchesDeposit ||
                domain == MailboxCapabilityDomain.Retrieve && matchesDeposit)
                throw new CryptographicException("The holder role/capability differs from its DID2 route.");
            return new(route, locator.Span, capability.Span, domain);
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(RoleCapability);
    }

    public sealed class ReachabilityMailboxHolderSigner :
        IReachabilityMailboxHolderSigner,
        IMailboxOperationSigner,
        IDisposable
    {
        private static ReadOnlySpan<byte> Xmg2Domain =>
            "Deep/ContactResolver/V2/XMG2"u8;
        private static readonly int[] Xmg2ProjectionLengths =
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

        public ReadOnlyMemory<byte> Ed25519PublicKey
        { get { ObjectDisposedException.ThrowIf(seed is null, this); return publicKey.ToArray(); } }

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
                    "The XMG2 signature destination is too short.",
                    nameof(signature64));
            ValidateXmg2SigningInput(exactSigningInput.Span);
            await binding.Recheck(cancellationToken).ConfigureAwait(false);
            var signature = Sign(exactSigningInput.Span);
            try
            {
                signature.CopyTo(signature64);
                await binding.Recheck(cancellationToken).ConfigureAwait(false);
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
            ValidateMcp3SigningInput(operation, canonicalPresentationSigningBytes);
            return Sign(canonicalPresentationSigningBytes);
        }

        public void Dispose()
        {
            var current = Interlocked.Exchange(ref seed, null);
            if (current is not null)
                CryptographicOperations.ZeroMemory(current);
            binding.Dispose();
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

        private void ValidateMcp3SigningInput(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> input)
        {
            var tag = operation switch
            {
                MailboxAuthenticatedOperation.Store => "DEEP-MCP3-STR\0\0\0"u8,
                MailboxAuthenticatedOperation.Retrieve => "DEEP-MCP3-GET\0\0\0"u8,
                MailboxAuthenticatedOperation.Ack => "DEEP-MCP3-ACK\0\0\0"u8,
                _ => throw new ArgumentOutOfRangeException(nameof(operation)),
            };
            const int unsignedPresentationLength =
                MailboxAuthenticatedCapabilityLimits.PresentationLength -
                MailboxAuthenticatedCapabilityLimits.SignatureLength;
            if (input.Length != tag.Length + unsignedPresentationLength ||
                !CryptographicOperations.FixedTimeEquals(input[..tag.Length], tag))
                throw new CryptographicException(
                    "The holder key accepts only exact domain-separated MCP3 signing input.");

            var unsigned = input[tag.Length..];
            if (!unsigned[..4].SequenceEqual("MCP3"u8) ||
                unsigned[4] != 3 ||
                unsigned[5] != (byte)operation ||
                unsigned.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
                BinaryPrimitives.ReadUInt16BigEndian(unsigned.Slice(64, 2)) !=
                    MailboxAuthenticatedCapabilityLimits.GrantLength ||
                unsigned.Slice(66, 6).IndexOfAnyExcept((byte)0) >= 0)
                throw new CryptographicException(
                    "The MCP3 signing input is not canonical.");

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
                    "The MCP3 signing input contains an invalid MCG3 grant.",
                    exception);
            }
            var expectedDomain = operation == MailboxAuthenticatedOperation.Store
                ? MailboxCapabilityDomain.Deposit
                : MailboxCapabilityDomain.Retrieve;
            if (binding.Domain != expectedDomain ||
                grant.Domain != expectedDomain ||
                grant.Epoch != binding.Epoch ||
                !Fixed(grant.SelectionInput.Span, binding.SelectionInput) ||
                !Fixed(grant.PlacementCommitment.Span, binding.PlacementCommitment) ||
                !Fixed(grant.NetworkId.Span, binding.NetworkId) ||
                !Fixed(grant.HolderPublicKey.Span, publicKey))
                throw new CryptographicException(
                    "The MCP3 grant differs from the protected reachability holder scope.");
        }

        private void ValidateXmg2SigningInput(ReadOnlySpan<byte> input)
        {
            var header = Xmg2Domain.Length + 7;
            if (input.Length <= header ||
                !input[..Xmg2Domain.Length].SequenceEqual(Xmg2Domain) ||
                input[Xmg2Domain.Length] != 0 ||
                BinaryPrimitives.ReadUInt16BigEndian(
                    input.Slice(Xmg2Domain.Length + 1, 2)) != 0x0201)
                throw new CryptographicException(
                    "The holder key accepts only exact XMG2 signature input.");
            var projectionLength = BinaryPrimitives.ReadUInt32BigEndian(
                input.Slice(Xmg2Domain.Length + 3, 4));
            if (projectionLength != 363 || projectionLength != input.Length - header)
                throw new CryptographicException(
                    "The XMG2 signature projection length is invalid.");
            var projection = input[header..];
            if (projection.Length < 12 ||
                !projection[..4].SequenceEqual("XMG2"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(projection.Slice(4, 2)) != 1 ||
                BinaryPrimitives.ReadUInt16BigEndian(projection.Slice(6, 2)) != 0x0201 ||
                BinaryPrimitives.ReadUInt16BigEndian(projection.Slice(8, 2)) !=
                    Xmg2ProjectionLengths.Length ||
                BinaryPrimitives.ReadUInt16BigEndian(projection.Slice(10, 2)) != 0)
                throw new CryptographicException(
                    "The XMG2 signature projection header is not canonical.");
            var offset = 12;
            for (var index = 0; index < Xmg2ProjectionLengths.Length; index++)
            {
                if (projection.Length - offset < 8 ||
                    BinaryPrimitives.ReadUInt16BigEndian(projection[offset..]) != index + 1 ||
                    BinaryPrimitives.ReadUInt16BigEndian(projection[(offset + 2)..]) != 0 ||
                    BinaryPrimitives.ReadUInt32BigEndian(projection[(offset + 4)..]) !=
                        Xmg2ProjectionLengths[index])
                    throw new CryptographicException(
                        "The XMG2 signature projection is not canonical.");
                offset += 8;
                var field = projection.Slice(offset, Xmg2ProjectionLengths[index]);
                if (index == 0 && !Fixed(field, binding.NetworkId) ||
                    index == 2 && !Fixed(field, binding.LocatorHash) ||
                    index == 3 && !Fixed(field, binding.RoleCapability) ||
                    index == 4 && !Fixed(field, publicKey) ||
                    index == 5 && field[0] != (byte)binding.Domain ||
                    index == 6 && !Fixed(field, binding.Pmt2Reference) ||
                    index == 7 && !Fixed(field, binding.Pms2Hash) ||
                    index == 10 && !Fixed(field, binding.ExactRouteHash))
                    throw new CryptographicException(
                        "The XMG2 signature projection differs from the protected reachability scope.");
                offset += field.Length;
            }
            if (offset != projection.Length)
                throw new CryptographicException(
                    "The XMG2 signature projection has trailing bytes.");
        }

        private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
            left.Length == right.Length &&
            CryptographicOperations.FixedTimeEquals(left, right);
    }
}
