using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Tests.Persistence.PreKeyV1;

internal sealed class OpaquePreKeyV1AuthoringFixture : IDisposable
{
    private const string Mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    private readonly DeepRecoveryAccountCapabilities recovery;
    private readonly OwnedGenesisDeviceSecrets device;
    private readonly Dpk2AuthoringAuthority author;

    private OpaquePreKeyV1AuthoringFixture(
        DeepRecoveryAccountCapabilities recovery,
        OwnedGenesisDeviceSecrets device,
        VerifiedDeviceRelative verifiedDevice,
        Dmd1LineageState currentDirectory)
    {
        this.recovery = recovery;
        this.device = device;
        author = device.CreateDpk2AuthoringAuthority(verifiedDevice);
        CurrentDirectory = currentDirectory;
        AccountIdentity = recovery.AccountIdentity;
        NetworkId = currentDirectory.Head.Record.NetworkId.ToArray();
        AccountId = currentDirectory.Head.Record.DeepAccountId.ToArray();
        DeviceId = verifiedDevice.Certificate.DeviceId.ToArray();
        DeviceGeneration = verifiedDevice.Certificate.DeviceGeneration;
        Dpd1Reference = CanonicalContactReference(
            "DPD1", verifiedDevice.Certificate.CanonicalHash.Span);
        Dpd1Hash = verifiedDevice.Certificate.CanonicalHash.ToArray();
    }

    internal ReadOnlyMemory<byte> NetworkId { get; }
    internal DeepAccountIdentityCapability AccountIdentity { get; }
    internal ReadOnlyMemory<byte> AccountId { get; }
    internal ReadOnlyMemory<byte> DeviceId { get; }
    internal ulong DeviceGeneration { get; }
    internal ReadOnlyMemory<byte> Dpd1Reference { get; }
    internal ReadOnlyMemory<byte> Dpd1Hash { get; }
    internal Dmd1LineageState CurrentDirectory { get; }

    internal static async Task<OpaquePreKeyV1AuthoringFixture> CreateAsync()
    {
        var network = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray();
        var mnemonic = Encoding.ASCII.GetBytes(Mnemonic);
        DeepRecoveryAccountCapabilities? recovery = null;
        OwnedGenesisDeviceSecrets? device = null;
        try
        {
            using (var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(mnemonic))
                recovery = DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 1);
            var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
                recovery, 1_900_000_000, 1);
            device = new OwnedGenesisDeviceSecrets();
            var issued = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery,
                account,
                device,
                new SingleDeviceIssuancePersistence(network),
                1_900_000_100,
                1_900_086_500,
                1_900_172_900);
            var verifiedDevice = issued.IssuedDevice?.Verified ??
                throw new InvalidOperationException("Genesis device issuance did not produce verified evidence.");
            var closure = ApplicationCoreVerifier.CreateIdentityClosure(
                verifiedDevice.Identity, [verifiedDevice]);
            var current = recovery.AuthorGenesisDmd1(closure, 1_900_000_200);
            var result = new OpaquePreKeyV1AuthoringFixture(
                recovery, device, verifiedDevice, current);
            recovery = null;
            device = null;
            return result;
        }
        finally
        {
            device?.Dispose();
            recovery?.Dispose();
            CryptographicOperations.ZeroMemory(network);
            CryptographicOperations.ZeroMemory(mnemonic);
        }
    }

    internal AuthoredDpk2Offering Author(
        Dpk2PrekeyKind kind,
        ulong inventoryEpoch,
        ushort reuseLimit = 0)
    {
        var context = new Dpk2AuthoringContext(
            CurrentDirectory,
            prekeyServiceGeneration: 17,
            inventoryEpoch,
            policyGeneration: 29,
            notBeforeUnixSeconds: 1_900_000_300,
            issuedAtUnixSeconds: 1_900_000_250,
            expiresAtUnixSeconds: 1_900_086_400);
        return kind == Dpk2PrekeyKind.OneTime
            ? author.AuthorOneTime(context)
            : author.AuthorLastResort(context, reuseLimit);
    }

    public void Dispose()
    {
        author.Dispose();
        device.Dispose();
        recovery.Dispose();
    }

    private static byte[] CanonicalContactReference(string magic, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private sealed class SingleDeviceIssuancePersistence(byte[] network)
        : Dnp1IdentityIssuancePersistence
    {
        private static readonly byte[] CatalogKeyId = Bytes(32, 0x31);
        private static readonly byte[] DxrKeyId = Bytes(32, 0x32);
        private static readonly byte[] DxrHmacKey = Bytes(32, 0x41);
        private static readonly byte[] NonceIndexKey = Bytes(32, 0x51);
        private readonly byte[] networkId = network.ToArray();
        private DxpReplayMaterial? material;
        private byte[]? current;
        private ulong revision;
        private ulong subjectRevision;

        protected override ValueTask<UntrustedDxpPersistenceProfileReadResult> ReadProfileCoreAsync(
            DxpPersistenceProfileRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var keyId = NonceIndexKeyId(1, networkId, request.IssuanceScope.Span);
            try
            {
                return ValueTask.FromResult(new UntrustedDxpPersistenceProfileReadResult(
                    CatalogKeyId, DxrKeyId, keyId, 7));
            }
            finally { CryptographicOperations.ZeroMemory(keyId); }
        }

        protected override ValueTask<UntrustedDxpNonceLedgerReadResult> DeriveNonceLedgerCoreAsync(
            DxpNonceLedgerRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ledger = NonceLedgerKey(
                request.SourceKind, request.Role, request.Network.Span,
                request.IssuanceScope.Span, request.Nonce.Span);
            var keyId = NonceIndexKeyId(
                request.SourceKind, request.Network.Span, request.IssuanceScope.Span);
            try
            {
                return ValueTask.FromResult(new UntrustedDxpNonceLedgerReadResult(ledger, keyId));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ledger);
                CryptographicOperations.ZeroMemory(keyId);
            }
        }

        protected override ValueTask<ReadOnlyMemory<byte>> ComputeDxrTagCoreAsync(
            DxpProtectedTagRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!request.ProtectedStateKeyId.Span.SequenceEqual(DxrKeyId))
                throw new CryptographicException("Unexpected protected DXP key role.");
            var domain = Encoding.ASCII.GetBytes(request.Domain);
            var unsigned = request.UnsignedCanonicalDxr1;
            var input = new byte[2 + domain.Length + 2 + 4 + unsigned.Length];
            BinaryPrimitives.WriteUInt16BigEndian(input, checked((ushort)domain.Length));
            domain.CopyTo(input, 2);
            var offset = 2 + domain.Length;
            BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), request.Suite);
            BinaryPrimitives.WriteUInt32BigEndian(
                input.AsSpan(offset + 2), checked((uint)unsigned.Length));
            unsigned.Span.CopyTo(input.AsSpan(offset + 6));
            var tag = HMACSHA256.HashData(DxrHmacKey, input);
            CryptographicOperations.ZeroMemory(input);
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(tag);
        }

        protected override ValueTask<UntrustedDxpReplayReadResult?> ReadByDeviceSubjectCoreAsync(
            DxpDeviceSubjectRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(current is null
                ? null
                : new UntrustedDxpReplayReadResult(current, revision, material, subjectRevision));
        }

        protected override ValueTask<UntrustedDxpReplayReadResult> ReservePendingCoreAsync(
            DxpPendingWriteRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (current is not null)
                return ValueTask.FromResult(new UntrustedDxpReplayReadResult(
                    current, revision, material, subjectRevision));
            material = request.Material;
            current = request.CanonicalDxr1.ToArray();
            revision = 1;
            return ValueTask.FromResult(new UntrustedDxpReplayReadResult(
                current, revision, material, subjectRevision));
        }

        protected override ValueTask<UntrustedDxpReplayReadResult> CompareExchangeVerifiedCoreAsync(
            DxpVerifiedCasRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (current is null || revision != request.ExpectedSourceRevision ||
                !current.AsSpan().SequenceEqual(request.CurrentDxr1.Span))
                throw new CryptographicException("The test DXP exact CAS failed.");
            current = request.NextDxr1.ToArray();
            material = request.Material;
            revision++;
            subjectRevision = 1;
            return ValueTask.FromResult(new UntrustedDxpReplayReadResult(
                current, revision, material, subjectRevision));
        }

        protected override ValueTask<UntrustedDxpReplayReadResult> CompareExchangeAbortedCoreAsync(
            DxpAbortedCasRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The successful fixture must not abort DXP issuance.");

        private static byte[] NonceLedgerKey(
            byte sourceKind,
            byte role,
            ReadOnlySpan<byte> network,
            ReadOnlySpan<byte> scope,
            ReadOnlySpan<byte> nonce)
        {
            const string label = "Deep/ProtectedState/V2/DXP1-nonce-ledger-key";
            var domain = Encoding.ASCII.GetBytes(label);
            var input = new byte[2 + domain.Length + 1 + 16 + 32 + 1 + 32];
            BinaryPrimitives.WriteUInt16BigEndian(input, checked((ushort)domain.Length));
            domain.CopyTo(input, 2);
            var offset = 2 + domain.Length;
            input[offset++] = sourceKind;
            network.CopyTo(input.AsSpan(offset));
            offset += 16;
            scope.CopyTo(input.AsSpan(offset));
            offset += 32;
            input[offset++] = role;
            nonce.CopyTo(input.AsSpan(offset));
            var result = HMACSHA256.HashData(NonceIndexKey, input);
            CryptographicOperations.ZeroMemory(input);
            return result;
        }

        private static byte[] NonceIndexKeyId(
            byte sourceKind,
            ReadOnlySpan<byte> network,
            ReadOnlySpan<byte> scope)
        {
            var input = new byte[1 + 16 + 32 + 32];
            input[0] = sourceKind;
            network.CopyTo(input.AsSpan(1));
            scope.CopyTo(input.AsSpan(17));
            NonceIndexKey.CopyTo(input, 49);
            var result = Sha256Domain(
                "Deep/ProtectedState/V2/DXP1-nonce-index-key-id", input);
            CryptographicOperations.ZeroMemory(input);
            return result;
        }

        private static byte[] Sha256Domain(string label, ReadOnlySpan<byte> value)
        {
            var domain = Encoding.ASCII.GetBytes(label);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            Span<byte> scalar = stackalloc byte[4];
            BinaryPrimitives.WriteUInt16BigEndian(scalar[..2], checked((ushort)domain.Length));
            hash.AppendData(scalar[..2]);
            hash.AppendData(domain);
            BinaryPrimitives.WriteUInt32BigEndian(scalar, checked((uint)value.Length));
            hash.AppendData(scalar);
            hash.AppendData(value);
            return hash.GetHashAndReset();
        }

        private static byte[] Bytes(int length, byte marker) =>
            Enumerable.Repeat(marker, length).ToArray();
    }
}
