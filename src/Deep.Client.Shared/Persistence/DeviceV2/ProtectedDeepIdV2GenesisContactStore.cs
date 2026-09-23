using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// Add-only, account-scoped custody for the exact PQ-backed genesis public
/// closure. Raw read returns untrusted bytes; verified read rechecks the entire
/// DPA1/DRS1/DPD1/DMD1/DID2/DAB2/DCA1 V2/ADC1 V2 lineage after restart.
/// This V2 namespace has no V1 reader or fallback.
/// </summary>
internal sealed class ProtectedDeepIdV2GenesisContactStore
{
    private const int HeaderLength = 40;
    private const int MaximumDrs1Length = 16_384;
    private const int MaximumDmd1Length = 57_344;
    private static readonly int MaximumRecordLength = checked(HeaderLength + 644 +
        MaximumDrs1Length + 776 + MaximumDmd1Length +
        DeepIdV2Codec.Did2Length + DeepIdV2Codec.Dab2Length +
        DeepIdV2ContactAuthorizationCodec.CanonicalLength +
        DeepIdV2AccountDirectoryCodec.CanonicalLength);
    private static readonly byte[] Magic = "DGC2"u8.ToArray();
    private readonly IDeepSecureStorage storage;
    private readonly string slot;
    private readonly byte[] networkId;
    private readonly byte[] accountId;

    internal ProtectedDeepIdV2GenesisContactStore(IDeepSecureStorage storage,
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
        slot = "deep.store.v2." + Convert.ToHexStringLower(digest) +
            ".genesis-contact";
        CryptographicOperations.ZeroMemory(scope);
        CryptographicOperations.ZeroMemory(digest);
    }

    internal async ValueTask WriteVerifiedAsync(VerifiedDab2 binding,
        VerifiedDca1V2 authorization, VerifiedAdc1V2 checkpoint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(checkpoint);
        if (binding.Record.BindingGeneration != 0 ||
            checkpoint.Checkpoint.CheckpointGeneration != 0 ||
            checkpoint.Checkpoint.MinimumReader < 2 ||
            checkpoint.RevokedDcaAuthorizationCount != 0 ||
            binding.Identity.ActiveDevices.Count != 1 ||
            !Fixed(binding.Identity.Account.Certificate.NetworkId.Span, networkId) ||
            !Fixed(binding.Identity.Account.DeepAccountIdHash.Span, accountId) ||
            !Fixed(authorization.Binding.Record.CanonicalBytes.Span,
                binding.Record.CanonicalBytes.Span) ||
            !Fixed(checkpoint.Binding.Record.CanonicalBytes.Span,
                binding.Record.CanonicalBytes.Span) ||
            !Fixed(authorization.Directory.Record.CanonicalBytes.Span,
                checkpoint.Directory.Record.CanonicalBytes.Span))
            throw new CryptographicException(
                "Verified DID2 genesis contact closure is cross-sourced or out of scope.");

        var encoded = Encode(
            binding.Identity.Account.Certificate.CanonicalBytes.Span,
            binding.Identity.Revocations.Snapshot.CanonicalBytes.Span,
            binding.Identity.ActiveDevices.Single().Certificate.CanonicalBytes.Span,
            checkpoint.Directory.Record.CanonicalBytes.Span,
            binding.DeepId.CanonicalBytes.Span,
            binding.Record.CanonicalBytes.Span,
            authorization.Record.CanonicalBytes.Span,
            checkpoint.Checkpoint.CanonicalBytes.Span);
        try
        {
            using var current = await storage.ReadOwnedAsync(slot,
                cancellationToken).ConfigureAwait(false);
            if (current is not null)
            {
                if (current.Length != encoded.Length ||
                    !current.Use(value => Fixed(value, encoded)))
                    throw new CryptographicException(
                        "The protected DID2 genesis contact winner differs.");
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

    internal async ValueTask<UntrustedDeepIdV2GenesisContactEvidence?>
        ReadUntrustedAsync(CancellationToken cancellationToken)
    {
        using var owned = await storage.ReadOwnedAsync(slot,
            cancellationToken).ConfigureAwait(false);
        if (owned is null) return null;
        if (owned.Length < HeaderLength || owned.Length > MaximumRecordLength)
            throw new InvalidDataException(
                "Protected DID2 contact record has a hostile size.");
        var encoded = new byte[owned.Length];
        owned.CopyTo(encoded);
        try { return Decode(encoded); }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    internal async ValueTask<VerifiedDeepIdV2GenesisContactEvidence?>
        ReadVerifiedAsync(ulong trustedUnixSeconds,
            ushort deploymentProfileId, IDeepMlDsa65Verifier mlDsa65,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(mlDsa65);
        if (trustedUnixSeconds == 0)
            throw new ArgumentOutOfRangeException(nameof(trustedUnixSeconds));
        var untrusted = await ReadUntrustedAsync(cancellationToken)
            .ConfigureAwait(false);
        if (untrusted is null) return null;
        var request = new DeepIdV2GenesisAdmissionRequest(
            untrusted.ExactDpa1.Span, untrusted.ExactDrs1.Span,
            [untrusted.ExactDpd1], untrusted.ExactDid2.Span,
            untrusted.ExactDab2.Span, untrusted.ExactDmd1.Span,
            untrusted.ExactAdc1V2.Span, []);
        var checkpoint = DeepIdV2GenesisAdmissionVerifier.Verify(request,
            trustedUnixSeconds, deploymentProfileId, 2, mlDsa65);
        var binding = checkpoint.Binding;
        var directory = checkpoint.Directory;
        if (!Fixed(binding.Identity.Account.Certificate.NetworkId.Span, networkId) ||
            !Fixed(binding.Identity.Account.DeepAccountIdHash.Span, accountId))
            throw new CryptographicException(
                "Restored DID2 authority has a different account scope.");
        var authorization = DeepIdV2ContactAuthorizationCodec.Verify(
            DeepIdV2ContactAuthorizationCodec.Decode(
                untrusted.ExactDca1V2.Span), binding, directory);
        return new(binding, directory, authorization, checkpoint);
    }

    private static byte[] Encode(ReadOnlySpan<byte> dpa,
        ReadOnlySpan<byte> drs, ReadOnlySpan<byte> dpd,
        ReadOnlySpan<byte> dmd,
        ReadOnlySpan<byte> did, ReadOnlySpan<byte> dab,
        ReadOnlySpan<byte> dca, ReadOnlySpan<byte> adc)
    {
        if (dpa.Length != 644 ||
            drs.Length is < 1 or > MaximumDrs1Length ||
            dpd.Length != 776 ||
            dmd.Length is < 1 or > MaximumDmd1Length ||
            did.Length != DeepIdV2Codec.Did2Length ||
            dab.Length != DeepIdV2Codec.Dab2Length ||
            dca.Length != DeepIdV2ContactAuthorizationCodec.CanonicalLength ||
            adc.Length != DeepIdV2AccountDirectoryCodec.CanonicalLength)
            throw new InvalidDataException("DID2 genesis contact artifact length is invalid.");
        var result = new byte[checked(HeaderLength + dpa.Length + drs.Length +
            dpd.Length + dmd.Length + did.Length + dab.Length +
            dca.Length + adc.Length)];
        Magic.CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 2);
        var lengths = new[] { dpa.Length, drs.Length, dpd.Length, dmd.Length,
            did.Length, dab.Length, dca.Length, adc.Length };
        for (var index = 0; index < lengths.Length; index++)
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8 + index * 4),
                checked((uint)lengths[index]));
        var offset = HeaderLength;
        dpa.CopyTo(result.AsSpan(offset)); offset += dpa.Length;
        drs.CopyTo(result.AsSpan(offset)); offset += drs.Length;
        dpd.CopyTo(result.AsSpan(offset)); offset += dpd.Length;
        dmd.CopyTo(result.AsSpan(offset)); offset += dmd.Length;
        did.CopyTo(result.AsSpan(offset)); offset += did.Length;
        dab.CopyTo(result.AsSpan(offset)); offset += dab.Length;
        dca.CopyTo(result.AsSpan(offset)); offset += dca.Length;
        adc.CopyTo(result.AsSpan(offset));
        return result;
    }

    private static UntrustedDeepIdV2GenesisContactEvidence Decode(
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < HeaderLength ||
            !encoded[..4].SequenceEqual(Magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded[4..]) != 2 ||
            encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Protected DID2 contact record is malformed.");
        Span<int> lengths = stackalloc int[8];
        for (var index = 0; index < lengths.Length; index++)
            lengths[index] = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                encoded.Slice(8 + index * 4, 4)));
        if (lengths[0] != 644 ||
            lengths[1] is < 1 or > MaximumDrs1Length ||
            lengths[2] != 776 ||
            lengths[3] is < 1 or > MaximumDmd1Length ||
            lengths[4] != DeepIdV2Codec.Did2Length ||
            lengths[5] != DeepIdV2Codec.Dab2Length ||
            lengths[6] != DeepIdV2ContactAuthorizationCodec.CanonicalLength ||
            lengths[7] != DeepIdV2AccountDirectoryCodec.CanonicalLength ||
            encoded.Length != checked(HeaderLength + lengths.ToArray().Sum()))
            throw new InvalidDataException("Protected DID2 contact record has a hostile size.");
        var offset = HeaderLength;
        var dpa = encoded.Slice(offset, lengths[0]).ToArray(); offset += lengths[0];
        var drs = encoded.Slice(offset, lengths[1]).ToArray(); offset += lengths[1];
        var dpd = encoded.Slice(offset, lengths[2]).ToArray(); offset += lengths[2];
        var dmd = encoded.Slice(offset, lengths[3]).ToArray(); offset += lengths[3];
        var did = encoded.Slice(offset, lengths[4]).ToArray(); offset += lengths[4];
        var dab = encoded.Slice(offset, lengths[5]).ToArray(); offset += lengths[5];
        var dca = encoded.Slice(offset, lengths[6]).ToArray(); offset += lengths[6];
        var adc = encoded.Slice(offset, lengths[7]).ToArray();
        try
        {
            _ = IdentityCodec.DecodeAccountCertificate(dpa);
            _ = IdentityCodec.DecodeRevocationSnapshot(drs);
            _ = IdentityCodec.DecodeDeviceCertificate(dpd);
            _ = ApplicationCoreCodec.DecodeDmd1(dmd);
            _ = DeepIdV2Codec.DecodeDid2(did);
            _ = DeepIdV2Codec.DecodeDab2(dab);
            _ = DeepIdV2ContactAuthorizationCodec.Decode(dca);
            _ = DeepIdV2AccountDirectoryCodec.Decode(adc);
            return new(dpa, drs, dpd, dmd, did, dab, dca, adc);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dpa);
            CryptographicOperations.ZeroMemory(drs);
            CryptographicOperations.ZeroMemory(dpd);
            CryptographicOperations.ZeroMemory(dmd);
            CryptographicOperations.ZeroMemory(did);
            CryptographicOperations.ZeroMemory(dab);
            CryptographicOperations.ZeroMemory(dca);
            CryptographicOperations.ZeroMemory(adc);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed record VerifiedDeepIdV2GenesisContactEvidence(
    VerifiedDab2 Binding, VerifiedDmd1 Directory,
    VerifiedDca1V2 Authorization, VerifiedAdc1V2 Checkpoint);

internal sealed class UntrustedDeepIdV2GenesisContactEvidence
{
    private readonly byte[] dpa;
    private readonly byte[] drs;
    private readonly byte[] dpd;
    private readonly byte[] dmd;
    private readonly byte[] did;
    private readonly byte[] dab;
    private readonly byte[] dca;
    private readonly byte[] adc;

    internal UntrustedDeepIdV2GenesisContactEvidence(ReadOnlySpan<byte> dpa,
        ReadOnlySpan<byte> drs, ReadOnlySpan<byte> dpd,
        ReadOnlySpan<byte> dmd,
        ReadOnlySpan<byte> did, ReadOnlySpan<byte> dab,
        ReadOnlySpan<byte> dca, ReadOnlySpan<byte> adc)
    {
        this.dpa = dpa.ToArray();
        this.drs = drs.ToArray();
        this.dpd = dpd.ToArray();
        this.dmd = dmd.ToArray();
        this.did = did.ToArray();
        this.dab = dab.ToArray();
        this.dca = dca.ToArray();
        this.adc = adc.ToArray();
    }

    internal ReadOnlyMemory<byte> ExactDpa1 => dpa.ToArray();
    internal ReadOnlyMemory<byte> ExactDrs1 => drs.ToArray();
    internal ReadOnlyMemory<byte> ExactDpd1 => dpd.ToArray();
    internal ReadOnlyMemory<byte> ExactDmd1 => dmd.ToArray();
    internal ReadOnlyMemory<byte> ExactDid2 => did.ToArray();
    internal ReadOnlyMemory<byte> ExactDab2 => dab.ToArray();
    internal ReadOnlyMemory<byte> ExactDca1V2 => dca.ToArray();
    internal ReadOnlyMemory<byte> ExactAdc1V2 => adc.ToArray();
}
