using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV1;

/// <summary>
/// Add-only, crash-recoverable DXP1 persistence for the single generation-one
/// device created with a local Deep account. Every phase and nonce reservation is
/// an immutable protected-storage slot, so a process loss cannot replace the
/// winning replay tuple or reuse its nonce.
/// </summary>
internal sealed class ProtectedGenesisDeviceIssuancePersistence :
    Dnp1IdentityIssuancePersistence
{
    private const byte SourceKind = 1;
    private const ulong ProfileRevision = 1;
    private const int ProfileBytes = 4 + 1 + 3 + (4 * 32) + 8;
    private const int MaterialBytes = (2 * 573) + 776 + 168 + 88 + (2 * 38) +
        (3 * 32) + 8 + 32;
    private const int StateHeaderBytes = 4 + 1 + 1 + 2 + 8 + 8 + 573 + 1;
    private static readonly byte[] ProfileMagic = "DXP1"u8.ToArray();
    private static readonly byte[] StateMagic = "DXS1"u8.ToArray();
    private readonly IDeepSecureStorage storage;
    private readonly string prefix;
    private readonly byte[] networkId;
    private readonly SemaphoreSlim gate = new(1, 1);

    internal ProtectedGenesisDeviceIssuancePersistence(
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
        this.networkId = networkId.ToArray();
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(scope, digest);
        prefix = $"deep.store.v1.{Convert.ToHexStringLower(digest[..16])}.dxp";
        CryptographicOperations.ZeroMemory(scope);
        CryptographicOperations.ZeroMemory(digest);
    }

    protected override async ValueTask<UntrustedDxpPersistenceProfileReadResult>
        ReadProfileCoreAsync(
            DxpPersistenceProfileRequest request,
            CancellationToken cancellationToken)
    {
        var profile = await GetOrCreateProfileAsync(request, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var nonceKeyId = NonceIndexKeyId(
                SourceKind,
                profile.NonceIndexKey,
                networkId,
                request.IssuanceScope.Span);
            try
            {
                if (Fixed(profile.CatalogKeyId, profile.DxrKeyId) ||
                    Fixed(profile.CatalogKeyId, nonceKeyId) ||
                    Fixed(profile.DxrKeyId, nonceKeyId))
                    throw new CryptographicException(
                        "Protected DXP key roles are not distinct.");
                return new UntrustedDxpPersistenceProfileReadResult(
                    profile.CatalogKeyId,
                    profile.DxrKeyId,
                    nonceKeyId,
                    ProfileRevision);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nonceKeyId);
            }
        }
        finally
        {
            profile.Dispose();
        }
    }

    protected override async ValueTask<UntrustedDxpNonceLedgerReadResult>
        DeriveNonceLedgerCoreAsync(
            DxpNonceLedgerRequest request,
            CancellationToken cancellationToken)
    {
        var profile = await ReadProfileAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("The protected DXP profile is unavailable.");
        try
        {
            var ledger = NonceLedgerKey(
                request.SourceKind,
                request.Role,
                profile.NonceIndexKey,
                request.Network.Span,
                request.IssuanceScope.Span,
                request.Nonce.Span);
            var keyId = NonceIndexKeyId(
                request.SourceKind,
                profile.NonceIndexKey,
                request.Network.Span,
                request.IssuanceScope.Span);
            try
            {
                return new UntrustedDxpNonceLedgerReadResult(ledger, keyId);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ledger);
                CryptographicOperations.ZeroMemory(keyId);
            }
        }
        finally
        {
            profile.Dispose();
        }
    }

    protected override async ValueTask<ReadOnlyMemory<byte>> ComputeDxrTagCoreAsync(
        DxpProtectedTagRequest request,
        CancellationToken cancellationToken)
    {
        var profile = await ReadProfileAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("The protected DXP profile is unavailable.");
        try
        {
            if (!Fixed(request.ProtectedStateKeyId.Span, profile.DxrKeyId))
                throw new CryptographicException("The protected DXP HMAC key role changed.");
            var domain = Encoding.ASCII.GetBytes(request.Domain);
            var unsigned = request.UnsignedCanonicalDxr1;
            var input = new byte[2 + domain.Length + 2 + 4 + unsigned.Length];
            try
            {
                BinaryPrimitives.WriteUInt16BigEndian(
                    input, checked((ushort)domain.Length));
                domain.CopyTo(input, 2);
                var offset = 2 + domain.Length;
                BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), request.Suite);
                BinaryPrimitives.WriteUInt32BigEndian(
                    input.AsSpan(offset + 2), checked((uint)unsigned.Length));
                unsigned.Span.CopyTo(input.AsSpan(offset + 6));
                return HMACSHA256.HashData(profile.DxrHmacKey, input);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }
        finally
        {
            profile.Dispose();
        }
    }

    protected override async ValueTask<UntrustedDxpReplayReadResult?>
        ReadByDeviceSubjectCoreAsync(
            DxpDeviceSubjectRequest request,
            CancellationToken cancellationToken)
    {
        var subject = SubjectPrefix(request.DeviceSubjectKey.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ReadWinnerAsync(subject, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    protected override async ValueTask<UntrustedDxpReplayReadResult>
        ReservePendingCoreAsync(
            DxpPendingWriteRequest request,
            CancellationToken cancellationToken)
    {
        var subject = SubjectPrefix(request.Material.DeviceSubjectKey.Span);
        var pendingSlot = subject + ".pending";
        var ledgerSlot = NonceSlot(request.Material);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var existing = await ReadWinnerAsync(subject, cancellationToken)
                .ConfigureAwait(false);
            if (existing is not null) return existing;
            using (var ledger = await storage.ReadOwnedAsync(ledgerSlot, cancellationToken)
                       .ConfigureAwait(false))
            {
                if (ledger is not null)
                    throw new CryptographicException("A protected DXP nonce was already reserved.");
            }

            var state = EncodeState(
                phase: 0,
                revision: 1,
                subjectRevision: 0,
                request.CanonicalDxr1.Span,
                request.Material);
            var marker = SHA256.HashData(request.CanonicalDxr1.Span);
            try
            {
                await storage.WriteBatchAsync(
                    [
                        new DeepSecureStorageWrite(pendingSlot, state),
                        new DeepSecureStorageWrite(ledgerSlot, marker)
                    ],
                    cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                var raced = await ReadWinnerAsync(subject, CancellationToken.None)
                    .ConfigureAwait(false);
                if (raced is not null) return raced;
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(state);
                CryptographicOperations.ZeroMemory(marker);
            }
            return await ReadWinnerAsync(subject, cancellationToken).ConfigureAwait(false)
                ?? throw new IOException("The protected DXP pending row disappeared after commit.");
        }
        finally
        {
            gate.Release();
        }
    }

    protected override async ValueTask<UntrustedDxpReplayReadResult>
        CompareExchangeVerifiedCoreAsync(
            DxpVerifiedCasRequest request,
            CancellationToken cancellationToken)
    {
        var subject = SubjectPrefix(request.DeviceSubjectKey.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var verified = await ReadStateAsync(subject + ".verified", cancellationToken)
                .ConfigureAwait(false);
            if (verified is not null) return verified;
            if (await ReadStateAsync(subject + ".aborted", cancellationToken)
                    .ConfigureAwait(false) is not null)
                throw new CryptographicException("The protected DXP subject is already aborted.");
            var pending = await ReadStateAsync(subject + ".pending", cancellationToken)
                .ConfigureAwait(false)
                ?? throw new CryptographicException("The protected DXP pending row is missing.");
            if (pending.DxrSourceRevision != request.ExpectedSourceRevision ||
                !Fixed(pending.CurrentCanonicalDxr1.Span, request.CurrentDxr1.Span) ||
                pending.SubjectRevision != 0 || pending.Material is null ||
                !SameMaterial(pending.Material, request.Material) ||
                !request.ExpectedDeviceSubjectAbsent ||
                !Fixed(request.NewSubjectHead.Span, request.Material.NewSubjectHead.Span) ||
                !Fixed(request.CanonicalDpd1.Span, request.Material.CanonicalDpd1.Span))
                throw new CryptographicException("The protected DXP verified CAS is not exact.");

            var state = EncodeState(
                phase: 1,
                revision: checked(pending.DxrSourceRevision + 1),
                subjectRevision: 1,
                request.NextDxr1.Span,
                request.Material);
            try
            {
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(subject + ".verified", state)],
                    cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                verified = await ReadStateAsync(subject + ".verified", CancellationToken.None)
                    .ConfigureAwait(false);
                if (verified is not null) return verified;
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(state);
            }
            return await ReadStateAsync(subject + ".verified", cancellationToken)
                .ConfigureAwait(false)
                ?? throw new IOException("The protected DXP verified row disappeared after commit.");
        }
        finally
        {
            gate.Release();
        }
    }

    protected override async ValueTask<UntrustedDxpReplayReadResult>
        CompareExchangeAbortedCoreAsync(
            DxpAbortedCasRequest request,
            CancellationToken cancellationToken)
    {
        var subject = SubjectPrefix(request.DeviceSubjectKey.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (await ReadStateAsync(subject + ".verified", cancellationToken)
                    .ConfigureAwait(false) is not null)
                throw new CryptographicException("A verified DXP subject cannot be aborted.");
            var aborted = await ReadStateAsync(subject + ".aborted", cancellationToken)
                .ConfigureAwait(false);
            if (aborted is not null) return aborted;
            var pending = await ReadStateAsync(subject + ".pending", cancellationToken)
                .ConfigureAwait(false)
                ?? throw new CryptographicException("The protected DXP pending row is missing.");
            if (pending.DxrSourceRevision != request.ExpectedSourceRevision ||
                !Fixed(pending.CurrentCanonicalDxr1.Span, request.CurrentDxr1.Span) ||
                pending.SubjectRevision != 0)
                throw new CryptographicException("The protected DXP abort CAS is not exact.");
            var state = EncodeState(
                phase: 2,
                revision: checked(pending.DxrSourceRevision + 1),
                subjectRevision: 0,
                request.AbortedDxr1.Span,
                material: null);
            try
            {
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(subject + ".aborted", state)],
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(state);
            }
            return await ReadStateAsync(subject + ".aborted", cancellationToken)
                .ConfigureAwait(false)
                ?? throw new IOException("The protected DXP aborted row disappeared after commit.");
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<Profile> GetOrCreateProfileAsync(
        DxpPersistenceProfileRequest request,
        CancellationToken cancellationToken)
    {
        var existing = await ReadProfileAsync(cancellationToken).ConfigureAwait(false);
        if (existing is not null) return existing;
        var values = new byte[4][];
        try
        {
            for (var index = 0; index < values.Length; index++)
            {
                var candidate = Nonzero32();
                if (values.Take(index).Any(prior => Fixed(prior, candidate)))
                {
                    CryptographicOperations.ZeroMemory(candidate);
                    index--;
                    continue;
                }
                values[index] = candidate;
            }
            var encoded = EncodeProfile(values[0], values[1], values[2], values[3]);
            try
            {
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(prefix + ".profile", encoded)],
                    cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                var raced = await ReadProfileAsync(CancellationToken.None)
                    .ConfigureAwait(false);
                if (raced is not null) return raced;
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
            return await ReadProfileAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new IOException("The protected DXP profile disappeared after commit.");
        }
        finally
        {
            foreach (var value in values)
                if (value is not null) CryptographicOperations.ZeroMemory(value);
        }
    }

    private async Task<Profile?> ReadProfileAsync(CancellationToken cancellationToken)
    {
        using var owned = await storage.ReadOwnedAsync(prefix + ".profile", cancellationToken)
            .ConfigureAwait(false);
        if (owned is null) return null;
        byte[]? bytes = null;
        try
        {
            owned.Use(value => bytes = value.ToArray());
            return DecodeProfile(bytes!);
        }
        finally
        {
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task<UntrustedDxpReplayReadResult?> ReadWinnerAsync(
        string subject,
        CancellationToken cancellationToken)
    {
        var verified = await ReadStateAsync(subject + ".verified", cancellationToken)
            .ConfigureAwait(false);
        var aborted = await ReadStateAsync(subject + ".aborted", cancellationToken)
            .ConfigureAwait(false);
        if (verified is not null && aborted is not null)
            throw new CryptographicException("The protected DXP subject has conflicting terminals.");
        return verified ?? aborted ??
            await ReadStateAsync(subject + ".pending", cancellationToken).ConfigureAwait(false);
    }

    private async Task<UntrustedDxpReplayReadResult?> ReadStateAsync(
        string slot,
        CancellationToken cancellationToken)
    {
        using var owned = await storage.ReadOwnedAsync(slot, cancellationToken)
            .ConfigureAwait(false);
        if (owned is null) return null;
        byte[]? bytes = null;
        try
        {
            owned.Use(value => bytes = value.ToArray());
            return DecodeState(bytes!);
        }
        finally
        {
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private string SubjectPrefix(ReadOnlySpan<byte> subject)
    {
        if (subject.Length != 88 || subject.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The protected DXP subject must be exact88.");
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(subject, digest);
        var result = prefix + ".subject." + Convert.ToHexStringLower(digest[..16]);
        CryptographicOperations.ZeroMemory(digest);
        return result;
    }

    private string NonceSlot(DxpReplayMaterial material)
    {
        ArgumentNullException.ThrowIfNull(material);
        var dxp = material.ExactDxp1.Span;
        if (dxp.Length != 168 || dxp.Slice(120, 32).IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The protected DXP1 nonce is malformed.");
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(dxp.Slice(120, 32), digest);
        var result = prefix + ".nonce." + Convert.ToHexStringLower(digest);
        CryptographicOperations.ZeroMemory(digest);
        return result;
    }

    private static byte[] EncodeProfile(
        ReadOnlySpan<byte> catalog,
        ReadOnlySpan<byte> dxr,
        ReadOnlySpan<byte> hmac,
        ReadOnlySpan<byte> nonce)
    {
        var result = new byte[ProfileBytes];
        ProfileMagic.CopyTo(result, 0);
        result[4] = 1;
        catalog.CopyTo(result.AsSpan(8, 32));
        dxr.CopyTo(result.AsSpan(40, 32));
        hmac.CopyTo(result.AsSpan(72, 32));
        nonce.CopyTo(result.AsSpan(104, 32));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(136), ProfileRevision);
        return result;
    }

    private static Profile DecodeProfile(ReadOnlySpan<byte> value)
    {
        if (value.Length != ProfileBytes || !value[..4].SequenceEqual(ProfileMagic) ||
            value[4] != 1 || value.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(value[136..]) != ProfileRevision)
            throw new InvalidDataException("The protected DXP profile is malformed.");
        return new Profile(
            value.Slice(8, 32), value.Slice(40, 32),
            value.Slice(72, 32), value.Slice(104, 32));
    }

    private static byte[] EncodeState(
        byte phase,
        ulong revision,
        ulong subjectRevision,
        ReadOnlySpan<byte> current,
        DxpReplayMaterial? material)
    {
        if (phase > 2 || revision == 0 || current.Length != 573 ||
            (material is null) != (phase == 2))
            throw new ArgumentException("The protected DXP state is malformed.");
        var result = new byte[StateHeaderBytes + (material is null ? 0 : MaterialBytes)];
        StateMagic.CopyTo(result, 0);
        result[4] = 1;
        result[5] = phase;
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(8), revision);
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(16), subjectRevision);
        current.CopyTo(result.AsSpan(24, 573));
        result[597] = material is null ? (byte)0 : (byte)1;
        if (material is not null)
        {
            var encodedMaterial = EncodeMaterial(material);
            try
            {
                encodedMaterial.CopyTo(result, StateHeaderBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encodedMaterial);
            }
        }
        return result;
    }

    private static UntrustedDxpReplayReadResult DecodeState(ReadOnlySpan<byte> value)
    {
        if (value.Length < StateHeaderBytes || !value[..4].SequenceEqual(StateMagic) ||
            value[4] != 1 || value[5] > 2 || value.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("The protected DXP state header is malformed.");
        var revision = BinaryPrimitives.ReadUInt64BigEndian(value[8..]);
        var subjectRevision = BinaryPrimitives.ReadUInt64BigEndian(value[16..]);
        var hasMaterial = value[597] == 1;
        if (revision == 0 || value[597] > 1 ||
            value.Length != StateHeaderBytes + (hasMaterial ? MaterialBytes : 0))
            throw new InvalidDataException("The protected DXP state shape is malformed.");
        var material = hasMaterial ? DecodeMaterial(value[StateHeaderBytes..]) : null;
        return new UntrustedDxpReplayReadResult(
            value.Slice(24, 573), revision, material, subjectRevision);
    }

    private static byte[] EncodeMaterial(DxpReplayMaterial value)
    {
        var output = new byte[MaterialBytes];
        var offset = 0;
        Put(value.CanonicalPendingDxr1.Span);
        Put(value.CanonicalVerifiedDxr1.Span);
        Put(value.CanonicalDpd1.Span);
        Put(value.ExactDxp1.Span);
        Put(value.DeviceSubjectKey.Span);
        Put(value.ExpectedSubjectPredecessor.Span);
        Put(value.NewSubjectHead.Span);
        Put(value.IdentityCatalogKeyId.Span);
        Put(value.DxrKeyId.Span);
        Put(value.NonceIndexKeyId.Span);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset), value.ProfileSourceRevision);
        offset += 8;
        Put(value.ProtectedTag.Span);
        if (offset != MaterialBytes) throw new InvalidOperationException("DXP material size drifted.");
        if (BinaryPrimitives.ReadUInt64BigEndian(output.AsSpan(MaterialBytes - 40, 8)) == 0)
            throw new InvalidOperationException("DXP material profile revision was not encoded.");
        return output;

        void Put(ReadOnlySpan<byte> bytes)
        {
            bytes.CopyTo(output.AsSpan(offset));
            offset += bytes.Length;
        }
    }

    private static DxpReplayMaterial DecodeMaterial(ReadOnlySpan<byte> value)
    {
        var offset = 0;
        var pending = value.Slice(offset, 573).ToArray(); offset += 573;
        var verified = value.Slice(offset, 573).ToArray(); offset += 573;
        var dpd = value.Slice(offset, 776).ToArray(); offset += 776;
        var dxp = value.Slice(offset, 168).ToArray(); offset += 168;
        var subject = value.Slice(offset, 88).ToArray(); offset += 88;
        var predecessor = value.Slice(offset, 38).ToArray(); offset += 38;
        var head = value.Slice(offset, 38).ToArray(); offset += 38;
        var catalog = value.Slice(offset, 32).ToArray(); offset += 32;
        var dxr = value.Slice(offset, 32).ToArray(); offset += 32;
        var nonce = value.Slice(offset, 32).ToArray(); offset += 32;
        var revision = BinaryPrimitives.ReadUInt64BigEndian(value[offset..]);
        offset += 8;
        var tag = value.Slice(offset, 32).ToArray(); offset += 32;
        if (offset != MaterialBytes) throw new InvalidDataException("DXP material size drifted.");
        if (revision == 0)
            throw new InvalidDataException("The protected DXP material has no profile revision.");
        if (subject.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            head.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            catalog.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            dxr.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            nonce.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            tag.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("The protected DXP material lost a required role.");
        if (Fixed(catalog, dxr) || Fixed(catalog, nonce) || Fixed(dxr, nonce))
            throw new InvalidDataException("The protected DXP material collapsed distinct roles.");
        return new DxpReplayMaterial(
            pending, verified, dpd, dxp, subject, predecessor, head,
            catalog, dxr, nonce, revision, tag);
    }

    private static bool SameMaterial(DxpReplayMaterial left, DxpReplayMaterial right) =>
        Fixed(left.CanonicalPendingDxr1.Span, right.CanonicalPendingDxr1.Span) &&
        Fixed(left.CanonicalVerifiedDxr1.Span, right.CanonicalVerifiedDxr1.Span) &&
        Fixed(left.CanonicalDpd1.Span, right.CanonicalDpd1.Span) &&
        Fixed(left.ExactDxp1.Span, right.ExactDxp1.Span) &&
        Fixed(left.DeviceSubjectKey.Span, right.DeviceSubjectKey.Span) &&
        Fixed(left.ExpectedSubjectPredecessor.Span, right.ExpectedSubjectPredecessor.Span) &&
        Fixed(left.NewSubjectHead.Span, right.NewSubjectHead.Span) &&
        Fixed(left.IdentityCatalogKeyId.Span, right.IdentityCatalogKeyId.Span) &&
        Fixed(left.DxrKeyId.Span, right.DxrKeyId.Span) &&
        Fixed(left.NonceIndexKeyId.Span, right.NonceIndexKeyId.Span) &&
        left.ProfileSourceRevision == right.ProfileSourceRevision &&
        Fixed(left.ProtectedTag.Span, right.ProtectedTag.Span);

    private static byte[] NonceLedgerKey(
        byte sourceKind,
        byte role,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> scope,
        ReadOnlySpan<byte> nonce)
    {
        var domain = Encoding.ASCII.GetBytes("Deep/ProtectedState/V2/DXP1-nonce-ledger-key");
        var input = new byte[2 + domain.Length + 1 + 16 + 32 + 1 + 32];
        try
        {
            BinaryPrimitives.WriteUInt16BigEndian(input, checked((ushort)domain.Length));
            domain.CopyTo(input, 2);
            var offset = 2 + domain.Length;
            input[offset++] = sourceKind;
            network.CopyTo(input.AsSpan(offset)); offset += 16;
            scope.CopyTo(input.AsSpan(offset)); offset += 32;
            input[offset++] = role;
            nonce.CopyTo(input.AsSpan(offset));
            return HMACSHA256.HashData(key, input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static byte[] NonceIndexKeyId(
        byte sourceKind,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> scope)
    {
        if (network.Length != 16)
            throw new CryptographicException("The protected DXP network scope is malformed.");
        var input = new byte[1 + 16 + 32 + 32];
        try
        {
            input[0] = sourceKind;
            network.CopyTo(input.AsSpan(1));
            scope.CopyTo(input.AsSpan(17));
            key.CopyTo(input.AsSpan(49));
            return Sha256Domain(
                "Deep/ProtectedState/V2/DXP1-nonce-index-key-id", input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
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

    private static byte[] Nonzero32()
    {
        var result = new byte[32];
        do RandomNumberGenerator.Fill(result);
        while (result.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return result;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed class Profile(
        ReadOnlySpan<byte> catalogKeyId,
        ReadOnlySpan<byte> dxrKeyId,
        ReadOnlySpan<byte> dxrHmacKey,
        ReadOnlySpan<byte> nonceIndexKey) : IDisposable
    {
        internal byte[] CatalogKeyId { get; } = catalogKeyId.ToArray();
        internal byte[] DxrKeyId { get; } = dxrKeyId.ToArray();
        internal byte[] DxrHmacKey { get; } = dxrHmacKey.ToArray();
        internal byte[] NonceIndexKey { get; } = nonceIndexKey.ToArray();

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(CatalogKeyId);
            CryptographicOperations.ZeroMemory(DxrKeyId);
            CryptographicOperations.ZeroMemory(DxrHmacKey);
            CryptographicOperations.ZeroMemory(NonceIndexKey);
        }
    }
}
