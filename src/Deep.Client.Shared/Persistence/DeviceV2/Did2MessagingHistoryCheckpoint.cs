using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Private mandatory history/prefix metadata, not permission to delete
/// SQL or mutate ratchet custody. A producer captures the projection only from
/// already verified SQL; a reader obtains the expected root from owned storage.</summary>
internal sealed class Did2MessagingHistoryCheckpoint
{
    internal const int Bytes = 304;
    private readonly byte[] exact;
    private Did2MessagingHistoryCheckpoint(byte[] exact, Did2MessagingFloor basis)
    { this.exact = exact; Basis = basis; }
    internal ReadOnlyMemory<byte> Exact => exact;
    internal Did2MessagingFloor Basis { get; }
    internal ulong Revision => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(4));
    internal ulong HistoryCount => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(296));
    internal ReadOnlySpan<byte> InitialHeaderHash => exact.AsSpan(232, 32);
    internal ReadOnlySpan<byte> HistoryDigest => exact.AsSpan(264, 32);
    internal static string Slot(Did2MessagingSessionScope scope) => scope.FloorSlot + ".history";

    internal static Did2MessagingHistoryCheckpoint RegisteredEmpty(Did2MessagingSessionScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        var raw = new byte[Bytes]; raw[0] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(4), 1);
        scope.Hash.CopyTo(raw.AsSpan(12)); Did2MessagingFloor.Empty(scope).Exact.Span.CopyTo(raw.AsSpan(44));
        return Decode(raw, scope);
    }
    internal static Did2MessagingHistoryCheckpoint Decode(ReadOnlySpan<byte> raw, Did2MessagingSessionScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (raw.Length != Bytes || raw[0] != 1 || !Did2MessagingSessionScope.Zero(raw.Slice(1, 3)) ||
            !Did2MessagingSessionScope.Fixed(raw.Slice(12, 32), scope.Hash))
            throw new InvalidDataException("Messaging history checkpoint is absent, foreign or unsupported.");
        var revision = BinaryPrimitives.ReadUInt64BigEndian(raw[4..]);
        var count = BinaryPrimitives.ReadUInt64BigEndian(raw[296..]);
        var basis = Did2MessagingFloor.Decode(raw.Slice(44, Did2MessagingFloor.Bytes), scope);
        if (revision == 0 || basis.Phase != 1 || basis.Ordinal > long.MaxValue)
            throw new InvalidDataException("Messaging history checkpoint has an invalid revision or basis.");
        if (basis.Ordinal == 0)
        {
            if (revision != 1 || count != 0 || !Did2MessagingSessionScope.Zero(raw[232..]))
                throw new InvalidDataException("Messaging empty history checkpoint is not canonical.");
        }
        else if (revision < 2 || basis.Status != 1 || basis.Ordinal < 2 || count > basis.Ordinal - 2 ||
            Did2MessagingSessionScope.Zero(raw.Slice(232, 32)) || Did2MessagingSessionScope.Zero(raw.Slice(264, 32)))
            throw new InvalidDataException("Messaging history checkpoint lost its active prefix commitments.");
        return new(raw.ToArray(), basis);
    }

    // Encodes facts, not authorization. The actual plan/owner must independently
    // authenticate all dependencies and before/after SQL effects before CAS.
    internal Did2MessagingHistoryCheckpoint NextProjection(Did2MessagingSessionScope scope,
        Did2MessagingFloor basis, ReadOnlySpan<byte> initialHeader, ReadOnlySpan<byte> digest, ulong count)
    {
        _ = Decode(Exact.Span, scope); _ = Did2MessagingFloor.Decode(basis.Exact.Span, scope);
        if (basis.Ordinal <= Basis.Ordinal || basis.RatchetGeneration < Basis.RatchetGeneration || count < HistoryCount ||
            initialHeader.Length != Did2MessagingFloor.MetadataBytes || digest.Length != 32)
            throw new InvalidDataException("Messaging history projection is not a forward exact prefix.");
        if (Basis.Ordinal != 0 && !Did2MessagingSessionScope.Fixed(SHA256.HashData(initialHeader), InitialHeaderHash))
            throw new CryptographicException("Messaging history projection cannot replace its initial evidence.");
        var raw = exact.ToArray();
        try
        {
            BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(4), checked(Revision + 1));
            basis.Exact.Span.CopyTo(raw.AsSpan(44)); SHA256.HashData(initialHeader, raw.AsSpan(232, 32));
            digest.CopyTo(raw.AsSpan(264)); BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(296), count);
            return Decode(raw, scope);
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    internal static async Task<Did2MessagingHistoryCheckpoint> ReadRegisteredAsync(
        IDeepSecureStorage storage, Did2MessagingSessionScope scope, CancellationToken ct)
    {
        using var owned = await storage.ReadOwnedAsync(Slot(scope), ct).ConfigureAwait(false)
            ?? throw new InvalidDataException("Mandatory messaging history checkpoint is absent; no initialization is permitted.");
        ct.ThrowIfCancellationRequested(); return owned.Use(bytes => Decode(bytes, scope));
    }
}
