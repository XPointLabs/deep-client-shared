using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Closed local fork evidence, never minted from remote ciphertext.</summary>
internal sealed class Did2OwnedSendConflict
{
    private readonly byte[] operation, commitment;
    private Did2OwnedSendConflict(Did2MessagingSessionScope scope, Did2MessagingFloor floor,
        ReadOnlySpan<byte> operation, ReadOnlySpan<byte> incumbentHash, ReadOnlySpan<byte> conflictingHash)
    {
        Scope = scope; Floor = floor; this.operation = operation.ToArray();
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("Deep/STORE-V2/messaging-owned-send-conflict"u8); digest.AppendData([0]);
        digest.AppendData(scope.Hash); digest.AppendData(floor.Head); digest.AppendData(operation);
        digest.AppendData(incumbentHash); digest.AppendData(conflictingHash); commitment = digest.GetHashAndReset();
    }
    internal Did2MessagingSessionScope Scope { get; }
    internal Did2MessagingFloor Floor { get; }
    internal ReadOnlySpan<byte> Operation => operation;
    internal ReadOnlySpan<byte> Commitment => commitment;

    internal static Did2OwnedSendConflict Verify(Did2MessagingSqlJournal sql, Did2MessagingSessionScope scope,
        Did2MessagingFloor floor, ReadOnlySpan<byte> operation, ReadOnlySpan<byte> exactLocalDmc2)
    {
        // The SQL reader independently verifies its actual scope/full floor and
        // retained event. No caller hash or boolean stands in for this row.
        sql.RequireScope(scope);
        var parsed = ApplicationCoreCodec.DecodeDmc2(exactLocalDmc2);
        if (!Did2MessagingSessionScope.Fixed(parsed.NetworkId.Span, scope.Network) ||
            !Did2MessagingSessionScope.Fixed(parsed.SenderAccountId.Span, scope.LocalAccount) ||
            !Did2MessagingSessionScope.Fixed(parsed.SenderDeviceId.Span, scope.LocalDevice))
            throw new CryptographicException("Owned-send conflict does not belong to the local endpoint.");
        using var retained = sql.ReadVerifiedOperation(floor, operation);
        var hash = SHA256.HashData(exactLocalDmc2);
        if (retained is null || retained.Direction != 1 || Did2MessagingSessionScope.Fixed(retained.EventHash, hash))
            throw new CryptographicException("Owned-send conflict has no verified differing local send.");
        return new(scope, floor, operation, retained.EventHash, hash);
    }
}
