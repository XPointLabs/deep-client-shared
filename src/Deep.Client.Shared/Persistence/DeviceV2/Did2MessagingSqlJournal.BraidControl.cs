using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed class OwnedDid2BraidControlPersistedEvent : IDisposable
{
    private byte[]? frame;
    internal OwnedDid2BraidControlPersistedEvent(int direction, ulong ordinal, byte[] frame)
    { Direction = direction; Ordinal = ordinal; this.frame = frame; }
    internal int Direction { get; }
    internal ulong Ordinal { get; }
    internal ReadOnlySpan<byte> ExactControl => frame ?? throw new ObjectDisposedException(nameof(OwnedDid2BraidControlPersistedEvent));
    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref frame, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

internal sealed partial class Did2MessagingSqlJournal
{
    // Classification is a verified native-history read, never a raw SQL flag
    // or permission supplied to a transport callback by the caller.
    internal int? ReadVerifiedNativeEventDirection(Did2MessagingFloor stable, ReadOnlySpan<byte> operation)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation);
        _ = Did2MessagingFloor.Decode(stable.Exact.Span, scope);
        if (stable.Phase != 1 || stable.Status != 1)
            throw new InvalidDataException("Native event classification requires active stable custody.");
        RequireSame(stable, VerifyTip());
        using var command = Command("SELECT direction,ordinal,length(envelope),typeof(envelope),length(plaintext),typeof(plaintext),envelope,plaintext,metadata,length(metadata),typeof(metadata) FROM events WHERE operation=$op;");
        command.Parameters.AddWithValue("$op", operation.ToArray()); using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        var direction = row.GetInt32(0); var ordinal = row.GetInt64(1);
        if (direction is < 1 or > 4 || ordinal < 1 || (ulong)ordinal > stable.Ordinal ||
            row.GetString(3) != "blob" || row.GetInt64(2) is < 1 or > 65536 ||
            (direction is 3 or 4 && row.GetInt64(2) != Dbr2Codec.TotalBytes) ||
            row.GetString(10) != "blob" || row.GetInt64(9) != Did2MessagingFloor.MetadataBytes ||
            (direction == 2 ? row.GetString(5) != "blob" || row.GetInt64(4) is < 1 or > 33082 :
                row.GetString(5) != "null" || !row.IsDBNull(4)))
            throw new InvalidDataException("Native event classification has changed shape.");
        var exact = row.GetFieldValue<byte[]>(6); var plaintext = direction == 2 ? row.GetFieldValue<byte[]>(7) : [];
        try
        {
            VerifyHistoricalEvent((ulong)ordinal, direction, operation, row.GetFieldValue<byte[]>(8), exact, plaintext);
            if (row.Read()) throw new InvalidDataException("Native event operation is not unique.");
            return direction;
        }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal bool HasVerifiedPeerBraidPurposeProgress(Did2MessagingFloor stable, ulong braidEpoch, CancellationToken ct)
    {
        if (braidEpoch == 0 || braidEpoch == ulong.MaxValue)
            throw new InvalidDataException("Braid purpose has an invalid epoch.");
        var progressed = false;
        // Do not return early: consuming the complete owned enumeration also
        // verifies its final tip. These are actual authenticated direction2
        // native events, including independently protected compacted history.
        foreach (var received in ReadVerifiedIncomingEvents(stable, ct))
        {
            var data = Dpe2Codec.Decode(received.ExactEnvelope);
            if (!Fixed(data.NetworkId.Span, scope.Network) || !Fixed(data.SessionId.Span, scope.Session) ||
                !Fixed(data.SenderDeviceId.Span, scope.RemoteDevice) || !Fixed(data.RecipientDeviceId.Span, scope.LocalDevice))
                throw new CryptographicException("Peer progress lost its native session/direction.");
            if (data.RatchetHeader.SckaSendingEpoch >= braidEpoch) progressed = true;
        }
        return progressed;
    }

    internal OwnedDid2BraidControlPersistedEvent? ReadVerifiedBraidControl(Did2MessagingFloor stable, ReadOnlySpan<byte> operation)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation);
        _ = Did2MessagingFloor.Decode(stable.Exact.Span, scope);
        if (stable.Phase != 1 || stable.Status != 1)
            throw new InvalidDataException("Braid control read-back requires the active stable floor.");
        RequireSame(stable, VerifyTip());
        using var command = Command("SELECT direction,ordinal,length(envelope),envelope,plaintext,metadata FROM events WHERE operation=$op;");
        command.Parameters.AddWithValue("$op", operation.ToArray()); using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        var direction = row.GetInt32(0); var ordinal = row.GetInt64(1);
        if (direction is not (3 or 4) || ordinal < 1 || (ulong)ordinal > stable.Ordinal ||
            row.GetInt64(2) != Dbr2Codec.TotalBytes || !row.IsDBNull(4))
            throw new CryptographicException("Braid control operation collides with data or has changed custody.");
        var exact = row.GetFieldValue<byte[]>(3);
        try
        {
            var metadata = row.GetFieldValue<byte[]>(5);
            VerifyHistoricalEvent((ulong)ordinal, direction, operation, metadata, exact, []);
            if (row.Read()) throw new InvalidDataException("Braid control operation is not unique.");
            var result = new OwnedDid2BraidControlPersistedEvent(direction, (ulong)ordinal, exact);
            exact = []; return result;
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    internal ExactDpe2DurableTransitionContext CreateVerifiedBraidTransitionContext(Did2MessagingFloor stable,
        ReadOnlySpan<byte> operation, ReadOnlySpan<byte> receivedControl)
    {
        using var retained = ReadVerifiedBraidControl(stable, operation);
        var replay = ExactDpe2ReceiveReplayDisposition.Fresh;
        if (retained is not null)
        {
            if (receivedControl.IsEmpty || retained.Direction != 4 || !Fixed(retained.ExactControl, receivedControl))
                throw new CryptographicException("Braid control replay differs from its original authenticated frame/direction.");
            replay = ExactDpe2ReceiveReplayDisposition.ExactReplay;
        }
        return CreateVerifiedContext(stable, replay);
    }
}
