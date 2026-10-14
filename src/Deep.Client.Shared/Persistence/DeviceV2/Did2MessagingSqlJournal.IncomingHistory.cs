using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    // A bounded-memory view of actual native events, including the
    // independently protected prefix. SQL ordering alone is not authority:
    // verify the complete tip first and each event against native commitments.
    // The owner holds its account lease for the entire enumeration. A yielded
    // event lives until the next MoveNext/Dispose; it cannot escape as authority.
    internal IEnumerable<OwnedDid2MessagingPersistedEvent> ReadVerifiedIncomingEvents(
        Did2MessagingFloor protectedStable, CancellationToken ct) => ReadVerifiedEvents(protectedStable, 2, ct);

    // Narrow only materialization after complete tip verification. That check
    // authenticates every row, including ordinary events and the retained
    // prefix, and binds route-processing presence to the actual DMC2 kind.
    // Unknown/hidden markers therefore reject before the SQL filter runs.
    internal IEnumerable<OwnedDid2MessagingPersistedEvent> ReadVerifiedIncomingRouteControls(
        Did2MessagingFloor protectedStable, CancellationToken ct) =>
        ReadVerifiedEvents(protectedStable, 2, ct, routeControlsOnly: true);

    internal IEnumerable<OwnedDid2MessagingPersistedEvent> ReadVerifiedOutgoingEvents(
        Did2MessagingFloor protectedStable, CancellationToken ct) => ReadVerifiedEvents(protectedStable, 1, ct);

    private IEnumerable<OwnedDid2MessagingPersistedEvent> ReadVerifiedEvents(
        Did2MessagingFloor protectedStable, int direction, CancellationToken ct, bool routeControlsOnly = false)
    {
        ct.ThrowIfCancellationRequested();
        _ = Did2MessagingFloor.Decode(protectedStable.Exact.Span, scope);
        if (protectedStable.Phase != 1 || protectedStable.Status != 1)
            throw new InvalidDataException("Event history requires an active stable messaging floor.");
        RequireSame(protectedStable, VerifyTip());
        using var command = Command("SELECT ordinal,operation,metadata,envelope,plaintext,typeof(operation),length(operation),typeof(metadata),length(metadata),typeof(envelope),length(envelope),typeof(plaintext),length(plaintext) FROM events WHERE direction=$direction" +
            (routeControlsOnly ? " AND substr(metadata,$routeOffset,1) IN (X'01',X'02')" : string.Empty) + " ORDER BY ordinal;");
        command.Parameters.AddWithValue("$direction", direction);
        if (routeControlsOnly) command.Parameters.AddWithValue("$routeOffset", Did2RouteProcessingMetadata.Offset + 1);
        using (var reader = command.ExecuteReader())
        {
            ulong previous = 0;
            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();
                var ordinal = reader.GetInt64(0);
                if (ordinal <= 0 || (ulong)ordinal <= previous || (ulong)ordinal > protectedStable.Ordinal ||
                    reader.GetString(5) != "blob" || reader.GetInt64(6) != 32 ||
                    reader.GetString(7) != "blob" || reader.GetInt64(8) != Did2MessagingFloor.MetadataBytes ||
                    reader.GetString(9) != "blob" || reader.GetInt64(10) is < 1 or > 65536 ||
                    (direction == 1 ? reader.GetString(11) != "null" || !reader.IsDBNull(12) :
                        reader.GetString(11) != "blob" || reader.GetInt64(12) is < 1 or > 33082))
                    throw new InvalidDataException("Event history has a noncanonical native event shape.");
                var operation = reader.GetFieldValue<byte[]>(1);
                var metadata = reader.GetFieldValue<byte[]>(2);
                byte[] envelope = [], plaintext = [];
                OwnedDid2MessagingPersistedEvent? result = null;
                try
                {
                    envelope = reader.GetFieldValue<byte[]>(3);
                    if (direction == 2) plaintext = reader.GetFieldValue<byte[]>(4);
                    VerifyHistoricalEvent((ulong)ordinal, direction, operation, metadata, envelope, plaintext);
                    if (routeControlsOnly && metadata[Did2RouteProcessingMetadata.Offset] is not (1 or 2))
                        throw new InvalidDataException("Route-only history selected a non-control native event.");
                    result = new(direction, (ulong)ordinal, envelope, plaintext, metadata.AsSpan(300, 32),
                        metadata.AsSpan(Did2RouteProcessingMetadata.Offset, Did2RouteProcessingMetadata.Bytes));
                    envelope = []; plaintext = [];
                    previous = (ulong)ordinal;
                    yield return result;
                }
                finally
                {
                    result?.Dispose();
                    CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(plaintext);
                    CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(metadata);
                }
            }
        }
        ct.ThrowIfCancellationRequested();
        RequireSame(protectedStable, VerifyTip());
    }
}
