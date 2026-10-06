using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    internal void RequireAppendCapacity(Did2MessagingFloor protectedStable)
    {
        RequireSame(protectedStable, VerifyTip());
        var headers = ReadJournal(out var tip); RequireSame(protectedStable, tip);
        if (headers.Count >= MaximumEntries || protectedStable.Ordinal >= long.MaxValue)
            throw new InvalidOperationException("Messaging working journal/lifetime ordinal has no append capacity.");
    }

    private void RequireEmptyHistory()
    {
        if (!Fixed(historyRoot.Exact.Span, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.Span))
            throw new CryptographicException("Messaging SQL initialization requires the mandatory registered empty history root.");
    }

    private void VerifyHistoryPrefix(SqliteTransaction? tx = null)
    {
        _ = Did2MessagingHistoryCheckpoint.Decode(historyRoot.Exact.Span, scope);
        if (historyRoot.Basis.Ordinal == 0)
        {
            using var command = Command("SELECT count(*) FROM events WHERE ordinal<=0;", tx);
            if (Convert.ToInt64(command.ExecuteScalar()) != 0)
                throw new InvalidDataException("Empty messaging history has invalid prefix rows.");
            return;
        }
        var initial = ReadInitialMetadata(tx);
        if (!Fixed(SHA256.HashData(initial), historyRoot.InitialHeaderHash))
            throw new CryptographicException("Protected messaging history lost its initial evidence.");
        var projection = ComputeHistoryProjection(historyRoot.Basis, initial, tx);
        if (projection.Count != historyRoot.HistoryCount || !Fixed(projection.Digest, historyRoot.HistoryDigest))
            throw new CryptographicException("Messaging retained history differs from its protected checkpoint.");
    }

    /// <summary>Read-only candidate from verified current SQL, not a deletion
    /// capability or persisted checkpoint. S04's held owner must revalidate all
    /// dependencies, persist its exact plan, verify complete SQL effects and
    /// adopt the protected root; this method performs none of those writes.</summary>
    internal Did2MessagingHistoryCheckpoint CaptureHistoryPrefix(Did2MessagingFloor protectedStable, int prefixRows)
    {
        if (protectedStable.Phase != 1 || protectedStable.Status != 1 || prefixRows is < 1 or > Did2CompactionPlan.MaximumRows)
            throw new InvalidDataException("History capture requires a stable active floor and bounded exact prefix.");
        RequireCipherPolicy(); ValidateSchema();
        using var tx = connection.BeginTransaction();
        VerifyHistoryPrefix(tx);
        var headers = ReadJournal(out var tip, tx); VerifyRows(headers, tip, tx); RequireSame(protectedStable, tip);
        if (prefixRows > headers.Count) throw new InvalidDataException("History capture exceeds the retained working prefix.");
        var basis = historyRoot.Basis;
        for (var index = 0; index < prefixRows; index++) basis = Did2MessagingFloor.FromJournalMetadata(scope, basis, headers[index]);
        if (basis.Status != 1) throw new InvalidDataException("Unactivated/latched custody is not an active history checkpoint.");
        var initial = ReadInitialMetadata(tx); var projection = ComputeHistoryProjection(basis, initial, tx);
        return historyRoot.NextProjection(scope, basis, initial, projection.Digest, projection.Count);
    }

    private byte[] ReadInitialMetadata(SqliteTransaction? tx = null)
    {
        using var command = Command("SELECT length(metadata),metadata FROM initial_events WHERE singleton=1;", tx);
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetInt64(0) != Did2MessagingFloor.MetadataBytes)
            throw new InvalidDataException("Messaging history lost bounded initial metadata.");
        var result = reader.GetFieldValue<byte[]>(1);
        OwnedDid2MessagingMutation.ValidateMetadataTransition(result, scope, Did2MessagingFloor.Empty(scope));
        if (result[5] != 1 || reader.Read()) throw new InvalidDataException("Messaging history initial metadata is not unique import custody.");
        return result;
    }

    // Stream retained metadata; plaintext/ciphertext is independently verified
    // against those commitments before it contributes to the projection. No
    // lifetime-sized list, key archive or caller-supplied digest is used.
    private (byte[] Digest, ulong Count) ComputeHistoryProjection(Did2MessagingFloor basis,
        ReadOnlySpan<byte> initial, SqliteTransaction? tx = null)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("Deep/STORE-V2/messaging-history-prefix"u8); digest.AppendData([0]);
        digest.AppendData(scope.Hash); digest.AppendData(basis.Exact.Span); digest.AppendData(initial);
        using var command = Command("SELECT ordinal,direction,operation,metadata,envelope,plaintext,length(operation),length(metadata),length(envelope),length(plaintext) FROM events WHERE ordinal<=$basis ORDER BY ordinal;", tx);
        command.Parameters.AddWithValue("$basis", checked((long)basis.Ordinal)); using var reader = command.ExecuteReader();
        ulong count = 0, previous = 0; Span<byte> number = stackalloc byte[8];
        while (reader.Read())
        {
            var ordinal = reader.GetInt64(0); var direction = reader.GetInt32(1);
            if (ordinal < 1 || (ulong)ordinal <= previous || (ulong)ordinal > basis.Ordinal || direction is not (1 or 2) ||
                reader.GetInt64(6) != 32 || reader.GetInt64(7) != Did2MessagingFloor.MetadataBytes || reader.GetInt64(8) is < 1 or > 65536 ||
                (direction == 1 ? !reader.IsDBNull(9) : reader.IsDBNull(9) || reader.GetInt64(9) is < 1 or > 33082))
                throw new InvalidDataException("Retained messaging history has a noncanonical reference or size.");
            var operation = reader.GetFieldValue<byte[]>(2); var metadata = reader.GetFieldValue<byte[]>(3);
            var envelope = reader.GetFieldValue<byte[]>(4); byte[] plaintext = [];
            try
            {
                if (direction == 2) plaintext = reader.GetFieldValue<byte[]>(5);
                VerifyHistoricalEvent((ulong)ordinal, direction, operation, metadata, envelope, plaintext);
                BinaryPrimitives.WriteUInt64BigEndian(number, (ulong)ordinal); digest.AppendData(number); digest.AppendData(metadata);
                count = checked(count + 1); previous = (ulong)ordinal;
            }
            finally { CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(plaintext); }
        }
        BinaryPrimitives.WriteUInt64BigEndian(number, count); digest.AppendData(number);
        return (digest.GetHashAndReset(), count);
    }

    private void VerifyHistoricalEvent(ulong ordinal, int direction, ReadOnlySpan<byte> operation,
        ReadOnlySpan<byte> metadata, byte[] envelopeBytes, byte[] plaintext)
    {
        var prior = Did2MessagingFloor.Decode(metadata.Slice(8, Did2MessagingFloor.Bytes), scope);
        OwnedDid2MessagingMutation.ValidateMetadataTransition(metadata, scope, prior);
        var envelope = Dpe2Codec.Decode(envelopeBytes);
        if (prior.Ordinal == ulong.MaxValue || ordinal != prior.Ordinal + 1 || metadata[5] != 2 || direction != metadata[6] ||
            !Fixed(operation, metadata.Slice(268, 32)) || !Fixed(envelope.OperationId.Span, operation) ||
            !Fixed(envelope.NetworkId.Span, scope.Network) || !Fixed(envelope.SessionId.Span, scope.Session) ||
            !Fixed(envelope.SenderDeviceId.Span, direction == 1 ? scope.LocalDevice : scope.RemoteDevice) ||
            !Fixed(envelope.RecipientDeviceId.Span, direction == 1 ? scope.RemoteDevice : scope.LocalDevice) ||
            !Fixed(MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(envelope), metadata.Slice(332, 32)) ||
            !Fixed(MessagingWireCryptographicInputs.ComputeDtr2HeaderHash(envelope.RatchetHeader), metadata.Slice(364, 32)))
            throw new CryptographicException("Retained messaging history differs from its committed event metadata.");
        if (direction == 1)
        { if (plaintext.Length != 0) throw new InvalidDataException("Retained send history has unexpected plaintext."); }
        else
        {
            var parsed = ApplicationCoreCodec.DecodeDmc2(plaintext);
            if (!Fixed(SHA256.HashData(plaintext), metadata.Slice(300, 32)) || !Fixed(parsed.NetworkId.Span, scope.Network) ||
                !Fixed(parsed.SenderAccountId.Span, scope.RemoteAccount) || !Fixed(parsed.SenderDeviceId.Span, scope.RemoteDevice))
                throw new CryptographicException("Retained receive history lost its authenticated event.");
        }
    }
}
