#if DEEP_CLEAN_PRODUCTION
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    internal static byte[] CaptureArchiveAuthoredSourceFromConnection(SqliteConnection connection,
        IncrementalHash prefix, Did2MessagingSessionScope scope, CancellationToken ct)
    {
        ValidateCipher(connection);
        using var tx = connection.BeginTransaction(deferred: true);
        ValidateTransportOutboxSchema(connection, tx); ValidateDirectInboxState(connection, tx);
        AppendApplicationCompactionCells(prefix, connection, tx, scope.Hash, null, ct);
        return prefix.GetHashAndReset();
    }
    internal static byte[] ReadArchiveAuthoredOriginal(SqliteConnection connection, Did2MessagingSessionScope scope,
        Did2MessagingArchiveOriginal native, ProtectedDid2DirectTextJournal.State ordinary,
        ProtectedDid2ContactAcceptJournal.Entry? acceptance, ReadOnlyMemory<byte> groupExact)
    {
        if (native.Reference.Direction != 1) throw new InvalidDataException("An authored original must be outgoing.");
        using var tx = connection.BeginTransaction(deferred: true);
        if (ReadPragma(connection, tx, "application_id") != ApplicationId || ReadPragma(connection, tx, "user_version") != SchemaVersion)
            throw new InvalidDataException("Selected authored source has a foreign schema generation.");
        ValidateTransportOutboxSchema(connection, tx);
        var generation = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(generation, BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]));
        BindDirectInboxOwner(connection, tx, scope.LocalAccount.ToArray(), generation, requireExisting: true);
        var operation = Convert.ToHexString(native.Reference.Operation);
        ordinary.Entries.TryGetValue(operation, out var command);
        byte[] exact;
        if (command is not null)
        {
            if (command.Pending || !DirectFixed(command.Scope.Exact, scope.Exact) || !DirectFixed(command.EventHash, native.Metadata.AsSpan(300, 32)))
                throw new CryptographicException("Native outgoing source differs from its protected authored command.");
            RequireSelectedOrdinaryRow(connection, tx, command);
            using var query = connection.CreateCommand(); query.Transaction = tx;
            query.CommandText = "SELECT exact_dmc2 FROM direct_text_outbox WHERE operation_id=$operation;";
            query.Parameters.AddWithValue("$operation", native.Reference.Operation.ToArray());
            exact = (byte[])(query.ExecuteScalar() ?? throw new CryptographicException("Selected authored command lost its actual payload."));
            command.RequireEvent(exact);
        }
        else if (!groupExact.IsEmpty) exact = groupExact.ToArray();
        else
        {
            using var query = connection.CreateCommand(); query.Transaction = tx;
            query.CommandText = "SELECT exact_dmc2,typeof(exact_dmc2),length(exact_dmc2),conversation_id,author_account_id,author_device_id,sender_sequence,content_kind,exact_dmc2_hash FROM authenticated_dmc2_inbox WHERE conversation_id=$conversation AND author_account_id=$account AND author_device_id=$device AND exact_dmc2_hash=$hash LIMIT 2;";
            query.Parameters.AddWithValue("$conversation", scope.Conversation.ToArray()); query.Parameters.AddWithValue("$account", scope.LocalAccount.ToArray());
            query.Parameters.AddWithValue("$device", scope.LocalDevice.ToArray()); query.Parameters.AddWithValue("$hash", native.Metadata.AsSpan(300, 32).ToArray());
            using var row = query.ExecuteReader();
            if (!row.Read() || row.GetString(1) != "blob" || row.GetInt64(2) is < 282 or > 33082)
                throw new CryptographicException("Outgoing archive source lost its exact authored application original.");
            exact = row.GetFieldValue<byte[]>(0);
            var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
            try
            {
                if (!DirectFixed(row.GetFieldValue<byte[]>(3), parsed.ConversationId.Span) || !DirectFixed(row.GetFieldValue<byte[]>(4), parsed.SenderAccountId.Span) ||
                    !DirectFixed(row.GetFieldValue<byte[]>(5), parsed.SenderDeviceId.Span) || row.GetFieldValue<byte[]>(6).Length != 8 ||
                    BinaryPrimitives.ReadUInt64BigEndian(row.GetFieldValue<byte[]>(6)) != parsed.SenderClientSequence || row.GetInt32(7) != (int)parsed.ContentKind ||
                    !DirectFixed(row.GetFieldValue<byte[]>(8), SHA256.HashData(exact)) || row.Read())
                    throw new CryptographicException("Authored application original changed its exact columns or uniqueness.");
            }
            finally { if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        }
        try
        {
            var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
            try
            {
                if (!DirectFixed(SHA256.HashData(exact), native.Metadata.AsSpan(300, 32)) || !DirectFixed(parsed.NetworkId.Span, scope.Network) ||
                    !DirectFixed(parsed.ConversationId.Span, scope.Conversation) || !DirectFixed(parsed.SenderAccountId.Span, scope.LocalAccount) ||
                    !DirectFixed(parsed.SenderDeviceId.Span, scope.LocalDevice)) throw new CryptographicException("Outgoing archive original changes its actual native scope/hash.");
                if (parsed.ContentKind == Dmc2ContentKind.ContactAccept)
                {
                    if (acceptance is null || !DirectFixed(acceptance.Operation, native.Reference.Operation))
                        throw new CryptographicException("Outgoing acceptance lost its protected explicit author.");
                    acceptance.RequireExactAccept(exact);
                }
                else
                {
                    var next = ordinary.NextSequence(scope);
                    if (parsed.SenderClientSequence >= next) throw new CryptographicException("Outgoing archive original exceeds its independent authored counter.");
                    using var query = connection.CreateCommand(); query.Transaction = tx;
                    query.CommandText = "SELECT next_sequence,typeof(next_sequence) FROM direct_sender_sequences WHERE conversation_id=$conversation AND author_device_id=$device;";
                    query.Parameters.AddWithValue("$conversation", scope.Conversation.ToArray()); query.Parameters.AddWithValue("$device", scope.LocalDevice.ToArray());
                    using var row = query.ExecuteReader();
                    if (!row.Read() || row.GetString(1) != "integer" || row.GetInt64(0) != checked((long)next) || row.Read())
                        throw new CryptographicException("Actual authored SQL counter differs from independent protected custody.");
                }
            }
            finally { if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
            var result = exact; exact = []; return result;
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
}
#endif
