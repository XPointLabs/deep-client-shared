#if DEEP_CLEAN_PRODUCTION
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    // Only the currently materialized direct user-content kinds create work.
    // Control events and receipts themselves must not cause acknowledgement loops.
    internal static bool NeedsDirectApplicationReceipt(IAuthenticatedDmc2InboxEvent handoff) =>
        handoff is AuthenticatedDirectDmc2 &&
        (handoff.ContentKind is Dmc2ContentKind.MessageCreate or Dmc2ContentKind.AttachmentOffer) &&
        !DirectFixed(handoff.LocalAccountId.Span, handoff.AuthorAccountId.Span);

    private static void InsertDirectReceiptObligation(SqliteConnection connection,
        SqliteTransaction transaction, AuthenticatedDirectDmc2 handoff, ReadOnlySpan<byte> eventHash)
    {
        using var insert = connection.CreateCommand(); insert.Transaction = transaction;
        insert.CommandText = "INSERT INTO direct_application_receipt_obligations VALUES($conversation,$logical,$device,$account,$local_device,$hash);";
        AddDirectKey(insert, handoff.ConversationId.ToArray(), handoff.LogicalMessageId.ToArray(), handoff.AuthorDeviceId.ToArray());
        insert.Parameters.AddWithValue("$account", handoff.AuthorAccountId.ToArray());
        insert.Parameters.AddWithValue("$local_device", handoff.LocalDeviceId.ToArray());
        insert.Parameters.AddWithValue("$hash", eventHash.ToArray());
        if (insert.ExecuteNonQuery() != 1)
            throw new CryptographicException("Application receipt obligation was not durable.");
    }

    private static void RequireDirectReceiptObligation(SqliteConnection connection,
        SqliteTransaction transaction, IAuthenticatedDmc2InboxEvent handoff, ReadOnlySpan<byte> eventHash)
    {
        if (!NeedsDirectApplicationReceipt(handoff)) return;
        var direct = (AuthenticatedDirectDmc2)handoff;
        using var read = connection.CreateCommand(); read.Transaction = transaction;
        read.CommandText = "SELECT author_account_id,local_device_id,exact_dmc2_hash FROM direct_application_receipt_obligations WHERE conversation_id=$conversation AND logical_message_id=$logical AND author_device_id=$device;";
        AddDirectKey(read, handoff.ConversationId.ToArray(), handoff.LogicalMessageId.ToArray(), handoff.AuthorDeviceId.ToArray());
        using var reader = read.ExecuteReader();
        if (!reader.Read()) throw new CryptographicException("Materialized content lost its application receipt obligation.");
        foreach (var pair in new[] { (0, handoff.AuthorAccountId.ToArray()), (1, direct.LocalDeviceId.ToArray()), (2, eventHash.ToArray()) })
        {
            var actual = reader.GetFieldValue<byte[]>(pair.Item1);
            try
            {
                if (!DirectFixed(actual, pair.Item2))
                    throw new CryptographicException("Application receipt obligation differs from its authenticated receive.");
            }
            finally { CryptographicOperations.ZeroMemory(actual); CryptographicOperations.ZeroMemory(pair.Item2); }
        }
        if (reader.Read()) throw new CryptographicException("Duplicate application receipt obligations exist.");
    }

    private static void ValidateDirectReceiptObligations(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var shape = connection.CreateCommand(); shape.Transaction = transaction;
        shape.CommandText = "SELECT count(*) FROM direct_application_receipt_obligations WHERE " + string.Join(" OR ",
            new[] { "conversation_id", "logical_message_id", "author_device_id", "author_account_id", "local_device_id", "exact_dmc2_hash" }
                .Select(column => $"typeof({column})<>'blob' OR length({column})<>32 OR {column}=zeroblob(32)")) + ";";
        if (Convert.ToInt64(shape.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0)
            throw ResetRequired("Application receipt metadata exceeds its closed type/size bounds.");
        using var validate = connection.CreateCommand(); validate.Transaction = transaction;
        // All current remote user-content events and only those events have one
        // obligation. No reader synthesizes missing work from retained history.
        validate.CommandText = """
            SELECT
                (SELECT count(*) FROM direct_application_receipt_obligations r
                 LEFT JOIN authenticated_dmc2_inbox i USING(conversation_id,logical_message_id,author_device_id)
                 LEFT JOIN authenticated_dmc2_inbox_owner o ON o.singleton=1
                 WHERE i.logical_message_id IS NULL OR o.singleton IS NULL OR i.content_kind NOT IN ($message,$offer)
                    OR i.author_account_id=o.local_account_id OR r.author_account_id<>i.author_account_id
                    OR r.exact_dmc2_hash<>i.exact_dmc2_hash
                    OR typeof(r.local_device_id)<>'blob' OR length(r.local_device_id)<>32 OR r.local_device_id=zeroblob(32)),
                (SELECT count(*) FROM authenticated_dmc2_inbox i
                 JOIN authenticated_dmc2_inbox_owner o ON o.singleton=1
                 LEFT JOIN direct_application_receipt_obligations r USING(conversation_id,logical_message_id,author_device_id)
                 WHERE i.content_kind IN ($message,$offer) AND i.author_account_id<>o.local_account_id AND r.logical_message_id IS NULL);
            """;
        validate.Parameters.AddWithValue("$message", (int)Dmc2ContentKind.MessageCreate);
        validate.Parameters.AddWithValue("$offer", (int)Dmc2ContentKind.AttachmentOffer);
        using var reader = validate.ExecuteReader();
        if (!reader.Read() || reader.GetInt64(0) != 0 || reader.GetInt64(1) != 0)
            throw ResetRequired("Application receipt obligations are missing or inconsistent.");
    }

    /// <summary>Bounded key-free due-work facts, not receipt authoring/dispatch authority.</summary>
    internal Task<IReadOnlyList<DirectApplicationReceiptObligation>> ListPendingDirectApplicationReceiptsAsync(
        Did2MessagingSessionScope scope, int maximumItems = 100, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (maximumItems is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(maximumItems));
        return WithReplayConnectionAsync<IReadOnlyList<DirectApplicationReceiptObligation>>(connection =>
        {
            using var transaction = connection.BeginTransaction();
            ValidateTransportOutboxSchema(connection, transaction); ValidateDirectInboxState(connection, transaction);
            using var owner = connection.CreateCommand(); owner.Transaction = transaction;
            owner.CommandText = "SELECT local_account_id,local_account_generation FROM authenticated_dmc2_inbox_owner WHERE singleton=1;";
            using (var reader = owner.ExecuteReader())
            {
                if (!reader.Read()) return Task.FromResult<IReadOnlyList<DirectApplicationReceiptObligation>>([]);
                if (!DirectFixed(reader.GetFieldValue<byte[]>(0), scope.LocalAccount) ||
                    !SequenceMatches(reader.GetFieldValue<byte[]>(1), BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..])))
                    throw new CryptographicException("Receipt work belongs to another account generation.");
            }
            using var read = connection.CreateCommand(); read.Transaction = transaction;
            read.CommandText = "SELECT r.logical_message_id,r.exact_dmc2_hash,f.incumbent_hash,length(i.exact_dmc2),typeof(i.exact_dmc2),i.exact_dmc2 FROM direct_application_receipt_obligations r JOIN authenticated_dmc2_inbox i USING(conversation_id,logical_message_id,author_device_id) LEFT JOIN authenticated_dmc2_inbox_forks f USING(conversation_id,logical_message_id,author_device_id) WHERE r.conversation_id=$conversation AND r.local_device_id=$local_device AND r.author_account_id=$account AND r.author_device_id=$device ORDER BY r.logical_message_id LIMIT $limit;";
            read.Parameters.AddWithValue("$conversation", scope.Conversation.ToArray());
            read.Parameters.AddWithValue("$local_device", scope.LocalDevice.ToArray());
            read.Parameters.AddWithValue("$account", scope.RemoteAccount.ToArray());
            read.Parameters.AddWithValue("$device", scope.RemoteDevice.ToArray());
            read.Parameters.AddWithValue("$limit", maximumItems);
            var dueQuery = read.CommandText;
            read.CommandText = "SELECT count(*) FROM direct_application_receipt_obligations WHERE conversation_id=$conversation AND author_account_id=$account AND author_device_id=$device AND local_device_id<>$local_device;";
            if (Convert.ToInt64(read.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0)
                throw new CryptographicException("Application receipt work changed its recipient device binding.");
            read.CommandText = dueQuery;
            using var eventReader = read.ExecuteReader();
            var results = new List<DirectApplicationReceiptObligation>();
            while (eventReader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!eventReader.IsDBNull(2)) throw new CryptographicException("Forked content cannot issue an application receipt.");
                if (eventReader.GetString(4) != "blob" || eventReader.GetInt64(3) is < 282 or > 33082)
                    throw new CryptographicException("Receipt source event exceeds its exact payload bound.");
                var exact = eventReader.GetFieldValue<byte[]>(5);
                var logical = eventReader.GetFieldValue<byte[]>(0); var hash = eventReader.GetFieldValue<byte[]>(1);
                ParsedDmc2? parsed = null;
                try
                {
                    parsed = ApplicationCoreCodec.DecodeDmc2(exact);
                    if (!DirectFixed(SHA256.HashData(exact), hash) || !DirectFixed(parsed.CanonicalBytes.Span, exact) ||
                        !DirectFixed(parsed.NetworkId.Span, scope.Network) || !DirectFixed(parsed.ConversationId.Span, scope.Conversation) ||
                        !DirectFixed(parsed.SenderAccountId.Span, scope.RemoteAccount) || !DirectFixed(parsed.SenderDeviceId.Span, scope.RemoteDevice) ||
                        !DirectFixed(parsed.LogicalMessageId.Span, logical) ||
                        parsed.ContentKind is not (Dmc2ContentKind.MessageCreate or Dmc2ContentKind.AttachmentOffer))
                        throw new CryptographicException("Receipt source event differs from its authenticated semantic binding.");
                    results.Add(new(logical, hash));
                }
                finally
                {
                    if (parsed?.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose();
                    CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(logical); CryptographicOperations.ZeroMemory(hash);
                }
            }
            return Task.FromResult<IReadOnlyList<DirectApplicationReceiptObligation>>(results);
        }, cancellationToken);
    }
}

// The scope supplied to the reader provides conversation/author/target-device
// binding. These metadata snapshots contain no payload, keys or signing rights.
internal sealed class DirectApplicationReceiptObligation
{
    private readonly byte[] logical, eventHash;
    internal DirectApplicationReceiptObligation(ReadOnlySpan<byte> logical, ReadOnlySpan<byte> eventHash)
    {
        if (logical.Length != 32 || eventHash.Length != 32 ||
            logical.IndexOfAnyExcept((byte)0) < 0 || eventHash.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("Application receipt metadata exceeds its exact bound.");
        this.logical = logical.ToArray(); this.eventHash = eventHash.ToArray();
    }
    internal ReadOnlyMemory<byte> LogicalMessageId => logical.ToArray();
    internal ReadOnlyMemory<byte> EventHash => eventHash.ToArray();
}
#endif
