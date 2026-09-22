#if DEEP_CLEAN_PRODUCTION
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed record DirectMessageCreateSnapshot(
    string Text,
    bool IsLocalAuthor,
    DateTimeOffset CreatedAt);

public sealed partial class SqliteDeepMailboxStore
{
    private const long MaximumDirectInboxEvents = 100_000;

    /// <summary>
    /// Materializes a committed direct-session DMC2 into the account-wide
    /// semantic inbox. A retained session-local DMC2 stage makes a crash
    /// between ratchet and this transaction safely retryable. This result is
    /// not a transport ACK or a stage-retirement capability.
    /// </summary>
    internal Task<DirectDmc2InboxDisposition> MaterializeDirectDmc2Async(
        AuthenticatedDirectDmc2 handoff,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        return WithReplayConnectionAsync(connection =>
        {
            var local = handoff.LocalAccountId.ToArray();
            var generation = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(generation, handoff.LocalAccountGeneration);
            var conversation = handoff.ConversationId.ToArray();
            var logical = handoff.LogicalMessageId.ToArray();
            var authorDevice = handoff.AuthorDeviceId.ToArray();
            var authorAccount = handoff.AuthorAccountId.ToArray();
            var exact = handoff.ExactDmc2.ToArray();
            var hash = SHA256.HashData(exact);
            try
            {
                using var transaction = connection.BeginTransaction(deferred: false);
                BindDirectInboxOwner(connection, transaction, local, generation);

                using var fork = connection.CreateCommand();
                fork.Transaction = transaction;
                fork.CommandText = "SELECT count(*) FROM authenticated_dmc2_inbox_forks WHERE conversation_id=$conversation AND logical_message_id=$logical AND author_device_id=$device;";
                AddDirectKey(fork, conversation, logical, authorDevice);
                if (Convert.ToInt64(fork.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0)
                    return Task.FromResult(DirectDmc2InboxDisposition.ForkLatched);

                byte[]? incumbent = null;
                byte[]? incumbentHash = null;
                using (var read = connection.CreateCommand())
                {
                    read.Transaction = transaction;
                    read.CommandText = "SELECT exact_dmc2,exact_dmc2_hash FROM authenticated_dmc2_inbox WHERE conversation_id=$conversation AND logical_message_id=$logical AND author_device_id=$device;";
                    AddDirectKey(read, conversation, logical, authorDevice);
                    using var reader = read.ExecuteReader();
                    if (reader.Read())
                    {
                        incumbent = (byte[])reader[0];
                        incumbentHash = (byte[])reader[1];
                    }
                }

                if (incumbent is not null)
                {
                    try
                    {
                        if (DirectFixed(incumbentHash!, hash) && DirectFixed(incumbent, exact))
                            return Task.FromResult(DirectDmc2InboxDisposition.ExactReplay);
                        using var latch = connection.CreateCommand();
                        latch.Transaction = transaction;
                        latch.CommandText = "INSERT INTO authenticated_dmc2_inbox_forks VALUES($conversation,$logical,$device,$incumbent,$conflicting);";
                        AddDirectKey(latch, conversation, logical, authorDevice);
                        latch.Parameters.AddWithValue("$incumbent", incumbentHash!);
                        latch.Parameters.AddWithValue("$conflicting", hash);
                        cancellationToken.ThrowIfCancellationRequested();
                        if (latch.ExecuteNonQuery() != 1)
                            throw new CryptographicException("Direct inbox fork latch was not durable.");
                        transaction.Commit();
                        return Task.FromResult(DirectDmc2InboxDisposition.ForkLatched);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(incumbent);
                        CryptographicOperations.ZeroMemory(incumbentHash!);
                    }
                }

                using var count = connection.CreateCommand();
                count.Transaction = transaction;
                count.CommandText = "SELECT count(*) FROM authenticated_dmc2_inbox;";
                if (Convert.ToInt64(count.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture)
                    >= MaximumDirectInboxEvents)
                    return Task.FromResult(DirectDmc2InboxDisposition.CapacityExceeded);

                using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = "INSERT INTO authenticated_dmc2_inbox VALUES($conversation,$logical,$device,$account,$kind,$hash,$exact,$at);";
                AddDirectKey(insert, conversation, logical, authorDevice);
                insert.Parameters.AddWithValue("$account", authorAccount);
                insert.Parameters.AddWithValue("$kind", (int)handoff.ContentKind);
                insert.Parameters.AddWithValue("$hash", hash);
                insert.Parameters.AddWithValue("$exact", exact);
                insert.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                cancellationToken.ThrowIfCancellationRequested();
                if (insert.ExecuteNonQuery() != 1)
                    throw new CryptographicException("Direct inbox materialization was not durable.");
#if DEEP_TEST_INTERNALS
                DirectDmc2InboxTestHooks.Hit(DirectDmc2InboxFaultPoint.BeforeCommit);
#endif
                transaction.Commit();
#if DEEP_TEST_INTERNALS
                DirectDmc2InboxTestHooks.Hit(DirectDmc2InboxFaultPoint.AfterCommit);
#endif
                return Task.FromResult(DirectDmc2InboxDisposition.Materialized);
            }
            finally
            {
                foreach (var value in new[] { local, generation, conversation, logical,
                             authorDevice, authorAccount, exact, hash })
                    CryptographicOperations.ZeroMemory(value);
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Applies the authenticated initial DPH2 batch in one account-inbox
    /// transaction. SessionInit is a control event; an optional ContactHello
    /// or direct application event is retained beside it. No ACK is granted.
    /// </summary>
    internal Task<DirectDmc2InboxDisposition> MaterializeInitialDmc2BatchAsync(
        AuthenticatedInitialDmc2Batch batch,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batch);
        return WithReplayConnectionAsync(connection =>
        {
            var local = batch.LocalAccountId;
            var generation = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(generation, batch.LocalAccountGeneration);
            var events = new List<InitialInboxEvent>(batch.EventCount);
            var sessionExact = batch.SessionInitDmc2;
            var firstExact = batch.EventCount == 2
                ? batch.FirstApplicationDmc2 : null;
            try
            {
                events.Add(new InitialInboxEvent(sessionExact));
                if (firstExact is not null)
                    events.Add(new InitialInboxEvent(firstExact));
                using var transaction = connection.BeginTransaction(deferred: false);
                BindDirectInboxOwner(connection, transaction, local, generation);
                var newEvents = new List<InitialInboxEvent>(events.Count);
                foreach (var item in events)
                {
                    using var fork = connection.CreateCommand();
                    fork.Transaction = transaction;
                    fork.CommandText = "SELECT count(*) FROM authenticated_dmc2_inbox_forks WHERE conversation_id=$conversation AND logical_message_id=$logical AND author_device_id=$device;";
                    AddDirectKey(fork, item.ConversationId, item.LogicalMessageId, item.AuthorDeviceId);
                    if (Convert.ToInt64(fork.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0)
                        return Task.FromResult(DirectDmc2InboxDisposition.ForkLatched);

                    using var read = connection.CreateCommand();
                    read.Transaction = transaction;
                    read.CommandText = "SELECT exact_dmc2,exact_dmc2_hash FROM authenticated_dmc2_inbox WHERE conversation_id=$conversation AND logical_message_id=$logical AND author_device_id=$device;";
                    AddDirectKey(read, item.ConversationId, item.LogicalMessageId, item.AuthorDeviceId);
                    using var reader = read.ExecuteReader();
                    if (!reader.Read())
                    {
                        newEvents.Add(item);
                        continue;
                    }
                    var incumbent = (byte[])reader[0];
                    var incumbentHash = (byte[])reader[1];
                    try
                    {
                        if (reader.Read())
                            throw new CryptographicException("Duplicate initial inbox event rows exist.");
                        if (DirectFixed(incumbentHash, item.Hash) &&
                            DirectFixed(incumbent, item.ExactDmc2))
                            continue;
                        reader.Close();
                        using var latch = connection.CreateCommand();
                        latch.Transaction = transaction;
                        latch.CommandText = "INSERT INTO authenticated_dmc2_inbox_forks VALUES($conversation,$logical,$device,$incumbent,$conflicting);";
                        AddDirectKey(latch, item.ConversationId, item.LogicalMessageId, item.AuthorDeviceId);
                        latch.Parameters.AddWithValue("$incumbent", incumbentHash);
                        latch.Parameters.AddWithValue("$conflicting", item.Hash);
                        cancellationToken.ThrowIfCancellationRequested();
                        if (latch.ExecuteNonQuery() != 1)
                            throw new CryptographicException("Initial inbox fork latch was not durable.");
                        transaction.Commit();
                        return Task.FromResult(DirectDmc2InboxDisposition.ForkLatched);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(incumbent);
                        CryptographicOperations.ZeroMemory(incumbentHash);
                    }
                }
                using var count = connection.CreateCommand();
                count.Transaction = transaction;
                count.CommandText = "SELECT count(*) FROM authenticated_dmc2_inbox;";
                var storedCount = Convert.ToInt64(count.ExecuteScalar(),
                    System.Globalization.CultureInfo.InvariantCulture);
                if (storedCount + newEvents.Count > MaximumDirectInboxEvents)
                    return Task.FromResult(DirectDmc2InboxDisposition.CapacityExceeded);
                foreach (var item in newEvents)
                {
                    using var insert = connection.CreateCommand();
                    insert.Transaction = transaction;
                    insert.CommandText = "INSERT INTO authenticated_dmc2_inbox VALUES($conversation,$logical,$device,$account,$kind,$hash,$exact,$at);";
                    AddDirectKey(insert, item.ConversationId, item.LogicalMessageId, item.AuthorDeviceId);
                    insert.Parameters.AddWithValue("$account", item.AuthorAccountId);
                    insert.Parameters.AddWithValue("$kind", (int)item.ContentKind);
                    insert.Parameters.AddWithValue("$hash", item.Hash);
                    insert.Parameters.AddWithValue("$exact", item.ExactDmc2);
                    insert.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                    cancellationToken.ThrowIfCancellationRequested();
                    if (insert.ExecuteNonQuery() != 1)
                        throw new CryptographicException("Initial inbox event was not durable.");
                }
#if DEEP_TEST_INTERNALS
                DirectDmc2InboxTestHooks.Hit(DirectDmc2InboxFaultPoint.BeforeCommit);
#endif
                transaction.Commit();
#if DEEP_TEST_INTERNALS
                DirectDmc2InboxTestHooks.Hit(DirectDmc2InboxFaultPoint.AfterCommit);
#endif
                return Task.FromResult(newEvents.Count == 0
                    ? DirectDmc2InboxDisposition.ExactReplay
                    : DirectDmc2InboxDisposition.Materialized);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(local);
                CryptographicOperations.ZeroMemory(generation);
                CryptographicOperations.ZeroMemory(sessionExact);
                if (firstExact is not null) CryptographicOperations.ZeroMemory(firstExact);
                foreach (var item in events) item.Dispose();
            }
        }, cancellationToken);
    }

    /// <summary>Returns an owned exact event from a non-forked local inbox.</summary>
    internal Task<byte[]?> ReadDirectDmc2Async(
        ReadOnlyMemory<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlyMemory<byte> conversationId,
        ReadOnlyMemory<byte> logicalMessageId,
        ReadOnlyMemory<byte> authorDeviceId,
        CancellationToken cancellationToken = default)
    {
        RequireDirectId(localAccountId, nameof(localAccountId));
        RequireDirectId(conversationId, nameof(conversationId));
        RequireDirectId(logicalMessageId, nameof(logicalMessageId));
        RequireDirectId(authorDeviceId, nameof(authorDeviceId));
        if (localAccountGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(localAccountGeneration));
        return WithReplayConnectionAsync(connection =>
        {
            var local = localAccountId.ToArray();
            var generation = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(generation, localAccountGeneration);
            var conversation = conversationId.ToArray();
            var logical = logicalMessageId.ToArray();
            var device = authorDeviceId.ToArray();
            try
            {
                using var owner = connection.CreateCommand();
                owner.CommandText = "SELECT local_account_id,local_account_generation FROM authenticated_dmc2_inbox_owner WHERE singleton=1;";
                using (var reader = owner.ExecuteReader())
                {
                    if (!reader.Read()) return Task.FromResult<byte[]?>(null);
                    var storedAccount = (byte[])reader[0];
                    var storedGeneration = (byte[])reader[1];
                    try
                    {
                        if (!DirectFixed(local, storedAccount) ||
                            !DirectFixed(generation, storedGeneration) || reader.Read())
                            throw new CryptographicException(
                                "The direct inbox belongs to another local account generation.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(storedAccount);
                        CryptographicOperations.ZeroMemory(storedGeneration);
                    }
                }
                using var read = connection.CreateCommand();
                read.CommandText = "SELECT i.exact_dmc2,i.exact_dmc2_hash,f.incumbent_hash,i.author_account_id,i.content_kind FROM authenticated_dmc2_inbox i LEFT JOIN authenticated_dmc2_inbox_forks f ON i.conversation_id=f.conversation_id AND i.logical_message_id=f.logical_message_id AND i.author_device_id=f.author_device_id WHERE i.conversation_id=$conversation AND i.logical_message_id=$logical AND i.author_device_id=$device;";
                AddDirectKey(read, conversation, logical, device);
                using var eventReader = read.ExecuteReader();
                if (!eventReader.Read()) return Task.FromResult<byte[]?>(null);
                var exact = (byte[])eventReader[0];
                var hash = (byte[])eventReader[1];
                var actualHash = SHA256.HashData(exact);
                try
                {
                    if (!eventReader.IsDBNull(2) ||
                        !DirectFixed(hash, actualHash))
                        throw new CryptographicException(
                            "The direct inbox event is forked or corrupt.");
                    var parsed = Deep.Protocol.ApplicationCore.ApplicationCoreCodec.DecodeDmc2(exact);
                    var storedAuthor = (byte[])eventReader[3];
                    var canonical = parsed.CanonicalBytes.ToArray();
                    try
                    {
                        if (!DirectFixed(parsed.ConversationId.Span, conversation) ||
                            !DirectFixed(parsed.LogicalMessageId.Span, logical) ||
                            !DirectFixed(parsed.SenderDeviceId.Span, device) ||
                            !DirectFixed(parsed.SenderAccountId.Span, storedAuthor) ||
                            !DirectFixed(canonical, exact) ||
                            !IsAccountInboxKind(parsed.ContentKind) ||
                            eventReader.GetInt32(4) != (int)parsed.ContentKind)
                            throw new CryptographicException(
                                "The direct inbox event differs from its semantic key.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(storedAuthor);
                        CryptographicOperations.ZeroMemory(canonical);
                    }
                    return Task.FromResult<byte[]?>(exact);
                }
                catch
                {
                    CryptographicOperations.ZeroMemory(exact);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(hash);
                    CryptographicOperations.ZeroMemory(actualHash);
                }
            }
            finally
            {
                foreach (var value in new[] { local, generation, conversation, logical, device })
                    CryptographicOperations.ZeroMemory(value);
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Projects only canonical, non-forked authenticated MessageCreate events
    /// from one owned conversation. The SQLCipher inbox, not a mailbox deposit
    /// or unverified routing header, is the source of UI text.
    /// </summary>
    public Task<IReadOnlyList<DirectMessageCreateSnapshot>> ListDirectMessageCreatesAsync(
        ReadOnlyMemory<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlyMemory<byte> conversationId,
        int maximumItems = 100,
        CancellationToken cancellationToken = default)
    {
        RequireDirectId(localAccountId, nameof(localAccountId));
        RequireDirectId(conversationId, nameof(conversationId));
        if (localAccountGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(localAccountGeneration));
        if (maximumItems is < 1 or > 100)
            throw new ArgumentOutOfRangeException(nameof(maximumItems));
        return WithReplayConnectionAsync<IReadOnlyList<DirectMessageCreateSnapshot>>(connection =>
        {
            var local = localAccountId.ToArray();
            var generation = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(generation, localAccountGeneration);
            var conversation = conversationId.ToArray();
            try
            {
                using (var owner = connection.CreateCommand())
                {
                    owner.CommandText = "SELECT local_account_id,local_account_generation FROM authenticated_dmc2_inbox_owner WHERE singleton=1;";
                    using var ownerReader = owner.ExecuteReader();
                    if (!ownerReader.Read())
                        return Task.FromResult<IReadOnlyList<DirectMessageCreateSnapshot>>([]);
                    var storedAccount = (byte[])ownerReader[0];
                    var storedGeneration = (byte[])ownerReader[1];
                    try
                    {
                        if (!DirectFixed(local, storedAccount) ||
                            !DirectFixed(generation, storedGeneration) || ownerReader.Read())
                            throw new CryptographicException(
                                "The direct inbox belongs to another local account generation.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(storedAccount);
                        CryptographicOperations.ZeroMemory(storedGeneration);
                    }
                }

                using var read = connection.CreateCommand();
                read.CommandText = "SELECT i.exact_dmc2,i.exact_dmc2_hash,i.logical_message_id,i.author_device_id,i.author_account_id,f.incumbent_hash FROM authenticated_dmc2_inbox i LEFT JOIN authenticated_dmc2_inbox_forks f ON i.conversation_id=f.conversation_id AND i.logical_message_id=f.logical_message_id AND i.author_device_id=f.author_device_id WHERE i.conversation_id=$conversation AND i.content_kind=$kind ORDER BY i.materialized_at DESC,i.logical_message_id DESC LIMIT $limit;";
                read.Parameters.AddWithValue("$conversation", conversation);
                read.Parameters.AddWithValue("$kind", (int)Dmc2ContentKind.MessageCreate);
                read.Parameters.AddWithValue("$limit", maximumItems);
                using var reader = read.ExecuteReader();
                var results = new List<DirectMessageCreateSnapshot>();
                while (reader.Read())
                {
                    var exact = (byte[])reader[0];
                    var hash = (byte[])reader[1];
                    var logical = (byte[])reader[2];
                    var device = (byte[])reader[3];
                    var author = (byte[])reader[4];
                    var actualHash = SHA256.HashData(exact);
                    try
                    {
                        var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
                        if (!reader.IsDBNull(5) ||
                            !DirectFixed(hash, actualHash) ||
                            !DirectFixed(parsed.CanonicalBytes.Span, exact) ||
                            !DirectFixed(parsed.ConversationId.Span, conversation) ||
                            !DirectFixed(parsed.LogicalMessageId.Span, logical) ||
                            !DirectFixed(parsed.SenderDeviceId.Span, device) ||
                            !DirectFixed(parsed.SenderAccountId.Span, author) ||
                            parsed.ContentKind != Dmc2ContentKind.MessageCreate)
                            throw new CryptographicException(
                                "A direct message projection is forked or corrupt.");
                        var payload = parsed.PayloadBytes.ToArray();
                        try
                        {
                            var length = BinaryPrimitives.ReadUInt16BigEndian(payload);
                            if (payload.Length != length + 2)
                                throw new CryptographicException(
                                    "The authenticated text payload length is invalid.");
                            var text = new UTF8Encoding(false, true).GetString(payload, 2, length);
                            results.Add(new DirectMessageCreateSnapshot(
                                text,
                                DirectFixed(author, local),
                                DateTimeOffset.FromUnixTimeMilliseconds(
                                    checked((long)parsed.CreatedAtUnixMilliseconds))));
                        }
                        finally { CryptographicOperations.ZeroMemory(payload); }
                    }
                    finally
                    {
                        foreach (var value in new[] { exact, hash, logical, device,
                                     author, actualHash })
                            CryptographicOperations.ZeroMemory(value);
                    }
                }
                results.Reverse();
                return Task.FromResult<IReadOnlyList<DirectMessageCreateSnapshot>>(results);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(local);
                CryptographicOperations.ZeroMemory(generation);
                CryptographicOperations.ZeroMemory(conversation);
            }
        }, cancellationToken);
    }

    private static void BindDirectInboxOwner(
        SqliteConnection connection,
        SqliteTransaction transaction,
        byte[] localAccountId,
        byte[] generation)
    {
        using var read = connection.CreateCommand();
        read.Transaction = transaction;
        read.CommandText = "SELECT local_account_id,local_account_generation FROM authenticated_dmc2_inbox_owner WHERE singleton=1;";
        using var reader = read.ExecuteReader();
        if (reader.Read())
        {
            var storedAccount = (byte[])reader[0];
            var storedGeneration = (byte[])reader[1];
            try
            {
                if (!DirectFixed(storedAccount, localAccountId) ||
                    !DirectFixed(storedGeneration, generation) || reader.Read())
                    throw new CryptographicException(
                        "The direct inbox belongs to another local account generation.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(storedAccount);
                CryptographicOperations.ZeroMemory(storedGeneration);
            }
            return;
        }
        reader.Close();
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = "INSERT INTO authenticated_dmc2_inbox_owner VALUES(1,$account,$generation);";
        insert.Parameters.AddWithValue("$account", localAccountId);
        insert.Parameters.AddWithValue("$generation", generation);
        if (insert.ExecuteNonQuery() != 1)
            throw new CryptographicException("The direct inbox owner was not durably bound.");
    }

    private static void AddDirectKey(
        SqliteCommand command,
        byte[] conversation,
        byte[] logical,
        byte[] authorDevice)
    {
        command.Parameters.AddWithValue("$conversation", conversation);
        command.Parameters.AddWithValue("$logical", logical);
        command.Parameters.AddWithValue("$device", authorDevice);
    }

    private static bool DirectFixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static bool IsAccountInboxKind(Dmc2ContentKind kind) =>
        kind == Dmc2ContentKind.SessionInit ||
        AuthenticatedInitialDmc2Batch.IsSupportedInitialApplicationKind(kind);

    private sealed class InitialInboxEvent : IDisposable
    {
        internal InitialInboxEvent(ReadOnlySpan<byte> exact)
        {
            var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
            if (!IsAccountInboxKind(parsed.ContentKind) ||
                !DirectFixed(parsed.CanonicalBytes.Span, exact))
                throw new CryptographicException("The initial inbox event is not canonical or supported.");
            ExactDmc2 = exact.ToArray();
            Hash = SHA256.HashData(exact);
            ConversationId = parsed.ConversationId.ToArray();
            LogicalMessageId = parsed.LogicalMessageId.ToArray();
            AuthorDeviceId = parsed.SenderDeviceId.ToArray();
            AuthorAccountId = parsed.SenderAccountId.ToArray();
            ContentKind = parsed.ContentKind;
        }

        internal byte[] ExactDmc2 { get; }
        internal byte[] Hash { get; }
        internal byte[] ConversationId { get; }
        internal byte[] LogicalMessageId { get; }
        internal byte[] AuthorDeviceId { get; }
        internal byte[] AuthorAccountId { get; }
        internal Dmc2ContentKind ContentKind { get; }

        public void Dispose()
        {
            foreach (var value in new[] { ExactDmc2, Hash, ConversationId,
                         LogicalMessageId, AuthorDeviceId, AuthorAccountId })
                CryptographicOperations.ZeroMemory(value);
        }
    }

    private static void RequireDirectId(ReadOnlyMemory<byte> value, string name)
    {
        if (value.Length != 32 || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte identifier is required.", name);
    }
}

#if DEEP_TEST_INTERNALS
internal enum DirectDmc2InboxFaultPoint
{
    BeforeCommit = 1,
    AfterCommit = 2,
}

internal static class DirectDmc2InboxTestHooks
{
    private static readonly AsyncLocal<Action<DirectDmc2InboxFaultPoint>?> Current = new();

    internal static IDisposable Push(Action<DirectDmc2InboxFaultPoint> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        var prior = Current.Value;
        Current.Value = action;
        return new Restore(prior);
    }

    internal static void Hit(DirectDmc2InboxFaultPoint point) => Current.Value?.Invoke(point);

    private sealed class Restore(Action<DirectDmc2InboxFaultPoint>? prior) : IDisposable
    {
        private int disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
                Current.Value = prior;
        }
    }
}
#endif
#endif
