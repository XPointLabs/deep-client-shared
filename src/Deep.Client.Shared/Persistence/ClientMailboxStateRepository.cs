using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence;

public static class ClientMailboxStateLimits
{
    public const int ScopeBytes = 32;
    public const int MaximumInboxEntries = 200;
    public const int MaximumInboxBytes = 8 * 1024 * 1024;
    public const int MaximumExpiredQuarantineEntries = 200;
    public const int MaximumExpiredQuarantineBytes = 8 * 1024 * 1024;
    public const int MaximumInstallationInboxEntries = 1000;
    public const int MaximumInstallationInboxBytes = 32 * 1024 * 1024;
    public const int MaximumInstallationScopes = 1024;
    public const int MaximumInstallationExpiredQuarantineEntries = 1000;
    public const int MaximumInstallationExpiredQuarantineBytes = 32 * 1024 * 1024;
    public const ulong MaximumActiveInboxAgeSeconds = 7 * 24 * 60 * 60;
    public const ulong ExpiredQuarantineRetentionSeconds = 30 * 24 * 60 * 60;
    public const int MaximumCoordinatorStatements = 1024;
    public const int MaximumMigrationArtifacts = MaximumInstallationScopes;
    public const int MaximumMigrationArtifactBytes = 64 * 1024 * 1024;
    public const long MigrationArtifactRetentionSeconds = 30L * 24 * 60 * 60;
}

public sealed class ClientMailboxScope : IEquatable<ClientMailboxScope>
{
    private static ReadOnlySpan<byte> Domain => "deep.client.mailbox.scope.v1"u8;
    private readonly byte[] value;

    private ClientMailboxScope(ReadOnlySpan<byte> value)
    {
        if (value.Length != ClientMailboxStateLimits.ScopeBytes ||
            value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("Opaque mailbox scope is invalid.", nameof(value));
        }

        this.value = value.ToArray();
    }

    internal ReadOnlySpan<byte> Value => value;

    public static ClientMailboxScope Derive(
        ReadOnlySpan<byte> issuerContext,
        BlindedMailboxId mailboxId,
        ulong epoch)
    {
        ArgumentNullException.ThrowIfNull(mailboxId);
        if (issuerContext.Length != 32 ||
            epoch == 0 ||
            issuerContext.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "Mailbox issuer context must be 32 nonzero bytes.",
                nameof(issuerContext));
        }

        return new(SHA256.HashData([
            .. Domain,
            .. issuerContext,
            .. mailboxId.Bytes.Span,
            .. EpochBytes(epoch)
        ]));
    }

    private static byte[] EpochBytes(ulong epoch)
    {
        var encoded = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, epoch);
        return encoded;
    }

    public byte[] ToArray() => value.ToArray();

    public bool Equals(ClientMailboxScope? other) =>
        other is not null &&
        CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) => Equals(obj as ClientMailboxScope);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(value);
        return hash.ToHashCode();
    }

    public override string ToString() => "[opaque-client-mailbox-scope]";
}

public sealed class ClientMailboxJournalScope : IEquatable<ClientMailboxJournalScope>
{
    private static ReadOnlySpan<byte> Domain =>
        "deep.client.mailbox.installation-journal.v1"u8;
    private readonly byte[] value;

    private ClientMailboxJournalScope(ReadOnlySpan<byte> value)
    {
        if (value.Length != ClientMailboxStateLimits.ScopeBytes ||
            value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "Opaque mailbox journal scope is invalid.",
                nameof(value));
        }

        this.value = value.ToArray();
    }

    internal ReadOnlySpan<byte> Value => value;

    public static ClientMailboxJournalScope Derive(
        ReadOnlySpan<byte> issuerContext)
    {
        if (issuerContext.Length != 32 ||
            issuerContext.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "Mailbox issuer context must be 32 nonzero bytes.",
                nameof(issuerContext));
        }

        return new(SHA256.HashData([.. Domain, .. issuerContext]));
    }

    public byte[] ToArray() => value.ToArray();

    public bool Equals(ClientMailboxJournalScope? other) =>
        other is not null &&
        CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) =>
        Equals(obj as ClientMailboxJournalScope);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(value);
        return hash.ToHashCode();
    }

    public override string ToString() =>
        "[opaque-client-mailbox-installation-journal-scope]";
}

public sealed class ClientMailboxTraversal
{
    private readonly byte[] continuationToken;

    internal ClientMailboxTraversal(
        ulong afterCursor,
        ReadOnlySpan<byte> continuationToken)
    {
        if (afterCursor == 0 != continuationToken.IsEmpty ||
            continuationToken.Length > MailboxClientLimits.MaximumContinuationTokenLength)
        {
            throw new ArgumentException("Mailbox traversal cursor/token is invalid.");
        }

        AfterCursor = afterCursor;
        this.continuationToken = continuationToken.ToArray();
    }

    public ulong AfterCursor { get; }
    public byte[] GetContinuationTokenCopy() => continuationToken.ToArray();
    internal ReadOnlySpan<byte> ContinuationToken => continuationToken;
}

public sealed record ClientMailboxReceiveCommitResult(
    ClientMailboxTraversal Traversal,
    IReadOnlyList<MailboxRetrievedEnvelope> DurableInbox);

public sealed record ClientMailboxAckExpectation(
    ulong Cursor,
    ReadOnlyMemory<byte> EnvelopeDigest,
    ulong ExpiresAtUnixSeconds);

public sealed record ClientMailboxExpiryReconciliationResult(
    int QuarantinedUnacknowledged,
    int RemovedAcknowledged);

public enum ClientMailboxAckState
{
    Pending = 1,
    AlreadyCommitted = 2,
    Conflict = 3
}

public enum ClientMailboxCoordinatorRecordResult
{
    Applied = 1,
    Idempotent = 2,
    Equivocation = 3,
    CapacityExceeded = 4
}

internal enum ClientMailboxCommitFaultPoint
{
    BeforeCommit,
    AfterCommit
}

public interface IClientMailboxStateRepository
{
    Task<ClientMailboxTraversal> ReadTraversalAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<MailboxRetrievedEnvelope>> ReadDurableInboxAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken = default);

    Task<ClientMailboxExpiryReconciliationResult> ReconcileExpiredAsync(
        ClientMailboxScope scope,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default);

    Task<ClientMailboxReceiveCommitResult> CommitRetrievePageAsync(
        ClientMailboxScope scope,
        ClientMailboxTraversal expectedTraversal,
        MailboxRetrievePage page,
        CancellationToken cancellationToken = default);

    Task<ClientMailboxAckState> CheckAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ClientMailboxAckExpectation>> ReadAckExpectationsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default);

    Task<ClientMailboxAckState> CommitAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default);

    Task<ClientMailboxCoordinatorRecordResult> RecordCoordinatorStatementAsync(
        ClientMailboxJournalScope scope,
        ReadOnlyMemory<byte> membershipCommitment,
        ulong epoch,
        ReadOnlyMemory<byte> coordinatorId,
        ulong coordinatorSequence,
        ReadOnlyMemory<byte> statementDigest,
        ulong expiresAtUnixSeconds,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default);
}

internal sealed class ClientMailboxStoredEntry
{
    public required ulong Cursor { get; init; }
    public required byte[] Digest { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required byte[] CanonicalEnvelope { get; init; }
    public bool Acknowledged { get; set; }

    public ClientMailboxStoredEntry Clone() => new()
    {
        Cursor = Cursor,
        Digest = Digest.ToArray(),
        ExpiresAtUnixSeconds = ExpiresAtUnixSeconds,
        CanonicalEnvelope = CanonicalEnvelope.ToArray(),
        Acknowledged = Acknowledged
    };
}

internal sealed class ClientMailboxExpiredQuarantineEntry
{
    public required ClientMailboxStoredEntry Entry { get; init; }
    public required ulong QuarantinedAtUnixSeconds { get; init; }

    public ClientMailboxExpiredQuarantineEntry Clone() => new()
    {
        Entry = Entry.Clone(),
        QuarantinedAtUnixSeconds = QuarantinedAtUnixSeconds
    };
}

internal sealed class ClientMailboxCoordinatorStatement
{
    public required byte[] MembershipCommitment { get; init; }
    public required ulong Epoch { get; init; }
    public required byte[] CoordinatorId { get; init; }
    public required ulong CoordinatorSequence { get; init; }
    public required byte[] StatementDigest { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }

    public ClientMailboxCoordinatorStatement Clone() => new()
    {
        MembershipCommitment = MembershipCommitment.ToArray(),
        Epoch = Epoch,
        CoordinatorId = CoordinatorId.ToArray(),
        CoordinatorSequence = CoordinatorSequence,
        StatementDigest = StatementDigest.ToArray(),
        ExpiresAtUnixSeconds = ExpiresAtUnixSeconds
    };
}

internal sealed class ClientMailboxStoredState
{
    public ulong AfterCursor { get; set; }
    public byte[] ContinuationToken { get; set; } = [];
    public List<ClientMailboxStoredEntry> Entries { get; } = [];
    public List<ClientMailboxCoordinatorStatement> CoordinatorStatements { get; } = [];

    public ClientMailboxStoredState Clone()
    {
        var clone = new ClientMailboxStoredState
        {
            AfterCursor = AfterCursor,
            ContinuationToken = ContinuationToken.ToArray()
        };
        clone.Entries.AddRange(Entries.Select(static entry => entry.Clone()));
        clone.CoordinatorStatements.AddRange(
            CoordinatorStatements.Select(static statement => statement.Clone()));
        return clone;
    }
}

internal sealed class ClientMailboxJournalState
{
    public List<ClientMailboxCoordinatorStatement> CoordinatorStatements { get; } = [];

    public ClientMailboxJournalState Clone()
    {
        var clone = new ClientMailboxJournalState();
        clone.CoordinatorStatements.AddRange(
            CoordinatorStatements.Select(static statement => statement.Clone()));
        return clone;
    }
}

internal static class ClientMailboxStateMachine
{
    public static ClientMailboxTraversal Traversal(ClientMailboxStoredState state)
    {
        Validate(state);
        return new ClientMailboxTraversal(state.AfterCursor, state.ContinuationToken);
    }

    public static ClientMailboxReceiveCommitResult CommitPage(
        ClientMailboxStoredState state,
        ClientMailboxTraversal expected,
        MailboxRetrievePage page)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(page);
        Validate(state);
        _ = MailboxClientCodec.EncodeRetrievePage(page);
        if (state.AfterCursor != expected.AfterCursor ||
            !FixedEquals(state.ContinuationToken, expected.ContinuationToken))
        {
            throw new InvalidOperationException(
                "Mailbox traversal changed before durable page commit.");
        }

        var committedPage = new List<MailboxRetrievedEnvelope>(page.Items.Count);
        foreach (var item in page.Items)
        {
            var canonicalEnvelope = MailboxClientCodec.EncodeEncryptedEnvelope(
                item.Envelope);
            var digest = item.Envelope.DeduplicationDigest.ToArray();
            var byCursor = state.Entries.SingleOrDefault(entry =>
                entry.Cursor == item.Cursor);
            var byDigest = state.Entries.SingleOrDefault(entry =>
                FixedEquals(entry.Digest, digest));
            if (byCursor is not null || byDigest is not null)
            {
                if (byCursor is null || byDigest is null ||
                    !ReferenceEquals(byCursor, byDigest) ||
                    byCursor.ExpiresAtUnixSeconds !=
                        item.Envelope.ExpiresAtUnixSeconds ||
                    !FixedEquals(byCursor.CanonicalEnvelope, canonicalEnvelope))
                {
                    throw new InvalidDataException(
                        "Mailbox cursor/digest history conflicts with durable inbox.");
                }

                if (!byCursor.Acknowledged)
                {
                    committedPage.Add(item);
                }

                continue;
            }

            if (expected.AfterCursor != 0 && item.Cursor <= expected.AfterCursor)
            {
                throw new InvalidDataException(
                    "Continuation page rolled back below its authorized cursor.");
            }

            state.Entries.Add(new ClientMailboxStoredEntry
            {
                Cursor = item.Cursor,
                Digest = digest,
                ExpiresAtUnixSeconds = item.Envelope.ExpiresAtUnixSeconds,
                CanonicalEnvelope = canonicalEnvelope,
                Acknowledged = false
            });
            committedPage.Add(item);
        }

        if (page.HasMore)
        {
            state.AfterCursor = page.NextCursor;
            state.ContinuationToken = page.ContinuationToken.ToArray();
        }
        else
        {
            state.AfterCursor = 0;
            state.ContinuationToken = [];
        }

        PruneAcknowledged(state);
        Validate(state);
        return new ClientMailboxReceiveCommitResult(
            Traversal(state),
            PageInbox(committedPage));
    }

    public static ClientMailboxAckState Check(
        ClientMailboxStoredState state,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements)
    {
        Validate(state);
        ValidateAcknowledgements(acknowledgements);
        var matches = Matches(state, acknowledgements);
        if (matches.Any(static entry => entry is null))
        {
            return ClientMailboxAckState.Conflict;
        }

        if (matches.All(static entry => entry!.Acknowledged))
        {
            return ClientMailboxAckState.AlreadyCommitted;
        }

        if (matches.Any(static entry => entry!.Acknowledged))
        {
            return ClientMailboxAckState.Conflict;
        }

        var pendingPrefix = state.Entries
            .Where(static entry => !entry.Acknowledged)
            .OrderBy(static entry => entry.Cursor)
            .Take(acknowledgements.Count)
            .ToArray();
        return pendingPrefix.Length == matches.Length &&
               pendingPrefix.SequenceEqual(matches!)
            ? ClientMailboxAckState.Pending
            : ClientMailboxAckState.Conflict;
    }

    public static IReadOnlyList<ClientMailboxAckExpectation> AckExpectations(
        ClientMailboxStoredState state,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements)
    {
        if (Check(state, acknowledgements) == ClientMailboxAckState.Conflict)
        {
            throw new InvalidOperationException(
                "Acknowledgements do not match the durable inbox.");
        }

        return Matches(state, acknowledgements)
            .Select(static entry => new ClientMailboxAckExpectation(
                entry!.Cursor,
                entry.Digest.ToArray(),
                entry.ExpiresAtUnixSeconds))
            .ToArray();
    }

    public static ClientMailboxAckState CommitAck(
        ClientMailboxStoredState state,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements)
    {
        var result = Check(state, acknowledgements);
        if (result != ClientMailboxAckState.Pending)
        {
            return result;
        }

        foreach (var acknowledgement in acknowledgements)
        {
            state.Entries.Single(entry =>
                entry.Cursor == acknowledgement.Cursor).Acknowledged = true;
        }

        PruneAcknowledged(state);
        Validate(state);
        return ClientMailboxAckState.Pending;
    }

    public static ClientMailboxExpiryReconciliationResult ReconcileExpired(
        ClientMailboxStoredState state,
        ulong nowUnixSeconds,
        ICollection<ClientMailboxStoredEntry>? quarantine = null)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (nowUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nowUnixSeconds));
        }

        var expired = state.Entries
            .Where(entry => entry.ExpiresAtUnixSeconds <= nowUnixSeconds)
            .ToArray();
        var unacknowledged = expired.Where(static entry => !entry.Acknowledged)
            .ToArray();
        if (quarantine is not null)
        {
            foreach (var entry in unacknowledged)
            {
                quarantine.Add(entry.Clone());
            }
        }

        foreach (var entry in expired)
        {
            state.Entries.Remove(entry);
        }

        Validate(state);
        return new(
            unacknowledged.Length,
            expired.Length - unacknowledged.Length);
    }

    public static ClientMailboxCoordinatorRecordResult RecordCoordinator(
        ClientMailboxJournalState state,
        ReadOnlySpan<byte> membershipCommitment,
        ulong epoch,
        ReadOnlySpan<byte> coordinatorId,
        ulong coordinatorSequence,
        ReadOnlySpan<byte> statementDigest,
        ulong expiresAtUnixSeconds,
        ulong nowUnixSeconds)
    {
        ValidateJournal(state);
        ValidateCoordinatorInput(
            membershipCommitment,
            epoch,
            coordinatorId,
            coordinatorSequence,
            statementDigest,
            expiresAtUnixSeconds,
            nowUnixSeconds);
        state.CoordinatorStatements.RemoveAll(statement =>
            statement.ExpiresAtUnixSeconds <= nowUnixSeconds);
        var membership = membershipCommitment.ToArray();
        var coordinator = coordinatorId.ToArray();
        var existing = state.CoordinatorStatements.SingleOrDefault(statement =>
            statement.Epoch == epoch &&
            statement.CoordinatorSequence == coordinatorSequence &&
            FixedEquals(statement.MembershipCommitment, membership) &&
            FixedEquals(statement.CoordinatorId, coordinator));
        if (existing is not null)
        {
            return FixedEquals(existing.StatementDigest, statementDigest)
                ? ClientMailboxCoordinatorRecordResult.Idempotent
                : ClientMailboxCoordinatorRecordResult.Equivocation;
        }

        if (state.CoordinatorStatements.Count >=
            ClientMailboxStateLimits.MaximumCoordinatorStatements)
        {
            return ClientMailboxCoordinatorRecordResult.CapacityExceeded;
        }

        state.CoordinatorStatements.Add(new ClientMailboxCoordinatorStatement
        {
            MembershipCommitment = membership,
            Epoch = epoch,
            CoordinatorId = coordinator,
            CoordinatorSequence = coordinatorSequence,
            StatementDigest = statementDigest.ToArray(),
            ExpiresAtUnixSeconds = expiresAtUnixSeconds
        });
        ValidateJournal(state);
        return ClientMailboxCoordinatorRecordResult.Applied;
    }

    public static void ValidateJournal(ClientMailboxJournalState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.CoordinatorStatements.Count >
                ClientMailboxStateLimits.MaximumCoordinatorStatements ||
            state.CoordinatorStatements.Any(static statement =>
                statement.MembershipCommitment.Length != 32 ||
                statement.CoordinatorId.Length != 32 ||
                statement.StatementDigest.Length != 32 ||
                statement.MembershipCommitment.AsSpan()
                    .IndexOfAnyExcept((byte)0) < 0 ||
                statement.CoordinatorId.AsSpan()
                    .IndexOfAnyExcept((byte)0) < 0 ||
                statement.StatementDigest.AsSpan()
                    .IndexOfAnyExcept((byte)0) < 0 ||
                statement.Epoch == 0 ||
                statement.CoordinatorSequence == 0 ||
                statement.ExpiresAtUnixSeconds == 0) ||
            state.CoordinatorStatements
                .Select(static statement =>
                    $"{Convert.ToHexString(statement.MembershipCommitment)}:" +
                    $"{statement.Epoch}:" +
                    $"{Convert.ToHexString(statement.CoordinatorId)}:" +
                    $"{statement.CoordinatorSequence}")
                .Distinct(StringComparer.Ordinal).Count() !=
                state.CoordinatorStatements.Count)
        {
            throw new InvalidDataException(
                "Persisted client mailbox coordinator journal is invalid.");
        }
    }

    public static void Validate(ClientMailboxStoredState state)
    {
        var inboxBytes = state.Entries.Sum(static entry =>
            (long)entry.CanonicalEnvelope.Length);
        if (state.AfterCursor == 0 != state.ContinuationToken.AsSpan().IsEmpty ||
            state.ContinuationToken.Length >
                MailboxClientLimits.MaximumContinuationTokenLength ||
            state.Entries.Count > ClientMailboxStateLimits.MaximumInboxEntries ||
            inboxBytes > ClientMailboxStateLimits.MaximumInboxBytes ||
            state.Entries.Any(static entry =>
                entry.Cursor == 0 ||
                entry.ExpiresAtUnixSeconds == 0 ||
                entry.Digest.Length != MailboxClientLimits.DigestLength ||
                entry.Digest.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                entry.CanonicalEnvelope.Length is
                    < MailboxClientLimits.EncryptedEnvelopeHeaderLength +
                      MailboxClientLimits.MinimumCiphertextLength or
                    > MailboxClientLimits.MaximumEncryptedEnvelopeLength) ||
            state.Entries.Select(static entry => entry.Cursor).Distinct().Count() !=
                state.Entries.Count ||
            state.Entries.Select(static entry => Convert.ToHexString(entry.Digest))
                .Distinct(StringComparer.Ordinal).Count() != state.Entries.Count)
        {
            throw new InvalidDataException("Persisted client mailbox state is invalid.");
        }

        foreach (var entry in state.Entries)
        {
            var envelope = DecodePersistedEnvelope(entry);
            if (envelope.ExpiresAtUnixSeconds != entry.ExpiresAtUnixSeconds ||
                !FixedEquals(envelope.DeduplicationDigest.Span, entry.Digest) ||
                envelope.ExpiresAtUnixSeconds <
                    envelope.CreatedAtUnixSeconds ||
                envelope.ExpiresAtUnixSeconds -
                    envelope.CreatedAtUnixSeconds >
                    ClientMailboxStateLimits.MaximumActiveInboxAgeSeconds)
            {
                throw new InvalidDataException(
                    "Durable mailbox inbox envelope binding is invalid.");
            }
        }
    }

    public static IReadOnlyList<MailboxRetrievedEnvelope> DurableInbox(
        ClientMailboxStoredState state) =>
        state.Entries
            .Where(static entry => !entry.Acknowledged)
            .OrderBy(static entry => entry.Cursor)
            .Select(static entry => new MailboxRetrievedEnvelope
            {
                Cursor = entry.Cursor,
                Envelope = DecodePersistedEnvelope(entry)
            })
            .ToArray();

    public static IReadOnlyList<MailboxRetrievedEnvelope> PageInbox(
        IEnumerable<MailboxRetrievedEnvelope> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        return items
            .OrderBy(static item => item.Cursor)
            .Select(static item =>
            {
                var canonical = MailboxClientCodec.EncodeEncryptedEnvelope(
                    item.Envelope);
                return new MailboxRetrievedEnvelope
                {
                    Cursor = item.Cursor,
                    Envelope = MailboxClientCodec.DecodeEncryptedEnvelope(
                        canonical,
                        ClientMailboxStateCodec.PersistenceDecodePolicy(
                            canonical,
                            item.Envelope.ExpiresAtUnixSeconds))
                };
            })
            .ToArray();
    }

    private static MailboxEncryptedEnvelope DecodePersistedEnvelope(
        ClientMailboxStoredEntry entry)
    {
        try
        {
            return MailboxClientCodec.DecodeEncryptedEnvelope(
                entry.CanonicalEnvelope,
                ClientMailboxStateCodec.PersistenceDecodePolicy(
                    entry.CanonicalEnvelope,
                    entry.ExpiresAtUnixSeconds));
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is MailboxClientException or ArgumentException or
            OverflowException or IndexOutOfRangeException)
        {
            throw new InvalidDataException(
                "Persisted mailbox envelope is corrupt.",
                exception);
        }
    }

    private static ClientMailboxStoredEntry?[] Matches(
        ClientMailboxStoredState state,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements) =>
        acknowledgements.Select(ack =>
            state.Entries.SingleOrDefault(entry =>
                entry.Cursor == ack.Cursor &&
                FixedEquals(entry.Digest, ack.EnvelopeDigest.Span))).ToArray();

    private static void ValidateAcknowledgements(
        IReadOnlyList<MailboxAcknowledgement> acknowledgements)
    {
        ArgumentNullException.ThrowIfNull(acknowledgements);
        if (acknowledgements.Count is 0 or > MailboxClientLimits.MaximumPageItems)
        {
            throw new ArgumentOutOfRangeException(nameof(acknowledgements));
        }

        ulong prior = 0;
        foreach (var acknowledgement in acknowledgements)
        {
            if (acknowledgement.Cursor <= prior ||
                acknowledgement.EnvelopeDigest.Length !=
                    MailboxClientLimits.DigestLength ||
                acknowledgement.EnvelopeDigest.Span.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new ArgumentException(
                    "Mailbox acknowledgements are not canonical.",
                    nameof(acknowledgements));
            }

            prior = acknowledgement.Cursor;
        }
    }

    private static void ValidateCoordinatorInput(
        ReadOnlySpan<byte> membershipCommitment,
        ulong epoch,
        ReadOnlySpan<byte> coordinatorId,
        ulong coordinatorSequence,
        ReadOnlySpan<byte> statementDigest,
        ulong expiresAtUnixSeconds,
        ulong nowUnixSeconds)
    {
        if (membershipCommitment.Length != 32 ||
            coordinatorId.Length != 32 ||
            statementDigest.Length != 32 ||
            membershipCommitment.IndexOfAnyExcept((byte)0) < 0 ||
            coordinatorId.IndexOfAnyExcept((byte)0) < 0 ||
            statementDigest.IndexOfAnyExcept((byte)0) < 0 ||
            epoch == 0 ||
            coordinatorSequence == 0 ||
            expiresAtUnixSeconds <= nowUnixSeconds ||
            expiresAtUnixSeconds - nowUnixSeconds >
                ClientMailboxStateLimits.MaximumActiveInboxAgeSeconds)
        {
            throw new ArgumentException(
                "Coordinator statement journal input is invalid.");
        }
    }

    private static void PruneAcknowledged(ClientMailboxStoredState state)
    {
        while ((state.Entries.Count > ClientMailboxStateLimits.MaximumInboxEntries ||
                state.Entries.Sum(static entry =>
                    (long)entry.CanonicalEnvelope.Length) >
                    ClientMailboxStateLimits.MaximumInboxBytes) &&
               state.Entries
                   .Where(static entry => entry.Acknowledged)
                   .MinBy(static entry => entry.Cursor) is { } oldest)
        {
            state.Entries.Remove(oldest);
        }

        Validate(state);
    }

    private static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}

internal static class ClientMailboxStateCodec
{
    private static ReadOnlySpan<byte> V1Magic => "CMS1"u8;
    private static ReadOnlySpan<byte> V2Magic => "CMS2"u8;
    private const int HeaderBytes = 32;
    private const int V1HeaderBytes = 16;
    private const int V1EntryBytes = 40;
    private const int EntryHeaderBytes = 64;
    private const int CoordinatorBytes = 120;

    public static bool IsVersionOne(ReadOnlySpan<byte> encoded) =>
        encoded.Length >= 4 && encoded[..4].SequenceEqual(V1Magic);

    public static byte[] Encode(ClientMailboxStoredState state)
    {
        ClientMailboxStateMachine.Validate(state);
        var legacyJournal = new ClientMailboxJournalState();
        legacyJournal.CoordinatorStatements.AddRange(
            state.CoordinatorStatements.Select(static statement => statement.Clone()));
        ClientMailboxStateMachine.ValidateJournal(legacyJournal);
        var length = checked(
            HeaderBytes +
            state.ContinuationToken.Length +
            state.Entries.Sum(static entry =>
                EntryHeaderBytes + entry.CanonicalEnvelope.Length) +
            (state.CoordinatorStatements.Count * CoordinatorBytes));
        var output = new byte[length];
        V2Magic.CopyTo(output);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(4, 8), state.AfterCursor);
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(12, 2),
            checked((ushort)state.ContinuationToken.Length));
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(16, 4),
            checked((uint)state.Entries.Count));
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(20, 4),
            checked((uint)state.CoordinatorStatements.Count));
        var offset = HeaderBytes;
        state.ContinuationToken.CopyTo(output, offset);
        offset += state.ContinuationToken.Length;
        foreach (var entry in state.Entries.OrderBy(static entry => entry.Cursor))
        {
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset, 8), entry.Cursor);
            BinaryPrimitives.WriteUInt64BigEndian(
                output.AsSpan(offset + 8, 8),
                entry.ExpiresAtUnixSeconds);
            output[offset + 16] = entry.Acknowledged ? (byte)1 : (byte)0;
            entry.Digest.CopyTo(output, offset + 24);
            BinaryPrimitives.WriteUInt32BigEndian(
                output.AsSpan(offset + 56, 4),
                checked((uint)entry.CanonicalEnvelope.Length));
            offset += EntryHeaderBytes;
            entry.CanonicalEnvelope.CopyTo(output, offset);
            offset += entry.CanonicalEnvelope.Length;
        }

        foreach (var statement in state.CoordinatorStatements)
        {
            statement.MembershipCommitment.CopyTo(output, offset);
            BinaryPrimitives.WriteUInt64BigEndian(
                output.AsSpan(offset + 32, 8),
                statement.Epoch);
            statement.CoordinatorId.CopyTo(output, offset + 40);
            BinaryPrimitives.WriteUInt64BigEndian(
                output.AsSpan(offset + 72, 8),
                statement.CoordinatorSequence);
            statement.StatementDigest.CopyTo(output, offset + 80);
            BinaryPrimitives.WriteUInt64BigEndian(
                output.AsSpan(offset + 112, 8),
                statement.ExpiresAtUnixSeconds);
            offset += CoordinatorBytes;
        }

        return output;
    }

    public static ClientMailboxStoredState Decode(ReadOnlySpan<byte> encoded)
    {
        try
        {
            return DecodeCore(encoded);
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is MailboxClientException or ArgumentException or
            OverflowException or IndexOutOfRangeException)
        {
            throw new InvalidDataException(
                "Client mailbox state is corrupt.",
                exception);
        }
    }

    private static ClientMailboxStoredState DecodeCore(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < HeaderBytes || !encoded[..4].SequenceEqual(V2Magic) ||
            encoded.Slice(14, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(24, 8).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw new InvalidDataException(
                "Client mailbox state version/header is invalid.");
        }

        var tokenLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(12, 2));
        var entryCount = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(16, 4));
        var coordinatorCount =
            BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(20, 4));
        if (tokenLength > MailboxClientLimits.MaximumContinuationTokenLength ||
            entryCount > ClientMailboxStateLimits.MaximumInboxEntries ||
            coordinatorCount > ClientMailboxStateLimits.MaximumCoordinatorStatements ||
            tokenLength > encoded.Length - HeaderBytes)
        {
            throw new InvalidDataException("Client mailbox state bounds are invalid.");
        }

        var state = new ClientMailboxStoredState
        {
            AfterCursor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(4, 8)),
            ContinuationToken = encoded.Slice(HeaderBytes, tokenLength).ToArray()
        };
        var offset = HeaderBytes + tokenLength;
        for (var index = 0; index < entryCount; index++)
        {
            if (offset > encoded.Length - EntryHeaderBytes ||
                encoded[offset + 16] > 1 ||
                encoded.Slice(offset + 17, 7).IndexOfAnyExcept((byte)0) >= 0 ||
                encoded.Slice(offset + 60, 4).IndexOfAnyExcept((byte)0) >= 0)
            {
                throw new InvalidDataException("Client mailbox inbox entry is invalid.");
            }

            var envelopeLength = BinaryPrimitives.ReadUInt32BigEndian(
                encoded.Slice(offset + 56, 4));
            if (envelopeLength >
                    MailboxClientLimits.MaximumEncryptedEnvelopeLength ||
                envelopeLength > encoded.Length - offset - EntryHeaderBytes)
            {
                throw new InvalidDataException(
                    "Client mailbox inbox envelope length is invalid.");
            }

            state.Entries.Add(new ClientMailboxStoredEntry
            {
                Cursor = BinaryPrimitives.ReadUInt64BigEndian(
                    encoded.Slice(offset, 8)),
                ExpiresAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(
                    encoded.Slice(offset + 8, 8)),
                Acknowledged = encoded[offset + 16] == 1,
                Digest = encoded.Slice(offset + 24, 32).ToArray(),
                CanonicalEnvelope = encoded.Slice(
                    offset + EntryHeaderBytes,
                    checked((int)envelopeLength)).ToArray()
            });
            offset += EntryHeaderBytes + checked((int)envelopeLength);
        }

        for (var index = 0; index < coordinatorCount; index++)
        {
            if (offset > encoded.Length - CoordinatorBytes)
            {
                throw new InvalidDataException(
                    "Client mailbox coordinator journal is truncated.");
            }

            state.CoordinatorStatements.Add(new ClientMailboxCoordinatorStatement
            {
                MembershipCommitment = encoded.Slice(offset, 32).ToArray(),
                Epoch = BinaryPrimitives.ReadUInt64BigEndian(
                    encoded.Slice(offset + 32, 8)),
                CoordinatorId = encoded.Slice(offset + 40, 32).ToArray(),
                CoordinatorSequence = BinaryPrimitives.ReadUInt64BigEndian(
                    encoded.Slice(offset + 72, 8)),
                StatementDigest = encoded.Slice(offset + 80, 32).ToArray(),
                ExpiresAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(
                    encoded.Slice(offset + 112, 8))
            });
            offset += CoordinatorBytes;
        }

        if (offset != encoded.Length)
        {
            throw new InvalidDataException(
                "Client mailbox state has trailing bytes.");
        }

        ClientMailboxStateMachine.Validate(state);
        var legacyJournal = new ClientMailboxJournalState();
        legacyJournal.CoordinatorStatements.AddRange(
            state.CoordinatorStatements.Select(static statement => statement.Clone()));
        ClientMailboxStateMachine.ValidateJournal(legacyJournal);
        return state;
    }

    public static ClientMailboxStoredState MigrateVersionOneToSafeReplay(
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < V1HeaderBytes ||
            !encoded[..4].SequenceEqual(V1Magic))
        {
            throw new InvalidDataException("CMS1 migration input is invalid.");
        }

        var count = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(12, 4));
        if (count > 2048 ||
            encoded.Length != V1HeaderBytes + checked((int)count * V1EntryBytes))
        {
            throw new InvalidDataException("CMS1 migration input length is invalid.");
        }

        // CMS1 advanced the cursor without retaining ciphertext. Retaining either
        // its cursor or digest set would hide messages permanently. Preserve the
        // original bytes in the migration backup and restart a safe cursor-zero cycle.
        return new ClientMailboxStoredState();
    }

    public static MailboxClientDecodePolicy PersistenceDecodePolicy(
        ReadOnlySpan<byte> canonicalEnvelope,
        ulong expiresAtUnixSeconds)
    {
        if (canonicalEnvelope.Length <
            MailboxClientLimits.EncryptedEnvelopeHeaderLength)
        {
            throw new InvalidDataException("Persisted envelope is truncated.");
        }

        var epoch = BinaryPrimitives.ReadUInt64BigEndian(
            canonicalEnvelope.Slice(8, 8));
        var createdAt = BinaryPrimitives.ReadUInt64BigEndian(
            canonicalEnvelope.Slice(128, 8));
        if (epoch is 0 or ulong.MaxValue ||
            createdAt <= 1 ||
            expiresAtUnixSeconds is 0 or ulong.MaxValue)
        {
            throw new InvalidDataException(
                "Persisted envelope epoch/timeline is invalid.");
        }

        return new MailboxClientDecodePolicy
        {
            NowUnixSeconds = createdAt,
            EpochWindow = new MailboxEpochWindow
            {
                CurrentEpoch = epoch,
                NextEpoch = epoch + 1,
                CurrentNotBeforeUnixSeconds = createdAt - 1,
                NextNotBeforeUnixSeconds = createdAt,
                CurrentExpiresAtUnixSeconds = expiresAtUnixSeconds,
                NextExpiresAtUnixSeconds = expiresAtUnixSeconds + 1
            },
            CapabilityPolicy = new MailboxCapabilityDecodePolicy
            {
                CurrentBucket = 1,
                MinimumGeneration = 1
            },
            AllowLegacyMirrorOverlap = true
        };
    }
}
