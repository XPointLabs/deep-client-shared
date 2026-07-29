using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence;

public static class ClientMailboxStateLimits
{
    public const int ScopeBytes = 32;
    public const int MaximumSeenEntries = 2048;
}

public sealed class ClientMailboxScope : IEquatable<ClientMailboxScope>
{
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

    public static ClientMailboxScope FromBytes(ReadOnlySpan<byte> value) => new(value);

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

public sealed record ClientMailboxMergeResult(
    ulong AfterCursor,
    IReadOnlyList<MailboxRetrievedEnvelope> NewItems);

public enum ClientMailboxAckState
{
    Pending = 1,
    AlreadyCommitted = 2,
    Conflict = 3
}

public interface IClientMailboxStateRepository
{
    Task<ulong> ReadAfterCursorAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken = default);

    Task<ClientMailboxMergeResult> MergeRetrievePageAsync(
        ClientMailboxScope scope,
        MailboxRetrievePage page,
        CancellationToken cancellationToken = default);

    Task<ClientMailboxAckState> CheckAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default);

    Task<ClientMailboxAckState> CommitAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default);
}

internal sealed class ClientMailboxStoredEntry
{
    public required ulong Cursor { get; init; }
    public required byte[] Digest { get; init; }
    public bool Acknowledged { get; set; }

    public ClientMailboxStoredEntry Clone() => new()
    {
        Cursor = Cursor,
        Digest = Digest.ToArray(),
        Acknowledged = Acknowledged
    };
}

internal sealed class ClientMailboxStoredState
{
    public ulong AfterCursor { get; set; }
    public List<ClientMailboxStoredEntry> Entries { get; } = [];

    public ClientMailboxStoredState Clone()
    {
        var clone = new ClientMailboxStoredState { AfterCursor = AfterCursor };
        clone.Entries.AddRange(Entries.Select(static entry => entry.Clone()));
        return clone;
    }
}

internal static class ClientMailboxStateMachine
{
    public static ClientMailboxMergeResult Merge(
        ClientMailboxStoredState state,
        MailboxRetrievePage page)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(page);
        Validate(state);
        _ = MailboxClientCodec.EncodeRetrievePage(page);

        var newItems = new List<MailboxRetrievedEnvelope>();
        foreach (var item in page.Items)
        {
            var digest = item.Envelope.DeduplicationDigest.ToArray();
            var byCursor = state.Entries.SingleOrDefault(entry => entry.Cursor == item.Cursor);
            var byDigest = state.Entries.SingleOrDefault(entry =>
                CryptographicOperations.FixedTimeEquals(entry.Digest, digest));
            if (byCursor is not null || byDigest is not null)
            {
                if (byCursor is null || byDigest is null ||
                    !ReferenceEquals(byCursor, byDigest) ||
                    !CryptographicOperations.FixedTimeEquals(byCursor.Digest, digest))
                {
                    throw new InvalidDataException(
                        "Mailbox cursor/digest history conflicts with persisted state.");
                }

                continue;
            }

            if (item.Cursor <= state.AfterCursor)
            {
                throw new InvalidDataException(
                    "Mailbox page rolled back below the persisted cursor.");
            }

            state.Entries.Add(new ClientMailboxStoredEntry
            {
                Cursor = item.Cursor,
                Digest = digest,
                Acknowledged = false
            });
            newItems.Add(item);
        }

        if (page.NextCursor != 0)
        {
            if (page.NextCursor < state.AfterCursor)
            {
                throw new InvalidDataException(
                    "Mailbox page next cursor rolled back persisted state.");
            }

            state.AfterCursor = page.NextCursor;
        }

        Prune(state);
        Validate(state);
        return new ClientMailboxMergeResult(state.AfterCursor, newItems);
    }

    public static ClientMailboxAckState Check(
        ClientMailboxStoredState state,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements)
    {
        Validate(state);
        ValidateAcknowledgements(acknowledgements);
        var matches = acknowledgements
            .Select(ack => state.Entries.SingleOrDefault(entry =>
                entry.Cursor == ack.Cursor &&
                CryptographicOperations.FixedTimeEquals(
                    entry.Digest,
                    ack.EnvelopeDigest.Span)))
            .ToArray();
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

    public static ClientMailboxAckState Commit(
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

        Prune(state);
        Validate(state);
        return ClientMailboxAckState.Pending;
    }

    public static void Validate(ClientMailboxStoredState state)
    {
        if (state.Entries.Count > ClientMailboxStateLimits.MaximumSeenEntries ||
            state.Entries.Any(static entry =>
                entry.Cursor == 0 ||
                entry.Digest.Length != MailboxClientLimits.DigestLength ||
                entry.Digest.AsSpan().IndexOfAnyExcept((byte)0) < 0) ||
            state.Entries.Select(static entry => entry.Cursor).Distinct().Count() !=
                state.Entries.Count ||
            state.Entries.Select(static entry => Convert.ToHexString(entry.Digest))
                .Distinct(StringComparer.Ordinal).Count() != state.Entries.Count ||
            state.Entries.Any(entry => entry.Cursor > state.AfterCursor))
        {
            throw new InvalidDataException("Persisted client mailbox state is invalid.");
        }
    }

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

    private static void Prune(ClientMailboxStoredState state)
    {
        if (state.Entries.Count <= ClientMailboxStateLimits.MaximumSeenEntries)
        {
            return;
        }

        var remove = state.Entries
            .Where(static entry => entry.Acknowledged)
            .OrderBy(static entry => entry.Cursor)
            .Take(state.Entries.Count - ClientMailboxStateLimits.MaximumSeenEntries)
            .ToArray();
        foreach (var entry in remove)
        {
            state.Entries.Remove(entry);
        }

        if (state.Entries.Count > ClientMailboxStateLimits.MaximumSeenEntries)
        {
            throw new InvalidDataException(
                "Unacknowledged mailbox history exceeded its persistent bound.");
        }
    }
}

internal static class ClientMailboxStateCodec
{
    private static ReadOnlySpan<byte> V1Magic => "CMS1"u8;
    private static ReadOnlySpan<byte> V2Magic => "CMS2"u8;
    private const int HeaderBytes = 16;
    private const int V1EntryBytes = 40;
    private const int V2EntryBytes = 48;

    public static byte[] Encode(ClientMailboxStoredState state)
    {
        ClientMailboxStateMachine.Validate(state);
        var output = new byte[HeaderBytes + (state.Entries.Count * V2EntryBytes)];
        V2Magic.CopyTo(output);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(4, 8), state.AfterCursor);
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(12, 4),
            checked((uint)state.Entries.Count));
        var offset = HeaderBytes;
        foreach (var entry in state.Entries.OrderBy(static entry => entry.Cursor))
        {
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset, 8), entry.Cursor);
            entry.Digest.CopyTo(output, offset + 8);
            output[offset + 40] = entry.Acknowledged ? (byte)1 : (byte)0;
            offset += V2EntryBytes;
        }

        return output;
    }

    public static ClientMailboxStoredState Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < HeaderBytes)
        {
            throw new InvalidDataException("Client mailbox state is truncated.");
        }

        var isV1 = encoded[..4].SequenceEqual(V1Magic);
        if (!isV1 && !encoded[..4].SequenceEqual(V2Magic))
        {
            throw new InvalidDataException("Client mailbox state version is unsupported.");
        }

        var count = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(12, 4));
        var entryBytes = isV1 ? V1EntryBytes : V2EntryBytes;
        if (count > ClientMailboxStateLimits.MaximumSeenEntries ||
            encoded.Length != HeaderBytes + checked((int)count * entryBytes))
        {
            throw new InvalidDataException("Client mailbox state length is invalid.");
        }

        var state = new ClientMailboxStoredState
        {
            AfterCursor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(4, 8))
        };
        var offset = HeaderBytes;
        for (var index = 0; index < count; index++)
        {
            if (!isV1 &&
                (encoded[offset + 40] > 1 ||
                 encoded.Slice(offset + 41, 7).IndexOfAnyExcept((byte)0) >= 0))
            {
                throw new InvalidDataException("Client mailbox state flags are invalid.");
            }

            state.Entries.Add(new ClientMailboxStoredEntry
            {
                Cursor = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(offset, 8)),
                Digest = encoded.Slice(offset + 8, 32).ToArray(),
                Acknowledged = !isV1 && encoded[offset + 40] == 1
            });
            offset += entryBytes;
        }

        ClientMailboxStateMachine.Validate(state);
        return state;
    }
}
