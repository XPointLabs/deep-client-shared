using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Client.Shared.Persistence.XPointNetworkV1;

public sealed class EntryGuardState
{
    private readonly byte[] networkId, viewHash, localSalt, primaryNodeId;
    private readonly byte[][] confirmedGuardNodeIds;

    public EntryGuardState(
        ulong revision,
        ReadOnlySpan<byte> networkId,
        ulong viewGeneration,
        ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> localSalt,
        ReadOnlySpan<byte> primaryNodeId,
        IEnumerable<ReadOnlyMemory<byte>> confirmedGuardNodeIds)
    {
        if (revision == 0) throw new ArgumentOutOfRangeException(nameof(revision));
        RequireId(networkId, 16, nameof(networkId));
        RequireId(viewHash, 32, nameof(viewHash));
        RequireId(localSalt, 32, nameof(localSalt));
        RequireId(primaryNodeId, 32, nameof(primaryNodeId));
        ArgumentNullException.ThrowIfNull(confirmedGuardNodeIds);
        var guards = confirmedGuardNodeIds.Select(static value => value.ToArray()).ToArray();
        if (guards.Length is < 1 or > 3)
            throw new ArgumentException("Entry guard state requires one to three confirmed guards.", nameof(confirmedGuardNodeIds));
        if (guards.Any(static value => value.Length != 32 || value.AsSpan().IndexOfAnyExcept((byte)0) < 0) ||
            guards.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count() != guards.Length)
            throw new ArgumentException("Confirmed guard IDs must be unique nonzero 32-byte values.", nameof(confirmedGuardNodeIds));
        var containsPrimary = false;
        foreach (var guard in guards)
            containsPrimary |= CryptographicOperations.FixedTimeEquals(guard, primaryNodeId);
        if (!containsPrimary)
            throw new ArgumentException("The primary entry guard must be in the confirmed guard set.", nameof(primaryNodeId));

        Revision = revision;
        this.networkId = networkId.ToArray();
        ViewGeneration = viewGeneration;
        this.viewHash = viewHash.ToArray();
        this.localSalt = localSalt.ToArray();
        this.primaryNodeId = primaryNodeId.ToArray();
        this.confirmedGuardNodeIds = guards;
    }

    public ulong Revision { get; }
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong ViewGeneration { get; }
    public ReadOnlyMemory<byte> ViewHash => viewHash.ToArray();
    public ReadOnlyMemory<byte> LocalSalt => localSalt.ToArray();
    public ReadOnlyMemory<byte> PrimaryNodeId => primaryNodeId.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> ConfirmedGuardNodeIds =>
        Array.AsReadOnly(confirmedGuardNodeIds.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());

    internal static EntryGuardState Copy(EntryGuardState value) => EntryGuardStateCodec.Decode(EntryGuardStateCodec.Encode(value));

    private static void RequireId(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be a nonzero {length}-byte value.", name);
    }
}

public static class EntryGuardStateCodec
{
    private static readonly byte[] Magic = "XGS1"u8.ToArray();
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("Deep/Route01/EntryGuardState/v1");

    public static byte[] Encode(EntryGuardState value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var guards = value.ConfirmedGuardNodeIds;
        var primaryIndex = guards.Select(static guard => guard.ToArray()).ToList()
            .FindIndex(guard => CryptographicOperations.FixedTimeEquals(guard, value.PrimaryNodeId.Span));
        if (primaryIndex < 0) throw new InvalidDataException("Primary entry guard is absent.");
        var bodyLength = 104 + guards.Count * 32;
        var result = new byte[bodyLength + 32];
        var span = result.AsSpan();
        Magic.CopyTo(span); span[4] = 0; span[5] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(span[6..14], value.Revision);
        value.NetworkId.Span.CopyTo(span[14..30]);
        BinaryPrimitives.WriteUInt64BigEndian(span[30..38], value.ViewGeneration);
        value.ViewHash.Span.CopyTo(span[38..70]);
        value.LocalSalt.Span.CopyTo(span[70..102]);
        span[102] = checked((byte)guards.Count);
        span[103] = checked((byte)primaryIndex);
        var offset = 104;
        foreach (var guard in guards)
        {
            guard.Span.CopyTo(span[offset..(offset + 32)]);
            offset += 32;
        }
        var digest = Hash(span[..bodyLength]);
        digest.CopyTo(span[bodyLength..]);
        CryptographicOperations.ZeroMemory(digest);
        return result;
    }

    public static EntryGuardState Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < 168 || !encoded[..4].SequenceEqual(Magic) || encoded[4] != 0 || encoded[5] != 1)
            throw new InvalidDataException("Entry guard state framing is invalid.");
        var count = encoded[102];
        if (count is < 1 or > 3 || encoded.Length != 136 + count * 32 || encoded[103] >= count)
            throw new InvalidDataException("Entry guard state cardinality is invalid.");
        var bodyLength = encoded.Length - 32;
        var digest = Hash(encoded[..bodyLength]);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(digest, encoded[bodyLength..]))
                throw new CryptographicException("Entry guard state authentication failed.");
        }
        finally { CryptographicOperations.ZeroMemory(digest); }

        var guards = new ReadOnlyMemory<byte>[count];
        for (var index = 0; index < count; index++)
            guards[index] = encoded.Slice(104 + index * 32, 32).ToArray();
        var state = new EntryGuardState(
            BinaryPrimitives.ReadUInt64BigEndian(encoded[6..14]),
            encoded[14..30],
            BinaryPrimitives.ReadUInt64BigEndian(encoded[30..38]),
            encoded[38..70], encoded[70..102], guards[encoded[103]].Span, guards);
        var canonical = Encode(state);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(canonical, encoded))
                throw new InvalidDataException("Entry guard state is not canonical.");
        }
        finally { CryptographicOperations.ZeroMemory(canonical); }
        return state;
    }

    private static byte[] Hash(ReadOnlySpan<byte> body)
    {
        var input = new byte[Domain.Length + 1 + body.Length];
        Domain.CopyTo(input, 0);
        body.CopyTo(input.AsSpan(Domain.Length + 1));
        try { return SHA256.HashData(input); }
        finally { CryptographicOperations.ZeroMemory(input); }
    }
}

public enum EntryGuardStoreWriteDisposition { Applied = 1, Conflict = 2 }

public sealed record EntryGuardStoreWriteResult(
    EntryGuardStoreWriteDisposition Disposition,
    EntryGuardState? State);

public interface IProtectedEntryGuardStore
{
    ValueTask<EntryGuardState?> ReadAsync(CancellationToken cancellationToken);
    ValueTask<EntryGuardStoreWriteResult> CompareExchangeAsync(
        ulong? expectedRevision,
        EntryGuardState replacement,
        CancellationToken cancellationToken);
}

public sealed class InMemoryProtectedEntryGuardStore : IProtectedEntryGuardStore
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private EntryGuardState? state;

    public async ValueTask<EntryGuardState?> ReadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return state is null ? null : EntryGuardState.Copy(state); }
        finally { gate.Release(); }
    }

    public async ValueTask<EntryGuardStoreWriteResult> CompareExchangeAsync(
        ulong? expectedRevision,
        EntryGuardState replacement,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (state?.Revision != expectedRevision)
                return new(EntryGuardStoreWriteDisposition.Conflict, state is null ? null : EntryGuardState.Copy(state));
            var required = expectedRevision is null ? 1UL : checked(expectedRevision.Value + 1);
            if (replacement.Revision != required)
                throw new InvalidOperationException("Replacement must use the next guard-state revision.");
            state = EntryGuardState.Copy(replacement);
            return new(EntryGuardStoreWriteDisposition.Applied, EntryGuardState.Copy(state));
        }
        finally { gate.Release(); }
    }
}
