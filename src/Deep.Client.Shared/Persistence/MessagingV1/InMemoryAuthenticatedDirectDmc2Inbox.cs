using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.MessagingV1;

/// <summary>Deterministic parity model for the clean account-wide DMC2 inbox.</summary>
internal sealed class InMemoryAuthenticatedDirectDmc2Inbox : IDisposable
{
    private const int MaximumEvents = 100_000;
    private readonly object gate = new();
    private readonly Dictionary<string, byte[]> events = new(StringComparer.Ordinal);
    private readonly HashSet<string> forks = new(StringComparer.Ordinal);
    private byte[]? localAccountId;
    private ulong localAccountGeneration;
    private bool disposed;

    internal Task<DirectDmc2InboxDisposition> MaterializeDirectDmc2Async(
        AuthenticatedDirectDmc2 handoff,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ThrowIfDisposed();
            var local = handoff.LocalAccountId.ToArray();
            try
            {
                CheckOwner(local, handoff.LocalAccountGeneration);
                var key = Key(handoff.ConversationId.Span,
                    handoff.LogicalMessageId.Span, handoff.AuthorDeviceId.Span);
                if (forks.Contains(key))
                    return Task.FromResult(DirectDmc2InboxDisposition.ForkLatched);
                var exact = handoff.ExactDmc2.ToArray();
                try
                {
                    if (events.TryGetValue(key, out var incumbent))
                    {
                        if (Fixed(incumbent, exact))
                            return Task.FromResult(DirectDmc2InboxDisposition.ExactReplay);
                        cancellationToken.ThrowIfCancellationRequested();
                        BindOwner(local, handoff.LocalAccountGeneration);
                        forks.Add(key);
                        return Task.FromResult(DirectDmc2InboxDisposition.ForkLatched);
                    }
                    if (events.Count >= MaximumEvents)
                        return Task.FromResult(DirectDmc2InboxDisposition.CapacityExceeded);
                    cancellationToken.ThrowIfCancellationRequested();
                    BindOwner(local, handoff.LocalAccountGeneration);
                    events.Add(key, exact.ToArray());
                    return Task.FromResult(DirectDmc2InboxDisposition.Materialized);
                }
                finally { CryptographicOperations.ZeroMemory(exact); }
            }
            finally { CryptographicOperations.ZeroMemory(local); }
        }
    }

    internal Task<DirectDmc2InboxDisposition> MaterializeInitialDmc2BatchAsync(
        AuthenticatedInitialDmc2Batch batch,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batch);
        cancellationToken.ThrowIfCancellationRequested();
        var exacts = new List<byte[]>(batch.EventCount)
        {
            batch.SessionInitDmc2,
        };
        if (batch.EventCount == 2) exacts.Add(batch.FirstApplicationDmc2);
        var local = batch.LocalAccountId;
        try
        {
            lock (gate)
            {
                ThrowIfDisposed();
                CheckOwner(local, batch.LocalAccountGeneration);
                var newItems = new List<(string Key, byte[] Exact)>(exacts.Count);
                foreach (var exact in exacts)
                {
                    var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
                    if (parsed.ContentKind != Dmc2ContentKind.SessionInit &&
                        !AuthenticatedInitialDmc2Batch.IsSupportedInitialApplicationKind(parsed.ContentKind))
                        throw new CryptographicException("The initial inbox event kind is unsupported.");
                    var key = Key(parsed.ConversationId.Span,
                        parsed.LogicalMessageId.Span, parsed.SenderDeviceId.Span);
                    if (forks.Contains(key))
                        return Task.FromResult(DirectDmc2InboxDisposition.ForkLatched);
                    if (events.TryGetValue(key, out var incumbent))
                    {
                        if (Fixed(incumbent, exact)) continue;
                        cancellationToken.ThrowIfCancellationRequested();
                        BindOwner(local, batch.LocalAccountGeneration);
                        forks.Add(key);
                        return Task.FromResult(DirectDmc2InboxDisposition.ForkLatched);
                    }
                    newItems.Add((key, exact));
                }
                if (events.Count + newItems.Count > MaximumEvents)
                    return Task.FromResult(DirectDmc2InboxDisposition.CapacityExceeded);
                cancellationToken.ThrowIfCancellationRequested();
                BindOwner(local, batch.LocalAccountGeneration);
                foreach (var item in newItems) events.Add(item.Key, item.Exact.ToArray());
                return Task.FromResult(newItems.Count == 0
                    ? DirectDmc2InboxDisposition.ExactReplay
                    : DirectDmc2InboxDisposition.Materialized);
            }
        }
        finally
        {
            foreach (var exact in exacts) CryptographicOperations.ZeroMemory(exact);
            CryptographicOperations.ZeroMemory(local);
        }
    }

    internal Task<byte[]?> ReadDirectDmc2Async(
        ReadOnlyMemory<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlyMemory<byte> conversationId,
        ReadOnlyMemory<byte> logicalMessageId,
        ReadOnlyMemory<byte> authorDeviceId,
        CancellationToken cancellationToken = default)
    {
        ValidateId(localAccountId, nameof(localAccountId));
        ValidateId(conversationId, nameof(conversationId));
        ValidateId(logicalMessageId, nameof(logicalMessageId));
        ValidateId(authorDeviceId, nameof(authorDeviceId));
        if (localAccountGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(localAccountGeneration));
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ThrowIfDisposed();
            if (this.localAccountId is null) return Task.FromResult<byte[]?>(null);
            CheckOwner(localAccountId.Span, localAccountGeneration);
            var key = Key(conversationId.Span, logicalMessageId.Span, authorDeviceId.Span);
            if (forks.Contains(key))
                throw new CryptographicException("The direct inbox event is forked.");
            return Task.FromResult(events.TryGetValue(key, out var exact)
                ? (byte[]?)exact.ToArray() : null);
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            if (localAccountId is not null)
                CryptographicOperations.ZeroMemory(localAccountId);
            foreach (var value in events.Values)
                CryptographicOperations.ZeroMemory(value);
            events.Clear();
            forks.Clear();
        }
    }

    private void CheckOwner(ReadOnlySpan<byte> account, ulong generation)
    {
        if (localAccountId is not null &&
            (!Fixed(localAccountId, account) ||
             localAccountGeneration != generation))
            throw new CryptographicException(
                "The direct inbox belongs to another local account generation.");
    }

    private void BindOwner(ReadOnlySpan<byte> account, ulong generation)
    {
        if (localAccountId is not null) return;
        localAccountId = account.ToArray();
        localAccountGeneration = generation;
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(disposed, this);

    private static string Key(
        ReadOnlySpan<byte> conversation,
        ReadOnlySpan<byte> logical,
        ReadOnlySpan<byte> device) =>
        string.Concat(Convert.ToHexString(conversation), ":",
            Convert.ToHexString(logical), ":", Convert.ToHexString(device));

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void ValidateId(ReadOnlyMemory<byte> value, string name)
    {
        if (value.Length != 32 || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte identifier is required.", name);
    }
}
