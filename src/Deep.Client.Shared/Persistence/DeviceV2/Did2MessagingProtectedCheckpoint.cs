using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>DR-0027 protected staging/recovery mechanics. Every call requires
/// the account owner's process-independent lease. This component neither
/// authorizes SQL transitions nor mints send/receive/retirement capabilities.</summary>
internal sealed class Did2MessagingProtectedCheckpoint(IDeepSecureStorage storage, Did2MessagingSessionScope scope)
{
    private readonly IDeepSecureStorage storage = storage ?? throw new ArgumentNullException(nameof(storage));
    private readonly Did2MessagingSessionScope scope = scope ?? throw new ArgumentNullException(nameof(scope));
    private string PartSlot(int index) => scope.FloorSlot + ".pending." + index.ToString(System.Globalization.CultureInfo.InvariantCulture);
    private string[] PartSlots() => Enumerable.Range(0, Did2MessagingFloor.MaximumParts).Select(PartSlot).ToArray();

    internal async Task<Did2MessagingFloor> ReadAsync(CancellationToken ct)
    {
        using var owned = await storage.ReadOwnedAsync(scope.FloorSlot, ct).ConfigureAwait(false)
            ?? throw new InvalidDataException("Protected DID2 messaging floor is absent; no state repair is permitted.");
        return owned.Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
    }

    #if DEEP_TEST_INTERNALS
    // Structural test fixture only. Production initialization is atomic catalog
    // CAS-and-insert; no standalone floor initializer exists in shipping code.
    internal Task InitializeRegisteredSessionAsync(CancellationToken ct) => storage.WriteBatchAsync(
        [new(scope.FloorSlot, Did2MessagingFloor.Empty(scope).Exact)], ct);
    #endif

    internal async Task EraseStableOrphansAsync(Did2MessagingFloor stable, CancellationToken ct)
    {
        _ = Did2MessagingFloor.Decode(stable.Exact.Span, scope);
        var current = await ReadAsync(ct).ConfigureAwait(false);
        if (stable.Phase != 1 || !Did2MessagingSessionScope.Fixed(current.Exact.Span, stable.Exact.Span))
            throw new CryptographicException("Protected messaging orphan cleanup lacks its exact stable floor.");
        await storage.DeleteBatchAsync(PartSlots(), ct).ConfigureAwait(false);
    }

    internal async Task StageAsync(Did2MessagingFloor predecessor, Did2MessagingFloor pending,
        ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        _ = Did2MessagingFloor.Decode(predecessor.Exact.Span, scope);
        _ = Did2MessagingFloor.Decode(pending.Exact.Span, scope);
        if (predecessor.Phase != 1 || pending.Phase != 2 || predecessor.Ordinal == ulong.MaxValue ||
            pending.Ordinal != predecessor.Ordinal + 1 || payload.Length != pending.PendingBytes ||
            payload.Length < Did2MessagingFloor.MetadataBytes || payload.Length > Did2MessagingFloor.MaximumPendingBytes)
            throw new InvalidDataException("Protected messaging staging has a different predecessor or size.");
        // Take ownership before the first await; caller memory cannot change
        // what the floor's full-payload hash authenticates.
        using var copy = new OwnedDeepSecret(payload.Span);
        copy.Use(bytes =>
        {
            if (!Did2MessagingSessionScope.Fixed(SHA256.HashData(bytes), pending.PendingHash) ||
                !Did2MessagingSessionScope.Fixed(Did2MessagingFloor.JournalHead(scope, pending.Ordinal, predecessor.Head, bytes[..Did2MessagingFloor.MetadataBytes]), pending.Head))
                throw new CryptographicException("Protected messaging pending commitments differ.");
        });
        var current = await ReadAsync(ct).ConfigureAwait(false);
        if (Did2MessagingSessionScope.Fixed(current.Exact.Span, pending.Exact.Span))
        {
            using var retained = await ReadPendingAsync(current, ct).ConfigureAwait(false);
            // Both owned values have been checked against the same exact
            // protected full-payload commitment; no fresh crypto is prepared.
            return;
        }
        if (!Did2MessagingSessionScope.Fixed(current.Exact.Span, predecessor.Exact.Span))
            throw new CryptographicException("Protected messaging predecessor changed; pending keys are not overwritten.");
        // A crash after atomic part write but before floor CAS leaves only
        // unreferenced parts. Never delete parts of a different pending floor.
        await storage.DeleteBatchAsync(PartSlots(), ct).ConfigureAwait(false);
        var chunks = copy.Use(bytes => Split(bytes));
        try
        {
            var writes = chunks.Select((bytes, index) => new DeepSecureStorageWrite(PartSlot(index), bytes)).ToArray();
            await storage.WriteBatchAsync(writes, ct).ConfigureAwait(false);
            if (!await storage.CompareExchangeAsync(scope.FloorSlot, predecessor.Exact, pending.Exact, ct).ConfigureAwait(false))
                throw new CryptographicException("Protected messaging pending CAS failed.");
        }
        finally { foreach (var chunk in chunks) CryptographicOperations.ZeroMemory(chunk); }
    }

    internal async Task<OwnedDeepSecret> ReadPendingAsync(Did2MessagingFloor pending, CancellationToken ct)
    {
        _ = Did2MessagingFloor.Decode(pending.Exact.Span, scope);
        if (pending.Phase != 2) throw new InvalidDataException("Only a pending floor requires protected message payload.");
        var current = await ReadAsync(ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(current.Exact.Span, pending.Exact.Span))
            throw new CryptographicException("Protected messaging pending floor changed.");
        var bytes = new byte[pending.PendingBytes];
        try
        {
            for (var index = 0; index < pending.PartCount; index++)
            {
                using var part = await storage.ReadOwnedAsync(PartSlot(index), ct).ConfigureAwait(false)
                    ?? throw new InvalidDataException("A protected messaging pending part is absent.");
                var offset = index * Did2MessagingFloor.PartBytes;
                var length = Math.Min(Did2MessagingFloor.PartBytes, bytes.Length - offset);
                if (part.Length != length) throw new InvalidDataException("A protected messaging pending part has a different size.");
                part.CopyTo(bytes.AsSpan(offset, length));
            }
            for (var index = pending.PartCount; index < Did2MessagingFloor.MaximumParts; index++)
            {
                using var extra = await storage.ReadOwnedAsync(PartSlot(index), ct).ConfigureAwait(false);
                if (extra is not null) throw new InvalidDataException("Protected messaging pending has noncanonical extra parts.");
            }
            if (!Did2MessagingSessionScope.Fixed(SHA256.HashData(bytes), pending.PendingHash))
                throw new CryptographicException("Protected messaging pending payload hash differs.");
            return new OwnedDeepSecret(bytes);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    /// <summary>Call only after independently checking SQL contains this exact
    /// successor (journal, latest TRS and inbox/outbox). Cleanup tolerates already
    /// erased parts; it does not use an erased predecessor key to recover.</summary>
    internal async Task<Did2MessagingFloor> FinishVerifiedSqlCommitAsync(Did2MessagingFloor pending, CancellationToken ct)
    {
        _ = Did2MessagingFloor.Decode(pending.Exact.Span, scope);
        var cleanup = pending.Cleanup(scope); var stable = cleanup.Stable(scope);
        var current = await ReadAsync(ct).ConfigureAwait(false);
        if (Did2MessagingSessionScope.Fixed(current.Exact.Span, pending.Exact.Span))
        {
            if (!await storage.CompareExchangeAsync(scope.FloorSlot, pending.Exact, cleanup.Exact, ct).ConfigureAwait(false))
                throw new CryptographicException("Protected messaging cleanup CAS failed.");
        }
        else if (!Did2MessagingSessionScope.Fixed(current.Exact.Span, cleanup.Exact.Span) &&
                 !Did2MessagingSessionScope.Fixed(current.Exact.Span, stable.Exact.Span))
            throw new CryptographicException("Protected messaging SQL completion has a different successor.");
        await storage.DeleteBatchAsync(PartSlots(), ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(current.Exact.Span, stable.Exact.Span) &&
            !await storage.CompareExchangeAsync(scope.FloorSlot, cleanup.Exact, stable.Exact, ct).ConfigureAwait(false))
            throw new CryptographicException("Protected messaging stable CAS failed.");
        return stable;
    }

    private static byte[][] Split(ReadOnlySpan<byte> bytes)
    {
        var count = Did2MessagingFloor.PartsFor(bytes.Length); var result = new byte[count][];
        try
        {
            for (var index = 0; index < count; index++)
            {
                var offset = index * Did2MessagingFloor.PartBytes;
                result[index] = bytes.Slice(offset, Math.Min(Did2MessagingFloor.PartBytes, bytes.Length - offset)).ToArray();
            }
            return result;
        }
        catch { foreach (var part in result) if (part is not null) CryptographicOperations.ZeroMemory(part); throw; }
    }
}
