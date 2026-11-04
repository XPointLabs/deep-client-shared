using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Detached import evidence only. It contains no original source key, SQL
// connection, permission to activate, or permission to reconstruct Initial.
internal sealed class Did2EstablishedNativeProvenance
{
    internal Did2MessagingSessionScope Scope { get; }
    internal ReadOnlyMemory<byte> OriginalTrsHash { get; }
    internal ReadOnlyMemory<byte> ClaimOperation { get; }
    internal ReadOnlyMemory<byte> InitialHeaderHash { get; }
    internal ReadOnlyMemory<byte> SourceInstance { get; }
    internal ReadOnlyMemory<byte> InitialBasis { get; }
    internal byte Role { get; }
    internal Did2EstablishedNativeProvenance(Did2MessagingSessionScope scope, ReadOnlySpan<byte> metadata,
        ProtectedInitialKeyRetirementJournal.Entry retirement)
    {
        Scope = scope; OriginalTrsHash = metadata.Slice(236, 32).ToArray();
        ClaimOperation = metadata.Slice(268, 32).ToArray(); InitialHeaderHash = SHA256.HashData(metadata);
        SourceInstance = retirement.SourceInstance.ToArray(); InitialBasis = scope.InitialBasis.ToArray(); Role = retirement.Role;
    }
}

internal sealed partial class Did2MessagingSqlJournal
{
    // Positive classification for the cold audit's Initial owner only. A
    // failed established proof must never be treated as inactive custody.
    internal bool ClassifyInitialOwnedNativeAudit(Did2MessagingFloor actualFloor, byte[]? authenticatedPendingHeader)
    {
        _ = Did2MessagingFloor.Decode(actualFloor.Exact.Span, scope);
        var candidate = actualFloor.Ordinal == 0 && actualFloor.Status == 0 ||
            actualFloor.Ordinal == 1 && actualFloor.Status == 0 ||
            actualFloor.Ordinal == 2 && (actualFloor.Status == 2 || actualFloor.Status == 1 && actualFloor.Phase is 2 or 3);
        if (!candidate) return false;
        if (archiveRoot is null || !Fixed(archiveRoot.Exact.Span, Did2MessagingArchiveRoot.Empty(scope).Exact.Span) ||
            !Fixed(historyRoot.Exact.Span, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.Span))
            throw new CryptographicException("Initial-owned native audit requires its exact canonical empty archive/history.");
        using var tx = connection.BeginTransaction(deferred: true);
        var tip = VerifyActiveTip(tx, null, out var headers);
        if (actualFloor.Ordinal == 0)
        {
            if (authenticatedPendingHeader is not null) throw new InvalidDataException("Empty native custody cannot retain a pending import header.");
            RequireSame(actualFloor, tip); return true;
        }
        var expectedKind = actualFloor.Ordinal == 1 ? (byte)1 : actualFloor.Status == 1 ? (byte)3 : (byte)4;
        byte[] header;
        if (actualFloor.Phase == 1)
        {
            if (authenticatedPendingHeader is not null || headers.Count == 0)
                throw new InvalidDataException("Stable Initial-owned custody has inconsistent pending metadata.");
            RequireSame(actualFloor, tip); header = headers[^1];
        }
        else
        {
            if (authenticatedPendingHeader is not null) header = authenticatedPendingHeader;
            else if (actualFloor.Phase == 3 && headers.Count != 0) header = headers[^1];
            else throw new CryptographicException("Pending Initial-owned audit lost its authenticated exact header.");
        }
        if (header.Length != Did2MessagingFloor.MetadataBytes || header[5] != expectedKind)
            throw new CryptographicException("Initial-owned audit has a different actual mutation kind.");
        var before = Did2MessagingFloor.Decode(header.AsSpan(8, Did2MessagingFloor.Bytes), scope);
        if (expectedKind == 1 ? before.Ordinal != 0 || before.Status != 0 : before.Ordinal != 1 || before.Status != 0)
            throw new CryptographicException("Initial-owned audit has a different exact import predecessor.");
        var after = Did2MessagingFloor.FromJournalMetadata(scope, before, header);
        var stable = actualFloor.Phase == 2 ? actualFloor.Cleanup(scope).Stable(scope) :
            actualFloor.Phase == 3 ? actualFloor.Stable(scope) : actualFloor;
        RequireSame(stable, after);
        if (Fixed(tip.Exact.Span, after.Exact.Span))
        {
            if (headers.Count == 0 || !Fixed(headers[^1], header))
                throw new CryptographicException("Initial-owned SQL-after lost its exact actual header.");
        }
        else
        {
            if (actualFloor.Phase != 2) throw new CryptographicException("Initial-owned cleanup cannot precede its SQL commit.");
            RequireSame(before, tip);
        }
        return true;
    }

    // Stored-prefix handoff can temporarily have SQL at the exact successor
    // while its protected root is still before. Its existing plan operation
    // verifies that exact ancestry/suffix; this seam verifies only the actual
    // original import and retirement, without assuming mirror equality.
    internal Did2EstablishedNativeProvenance RequireEstablishedNativeImport(
        ProtectedInitialKeyRetirementJournal.Entry retirement)
    {
        using var tx = connection.BeginTransaction(deferred: true);
        RequireCipherPolicy(tx); ValidateSchema(tx);
        return RequireEstablishedNativeImport(retirement, tx);
    }

    internal Did2EstablishedNativeProvenance RequireEstablishedNativeProvenance(Did2MessagingFloor actualFloor,
        ProtectedInitialKeyRetirementJournal.Entry retirement)
    {
        _ = Did2MessagingFloor.Decode(actualFloor.Exact.Span, scope);
        if (actualFloor.Status == 0 || actualFloor.Ordinal < 2 || actualFloor.Ordinal == 2 && actualFloor.Status == 2)
            throw new CryptographicException("Established admission cannot import or activate an Initial session.");
        using var tx = connection.BeginTransaction(deferred: true);
        var tip = VerifyActiveTip(tx, null, out var headers);
        var proof = RequireEstablishedNativeImport(retirement, tx);
        if (actualFloor.Phase == 1)
        {
            RequireSame(actualFloor, tip);
            return proof;
        }
        var after = actualFloor.Phase == 2 ? actualFloor.Cleanup(scope).Stable(scope) : actualFloor.Stable(scope);
        if (Fixed(after.Exact.Span, tip.Exact.Span))
        {
            // The actual SQL-after header determines the recovered kind. Never
            // admit a pending kind1/kind3 via this established opener.
            if (headers.Count == 0 || headers[^1][5] is not (2 or 4 or 5 or 6) ||
                Did2MessagingFloor.Decode(headers[^1].AsSpan(8, 188), scope).Status != 1)
                throw new CryptographicException("Established recovery has no actual active mutation predecessor.");
            return proof;
        }
        // Phase2 may precede its SQL append. Reconcile subsequently verifies
        // the exact protected payload/hash/header before any append or cleanup.
        // Phase3 cannot precede SQL, and activation's ordinal2 cannot enter.
        if (actualFloor.Phase != 2 || tip.Status != 1 || tip.Ordinal < 2 ||
            tip.Ordinal == ulong.MaxValue || actualFloor.Ordinal != tip.Ordinal + 1)
            throw new CryptographicException("Established pending custody differs from its actual SQL predecessor.");
        var advancing = actualFloor.Status == 1 && tip.RatchetGeneration != ulong.MaxValue &&
            actualFloor.RatchetGeneration == tip.RatchetGeneration + 1;
        var same = actualFloor.Status == 1 && actualFloor.RatchetGeneration == tip.RatchetGeneration &&
            Fixed(actualFloor.RatchetCommitment, tip.RatchetCommitment) && Fixed(actualFloor.RatchetHash, tip.RatchetHash);
        var terminal = actualFloor.Status == 2 && actualFloor.RatchetGeneration == tip.RatchetGeneration;
        if (!advancing && !same && !terminal)
            throw new CryptographicException("Established pending ratchet shape differs from active custody.");
        return proof;
    }

    private Did2EstablishedNativeProvenance RequireEstablishedNativeImport(
        ProtectedInitialKeyRetirementJournal.Entry retirement, SqliteTransaction tx)
    {
        ArgumentNullException.ThrowIfNull(retirement);
        var header = ReadVerifiedInitialImport(tx);
        using (var query = Command("SELECT singleton,exact_scope,typeof(exact_scope),length(exact_scope) FROM scope;", tx))
        using (var row = query.ExecuteReader())
            if (!row.Read() || row.GetInt64(0) != 1 || row.GetString(2) != "blob" || row.GetInt64(3) != Did2MessagingSessionScope.Bytes ||
                !Fixed(row.GetFieldValue<byte[]>(1), scope.Exact) || row.Read())
                throw new CryptographicException("Established native import has a different actual SQL scope.");
        if (WorkingBasis.Ordinal != 0 && !Fixed(SHA256.HashData(header), ReadArchiveInitialHeaderHash(tx)))
            throw new CryptographicException("Established native import lost its protected initial-header commitment.");
        byte[] source;
        if (scope.IsInitiator)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData("Deep/STORE-V2/device-state-key"u8); hash.AppendData(scope.Network);
            hash.AppendData(scope.LocalAccount); hash.AppendData(scope.Instance); source = hash.GetHashAndReset();
        }
        else source = scope.Instance.ToArray();
        if (retirement.Role != (scope.IsInitiator ? 1 : 2) || retirement.Phase != 2 ||
            !Fixed(retirement.SourceInstance, source) || !Fixed(retirement.ScopeHash, scope.Hash) ||
            !Fixed(retirement.Basis, scope.InitialBasis) || !Fixed(retirement.TrsHash, header.AsSpan(236, 32)) ||
            !scope.IsInitiator && !Fixed(retirement.Intent, header.AsSpan(268, 32)))
            throw new CryptographicException("Established native import has no exact stable source retirement.");
        return new(scope, header, retirement);
    }
}
