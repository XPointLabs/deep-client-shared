using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    internal const int MaximumOperationReadBatch = 32;

    // Local materialization only. Every invocation verifies the COMPLETE actual
    // SQL state against the independent floor in one read transaction. No await,
    // callback, mutation or previous verification result crosses this snapshot.
    // Bound memory to at most32 selected envelopes/plaintexts; caller owns them.
    internal IReadOnlyList<OwnedDid2MessagingPersistedEvent?> ReadVerifiedOperations(
        Did2MessagingFloor protectedStable, IReadOnlyList<ReadOnlyMemory<byte>> operations)
    {
        ArgumentNullException.ThrowIfNull(operations);
        var count = operations.Count;
        if (count is < 1 or > MaximumOperationReadBatch)
            throw new ArgumentException("Native operation read batch exceeds its closed bound.", nameof(operations));
        var selectors = new List<byte[]>(count);
        var result = new List<OwnedDid2MessagingPersistedEvent?>(count);
        try
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 0; index < count; index++)
            {
                var input = operations[index];
                if (input.Length != 32) throw new ArgumentException("Native operation selector has another size.", nameof(operations));
                var selector = input.ToArray(); selectors.Add(selector);
                if (Did2MessagingSessionScope.Zero(selector) ||
                    !seen.Add(Convert.ToHexString(selector)))
                    throw new ArgumentException("Native operation read batch requires distinct nonzero selectors.", nameof(operations));
            }
            _ = Did2MessagingFloor.Decode(protectedStable.Exact.Span, scope);
            if (protectedStable.Phase != 1 || protectedStable.Status != 1)
                throw new InvalidDataException("Native operation read batch requires active stable custody.");
            using var tx = connection.BeginTransaction(deferred: true);
            RequireSame(protectedStable, VerifyTipInTransaction(tx));
            using var command = Command("SELECT direction,length(envelope),envelope,length(plaintext),plaintext,metadata,ordinal FROM events WHERE operation=$op;", tx);
            var parameter = command.Parameters.Add("$op", Microsoft.Data.Sqlite.SqliteType.Blob);
            foreach (var selector in selectors)
            {
                parameter.Value = selector;
                using var row = command.ExecuteReader();
                result.Add(ReadSelectedOrdinaryEvent(protectedStable, row));
            }
            return result;
        }
        catch { foreach (var item in result) item?.Dispose(); throw; }
        finally { foreach (var selector in selectors) CryptographicOperations.ZeroMemory(selector); }
    }
}
