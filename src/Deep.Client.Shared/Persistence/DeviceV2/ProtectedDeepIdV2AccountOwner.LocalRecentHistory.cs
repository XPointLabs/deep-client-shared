using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<IReadOnlyList<DirectMessageCreateSnapshot>> ReadLocalRecentMessagesAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, string conversationId, int maximumItems, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage,
                networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            var selected = Enumerable.Range(0, catalog.Count).Where(index => catalog.Phase(index) == 2 &&
                string.Equals(conversationId, Convert.ToHexString(catalog.Scope(index).Conversation), StringComparison.Ordinal)).ToArray();
            if (selected.Length != 1) throw new InvalidOperationException("The owned conversation is absent or ambiguous.");
            var scope = catalog.Scope(selected[0]);
            using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (floor.Status != 1) throw new InvalidDataException("An inactive or latched session grants no local history.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            _ = await ReadLocalConversationSnapshotUnderLeaseAsync(current, scope, opened, application, floor, ct).ConfigureAwait(false);
            var messages = await application.ListDirectMessageCreatesAsync(current.AccountId,
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]),
                scope.Conversation.ToArray(), maximumItems, cancellationToken: ct).ConfigureAwait(false);
            await RequireLocalHistoryCatalogAsync(catalog.Exact, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return messages;
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }
}
