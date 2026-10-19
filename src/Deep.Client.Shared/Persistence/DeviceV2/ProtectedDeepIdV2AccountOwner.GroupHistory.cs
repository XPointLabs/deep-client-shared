using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task<byte[]?> ReadOwnedAuthoredHistoryUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        SqliteDeepMailboxStore application, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> eventHash, CancellationToken ct)
    {
        using var groups = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        return RequireGroupAuthoredEvent(groups.State, scope, operation.Span, eventHash.Span) ??
            await application.ReadRetainedAuthoredEventAsync(scope, eventHash, ct).ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<DeepIdV2GroupSnapshot>> ListGroupsAsync(ulong seconds, IDeepMlDsa65Verifier verifier, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        using var root = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        var result = root.State.Groups.Select(group =>
        {
            var package = GroupCodec.Decode("GCP1", group.Packages[^1]); var commit = GroupCodec.Decode("DGC1", package.Field(4).Span[4..]);
            return new DeepIdV2GroupSnapshot(Convert.ToHexStringLower(group.Id), group.Fork ? "Forked" : GroupMemberSelectors(commit).Any(id => id.AsSpan().SequenceEqual(current.AccountId.Span)) && group.Packages.Count > 1 ? "Active" : group.Invitations.Any(item => item.Acceptance.Length != 0) ? "Accepted" : group.Invitations.Count != 0 ? "Invited" : "Created",
                BinaryPrimitives.ReadUInt64BigEndian(package.Field(3).Span), root.State.Outbox.Where(item => item.Group.AsSpan().SequenceEqual(group.Id) && ApplicationCoreCodec.DecodeDmc2(item.Event).ContentKind == Dmc2ContentKind.GroupApplicationMessage).Select(item => Convert.ToHexString(((GroupDmc2Payload)ApplicationCoreCodec.DecodeDmc2(item.Event).ParsedPayload).Record.Field(5).Span)).Distinct(StringComparer.Ordinal).Count(),
                new UTF8Encoding(false, true).GetString(commit.Field(13).Span), GroupMemberSelectors(commit).Count);
        }).ToArray();
        held.RequireActive(); ct.ThrowIfCancellationRequested(); return result;
    }

    internal async Task<IReadOnlyList<DeepIdV2GroupMessageSnapshot>> ListGroupMessagesAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        ReadOnlyMemory<byte> groupId, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        using var root = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false); _ = root.State.Find(groupId.Span);
        var selected = root.State.Messages.Where(item => item.Group.AsSpan().SequenceEqual(groupId.Span))
            .Select((item, index) => (Item: item, Index: index)).ToArray();
        var result = new DeepIdV2GroupMessageSnapshot[selected.Length];
        foreach (var byScope in selected.GroupBy(row => Convert.ToHexString(row.Item.Scope), StringComparer.Ordinal))
        {
            var scope = Did2MessagingSessionScope.RestoreMetadata(byScope.First().Item.Scope);
            using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (floor.Status != 1) throw new CryptographicException("Latched session grants no group history.");
            foreach (var chunk in byScope.Chunk(Did2MessagingSqlJournal.MaximumOperationReadBatch))
            {
                ct.ThrowIfCancellationRequested();
                var nativeRows = opened.Sql.ReadVerifiedOperations(floor, chunk.Select(row => (ReadOnlyMemory<byte>)row.Item.Operation).ToArray());
                try
                {
                    for (var index = 0; index < chunk.Length; index++)
                    {
                        var native = nativeRows[index] ?? throw new CryptographicException("Group history lost its actual native row.");
                        // Preserve the protected journal's original cross-scope order.
                        result[chunk[index].Index] = ReadGroupHistorySnapshot(root.State, scope, chunk[index].Item, native);
                    }
                }
                finally { foreach (var native in nativeRows) native?.Dispose(); }
            }
        }
        held.RequireActive(); ct.ThrowIfCancellationRequested(); return result;
    }

    private static DeepIdV2GroupMessageSnapshot ReadGroupHistorySnapshot(ProtectedDid2GroupJournal.State state,
        Did2MessagingSessionScope scope, ProtectedDid2GroupJournal.Message item, OwnedDid2MessagingPersistedEvent native)
    {
        if (native.Direction != item.Direction) throw new CryptographicException("Group history direction changed.");
        byte[] exact;
        if (native.Direction == 1) exact = RequireGroupAuthoredEvent(state, scope, item.Operation, native.EventHash) ?? throw new CryptographicException("Group history lost original authored custody.");
        else { using var owned = native.OwnAuthenticatedDmc2(); exact = owned.Use(bytes => bytes.ToArray()); }
        try
        {
            var record = RequireGroupEnvelope(ApplicationCoreCodec.DecodeDmc2(exact), scope, native.Direction == 1);
            if (!SHA256.HashData(exact).AsSpan().SequenceEqual(native.EventHash) || !record.CanonicalBytes.Span.SequenceEqual(item.Record))
                throw new CryptographicException("Group projection differs from actual native history.");
            return new(new UTF8Encoding(false, true).GetString(record.Field(12).Span), item.Direction == 1,
                BinaryPrimitives.ReadUInt64BigEndian(record.Field(8).Span));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    internal async Task<IReadOnlyList<byte[]>> ReadGroupMemberSelectorsAsync(ulong seconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> groupId, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        using var root = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        var group = root.State.Find(groupId.Span); if (group.Fork) throw new CryptographicException("Group is fork-latched.");
        var package = GroupCodec.Decode("GCP1", group.Packages[^1]);
        return GroupMemberSelectors(GroupCodec.Decode("DGC1", package.Field(4).Span[4..]));
    }

    internal async Task<IReadOnlyList<ProtectedDid2GroupJournal.Outgoing>> ReadGroupBatchAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        ReadOnlyMemory<byte> groupId, Did2MessagingSessionScope scope, CancellationToken ct, bool pendingOnly = false)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        await ResumeGroupOrdinaryUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
        using var root = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        var group = root.State.Find(groupId.Span);
        if (group.Fork) throw new CryptographicException("Group fanout scope is unavailable.");
        using var ordinaryRoot = pendingOnly
            ? await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Group scheduling lost actual authored custody.") : null;
        using var ordinary = ordinaryRoot?.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        var result = root.State.Outbox.Where(item => item.Group.AsSpan().SequenceEqual(groupId.Span) && item.Scope.AsSpan().SequenceEqual(scope.Exact) &&
                (!pendingOnly || !HasCompletedGroupDeliveryHint(item, ordinary!, scope)))
            .Select(item => new ProtectedDid2GroupJournal.Outgoing { Group = item.Group.ToArray(), Operation = item.Operation.ToArray(), Scope = item.Scope.ToArray(), Event = item.Event.ToArray(), Adopted = item.Adopted }).ToArray();
        if (result.Length == 0) return result;
        try
        {
            using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            foreach (var chunk in result.Chunk(Did2MessagingSqlJournal.MaximumOperationReadBatch))
            {
                ct.ThrowIfCancellationRequested();
                var nativeRows = opened.Sql.ReadVerifiedOperations(floor, chunk.Select(item => (ReadOnlyMemory<byte>)item.Operation).ToArray());
                try
                {
                    for (var index = 0; index < chunk.Length; index++)
                    {
                        var item = chunk[index]; var native = nativeRows[index];
                        if (native is null) continue;
                        if (native.Direction != 1 || !SHA256.HashData(item.Event).AsSpan().SequenceEqual(native.EventHash))
                            throw new CryptographicException("Group batch differs from actual native send custody.");
                        item.NativeCommitted = true;
                    }
                }
                finally { foreach (var native in nativeRows) native?.Dispose(); }
            }
            if (ordinaryRoot is not null)
            {
                var expected = ordinaryRoot.Use(bytes => bytes.ToArray());
                try { await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, expected, ct).ConfigureAwait(false); }
                finally { CryptographicOperations.ZeroMemory(expected); }
            }
            held.RequireActive(); ct.ThrowIfCancellationRequested(); return result;
        }
        catch
        {
            foreach (var item in result) foreach (var bytes in new[] { item.Group, item.Operation, item.Scope, item.Event }) CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    // Scheduling metadata ONLY. True does not return a Store receipt, ACK,
    // delivery success or permission to retire anything. No journal is changed.
    // Unknown/missing/stopped custody stays in the ordinary owned path. Explicit
    // flush never invokes this filter and still audits every original receipt.
    internal static bool HasCompletedGroupDeliveryHint(ProtectedDid2GroupJournal.Outgoing item,
        ProtectedDid2DirectTextJournal.State ordinary, Did2MessagingSessionScope scope)
    {
        if (!item.Scope.AsSpan().SequenceEqual(scope.Exact))
            throw new CryptographicException("Group scheduling selected another native scope.");
        if (!item.Adopted) return false;
        var key = Convert.ToHexString(item.Operation);
        if (ordinary.Entries.TryGetValue(key, out var entry))
        {
            if (!entry.Scope.Exact.SequenceEqual(scope.Exact))
                throw new CryptographicException("Group scheduling selected another authored scope.");
            entry.RequireEvent(item.Event);
            return entry.Stored;
        }
        return ordinary.TerminalAudits.TryGetValue(key, out var terminal) && terminal.Reason == 3;
    }
}
