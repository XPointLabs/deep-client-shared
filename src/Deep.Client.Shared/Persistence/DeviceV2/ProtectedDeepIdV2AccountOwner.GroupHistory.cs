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
        var result = new List<DeepIdV2GroupMessageSnapshot>();
        var openedScopes = new Dictionary<string, OwnedDid2MessagingStorage>(StringComparer.Ordinal);
        try
        {
        foreach (var item in root.State.Messages.Where(item => item.Group.AsSpan().SequenceEqual(groupId.Span)))
        {
            var scope = Did2MessagingSessionScope.RestoreMetadata(item.Scope);
            var scopeKey = Convert.ToHexString(scope.Exact);
            if (!openedScopes.TryGetValue(scopeKey, out var opened))
            {
                opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
                openedScopes.Add(scopeKey, opened);
            }
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (floor.Status != 1) throw new CryptographicException("Latched session grants no group history.");
            using var native = opened.Sql.ReadVerifiedOperation(floor, item.Operation) ?? throw new CryptographicException("Group history lost its actual native row.");
            if (native.Direction != item.Direction) throw new CryptographicException("Group history direction changed.");
            byte[] exact;
            if (native.Direction == 1) exact = RequireGroupAuthoredEvent(root.State, scope, item.Operation, native.EventHash) ?? throw new CryptographicException("Group history lost original authored custody.");
            else { using var owned = native.OwnAuthenticatedDmc2(); exact = owned.Use(bytes => bytes.ToArray()); }
            try
            {
                var record = RequireGroupEnvelope(ApplicationCoreCodec.DecodeDmc2(exact), scope, native.Direction == 1);
                if (!SHA256.HashData(exact).AsSpan().SequenceEqual(native.EventHash) || !record.CanonicalBytes.Span.SequenceEqual(item.Record))
                    throw new CryptographicException("Group projection differs from actual native history.");
                result.Add(new(new UTF8Encoding(false, true).GetString(record.Field(12).Span), item.Direction == 1,
                    BinaryPrimitives.ReadUInt64BigEndian(record.Field(8).Span)));
            }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
        held.RequireActive(); ct.ThrowIfCancellationRequested(); return result;
        }
        finally { foreach (var opened in openedScopes.Values) opened.Dispose(); }
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
        ReadOnlyMemory<byte> groupId, Did2MessagingSessionScope scope, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        await ResumeGroupOrdinaryUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
        using var root = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        var group = root.State.Find(groupId.Span);
        if (group.Fork) throw new CryptographicException("Group fanout scope is unavailable.");
        var result = root.State.Outbox.Where(item => item.Group.AsSpan().SequenceEqual(groupId.Span) && item.Scope.AsSpan().SequenceEqual(scope.Exact))
            .Select(item => new ProtectedDid2GroupJournal.Outgoing { Group = item.Group.ToArray(), Operation = item.Operation.ToArray(), Scope = item.Scope.ToArray(), Event = item.Event.ToArray(), Adopted = item.Adopted }).ToArray();
        if (result.Length == 0) return result;
        try
        {
            using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            foreach (var item in result)
            {
                using var native = opened.Sql.ReadVerifiedOperation(floor, item.Operation);
                if (native is null) continue;
                if (native.Direction != 1 || !SHA256.HashData(item.Event).AsSpan().SequenceEqual(native.EventHash))
                    throw new CryptographicException("Group batch differs from actual native send custody.");
                item.NativeCommitted = true;
            }
            held.RequireActive(); ct.ThrowIfCancellationRequested(); return result;
        }
        catch
        {
            foreach (var item in result) foreach (var bytes in new[] { item.Group, item.Operation, item.Scope, item.Event }) CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }
}
