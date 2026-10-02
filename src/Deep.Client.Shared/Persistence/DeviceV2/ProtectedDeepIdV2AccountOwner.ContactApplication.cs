using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<IReadOnlyList<DeepIdV2PendingTextSnapshot>> ReadPendingTextOperationsAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[] snapshot = [];
        var rows = new List<DirectTextOutboxEntry>();
        try
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("The mandatory ordinary command root is absent.");
            snapshot = root.Use(bytes => bytes.ToArray());
            using var journal = ProtectedDid2DirectTextJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            var result = new List<DeepIdV2PendingTextSnapshot>();
            foreach (var entry in journal.Entries.Values)
            {
                var scope = entry.Scope; var index = catalog.FindExact(scope);
                if (index < 0 || catalog.Phase(index) != 2) throw new CryptographicException("An ordinary command lost its initialized catalog scope.");
            }
            if (journal.Entries.Values.FirstOrDefault() is { } first)
            {
                var scope = first.Scope;
                using var ignored = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                    BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, ReadOnlyMemory<byte>.Empty, ct, rows).ConfigureAwait(false);
            }
            foreach (var row in rows.OrderBy(value => journal.Entries[Convert.ToHexString(value.OperationId.Span)].Created)
                .ThenBy(value => value.SenderSequence))
            {
                var entry = journal.Entries[Convert.ToHexString(row.OperationId.Span)];
                var scope = entry.Scope;
                var exact = row.ExactDmc2.ToArray();
                try
                {
                    entry.RequireEvent(exact);
                    var message = ApplicationCoreCodec.DecodeDmc2(exact);
                    if (message.ParsedPayload is MessageCreateDmc2Payload text && !entry.Stored)
                        result.Add(new(entry.Operation, Convert.ToHexString(scope.Conversation), text.Text, entry.Sequence));
                    else if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose();
                }
                finally { CryptographicOperations.ZeroMemory(exact); }
            }
            using var readback = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("The ordinary command root disappeared during projection.");
            if (!readback.Use(bytes => Did2MessagingSessionScope.Fixed(snapshot, bytes)))
                throw new CryptographicException("The ordinary command root changed during projection.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MessagingSessionCatalog.Slot, catalog.Exact.ToArray(), ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return result.AsReadOnly();
        }
        finally { foreach (var row in rows) row.Dispose(); CryptographicOperations.ZeroMemory(instance); CryptographicOperations.ZeroMemory(snapshot); }
    }

    internal async Task<IReadOnlyList<DeepIdV2ContactOperationSnapshot>> ReadContactStartOperationsAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[] snapshot = [];
        try
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("The mandatory contact start root is absent.");
            using var state = root.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, networkId, current.AccountId.Span, instance));
            snapshot = root.Use(bytes => bytes.ToArray());
            var result = new List<DeepIdV2ContactOperationSnapshot>(state.Entries.Count);
            foreach (var entry in state.Entries.Values)
            {
                var hello = ApplicationCoreCodec.DecodeDmc2(entry.Hello);
                result.Add(new(entry.Intent, entry.Exact.Slice(32, 32), hello.CreatedAtUnixMilliseconds, hello.ExpiresAtUnixMilliseconds));
            }
            using var readback = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("The contact start root disappeared during projection.");
            if (!readback.Use(other => Did2MessagingSessionScope.Fixed(snapshot, other)))
                throw new CryptographicException("The contact start root changed during projection.");
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return result.AsReadOnly();
        }
        finally { CryptographicOperations.ZeroMemory(instance); CryptographicOperations.ZeroMemory(snapshot); }
    }
    internal async Task<IReadOnlyList<Did2MessagingSessionScope>> ReadInitializedConversationScopesAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            var result = new List<Did2MessagingSessionScope>(catalog.Count);
            for (var index = 0; index < catalog.Count; index++)
                if (catalog.Phase(index) == 2) result.Add(catalog.Scope(index));
            using var readback = await storage.ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("The owned conversation catalog disappeared during projection.");
            if (!readback.Use(bytes => Did2MessagingSessionScope.Fixed(bytes, catalog.Exact.Span)))
                throw new CryptographicException("The owned conversation catalog changed during projection.");
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return result.AsReadOnly();
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }
}
