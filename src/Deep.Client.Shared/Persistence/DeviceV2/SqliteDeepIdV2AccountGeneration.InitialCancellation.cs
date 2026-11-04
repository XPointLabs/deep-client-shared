using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal static async Task RequireInitialIntentNotStoppedUnderLeaseAsync(IDeepSecureStorage storage,
        ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        ReadOnlyMemory<byte> intent, CancellationToken ct)
    {
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var drafts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, network.Span, account.Span, instance.Span));
        if (drafts.Entries.TryGetValue(Convert.ToHexString(intent.Span), out var draft) && draft.WorkStopped)
            throw new IOException("Stopped Initial intent cannot create, complete or import another claim.");
        // This denial fence grants no positive draft/claim authority. The
        // business owner still independently requires its exact actual draft.
    }

    internal static async Task RequireCancellationNativeAbsenceUnderLeaseAsync(IDeepSecureStorage storage,
        string accountPath, ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        ProtectedInitialKeyRetirementJournal.Entry entry, HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        string[] owners = [ProtectedDid2ContactStartJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot,
            ProtectedDid2MessagingArchiveEnrollment.Slot];
        byte[] draftHash, catalogHash;
        Did2MessagingSessionScope[] scopes;
        using (var discovery = await storage.ReadOwnedBatchAsync(owners, ct).ConfigureAwait(false))
        {
            if (discovery[2] is not null) throw new InvalidOperationException("Explicit messaging archive enrollment owns the account.");
            var draftRaw = discovery[0] ?? throw new InvalidDataException("Initial cancellation lost its actual draft owner.");
            var catalogRaw = discovery[1] ?? throw new InvalidDataException("Initial cancellation lost its actual native catalog.");
            draftHash = draftRaw.Use(bytes => SHA256.HashData(bytes)); catalogHash = catalogRaw.Use(bytes => SHA256.HashData(bytes));
            using var drafts = draftRaw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, network.Span, account.Span, instance.Span));
            using var catalog = catalogRaw.Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes, network.Span, account.Span, instance.Span));
            scopes = SelectCancellationScopes(drafts, catalog, entry);
        }
        // Discovery exports only public hashes/scope metadata. Every SQL open
        // reacquires the actual catalog key together with all absence roots.
        var selections = scopes.Length == 0 ? new Did2MessagingSessionScope?[] { null } : scopes.Cast<Did2MessagingSessionScope?>().ToArray();
        foreach (var scope in selections)
        {
            string[] slots = scope is null ? owners : [owners[0], owners[1], scope.FloorSlot,
                Did2MessagingHistoryCheckpoint.Slot(scope), Did2MessagingArchiveRoot.Slot(scope), owners[2]];
            using var final = await storage.ReadOwnedBatchAsync(slots, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            if (final[scope is null ? 2 : 5] is not null) throw new InvalidOperationException("Explicit messaging archive enrollment owns the account.");
            var draftRaw = final[0] ?? throw new InvalidDataException("Final Initial cancellation lost its draft owner.");
            var catalogRaw = final[1] ?? throw new InvalidDataException("Final Initial cancellation lost its native catalog.");
            if (!draftRaw.Use(bytes => Fixed(SHA256.HashData(bytes), draftHash)) || !catalogRaw.Use(bytes => Fixed(SHA256.HashData(bytes), catalogHash)))
                throw new CryptographicException("Initial cancellation owners changed before native absence verification.");
            using var drafts = draftRaw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, network.Span, account.Span, instance.Span));
            using var catalog = catalogRaw.Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes, network.Span, account.Span, instance.Span));
            var selected = SelectCancellationScopes(drafts, catalog, entry);
            if (selected.Length != scopes.Length || selected.Where((value, index) => !Fixed(value.Exact, scopes[index].Exact)).Any())
                throw new CryptographicException("Initial cancellation changed its exact native scope selection.");
            if (scope is null) continue; // Fresh owners also prove no matching registration.
            var floor = (final[2] ?? throw new InvalidDataException("Initial cancellation lost its native floor.")).Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
            var history = (final[3] ?? throw new InvalidDataException("Initial cancellation lost its native history.")).Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
            var archive = (final[4] ?? throw new InvalidDataException("Initial cancellation lost its native archive root.")).Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
            archive.RequireSource(history);
            if (!Fixed(archive.Exact.Span, Did2MessagingArchiveRoot.Empty(scope).Exact.Span))
                throw new CryptographicException("Initial cancellation requires its actual canonical empty archive.");
            final.Dispose();
            using var connection = OpenExistingMessagingForCompactionUnderLease(accountPath, catalog, scope, held, lease);
            var sql = new Did2MessagingSqlJournal(connection, scope, history); sql.BindArchiveRoot(archive);
            var actual = sql.VerifyTip();
            if (!Fixed(floor.Exact.Span, Did2MessagingFloor.Empty(scope).Exact.Span) || !Fixed(actual.Exact.Span, floor.Exact.Span) ||
                !Fixed(history.Exact.Span, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.Span))
                throw new CryptographicException("Initial cancellation cannot erase keys belonging to an imported native ratchet.");
        }
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);

    }

        private static Did2MessagingSessionScope[] SelectCancellationScopes(ProtectedDid2ContactStartJournal.State drafts,
            ProtectedDid2MessagingSessionCatalog.Snapshot catalog, ProtectedInitialKeyRetirementJournal.Entry entry)
        {
            if (entry.Role != 3 || !drafts.Entries.TryGetValue(Convert.ToHexString(entry.Intent), out var draft) ||
                !draft.WorkStopped || draft.NativeStopMode != 2 || !Fixed(draft.CancellationBinding, entry.ScopeHash))
                throw new CryptographicException("Initial key cancellation lost its exact stop owner.");
            var selected = new List<Did2MessagingSessionScope>();
            for (var index = 0; index < catalog.Count; index++)
            {
                var scope = catalog.Scope(index);
                if (!scope.IsInitiator || !Fixed(scope.Conversation, draft.Conversation) || !Fixed(scope.LocalDevice, draft.LocalDevice) ||
                    !Fixed(scope.RemoteAccount, draft.Exact.Slice(64, 32))) continue;
                if (entry.Ordinal == 0 || !Fixed(scope.InitialBasis, entry.Basis) || catalog.Phase(index) != 2)
                    throw new CryptographicException("Initial cancellation has foreign or incomplete native registration.");
                selected.Add(Did2MessagingSessionScope.RestoreMetadata(scope.Exact));
            }
            // Catalog decoding already rejects duplicate Initial bases. Every
            // match above must equal this one exact basis, hence at most one.
            if (selected.Count > 1) throw new CryptographicException("Initial cancellation has duplicate native source ownership.");
            return selected.ToArray();
        }

}
