using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Microsoft.Data.Sqlite;

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
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var drafts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, network.Span, account.Span, instance.Span));
        if (entry.Role != 3 || !drafts.Entries.TryGetValue(Convert.ToHexString(entry.Intent), out var draft) ||
            !draft.WorkStopped || draft.NativeStopMode != 2 || !Fixed(draft.CancellationBinding, entry.ScopeHash))
            throw new CryptographicException("Initial key cancellation lost its exact stop owner.");
        using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, network.Span, account.Span, instance.Span).ReadAsync(ct).ConfigureAwait(false);
        for (var index = 0; index < catalog.Count; index++)
        {
            var scope = catalog.Scope(index);
            if (!scope.IsInitiator || !Fixed(scope.Conversation, draft.Conversation) || !Fixed(scope.LocalDevice, draft.LocalDevice) ||
                !Fixed(scope.RemoteAccount, draft.Exact.Slice(64, 32))) continue;
            if (entry.Ordinal == 0 || !Fixed(scope.InitialBasis, entry.Basis) || catalog.Phase(index) != 2)
                throw new CryptographicException("Initial cancellation has foreign or incomplete native registration.");
            var floor = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadAsync(ct).ConfigureAwait(false);
            var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
            using var connection = OpenExistingMessagingForCompactionUnderLease(accountPath, catalog, scope, held, lease);
            var actual = new Did2MessagingSqlJournal(connection, scope, history).VerifyTip();
            if (!Fixed(floor.Exact.Span, Did2MessagingFloor.Empty(scope).Exact.Span) || !Fixed(actual.Exact.Span, floor.Exact.Span) ||
                !Fixed(history.Exact.Span, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.Span))
                throw new CryptographicException("Initial cancellation cannot erase keys belonging to an imported native ratchet.");
        }
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    // Reopen only the actual registered source for local cancellation recovery.
    // Stored generation is a checked local fact, never current device/network
    // authority. This opener neither provisions a source nor creates a claim.
    internal static async Task<SqliteDeviceStateStore> OpenExistingCancellationSourceUnderLeaseAsync(IDeepSecureStorage storage,
        string accountPath, ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        using var raw = await storage.ReadOwnedAsync(KeySlot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var record = raw.Use(bytes => bytes.ToArray()); byte[] transcript = [], key = [], storeId = [], marker = [];
        try
        {
            ValidateRecord(record, network.Span, account.Span);
            if (!Fixed(record.AsSpan(56, 32), instance.Span)) throw new CryptographicException("Cancelled source changed its registered account instance.");
            var domain = "Deep/STORE-V2/device-state-key"u8;
            transcript = new byte[domain.Length + 80]; domain.CopyTo(transcript);
            record.AsSpan(8, 48).CopyTo(transcript.AsSpan(domain.Length)); record.AsSpan(56, 32).CopyTo(transcript.AsSpan(domain.Length + 48));
            key = HMACSHA256.HashData(record.AsSpan(88, 32), transcript); storeId = SHA256.HashData(transcript);
            var markerInput = new byte[80]; storeId.CopyTo(markerInput, 0); network.Span.CopyTo(markerInput.AsSpan(32)); account.Span.CopyTo(markerInput.AsSpan(48));
            try { marker = SHA256.HashData(markerInput); } finally { CryptographicOperations.ZeroMemory(markerInput); }
            using var installed = await storage.ReadOwnedAsync(DeviceStateMarkerSlot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Cancellation cannot initialize a missing source marker.");
            if (!installed.Use(bytes => Fixed(bytes, marker))) throw new CryptographicException("Cancellation opened a foreign source marker.");
            var path = DeviceStatePath(accountPath); RequireOrdinaryDirectory(Path.GetDirectoryName(path) ?? throw new InvalidDataException());
            RequireApplicationFileFamily(path);
            if (!File.Exists(path) || new[] { "-wal", "-shm" }.Any(suffix => File.Exists(path + suffix))) throw new InvalidDataException("Cancellation requires its exact existing source file family.");
            ulong generation;
            using (var readOnly = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString()))
            {
                readOnly.Open(); SqliteDeviceStateStore.InstallRandomKey(readOnly, key);
                SqliteDeviceStateStore.RequireReadOnlyMailboxSource(readOnly, storeId, account.Span);
                using var query = readOnly.CreateCommand();
                query.CommandText = "SELECT account_generation FROM device_store_meta WHERE singleton=1 AND typeof(account_generation)='blob' AND length(account_generation)=8;";
                using var row = query.ExecuteReader();
                if (!row.Read()) throw new InvalidDataException("Cancellation source lost its canonical stored generation.");
                generation = BinaryPrimitives.ReadUInt64BigEndian(row.GetFieldValue<byte[]>(0));
                if (generation == 0 || row.Read()) throw new InvalidDataException("Cancellation source generation is absent or ambiguous.");
            }
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            var store = new SqliteDeviceStateStore(new SqliteDeviceStateStoreOptions(path, key,
                DeviceAccountId32.FromBytes(account.Span), generation, 1, DeviceOperationId32.FromBytes(storeId), allowCreate: false));
            try { await store.OpenInitialSessionCustodyAsync(storage, network, ct).ConfigureAwait(false); return store; }
            catch { store.Dispose(); throw; }
        }
        finally
        {
            foreach (var bytes in new[] { record, transcript, key, storeId, marker }) CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
