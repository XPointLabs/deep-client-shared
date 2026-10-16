using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal const string ApplicationStateSlot = "deep.store.v2.application-state";

    // Recovery opens only the already-initialized, exact account database.
    // No current network proof, file creation or registration promotion occurs.
    internal static async Task<SqliteDeepMailboxStore> OpenExistingApplicationForCompactionUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, Did2MessagingSessionScope scope,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
        => await OpenExistingApplicationForOwnerUnderLeaseAsync(storage, accountPath, scope.Network.ToArray(),
            scope.LocalAccount.ToArray(), scope.Instance.ToArray(), held, lease, ct).ConfigureAwait(false);

    // Exact local owner/plan readback only; these copied fields mint no authority.
    internal static async Task<SqliteDeepMailboxStore> OpenExistingApplicationForOwnerUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        using var custody = await ReadApplicationCustodyAsync(storage, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        var secret = custody[0] ??
            throw new InvalidDataException("Application recovery lost its account key registration.");
        var registered = custody[1] ??
            throw new InvalidDataException("Application recovery lost its initialized registration.");
        var record = secret.Use(bytes => bytes.ToArray());
        var registration = registered.Use(bytes => bytes.ToArray()); byte[] key = [];
        try
        {
            ValidateRecord(record, network.Span, account.Span);
            ValidateApplicationRegistration(registration, record);
            if (registration[1] != 2 || !Fixed(record.AsSpan(56, 32), instance.Span))
                throw new CryptographicException("Application recovery requires its exact initialized account instance.");
            var path = ApplicationStatePath(accountPath); RequireApplicationFileFamily(path);
            key = DeriveApplicationKey(record);
            using var options = new SqliteDeepMailboxStoreOptions(path, key);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            var store = SqliteDeepMailboxStore.OpenExisting(options);
            try
            {
                BindStoppedAuditKey(store, record);
                BindControlAuditCustody(store, custody, record, held, ct);
                await ValidateIdleStoppedAuditCustodyAsync(store, custody, record, held, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                return store;
            }
            catch { store.Dispose(); throw; }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(record); CryptographicOperations.ZeroMemory(registration);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] DeriveApplicationKey(ReadOnlySpan<byte> accountRecord)
    {
        var domain = "Deep/STORE-V2/application-state-key"u8;
        var context = new byte[domain.Length + 1 + 16 + 32 + 32];
        try
        {
            domain.CopyTo(context);
            accountRecord.Slice(8, 48).CopyTo(context.AsSpan(domain.Length + 1));
            accountRecord.Slice(56, 32).CopyTo(context.AsSpan(domain.Length + 49));
            return HMACSHA256.HashData(accountRecord.Slice(88, 32), context);
        }
        finally { CryptographicOperations.ZeroMemory(context); }
    }

    private static void BindStoppedAuditKey(SqliteDeepMailboxStore store, ReadOnlySpan<byte> record)
    {
        var domain = "Deep/STORE-V2/stopped-work-audit-key"u8;
        var context = new byte[domain.Length + 1 + 80]; byte[] key = [];
        try
        {
            domain.CopyTo(context); record.Slice(8, 80).CopyTo(context.AsSpan(domain.Length + 1));
            key = HMACSHA256.HashData(record.Slice(88, 32), context);
            store.BindStoppedAuditKey(key);
        }
        finally { CryptographicOperations.ZeroMemory(context); CryptographicOperations.ZeroMemory(key); }
    }

    // One fresh authenticated inventory for the six inseparable application
    // registrations/roots. Never retain it across an open or skip SQL/audit
    // validation; each caller owns and disposes this exact snapshot.
    private static Task<OwnedDeepSecretBatch> ReadApplicationCustodyAsync(IDeepSecureStorage storage, CancellationToken ct) =>
        storage.ReadOwnedBatchAsync([KeySlot, ApplicationStateSlot, ProtectedDid2ContactStartJournal.Slot,
            ProtectedDid2ContactAcceptJournal.Slot, Did2CompactionPlan.Slot, ProtectedDid2DirectTextJournal.Slot], ct);

    private static void BindControlAuditCustody(SqliteDeepMailboxStore store, OwnedDeepSecretBatch custody,
        byte[] record, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireActive();
        var startsRaw = custody[2] ?? throw new InvalidDataException("Control audit binding lost Initial custody.");
        var acceptsRaw = custody[3] ?? throw new InvalidDataException("Control audit binding lost acceptance custody.");
        using var starts = startsRaw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, record.AsSpan(8, 16), record.AsSpan(24, 32), record.AsSpan(56, 32)));
        using var accepts = acceptsRaw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, record.AsSpan(8, 16), record.AsSpan(24, 32), record.AsSpan(56, 32)));
        var rows = new List<SqliteDeepMailboxStore.ControlAuditCustody>();
        try
        {
            foreach (var entry in starts.Entries.Values.Where(entry => entry.WorkStopped || entry.SuccessfullyStored))
                rows.Add(new(1, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(entry.Intent), entry.WorkStopped ? (byte)entry.StopReason : (byte)3,
                    entry.TerminalAtUpper, entry.PayloadRetired, entry.AuditDisposition));
            foreach (var entry in accepts.Entries.Values.Where(entry => entry.WorkStopped || entry.SuccessfullyStored))
                rows.Add(new(2, entry.Operation.ToArray(), entry.WorkStopped ? (byte)entry.StopReason : (byte)3, entry.TerminalAtUpper, entry.PayloadRetired, entry.AuditDisposition));
            ct.ThrowIfCancellationRequested(); held.RequireActive(); store.BindControlAuditCustody(rows);
        }
        finally { foreach (var row in rows) CryptographicOperations.ZeroMemory(row.Operation); }
    }

    private static async Task ValidateIdleStoppedAuditCustodyAsync(SqliteDeepMailboxStore store, OwnedDeepSecretBatch custody,
        byte[] record, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireActive();
        var planRaw = custody[4] ?? throw new InvalidDataException("Protected compaction registration is absent; explicit reset is required.");
        using var plan = planRaw.Use(bytes => Did2CompactionPlan.Decode(bytes, record.AsSpan(8, 16),
            record.AsSpan(24, 32), record.AsSpan(56, 32)));
        if (plan.Phase != 0) return; // The exact active transaction owns intermediate SQL/root agreement.
        var raw = custody[5] ??
            throw new InvalidDataException("Audit completeness lost ordinary custody.");
        using var ordinary = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, record.AsSpan(8, 16),
            record.AsSpan(24, 32), record.AsSpan(56, 32)));
        await store.ValidateCompleteStoppedAuditsAsync(ordinary, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireActive();
    }

    private static byte[] NewApplicationRegistration(ReadOnlySpan<byte> accountRecord)
    {
        var registration = new byte[116]; registration[0] = 3; registration[1] = 1;
        accountRecord.Slice(8, 48).CopyTo(registration.AsSpan(4));
        accountRecord.Slice(56, 32).CopyTo(registration.AsSpan(52));
        var key = DeriveApplicationKey(accountRecord);
        try { SHA256.HashData(key, registration.AsSpan(84)); return registration; }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static void ValidateApplicationRegistration(ReadOnlySpan<byte> registration,
        ReadOnlySpan<byte> accountRecord)
    {
        var expected = NewApplicationRegistration(accountRecord);
        try
        {
            if (registration.Length != 116 || registration[0] != 3 ||
                registration[1] is not (1 or 2) || registration[2] != 0 || registration[3] != 0 ||
                !Fixed(registration[4..], expected.AsSpan(4)))
                throw new InvalidDataException("DID2 application registration is absent, foreign or unsupported; explicit reset is required.");
        }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    internal static async Task<SqliteDeepMailboxStore> OpenApplicationUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireActive();
        using var custody = await ReadApplicationCustodyAsync(storage, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireActive();
        var secret = custody[0] ??
            throw new InvalidDataException("The DID2 account SQL key is absent.");
        var registered = custody[1] ??
            throw new InvalidDataException("The DID2 application registration is absent; no repair is permitted.");
        var record = secret.Use(static bytes => bytes.ToArray());
        var registration = registered.Use(static bytes => bytes.ToArray());
        byte[] key = []; SqliteDeepMailboxStore? store = null;
        try
        {
            ValidateRecord(record, current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.NetworkId.Span,
                current.AccountId.Span);
            ValidateApplicationRegistration(registration, record);
            var path = ApplicationStatePath(accountPath);
            RequireApplicationFileFamily(path);
            key = DeriveApplicationKey(record);
            using var options = new SqliteDeepMailboxStoreOptions(path, key);
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            store = registration[1] == 1 && !File.Exists(path)
                ? new(options) : SqliteDeepMailboxStore.OpenExisting(options);
            BindStoppedAuditKey(store, record);
            BindControlAuditCustody(store, custody, record, held, ct);
            await ValidateIdleStoppedAuditCustodyAsync(store, custody, record, held, ct).ConfigureAwait(false);
            if (registration[1] == 1)
            {
                store.RequireInitializedEmpty();
                var next = registration.ToArray(); next[1] = 2;
                try
                {
                    if (!await storage.CompareExchangeAsync(ApplicationStateSlot, registration, next, ct).ConfigureAwait(false))
                        throw new CryptographicException("DID2 application registration changed under its account lease.");
                }
                finally { CryptographicOperations.ZeroMemory(next); }
            }
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            var result = store; store = null; return result;
        }
        finally
        {
            store?.Dispose(); CryptographicOperations.ZeroMemory(record);
            CryptographicOperations.ZeroMemory(registration); CryptographicOperations.ZeroMemory(key);
        }
    }

    private static string ApplicationStatePath(string accountPath)
    {
        var full = Path.GetFullPath(accountPath);
        RequireOrdinaryDirectory(Path.GetDirectoryName(full) ?? throw new InvalidDataException("An account-private directory is required."));
        return full + ".application.dmb1";
    }

    private static void RequireApplicationFileFamily(string path, bool allowOrphans = false)
    {
        foreach (var artifact in new[] { path, path + "-journal", path + "-wal", path + "-shm" })
        {
            if (Directory.Exists(artifact) || File.Exists(artifact) &&
                (File.GetAttributes(artifact) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("DID2 application state cannot contain linked or directory artifacts.");
            if (!allowOrphans && artifact != path && File.Exists(artifact) && !File.Exists(path))
                throw new InvalidDataException("DID2 application state has orphan sidecars.");
        }
    }

    internal static void DeleteApplicationAfterExplicitReset(string accountPath)
    {
        var path = ApplicationStatePath(accountPath);
        RequireApplicationFileFamily(path, allowOrphans: true);
        foreach (var artifact in new[] { path, path + "-journal", path + "-wal", path + "-shm" })
            File.Delete(artifact);
    }
}
