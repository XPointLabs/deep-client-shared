using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    // Optional local discovery only. An absent marker grants no provisioning;
    // the owner separately rejects a registered sender that lost this source.
    internal static async ValueTask<Deep.Client.Shared.Persistence.DeviceV1.SqliteDeviceStateStore?>
        TryOpenExistingMessagingSenderSourceUnderLeaseAsync(IDeepSecureStorage storage,
            string accountPath, VerifiedDeepIdV2CurrentAccount current, CancellationToken ct)
    {
        using var marker = await storage.ReadOwnedAsync(DeviceStateMarkerSlot, ct).ConfigureAwait(false);
        if (marker is null)
        {
            var path = DeviceStatePath(accountPath);
            if (File.Exists(path) || File.Exists(path + "-journal") || File.Exists(path + "-wal") || File.Exists(path + "-shm"))
                throw new InvalidDataException("Initial source file family lost its protected marker; no provisioning is allowed.");
            ct.ThrowIfCancellationRequested(); return null;
        }
        return await OpenCurrentDeviceStateStoreAsync(storage, accountPath, current, ct).ConfigureAwait(false);
    }

    internal static async ValueTask<Deep.Client.Shared.Persistence.DeviceV1.SqliteDeviceStateStore>
        OpenExistingMessagingSenderSourceUnderLeaseAsync(IDeepSecureStorage storage,
            string accountPath, VerifiedDeepIdV2CurrentAccount current, CancellationToken ct)
    {
        using var marker = await storage.ReadOwnedAsync(DeviceStateMarkerSlot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Owned messaging lost its sender source marker; no provisioning is permitted.");
        return await OpenCurrentDeviceStateStoreAsync(storage, accountPath, current, ct).ConfigureAwait(false);
    }
    /// <summary>Account-level reopen: authenticate source history and completed
    /// deletion before ordinary state can escape the lower SQL backend.</summary>
    internal static async Task<OwnedDid2MessagingStorage> OpenOwnedMessagingUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, CancellationToken ct)
        => await OpenOwnedMessagingCoreAsync(storage, accountPath, current, scope, NativeArchiveAlgorithm.Full, ct).ConfigureAwait(false);

    // The private account-runtime wrapper owns cold admission. This named
    // algorithm still authenticates all current roots, pages and compact rows;
    // it accepts no caller-supplied verification/skip/currentness flag.
    internal static async Task<OwnedDid2MessagingStorage> OpenOrdinaryMessagingUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, CancellationToken ct)
        => await OpenOwnedMessagingCoreAsync(storage, accountPath, current, scope, NativeArchiveAlgorithm.Active, ct).ConfigureAwait(false);

    private enum NativeArchiveAlgorithm { Full, Active }

    private static async Task<OwnedDid2MessagingStorage> OpenOwnedMessagingCoreAsync(
        IDeepSecureStorage storage, string accountPath, VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, NativeArchiveAlgorithm algorithm, CancellationToken ct)
    {
        var identity = current.Verified.PublicEvidence.Binding.Identity;
        var certificate = identity.ActiveDevices.Single().Certificate;
        if (!Did2MessagingSessionScope.Fixed(scope.LocalAccount, current.AccountId.Span) ||
            !Did2MessagingSessionScope.Fixed(scope.Network, identity.Account.Certificate.NetworkId.Span) ||
            !Did2MessagingSessionScope.Fixed(scope.LocalDevice, certificate.DeviceId.Span) ||
            scope.LocalDeviceGeneration != certificate.DeviceGeneration)
            throw new CryptographicException("Owned messaging session is outside the current local account/device.");
        async Task VerifySource(bool retired)
        {
            if (scope.IsInitiator)
            {
                using var source = await OpenExistingMessagingSenderSourceUnderLeaseAsync(storage, accountPath, current, ct).ConfigureAwait(false);
                await source.VerifyMessagingSourceUnderLeaseAsync(scope, retired, ct).ConfigureAwait(false);
            }
            else await VerifyReceiverMessagingSourceUnderLeaseAsync(storage, accountPath, current, scope, retired, ct).ConfigureAwait(false);
        }
        var protectedFloor = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadAsync(ct).ConfigureAwait(false);
        await VerifySource(protectedFloor.Status != 0).ConfigureAwait(false);
        var opened = await OpenRegisteredMessagingCoreAsync(storage, accountPath,
            scope.Network.ToArray(), current.AccountId, scope, algorithm, ct).ConfigureAwait(false);
        try
        {
            var stable = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            await VerifySource(stable.Status != 0).ConfigureAwait(false);
            var readback = await opened.Custody.ReadCurrentFloorAsync(ct).ConfigureAwait(false);
            if (!Did2MessagingSessionScope.Fixed(stable.Exact.Span, readback.Exact.Span))
                throw new CryptographicException("Native protected roots changed during source verification.");
            return opened;
        }
        catch { opened.Dispose(); throw; }
    }

    /// <summary>Open only a protected registered session, under the account lease.
    /// The returned storage owns no lease and is never a public runtime handle.</summary>
    internal static async Task<OwnedDid2MessagingStorage> OpenRegisteredMessagingUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, Did2MessagingSessionScope scope, CancellationToken ct)
        => await OpenRegisteredMessagingCoreAsync(storage, accountPath, network, account, scope, NativeArchiveAlgorithm.Full, ct).ConfigureAwait(false);

    private static async Task<OwnedDid2MessagingStorage> OpenRegisteredMessagingCoreAsync(
        IDeepSecureStorage storage, string accountPath, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, Did2MessagingSessionScope scope, NativeArchiveAlgorithm algorithm, CancellationToken ct)
    {
        // One bounded actual inventory owns registration selection. Only pure
        // decoders/path checks run before opening SQL; no authority callback or
        // previously successful read can supply any member of this snapshot.
        using var inventory = await storage.ReadOwnedBatchAsync([KeySlot,
            ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot,
            Did2MessagingHistoryCheckpoint.Slot(scope)], ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var registration = inventory[0] ?? throw new InvalidDataException("The DID2 SQL key record is absent.");
        var instance = registration.Use(bytes => ReadAccountInstanceFromRegistration(bytes, network.Span, account.Span));
        ProtectedDid2MessagingSessionCatalog catalog;
        try
        {
            if (!Did2MessagingSessionScope.Fixed(instance, scope.Instance))
                throw new CryptographicException("Owned messaging registration has another account instance.");
            catalog = new ProtectedDid2MessagingSessionCatalog(storage, network.Span, account.Span, instance);
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
        var catalogBytes = inventory[1] ?? throw new InvalidDataException("The protected DID2 messaging catalog is absent; explicit reset is required.");
        using var registered = catalogBytes.Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes,
            network.Span, account.Span, scope.Instance));
        var index = registered.FindExact(scope);
        if (index < 0) throw new InvalidDataException("DID2 messaging SQL has no protected registration.");
        var phase = registered.Phase(index);
        var directory = MessagingDirectory(accountPath);
        var path = Path.Combine(directory, Convert.ToHexStringLower(scope.Hash) + ".dms2");
        if (Directory.Exists(directory)) RequireOrdinaryDirectory(directory);
        else
        {
            if (phase == 2) throw new InvalidDataException("Initialized DID2 messaging directory is absent; no repair is permitted.");
            Directory.CreateDirectory(directory); RequireOrdinaryDirectory(directory);
        }
        var exists = File.Exists(path);
        if (phase == 2 && !exists)
            throw new InvalidDataException("Initialized DID2 messaging SQL is absent; no initial-state reimport is permitted.");
        if (exists && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("DID2 messaging SQL cannot be a linked file.");
        if (File.Exists(path + "-wal") || File.Exists(path + "-shm") || !exists && File.Exists(path + "-journal"))
            throw new InvalidDataException("DID2 messaging SQL has an incompatible/orphan file family.");
        var checkpoint = new Did2MessagingProtectedCheckpoint(storage, scope);
        var floorBytes = inventory[2] ?? throw new InvalidDataException("Protected DID2 messaging floor is absent; no state repair is permitted.");
        var floor = floorBytes.Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
        var historyBytes = inventory[3] ?? throw new InvalidDataException("Mandatory messaging history checkpoint is absent; no initialization is permitted.");
        var history = historyBytes.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
        var actualRegistrationHash = registration.Use(bytes => SHA256.HashData(bytes));
        var actualCatalogHash = catalogBytes.Use(bytes => SHA256.HashData(bytes));
        inventory.Dispose(); // No raw inventory is retained over SQL/storage callbacks.
        if (phase == 1 && !Did2MessagingSessionScope.Fixed(floor.Exact.Span, Did2MessagingFloor.Empty(scope).Exact.Span))
            throw new CryptographicException("Uninitialized DID2 messaging registration has a nonempty floor.");
        if (phase == 1 && !Did2MessagingSessionScope.Fixed(history.Exact.Span, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.Span))
            throw new CryptographicException("Uninitialized DID2 messaging registration has a nonempty history checkpoint.");
        ct.ThrowIfCancellationRequested();
        using var key = registered.ReadKey(index);
        SqliteConnection? connection = key.Use(bytes => OpenMessagingConnection(path, bytes, create: phase == 1));
        try
        {
            var sql = algorithm == NativeArchiveAlgorithm.Active && phase == 2 ? Did2MessagingSqlJournal.ForOrdinaryRuntime(connection, scope, history) :
                new Did2MessagingSqlJournal(connection, scope, history);
            if (algorithm == NativeArchiveAlgorithm.Active && phase == 2)
                sql.BindOpenRegistration(actualRegistrationHash, actualCatalogHash);
            if (phase == 1)
            {
                sql.InitializeOrVerifyRegisteredEmpty(floor);
                await catalog.MarkSqlInitializedAsync(scope, sql, ct).ConfigureAwait(false);
            }
            var custody = new Did2MessagingDurableCustody(scope, checkpoint, sql);
            _ = await custody.ReconcileAsync(ct).ConfigureAwait(false);
            var result = new OwnedDid2MessagingStorage(connection, scope, checkpoint, sql, custody);
            connection = null; return result;
        }
        finally { connection?.Dispose(); }
    }

    internal static void DeleteMessagingAfterExplicitReset(string accountPath)
    {
        var directory = MessagingDirectory(accountPath);
        if (!Directory.Exists(directory)) return;
        RequireOrdinaryDirectory(directory);
        foreach (var path in Directory.EnumerateFiles(directory))
        {
            var name = Path.GetFileName(path);
            if (name.Length < 69 || name.AsSpan(0, 64).IndexOfAnyExcept("0123456789abcdef") >= 0 ||
                name[64..] is not (".dms2" or ".dms2-journal" or ".dms2-wal" or ".dms2-shm")) continue;
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("DID2 explicit reset refuses a linked messaging file.");
            File.Delete(path);
        }
        if (!Directory.EnumerateFileSystemEntries(directory).Any()) Directory.Delete(directory);
    }

    private static string MessagingDirectory(string accountPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountPath);
        var full = Path.GetFullPath(accountPath);
        var parent = Path.GetDirectoryName(full) ?? throw new ArgumentException("An account-private SQL path is required.");
        RequireOrdinaryDirectory(parent);
        var directory = Path.GetFullPath(full + ".messaging");
        if (!string.Equals(Path.GetDirectoryName(directory), parent, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("DID2 messaging path escaped its account-private parent.");
        return directory;
    }

    // Existing-only recovery open: never invokes ordinary reconciliation,
    // provisions SQL or selects a caller-supplied database/key.
    internal static SqliteConnection OpenExistingMessagingForCompactionUnderLease(
        string accountPath, ProtectedDid2MessagingSessionCatalog.Snapshot catalog,
        Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease)
    {
        held.RequireOwner(lease);
        var index = catalog.FindExact(scope);
        if (index < 0 || catalog.Phase(index) != 2) throw new InvalidDataException("Local recovery requires an initialized registered session.");
        var directory = MessagingDirectory(accountPath);
        if (!Directory.Exists(directory)) throw new InvalidDataException("Local recovery lost its messaging directory.");
        RequireOrdinaryDirectory(directory);
        var path = Path.Combine(directory, Convert.ToHexStringLower(scope.Hash) + ".dms2");
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 ||
            File.Exists(path + "-wal") || File.Exists(path + "-shm"))
            throw new InvalidDataException("Local recovery lost its exact ordinary SQL file family.");
        using var key = catalog.ReadKey(index);
        return key.Use(bytes => OpenMessagingConnection(path, bytes, create: false));
    }
    private static void RequireOrdinaryDirectory(string path)
    {
        if (!Directory.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("DID2 messaging requires an existing unlinked private directory.");
    }
}

internal sealed class OwnedDid2MessagingStorage : IDisposable
{
    private SqliteConnection? connection;
    private readonly Did2MessagingSessionScope scope;
    private readonly Did2MessagingProtectedCheckpoint checkpoint;
    private readonly Did2MessagingSqlJournal sql;
    private readonly Did2MessagingDurableCustody custody;
    internal OwnedDid2MessagingStorage(SqliteConnection connection, Did2MessagingSessionScope scope,
        Did2MessagingProtectedCheckpoint checkpoint, Did2MessagingSqlJournal sql, Did2MessagingDurableCustody custody)
    { this.connection = connection; this.scope = scope; this.checkpoint = checkpoint; this.sql = sql; this.custody = custody; }
    internal Did2MessagingSessionScope Scope { get { RequireLive(); return scope; } }
    internal Did2MessagingProtectedCheckpoint Checkpoint { get { RequireLive(); return checkpoint; } }
    internal Did2MessagingSqlJournal Sql { get { RequireLive(); return sql; } }
    internal Did2MessagingDurableCustody Custody { get { RequireLive(); return custody; } }
    // Scheduling budget only. It never supplies a floor, verification result,
    // skip permission or mutable-state loan to the ordinary verifier.
    internal bool RecoveredLocalCompaction { get; set; }
    private void RequireLive() => ObjectDisposedException.ThrowIf(connection is null, this);
    public void Dispose() => Interlocked.Exchange(ref connection, null)?.Dispose();
}
