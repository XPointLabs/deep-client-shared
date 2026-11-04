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
    internal static async Task<OwnedDid2MessagingStorage> OpenMessagingArchiveAuditUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, CancellationToken ct, Action<OwnedDid2MessagingStorage>? configureRouteHistory = null)
        => await OpenOwnedMessagingCoreAsync(storage, accountPath, current, scope, NativeArchiveAlgorithm.Full, NativeProvenancePurpose.SourceAudit, ct, configureRouteHistory).ConfigureAwait(false);

    internal static Task<OwnedDid2MessagingStorage> OpenEstablishedNativeArchiveAuditUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, CancellationToken ct, Action<OwnedDid2MessagingStorage>? configureRouteHistory = null)
        => OpenOwnedMessagingCoreAsync(storage, accountPath, current, scope, NativeArchiveAlgorithm.Full, NativeProvenancePurpose.Established, ct, configureRouteHistory);

    internal static Task<OwnedDid2MessagingStorage> OpenInitialTransferMessagingUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, CancellationToken ct, Action<OwnedDid2MessagingStorage>? configureRouteHistory = null)
        => OpenOwnedMessagingCoreAsync(storage, accountPath, current, scope, NativeArchiveAlgorithm.Active, NativeProvenancePurpose.InitialTransfer, ct, configureRouteHistory);

    // The private account-runtime wrapper owns cold admission. This named
    // algorithm still authenticates all current roots, pages and compact rows;
    // it accepts no caller-supplied verification/skip/currentness flag.
    internal static async Task<OwnedDid2MessagingStorage> OpenOrdinaryMessagingUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, CancellationToken ct, Action<OwnedDid2MessagingStorage>? configureRouteHistory = null)
        => await OpenOwnedMessagingCoreAsync(storage, accountPath, current, scope, NativeArchiveAlgorithm.Active, NativeProvenancePurpose.Established, ct, configureRouteHistory).ConfigureAwait(false);

    private enum NativeArchiveAlgorithm { Full, Active, Enrollment, EnrollmentSelection }
    private enum NativeProvenancePurpose { Established, InitialTransfer, SourceAudit, Enrollment, InitialAuditClassification }
    private static bool IsArchiveEnrollmentAlgorithm(NativeArchiveAlgorithm algorithm)
        => algorithm is NativeArchiveAlgorithm.Enrollment or NativeArchiveAlgorithm.EnrollmentSelection;

    private static async Task<OwnedDid2MessagingStorage> OpenOwnedMessagingCoreAsync(
        IDeepSecureStorage storage, string accountPath, VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, NativeArchiveAlgorithm algorithm, NativeProvenancePurpose provenancePurpose, CancellationToken ct,
        Action<OwnedDid2MessagingStorage>? configureRouteHistory = null)
    {
        RequireOwnedMessagingScope(current, scope);
        var opened = await OpenRegisteredMessagingCoreAsync(storage, accountPath,
            scope.Network.ToArray(), current.AccountId, scope, algorithm, ct, configureRouteHistory,
            provenancePurpose == NativeProvenancePurpose.Established ? null :
                token => CaptureMessagingSourceObservationAsync(storage, accountPath, current, scope, IsArchiveEnrollmentAlgorithm(algorithm), token),
            provenancePurpose).ConfigureAwait(false);
        try
        {
            var stable = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            var readback = await opened.Custody.ReadCurrentFloorAsync(ct).ConfigureAwait(false);
            if (!Did2MessagingSessionScope.Fixed(stable.Exact.Span, readback.Exact.Span))
                throw new CryptographicException("Native protected roots changed during source verification.");
            _ = await opened.WithSqlAsync(sql =>
            {
                if (!Did2MessagingSessionScope.Fixed(sql.VerifyOrdinaryState().Exact.Span, stable.Exact.Span))
                    throw new CryptographicException("Native protected source changed during final source verification.");
                return true;
            }, ct).ConfigureAwait(false);
            return opened;
        }
        catch { opened.Dispose(); throw; }
    }

    private static void RequireOwnedMessagingScope(VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope)
    {
        var identity = current.Verified.PublicEvidence.Binding.Identity;
        var certificate = identity.ActiveDevices.Single().Certificate;
        if (!Did2MessagingSessionScope.Fixed(scope.LocalAccount, current.AccountId.Span) ||
            !Did2MessagingSessionScope.Fixed(scope.Network, identity.Account.Certificate.NetworkId.Span) ||
            !Did2MessagingSessionScope.Fixed(scope.LocalDevice, certificate.DeviceId.Span) ||
            scope.LocalDeviceGeneration != certificate.DeviceGeneration)
            throw new CryptographicException("Owned messaging session is outside the current local account/device.");
    }

    // One fixed read-only owner operation. It cannot return a mutable store,
    // recover Initial or lend its source/TRS to an established operation.
    internal static async Task<bool> IsInitialOwnedNativeAuditUnderLeaseAsync(IDeepSecureStorage storage,
        string accountPath, VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, CancellationToken ct)
    {
        RequireOwnedMessagingScope(current, scope);
        var checkpoint = new Did2MessagingProtectedCheckpoint(storage, scope);
        var floor = await checkpoint.ReadAsync(ct).ConfigureAwait(false);
        byte[]? header = null;
        try
        {
            if (floor.Phase == 2 && floor.Ordinal <= 2)
            {
                using var pending = await checkpoint.ReadPendingAsync(floor, ct).ConfigureAwait(false);
                header = pending.Use(bytes => bytes[..Did2MessagingFloor.MetadataBytes].ToArray());
            }
            using var segment = await OpenRegisteredMessagingSegmentAsync(storage, accountPath,
                scope.Network.ToArray(), current.AccountId, scope, NativeArchiveAlgorithm.Full, ct,
                provenancePurpose: NativeProvenancePurpose.InitialAuditClassification).ConfigureAwait(false);
            if (!Did2MessagingSessionScope.Fixed(segment.Sql.ReadOpenedFloor().Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Native Initial classification changed its actual protected floor.");
            return segment.Sql.ClassifyInitialOwnedNativeAudit(floor, header);
        }
        finally { if (header is not null) CryptographicOperations.ZeroMemory(header); }
    }

    /// <summary>Open only a protected registered session, under the account lease.
    /// The returned storage owns no lease and is never a public runtime handle.</summary>
    internal static async Task<OwnedDid2MessagingStorage> OpenRegisteredMessagingUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, Did2MessagingSessionScope scope, CancellationToken ct,
        Action<OwnedDid2MessagingStorage>? configureRouteHistory = null)
        => await OpenRegisteredMessagingCoreAsync(storage, accountPath, network, account, scope, NativeArchiveAlgorithm.Active, ct, configureRouteHistory).ConfigureAwait(false);

    // Only the explicit account enrollment owner calls this lower path. Actual
    // catalog/progress select schema5 draining or the exact staged schema6.
    internal static Task<OwnedDid2MessagingStorage> OpenArchiveEnrollmentMessagingUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, Did2MessagingSessionScope scope, CancellationToken ct)
        => OpenRegisteredMessagingCoreAsync(storage, accountPath, network, account, scope, NativeArchiveAlgorithm.Enrollment, ct,
            provenancePurpose: NativeProvenancePurpose.Enrollment);

    internal static Task<OwnedDid2MessagingStorage> OpenArchiveEnrollmentSelectionUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, Did2MessagingSessionScope scope, CancellationToken ct)
        => OpenRegisteredMessagingCoreAsync(storage, accountPath, network, account, scope, NativeArchiveAlgorithm.EnrollmentSelection, ct,
            provenancePurpose: NativeProvenancePurpose.Enrollment);

    internal static Task<OwnedDid2MessagingStorage> OpenOwnedArchiveEnrollmentUnderLeaseAsync(IDeepSecureStorage storage,
        string accountPath, VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, CancellationToken ct)
        => OpenOwnedMessagingCoreAsync(storage, accountPath, current, scope, NativeArchiveAlgorithm.Enrollment, NativeProvenancePurpose.Enrollment, ct);

    internal static Task<OwnedDid2MessagingStorage> OpenOwnedArchiveEnrollmentSelectionUnderLeaseAsync(IDeepSecureStorage storage,
        string accountPath, VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, CancellationToken ct)
        => OpenOwnedMessagingCoreAsync(storage, accountPath, current, scope, NativeArchiveAlgorithm.EnrollmentSelection, NativeProvenancePurpose.Enrollment, ct);

#if DEEP_TEST_INTERNALS
    // Structural registration inspection only. Shipping initial transfer uses
    // the current-account full-source purpose above, never this test adapter.
    internal static Task<OwnedDid2MessagingStorage> InspectRegisteredEmptyMessagingForTestAsync(
        IDeepSecureStorage storage, string accountPath, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, Did2MessagingSessionScope scope, CancellationToken ct)
        => OpenRegisteredMessagingCoreAsync(storage, accountPath, network, account, scope, NativeArchiveAlgorithm.Active, ct,
            provenancePurpose: NativeProvenancePurpose.InitialTransfer);
#endif

    private static async Task<OwnedDid2MessagingStorage> OpenRegisteredMessagingCoreAsync(
        IDeepSecureStorage storage, string accountPath, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, Did2MessagingSessionScope scope, NativeArchiveAlgorithm algorithm, CancellationToken ct,
        Action<OwnedDid2MessagingStorage>? configureRouteHistory = null,
        Func<CancellationToken, Task<MessagingSourceObservation>>? captureSource = null,
        NativeProvenancePurpose provenancePurpose = NativeProvenancePurpose.Established)
    {
        var checkpoint = new Did2MessagingProtectedCheckpoint(storage, scope);
        var result = new OwnedDid2MessagingStorage(scope, checkpoint,
            (token, paired) => OpenRegisteredMessagingSegmentAsync(storage, accountPath, network, account, scope, algorithm, token, paired, captureSource, provenancePurpose));
        try
        {
            configureRouteHistory?.Invoke(result);
            var initial = await result.WithSqlAsync(sql => (Tip: sql.VerifyOrdinaryState(), Frozen: sql.HasFrozenArchiveEnrollment), ct).ConfigureAwait(false);
            // Initialization CAS runs after the physical connection and all SQL
            // key loans are closed. Its result is rejoined by the next segment.
            if (!IsArchiveEnrollmentAlgorithm(algorithm))
            {
                var catalog = new ProtectedDid2MessagingSessionCatalog(storage, network.Span, account.Span, scope.Instance);
                await catalog.MarkSqlInitializedAsync(scope, initial.Tip, ct).ConfigureAwait(false);
            }
            else if (!initial.Frozen && algorithm != NativeArchiveAlgorithm.EnrollmentSelection)
            {
                var catalog = new ProtectedDid2MessagingSessionCatalog(storage, network.Span, account.Span, scope.Instance);
                await catalog.MarkOldSqlInitializedForEnrollmentAsync(scope, initial.Tip, ct).ConfigureAwait(false);
            }
            if (!initial.Frozen && algorithm != NativeArchiveAlgorithm.EnrollmentSelection) _ = await result.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            return result;
        }
        catch { result.Dispose(); throw; }
    }

    private static async Task<Did2MessagingSqlSegment> OpenRegisteredMessagingSegmentAsync(
        IDeepSecureStorage storage, string accountPath, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, Did2MessagingSessionScope scope, NativeArchiveAlgorithm algorithm, CancellationToken ct,
        Did2MessagingArchiveAuthoredRead? paired = null,
        Func<CancellationToken, Task<MessagingSourceObservation>>? captureSource = null,
        NativeProvenancePurpose provenancePurpose = NativeProvenancePurpose.Established)
    {
        using var source = captureSource is null ? null : await captureSource(ct).ConfigureAwait(false);
        // One bounded actual inventory owns registration selection. Only pure
        // decoders/path checks run before opening SQL; no authority callback or
        // previously successful read can supply any member of this snapshot.
        var slots = new List<string> { KeySlot,
            ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot,
            Did2MessagingHistoryCheckpoint.Slot(scope), Did2MessagingArchiveRoot.Slot(scope),
            ProtectedDid2MessagingArchiveEnrollment.Slot, ProtectedDid2MessagingPeerBootstrap.Slot(scope) };
        if (paired is not null) { slots.Add(ApplicationStateSlot); slots.AddRange(paired.Roots.Keys.Order(StringComparer.Ordinal)); }
        var authoredEnd = slots.Count;
        var retirementIndex = -1;
        if (provenancePurpose == NativeProvenancePurpose.Established)
        { retirementIndex = slots.Count; slots.Add(ProtectedInitialKeyRetirementJournal.Slot); }
        using var inventory = source is null ? await storage.ReadOwnedBatchAsync(slots, ct).ConfigureAwait(false) :
            await storage.ReadOwnedGuardedBatchAsync(slots, source.Roots, ct).ConfigureAwait(false);
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
        if (!IsArchiveEnrollmentAlgorithm(algorithm) && inventory[5] is not null)
            throw new InvalidOperationException("Explicit messaging archive enrollment owns ordinary account admission.");
        using var registered = catalogBytes.Use(bytes => IsArchiveEnrollmentAlgorithm(algorithm) ?
            ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(bytes, network.Span, account.Span, scope.Instance) :
            ProtectedDid2MessagingSessionCatalog.Decode(bytes, network.Span, account.Span, scope.Instance));
        var index = registered.FindExact(scope);
        if (index < 0) throw new InvalidDataException("DID2 messaging SQL has no protected registration.");
        ProtectedDid2MessagingArchiveEnrollment? progress = null;
        if (IsArchiveEnrollmentAlgorithm(algorithm) && registered.Version == 2)
        {
            if (inventory[5] is { } progressBytes)
            {
                if (algorithm == NativeArchiveAlgorithm.EnrollmentSelection)
                    throw new InvalidOperationException("Actual stored enrollment progress owns selection.");
                progress = progressBytes.Use(bytes => ProtectedDid2MessagingArchiveEnrollment.Decode(bytes, scope));
            }
            else
            {
                var selected = Enumerable.Range(0, registered.Count).FirstOrDefault(i => registered.ArchiveState(i) == 0, -1);
                if (algorithm != NativeArchiveAlgorithm.EnrollmentSelection || selected != index || registered.ArchiveState(index) != 0)
                    throw new InvalidOperationException("Only explicit lowest state0 selection may audit before SourceFrozen.");
            }
        }
        else if (algorithm == NativeArchiveAlgorithm.EnrollmentSelection)
            throw new InvalidOperationException("Pre-progress selection requires the actual V2 enrollment catalog.");
        var peerBytes = inventory[6] ?? throw new InvalidDataException("The protected native peer bootstrap is absent.");
        _ = peerBytes.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope));
        var phase = registered.Phase(index);
        if ((provenancePurpose is NativeProvenancePurpose.Established or NativeProvenancePurpose.InitialAuditClassification) && phase != 2)
            throw new InvalidOperationException("Established native work requires an initialized session; use explicit initial transfer.");
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
        ProtectedInitialKeyRetirementJournal.Entry? retirement = null;
        if (provenancePurpose == NativeProvenancePurpose.Established)
        {
            if (floor.Status == 0 || floor.Ordinal < 2)
                throw new InvalidOperationException("Pending initial transfer cannot enter established native work.");
            retirement = (inventory[retirementIndex] ?? throw new InvalidDataException("Established native work lost its source retirement proof."))
                .Use(bytes => ProtectedInitialKeyRetirementJournal.CaptureEstablishedProof(bytes, scope));
        }
        var historyBytes = inventory[3] ?? throw new InvalidDataException("Mandatory messaging history checkpoint is absent; no initialization is permitted.");
        var history = historyBytes.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
        Did2MessagingArchiveRoot? archive = null;
        if (!IsArchiveEnrollmentAlgorithm(algorithm) || registered.ArchiveState(index) == 1)
        {
            var archiveBytes = inventory[4] ?? throw new InvalidDataException("An indexed messaging archive root is absent; no reconstruction is allowed.");
            archive = archiveBytes.Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope)); archive.RequireSource(history);
        }
        else if (inventory[4] is not null) throw new CryptographicException("An unindexed enrollment entry has an unexpected protected archive root.");
        var actualRegistrationHash = registration.Use(bytes => SHA256.HashData(bytes));
        var actualCatalogHash = catalogBytes.Use(bytes => SHA256.HashData(bytes));
        if (progress is not null)
        {
            byte[] comparison;
            if (registered.ArchiveState(index) == 1)
            {
                if (progress.Phase != ProtectedDid2MessagingArchiveEnrollment.PhaseKind.FinalReady || archive is null ||
                    !Did2MessagingSessionScope.Fixed(archive.Exact.Span, progress.FinalRoot(scope).Exact.Span))
                    throw new CryptographicException("Indexed enrollment recovery lacks its exact already-adopted root.");
                comparison = registered.BeforeIndexedComparison(index);
            }
            else comparison = registered.Exact.ToArray();
            try
            {
                if (!Did2MessagingSessionScope.Fixed(SHA256.HashData(comparison), progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.Catalog)) ||
                    !Did2MessagingSessionScope.Fixed(actualRegistrationHash, progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.Registration)) ||
                    !peerBytes.Use(bytes => Did2MessagingSessionScope.Fixed(SHA256.HashData(bytes), progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.PeerBootstrap))) ||
                    !Did2MessagingSessionScope.Fixed(floor.Exact.Span, progress.SourceFloor.Exact.Span) ||
                    !Did2MessagingSessionScope.Fixed(history.Exact.Span, progress.SourceHistory.Exact.Span))
                    throw new CryptographicException("Actual enrollment protected source guards differ from the frozen progress.");
            }
            finally { CryptographicOperations.ZeroMemory(comparison); }
        }
        byte[] pairedRegistration = [], pairedApplication = [];
        var pairedRoots = new Dictionary<string, byte[]?>(StringComparer.Ordinal);
        using var fullSourcePrefix = paired?.FullSourceHash is null ? null : CreateArchiveAuthoredPrefix(scope, slots.Take(authoredEnd).ToArray(), inventory, 8);
        try
        {
            if (paired is not null || source is not null)
                pairedRegistration = registration.Use(bytes => bytes.ToArray());
            if (paired is not null)
            {
                pairedApplication = (inventory[7] ?? throw new InvalidDataException("Final paired admission lost application registration.")).Use(bytes => bytes.ToArray());
                for (var i = 8; i < authoredEnd; i++) pairedRoots.Add(slots[i], inventory[i]?.Use(bytes => SHA256.HashData(bytes)));
            }
            inventory.Dispose(); // In particular no raw Group/root/key loan crosses the application read.
            source?.Verify(pairedRegistration, floor.Status != 0);
            source?.Dispose();
            if (paired is not null) VerifyPairedArchiveApplication(accountPath, scope, pairedRegistration, pairedApplication,
                pairedRoots, paired, ct: ct, fullSourcePrefix: fullSourcePrefix);
        }
        finally { CryptographicOperations.ZeroMemory(pairedRegistration); CryptographicOperations.ZeroMemory(pairedApplication); }
        if (phase == 1 && !Did2MessagingSessionScope.Fixed(floor.Exact.Span, Did2MessagingFloor.Empty(scope).Exact.Span))
            throw new CryptographicException("Uninitialized DID2 messaging registration has a nonempty floor.");
        if (phase == 1 && !Did2MessagingSessionScope.Fixed(history.Exact.Span, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.Span))
            throw new CryptographicException("Uninitialized DID2 messaging registration has a nonempty history checkpoint.");
        ct.ThrowIfCancellationRequested();
        using var key = registered.ReadKey(index);
        SqliteConnection? connection = key.Use(bytes => OpenMessagingConnection(path, bytes, create: phase == 1));
        try
        {
            var sql = IsArchiveEnrollmentAlgorithm(algorithm) ?
                registered.Version == 1 && phase == 1 ? Did2MessagingSqlJournal.InitializeOldEnrollmentSource(connection, scope, history, floor) :
                    Did2MessagingSqlJournal.ForArchiveEnrollment(connection, scope, history, progress) :
                algorithm == NativeArchiveAlgorithm.Active && phase == 2 ? Did2MessagingSqlJournal.ForOrdinaryRuntime(connection, scope, history, archive!) :
                new Did2MessagingSqlJournal(connection, scope, history);
            if (archive is not null && !IsArchiveEnrollmentAlgorithm(algorithm)) sql.BindArchiveRoot(archive);
            sql.BindOpenedFloor(floor);
            sql.BindEnrollmentProgress(progress);
            if (retirement is not null) _ = sql.RequireEstablishedNativeProvenance(floor, retirement);
            if (phase == 1)
            {
                sql.InitializeOrVerifyRegisteredEmpty(floor);

            }
            var result = new Did2MessagingSqlSegment(connection, sql);
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

// A physical SQL handle exists only inside one synchronous segment. No SQL
// connection, transaction, key loan or decoded registration crosses an await.
internal sealed class Did2MessagingSqlSegment(SqliteConnection connection, Did2MessagingSqlJournal sql) : IDisposable
{
    internal Did2MessagingSqlJournal Sql { get; } = sql;
    public void Dispose() => connection.Dispose();
}

internal sealed class OwnedDid2MessagingStorage : IDisposable
{
    private readonly Did2MessagingSessionScope scope;
    private readonly Did2MessagingProtectedCheckpoint checkpoint;
    private readonly Func<CancellationToken, Did2MessagingArchiveAuthoredRead?, Task<Did2MessagingSqlSegment>> open;
    private readonly Did2MessagingDurableCustody custody;
    private Func<OwnedDid2MessagingMutation, Func<Did2MessagingSqlJournal, object?>, CancellationToken, Task<object?>>? routeHistoryDecisionSql;
    private int disposed;
    internal OwnedDid2MessagingStorage(Did2MessagingSessionScope scope,
        Did2MessagingProtectedCheckpoint checkpoint, Func<CancellationToken, Task<Did2MessagingSqlSegment>> open)
        : this(scope, checkpoint, (token, paired) => paired is null ? open(token) : throw new InvalidOperationException("This SQL factory has no paired authored-source admission.")) { }
    internal OwnedDid2MessagingStorage(Did2MessagingSessionScope scope,
        Did2MessagingProtectedCheckpoint checkpoint, Func<CancellationToken, Did2MessagingArchiveAuthoredRead?, Task<Did2MessagingSqlSegment>> open)
    {
        this.scope = scope; this.checkpoint = checkpoint; this.open = open;
        custody = new Did2MessagingDurableCustody(scope, checkpoint, this);
    }
    internal Did2MessagingSessionScope Scope { get { RequireLive(); return scope; } }
    internal Did2MessagingProtectedCheckpoint Checkpoint { get { RequireLive(); return checkpoint; } }
    internal Did2MessagingDurableCustody Custody { get { RequireLive(); return custody; } }
    internal Task<T> WithSqlAsync<T>(Func<Did2MessagingSqlJournal, T> operation, CancellationToken ct)
        => WithSqlCoreAsync(operation, null, ct);
    internal Task<T> WithPairedSqlAsync<T>(Did2MessagingArchiveAuthoredRead paired, Func<Did2MessagingSqlJournal, T> operation, CancellationToken ct)
        => WithSqlCoreAsync(operation, paired, ct);
    internal void ConfigureRouteHistoryDecisionSql(
        Func<OwnedDid2MessagingMutation, Func<Did2MessagingSqlJournal, object?>, CancellationToken, Task<object?>> operation)
    {
        RequireLive();
        if (routeHistoryDecisionSql is not null) throw new InvalidOperationException("Route-history recovery is already bound to its actual account owner.");
        routeHistoryDecisionSql = operation ?? throw new ArgumentNullException(nameof(operation));
    }
    internal async Task<T> WithRouteHistoryDecisionSqlAsync<T>(OwnedDid2MessagingMutation mutation,
        Func<Did2MessagingSqlJournal, T> operation, CancellationToken ct)
    {
        RequireLive();
        if (mutation.Kind != 6) throw new InvalidOperationException("The paired recovery boundary accepts only exact stored route-history decisions.");
        var run = routeHistoryDecisionSql ?? throw new InvalidOperationException("Route-history recovery has no actual held account owner.");
        return (T)(await run(mutation, sql => operation(sql), ct).ConfigureAwait(false))!;
    }
    private async Task<T> WithSqlCoreAsync<T>(Func<Did2MessagingSqlJournal, T> operation, Did2MessagingArchiveAuthoredRead? paired, CancellationToken ct)
    {
        RequireLive(); ct.ThrowIfCancellationRequested();
#if DEEP_TEST_INTERNALS
        for (var attempt = 0; ; attempt++)
        {
            try
            {
#endif
        using var segment = await open(ct, paired).ConfigureAwait(false);
        RequireLive(); ct.ThrowIfCancellationRequested();
        var result = operation(segment.Sql);
        if (result is Task) throw new InvalidOperationException("SQL segments cannot cross an asynchronous callback.");
        return result;
#if DEEP_TEST_INTERNALS
            }
            catch (Did2ActiveReadBoundary boundary)
            {
                // The using scope has ended: no SQL/key/source loan crosses the
                // adversarial callback. Only one test-requested fresh read runs.
                if (attempt != 0) throw new CryptographicException("A selected-read test boundary invalidated its fresh retry.");
                boundary.Invoke();
            }
        }
#endif
    }
    internal async Task WithSqlAsync(Action<Did2MessagingSqlJournal> operation, CancellationToken ct)
    { _ = await WithSqlAsync(sql => { operation(sql); return 0; }, ct).ConfigureAwait(false); }
    // Pure scheduling metadata only; it never suppresses actual segment joins.
    internal bool RecoveredLocalCompaction { get; set; }
    private void RequireLive() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    public void Dispose() => Interlocked.Exchange(ref disposed, 1);
}
