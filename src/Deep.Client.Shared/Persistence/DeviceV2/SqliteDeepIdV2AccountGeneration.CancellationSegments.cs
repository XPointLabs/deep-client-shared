using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal sealed record CancellationSourceCoordinate(SqliteDeviceStateStore.CancellationSource? Source,
        byte[] SourceInstance, byte[] DraftBinding);

    internal static async Task<CancellationSourceCoordinate> ReadCancellationSourceUnderLeaseAsync(IDeepSecureStorage storage,
        string accountPath, ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        ReadOnlyMemory<byte> intent, HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct,
        ulong? expectedGeneration = null)
        => await WithCancellationSourceSegmentAsync(storage, accountPath, network, account, instance, intent,
            null, false, false, held, lease, ct, expectedGeneration).ConfigureAwait(false);

    internal static async Task RetireCancelledInitialUnderLeaseAsync(IDeepSecureStorage storage,
        string accountPath, ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        ReadOnlyMemory<byte> intent, HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        var observed = await ReadCancellationSourceUnderLeaseAsync(storage, accountPath, network, account, instance, intent, held, lease, ct).ConfigureAwait(false);
        var preclaim = await ReadPreclaimCancellationHashUnderLeaseAsync(storage, network, account, instance,
            intent, observed.DraftBinding, observed.Source is not null, ct).ConfigureAwait(false);
        var bytes = new byte[ProtectedInitialKeyRetirementJournal.EntryBytes];
        try
        {
            bytes[0] = 3; bytes[1] = 1; observed.SourceInstance.CopyTo(bytes, 4);
            if (observed.Source is { } source)
            {
                BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(36), source.Ordinal);
                source.RecordHash.CopyTo(bytes, 44); source.Basis.CopyTo(bytes, 108); source.TrsHash.CopyTo(bytes, 140);
            }
            observed.DraftBinding.CopyTo(bytes, 76); intent.Span.CopyTo(bytes.AsSpan(172)); preclaim.CopyTo(bytes, 204);
            var candidate = new ProtectedInitialKeyRetirementJournal.Entry(bytes);
            // Rejoin the exact source and actual native absence after the
            // preclaim provider, before publishing this deletion manifest.
            await WithCancellationSourceSegmentAsync(storage, accountPath, network, account, instance, intent,
                candidate, false, false, held, lease, ct).ConfigureAwait(false);
            var pending = await ProtectedInitialKeyRetirementJournal.StageCancellationUnderLeaseAsync(storage,
                network, account, instance, candidate, ct).ConfigureAwait(false);
            if (pending.Phase == 2)
            {
                await WithCancellationSourceSegmentAsync(storage, accountPath, network, account, instance, intent,
                    pending, false, true, held, lease, ct).ConfigureAwait(false);
                await CancelPreclaimUnderLeaseAsync(storage, network, account, instance, pending, ct).ConfigureAwait(false);
                await WithCancellationSourceSegmentAsync(storage, accountPath, network, account, instance, intent,
                    pending, false, true, held, lease, ct).ConfigureAwait(false);
                return;
            }
#if DEEP_TEST_INTERNALS
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterPending);
#endif
            await CancelPreclaimUnderLeaseAsync(storage, network, account, instance, pending, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterPreclaim);
#endif
            await WithCancellationSourceSegmentAsync(storage, accountPath, network, account, instance, intent,
                pending, true, false, held, lease, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterSourceDelete);
#endif
            // The physical deletion is committed. Finish its bounded receipt
            // without caller cancellation, then independently prove no keys.
            await WithCancellationSourceSegmentAsync(storage, accountPath, network, account, instance, intent,
                pending, false, true, held, lease, CancellationToken.None).ConfigureAwait(false);
            await ProtectedInitialKeyRetirementJournal.CompleteCancellationUnderLeaseAsync(storage, network,
                account, instance, pending, CancellationToken.None).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterStable);
#endif
            await WithCancellationSourceSegmentAsync(storage, accountPath, network, account, instance, intent,
                pending.Stable(), false, true, held, lease, CancellationToken.None).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(preclaim); CryptographicOperations.ZeroMemory(bytes); }
    }

    private static async Task<CancellationSourceCoordinate> WithCancellationSourceSegmentAsync(IDeepSecureStorage storage,
        string accountPath, ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        ReadOnlyMemory<byte> intent, ProtectedInitialKeyRetirementJournal.Entry? expected, bool delete, bool requireNoKeys,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct, ulong? expectedGeneration = null)
    {
        using var borrowed = held.BorrowFor(lease);
        string[] basisSlots = [KeySlot, DeviceStateMarkerSlot, DeviceInitialSessionCheckpoint.Slot,
            ProtectedInitialKeyRetirementJournal.Slot, ProtectedDid2ContactStartJournal.Slot,
            ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDph2PreClaimJournal.Slot, ProtectedDid2MessagingArchiveEnrollment.Slot];
        for (var attempt = 0; ; attempt++)
        {
            var retirement = await ProtectedInitialKeyRetirementJournal.ReadSourceSnapshotAsync(storage, network, account, ct).ConfigureAwait(false);
            var guards = new Dictionary<string, byte[]?>(retirement.OwnerHashes, StringComparer.Ordinal);
            byte phase; Did2MessagingSessionScope? scope = null;
            using (var observed = await storage.ReadOwnedGuardedBatchAsync(basisSlots, guards, ct).ConfigureAwait(false))
            {
                for (var index = 0; index < basisSlots.Length; index++) guards[basisSlots[index]] = observed[index]?.Use(bytes => SHA256.HashData(bytes));
                if (observed[7] is not null) throw new InvalidOperationException("Explicit messaging archive enrollment owns cancellation.");
                var checkpoint = observed[2] ?? throw new InvalidDataException("Cancellation source checkpoint is absent.");
                phase = checkpoint.Use(bytes => bytes.Length >= 2 && bytes[1] is 1 or 2 ? bytes[1] :
                    throw new InvalidDataException("Cancellation source checkpoint has another phase."));
                if (expected is not null)
                {
                    using var drafts = (observed[4] ?? throw new InvalidDataException()).Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, network.Span, account.Span, instance.Span));
                    using var catalog = (observed[5] ?? throw new InvalidDataException()).Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes, network.Span, account.Span, instance.Span));
                    scope = SelectCancellationScopes(drafts, catalog, expected).SingleOrDefault();
                }
            }
            if (phase == 2)
            {
                if (attempt != 0) throw new CryptographicException("Cancellation source remained pending after exact recovery.");
                byte[] registration = [], pending = [], stable = [];
                try
                {
                    using (var actual = await storage.ReadOwnedGuardedBatchAsync(basisSlots, guards, ct).ConfigureAwait(false))
                    {
                        registration = (actual[0] ?? throw new InvalidDataException()).Use(bytes => bytes.ToArray());
                        pending = (actual[2] ?? throw new InvalidDataException()).Use(bytes => bytes.ToArray());
                        var marker = (actual[1] ?? throw new InvalidDataException()).Use(bytes => bytes.ToArray());
                        (actual[6] ?? throw new InvalidDataException()).Use(bytes =>
                            retirement.State.RequirePreclaimState(ProtectedDph2PreClaimJournal.Decode(bytes, network.Span, account.Span, instance.Span)));
                        actual.Dispose(); ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                        using var source = OpenCancellationDeviceSegment(accountPath, registration, marker, network.Span, account.Span, instance.Span,
                            readOnly: false, expectedGeneration: expectedGeneration);
                        stable = source.RecoverMessagingSourceSegment(network, pending, retirement.State);
                    }
                    CryptographicOperations.ZeroMemory(registration); registration = [];
                    CryptographicOperations.ZeroMemory(pending); pending = [];
                    // A pending checkpoint contains private TRS. Reacquire it
                    // only for this one exact guarded write, then wipe it.
                    using (var owner = await storage.ReadOwnedAsync(DeviceInitialSessionCheckpoint.Slot, CancellationToken.None).ConfigureAwait(false) ?? throw new InvalidDataException())
                    {
                        if (owner.Use(bytes => Fixed(bytes, stable))) continue;
                        if (!owner.Use(bytes => Fixed(SHA256.HashData(bytes), guards[DeviceInitialSessionCheckpoint.Slot]!)))
                            throw new CryptographicException("Cancellation source pending changed before stabilization.");
                        pending = owner.Use(bytes => bytes.ToArray());
                    }
                    bool applied;
                    try { applied = await storage.CompareExchangeAsync(DeviceInitialSessionCheckpoint.Slot, pending, stable, CancellationToken.None).ConfigureAwait(false); }
                    finally { CryptographicOperations.ZeroMemory(pending); pending = []; }
                    if (!applied)
                    {
                        using var owner = await storage.ReadOwnedAsync(DeviceInitialSessionCheckpoint.Slot, CancellationToken.None).ConfigureAwait(false);
                        if (owner?.Use(bytes => Fixed(bytes, stable)) != true) throw new CryptographicException("Cancellation source lost its exact stable result.");
                    }
                    continue;
                }
                finally { CryptographicOperations.ZeroMemory(registration); CryptographicOperations.ZeroMemory(pending); CryptographicOperations.ZeroMemory(stable); }
            }
            var returned = scope is null ? basisSlots : basisSlots.Concat([scope.FloorSlot,
                Did2MessagingHistoryCheckpoint.Slot(scope), Did2MessagingArchiveRoot.Slot(scope)]).ToArray();
            // At most one matching basis is permitted by the actual catalog.
            // All other cancellation dependencies remain guards, not returns.
            using var final = await storage.ReadOwnedGuardedBatchAsync(returned, guards, ct).ConfigureAwait(false);
            byte[] record = [], checkpointExact = [];
            try
            {
                record = (final[0] ?? throw new InvalidDataException()).Use(bytes => bytes.ToArray());
                var marker = (final[1] ?? throw new InvalidDataException()).Use(bytes => bytes.ToArray());
                checkpointExact = (final[2] ?? throw new InvalidDataException()).Use(bytes => bytes.ToArray());
                using var drafts = (final[4] ?? throw new InvalidDataException()).Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, network.Span, account.Span, instance.Span));
                using var catalog = (final[5] ?? throw new InvalidDataException()).Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes, network.Span, account.Span, instance.Span));
                (final[6] ?? throw new InvalidDataException()).Use(bytes =>
                {
                    var claims = ProtectedDph2PreClaimJournal.Decode(bytes, network.Span, account.Span, instance.Span);
                    retirement.State.RequirePreclaimState(claims);
                    if (expected is not null) RequireCancellationPreclaim(claims, expected, delete || requireNoKeys || expected.Phase == 2);
                });
                if (!drafts.Entries.TryGetValue(Convert.ToHexString(intent.Span), out var draft)) throw new CryptographicException("Cancellation lost its actual draft intent.");
                if (expected?.Phase == 2)
                {
                    var completed = retirement.State.FindCancellation(intent.Span);
                    if (completed is null || !Fixed(completed.Exact, expected.Exact))
                        throw new CryptographicException("Completed cancellation lost its exact stable retirement owner.");
                }
                if (expected is not null)
                {
                    var scopes = SelectCancellationScopes(drafts, catalog, expected);
                    if (scopes.Length != (scope is null ? 0 : 1) || scope is not null && !Fixed(scope.Exact, scopes[0].Exact))
                        throw new CryptographicException("Cancellation changed its native source selection.");
                }
                var floor = scope is null ? null : (final[8] ?? throw new InvalidDataException()).Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
                var history = scope is null ? null : (final[9] ?? throw new InvalidDataException()).Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
                var archive = scope is null ? null : (final[10] ?? throw new InvalidDataException()).Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
                final.Dispose(); ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (scope is not null)
                {
                    archive!.RequireSource(history!);
                    if (!Fixed(archive.Exact.Span, Did2MessagingArchiveRoot.Empty(scope).Exact.Span))
                        throw new CryptographicException("Initial cancellation requires its exact canonical empty archive.");
                    using var native = OpenExistingMessagingForCompactionUnderLease(accountPath, catalog, scope, held, lease);
                    var sql = new Did2MessagingSqlJournal(native, scope, history!); sql.BindArchiveRoot(archive);
                    if (!Fixed(floor!.Exact.Span, Did2MessagingFloor.Empty(scope).Exact.Span) ||
                        !Fixed(sql.VerifyTip().Exact.Span, floor.Exact.Span) || !Fixed(history!.Exact.Span, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.Span))
                        throw new CryptographicException("Initial cancellation cannot delete an imported native source.");
                }
                using var device = OpenCancellationDeviceSegment(accountPath, record, marker, network.Span, account.Span, instance.Span,
                    readOnly: !delete, expectedGeneration: expectedGeneration);
                var source = device.InspectCancellationSourceSegment(network, checkpointExact, retirement.State, draft);
                if (expected is not null) device.RequireCancellationSource(expected, draft, source);
                if (requireNoKeys && source?.Live == true) throw new CryptographicException("Cancelled Initial keys survived deletion or were resurrected.");
                if (delete)
                {
                    if (expected is null) throw new InvalidOperationException("Deletion requires actual staged cancellation.");
                    var retained = retirement.State.FindCancellation(intent.Span);
                    if (retained is null || retained.Phase != 1 || !Fixed(retained.Exact, expected.Exact))
                        throw new CryptographicException("Source deletion lost its exact pending cancellation owner.");
                    device.DeleteCancellationSourceSegment(network, checkpointExact, retirement.State, draft, retained);
                }
                return new(source, CancellationSourceInstance(network.Span, account.Span, instance.Span), draft.CancellationBinding);
            }
            finally { CryptographicOperations.ZeroMemory(record); CryptographicOperations.ZeroMemory(checkpointExact); }
        }
    }

    private static void RequireCancellationPreclaim(ProtectedDph2PreClaimJournal.State claims,
        ProtectedInitialKeyRetirementJournal.Entry expected, bool requireCancelled)
    {
        var name = Convert.ToHexString(expected.Intent);
        if (claims.Retired.ContainsKey(name)) throw new CryptographicException("Cancellation cannot borrow transferred preclaim custody.");
        if (claims.Cancelled.TryGetValue(name, out var cancelled))
        {
            if (!Fixed(cancelled.BlobHash, expected.PreclaimHash) || !Fixed(cancelled.DraftBinding, expected.ScopeHash))
                throw new CryptographicException("Cancellation lost its exact preclaim tombstone.");
            return;
        }
        if (requireCancelled) throw new CryptographicException("Source deletion/completion requires its actual preclaim cancellation tombstone.");
        if (claims.Claims.TryGetValue(name, out var live))
        {
            if (!Fixed(SHA256.HashData(live.CanonicalBytes.Span), expected.PreclaimHash))
                throw new CryptographicException("Cancellation selected another live preclaim.");
        }
        else if (expected.Ordinal != 0 || expected.PreclaimHash.IndexOfAnyExcept((byte)0) >= 0)
            throw new CryptographicException("Completed cancellation source lost its original preclaim.");
    }

    // Preserve the existing pre-stop provision of an absolutely absent empty
    // Device store. Recovery callers never enter this current-owner method.
    internal static async Task EnsureCancellationSourceUnderLeaseAsync(IDeepSecureStorage storage,
        string accountPath, VerifiedDeepIdV2CurrentAccount current, ReadOnlyMemory<byte> intent, HeldDeepIdV2AccountLease held,
        DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        var network = current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.NetworkId;
        string[] slots = [KeySlot, DeviceStateMarkerSlot, DeviceInitialSessionCheckpoint.Slot, ProtectedDid2ContactStartJournal.Slot];
        var retirement = await ProtectedInitialKeyRetirementJournal.ReadSourceSnapshotAsync(storage, network, current.AccountId, ct).ConfigureAwait(false);
        var guards = new Dictionary<string, byte[]?>(retirement.OwnerHashes, StringComparer.Ordinal);
        byte[] instance, storeId, marker, checkpoint, draftExpected;
        using (var roots = await storage.ReadOwnedGuardedBatchAsync(slots, guards, ct).ConfigureAwait(false))
        {
            for (var index = 0; index < slots.Length; index++) guards[slots[index]] = roots[index]?.Use(bytes => SHA256.HashData(bytes));
            var registration = roots[0] ?? throw new InvalidDataException();
            instance = registration.Use(bytes => ReadAccountInstanceFromRegistration(bytes, network.Span, current.AccountId.Span));
            registration.Use(bytes => ValidateDatabase(Path.GetFullPath(accountPath), bytes.Slice(88, 32),
                AccountBinding.From(current.Verified, current.AccountId.Span, network.Span, current.DisplayName, current.PermanentId.CanonicalText, instance)));
            var draftRoot = roots[3] ?? throw new InvalidDataException("Source provisioning lost its actual Initial draft owner.");
            using var drafts = draftRoot.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, network.Span, current.AccountId.Span, instance));
            if (!drafts.Entries.TryGetValue(Convert.ToHexString(intent.Span), out var selectedDraft))
                throw new CryptographicException("Cancellation source has no actual selected Initial draft.");
            storeId = CancellationSourceInstance(network.Span, current.AccountId.Span, instance);
            marker = SHA256.HashData(storeId.Concat(network.ToArray()).Concat(current.AccountId.ToArray()).ToArray());
            var path = DeviceStatePath(accountPath); RequireApplicationFileFamily(path);
            if (roots[1] is { } installed)
            {
                if (!installed.Use(bytes => Fixed(bytes, marker)) || roots[2] is null || !File.Exists(path))
                    throw new CryptographicException("Cancellation cannot repair an existing source registration.");
                var existingRecord = registration.Use(bytes => bytes.ToArray());
                try
                {
                    roots.Dispose(); ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                    using var source = OpenCancellationDeviceSegment(accountPath, existingRecord, marker, network.Span,
                        current.AccountId.Span, instance, readOnly: true,
                        expectedGeneration: current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.AccountGeneration);
                }
                finally { CryptographicOperations.ZeroMemory(existingRecord); }
                return;
            }
            if (roots[2] is not null || new[] { "", "-journal", "-wal", "-shm" }.Any(suffix => File.Exists(path + suffix)))
                throw new InvalidDataException("Cancellation found source data without its protected marker.");
            if (selectedDraft.WorkStopped)
                throw new CryptographicException("Stopped Initial cancellation cannot provision missing source custody.");
            checkpoint = DeviceInitialSessionCheckpoint.Stable(storeId, current.AccountId.Span, network.Span, 0, new byte[32]);
            draftExpected = draftRoot.Use(bytes => bytes.ToArray());
        }
        // Marker/checkpoint are public facts. No registration bytes, derived
        // key, source SQL handle or private checkpoint survives this provider.
        try
        {
            // Existing exact guard+insert atomically proves this selected
            // draft is still pre-stop and both source roots remain absent.
            if (!await storage.CompareExchangeAndInsertAsync(ProtectedDid2ContactStartJournal.Slot, draftExpected, draftExpected,
                [new DeepSecureStorageWrite(DeviceStateMarkerSlot, marker),
                 new DeepSecureStorageWrite(DeviceInitialSessionCheckpoint.Slot, checkpoint)], ct).ConfigureAwait(false))
                throw new CryptographicException("Initial draft stopped or source custody appeared before provisioning.");
        }
        finally { CryptographicOperations.ZeroMemory(draftExpected); }
        guards[DeviceStateMarkerSlot] = SHA256.HashData(marker); guards[DeviceInitialSessionCheckpoint.Slot] = SHA256.HashData(checkpoint);
        using var final = await storage.ReadOwnedGuardedBatchAsync(slots, guards, ct).ConfigureAwait(false);
        var record = (final[0] ?? throw new InvalidDataException()).Use(bytes => bytes.ToArray());
        byte[] transcript = [], key = [];
        try
        {
            final.Dispose(); ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            ValidateRecord(record, network.Span, current.AccountId.Span);
            if (!Fixed(record.AsSpan(56, 32), instance)) throw new CryptographicException("Cancellation provisioning changed its account instance.");
            var domain = "Deep/STORE-V2/device-state-key"u8; transcript = new byte[domain.Length + 80]; domain.CopyTo(transcript);
            network.Span.CopyTo(transcript.AsSpan(domain.Length)); current.AccountId.Span.CopyTo(transcript.AsSpan(domain.Length + 16)); instance.CopyTo(transcript, domain.Length + 48);
            key = HMACSHA256.HashData(record.AsSpan(88, 32), transcript);
            using var source = SqliteDeviceStateStore.OpenMessagingSourceSegment(new SqliteDeviceStateStoreOptions(DeviceStatePath(accountPath), key,
                DeviceAccountId32.FromBytes(current.AccountId.Span), current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.AccountGeneration,
                1, DeviceOperationId32.FromBytes(storeId), allowCreate: true), readOnlySource: false);
        }
        finally { CryptographicOperations.ZeroMemory(record); CryptographicOperations.ZeroMemory(transcript); CryptographicOperations.ZeroMemory(key); }
    }

    private static byte[] CancellationSourceInstance(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/device-state-key"u8); hash.AppendData(network); hash.AppendData(account); hash.AppendData(instance);
        return hash.GetHashAndReset();
    }

    private static SqliteDeviceStateStore OpenCancellationDeviceSegment(string accountPath, ReadOnlySpan<byte> record,
        ReadOnlySpan<byte> marker, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance, bool readOnly,
        ulong? expectedGeneration = null)
    {
        ValidateRecord(record, network, account);
        if (!Fixed(record.Slice(56, 32), instance)) throw new CryptographicException("Cancellation changed its registered account instance.");
        var domain = "Deep/STORE-V2/device-state-key"u8; var transcript = new byte[domain.Length + 80]; domain.CopyTo(transcript);
        network.CopyTo(transcript.AsSpan(domain.Length)); account.CopyTo(transcript.AsSpan(domain.Length + 16)); instance.CopyTo(transcript.AsSpan(domain.Length + 48));
        var key = HMACSHA256.HashData(record.Slice(88, 32), transcript); var storeId = SHA256.HashData(transcript);
        try
        {
            if (!Fixed(marker, SHA256.HashData(storeId.Concat(network.ToArray()).Concat(account.ToArray()).ToArray())))
                throw new CryptographicException("Cancellation opened a foreign source marker.");
            var path = DeviceStatePath(accountPath); RequireOrdinaryDirectory(Path.GetDirectoryName(path) ?? throw new InvalidDataException()); RequireApplicationFileFamily(path);
            if (!File.Exists(path) || new[] { "-wal", "-shm" }.Any(suffix => File.Exists(path + suffix))) throw new InvalidDataException("Cancellation requires its exact existing source file family.");
            ulong generation;
            using (var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString()))
            {
                db.Open(); SqliteDeviceStateStore.InstallRandomKey(db, key); SqliteDeviceStateStore.RequireReadOnlyMailboxSource(db, storeId, account);
                using var query = db.CreateCommand(); query.CommandText = "SELECT account_generation FROM device_store_meta WHERE singleton=1;";
                using var row = query.ExecuteReader();
                if (!row.Read()) throw new InvalidDataException("Cancellation source generation is absent.");
                var exact = row.GetFieldValue<byte[]>(0);
                if (exact.Length != 8 || (generation = BinaryPrimitives.ReadUInt64BigEndian(exact)) == 0 || row.Read())
                    throw new InvalidDataException("Cancellation source generation is not canonical.");
                if (expectedGeneration is { } currentGeneration && generation != currentGeneration)
                    throw new CryptographicException("Cancellation source has another current account generation.");
            }
            return SqliteDeviceStateStore.OpenMessagingSourceSegment(new SqliteDeviceStateStoreOptions(path, key,
                DeviceAccountId32.FromBytes(account), generation, 1, DeviceOperationId32.FromBytes(storeId), allowCreate: false), readOnly);
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(transcript); }
    }
}
