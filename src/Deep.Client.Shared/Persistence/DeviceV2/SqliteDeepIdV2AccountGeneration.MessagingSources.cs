using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    // Call-local, key-free protected observations and opaque sealed inventory
    // only. A registration/key/SQL handle exists solely inside Verify/Recover.
    private sealed class MessagingSourceObservation : IDisposable
    {
        internal readonly Dictionary<string, byte[]?> Roots = new(StringComparer.Ordinal);
        internal readonly Dictionary<string, byte[]?> PublicRoots = new(StringComparer.Ordinal);
        internal readonly Did2MessagingSessionScope Scope;
        internal readonly VerifiedDeepIdV2CurrentAccount Current;
        internal readonly string AccountPath;
        internal readonly ProtectedInitialKeyRetirementJournal.State Retirements;
        internal ProtectedPreKeyInventoryChain.Snapshot? Successors;
        internal byte[] Checkpoint = [];
        internal byte CheckpointPhase;
        internal MessagingSourceObservation(string accountPath, VerifiedDeepIdV2CurrentAccount current,
            Did2MessagingSessionScope scope, ProtectedInitialKeyRetirementJournal.SourceSnapshot retirement)
        {
            AccountPath = accountPath; Current = current; Scope = scope; Retirements = retirement.State;
            foreach (var pair in retirement.OwnerHashes) Roots.Add(pair.Key, pair.Value);
        }
        internal string CheckpointSlot => Scope.IsInitiator ? DeviceInitialSessionCheckpoint.Slot : ResponderInitialSessionCheckpoint.Slot;
        internal void RequireRoots(IReadOnlyDictionary<string, byte[]?> actual)
        {
            if (Roots.Any(pair => !actual.TryGetValue(pair.Key, out var value) ||
                (pair.Value is null ? value is not null : value is null || !Fixed(pair.Value, value))))
                throw new CryptographicException("Initial messaging source changed across its final protected inventory.");
        }
        internal void Verify(ReadOnlySpan<byte> registration, bool retired)
        {
            ValidateSourceRegistration(registration);
            if (CheckpointPhase != 1) throw new IOException("Initial messaging source has unresolved protected pending work.");
            if (Scope.IsInitiator)
            {
                using var source = OpenDevice(registration, readOnly: true);
                source.VerifyMessagingSourceReadSegment(Scope, retired, Checkpoint, Retirements);
            }
            else
            {
                var source = OpenReceiver(registration, readOnly: true);
                try
                {
                    RequireReceiverMarkers(source);
                    source.VerifyMessagingSourceReadSegment(Scope, retired, Checkpoint, Retirements, Scope.Instance.ToArray());
                }
                finally { source.DisposeAsync().GetAwaiter().GetResult(); }
            }
        }
        internal SqlitePreKeyV2InventoryStore.SourceRecovery Recover(ReadOnlySpan<byte> registration)
        {
            ValidateSourceRegistration(registration);
            if (CheckpointPhase != 2 || Checkpoint.Length < 2 || Checkpoint[1] != 2)
                throw new InvalidOperationException("Initial source recovery requires actual protected pending.");
            if (Scope.IsInitiator)
            {
                using var source = OpenDevice(registration, readOnly: false);
                return new(source.RecoverMessagingSourceSegment(Scope.Network.ToArray(), Checkpoint, Retirements), []);
            }
            var receiver = OpenReceiver(registration, readOnly: false);
            try
            {
                RequireReceiverMarkers(receiver);
                return receiver.RecoverMessagingSourceSegment(Checkpoint, Retirements, Scope.Instance.ToArray());
            }
            finally { receiver.DisposeAsync().GetAwaiter().GetResult(); }
        }
        private void ValidateSourceRegistration(ReadOnlySpan<byte> registration)
        {
            ValidateRecord(registration, Scope.Network, Scope.LocalAccount);
            if (!Fixed(registration.Slice(56, 32), Scope.Instance))
                throw new CryptographicException("Initial messaging source changed its registered account instance.");
            var binding = AccountBinding.From(Current.Verified, Scope.LocalAccount, Scope.Network, Current.DisplayName,
                Current.PermanentId.CanonicalText, Scope.Instance);
            ValidateDatabase(Path.GetFullPath(AccountPath), registration.Slice(88, 32), binding);
        }
        private SqliteDeviceStateStore OpenDevice(ReadOnlySpan<byte> registration, bool readOnly)
        {
            var transcript = DeviceSourceTranscript(Scope); var key = HMACSHA256.HashData(registration.Slice(88, 32), transcript);
            var storeId = SHA256.HashData(transcript);
            try
            {
                var marker = SHA256.HashData(storeId.Concat(Scope.Network.ToArray()).Concat(Scope.LocalAccount.ToArray()).ToArray());
                if (PublicRoots.GetValueOrDefault(DeviceStateMarkerSlot) is not { } installed || !Fixed(installed, marker))
                    throw new CryptographicException("Initial sender source has another actual installed marker.");
                using var state = DeviceInitialSessionCheckpoint.Decode(Checkpoint, storeId, Scope.LocalAccount, Scope.Network);
                var path = DeviceStatePath(AccountPath); RequireApplicationFileFamily(path);
                return SqliteDeviceStateStore.OpenMessagingSourceSegment(new SqliteDeviceStateStoreOptions(path, key,
                    DeviceAccountId32.FromBytes(Scope.LocalAccount), BinaryPrimitives.ReadUInt64BigEndian(Scope.Exact[84..]),
                    databaseGeneration: 1, DeviceOperationId32.FromBytes(storeId), allowCreate: false), readOnly);
            }
            finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(transcript); }
        }
        private SqlitePreKeyV2InventoryStore OpenReceiver(ReadOnlySpan<byte> registration, bool readOnly)
        {
            var identity = Current.Verified.PublicEvidence.Binding.Identity;
            var certificate = identity.ActiveDevices.Single().Certificate;
            var dpd = new byte[38]; "DPD1"u8.CopyTo(dpd); BinaryPrimitives.WriteUInt16BigEndian(dpd.AsSpan(4), 1);
            certificate.CanonicalHash.Span.CopyTo(dpd.AsSpan(6));
            var transcript = ReceiverSourceTranscript(Scope, dpd);
            var key = HMACSHA256.HashData(registration.Slice(88, 32), transcript); var sourceScope = SHA256.HashData(transcript);
            try
            {
                if (PublicRoots.GetValueOrDefault(PreKeyInstallMarkerSlot) is not { } installed || !Fixed(installed, sourceScope))
                    throw new CryptographicException("Initial receiver source has another actual installed marker.");
                var path = PreKeyStatePath(AccountPath); RequireApplicationFileFamily(path);
                return new(path, key, Scope.Network, Scope.LocalAccount, BinaryPrimitives.ReadUInt64BigEndian(Scope.Exact[84..]),
                    Scope.LocalDevice, Scope.LocalDeviceGeneration, dpd, certificate.DeviceEd25519PublicKey.Span,
                    allowCreate: false, successorCustody: Successors, connectionKey: null, readOnlySource: readOnly);
            }
            finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(transcript); }
        }
        private void RequireReceiverMarkers(SqlitePreKeyV2InventoryStore source)
        {
            var staged = source.ReadInitialPublicationHash();
            var installed = PublicRoots[PreKeyInstallMarkerSlot]!;
            var tip = PublicRoots.GetValueOrDefault(PreKeyInventoryMarkerSlot);
            var committed = PublicRoots.GetValueOrDefault(PreKeyCommitMarkerSlot);
            if (committed is not null)
            {
                var publication = source.ReadInitialPublication() ?? throw new CryptographicException("Committed receiver source lost its original inventory.");
                _ = DecodePreKeyCommitPairMarker(committed, installed, DeepIdV2PreKeyPublicationCodec.Decode(publication));
            }
            if (staged is null || tip is null || (Successors is null ?
                tip.Length != 64 || !Fixed(tip.AsSpan(0, 32), installed) || !Fixed(tip.AsSpan(32, 32), staged) : !Fixed(tip, Successors.Tip)))
                throw new CryptographicException("Initial receiver inventory differs from its actual protected pointer.");
        }
        public void Dispose()
        {
            Successors?.Dispose(); Successors = null;
            CryptographicOperations.ZeroMemory(Checkpoint);
            foreach (var value in PublicRoots.Values) if (value is not null) CryptographicOperations.ZeroMemory(value);
        }
    }

    private static byte[] DeviceSourceTranscript(Did2MessagingSessionScope scope)
    {
        ReadOnlySpan<byte> domain = "Deep/STORE-V2/device-state-key"u8;
        var transcript = new byte[domain.Length + 80]; domain.CopyTo(transcript);
        scope.Network.CopyTo(transcript.AsSpan(domain.Length)); scope.LocalAccount.CopyTo(transcript.AsSpan(domain.Length + 16));
        scope.Instance.CopyTo(transcript.AsSpan(domain.Length + 48)); return transcript;
    }
    private static byte[] ReceiverSourceTranscript(Did2MessagingSessionScope scope, ReadOnlySpan<byte> dpd)
    {
        ReadOnlySpan<byte> domain = "Deep/STORE-V2/prekey-state-key"u8;
        var transcript = new byte[domain.Length + 166]; var offset = domain.Length; domain.CopyTo(transcript);
        scope.Network.CopyTo(transcript.AsSpan(offset)); offset += 16; scope.LocalAccount.CopyTo(transcript.AsSpan(offset)); offset += 32;
        scope.Exact.Slice(84, 8).CopyTo(transcript.AsSpan(offset)); offset += 8; scope.LocalDevice.CopyTo(transcript.AsSpan(offset)); offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(offset), scope.LocalDeviceGeneration); offset += 8;
        dpd.CopyTo(transcript.AsSpan(offset)); offset += 38; scope.Instance.CopyTo(transcript.AsSpan(offset)); return transcript;
    }

    private static async Task<MessagingSourceObservation> CaptureMessagingSourceObservationAsync(IDeepSecureStorage storage,
        string accountPath, VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope,
        bool archiveEnrollment, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            var retirement = await (archiveEnrollment ?
                ProtectedInitialKeyRetirementJournal.ReadArchiveEnrollmentSourceSnapshotAsync(storage, scope.Network.ToArray(), scope.LocalAccount.ToArray(), ct) :
                ProtectedInitialKeyRetirementJournal.ReadSourceSnapshotAsync(storage, scope.Network.ToArray(), scope.LocalAccount.ToArray(), ct)).ConfigureAwait(false);
            var observation = new MessagingSourceObservation(accountPath, current, scope, retirement);
            try
            {
                string[] slots = scope.IsInitiator ? [DeviceStateMarkerSlot, DeviceInitialSessionCheckpoint.Slot] :
                    [PreKeyInstallMarkerSlot, PreKeyInventoryMarkerSlot, PreKeyCommitMarkerSlot, ResponderInitialSessionCheckpoint.Slot];
                using (var actual = await storage.ReadOwnedBatchAsync(slots, ct).ConfigureAwait(false))
                {
                    for (var index = 0; index < slots.Length; index++)
                    {
                        var raw = actual[index]; observation.Roots[slots[index]] = raw?.Use(bytes => SHA256.HashData(bytes));
                        if (slots[index] == observation.CheckpointSlot)
                        {
                            if (raw is null) throw new InvalidDataException("Initial messaging source checkpoint is absent.");
                            observation.CheckpointPhase = raw.Use(bytes => bytes.Length >= 2 && bytes[1] is 1 or 2 ? bytes[1] :
                                throw new InvalidDataException("Initial messaging source checkpoint has another phase."));
                            // A pending checkpoint contains private initial TRS.
                            // Retain only its phase/hash until the final recovery
                            // inventory; stable checkpoints contain public tips.
                            if (observation.CheckpointPhase == 1) observation.Checkpoint = raw.Use(bytes => bytes.ToArray());
                        }
                        else observation.PublicRoots[slots[index]] = raw?.Use(bytes => bytes.ToArray());
                    }
                }
                if (!scope.IsInitiator) await CaptureReceiverSourceCustodyAsync(storage, observation, ct).ConfigureAwait(false);
                if (observation.CheckpointPhase == 1) return observation;
                if (attempt != 0) throw new CryptographicException("Initial source remained pending after exact source recovery.");
                string[] readSlots = [KeySlot, observation.CheckpointSlot];
                byte[] registration = [], pending = [], stable = [];
                IReadOnlyList<SqlitePreKeyV2InventoryStore.SourceConsumption> consumption;
                try
                {
                    using (var actual = await storage.ReadOwnedGuardedBatchAsync(readSlots, observation.Roots, ct).ConfigureAwait(false))
                    {
                        registration = (actual[0] ?? throw new InvalidDataException("Source recovery lost its registration.")).Use(bytes => bytes.ToArray());
                        observation.Checkpoint = (actual[1] ??
                            throw new InvalidDataException("Source recovery lost its exact pending checkpoint.")).Use(bytes => bytes.ToArray());
                        actual.Dispose();
                        ct.ThrowIfCancellationRequested();
                        var recovered = observation.Recover(registration); stable = recovered.StableCheckpoint; consumption = recovered.Consumption;
                    }
                    CryptographicOperations.ZeroMemory(registration); registration = [];
                    var checkpointSlot = observation.CheckpointSlot;
                    var pendingHash = observation.Roots[checkpointSlot]!;
                    observation.Dispose();
                    await ApplyReceiverSourceConsumptionAsync(storage, consumption, CancellationToken.None).ConfigureAwait(false);
                    // Reacquire private expected bytes only for their one exact
                    // guarded write. No source key/handle or unrelated provider
                    // is retained across this CAS.
                    using (var currentPending = await storage.ReadOwnedAsync(checkpointSlot, CancellationToken.None).ConfigureAwait(false) ??
                        throw new InvalidDataException("Source stable publication lost its protected checkpoint."))
                    {
                        if (currentPending.Use(bytes => Fixed(bytes, stable))) continue;
                        if (!currentPending.Use(bytes => Fixed(SHA256.HashData(bytes), pendingHash)))
                            throw new CryptographicException("Initial source checkpoint changed before stable publication.");
                        pending = currentPending.Use(bytes => bytes.ToArray()); currentPending.Dispose();
                    }
                    bool applied;
                    try { applied = await storage.CompareExchangeAsync(checkpointSlot, pending, stable, CancellationToken.None).ConfigureAwait(false); }
                    finally { CryptographicOperations.ZeroMemory(pending); pending = []; }
                    if (!applied)
                    {
                        using var currentCheckpoint = await storage.ReadOwnedAsync(checkpointSlot, CancellationToken.None).ConfigureAwait(false);
                        if (currentCheckpoint?.Use(bytes => Fixed(bytes, stable)) != true)
                            throw new CryptographicException("Initial source checkpoint changed before stable publication.");
                    }
                }
                finally { CryptographicOperations.ZeroMemory(registration); CryptographicOperations.ZeroMemory(pending); CryptographicOperations.ZeroMemory(stable); }
            }
            catch { observation.Dispose(); throw; }
        }
    }

    private static async Task CaptureReceiverSourceCustodyAsync(IDeepSecureStorage storage, MessagingSourceObservation observation, CancellationToken ct)
    {
        var installed = observation.PublicRoots.GetValueOrDefault(PreKeyInstallMarkerSlot) ?? throw new InvalidDataException("Receiver source install marker is absent.");
        var tip = observation.PublicRoots.GetValueOrDefault(PreKeyInventoryMarkerSlot);
        var committed = observation.PublicRoots.GetValueOrDefault(PreKeyCommitMarkerSlot);
        if (committed is null) return;
        if (installed.Length != 32 || committed.Length != PreKeyCommitMarkerLength || !Fixed(committed.AsSpan(0, 32), installed) || tip is null)
            throw new CryptographicException("Receiver source commit anchor has another installed scope.");
        observation.Successors = await ProtectedPreKeyInventoryChain.ReadAsync(storage, installed, committed.AsMemory(32, 32), ct).ConfigureAwait(false);
        if (!Fixed(observation.Successors.Tip, tip)) throw new CryptographicException("Receiver source successor tip changed during capture.");
        observation.Roots[ProtectedPreKeyInventoryChain.TipSlot] = SHA256.HashData(tip);
        foreach (var entry in observation.Successors.Entries)
        {
            var exact = entry.CopyExact();
            try { observation.Roots[ProtectedPreKeyInventoryChain.EntrySlot(entry.PublicationHash)] = SHA256.HashData(exact); }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
        for (var offset = 0; offset < observation.Successors.Entries.Count; offset += 32)
        {
            var entries = observation.Successors.Entries.Skip(offset).Take(32).ToArray();
            var slots = entries.Select(entry => ProtectedPreKeyInventoryChain.CommitSlot(entry.PublicationHash)).ToArray();
            using var pairs = await storage.ReadOwnedBatchAsync(slots, ct).ConfigureAwait(false);
            for (var index = 0; index < entries.Length; index++)
            {
                var entry = entries[index]; var pair = pairs[index]; observation.Roots[slots[index]] = pair?.Use(bytes => SHA256.HashData(bytes));
                if (pair is null)
                {
                    if (offset + index != observation.Successors.Entries.Count - 1)
                        throw new InvalidDataException("Receiver source predecessor lost its protected replica pair.");
                    continue;
                }
                _ = pair.Use(bytes => DecodePreKeyCommitPairMarker(bytes, installed, DeepIdV2PreKeyPublicationCodec.Decode(entry.CopyPublication())));
            }
        }
    }

    private static async Task ApplyReceiverSourceConsumptionAsync(IDeepSecureStorage storage,
        IReadOnlyList<SqlitePreKeyV2InventoryStore.SourceConsumption> consumption, CancellationToken ct)
    {
        foreach (var item in consumption)
        {
            using var actual = await storage.ReadOwnedAsync(item.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Receiver source consumption lost its exact protected inventory.");
            byte[] expected = actual.Use(bytes => bytes.ToArray()), replacement = [];
            try
            {
                if (!Fixed(SHA256.HashData(expected), item.ExpectedHash)) throw new CryptographicException("Receiver source consumption inventory changed after SQL verification.");
                using var entry = ProtectedPreKeyInventoryChain.Entry.Decode(expected, expected.AsSpan(4, 32), expected.AsSpan(68, 32));
                using var consumed = entry.WithoutSecrets(item.Indices.ToHashSet()); replacement = consumed.CopyExact(); actual.Dispose();
                if (!await storage.CompareExchangeAsync(item.Slot, expected, replacement, ct).ConfigureAwait(false))
                    throw new CryptographicException("Receiver source consumption lost its exact protected predecessor.");
            }
            finally { CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(replacement); }
        }
    }
}
