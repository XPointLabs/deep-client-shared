using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    // Local guard facts from the actual registered database and its protected
    // markers, not a current network authority or a caller-supplied capsule.
    // The existing committed DNH2 floor is the durable exclusion fence; do not
    // duplicate its lifetime/rollback custody in another journal.
    internal static async Task<Did2CompactionPlan.RootReadback> ReadNativeReplayFenceUnderLeaseAsync(
        IDeepSecureStorage storage, DeepIdV2AccountFileLease accountLease, string statePath,
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(accountLease);
        using var secret = await storage.ReadOwnedAsync(KeySlot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Native replay fence lost account registration.");
        var record = secret.Use(value => value.ToArray());
        try
        {
            var network = current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.NetworkId;
            ValidateRecord(record, network.Span, current.AccountId.Span);
            var binding = AccountBinding.From(current.Verified, current.AccountId.Span, network.Span,
                current.DisplayName, current.PermanentId.CanonicalText, record.AsSpan(56, 32));
            using var connection = await OpenBoundLkgConnectionAsync(storage, Path.GetFullPath(statePath), binding, ct).ConfigureAwait(false);
            return await ReadNativeReplayFenceInConnectionAsync(storage, accountLease, statePath, connection, binding, held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(record); }
    }

    private static async Task<Did2CompactionPlan.RootReadback> ReadNativeReplayFenceInConnectionAsync(
        IDeepSecureStorage storage, DeepIdV2AccountFileLease accountLease, string statePath,
        SqliteConnection connection, AccountBinding binding, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        byte[] genesis = [];
        try
        {
            using var tx = connection.BeginTransaction(deferred: false);
            var actualBinding = ReadNativeFenceBinding(connection, tx);
            var bindingHash = NativeFenceBindingHash(binding);
            if (!Fixed(bindingHash, NativeFenceBindingHash(actualBinding)))
                throw new CryptographicException("Native replay fence changed its exact local account binding.");
            using (var command = connection.CreateCommand())
            {
                command.Transaction = tx;
                // Only bounded genesis bytes are read before the complete
                // existing row/marker/anchor verifier authenticates this pin.
                command.CommandText = "SELECT length(payload),typeof(payload),revision,substr(payload,9,32),typeof(revision) FROM protected_lkg_root WHERE root_kind=3;";
                using var reader = command.ExecuteReader();
                if (!reader.Read() || reader.GetString(4) != "integer" || reader.GetString(1) != "blob" ||
                    reader.GetInt64(0) != 305 || reader.GetInt64(2) < 1)
                    throw new InvalidDataException("Native replay fence requires an initialized exact network floor.");
                genesis = reader.GetFieldValue<byte[]>(3);
                if (genesis.Length != 32 || genesis.AsSpan().IndexOfAnyExcept((byte)0) < 0 || reader.Read())
                    throw new InvalidDataException("Native replay fence has an ambiguous network pin.");
            }
            var backend = new NetworkLkgStore(storage, accountLease, Path.GetFullPath(statePath), binding, genesis);
            var snapshot = await backend.ReadExistingHistoryInTransactionAsync(connection, tx, ct).ConfigureAwait(false);
            if (snapshot.Snapshot.ForkLatched) throw new CryptographicException("A fork-latched floor cannot guard retirement.");
            var scope = new byte[80]; binding.NetworkId.CopyTo(scope, 0); binding.AccountId.CopyTo(scope, 16);
            binding.InstanceId.CopyTo(scope, 48);
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var floor = XPointNetworkProtectedLkgCodec.Encode(snapshot.Snapshot.ProtectedLkg);
            var history = snapshot.ExactHistory.ToArray();
            try
            {
                Span<byte> revision = stackalloc byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(revision, snapshot.Snapshot.Revision);
                digest.AppendData(bindingHash); digest.AppendData(revision); digest.AppendData(floor); digest.AppendData(history);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(accountLease); tx.Commit();
                return new(Did2CompactionPlan.RootKind.NativeFence, SHA256.HashData(scope), digest.GetHashAndReset());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(scope); CryptographicOperations.ZeroMemory(floor);
                CryptographicOperations.ZeroMemory(history);
            }
        }
        finally { CryptographicOperations.ZeroMemory(genesis); }
    }

    internal static async ValueTask<IXPointNetworkStateStore> OpenNetworkLkgStoreAsync(
        IDeepSecureStorage storage, DeepIdV2AccountFileLease accountLease,
        string statePath, VerifiedDeepIdV2CurrentAccount current,
        XPointNetworkGenesisPin genesisPin, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(genesisPin);
        var network = current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.NetworkId;
        if (!Fixed(network.Span, genesisPin.NetworkId.Span))
            throw new CryptographicException("The DID2 network floor has another pinned network.");
        using var secret = await storage.ReadOwnedAsync(KeySlot, cancellationToken)
            .ConfigureAwait(false) ?? throw new InvalidDataException("The DID2 SQL key record is absent.");
        var record = secret.Use(static value => value.ToArray());
        try
        {
            ValidateRecord(record, network.Span, current.AccountId.Span);
            var binding = AccountBinding.From(current.Verified, current.AccountId.Span,
                network.Span, current.DisplayName, current.PermanentId.CanonicalText,
                record.AsSpan(56, 32));
            var store = new NetworkLkgStore(storage, accountLease, Path.GetFullPath(statePath),
                binding, genesisPin.AuthorityCoreHash.ToArray());
            // The caller already holds the account lease. Opening validates
            // custody immediately, without recursively acquiring that lease.
            _ = await store.ReadUnderLeaseAsync(cancellationToken).ConfigureAwait(false);
            return store;
        }
        finally { CryptographicOperations.ZeroMemory(record); }
    }

    private static async ValueTask<SqliteConnection> OpenBoundLkgConnectionAsync(
        IDeepSecureStorage storage, string path, AccountBinding binding,
        CancellationToken cancellationToken)
    {
        using var secret = await storage.ReadOwnedAsync(KeySlot, cancellationToken)
            .ConfigureAwait(false) ?? throw new InvalidDataException("The DID2 SQL key record is absent.");
        var record = secret.Use(static value => value.ToArray());
        try
        {
            ValidateRecord(record, binding.NetworkId, binding.AccountId);
            if (!Fixed(record.AsSpan(56, 32), binding.InstanceId))
                throw new InvalidDataException("The DID2 SQL instance changed after LKG-store opening.");
            if (new FileInfo(path).Length == 0)
                throw new InvalidDataException("The DID2 SQL database is empty.");
            var connection = OpenConnection(path, record.AsSpan(88, 32), create: false);
            try
            {
                // Verify and consume one actual connection, rather than opening
                // a separate password-keyed connection solely for validation.
                // All integrity/schema/account/device/instance checks remain.
                ValidateDatabaseConnection(connection, binding);
                using var durable = connection.CreateCommand();
                durable.CommandText = "PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON;";
                durable.ExecuteNonQuery();
                return connection;
            }
            catch { connection.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(record); }
    }

    // This is protected local state, not network evidence. Only the verified
    // account-owned verified-history method may advance trust; the store enforces custody,
    // exact CAS, monotonic revisions and an irreversible fork latch.
    private sealed class NetworkLkgStore(IDeepSecureStorage storage,
        DeepIdV2AccountFileLease accountLease, string path, AccountBinding binding,
        byte[] genesisAuthorityHash) : IXPointNetworkStateStore, IDeepIdV2NetworkHistoryStore, IDeepIdV2NetworkHistoryLeaseRead
    {
        private const int RootKind = 3;
        private const int PayloadBytes = 305; // header8 | genesis32 | XLK1(265)
        private const int HistoryRootKind = 7;
        private const int HistoryHeaderBytes = 68;
        private const int MinimumHistoryBytes = 16 + 225 + 2;
        private const int MaximumHistoryBytes = 16 + 225 + 2 * 65_535;
        private readonly string markerPrefix = "deep.store.v2." +
            Convert.ToHexStringLower(SHA256.HashData(
            binding.NetworkId.Concat(binding.AccountId).ToArray())) + ".network-lkg-floor.";

        public void RequireAccountScope(ReadOnlyMemory<byte> accountId)
        {
            if (!Fixed(accountId.Span, binding.AccountId))
                throw new CryptographicException("The DID2 network history belongs to another account.");
        }

        public async ValueTask<XPointNetworkStateSnapshot?> ReadAsync(CancellationToken cancellationToken)
        {
            using var held = await accountLease.AcquireAsync(cancellationToken).ConfigureAwait(false);
            return await ReadUnderLeaseAsync(cancellationToken).ConfigureAwait(false);
        }

        internal async ValueTask<XPointNetworkStateSnapshot?> ReadUnderLeaseAsync(CancellationToken cancellationToken)
        {
            using var connection = await OpenBoundLkgConnectionAsync(storage, path, binding,
                cancellationToken).ConfigureAwait(false);
            using var transaction = connection.BeginTransaction(deferred: false);
            var row = ReadRow(connection, transaction);
            await CheckMarkersAsync(row, cancellationToken).ConfigureAwait(false);
            transaction.Commit();
            return row?.Snapshot;
        }

        public async ValueTask<DeepIdV2NetworkHistorySnapshot?> ReadHistoryAsync(CancellationToken cancellationToken)
        {
            using var held = await accountLease.AcquireAsync(cancellationToken).ConfigureAwait(false);
            return await ReadHistoryUnderLeaseAsync(held, cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask<DeepIdV2NetworkHistorySnapshot?> ReadHistoryUnderLeaseAsync(HeldDeepIdV2AccountLease held, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(held);
            using var borrow = held.BorrowFor(accountLease);
            using var connection = await OpenBoundLkgConnectionAsync(storage, path, binding,
                cancellationToken).ConfigureAwait(false);
            using var transaction = connection.BeginTransaction(deferred: false);
            var row = ReadRow(connection, transaction);
            await CheckMarkersAsync(row, cancellationToken).ConfigureAwait(false);
            transaction.Commit();
            held.RequireOwner(accountLease);
            return row is null ? null : new(row.Snapshot, row.ExactHistory);
        }

        public async ValueTask<XPointNetworkAdvanceResult> ApplyVerifiedHistoryAsync(
            DeepIdV2NetworkHistorySnapshot? expected, VerifiedOnionNetworkContext verified,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(verified);
            verified.EnsureCurrent();
            var next = verified.ProtectedLkg ?? throw new CryptographicException("Complete network custody is required.");
            if (!Fixed(next.NetworkId.Span, binding.NetworkId))
                throw new CryptographicException("The verified DID2 network is out of scope.");
            var history = OnionNetworkProtectedHistoryCodec.Encode(verified);
            using var held = await accountLease.AcquireAsync(cancellationToken).ConfigureAwait(false);
            using var connection = await OpenBoundLkgConnectionAsync(storage, path, binding,
                cancellationToken).ConfigureAwait(false);
            using var transaction = connection.BeginTransaction(deferred: false);
            var row = ReadRow(connection, transaction);
            await CheckMarkersAsync(row, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            verified.EnsureCurrent();
            if (row?.Snapshot.Revision != expected?.Snapshot.Revision ||
                row is not null && !Fixed(row.ExactHistory, expected!.ExactHistory.Span))
                throw new IOException("The exact DID2 network predecessor changed before CAS.");
            if (row?.Snapshot.ForkLatched == true)
                return new(XPointNetworkAdvanceDisposition.ForkLatched, row.Snapshot);
            if (row is null)
            {
                if (verified.PriorProtectedLkg is not null)
                    throw new CryptographicException("A successor cannot initialize empty DID2 network custody.");
            }
            else
            {
                if (verified.PriorProtectedLkg is null ||
                    !SameFloor(row.Snapshot.ProtectedLkg, verified.PriorProtectedLkg) ||
                    !OnionNetworkProtectedHistoryCodec.BindsPredecessor(verified, row.ExactHistory))
                    throw new CryptographicException("The complete verified predecessor differs from DID2 custody.");
                if (SameFloor(next, row.Snapshot.ProtectedLkg))
                {
                    if (!Fixed(history, row.ExactHistory))
                        throw new CryptographicException("The unchanged DID2 floor has different policy or PMT history.");
                    verified.EnsureCurrent();
                    return new(XPointNetworkAdvanceDisposition.Idempotent, row.Snapshot);
                }
                if (next.ViewGeneration <= row.Snapshot.ProtectedLkg.ViewGeneration ||
                    next.HeadTreeSize <= row.Snapshot.ProtectedLkg.HeadTreeSize)
                    throw new CryptographicException("The complete DID2 network advance is not monotonic.");
            }
            var replacement = new XPointNetworkStateSnapshot(
                row is null ? 1 : checked(row.Snapshot.Revision + 1), next, false);
            await CommitAsync(connection, transaction, row, replacement, history,
                verified, cancellationToken).ConfigureAwait(false);
            return new(XPointNetworkAdvanceDisposition.Applied, replacement);
        }

        public async ValueTask<XPointNetworkStoreWriteResult> CompareExchangeAsync(
            ulong? expectedRevision, XPointNetworkStateSnapshot replacement,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(replacement);
            if (replacement.Revision > long.MaxValue ||
                !Fixed(replacement.ProtectedLkg.NetworkId.Span, binding.NetworkId))
                throw new CryptographicException("The DID2 network replacement is out of scope.");
            using var held = await accountLease.AcquireAsync(cancellationToken).ConfigureAwait(false);
            using var connection = await OpenBoundLkgConnectionAsync(storage, path, binding,
                cancellationToken).ConfigureAwait(false);
            using var transaction = connection.BeginTransaction(deferred: false);
            var row = ReadRow(connection, transaction);
            await CheckMarkersAsync(row, cancellationToken).ConfigureAwait(false);
            var current = row?.Snapshot;
            if (current?.Revision != expectedRevision)
                return new(XPointNetworkStoreWriteDisposition.Conflict, current);
            if (replacement.Revision != (expectedRevision is null ? 1UL : checked(expectedRevision.Value + 1)))
                throw new InvalidOperationException("The DID2 network replacement must be the next CAS revision.");
            if (current is null || !SameFloor(replacement.ProtectedLkg, current.ProtectedLkg))
                throw new CryptographicException("Raw LKG CAS cannot initialize or advance DID2 network history.");
            if (current.ForkLatched && !replacement.ForkLatched)
                throw new CryptographicException("The protected DID2 network fork latch cannot be cleared.");
            await CommitAsync(connection, transaction, row, replacement, row!.ExactHistory,
                null, cancellationToken).ConfigureAwait(false);
            return new(XPointNetworkStoreWriteDisposition.Applied,
                new(replacement.Revision, replacement.ProtectedLkg, replacement.ForkLatched));
        }

        private async ValueTask CommitAsync(SqliteConnection connection, SqliteTransaction transaction,
            Row? row, XPointNetworkStateSnapshot replacement, byte[] history,
            VerifiedOnionNetworkContext? verified, CancellationToken cancellationToken)
        {
            var payload = Encode(replacement);
            var revision = checked((long)replacement.Revision);
            var marker = Marker(revision, payload);
            var envelope = HistoryEnvelope(revision, history, anchor: false);
            var anchor = HistoryEnvelope(revision, history, anchor: true);
            // SecureStorage precedes SQL, so a crash cannot silently roll the
            // account back to an older valid SQL backup or an empty floor.
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                verified?.EnsureCurrent();
                await storage.WriteBatchAsync([new DeepSecureStorageWrite(MarkerSlot(revision), marker),
                    new DeepSecureStorageWrite(HistoryAnchorSlot(revision), anchor)],
                    cancellationToken).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(marker); CryptographicOperations.ZeroMemory(anchor); }
            using var write = connection.CreateCommand();
            write.Transaction = transaction;
            write.CommandText = row is null
                ? "INSERT INTO protected_lkg_root(root_kind,revision,payload) VALUES($kind,$next,$payload);"
                : "UPDATE protected_lkg_root SET revision=$next,payload=$payload WHERE root_kind=$kind AND revision=$prior AND payload=$expected;";
            write.Parameters.AddWithValue("$kind", RootKind);
            write.Parameters.AddWithValue("$next", revision);
            write.Parameters.AddWithValue("$payload", payload);
            if (row is not null)
            {
                write.Parameters.AddWithValue("$prior", checked((long)row.Snapshot.Revision));
                write.Parameters.AddWithValue("$expected", row.Payload);
            }
            if (write.ExecuteNonQuery() != 1)
                throw new CryptographicException("The protected DID2 network CAS did not commit.");
            using var historyWrite = connection.CreateCommand();
            historyWrite.Transaction = transaction;
            historyWrite.CommandText = row is null
                ? "INSERT INTO protected_lkg_root(root_kind,revision,payload) VALUES($kind,$next,$payload);"
                : "UPDATE protected_lkg_root SET revision=$next,payload=$payload WHERE root_kind=$kind AND revision=$prior AND payload=$expected;";
            historyWrite.Parameters.AddWithValue("$kind", HistoryRootKind);
            historyWrite.Parameters.AddWithValue("$next", revision);
            historyWrite.Parameters.AddWithValue("$payload", envelope);
            if (row is not null)
            {
                historyWrite.Parameters.AddWithValue("$prior", checked((long)row.Snapshot.Revision));
                historyWrite.Parameters.AddWithValue("$expected", row.HistoryEnvelope);
            }
            if (historyWrite.ExecuteNonQuery() != 1)
                throw new CryptographicException("The protected DID2 full-history CAS did not commit.");
            transaction.Commit();
            using var recheck = connection.BeginTransaction(deferred: false);
            var durable = ReadRow(connection, recheck);
            await CheckMarkersAsync(durable, cancellationToken).ConfigureAwait(false);
            if (durable is null || durable.Snapshot.Revision != replacement.Revision ||
                !Fixed(durable.Payload, payload) || !Fixed(durable.HistoryEnvelope, envelope))
                throw new CryptographicException("The complete DID2 network custody did not durably reread.");
            recheck.Commit();
            verified?.EnsureCurrent();
        }

        private sealed record ProjectionRow(XPointNetworkStateSnapshot Snapshot, byte[] Payload);
        private sealed record Row(XPointNetworkStateSnapshot Snapshot, byte[] Payload,
            byte[] HistoryEnvelope, byte[] ExactHistory);
        internal async ValueTask<DeepIdV2NetworkHistorySnapshot> ReadExistingHistoryInTransactionAsync(
            SqliteConnection connection, SqliteTransaction transaction, CancellationToken ct)
        {
            var row = ReadRow(connection, transaction) ??
                throw new InvalidDataException("Native replay fence cannot initialize missing network history.");
            await CheckMarkersAsync(row, ct).ConfigureAwait(false);
            return new(row.Snapshot, row.ExactHistory);
        }
        private ProjectionRow? ReadProjectionRow(SqliteConnection connection, SqliteTransaction transaction)
        {
            using var read = connection.CreateCommand();
            read.Transaction = transaction;
            read.CommandText = "SELECT revision,length(payload),payload,typeof(revision),typeof(payload) FROM protected_lkg_root WHERE root_kind=$kind;";
            read.Parameters.AddWithValue("$kind", RootKind);
            using var reader = read.ExecuteReader();
            if (!reader.Read()) return null;
            if (reader.GetString(3) != "integer" || reader.GetString(4) != "blob")
                throw new InvalidDataException("The protected DID2 network row has noncanonical scalar types.");
            var revision = reader.GetInt64(0);
            if (revision < 1 || reader.GetInt64(1) != PayloadBytes)
                throw new InvalidDataException("The protected DID2 network row is malformed.");
            var payload = reader.GetFieldValue<byte[]>(2);
            if (!payload.AsSpan(0, 4).SequenceEqual("NLK2"u8) || payload[4] != 2 ||
                payload[5] > 1 || payload[6] != 0 || payload[7] != 0 || reader.Read())
                throw new InvalidDataException("The protected DID2 network payload is malformed.");
            if (!Fixed(payload.AsSpan(8, 32), genesisAuthorityHash))
                throw new CryptographicException("The protected DID2 network genesis pin changed.");
            var floor = XPointNetworkProtectedLkgCodec.Decode(payload.AsSpan(40));
            if (!Fixed(floor.NetworkId.Span, binding.NetworkId))
                throw new CryptographicException("The protected DID2 network row is out of scope.");
            return new(new(checked((ulong)revision), floor, payload[5] == 1), payload);
        }

        private Row? ReadRow(SqliteConnection connection, SqliteTransaction transaction)
        {
            var projection = ReadProjectionRow(connection, transaction);
            using var read = connection.CreateCommand();
            read.Transaction = transaction;
            read.CommandText = "SELECT revision,length(payload),payload,typeof(revision),typeof(payload) FROM protected_lkg_root WHERE root_kind=$kind;";
            read.Parameters.AddWithValue("$kind", HistoryRootKind);
            using var reader = read.ExecuteReader();
            if (!reader.Read())
            {
                if (projection is not null)
                    throw new InvalidDataException("Initialized DID2 custody requires complete network history; no migration is available.");
                return null;
            }
            if (reader.GetString(3) != "integer" || reader.GetString(4) != "blob" ||
                projection is null || reader.GetInt64(0) != checked((long)projection.Snapshot.Revision) ||
                reader.GetInt64(1) is < HistoryHeaderBytes + MinimumHistoryBytes or > HistoryHeaderBytes + MaximumHistoryBytes)
                throw new InvalidDataException("The protected DID2 network history is split or oversized.");
            var envelope = reader.GetFieldValue<byte[]>(2);
            var history = envelope.AsSpan(HistoryHeaderBytes).ToArray();
            var expected = HistoryEnvelope(checked((long)projection.Snapshot.Revision), history, anchor: false);
            if (!Fixed(envelope, expected) || reader.Read())
                throw new InvalidDataException("The protected DID2 network history envelope is malformed.");
            return new(projection.Snapshot, projection.Payload, envelope, history);
        }

        private async ValueTask CheckMarkersAsync(Row? row, CancellationToken cancellationToken)
        {
            var revision = row is null ? 1L : checked((long)row.Snapshot.Revision);
            using var marker = await storage.ReadOwnedAsync(MarkerSlot(revision), cancellationToken).ConfigureAwait(false);
            using var historyAnchor = await storage.ReadOwnedAsync(HistoryAnchorSlot(revision), cancellationToken).ConfigureAwait(false);
            if (row is null && (marker is not null || historyAnchor is not null))
                throw new CryptographicException("The protected DID2 network floor disappeared after initialization.");
            if (row is not null)
            {
                var expected = Marker(revision, row.Payload);
                try
                {
                    if (marker is null || marker.Length != expected.Length || !marker.Use(value => Fixed(value, expected)))
                        throw new CryptographicException("The protected DID2 network marker is absent or mismatched.");
                }
                finally { CryptographicOperations.ZeroMemory(expected); }
                var expectedAnchor = HistoryEnvelope(revision, row.ExactHistory, anchor: true);
                try
                {
                    if (historyAnchor is null || historyAnchor.Length != expectedAnchor.Length ||
                        !historyAnchor.Use(value => Fixed(value, expectedAnchor)))
                        throw new CryptographicException("The protected DID2 full-history anchor is absent or mismatched.");
                }
                finally { CryptographicOperations.ZeroMemory(expectedAnchor); }
            }
            if (revision < long.MaxValue)
            {
                using var future = await storage.ReadOwnedAsync(MarkerSlot(revision + 1), cancellationToken).ConfigureAwait(false);
                using var futureHistory = await storage.ReadOwnedAsync(HistoryAnchorSlot(revision + 1), cancellationToken).ConfigureAwait(false);
                if (future is not null || futureHistory is not null)
                    throw new CryptographicException("The protected DID2 network SQL floor is behind its marker.");
            }
        }

        private byte[] Encode(XPointNetworkStateSnapshot snapshot)
        {
            var payload = new byte[PayloadBytes];
            "NLK2"u8.CopyTo(payload);
            payload[4] = 2;
            payload[5] = snapshot.ForkLatched ? (byte)1 : (byte)0;
            genesisAuthorityHash.CopyTo(payload, 8);
            XPointNetworkProtectedLkgCodec.Encode(snapshot.ProtectedLkg).CopyTo(payload, 40);
            return payload;
        }

        private byte[] Marker(long revision, byte[] payload)
        {
            var marker = new byte[156];
            "NLG2"u8.CopyTo(marker);
            binding.NetworkId.CopyTo(marker, 4);
            binding.AccountId.CopyTo(marker, 20);
            binding.InstanceId.CopyTo(marker, 52);
            genesisAuthorityHash.CopyTo(marker, 84);
            BinaryPrimitives.WriteInt64BigEndian(marker.AsSpan(116, 8), revision);
            SHA256.HashData(payload).CopyTo(marker, 124);
            return marker;
        }

        private string MarkerSlot(long revision) => markerPrefix +
            revision.ToString(System.Globalization.CultureInfo.InvariantCulture);

        private string HistoryAnchorSlot(long revision) => markerPrefix + "history." +
            Convert.ToHexStringLower(genesisAuthorityHash) + "." +
            revision.ToString(System.Globalization.CultureInfo.InvariantCulture);

        private byte[] HistoryEnvelope(long revision, byte[] history, bool anchor)
        {
            if (revision < 1 || history.Length is < MinimumHistoryBytes or > MaximumHistoryBytes)
                throw new InvalidDataException("The DID2 history envelope is outside its bounds.");
            var value = new byte[HistoryHeaderBytes + (anchor ? 0 : history.Length)];
            "DNF2"u8.CopyTo(value);
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 2);
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(6), anchor ? (ushort)1 : (ushort)0);
            BinaryPrimitives.WriteInt64BigEndian(value.AsSpan(8), revision);
            binding.InstanceId.AsSpan(0, 16).CopyTo(value.AsSpan(16));
            SHA256.HashData(history).CopyTo(value, 32);
            // Both kinds retain the same authenticated history length; only
            // the floor carries the bytes, matching the existing host DNF2.
            BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(64), checked((uint)history.Length));
            if (!anchor) history.CopyTo(value, HistoryHeaderBytes);
            return value;
        }

        private static bool SameFloor(XPointNetworkProtectedLkg left, XPointNetworkProtectedLkg right) =>
            Fixed(XPointNetworkProtectedLkgCodec.Encode(left), XPointNetworkProtectedLkgCodec.Encode(right));
    }
}
