using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
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
            ValidateDatabase(path, record.AsSpan(88, 32), binding);
            var connection = OpenConnection(path, record.AsSpan(88, 32), create: false);
            try
            {
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
    // XPointNetworkStateClient may advance trust; the store enforces custody,
    // exact CAS, monotonic revisions and an irreversible fork latch.
    private sealed class NetworkLkgStore(IDeepSecureStorage storage,
        DeepIdV2AccountFileLease accountLease, string path, AccountBinding binding,
        byte[] genesisAuthorityHash) : IXPointNetworkStateStore
    {
        private const int RootKind = 3;
        private const int PayloadBytes = 305; // header8 | genesis32 | XLK1(265)
        private readonly string markerPrefix = "deep.store.v2." +
            Convert.ToHexStringLower(SHA256.HashData(
                binding.NetworkId.Concat(binding.AccountId).ToArray())) + ".network-lkg-floor.";

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
            if (current is not null)
            {
                if (current.ForkLatched && !replacement.ForkLatched)
                    throw new CryptographicException("The protected DID2 network fork latch cannot be cleared.");
                var prior = current.ProtectedLkg;
                var next = replacement.ProtectedLkg;
                if (next.ViewGeneration < prior.ViewGeneration || next.HeadTreeSize < prior.HeadTreeSize ||
                    prior.LastForwardCheckpointGeneration.HasValue &&
                    (!next.LastForwardCheckpointGeneration.HasValue ||
                     next.LastForwardCheckpointGeneration < prior.LastForwardCheckpointGeneration) ||
                    next.ViewGeneration == prior.ViewGeneration &&
                    !Fixed(XPointNetworkProtectedLkgCodec.Encode(next), XPointNetworkProtectedLkgCodec.Encode(prior)))
                    throw new CryptographicException("The DID2 network floor rolls back or conflicts at the same generation.");
            }
            var payload = Encode(replacement);
            var revision = checked((long)replacement.Revision);
            var marker = Marker(revision, payload);
            // SecureStorage precedes SQL, so a crash cannot silently roll the
            // account back to an older valid SQL backup or an empty floor.
            try
            {
                await storage.WriteBatchAsync([new DeepSecureStorageWrite(MarkerSlot(revision), marker)],
                    cancellationToken).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(marker); }
            using var write = connection.CreateCommand();
            write.Transaction = transaction;
            write.CommandText = current is null
                ? "INSERT INTO protected_lkg_root(root_kind,revision,payload) VALUES($kind,$next,$payload);"
                : "UPDATE protected_lkg_root SET revision=$next,payload=$payload WHERE root_kind=$kind AND revision=$prior AND payload=$expected;";
            write.Parameters.AddWithValue("$kind", RootKind);
            write.Parameters.AddWithValue("$next", revision);
            write.Parameters.AddWithValue("$payload", payload);
            if (row is not null)
            {
                write.Parameters.AddWithValue("$prior", checked((long)current!.Revision));
                write.Parameters.AddWithValue("$expected", row.Payload);
            }
            if (write.ExecuteNonQuery() != 1)
                throw new CryptographicException("The protected DID2 network CAS did not commit.");
            transaction.Commit();
            return new(XPointNetworkStoreWriteDisposition.Applied,
                new(replacement.Revision, replacement.ProtectedLkg, replacement.ForkLatched));
        }

        private sealed record Row(XPointNetworkStateSnapshot Snapshot, byte[] Payload);
        private Row? ReadRow(SqliteConnection connection, SqliteTransaction transaction)
        {
            using var read = connection.CreateCommand();
            read.Transaction = transaction;
            read.CommandText = "SELECT revision,length(payload),payload FROM protected_lkg_root WHERE root_kind=$kind;";
            read.Parameters.AddWithValue("$kind", RootKind);
            using var reader = read.ExecuteReader();
            if (!reader.Read()) return null;
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

        private async ValueTask CheckMarkersAsync(Row? row, CancellationToken cancellationToken)
        {
            var revision = row is null ? 1L : checked((long)row.Snapshot.Revision);
            using var marker = await storage.ReadOwnedAsync(MarkerSlot(revision), cancellationToken).ConfigureAwait(false);
            if (row is null && marker is not null)
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
            }
            if (revision < long.MaxValue)
            {
                using var future = await storage.ReadOwnedAsync(MarkerSlot(revision + 1), cancellationToken).ConfigureAwait(false);
                if (future is not null)
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
    }
}
