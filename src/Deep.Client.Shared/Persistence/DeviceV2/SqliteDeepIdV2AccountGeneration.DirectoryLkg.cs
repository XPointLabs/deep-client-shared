using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal static async ValueTask<IDeepIdV2DirectoryProtectedLkgStore>
        OpenDirectoryLkgStoreAsync(IDeepSecureStorage storage,
            DeepIdV2AccountFileLease accountLease, string statePath,
            VerifiedDeepIdV2CurrentAccount current,
            VerifiedXPointNetworkAuthority authority,
            ReadOnlyMemory<byte> exactGenesisAdh1,
            ReadOnlyMemory<byte> protectedGenesisCoreHash,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(accountLease);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(authority);
        var genesis = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
            authority, exactGenesisAdh1, protectedGenesisCoreHash.Span);
        var network = current.Verified.PublicEvidence.Binding.Identity.Account
            .Certificate.NetworkId;
        if (!Fixed(network.Span, authority.NetworkId.Span))
            throw new CryptographicException(
                "The signed DID2 directory genesis belongs to another account network.");
        var path = Path.GetFullPath(statePath);
        using var secret = await storage.ReadOwnedAsync(KeySlot,
            cancellationToken).ConfigureAwait(false) ??
            throw new InvalidDataException("The DID2 SQL key record is absent.");
        var record = secret.Use(static value => value.ToArray());
        try
        {
            ValidateRecord(record, network.Span, current.AccountId.Span);
            var binding = AccountBinding.From(current.Verified,
                current.AccountId.Span, network.Span, current.DisplayName,
                record.AsSpan(56, 32));
            ValidateDatabase(path, record.AsSpan(88, 32), binding);
            return new DirectoryLkgStore(storage, accountLease, path,
                binding, genesis);
        }
        finally { CryptographicOperations.ZeroMemory(record); }
    }

    private sealed class DirectoryLkgStore(
        IDeepSecureStorage storage, DeepIdV2AccountFileLease accountLease,
        string path, AccountBinding binding, AccountDirectoryProtectedLkg genesis)
        : IDeepIdV2DirectoryProtectedLkgStore
    {
        private const int DirectoryRootKind = 2;
        private readonly string markerPrefix = "deep.store.v2." +
            Convert.ToHexStringLower(SHA256.HashData(
                binding.NetworkId.Concat(binding.AccountId).ToArray())) +
            ".directory-lkg-floor.";

        public async ValueTask<AccountDirectoryProtectedLkg> RestoreAsync(
            VerifiedXPointNetworkAuthority authority,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(authority);
            if (!Fixed(authority.NetworkId.Span, binding.NetworkId))
                throw new CryptographicException(
                    "The DID2 directory authority belongs to another network.");
            using var held = await accountLease.AcquireAsync(cancellationToken)
                .ConfigureAwait(false);
            using var connection = await OpenVerifiedAsync(cancellationToken)
                .ConfigureAwait(false);
            using var transaction = connection.BeginTransaction(deferred: false);
            var row = ReadRow(connection, transaction);
            var marked = await MarkerMatchesTipAsync(null, 1, cancellationToken)
                .ConfigureAwait(false);
            if (row is null)
            {
                if (marked)
                    throw new CryptographicException(
                        "The protected DID2 directory floor disappeared after provisioning.");
                // The signed empty V2 head is the sole allowed initial floor.
                _ = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
                    authority, genesis.ExactAdh1, genesis.CoreHash.Span);
                // Secure marker first: a crash before the SQL commit must
                // fail closed, never silently restart at genesis.
                var marker = Marker(genesis, 1);
                try
                {
                    await storage.WriteBatchAsync(
                        [new DeepSecureStorageWrite(MarkerSlot(1), marker)],
                        cancellationToken).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(marker); }
                using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = "INSERT INTO protected_lkg_root(root_kind,revision,payload) VALUES($kind,1,$head);";
                insert.Parameters.AddWithValue("$kind", DirectoryRootKind);
                insert.Parameters.AddWithValue("$head", EncodeHead(genesis));
                if (insert.ExecuteNonQuery() != 1)
                    throw new IOException("The DID2 directory genesis floor was not durable.");
                transaction.Commit();
                return genesis;
            }
            var restored = RestoreRow(row.Value, authority);
            if (!await MarkerMatchesTipAsync(restored, row.Value.Revision,
                    cancellationToken).ConfigureAwait(false))
                throw new CryptographicException(
                    "The protected DID2 directory floor marker is absent.");
            transaction.Commit();
            return restored;
        }

        public async ValueTask CommitVerifiedAsync(
            AccountDirectoryProtectedLkg expectedHead,
            VerifiedDeepIdV2DirectoryFreshness verified,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(expectedHead);
            ArgumentNullException.ThrowIfNull(verified);
            var next = verified.NextProtectedLkg;
            if (!Fixed(verified.NetworkId.Span, binding.NetworkId) ||
                !Fixed(next.Head.NetworkId.Span, binding.NetworkId) ||
                !Fixed(verified.ExactAdh1.Span, next.ExactAdh1.Span))
                throw new CryptographicException(
                    "The verified DID2 directory head is out of scope.");
            await CommitAuthenticatedHeadAsync(expectedHead, next,
                cancellationToken).ConfigureAwait(false);
        }

        internal async ValueTask CommitAuthenticatedHeadAsync(
            AccountDirectoryProtectedLkg expectedHead,
            AccountDirectoryProtectedLkg next,
            CancellationToken cancellationToken)
        {
            if (!Fixed(next.Head.NetworkId.Span, binding.NetworkId) ||
                next.Head.MinimumReader < 2 ||
                next.LogGeneration < expectedHead.LogGeneration ||
                next.TreeSize < expectedHead.TreeSize)
                throw new CryptographicException(
                    "The verified DID2 directory head is out of scope or rolls back.");
            var exactReplay = next.LogGeneration == expectedHead.LogGeneration;
            if (exactReplay
                ? !Fixed(next.ExactAdh1.Span, expectedHead.ExactAdh1.Span)
                : expectedHead.LogGeneration == ulong.MaxValue ||
                  next.LogGeneration != expectedHead.LogGeneration + 1 ||
                  !Fixed(next.Head.PredecessorAdh1CoreHash.Span,
                      expectedHead.CoreHash.Span))
                throw new CryptographicException(
                    "The verified DID2 directory head is not the exact successor.");

            using var held = await accountLease.AcquireAsync(cancellationToken)
                .ConfigureAwait(false);
            using var connection = await OpenVerifiedAsync(cancellationToken)
                .ConfigureAwait(false);
            using var transaction = connection.BeginTransaction(deferred: false);
            var row = ReadRow(connection, transaction) ??
                throw new CryptographicException(
                    "The protected DID2 directory genesis floor is absent.");
            if (!await MarkerMatchesTipAsync(expectedHead, row.Revision,
                    cancellationToken).ConfigureAwait(false))
                throw new CryptographicException(
                    "The protected DID2 directory floor marker is absent.");
            if (!Fixed(row.ExactAdh1, expectedHead.ExactAdh1.Span) ||
                !Fixed(row.CoreHash, expectedHead.CoreHash.Span))
                throw new CryptographicException(
                    "The protected DID2 directory head changed concurrently.");
            if (exactReplay)
            {
                transaction.Commit();
                return;
            }
            if (row.Revision == long.MaxValue)
                throw new CryptographicException(
                    "The protected DID2 directory revision is exhausted.");
            // Pin the next signed head outside the SQL backup domain first.
            // A crash before the SQL commit fails closed; an old valid SQL
            // snapshot cannot be replayed as the current directory floor.
            var marker = Marker(next, row.Revision + 1);
            try
            {
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(MarkerSlot(row.Revision + 1), marker)],
                    cancellationToken).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(marker); }
            using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = "UPDATE protected_lkg_root SET revision=$next,payload=$head WHERE root_kind=$kind AND revision=$current AND payload=$expected;";
            update.Parameters.AddWithValue("$next", row.Revision + 1);
            update.Parameters.AddWithValue("$head", EncodeHead(next));
            update.Parameters.AddWithValue("$kind", DirectoryRootKind);
            update.Parameters.AddWithValue("$current", row.Revision);
            update.Parameters.AddWithValue("$expected", row.Payload);
            if (update.ExecuteNonQuery() != 1)
                throw new CryptographicException(
                    "The protected DID2 directory compare/exchange failed.");
            transaction.Commit();
        }

        private async ValueTask<bool> MarkerMatchesTipAsync(
            AccountDirectoryProtectedLkg? head, long revision,
            CancellationToken cancellationToken)
        {
            using var marker = await storage.ReadOwnedAsync(MarkerSlot(revision),
                cancellationToken).ConfigureAwait(false);
            if (marker is null)
            {
                if (head is null && revision < long.MaxValue)
                {
                    using var future = await storage.ReadOwnedAsync(
                        MarkerSlot(revision + 1), cancellationToken)
                        .ConfigureAwait(false);
                    if (future is not null)
                        throw new CryptographicException(
                            "The protected DID2 directory marker chain is incomplete.");
                }
                return false;
            }
            if (head is null) return true;
            var expected = Marker(head, revision);
            try
            {
                if (marker.Length != expected.Length ||
                    !marker.Use(value => Fixed(value, expected)))
                    throw new CryptographicException(
                        "The protected DID2 directory provisioning marker is out of scope.");
                if (revision < long.MaxValue)
                {
                    using var future = await storage.ReadOwnedAsync(
                        MarkerSlot(revision + 1), cancellationToken)
                        .ConfigureAwait(false);
                    if (future is not null)
                        throw new CryptographicException(
                            "The protected DID2 directory SQL row rolled back behind its marker.");
                }
                return true;
            }
            finally { CryptographicOperations.ZeroMemory(expected); }
        }

        private byte[] Marker(AccountDirectoryProtectedLkg head, long revision)
        {
            if (revision < 1)
                throw new CryptographicException(
                    "The protected DID2 directory revision is invalid.");
            var value = new byte[124];
            "DLG2"u8.CopyTo(value);
            binding.NetworkId.CopyTo(value, 4);
            binding.AccountId.CopyTo(value, 20);
            genesis.CoreHash.Span.CopyTo(value.AsSpan(52));
            BinaryPrimitives.WriteInt64BigEndian(value.AsSpan(84, 8), revision);
            head.CoreHash.Span.CopyTo(value.AsSpan(92));
            return value;
        }

        private string MarkerSlot(long revision) =>
            markerPrefix + revision.ToString(
                System.Globalization.CultureInfo.InvariantCulture);

        private async ValueTask<SqliteConnection> OpenVerifiedAsync(
            CancellationToken cancellationToken)
        {
            using var secret = await storage.ReadOwnedAsync(KeySlot,
                cancellationToken).ConfigureAwait(false) ??
                throw new InvalidDataException("The DID2 SQL key record is absent.");
            var record = secret.Use(static value => value.ToArray());
            try
            {
                ValidateRecord(record, binding.NetworkId, binding.AccountId);
                if (!Fixed(record.AsSpan(56, 32), binding.InstanceId))
                    throw new InvalidDataException(
                        "The DID2 SQL instance changed after LKG-store opening.");
                ValidateDatabase(path, record.AsSpan(88, 32), binding);
                var connection = OpenConnection(path, record.AsSpan(88, 32),
                    create: false);
                using var durable = connection.CreateCommand();
                durable.CommandText = "PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON;";
                durable.ExecuteNonQuery();
                return connection;
            }
            finally { CryptographicOperations.ZeroMemory(record); }
        }

        private static (long Revision, byte[] Payload, byte[] ExactAdh1,
            byte[] CoreHash)? ReadRow(
            SqliteConnection connection, SqliteTransaction transaction)
        {
            using var read = connection.CreateCommand();
            read.Transaction = transaction;
            read.CommandText = "SELECT revision,payload FROM protected_lkg_root WHERE root_kind=$kind;";
            read.Parameters.AddWithValue("$kind", DirectoryRootKind);
            using var reader = read.ExecuteReader();
            if (!reader.Read()) return null;
            var revision = reader.GetInt64(0);
            var payload = reader.GetFieldValue<byte[]>(1);
            if (revision < 1 || payload.Length is < 45 or > 4140 ||
                !payload.AsSpan(0, 4).SequenceEqual("DLK2"u8) ||
                payload[4] != 2 || payload[5] != 0 || payload[6] != 0 ||
                payload[7] != 0 || reader.Read())
                throw new InvalidDataException("The protected DID2 directory head row is malformed.");
            var length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(
                payload.AsSpan(40, 4));
            if (length is < 1 or > 4096 || payload.Length != 44 + length)
                throw new InvalidDataException("The protected DID2 directory head length is malformed.");
            return (revision, payload, payload.AsSpan(44).ToArray(),
                payload.AsSpan(8, 32).ToArray());
        }

        private static AccountDirectoryProtectedLkg RestoreRow(
            (long Revision, byte[] Payload, byte[] ExactAdh1,
                byte[] CoreHash) row,
            VerifiedXPointNetworkAuthority authority)
        {
            var restored = AccountDirectoryProtectedLkgFactory.Restore(
                authority, row.ExactAdh1, row.CoreHash);
            if (restored.Head.MinimumReader < 2)
                throw new CryptographicException(
                    "The protected DID2 directory head has a V1 reader floor.");
            return restored;
        }

        private static byte[] EncodeHead(AccountDirectoryProtectedLkg head)
        {
            var exact = head.ExactAdh1;
            if (exact.Length is < 1 or > 4096)
                throw new CryptographicException("The DID2 directory head length is invalid.");
            var payload = new byte[44 + exact.Length];
            "DLK2"u8.CopyTo(payload);
            payload[4] = 2;
            head.CoreHash.Span.CopyTo(payload.AsSpan(8, 32));
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
                payload.AsSpan(40, 4), checked((uint)exact.Length));
            exact.Span.CopyTo(payload.AsSpan(44));
            return payload;
        }
    }

#if DEEP_TEST_INTERNALS
    internal static ValueTask CommitDirectoryLkgForTestsAsync(
        IDeepIdV2DirectoryProtectedLkgStore store,
        AccountDirectoryProtectedLkg expectedHead,
        AccountDirectoryProtectedLkg next,
        CancellationToken cancellationToken = default) =>
        store is DirectoryLkgStore owned
            ? owned.CommitAuthenticatedHeadAsync(expectedHead, next,
                cancellationToken)
            : throw new ArgumentException(
                "The test requires the production DID2 directory LKG store.",
                nameof(store));
#endif

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
