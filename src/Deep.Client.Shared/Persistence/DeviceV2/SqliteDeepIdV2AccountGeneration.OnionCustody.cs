using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal static async ValueTask<DeepIdV2OnionClientCustody> OpenOnionCustodyAsync(
        IDeepSecureStorage storage, DeepIdV2AccountFileLease accountLease,
        string statePath, VerifiedDeepIdV2CurrentAccount current,
        DeepIdV2AccountService owner, CancellationToken cancellationToken)
    {
        using var secret = await storage.ReadOwnedAsync(KeySlot, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("The DID2 SQL key record is absent.");
        var record = secret.Use(static value => value.ToArray());
        try
        {
            var network = current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.NetworkId;
            ValidateRecord(record, network.Span, current.AccountId.Span);
            var binding = AccountBinding.From(current.Verified, current.AccountId.Span,
                network.Span, current.DisplayName, current.PermanentId.CanonicalText, record.AsSpan(56, 32));
            var guards = new OnionGuardStore(new OnionCustodyRoot(storage, accountLease,
                statePath, binding, 4, 232));
            var entropy = new OnionEntropyLedger(new OnionCustodyRoot(storage, accountLease,
                statePath, binding, 5, 8 + OnionEntropyLedger.MaximumCommitments * 32));
            // The caller holds the account lease. Do not recursively acquire it.
            var guard = await guards.Root.ReadUnderLeaseAsync(cancellationToken).ConfigureAwait(false);
            if (guard is not null) guards.Decode(guard);
            var reserved = await entropy.Root.ReadUnderLeaseAsync(cancellationToken).ConfigureAwait(false);
            if (reserved is not null) OnionEntropyLedger.Decode(reserved.Payload);
            return new(owner, guards, entropy);
        }
        finally { CryptographicOperations.ZeroMemory(record); }
    }

    private sealed record OnionCustodyRow(long Revision, byte[] Payload);

    // Fixed two-slot protected floors precede SQL. A crash cannot release a
    // frame while permitting rollback. No per-message SecureStorage key grows.
    private sealed class OnionCustodyRoot
    {
        private readonly IDeepSecureStorage storage;
        private readonly DeepIdV2AccountFileLease lease;
        private readonly string path;
        private readonly AccountBinding binding;
        private readonly int kind, maximumPayload;
        private readonly byte[] scope;
        private readonly string prefix;
        internal ReadOnlyMemory<byte> NetworkId => binding.NetworkId;

        internal OnionCustodyRoot(IDeepSecureStorage storage, DeepIdV2AccountFileLease lease,
            string path, AccountBinding binding, int kind, int maximumPayload)
        {
            this.storage = storage; this.lease = lease; this.path = Path.GetFullPath(path);
            this.binding = binding; this.kind = kind; this.maximumPayload = maximumPayload;
            scope = SHA256.HashData("Deep/STORE-V2/onion-custody"u8.ToArray()
                .Concat(binding.NetworkId).Concat(binding.AccountId).Concat(binding.DeviceId)
                .Concat(binding.InstanceId).Append(checked((byte)kind)).ToArray());
            prefix = "deep.store.v2.onion-custody." + Convert.ToHexStringLower(scope) + ".floor.";
        }

        internal async ValueTask<OnionCustodyRow?> ReadUnderLeaseAsync(CancellationToken ct)
        {
            using var connection = await OpenBoundLkgConnectionAsync(storage, path, binding, ct).ConfigureAwait(false);
            using var transaction = connection.BeginTransaction(deferred: false);
            var row = ReadRow(connection, transaction);
            await RequireFloorAsync(row, ct).ConfigureAwait(false);
            return row;
        }

        internal async ValueTask<OnionCustodyRow?> ReadAsync(CancellationToken ct)
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            return await ReadUnderLeaseAsync(ct).ConfigureAwait(false);
        }

        internal async ValueTask<bool> CompareExchangeAsync(OnionCustodyRow? expected,
            byte[] payload, CancellationToken ct)
        {
            if (payload.Length is < 1 || payload.Length > maximumPayload)
                throw new InvalidDataException("The DID2 ONION custody payload is outside its closed bound.");
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var connection = await OpenBoundLkgConnectionAsync(storage, path, binding, ct).ConfigureAwait(false);
            using var transaction = connection.BeginTransaction(deferred: false);
            var current = ReadRow(connection, transaction);
            await RequireFloorAsync(current, ct).ConfigureAwait(false);
            if (current?.Revision != expected?.Revision || current is not null &&
                !Fixed(current.Payload, expected!.Payload)) return false;
            var revision = checked((expected?.Revision ?? 0) + 1);
            var marker = Marker(revision, payload);
            try
            {
                var slot = prefix + (revision % 2).ToString(System.Globalization.CultureInfo.InvariantCulture);
                if (revision <= 2)
                    await storage.WriteBatchAsync([new DeepSecureStorageWrite(slot, marker)], ct).ConfigureAwait(false);
                else
                {
                    using var prior = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false)
                        ?? throw new CryptographicException("The protected ONION replacement slot disappeared.");
                    var expectedMarker = prior.Use(static value => value.ToArray());
                    try
                    {
                        if (!await storage.CompareExchangeAsync(slot, expectedMarker, marker, ct).ConfigureAwait(false))
                            throw new CryptographicException("The protected ONION replacement slot changed.");
                    }
                    finally { CryptographicOperations.ZeroMemory(expectedMarker); }
                }
            }
            finally { CryptographicOperations.ZeroMemory(marker); }
            using var write = connection.CreateCommand();
            write.Transaction = transaction;
            write.CommandText = current is null
                ? "INSERT INTO protected_lkg_root(root_kind,revision,payload) VALUES($kind,$next,$payload);"
                : "UPDATE protected_lkg_root SET revision=$next,payload=$payload WHERE root_kind=$kind AND revision=$prior AND payload=$expected;";
            write.Parameters.AddWithValue("$kind", kind);
            write.Parameters.AddWithValue("$next", revision);
            write.Parameters.AddWithValue("$payload", payload);
            if (current is not null)
            {
                write.Parameters.AddWithValue("$prior", current.Revision);
                write.Parameters.AddWithValue("$expected", current.Payload);
            }
            if (write.ExecuteNonQuery() != 1)
                throw new CryptographicException("The DID2 ONION custody CAS did not commit.");
            ct.ThrowIfCancellationRequested();
            transaction.Commit();
            return true;
        }

        private OnionCustodyRow? ReadRow(SqliteConnection connection, SqliteTransaction transaction)
        {
            using var read = connection.CreateCommand();
            read.Transaction = transaction;
            read.CommandText = "SELECT revision,length(payload),payload FROM protected_lkg_root WHERE root_kind=$kind;";
            read.Parameters.AddWithValue("$kind", kind);
            using var reader = read.ExecuteReader();
            if (!reader.Read()) return null;
            var revision = reader.GetInt64(0);
            var length = reader.GetInt64(1);
            if (revision < 1 || length < 1 || length > maximumPayload)
                throw new InvalidDataException("The DID2 ONION custody row is malformed or oversized.");
            var payload = reader.GetFieldValue<byte[]>(2);
            if (reader.Read()) throw new InvalidDataException("The DID2 ONION custody row is not unique.");
            return new(revision, payload);
        }

        private async ValueTask RequireFloorAsync(OnionCustodyRow? row, CancellationToken ct)
        {
            byte[]? highest = null;
            long maximumRevision = 0, minimumRevision = long.MaxValue;
            var present = 0;
            for (var slot = 0; slot < 2; slot++)
            {
                using var stored = await storage.ReadOwnedAsync(
                    prefix + slot.ToString(System.Globalization.CultureInfo.InvariantCulture), ct).ConfigureAwait(false);
                if (stored is null) continue;
                present++;
                var exact = stored.Use(static value => value.ToArray());
                if (exact.Length != 80 || !exact.AsSpan(0, 4).SequenceEqual("OCF2"u8) ||
                    !Fixed(exact.AsSpan(4, 32), scope) ||
                    BinaryPrimitives.ReadInt32BigEndian(exact.AsSpan(76)) != kind)
                    throw new CryptographicException("The protected DID2 ONION floor has a different scope.");
                var revision = BinaryPrimitives.ReadInt64BigEndian(exact.AsSpan(36, 8));
                if (revision < 1 || revision % 2 != slot)
                    throw new CryptographicException("The protected DID2 ONION floor revision is invalid.");
                minimumRevision = Math.Min(minimumRevision, revision);
                if (revision > maximumRevision) { maximumRevision = revision; highest = exact; }
            }
            if (highest is null)
            {
                if (row is not null) throw new CryptographicException("DID2 ONION custody lost its protected floor.");
                return;
            }
            if (maximumRevision > 1 && present != 2 || maximumRevision - minimumRevision > 1 || row is null || row.Revision != maximumRevision ||
                !Fixed(highest, Marker(row.Revision, row.Payload)))
                throw new CryptographicException("DID2 ONION SQL custody is missing, rolled back or behind its floor.");
        }

        private byte[] Marker(long revision, byte[] payload)
        {
            var result = new byte[80];
            "OCF2"u8.CopyTo(result);
            scope.CopyTo(result, 4);
            BinaryPrimitives.WriteInt64BigEndian(result.AsSpan(36, 8), revision);
            SHA256.HashData(payload).CopyTo(result, 44);
            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(76), kind);
            return result;
        }
    }

    private sealed class OnionGuardStore(OnionCustodyRoot root) : IProtectedEntryGuardStore
    {
        internal OnionCustodyRoot Root => root;
        internal EntryGuardState Decode(OnionCustodyRow row)
        {
            var value = EntryGuardStateCodec.Decode(row.Payload);
            if (value.Revision != checked((ulong)row.Revision) || !Fixed(value.NetworkId.Span, root.NetworkId.Span))
                throw new CryptographicException("DID2 entry guards have a different revision or network.");
            return value;
        }

        public async ValueTask<EntryGuardState?> ReadAsync(CancellationToken ct)
        {
            var row = await root.ReadAsync(ct).ConfigureAwait(false);
            return row is null ? null : Decode(row);
        }

        public async ValueTask<EntryGuardStoreWriteResult> CompareExchangeAsync(ulong? expectedRevision,
            EntryGuardState replacement, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(replacement);
            var row = await root.ReadAsync(ct).ConfigureAwait(false);
            var current = row is null ? null : Decode(row);
            if (current?.Revision != expectedRevision) return new(EntryGuardStoreWriteDisposition.Conflict, current);
            if (replacement.Revision != checked((expectedRevision ?? 0) + 1) ||
                !Fixed(replacement.NetworkId.Span, root.NetworkId.Span) ||
                current is not null && (replacement.ViewGeneration < current.ViewGeneration ||
                    !Fixed(replacement.LocalSalt.Span, current.LocalSalt.Span) ||
                    replacement.ViewGeneration == current.ViewGeneration && !Fixed(replacement.ViewHash.Span, current.ViewHash.Span)))
                throw new CryptographicException("DID2 entry guards roll back or conflict with protected state.");
            return await root.CompareExchangeAsync(row, EntryGuardStateCodec.Encode(replacement), ct).ConfigureAwait(false)
                ? new(EntryGuardStoreWriteDisposition.Applied, EntryGuardState.Copy(replacement))
                : new(EntryGuardStoreWriteDisposition.Conflict, await ReadAsync(ct).ConfigureAwait(false));
        }
    }

    private sealed class OnionEntropyLedger(OnionCustodyRoot root) : IOnionEntropyUniquenessLedger
    {
        internal const int MaximumCommitments = 262_144;
        internal OnionCustodyRoot Root => root;

        public async ValueTask<OnionEntropyCommitOutcome> CommitAsync(OnionEntropyCommitmentBatch batch, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(batch);
            var additions = batch.Commitments.Select(static value => value.ToArray()).ToArray();
            if (additions.Length != (batch.IsResponse ? 1 : 8) ||
                additions.Any(static value => value.Length != 32 || value.AsSpan().IndexOfAnyExcept((byte)0) < 0) ||
                additions.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count() != additions.Length)
                return OnionEntropyCommitOutcome.Rejected;
            for (var attempt = 0; attempt < 8; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                var row = await root.ReadAsync(ct).ConfigureAwait(false);
                var current = row is null ? new HashSet<string>(StringComparer.Ordinal) : Decode(row.Payload);
                var encoded = additions.Select(Convert.ToHexString).ToArray();
                if (encoded.Any(current.Contains)) return OnionEntropyCommitOutcome.Duplicate;
                if (current.Count > MaximumCommitments - additions.Length) return OnionEntropyCommitOutcome.Rejected;
                current.UnionWith(encoded);
                var payload = new byte[8 + current.Count * 32];
                "OCE2"u8.CopyTo(payload);
                BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(4, 4), current.Count);
                var index = 8;
                foreach (var value in current.Order(StringComparer.Ordinal))
                { Convert.FromHexString(value).CopyTo(payload, index); index += 32; }
                if (await root.CompareExchangeAsync(row, payload, ct).ConfigureAwait(false))
                    return OnionEntropyCommitOutcome.Committed;
            }
            throw new IOException("DID2 ONION entropy custody remained contended.");
        }

        internal static HashSet<string> Decode(byte[] payload)
        {
            if (payload.Length < 8 || !payload.AsSpan(0, 4).SequenceEqual("OCE2"u8))
                throw new InvalidDataException("DID2 ONION entropy payload is malformed.");
            var count = BinaryPrimitives.ReadInt32BigEndian(payload.AsSpan(4, 4));
            if (count is < 1 or > MaximumCommitments || payload.Length != 8 + count * 32)
                throw new InvalidDataException("DID2 ONION entropy payload is outside its closed bound.");
            var values = new HashSet<string>(StringComparer.Ordinal);
            string? previous = null;
            for (var index = 0; index < count; index++)
            {
                var span = payload.AsSpan(8 + index * 32, 32);
                var value = Convert.ToHexString(span);
                if (span.IndexOfAnyExcept((byte)0) < 0 || previous is not null &&
                    string.CompareOrdinal(previous, value) >= 0 || !values.Add(value))
                    throw new InvalidDataException("DID2 ONION entropy commitments are not canonical.");
                previous = value;
            }
            return values;
        }
    }
}
