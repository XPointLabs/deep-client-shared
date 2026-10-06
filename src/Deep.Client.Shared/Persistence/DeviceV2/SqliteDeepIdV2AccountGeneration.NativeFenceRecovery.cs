using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Protocol.Identity;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    // Readback for an already-owned local plan, not account/network authority.
    // Full binding is part of the guard captured by the verified held producer.
    internal static async Task<Did2CompactionPlan.RootReadback> ReadStoredPlanNativeFenceUnderLeaseAsync(
        IDeepSecureStorage storage, DeepIdV2AccountFileLease lease, string statePath,
        Did2CompactionPlan plan, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        using var registeredPlan = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage,
            plan.Exact.Slice(16, 16), plan.Exact.Slice(32, 32), plan.Exact.Slice(64, 32), ct).ConfigureAwait(false);
        if (plan.Phase == 0 || !Fixed(registeredPlan.Exact.Span, plan.Exact.Span))
            throw new CryptographicException("Native fence recovery requires the exact active protected plan.");
        using var secret = await storage.ReadOwnedAsync(KeySlot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Native fence recovery lost its account key registration.");
        var record = secret.Use(bytes => bytes.ToArray());
        try
        {
            ValidateRecord(record, plan.Exact.Slice(16, 16).Span, plan.Exact.Slice(32, 32).Span);
            if (!Fixed(record.AsSpan(56, 32), plan.Exact.Slice(64, 32).Span))
                throw new CryptographicException("Native fence recovery changed its account instance.");
            var path = Path.GetFullPath(statePath);
            if (!File.Exists(path) || new FileInfo(path).Length == 0)
                throw new InvalidDataException("Native fence recovery cannot initialize an account database.");
            using var connection = OpenConnection(path, record.AsSpan(88, 32), create: false);
            var binding = ReadNativeFenceBinding(connection, null);
            if (!Fixed(binding.NetworkId, record.AsSpan(8, 16)) || !Fixed(binding.AccountId, record.AsSpan(24, 32)) ||
                !Fixed(binding.InstanceId, record.AsSpan(56, 32)))
                throw new CryptographicException("Native fence recovery opened a foreign account database.");
            ValidateDatabaseConnection(connection, binding);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return await ReadNativeReplayFenceInConnectionAsync(storage, lease, path, connection, binding, held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(record); }
    }

    private static AccountBinding ReadNativeFenceBinding(SqliteConnection connection, SqliteTransaction? transaction)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        // Check types and byte bounds before copying any field. These are
        // local guard facts, not a self-verified genesis or a current clock.
        command.CommandText = """
            SELECT a.network_id,a.account_id,a.did2_hash,a.dab2_hash,a.deep_id_text,
                   d.device_id,d.dpd1_hash,d.dmd1_hash,p.display_name,i.database_instance_id,
                   CASE WHEN typeof(a.network_id)='blob' AND length(a.network_id)=16
                     AND typeof(a.account_id)='blob' AND length(a.account_id)=32
                     AND typeof(a.did2_hash)='blob' AND length(a.did2_hash)=32
                     AND typeof(a.dab2_hash)='blob' AND length(a.dab2_hash)=32
                     AND typeof(a.deep_id_text)='text' AND length(CAST(a.deep_id_text AS BLOB)) BETWEEN 1 AND 4096
                     AND typeof(d.device_id)='blob' AND length(d.device_id)=32
                     AND typeof(d.dpd1_hash)='blob' AND length(d.dpd1_hash)=32
                     AND typeof(d.dmd1_hash)='blob' AND length(d.dmd1_hash)=32
                     AND typeof(p.display_name)='text' AND length(CAST(p.display_name AS BLOB)) BETWEEN 1 AND 256
                     AND typeof(p.revision)='integer' AND p.revision=1
                     AND typeof(i.database_instance_id)='blob' AND length(i.database_instance_id)=32
                     AND typeof(i.cipher_generation)='integer' AND i.cipher_generation=3
                     AND (SELECT count(*) FROM local_account)=1 AND (SELECT count(*) FROM local_device)=1
                     AND (SELECT count(*) FROM local_profile)=1 AND (SELECT count(*) FROM store_identity)=1
                   THEN 1 ELSE 0 END
            FROM local_account a,local_device d,local_profile p,store_identity i
            WHERE a.singleton=1 AND d.singleton=1 AND p.singleton=1 AND i.singleton=1;
            """;
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetInt64(10) != 1)
            throw new InvalidDataException("Native fence local binding is absent, oversized or noncanonical.");
        var binding = new AccountBinding(reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1),
            reader.GetFieldValue<byte[]>(2), reader.GetFieldValue<byte[]>(3), reader.GetString(8), reader.GetString(4),
            reader.GetFieldValue<byte[]>(5), reader.GetFieldValue<byte[]>(6), reader.GetFieldValue<byte[]>(7), reader.GetFieldValue<byte[]>(9));
        if (reader.Read() || DeepDisplayName.Normalize(binding.DisplayName, nameof(binding.DisplayName)) != binding.DisplayName ||
            !Fixed(DeepPermanentIdV2.ParseCanonical(binding.DeepIdText).ExactDid2Hash.Span, binding.Did2Hash))
            throw new InvalidDataException("Native fence local name/identity binding is noncanonical.");
        return binding;
    }

    private static byte[] NativeFenceBindingHash(AccountBinding binding)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/native-replay-fence-account"u8); hash.AppendData([0]);
        foreach (var bytes in new[] { binding.NetworkId, binding.AccountId, binding.InstanceId, binding.Did2Hash,
            binding.Dab2Hash, binding.DeviceId, binding.Dpd1Hash, binding.Dmd1Hash }) hash.AppendData(bytes);
        Span<byte> length = stackalloc byte[4];
        foreach (var value in new[] { binding.DisplayName, binding.DeepIdText })
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            try
            {
                BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
                hash.AppendData(length); hash.AppendData(bytes);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        return hash.GetHashAndReset();
    }
}
