using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed class Did2MessagingArchiveAuthoredRead(IReadOnlyDictionary<string, byte[]?> roots, Action<SqliteConnection> verify,
    bool hasSources = true, byte[]? fullSourceHash = null)
{
    internal IReadOnlyDictionary<string, byte[]?> Roots { get; } = roots;
    internal bool HasSources { get; } = hasSources;
    internal byte[]? FullSourceHash { get; } = fullSourceHash;
    internal Did2MessagingArchiveAuthoredRead WithFullSourceHash(ReadOnlySpan<byte> hash)
        => hash.Length == 32 ? new(Roots, verify, HasSources, hash.ToArray()) : throw new InvalidDataException("A complete authored-source guard has another width.");
    internal void Verify(SqliteConnection connection) => verify(connection);
}

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal static IncrementalHash CreateArchiveAuthoredPrefix(Did2MessagingSessionScope scope,
        IReadOnlyList<string> slots, OwnedDeepSecretBatch inventory, int firstRoot)
    {
        var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            hash.AppendData("Deep/STORE-V2/archive-enrollment-authored"u8); hash.AppendData([0]);
            hash.AppendData(scope.LocalAccount); hash.AppendData(scope.Hash);
            for (var i = firstRoot; i < slots.Count; i++)
            {
                var name = Encoding.UTF8.GetBytes(slots[i]); var number = new byte[8];
                BinaryPrimitives.WriteUInt16BigEndian(number, checked((ushort)name.Length)); hash.AppendData(number.AsSpan(0, 2)); hash.AppendData(name);
                var raw = inventory[i] ?? throw new InvalidDataException("A mandatory full authored-source root is absent.");
                raw.Use(bytes => { hash.AppendData([2]); BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)bytes.Length)); hash.AppendData(number); hash.AppendData(bytes); });
            }
            return hash;
        }
        catch { hash.Dispose(); throw; }
    }
    internal static void VerifyPairedArchiveApplication(string accountPath, Did2MessagingSessionScope scope,
        ReadOnlySpan<byte> registration, ReadOnlySpan<byte> applicationRegistration,
        IReadOnlyDictionary<string, byte[]?> actualRoots, Did2MessagingArchiveAuthoredRead expected,
        CancellationToken ct, IncrementalHash? fullSourcePrefix = null)
    {
        ct.ThrowIfCancellationRequested();
        ValidateRecord(registration, scope.Network, scope.LocalAccount);
        ValidateApplicationRegistration(applicationRegistration, registration);
        if ((expected.HasSources || expected.FullSourceHash is not null) && applicationRegistration[1] != 2 || !Fixed(registration.Slice(56, 32), scope.Instance) ||
            actualRoots.Count != expected.Roots.Count || expected.Roots.Any(pair =>
                !actualRoots.TryGetValue(pair.Key, out var value) || (pair.Value is null ? value is not null : value is null || !Fixed(pair.Value, value))))
            throw new CryptographicException("Final paired admission changed actual authored/application custody.");
        if (!expected.HasSources && expected.FullSourceHash is null) return;
        if ((expected.FullSourceHash is null) != (fullSourcePrefix is null)) throw new InvalidDataException("The final paired full-source hash state is absent or unexpected.");
        var path = ApplicationStatePath(accountPath); RequireApplicationFileFamily(path);
        if (!File.Exists(path)) throw new InvalidDataException("Final paired admission lost application SQL.");
        var key = DeriveApplicationKey(registration);
        try
        {
            using var connection = OpenRandomKeyConnection(path, key, create: false);
            CryptographicOperations.ZeroMemory(key);
            expected.Verify(connection);
            if (fullSourcePrefix is not null && !Fixed(SqliteDeepMailboxStore.CaptureArchiveAuthoredSourceFromConnection(
                connection, fullSourcePrefix, scope, ct), expected.FullSourceHash!))
                throw new CryptographicException("Full authored source changed at final combined admission.");
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    // A closed selected-source reader. It cannot create an application database,
    // mutate its registration or suppress an ordinary application admission.
    // All protected callbacks finish before the physical read begins.
    internal static async Task<T> ReadArchiveAuthoredSqlUnderLeaseAsync<T>(IDeepSecureStorage storage,
        string accountPath, Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held,
        DeepIdV2AccountFileLease lease, IReadOnlyDictionary<string, byte[]?> roots,
        Func<SqliteConnection, T> read, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var slots = new[] { KeySlot, ApplicationStateSlot }.Concat(roots.Keys.Order(StringComparer.Ordinal)).ToArray();
        using var actual = await storage.ReadOwnedBatchAsync(slots, ct).ConfigureAwait(false);
        var raw = actual[0] ?? throw new InvalidDataException("Selected authored source lost account registration.");
        var registered = actual[1] ?? throw new InvalidDataException("Selected authored source lost application registration.");
        var record = raw.Use(bytes => bytes.ToArray()); byte[] key = [];
        try
        {
            ValidateRecord(record, scope.Network, scope.LocalAccount);
            registered.Use(bytes =>
            {
                ValidateApplicationRegistration(bytes, record);
                if (bytes[1] != 2 || !Fixed(record.AsSpan(56, 32), scope.Instance))
                    throw new CryptographicException("Selected authored source requires the initialized actual account instance.");
            });
            for (var i = 2; i < slots.Length; i++)
            {
                var expected = roots[slots[i]]; var value = actual[i];
                if (expected is null ? value is not null : value is null || !value.Use(bytes => Fixed(SHA256.HashData(bytes), expected)))
                    throw new CryptographicException("Actual authored custody changed before its fresh selected application read.");
            }
            var path = ApplicationStatePath(accountPath); RequireApplicationFileFamily(path);
            if (!File.Exists(path)) throw new InvalidDataException("Selected authored source has no initialized application SQL.");
            key = DeriveApplicationKey(record);
            actual.Dispose();
            CryptographicOperations.ZeroMemory(record); record = [];
            using var connection = OpenRandomKeyConnection(path, key, create: false);
            CryptographicOperations.ZeroMemory(key); key = [];
            held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
            return read(connection);
        }
        finally { CryptographicOperations.ZeroMemory(record); CryptographicOperations.ZeroMemory(key); }
    }
}
