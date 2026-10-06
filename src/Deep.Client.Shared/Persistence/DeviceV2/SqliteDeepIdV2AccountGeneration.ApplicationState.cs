using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal const string ApplicationStateSlot = "deep.store.v2.application-state";

    // Recovery opens only the already-initialized, exact account database.
    // No current network proof, file creation or registration promotion occurs.
    internal static async Task<SqliteDeepMailboxStore> OpenExistingApplicationForCompactionUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, Did2MessagingSessionScope scope,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        using var secret = await storage.ReadOwnedAsync(KeySlot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Application recovery lost its account key registration.");
        using var registered = await storage.ReadOwnedAsync(ApplicationStateSlot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Application recovery lost its initialized registration.");
        var record = secret.Use(bytes => bytes.ToArray());
        var registration = registered.Use(bytes => bytes.ToArray()); byte[] key = [];
        try
        {
            ValidateRecord(record, scope.Network, scope.LocalAccount);
            ValidateApplicationRegistration(registration, record);
            if (registration[1] != 2 || !Fixed(record.AsSpan(56, 32), scope.Instance))
                throw new CryptographicException("Application recovery requires its exact initialized account instance.");
            var path = ApplicationStatePath(accountPath); RequireApplicationFileFamily(path);
            key = DeriveApplicationKey(record);
            using var options = new SqliteDeepMailboxStoreOptions(path, key);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return SqliteDeepMailboxStore.OpenExisting(options);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(record); CryptographicOperations.ZeroMemory(registration);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] DeriveApplicationKey(ReadOnlySpan<byte> accountRecord)
    {
        var domain = "Deep/STORE-V2/application-state-key"u8;
        var context = new byte[domain.Length + 1 + 16 + 32 + 32];
        try
        {
            domain.CopyTo(context);
            accountRecord.Slice(8, 48).CopyTo(context.AsSpan(domain.Length + 1));
            accountRecord.Slice(56, 32).CopyTo(context.AsSpan(domain.Length + 49));
            return HMACSHA256.HashData(accountRecord.Slice(88, 32), context);
        }
        finally { CryptographicOperations.ZeroMemory(context); }
    }

    private static byte[] NewApplicationRegistration(ReadOnlySpan<byte> accountRecord)
    {
        var registration = new byte[116]; registration[0] = 3; registration[1] = 1;
        accountRecord.Slice(8, 48).CopyTo(registration.AsSpan(4));
        accountRecord.Slice(56, 32).CopyTo(registration.AsSpan(52));
        var key = DeriveApplicationKey(accountRecord);
        try { SHA256.HashData(key, registration.AsSpan(84)); return registration; }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static void ValidateApplicationRegistration(ReadOnlySpan<byte> registration,
        ReadOnlySpan<byte> accountRecord)
    {
        var expected = NewApplicationRegistration(accountRecord);
        try
        {
            if (registration.Length != 116 || registration[0] != 3 ||
                registration[1] is not (1 or 2) || registration[2] != 0 || registration[3] != 0 ||
                !Fixed(registration[4..], expected.AsSpan(4)))
                throw new InvalidDataException("DID2 application registration is absent, foreign or unsupported; explicit reset is required.");
        }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    internal static async Task<SqliteDeepMailboxStore> OpenApplicationUnderLeaseAsync(
        IDeepSecureStorage storage, string accountPath, VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireActive();
        using var secret = await storage.ReadOwnedAsync(KeySlot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("The DID2 account SQL key is absent.");
        using var registered = await storage.ReadOwnedAsync(ApplicationStateSlot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("The DID2 application registration is absent; no repair is permitted.");
        var record = secret.Use(static bytes => bytes.ToArray());
        var registration = registered.Use(static bytes => bytes.ToArray());
        byte[] key = []; SqliteDeepMailboxStore? store = null;
        try
        {
            ValidateRecord(record, current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.NetworkId.Span,
                current.AccountId.Span);
            ValidateApplicationRegistration(registration, record);
            var path = ApplicationStatePath(accountPath);
            RequireApplicationFileFamily(path);
            key = DeriveApplicationKey(record);
            using var options = new SqliteDeepMailboxStoreOptions(path, key);
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            store = registration[1] == 1 && !File.Exists(path)
                ? new(options) : SqliteDeepMailboxStore.OpenExisting(options);
            if (registration[1] == 1)
            {
                store.RequireInitializedEmpty();
                var next = registration.ToArray(); next[1] = 2;
                try
                {
                    if (!await storage.CompareExchangeAsync(ApplicationStateSlot, registration, next, ct).ConfigureAwait(false))
                        throw new CryptographicException("DID2 application registration changed under its account lease.");
                }
                finally { CryptographicOperations.ZeroMemory(next); }
            }
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            var result = store; store = null; return result;
        }
        finally
        {
            store?.Dispose(); CryptographicOperations.ZeroMemory(record);
            CryptographicOperations.ZeroMemory(registration); CryptographicOperations.ZeroMemory(key);
        }
    }

    private static string ApplicationStatePath(string accountPath)
    {
        var full = Path.GetFullPath(accountPath);
        RequireOrdinaryDirectory(Path.GetDirectoryName(full) ?? throw new InvalidDataException("An account-private directory is required."));
        return full + ".application.dmb1";
    }

    private static void RequireApplicationFileFamily(string path, bool allowOrphans = false)
    {
        foreach (var artifact in new[] { path, path + "-journal", path + "-wal", path + "-shm" })
        {
            if (Directory.Exists(artifact) || File.Exists(artifact) &&
                (File.GetAttributes(artifact) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("DID2 application state cannot contain linked or directory artifacts.");
            if (!allowOrphans && artifact != path && File.Exists(artifact) && !File.Exists(path))
                throw new InvalidDataException("DID2 application state has orphan sidecars.");
        }
    }

    internal static void DeleteApplicationAfterExplicitReset(string accountPath)
    {
        var path = ApplicationStatePath(accountPath);
        RequireApplicationFileFamily(path, allowOrphans: true);
        foreach (var artifact in new[] { path, path + "-journal", path + "-wal", path + "-shm" })
            File.Delete(artifact);
    }
}
