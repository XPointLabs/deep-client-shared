using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.MessagingV1;

namespace Deep.Client.Shared.Persistence;

internal enum SqliteDeepAccountStoreLifecycleFaultPoint
{
    AfterGenerationRecordWritten = 1,
    AfterTemporaryDatabaseCreated = 2,
    AfterDatabaseMoved = 3,
    AfterDestroyTombstoneWritten = 4,
    AfterGenerationSlotsDeleted = 5,
    AfterDatabaseArtifactsDeleted = 6
}

internal sealed class SqliteDeepAccountStoreSimulatedCrashException(
    SqliteDeepAccountStoreLifecycleFaultPoint point,
    Exception innerException) :
    IOException($"Simulated STORE-01 lifecycle crash after {point}.", innerException)
{
    internal SqliteDeepAccountStoreLifecycleFaultPoint Point { get; } = point;
}

internal sealed record DeepGenerationAccountManifest(
    DeepAccountCreationOperation Operation,
    ReadOnlyMemory<byte> ImmutableIdentityCommitment,
    MessageStoreInstanceId32 MessageStoreInstanceId,
    DeepSecureStorageSlots SecureSlots)
{
    internal string[] Slots =>
    [
        SecureSlots.DeviceSigningKey,
        SecureSlots.DeviceAgreementKey,
        SecureSlots.DeviceId,
        SecureSlots.DeviceRevocationHandle,
        SecureSlots.DevicePrekey,
        SecureSlots.PushKey,
        SecureSlots.MessageStoreInstanceId
    ];

    internal bool Matches(DeepGenerationAccountManifest other) =>
        Operation.Matches(other.Operation)
        && CryptographicOperations.FixedTimeEquals(
            ImmutableIdentityCommitment.Span,
            other.ImmutableIdentityCommitment.Span)
        && MessageStoreInstanceId.Equals(other.MessageStoreInstanceId)
        && Slots.SequenceEqual(other.Slots, StringComparer.Ordinal);
}

/// <summary>
/// Owns the SQLCipher database generation lifecycle. Every returned store holds a
/// cross-process shared generation lease; destruction requires the exclusive lease.
/// </summary>
public static class SqliteDeepAccountStoreBootstrap
{
    // Deliberately outside the purged STORE-V1 value namespace. Its presence is
    // sufficient to resume destruction; its payload is never decoded.
    internal const string ResetTombstoneSlot = "deep.store.reset.v1.database-reset";
    private const int RecordSize = 72;
    private const byte RecordVersion = 1;
    private static readonly byte[] RecordMagic = "DSK1"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public static Task<SqliteDeepAccountStore> OpenAsync(
        string statePath,
        IDeepSecureStorage secureStorage,
        CancellationToken cancellationToken = default) =>
        OpenCoreAsync(statePath, secureStorage, null, cancellationToken);

    internal static Task<SqliteDeepAccountStore> OpenAsync(
        string statePath,
        IDeepSecureStorage secureStorage,
        Action<SqliteDeepAccountStoreLifecycleFaultPoint> faultInjector,
        CancellationToken cancellationToken = default) =>
        OpenCoreAsync(statePath, secureStorage, faultInjector, cancellationToken);

    private static async Task<SqliteDeepAccountStore> OpenCoreAsync(
        string statePath,
        IDeepSecureStorage secureStorage,
        Action<SqliteDeepAccountStoreLifecycleFaultPoint>? faultInjector,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(secureStorage);
        var fullPath = Path.GetFullPath(statePath);

        FileStream? generationLease = await AcquireSharedGenerationLeaseAsync(fullPath, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await using var fileLock = await AcquireExclusiveFileLockAsync(
                        fullPath + ".bootstrap.lock",
                        cancellationToken)
                    .ConfigureAwait(false);
                await using var accountLock = await AcquireExclusiveFileLockAsync(
                        fullPath + ".account.lock",
                        cancellationToken)
                    .ConfigureAwait(false);
                await CompleteInterruptedDestroyAsync(fullPath, secureStorage, faultInjector)
                    .ConfigureAwait(false);

                using var encoded = await secureStorage
                    .ReadOwnedAsync(DeepAccountStoreContract.DatabaseGenerationSlot, cancellationToken)
                    .ConfigureAwait(false);
                if (encoded is null)
                {
                    if (DatabaseGenerationArtifactsExist(fullPath)
                        || await SecureAccountStateExistsAsync(secureStorage, cancellationToken).ConfigureAwait(false))
                    {
                        throw ResetRequired(
                            "Local state exists but its database generation record is missing.");
                    }

                    var createdRecord = CreateRecord();
                    try
                    {
                        await secureStorage.WriteBatchAsync(
                                [new DeepSecureStorageWrite(
                                    DeepAccountStoreContract.DatabaseGenerationSlot,
                                    createdRecord)],
                                cancellationToken)
                            .ConfigureAwait(false);
                        InvokeFault(faultInjector, SqliteDeepAccountStoreLifecycleFaultPoint.AfterGenerationRecordWritten);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(createdRecord);
                    }
                }

                using var currentRecord = encoded is null
                    ? await secureStorage.ReadOwnedAsync(
                            DeepAccountStoreContract.DatabaseGenerationSlot,
                            CancellationToken.None)
                        .ConfigureAwait(false)
                        ?? throw ResetRequired("The database generation record was not durably written.")
                    : encoded.Use(static value => new OwnedDeepSecret(value));
                using var record = currentRecord.Use(static value => DecodeRecord(value));

                if (!File.Exists(fullPath)
                    && (File.Exists(fullPath + "-wal") || File.Exists(fullPath + "-shm")))
                {
                    throw ResetRequired("Local database main/WAL/SHM files are incomplete.");
                }
                if (!File.Exists(fullPath))
                {
                    var generationSlots = DeepSecureStorageSlots.CreateForGeneration(record.InstanceId.Span);
                    if (await SecureAccountStateExistsAsync(secureStorage, cancellationToken).ConfigureAwait(false)
                        || await AnyAccountSlotExistsAsync(
                                secureStorage,
                                generationSlots,
                                cancellationToken)
                            .ConfigureAwait(false))
                    {
                        throw ResetRequired("Account secure state exists without its encrypted database.");
                    }
                    await CreateAtomicallyAsync(fullPath, record, faultInjector, cancellationToken)
                        .ConfigureAwait(false);
                }

                var store = new SqliteDeepAccountStore(new SqliteDeepAccountStoreOptions(
                    fullPath,
                    record.Key,
                    record.InstanceId,
                    allowCreate: false,
                    generationLease));
                generationLease = null;
                return store;
            }
            finally
            {
                Gate.Release();
            }
        }
        finally
        {
            if (generationLease is not null)
            {
                await generationLease.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    public static Task DestroyGenerationAsync(
        string statePath,
        IDeepSecureStorage secureStorage,
        CancellationToken cancellationToken = default) =>
        DestroyGenerationCoreAsync(statePath, secureStorage, null, cancellationToken);

    internal static Task DestroyGenerationAsync(
        string statePath,
        IDeepSecureStorage secureStorage,
        Action<SqliteDeepAccountStoreLifecycleFaultPoint> faultInjector,
        CancellationToken cancellationToken = default) =>
        DestroyGenerationCoreAsync(statePath, secureStorage, faultInjector, cancellationToken);

    private static async Task DestroyGenerationCoreAsync(
        string statePath,
        IDeepSecureStorage secureStorage,
        Action<SqliteDeepAccountStoreLifecycleFaultPoint>? faultInjector,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(secureStorage);
        var fullPath = Path.GetFullPath(statePath);

        await using var generationLease = await AcquireExclusiveGenerationLeaseAsync(fullPath, cancellationToken)
            .ConfigureAwait(false);
        await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var fileLock = await AcquireExclusiveFileLockAsync(
                    fullPath + ".bootstrap.lock",
                    cancellationToken)
                .ConfigureAwait(false);
            await using var accountLock = await AcquireExclusiveFileLockAsync(
                    fullPath + ".account.lock",
                    cancellationToken)
                .ConfigureAwait(false);

            if (await CompleteInterruptedDestroyAsync(fullPath, secureStorage, faultInjector)
                    .ConfigureAwait(false))
            {
                return;
            }

            // Destruction must not depend on decoding any lifecycle value. The
            // out-of-namespace tombstone makes the purge restartable even after
            // every STORE-V1 secure value has already been removed.
            var tombstone = "DST4"u8.ToArray();
            try
            {
                await secureStorage.WriteBatchAsync(
                        [new DeepSecureStorageWrite(ResetTombstoneSlot, tombstone)],
                        cancellationToken)
                    .ConfigureAwait(false);
                InvokeFault(faultInjector, SqliteDeepAccountStoreLifecycleFaultPoint.AfterDestroyTombstoneWritten);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(tombstone);
            }

            _ = await CompleteInterruptedDestroyAsync(fullPath, secureStorage, faultInjector)
                .ConfigureAwait(false);
        }
        finally
        {
            Gate.Release();
        }
    }

    internal static byte[] EncodeAccountManifest(
        DeepAccountCreationOperation operation,
        ReadOnlySpan<byte> immutableIdentityCommitment,
        MessageStoreInstanceId32 messageStoreInstanceId,
        DeepSecureStorageSlots slots)
    {
        ArgumentNullException.ThrowIfNull(operation);
        DeepAccountImmutableIdentityHash.Validate(
            immutableIdentityCommitment,
            nameof(immutableIdentityCommitment));
        ArgumentNullException.ThrowIfNull(messageStoreInstanceId);
        DeepSecureStorageSlots.Validate(slots);
        return StrictUtf8.GetBytes(string.Join('\n',
            new[]
            {
                "DSM3",
                Convert.ToHexStringLower(operation.OperationId.Span),
                Convert.ToHexStringLower(operation.InitialSnapshotHash.Span),
                Convert.ToHexStringLower(immutableIdentityCommitment),
                Convert.ToHexStringLower(messageStoreInstanceId.Span),
                slots.DeviceSigningKey,
                slots.DeviceAgreementKey,
                slots.DeviceId,
                slots.DeviceRevocationHandle,
                slots.DevicePrekey,
                slots.PushKey,
                slots.MessageStoreInstanceId
            }));
    }

    internal static DeepGenerationAccountManifest DecodeAccountManifest(ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty || encoded.Length > 1024)
        {
            throw ResetRequired("The account secure-state manifest is malformed.");
        }

        string text;
        try
        {
            text = StrictUtf8.GetString(encoded);
        }
        catch (DecoderFallbackException exception)
        {
            throw ResetRequired("The account secure-state manifest is not canonical UTF-8.", exception);
        }
        var values = text.Split('\n', StringSplitOptions.None);
        if (values.Length != 12
            || !string.Equals(values[0], "DSM3", StringComparison.Ordinal)
            || values[1].Length != DeepAccountCreationOperation.ValueSize * 2
            || values[2].Length != DeepAccountCreationOperation.ValueSize * 2
            || values[3].Length != DeepAccountImmutableIdentityHash.Size * 2
            || values[4].Length != 64
            || values[1].AsSpan().IndexOfAnyExcept("0123456789abcdef") >= 0
            || values[2].AsSpan().IndexOfAnyExcept("0123456789abcdef") >= 0
            || values[3].AsSpan().IndexOfAnyExcept("0123456789abcdef") >= 0
            || values[4].AsSpan().IndexOfAnyExcept("0123456789abcdef") >= 0)
        {
            throw ResetRequired("The account secure-state manifest is malformed.");
        }

        var operationId = Convert.FromHexString(values[1]);
        var initialSnapshotHash = Convert.FromHexString(values[2]);
        var immutableIdentityCommitment = Convert.FromHexString(values[3]);
        var messageStoreInstanceId = Convert.FromHexString(values[4]);
        try
        {
            var operation = DeepAccountCreationOperation.FromPersisted(operationId, initialSnapshotHash);
            DeepAccountImmutableIdentityHash.Validate(
                immutableIdentityCommitment,
                nameof(immutableIdentityCommitment));
            var instanceId = MessageStoreInstanceId32.FromBytes(messageStoreInstanceId);
            var slots = new DeepSecureStorageSlots(
                values[5], values[6], values[7], values[8], values[9], values[10], values[11]);
            DeepSecureStorageSlots.Validate(slots);
            return new DeepGenerationAccountManifest(
                operation,
                immutableIdentityCommitment.ToArray(),
                instanceId,
                slots);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw ResetRequired("The account secure-state manifest contains invalid values.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(operationId);
            CryptographicOperations.ZeroMemory(initialSnapshotHash);
            CryptographicOperations.ZeroMemory(immutableIdentityCommitment);
            CryptographicOperations.ZeroMemory(messageStoreInstanceId);
        }
    }

    internal static async Task<FileStream> AcquireSharedGenerationLeaseAsync(
        string fullPath,
        CancellationToken cancellationToken) =>
        await AcquireFileLockAsync(
                fullPath + ".generation.lock",
                FileAccess.Read,
                FileShare.Read,
                cancellationToken)
            .ConfigureAwait(false);

    private static async Task<FileStream> AcquireExclusiveGenerationLeaseAsync(
        string fullPath,
        CancellationToken cancellationToken) =>
        await AcquireFileLockAsync(
                fullPath + ".generation.lock",
                FileAccess.ReadWrite,
                FileShare.None,
                cancellationToken)
            .ConfigureAwait(false);

    private static async Task<bool> CompleteInterruptedDestroyAsync(
        string fullPath,
        IDeepSecureStorage secureStorage,
        Action<SqliteDeepAccountStoreLifecycleFaultPoint>? faultInjector)
    {
        using var encoded = await secureStorage
            .ReadOwnedAsync(ResetTombstoneSlot, CancellationToken.None)
            .ConfigureAwait(false);
        if (encoded is null)
        {
            return false;
        }

        await secureStorage.PurgeStoreV1NamespaceAsync(CancellationToken.None)
            .ConfigureAwait(false);
        InvokeFault(faultInjector, SqliteDeepAccountStoreLifecycleFaultPoint.AfterGenerationSlotsDeleted);
        DeleteDatabaseGenerationArtifacts(fullPath);
        InvokeFault(faultInjector, SqliteDeepAccountStoreLifecycleFaultPoint.AfterDatabaseArtifactsDeleted);
        await secureStorage.DeleteBatchAsync([ResetTombstoneSlot], CancellationToken.None)
            .ConfigureAwait(false);
        return true;
    }

    private static async Task CreateAtomicallyAsync(
        string fullPath,
        DatabaseGenerationRecord record,
        Action<SqliteDeepAccountStoreLifecycleFaultPoint>? faultInjector,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporaryPath = fullPath + ".creating";
        DeleteDatabaseArtifacts(temporaryPath);
        var preserveCrashArtifacts = false;
        try
        {
            await using (var created = new SqliteDeepAccountStore(new SqliteDeepAccountStoreOptions(
                             temporaryPath,
                             record.Key,
                             record.InstanceId,
                             allowCreate: true)))
            {
                _ = await created.ReadAsync(null, cancellationToken).ConfigureAwait(false);
            }
            try
            {
                InvokeFault(faultInjector, SqliteDeepAccountStoreLifecycleFaultPoint.AfterTemporaryDatabaseCreated);
            }
            catch (SqliteDeepAccountStoreSimulatedCrashException)
            {
                preserveCrashArtifacts = true;
                throw;
            }
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, fullPath, overwrite: false);
            InvokeFault(faultInjector, SqliteDeepAccountStoreLifecycleFaultPoint.AfterDatabaseMoved);
        }
        finally
        {
            if (!preserveCrashArtifacts)
            {
                DeleteDatabaseArtifacts(temporaryPath);
            }
        }
    }

    private static byte[] CreateRecord()
    {
        var result = new byte[RecordSize];
        RecordMagic.CopyTo(result, 0);
        result[4] = RecordVersion;
        result[5] = 1;
        RandomNumberGenerator.Fill(result.AsSpan(8, 64));
        if (result.AsSpan(8, 32).IndexOfAnyExcept((byte)0) < 0
            || result.AsSpan(40, 32).IndexOfAnyExcept((byte)0) < 0)
        {
            CryptographicOperations.ZeroMemory(result);
            return CreateRecord();
        }
        return result;
    }

    private static DatabaseGenerationRecord DecodeRecord(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != RecordSize
            || !encoded[..4].SequenceEqual(RecordMagic)
            || encoded[4] != RecordVersion
            || encoded[5] != 1
            || encoded[6] != 0
            || encoded[7] != 0)
        {
            throw ResetRequired("The database generation record is malformed or unsupported.");
        }
        return new DatabaseGenerationRecord(encoded.Slice(8, 32), encoded.Slice(40, 32));
    }

    private static async Task<bool> SecureAccountStateExistsAsync(
        IDeepSecureStorage secureStorage,
        CancellationToken cancellationToken)
    {
        using var manifest = await secureStorage
            .ReadOwnedAsync(DeepAccountStoreContract.DatabaseAccountManifestSlot, cancellationToken)
            .ConfigureAwait(false);
        using var pending = await secureStorage
            .ReadOwnedAsync(DeepAccountStoreContract.PendingAccountSlot, cancellationToken)
            .ConfigureAwait(false);
        return manifest is not null || pending is not null;
    }

    private static async Task<bool> AnyAccountSlotExistsAsync(
        IDeepSecureStorage secureStorage,
        DeepSecureStorageSlots slots,
        CancellationToken cancellationToken)
    {
        foreach (var slot in AccountSlots(slots))
        {
            using var value = await secureStorage.ReadOwnedAsync(slot, cancellationToken)
                .ConfigureAwait(false);
            if (value is not null)
            {
                return true;
            }
        }
        return false;
    }

    private static string[] AccountSlots(DeepSecureStorageSlots slots) =>
    [
        slots.DeviceSigningKey,
        slots.DeviceAgreementKey,
        slots.DeviceId,
        slots.DeviceRevocationHandle,
        slots.DevicePrekey,
        slots.PushKey,
        slots.MessageStoreInstanceId
    ];

    private static async Task<FileStream> AcquireExclusiveFileLockAsync(
        string lockPath,
        CancellationToken cancellationToken) =>
        await AcquireFileLockAsync(
                lockPath,
                FileAccess.ReadWrite,
                FileShare.None,
                cancellationToken)
            .ConfigureAwait(false);

    private static async Task<FileStream> AcquireFileLockAsync(
        string lockPath,
        FileAccess access,
        FileShare share,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(lockPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    lockPath,
                    FileMode.OpenOrCreate,
                    access,
                    share,
                    1,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);
            }
            catch (IOException)
            {
                await Task.Delay(25, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static bool DatabaseGenerationArtifactsExist(string path) =>
        DatabaseArtifactsExist(path) || DatabaseArtifactsExist(path + ".creating");

    private static bool DatabaseArtifactsExist(string path) =>
        File.Exists(path) || File.Exists(path + "-wal") || File.Exists(path + "-shm");

    private static void DeleteDatabaseGenerationArtifacts(string path)
    {
        DeleteDatabaseArtifacts(path);
        DeleteDatabaseArtifacts(path + ".creating");
    }

    private static void DeleteDatabaseArtifacts(string path)
    {
        foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
        {
            if (File.Exists(candidate))
            {
                File.Delete(candidate);
            }
        }
    }

    private static void InvokeFault(
        Action<SqliteDeepAccountStoreLifecycleFaultPoint>? faultInjector,
        SqliteDeepAccountStoreLifecycleFaultPoint point)
    {
        if (faultInjector is null)
        {
            return;
        }
        try
        {
            faultInjector(point);
        }
        catch (Exception exception)
        {
            throw new SqliteDeepAccountStoreSimulatedCrashException(point, exception);
        }
    }

    private static LocalStateResetRequiredException ResetRequired(string message, Exception? inner = null) =>
        new(LocalStateResetRequiredReason.UnreadableOrWrongKey, message, inner);

    private sealed class DatabaseGenerationRecord : IDisposable
    {
        private readonly byte[] instanceId;
        private readonly byte[] key;

        internal DatabaseGenerationRecord(ReadOnlySpan<byte> instanceId, ReadOnlySpan<byte> key)
        {
            if (instanceId.Length != 32 || instanceId.IndexOfAnyExcept((byte)0) < 0
                || key.Length != 32 || key.IndexOfAnyExcept((byte)0) < 0)
            {
                throw ResetRequired("The database generation record contains an invalid key or instance ID.");
            }
            this.instanceId = instanceId.ToArray();
            this.key = key.ToArray();
        }

        internal ReadOnlyMemory<byte> InstanceId => instanceId;
        internal ReadOnlyMemory<byte> Key => key;

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(instanceId);
            CryptographicOperations.ZeroMemory(key);
        }
    }

}
