using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Protocol.Identity;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed class SqliteDeepAccountStore : IDeepAccountStore
{
    private const int ApplicationId = 0x44535431; // DST1
    private const int SchemaVersion = DeepAccountStoreContract.CurrentStoreGeneration;
    private const string ExpectedSchemaSha256 = "2213e0a3666600653a13e2a4f5928d5097efb1feb5e9905b33d28fd754f35703";
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly object mutationOwner = new();
    private readonly string connectionString;
    private readonly string mutationLockPath;
    private readonly byte[]? encryptionKey;
    private readonly byte[] databaseInstanceId;
    private readonly IAsyncDisposable generationLease;
    private readonly Action<DeepAccountCommitFaultPoint>? faultInjector;
    private int disposed;

    static SqliteDeepAccountStore() => SQLitePCL.Batteries_V2.Init();

    internal SqliteDeepAccountStore(SqliteDeepAccountStoreOptions options)
        : this(options, null)
    {
    }

    internal SqliteDeepAccountStore(
        SqliteDeepAccountStoreOptions options,
        Action<DeepAccountCommitFaultPoint>? faultInjector)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.StatePath))
        {
            throw new ArgumentException("State path is required.", nameof(options));
        }

        var path = Path.GetFullPath(options.StatePath);
        var mainExists = File.Exists(path);
        var walExists = File.Exists(path + "-wal");
        var shmExists = File.Exists(path + "-shm");
        if (!mainExists && (walExists || shmExists))
        {
            throw ResetRequired("Local Deep account state is incomplete. Reset local data before retrying.");
        }
        if (mainExists && new FileInfo(path).Length == 0)
        {
            throw ResetRequired("Local Deep account state is empty. Reset local data before retrying.");
        }
        if (!mainExists && options.EncryptionKey.IsEmpty)
        {
            throw new ArgumentException("A SQLCipher key is required when creating the Deep account store.", nameof(options));
        }
        if (!options.EncryptionKey.IsEmpty
            && options.EncryptionKey.Length != DeepAccountStoreContract.KeyMaterialSize)
        {
            throw new ArgumentException(
                $"The SQLCipher key must contain exactly {DeepAccountStoreContract.KeyMaterialSize} bytes.",
                nameof(options));
        }
        if (options.DatabaseInstanceId.Length != DeepAccountStoreContract.KeyMaterialSize
            || options.DatabaseInstanceId.Span.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("A nonzero 32-byte database instance ID is required.", nameof(options));
        }
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        };
        connectionString = builder.ToString();
        mutationLockPath = path + ".account.lock";
        encryptionKey = options.EncryptionKey.IsEmpty ? null : options.EncryptionKey.ToArray();
        databaseInstanceId = options.DatabaseInstanceId.ToArray();
        try
        {
            generationLease = options.GenerationLease
                ?? SqliteDeepAccountStoreBootstrap.AcquireSharedGenerationLeaseAsync(path, CancellationToken.None)
                    .GetAwaiter().GetResult();
        }
        catch
        {
            if (encryptionKey is not null)
            {
                CryptographicOperations.ZeroMemory(encryptionKey);
            }
            CryptographicOperations.ZeroMemory(databaseInstanceId);
            throw;
        }
        this.faultInjector = faultInjector;
        try
        {
            Initialize(path);
        }
        catch
        {
            if (encryptionKey is not null)
            {
                CryptographicOperations.ZeroMemory(encryptionKey);
            }
            CryptographicOperations.ZeroMemory(databaseInstanceId);
            generationLease.DisposeAsync().AsTask().GetAwaiter().GetResult();

            throw;
        }
    }

    public async ValueTask<DeepAccountMutationLease> AcquireMutationLeaseAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var stream = new FileStream(
                    mutationLockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);
                if (Volatile.Read(ref disposed) != 0)
                {
                    await stream.DisposeAsync().ConfigureAwait(false);
                    ThrowIfDisposed();
                }
                return new DeepAccountMutationLease(mutationOwner, stream.DisposeAsync);
            }
            catch (IOException)
            {
                await Task.Delay(25, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    public async Task<DeepAccountIdentityCapability?> ReadAccountIdentityAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await connection
                .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            var result = await ReadAccountIdentityCoreAsync(
                    connection,
                    transaction,
                    cancellationToken)
                .ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (SqliteException exception) when (IsCorruption(exception))
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "Local Deep account state is damaged and must be reset.",
                exception);
        }
        catch (Exception exception) when (IsInvalidPersistedValue(exception))
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "Local Deep account values are invalid and must be reset.",
                exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<DeepLocalIdentitySnapshot?> ReadAsync(
        LocalDeviceIdentityIntent? localDeviceIdentity,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await connection
                .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            var account = await ReadAccountAsync(
                    connection,
                    transaction,
                    localDeviceIdentity,
                    cancellationToken)
                .ConfigureAwait(false);
            if (account is null)
            {
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return null;
            }

            var device = await ReadDeviceAsync(
                    connection,
                    transaction,
                    localDeviceIdentity!,
                    cancellationToken)
                .ConfigureAwait(false)
                ?? throw ResetRequired("Local account exists without its device row.");
            var profile = await ReadProfileAsync(connection, transaction, cancellationToken).ConfigureAwait(false)
                ?? throw ResetRequired("Local account exists without its profile row.");
            var result = new DeepLocalIdentitySnapshot(
                SchemaVersion,
                account.Value.NetworkId,
                account.Value.Account,
                device.Device,
                profile,
                device.Slots);
            DeepAccountStoreValidation.Validate(result);
            VerifyImmutableIdentity(result, account.Value.ImmutableIdentityCommitment);
            var operation = await ReadCreationOperationCoreAsync(connection, transaction, cancellationToken)
                .ConfigureAwait(false)
                ?? throw ResetRequired("Local account exists without its creation receipt.");
            if (!operation.MatchesIdentity(result))
                throw ResetRequired(
                    "Local account creation receipt does not match immutable genesis state.");
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (SqliteException exception) when (IsCorruption(exception))
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "Local Deep account state is damaged and must be reset.",
                exception);
        }
        catch (Exception exception) when (IsInvalidPersistedValue(exception))
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "Local Deep account values are invalid and must be reset.",
                exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task CreateAsync(
        DeepAccountReconciledMutationCapability mutationCapability,
        DeepLocalIdentitySnapshot identity,
        DeepAccountCreationOperation operation,
        ReadOnlyMemory<byte> immutableIdentityCommitment,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(mutationCapability);
        await using var mutationUse = await mutationCapability
            .EnterAsync(mutationOwner, cancellationToken)
            .ConfigureAwait(false);
        DeepAccountStoreValidation.Validate(identity);
        ArgumentNullException.ThrowIfNull(operation);
        if (!operation.MatchesIdentity(identity))
        {
            throw new ArgumentException("Creation operation does not match the identity snapshot.", nameof(operation));
        }
        DeepAccountImmutableIdentityHash.Validate(
            immutableIdentityCommitment.Span,
            nameof(immutableIdentityCommitment));
        var actualImmutableCommitment = DeepAccountImmutableIdentityHash.Compute(identity);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    actualImmutableCommitment,
                    immutableIdentityCommitment.Span))
            {
                throw new ArgumentException(
                    "Immutable identity commitment does not match the identity snapshot.",
                    nameof(immutableIdentityCommitment));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualImmutableCommitment);
        }
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            faultInjector?.Invoke(DeepAccountCommitFaultPoint.BeforeTransaction);
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await connection
                .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            await ValidateExpectedStateAsync(
                    connection,
                    transaction,
                    mutationCapability,
                    cancellationToken)
                .ConfigureAwait(false);
            if (await HasAccountAsync(connection, transaction, cancellationToken).ConfigureAwait(false))
            {
                throw new DeepAccountAlreadyExistsException();
            }

            await InsertAccountAsync(
                    connection,
                    transaction,
                    identity,
                    operation,
                    immutableIdentityCommitment,
                    cancellationToken)
                .ConfigureAwait(false);
            faultInjector?.Invoke(DeepAccountCommitFaultPoint.AfterAccount);
            await InsertDeviceAsync(connection, transaction, identity, cancellationToken).ConfigureAwait(false);
            faultInjector?.Invoke(DeepAccountCommitFaultPoint.AfterDevice);
            await InsertProfileAsync(connection, transaction, identity.Profile, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            faultInjector?.Invoke(DeepAccountCommitFaultPoint.BeforeCommit);
            await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(false);
            faultInjector?.Invoke(DeepAccountCommitFaultPoint.AfterCommit);
        }
        catch (SqliteException exception) when (IsCorruption(exception) || IsLateMutationFailure(exception))
        {
            throw ResetRequired("Local Deep account state changed or became unreadable during creation.", exception);
        }
        catch (Exception exception) when (IsInvalidPersistedValue(exception))
        {
            throw ResetRequired("Local Deep account state contains invalid persisted values.", exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<DeepAccountCreationOperation?> ReadCreationOperationAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT creation_operation_id,creation_initial_snapshot_hash FROM local_account WHERE singleton=1;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
                ? DeepAccountCreationOperation.FromPersisted((byte[])reader[0], (byte[])reader[1])
                : null;
        }
        catch (SqliteException exception) when (IsCorruption(exception))
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "Local Deep account creation receipt is damaged and must be reset.",
                exception);
        }
        catch (Exception exception) when (IsInvalidPersistedValue(exception))
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "Local Deep account creation receipt is invalid and must be reset.",
                exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task UpdateProfileAsync(
        DeepAccountReconciledMutationCapability mutationCapability,
        DeepPermanentIdV1 account,
        DeepLocalProfile profile,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(mutationCapability);
        await using var mutationUse = await mutationCapability
            .EnterAsync(mutationOwner, cancellationToken)
            .ConfigureAwait(false);
        DeepAccountStoreValidation.ValidateProfile(profile);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await connection
                .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            await ValidateExpectedStateAsync(
                    connection,
                    transaction,
                    mutationCapability,
                    cancellationToken)
                .ConfigureAwait(false);
            await using var accountCommand = connection.CreateCommand();
            accountCommand.Transaction = transaction;
            accountCommand.CommandText = "UPDATE local_account SET display_name=$name WHERE singleton=1 AND deep_id=$deepId;";
            accountCommand.Parameters.AddWithValue("$name", profile.DisplayName);
            accountCommand.Parameters.AddWithValue("$deepId", account.CanonicalText);
            if (await accountCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            {
                throw new InvalidOperationException("Profile account does not match the local Deep account.");
            }

            await using var profileCommand = connection.CreateCommand();
            profileCommand.Transaction = transaction;
            profileCommand.CommandText = "UPDATE local_profile SET display_name=$name, updated_at=$updatedAt WHERE singleton=1;";
            profileCommand.Parameters.AddWithValue("$name", profile.DisplayName);
            profileCommand.Parameters.AddWithValue("$updatedAt", profile.UpdatedAt.ToUnixTimeMilliseconds());
            if (await profileCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            {
                throw ResetRequired("Local profile row is missing.");
            }

            await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (SqliteException exception) when (IsCorruption(exception) || IsLateMutationFailure(exception))
        {
            throw ResetRequired("Local Deep account state changed or became unreadable during profile update.", exception);
        }
        catch (Exception exception) when (IsInvalidPersistedValue(exception))
        {
            throw ResetRequired("Local Deep account state contains invalid persisted values.", exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task ClearLocalAccountAsync(
        DeepAccountReconciledMutationCapability mutationCapability,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(mutationCapability);
        await using var mutationUse = await mutationCapability
            .EnterAsync(mutationOwner, cancellationToken)
            .ConfigureAwait(false);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await connection
                .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            await ValidateExpectedStateAsync(
                    connection,
                    transaction,
                    mutationCapability,
                    cancellationToken)
                .ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                DELETE FROM security_events;
                DELETE FROM protected_lkg_root;
                DELETE FROM outbox_root;
                DELETE FROM inbox_root;
                DELETE FROM local_account;
                """;
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (SqliteException exception) when (IsCorruption(exception) || IsLateMutationFailure(exception))
        {
            throw ResetRequired("Local Deep account state changed or became unreadable during reset.", exception);
        }
        catch (Exception exception) when (IsInvalidPersistedValue(exception))
        {
            throw ResetRequired("Local Deep account state contains invalid persisted values.", exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
        {
            await gate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (encryptionKey is not null)
                {
                    CryptographicOperations.ZeroMemory(encryptionKey);
                }
                CryptographicOperations.ZeroMemory(databaseInstanceId);
                await generationLease.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        }
    }

    public DeepSecureStorageSlots GetGenerationSecureStorageSlots()
    {
        try
        {
            gate.Wait();
        }
        catch (ObjectDisposedException)
        {
            throw new ObjectDisposedException(nameof(SqliteDeepAccountStore));
        }

        try
        {
            ThrowIfDisposed();
            return DeepSecureStorageSlots.CreateForGeneration(databaseInstanceId);
        }
        finally
        {
            gate.Release();
        }
    }

    private void Initialize(string path)
    {
        var existed = File.Exists(path);
        try
        {
            using var connection = new SqliteConnection(connectionString);
            connection.Open();
            ApplyEncryptionKey(connection);
            Configure(connection);
            ValidateCipher(connection);
            using var transaction = connection.BeginTransaction();
            if (existed)
            {
                ValidateSchema(connection, transaction);
            }
            else
            {
                using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = $"""
                    CREATE TABLE local_account (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        network_id BLOB NOT NULL CHECK(length(network_id)=16),
                        account_generation INTEGER NOT NULL CHECK(account_generation=1),
                        account_id BLOB NOT NULL UNIQUE CHECK(length(account_id)=32),
                        account_signing_public_key BLOB NOT NULL CHECK(length(account_signing_public_key)=32),
                        immutable_identity_hash BLOB NOT NULL CHECK(length(immutable_identity_hash)=32),
                        creation_operation_id BLOB NOT NULL UNIQUE CHECK(length(creation_operation_id)=32),
                        creation_initial_snapshot_hash BLOB NOT NULL CHECK(length(creation_initial_snapshot_hash)=32),
                        deep_id TEXT NOT NULL UNIQUE,
                        display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128 AND length(CAST(display_name AS BLOB)) BETWEEN 1 AND 256),
                        registered_at INTEGER NOT NULL,
                        activation_state INTEGER NOT NULL CHECK(activation_state IN (1,2)),
                        current_device_id BLOB NOT NULL UNIQUE CHECK(length(current_device_id)=32)
                    );
                    CREATE TABLE store_identity (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        database_instance_id BLOB NOT NULL UNIQUE CHECK(length(database_instance_id)=32),
                        cipher_generation INTEGER NOT NULL CHECK(cipher_generation=1)
                    );
                    INSERT INTO store_identity(singleton,database_instance_id,cipher_generation)
                    VALUES(1,X'{Convert.ToHexString(databaseInstanceId)}',1);
                    CREATE TABLE local_device (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        device_id BLOB NOT NULL UNIQUE CHECK(length(device_id)=32),
                        device_generation INTEGER NOT NULL CHECK(device_generation=1),
                        signing_public_key BLOB NOT NULL CHECK(length(signing_public_key)=32),
                        agreement_public_key BLOB NOT NULL CHECK(length(agreement_public_key)=32),
                        revocation_handle BLOB NOT NULL UNIQUE CHECK(length(revocation_handle)=32),
                        prekey_public_key BLOB NOT NULL CHECK(length(prekey_public_key)=32),
                        created_at INTEGER NOT NULL,
                        signing_slot TEXT NOT NULL UNIQUE,
                        agreement_slot TEXT NOT NULL UNIQUE,
                        device_id_slot TEXT NOT NULL UNIQUE,
                        revocation_handle_slot TEXT NOT NULL UNIQUE,
                        prekey_slot TEXT NOT NULL UNIQUE,
                        push_slot TEXT NOT NULL UNIQUE,
                        message_store_instance_slot TEXT NOT NULL UNIQUE,
                        FOREIGN KEY(singleton) REFERENCES local_account(singleton) ON DELETE CASCADE
                    );
                    CREATE TABLE local_profile (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128 AND length(CAST(display_name AS BLOB)) BETWEEN 1 AND 256),
                        updated_at INTEGER NOT NULL,
                        FOREIGN KEY(singleton) REFERENCES local_account(singleton) ON DELETE CASCADE
                    );
                    CREATE TABLE protected_lkg_root (root_kind INTEGER PRIMARY KEY, revision INTEGER NOT NULL, payload BLOB NOT NULL);
                    CREATE TABLE outbox_root (root_kind INTEGER PRIMARY KEY, revision INTEGER NOT NULL, payload BLOB NOT NULL);
                    CREATE TABLE inbox_root (root_kind INTEGER PRIMARY KEY, revision INTEGER NOT NULL, payload BLOB NOT NULL);
                    CREATE TABLE security_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at INTEGER NOT NULL, event_kind INTEGER NOT NULL, payload BLOB NOT NULL);
                    PRAGMA application_id={ApplicationId};
                    PRAGMA user_version={SchemaVersion};
                    """;
                command.ExecuteNonQuery();
                ValidateSchema(connection, transaction);
            }

            transaction.Commit();
        }
        catch (LocalStateResetRequiredException)
        {
            throw;
        }
        catch (SqliteException exception) when (IsCorruption(exception))
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.UnreadableOrWrongKey,
                "Local Deep account state is unreadable, uses another key, or has an unsupported schema. Reset local data before retrying.",
                exception);
        }
        catch (Exception exception) when (IsInvalidPersistedValue(exception))
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "Local Deep account schema or store identity contains invalid persisted values and must be reset.",
                exception);
        }
    }

    private void ValidateSchema(SqliteConnection connection, SqliteTransaction transaction)
    {
        if (ReadPragma(connection, transaction, "application_id") != ApplicationId
            || ReadPragma(connection, transaction, "user_version") != SchemaVersion)
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.UnsupportedVersion,
                $"Only Deep account store generation {SchemaVersion} is supported. Reset old local state before retrying.");
        }

        var schemaFingerprint = ComputeSchemaFingerprint(connection, transaction);
        if (!string.Equals(schemaFingerprint, ExpectedSchemaSha256, StringComparison.Ordinal))
        {
            throw ResetRequired(
                $"Local Deep account schema fingerprint {schemaFingerprint} is not the exact current generation.");
        }

        var expected = new[]
        {
            "inbox_root", "local_account", "local_device", "local_profile", "outbox_root",
            "protected_lkg_root", "security_events", "store_identity"
        };
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;";
        using var reader = command.ExecuteReader();
        var actual = new List<string>();
        while (reader.Read())
        {
            actual.Add(reader.GetString(0));
        }

        if (!actual.SequenceEqual(expected, StringComparer.Ordinal))
        {
            throw ResetRequired("Local Deep account schema is not the exact current generation.");
        }

        ValidateColumns(connection, transaction, "local_account",
        [
            ("singleton", "INTEGER", 1), ("network_id", "BLOB", 0),
            ("account_generation", "INTEGER", 0), ("account_id", "BLOB", 0),
            ("account_signing_public_key", "BLOB", 0), ("immutable_identity_hash", "BLOB", 0),
            ("creation_operation_id", "BLOB", 0), ("creation_initial_snapshot_hash", "BLOB", 0),
            ("deep_id", "TEXT", 0),
            ("display_name", "TEXT", 0), ("registered_at", "INTEGER", 0),
            ("activation_state", "INTEGER", 0), ("current_device_id", "BLOB", 0)
        ]);
        ValidateColumns(connection, transaction, "local_device",
        [
            ("singleton", "INTEGER", 1), ("device_id", "BLOB", 0),
            ("device_generation", "INTEGER", 0), ("signing_public_key", "BLOB", 0),
            ("agreement_public_key", "BLOB", 0), ("revocation_handle", "BLOB", 0),
            ("prekey_public_key", "BLOB", 0), ("created_at", "INTEGER", 0),
            ("signing_slot", "TEXT", 0),
            ("agreement_slot", "TEXT", 0), ("device_id_slot", "TEXT", 0),
            ("revocation_handle_slot", "TEXT", 0), ("prekey_slot", "TEXT", 0),
            ("push_slot", "TEXT", 0), ("message_store_instance_slot", "TEXT", 0)
        ]);
        ValidateColumns(connection, transaction, "local_profile",
        [
            ("singleton", "INTEGER", 1), ("display_name", "TEXT", 0),
            ("updated_at", "INTEGER", 0)
        ]);
        foreach (var root in new[] { "protected_lkg_root", "outbox_root", "inbox_root" })
        {
            ValidateColumns(connection, transaction, root,
            [
                ("root_kind", "INTEGER", 1), ("revision", "INTEGER", 0),
                ("payload", "BLOB", 0)
            ]);
        }
        ValidateColumns(connection, transaction, "security_events",
        [
            ("sequence", "INTEGER", 1), ("occurred_at", "INTEGER", 0),
            ("event_kind", "INTEGER", 0), ("payload", "BLOB", 0)
        ]);
        ValidateColumns(connection, transaction, "store_identity",
        [
            ("singleton", "INTEGER", 1), ("database_instance_id", "BLOB", 0),
            ("cipher_generation", "INTEGER", 0)
        ]);
        using var identityCommand = connection.CreateCommand();
        identityCommand.Transaction = transaction;
        identityCommand.CommandText = "SELECT database_instance_id,cipher_generation FROM store_identity WHERE singleton=1;";
        using var identityReader = identityCommand.ExecuteReader();
        if (!identityReader.Read()
            || identityReader.GetInt32(1) != 1
            || !CryptographicOperations.FixedTimeEquals((byte[])identityReader[0], databaseInstanceId)
            || identityReader.Read())
        {
            throw ResetRequired("Local database instance identity does not match secure storage.");
        }
    }

    private static string ComputeSchemaFingerprint(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT type,name,tbl_name,coalesce(sql,'')
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type,name,tbl_name;
            """;
        using var reader = command.ExecuteReader();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[sizeof(uint)];
        while (reader.Read())
        {
            for (var column = 0; column < 4; column++)
            {
                var value = reader.GetString(column);
                // sqlite_schema preserves whitespace from the submitted DDL. Keep the
                // sealed fingerprint independent of Git checkout line endings so the
                // same store generation is accepted on Windows and Unix builds.
                if (column == 3)
                {
                    value = value.ReplaceLineEndings("\n");
                }
                var bytes = Encoding.UTF8.GetBytes(value);
                try
                {
                    BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
                    hash.AppendData(length);
                    hash.AppendData(bytes);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static void ValidateColumns(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string table,
        IReadOnlyList<(string Name, string Type, int PrimaryKey)> expected)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA table_info(\"{table}\");";
        using var reader = command.ExecuteReader();
        var index = 0;
        while (reader.Read())
        {
            if (index >= expected.Count)
            {
                throw ResetRequired($"Local Deep account table {table} has extra columns.");
            }

            var column = expected[index++];
            if (!string.Equals(reader.GetString(1), column.Name, StringComparison.Ordinal)
                || !string.Equals(reader.GetString(2), column.Type, StringComparison.Ordinal)
                || reader.GetInt32(5) != column.PrimaryKey)
            {
                throw ResetRequired(
                    $"Local Deep account table {table} column {index - 1} is incompatible " +
                    $"(expected {column.Name}/{column.Type}/pk={column.PrimaryKey}, " +
                    $"found {reader.GetString(1)}/{reader.GetString(2)}/pk={reader.GetInt32(5)}).");
            }
        }

        if (index != expected.Count)
        {
            throw ResetRequired($"Local Deep account table {table} is missing columns.");
        }
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            ApplyEncryptionKey(connection);
            Configure(connection);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static void Configure(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;";
        command.ExecuteNonQuery();
    }

    private static void ValidateCipher(SqliteConnection connection)
    {
        using var version = connection.CreateCommand();
        version.CommandText = "PRAGMA cipher_version;";
        var cipherVersion = Convert.ToString(
            version.ExecuteScalar(),
            System.Globalization.CultureInfo.InvariantCulture);
        if (string.IsNullOrWhiteSpace(cipherVersion)
            || !cipherVersion.StartsWith("4.", StringComparison.Ordinal))
        {
            throw ResetRequired("SQLCipher generation 4 is required.");
        }

        using var integrity = connection.CreateCommand();
        integrity.CommandText = "PRAGMA cipher_integrity_check;";
        using var reader = integrity.ExecuteReader();
        if (reader.Read())
        {
            throw ResetRequired("SQLCipher integrity verification failed.");
        }
    }

    private void ApplyEncryptionKey(SqliteConnection connection)
    {
        if (encryptionKey is null)
        {
            return;
        }

        var result = SQLitePCL.raw.sqlite3_key(connection.Handle, encryptionKey);
        if (result != SQLitePCL.raw.SQLITE_OK)
        {
            throw new SqliteException("SQLCipher rejected the database key.", result);
        }
    }

    private static int ReadPragma(SqliteConnection connection, SqliteTransaction transaction, string name)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA {name};";
        return Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<bool> HasAccountAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT EXISTS(SELECT 1 FROM local_account WHERE singleton=1);";
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) == 1;
    }

    private static async Task ValidateExpectedStateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DeepAccountReconciledMutationCapability capability,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT creation_operation_id,creation_initial_snapshot_hash,immutable_identity_hash FROM local_account WHERE singleton=1;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (capability.ExpectedOperation is not null)
            {
                throw new InvalidOperationException("The reconciled mutation capability is stale.");
            }
            return;
        }

        if (capability.ExpectedOperation is null)
        {
            throw new InvalidOperationException("The reconciled empty-store capability is stale.");
        }
        var operation = DeepAccountCreationOperation.FromPersisted(
            (byte[])reader[0],
            (byte[])reader[1]);
        var immutableIdentityCommitment = (byte[])reader[2];
        if (!operation.Matches(capability.ExpectedOperation)
            || !CryptographicOperations.FixedTimeEquals(
                immutableIdentityCommitment,
                capability.ExpectedImmutableIdentityCommitment))
        {
            throw new InvalidOperationException("The reconciled mutation capability is stale.");
        }
    }

    private static void VerifyImmutableIdentity(
        DeepLocalIdentitySnapshot identity,
        ReadOnlySpan<byte> expectedCommitment)
    {
        DeepAccountImmutableIdentityHash.Validate(expectedCommitment, nameof(expectedCommitment));
        var actual = DeepAccountImmutableIdentityHash.Compute(identity);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expectedCommitment, actual))
            {
                throw ResetRequired(
                    "Local Deep account immutable identity commitment does not match current state.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static async Task<DeepAccountCreationOperation?> ReadCreationOperationCoreAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT creation_operation_id,creation_initial_snapshot_hash FROM local_account WHERE singleton=1;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? DeepAccountCreationOperation.FromPersisted((byte[])reader[0], (byte[])reader[1])
            : null;
    }

    private static async Task InsertAccountAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DeepLocalIdentitySnapshot identity,
        DeepAccountCreationOperation operation,
        ReadOnlyMemory<byte> immutableIdentityCommitment,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO local_account(singleton,network_id,account_generation,account_id,account_signing_public_key,immutable_identity_hash,creation_operation_id,creation_initial_snapshot_hash,deep_id,display_name,registered_at,activation_state,current_device_id)
            VALUES(1,$network,$generation,$accountId,$accountPublic,$immutableIdentityHash,$operationId,$initialSnapshotHash,$deepId,$display,$registered,$state,$deviceId);
            """;
        command.Parameters.AddWithValue("$network", identity.NetworkId.ToArray());
        command.Parameters.AddWithValue("$generation", checked((long)identity.Account.AccountIdentity.AccountGeneration));
        command.Parameters.AddWithValue("$accountId", identity.Account.AccountIdentity.AccountId.Bytes.ToArray());
        command.Parameters.AddWithValue("$accountPublic", identity.Account.AccountIdentity.AccountSigningPublicKey.Bytes.ToArray());
        command.Parameters.AddWithValue("$immutableIdentityHash", immutableIdentityCommitment.ToArray());
        command.Parameters.AddWithValue("$operationId", operation.OperationId.ToArray());
        command.Parameters.AddWithValue("$initialSnapshotHash", operation.InitialSnapshotHash.ToArray());
        command.Parameters.AddWithValue("$deepId", identity.Account.PermanentId.CanonicalText);
        command.Parameters.AddWithValue("$display", identity.Account.DisplayName);
        command.Parameters.AddWithValue("$registered", identity.Account.RegisteredAt.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$state", (int)identity.Account.ActivationState);
        command.Parameters.AddWithValue("$deviceId", identity.Device.DeviceId.Bytes.ToArray());
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task InsertDeviceAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DeepLocalIdentitySnapshot identity,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO local_device(singleton,device_id,device_generation,signing_public_key,agreement_public_key,revocation_handle,prekey_public_key,created_at,signing_slot,agreement_slot,device_id_slot,revocation_handle_slot,prekey_slot,push_slot,message_store_instance_slot)
            VALUES(1,$deviceId,$deviceGeneration,$signing,$agreement,$revocation,$prekey,$created,$signingSlot,$agreementSlot,$deviceIdSlot,$revocationSlot,$prekeySlot,$pushSlot,$messageStoreInstanceSlot);
            """;
        command.Parameters.AddWithValue("$deviceId", identity.Device.DeviceId.Bytes.ToArray());
        command.Parameters.AddWithValue("$deviceGeneration", checked((long)identity.Device.DeviceGeneration));
        command.Parameters.AddWithValue("$signing", identity.Device.SigningPublicKey.ToArray());
        command.Parameters.AddWithValue("$agreement", identity.Device.AgreementPublicKey.ToArray());
        command.Parameters.AddWithValue("$revocation", identity.Device.RevocationHandle.Bytes.ToArray());
        command.Parameters.AddWithValue("$prekey", identity.Device.PrekeyPublicKey.ToArray());
        command.Parameters.AddWithValue("$created", identity.Device.CreatedAt.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$signingSlot", identity.SecureSlots.DeviceSigningKey);
        command.Parameters.AddWithValue("$agreementSlot", identity.SecureSlots.DeviceAgreementKey);
        command.Parameters.AddWithValue("$deviceIdSlot", identity.SecureSlots.DeviceId);
        command.Parameters.AddWithValue("$revocationSlot", identity.SecureSlots.DeviceRevocationHandle);
        command.Parameters.AddWithValue("$prekeySlot", identity.SecureSlots.DevicePrekey);
        command.Parameters.AddWithValue("$pushSlot", identity.SecureSlots.PushKey);
        command.Parameters.AddWithValue(
            "$messageStoreInstanceSlot",
            identity.SecureSlots.MessageStoreInstanceId);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task InsertProfileAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DeepLocalProfile profile,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO local_profile(singleton,display_name,updated_at) VALUES(1,$display,$updated);";
        command.Parameters.AddWithValue("$display", profile.DisplayName);
        command.Parameters.AddWithValue("$updated", profile.UpdatedAt.ToUnixTimeMilliseconds());
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<DeepAccountIdentityCapability?> ReadAccountIdentityCoreAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT a.network_id,a.account_generation,a.account_id,a.account_signing_public_key,
                   a.immutable_identity_hash,a.creation_operation_id,a.creation_initial_snapshot_hash,
                   a.deep_id,a.registered_at,
                   d.device_id,d.device_generation,d.signing_public_key,d.agreement_public_key,
                   d.revocation_handle,d.prekey_public_key,d.created_at
            FROM local_account AS a
            LEFT JOIN local_device AS d ON d.singleton=a.singleton
            WHERE a.singleton=1;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var networkId = (byte[])reader[0];
        var accountGeneration = checked((ulong)reader.GetInt64(1));
        var accountId = (byte[])reader[2];
        var accountPublicKey = (byte[])reader[3];
        var identity = DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(networkId),
            accountGeneration,
            AccountEd25519PublicKey32.FromVerifiedBytes(accountPublicKey));
        if (!identity.AccountId.Matches(accountId))
        {
            throw ResetRequired("Stored Deep account ID does not match its verified identity inputs.");
        }

        var expectedCommitment = (byte[])reader[4];
        DeepAccountImmutableIdentityHash.Validate(
            expectedCommitment,
            nameof(expectedCommitment));
        var operation = DeepAccountCreationOperation.FromPersisted(
            (byte[])reader[5],
            (byte[])reader[6]);
        var deepId = DeepPermanentIdV1.ParseCanonical(reader.GetString(7));
        var deviceId = RequiredNonzero32((byte[])reader[9], "Stored genesis device ID");
        var deviceGeneration = checked((ulong)reader.GetInt64(10));
        var deviceSigningPublicKey = RequiredNonzero32(
            (byte[])reader[11], "Stored genesis device signing key");
        var deviceAgreementPublicKey = RequiredNonzero32(
            (byte[])reader[12], "Stored genesis device agreement key");
        var revocationHandle = RequiredNonzero32(
            (byte[])reader[13], "Stored genesis device revocation handle");
        var prekeyPublicKey = RequiredNonzero32(
            (byte[])reader[14], "Stored genesis device prekey");
        var actualCommitment = ComputePersistedGenesisCommitment(
            "Deep/Store/V1/immutable-identity"u8,
            networkId,
            deepId.CanonicalText,
            accountId,
            accountGeneration,
            accountPublicKey,
            deviceId,
            deviceGeneration,
            revocationHandle,
            deviceSigningPublicKey,
            deviceAgreementPublicKey,
            prekeyPublicKey,
            reader.GetInt64(15));
        var actualCreationSnapshotHash = ComputePersistedGenesisCommitment(
            "Deep/Store/V1/account-creation"u8,
            networkId,
            deepId.CanonicalText,
            accountId,
            accountGeneration,
            accountPublicKey,
            deviceId,
            deviceGeneration,
            revocationHandle,
            deviceSigningPublicKey,
            deviceAgreementPublicKey,
            prekeyPublicKey,
            reader.GetInt64(15));
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expectedCommitment, actualCommitment))
            {
                throw ResetRequired(
                    "Stored Deep account immutable identity commitment does not match current state.");
            }
            if (!CryptographicOperations.FixedTimeEquals(
                    operation.InitialSnapshotHash.Span,
                    actualCreationSnapshotHash))
            {
                throw ResetRequired(
                    "Stored Deep account creation receipt does not match immutable genesis state.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualCommitment);
            CryptographicOperations.ZeroMemory(actualCreationSnapshotHash);
        }
        return identity;
    }

    private static byte[] ComputePersistedGenesisCommitment(
        ReadOnlySpan<byte> domain,
        ReadOnlySpan<byte> networkId,
        string canonicalDeepId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> accountPublicKey,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> revocationHandle,
        ReadOnlySpan<byte> deviceSigningPublicKey,
        ReadOnlySpan<byte> deviceAgreementPublicKey,
        ReadOnlySpan<byte> prekeyPublicKey,
        long deviceCreatedAtUnixMilliseconds)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendCommitment(hash, domain);
        AppendCommitmentInt32(hash, SchemaVersion);
        AppendCommitment(hash, networkId);
        AppendCommitmentUtf8(hash, canonicalDeepId);
        AppendCommitment(hash, accountId);
        AppendCommitmentUInt64(hash, accountGeneration);
        AppendCommitment(hash, accountPublicKey);
        AppendCommitment(hash, deviceId);
        AppendCommitmentUInt64(hash, deviceGeneration);
        AppendCommitment(hash, revocationHandle);
        AppendCommitment(hash, deviceSigningPublicKey);
        AppendCommitment(hash, deviceAgreementPublicKey);
        AppendCommitment(hash, prekeyPublicKey);
        AppendCommitmentInt64(hash, deviceCreatedAtUnixMilliseconds);
        return hash.GetHashAndReset();
    }

    private static byte[] RequiredNonzero32(byte[] value, string name)
    {
        if (value.Length != DeepAccountStoreContract.KeyMaterialSize
            || value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw ResetRequired($"{name} is invalid.");
        return value;
    }

    private static void AppendCommitment(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static void AppendCommitmentUtf8(IncrementalHash hash, string value)
    {
        var utf8 = Encoding.UTF8.GetBytes(value);
        try
        {
            AppendCommitment(hash, utf8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
        }
    }

    private static void AppendCommitmentInt32(IncrementalHash hash, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        AppendCommitment(hash, bytes);
    }

    private static void AppendCommitmentInt64(IncrementalHash hash, long value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(bytes, value);
        AppendCommitment(hash, bytes);
    }

    private static void AppendCommitmentUInt64(IncrementalHash hash, ulong value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        AppendCommitment(hash, bytes);
    }

    private static async Task<(DeepAccount Account, byte[] NetworkId, byte[] ImmutableIdentityCommitment)?> ReadAccountAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        LocalDeviceIdentityIntent? localDeviceIdentity,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT network_id,account_generation,account_id,account_signing_public_key,immutable_identity_hash,deep_id,display_name,registered_at,activation_state,current_device_id FROM local_account WHERE singleton=1;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var network = (byte[])reader[0];
        var accountId = (byte[])reader[2];
        var accountIdentity = DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(network),
            checked((ulong)reader.GetInt64(1)),
            AccountEd25519PublicKey32.FromVerifiedBytes((byte[])reader[3]));
        if (!accountIdentity.AccountId.Matches(accountId))
        {
            throw ResetRequired("Stored Deep account ID does not match its verified identity inputs.");
        }
        if (localDeviceIdentity is null
            || !localDeviceIdentity.AccountIdentity.Equals(accountIdentity)
            || !localDeviceIdentity.DeviceId.Matches((byte[])reader[9]))
        {
            throw ResetRequired(
                "The supplied owned local-device intent does not match the persisted account.");
        }
        var account = new DeepAccount(
            DeepPermanentIdV1.ParseCanonical(reader.GetString(5)),
            accountIdentity,
            reader.GetString(6),
            DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(7)),
            (DeepAccountActivationState)reader.GetInt32(8),
            localDeviceIdentity.DeviceId);
        var immutableIdentityCommitment = (byte[])reader[4];
        DeepAccountImmutableIdentityHash.Validate(
            immutableIdentityCommitment,
            nameof(immutableIdentityCommitment));
        return (account, network, immutableIdentityCommitment);
    }

    private static async Task<(DeepDevice Device, DeepSecureStorageSlots Slots)?> ReadDeviceAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        LocalDeviceIdentityIntent localDeviceIdentity,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT device_id,device_generation,signing_public_key,agreement_public_key,revocation_handle,prekey_public_key,created_at,signing_slot,agreement_slot,device_id_slot,revocation_handle_slot,prekey_slot,push_slot,message_store_instance_slot FROM local_device WHERE singleton=1;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var persistedGeneration = checked((ulong)reader.GetInt64(1));
        if (!localDeviceIdentity.DeviceId.Matches((byte[])reader[0])
            || localDeviceIdentity.DeviceGeneration != persistedGeneration
            || !localDeviceIdentity.SigningPublicKey.Matches((byte[])reader[2])
            || !localDeviceIdentity.AgreementPublicKey.Matches((byte[])reader[3])
            || !localDeviceIdentity.RevocationHandle.Matches((byte[])reader[4]))
        {
            throw ResetRequired(
                "The supplied owned local-device intent does not match the persisted device.");
        }

        return (
            new DeepDevice(
                localDeviceIdentity,
                (byte[])reader[5],
                DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(6))),
            new DeepSecureStorageSlots(
                reader.GetString(7), reader.GetString(8), reader.GetString(9),
                reader.GetString(10), reader.GetString(11), reader.GetString(12),
                reader.GetString(13)));
    }

    private static async Task<DeepLocalProfile?> ReadProfileAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT display_name,updated_at FROM local_profile WHERE singleton=1;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? new DeepLocalProfile(reader.GetString(0), DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(1)))
            : null;
    }

    private static bool IsCorruption(SqliteException exception) =>
        (exception.SqliteExtendedErrorCode & 0xff) is 11 or 26;

    private static bool IsInvalidPersistedValue(Exception exception) =>
        exception is ArgumentException
            or OverflowException
            or InvalidCastException
            or FormatException
            or IndexOutOfRangeException
        || exception is SqliteException sqlite
            && (sqlite.SqliteExtendedErrorCode & 0xff) is 1 or 11 or 17 or 20 or 24 or 26;

    private static bool IsLateMutationFailure(SqliteException exception) =>
        (exception.SqliteExtendedErrorCode & 0xff) is 1 or 11 or 17 or 20 or 24 or 26;

    private static LocalStateResetRequiredException ResetRequired(
        string message,
        Exception? inner = null) =>
        new(LocalStateResetRequiredReason.InvalidCurrentSchema, message, inner);

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed != 0, this);
}

internal sealed class SqliteDeepAccountStoreOptions
{
    public SqliteDeepAccountStoreOptions(
        string statePath,
        ReadOnlyMemory<byte> encryptionKey,
        ReadOnlyMemory<byte> databaseInstanceId,
        bool allowCreate = true,
        IAsyncDisposable? generationLease = null)
    {
        StatePath = statePath;
        EncryptionKey = encryptionKey;
        DatabaseInstanceId = databaseInstanceId;
        AllowCreate = allowCreate;
        GenerationLease = generationLease;
    }

    public string StatePath { get; }

    internal ReadOnlyMemory<byte> EncryptionKey { get; }

    internal ReadOnlyMemory<byte> DatabaseInstanceId { get; }

    internal bool AllowCreate { get; }

    internal IAsyncDisposable? GenerationLease { get; }

    public override string ToString() =>
        $"{nameof(SqliteDeepAccountStoreOptions)} {{ StatePath = {(string.IsNullOrWhiteSpace(StatePath) ? "[missing]" : "[configured]")}, EncryptionKey = {(EncryptionKey.IsEmpty ? "[not-configured]" : "[redacted]")} }}";
}
