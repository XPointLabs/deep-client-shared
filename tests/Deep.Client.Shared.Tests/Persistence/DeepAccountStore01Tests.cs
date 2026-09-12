using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.Identity;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class DeepAccountStore01Tests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-08-30T00:00:00Z");
    private static readonly byte[] NetworkId = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray();

    public static TheoryData<bool, bool, bool, bool> MissingOrCorruptLifecycleMetadata
    {
        get
        {
            var data = new TheoryData<bool, bool, bool, bool>();
            foreach (var generationCorrupt in new[] { false, true })
            foreach (var tombstoneCorrupt in new[] { false, true })
            foreach (var manifestCorrupt in new[] { false, true })
            foreach (var pendingCorrupt in new[] { false, true })
            {
                data.Add(generationCorrupt, tombstoneCorrupt, manifestCorrupt, pendingCorrupt);
            }
            return data;
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Create_HasSqliteAndInMemoryParity(bool sqlite)
    {
        var path = TempPath();
        await using var store = CreateStore(sqlite, path);
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);

        var created = await CreateConfirmedAsync(service, " Alice ");
        var stored = await service.GetLocalIdentityAsync();

        Assert.Equal(90, created.Identity.Account.PermanentId.CanonicalText.Length);
        Assert.StartsWith("deep1", created.Identity.Account.PermanentId.CanonicalText, StringComparison.Ordinal);
        Assert.Equal(
            created.Identity.Account.PermanentId.CanonicalText,
            DeepPermanentIdV1.ParseCanonical(created.Identity.Account.PermanentId.CanonicalText).CanonicalText);
        Assert.NotNull(stored);
        Assert.Equal(DeepAccountStoreContract.CurrentStoreGeneration, stored!.StoreGeneration);
        Assert.Equal(DeepAccountStoreContract.CurrentAccountGeneration, stored.Account.AccountIdentity.AccountGeneration);
        Assert.Equal(DeepAccountActivationState.ActiveLocal, stored.Account.ActivationState);
        Assert.Equal("Alice", stored.Account.DisplayName);
        Assert.Equal(stored.Account.CurrentDeviceId, stored.Device.DeviceId);
        Assert.Equal(32, stored.Device.SigningPublicKey.Length);
        Assert.Equal(32, stored.Device.AgreementPublicKey.Length);
        Assert.Equal(32, stored.Device.PrekeyPublicKey.Length);

        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task LocalAccountSurface_ExposesOnlyNonAuthoritativeDeviceIntent()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var created = await CreateConfirmedAsync(
            CreateService(store, secureStorage),
            "Alice");

        var identityProperty = Assert.Single(
            typeof(DeepDevice).GetProperties(),
            static property => string.Equals(
                property.Name,
                nameof(DeepDevice.Identity),
                StringComparison.Ordinal));
        Assert.Equal(typeof(LocalDeviceIdentityIntent), identityProperty.PropertyType);
        Assert.True(created.Identity.Device.Identity.NoAuthorityClaim);
        Assert.DoesNotContain(
            typeof(Deep.Client.Shared.Domain.DeepAccount).Assembly.GetExportedTypes(),
            static type => string.Equals(
                type.Name,
                "DeepDeviceIdentityCapability",
                StringComparison.Ordinal));
        Assert.DoesNotContain(
            typeof(DeepAccountService).GetMethods(),
            static method => method.Name.Contains("DPD", StringComparison.OrdinalIgnoreCase)
                || method.Name.Contains("DXR", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SecureIdentitySlots_RestoreOwnedIntentWithStoreParity(bool sqlite)
    {
        var path = TempPath();
        await using var store = CreateStore(sqlite, path);
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(service, "Alice");

        var restored = Assert.IsType<DeepLocalIdentitySnapshot>(
            await CreateService(store, secureStorage).GetLocalIdentityAsync());

        Assert.Equal(created.Identity.Device.Identity, restored.Device.Identity);
        Assert.True(restored.Device.Identity.NoAuthorityClaim);
        Assert.Equal(store.GetGenerationSecureStorageSlots(), restored.SecureSlots);
        DeleteSqliteFiles(path);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TamperedOwnedIdentitySlot_IsRejectedWithStoreParity(bool sqlite)
    {
        var path = TempPath();
        await using var store = CreateStore(sqlite, path);
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(service, "Alice");
        var slots = created.Identity.SecureSlots;
        var identitySlots = new[]
        {
            slots.DeviceSigningKey,
            slots.DeviceAgreementKey,
            slots.DeviceId,
            slots.DeviceRevocationHandle
        };

        foreach (var slot in identitySlots)
        {
            var original = Assert.IsType<byte[]>(
                await ReadSecretSnapshotAsync(secureStorage, slot));
            var replacement = RandomNumberGenerator.GetBytes(
                DeepAccountStoreContract.KeyMaterialSize);
            try
            {
                await secureStorage.DeleteBatchAsync([slot]);
                await secureStorage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(slot, replacement)]);
                var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
                    service.GetLocalIdentityAsync());
                Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);

                await secureStorage.DeleteBatchAsync([slot]);
                await secureStorage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(slot, original)]);
                Assert.NotNull(await service.GetLocalIdentityAsync());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(original);
                CryptographicOperations.ZeroMemory(replacement);
            }
        }
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task Creation_ZeroesEveryBorrowedDevicePersistenceCopyAfterCommit()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var inner = new InMemoryDeepSecureStorage();
        var capture = new BorrowingWriteCaptureSecureStorage(inner);
        var created = await CreateConfirmedAsync(
            CreateService(store, capture),
            "Alice");
        var slots = created.Identity.SecureSlots;

        foreach (var slot in new[]
                 {
                     slots.DeviceSigningKey,
                     slots.DeviceAgreementKey,
                     slots.DeviceId,
                     slots.DeviceRevocationHandle,
                     slots.DevicePrekey,
                     slots.PushKey,
                     slots.MessageStoreInstanceId
                 })
        {
            Assert.True(capture.BorrowedWrites.TryGetValue(slot, out var borrowed));
            Assert.Equal(DeepAccountStoreContract.KeyMaterialSize, borrowed.Length);
            Assert.True(borrowed.Span.IndexOfAnyExcept((byte)0) < 0);

            var persisted = Assert.IsType<byte[]>(await ReadSecretSnapshotAsync(inner, slot));
            try
            {
                Assert.True(persisted.AsSpan().IndexOfAnyExcept((byte)0) >= 0);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(persisted);
            }
        }
    }

    [Fact]
    public async Task Restore_CreatesSamePermanentDeepIdAndIndependentPendingDevice()
    {
        await using var firstStore = new InMemoryDeepAccountStore();
        using var firstSecureStorage = new InMemoryDeepSecureStorage();
        var firstService = CreateService(firstStore, firstSecureStorage);
        var (created, recoveryBytes) = await CreateConfirmedWithPhraseAsync(firstService, "Alice");

        try
        {
            await using var restoredStore = new InMemoryDeepAccountStore();
            using var restoredSecureStorage = new InMemoryDeepSecureStorage();
            var restoredService = CreateService(restoredStore, restoredSecureStorage);
            using var recovery = DeepOwnedRecoveryPhraseUtf8.CopyFrom(recoveryBytes);
            var restored = await restoredService.RestoreAsNewDeviceAsync(recovery, "Alice restored");

            Assert.Equal(created.Identity.Account.PermanentId, restored.Identity.Account.PermanentId);
            Assert.Equal(created.Identity.Account.AccountIdentity.AccountId, restored.Identity.Account.AccountIdentity.AccountId);
            Assert.NotEqual(created.Identity.Device.DeviceId, restored.Identity.Device.DeviceId);
            Assert.False(created.Identity.Device.SigningPublicKey.Span.SequenceEqual(restored.Identity.Device.SigningPublicKey.Span));
            Assert.False(created.Identity.Device.AgreementPublicKey.Span.SequenceEqual(restored.Identity.Device.AgreementPublicKey.Span));
            Assert.False(created.Identity.Device.PrekeyPublicKey.Span.SequenceEqual(restored.Identity.Device.PrekeyPublicKey.Span));
            Assert.Equal(DeepAccountActivationState.RestorePendingActivation, restored.Identity.Account.ActivationState);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recoveryBytes);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProfileUpdate_AfterClearedCreationJournal_HasStoreParity(bool sqlite)
    {
        var path = TempPath();
        await using var store = CreateStore(sqlite, path);
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(service, "Alice");

        var updated = await service.UpdateDisplayNameAsync(" Alice Updated ");
        var persisted = Assert.IsType<DeepLocalIdentitySnapshot>(await service.GetLocalIdentityAsync());

        Assert.Equal("Alice Updated", updated.DisplayName);
        Assert.Equal("Alice Updated", persisted.Account.DisplayName);
        Assert.Equal("Alice Updated", persisted.Profile.DisplayName);
        Assert.NotNull(await store.ReadCreationOperationAsync());
        Assert.Null(await ReadSecretSnapshotAsync(
            secureStorage,
            DeepAccountService.PendingSecureStorageJournalSlot));
        DeleteSqliteFiles(path);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReadAccountIdentity_VerifiesCommittedIdentityWithStoreParity(bool sqlite)
    {
        var path = TempPath();
        await using var store = CreateStore(sqlite, path);
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(service, "Alice");

        var identity = Assert.IsType<DeepAccountIdentityCapability>(
            await store.ReadAccountIdentityAsync());

        Assert.Equal(created.Identity.Account.AccountIdentity, identity);
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteReadAccountIdentity_RejectsSemanticImmutableCommitmentCorruption()
    {
        var path = TempPath();
        await using var store = new SqliteDeepAccountStore(
            new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId()));
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        _ = await CreateConfirmedAsync(service, "Alice");

        using (var connection = OpenTestDatabase(path))
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE local_account SET immutable_identity_hash=$value WHERE singleton=1;";
            command.Parameters.AddWithValue("$value", Enumerable.Repeat((byte)0xa5, 32).ToArray());
            Assert.Equal(1, command.ExecuteNonQuery());
        }

        var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(
            () => store.ReadAccountIdentityAsync());

        Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
        DeleteSqliteFiles(path);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReadAccountIdentity_RejectsSemanticCreationReceiptCorruptionWithStoreParity(
        bool sqlite)
    {
        var path = TempPath();
        await using var store = CreateStore(sqlite, path);
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        _ = await CreateConfirmedAsync(service, "Alice");
        var replacement = Enumerable.Repeat((byte)0xa5, 32).ToArray();

        if (sqlite)
        {
            using var connection = OpenTestDatabase(path);
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE local_account SET creation_initial_snapshot_hash=$value WHERE singleton=1;";
            command.Parameters.AddWithValue("$value", replacement);
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        else
        {
            var operationField = typeof(InMemoryDeepAccountStore).GetField(
                "creationOperation", BindingFlags.NonPublic | BindingFlags.Instance);
            var operation = Assert.IsType<DeepAccountCreationOperation>(operationField!.GetValue(store));
            var hashField = typeof(DeepAccountCreationOperation).GetField(
                "initialSnapshotHash", BindingFlags.NonPublic | BindingFlags.Instance);
            replacement.CopyTo(Assert.IsType<byte[]>(hashField!.GetValue(operation)), 0);
        }

        var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(
            () => store.ReadAccountIdentityAsync());

        Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
        CryptographicOperations.ZeroMemory(replacement);
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteImmutableIdentityMutationAfterReconciliation_IsRejected()
    {
        var path = TempPath();
        await using var store = new SqliteDeepAccountStore(
            new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId()));
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(service, "Alice");
        var replacementDeviceId = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var connection = OpenTestDatabase(path);
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE local_device SET device_id=$id WHERE singleton=1; UPDATE local_account SET current_device_id=$id WHERE singleton=1;";
            command.Parameters.AddWithValue("$id", replacementDeviceId);
            _ = command.ExecuteNonQuery();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(replacementDeviceId);
        }

        var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
            service.GetLocalIdentityAsync());

        Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task Restore_RejectsOldThirteenWordSessionStateWithoutMutation()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);

        var legacyBytes = Encoding.UTF8.GetBytes(
            "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed");
        try
        {
            using var legacy = DeepOwnedRecoveryPhraseUtf8.CopyFrom(legacyBytes);
            await Assert.ThrowsAsync<ArgumentException>(() =>
                service.RestoreAsNewDeviceAsync(legacy, "Alice"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(legacyBytes);
        }

        Assert.Null(await store.ReadAsync(null));
    }

    [Fact]
    public async Task PreparedCreate_AtomicallyRetainsConfirmedPhraseWithAccount()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var innerSecureStorage = new InMemoryDeepSecureStorage();
        var trackingStorage = new TrackingSecureStorage(innerSecureStorage);
        var service = CreateService(store, trackingStorage);

        using var draft = service.PrepareCreate("Alice");
        var phraseBytes = RevealPhraseBytes(draft);

        Assert.Equal(24, phraseBytes.Count(static value => value == (byte)' ') + 1);
        Assert.Throws<InvalidOperationException>(() =>
            draft.RevealCanonicalPhraseOnce(static _ => { }));
        Assert.Null(await store.ReadAsync(null));
        Assert.Empty(trackingStorage.LastWrittenSlots);

        using var confirmation = DeepOwnedRecoveryPhraseUtf8.CopyFrom(phraseBytes);
        var created = await service.CommitPreparedAsync(draft, confirmation);

        Assert.NotNull(created.Identity);
        Assert.Equal(10, trackingStorage.LastWrittenSlots.Count);
        Assert.Contains(
            DeepAccountStoreContract.RetainedRecoveryPhraseSlot,
            trackingStorage.LastWrittenSlots);
        try
        {
            foreach (var slot in trackingStorage.LastWrittenSlots)
            {
                var stored = await ReadSecretSnapshotAsync(innerSecureStorage, slot);
                if (stored is null)
                {
                    continue;
                }
                try
                {
                    if (string.Equals(
                            slot,
                            DeepAccountStoreContract.RetainedRecoveryPhraseSlot,
                            StringComparison.Ordinal))
                    {
                        Assert.Equal(phraseBytes, stored);
                    }
                    else
                    {
                        Assert.False(stored.AsSpan().SequenceEqual(phraseBytes));
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(stored);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(phraseBytes);
        }
    }

    [Fact]
    public async Task CommitPrepared_WrongConfirmationAndDisposedDraftNeverMutate()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var innerSecureStorage = new InMemoryDeepSecureStorage();
        var trackingStorage = new TrackingSecureStorage(innerSecureStorage);
        var service = CreateService(store, trackingStorage);
        var draft = service.PrepareCreate("Alice");
        var phraseBytes = RevealPhraseBytes(draft);
        var wrongBytes = phraseBytes.Append((byte)' ').ToArray();

        using var wrong = DeepOwnedRecoveryPhraseUtf8.CopyFrom(wrongBytes);
        await Assert.ThrowsAsync<ArgumentException>(() => service.CommitPreparedAsync(draft, wrong));
        Assert.Null(await store.ReadAsync(null));
        Assert.Empty(trackingStorage.LastWrittenSlots);

        draft.Dispose();
        using var confirmation = DeepOwnedRecoveryPhraseUtf8.CopyFrom(phraseBytes);
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            service.CommitPreparedAsync(draft, confirmation));
        Assert.Null(await store.ReadAsync(null));
        Assert.Empty(trackingStorage.LastWrittenSlots);
        CryptographicOperations.ZeroMemory(phraseBytes);
        CryptographicOperations.ZeroMemory(wrongBytes);
    }

    [Fact]
    public async Task OneShotCreate_CommitsAccountAndRetainsPhraseWithoutUiConfirmation()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var result = await service.CreateAsync("Alice");

        Assert.NotNull(result.Identity);
        Assert.Contains(
            typeof(DeepAccountService).GetMethods(),
            static method => string.Equals(method.Name, "CreateAsync", StringComparison.Ordinal));
        Assert.Single(typeof(DeepAccountCreationResult).GetProperties());
        Assert.True(await service.HasRetainedRecoveryPhraseAsync());
        var words = 0;
        Assert.True(await service.RevealRetainedRecoveryPhraseAsync(
            phrase =>
            {
                words = 1;
                foreach (var value in phrase)
                {
                    if (value == (byte)' ')
                    {
                        words++;
                    }
                }
            }));
        Assert.Equal(24, words);
    }

    [Fact]
    public async Task RetainedPhrase_CanBeDeletedWithoutDeletingAccountOrDeviceKeys()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await service.CreateAsync("Alice");

        await service.DeleteRetainedRecoveryPhraseAsync();

        Assert.False(await service.HasRetainedRecoveryPhraseAsync());
        Assert.False(await service.RevealRetainedRecoveryPhraseAsync(static _ =>
            throw new InvalidOperationException("Missing phrase must not invoke the callback.")));
        var identity = await service.GetLocalIdentityAsync();
        Assert.NotNull(identity);
        Assert.Equal(created.Identity.Account.PermanentId, identity.Account.PermanentId);
        using var deviceSigning = await secureStorage.ReadOwnedAsync(
            identity.SecureSlots.DeviceSigningKey);
        Assert.NotNull(deviceSigning);
    }

    [Fact]
    public async Task CommitPrepared_ZeroesRecoveryEntropyBeforeFirstStoreAwait()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        using var draft = service.PrepareCreate("Alice");
        var phraseField = typeof(DeepPreparedAccountCreationDraft).GetField(
            "phrase",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        var phrase = Assert.IsType<VerifiedDeepRecoveryPhrase>(phraseField!.GetValue(draft));
        var entropyField = typeof(VerifiedDeepRecoveryPhrase).GetField(
            "entropy",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        var entropy = Assert.IsType<byte[]>(entropyField!.GetValue(phrase));
        var recoveryBytes = RevealPhraseBytes(draft);
        using var confirmation = DeepOwnedRecoveryPhraseUtf8.CopyFrom(recoveryBytes);
        using var cancelled = new CancellationTokenSource();
        var processGateField = typeof(DeepAccountService).GetField(
            "ProcessMutationGate",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        var processGate = Assert.IsType<SemaphoreSlim>(processGateField!.GetValue(null));
        await processGate.WaitAsync();
        try
        {
            var commit = service.CommitPreparedAsync(draft, confirmation, cancelled.Token);

            Assert.All(entropy, static value => Assert.Equal(0, value));
            Assert.Null(await store.ReadAsync(null));
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => commit);
        }
        finally
        {
            processGate.Release();
            CryptographicOperations.ZeroMemory(recoveryBytes);
        }
    }

    [Theory]
    [InlineData(DeepAccountCommitFaultPoint.BeforeTransaction)]
    [InlineData(DeepAccountCommitFaultPoint.AfterAccount)]
    [InlineData(DeepAccountCommitFaultPoint.AfterDevice)]
    [InlineData(DeepAccountCommitFaultPoint.BeforeCommit)]
    public async Task InMemoryInjectedPreCommitFault_RollsBackAccountAndSecureSlots(
        DeepAccountCommitFaultPoint faultPoint)
    {
        await using var store = new InMemoryDeepAccountStore(point =>
        {
            if (point == faultPoint)
            {
                throw new InjectedCommitFaultException(point);
            }
        });
        using var innerSecureStorage = new InMemoryDeepSecureStorage();
        var trackingStorage = new TrackingSecureStorage(innerSecureStorage);
        var service = CreateService(store, trackingStorage);

        await Assert.ThrowsAsync<InjectedCommitFaultException>(() => CreateConfirmedAsync(service, "Alice"));

        Assert.Null(await store.ReadAsync(null));
        Assert.Equal(trackingStorage.LastWrittenSlots.Order(), trackingStorage.LastDeletedSlots.Order());
        foreach (var slot in trackingStorage.LastWrittenSlots)
        {
            Assert.Null(await ReadSecretSnapshotAsync(innerSecureStorage, slot));
        }
    }

    [Theory]
    [InlineData(DeepAccountCommitFaultPoint.AfterAccount)]
    [InlineData(DeepAccountCommitFaultPoint.AfterDevice)]
    [InlineData(DeepAccountCommitFaultPoint.BeforeCommit)]
    public async Task SqliteInjectedPreCommitFault_RollsBackAllThreeRows(
        DeepAccountCommitFaultPoint faultPoint)
    {
        var path = TempPath();
        await using var store = new SqliteDeepAccountStore(
            new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId()),
            point =>
            {
                if (point == faultPoint)
                {
                    throw new InjectedCommitFaultException(point);
                }
            });
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);

        await Assert.ThrowsAsync<InjectedCommitFaultException>(() => CreateConfirmedAsync(service, "Alice"));

        Assert.Null(await store.ReadAsync(null));
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteAfterCommitFault_IsRecognizedAsDurableSuccess()
    {
        var path = TempPath();
        await using var store = new SqliteDeepAccountStore(
            new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId()),
            point =>
            {
                if (point == DeepAccountCommitFaultPoint.AfterCommit)
                {
                    throw new InjectedCommitFaultException(point);
                }
            });
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);

        var result = await CreateConfirmedAsync(service, "Alice");

        var durable = Assert.IsType<DeepLocalIdentitySnapshot>(
            await store.ReadAsync(result.Identity.Device.Identity));
        Assert.Equal(result.Identity.Account.PermanentId, durable.Account.PermanentId);
        Assert.Equal(
            result.Identity.Account.AccountIdentity.AccountId,
            durable.Account.AccountIdentity.AccountId);
        Assert.Equal(result.Identity.Account.DisplayName, durable.Account.DisplayName);
        Assert.Equal(result.Identity.Account.CurrentDeviceId, durable.Account.CurrentDeviceId);
        Assert.Equal(result.Identity.Profile, durable.Profile);
        Assert.Equal(result.Identity.Device.DeviceId, durable.Device.DeviceId);
        Assert.True(result.Identity.NetworkId.Span.SequenceEqual(durable.NetworkId.Span));
        Assert.True(result.Identity.Device.SigningPublicKey.Span.SequenceEqual(durable.Device.SigningPublicKey.Span));
        Assert.True(result.Identity.Device.AgreementPublicKey.Span.SequenceEqual(durable.Device.AgreementPublicKey.Span));
        Assert.True(result.Identity.Device.PrekeyPublicKey.Span.SequenceEqual(durable.Device.PrekeyPublicKey.Span));
        Assert.Equal(result.Identity.SecureSlots, durable.SecureSlots);
        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, DeepAccountService.PendingSecureStorageJournalSlot));
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task CommitPrepared_PendingCleanupFailureStillSucceedsAndRetries()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var innerSecureStorage = new InMemoryDeepSecureStorage();
        var secureStorage = new FailPendingDeleteOnceSecureStorage(innerSecureStorage);
        var service = CreateService(store, secureStorage);
        using var draft = service.PrepareCreate("Alice");
        var phraseBytes = RevealPhraseBytes(draft);
        using var confirmation = DeepOwnedRecoveryPhraseUtf8.CopyFrom(phraseBytes);

        var result = await service.CommitPreparedAsync(draft, confirmation);

        Assert.NotNull(result.Identity);
        Assert.Equal(1, secureStorage.InjectedFailures);
        Assert.NotNull(await ReadSecretSnapshotAsync(
            innerSecureStorage,
            DeepAccountService.PendingSecureStorageJournalSlot));

        Assert.NotNull(await service.GetLocalIdentityAsync());
        Assert.Null(await ReadSecretSnapshotAsync(
            innerSecureStorage,
            DeepAccountService.PendingSecureStorageJournalSlot));
        CryptographicOperations.ZeroMemory(phraseBytes);
    }

    [Fact]
    public async Task SqliteBootstrap_CreatesInstallScopedBinaryKeyAndReopensEncryptedDatabase()
    {
        var path = TempPath();
        using var secureStorage = new InMemoryDeepSecureStorage();
        await using (var store = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage))
        {
            Assert.Null(await store.ReadAsync(null));
        }

        var record = Assert.IsType<byte[]>(
            await ReadSecretSnapshotAsync(secureStorage, DeepAccountStoreContract.DatabaseGenerationSlot));
        try
        {
            Assert.Equal(72, record.Length);
            Assert.Equal("DSK1"u8.ToArray(), record[..4]);
            Assert.False(record.AsSpan(8, 32).SequenceEqual(record.AsSpan(40, 32)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(record);
        }

        await using (var reopened = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage))
        {
            Assert.Null(await reopened.ReadAsync(null));
        }

        using (var unkeyed = new SqliteConnection($"Data Source={path};Mode=ReadWrite;Pooling=False"))
        {
            unkeyed.Open();
            using var command = unkeyed.CreateCommand();
            command.CommandText = "SELECT count(*) FROM sqlite_schema;";
            Assert.Throws<SqliteException>(() => command.ExecuteScalar());
        }
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteBootstrap_DoesNotReplaceMissingKeyForExistingEncryptedState()
    {
        var path = TempPath();
        using var secureStorage = new InMemoryDeepSecureStorage();
        await using (var store = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage))
        {
            Assert.Null(await store.ReadAsync(null));
        }

        await secureStorage.DeleteBatchAsync([DeepAccountStoreContract.DatabaseGenerationSlot]);
        var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
            SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage));

        Assert.Equal(LocalStateResetRequiredReason.UnreadableOrWrongKey, exception.Reason);
        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, DeepAccountStoreContract.DatabaseGenerationSlot));
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteBootstrap_DestroyGenerationWorksWithoutOpeningDatabaseAndRotatesIdentity()
    {
        var path = TempPath();
        using var secureStorage = new InMemoryDeepSecureStorage();
        await using (var store = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage))
        {
            Assert.Null(await store.ReadAsync(null));
        }
        var firstRecord = Assert.IsType<byte[]>(
            await ReadSecretSnapshotAsync(secureStorage, DeepAccountStoreContract.DatabaseGenerationSlot));

        await SqliteDeepAccountStoreBootstrap.DestroyGenerationAsync(path, secureStorage);

        Assert.False(File.Exists(path));
        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, DeepAccountStoreContract.DatabaseGenerationSlot));
        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, SqliteDeepAccountStoreBootstrap.ResetTombstoneSlot));

        await using (var reopened = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage))
        {
            Assert.Null(await reopened.ReadAsync(null));
        }
        var secondRecord = Assert.IsType<byte[]>(
            await ReadSecretSnapshotAsync(secureStorage, DeepAccountStoreContract.DatabaseGenerationSlot));
        try
        {
            Assert.False(firstRecord.AsSpan().SequenceEqual(secondRecord));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstRecord);
            CryptographicOperations.ZeroMemory(secondRecord);
        }
        DeleteSqliteFiles(path);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SqliteDestroy_UsesDeterministicGenerationInventoryWhenManifestIsMissingOrCorrupt(
        bool corruptManifest)
    {
        var path = TempPath();
        using var secureStorage = new InMemoryDeepSecureStorage();
        DeepSecureStorageSlots slots;
        await using (var store = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage))
        {
            slots = (await CreateConfirmedAsync(
                CreateService(store, secureStorage),
                "Alice")).Identity.SecureSlots;
        }

        await secureStorage.DeleteBatchAsync(
            [DeepAccountStoreContract.DatabaseAccountManifestSlot]);
        if (corruptManifest)
        {
            await secureStorage.WriteBatchAsync(
                [new DeepSecureStorageWrite(
                    DeepAccountStoreContract.DatabaseAccountManifestSlot,
                    "corrupt-manifest"u8.ToArray())]);
        }

        await SqliteDeepAccountStoreBootstrap.DestroyGenerationAsync(path, secureStorage);

        foreach (var slot in new[]
                 {
                     slots.DeviceSigningKey,
                     slots.DeviceAgreementKey,
                     slots.DeviceId,
                     slots.DeviceRevocationHandle,
                     slots.DevicePrekey,
                     slots.PushKey,
                     slots.MessageStoreInstanceId,
                     DeepAccountStoreContract.DatabaseGenerationSlot,
                     DeepAccountStoreContract.DatabaseAccountManifestSlot,
                     DeepAccountStoreContract.PendingAccountSlot,
                     SqliteDeepAccountStoreBootstrap.ResetTombstoneSlot
                 })
        {
            Assert.Null(await ReadSecretSnapshotAsync(secureStorage, slot));
        }
        AssertDatabaseGenerationArtifactsAbsent(path);
        DeleteSqliteFiles(path);
    }

    [Theory]
    [MemberData(nameof(MissingOrCorruptLifecycleMetadata))]
    public async Task SqliteDestroy_PurgesNamespaceWithoutDecodingAnyLifecycleMetadata(
        bool generationCorrupt,
        bool tombstoneCorrupt,
        bool manifestCorrupt,
        bool pendingCorrupt)
    {
        var path = TempPath();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var storeValues = new List<DeepSecureStorageWrite>
        {
            new("deep.store.v1.orphaned-generation-secret", "secret"u8.ToArray())
        };
        if (generationCorrupt)
        {
            storeValues.Add(new(DeepAccountStoreContract.DatabaseGenerationSlot, "corrupt-DSK1"u8.ToArray()));
        }
        if (manifestCorrupt)
        {
            storeValues.Add(new(DeepAccountStoreContract.DatabaseAccountManifestSlot, "corrupt-DSM3"u8.ToArray()));
        }
        if (pendingCorrupt)
        {
            storeValues.Add(new(DeepAccountStoreContract.PendingAccountSlot, "corrupt-pending"u8.ToArray()));
        }
        if (tombstoneCorrupt)
        {
            storeValues.Add(new(SqliteDeepAccountStoreBootstrap.ResetTombstoneSlot, "corrupt-DST3"u8.ToArray()));
        }
        await secureStorage.WriteBatchAsync(storeValues);
        await secureStorage.WriteBatchAsync(
            [new DeepSecureStorageWrite("another.component.secret", "preserve"u8.ToArray())]);
        await File.WriteAllBytesAsync(path, [1, 2, 3]);
        await File.WriteAllBytesAsync(path + "-wal", [4]);
        await File.WriteAllBytesAsync(path + ".creating", [5]);

        await SqliteDeepAccountStoreBootstrap.DestroyGenerationAsync(path, secureStorage);
        await SqliteDeepAccountStoreBootstrap.DestroyGenerationAsync(path, secureStorage);

        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, "deep.store.v1.orphaned-generation-secret"));
        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, DeepAccountStoreContract.DatabaseGenerationSlot));
        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, DeepAccountStoreContract.DatabaseAccountManifestSlot));
        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, DeepAccountStoreContract.PendingAccountSlot));
        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, SqliteDeepAccountStoreBootstrap.ResetTombstoneSlot));
        var unrelated = Assert.IsType<byte[]>(
            await ReadSecretSnapshotAsync(secureStorage, "another.component.secret"));
        try
        {
            Assert.Equal("preserve"u8.ToArray(), unrelated);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(unrelated);
        }
        AssertDatabaseGenerationArtifactsAbsent(path);
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task InMemoryDeleteBatch_PrevalidatesEverySlotBeforeMutation()
    {
        using var secureStorage = new InMemoryDeepSecureStorage();
        await secureStorage.WriteBatchAsync(
            [new DeepSecureStorageWrite("deep.store.v1.keep", "secret"u8.ToArray())]);

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            secureStorage.DeleteBatchAsync(["deep.store.v1.keep", null!]));

        Assert.NotNull(await ReadSecretSnapshotAsync(secureStorage, "deep.store.v1.keep"));
    }

    [Fact]
    public async Task OwnedDeepSecret_DisposeWaitsForActiveReaderAndThenRejectsReads()
    {
        using var secureStorage = new InMemoryDeepSecureStorage();
        await secureStorage.WriteBatchAsync(
            [new DeepSecureStorageWrite("deep.store.v1.race", "secret"u8.ToArray())]);
        var owned = Assert.IsType<OwnedDeepSecret>(
            await secureStorage.ReadOwnedAsync("deep.store.v1.race"));
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var read = Task.Run(() => owned.Use(value =>
        {
            entered.Set();
            release.Wait();
            return value.ToArray();
        }));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));

        var dispose = Task.Run(owned.Dispose);
        Assert.False(dispose.IsCompleted);
        release.Set();
        var copy = await read;
        try
        {
            Assert.Equal("secret"u8.ToArray(), copy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
        await dispose;
        Assert.Throws<ObjectDisposedException>(() => owned.Use(static _ => true));
    }

    [Theory]
    [InlineData("Alice\u202Eadmin")]
    [InlineData("Alice\u200Dadmin")]
    [InlineData("Alice\nadmin")]
    public async Task DisplayName_RejectsBidiFormatControlAndInvalidUtf16(string value)
    {
        using var secureStorage = new InMemoryDeepSecureStorage();
        var store = new InMemoryDeepAccountStore();
        try
        {
            var service = CreateService(store, secureStorage);
            Assert.Throws<ArgumentException>(() => service.PrepareCreate(value));
        }
        finally
        {
            await store.DisposeAsync();
        }
    }

    [Fact]
    public async Task DisplayName_RejectsRuntimeConstructedInvalidUtf16()
    {
        using var secureStorage = new InMemoryDeepSecureStorage();
        await using var store = new InMemoryDeepAccountStore();
        var service = CreateService(store, secureStorage);

        Assert.Throws<ArgumentException>(() =>
            service.PrepareCreate(new string('\uD800', 1)));
    }

    [Fact]
    public async Task DisplayName_IsNfcBeforeReceiptAndPersistence()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);

        var created = await CreateConfirmedAsync(service, "  Jose\u0301  ");

        Assert.Equal("José", created.Identity.Account.DisplayName);
        Assert.Equal(
            Encoding.UTF8.GetBytes("José"),
            Encoding.UTF8.GetBytes(created.Identity.Profile.DisplayName));
    }

    [Fact]
    public async Task DisplayName_EnforcesExactUtf8ByteBoundBeforeMutation()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var maximum = new string('界', 85);

        using var accepted = service.PrepareCreate(maximum);
        Assert.Equal(255, Encoding.UTF8.GetByteCount(maximum));
        Assert.Throws<ArgumentException>(() =>
            service.PrepareCreate(new string('界', 86)));
        Assert.Null(await store.ReadAsync(null));
    }

    [Theory]
    [InlineData((int)SqliteDeepAccountStoreLifecycleFaultPoint.AfterGenerationRecordWritten)]
    [InlineData((int)SqliteDeepAccountStoreLifecycleFaultPoint.AfterTemporaryDatabaseCreated)]
    [InlineData((int)SqliteDeepAccountStoreLifecycleFaultPoint.AfterDatabaseMoved)]
    public async Task SqliteBootstrap_RestartsAfterEveryCreationCrashPoint(
        int faultPointValue)
    {
        var faultPoint = (SqliteDeepAccountStoreLifecycleFaultPoint)faultPointValue;
        var path = TempPath();
        using var secureStorage = new InMemoryDeepSecureStorage();

        var exception = await Assert.ThrowsAsync<SqliteDeepAccountStoreSimulatedCrashException>(() =>
            SqliteDeepAccountStoreBootstrap.OpenAsync(
                path,
                secureStorage,
                point =>
                {
                    if (point == faultPoint)
                    {
                        throw new InjectedLifecycleFaultException(point);
                    }
                }));

        Assert.Equal(faultPoint, exception.Point);
        if (faultPoint == SqliteDeepAccountStoreLifecycleFaultPoint.AfterTemporaryDatabaseCreated)
        {
            Assert.True(File.Exists(path + ".creating"));
        }

        await using (var recovered = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage))
        {
            Assert.Null(await recovered.ReadAsync(null));
        }
        Assert.True(File.Exists(path));
        Assert.False(File.Exists(path + ".creating"));
        DeleteSqliteFiles(path);
    }

    [Theory]
    [InlineData((int)SqliteDeepAccountStoreLifecycleFaultPoint.AfterDestroyTombstoneWritten)]
    [InlineData((int)SqliteDeepAccountStoreLifecycleFaultPoint.AfterGenerationSlotsDeleted)]
    [InlineData((int)SqliteDeepAccountStoreLifecycleFaultPoint.AfterDatabaseArtifactsDeleted)]
    public async Task SqliteDestroy_RestartsAfterEveryDestructionCrashPointAndDeletesExactGeneration(
        int faultPointValue)
    {
        var faultPoint = (SqliteDeepAccountStoreLifecycleFaultPoint)faultPointValue;
        var path = TempPath();
        using var secureStorage = new InMemoryDeepSecureStorage();
        DeepSecureStorageSlots slots;
        await using (var store = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage))
        {
            var created = await CreateConfirmedAsync(CreateService(store, secureStorage), "Alice");
            slots = created.Identity.SecureSlots;
        }

        File.Copy(path, path + ".creating", overwrite: true);
        File.WriteAllBytes(path + "-wal", [1]);
        File.WriteAllBytes(path + "-shm", [2]);
        File.WriteAllBytes(path + ".creating-wal", [3]);
        File.WriteAllBytes(path + ".creating-shm", [4]);

        var exception = await Assert.ThrowsAsync<SqliteDeepAccountStoreSimulatedCrashException>(() =>
            SqliteDeepAccountStoreBootstrap.DestroyGenerationAsync(
                path,
                secureStorage,
                point =>
                {
                    if (point == faultPoint)
                    {
                        throw new InjectedLifecycleFaultException(point);
                    }
                }));
        Assert.Equal(faultPoint, exception.Point);

        await SqliteDeepAccountStoreBootstrap.DestroyGenerationAsync(path, secureStorage);

        foreach (var slot in new[]
                 {
                     DeepAccountStoreContract.DatabaseGenerationSlot,
                     DeepAccountStoreContract.DatabaseAccountManifestSlot,
                     DeepAccountStoreContract.PendingAccountSlot,
                     SqliteDeepAccountStoreBootstrap.ResetTombstoneSlot,
                     slots.DeviceSigningKey,
                     slots.DeviceAgreementKey,
                     slots.DeviceId,
                     slots.DeviceRevocationHandle,
                     slots.DevicePrekey,
                     slots.PushKey,
                     slots.MessageStoreInstanceId
                 })
        {
            Assert.Null(await ReadSecretSnapshotAsync(secureStorage, slot));
        }
        AssertDatabaseGenerationArtifactsAbsent(path);
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteDestroy_WaitsForEveryLifetimeGenerationLease()
    {
        var path = TempPath();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var first = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage);
        var second = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage);
        try
        {
            using (var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150)))
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    SqliteDeepAccountStoreBootstrap.DestroyGenerationAsync(
                        path,
                        secureStorage,
                        cancellation.Token));
            }

            await first.DisposeAsync();
            using (var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150)))
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    SqliteDeepAccountStoreBootstrap.DestroyGenerationAsync(
                        path,
                        secureStorage,
                        cancellation.Token));
            }

            await second.DisposeAsync();
            await SqliteDeepAccountStoreBootstrap.DestroyGenerationAsync(path, secureStorage);
            AssertDatabaseGenerationArtifactsAbsent(path);
        }
        finally
        {
            await first.DisposeAsync();
            await second.DisposeAsync();
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task SqliteMutationLease_SerializesIndependentStoreInstances()
    {
        var path = TempPath();
        await using var first = new SqliteDeepAccountStore(new SqliteDeepAccountStoreOptions(
            path,
            TestDatabaseKey(),
            TestDatabaseInstanceId()));
        await using var second = new SqliteDeepAccountStore(new SqliteDeepAccountStoreOptions(
            path,
            TestDatabaseKey(),
            TestDatabaseInstanceId()));
        await using (var firstLease = await first.AcquireMutationLeaseAsync())
        {
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                second.AcquireMutationLeaseAsync(cancellation.Token).AsTask());
        }

        await using (var secondLease = await second.AcquireMutationLeaseAsync())
        {
            Assert.NotNull(secondLease);
        }
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteGenerationSlots_AreExactOrDisposedDuringConcurrentDispose()
    {
        var path = TempPath();
        var instanceId = TestDatabaseInstanceId();
        var expected = DeepSecureStorageSlots.CreateForGeneration(instanceId);
        var store = new SqliteDeepAccountStore(new SqliteDeepAccountStoreOptions(
            path,
            TestDatabaseKey(),
            instanceId));
        try
        {
            using var start = new ManualResetEventSlim();
            var readers = Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
            {
                start.Wait();
                for (var attempt = 0; attempt < 128; attempt++)
                {
                    try
                    {
                        Assert.Equal(expected, store.GetGenerationSecureStorageSlots());
                    }
                    catch (ObjectDisposedException)
                    {
                        return;
                    }
                }
            })).ToArray();
            var dispose = Task.Run(async () =>
            {
                start.Wait();
                await store.DisposeAsync();
            });

            start.Set();
            await Task.WhenAll(readers.Append(dispose));
            Assert.Throws<ObjectDisposedException>(() => store.GetGenerationSecureStorageSlots());
        }
        finally
        {
            await store.DisposeAsync();
            CryptographicOperations.ZeroMemory(instanceId);
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task MutationLease_RejectsForeignAndDisposedCapabilities()
    {
        Assert.Empty(typeof(DeepAccountReconciledMutationCapability).GetConstructors());
        await using var first = new InMemoryDeepAccountStore();
        await using var second = new InMemoryDeepAccountStore();
        var lease = await first.AcquireMutationLeaseAsync();
        var capability = new DeepAccountReconciledMutationCapability(lease, null, default);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            second.ClearLocalAccountAsync(capability));

        await lease.DisposeAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            first.ClearLocalAccountAsync(capability));
    }

    [Fact]
    public async Task SecureStorageRead_IsOwnedAndCannotBeUsedAfterDisposal()
    {
        using var secureStorage = new InMemoryDeepSecureStorage();
        var expected = RandomNumberGenerator.GetBytes(32);
        try
        {
            await secureStorage.WriteBatchAsync(
                [new DeepSecureStorageWrite("deep.store.v1.test-owned", expected)]);
            var owned = Assert.IsType<OwnedDeepSecret>(
                await secureStorage.ReadOwnedAsync("deep.store.v1.test-owned"));
            var actual = new byte[32];
            owned.CopyTo(actual);
            Assert.Equal(expected, actual);

            owned.Dispose();
            Assert.Throws<ObjectDisposedException>(() => owned.CopyTo(actual));

            using var secondRead = Assert.IsType<OwnedDeepSecret>(
                await secureStorage.ReadOwnedAsync("deep.store.v1.test-owned"));
            Assert.True(secondRead.Use(value => value.SequenceEqual(expected)));
            CryptographicOperations.ZeroMemory(actual);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    [Fact]
    public async Task InMemorySecureStorage_DisposeRaceCannotPublishSecretsAfterDisposal()
    {
        for (var iteration = 0; iteration < 64; iteration++)
        {
            var secureStorage = new InMemoryDeepSecureStorage();
            var secret = RandomNumberGenerator.GetBytes(32);
            using var start = new ManualResetEventSlim();
            var write = Task.Run(async () =>
            {
                start.Wait();
                try
                {
                    await secureStorage.WriteBatchAsync(
                        [new DeepSecureStorageWrite($"deep.store.v1.race-{iteration}", secret)]);
                }
                catch (ObjectDisposedException)
                {
                }
            });
            var dispose = Task.Run(() =>
            {
                start.Wait();
                secureStorage.Dispose();
            });
            start.Set();
            await Task.WhenAll(write, dispose);

            var field = typeof(InMemoryDeepSecureStorage).GetField(
                "values",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            Assert.NotNull(field);
            var values = Assert.IsAssignableFrom<IEnumerable<KeyValuePair<string, byte[]>>>(
                field!.GetValue(secureStorage));
            Assert.Empty(values);
            await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                secureStorage.ReadOwnedAsync("deep.store.v1.any"));
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    [Fact]
    public async Task InMemoryStore_DisposeCoordinatesConcurrentReads()
    {
        var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        await CreateConfirmedAsync(service, "Alice");
        var localDeviceIdentity = Assert.IsType<DeepLocalIdentitySnapshot>(
            await service.GetLocalIdentityAsync()).Device.Identity;
        using var start = new ManualResetEventSlim();
        var reads = Enumerable.Range(0, 32).Select(index => Task.Run(async () =>
        {
            _ = index;
            start.Wait();
            try
            {
                _ = await store.ReadAsync(localDeviceIdentity);
            }
            catch (ObjectDisposedException)
            {
            }
        })).ToArray();
        var dispose = Task.Run(async () =>
        {
            start.Wait();
            await store.DisposeAsync();
        });

        start.Set();
        await Task.WhenAll(reads.Append(dispose));
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            store.ReadAsync(localDeviceIdentity));
    }

    [Fact]
    public async Task PendingSecureStorageJournal_DeletesOrphanedAccountSecretsBeforeRetry()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var orphanGeneration = RandomNumberGenerator.GetBytes(32);
        var orphan = DeepSecureStorageSlots.CreateForGeneration(orphanGeneration);
        var orphanSlots = new[]
        {
            orphan.DeviceSigningKey,
            orphan.DeviceAgreementKey,
            orphan.DeviceId,
            orphan.DeviceRevocationHandle,
            orphan.DevicePrekey,
            orphan.PushKey,
            orphan.MessageStoreInstanceId
        };
        var orphanOperationId = RandomNumberGenerator.GetBytes(32);
        var orphanInitialSnapshotHash = RandomNumberGenerator.GetBytes(32);
        var orphanImmutableIdentityHash = RandomNumberGenerator.GetBytes(32);
        var orphanOperation = DeepAccountCreationOperation.FromPersisted(
            orphanOperationId,
            orphanInitialSnapshotHash);
        var secret = RandomNumberGenerator.GetBytes(32);
        var journal = SqliteDeepAccountStoreBootstrap.EncodeAccountManifest(
            orphanOperation,
            orphanImmutableIdentityHash,
            MessageStoreInstanceId32.FromBytes(secret),
            orphan);
        try
        {
            var writes = orphanSlots
                .Select(slot => new DeepSecureStorageWrite(slot, secret))
                .Prepend(new DeepSecureStorageWrite(
                    DeepAccountService.PendingSecureStorageJournalSlot,
                    journal))
                .Prepend(new DeepSecureStorageWrite(
                    DeepAccountStoreContract.DatabaseAccountManifestSlot,
                    journal))
                .ToArray();
            await secureStorage.WriteBatchAsync(writes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(journal);
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(orphanGeneration);
            CryptographicOperations.ZeroMemory(orphanOperationId);
            CryptographicOperations.ZeroMemory(orphanInitialSnapshotHash);
            CryptographicOperations.ZeroMemory(orphanImmutableIdentityHash);
        }

        var created = await CreateConfirmedAsync(service, "Alice");

        Assert.NotNull(created.Identity);
        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, DeepAccountService.PendingSecureStorageJournalSlot));
        foreach (var slot in orphanSlots)
        {
            Assert.Null(await ReadSecretSnapshotAsync(secureStorage, slot));
        }
    }

    [Fact]
    public async Task UnknownCommitOutcome_PreservesSecretsAndJournalUntilExactReceiptCanBeRead()
    {
        await using var inner = new InMemoryDeepAccountStore(point =>
        {
            if (point == DeepAccountCommitFaultPoint.AfterCommit)
            {
                throw new InjectedCommitFaultException(point);
            }
        });
        await using var store = new ReceiptReadFailingStore(inner);
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);

        await Assert.ThrowsAsync<DeepAccountCreationOutcomeUnknownException>(() =>
            CreateConfirmedAsync(service, "Alice"));

        Assert.NotNull(await inner.ReadAccountIdentityAsync());
        Assert.NotNull(await ReadSecretSnapshotAsync(secureStorage, DeepAccountService.PendingSecureStorageJournalSlot));

        var recovered = await service.GetLocalIdentityAsync();
        Assert.NotNull(recovered);
        Assert.Null(await ReadSecretSnapshotAsync(secureStorage, DeepAccountService.PendingSecureStorageJournalSlot));
    }

    [Fact]
    public async Task PendingCreation_TamperedDeviceRejectsBeforeJournalIsCleared()
    {
        var path = TempPath();
        await using var inner = new SqliteDeepAccountStore(
            new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId()),
            point =>
            {
                if (point == DeepAccountCommitFaultPoint.AfterCommit)
                {
                    throw new InjectedCommitFaultException(point);
                }
            });
        await using var store = new ReceiptReadFailingStore(inner);
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        await Assert.ThrowsAsync<DeepAccountCreationOutcomeUnknownException>(() =>
            CreateConfirmedAsync(service, "Alice"));

        using (var connection = OpenTestDatabase(path))
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE local_device SET prekey_public_key=randomblob(32) WHERE singleton=1;";
            Assert.Equal(1, command.ExecuteNonQuery());
        }

        await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
            service.UpdateDisplayNameAsync("Tampered"));
        Assert.NotNull(await ReadSecretSnapshotAsync(
            secureStorage,
            DeepAccountService.PendingSecureStorageJournalSlot));
        DeleteSqliteFiles(path);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task CorruptedDeviceSeed_IsRejectedEvenWhenLengthIsCorrect(int keyKind)
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(service, "Alice");
        var slot = keyKind switch
        {
            0 => created.Identity.SecureSlots.DeviceSigningKey,
            1 => created.Identity.SecureSlots.DeviceAgreementKey,
            _ => created.Identity.SecureSlots.DevicePrekey
        };
        var replacement = RandomNumberGenerator.GetBytes(32);
        try
        {
            await secureStorage.DeleteBatchAsync([slot]);
            await secureStorage.WriteBatchAsync([new DeepSecureStorageWrite(slot, replacement)]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(replacement);
        }

        var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
            service.GetLocalIdentityAsync());

        Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
    }

    [Fact]
    public async Task Reset_RemovesAccountSecretsPreservesDatabaseKeyAndAllowsFreshAccount()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var first = await CreateConfirmedAsync(service, "Alice");
        var accountSlots = new[]
        {
            first.Identity.SecureSlots.DeviceSigningKey,
            first.Identity.SecureSlots.DeviceAgreementKey,
            first.Identity.SecureSlots.DeviceId,
            first.Identity.SecureSlots.DeviceRevocationHandle,
            first.Identity.SecureSlots.DevicePrekey,
            first.Identity.SecureSlots.PushKey,
            first.Identity.SecureSlots.MessageStoreInstanceId
        };

        await service.ResetLocalAccountAsync();

        Assert.Null(await store.ReadAsync(null));
        foreach (var slot in accountSlots)
        {
            Assert.Null(await ReadSecretSnapshotAsync(secureStorage, slot));
        }
        var second = await CreateConfirmedAsync(service, "Bob");
        Assert.NotEqual(first.Identity.Account.PermanentId, second.Identity.Account.PermanentId);
    }

    [Fact]
    public void SqliteOldGeneration_RequiresExplicitResetAndDoesNotMigrate()
    {
        var path = TempPath();
        SQLitePCL.Batteries_V2.Init();
        using (var connection = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE settings(key TEXT PRIMARY KEY,payload TEXT NOT NULL); PRAGMA application_id=1145390416; PRAGMA user_version=16;";
            command.ExecuteNonQuery();
        }

        var exception = Assert.Throws<LocalStateResetRequiredException>(() =>
            new SqliteDeepAccountStore(new SqliteDeepAccountStoreOptions(path, default, TestDatabaseInstanceId())));

        Assert.Equal(LocalStateResetRequiredReason.UnsupportedVersion, exception.Reason);
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task OfflineCreate_HasNoNetworkDnsRegistryOrBootstrapDependencySurface()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);

        var result = await CreateConfirmedAsync(service, "Offline Alice");

        Assert.NotNull(await store.ReadAsync(result.Identity.Device.Identity));
        var constructorDependencies = typeof(DeepAccountService).GetConstructors().Single().GetParameters();
        Assert.DoesNotContain(constructorDependencies, parameter =>
            parameter.ParameterType.Name.Contains("Transport", StringComparison.OrdinalIgnoreCase)
            || parameter.ParameterType.Name.Contains("Network", StringComparison.OrdinalIgnoreCase)
            || parameter.ParameterType.Name.Contains("Registry", StringComparison.OrdinalIgnoreCase)
            || parameter.ParameterType.Name.Contains("Bootstrap", StringComparison.OrdinalIgnoreCase)
            || parameter.ParameterType.FullName?.StartsWith("System.Net.", StringComparison.Ordinal) == true);
        Assert.Equal(DeepAccountActivationState.ActiveLocal, result.Identity.Account.ActivationState);
    }

    [Fact]
    public async Task SqliteBootstrap_CreateAndRestoreCompleteWithoutNetworkDependency()
    {
        var firstPath = TempPath();
        var secondPath = TempPath();
        using var firstSecureStorage = new InMemoryDeepSecureStorage();
        using var secondSecureStorage = new InMemoryDeepSecureStorage();
        await using var firstStore = await SqliteDeepAccountStoreBootstrap.OpenAsync(
            firstPath,
            firstSecureStorage);
        var firstService = CreateService(firstStore, firstSecureStorage);

        var (created, recoveryBytes) = await CreateConfirmedWithPhraseAsync(firstService, "Offline Alice");

        try
        {
            await using var secondStore = await SqliteDeepAccountStoreBootstrap.OpenAsync(
                secondPath,
                secondSecureStorage);
            var secondService = CreateService(secondStore, secondSecureStorage);
            using var recovery = DeepOwnedRecoveryPhraseUtf8.CopyFrom(recoveryBytes);
            var restored = await secondService.RestoreAsNewDeviceAsync(
                recovery,
                "Offline Alice restored");

            Assert.Equal(created.Identity.Account.PermanentId, restored.Identity.Account.PermanentId);
            Assert.Equal(
                created.Identity.Account.AccountIdentity.AccountId,
                restored.Identity.Account.AccountIdentity.AccountId);
            Assert.NotEqual(created.Identity.Device.DeviceId, restored.Identity.Device.DeviceId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recoveryBytes);
        }
        DeleteSqliteFiles(firstPath);
        DeleteSqliteFiles(secondPath);
    }

    [Fact]
    public async Task DevicePushAndMessageStoreMaterial_AreIndependentCprngSlots()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(service, "Alice");
        var slots = created.Identity.SecureSlots;
        var secretSlots = new[]
        {
            slots.DeviceSigningKey,
            slots.DeviceAgreementKey,
            slots.DeviceId,
            slots.DeviceRevocationHandle,
            slots.DevicePrekey,
            slots.PushKey,
            slots.MessageStoreInstanceId
        };
        var materials = new List<byte[]>();
        try
        {
            foreach (var slot in secretSlots)
            {
                materials.Add(Assert.IsType<byte[]>(await ReadSecretSnapshotAsync(secureStorage, slot)));
            }

            Assert.All(materials, value => Assert.Equal(32, value.Length));
            for (var left = 0; left < materials.Count; left++)
            {
                for (var right = left + 1; right < materials.Count; right++)
                {
                    Assert.False(materials[left].AsSpan().SequenceEqual(materials[right]));
                }
            }
        }
        finally
        {
            foreach (var material in materials)
            {
                CryptographicOperations.ZeroMemory(material);
            }
        }
    }

    [Fact]
    public async Task CanceledCreate_DoesNotMutateStoreOrSecureStorage()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var innerSecureStorage = new InMemoryDeepSecureStorage();
        var trackingStorage = new TrackingSecureStorage(innerSecureStorage);
        var service = CreateService(store, trackingStorage);
        trackingStorage.ClearTracking();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CreateConfirmedAsync(service, "Alice", cancellation.Token));

        Assert.Null(await store.ReadAsync(null));
        Assert.Empty(trackingStorage.LastWrittenSlots);
    }

    [Fact]
    public async Task WrongAccountGeneration_IsRejectedWithoutMutation()
    {
        await using var sourceStore = new InMemoryDeepAccountStore();
        using var sourceSecureStorage = new InMemoryDeepSecureStorage();
        var valid = await CreateConfirmedAsync(CreateService(sourceStore, sourceSecureStorage), "Alice");
        var wrongIdentity = DeepAccountIdentityCapability.FromVerifiedInputs(
            valid.Identity.Account.AccountIdentity.NetworkId,
            2,
            valid.Identity.Account.AccountIdentity.AccountSigningPublicKey);
        var wrongGeneration = valid.Identity with
        {
            Account = valid.Identity.Account with { AccountIdentity = wrongIdentity }
        };
        await using var targetStore = new InMemoryDeepAccountStore();
        var validOperation = DeepAccountCreationOperation.Create(valid.Identity);
        await using var mutationLease = await targetStore.AcquireMutationLeaseAsync();
        var mutationCapability = new DeepAccountReconciledMutationCapability(
            mutationLease,
            null,
            default);
        var immutableCommitment = RandomNumberGenerator.GetBytes(32);

        var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
            targetStore.CreateAsync(
                mutationCapability,
                wrongGeneration,
                validOperation,
                immutableCommitment));
        CryptographicOperations.ZeroMemory(immutableCommitment);

        Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
        Assert.Null(await targetStore.ReadAsync(null));
    }

    [Fact]
    public async Task SqliteCorruptCurrentSchema_IsQuarantinedInsteadOfRepaired()
    {
        var path = TempPath();
        await using (var store = new SqliteDeepAccountStore(
                         new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId())))
        {
            Assert.Null(await store.ReadAsync(null));
        }

        using (var connection = OpenTestDatabase(path))
        {
            using var command = connection.CreateCommand();
            command.CommandText = "ALTER TABLE local_profile RENAME COLUMN display_name TO damaged_name;";
            command.ExecuteNonQuery();
        }

        var exception = Assert.Throws<LocalStateResetRequiredException>(() =>
            new SqliteDeepAccountStore(new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId())));

        Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteChangedConstraintWithSameColumns_IsRejectedBySchemaFingerprint()
    {
        var path = TempPath();
        await using (var store = new SqliteDeepAccountStore(
                         new SqliteDeepAccountStoreOptions(
                             path,
                             TestDatabaseKey(),
                             TestDatabaseInstanceId())))
        {
            Assert.Null(await store.ReadAsync(null));
        }

        using (var connection = OpenTestDatabase(path))
        {
            using var command = connection.CreateCommand();
            command.CommandText = """
                PRAGMA writable_schema=ON;
                UPDATE sqlite_schema
                SET sql=replace(sql,'CHECK(account_generation=1)','CHECK(account_generation>0)')
                WHERE type='table' AND name='local_account';
                PRAGMA writable_schema=OFF;
                """;
            _ = command.ExecuteNonQuery();
        }

        var exception = Assert.Throws<LocalStateResetRequiredException>(() =>
            new SqliteDeepAccountStore(new SqliteDeepAccountStoreOptions(
                path,
                TestDatabaseKey(),
                TestDatabaseInstanceId())));

        Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteInvalidDeepIdValue_IsReportedAsResetRequired()
    {
        var path = TempPath();
        await using var store = new SqliteDeepAccountStore(
            new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId()));
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(service, "Alice");
        using (var connection = OpenTestDatabase(path))
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE local_account SET deep_id='deep1invalid' WHERE singleton=1;";
            command.ExecuteNonQuery();
        }

        var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
            store.ReadAsync(created.Identity.Device.Identity));

        Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteHostileStorageClass_IsNormalizedToResetRequired()
    {
        var path = TempPath();
        await using var store = new SqliteDeepAccountStore(
            new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId()));
        using var secureStorage = new InMemoryDeepSecureStorage();
        var created = await CreateConfirmedAsync(CreateService(store, secureStorage), "Alice");
        using (var connection = OpenTestDatabase(path))
        {
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA ignore_check_constraints=ON; UPDATE local_device SET device_generation='hostile' WHERE singleton=1;";
            Assert.Equal(1, command.ExecuteNonQuery());
        }

        var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
            store.ReadAsync(created.Identity.Device.Identity));

        Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
        DeleteSqliteFiles(path);
    }

    [Fact]
    public async Task SqliteLateMutationSchemaFailure_IsNormalizedToResetRequired()
    {
        var path = TempPath();
        await using var store = new SqliteDeepAccountStore(
            new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId()));
        using var secureStorage = new InMemoryDeepSecureStorage();
        var created = await CreateConfirmedAsync(CreateService(store, secureStorage), "Alice");
        await using var mutationLease = await store.AcquireMutationLeaseAsync();
        var identity = Assert.IsType<DeepLocalIdentitySnapshot>(
            await store.ReadAsync(created.Identity.Device.Identity));
        var operation = Assert.IsType<DeepAccountCreationOperation>(
            await store.ReadCreationOperationAsync());
        var immutableIdentityCommitment = DeepAccountImmutableIdentityHash.Compute(identity);
        try
        {
            var capability = new DeepAccountReconciledMutationCapability(
                mutationLease,
                operation,
                immutableIdentityCommitment);
            using (var connection = OpenTestDatabase(path))
            {
                using var command = connection.CreateCommand();
                command.CommandText = "ALTER TABLE local_profile RENAME COLUMN display_name TO damaged_name;";
                command.ExecuteNonQuery();
            }

            var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
                store.UpdateProfileAsync(
                    capability,
                    identity.Account.PermanentId,
                    new DeepLocalProfile("Alice updated", Now.AddMinutes(1))));

            Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(immutableIdentityCommitment);
            await mutationLease.DisposeAsync();
            DeleteSqliteFiles(path);
        }
    }

    private static DeepAccountService CreateService(
        IDeepAccountStore store,
        IDeepSecureStorage secureStorage) =>
        new(store, secureStorage, new FrozenClock(Now), NetworkId);

    private static async Task<DeepAccountCreationResult> CreateConfirmedAsync(
        DeepAccountService service,
        string displayName,
        CancellationToken cancellationToken = default)
    {
        using var draft = service.PrepareCreate(displayName);
        var phraseBytes = RevealPhraseBytes(draft);
        try
        {
            using var confirmation = DeepOwnedRecoveryPhraseUtf8.CopyFrom(phraseBytes);
            return await service.CommitPreparedAsync(draft, confirmation, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(phraseBytes);
        }
    }

    private static async Task<(DeepAccountCreationResult Result, byte[] RecoveryBytes)>
        CreateConfirmedWithPhraseAsync(DeepAccountService service, string displayName)
    {
        using var draft = service.PrepareCreate(displayName);
        var phraseBytes = RevealPhraseBytes(draft);
        try
        {
            using var confirmation = DeepOwnedRecoveryPhraseUtf8.CopyFrom(phraseBytes);
            var result = await service.CommitPreparedAsync(draft, confirmation);
            return (result, phraseBytes);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(phraseBytes);
            throw;
        }
    }

    private static byte[] RevealPhraseBytes(DeepPreparedAccountCreationDraft draft)
    {
        byte[]? result = null;
        draft.RevealCanonicalPhraseOnce(value => result = value.ToArray());
        return result ?? throw new InvalidOperationException("Recovery phrase callback was not invoked.");
    }

    private static async Task<byte[]?> ReadSecretSnapshotAsync(
        IDeepSecureStorage secureStorage,
        string slot)
    {
        using var owned = await secureStorage.ReadOwnedAsync(slot);
        if (owned is null)
        {
            return null;
        }
        var result = new byte[owned.Length];
        owned.CopyTo(result);
        return result;
    }

    private static IDeepAccountStore CreateStore(bool sqlite, string path) =>
        sqlite
            ? new SqliteDeepAccountStore(new SqliteDeepAccountStoreOptions(path, TestDatabaseKey(), TestDatabaseInstanceId()))
            : new InMemoryDeepAccountStore();

    private static byte[] TestDatabaseKey() =>
        SHA256.HashData("Deep/Store/V1/tests/database-key"u8);

    private static byte[] TestDatabaseInstanceId() =>
        SHA256.HashData("Deep/Store/V1/tests/database-instance"u8);

    private static SqliteConnection OpenTestDatabase(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false
        }.ToString());
        connection.Open();
        var key = TestDatabaseKey();
        try
        {
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(connection.Handle, key));
            return connection;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private sealed class BorrowingWriteCaptureSecureStorage(IDeepSecureStorage inner) :
        IDeepSecureStorage
    {
        public Dictionary<string, ReadOnlyMemory<byte>> BorrowedWrites { get; } =
            new(StringComparer.Ordinal);

        public Task<OwnedDeepSecret?> ReadOwnedAsync(
            string slot,
            CancellationToken cancellationToken = default) =>
            inner.ReadOwnedAsync(slot, cancellationToken);

        public Task WriteBatchAsync(
            IReadOnlyList<DeepSecureStorageWrite> writes,
            CancellationToken cancellationToken = default)
        {
            foreach (var write in writes)
            {
                BorrowedWrites[write.Slot] = write.Value;
            }
            return inner.WriteBatchAsync(writes, cancellationToken);
        }

        public Task DeleteBatchAsync(
            IReadOnlyList<string> slots,
            CancellationToken cancellationToken = default) =>
            inner.DeleteBatchAsync(slots, cancellationToken);

        public Task PurgeStoreV1NamespaceAsync(
            CancellationToken cancellationToken = default) =>
            inner.PurgeStoreV1NamespaceAsync(cancellationToken);
    }

    private sealed class TrackingSecureStorage(IDeepSecureStorage inner) : IDeepSecureStorage
    {
        public IReadOnlyList<string> LastWrittenSlots { get; private set; } = [];
        public IReadOnlyList<string> LastDeletedSlots { get; private set; } = [];

        public void ClearTracking()
        {
            LastWrittenSlots = [];
            LastDeletedSlots = [];
        }

        public Task<OwnedDeepSecret?> ReadOwnedAsync(
            string slot,
            CancellationToken cancellationToken = default) =>
            inner.ReadOwnedAsync(slot, cancellationToken);

        public Task WriteBatchAsync(
            IReadOnlyList<DeepSecureStorageWrite> writes,
            CancellationToken cancellationToken = default)
        {
            LastWrittenSlots = writes.Select(static write => write.Slot).ToArray();
            return inner.WriteBatchAsync(writes, cancellationToken);
        }

        public Task DeleteBatchAsync(
            IReadOnlyList<string> slots,
            CancellationToken cancellationToken = default)
        {
            LastDeletedSlots = slots.ToArray();
            return inner.DeleteBatchAsync(slots, cancellationToken);
        }

        public Task PurgeStoreV1NamespaceAsync(CancellationToken cancellationToken = default) =>
            inner.PurgeStoreV1NamespaceAsync(cancellationToken);
    }

    private sealed class FailPendingDeleteOnceSecureStorage(IDeepSecureStorage inner) : IDeepSecureStorage
    {
        private int failNextPendingDelete = 1;

        public int InjectedFailures { get; private set; }

        public Task<OwnedDeepSecret?> ReadOwnedAsync(
            string slot,
            CancellationToken cancellationToken = default) =>
            inner.ReadOwnedAsync(slot, cancellationToken);

        public Task WriteBatchAsync(
            IReadOnlyList<DeepSecureStorageWrite> writes,
            CancellationToken cancellationToken = default) =>
            inner.WriteBatchAsync(writes, cancellationToken);

        public Task DeleteBatchAsync(
            IReadOnlyList<string> slots,
            CancellationToken cancellationToken = default)
        {
            if (slots.Count == 1
                && string.Equals(
                    slots[0],
                    DeepAccountService.PendingSecureStorageJournalSlot,
                    StringComparison.Ordinal)
                && Interlocked.Exchange(ref failNextPendingDelete, 0) == 1)
            {
                InjectedFailures++;
                throw new IOException("Injected pending-journal cleanup failure.");
            }
            return inner.DeleteBatchAsync(slots, cancellationToken);
        }

        public Task PurgeStoreV1NamespaceAsync(CancellationToken cancellationToken = default) =>
            inner.PurgeStoreV1NamespaceAsync(cancellationToken);
    }

    private sealed class ReceiptReadFailingStore(IDeepAccountStore inner) : IDeepAccountStore
    {
        private int failNextReceiptRead;

        public ValueTask<DeepAccountMutationLease> AcquireMutationLeaseAsync(
            CancellationToken cancellationToken = default) =>
            inner.AcquireMutationLeaseAsync(cancellationToken);

        public Task<DeepAccountIdentityCapability?> ReadAccountIdentityAsync(
            CancellationToken cancellationToken = default) =>
            inner.ReadAccountIdentityAsync(cancellationToken);

        public Task<DeepLocalIdentitySnapshot?> ReadAsync(
            LocalDeviceIdentityIntent? localDeviceIdentity,
            CancellationToken cancellationToken = default) =>
            inner.ReadAsync(localDeviceIdentity, cancellationToken);

        public async Task CreateAsync(
            DeepAccountReconciledMutationCapability mutationCapability,
            DeepLocalIdentitySnapshot identity,
            DeepAccountCreationOperation operation,
            ReadOnlyMemory<byte> immutableIdentityCommitment,
            CancellationToken cancellationToken = default)
        {
            try
            {
                await inner.CreateAsync(
                    mutationCapability,
                    identity,
                    operation,
                    immutableIdentityCommitment,
                    cancellationToken);
            }
            catch
            {
                Volatile.Write(ref failNextReceiptRead, 1);
                throw;
            }
        }

        public Task<DeepAccountCreationOperation?> ReadCreationOperationAsync(
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref failNextReceiptRead, 0) == 1)
            {
                throw new IOException("Injected receipt read failure.");
            }
            return inner.ReadCreationOperationAsync(cancellationToken);
        }

        public Task UpdateProfileAsync(
            DeepAccountReconciledMutationCapability mutationCapability,
            DeepPermanentIdV1 account,
            DeepLocalProfile profile,
            CancellationToken cancellationToken = default) =>
            inner.UpdateProfileAsync(mutationCapability, account, profile, cancellationToken);

        public Task ClearLocalAccountAsync(
            DeepAccountReconciledMutationCapability mutationCapability,
            CancellationToken cancellationToken = default) =>
            inner.ClearLocalAccountAsync(mutationCapability, cancellationToken);

        public DeepSecureStorageSlots GetGenerationSecureStorageSlots() =>
            inner.GetGenerationSecureStorageSlots();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class InjectedCommitFaultException(DeepAccountCommitFaultPoint point) :
        Exception($"Injected STORE-01 fault at {point}.");

    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), $"deep-store01-{Guid.NewGuid():N}.db");

    private static void DeleteSqliteFiles(string path)
    {
        foreach (var candidate in new[]
                 {
                     path, path + "-wal", path + "-shm",
                      path + ".creating", path + ".creating-wal", path + ".creating-shm",
                      path + ".bootstrap.lock", path + ".account.lock",
                      path + ".creating.generation.lock"
                 })
        {
            if (File.Exists(candidate))
            {
                File.Delete(candidate);
            }
        }
    }

    private static void AssertDatabaseGenerationArtifactsAbsent(string path)
    {
        foreach (var candidate in new[]
                 {
                     path, path + "-wal", path + "-shm",
                     path + ".creating", path + ".creating-wal", path + ".creating-shm"
                 })
        {
            Assert.False(File.Exists(candidate), $"Unexpected generation artifact: {candidate}");
        }
    }

    private sealed class InjectedLifecycleFaultException(
        SqliteDeepAccountStoreLifecycleFaultPoint point) :
        Exception($"Injected STORE-01 lifecycle fault at {point}.");
}
