using System.Reflection;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.Identity;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class DeepAccountIdentityOperationsTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-07T00:00:00Z");
    private static readonly byte[] NetworkId = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray();

    [Fact]
    public async Task CurrentDeviceOperations_SignAndScopeExactAgreementAndPrekeySecrets()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var storage = new ReadTrackingSecureStorage();
        var service = CreateService(store, storage);
        var identity = (await CreateConfirmedAsync(service)).Identity;
        storage.ClearCapturedReads();

        var message = "future-dpk2-signing-input"u8.ToArray();
        var signature = await service.SignWithCurrentDeviceAsync(identity, message);
        var signingPublic = identity.Device.SigningPublicKey.ToArray();
        try
        {
            Assert.True(PublicKeyAuth.VerifyDetached(signature, message, signingPublic));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(signingPublic);
        }

        var agreementPublic = await service.UseCurrentDeviceAgreementKeyAsync(identity, (lease, token) =>
        {
            token.ThrowIfCancellationRequested();
            byte[]? result = null;
            lease.Use(secret => result = DeepIdentityCrypto.DeriveX25519PublicKey(secret));
            return result ?? throw new InvalidOperationException("Agreement callback did not run.");
        });
        Assert.True(identity.Device.AgreementPublicKey.Span.SequenceEqual(agreementPublic));

        var prekeyPublic = await service.UseCurrentDevicePrekeyAsync(identity, (lease, token) =>
        {
            token.ThrowIfCancellationRequested();
            byte[]? result = null;
            lease.Use(secret => result = DeepIdentityCrypto.DeriveX25519PublicKey(secret));
            return result ?? throw new InvalidOperationException("Prekey callback did not run.");
        });
        Assert.True(identity.Device.PrekeyPublicKey.Span.SequenceEqual(prekeyPublic));
        Assert.All(storage.CapturedReadBuffers, static value =>
            Assert.True(value.AsSpan().IndexOfAnyExcept((byte)0) < 0));
        Zero(agreementPublic);
        Zero(prekeyPublic);
    }

    [Theory]
    [InlineData("signing", true)]
    [InlineData("signing", false)]
    [InlineData("agreement", true)]
    [InlineData("agreement", false)]
    [InlineData("prekey", true)]
    [InlineData("prekey", false)]
    public async Task CurrentDeviceOperations_MissingOrMismatchedRoleSlotFailsClosed(
        string role,
        bool missing)
    {
        await using var store = new InMemoryDeepAccountStore();
        using var storage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, storage);
        var identity = (await CreateConfirmedAsync(service)).Identity;
        var slot = role switch
        {
            "signing" => identity.SecureSlots.DeviceSigningKey,
            "agreement" => identity.SecureSlots.DeviceAgreementKey,
            "prekey" => identity.SecureSlots.DevicePrekey,
            _ => throw new InvalidOperationException()
        };
        var replacement = Enumerable.Repeat((byte)0xa5, 32).ToArray();
        try
        {
            await storage.DeleteBatchAsync([slot]);
            if (!missing)
            {
                await storage.WriteBatchAsync([new DeepSecureStorageWrite(slot, replacement)]);
            }

            var callbackInvoked = false;
            Task operation = role switch
            {
                "signing" => service.SignWithCurrentDeviceAsync(identity, "message"u8.ToArray()),
                "agreement" => service.UseCurrentDeviceAgreementKeyAsync(
                    identity,
                    (_, _) => callbackInvoked = true),
                "prekey" => service.UseCurrentDevicePrekeyAsync(
                    identity,
                    (_, _) => callbackInvoked = true),
                _ => throw new InvalidOperationException()
            };
            var exception = await Assert.ThrowsAsync<LocalStateResetRequiredException>(() => operation);
            Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
            Assert.False(callbackInvoked);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(replacement);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CurrentDeviceOperations_MissingOrMismatchedDeviceIdSlotFailsBeforeCallback(
        bool missing)
    {
        await using var store = new InMemoryDeepAccountStore();
        using var storage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, storage);
        var identity = (await CreateConfirmedAsync(service)).Identity;
        var replacement = Enumerable.Repeat((byte)0x5a, 32).ToArray();
        try
        {
            await storage.DeleteBatchAsync([identity.SecureSlots.DeviceId]);
            if (!missing)
            {
                await storage.WriteBatchAsync(
                    [new DeepSecureStorageWrite(identity.SecureSlots.DeviceId, replacement)]);
            }

            var callbackInvoked = false;
            await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
                service.UseCurrentDeviceAgreementKeyAsync(
                    identity,
                    (_, _) => callbackInvoked = true));
            Assert.False(callbackInvoked);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(replacement);
        }
    }

    [Fact]
    public async Task CurrentDeviceOperations_MissingOrForeignExpectedSnapshotFailsBeforeCallback()
    {
        await using var populatedStore = new InMemoryDeepAccountStore();
        using var populatedStorage = new InMemoryDeepSecureStorage();
        var populatedService = CreateService(populatedStore, populatedStorage);
        var expected = (await CreateConfirmedAsync(populatedService)).Identity;

        await using var emptyStore = new InMemoryDeepAccountStore();
        using var emptyStorage = new InMemoryDeepSecureStorage();
        var emptyService = CreateService(emptyStore, emptyStorage);
        var callbackInvoked = false;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            emptyService.UseCurrentDeviceAgreementKeyAsync(
                expected,
                (_, _) => callbackInvoked = true));
        Assert.False(callbackInvoked);

        await using var foreignStore = new InMemoryDeepAccountStore();
        using var foreignStorage = new InMemoryDeepSecureStorage();
        var foreignIdentity = (await CreateConfirmedAsync(
            CreateService(foreignStore, foreignStorage))).Identity;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            populatedService.UseCurrentDevicePrekeyAsync(
                foreignIdentity,
                (_, _) => callbackInvoked = true));
        Assert.False(callbackInvoked);
    }

    [Fact]
    public async Task CurrentDeviceOperations_CallbackThrowAndCancellationDisposeAndZeroOwnedReads()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var storage = new ReadTrackingSecureStorage();
        var service = CreateService(store, storage);
        var identity = (await CreateConfirmedAsync(service)).Identity;
        storage.ClearCapturedReads();

        await Assert.ThrowsAsync<InjectedCallbackException>(() =>
            service.UseCurrentDeviceAgreementKeyAsync<bool>(identity, (_, _) =>
            {
                throw new InjectedCallbackException();
            }));
        Assert.All(storage.CapturedReadBuffers, AssertZero);

        storage.ClearCapturedReads();
        using var cancellation = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.UseCurrentDevicePrekeyAsync<bool>(identity, (_, token) =>
            {
                cancellation.Cancel();
                token.ThrowIfCancellationRequested();
                return true;
            }, cancellation.Token));
        Assert.All(storage.CapturedReadBuffers, AssertZero);

        storage.ClearCapturedReads();
        using var alreadyCancelled = new CancellationTokenSource();
        alreadyCancelled.Cancel();
        var invoked = false;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.UseCurrentDeviceAgreementKeyAsync(
                identity,
                (_, _) => invoked = true,
                alreadyCancelled.Token));
        Assert.False(invoked);
        Assert.Empty(storage.CapturedReadBuffers);
    }

    [Fact]
    public void CurrentDeviceSecretSurface_HasNoRawSecretReturnOrAccessor()
    {
        Assert.True(typeof(DeepDeviceSecretScope).IsByRefLike);
        Assert.False(typeof(DeepDeviceSecretScope).IsPublic);
        Assert.Empty(typeof(DeepDeviceSecretScope).GetProperties(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(DeepDeviceSecretScope).GetFields(BindingFlags.Public | BindingFlags.Instance));
        var use = Assert.Single(
            typeof(DeepDeviceSecretScope).GetMethods(BindingFlags.NonPublic | BindingFlags.Instance),
            static method => method.Name == nameof(DeepDeviceSecretScope.Use));
        Assert.Equal(typeof(void), use.ReturnType);
        Assert.False(typeof(DeepDeviceSecretScopeFunc<>).IsPublic);
        Assert.True(typeof(DeepDeviceSecretScopeFunc<>).GetMethod("Invoke")!.ReturnType.IsGenericParameter);

        Assert.DoesNotContain(
            typeof(DeepAccountService).GetMethods(BindingFlags.Public | BindingFlags.Instance),
            static method => method.Name.Contains("AgreementKey", StringComparison.Ordinal)
                || method.Name.Contains("Prekey", StringComparison.Ordinal)
                || method.Name.Contains("SessionId", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            typeof(DeepAccountService).Assembly.GetExportedTypes(),
            static type => type.Name.Contains("DeviceSecret", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CurrentDeviceOperation_SerializesConcurrentResetUntilCallbackCompletes()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var storage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, storage);
        var identity = (await CreateConfirmedAsync(service)).Identity;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim();

        var operation = Task.Run(() => service.UseCurrentDeviceAgreementKeyAsync(identity, (_, _) =>
        {
            entered.TrySetResult();
            release.Wait();
            return true;
        }));
        Task? reset = null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            reset = service.ResetLocalAccountAsync();
            Assert.NotSame(reset, await Task.WhenAny(reset, Task.Delay(100)));
        }
        finally
        {
            release.Set();
        }
        await operation;
        await (reset ?? throw new InvalidOperationException("Reset did not start."));
        Assert.Null(await service.GetLocalIdentityAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.SignWithCurrentDeviceAsync(identity, "after-reset"u8.ToArray()));
    }

    [Fact]
    public async Task CurrentDeviceOperation_SerializesConcurrentProfileUpdateWithoutInvalidatingKeyBinding()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var storage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, storage);
        var identity = (await CreateConfirmedAsync(service)).Identity;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim();

        var operation = Task.Run(() => service.UseCurrentDevicePrekeyAsync(identity, (_, _) =>
        {
            entered.TrySetResult();
            release.Wait();
            return true;
        }));
        Task<DeepAccount>? update = null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            update = service.UpdateDisplayNameAsync("Alice updated");
            Assert.NotSame(update, await Task.WhenAny(update, Task.Delay(100)));
        }
        finally
        {
            release.Set();
        }
        await operation;
        Assert.Equal(
            "Alice updated",
            (await (update ?? throw new InvalidOperationException("Update did not start."))).DisplayName);

        var invoked = false;
        await service.UseCurrentDeviceAgreementKeyAsync(identity, (_, _) => invoked = true);
        Assert.True(invoked);
    }

    private static DeepAccountService CreateService(
        IDeepAccountStore store,
        IDeepSecureStorage storage) =>
        new(store, storage, new FrozenClock(Now), NetworkId);

    private static async Task<DeepAccountCreationResult> CreateConfirmedAsync(
        DeepAccountService service)
    {
        using var draft = service.PrepareCreate("Alice");
        byte[]? phrase = null;
        draft.RevealCanonicalPhraseOnce(value => phrase = value.ToArray());
        try
        {
            using var confirmation = DeepOwnedRecoveryPhraseUtf8.CopyFrom(phrase!);
            return await service.CommitPreparedAsync(draft, confirmation);
        }
        finally
        {
            Zero(phrase);
        }
    }

    private static void AssertZero(byte[] value) =>
        Assert.True(value.AsSpan().IndexOfAnyExcept((byte)0) < 0);

    private static void Zero(byte[]? value)
    {
        if (value is not null)
            CryptographicOperations.ZeroMemory(value);
    }

    private sealed class InjectedCallbackException : Exception
    {
    }

    private sealed class ReadTrackingSecureStorage : IDeepSecureStorage, IDisposable
    {
        private static readonly FieldInfo OwnedValueField = typeof(OwnedDeepSecret).GetField(
            "value",
            BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException("OwnedDeepSecret backing field is absent.");
        private readonly InMemoryDeepSecureStorage inner = new();
        private readonly object gate = new();
        private readonly List<byte[]> capturedReadBuffers = [];

        internal IReadOnlyList<byte[]> CapturedReadBuffers
        {
            get
            {
                lock (gate)
                    return capturedReadBuffers.ToArray();
            }
        }

        internal void ClearCapturedReads()
        {
            lock (gate)
                capturedReadBuffers.Clear();
        }

        public async Task<OwnedDeepSecret?> ReadOwnedAsync(
            string slot,
            CancellationToken cancellationToken = default)
        {
            var owned = await inner.ReadOwnedAsync(slot, cancellationToken);
            if (owned is not null)
            {
                var buffer = Assert.IsType<byte[]>(OwnedValueField.GetValue(owned));
                lock (gate)
                    capturedReadBuffers.Add(buffer);
            }
            return owned;
        }

        public Task WriteBatchAsync(
            IReadOnlyList<DeepSecureStorageWrite> writes,
            CancellationToken cancellationToken = default) =>
            inner.WriteBatchAsync(writes, cancellationToken);

        public Task DeleteBatchAsync(
            IReadOnlyList<string> slots,
            CancellationToken cancellationToken = default) =>
            inner.DeleteBatchAsync(slots, cancellationToken);

        public Task PurgeStoreV1NamespaceAsync(CancellationToken cancellationToken = default) =>
            inner.PurgeStoreV1NamespaceAsync(cancellationToken);

        public void Dispose() => inner.Dispose();
    }
}
