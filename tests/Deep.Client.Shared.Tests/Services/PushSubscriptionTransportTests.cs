using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Platform;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Services;

public sealed class PushSubscriptionTransportTests
{
    private const string ValidRecoveryPhrase = "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed";

    [Fact]
    public async Task HttpPushSubscriptionTransport_UsesBackendContractJson()
    {
        var requestBodies = new List<string>();

        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            requestBodies.Add(request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"success\":true}", Encoding.UTF8, "application/json")
            };
        }))
        {
            BaseAddress = new Uri("http://localhost/")
        };

        var transport = new HttpPushSubscriptionTransport(client, new HttpPushSubscriptionTransportOptions("http://localhost"));

        await transport.SubscribeAsync(new PushSubscriptionRequest(
            "05abc",
            "ed25519pub",
            [0],
            true,
            "firebase",
            123,
            "signature",
            new PushSubscriptionServiceInfo("token-1"),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"));
        await transport.UnsubscribeAsync(new PushUnsubscribeRequest(
            "05abc",
            "ed25519pub",
            "firebase",
            124,
            "signature-2",
            new PushSubscriptionServiceInfo("token-2")));

        Assert.Equal(2, requestBodies.Count);

        using var subscribeJson = JsonDocument.Parse(requestBodies[0]);
        Assert.Equal("05abc", subscribeJson.RootElement.GetProperty("pubkey").GetString());
        Assert.Equal("ed25519pub", subscribeJson.RootElement.GetProperty("session_ed25519").GetString());
        Assert.Equal("firebase", subscribeJson.RootElement.GetProperty("service").GetString());
        Assert.Equal("token-1", subscribeJson.RootElement.GetProperty("service_info").GetProperty("token").GetString());
        Assert.Equal("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", subscribeJson.RootElement.GetProperty("enc_key").GetString());
        Assert.Equal(2, subscribeJson.RootElement.GetProperty("sig_v").GetInt32());

        using var unsubscribeJson = JsonDocument.Parse(requestBodies[1]);
        Assert.Equal("token-2", unsubscribeJson.RootElement.GetProperty("service_info").GetProperty("token").GetString());
        Assert.False(unsubscribeJson.RootElement.TryGetProperty("enc_key", out _));
        Assert.Equal(2, unsubscribeJson.RootElement.GetProperty("sig_v").GetInt32());
    }

    [Fact]
    public void HttpPushSubscriptionTransport_RequiresHttpsOutsideExplicitLoopback()
    {
        using var client = new HttpClient(new FakeHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)));

        Assert.Throws<ArgumentException>(() => new HttpPushSubscriptionTransport(
            client,
            new HttpPushSubscriptionTransportOptions("http://push.example.test")));

        var loopback = new HttpPushSubscriptionTransport(
            client,
            new HttpPushSubscriptionTransportOptions("http://127.0.0.1:8080"));
        Assert.True(loopback.IsEnabled);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_RegisterAsync_ComposesVerifiableRemoteSubscription()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");

        var pushNotifications = new FakePushNotificationService(new PushRegistration(
            "token-123",
            "fcm",
            DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var transport = new FakePushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(
            runtime,
            pushNotifications,
            transport,
            runtime.Clock,
            new PushClientMetadata(PushNotificationCrypto.PackageName, "0.2.8"));

        var registration = await coordinator.RegisterAsync();
        var activeAccount = await runtime.Accounts.GetActiveAccountAsync();

        Assert.NotNull(registration);
        Assert.Single(transport.SubscribeRequests);
        Assert.Equal("firebase", transport.SubscribeRequests[0].Service);
        Assert.Equal("token-123", transport.SubscribeRequests[0].ServiceInfo.Token);
        Assert.Equal([0, 10], transport.SubscribeRequests[0].Namespaces);
        Assert.Equal(activeAccount!.SessionId.Value, transport.SubscribeRequests[0].Pubkey);
        Assert.Equal(pushNotifications.EncryptionState?.KeyHex, transport.SubscribeRequests[0].EncKey);
        Assert.Equal(PushNotificationCrypto.PackageName, transport.SubscribeRequests[0].AppId);
        Assert.Equal("0.2.8", transport.SubscribeRequests[0].AppVersion);
        Assert.False(string.IsNullOrWhiteSpace(transport.SubscribeRequests[0].SessionEd25519));
        Assert.NotNull(pushNotifications.EncryptionState);
        Assert.True(pushNotifications.EncryptionState!.RemoteSubscribed);
        Assert.Equal(registration, pushNotifications.EncryptionState!.Registration);
        Assert.Equal(transport.SubscribeRequests[0].Pubkey, pushNotifications.EncryptionState.SessionBinding);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_UnregisterAsync_UsesCachedRegistrationForRemoteUnsubscribe()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");

        var cachedRegistration = new PushRegistration("token-123", "fcm", DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var pushNotifications = new FakePushNotificationService(cachedRegistration);
        var transport = new FakePushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        await coordinator.UnregisterAsync();

        Assert.Single(transport.UnsubscribeRequests);
        Assert.Equal("firebase", transport.UnsubscribeRequests[0].Service);
        Assert.Equal("token-123", transport.UnsubscribeRequests[0].ServiceInfo.Token);
        Assert.True(pushNotifications.UnregisterCalled);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_SkipsUnsupportedProviders()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");

        var pushNotifications = new FakePushNotificationService(new PushRegistration(
            "token-123",
            "apns",
            DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var transport = new FakePushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        var registration = await coordinator.RegisterAsync();

        Assert.Null(registration);
        Assert.Empty(transport.SubscribeRequests);
        Assert.Null(pushNotifications.EncryptionState);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_UnregisterCancelsLateSubscribeAndAllowsSameAccountReregister()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");
        var pushNotifications = new FakePushNotificationService(
            new PushRegistration("token-race", "fcm", DateTimeOffset.UtcNow));
        var transport = new BlockingPushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        var registration = coordinator.RegisterAsync();
        await transport.SubscribeStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var logout = coordinator.UnregisterAsync();
        transport.ReleaseSubscribe();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await registration);
        await logout;

        Assert.False(transport.RemoteSubscribed);
        Assert.Null(pushNotifications.EncryptionState);
        Assert.True(pushNotifications.UnregisterCalled);
        Assert.NotNull(await coordinator.RegisterAsync());
        await coordinator.UnregisterAsync();

        await runtime.Accounts.SignOutAsync();
        await runtime.Accounts.RegisterAsync("Bob");
        Assert.NotNull(await coordinator.RegisterAsync());
        Assert.True(transport.RemoteSubscribed);
    }

    [Theory]
    [InlineData("apns")]
    [InlineData("huawei")]
    public void PushRegistrationCoordinator_DoesNotAdvertiseUnconfiguredServerProviders(string provider)
    {
        Assert.False(PushRegistrationCoordinator.TryResolvePushService(provider, out _));
    }

    [Theory]
    [InlineData("wns")]
    [InlineData("WNS")]
    public void PushRegistrationCoordinator_MapsWindowsProviderToWns(string provider)
    {
        Assert.True(PushRegistrationCoordinator.TryResolvePushService(provider, out var service));
        Assert.Equal("wns", service);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_UnregisterWithoutAccountDoesNotBlockFutureLogin()
    {
        var runtime = ClientRuntime.CreateStubbed();
        var pushNotifications = new FakePushNotificationService(
            new PushRegistration("token-new-account", "fcm", DateTimeOffset.UtcNow));
        var coordinator = new PushRegistrationCoordinator(
            runtime,
            pushNotifications,
            new FakePushSubscriptionTransport(),
            runtime.Clock);

        await coordinator.UnregisterAsync();
        await runtime.Accounts.RegisterAsync("Alice");

        Assert.NotNull(await coordinator.RegisterAsync());
    }

    [Fact]
    public async Task PushRegistrationCoordinator_DoesNotPersistLocalStateWhenRemoteSubscribeFails()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");
        var pushNotifications = new FakePushNotificationService(new PushRegistration("token-123", "fcm", DateTimeOffset.UtcNow));
        var transport = new FakePushSubscriptionTransport { SubscribeFailure = new InvalidOperationException("backend unavailable") };
        var coordinator = new PushRegistrationCoordinator(
            runtime,
            pushNotifications,
            transport,
            runtime.Clock,
            new PushClientMetadata(PushNotificationCrypto.PackageName, "0.2.8"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => coordinator.RegisterAsync());

        Assert.Null(pushNotifications.EncryptionState);
        Assert.Null(await runtime.Store.GetAsync<string>(PushRegistrationCoordinator.NotificationEncryptionKeySetting));
    }

    [Fact]
    public async Task PushRegistrationCoordinator_InvalidatesAndResubscribesAfterTokenRotation()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");
        var pushNotifications = new FakePushNotificationService(new PushRegistration("token-old", "fcm", DateTimeOffset.UtcNow));
        var transport = new FakePushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        await coordinator.RegisterAsync();
        pushNotifications.Registration = new PushRegistration("token-new", "fcm", DateTimeOffset.UtcNow);
        await coordinator.RegisterAsync();

        Assert.Equal(["token-old", "token-new"], transport.SubscribeRequests.Select(static request => request.ServiceInfo.Token));
        Assert.Equal("token-new", pushNotifications.EncryptionState!.Registration.Token);
        Assert.True(pushNotifications.RemoveCalls >= 1);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_CurrentAccountRegistrationIsIdempotent()
    {
        var runtime = ClientRuntime.CreateStubbed();
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");
        var pushNotifications = new FakePushNotificationService(
            new PushRegistration("token-123", "fcm", DateTimeOffset.UtcNow));
        var transport = new FakePushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        var first = await coordinator.RegisterAsync();
        var second = await coordinator.RegisterAsync();

        Assert.Equal(first, second);
        Assert.Single(transport.SubscribeRequests);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_AccountSwitchReRegistersForTheNewSession()
    {
        var runtime = ClientRuntime.CreateStubbed();
        var firstAccount = await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");
        var pushNotifications = new FakePushNotificationService(
            new PushRegistration("token-123", "fcm", DateTimeOffset.UtcNow));
        var transport = new FakePushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        await coordinator.RegisterAsync();
        await runtime.Accounts.SignOutAsync();
        var secondAccount = await runtime.Accounts.RegisterAsync("Bob");
        await coordinator.RegisterAsync();

        Assert.Equal(
            [firstAccount.SessionId.Value, secondAccount.SessionId.Value],
            transport.SubscribeRequests.Select(static request => request.Pubkey));
        Assert.Equal(secondAccount.SessionId.Value, pushNotifications.EncryptionState!.SessionBinding);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_FailedUnsubscribeRetriesAfterSeedIsPurged()
    {
        var runtime = ClientRuntime.CreateStubbed();
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");
        var pushNotifications = new FakePushNotificationService(
            new PushRegistration("token-123", "fcm", DateTimeOffset.UtcNow));
        var transport = new FakePushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);
        await coordinator.RegisterAsync();
        transport.UnsubscribeFailure = new InvalidOperationException("offline");

        await Assert.ThrowsAsync<InvalidOperationException>(() => coordinator.UnregisterAsync());
        var pending = Assert.IsType<PushUnsubscribeRequest>(pushNotifications.PendingUnsubscribe);
        Assert.Equal("token-123", pending.ServiceInfo.Token);

        await runtime.Accounts.SignOutAsync();
        Assert.Null(await runtime.Accounts.GetRecoveryPhraseAsync());
        transport.UnsubscribeFailure = null;

        Assert.True(await coordinator.RetryPendingUnsubscribeAsync());
        Assert.Null(pushNotifications.PendingUnsubscribe);
        Assert.False(transport.RemoteSubscribed);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_LateSubscribeAfterTimedOutLogoutIsCompensated()
    {
        var runtime = ClientRuntime.CreateStubbed();
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");
        var pushNotifications = new FakePushNotificationService(
            new PushRegistration("token-race", "fcm", DateTimeOffset.UtcNow));
        var transport = new BlockingPushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        var registration = coordinator.RegisterAsync();
        await transport.SubscribeStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        using var logoutCancellation = new CancellationTokenSource();
        var unregister = coordinator.UnregisterAsync(logoutCancellation.Token);
        logoutCancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await unregister);

        var durableUnsubscribe = Assert.IsType<PushUnsubscribeRequest>(pushNotifications.PendingUnsubscribe);
        Assert.Equal("token-race", durableUnsubscribe.ServiceInfo.Token);
        Assert.Equal(64, Convert.FromBase64String(durableUnsubscribe.Signature).Length);
        Assert.Equal(32, Convert.FromHexString(durableUnsubscribe.SessionEd25519).Length);
        Assert.True(pushNotifications.UnregisterCalled);
        Assert.Null(pushNotifications.EncryptionState);

        await runtime.Accounts.SignOutAsync();
        transport.ReleaseSubscribe();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await registration);
        Assert.False(transport.RemoteSubscribed);
        Assert.Null(pushNotifications.EncryptionState);
        Assert.Null(pushNotifications.PendingUnsubscribe);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_SameAccountCanRegisterAfterOffOnAndRelogin()
    {
        var runtime = ClientRuntime.CreateStubbed();
        var firstLogin = await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");
        var pushNotifications = new FakePushNotificationService(
            new PushRegistration("token-same-account", "fcm", DateTimeOffset.UtcNow));
        var transport = new FakePushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        Assert.NotNull(await coordinator.RegisterAsync());
        await coordinator.UnregisterAsync();
        Assert.NotNull(await coordinator.RegisterAsync());

        await coordinator.UnregisterAsync();
        await runtime.Accounts.SignOutAsync();
        var secondLogin = await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice again");
        Assert.Equal(firstLogin.SessionId, secondLogin.SessionId);
        Assert.NotNull(await coordinator.RegisterAsync());

        Assert.Equal(3, transport.SubscribeRequests.Count);
        Assert.All(
            transport.SubscribeRequests,
            request => Assert.Equal(firstLogin.SessionId.Value, request.Pubkey));
    }

    [Fact]
    public async Task PushRegistrationCoordinator_CancelledRemoteUnsubscribeKeepsLocalStateInvalidAndSignedRetryDurable()
    {
        var runtime = ClientRuntime.CreateStubbed();
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");
        var pushNotifications = new FakePushNotificationService(
            new PushRegistration("token-timeout", "fcm", DateTimeOffset.UtcNow));
        var transport = new BlockingUnsubscribeTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);
        Assert.NotNull(await coordinator.RegisterAsync());

        using var timeout = new CancellationTokenSource();
        var unregister = coordinator.UnregisterAsync(timeout.Token);
        await transport.UnsubscribeStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        timeout.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await unregister);
        var pending = Assert.IsType<PushUnsubscribeRequest>(pushNotifications.PendingUnsubscribe);
        Assert.False(string.IsNullOrWhiteSpace(pending.Signature));
        Assert.Null(pushNotifications.EncryptionState);
        Assert.True(pushNotifications.UnregisterCalled);
        Assert.True(transport.RemoteSubscribed);

        transport.ReleaseUnsubscribe();
        Assert.True(await coordinator.RetryPendingUnsubscribeAsync());
        Assert.Null(pushNotifications.PendingUnsubscribe);
        Assert.False(transport.RemoteSubscribed);
    }

    [Fact]
    public async Task PushRegistrationCoordinator_RoundTripsRemoteSubscriptionThroughLivePush_WhenConfigured()
    {
        var pushUrl = Environment.GetEnvironmentVariable("DEEP_PUSH_URL");
        if (string.IsNullOrWhiteSpace(pushUrl))
        {
            return;
        }

        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            ClientFeatureFlags.ReleaseDefaults,
            new SystemClock(),
            new ThrowingMessageTransport());
        var account = await runtime.Accounts.RegisterAsync("Push Live");
        var token = $"live-fcm-{Guid.NewGuid():N}";
        var pushNotifications = new FakePushNotificationService(new PushRegistration(token, "fcm", DateTimeOffset.UtcNow));
        using var client = new HttpClient();
        var transport = new HttpPushSubscriptionTransport(client, new HttpPushSubscriptionTransportOptions(pushUrl));
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        var registration = await coordinator.RegisterAsync();

        Assert.NotNull(registration);
        Assert.Equal(token, registration.Token);
        Assert.True(await HasRemoteSubscriptionAsync(pushUrl, account.SessionId, token));

        await coordinator.UnregisterAsync();

        Assert.True(pushNotifications.UnregisterCalled);
        Assert.False(await HasRemoteSubscriptionAsync(pushUrl, account.SessionId, token));
    }

    private static async Task<bool> HasRemoteSubscriptionAsync(string pushUrl, SessionId sessionId, string token)
    {
        using var client = new HttpClient
        {
            BaseAddress = new Uri(pushUrl.EndsWith('/') ? pushUrl : pushUrl + "/", UriKind.Absolute)
        };
        var json = await client.GetStringAsync($"/subscriptions/{Uri.EscapeDataString(sessionId.Value)}");
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("subscriptions", out var subscriptions) ||
            subscriptions.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var subscription in subscriptions.EnumerateArray())
        {
            if (!subscription.TryGetProperty("service_info", out var serviceInfo) ||
                !serviceInfo.TryGetProperty("token", out var tokenElement))
            {
                continue;
            }

            if (string.Equals(tokenElement.GetString(), token, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private sealed class FakePushNotificationService(PushRegistration registration) :
        IPushNotificationService,
        IPushNotificationEncryptionKeyStore,
        IPushUnsubscribeRetryStore
    {
        public bool UnregisterCalled { get; private set; }
        public PushNotificationKeyState? EncryptionState { get; private set; }
        public int RemoveCalls { get; private set; }
        public PushRegistration Registration { get; set; } = registration;
        public PushUnsubscribeRequest? PendingUnsubscribe { get; private set; }

        public Task<PushRegistration?> RegisterAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<PushRegistration?>(Registration);

        public Task<PushRegistration?> GetCachedRegistrationAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<PushRegistration?>(EncryptionState?.RemoteSubscribed == true ? EncryptionState.Registration : Registration);

        public Task UnregisterAsync(CancellationToken cancellationToken = default)
        {
            UnregisterCalled = true;
            return Task.CompletedTask;
        }

        public Task<PushNotificationKeyState?> GetAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(EncryptionState);

        public Task SetAsync(PushNotificationKeyState state, CancellationToken cancellationToken = default)
        {
            EncryptionState = state;
            return Task.CompletedTask;
        }

        public Task RemoveAsync(CancellationToken cancellationToken = default)
        {
            RemoveCalls++;
            EncryptionState = null;
            return Task.CompletedTask;
        }

        public Task<PushUnsubscribeRequest?> GetPendingUnsubscribeAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult(PendingUnsubscribe);

        public Task SetPendingUnsubscribeAsync(
            PushUnsubscribeRequest request,
            CancellationToken cancellationToken = default)
        {
            PendingUnsubscribe = request;
            return Task.CompletedTask;
        }

        public Task RemovePendingUnsubscribeAsync(CancellationToken cancellationToken = default)
        {
            PendingUnsubscribe = null;
            return Task.CompletedTask;
        }
    }

    private sealed class FakePushSubscriptionTransport : IPushSubscriptionTransport
    {
        public bool IsEnabled => true;
        public Exception? SubscribeFailure { get; init; }
        public Exception? UnsubscribeFailure { get; set; }
        public bool RemoteSubscribed { get; private set; }

        public List<PushSubscriptionRequest> SubscribeRequests { get; } = [];

        public List<PushUnsubscribeRequest> UnsubscribeRequests { get; } = [];

        public Task SubscribeAsync(PushSubscriptionRequest request, CancellationToken cancellationToken = default)
        {
            SubscribeRequests.Add(request);
            if (SubscribeFailure is not null)
            {
                return Task.FromException(SubscribeFailure);
            }

            RemoteSubscribed = true;
            return Task.CompletedTask;
        }

        public Task UnsubscribeAsync(PushUnsubscribeRequest request, CancellationToken cancellationToken = default)
        {
            UnsubscribeRequests.Add(request);
            if (UnsubscribeFailure is not null)
            {
                return Task.FromException(UnsubscribeFailure);
            }

            RemoteSubscribed = false;
            return Task.CompletedTask;
        }
    }

    private sealed class BlockingPushSubscriptionTransport : IPushSubscriptionTransport
    {
        private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool IsEnabled => true;
        public bool RemoteSubscribed { get; private set; }
        public TaskCompletionSource SubscribeStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task SubscribeAsync(PushSubscriptionRequest request, CancellationToken cancellationToken = default)
        {
            SubscribeStarted.TrySetResult();
            await release.Task.ConfigureAwait(false);
            RemoteSubscribed = true;
        }

        public Task UnsubscribeAsync(PushUnsubscribeRequest request, CancellationToken cancellationToken = default)
        {
            RemoteSubscribed = false;
            return Task.CompletedTask;
        }

        public void ReleaseSubscribe() => release.TrySetResult();
    }

    private sealed class BlockingUnsubscribeTransport : IPushSubscriptionTransport
    {
        private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool IsEnabled => true;
        public bool RemoteSubscribed { get; private set; }
        public TaskCompletionSource UnsubscribeStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task SubscribeAsync(PushSubscriptionRequest request, CancellationToken cancellationToken = default)
        {
            RemoteSubscribed = true;
            return Task.CompletedTask;
        }

        public async Task UnsubscribeAsync(PushUnsubscribeRequest request, CancellationToken cancellationToken = default)
        {
            UnsubscribeStarted.TrySetResult();
            await release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            RemoteSubscribed = false;
        }

        public void ReleaseUnsubscribe() => release.TrySetResult();
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler;

        public FakeHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler)
        {
            this.handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(handler(request, cancellationToken));
    }

    private sealed class ThrowingMessageTransport : ISessionMessageTransport
    {
        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Live push e2e must not use message transport.");

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Live push e2e must not use message transport.");
    }
}
