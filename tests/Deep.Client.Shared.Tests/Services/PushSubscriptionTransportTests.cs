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
    private const string ValidRecoveryPhrase = "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade";

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
            BaseAddress = new Uri("http://push.local/")
        };

        var transport = new HttpPushSubscriptionTransport(client, new HttpPushSubscriptionTransportOptions("http://push.local"));

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

        using var unsubscribeJson = JsonDocument.Parse(requestBodies[1]);
        Assert.Equal("token-2", unsubscribeJson.RootElement.GetProperty("service_info").GetProperty("token").GetString());
        Assert.False(unsubscribeJson.RootElement.TryGetProperty("enc_key", out _));
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
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        var registration = await coordinator.RegisterAsync();
        var storedEncKey = await runtime.Store.GetAsync<string>(PushRegistrationCoordinator.NotificationEncryptionKeySetting);
        var activeAccount = await runtime.Accounts.GetActiveAccountAsync();

        Assert.NotNull(registration);
        Assert.Single(transport.SubscribeRequests);
        Assert.Equal("firebase", transport.SubscribeRequests[0].Service);
        Assert.Equal("token-123", transport.SubscribeRequests[0].ServiceInfo.Token);
        Assert.Equal([0, 10], transport.SubscribeRequests[0].Namespaces);
        Assert.Equal(activeAccount!.SessionId.Value, transport.SubscribeRequests[0].Pubkey);
        Assert.Equal(storedEncKey, transport.SubscribeRequests[0].EncKey);
        Assert.False(string.IsNullOrWhiteSpace(transport.SubscribeRequests[0].SessionEd25519));
    }

    [Fact]
    public async Task PushRegistrationCoordinator_UnregisterAsync_UsesCachedRegistrationForRemoteUnsubscribe()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        await runtime.Accounts.LoginAsync(ValidRecoveryPhrase, "Alice");

        var cachedRegistration = new PushRegistration("token-123", "apns", DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var pushNotifications = new FakePushNotificationService(cachedRegistration);
        var transport = new FakePushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        await coordinator.UnregisterAsync();

        Assert.Single(transport.UnsubscribeRequests);
        Assert.Equal("apns", transport.UnsubscribeRequests[0].Service);
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
            "wns",
            DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var transport = new FakePushSubscriptionTransport();
        var coordinator = new PushRegistrationCoordinator(runtime, pushNotifications, transport, runtime.Clock);

        var registration = await coordinator.RegisterAsync();

        Assert.NotNull(registration);
        Assert.Empty(transport.SubscribeRequests);
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

    private sealed class FakePushNotificationService(PushRegistration registration) : IPushNotificationService
    {
        public bool UnregisterCalled { get; private set; }

        public Task<PushRegistration?> RegisterAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<PushRegistration?>(registration);

        public Task<PushRegistration?> GetCachedRegistrationAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<PushRegistration?>(registration);

        public Task UnregisterAsync(CancellationToken cancellationToken = default)
        {
            UnregisterCalled = true;
            return Task.CompletedTask;
        }
    }

    private sealed class FakePushSubscriptionTransport : IPushSubscriptionTransport
    {
        public bool IsEnabled => true;

        public List<PushSubscriptionRequest> SubscribeRequests { get; } = [];

        public List<PushUnsubscribeRequest> UnsubscribeRequests { get; } = [];

        public Task SubscribeAsync(PushSubscriptionRequest request, CancellationToken cancellationToken = default)
        {
            SubscribeRequests.Add(request);
            return Task.CompletedTask;
        }

        public Task UnsubscribeAsync(PushUnsubscribeRequest request, CancellationToken cancellationToken = default)
        {
            UnsubscribeRequests.Add(request);
            return Task.CompletedTask;
        }
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
