using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Platform;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Services;

public interface IPushSubscriptionTransport
{
    bool IsEnabled { get; }

    Task SubscribeAsync(PushSubscriptionRequest request, CancellationToken cancellationToken = default);

    Task UnsubscribeAsync(PushUnsubscribeRequest request, CancellationToken cancellationToken = default);
}

public interface IPushRegistrationCoordinator
{
    Task<PushRegistration?> RegisterAsync(CancellationToken cancellationToken = default);

    Task UnregisterAsync(CancellationToken cancellationToken = default);
}

public sealed record PushSubscriptionServiceInfo(
    [property: JsonPropertyName("token")] string Token);

public sealed record PushSubscriptionRequest(
    [property: JsonPropertyName("pubkey")] string Pubkey,
    [property: JsonPropertyName("session_ed25519")] string SessionEd25519,
    [property: JsonPropertyName("namespaces")] IReadOnlyList<int> Namespaces,
    [property: JsonPropertyName("data")] bool Data,
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("sig_ts")] long SigTs,
    [property: JsonPropertyName("signature")] string Signature,
    [property: JsonPropertyName("service_info")] PushSubscriptionServiceInfo ServiceInfo,
    [property: JsonPropertyName("enc_key")] string EncKey);

public sealed record PushUnsubscribeRequest(
    [property: JsonPropertyName("pubkey")] string Pubkey,
    [property: JsonPropertyName("session_ed25519")] string SessionEd25519,
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("sig_ts")] long SigTs,
    [property: JsonPropertyName("signature")] string Signature,
    [property: JsonPropertyName("service_info")] PushSubscriptionServiceInfo ServiceInfo);

public sealed record HttpPushSubscriptionTransportOptions(
    string BaseUrl,
    string SubscribePath = "/subscribe",
    string UnsubscribePath = "/unsubscribe");

public sealed class DisabledPushSubscriptionTransport : IPushSubscriptionTransport
{
    public bool IsEnabled => false;

    public Task SubscribeAsync(PushSubscriptionRequest request, CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task UnsubscribeAsync(PushUnsubscribeRequest request, CancellationToken cancellationToken = default) => Task.CompletedTask;
}

public sealed class HttpPushSubscriptionTransport : IPushSubscriptionTransport
{
    private readonly HttpClient httpClient;
    private readonly HttpPushSubscriptionTransportOptions options;

    public HttpPushSubscriptionTransport(HttpClient httpClient, HttpPushSubscriptionTransportOptions options)
    {
        this.httpClient = httpClient;
        this.options = options;

        if (string.IsNullOrWhiteSpace(options.BaseUrl))
        {
            throw new ArgumentException("Push transport base URL is required.", nameof(options));
        }

        if (this.httpClient.BaseAddress is null)
        {
            this.httpClient.BaseAddress = new Uri(options.BaseUrl.EndsWith('/')
                ? options.BaseUrl
                : options.BaseUrl + "/", UriKind.Absolute);
        }
    }

    public bool IsEnabled => true;

    public Task SubscribeAsync(PushSubscriptionRequest request, CancellationToken cancellationToken = default) =>
        SendAsync(options.SubscribePath, request, cancellationToken);

    public Task UnsubscribeAsync(PushUnsubscribeRequest request, CancellationToken cancellationToken = default) =>
        SendAsync(options.UnsubscribePath, request, cancellationToken);

    private async Task SendAsync<TRequest>(string path, TRequest request, CancellationToken cancellationToken)
    {
        using var response = await httpClient.PostAsJsonAsync(path, request, cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            var successPayload = await response.Content.ReadFromJsonAsync<PushOperationResponse>(cancellationToken).ConfigureAwait(false);
            if (successPayload?.Success == false)
            {
                throw new InvalidOperationException(successPayload.Message ?? "Push subscription request was rejected.");
            }

            return;
        }

        PushOperationResponse? failurePayload = null;
        try
        {
            failurePayload = await response.Content.ReadFromJsonAsync<PushOperationResponse>(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            failurePayload = null;
        }

        throw new InvalidOperationException(
            failurePayload?.Message ??
            $"Push subscription request failed with status {(int)response.StatusCode}.");
    }

    private sealed record PushOperationResponse(
        [property: JsonPropertyName("success")] bool? Success,
        [property: JsonPropertyName("message")] string? Message,
        [property: JsonPropertyName("error")] int? Error);
}

public sealed class PushRegistrationCoordinator : IPushRegistrationCoordinator
{
    public const string NotificationEncryptionKeySetting = "push.notification-encryption-key";
    private static readonly IReadOnlyList<int> RegularPushNamespaces = [0];

    private readonly ClientRuntime runtime;
    private readonly IPushNotificationService pushNotifications;
    private readonly IPushSubscriptionTransport transport;
    private readonly IClock clock;

    public PushRegistrationCoordinator(
        ClientRuntime runtime,
        IPushNotificationService pushNotifications,
        IPushSubscriptionTransport transport,
        IClock clock)
    {
        this.runtime = runtime;
        this.pushNotifications = pushNotifications;
        this.transport = transport;
        this.clock = clock;
    }

    public async Task<PushRegistration?> RegisterAsync(CancellationToken cancellationToken = default)
    {
        var registration = await pushNotifications.RegisterAsync(cancellationToken).ConfigureAwait(false);
        if (registration is null)
        {
            return null;
        }

        await SubscribeRemoteAsync(registration, cancellationToken).ConfigureAwait(false);
        return registration;
    }

    public async Task UnregisterAsync(CancellationToken cancellationToken = default)
    {
        var cachedRegistration = await pushNotifications.GetCachedRegistrationAsync(cancellationToken).ConfigureAwait(false);
        if (cachedRegistration is not null)
        {
            await UnsubscribeRemoteAsync(cachedRegistration, cancellationToken).ConfigureAwait(false);
        }

        await pushNotifications.UnregisterAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task SubscribeRemoteAsync(PushRegistration registration, CancellationToken cancellationToken)
    {
        if (!transport.IsEnabled || !TryResolvePushService(registration.Provider, out var service))
        {
            return;
        }

        var recoveryPhrase = await runtime.Accounts.GetRecoveryPhraseAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recoveryPhrase))
        {
            return;
        }

        var identity = SessionIdentityMaterial.FromRecoveryPhrase(recoveryPhrase);
        var sigTs = clock.UtcNow.ToUnixTimeSeconds();
        var encKey = await GetOrCreateNotificationEncryptionKeyAsync(cancellationToken).ConfigureAwait(false);
        var request = new PushSubscriptionRequest(
            identity.SessionId.Value,
            identity.Ed25519PublicKeyHex,
            RegularPushNamespaces,
            true,
            service,
            sigTs,
            identity.SignPushSubscribe(sigTs, wantData: true, RegularPushNamespaces),
            new PushSubscriptionServiceInfo(registration.Token),
            encKey);

        await transport.SubscribeAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task UnsubscribeRemoteAsync(PushRegistration registration, CancellationToken cancellationToken)
    {
        if (!transport.IsEnabled || !TryResolvePushService(registration.Provider, out var service))
        {
            return;
        }

        var recoveryPhrase = await runtime.Accounts.GetRecoveryPhraseAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recoveryPhrase))
        {
            return;
        }

        var identity = SessionIdentityMaterial.FromRecoveryPhrase(recoveryPhrase);
        var sigTs = clock.UtcNow.ToUnixTimeSeconds();
        var request = new PushUnsubscribeRequest(
            identity.SessionId.Value,
            identity.Ed25519PublicKeyHex,
            service,
            sigTs,
            identity.SignPushUnsubscribe(sigTs),
            new PushSubscriptionServiceInfo(registration.Token));

        await transport.UnsubscribeAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task<string> GetOrCreateNotificationEncryptionKeyAsync(CancellationToken cancellationToken)
    {
        var existing = await runtime.Store.GetAsync<string>(NotificationEncryptionKeySetting, cancellationToken).ConfigureAwait(false);
        if (IsHexKey(existing))
        {
            return existing!;
        }

        Span<byte> keyBytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        var generated = Convert.ToHexString(keyBytes).ToLowerInvariant();
        await runtime.Store.SetAsync(NotificationEncryptionKeySetting, generated, cancellationToken).ConfigureAwait(false);
        return generated;
    }

    private static bool TryResolvePushService(string provider, out string service)
    {
        switch (provider.Trim().ToLowerInvariant())
        {
            case "fcm":
            case "firebase":
                service = "firebase";
                return true;
            case "apns":
                service = "apns";
                return true;
            case "huawei":
                service = "huawei";
                return true;
            default:
                service = string.Empty;
                return false;
        }
    }

    private static bool IsHexKey(string? candidate) =>
        !string.IsNullOrWhiteSpace(candidate) &&
        candidate.Length == 64 &&
        candidate.All(Uri.IsHexDigit);
}