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

public interface IPushNotificationEncryptionKeyStore
{
    Task<PushNotificationKeyState?> GetAsync(CancellationToken cancellationToken = default);

    Task SetAsync(PushNotificationKeyState state, CancellationToken cancellationToken = default);

    Task RemoveAsync(CancellationToken cancellationToken = default);
}

public interface IPushUnsubscribeRetryStore
{
    Task<PushUnsubscribeRequest?> GetPendingUnsubscribeAsync(CancellationToken cancellationToken = default);

    Task SetPendingUnsubscribeAsync(
        PushUnsubscribeRequest request,
        CancellationToken cancellationToken = default);

    Task RemovePendingUnsubscribeAsync(CancellationToken cancellationToken = default);
}

public interface IPushUnsubscribeRetryCoordinator
{
    Task<bool> RetryPendingUnsubscribeAsync(CancellationToken cancellationToken = default);
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
    [property: JsonPropertyName("enc_key")] string EncKey,
    [property: JsonPropertyName("app_id")] string AppId = PushNotificationCrypto.PackageName,
    [property: JsonPropertyName("app_version")] string AppVersion = "0.0.0")
{
    [JsonPropertyName("sig_v")]
    public int SigVersion => PushSubscriptionCanonicalFormat.SignatureVersion;
}

public sealed record PushUnsubscribeRequest(
    [property: JsonPropertyName("pubkey")] string Pubkey,
    [property: JsonPropertyName("session_ed25519")] string SessionEd25519,
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("sig_ts")] long SigTs,
    [property: JsonPropertyName("signature")] string Signature,
    [property: JsonPropertyName("service_info")] PushSubscriptionServiceInfo ServiceInfo)
{
    [JsonPropertyName("sig_v")]
    public int SigVersion => PushSubscriptionCanonicalFormat.SignatureVersion;
}

public sealed record HttpPushSubscriptionTransportOptions(
    string BaseUrl,
    string SubscribePath = "/subscribe",
    string UnsubscribePath = "/unsubscribe");

public sealed record PushClientMetadata(string AppId, string AppVersion)
{
    public static PushClientMetadata Default { get; } = new(PushNotificationCrypto.PackageName, "0.0.0");
}

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

        if (!Uri.TryCreate(options.BaseUrl, UriKind.Absolute, out var baseUri) || !IsSecurePushEndpoint(baseUri) ||
            (this.httpClient.BaseAddress is not null && !IsSecurePushEndpoint(this.httpClient.BaseAddress)))
        {
            throw new ArgumentException(
                "Push transport must use HTTPS unless the endpoint is an explicit loopback test endpoint.",
                nameof(options));
        }

        if (this.httpClient.BaseAddress is null)
        {
            this.httpClient.BaseAddress = new Uri(baseUri.AbsoluteUri.EndsWith('/')
                ? baseUri.AbsoluteUri
                : baseUri.AbsoluteUri + "/", UriKind.Absolute);
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

    private static bool IsSecurePushEndpoint(Uri endpoint) =>
        endpoint.Scheme == Uri.UriSchemeHttps ||
        (endpoint.Scheme == Uri.UriSchemeHttp && endpoint.IsLoopback);
}

public sealed class PushRegistrationCoordinator : IPushRegistrationCoordinator, IPushUnsubscribeRetryCoordinator
{
    public const string NotificationEncryptionKeySetting = "push.notification-encryption-key";
    private static readonly IReadOnlyList<int> RegularPushNamespaces = [0, 10];

    private readonly ClientRuntime runtime;
    private readonly IPushNotificationService pushNotifications;
    private readonly IPushSubscriptionTransport transport;
    private readonly IClock clock;
    private readonly PushClientMetadata clientMetadata;
    private readonly SemaphoreSlim lifecycleGate = new(1, 1);
    private readonly object accountEpochGate = new();
    private CancellationTokenSource accountEpochCancellation = new();
    private long accountEpoch;
    private bool unregistrationInProgress;

    public PushRegistrationCoordinator(
        ClientRuntime runtime,
        IPushNotificationService pushNotifications,
        IPushSubscriptionTransport transport,
        IClock clock,
        PushClientMetadata? clientMetadata = null)
    {
        this.runtime = runtime;
        this.pushNotifications = pushNotifications;
        this.transport = transport;
        this.clock = clock;
        this.clientMetadata = clientMetadata ?? PushClientMetadata.Default;
        ValidateClientMetadata(this.clientMetadata);
    }

    public async Task<PushRegistration?> RegisterAsync(CancellationToken cancellationToken = default)
    {
        using var attempt = CaptureRegistrationAttempt(cancellationToken);
        await lifecycleGate.WaitAsync(attempt.Token).ConfigureAwait(false);
        try
        {
            if (!await RetryPendingUnsubscribeCoreAsync(attempt.Token).ConfigureAwait(false))
            {
                return null;
            }

            var account = await runtime.Accounts.GetActiveAccountAsync(attempt.Token).ConfigureAwait(false);
            if (account is null || !TryActivateRegistration(attempt.Epoch))
            {
                return null;
            }

            var registration = await pushNotifications.RegisterAsync(attempt.Token).ConfigureAwait(false);
            if (registration is null)
            {
                return null;
            }

            if (await IsCurrentRemoteSubscriptionAsync(
                    registration,
                    account.SessionId.Value,
                    attempt.Token).ConfigureAwait(false))
            {
                return registration;
            }

            ThrowIfRegistrationIsStale(attempt, account.SessionId.Value);
            if (!transport.IsEnabled || !TryResolvePushService(registration.Provider, out _))
            {
                await InvalidateRemoteSubscriptionStateAsync(CancellationToken.None).ConfigureAwait(false);
                return null;
            }

            var subscribed = await SubscribeRemoteAsync(
                registration,
                account.SessionId.Value,
                attempt,
                attempt.Token).ConfigureAwait(false);
            return subscribed ? registration : null;
        }
        finally
        {
            lifecycleGate.Release();
        }
    }

    public async Task<bool> RetryPendingUnsubscribeAsync(CancellationToken cancellationToken = default)
    {
        await lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await RetryPendingUnsubscribeCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            lifecycleGate.Release();
        }
    }

    public async Task UnregisterAsync(CancellationToken cancellationToken = default)
    {
        var account = await runtime.Accounts.GetActiveAccountAsync(CancellationToken.None).ConfigureAwait(false);
        var unregistrationEpoch = BeginUnregistration();
        Exception? preparationFailure = null;
        PushUnsubscribeRequest? request = null;
        try
        {
            try
            {
                request = await PrepareDurableUnsubscribeAsync(account?.SessionId.Value).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                preparationFailure = exception;
            }

            try
            {
                await pushNotifications.UnregisterAsync(CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                await InvalidateRemoteSubscriptionStateAsync(CancellationToken.None).ConfigureAwait(false);
            }

            if (preparationFailure is not null)
            {
                throw preparationFailure;
            }

            await lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (request is not null)
                {
                    await SendDurableUnsubscribeAsync(request, cancellationToken).ConfigureAwait(false);
                }
                else if (!await RetryPendingUnsubscribeCoreAsync(cancellationToken).ConfigureAwait(false))
                {
                    throw new InvalidOperationException("Pending push unsubscription could not be completed.");
                }
            }
            finally
            {
                lifecycleGate.Release();
            }
        }
        finally
        {
            CompleteUnregistration(unregistrationEpoch);
        }
    }

    private async Task<bool> SubscribeRemoteAsync(
        PushRegistration registration,
        string expectedSessionId,
        RegistrationAttempt attempt,
        CancellationToken cancellationToken)
    {
        if (!transport.IsEnabled || !TryResolvePushService(registration.Provider, out var service))
        {
            return false;
        }

        var recoveryPhrase = await runtime.Accounts.GetRecoveryPhraseAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recoveryPhrase))
        {
            return false;
        }

        using var identity = SessionIdentityMaterial.FromRecoveryPhrase(recoveryPhrase);
        if (!string.Equals(identity.SessionId.Value, expectedSessionId, StringComparison.Ordinal))
        {
            throw new OperationCanceledException("The active push account changed during registration.", cancellationToken);
        }

        ThrowIfRegistrationIsStale(attempt, expectedSessionId);
        var keyStore = pushNotifications as IPushNotificationEncryptionKeyStore;
        var existingState = keyStore is null
            ? null
            : await keyStore.GetAsync(cancellationToken).ConfigureAwait(false);
        var subscriptionBinding = PushNotificationCrypto.ComputeSubscriptionBinding(identity.SessionId.Value, service, registration.Token);
        if (existingState is not null && !IsCurrentRemoteSubscription(existingState, registration, identity.SessionId.Value, subscriptionBinding))
        {
            await keyStore!.RemoveAsync(cancellationToken).ConfigureAwait(false);
            existingState = null;
        }

        var encKey = await GetOrCreateNotificationEncryptionKeyAsync(existingState, cancellationToken).ConfigureAwait(false);
        var sigTs = clock.UtcNow.ToUnixTimeSeconds();
        var request = new PushSubscriptionRequest(
            identity.SessionId.Value,
            identity.Ed25519PublicKeyHex,
            RegularPushNamespaces,
            true,
            service,
            sigTs,
            identity.SignPushSubscribe(
                sigTs,
                wantData: true,
                namespaces: RegularPushNamespaces,
                service: service,
                deviceToken: registration.Token,
                encryptionKey: encKey,
                appId: clientMetadata.AppId,
                appVersion: clientMetadata.AppVersion),
            new PushSubscriptionServiceInfo(registration.Token),
            encKey,
            clientMetadata.AppId,
            clientMetadata.AppVersion);

        var retryStore = pushNotifications as IPushUnsubscribeRetryStore;
        if (retryStore is not null)
        {
            var compensatingRequest = CreateUnsubscribeRequest(identity, registration, service);
            await retryStore
                .SetPendingUnsubscribeAsync(compensatingRequest, CancellationToken.None)
                .ConfigureAwait(false);
        }

        try
        {
            await transport.SubscribeAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (keyStore is not null)
            {
                await keyStore.RemoveAsync(CancellationToken.None).ConfigureAwait(false);
            }
            else
            {
                await runtime.Store.DeleteAsync(NotificationEncryptionKeySetting, CancellationToken.None).ConfigureAwait(false);
            }

            throw;
        }

        if (!await IsRegistrationAttemptCurrentAsync(attempt, expectedSessionId).ConfigureAwait(false))
        {
            await CompensateStaleSubscriptionAsync(identity, registration, service).ConfigureAwait(false);
            throw StaleRegistrationException(attempt);
        }

        try
        {
            if (keyStore is not null)
            {
                await keyStore.SetAsync(
                    new PushNotificationKeyState(
                        encKey,
                        subscriptionBinding,
                        identity.SessionId.Value,
                        registration,
                        RemoteSubscribed: true),
                    CancellationToken.None).ConfigureAwait(false);
            }
            else
            {
                await runtime.Store.SetAsync(NotificationEncryptionKeySetting, encKey, CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch
        {
            await CompensateStaleSubscriptionAsync(identity, registration, service).ConfigureAwait(false);
            throw;
        }

        if (!await IsRegistrationAttemptCurrentAsync(attempt, expectedSessionId).ConfigureAwait(false))
        {
            await CompensateStaleSubscriptionAsync(identity, registration, service).ConfigureAwait(false);
            throw StaleRegistrationException(attempt);
        }

        if (retryStore is not null)
        {
            try
            {
                await retryStore.RemovePendingUnsubscribeAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                await CompensateStaleSubscriptionAsync(identity, registration, service).ConfigureAwait(false);
                throw;
            }
        }

        if (!await IsRegistrationAttemptCurrentAsync(attempt, expectedSessionId).ConfigureAwait(false))
        {
            await CompensateStaleSubscriptionAsync(identity, registration, service).ConfigureAwait(false);
            throw StaleRegistrationException(attempt);
        }

        return true;
    }

    private async Task<PushUnsubscribeRequest?> PrepareDurableUnsubscribeAsync(string? expectedSessionId)
    {
        var registration = await pushNotifications
            .GetCachedRegistrationAsync(CancellationToken.None)
            .ConfigureAwait(false);
        if (registration is null || !TryResolvePushService(registration.Provider, out var service))
        {
            return null;
        }

        var recoveryPhrase = await runtime.Accounts
            .GetRecoveryPhraseAsync(CancellationToken.None)
            .ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recoveryPhrase))
        {
            return null;
        }

        using var identity = SessionIdentityMaterial.FromRecoveryPhrase(recoveryPhrase);
        if (expectedSessionId is not null &&
            !string.Equals(identity.SessionId.Value, expectedSessionId, StringComparison.Ordinal))
        {
            return null;
        }

        var request = CreateUnsubscribeRequest(identity, registration, service);
        if (pushNotifications is IPushUnsubscribeRetryStore retryStore)
        {
            await retryStore.SetPendingUnsubscribeAsync(request, CancellationToken.None).ConfigureAwait(false);
        }

        return request;
    }

    private async Task SendDurableUnsubscribeAsync(
        PushUnsubscribeRequest request,
        CancellationToken cancellationToken)
    {
        if (!transport.IsEnabled)
        {
            throw new InvalidOperationException("Push unsubscription transport is unavailable.");
        }

        await transport.UnsubscribeAsync(request, cancellationToken).ConfigureAwait(false);
        if (pushNotifications is IPushUnsubscribeRetryStore completedRetryStore)
        {
            await completedRetryStore.RemovePendingUnsubscribeAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task<bool> RetryPendingUnsubscribeCoreAsync(CancellationToken cancellationToken)
    {
        if (pushNotifications is not IPushUnsubscribeRetryStore retryStore)
        {
            return true;
        }

        var request = await retryStore.GetPendingUnsubscribeAsync(cancellationToken).ConfigureAwait(false);
        if (request is null)
        {
            return true;
        }

        if (!transport.IsEnabled)
        {
            return false;
        }

        try
        {
            await transport.UnsubscribeAsync(request, cancellationToken).ConfigureAwait(false);
            await retryStore.RemovePendingUnsubscribeAsync(CancellationToken.None).ConfigureAwait(false);
            await InvalidateRemoteSubscriptionStateAsync(CancellationToken.None).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    private async Task CompensateStaleSubscriptionAsync(
        SessionIdentityMaterial identity,
        PushRegistration registration,
        string service)
    {
        var request = CreateUnsubscribeRequest(identity, registration, service);
        var retryStore = pushNotifications as IPushUnsubscribeRetryStore;
        try
        {
            if (retryStore is not null)
            {
                await retryStore.SetPendingUnsubscribeAsync(request, CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch
        {
            // The immediate compensating request can still remove the remote subscription.
        }

        try
        {
            await InvalidateRemoteSubscriptionStateAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            // Do not let local cleanup failure suppress the compensating remote request.
        }

        if (!transport.IsEnabled)
        {
            return;
        }

        try
        {
            await transport.UnsubscribeAsync(request, CancellationToken.None).ConfigureAwait(false);
            if (retryStore is not null)
            {
                await retryStore.RemovePendingUnsubscribeAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch
        {
            // The fully signed request remains in the retry store; no identity seed is retained.
        }
    }

    private PushUnsubscribeRequest CreateUnsubscribeRequest(
        SessionIdentityMaterial identity,
        PushRegistration registration,
        string service)
    {
        var sigTs = clock.UtcNow.ToUnixTimeSeconds();
        return new PushUnsubscribeRequest(
            identity.SessionId.Value,
            identity.Ed25519PublicKeyHex,
            service,
            sigTs,
            identity.SignPushUnsubscribe(sigTs, service, registration.Token),
            new PushSubscriptionServiceInfo(registration.Token));
    }

    private async Task<string> GetOrCreateNotificationEncryptionKeyAsync(
        PushNotificationKeyState? existingState,
        CancellationToken cancellationToken)
    {
        if (IsHexKey(existingState?.KeyHex))
        {
            return existingState!.KeyHex;
        }

        if (pushNotifications is not IPushNotificationEncryptionKeyStore)
        {
            var existing = await runtime.Store.GetAsync<string>(NotificationEncryptionKeySetting, cancellationToken).ConfigureAwait(false);
            if (IsHexKey(existing))
            {
                return existing!;
            }
        }

        Span<byte> keyBytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        var generated = Convert.ToHexString(keyBytes).ToLowerInvariant();
        CryptographicOperations.ZeroMemory(keyBytes);
        return generated;
    }

    private Task InvalidateRemoteSubscriptionStateAsync(CancellationToken cancellationToken) =>
        pushNotifications is IPushNotificationEncryptionKeyStore keyStore
            ? keyStore.RemoveAsync(cancellationToken)
            : runtime.Store.DeleteAsync(NotificationEncryptionKeySetting, cancellationToken);

    private RegistrationAttempt CaptureRegistrationAttempt(CancellationToken cancellationToken)
    {
        lock (accountEpochGate)
        {
            return new RegistrationAttempt(
                accountEpoch,
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken,
                    accountEpochCancellation.Token));
        }
    }

    private long BeginUnregistration()
    {
        CancellationTokenSource previousCancellation;
        long epoch;
        lock (accountEpochGate)
        {
            unregistrationInProgress = true;
            accountEpoch++;
            epoch = accountEpoch;
            previousCancellation = accountEpochCancellation;
            accountEpochCancellation = new CancellationTokenSource();
        }

        try
        {
            previousCancellation.Cancel();
        }
        finally
        {
            previousCancellation.Dispose();
        }

        return epoch;
    }

    private void CompleteUnregistration(long epoch)
    {
        lock (accountEpochGate)
        {
            if (accountEpoch == epoch)
            {
                unregistrationInProgress = false;
            }
        }
    }

    private bool TryActivateRegistration(long epoch)
    {
        lock (accountEpochGate)
        {
            if (accountEpoch != epoch)
            {
                return false;
            }

            return !unregistrationInProgress;
        }
    }

    private void ThrowIfRegistrationIsStale(RegistrationAttempt attempt, string sessionId)
    {
        attempt.Token.ThrowIfCancellationRequested();
        lock (accountEpochGate)
        {
            if (accountEpoch != attempt.Epoch || unregistrationInProgress)
            {
                throw new OperationCanceledException(
                    "Push registration was superseded by an account lifecycle change.",
                    attempt.Token);
            }
        }
    }

    private async Task<bool> IsRegistrationAttemptCurrentAsync(
        RegistrationAttempt attempt,
        string sessionId)
    {
        lock (accountEpochGate)
        {
            if (accountEpoch != attempt.Epoch || unregistrationInProgress || attempt.Token.IsCancellationRequested)
            {
                return false;
            }
        }

        var account = await runtime.Accounts
            .GetActiveAccountAsync(CancellationToken.None)
            .ConfigureAwait(false);
        return string.Equals(account?.SessionId.Value, sessionId, StringComparison.Ordinal);
    }

    private async Task<bool> IsCurrentRemoteSubscriptionAsync(
        PushRegistration registration,
        string sessionId,
        CancellationToken cancellationToken)
    {
        if (!TryResolvePushService(registration.Provider, out var service) ||
            pushNotifications is not IPushNotificationEncryptionKeyStore keyStore)
        {
            return false;
        }

        var state = await keyStore.GetAsync(cancellationToken).ConfigureAwait(false);
        if (state is null)
        {
            return false;
        }

        var subscriptionBinding = PushNotificationCrypto.ComputeSubscriptionBinding(
            sessionId,
            service,
            registration.Token);
        if (IsCurrentRemoteSubscription(state, registration, sessionId, subscriptionBinding))
        {
            return true;
        }

        await keyStore.RemoveAsync(cancellationToken).ConfigureAwait(false);
        return false;
    }

    private static OperationCanceledException StaleRegistrationException(RegistrationAttempt attempt) =>
        new(
            "Push registration was superseded by an account lifecycle change.",
            attempt.Token);

    private static bool IsCurrentRemoteSubscription(
        PushNotificationKeyState state,
        PushRegistration registration,
        string sessionId,
        string subscriptionBinding) =>
        state.RemoteSubscribed &&
        string.Equals(state.SessionBinding, sessionId, StringComparison.Ordinal) &&
        string.Equals(state.SubscriptionBinding, subscriptionBinding, StringComparison.Ordinal) &&
        string.Equals(state.Registration.Token, registration.Token, StringComparison.Ordinal) &&
        string.Equals(state.Registration.Provider, registration.Provider, StringComparison.OrdinalIgnoreCase);

    public static bool TryResolvePushService(string provider, out string service)
    {
        if (string.IsNullOrWhiteSpace(provider))
        {
            service = string.Empty;
            return false;
        }

        switch (provider.Trim().ToLowerInvariant())
        {
            case "fcm":
            case "firebase":
                service = "firebase";
                return true;
            case "wns":
                service = "wns";
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

    private static void ValidateClientMetadata(PushClientMetadata metadata)
    {
        if (!string.Equals(metadata.AppId, PushNotificationCrypto.PackageName, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(metadata.AppVersion)
            || metadata.AppVersion.Length > 64
            || metadata.AppVersion != metadata.AppVersion.Trim()
            || metadata.AppVersion.Any(static character =>
                character is not (>= '0' and <= '9')
                    and not (>= 'a' and <= 'z')
                    and not (>= 'A' and <= 'Z')
                    and not '.' and not '-' and not '_' and not '+'))
        {
            throw new ArgumentException("Push client metadata is invalid.", nameof(metadata));
        }
    }

    private sealed record RegistrationAttempt(long Epoch, CancellationTokenSource Cancellation) : IDisposable
    {
        public CancellationToken Token => Cancellation.Token;

        public void Dispose() => Cancellation.Dispose();
    }
}
