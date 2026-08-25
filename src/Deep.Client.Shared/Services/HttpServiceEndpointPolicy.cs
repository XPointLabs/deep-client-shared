using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Explicit authority for HTTP service origins used by client transports.
/// Only loopback test endpoints may use cleartext; physical/UAT and public
/// transports always use HTTPS with the platform TLS validator.
/// </summary>
public sealed class HttpServiceEndpointPolicy
{
    private HttpServiceEndpointPolicy()
    {
    }

    public static HttpServiceEndpointPolicy Production { get; } =
        new();

    internal Uri RequireOrigin(string value, string description)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException($"{description} must be an absolute service origin.");
        }

        ValidateEndpoint(uri, description, requireRootPath: true);
        return CanonicalOrigin(uri);
    }

    internal HttpServiceOrigin RequireServiceOrigin(string value, string description) =>
        new(RequireOrigin(value, description));

    private void ValidateEndpoint(Uri value, string description, bool requireRootPath)
    {
        if (!value.IsAbsoluteUri ||
            value.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(value.UserInfo) ||
            !string.IsNullOrEmpty(value.Query) ||
            !string.IsNullOrEmpty(value.Fragment) ||
            value.Port <= 0 ||
            requireRootPath && value.AbsolutePath != "/")
        {
            throw new ArgumentException(
                $"{description} must be an absolute HTTP(S) URL without credentials, query, or fragment.");
        }

        if (value.Scheme == Uri.UriSchemeHttps)
        {
            return;
        }

        if (!value.IsLoopback)
        {
            throw new ArgumentException(
                $"{description} must use HTTPS unless it is an explicit loopback test endpoint.");
        }
    }

    private static Uri CanonicalOrigin(Uri value)
    {
        var builder = new UriBuilder(value.Scheme, value.IdnHost)
        {
            Path = "/",
            Query = "",
            Fragment = "",
            Port = value.IsDefaultPort ? -1 : value.Port
        };
        return builder.Uri;
    }

    internal static bool SameOrigin(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase) &&
        left.Port == right.Port;

}

internal sealed class HttpServiceOrigin
{
    private static readonly Regex LiteralSegmentPattern = new(
        "^[A-Za-z0-9._-]+$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private readonly Uri origin;

    internal HttpServiceOrigin(Uri origin)
    {
        this.origin = origin;
    }

    internal Uri Origin => origin;

    internal string RequirePath(string value, string description) =>
        RequireTemplate(value, description, []);

    internal string RequireTemplate(
        string value,
        string description,
        params string[] allowedPlaceholders)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            value[0] != '/' ||
            value.StartsWith("//", StringComparison.Ordinal) ||
            value.EndsWith("/", StringComparison.Ordinal) ||
            value.Contains('\\') ||
            value.Contains(':') ||
            value.Contains('?') ||
            value.Contains('#') ||
            value.Contains('%'))
        {
            throw new ArgumentException(
                $"{description} must be a canonical rooted relative path.",
                nameof(value));
        }

        var allowed = allowedPlaceholders.ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var segment in value.Split('/').Skip(1))
        {
            if (segment.Length == 0 || segment is "." or "..")
            {
                throw new ArgumentException(
                    $"{description} contains an empty or traversal segment.",
                    nameof(value));
            }

            if (segment[0] == '{' && segment[^1] == '}')
            {
                var placeholder = segment[1..^1];
                if (!allowed.Contains(placeholder) || !seen.Add(placeholder))
                {
                    throw new ArgumentException(
                        $"{description} contains an unknown or repeated placeholder.",
                        nameof(value));
                }

                continue;
            }

            if (segment.Contains('{') ||
                segment.Contains('}') ||
                !LiteralSegmentPattern.IsMatch(segment))
            {
                throw new ArgumentException(
                    $"{description} contains a non-canonical segment.",
                    nameof(value));
            }
        }

        if (!seen.SetEquals(allowed))
        {
            throw new ArgumentException(
                $"{description} must contain each required placeholder exactly once.",
                nameof(value));
        }

        _ = Build(value, description);
        return value;
    }

    internal Uri Build(string path, string description)
    {
        var resource = new Uri(origin, path);
        if (!HttpServiceEndpointPolicy.SameOrigin(origin, resource) ||
            !string.IsNullOrEmpty(resource.UserInfo) ||
            !string.IsNullOrEmpty(resource.Query) ||
            !string.IsNullOrEmpty(resource.Fragment))
        {
            throw new InvalidOperationException(
                $"{description} escaped the configured service origin.");
        }

        return resource;
    }

    internal Uri Format(
        string template,
        string placeholder,
        string value,
        string description)
    {
        RequirePlaceholderValue(value, description);
        var escaped = Uri.EscapeDataString(value);
        var path = template.Replace(
            $"{{{placeholder}}}",
            escaped,
            StringComparison.Ordinal);
        if (path.Contains('{') || path.Contains('}'))
        {
            throw new InvalidOperationException(
                $"{description} contains an unresolved placeholder.");
        }

        var resource = Build(path, description);
        var expectedPath = path[1..];
        if (!string.Equals(
                resource.GetComponents(UriComponents.Path, UriFormat.UriEscaped),
                expectedPath,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{description} was not preserved canonically.");
        }

        return resource;
    }

    private static void RequirePlaceholderValue(
        string value,
        string description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!string.Equals(value, value.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"{description} placeholder must be canonical.",
                nameof(value));
        }

        var candidate = value;
        for (var decodePass = 0; decodePass < 3; decodePass++)
        {
            if (candidate is "." or ".." ||
                candidate.Contains('/') ||
                candidate.Contains('\\') ||
                candidate.Contains('%') ||
                candidate.Contains('?') ||
                candidate.Contains('#') ||
                candidate.Any(char.IsControl))
            {
                throw new ArgumentException(
                    $"{description} placeholder contains traversal or URI syntax.",
                    nameof(value));
            }

            var decoded = Uri.UnescapeDataString(candidate);
            if (string.Equals(decoded, candidate, StringComparison.Ordinal))
            {
                break;
            }

            candidate = decoded;
        }
    }

    internal Uri RequireExactResource(
        Uri value,
        Uri expected,
        string description)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.IsAbsoluteUri ||
            !HttpServiceEndpointPolicy.SameOrigin(origin, value) ||
            !string.IsNullOrEmpty(value.UserInfo) ||
            !string.IsNullOrEmpty(value.Query) ||
            !string.IsNullOrEmpty(value.Fragment) ||
            !string.Equals(
                value.OriginalString,
                expected.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"{description} must exactly match the configured service resource.",
                nameof(value));
        }

        return value;
    }
}

public sealed record HttpServiceClientOptions(
    TimeSpan Timeout = default,
    TimeSpan ConnectTimeout = default,
    TimeSpan PooledConnectionIdleTimeout = default,
    TimeSpan PooledConnectionLifetime = default,
    string? UserAgent = null);

internal sealed record HttpServiceNetworkHooks(
    Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>>? ConnectCallback = null,
    RemoteCertificateValidationCallback? ServerCertificateValidationCallback = null);

public sealed class HttpServiceTransportFactory
{
    private readonly HttpServiceEndpointPolicy endpointPolicy;
    private readonly HttpServiceNetworkHooks? networkHooks;

    public HttpServiceTransportFactory(HttpServiceEndpointPolicy endpointPolicy)
        : this(endpointPolicy, networkHooks: null)
    {
    }

    private HttpServiceTransportFactory(
        HttpServiceEndpointPolicy endpointPolicy,
        HttpServiceNetworkHooks? networkHooks)
    {
        this.endpointPolicy = endpointPolicy
            ?? throw new ArgumentNullException(nameof(endpointPolicy));
        this.networkHooks = networkHooks;
    }

    internal HttpServiceTransportFactory BindNetwork(HttpServiceNetworkHooks hooks) =>
        new(endpointPolicy, hooks ?? throw new ArgumentNullException(nameof(hooks)));

    public HttpAvatarProfileTransport CreateAvatar(
        HttpAvatarProfileTransportOptions options,
        HttpServiceClientOptions? clientOptions = null,
        TimeProvider? timeProvider = null) =>
        CreateOwned(
            clientOptions,
            client => new HttpAvatarProfileTransport(
                client,
                options,
                timeProvider,
                endpointPolicy));

    public HttpAttachmentFileTransport CreateAttachment(
        HttpAttachmentFileTransportOptions options,
        HttpServiceClientOptions? clientOptions = null) =>
        CreateOwned(
            clientOptions,
            client => new HttpAttachmentFileTransport(client, options, endpointPolicy));

    public HttpPushSubscriptionTransport CreatePush(
        HttpPushSubscriptionTransportOptions options,
        HttpServiceClientOptions? clientOptions = null) =>
        CreateOwned(
            clientOptions,
            client => new HttpPushSubscriptionTransport(client, options, endpointPolicy));

    public HttpCallSignalingTransport CreateCallSignaling(
        HttpCallSignalingTransportOptions options,
        ICallRecoveryPhraseProvider? recoveryPhraseProvider = null,
        TimeProvider? timeProvider = null,
        HttpServiceClientOptions? clientOptions = null) =>
        CreateOwned(
            clientOptions,
            client => new HttpCallSignalingTransport(
                client,
                options,
                recoveryPhraseProvider is null
                    ? null
                    : recoveryPhraseProvider.GetRecoveryPhraseAsync,
                timeProvider,
                endpointPolicy));

    internal PrivacyRoutedMailboxBinaryIngress CreatePrivacyRoutedMailboxIngress(
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        IMailboxClientDecodePolicyProvider decodePolicies,
        HttpServiceClientOptions? clientOptions = null,
        int paddingBlockBytes = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
    {
        ArgumentNullException.ThrowIfNull(primaryRoute);
        ArgumentNullException.ThrowIfNull(fallbackRoute);
        ArgumentNullException.ThrowIfNull(decodePolicies);

        PrivacyManagedIngressHttpTransport? primary = null;
        PrivacyManagedIngressHttpTransport? fallback = null;
        try
        {
            primary = CreatePrivacyManagedIngress(primaryRoute.EntryOrigin, clientOptions);
            fallback = CreatePrivacyManagedIngress(fallbackRoute.EntryOrigin, clientOptions);
            var ingress = new PrivacyRoutedMailboxBinaryIngress(
                primaryRoute,
                fallbackRoute,
                decodePolicies,
                primary,
                fallback,
                paddingBlockBytes);
            primary = null;
            fallback = null;
            return ingress;
        }
        finally
        {
            fallback?.Dispose();
            primary?.Dispose();
        }
    }

    private TTransport CreateOwned<TTransport>(
        HttpServiceClientOptions? options,
        Func<HttpClient, TTransport> create)
    {
        var client = CreateHttpClient(options, networkHooks);
        try
        {
            return create(client);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private PrivacyManagedIngressHttpTransport CreatePrivacyManagedIngress(
        Uri origin,
        HttpServiceClientOptions? options)
    {
        var handler = CreateHttpHandler(options, networkHooks);
        handler.AutomaticDecompression = System.Net.DecompressionMethods.None;
        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        try
        {
            client.BaseAddress = origin;
            return new PrivacyManagedIngressHttpTransport(client);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static HttpClient CreateHttpClient(
        HttpServiceClientOptions? options,
        HttpServiceNetworkHooks? networkHooks)
    {
        var handler = CreateHttpHandler(options, networkHooks);
        var timeout = options is null || options.Timeout == default
            ? TimeSpan.FromSeconds(100)
            : options.Timeout;

        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = timeout
        };
        if (!string.IsNullOrWhiteSpace(options?.UserAgent))
        {
            client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
        }

        return client;
    }

    internal static SocketsHttpHandler CreateHttpHandler(
        HttpServiceClientOptions? options,
        HttpServiceNetworkHooks? networkHooks)
    {
        options ??= new HttpServiceClientOptions();
        var connectTimeout = options.ConnectTimeout == default
            ? TimeSpan.FromSeconds(10)
            : options.ConnectTimeout;
        var idleTimeout = options.PooledConnectionIdleTimeout == default
            ? TimeSpan.FromMinutes(1)
            : options.PooledConnectionIdleTimeout;
        var lifetime = options.PooledConnectionLifetime == default
            ? TimeSpan.FromMinutes(5)
            : options.PooledConnectionLifetime;
        var timeout = options.Timeout == default
            ? TimeSpan.FromSeconds(100)
            : options.Timeout;
        if (timeout <= TimeSpan.Zero ||
            connectTimeout <= TimeSpan.Zero ||
            idleTimeout <= TimeSpan.Zero ||
            lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "HTTP client timeouts must be positive.");
        }

        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = connectTimeout,
            PooledConnectionIdleTimeout = idleTimeout,
            PooledConnectionLifetime = lifetime,
            ConnectCallback = networkHooks?.ConnectCallback
        };

        // Public HTTPS services use the platform validator by default. The only
        // optional callback is a friend-assembly network hook for the compiled
        // physical UAT trust root; ordinary and release composition leave it null.
        // Online revocation remains mandatory for certificates that advertise it.
        handler.SslOptions.CertificateRevocationCheckMode = X509RevocationMode.Online;
        handler.SslOptions.RemoteCertificateValidationCallback =
            networkHooks?.ServerCertificateValidationCallback;

        // These invariants are deliberately assigned after network customization.
        handler.AllowAutoRedirect = false;
        handler.UseCookies = false;
        handler.UseProxy = false;

        return handler;
    }
}
