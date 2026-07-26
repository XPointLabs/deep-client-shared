using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Explicit authority for HTTP service origins used by client transports.
/// The development-local authority is deliberately obtainable only as an exact
/// policy instance; transports never inspect process environment or accept a
/// boolean cleartext bypass.
/// </summary>
public sealed class HttpServiceEndpointPolicy
{
    private enum PolicyKind
    {
        Production,
        PhysicalE2eDevelopment
    }

    private readonly PolicyKind kind;

    private HttpServiceEndpointPolicy(PolicyKind kind)
    {
        this.kind = kind;
    }

    public static HttpServiceEndpointPolicy Production { get; } =
        new(PolicyKind.Production);

    internal static HttpServiceEndpointPolicy PhysicalE2eDevelopment { get; } =
        new(PolicyKind.PhysicalE2eDevelopment);

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

        if (kind == PolicyKind.Production)
        {
            if (!value.IsLoopback)
            {
                throw new ArgumentException(
                    $"{description} must use HTTPS unless it is an explicit loopback test endpoint.");
            }

            return;
        }

        if (!TryGetCanonicalLiteralIpv4(value, out var address) ||
            !IsDevelopmentLocal(address))
        {
            throw new ArgumentException(
                $"{description} development HTTP requires a canonical literal loopback, RFC1918, or IPv4 link-local address.");
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

    private static bool TryGetCanonicalLiteralIpv4(Uri value, out IPAddress address)
    {
        address = IPAddress.None;
        var original = value.OriginalString;
        var schemeSeparator = original.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator < 0)
        {
            return false;
        }

        var authorityStart = schemeSeparator + 3;
        var authorityEnd = original.IndexOfAny(['/', '?', '#'], authorityStart);
        var authority = authorityEnd < 0
            ? original[authorityStart..]
            : original[authorityStart..authorityEnd];
        if (authority.Length == 0 || authority[0] == '[' || authority.Contains('@'))
        {
            return false;
        }

        var portSeparator = authority.LastIndexOf(':');
        var rawHost = portSeparator < 0 ? authority : authority[..portSeparator];
        if (rawHost.Length == 0 ||
            rawHost.Contains(':') ||
            !IPAddress.TryParse(rawHost, out var parsed) ||
            parsed.AddressFamily != AddressFamily.InterNetwork ||
            !string.Equals(rawHost, parsed.ToString(), StringComparison.Ordinal))
        {
            address = IPAddress.None;
            return false;
        }

        address = parsed;
        return true;
    }

    private static bool IsDevelopmentLocal(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 ||
               bytes[0] == 127 ||
               bytes[0] == 169 && bytes[1] == 254 ||
               bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
               bytes[0] == 192 && bytes[1] == 168;
    }
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
            value.Contains('?') ||
            value.Contains('#') ||
            value.Contains('%') ||
            Uri.TryCreate(value, UriKind.Absolute, out _))
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

    public HttpSessionTransport CreateSession(
        HttpSessionTransportOptions options,
        HttpServiceClientOptions? clientOptions = null) =>
        CreateOwned(
            clientOptions,
            client => new HttpSessionTransport(client, options, endpointPolicy));

    public SessionStorageMessageTransport CreateStorage(
        SessionStorageMessageTransportOptions options,
        OpaqueSessionStorageDependencies? opaque = null,
        HttpServiceClientOptions? clientOptions = null) =>
        CreateOwned(
            clientOptions,
            client => new SessionStorageMessageTransport(
                client,
                options,
                opaque,
                endpointPolicy));

    public SessionStorageGroupSyncTransport CreateGroupSync(
        SessionStorageGroupSyncTransportOptions options,
        HttpServiceClientOptions? clientOptions = null) =>
        CreateOwned(
            clientOptions,
            client => new SessionStorageGroupSyncTransport(
                client,
                options,
                endpointPolicy));

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

    private static HttpClient CreateHttpClient(
        HttpServiceClientOptions? options,
        HttpServiceNetworkHooks? networkHooks)
    {
        options ??= new HttpServiceClientOptions();
        var timeout = options.Timeout == default
            ? TimeSpan.FromSeconds(100)
            : options.Timeout;
        var connectTimeout = options.ConnectTimeout == default
            ? TimeSpan.FromSeconds(10)
            : options.ConnectTimeout;
        var idleTimeout = options.PooledConnectionIdleTimeout == default
            ? TimeSpan.FromMinutes(1)
            : options.PooledConnectionIdleTimeout;
        var lifetime = options.PooledConnectionLifetime == default
            ? TimeSpan.FromMinutes(5)
            : options.PooledConnectionLifetime;
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
        handler.SslOptions.RemoteCertificateValidationCallback =
            networkHooks?.ServerCertificateValidationCallback;

        // These invariants are deliberately assigned after caller customization.
        handler.AllowAutoRedirect = false;
        handler.UseCookies = false;
        handler.UseProxy = false;

        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = timeout
        };
        if (!string.IsNullOrWhiteSpace(options.UserAgent))
        {
            client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
        }

        return client;
    }
}
