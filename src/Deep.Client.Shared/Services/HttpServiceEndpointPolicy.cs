using System.Net;
using System.Net.Sockets;

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

    internal void RequireCompatibleBaseAddress(
        HttpClient httpClient,
        Uri configuredOrigin,
        string description)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(configuredOrigin);
        if (httpClient.BaseAddress is null)
        {
            httpClient.BaseAddress = configuredOrigin;
            return;
        }

        ValidateEndpoint(httpClient.BaseAddress, description, requireRootPath: true);
        var clientOrigin = CanonicalOrigin(httpClient.BaseAddress);
        if (!SameOrigin(clientOrigin, configuredOrigin))
        {
            throw new ArgumentException(
                $"{description} HttpClient base address must match the configured origin.",
                nameof(httpClient));
        }
    }

    internal void RequireSameOriginResource(
        Uri value,
        Uri configuredOrigin,
        string description)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(configuredOrigin);
        ValidateEndpoint(value, description, requireRootPath: false);
        if (!SameOrigin(value, configuredOrigin))
        {
            throw new ArgumentException(
                $"{description} must use the configured service origin.",
                nameof(value));
        }
    }

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

    private static bool SameOrigin(Uri left, Uri right) =>
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

public sealed class HttpServiceTransportFactory
{
    private readonly HttpServiceEndpointPolicy endpointPolicy;

    public HttpServiceTransportFactory(HttpServiceEndpointPolicy endpointPolicy)
    {
        this.endpointPolicy = endpointPolicy
            ?? throw new ArgumentNullException(nameof(endpointPolicy));
    }

    public HttpAvatarProfileTransport CreateAvatar(
        HttpClient httpClient,
        HttpAvatarProfileTransportOptions options,
        TimeProvider? timeProvider = null) =>
        new(httpClient, options, timeProvider, endpointPolicy);

    public HttpAttachmentFileTransport CreateAttachment(
        HttpClient httpClient,
        HttpAttachmentFileTransportOptions options) =>
        new(httpClient, options, endpointPolicy);

    public HttpPushSubscriptionTransport CreatePush(
        HttpClient httpClient,
        HttpPushSubscriptionTransportOptions options) =>
        new(httpClient, options, endpointPolicy);

    public HttpCallSignalingTransport CreateCallSignaling(
        HttpClient httpClient,
        HttpCallSignalingTransportOptions options,
        Func<CancellationToken, Task<string?>>? recoveryPhraseProvider = null,
        TimeProvider? timeProvider = null) =>
        new(httpClient, options, recoveryPhraseProvider, timeProvider, endpointPolicy);

    public HttpSessionTransport CreateSession(
        HttpClient httpClient,
        HttpSessionTransportOptions options) =>
        new(httpClient, options, endpointPolicy);

    public SessionStorageMessageTransport CreateStorage(
        HttpClient httpClient,
        SessionStorageMessageTransportOptions options,
        OpaqueSessionStorageDependencies? opaque = null) =>
        new(httpClient, options, opaque, endpointPolicy);

    public SessionStorageGroupSyncTransport CreateGroupSync(
        HttpClient httpClient,
        SessionStorageGroupSyncTransportOptions options) =>
        new(httpClient, options, endpointPolicy);
}
