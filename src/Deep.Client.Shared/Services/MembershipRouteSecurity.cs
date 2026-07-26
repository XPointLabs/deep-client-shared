using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Client.Shared.Services;

public sealed record MembershipRouteEndpointPolicy
{
    public bool AllowDevLocalHttp { get; init; }

    public static MembershipRouteEndpointPolicy Production { get; } = new();

    public static MembershipRouteEndpointPolicy DevLocalHttp { get; } = new()
    {
        AllowDevLocalHttp = true
    };

    internal bool IsExplicitDevLocal =>
        ReferenceEquals(this, DevLocalHttp);

    internal bool IsCanonicalDevLocalCatalogOrigin(Uri value)
    {
        try
        {
            if (!IsExplicitDevLocal ||
                value.Scheme != Uri.UriSchemeHttp ||
                value.AbsolutePath != "/" ||
                value.Port <= 0 ||
                !IsLocalIpv4(value.Host))
            {
                return false;
            }
            var canonical = RequireOrigin(value, "Membership catalog origin");
            return string.Equals(
                value.OriginalString,
                canonical.AbsoluteUri,
                StringComparison.Ordinal);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    internal bool IsCanonicalDevLocalCatalogUri(Uri value)
    {
        try
        {
            if (!IsExplicitDevLocal ||
                value.Scheme != Uri.UriSchemeHttp ||
                value.AbsolutePath != HttpMembershipRouteArtifactSource.DefaultArtifactPath ||
                value.Port <= 0 ||
                !IsLocalIpv4(value.Host))
            {
                return false;
            }
            var canonical = RequireCatalogUri(value);
            return string.Equals(
                value.OriginalString,
                canonical.AbsoluteUri,
                StringComparison.Ordinal);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    internal Uri RequireCatalogOrigin(Uri value)
    {
        var canonical = RequireOrigin(value, "Membership catalog origin");
        return canonical;
    }

    internal Uri RequireCatalogUri(Uri value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!string.Equals(
                value.AbsolutePath,
                HttpMembershipRouteArtifactSource.DefaultArtifactPath,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"Membership catalog URL path must be exactly {HttpMembershipRouteArtifactSource.DefaultArtifactPath}.",
                nameof(value));
        }

        var origin = RequireOrigin(value, "Membership catalog URL", requireRootPath: false);
        return new Uri(origin, HttpMembershipRouteArtifactSource.DefaultArtifactPath.TrimStart('/'));
    }

    internal string RequireMembershipOrigin(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var endpoint))
        {
            throw new MembershipRouteCatalogException(
                "Membership route endpoint must be an absolute origin URL.");
        }

        try
        {
            return RequireOrigin(endpoint, "Membership route endpoint").AbsoluteUri;
        }
        catch (ArgumentException exception)
        {
            throw new MembershipRouteCatalogException(
                "Membership route endpoint violates the configured URL policy.",
                exception);
        }
    }

    private Uri RequireOrigin(
        Uri value,
        string description,
        bool requireRootPath = true)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.IsAbsoluteUri ||
            value.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(value.UserInfo) ||
            !string.IsNullOrEmpty(value.Query) ||
            !string.IsNullOrEmpty(value.Fragment) ||
            value.Port <= 0 ||
            requireRootPath && value.AbsolutePath != "/")
        {
            throw new ArgumentException(
                $"{description} must be an absolute HTTP(S) origin without credentials, query, or fragment.");
        }

        if (value.Scheme == Uri.UriSchemeHttp &&
            (!AllowDevLocalHttp || !IsLocalIpv4(value.Host)))
        {
            throw new ArgumentException(
                $"{description} requires HTTPS unless explicit development-local HTTP is enabled for a local IPv4 address.");
        }

        var builder = new UriBuilder(value.Scheme, value.IdnHost)
        {
            Path = "/",
            Query = "",
            Fragment = "",
            Port = value.IsDefaultPort ? -1 : value.Port
        };
        return builder.Uri;
    }

    private static bool IsLocalIpv4(string host)
    {
        if (!IPAddress.TryParse(host, out var address) ||
            address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 ||
               bytes[0] == 127 ||
               bytes[0] == 169 && bytes[1] == 254 ||
               bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
               bytes[0] == 192 && bytes[1] == 168;
    }
}

internal interface ICanonicalDevLocalMembershipRouteArtifactSource
{
    bool IsCanonicalDevLocalHttpSource { get; }
}

public sealed record DevLocalMembershipTrustBootstrapOptions(
    string? ExpectedArtifactSha256,
    string ExpectedOpaqueProfileKey = "install:deep-survival-dev-v1");

public static class DevLocalMembershipTrustBootstrap
{
    public const string Version = "deep-membership-trust-bootstrap-v1";
    public const string Scope = "DEV-LOCAL-ONLY";

    private static readonly string[] ExactProperties =
    [
        "version",
        "scope",
        "opaqueProfileKey",
        "canonicalGenesis",
        "expectedNetworkId",
        "expectedCanonicalGenesisSha256",
        "signedDelegation",
        "bridgeAnchor",
        "membershipAnchor"
    ];

    private static readonly string[] ExactAnchorProperties = ["sequence", "canonicalHash"];

    public static MembershipTrustProfile CreateProfile(
        ReadOnlySpan<byte> exactArtifact,
        DevLocalMembershipTrustBootstrapOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (exactArtifact.Length is <= 0 or > HttpMembershipRouteArtifactSource.MaximumArtifactBytes)
            throw new MembershipRouteCatalogException("Membership artifact is outside its byte limit.");

        var expectedPin = DecodeLowerHexPin(options.ExpectedArtifactSha256);
        var actualPin = SHA256.HashData(exactArtifact);
        if (!CryptographicOperations.FixedTimeEquals(actualPin, expectedPin))
            throw new MembershipRouteCatalogException("Membership artifact SHA-256 pin does not match.");
        if (string.IsNullOrWhiteSpace(options.ExpectedOpaqueProfileKey) ||
            options.ExpectedOpaqueProfileKey.Length > MembershipTrustRecord.MaximumProfileKeyLength ||
            !options.ExpectedOpaqueProfileKey.StartsWith("install:", StringComparison.Ordinal) ||
            options.ExpectedOpaqueProfileKey.StartsWith(
                "install:self-hosted:",
                StringComparison.Ordinal))
        {
            throw new MembershipRouteCatalogException(
                "Expected development membership profile key is invalid.");
        }

        try
        {
            using var document = JsonDocument.Parse(exactArtifact.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32
            });
            var root = document.RootElement;
            RequireObject(root, "Membership artifact");
            RequireExactProperties(
                root,
                ["version", "trustBootstrap", "signedMembership", "members"],
                "Membership artifact");
            if (RequireString(root, "version") !=
                VerifiedMembershipRouteCatalogProvider.ArtifactVersion)
            {
                throw new MembershipRouteCatalogException(
                    "Membership artifact version is invalid.");
            }
            var trust = root.GetProperty("trustBootstrap");
            RequireObject(trust, "Membership trust bootstrap");
            RequireExactProperties(trust, ExactProperties, "Membership trust bootstrap");
            if (RequireString(trust, "version") != Version ||
                RequireString(trust, "scope") != Scope ||
                RequireString(trust, "opaqueProfileKey") != options.ExpectedOpaqueProfileKey)
            {
                throw new MembershipRouteCatalogException(
                    "Development membership trust bootstrap scope, version, or profile key is invalid.");
            }

            var genesisBytes = DecodeCanonicalBase64(
                RequireString(trust, "canonicalGenesis"),
                MembershipTrustRecord.MaximumEnvelopeLength);
            var genesis = MembershipContractCodec.DecodeGenesis(genesisBytes);
            RequireExactBinary(
                genesisBytes,
                MembershipContractCodec.EncodeGenesis(genesis),
                "Canonical genesis");

            var expectedNetworkId = DecodeCanonicalBase64(
                RequireString(trust, "expectedNetworkId"),
                MembershipLimits.NetworkIdLength,
                exactLength: true);
            var expectedGenesisHash = DecodeCanonicalBase64(
                RequireString(trust, "expectedCanonicalGenesisSha256"),
                MembershipLimits.HashLength,
                exactLength: true);
            if (!CryptographicOperations.FixedTimeEquals(
                    genesis.NetworkId.Span,
                    expectedNetworkId) ||
                !CryptographicOperations.FixedTimeEquals(
                    MembershipContractHash.Sha256(genesisBytes),
                    expectedGenesisHash))
            {
                throw new MembershipRouteCatalogException(
                    "Development membership genesis pins are inconsistent.");
            }

            var delegationBytes = DecodeCanonicalBase64(
                RequireString(trust, "signedDelegation"),
                MembershipTrustRecord.MaximumEnvelopeLength);
            var delegation = MembershipContractCodec.DecodeSignedDelegation(delegationBytes);
            RequireExactBinary(
                delegationBytes,
                MembershipContractCodec.EncodeSignedDelegation(delegation),
                "Signed delegation");
            if (!CryptographicOperations.FixedTimeEquals(
                    delegation.NetworkId.Span,
                    expectedNetworkId) ||
                !CryptographicOperations.FixedTimeEquals(
                    delegation.PreviousHash.Span,
                    expectedGenesisHash))
            {
                throw new MembershipRouteCatalogException(
                    "Development membership delegation is not bound to the pinned genesis.");
            }

            var delegationHash = MembershipContractHash.Sha256(
                MembershipContractCodec.GetDelegationSigningBytes(delegation));
            var bridgeAnchor = ReadAnchor(
                trust.GetProperty("bridgeAnchor"),
                delegation.Sequence,
                delegationHash,
                "bridge");
            var membershipAnchor = ReadAnchor(
                trust.GetProperty("membershipAnchor"),
                delegation.Sequence,
                delegationHash,
                "membership");

            return new MembershipTrustProfile(
                options.ExpectedOpaqueProfileKey,
                genesisBytes,
                expectedNetworkId,
                expectedGenesisHash,
                delegationBytes,
                bridgeAnchor,
                membershipAnchor);
        }
        catch (MembershipRouteCatalogException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is JsonException or
            InvalidOperationException or
            FormatException or
            MembershipContractException or
            OverflowException)
        {
            throw new MembershipRouteCatalogException(
                "Development membership trust bootstrap is malformed.",
                exception);
        }
    }

    internal static void RequireExactProperties(
        JsonElement value,
        IReadOnlyCollection<string> expected,
        string description)
    {
        RequireObject(value, description);
        var properties = value.EnumerateObject().Select(static property => property.Name).ToArray();
        if (properties.Length != expected.Count ||
            properties.Distinct(StringComparer.Ordinal).Count() != properties.Length ||
            properties.Any(property => !expected.Contains(property, StringComparer.Ordinal)))
        {
            throw new MembershipRouteCatalogException(
                $"{description} fields are not exact.");
        }
    }

    internal static byte[] DecodeCanonicalBase64(
        string? value,
        int maximumBytes,
        bool exactLength = false)
    {
        if (string.IsNullOrEmpty(value) ||
            value.Length > ((maximumBytes + 2) / 3) * 4)
        {
            throw new FormatException("Base64 value is outside its bound.");
        }

        var decoded = Convert.FromBase64String(value);
        if (decoded.Length == 0 ||
            exactLength && decoded.Length != maximumBytes ||
            !exactLength && decoded.Length > maximumBytes ||
            !string.Equals(Convert.ToBase64String(decoded), value, StringComparison.Ordinal))
        {
            throw new FormatException("Base64 value is not canonical.");
        }
        return decoded;
    }

    private static MembershipTrustAnchor ReadAnchor(
        JsonElement value,
        ulong delegationSequence,
        ReadOnlySpan<byte> delegationHash,
        string name)
    {
        RequireExactProperties(value, ExactAnchorProperties, $"{name} anchor");
        var sequence = value.GetProperty("sequence").GetUInt64();
        var hash = DecodeCanonicalBase64(
            RequireString(value, "canonicalHash"),
            MembershipLimits.HashLength,
            exactLength: true);
        if (sequence != delegationSequence ||
            !CryptographicOperations.FixedTimeEquals(hash, delegationHash))
        {
            throw new MembershipRouteCatalogException(
                $"Development membership {name} anchor is not bound to the signed delegation.");
        }
        return new MembershipTrustAnchor(sequence, hash);
    }

    private static byte[] DecodeLowerHexPin(string? value)
    {
        if (value is null ||
            value.Length != MembershipLimits.HashLength * 2 ||
            value.Any(character =>
                character is not (>= '0' and <= '9') and
                not (>= 'a' and <= 'f')))
        {
            throw new MembershipRouteCatalogException(
                "An exact lowercase membership artifact SHA-256 pin is required.");
        }
        return Convert.FromHexString(value);
    }

    private static string RequireString(JsonElement value, string propertyName)
    {
        var property = value.GetProperty(propertyName);
        return property.ValueKind == JsonValueKind.String && property.GetString() is { } text
            ? text
            : throw new MembershipRouteCatalogException(
                $"Membership trust bootstrap field {propertyName} is invalid.");
    }

    private static void RequireObject(JsonElement value, string description)
    {
        if (value.ValueKind != JsonValueKind.Object)
            throw new MembershipRouteCatalogException($"{description} must be an object.");
    }

    private static void RequireExactBinary(
        ReadOnlySpan<byte> actual,
        ReadOnlySpan<byte> expected,
        string description)
    {
        if (!actual.SequenceEqual(expected))
            throw new MembershipRouteCatalogException($"{description} is not canonical.");
    }
}
