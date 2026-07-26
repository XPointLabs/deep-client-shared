using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.MembershipRoutes;

namespace Deep.Client.Shared.Services;

public sealed record MembershipRouteCatalogMember(
    MembershipRouteDescriptor Descriptor,
    MembershipRouteInclusionProof Proof);

public sealed record MembershipRouteCatalogSnapshot(
    ulong Sequence,
    DateTimeOffset ValidUntil,
    IReadOnlyList<MembershipRouteCatalogMember> Members,
    byte[] CanonicalMembershipHash)
{
    public MembershipRouteEndpointPolicy EndpointPolicy { get; init; } =
        MembershipRouteEndpointPolicy.Production;
}

public interface IMembershipRouteCatalogProvider
{
    Task<MembershipRouteCatalogSnapshot> GetCatalogAsync(
        CancellationToken cancellationToken = default);
}

public interface IMembershipRouteArtifactSource
{
    Task<byte[]> FetchAsync(CancellationToken cancellationToken = default);
}

public interface IMembershipRouteArtifactCache
{
    Task<byte[]?> ReadAsync(CancellationToken cancellationToken = default);
    Task WriteAsync(ReadOnlyMemory<byte> artifact, CancellationToken cancellationToken = default);
}

public sealed class MembershipRouteCatalogException(string message, Exception? inner = null)
    : IOException(message, inner);

public sealed class MembershipRouteDirectoryUnavailableException(string message, Exception? inner = null)
    : IOException(message, inner);

public sealed class HttpMembershipRouteArtifactSource :
    IMembershipRouteArtifactSource,
    ICanonicalDevLocalMembershipRouteArtifactSource
{
    public const int MaximumArtifactBytes = 2 * 1024 * 1024;
    public const string DefaultArtifactPath = "/api/network/membership-route-catalog";

    private readonly HttpClient _httpClient;
    private readonly Uri[] _catalogEndpoints;
    private readonly bool _isCanonicalDevLocalHttpSource;

    bool ICanonicalDevLocalMembershipRouteArtifactSource.IsCanonicalDevLocalHttpSource =>
        _isCanonicalDevLocalHttpSource;

    public HttpMembershipRouteArtifactSource(
        HttpClient httpClient,
        IEnumerable<Uri> bootstrapEndpoints,
        string artifactPath = DefaultArtifactPath,
        MembershipRouteEndpointPolicy? endpointPolicy = null)
    {
        _httpClient = httpClient;
        if (!string.Equals(artifactPath, DefaultArtifactPath, StringComparison.Ordinal))
            throw new ArgumentException(
                $"Artifact path must be exactly {DefaultArtifactPath}.",
                nameof(artifactPath));
        var policy = endpointPolicy ?? MembershipRouteEndpointPolicy.Production;
        var suppliedEndpoints = bootstrapEndpoints?.ToArray()
            ?? throw new ArgumentNullException(nameof(bootstrapEndpoints));
        _isCanonicalDevLocalHttpSource =
            suppliedEndpoints.Length == 1 &&
            suppliedEndpoints.All(policy.IsCanonicalDevLocalCatalogOrigin);
        _catalogEndpoints = suppliedEndpoints
            .Select(policy.RequireCatalogOrigin)
            .DistinctBy(static endpoint => endpoint.AbsoluteUri, StringComparer.Ordinal)
            .Select(endpoint => new Uri(endpoint, DefaultArtifactPath.TrimStart('/')))
            .ToArray();
        if (_catalogEndpoints.Length == 0)
            throw new ArgumentException("At least one bootstrap fetch endpoint is required.", nameof(bootstrapEndpoints));
    }

    private HttpMembershipRouteArtifactSource(
        HttpClient httpClient,
        Uri[] catalogEndpoints,
        bool isCanonicalDevLocalHttpSource)
    {
        _httpClient = httpClient;
        _catalogEndpoints = catalogEndpoints;
        _isCanonicalDevLocalHttpSource = isCanonicalDevLocalHttpSource;
    }

    public static HttpMembershipRouteArtifactSource FromCatalogUrls(
        HttpClient httpClient,
        IEnumerable<Uri> catalogUrls,
        MembershipRouteEndpointPolicy? endpointPolicy = null)
    {
        var policy = endpointPolicy ?? MembershipRouteEndpointPolicy.Production;
        var suppliedUrls = catalogUrls?.ToArray()
            ?? throw new ArgumentNullException(nameof(catalogUrls));
        var isCanonicalDevLocalHttpSource =
            suppliedUrls.Length == 1 &&
            suppliedUrls.All(policy.IsCanonicalDevLocalCatalogUri);
        var endpoints = suppliedUrls
            .Select(policy.RequireCatalogUri)
            .DistinctBy(static endpoint => endpoint.AbsoluteUri, StringComparer.Ordinal)
            .ToArray();
        if (endpoints.Length == 0)
            throw new ArgumentException("At least one membership catalog URL is required.", nameof(catalogUrls));
        return new HttpMembershipRouteArtifactSource(
            httpClient,
            endpoints,
            isCanonicalDevLocalHttpSource);
    }

    public async Task<byte[]> FetchAsync(CancellationToken cancellationToken = default)
    {
        Exception? lastFailure = null;
        foreach (var endpoint in _catalogEndpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var response = await _httpClient.GetAsync(
                    endpoint,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken).ConfigureAwait(false);
                if (_isCanonicalDevLocalHttpSource &&
                    response.RequestMessage?.RequestUri is { } responseUri &&
                    !string.Equals(
                        responseUri.AbsoluteUri,
                        endpoint.AbsoluteUri,
                        StringComparison.Ordinal))
                {
                    throw new MembershipRouteCatalogException(
                        "Development membership catalog redirects are prohibited.");
                }
                if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.ServiceUnavailable)
                {
                    lastFailure = new HttpRequestException(
                        $"Membership artifact is unavailable at bootstrap endpoint ({(int)response.StatusCode}).");
                    continue;
                }
                response.EnsureSuccessStatusCode();
                return await ReadBoundedAsync(
                    response.Content,
                    MaximumArtifactBytes,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is HttpRequestException or IOException or TaskCanceledException)
            {
                lastFailure = exception;
            }
        }
        throw new MembershipRouteDirectoryUnavailableException(
            "All membership bootstrap fetch endpoints are unavailable.",
            lastFailure);
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > MaximumArtifactBytes)
            throw new MembershipRouteCatalogException("Membership artifact exceeds its byte limit.");
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
                return output.ToArray();
            if (output.Length + read > maximumBytes)
                throw new MembershipRouteCatalogException("Membership artifact exceeds its byte limit.");
            output.Write(buffer, 0, read);
        }
    }
}

public sealed class FileMembershipRouteArtifactCache : IMembershipRouteArtifactCache
{
    private readonly string _path;

    public FileMembershipRouteArtifactCache(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Membership cache path is required.", nameof(path));
        _path = Path.GetFullPath(path);
    }

    public async Task<byte[]?> ReadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_path))
            return null;
        var info = new FileInfo(_path);
        if (info.Length is <= 0 or > HttpMembershipRouteArtifactSource.MaximumArtifactBytes)
            throw new MembershipRouteCatalogException("Cached membership artifact is outside its byte limit.");
        return await File.ReadAllBytesAsync(_path, cancellationToken).ConfigureAwait(false);
    }

    public async Task WriteAsync(
        ReadOnlyMemory<byte> artifact,
        CancellationToken cancellationToken = default)
    {
        if (artifact.Length is <= 0 or > HttpMembershipRouteArtifactSource.MaximumArtifactBytes)
            throw new MembershipRouteCatalogException("Membership artifact is outside its byte limit.");
        var directory = Path.GetDirectoryName(_path)
            ?? throw new MembershipRouteCatalogException("Membership cache directory is invalid.");
        Directory.CreateDirectory(directory);
        var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllBytesAsync(temporary, artifact.ToArray(), cancellationToken).ConfigureAwait(false);
            File.Move(temporary, _path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}

public sealed class InMemoryMembershipRouteArtifactCache : IMembershipRouteArtifactCache
{
    private byte[]? _artifact;

    public Task<byte[]?> ReadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var artifact = Volatile.Read(ref _artifact);
        return Task.FromResult(artifact?.ToArray());
    }

    public Task WriteAsync(
        ReadOnlyMemory<byte> artifact,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Volatile.Write(ref _artifact, artifact.ToArray());
        return Task.CompletedTask;
    }
}

public sealed class VerifiedMembershipRouteCatalogProvider : IMembershipRouteCatalogProvider
{
    public const string ArtifactVersion = "deep-membership-route-catalog-v1";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        MaxDepth = 32
    };

    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly MembershipTrustService _trustService;
    private readonly IMembershipTrustRepository _trustRepository;
    private readonly MembershipTrustProfile? _trustProfile;
    private readonly IMembershipRouteArtifactSource _source;
    private readonly IMembershipRouteArtifactCache _cache;
    private readonly DevLocalMembershipTrustBootstrapOptions? _devLocalBootstrap;
    private readonly MembershipRouteEndpointPolicy _endpointPolicy;

    public VerifiedMembershipRouteCatalogProvider(
        MembershipTrustService trustService,
        IMembershipTrustRepository trustRepository,
        MembershipTrustProfile trustProfile,
        IMembershipRouteArtifactSource source,
        IMembershipRouteArtifactCache cache,
        TimeProvider? timeProvider = null,
        MembershipRouteEndpointPolicy? endpointPolicy = null)
    {
        _trustService = trustService;
        _trustRepository = trustRepository;
        _trustProfile = trustProfile ?? throw new ArgumentNullException(nameof(trustProfile));
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _endpointPolicy = endpointPolicy ?? MembershipRouteEndpointPolicy.Production;
    }

    public VerifiedMembershipRouteCatalogProvider(
        MembershipTrustService trustService,
        IMembershipTrustRepository trustRepository,
        DevLocalMembershipTrustBootstrapOptions devLocalBootstrap,
        IMembershipRouteArtifactSource source,
        IMembershipRouteArtifactCache cache,
        TimeProvider? timeProvider = null,
        MembershipRouteEndpointPolicy? endpointPolicy = null)
    {
        _trustService = trustService;
        _trustRepository = trustRepository;
        _devLocalBootstrap = devLocalBootstrap ??
            throw new ArgumentNullException(nameof(devLocalBootstrap));
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _timeProvider = timeProvider ?? TimeProvider.System;
        if (endpointPolicy is null || !endpointPolicy.IsExplicitDevLocal)
        {
            throw new ArgumentException(
                "Development membership trust bootstrap requires the explicit development-local HTTP endpoint policy.",
                nameof(endpointPolicy));
        }
        if (source is not ICanonicalDevLocalMembershipRouteArtifactSource
            {
                IsCanonicalDevLocalHttpSource: true
            })
        {
            throw new ArgumentException(
                "Development membership trust bootstrap requires a canonical local-IPv4 HTTP catalog source.",
                nameof(source));
        }
        _endpointPolicy = endpointPolicy;
    }

    public async Task<MembershipRouteCatalogSnapshot> GetCatalogAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] artifact;
            try
            {
                artifact = await _source.FetchAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (MembershipRouteDirectoryUnavailableException exception)
            {
                artifact = await _cache.ReadAsync(cancellationToken).ConfigureAwait(false)
                    ?? throw new MembershipRouteDirectoryUnavailableException(
                        "Membership directory is unavailable and no LKG catalog is cached.",
                        exception);
                return await VerifyAsync(artifact, cancellationToken).ConfigureAwait(false);
            }

            var verified = await VerifyAsync(artifact, cancellationToken).ConfigureAwait(false);
            await _cache.WriteAsync(artifact, cancellationToken).ConfigureAwait(false);
            return verified;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<MembershipRouteCatalogSnapshot> VerifyAsync(
        byte[] encoded,
        CancellationToken cancellationToken)
    {
        if (encoded.Length is <= 0 or > HttpMembershipRouteArtifactSource.MaximumArtifactBytes)
            throw new MembershipRouteCatalogException("Membership artifact is outside its byte limit.");
        var trustProfile = _devLocalBootstrap is null
            ? _trustProfile!
            : DevLocalMembershipTrustBootstrap.CreateProfile(encoded, _devLocalBootstrap);
        MembershipRouteArtifactDocument artifact;
        try
        {
            using var document = JsonDocument.Parse(encoded, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32
            });
            DevLocalMembershipTrustBootstrap.RequireExactProperties(
                document.RootElement,
                _devLocalBootstrap is null
                    ? ["version", "signedMembership", "members"]
                    : ["version", "trustBootstrap", "signedMembership", "members"],
                "Membership artifact");
            var rawMembers = document.RootElement.GetProperty("members");
            if (rawMembers.ValueKind != JsonValueKind.Array)
                throw new MembershipRouteCatalogException("Membership route members must be an array.");
            foreach (var rawMember in rawMembers.EnumerateArray())
            {
                DevLocalMembershipTrustBootstrap.RequireExactProperties(
                    rawMember,
                    ["leaf", "leafIndex", "memberCount", "siblingHashes"],
                    "Membership route member");
            }
            artifact = JsonSerializer.Deserialize<MembershipRouteArtifactDocument>(encoded, JsonOptions)
                ?? throw new JsonException("Membership artifact is empty.");
        }
        catch (JsonException exception)
        {
            throw new MembershipRouteCatalogException("Membership artifact JSON is malformed.", exception);
        }
        if (!string.Equals(artifact.Version, ArtifactVersion, StringComparison.Ordinal) ||
            artifact.SignedMembership is null ||
            artifact.Members is null)
            throw new MembershipRouteCatalogException("Membership artifact framing is invalid.");

        byte[] signedEnvelope;
        SignedMembershipCommitment signed;
        try
        {
            signedEnvelope = DecodeBase64(artifact.SignedMembership, MembershipTrustRecord.MaximumEnvelopeLength);
            signed = MembershipContractCodec.DecodeSignedMembership(signedEnvelope);
            if (!signedEnvelope.AsSpan().SequenceEqual(MembershipContractCodec.EncodeSignedMembership(signed)))
                throw new MembershipRouteCatalogException("Signed membership envelope is not canonical.");
        }
        catch (Exception exception) when (
            exception is FormatException or MembershipContractException)
        {
            throw new MembershipRouteCatalogException("Signed membership envelope is invalid.", exception);
        }

        var initialized = await _trustService.InitializeAsync(trustProfile, cancellationToken).ConfigureAwait(false);
        if (!initialized.Usable)
            throw new MembershipRouteCatalogException($"Membership trust initialization failed: {initialized.State}.");
        var applied = await _trustService.ApplyMembershipAsync(
            trustProfile,
            signedEnvelope,
            cancellationToken).ConfigureAwait(false);
        if (!applied.Usable)
            throw new MembershipRouteCatalogException($"Membership trust rejected the catalog: {applied.State}.");

        var persisted = await _trustRepository.ReadMembershipTrustAsync(
            trustProfile.OpaqueProfileKey,
            MembershipTrustDomain.Membership,
            cancellationToken).ConfigureAwait(false);
        var canonicalHash = MembershipContractHash.Sha256(
            MembershipContractCodec.GetMembershipSigningBytes(signed.Statement));
        if (persisted.Result != MembershipTrustReadResult.Found ||
            persisted.Head is null ||
            persisted.Head.State != MembershipTrustState.Healthy ||
            persisted.Head.Sequence != signed.Statement.Sequence ||
            !CryptographicOperations.FixedTimeEquals(persisted.Head.CanonicalHash, canonicalHash))
            throw new MembershipRouteCatalogException("Membership LKG does not match the signed catalog.");

        var now = _timeProvider.GetUtcNow();
        var nowSeconds = checked((ulong)now.ToUnixTimeSeconds());
        if (nowSeconds < signed.Statement.ValidFromUnixSeconds ||
            nowSeconds > signed.Statement.ValidUntilUnixSeconds)
            throw new MembershipRouteCatalogException("Membership catalog is outside its signed validity window.");
        if (signed.Statement.MemberCount < 6 ||
            signed.Statement.MemberCount > MembershipRouteDescriptorCodec.MaximumMembers ||
            artifact.Members.Count != signed.Statement.MemberCount)
            throw new MembershipRouteCatalogException("Membership catalog is incomplete or undersized.");

        var members = new MembershipRouteCatalogMember[artifact.Members.Count];
        var routerIds = new HashSet<string>(StringComparer.Ordinal);
        var endpoints = new HashSet<string>(StringComparer.Ordinal);
        var proofIndices = new HashSet<uint>();
        string? previousRouterId = null;
        for (var index = 0; index < artifact.Members.Count; index++)
        {
            var item = artifact.Members[index]
                ?? throw new MembershipRouteCatalogException("Membership catalog contains a null member.");
            MembershipRouteDescriptor descriptor;
            MembershipRouteInclusionProof proof;
            try
            {
                descriptor = MembershipRouteDescriptorCodec.Decode(
                    DecodeBase64(item.Leaf, 1024));
                proof = new MembershipRouteInclusionProof
                {
                    LeafIndex = item.LeafIndex,
                    MemberCount = item.MemberCount,
                    SiblingHashes = (item.SiblingHashes ??
                        throw new MembershipRouteCatalogException("Membership proof is missing."))
                        .Select(static value =>
                            (ReadOnlyMemory<byte>)DecodeBase64(
                                value,
                                MembershipRouteDescriptorCodec.HashLength))
                        .ToArray()
                };
            }
            catch (Exception exception) when (
                exception is FormatException or MembershipRouteDescriptorException)
            {
                throw new MembershipRouteCatalogException("Membership route leaf is invalid.", exception);
            }

            var routerId = Convert.ToHexStringLower(descriptor.RouterId.Span);
            var endpoint = _endpointPolicy.RequireMembershipOrigin(descriptor.RpcEndpoint);
            if (descriptor.Epoch != signed.Statement.Sequence ||
                descriptor.ValidFromUnixSeconds < signed.Statement.ValidFromUnixSeconds ||
                descriptor.ValidUntilUnixSeconds > signed.Statement.ValidUntilUnixSeconds ||
                !descriptor.RouterId.Span.SequenceEqual(descriptor.Ed25519PublicKey.Span) ||
                (descriptor.Roles & (MembershipRouteRole.Ingress |
                                     MembershipRouteRole.Core |
                                     MembershipRouteRole.Storage)) ==
                    MembershipRouteRole.None ||
                (descriptor.Capabilities & (MembershipRouteCapability.SessionRpc |
                                            MembershipRouteCapability.OnionV1)) !=
                    (MembershipRouteCapability.SessionRpc |
                     MembershipRouteCapability.OnionV1) ||
                descriptor.Roles.HasFlag(MembershipRouteRole.Storage) &&
                !descriptor.Capabilities.HasFlag(MembershipRouteCapability.Storage) ||
                previousRouterId is not null &&
                string.CompareOrdinal(previousRouterId, routerId) >= 0 ||
                !routerIds.Add(routerId) ||
                !endpoints.Add(endpoint) ||
                !proofIndices.Add(proof.LeafIndex) ||
                proof.LeafIndex != index ||
                proof.MemberCount != signed.Statement.MemberCount ||
                !MembershipRouteDescriptorCodec.VerifyInclusion(
                    descriptor,
                    proof,
                    signed.Statement.MerkleRoot.Span))
                throw new MembershipRouteCatalogException("Membership route catalog failed inclusion or uniqueness checks.");
            previousRouterId = routerId;
            members[index] = new MembershipRouteCatalogMember(descriptor, proof);
        }

        return new MembershipRouteCatalogSnapshot(
            signed.Statement.Sequence,
            DateTimeOffset.FromUnixTimeSeconds(checked((long)signed.Statement.ValidUntilUnixSeconds)),
            members,
            canonicalHash)
        {
            EndpointPolicy = _endpointPolicy
        };
    }

    private static byte[] DecodeBase64(string? value, int maximumBytes)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > ((maximumBytes + 2) / 3) * 4 + 4)
            throw new FormatException("Base64 value is outside its bound.");
        return DevLocalMembershipTrustBootstrap.DecodeCanonicalBase64(value, maximumBytes);
    }

    private sealed record MembershipRouteArtifactDocument(
        [property: JsonPropertyName("version")] string? Version,
        [property: JsonPropertyName("signedMembership")] string? SignedMembership,
        [property: JsonPropertyName("members")] IReadOnlyList<MembershipRouteArtifactMember?>? Members);

    private sealed record MembershipRouteArtifactMember(
        [property: JsonPropertyName("leaf")] string? Leaf,
        [property: JsonPropertyName("leafIndex")] uint LeafIndex,
        [property: JsonPropertyName("memberCount")] uint MemberCount,
        [property: JsonPropertyName("siblingHashes")] IReadOnlyList<string>? SiblingHashes);
}

public static class MembershipRouteSelector
{
    public const int RequiredRouteHops = 3;
    public const int RequiredDisjointMembers = 6;

    public static IReadOnlyList<MembershipRouteCatalogMember> Select(
        MembershipRouteCatalogSnapshot catalog,
        ReadOnlySpan<byte> entropy,
        IReadOnlySet<string>? excludedRouterIds = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        if (entropy.Length < 16)
            throw new ArgumentException("Route-selection entropy must be at least 128 bits.", nameof(entropy));
        var entropyBytes = entropy.ToArray();
        var excluded = excludedRouterIds ?? new HashSet<string>(StringComparer.Ordinal);
        var endpointOrigins = new HashSet<string>(StringComparer.Ordinal);
        foreach (var member in catalog.Members)
        {
            var origin = catalog.EndpointPolicy.RequireMembershipOrigin(
                member.Descriptor.RpcEndpoint);
            if (!endpointOrigins.Add(origin))
                throw new MembershipRouteCatalogException(
                    "Membership route catalog contains equivalent endpoint origins.");
        }
        var ranked = catalog.Members
            .Where(member => !excluded.Contains(
                Convert.ToHexStringLower(member.Descriptor.RouterId.Span)))
            .Select(member => new
            {
                Member = member,
                Rank = Rank(entropyBytes, member.Descriptor.RouterId.Span)
            })
            .OrderBy(static item => item.Rank, ByteArrayComparer.Instance)
            .ToArray();
        foreach (var ingress in ranked.Where(static item =>
                     item.Member.Descriptor.Roles.HasFlag(MembershipRouteRole.Ingress)))
        {
            foreach (var core in ranked.Where(item =>
                         !ReferenceEquals(item, ingress) &&
                         !item.Member.Descriptor.RouterId.Span.SequenceEqual(
                             ingress.Member.Descriptor.RouterId.Span) &&
                         item.Member.Descriptor.Roles.HasFlag(MembershipRouteRole.Core)))
            {
                var storage = ranked.FirstOrDefault(item =>
                    !item.Member.Descriptor.RouterId.Span.SequenceEqual(
                        ingress.Member.Descriptor.RouterId.Span) &&
                    !item.Member.Descriptor.RouterId.Span.SequenceEqual(
                        core.Member.Descriptor.RouterId.Span) &&
                    item.Member.Descriptor.Roles.HasFlag(MembershipRouteRole.Storage) &&
                    item.Member.Descriptor.Capabilities.HasFlag(
                        MembershipRouteCapability.Storage));
                if (storage is not null)
                    return [ingress.Member, core.Member, storage.Member];
            }
        }
        throw new MembershipRouteCatalogException(
            "No exact ingress/core/storage three-hop route remains in the trusted catalog.");
    }

    private static byte[] Rank(ReadOnlySpan<byte> entropy, ReadOnlySpan<byte> routerId)
    {
        using var hmac = new HMACSHA256(entropy.ToArray());
        return hmac.ComputeHash(routerId.ToArray());
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static ByteArrayComparer Instance { get; } = new();

        public int Compare(byte[]? left, byte[]? right)
        {
            if (ReferenceEquals(left, right))
                return 0;
            if (left is null)
                return -1;
            if (right is null)
                return 1;
            return left.AsSpan().SequenceCompareTo(right);
        }
    }
}
