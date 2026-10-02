using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

internal sealed class Did2ContactRouteConfiguration
{
    private readonly byte[] policy;
    internal Did2ContactRouteConfiguration(uint quota, ushort minimumReader, ReadOnlySpan<byte> antiSpamHash32)
    {
        if (quota is < 1 or > 65_535 || minimumReader is < 1 or > 256 ||
            antiSpamHash32.Length != 32 || antiSpamHash32.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The bounded DID2 route configuration is invalid.");
        Quota = quota; MinimumReader = minimumReader; policy = antiSpamHash32.ToArray();
    }
    internal uint Quota { get; }
    internal ushort MinimumReader { get; }
    internal ReadOnlyMemory<byte> AntiSpamHash => policy.ToArray();
}

// Private authority-coordination boundary, not a public storage/router input.
// Return values are untrusted parsed bytes; Protocol independently verifies them.
internal interface IDid2ContactRouteThresholdSource
{
    ValueTask<ParsedDeepIdV2RouteThreshold> FetchAsync(ContactRouteAuthorityWireRequest exactPendingRequest,
        DeepIdV2CurrentContactAuthorization authorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority trustedTime, Did2OwnedContactTransportContext operation, CancellationToken cancellationToken);
}

internal static class Did2ContactRouteRequestCustody
{
    internal static void RequireCurrent(ContactRouteAuthorityWireRequest request,
        DeepIdV2CurrentContactAuthorization authorization, VerifiedOnionNetworkContext network)
    {
        ArgumentNullException.ThrowIfNull(request);
        var floor = authorization.Freshness.NextProtectedLkg;
        if (!CryptographicOperations.FixedTimeEquals(request.NetworkId.Span, network.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(request.ExactDca1.Span, authorization.Authorization.Record.CanonicalBytes.Span) ||
            !CryptographicOperations.FixedTimeEquals(request.DirectoryLookupKey.Span, authorization.Freshness.QueriedDirectoryLeafKey.Span) ||
            request.MinimumAdh1Generation > floor.LogGeneration ||
            request.MinimumAdh1Generation == floor.LogGeneration &&
                !CryptographicOperations.FixedTimeEquals(request.MinimumAdh1CoreHash.Span, floor.CoreHash.Span))
            throw new CryptographicException("The retained coordination request differs from current owned authority.");
    }
}
