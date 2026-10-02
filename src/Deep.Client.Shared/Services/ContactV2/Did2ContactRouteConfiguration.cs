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
    ValueTask<ParsedDeepIdV2RouteThreshold> FetchAsync(ReadOnlyMemory<byte> durableNonce32,
        DeepIdV2CurrentContactAuthorization authorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority, ReadOnlyMemory<byte> exactXra1,
        OnionTrustedTimeAuthority trustedTime, Did2OwnedContactTransportContext operation, CancellationToken cancellationToken);
}
