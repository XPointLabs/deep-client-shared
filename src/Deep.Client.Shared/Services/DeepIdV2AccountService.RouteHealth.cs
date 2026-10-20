using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Services;

/// <summary>Denial-only interval diagnostics, not route/update or dispatch authority.</summary>
/// <param name="AdvertisementIntervalCoversNow">Whether the retained peer XRA1 covers current trusted time.</param>
/// <param name="UpdateIntervalCoversNow">Whether the original peer XUR1 covers current trusted time.</param>
/// <param name="RouteFaultRetained">Whether actual native history retains a route fault.</param>
public sealed record DeepIdV2ContactRouteHealth(bool AdvertisementIntervalCoversNow, bool UpdateIntervalCoversNow, bool RouteFaultRetained);

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Reads coarse route interval diagnostics from actual authenticated contact history. Exports no descriptor or capability.</summary>
    /// <param name="conversation">The existing locally owned conversation.</param>
    /// <param name="source">Independently current network/directory source.</param>
    /// <param name="ct">Cancellation for this read.</param>
    /// <returns>Diagnostic interval predicates only, never permission to use either route.</returns>
    public async Task<DeepIdV2ContactRouteHealth> ReadContactRouteHealthAsync(DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        var pair = await source.VerifyForOwnMessagingAsync(this, conversation.Scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.ReadContactRouteHealthAsync(TrustedUnixSeconds(), verifier, conversation.Scope,
            pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
    }
}
