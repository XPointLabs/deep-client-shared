using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Services;

/// <summary>Denial-only interval diagnostics, not route/update or dispatch authority.</summary>
/// <param name="AdvertisementIntervalCoversNow">Whether the retained peer XRA1 covers current trusted time.</param>
/// <param name="UpdateIntervalCoversNow">Whether the accepted peer XUR1 covers current trusted time.</param>
/// <param name="RouteFaultRetained">Whether actual native history retains a route fault.</param>
/// <param name="UpdateGeneration">Authenticated generation of the accepted peer XUR1.</param>
/// <param name="UpdateIssuedAtUnixSeconds">Signed issuance of the accepted XUR1, diagnostic only.</param>
/// <param name="UpdateExpiresAtUnixSeconds">Signed expiry of the accepted XUR1, diagnostic only.</param>
/// <param name="UpdateRemainingSeconds">Nonnegative remaining interval against the authenticated trusted upper bound.</param>
/// <param name="OwnUpdateGeneration">Generation of the independently verified owned signed XUR1 chain.</param>
/// <param name="OwnAnnouncementUpdateGeneration">Generation carried by the authenticated own native announcement; not Store evidence.</param>
/// <param name="OwnPendingRouteControl">Whether actual protected authored custody retains pending route-control work.</param>
public sealed record DeepIdV2ContactRouteHealth(bool AdvertisementIntervalCoversNow, bool UpdateIntervalCoversNow,
    bool RouteFaultRetained, ulong UpdateGeneration = 0, ulong UpdateIssuedAtUnixSeconds = 0,
    ulong UpdateExpiresAtUnixSeconds = 0, ulong UpdateRemainingSeconds = 0, ulong? OwnUpdateGeneration = null,
    ulong? OwnAnnouncementUpdateGeneration = null, bool? OwnPendingRouteControl = null);

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Requires the relationship's actual native peer delivery route to pass current Protocol verification. Exports no route or capability.</summary>
    /// <param name="conversation">The existing locally owned conversation.</param>
    /// <param name="source">This account's independent current network and directory source.</param>
    /// <param name="ct">Cancellation for this read.</param>
    /// <returns>A completed task after current route and native custody checks; subsequent effects must independently recheck them.</returns>
    public async Task RequireCurrentContactRouteAsync(DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        using var reads = source.OpenIndependentCommandReadScope(); source = reads.Source;
        var pair = await source.VerifyForOwnMessagingAsync(this, conversation.Scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        await owner.RequireCurrentContactRouteAsync(TrustedUnixSeconds(), verifier, conversation.Scope,
            pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
    }

    /// <summary>Reads coarse route interval diagnostics from actual authenticated contact history. Exports no descriptor or capability.</summary>
    /// <param name="conversation">The existing locally owned conversation.</param>
    /// <param name="source">Independently current network/directory source.</param>
    /// <param name="ct">Cancellation for this read.</param>
    /// <returns>Diagnostic interval predicates only, never permission to use either route.</returns>
    public Task<DeepIdV2ContactRouteHealth> ReadContactRouteHealthAsync(DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        ReadContactRouteHealthCoreAsync(conversation, source, false, ct);

    /// <summary>Explicit diagnostic read of peer health and authenticated own signed/native control custody. Grants no dispatch or Store permission.</summary>
    public Task<DeepIdV2ContactRouteHealth> ReadContactRouteDiagnosticsAsync(DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        ReadContactRouteHealthCoreAsync(conversation, source, true, ct);

    private async Task<DeepIdV2ContactRouteHealth> ReadContactRouteHealthCoreAsync(DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, bool includeOwnDiagnostics, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        var pair = await source.VerifyForOwnMessagingAsync(this, conversation.Scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.ReadContactRouteHealthAsync(TrustedUnixSeconds(), verifier, conversation.Scope,
            pair.Own, pair.Peer, source, ct, includeOwnDiagnostics).ConfigureAwait(false);
    }
}
