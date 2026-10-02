using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    // A data-only owned drafting input. Event embedding/retention is a separate
    // closed command; do not expose this as a UI-supplied route trust marker.
    internal async Task<ParsedDeepIdV2ContactMailboxRoute> ReadOwnPrivateContactMailboxRouteAsync(
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.ReadOwnPrivateContactMailboxRouteAsync(TrustedUnixSeconds(), verifier, source, fresh, ct).ConfigureAwait(false);
    }
}
