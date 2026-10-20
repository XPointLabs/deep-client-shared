using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Renews the own adopted publication and advertises its exact successor to one established contact through the existing ratcheted mailbox. Does not use an expired route or XUR.</summary>
    /// <param name="conversation">An existing mutually consented owned conversation.</param>
    /// <param name="source">Independently current network and directory source.</param>
    /// <param name="ct">Cancellation for this owned maintenance operation.</param>
    /// <returns>One for an original or resumed update with verified Store; zero when the actual native advertisement already matches.</returns>
    public async Task<int> RefreshContactRouteAsync(DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        // Publication renewal remains its existing exact pending/committed saga.
        // Discard any earlier read memo before acquiring the messaging endpoint.
        _ = await EnsureOwnPermanentContactPublishedAsync(source, ct).ConfigureAwait(false);
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        var pair = await source.VerifyForOwnMessagingAsync(this, conversation.Scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        var selection = await owner.SelectOwnRouteMaintenanceAsync(TrustedUnixSeconds(), verifier,
            conversation.Scope, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
        if (selection is null) return 0;
        try
        {
            using var command = selection.Length == 0
                ? await CreateOwnDirectRouteUpdateAsync(conversation.Scope, source, ct).ConfigureAwait(false)
                : await PrepareOwnDirectRouteUpdateAsync(conversation.Scope, selection, source, ct).ConfigureAwait(false);
            using var native = await SendOwnedMessagingCoreAsync(conversation.Scope, command.OperationId,
                command.ExactDmc2, source, ct, routeControl: true).ConfigureAwait(false);
            _ = await DeliverOwnMessagingAsync(conversation.Scope, command.OperationId, source, ct).ConfigureAwait(false);
            return 1;
        }
        finally { CryptographicOperations.ZeroMemory(selection); }
    }
}
