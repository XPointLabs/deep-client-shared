using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Requests a bounded next history page from the relationship's actual adopted peer progress.</summary>
    /// <param name="conversation">An existing mutually consented conversation.</param>
    /// <param name="source">Current account, peer and network authority.</param>
    /// <param name="ct">Cancellation for the owned command and dispatch.</param>
    /// <returns>One for newly authored or resumed work; zero while an unchanged request is awaiting progress.</returns>
    public Task<int> RequestContactRouteHistoryAsync(DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        DispatchRouteHistoryCommandAsync(conversation, false, ReadOnlyMemory<byte>.Empty, source, ct);

    /// <summary>Answers an exact received native mode4 operation using independently retained own history.</summary>
    /// <param name="conversation">The owned relationship receiving the request.</param>
    /// <param name="receivedOperation">An immutable incoming operation selector, never a request payload.</param>
    /// <param name="source">Current account, peer and network authority.</param>
    /// <param name="ct">Cancellation for the owned command and dispatch.</param>
    /// <returns>One for newly authored or resumed work; zero for already answered, expired or unmatched requests.</returns>
    public Task<int> RespondContactRouteHistoryAsync(DeepIdV2Conversation conversation, ReadOnlyMemory<byte> receivedOperation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        DispatchRouteHistoryCommandAsync(conversation, true, receivedOperation, source, ct);

    private async Task<int> DispatchRouteHistoryCommandAsync(DeepIdV2Conversation conversation, bool response,
        ReadOnlyMemory<byte> receivedOperation, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(source);
        using var command = response
            ? await PrepareOwnRouteHistoryCommandAsync(conversation.Scope, true, receivedOperation, source, ct).ConfigureAwait(false)
            : await PrepareOwnRouteHistoryRequestForDispatchAsync(conversation.Scope, source, ct).ConfigureAwait(false);
        if (command is null) return 0;
        using var native = await SendOwnedMessagingCoreAsync(conversation.Scope, command.OperationId,
            command.ExactDmc2, source, ct, routeControl: true).ConfigureAwait(false);
        _ = await DeliverOwnMessagingAsync(conversation.Scope, command.OperationId, source, ct).ConfigureAwait(false);
        return 1;
    }

    internal async Task<DirectTextOutboxEntry?> PrepareOwnRouteHistoryCommandAsync(Did2MessagingSessionScope scope, bool response,
        ReadOnlyMemory<byte> receivedOperation, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
        => await PrepareOwnRouteHistoryCommandCoreAsync(scope, response, receivedOperation, source, ct,
            immediateRequestDispatch: false).ConfigureAwait(false);

    internal Task<DirectTextOutboxEntry?> PrepareOwnRouteHistoryRequestForDispatchAsync(Did2MessagingSessionScope scope,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
        => PrepareOwnRouteHistoryCommandCoreAsync(scope, false, ReadOnlyMemory<byte>.Empty, source, ct,
            immediateRequestDispatch: true);

    private async Task<DirectTextOutboxEntry?> PrepareOwnRouteHistoryCommandCoreAsync(Did2MessagingSessionScope scope, bool response,
        ReadOnlyMemory<byte> receivedOperation, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct, bool immediateRequestDispatch)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        if (response || !receivedOperation.IsEmpty) ProtectedDph2PreClaimJournal.RequireIntent(receivedOperation.Span);
        var selected = receivedOperation.ToArray();
        try
        {
            var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            if (immediateRequestDispatch)
                return await owner.PrepareRouteHistoryRequestForDispatchAsync(TrustedUnixSeconds(), verifier, scope,
                    pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
            return await owner.PrepareRouteHistoryCommandAsync(TrustedUnixSeconds(), verifier, scope, response, selected,
                pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(selected); }
    }

    // Receive has already committed its exact original and released the owner
    // lease. Only count8 work enters here. The existing ordinary outbox owns
    // retry; normal route maintenance performs external Store separately.
    private async Task MaintainReceivedRouteHistoryAsync(Did2MessagingSessionScope scope,
        OwnedDid2MessagingPersistedEvent persisted, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        if (persisted.RouteProcessing[0] != 3) return;
        using var original = persisted.OwnAuthenticatedDmc2();
        var control = original.Use(bytes => ApplicationCoreCodec.DecodeDmc2(bytes).ParsedPayload as ContactRouteHistoryDmc2Payload) ??
            throw new CryptographicException("Staged history scheduling lost its actual count8 original.");
        if (control.Mode != DeepIdV2ContactRouteHistoryMode.HistoryRequest && !persisted.RouteHistoryCatchupRequired) return;
        var operation = Dpe2Codec.Decode(persisted.ExactEnvelope).OperationId.ToArray();
        try
        {
            if (control.Mode != DeepIdV2ContactRouteHistoryMode.HistoryRequest)
            {
                var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
                using var verifier = OpenVerifier();
                _ = await owner.ContinueRouteHistoryAsync(TrustedUnixSeconds(), verifier, scope,
                    pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
            }
            using var command = await PrepareOwnRouteHistoryCommandAsync(scope,
                control.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest, operation, source, ct).ConfigureAwait(false);
            if (command is null) return;
            using var native = await SendOwnedMessagingCoreAsync(scope, command.OperationId, command.ExactDmc2,
                source, ct, routeControl: true).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(operation); }
    }
}
