using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // A projection of already authenticated custody, never admission to a new
    // send, receive, materialization or ACK. Readers cannot initialize sessions.
    private async Task<OwnedDid2MessagingStorage> OpenLocalHistoryUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            var owner = new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance);
            using var catalog = await owner.ReadAsync(ct).ConfigureAwait(false);
            var index = catalog.FindExact(scope);
            if (index < 0 || catalog.Phase(index) != 2)
                throw new CryptographicException("Local history requires an exact initialized owned session.");
            _ = await owner.ReadPeerCredentialAsync(scope, ct).ConfigureAwait(false);
            // Unmapped application projections/history retain FULL native
            // semantics. App authentication alone is not native payload custody.
            if (!nativeAdmissionInProgress)
                _ = await EnsureNativeArchiveAdmissionUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
            var opened = await SqliteDeepIdV2AccountGeneration.OpenOrdinaryMessagingUnderLeaseAsync(
                storage, sqlStatePath, current, scope, ct, configureRouteHistory: configured => ConfigureRouteHistoryDecisionRecovery(configured, held)).ConfigureAwait(false);
            try
            {
                await RequireLocalHistoryCatalogAsync(catalog.Exact, ct).ConfigureAwait(false);
                return opened;
            }
            catch { opened.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    internal async Task<IReadOnlyList<DeepIdV2ConversationSnapshot>> ReadLocalConversationsAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, CancellationToken ct,
        string? conversationId = null, IReadOnlySet<string>? peerAccounts = null)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage,
                networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            var result = new List<DeepIdV2ConversationSnapshot>(catalog.Count);
            for (var index = 0; index < catalog.Count; index++)
            {
                if (catalog.Phase(index) != 2) continue;
                var scope = catalog.Scope(index);
                // Select from the actual protected catalog, not caller-provided
                // handles or an application projection. Unrelated sessions do
                // not authorize this operation. All selected custody and the
                // catalog read-back below are still independently checked.
                if (conversationId is not null && !string.Equals(conversationId,
                        Convert.ToHexString(scope.Conversation), StringComparison.Ordinal) ||
                    peerAccounts is not null && !peerAccounts.Contains(Convert.ToHexString(scope.RemoteAccount))) continue;
                using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
                var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                if (floor.Status != 1)
                    throw new InvalidDataException("An inactive or latched session grants no local history.");
                using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                    storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
                result.Add(await ReadLocalConversationSnapshotUnderLeaseAsync(current, scope, opened, application, floor, ct).ConfigureAwait(false));
            }
            await RequireLocalHistoryCatalogAsync(catalog.Exact, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return result.AsReadOnly();
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    private async Task<DeepIdV2ConversationSnapshot> ReadLocalConversationSnapshotUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, OwnedDid2MessagingStorage opened,
        SqliteDeepMailboxStore application, Did2MessagingFloor floor, CancellationToken ct)
    {
        var responder = (scope.IsInitiator ? scope.RemoteAccount : scope.LocalAccount).ToArray();
        var device = (scope.IsInitiator ? scope.RemoteDevice : scope.LocalDevice).ToArray();
        var retained = await opened.WithSqlAsync(sql => sql.ReadVerifiedActiveInitialEvents(floor), ct).ConfigureAwait(false);
        byte[]? accepted = null;
        try
        {
            accepted = await application.ReadContactAcceptAsync(current.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope.Conversation.ToArray(),
                responder, device, ct).ConfigureAwait(false);
            if (accepted is not null)
            {
                if (scope.IsInitiator)
                {
                    using var received = await opened.WithSqlAsync(sql => sql.ReadVerifiedReceiveForEvent(floor, SHA256.HashData(accepted)), ct).ConfigureAwait(false) ??
                        throw new CryptographicException("Local projection lost actual peer acceptance custody.");
                    using var plain = received.OwnAuthenticatedDmc2();
                    if (!plain.Use(bytes => Did2MessagingSessionScope.Fixed(bytes, accepted)))
                        throw new CryptographicException("Local acceptance projection differs from authenticated receive custody.");
                }
                else
                {
                    using var marker = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                        throw new InvalidDataException("Local acceptance lost its protected explicit command.");
                    using var commands = marker.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes,
                        scope.Network, scope.LocalAccount, scope.Instance));
                    var winner = commands.FindScope(scope) ?? throw new CryptographicException("Local acceptance lost its protected winner.");
                    using var sent = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(floor, winner.Operation), ct).ConfigureAwait(false) ??
                        throw new CryptographicException("Local acceptance lost actual send custody.");
                    winner.RequireExactAccept(accepted);
                    if (sent.Direction != 1 ||
                        !Did2MessagingSessionScope.Fixed(sent.EventHash, SHA256.HashData(accepted)))
                        throw new CryptographicException("Local acceptance differs from its exact command/send custody.");
                }
                var parsed = ApplicationCoreCodec.DecodeDmc2(accepted);
                if (parsed.ParsedPayload is not ContactAcceptDmc2Payload payload ||
                    !Did2MessagingSessionScope.Fixed(parsed.NetworkId.Span, scope.Network) ||
                    !Did2MessagingSessionScope.Fixed(parsed.ConversationId.Span, scope.Conversation) ||
                    !Did2MessagingSessionScope.Fixed(parsed.SenderAccountId.Span, responder) ||
                    !Did2MessagingSessionScope.Fixed(parsed.SenderDeviceId.Span, device) ||
                    !Did2MessagingSessionScope.Fixed(payload.RelationshipId.Span, scope.Relationship) ||
                    !Did2MessagingSessionScope.Fixed(payload.ContactHelloHash.Span, SHA256.HashData(retained.Hello)))
                    throw new CryptographicException("Local acceptance differs from its authenticated conversation.");
            }
            var state = accepted is null
                ? scope.IsInitiator ? DeepIdV2ContactState.OutgoingRequest : DeepIdV2ContactState.IncomingRequest
                : scope.IsInitiator ? DeepIdV2ContactState.PeerAcceptanceRetained : DeepIdV2ContactState.LocalAcceptanceRetained;
            return new(new(scope), state);
        }
        finally
        {
            foreach (var bytes in new[] { responder, device, retained.SessionInit, retained.Hello })
                CryptographicOperations.ZeroMemory(bytes);
            if (accepted is not null) CryptographicOperations.ZeroMemory(accepted);
        }
    }

    private async Task RequireLocalHistoryCatalogAsync(ReadOnlyMemory<byte> exact, CancellationToken ct)
    {
        using var root = await storage.ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot, ct).ConfigureAwait(false) ??
            throw new CryptographicException("The local history catalog disappeared during projection.");
        if (!root.Use(bytes => Did2MessagingSessionScope.Fixed(bytes, exact.Span)))
            throw new CryptographicException("The local history catalog changed during projection.");
    }

    // Scheduling metadata only. A group batch for each returned handle still
    // independently opens/reconciles that exact session before using native
    // events; an empty batch grants no transport or acceptance authority.
    internal async Task<IReadOnlyList<DeepIdV2Conversation>> ReadLocalConversationHandlesAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage,
                networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            var result = new List<DeepIdV2Conversation>(catalog.Count);
            for (var index = 0; index < catalog.Count; index++)
                if (catalog.Phase(index) == 2) result.Add(new(catalog.Scope(index)));
            await RequireLocalHistoryCatalogAsync(catalog.Exact, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return result.AsReadOnly();
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }
}
