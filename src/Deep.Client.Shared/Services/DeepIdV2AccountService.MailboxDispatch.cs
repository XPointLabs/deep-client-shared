using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    internal async Task RetireOwnCompletedContactMailboxSendAsync(Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> initialIntent, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        await owner.RetireOwnedCompletedContactMailboxSendAsync(TrustedUnixSeconds(), verifier, scope, operation, initialIntent,
            own, source, ct).ConfigureAwait(false);
    }

    internal Task<ClientMailboxStoreResult> DeliverOwnInitialContactAsync(ReadOnlyMemory<byte> intent,
        VerifiedDeepIdV2PermanentContactResolveClosure contact, DeepIdV2ContactPathAuthoritySource source,
        CancellationToken ct = default) => DeliverOwnInitialContactAsync(intent, contact, source,
            new Did2MailboxGrantOnionTransport(source), new Did2OwnedMailboxOnionTransportFactory(), ct);

    internal async Task<ClientMailboxStoreResult> DeliverOwnInitialContactAsync(ReadOnlyMemory<byte> intent,
        VerifiedDeepIdV2PermanentContactResolveClosure contact, DeepIdV2ContactPathAuthoritySource source,
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct = default,
        IExactContactResolveOnionTransport? contactRead = null)
    {
        ArgumentNullException.ThrowIfNull(contact); ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(grants); ArgumentNullException.ThrowIfNull(transport);
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span); source.RequireAccountOwner(this);
        var ownedIntent = intent.ToArray();
        try
        {
            using var verifier = OpenVerifier();
            var scope = await owner.FindOutgoingInitialMessagingScopeAsync(TrustedUnixSeconds(), verifier, ownedIntent, ct).ConfigureAwait(false);
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            var retained = await owner.ReadRetainedInitialStoreAsync(TrustedUnixSeconds(), verifier, scope, ownedIntent,
                contact.Candidate.Address, own, source, ct).ConfigureAwait(false);
            if (retained is not null) return retained;
            var refreshed = contactRead is null
                ? await ResolvePermanentContactAsync(contact.Candidate.Address, source, ct).ConfigureAwait(false)
                : await ResolvePermanentContactAsync(contact.Candidate.Address, source, contactRead, ct).ConfigureAwait(false);
            var fresh = await source.VerifyPermanentContactAsync(refreshed.Candidate, ct).ConfigureAwait(false);
            return await owner.DeliverInitialAsync(TrustedUnixSeconds(), verifier, scope, ownedIntent, source, fresh, grants, transport, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(ownedIntent); }
    }

    internal Task<ClientMailboxStoreResult> DeliverOwnMessagingAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        DeliverOwnMessagingAsync(scope, operation, source,
            new Did2MailboxGrantOnionTransport(source), new Did2OwnedMailboxOnionTransportFactory(), ct);

    // Connected runtime entry: callers supply no ciphertext, holder key or issuer policy.
    internal async Task<ClientMailboxStoreResult> DeliverOwnMessagingAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource source, IDid2MailboxGrantTransport grants,
        IDid2OwnedMailboxTransportFactory transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(transport);
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        source.RequireAccountOwner(this);
        var op = operation.ToArray();
        try
        {
            using var verifier = OpenVerifier();
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            var retained = await owner.ReadRetainedMessagingStoreAsync(TrustedUnixSeconds(), verifier, scope, op, own, source, ct).ConfigureAwait(false);
            if (retained is not null) return retained;
            // Reuse the independently verified owned endpoint; peer freshness
            // is fetched only for actual working dispatch, never historical Store.
            var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct, own).ConfigureAwait(false);
            return await owner.DeliverMessagingAsync(TrustedUnixSeconds(), verifier, scope, op,
                source, pair.Own, pair.Peer, grants, transport, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(op); }
    }
}
