using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
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
            var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.DeliverMessagingAsync(TrustedUnixSeconds(), verifier, scope, op,
                source, pair.Own, pair.Peer, grants, transport, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(op); }
    }
}
