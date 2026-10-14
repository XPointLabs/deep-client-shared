using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    internal async Task<Did2MessagingSessionScope> ReceiveOwnBraidMailboxEnvelopeAsync(ReadOnlyMemory<byte> exactControl,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        if (exactControl.Length != Dbr2Codec.TotalBytes)
            throw new InvalidDataException("Mailbox Braid control exceeds its fixed frame bound.");
        var exact = exactControl.ToArray();
        try
        {
            var frame = Dbr2Codec.Decode(exact);
            using var verifier = OpenVerifier();
            var scope = await owner.FindIncomingBraidMessagingScopeAsync(TrustedUnixSeconds(), verifier, frame, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Mailbox Braid control has no owned session.");
            var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
            if (!await owner.TryResolveBraidMailboxCustodyAsync(TrustedUnixSeconds(), verifier, scope, exact,
                    pair.Own, pair.Peer, source, ct).ConfigureAwait(false))
            {
                using var received = await owner.ReceiveBraidControlAsync(TrustedUnixSeconds(), verifier, scope, exact,
                    pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
            }
            return scope; // Lookup/local custody only, never a caller-supplied ACK disposition.
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(exact); }
    }

    internal async Task<ClientMailboxStoreResult> DeliverOwnBraidControlAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, DeepIdV2ContactPathAuthoritySource source,
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(grants); ArgumentNullException.ThrowIfNull(transport);
        source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var op = operation.ToArray();
        try
        {
            using var verifier = OpenVerifier();
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            var retained = await owner.ReadRetainedBraidStoreAsync(TrustedUnixSeconds(), verifier, scope, op,
                own, source, ct).ConfigureAwait(false);
            if (retained is not null)
            {
                await owner.RetireOwnedCompletedBraidSendAsync(TrustedUnixSeconds(), verifier, scope, op, own, source, ct).ConfigureAwait(false);
                return retained;
            }
            var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct, own).ConfigureAwait(false);
            var stored = await owner.DeliverBraidControlAsync(TrustedUnixSeconds(), verifier, scope, op, source,
                pair.Own, pair.Peer, grants, transport, ct).ConfigureAwait(false);
            await owner.RetireOwnedCompletedBraidSendAsync(TrustedUnixSeconds(), verifier, scope, op, pair.Own, source, ct).ConfigureAwait(false);
            return stored;
        }
        finally { CryptographicOperations.ZeroMemory(op); }
    }

    // Internal connected source target; shipping/physical activation remains gated.
    internal async Task<OwnedDid2BraidControlPersistedEvent> SendOwnBraidControlAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.SendBraidControlAsync(TrustedUnixSeconds(), verifier, scope, operation,
            pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
    }
    internal async Task<OwnedDid2BraidControlPersistedEvent> ReceiveOwnBraidControlAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> exact, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.ReceiveBraidControlAsync(TrustedUnixSeconds(), verifier, scope, exact,
            pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
    }
}
