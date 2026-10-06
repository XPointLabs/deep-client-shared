using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingV1;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    // Ordinary incoming consumer: no caller-selected session or acknowledgement
    // authority. Refresh only after the catalog lookup releases its lease.
    internal async Task<OwnedDid2MessagingPersistedEvent> ReceiveOwnMessagingEnvelopeAsync(
        ReadOnlyMemory<byte> exactDpe2, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        if (exactDpe2.IsEmpty || exactDpe2.Length > 65536)
            throw new InvalidDataException("Incoming DID2 envelope exceeds its closed bound.");
        var exact = exactDpe2.ToArray();
        try
        {
            var incoming = Dpe2Codec.Decode(exact);
            using var verifier = OpenVerifier();
            var scope = await owner.FindIncomingMessagingScopeAsync(TrustedUnixSeconds(), verifier, incoming, ct).ConfigureAwait(false) ??
                throw new InvalidOperationException("Incoming DID2 envelope has no initialized owned session; retain it without ACK.");
            var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
            return await owner.ReceiveMessagingAsync(TrustedUnixSeconds(), verifier, scope, exact,
                pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    internal async Task<ParsedDid2> ReadOwnMessagingPeerCredentialAsync(Did2MessagingSessionScope scope, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope);
        using var verifier = OpenVerifier();
        return await owner.ReadMessagingPeerCredentialAsync(TrustedUnixSeconds(), verifier, scope, ct).ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<DirectAttachmentOfferSnapshot>> ListOwnMessagingAttachmentOffersAsync(
        Did2MessagingSessionScope scope, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope);
        using var verifier = OpenVerifier();
        return await owner.ListMessagingAttachmentOffersAsync(TrustedUnixSeconds(), verifier, scope, ct).ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<DirectApplicationReceiptObligation>> ListOwnMessagingReceiptObligationsAsync(
        Did2MessagingSessionScope scope, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope);
        using var verifier = OpenVerifier();
        return await owner.ListMessagingReceiptObligationsAsync(TrustedUnixSeconds(), verifier, scope, ct).ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<DirectMessageCreateSnapshot>> ListOwnMessagingMessagesAsync(
        Did2MessagingSessionScope scope, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope);
        using var verifier = OpenVerifier();
        return await owner.ListMessagingMessagesAsync(TrustedUnixSeconds(), verifier, scope, ct).ConfigureAwait(false);
    }

    internal async Task<OwnedDid2MessagingPersistedEvent> SendOwnMessagingAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> exactDmc2,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source);
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        if (exactDmc2.IsEmpty || exactDmc2.Length > 33082) throw new InvalidDataException("DID2 send exceeds its closed bound.");
        var op = operation.ToArray(); var exact = exactDmc2.ToArray();
        ParsedDmc2? parsed = null;
        try
        {
            parsed = ApplicationCoreCodec.DecodeDmc2(exact);
            RequireOwnedSendKind(parsed.ContentKind);
            if (!Did2MessagingSessionScope.Fixed(parsed.NetworkId.Span, scope.Network) ||
                !Did2MessagingSessionScope.Fixed(parsed.SenderAccountId.Span, scope.LocalAccount) ||
                !Did2MessagingSessionScope.Fixed(parsed.SenderDeviceId.Span, scope.LocalDevice) ||
                AuthenticatedDirectDmc2.IsDirectKind(parsed.ContentKind) &&
                (parsed.SenderClientSequence < 3 || !Did2MessagingSessionScope.Fixed(parsed.ConversationId.Span, scope.Conversation)))
                throw new CryptographicException("DID2 send event has a different owned endpoint.");
            source.RequireAccountOwner(this);
            var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.SendMessagingAsync(TrustedUnixSeconds(), verifier, scope, op, exact, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
        }
        finally
        {
            if (parsed?.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose();
            CryptographicOperations.ZeroMemory(op); CryptographicOperations.ZeroMemory(exact);
        }
    }

    internal static void RequireOwnedSendKind(Dmc2ContentKind kind)
    {
        if (kind is not (Dmc2ContentKind.MessageCreate or Dmc2ContentKind.ContactAccept or Dmc2ContentKind.AttachmentOffer))
            throw new NotSupportedException("This DID2 event has no composed account-owned authoring custody.");
    }

    // Internal runtime composition only. Key-free scope does not grant MSG,
    // semantic materialization, route/dispatch or ACK authority.
    internal async Task<Did2MessagingSessionScope> EnsureOwnSenderMessagingAsync(
        ReadOnlyMemory<byte> intent, ReadOnlyMemory<byte> initial, ReadOnlyMemory<byte> hello,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(peer); ArgumentNullException.ThrowIfNull(source);
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span);
        if (initial.IsEmpty || hello.IsEmpty || initial.Length > 32768 || hello.Length > 32768)
            throw new InvalidDataException("Owned messaging initial events exceed their closed bounds.");
        var ownedIntent = intent.ToArray(); var ownedInitial = initial.ToArray(); var ownedHello = hello.ToArray();
        try
        {
            source.RequireAccountOwner(this);
            // Network acquisition/advancement is outside the account lease.
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.EnsureSenderMessagingAsync(TrustedUnixSeconds(), verifier, ownedIntent,
                ownedInitial, ownedHello, fresh, peer, source, ct).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ownedIntent);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(ownedInitial);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(ownedHello);
        }
    }

    internal async Task<Did2MessagingSessionScope> EnsureOwnReceiverMessagingAsync(
        ReadOnlyMemory<byte> exactDph2, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(peer); ArgumentNullException.ThrowIfNull(source);
        if (exactDph2.IsEmpty || exactDph2.Length > 65536)
            throw new InvalidDataException("Owned messaging initiation exceeds its closed bound.");
        var owned = exactDph2.ToArray();
        try
        {
            source.RequireAccountOwner(this);
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.EnsureReceiverMessagingAsync(TrustedUnixSeconds(), verifier, owned,
                fresh, peer, source, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(owned); }
    }
}
