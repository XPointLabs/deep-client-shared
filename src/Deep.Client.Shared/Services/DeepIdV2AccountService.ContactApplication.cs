using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    public async Task<IReadOnlyList<DeepIdV2PendingTextSnapshot>> ListPendingTextOperationsAsync(CancellationToken ct = default)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadPendingTextOperationsAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false);
    }

    public Task<IReadOnlyList<DeepIdV2ContactOperationSnapshot>> ListContactStartOperationsAsync(CancellationToken ct = default)
    {
        return ReadContactOperationsAsync(ct);
    }
    private async Task<IReadOnlyList<DeepIdV2ContactOperationSnapshot>> ReadContactOperationsAsync(CancellationToken ct)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadContactStartOperationsAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false);
    }

    public Task<DeepIdV2ContactStartResult> StartContactAsync(DeepPermanentIdV2 address,
        ReadOnlyMemory<byte> logicalIntent, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
        => StartContactAsync(address, logicalIntent, source, null, null,
            new Did2MailboxGrantOnionTransport(source), new Did2OwnedMailboxOnionTransportFactory(), ct);

    internal async Task<DeepIdV2ContactStartResult> StartContactAsync(DeepPermanentIdV2 address,
        ReadOnlyMemory<byte> logicalIntent, DeepIdV2ContactPathAuthoritySource source,
        IExactContactResolveOnionTransport? contactRead, IExactContactResolveOnionTransport? claimOnion,
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(address); ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(grants); ArgumentNullException.ThrowIfNull(transport);
        source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent.Span);
        var intent = logicalIntent.ToArray(); byte[] initial = [], hello = [];
        try
        {
            using (var verifier = OpenVerifier())
            {
                DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority? own = null;
                var existing = await owner.TryFindCompletedContactMessagingScopeAsync(TrustedUnixSeconds(), verifier, intent, address, ct).ConfigureAwait(false);
                if (existing is not null)
                {
                    own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
                    var retained = await owner.ReadRetainedInitialStoreAsync(TrustedUnixSeconds(), verifier, existing, intent,
                        address, own, source, ct).ConfigureAwait(false);
                    if (retained is not null) return new(new(existing), retained);
                }
                // The local projection selects work only, never authorizes a
                // stop. The actual owner reloads the root, proves lower-time
                // expiry and completes its native/pre-session transition.
                var pending = (await owner.ReadContactStartOperationsAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false))
                    .FirstOrDefault(value => value.LogicalIntent.Span.SequenceEqual(intent));
                if (pending is not null)
                {
                    if (!string.Equals(pending.PeerDid2Hash, Convert.ToHexString(address.ExactDid2Hash.Span), StringComparison.Ordinal))
                        throw new CryptographicException("The original contact intent names another recipient.");
                    own ??= await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
                    if (await owner.TryExpireInitialContactIntentAsync(TrustedUnixSeconds(), verifier, intent, own, source, ct).ConfigureAwait(false))
                        throw new DeepIdV2ContactRetryExpiredException();
                    if (existing is not null)
                    {
                        // A concurrently completed Store, or the stop owner's
                        // actual Store recovery, must still beat peer resolve.
                        var retained = await owner.ReadRetainedInitialStoreAsync(TrustedUnixSeconds(), verifier, existing, intent,
                            address, own, source, ct).ConfigureAwait(false);
                        if (retained is not null) return new(new(existing), retained);
                    }
                }
            }
            var contact = await ResolveOwnedPermanentContactAsync(address, source, contactRead, ct).ConfigureAwait(false);
            var resolved = contact.Contact;
            using var draft = await PrepareOwnedInitialContactDraftAsync(intent, contact, source, ct).ConfigureAwait(false);
            initial = draft.ExactInit.ToArray(); hello = draft.ExactHello.ToArray();
            using var completed = await CompletePreparedOwnInitialContactAsync(intent, contact, source, claimOnion, draft, ct).ConfigureAwait(false);
            using var senderVerifier = OpenVerifier();
            var scope = await owner.EnsureSenderMessagingAsync(TrustedUnixSeconds(), senderVerifier, intent, initial, hello,
                contact.Own, resolved.Authorization.Freshness, source, ct).ConfigureAwait(false);
            var stored = await DeliverOwnInitialContactAsync(intent, resolved, source, grants, transport, ct, contactRead).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return new(new(scope), stored);
        }
        finally { foreach (var bytes in new[] { intent, initial, hello }) CryptographicOperations.ZeroMemory(bytes); }
    }

    public async Task<IReadOnlyList<DeepIdV2ConversationSnapshot>> ListConversationsAsync(CancellationToken ct = default)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadLocalConversationsAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false);
    }

    public Task<ClientMailboxStoreResult> AcceptContactAsync(DeepIdV2Conversation conversation,
        ReadOnlyMemory<byte> logicalOperation, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
        => AcceptContactAsync(conversation, logicalOperation, source, new Did2MailboxGrantOnionTransport(source),
            new Did2OwnedMailboxOnionTransportFactory(), ct);

    internal async Task<ClientMailboxStoreResult> AcceptContactAsync(DeepIdV2Conversation conversation,
        ReadOnlyMemory<byte> logicalOperation, DeepIdV2ContactPathAuthoritySource source,
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(grants); ArgumentNullException.ThrowIfNull(transport);
        source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(logicalOperation.Span);
        var op = logicalOperation.ToArray(); byte[] retainedOp = [], exact = [];
        try
        {
            using var draft = await PrepareOwnContactAcceptAsync(conversation.Scope, op, source, ct).ConfigureAwait(false);
            retainedOp = draft.Operation.ToArray(); exact = draft.ExactDmc2.ToArray();
            using var sent = await SendOwnMessagingAsync(conversation.Scope, retainedOp, exact, source, ct).ConfigureAwait(false);
            return await DeliverOwnMessagingAsync(conversation.Scope, retainedOp, source, grants, transport, ct).ConfigureAwait(false);
        }
        finally { foreach (var bytes in new[] { op, retainedOp, exact }) CryptographicOperations.ZeroMemory(bytes); }
    }

    // Creation durably reserves a command before exposing its operation. Sending
    // that operation is a separate retry-only boundary, including after restart.
    public async Task<ReadOnlyMemory<byte>> QueueTextAsync(DeepIdV2Conversation conversation, string text,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        _ = ApplicationCoreCodec.CreateMessageCreatePayload(text);
        var state = await ReadOwnContactAcceptanceAsync(conversation.Scope, source, ct).ConfigureAwait(false);
        if (conversation.IsInitiator ? state != Did2ContactAcceptanceState.PeerAcceptanceRetained : state != Did2ContactAcceptanceState.LocalAcceptanceRetained)
            throw new InvalidOperationException("The contact has not retained the required explicit acceptance.");
        using var draft = await CreateOwnDirectTextAsync(conversation.Scope, text, source, ct).ConfigureAwait(false);
        return draft.OperationId.ToArray();
    }

    public Task<ClientMailboxStoreResult> RetryTextAsync(DeepIdV2Conversation conversation, ReadOnlyMemory<byte> logicalOperation,
        string text, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
        => RetryTextAsync(conversation, logicalOperation, text, source, new Did2MailboxGrantOnionTransport(source),
            new Did2OwnedMailboxOnionTransportFactory(), ct);

    internal async Task<ClientMailboxStoreResult> RetryTextAsync(DeepIdV2Conversation conversation, ReadOnlyMemory<byte> logicalOperation,
        string text, DeepIdV2ContactPathAuthoritySource source, IDid2MailboxGrantTransport grants,
        IDid2OwnedMailboxTransportFactory transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(grants); ArgumentNullException.ThrowIfNull(transport);
        source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(logicalOperation.Span);
        _ = ApplicationCoreCodec.CreateMessageCreatePayload(text);
        var op = logicalOperation.ToArray(); byte[] exact = [];
        try
        {
            var state = await ReadOwnContactAcceptanceAsync(conversation.Scope, source, ct).ConfigureAwait(false);
            if (conversation.IsInitiator ? state != Did2ContactAcceptanceState.PeerAcceptanceRetained : state != Did2ContactAcceptanceState.LocalAcceptanceRetained)
                throw new InvalidOperationException("The contact has not retained the required explicit acceptance.");
            var retained = await ReadRetainedPublicTextStoreAsync(conversation.Scope, op, text, source, ct).ConfigureAwait(false);
            if (retained is not null) return retained;
            using var draft = await PrepareOwnDirectTextAsync(conversation.Scope, op, text, source, ct).ConfigureAwait(false);
            exact = OwnedByteExports.TakeArray(draft.ExactDmc2);
            using var sent = await SendOwnMessagingAsync(conversation.Scope, op, exact, source, ct).ConfigureAwait(false);
            return await DeliverOwnMessagingAsync(conversation.Scope, op, source, grants, transport, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(op); CryptographicOperations.ZeroMemory(exact); }
    }

    public Task<IReadOnlyList<DirectMessageCreateSnapshot>> ListMessagesAsync(DeepIdV2Conversation conversation,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        return ListOwnMessagingMessagesAsync(conversation.Scope, ct);
    }
}
