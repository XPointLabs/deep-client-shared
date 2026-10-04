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
            var resolved = contactRead is null ? await ResolvePermanentContactAsync(address, source, ct).ConfigureAwait(false) :
                await ResolvePermanentContactAsync(address, source, contactRead, ct).ConfigureAwait(false);
            using var draft = await PrepareOwnInitialContactDraftAsync(intent, resolved, source, ct).ConfigureAwait(false);
            initial = draft.ExactInit.ToArray(); hello = draft.ExactHello.ToArray();
            using var completed = await CompleteOwnInitialContactAsync(intent, resolved, source, claimOnion, ct).ConfigureAwait(false);
            var refreshed = await source.VerifyPermanentContactAsync(resolved.Candidate, ct).ConfigureAwait(false);
            var scope = await EnsureOwnSenderMessagingAsync(intent, initial, hello, refreshed.Contact.Authorization.Freshness, source, ct).ConfigureAwait(false);
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

    public Task<ClientMailboxStoreResult> SendTextAsync(DeepIdV2Conversation conversation, ReadOnlyMemory<byte> logicalOperation,
        string text, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
        => SendTextAsync(conversation, logicalOperation, text, source, new Did2MailboxGrantOnionTransport(source),
            new Did2OwnedMailboxOnionTransportFactory(), ct);

    internal async Task<ClientMailboxStoreResult> SendTextAsync(DeepIdV2Conversation conversation, ReadOnlyMemory<byte> logicalOperation,
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
            using var draft = await PrepareOwnDirectTextAsync(conversation.Scope, op, text, source, ct).ConfigureAwait(false);
            exact = draft.ExactDmc2.ToArray();
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
