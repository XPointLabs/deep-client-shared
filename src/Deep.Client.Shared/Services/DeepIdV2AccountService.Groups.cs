using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed record DeepIdV2GroupSnapshot(string Group, string State, ulong Epoch, int LocalMessageCommands, string Name, int Members);
public sealed record DeepIdV2GroupMessageSnapshot(string Text, bool IsLocalAuthor, ulong Sequence);

public sealed partial class DeepIdV2AccountService
{
    public async Task<IReadOnlyList<DeepIdV2GroupSnapshot>> ListGroupsAsync(CancellationToken ct = default)
    { using var verifier = OpenVerifier(); return await owner.ListGroupsAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false); }

    public async Task<IReadOnlyList<DeepIdV2GroupMessageSnapshot>> ListGroupMessagesAsync(ReadOnlyMemory<byte> group, CancellationToken ct = default)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(group.Span); var selected = group.ToArray();
        try { ProtectedDph2PreClaimJournal.RequireIntent(selected); using var verifier = OpenVerifier(); return await owner.ListGroupMessagesAsync(TrustedUnixSeconds(), verifier, selected, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(selected); }
    }

    public async Task<string> CreateGroupAsync(string name, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        source.RequireAccountOwner(this); var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.GroupActionAsync(TrustedUnixSeconds(), verifier, "create", default, null, name, own, null, source, ct).ConfigureAwait(false);
    }

    public Task<int> InviteToGroupAsync(ReadOnlyMemory<byte> group, DeepIdV2Conversation conversation, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        GroupActionAndFlushAsync("invite", group, conversation, null, source, ct);
    public Task<int> AcceptGroupAsync(ReadOnlyMemory<byte> group, DeepIdV2Conversation conversation, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        GroupActionAndFlushAsync("accept", group, conversation, null, source, ct);
    public Task<int> AdvanceGroupAsync(ReadOnlyMemory<byte> group, DeepIdV2Conversation conversation, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        GroupActionAndFlushAsync("advance", group, conversation, null, source, ct);
    public Task<int> SendGroupTextAsync(ReadOnlyMemory<byte> group, DeepIdV2Conversation conversation, string text, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        GroupActionAndFlushAsync("send", group, conversation, text, source, ct);

    private async Task<int> GroupActionAndFlushAsync(string action, ReadOnlyMemory<byte> group, DeepIdV2Conversation conversation,
        string? text, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        ArgumentNullException.ThrowIfNull(conversation); source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(group.Span);
        var selected = group.ToArray();
        try
        {
            ProtectedDph2PreClaimJournal.RequireIntent(selected);
            if (action == "send") await PublishGroupControlAsync(selected, source, ct).ConfigureAwait(false);
            await RequireAttachmentConsentAsync(conversation, source, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            DeepIdV2Conversation[] candidates = [];
            IReadOnlyList<ProtectedDeepIdV2AccountOwner.GroupTarget>? targets = null;
            if (action is "advance" or "send")
            {
                var members = await owner.ReadGroupMemberSelectorsAsync(TrustedUnixSeconds(), verifier, selected, ct).ConfigureAwait(false);
                var accounts = members.Select(Convert.ToHexString).ToHashSet(StringComparer.Ordinal);
                if (action == "advance") accounts.Add(conversation.PeerAccountId);
                candidates = (await ReadGroupConversationsAsync(accounts, ct).ConfigureAwait(false))
                    .Select(item => item.Conversation).ToArray();
                // Consent reads independently mint current own/network authority.
                // Finish every such read before capturing a common endpoint set;
                // a later mint can otherwise advance the protected network floor
                // and correctly invalidate an earlier target's authority.
                foreach (var candidate in candidates.Where(item => item.ConversationId != conversation.ConversationId))
                    await RequireAttachmentConsentAsync(candidate, source, ct).ConfigureAwait(false);
            }
            var pair = await source.VerifyForOwnMessagingAsync(this, conversation.Scope, ct).ConfigureAwait(false);
            if (action is "advance" or "send")
            {
                var captured = new List<ProtectedDeepIdV2AccountOwner.GroupTarget>();
                foreach (var candidate in candidates)
                {
                    var authority = candidate.ConversationId == conversation.ConversationId ? pair :
                        await source.VerifyForOwnMessagingAsync(this, candidate.Scope, ct, pair.Own).ConfigureAwait(false);
                    captured.Add(new(candidate.Scope, authority.Own, authority.Peer));
                }
                targets = captured;
            }
            await owner.GroupActionAsync(TrustedUnixSeconds(), verifier, action, selected, conversation.Scope, text, pair.Own, pair.Peer, source, ct, targets).ConfigureAwait(false);
            if (action is "invite" or "advance") await PublishGroupControlAsync(selected, source, ct).ConfigureAwait(false);
            // Sending a new command is not a request to re-audit every old
            // Store. Drain actual unfinished work; explicit flush below keeps
            // the full original-batch historical verification contract.
            return await FlushGroupCoreAsync(selected, conversation, source, ct, pendingOnly: action == "send").ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(selected); }
    }

    /// <summary>Publishes original protected control chunks with actual two-replica evidence; unknown writes are never reminted.</summary>
    public async Task<int> PublishGroupControlAsync(ReadOnlyMemory<byte> group, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(group.Span);
        using var verifier = OpenVerifier(); var completed = 0;
        for (; completed < 512; completed++)
        {
            for (var acquisition = 0; acquisition < 2; acquisition++)
            {
                // Only a denied pre-control-effect acquisition can restart. The
                // owner has unwound/disposed its actual account lease before
                // this catch; captured GSW1 requests are neither renewed nor
                // reauthored. A retry MUST NOT borrow an outer command memo.
                using var retryReads = acquisition == 0 ? null : source.OpenIndependentCommandReadScope();
                var activeSource = retryReads?.Source ?? source;
                var fresh = await activeSource.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
                try
                {
                    if (!await owner.PublishOneGroupControlAsync(TrustedUnixSeconds(), verifier, group, fresh, activeSource, ct).ConfigureAwait(false)) return completed;
                    break;
                }
                catch (ProtectedDeepIdV2AccountOwner.GroupControlAuthorityRefreshRequiredException) when (acquisition == 0)
                {
                    // Discard only uncaptured scheduling state. Already issued
                    // loans retain their original authority and fail normally.
                    await source.DiscardUncapturedAuthorityAsync(ct).ConfigureAwait(false);
                }
            }
        }
        throw new IOException("Control publication exceeded its bounded stream work budget.");
    }

    /// <summary>Recovers verified group control independently of ordinary mailbox retention.</summary>
    public async Task<int> SyncGroupControlAsync(ReadOnlyMemory<byte> group, DeepIdV2Conversation ownerConversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(group.Span);
        await RequireAttachmentConsentAsync(ownerConversation, source, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier(); var completed = 0;
        for (var page = 0; page < 512; page++)
        {
            var pair = await source.VerifyForOwnMessagingAsync(this, ownerConversation.Scope, ct).ConfigureAwait(false);
            var result = await owner.SyncGroupControlAsync(TrustedUnixSeconds(), verifier, group, ownerConversation.Scope, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
            completed = checked(completed + result.Applied); if (!result.More) return completed;
        }
        throw new IOException("Control catch-up exceeded its bounded pagination budget.");
    }

    public Task<int> FlushGroupAsync(ReadOnlyMemory<byte> group, DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        FlushGroupCoreAsync(group, conversation, source, ct, pendingOnly: false);

    private async Task<int> FlushGroupCoreAsync(ReadOnlyMemory<byte> group, DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct, bool pendingOnly)
    {
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        ArgumentNullException.ThrowIfNull(conversation); source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(group.Span);
        var selected = group.ToArray();
        try
        {
            using var verifier = OpenVerifier();
            var conversations = await owner.ReadLocalConversationHandlesAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false);
            if (!conversations.Any(target => target.Scope.Exact.SequenceEqual(conversation.Scope.Exact)))
                throw new ArgumentException("Group flush requires this account\'s actual retained conversation.", nameof(conversation));
            // Preserve order within a session. Distinct sessions drain concurrently;
            // each child still uses the existing native/Store authority fences.
            using var concurrency = new SemaphoreSlim(4);
            // Current transport loans hold the actual account lock. Queue
            // account operations before minting a loan, rather than making
            // sibling targets exhaust the bounded file-lock wait.
            using var accountOperations = new SemaphoreSlim(1);
            var tasks = conversations.Select(async target =>
            {
                await concurrency.WaitAsync(ct).ConfigureAwait(false);
                try { return await FlushGroupTargetAsync(selected, target, source, accountOperations, pendingOnly, ct).ConfigureAwait(false); }
                finally { concurrency.Release(); }
            }).ToArray();
            return (await Task.WhenAll(tasks).ConfigureAwait(false)).Sum();
        }
        finally { CryptographicOperations.ZeroMemory(selected); }
    }

    private async Task<int> FlushGroupTargetAsync(ReadOnlyMemory<byte> selected, DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, SemaphoreSlim accountOperations, bool pendingOnly, CancellationToken ct)
    {
        IReadOnlyList<ProtectedDid2GroupJournal.Outgoing> batch = [];
        IReadOnlySet<string> retained = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            using var verifier = OpenVerifier();
            await accountOperations.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                batch = await owner.ReadGroupBatchAsync(TrustedUnixSeconds(), verifier, selected, conversation.Scope, ct, pendingOnly).ConfigureAwait(false);
                if (batch.Count == 0) return 0;
                await RequireAttachmentConsentAsync(conversation, source, ct).ConfigureAwait(false);
                var committed = batch.Where(item => item.NativeCommitted).ToArray();
                if (committed.Length != 0)
                {
                    var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
                    retained = await owner.ReadRetainedGroupStoresAsync(TrustedUnixSeconds(), verifier, conversation.Scope, committed, own, source, ct).ConfigureAwait(false);
                }
            }
            finally { accountOperations.Release(); }
            foreach (var item in batch)
            {
                await accountOperations.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    if (!retained.Contains(Convert.ToHexString(item.Operation)))
                    {
                        using var native = await SendOwnMessagingAsync(conversation.Scope, item.Operation, item.Event, source, ct).ConfigureAwait(false);
                        _ = await DeliverOwnMessagingAsync(conversation.Scope, item.Operation, source, ct).ConfigureAwait(false);
                    }
                }
                finally { accountOperations.Release(); }
            }
            return batch.Count;
        }
        finally { foreach (var item in batch) foreach (var bytes in new[] { item.Group, item.Operation, item.Scope, item.Event }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
