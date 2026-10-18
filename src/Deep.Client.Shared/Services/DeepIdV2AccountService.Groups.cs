using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed record DeepIdV2GroupSnapshot(string Group, string State, ulong Epoch, int LocalMessageCommands, string Name);
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
        ArgumentNullException.ThrowIfNull(conversation); source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(group.Span);
        var selected = group.ToArray();
        try
        {
            ProtectedDph2PreClaimJournal.RequireIntent(selected);
            await RequireAttachmentConsentAsync(conversation, source, ct).ConfigureAwait(false);
            var pair = await source.VerifyForOwnMessagingAsync(this, conversation.Scope, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            await owner.GroupActionAsync(TrustedUnixSeconds(), verifier, action, selected, conversation.Scope, text, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
            return await FlushGroupAsync(selected, conversation, source, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(selected); }
    }

    public async Task<int> FlushGroupAsync(ReadOnlyMemory<byte> group, DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(group.Span);
        var selected = group.ToArray(); IReadOnlyList<ProtectedDid2GroupJournal.Outgoing> batch = [];
        try
        {
            ProtectedDph2PreClaimJournal.RequireIntent(selected);
            await RequireAttachmentConsentAsync(conversation, source, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            batch = await owner.ReadGroupBatchAsync(TrustedUnixSeconds(), verifier, selected, conversation.Scope, ct).ConfigureAwait(false);
            var completed = 0;
            foreach (var item in batch)
            {
                ClientMailboxStoreResult? retained = null;
                if (item.NativeCommitted)
                {
                    var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
                    retained = await owner.ReadRetainedMessagingStoreAsync(TrustedUnixSeconds(), verifier, conversation.Scope, item.Operation, own, source, ct).ConfigureAwait(false);
                }
                if (retained is null)
                {
                    using var native = await SendOwnMessagingAsync(conversation.Scope, item.Operation, item.Event, source, ct).ConfigureAwait(false);
                    _ = await DeliverOwnMessagingAsync(conversation.Scope, item.Operation, source, ct).ConfigureAwait(false);
                }
                completed++;
            }
            return completed;
        }
        finally { CryptographicOperations.ZeroMemory(selected); foreach (var item in batch) foreach (var bytes in new[] { item.Group, item.Operation, item.Scope, item.Event }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
