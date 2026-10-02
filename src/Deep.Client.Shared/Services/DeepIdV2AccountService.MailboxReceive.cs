using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services;

/// <summary>One completed bounded mailbox page. Processed envelopes include
/// idempotent replays and contact events, not only new user messages. These
/// counts expose no plaintext, selector, key or acknowledgement authority.</summary>
public sealed class DeepIdV2MailboxSynchronizationResult
{
    internal DeepIdV2MailboxSynchronizationResult(int processedEnvelopes, bool hasMore, int durableTombstones)
    { ProcessedEnvelopes = processedEnvelopes; HasMore = hasMore; DurableTombstones = durableTombstones; }
    public int ProcessedEnvelopes { get; }
    public bool HasMore { get; }
    public int DurableTombstones { get; }
}

public sealed partial class DeepIdV2AccountService
{
    internal const int OwnedMailboxMaximumMessagesWithoutPqInjection = 32;

    internal async Task<Did2MessagingSessionScope> ReceiveOwnMailboxInitialAsync(ReadOnlyMemory<byte> exactDph2,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        if (exactDph2.IsEmpty || exactDph2.Length > 65536) throw new InvalidDataException("Initial mailbox envelope exceeds its closed bound.");
        var exact = exactDph2.ToArray();
        try
        {
            var incoming = Dph2Codec.Decode(exact);
            var pair = await source.VerifyForIncomingInitialAsync(this, incoming, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            await owner.CommitIncomingMailboxInitialAsync(TrustedUnixSeconds(), verifier, incoming, pair, source, ct).ConfigureAwait(false);
            // Source commit can consume a one-time key and finish cold crypto/SQL
            // work. Refresh the independent peer outside the released lease;
            // never stretch that earlier nonce-bound proof into mutable import.
            pair = await source.VerifyForIncomingInitialAsync(this, incoming, ct).ConfigureAwait(false);
            return await EnsureOwnReceiverMessagingAsync(exact, pair.Peer, source, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(exact); }
    }
    /// <summary>Processes one owned mailbox page through current authenticated
    /// transport, durable receive/materialization and signed tombstone ACK.
    /// Missing authority fails closed; there is no implicit poll/retry loop.</summary>
    public Task<DeepIdV2MailboxSynchronizationResult> SynchronizeOwnMailboxAsync(DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        SynchronizeOwnMailboxAsync(source, new Did2MailboxGrantOnionTransport(source), new Did2OwnedMailboxOnionTransportFactory(), ct);

    // Actual connected business entry; callers supply no page, mailbox selector,
    // signer, endpoint proof, semantic success flag or ACK list.
    internal async Task<DeepIdV2MailboxSynchronizationResult> SynchronizeOwnMailboxAsync(DeepIdV2ContactPathAuthoritySource source,
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(grants); ArgumentNullException.ThrowIfNull(transport);
        source.RequireAccountOwner(this);
        var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        using var descriptor = await owner.RetrieveOwnMailboxAsync(TrustedUnixSeconds(), verifier, source, own, grants, transport, ct).ConfigureAwait(false);
        var page = descriptor.ReadPage();
        if (page.Items.Count == 0) return new(0, page.HasMore, 0);
        var scopes = new Dictionary<string, Did2MessagingSessionScope>(StringComparer.Ordinal);
        foreach (var item in page.Items)
        {
            Did2MessagingSessionScope scope;
            if (item.Envelope.Ciphertext.Span.StartsWith("DPH2"u8))
                scope = await ReceiveOwnMailboxInitialAsync(item.Envelope.Ciphertext, source, ct).ConfigureAwait(false);
            else
            {
                // Unknown/group input still has no semantic fallback or ACK.
                using var received = await ReceiveOwnMessagingEnvelopeAsync(item.Envelope.Ciphertext, source, ct).ConfigureAwait(false);
                var incoming = Dpe2Codec.Decode(item.Envelope.Ciphertext.Span);
                scope = await owner.FindIncomingMessagingScopeAsync(TrustedUnixSeconds(), verifier, incoming, ct).ConfigureAwait(false) ??
                    throw new InvalidOperationException("Captured message no longer has an initialized owned session; no ACK.");
            }
            var name = Convert.ToHexString(scope.Hash);
            scopes.TryAdd(name, scope);
        }
        // Receive/materialization can do cold native and SQL work for every
        // item. Fetch the ACK endpoint set only after the whole batch, so a
        // first item's proof is not needlessly aged by later receive commits.
        var endpoints = new List<Did2MailboxSemanticEndpoints>(scopes.Count);
        foreach (var scope in scopes.Values)
            endpoints.Add(new(scope, await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false)));
        own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        var acknowledged = await owner.AcknowledgeOwnMailboxAsync(TrustedUnixSeconds(), verifier, descriptor,
            endpoints, source, own, transport, ct).ConfigureAwait(false);
        return new(page.Items.Count, page.HasMore, acknowledged.DurableTombstones);
    }
}
