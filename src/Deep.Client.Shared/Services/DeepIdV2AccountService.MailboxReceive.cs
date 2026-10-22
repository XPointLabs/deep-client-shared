using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services;

/// <summary>One completed bounded mailbox page. Processed envelopes include
/// idempotent replays, contact events and control disposal, not only new user messages. These
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
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        await ReceiveOwnMailboxInitialCoreAsync(exactDph2, source, ct).ConfigureAwait(false) ??
        throw new InvalidOperationException("Terminal expired Initial has no live messaging scope.");

    private async Task<Did2MessagingSessionScope?> ReceiveOwnMailboxInitialCoreAsync(ReadOnlyMemory<byte> exactDph2,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        if (exactDph2.IsEmpty || exactDph2.Length > 65536) throw new InvalidDataException("Initial mailbox envelope exceeds its closed bound.");
        var exact = exactDph2.ToArray();
        try
        {
            var incoming = Dph2Codec.Decode(exact);
            using var verifier = OpenVerifier();
            // Historical native lookup precedes proof acquisition. A fresh
            // Initial does not need a redundant own network proof before the
            // ordinary independently verified endpoint pair below.
            using (var retained = await owner.FindReceiverSessionAsync(TrustedUnixSeconds(), verifier, incoming, ct).ConfigureAwait(false))
                if (retained?.IsExpiredDisposal == true)
                {
                    var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
                    if (!await owner.HasCommittedExpiredMailboxInitialAsync(TrustedUnixSeconds(), verifier, incoming, source, own, ct).ConfigureAwait(false))
                        throw new System.Security.Cryptography.CryptographicException("Native terminal Initial changed before current replay verification.");
                    return null; // Exact native terminal replay needs no live old peer.
                }
            var pair = await source.VerifyForIncomingInitialAsync(this, incoming, ct).ConfigureAwait(false);
            if (await owner.CommitIncomingMailboxInitialAsync(TrustedUnixSeconds(), verifier, incoming, pair, source, ct).ConfigureAwait(false))
                return null;
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
        SynchronizeOwnMailboxWithRecoveryAsync(source, new Did2MailboxGrantOnionTransport(source), new Did2OwnedMailboxOnionTransportFactory(), ct);

    // Actual connected business entry; callers supply no page, mailbox selector,
    // signer, endpoint proof, semantic success flag or ACK list.
    internal async Task<DeepIdV2MailboxSynchronizationResult> SynchronizeOwnMailboxAsync(DeepIdV2ContactPathAuthoritySource source,
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(grants); ArgumentNullException.ThrowIfNull(transport);
        source.RequireAccountOwner(this);
        // One independently acquired PUBLIC own endpoint for this page's
        // Retrieve and ordinary receive. Every borrow still rejoins actual
        // time/floors; no private loan or captured request is renewed. Initial,
        // Braid and the later independent ACK keep the parent source below.
        using var receiveReads = source.OpenIndependentCommandReadScope();
        var pageSource = receiveReads.Source;
        var own = await pageSource.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        using var descriptor = await owner.RetrieveOwnMailboxAsync(TrustedUnixSeconds(), verifier, pageSource, own, grants, transport, ct).ConfigureAwait(false);
        var page = descriptor.ReadPage();
        if (page.Items.Count == 0) return new(0, page.HasMore, 0);
        // Borrow immutable public endpoint capabilities only for ordinary DPE2
        // receive within this page. Initial/Braid and the later ACK keep their
        // independent parent source; no old loan or captured request is renewed.
        var scopes = new Dictionary<string, Did2MessagingSessionScope>(StringComparer.Ordinal);
        foreach (var item in page.Items)
        {
            Did2MessagingSessionScope? scope;
            if (item.Envelope.Ciphertext.Span.StartsWith("DPH2"u8))
                scope = await ReceiveOwnMailboxInitialCoreAsync(item.Envelope.Ciphertext, source, ct).ConfigureAwait(false);
            else if (item.Envelope.Ciphertext.Span.StartsWith("DBR2"u8))
                scope = await ReceiveOwnBraidMailboxEnvelopeAsync(item.Envelope.Ciphertext, source, ct).ConfigureAwait(false);
            else
            {
                // Unknown/group input still has no semantic fallback or ACK.
                var received = await ReceiveOwnMessagingEnvelopeWithScopeAsync(item.Envelope.Ciphertext, receiveReads.Source, ct).ConfigureAwait(false);
                using (received.Persisted) scope = received.Scope;
                // Do not reopen/redecrypt the same catalog just to rediscover
                // this key-free scope. Fresh ACK endpoint acquisition reads the
                // actual catalog; ACK then reconstructs every native handoff.
            }
            if (scope is null) continue; // ACK still reconstructs actual terminal custody, not this selection.
            var name = Convert.ToHexString(scope.Hash);
            scopes.TryAdd(name, scope);
        }
        // Receive/materialization can do cold native and SQL work for every
        // item. Fetch the ACK endpoint set only after the whole batch, so a
        // first item's proof is not needlessly aged by later receive commits.
        // Fresh phase-local public memo, never receive's or a working group's.
        // Semantic group verification inside ACK may borrow this same snapshot
        // after rejoining actual floors/time, instead of fetching another proof
        // and advancing the floor underneath the already captured endpoint set.
        for (var acquisition = 0; acquisition < 2; acquisition++)
        {
            using var ackReads = source.OpenIndependentCommandReadScope();
            var ackSource = ackReads.Source;
            // One independently verified own/network snapshot for the entire ACK
            // set. Never renew just one member of an already captured set.
            own = await ackSource.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            var endpoints = new List<Did2MailboxSemanticEndpoints>(scopes.Count);
            try
            {
                foreach (var scope in scopes.Values)
                    endpoints.Add(new(scope, await ackSource.VerifyForOwnMessagingAsync(this, scope, ct, own).ConfigureAwait(false)));
            }
            catch (MessagingEndpointSnapshotChangedException) when (acquisition == 0 && !ct.IsCancellationRequested)
            {
                // No ACK factory/signing/transport call has started. Discard the
                // ENTIRE uncaptured endpoint set and acquire fresh own + all peers.
                // Actual received page, ratchets and original ACK custody stay.
                continue;
            }
            var acknowledged = await owner.AcknowledgeOwnMailboxAsync(TrustedUnixSeconds(), verifier, descriptor,
                endpoints, ackSource, own, grants, transport, ct).ConfigureAwait(false);
            return new(page.Items.Count, page.HasMore, acknowledged.DurableTombstones);
        }
        throw new CryptographicException("A matching current ACK endpoint set is unavailable.");
    }
}
