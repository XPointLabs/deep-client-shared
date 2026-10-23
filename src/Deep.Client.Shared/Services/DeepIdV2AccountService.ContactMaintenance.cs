using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Services;

/// <summary>Counts from one connection-maintenance cycle, not permission to send,
/// route availability, or proof that an offline peer has received an update.</summary>
/// <param name="AcceptedContacts">Retained mutually accepted relationships inspected.</param>
/// <param name="ControlsStored">Original or resumed route controls with verified Store.</param>
/// <param name="DeferredContacts">Peers whose retained advertisement is expired or faulted.</param>
/// <param name="ProcessedEnvelopes">Envelopes processed by the ordinary bounded mailbox page.</param>
/// <param name="DurableTombstones">Independently qualified transport ACKs.</param>
/// <param name="HasMore">Whether the ordinary mailbox page has further work.</param>
/// <param name="Reintroductions">Stored native re-introduction controls, not adopted peer routes.</param>
public sealed record DeepIdV2ContactMaintenanceResult(int AcceptedContacts, int ControlsStored,
    int DeferredContacts, int ProcessedEnvelopes, int DurableTombstones, bool HasMore, int Reintroductions = 0);

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Maximum caller-owned known address entries copied before one cycle.</summary>
    public const int MaximumKnownContactAddresses = 128;
    /// <summary>Renews the own publication through its existing proactive owner,
    /// receives one ordinary mailbox page, then advertises the adopted publication
    /// to every retained accepted contact. Expired/faulted peer routes are deferred,
    /// never admitted through historical evidence or replaced relationships.</summary>
    /// <param name="source">The account's independent connection authority source,
    /// not a captured group/receive/ACK context.</param>
    /// <param name="knownContacts">Optional existing address-book data keyed by conversation.
    /// It grants no authority: exact native peer/consent/current publication joins remain mandatory.</param>
    /// <param name="ct">Cancellation for the cycle; every transport retains its original shorter deadline.</param>
    /// <returns>Key-free diagnostic counts. A partial cycle grants no delivery authority.</returns>
    public async Task<DeepIdV2ContactMaintenanceResult> MaintainContactRoutesAsync(
        DeepIdV2ContactPathAuthoritySource source,
        IReadOnlyDictionary<string, DeepPermanentIdV2>? knownContacts = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        ct.ThrowIfCancellationRequested();
        var addresses = CopyKnownContactAddresses(knownContacts);
        // Once per cycle, not once per contact. The producer independently
        // authenticates all signed refresh windows and resumes exact pending work.
        _ = await EnsureOwnPermanentContactPublishedAsync(source, ct).ConfigureAwait(false);
        var page = await SynchronizeOwnMailboxAsync(source, ct).ConfigureAwait(false);
        var result = await AdvertisePublishedContactRoutesAsync(source, addresses, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        return result with { ProcessedEnvelopes = page.ProcessedEnvelopes,
            DurableTombstones = page.DurableTombstones, HasMore = page.HasMore };
    }

    private async Task<DeepIdV2ContactMaintenanceResult> AdvertisePublishedContactRoutesAsync(
        DeepIdV2ContactPathAuthoritySource source, IReadOnlyDictionary<string, DeepPermanentIdV2> addresses, CancellationToken ct)
    {
        var contacts = await ListConversationsAsync(ct).ConfigureAwait(false);
        return await MaintainAcceptedContactRoutesAsync(contacts,
            (conversation, token) => ReadContactRouteHealthAsync(conversation, source, token),
            (conversation, token) => RefreshPublishedContactRouteAsync(conversation, source, token), ct,
            async (conversation, token) => addresses.TryGetValue(conversation.ConversationId, out var address)
                ? await ReintroducePublishedContactRouteAsync(conversation, address, source, token).ConfigureAwait(false) : null).ConfigureAwait(false);
    }

    internal static IReadOnlyDictionary<string, DeepPermanentIdV2> CopyKnownContactAddresses(
        IReadOnlyDictionary<string, DeepPermanentIdV2>? addresses)
    {
        var copy = new Dictionary<string, DeepPermanentIdV2>(StringComparer.OrdinalIgnoreCase);
        if (addresses is null) return copy;
        if (addresses.Count > MaximumKnownContactAddresses) throw new ArgumentException("Known-contact metadata exceeds its bound.");
        foreach (var entry in addresses)
        {
            if (copy.Count >= MaximumKnownContactAddresses || entry.Key is null || entry.Key.Length != 64 ||
                entry.Key.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F')) ||
                entry.Value is null || !copy.TryAdd(entry.Key, entry.Value))
                throw new ArgumentException("Known-contact metadata has an invalid or duplicate selector.");
        }
        return copy; // Immutable descriptors, owned collection; never proof or dispatch authority.
    }

    // Scheduling only. Every actual refresh independently rejoins real native,
    // consent, account, route and currentness guards. No health Boolean becomes
    // a capability. The delegates isolate scheduling tests, not protocol evidence.
    internal static async Task<DeepIdV2ContactMaintenanceResult> MaintainAcceptedContactRoutesAsync(
        IReadOnlyList<DeepIdV2ConversationSnapshot> contacts,
        Func<DeepIdV2Conversation, CancellationToken, Task<DeepIdV2ContactRouteHealth>> health,
        Func<DeepIdV2Conversation, CancellationToken, Task<int>> refresh, CancellationToken ct,
        Func<DeepIdV2Conversation, CancellationToken, Task<int?>>? reintroduce = null)
    {
        ArgumentNullException.ThrowIfNull(contacts); ArgumentNullException.ThrowIfNull(health);
        ArgumentNullException.ThrowIfNull(refresh); ct.ThrowIfCancellationRequested();
        if (contacts.Any(item => item.ContactState is not (DeepIdV2ContactState.IncomingRequest or
            DeepIdV2ContactState.OutgoingRequest or DeepIdV2ContactState.LocalAcceptanceRetained or
            DeepIdV2ContactState.PeerAcceptanceRetained)) ||
            contacts.Select(item => Convert.ToHexString(item.Conversation.Scope.Hash)).Distinct(StringComparer.Ordinal).Count() != contacts.Count)
            throw new InvalidDataException("Contact maintenance requires unique current conversation metadata.");
        var accepted = 0; var stored = 0; var deferred = 0; var recovered = 0;
        foreach (var item in contacts)
        {
            ct.ThrowIfCancellationRequested();
            if (item.ContactState is DeepIdV2ContactState.IncomingRequest or DeepIdV2ContactState.OutgoingRequest) continue;
            accepted++;
            var current = await health(item.Conversation, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (current.RouteFaultRetained) { deferred++; continue; }
            if (!current.AdvertisementIntervalCoversNow)
            {
                // Sending our native control never promotes the peer's route.
                // It remains deferred until an ordinary receive adopts its reply.
                deferred++;
                if (reintroduce is not null)
                {
                    var recoveredCount = await reintroduce(item.Conversation, ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                    if (recoveredCount is not null and not (0 or 1)) throw new InvalidDataException("Re-introduction exceeded its one-control bound.");
                    stored += recoveredCount ?? 0; recovered += recoveredCount ?? 0;
                }
                continue;
            }
            // An accepted historical XUR need not still cover now. It is never
            // used as current permission: the real effect owner checks the route.
            var count = await refresh(item.Conversation, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (count is not (0 or 1)) throw new InvalidDataException("Route maintenance exceeded its one-control bound.");
            stored += count;
        }
        ct.ThrowIfCancellationRequested(); return new(accepted, stored, deferred, 0, 0, false, recovered);
    }
}
