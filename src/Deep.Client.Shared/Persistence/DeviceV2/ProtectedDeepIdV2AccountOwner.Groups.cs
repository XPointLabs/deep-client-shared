using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private sealed class GroupRoot(byte[] exact, byte[] instance, ProtectedDid2GroupJournal.State state) : IDisposable
    {
        internal byte[] Exact = exact;
        internal readonly byte[] Instance = instance;
        internal readonly ProtectedDid2GroupJournal.State State = state;
        public void Dispose() { State.Dispose(); CryptographicOperations.ZeroMemory(Exact); CryptographicOperations.ZeroMemory(Instance); }
    }

    private async Task<GroupRoot> OpenGroupsUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current, CancellationToken ct)
    {
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[] exact = [];
        try
        {
            using var value = await storage.ReadOwnedAsync(ProtectedDid2GroupJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected group registration is absent; no regeneration is permitted.");
            exact = value.Use(bytes => bytes.ToArray());
            var state = ProtectedDid2GroupJournal.Decode(exact, networkId, current.AccountId.Span, instance);
            return new(exact, instance, state);
        }
        catch { CryptographicOperations.ZeroMemory(instance); CryptographicOperations.ZeroMemory(exact); throw; }
    }

    private async Task SaveGroupsUnderLeaseAsync(GroupRoot root, VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        root.State.Revision = checked(root.State.Revision + 1);
        var next = ProtectedDid2GroupJournal.Encode(root.State, networkId, current.AccountId.Span, root.Instance);
        try
        {
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            if (!await storage.CompareExchangeAsync(ProtectedDid2GroupJournal.Slot, root.Exact, next, ct).ConfigureAwait(false))
                throw new CryptographicException("Protected group custody changed under the account lease.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2GroupJournal.Slot, next, ct).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(root.Exact); root.Exact = next; next = [];
        }
        finally { CryptographicOperations.ZeroMemory(next); }
    }

    internal sealed record GroupTarget(Did2MessagingSessionScope Scope,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority Own, VerifiedDeepIdV2DirectoryFreshness Peer);

    internal async Task<string> GroupActionAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        string action, ReadOnlyMemory<byte> id, Did2MessagingSessionScope? scope, string? value,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness? peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct,
        IReadOnlyList<GroupTarget>? capturedTargets = null)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        await ResumeGroupOrdinaryUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
        var self = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        if (own.Proof.CurrentCheckpoint!.Directory.Identity.ActiveDevices.Count != 1) throw new NotSupportedException("Group device enrollment is not yet qualified.");
        using var root = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        if (action == "create")
        {
            if (root.State.Groups.Count >= 32) throw new IOException("Protected group capacity is exhausted.");
            var authored = await DeepIdV2GroupTransitions.CreateGenesisAsync(self, current.Verified.DeviceSecrets, value!, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var groupId = authored.Transition.Commit.Field(2).ToArray();
            var group = new ProtectedDid2GroupJournal.Group { Id = groupId };
            group.Packages.Add(authored.CanonicalPackageBytes.ToArray()); root.State.Groups.Add(group);
            group.Controls.Add(await NewGroupControlAsync(authored.Transition, self, current, own, current.AccountId, default, source, ct).ConfigureAwait(false));
            await SaveGroupsUnderLeaseAsync(root, current, held, ct).ConfigureAwait(false);
            return Convert.ToHexStringLower(groupId);
        }
        if (scope is null || peer is null) throw new ArgumentException("Group action requires an exact accepted session.");
        var targets = capturedTargets?.ToArray() ?? [new GroupTarget(scope, own, peer)];
        if (targets.Length is < 1 or > 99 || targets.Select(t => Convert.ToHexString(t.Scope.RemoteAccount)).Distinct(StringComparer.Ordinal).Count() != targets.Length)
            throw new CryptographicException("Group target set is empty, repeated or exceeds its bound.");
        var readings = new List<Deep.Protocol.DeepExtension.PrivacyRouting.OnionMonotonicReading>();
        var capabilities = new Dictionary<string, VerifiedDeepIdV2GroupDirectory>(StringComparer.Ordinal);
        foreach (var target in targets)
        {
            var first = await RequireMessagingFreshnessAsync(current, target.Own, target.Peer, source, held, ct).ConfigureAwait(false);
            OwnedInitialMessagingSeed.RequireFreshScope(target.Scope, target.Own.Proof, target.Peer, first);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, target.Scope, ct).ConfigureAwait(false);
            await RequireGroupContactConsentUnderLeaseAsync(current, held, opened, target.Own, target.Peer, source, ct).ConfigureAwait(false);
            if (target.Peer.CurrentCheckpoint!.Directory.Identity.ActiveDevices.Count != 1) throw new NotSupportedException("Group device enrollment is not yet qualified.");
            capabilities.Add(Convert.ToHexString(target.Scope.RemoteAccount), await DeepIdV2GroupDirectoryAuthority.VerifyAsync(target.Peer, source.RendezvousTrustedTime, ct).ConfigureAwait(false));
            readings.Add(first);
        }
        if (!capabilities.TryGetValue(Convert.ToHexString(scope.RemoteAccount), out var other)) throw new ArgumentException("The selected session is not a group target.");
        var groupState = root.State.Find(id.Span);
        if (groupState.Fork) throw new CryptographicException("Group is permanently fork-latched.");
        var head = await VerifyGroupHeadAsync(groupState, self, other, own, held, source, ct).ConfigureAwait(false);
        var invitationState = groupState.ForScope(scope.Exact);
        var records = new List<(GroupRecord Record, VerifiedGroupTransition Head, ReadOnlyMemory<byte> Package, GroupTarget Target)>();
        ProtectedDid2GroupJournal.Control? newControl = null;
        GroupInvitationRecord? original = invitationState is null ? null : (GroupInvitationRecord)GroupCodec.Decode("GIV1", invitationState.Offer);
        switch (action)
        {
            case "invite":
                if (invitationState is not null) return Convert.ToHexStringLower(id.Span);
                original = await DeepIdV2GroupTransitions.InviteAsync(head, self, current.Verified.DeviceSecrets, other, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                invitationState = new() { Scope = scope.Exact.ToArray(), Offer = original.CanonicalBytes.ToArray(), InvitationProof = other.ExactLookupProof.ToArray() };
                groupState.Invitations.Add(invitationState);
                newControl = await NewGroupControlAsync(head, self, current, own, other.AccountId, scope.Exact.ToArray(), source, ct).ConfigureAwait(false);
                groupState.Controls.Add(newControl);
                // A new member receives the entire exact lineage, not only its tip.
                for (var epoch = 0; epoch < groupState.Packages.Count; epoch++)
                {
                    var prior = await VerifyGroupHeadAsync(groupState, self, other, own, held, source, ct, epoch).ConfigureAwait(false);
                    foreach (var chunk in DeepIdV2GroupEvents.Chunk(prior, groupState.Packages[epoch])) records.Add((chunk, prior, groupState.Packages[epoch], targets.Single(t => t.Scope.Exact.SequenceEqual(scope.Exact))));
                }
                records.Add((original, head, default, targets.Single(t => t.Scope.Exact.SequenceEqual(scope.Exact)))); break;
            case "accept":
                if (invitationState is null) throw new InvalidOperationException("No pending group invitation.");
                if (invitationState.Acceptance.Length != 0) return Convert.ToHexStringLower(id.Span);
                var acceptance = await DeepIdV2GroupTransitions.AcceptAsync(head, original!, other, self, current.Verified.DeviceSecrets, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                invitationState.Acceptance = acceptance.CanonicalBytes.ToArray(); records.Add((acceptance, head, default, targets.Single(t => t.Scope.Exact.SequenceEqual(scope.Exact)))); break;
            case "advance":
                if (invitationState is null || invitationState.Acceptance.Length == 0) throw new InvalidOperationException("Group activation requires retained explicit consent.");
                var baseEpoch = checked((int)BinaryPrimitives.ReadUInt64BigEndian(original!.Field(4).Span));
                if (groupState.Packages.Count > baseEpoch + 1)
                {
                    RequireGroupLocalConsent((GroupCommitPackageRecord)GroupCodec.Decode("GCP1", groupState.Packages[baseEpoch + 1]), invitationState);
                    return Convert.ToHexStringLower(id.Span);
                }
                RequireCompleteGroupTargets(head, self, targets, scope.RemoteAccount);
                var all = new[] { self }.Concat(capabilities.Values).ToArray();
                var activated = await DeepIdV2GroupTransitions.ActivateAsync(head, (GroupCommitPackageRecord)GroupCodec.Decode("GCP1", groupState.Packages[^1]),
                    original, (GroupInvitationAcceptanceRecord)GroupCodec.Decode("GIA1", invitationState.Acceptance), self, current.Verified.DeviceSecrets,
                    other, invitationState.InvitationProof, all, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                groupState.Packages.Add(activated.CanonicalPackageBytes.ToArray()); head = activated.Transition;
                // Current commits travel through the independently retained GSR1
                // streams, not a short-lived ordinary-mailbox substitute.
                break;
            case "send":
                if (!GroupMemberSelectors(head.Commit).Any(account => account.AsSpan().SequenceEqual(self.AccountId.Span)))
                    throw new InvalidOperationException("Pending invitation is not group membership.");
                RequireCompleteGroupTargets(head, self, targets, default);
                RequireGroupControlComplete(groupState, head, current.AccountId.Span, own.Network);
                var message = await DeepIdV2GroupEvents.TextAsync(head, self, other, current.Verified.DeviceSecrets,
                    RandomNumberGenerator.GetBytes(32), groupState.NextMessage, value!, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                groupState.NextMessage = checked(groupState.NextMessage + 1);
                foreach (var target in targets) records.Add((message, head, default, target)); break;
            default: throw new NotSupportedException("Unsupported owned group action.");
        }
        using var ordinaryValue = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Ordinary registration is absent.");
        using var ordinary = ordinaryValue.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        var recordCount = checked(records.Count + (newControl is null ? 0 : 1));
        if (ordinary.Pending is not null || ordinary.Entries.Count + recordCount > ProtectedDid2DirectTextJournal.MaximumEntries || root.State.Outbox.Count + recordCount > 512)
            throw new IOException("Complete group batch has no available ordinary capacity.");
        var sequences = targets.ToDictionary(t => Convert.ToHexString(t.Scope.Exact), t => ordinary.NextSequence(t.Scope), StringComparer.Ordinal);
        foreach (var item in records)
        {
            var selectedScope = item.Target.Scope; var key = Convert.ToHexString(selectedScope.Exact);
            var dmc = await DeepIdV2GroupEvents.AuthorAsync(item.Record, item.Head, self, capabilities[Convert.ToHexString(selectedScope.RemoteAccount)], current.Verified.DeviceSecrets,
                RandomNumberGenerator.GetBytes(32), selectedScope.Conversation.ToArray(), sequences[key]++, source.RendezvousTrustedTime, original, item.Package, ct).ConfigureAwait(false);
            root.State.Outbox.Add(new() { Group = id.ToArray(), Operation = RandomNumberGenerator.GetBytes(32), Scope = selectedScope.Exact.ToArray(), Event = dmc.CanonicalBytes.ToArray() });
        }
        if (newControl is not null)
        {
            var key = Convert.ToHexString(scope.Exact);
            var carrier = await DeepIdV2GroupEvents.AuthorControlAsync((GroupControlRendezvousRecord)GroupCodec.Decode("GSR1", newControl.Descriptor),
                newControl.Key, head, self, other, current.Verified.DeviceSecrets, own.Network, RandomNumberGenerator.GetBytes(32),
                scope.Conversation.ToArray(), sequences[key]++, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            root.State.Outbox.Add(new() { Group = id.ToArray(), Operation = RandomNumberGenerator.GetBytes(32), Scope = scope.Exact.ToArray(), Event = carrier.CanonicalBytes.ToArray() });
        }
        for (var index = 0; index < targets.Length; index++)
            await RequireFinalMessagingFreshnessAsync(current, targets[index].Scope, targets[index].Own, targets[index].Peer, source, held, readings[index], ct).ConfigureAwait(false);
        await SaveGroupsUnderLeaseAsync(root, current, held, ct).ConfigureAwait(false);
        await ResumeGroupOrdinaryUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
        return Convert.ToHexStringLower(id.Span);
    }

    private static void RequireCompleteGroupTargets(VerifiedGroupTransition head, VerifiedDeepIdV2GroupDirectory self, GroupTarget[] targets, ReadOnlySpan<byte> added)
    {
        var members = GroupMemberSelectors(head.Commit).Where(id => !id.AsSpan().SequenceEqual(self.AccountId.Span)).Select(Convert.ToHexString).ToHashSet(StringComparer.Ordinal);
        if (!added.IsEmpty) members.Add(Convert.ToHexString(added));
        if (members.Count == 0 || !members.SetEquals(targets.Select(t => Convert.ToHexString(t.Scope.RemoteAccount)))) throw new CryptographicException("The complete exact group target set is required before preparation.");
    }

    // Selectors only. Current directory capabilities and Protocol independently
    // validate membership, device sets, signatures, support and every predecessor.
    private static IReadOnlyList<byte[]> GroupMemberSelectors(GroupRecord commit)
    {
        var remaining = commit.Field(12).Span; var result = new List<byte[]>();
        var count = BinaryPrimitives.ReadUInt16BigEndian(commit.Field(11).Span);
        for (var i = 0; i < count; i++)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(remaining); remaining = remaining[2..];
            // Canonical member header is219 bytes before deviceCount. Do not
            // adopt a multi-device third member through an unqualified path.
            if (length < 220 || remaining[219] != 1) throw new NotSupportedException("Group device enrollment is not yet qualified.");
            result.Add(remaining[..32].ToArray()); remaining = remaining[length..];
        }
        if (!remaining.IsEmpty) throw new InvalidDataException("Noncanonical group member selectors."); return result;
    }

    private static async Task<VerifiedDeepIdV2GroupDirectory[]> ReadGroupAuthoritiesAsync(GroupCommitPackageRecord package,
        VerifiedDeepIdV2GroupDirectory self, VerifiedDeepIdV2GroupDirectory other,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, HeldDeepIdV2AccountLease held, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct,
        Dictionary<string, VerifiedDeepIdV2GroupDirectory>? verifiedDirectories = null)
    {
        var commit = GroupCodec.Decode("DGC1", package.Field(4).Span[4..]);
        var candidates = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var packed = package.Field(8).ToArray(); var at = 0; var count = BinaryPrimitives.ReadUInt32BigEndian(package.Field(7).Span);
        for (var i = 0; i < count; i++)
        {
            var kind = BinaryPrimitives.ReadUInt16BigEndian(packed.AsSpan(at)); at += 40;
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(packed.AsSpan(at))); at += 4;
            if (kind == 3)
            {
                var adp = DeepIdV2Adp1Codec.Decode(packed.AsSpan(at, length));
                var account = DeepIdV2Codec.DecodeDab2(adp.ExactDab2.Span).DeepAccountId;
                candidates.TryAdd(Convert.ToHexString(account.Span), adp.ExactDid2.ToArray());
            }
            at = checked(at + length);
        }
        if (at != packed.Length) throw new InvalidDataException("Noncanonical group support selectors.");
        var result = new List<VerifiedDeepIdV2GroupDirectory>();
        foreach (var id in GroupMemberSelectors(commit))
        {
            if (id.AsSpan().SequenceEqual(self.AccountId.Span)) result.Add(self);
            else if (id.AsSpan().SequenceEqual(other.AccountId.Span)) result.Add(other);
            else if (verifiedDirectories is not null && verifiedDirectories.TryGetValue(Convert.ToHexString(id), out var retained)) result.Add(retained);
            else if (candidates.TryGetValue(Convert.ToHexString(id), out var did))
            {
                var verified = await source.VerifyGroupDirectoryAsync(did, id, own, held, ct).ConfigureAwait(false);
                result.Add(verified); verifiedDirectories?.Add(Convert.ToHexString(id), verified);
            }
            else throw new CryptographicException("Group member has no directory query candidate.");
        }
        return result.ToArray();
    }

    private static async Task<VerifiedGroupTransition> VerifyGroupHeadAsync(ProtectedDid2GroupJournal.Group group,
        VerifiedDeepIdV2GroupDirectory self, VerifiedDeepIdV2GroupDirectory other,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, HeldDeepIdV2AccountLease held, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct, int? throughEpoch = null)
    {
        var genesis = (GroupCommitPackageRecord)GroupCodec.Decode("GCP1", group.Packages[0]);
        var accounts = await ReadGroupAuthoritiesAsync(genesis, self, other, own, held, source, ct, group.VerifiedDirectories).ConfigureAwait(false);
        var head = await DeepIdV2GroupTransitions.VerifyGenesisAsync(genesis, accounts.Single(), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        for (var epoch = 1; epoch <= (throughEpoch ?? group.Packages.Count - 1); epoch++)
        {
            var package = (GroupCommitPackageRecord)GroupCodec.Decode("GCP1", group.Packages[epoch]);
            accounts = await ReadGroupAuthoritiesAsync(package, self, other, own, held, source, ct, group.VerifiedDirectories).ConfigureAwait(false);
            head = await DeepIdV2GroupTransitions.VerifyActivationAsync(head, package, accounts, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        }
        return head;
    }

    private async Task ResumeGroupOrdinaryUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var groups = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        var pending = groups.State.Outbox.Where(item => !item.Adopted).ToArray(); if (pending.Length == 0) return;
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        foreach (var item in pending)
        {
            var scope = Did2MessagingSessionScope.RestoreMetadata(item.Scope);
            using var value = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Ordinary custody is absent.");
            var before = value.Use(bytes => bytes.ToArray()); byte[] next = [];
            try
            {
                using var journal = ProtectedDid2DirectTextJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                var name = Convert.ToHexString(item.Operation);
                if (!journal.Entries.TryGetValue(name, out var entry))
                {
                    var parsed = ApplicationCoreCodec.DecodeDmc2(item.Event);
                    if (journal.Pending is not null || journal.NextSequence(scope) != parsed.SenderClientSequence)
                        throw new CryptographicException("Group reservation differs from the preserved ordinary counter.");
                    journal.RequireCapacity(scope); entry = ProtectedDid2DirectTextJournal.Entry.Prepare(scope, item.Operation, parsed);
                    try { journal.AddPending(entry); } catch { entry.Dispose(); throw; }
                    next = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
                    if (!await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, before, next, ct).ConfigureAwait(false)) throw new CryptographicException("Group ordinary preparation conflicted.");
                    await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, next, ct).ConfigureAwait(false);
                }
                entry.RequireEvent(item.Event);
                using var readback = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                    BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, item.Operation, ct).ConfigureAwait(false) ?? throw new CryptographicException("Group ordinary SQL readback is absent.");
                if (entry.Pending)
                {
                    journal.Stabilize(name); var stable = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
                    try
                    {
                        if (!await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, next.Length == 0 ? before : next, stable, ct).ConfigureAwait(false)) throw new CryptographicException("Group ordinary stabilization conflicted.");
                        await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, stable, ct).ConfigureAwait(false);
                    }
                    finally { CryptographicOperations.ZeroMemory(stable); }
                }
                item.Adopted = true;
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(next); }
        }
        await SaveGroupsUnderLeaseAsync(groups, current, held, ct).ConfigureAwait(false);
    }
}
