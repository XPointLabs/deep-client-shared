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

    internal async Task<string> GroupActionAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        string action, ReadOnlyMemory<byte> id, Did2MessagingSessionScope? scope, string? value,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness? peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        await ResumeGroupOrdinaryUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
        var self = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        if (own.Proof.CurrentCheckpoint!.Directory.Identity.ActiveDevices.Count != 1) throw new NotSupportedException("Connected group candidate requires one active local device.");
        using var root = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        if (action == "create")
        {
            if (root.State.Groups.Count >= 32) throw new IOException("Protected group capacity is exhausted.");
            var authored = await DeepIdV2GroupTransitions.CreateGenesisAsync(self, current.Verified.DeviceSecrets, value!, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var groupId = authored.Transition.Commit.Field(2).ToArray();
            var group = new ProtectedDid2GroupJournal.Group { Id = groupId };
            group.Packages.Add(authored.CanonicalPackageBytes.ToArray()); root.State.Groups.Add(group);
            await SaveGroupsUnderLeaseAsync(root, current, held, ct).ConfigureAwait(false);
            return Convert.ToHexStringLower(groupId);
        }
        if (scope is null || peer is null) throw new ArgumentException("Group network action requires an exact accepted session.");
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        using (var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false))
            await RequireGroupContactConsentUnderLeaseAsync(current, held, opened, own, peer, source, ct).ConfigureAwait(false);
        var other = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(peer, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        if (peer.CurrentCheckpoint!.Directory.Identity.ActiveDevices.Count != 1) throw new NotSupportedException("Connected group candidate requires one peer device.");
        var groupState = root.State.Find(id.Span);
        if (groupState.Fork) throw new CryptographicException("Group is permanently fork-latched.");
        if (groupState.Scope.Length != 0 && !groupState.Scope.AsSpan().SequenceEqual(scope.Exact))
            throw new CryptographicException("Group candidate belongs to another exact contact/session.");
        var head = await VerifyGroupHeadAsync(groupState, self, other, source, ct).ConfigureAwait(false);
        var records = new List<GroupRecord>(); GroupInvitationRecord? original = null; ReadOnlyMemory<byte> package = default;
        switch (action)
        {
            case "invite":
                if (groupState.Offer.Length != 0) return Convert.ToHexStringLower(id.Span); // exact retained batch; never remint an unknown offer
                if (groupState.Packages.Count != 1) throw new InvalidOperationException("Connected group candidate is already activated.");
                original = await DeepIdV2GroupTransitions.InviteAsync(head, self, current.Verified.DeviceSecrets, other, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                groupState.Scope = scope.Exact.ToArray(); groupState.Offer = original.CanonicalBytes.ToArray();
                groupState.InvitationProof = other.ExactLookupProof.ToArray();
                package = groupState.Packages[0]; records.AddRange(DeepIdV2GroupEvents.Chunk(head, package)); records.Add(original);
                break;
            case "accept":
                if (groupState.Acceptance.Length != 0) return Convert.ToHexStringLower(id.Span);
                if (groupState.Packages.Count != 1 || groupState.Offer.Length == 0) throw new InvalidOperationException("No pending group invitation.");
                original = (GroupInvitationRecord)GroupCodec.Decode("GIV1", groupState.Offer);
                var acceptance = await DeepIdV2GroupTransitions.AcceptAsync(head, original, other, self,
                    current.Verified.DeviceSecrets, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                groupState.Acceptance = acceptance.CanonicalBytes.ToArray(); records.Add(acceptance); break;
            case "advance":
                if (groupState.Packages.Count == 2) return Convert.ToHexStringLower(id.Span);
                if (groupState.Offer.Length == 0 || groupState.Acceptance.Length == 0) throw new InvalidOperationException("Group activation requires retained explicit consent.");
                original = (GroupInvitationRecord)GroupCodec.Decode("GIV1", groupState.Offer);
                var activated = await DeepIdV2GroupTransitions.ActivateAsync(head, (GroupCommitPackageRecord)GroupCodec.Decode("GCP1", groupState.Packages[0]),
                    original, (GroupInvitationAcceptanceRecord)GroupCodec.Decode("GIA1", groupState.Acceptance), self, current.Verified.DeviceSecrets,
                    other, groupState.InvitationProof, [self, other], source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                groupState.Packages.Add(activated.CanonicalPackageBytes.ToArray()); head = activated.Transition;
                package = activated.CanonicalPackageBytes; records.AddRange(DeepIdV2GroupEvents.Chunk(head, package)); break;
            case "send":
                if (groupState.Packages.Count != 2) throw new InvalidOperationException("Group membership is not activated.");
                var message = await DeepIdV2GroupEvents.TextAsync(head, self, other, current.Verified.DeviceSecrets,
                    RandomNumberGenerator.GetBytes(32), groupState.NextMessage, value!, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                groupState.NextMessage = checked(groupState.NextMessage + 1); records.Add(message); break;
            default: throw new NotSupportedException("Unsupported owned group action.");
        }
        // One protected batch before any encryption or network dispatch. Every
        // target receives a separately authenticated pairwise DMC2 envelope.
        using var ordinaryValue = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Ordinary registration is absent.");
        using var ordinary = ordinaryValue.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        if (ordinary.Pending is not null || ordinary.Entries.Count + records.Count > ProtectedDid2DirectTextJournal.MaximumEntries || root.State.Outbox.Count + records.Count > 512)
            throw new IOException("Complete group batch has no available ordinary capacity.");
        var sequence = ordinary.NextSequence(scope);
        foreach (var record in records)
        {
            var dmc = await DeepIdV2GroupEvents.AuthorAsync(record, head, self, other, current.Verified.DeviceSecrets,
                RandomNumberGenerator.GetBytes(32), scope.Conversation.ToArray(), sequence++, source.RendezvousTrustedTime,
                original, package, ct).ConfigureAwait(false);
            root.State.Outbox.Add(new() { Group = id.ToArray(), Operation = RandomNumberGenerator.GetBytes(32),
                Scope = scope.Exact.ToArray(), Event = dmc.CanonicalBytes.ToArray() });
        }
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        await SaveGroupsUnderLeaseAsync(root, current, held, ct).ConfigureAwait(false);
        await ResumeGroupOrdinaryUnderLeaseAsync(current, held, ct).ConfigureAwait(false);
        return Convert.ToHexStringLower(id.Span);
    }

    private static async Task<VerifiedGroupTransition> VerifyGroupHeadAsync(ProtectedDid2GroupJournal.Group group,
        VerifiedDeepIdV2GroupDirectory self, VerifiedDeepIdV2GroupDirectory other, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var genesis = (GroupCommitPackageRecord)GroupCodec.Decode("GCP1", group.Packages[0]);
        var commit = GroupCodec.Decode("DGC1", genesis.Field(4).Span[4..]);
        var owner = commit.Field(6).Span.SequenceEqual(self.AccountId.Span) ? self : other;
        var head = await DeepIdV2GroupTransitions.VerifyGenesisAsync(genesis, owner, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        if (group.Packages.Count == 2)
            head = await DeepIdV2GroupTransitions.VerifyActivationAsync(head, (GroupCommitPackageRecord)GroupCodec.Decode("GCP1", group.Packages[1]),
                [self, other], source.RendezvousTrustedTime, ct).ConfigureAwait(false);
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
