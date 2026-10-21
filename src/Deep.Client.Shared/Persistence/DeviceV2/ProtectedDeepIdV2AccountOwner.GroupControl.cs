using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Only this producer's PRE-CONTROL-EFFECT head acquisition can request a
    // fresh outer iteration. It never represents an unknown captured GSW1.
    internal sealed class GroupControlAuthorityRefreshRequiredException(Exception inner)
        : CryptographicException("Group control requires a fresh pre-effect directory acquisition.", inner);

    private static void RequireGroupControlComplete(ProtectedDid2GroupJournal.Group group,
        VerifiedGroupTransition head, ReadOnlySpan<byte> self, VerifiedOnionNetworkContext network)
    {
        if (!head.Commit.Field(6).Span.SequenceEqual(self))
        {
            var selfId = self.ToArray();
            if (!group.Controls.Any(item => item.Recipient.AsSpan().SequenceEqual(selfId) && item.Cursor != 0))
                throw new CryptographicException("Application send requires authenticated control catch-up.");
            return;
        }
        foreach (var member in GroupMemberSelectors(head.Commit))
        {
            var control = group.Controls.SingleOrDefault(item => item.Recipient.AsSpan().SequenceEqual(member)) ??
                throw new CryptographicException("Group publication lost a current recipient.");
            foreach (var package in group.Packages)
            {
                var hash = GroupCodec.RecordHash("GCP1", package);
                var expected = checked((package.Length + 24575) / 24576);
                var writes = control.Writes.Where(write => GroupCodec.Decode("GCF1", write.Chunk).Field(1).Span.SequenceEqual(hash)).ToArray();
                if (writes.Length != expected || writes.Any(write => write.Receipt.Length == 0))
                    throw new CryptographicException("Group publication has incomplete recipient control evidence.");
                foreach (var write in writes)
                    _ = GroupControlProductionClient.VerifyRetainedWriteResult(network, (GroupControlWriteRecord)GroupCodec.Decode("GSW1", write.Request), write.Receipt);
            }
        }
    }

    private static async Task<ProtectedDid2GroupJournal.Control> NewGroupControlAsync(VerifiedGroupTransition head,
        VerifiedDeepIdV2GroupDirectory self, VerifiedDeepIdV2CurrentAccount current,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, ReadOnlyMemory<byte> recipient,
        ReadOnlyMemory<byte> scope, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var scalar = GroupControlCipher.GeneratePrivateKey();
        try
        {
            var descriptor = await GroupControlProductionClient.AuthorRendezvousAsync(head, self, current.Verified.DeviceSecrets,
                own.Network, GroupControlCipher.PublicKey(scalar), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            return new() { Recipient = recipient.ToArray(), Scope = scope.ToArray(), Descriptor = descriptor.CanonicalBytes.ToArray(), Key = scalar };
        }
        catch { CryptographicOperations.ZeroMemory(scalar); throw; }
    }

    // One original write per actual held loan. A new caller iteration refreshes
    // network authority before acquiring the account lease; no nested fetch gate.
    internal async Task<bool> PublishOneGroupControlAsync(ulong seconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> groupId,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
        using var root = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        var group = root.State.Find(groupId.Span); if (group.Fork) throw new CryptographicException("Forked group has no control publication authority.");
        var self = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        VerifiedGroupTransition head;
        try { head = await VerifyGroupHeadAsync(group, self, self, own, held, source, ct).ConfigureAwait(false); }
        catch (DeepIdV2GroupDirectoryViewAdvancedException changed)
        { throw new GroupControlAuthorityRefreshRequiredException(changed); }
        if (!head.Commit.Field(6).Span.SequenceEqual(current.AccountId.Span)) return false;
        var required = GroupMemberSelectors(head.Commit);
        if (required.Any(id => !group.Controls.Any(control => control.Recipient.AsSpan().SequenceEqual(id))))
            throw new CryptographicException("The complete group control recipient set is absent.");
        ProtectedDid2GroupJournal.Control? selected = null; ProtectedDid2GroupJournal.ControlWrite? pending = null;
        // Public verified package work is shared only inside this actual held
        // pre-dispatch phase. Never retain it across callbacks or owner loans.
        var phaseChunks = new Dictionary<int, IReadOnlyList<GroupCommitChunkRecord>>();
        foreach (var control in group.Controls)
        {
            var descriptor = (GroupControlRendezvousRecord)GroupCodec.Decode("GSR1", control.Descriptor);
            await GroupControlProductionClient.RequireRendezvousAsync(descriptor, head, self, own.Network, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            foreach (var write in control.Writes.Where(write => write.Receipt.Length != 0))
                _ = GroupControlProductionClient.VerifyRetainedWriteResult(own.Network,
                    (GroupControlWriteRecord)GroupCodec.Decode("GSW1", write.Request), write.Receipt);
            for (var epoch = 0; epoch < group.Packages.Count; epoch++)
            {
                if (!phaseChunks.TryGetValue(epoch, out var chunks))
                {
                    var prior = epoch == group.Packages.Count - 1 ? head :
                        await VerifyGroupHeadAsync(group, self, self, own, held, source, ct, epoch).ConfigureAwait(false);
                    chunks = DeepIdV2GroupEvents.Chunk(prior, group.Packages[epoch]); phaseChunks.Add(epoch, chunks);
                }
                foreach (var chunk in chunks)
                    if (!control.Writes.Any(write => write.Chunk.AsSpan().SequenceEqual(chunk.CanonicalBytes.Span)))
                    {
                        if (control.Writes.Count >= 512) throw new IOException("Protected control stream capacity exhausted.");
                        control.Writes.Add(new() { Chunk = chunk.CanonicalBytes.ToArray() });
                    }
            }
            if (selected is null && control.Writes.FirstOrDefault(write => write.Receipt.Length == 0) is { } next)
            { selected = control; pending = next; }
        }
        if (pending is null) { held.RequireActive(); return false; }
        var rendezvous = (GroupControlRendezvousRecord)GroupCodec.Decode("GSR1", selected!.Descriptor);
        var placement = GroupControlPlacementVerifier.Create(own.Network, GroupControlProductionClient.Selector(rendezvous), rendezvous.Field(6));
        if (pending.Request.Length == 0)
        {
            var index = selected.Writes.IndexOf(pending); var sequence = checked((ulong)index + 1);
            var previous = index == 0 ? new byte[32] : GroupCodec.Decode("GSW1", selected.Writes[index - 1].Request).Field(20).ToArray();
            var issued = GroupControlProductionClient.RequestIssued(placement, checked(own.Proof.TrustedLowerUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample));
            var expiry = BinaryPrimitives.ReadUInt64BigEndian(rendezvous.Field(13).Span);
            var sealedBytes = GroupControlCipher.Seal(rendezvous, sequence, previous, expiry,
                (GroupCommitChunkRecord)GroupCodec.Decode("GCF1", pending.Chunk));
            try
            {
                pending.Request = GroupControlProductionClient.AuthorWrite(placement, rendezvous, RandomNumberGenerator.GetBytes(32), issued,
                    GroupControlProductionClient.RequestExpiry(placement, issued), sequence, previous, sealedBytes, expiry).CanonicalBytes.ToArray();
            }
            finally { CryptographicOperations.ZeroMemory(sealedBytes); }
        }
        await SaveGroupsUnderLeaseAsync(root, current, held, ct).ConfigureAwait(false);
        var request = (GroupControlWriteRecord)GroupCodec.Decode("GSW1", pending.Request);
        var upper = checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample);
        if (BinaryPrimitives.ReadUInt64BigEndian(request.Field(6).Span) <= upper || !request.Field(4).Span.SequenceEqual(placement.PlacementHash.Span))
            throw new ClientMailboxDispatchOutcomeUnknownException("Retained control attempt expired or changed placement; no reencryption or semantic remint is permitted.");
        async Task Guard(CancellationToken token)
        {
            await RecheckRouteFreshnessAsync(current, source, own, held, first, token).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2GroupJournal.Slot, root.Exact, token).ConfigureAwait(false);
            held.RequireActive(); token.ThrowIfCancellationRequested();
        }
        var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease, sqlStatePath, current, source.AccountOwner, held, ct).ConfigureAwait(false);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var reply = await Did2GroupControlOnionTransport.ExchangeAsync(source, custody, placement, request, Guard, deadline.Token).ConfigureAwait(false);
        var status = (GroupControlResultStatus)BinaryPrimitives.ReadUInt16BigEndian(reply.Field(4).Span);
        if (status is not (GroupControlResultStatus.Committed or GroupControlResultStatus.ExactReplay))
        {
            var error = new ClientMailboxDispatchOutcomeUnknownException("Control write has no authenticated two-replica durable result.");
            error.Data["Deep.GroupControl.Status"] = status.ToString(); throw error;
        }
        await Guard(ct).ConfigureAwait(false);
        pending.Receipt = reply.CanonicalBytes.ToArray(); await SaveGroupsUnderLeaseAsync(root, current, held, ct).ConfigureAwait(false); return true;
    }

    internal async Task<(int Applied, bool More)> SyncGroupControlAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        ReadOnlyMemory<byte> groupId, Did2MessagingSessionScope scope,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        using var root = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        var group = root.State.Find(groupId.Span); if (group.Fork) throw new CryptographicException("Forked group has no control sync authority.");
        var control = group.Controls.SingleOrDefault(item => item.Recipient.AsSpan().SequenceEqual(current.AccountId.Span) && item.Scope.AsSpan().SequenceEqual(scope.Exact)) ??
            throw new CryptographicException("This group has no authenticated recipient control descriptor/key.");
        var self = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        var other = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(peer, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        var head = await VerifyGroupHeadAsync(group, self, other, own, held, source, ct).ConfigureAwait(false);
        var descriptor = (GroupControlRendezvousRecord)GroupCodec.Decode("GSR1", control.Descriptor);
        await GroupControlProductionClient.RequireRendezvousAsync(descriptor, head, other, own.Network, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        var placement = GroupControlPlacementVerifier.Create(own.Network, GroupControlProductionClient.Selector(descriptor), descriptor.Field(6));
        var issued = GroupControlProductionClient.RequestIssued(placement, checked(own.Proof.TrustedLowerUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample));
        var request = GroupControlProductionClient.AuthorQuery(placement, descriptor, RandomNumberGenerator.GetBytes(32), issued,
            GroupControlProductionClient.RequestExpiry(placement, issued), control.Cursor);
        async Task Guard(CancellationToken token)
        {
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, token).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2GroupJournal.Slot, root.Exact, token).ConfigureAwait(false);
        }
        var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease, sqlStatePath, current, source.AccountOwner, held, ct).ConfigureAwait(false);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var reply = await Did2GroupControlOnionTransport.ExchangeAsync(source, custody, placement, request, Guard, deadline.Token).ConfigureAwait(false);
        var status = (GroupControlResultStatus)BinaryPrimitives.ReadUInt16BigEndian(reply.Field(4).Span);
        if (status == GroupControlResultStatus.NoEvents && control.Cursor != 0) return (0, false);
        if (status != GroupControlResultStatus.Events) throw new IOException("Control synchronization has a missing, expired or conflicting stream; not an empty success.");
        var raw = reply.Field(18).ToArray(); var at = 0; var count = BinaryPrimitives.ReadUInt16BigEndian(reply.Field(17).Span);
        for (var index = 0; index < count; index++)
        {
            var sequence = BinaryPrimitives.ReadUInt64BigEndian(raw.AsSpan(at)); var previous = raw.AsSpan(at + 8, 32).ToArray();
            var hash = raw.AsSpan(at + 40, 32).ToArray(); var expires = BinaryPrimitives.ReadUInt64BigEndian(raw.AsSpan(at + 72));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(at + 80)));
            if (sequence != checked(control.Cursor + 1) || !previous.AsSpan().SequenceEqual(control.CursorHash) || expires <= checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample))
                throw new CryptographicException("Control stream has a missing/expired predecessor.");
            var chunk = GroupControlCipher.Open(descriptor, control.Key, sequence, previous, expires, raw.AsSpan(at + 84, length));
            // Chunk adoption and cursor are in the same protected root CAS. A
            // crash can replay an exact chunk, never skip an unapplied one.
            await AdoptGroupChunkAsync(root, current, held, scope, chunk, self, other, own, source, ct, groupId).ConfigureAwait(false);
            control.Cursor = sequence; CryptographicOperations.ZeroMemory(control.CursorHash); control.CursorHash = hash;
            at = checked(at + 84 + length);
        }
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        await SaveGroupsUnderLeaseAsync(root, current, held, ct).ConfigureAwait(false);
        return (count, reply.Field(20).Span[0] == 1);
    }
}
