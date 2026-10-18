using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.GroupV1;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private static GroupRecord RequireGroupEnvelope(ParsedDmc2 parsed, Did2MessagingSessionScope scope, bool send)
    {
        if (parsed.ParsedPayload is not GroupDmc2Payload payload || !ProtectedDid2GroupJournal.IsKind(parsed.ContentKind) ||
            !parsed.NetworkId.Span.SequenceEqual(scope.Network) || !parsed.ConversationId.Span.SequenceEqual(scope.Conversation) ||
            !parsed.SenderAccountId.Span.SequenceEqual(send ? scope.LocalAccount : scope.RemoteAccount) ||
            !parsed.SenderDeviceId.Span.SequenceEqual(send ? scope.LocalDevice : scope.RemoteDevice) ||
            parsed.SenderClientSequence < 3 || parsed.Flags != Dmc2Flags.None || parsed.ReplyToLogicalMessageId.Length != 0 || parsed.ExpiresAtUnixMilliseconds == 0)
            throw new CryptographicException("Group DMC2 differs from its authenticated pairwise scope.");
        return payload.Record;
    }

    private async Task RequireGroupAdmissionUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope, ParsedDmc2 parsed, bool send,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var record = RequireGroupEnvelope(parsed, scope, send);
        await RequireGroupContactConsentUnderLeaseAsync(current, held, opened, own, peer, source, ct).ConfigureAwait(false);
        if (own.Proof.CurrentCheckpoint!.Directory.Identity.ActiveDevices.Count != 1 || peer.CurrentCheckpoint!.Directory.Identity.ActiveDevices.Count != 1)
            throw new NotSupportedException("Connected group candidate supports one device per account.");
        using var root = await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
        if (send)
        {
            if (!root.State.Outbox.Any(item => item.Scope.AsSpan().SequenceEqual(scope.Exact) && item.Event.AsSpan().SequenceEqual(parsed.CanonicalBytes.Span)))
                throw new CryptographicException("Group send has no exact protected batch custody.");
        }
        // A fragment has no group identifier until full package authentication.
        // It is bounded canonical authenticated control data, never membership.
        if (record is GroupCommitChunkRecord) return;
        if (record is GroupControlRendezvousRecord)
        {
            await RequireGroupControlCarrierAsync(root, current, held, scope, parsed, send, own, peer, source, false, ct).ConfigureAwait(false);
            return;
        }
        var group = root.State.Find(record.Field(2).Span);
        if (group.Fork) throw new CryptographicException("Group is permanently fork-latched.");
        var self = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        var other = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(peer, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        var invitationState = group.ForScope(scope.Exact);
        var invitation = invitationState is null ? null : (GroupInvitationRecord)GroupCodec.Decode("GIV1", invitationState.Offer);
        var head = await VerifyGroupHeadAsync(group, self, other, own, held, source, ct, GroupRecordEpoch(record, invitation)).ConfigureAwait(false);
        await DeepIdV2GroupEvents.RequireAsync(record, head, send ? self : other, send ? other : self,
            parsed.SenderDeviceId, source.RendezvousTrustedTime, invitation, ct).ConfigureAwait(false);
    }

    // Called only with the actual verified native row, including repeated ACK
    // fences. Selectors/SQL flags/caller-decoded records cannot stand in for it.
    private async Task MaterializeGroupNativeUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, Did2MessagingSessionScope scope, OwnedDid2MessagingPersistedEvent native,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct, GroupRoot? borrowedRoot = null)
    {
        using var ownedRoot = borrowedRoot is null ? await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false) : null;
        var root = borrowedRoot ?? ownedRoot!;
        var operation = Dpe2Codec.Decode(native.ExactEnvelope).OperationId.ToArray();
        byte[] exact;
        if (native.Direction == 1)
            exact = RequireGroupAuthoredEvent(root.State, scope, operation, native.EventHash) ?? throw new CryptographicException("Native group send lost protected payload custody.");
        else { using var owned = native.OwnAuthenticatedDmc2(); exact = owned.Use(bytes => bytes.ToArray()); }
        try
        {
            if (!SHA256.HashData(exact).AsSpan().SequenceEqual(native.EventHash)) throw new CryptographicException("Group materialization lost native event binding.");
            var parsed = ApplicationCoreCodec.DecodeDmc2(exact); var record = RequireGroupEnvelope(parsed, scope, native.Direction == 1);
            var applied = root.State.Receives.SingleOrDefault(item => item.ScopeHash.AsSpan().SequenceEqual(scope.Hash) && item.Operation.AsSpan().SequenceEqual(operation));
            if (applied is not null)
            {
                if (!applied.Hash.AsSpan().SequenceEqual(native.EventHash)) throw new CryptographicException("Group native selector changed its event.");
                held.RequireActive(); return;
            }
            var self = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var other = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(peer, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            if (record is GroupCommitChunkRecord chunk)
            {
                if (native.Direction == 2) await AdoptGroupChunkAsync(root, current, held, scope, chunk, self, other, own, source, ct).ConfigureAwait(false);
            }
            else if (record is GroupControlRendezvousRecord)
                await RequireGroupControlCarrierAsync(root, current, held, scope, parsed, native.Direction == 1, own, peer, source, true, ct).ConfigureAwait(false);
            else
            {
                var group = root.State.Find(record.Field(2).Span);
                if (group.Fork) throw new CryptographicException("Group head/session is unavailable.");
                var invitationState = group.ForScope(scope.Exact);
                var invitation = invitationState is null ? null : (GroupInvitationRecord)GroupCodec.Decode("GIV1", invitationState.Offer);
                var head = await VerifyGroupHeadAsync(group, self, other, own, held, source, ct, GroupRecordEpoch(record, invitation)).ConfigureAwait(false);
                await DeepIdV2GroupEvents.RequireAsync(record, head, native.Direction == 1 ? self : other, native.Direction == 1 ? other : self,
                    parsed.SenderDeviceId, source.RendezvousTrustedTime, invitation, ct).ConfigureAwait(false);
                if (record is GroupInvitationRecord)
                {
                    if (invitationState is not null && !invitationState.Offer.AsSpan().SequenceEqual(record.CanonicalBytes.Span)) throw new CryptographicException("Group already retained another invitation.");
                    if (invitationState is null) group.Invitations.Add(new() { Scope = scope.Exact.ToArray(), Offer = record.CanonicalBytes.ToArray() });
                }
                else if (record is GroupInvitationAcceptanceRecord)
                {
                    if (invitationState!.Acceptance.Length != 0 && !invitationState!.Acceptance.AsSpan().SequenceEqual(record.CanonicalBytes.Span)) throw new CryptographicException("Group already retained another consent.");
                    if (invitationState!.Acceptance.Length == 0) invitationState!.Acceptance = record.CanonicalBytes.ToArray();
                }
                else if (record is GroupApplicationMessageRecord)
                {
                    if (!GroupMemberSelectors(head.Commit).Any(id => id.AsSpan().SequenceEqual(current.AccountId.Span))) throw new CryptographicException("Pending invitation is not group membership.");
                    var collision = root.State.Messages.Where(item => item.Group.AsSpan().SequenceEqual(group.Id)).FirstOrDefault(item =>
                    {
                        var old = GroupCodec.Decode("DGM1", item.Record);
                        return old.Field(5).Span.SequenceEqual(record.Field(5).Span) ||
                            old.Field(6).Span.SequenceEqual(record.Field(6).Span) && old.Field(7).Span.SequenceEqual(record.Field(7).Span) && old.Field(8).Span.SequenceEqual(record.Field(8).Span);
                    });
                    if (collision is not null && !collision.Record.AsSpan().SequenceEqual(record.CanonicalBytes.Span)) throw new CryptographicException("Group message logical identity/sequence was equivocated.");
                    if (collision is null) root.State.Messages.Add(new() { Group = group.Id.ToArray(), Operation = operation.ToArray(), Scope = scope.Exact.ToArray(), Record = record.CanonicalBytes.ToArray(), Direction = checked((byte)native.Direction) });
                }
            }
            root.State.Receives.Add(new() { ScopeHash = scope.Hash.ToArray(), Operation = operation.ToArray(), Hash = native.EventHash.ToArray() });
            await SaveGroupsUnderLeaseAsync(root, current, held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(operation); }
    }

    private async Task RequireGroupControlCarrierAsync(GroupRoot root, VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        Did2MessagingSessionScope scope, ParsedDmc2 parsed, bool send, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, bool materialize, CancellationToken ct)
    {
        var payload = (GroupDmc2Payload)parsed.ParsedPayload;
        if (BinaryPrimitives.ReadUInt64BigEndian(payload.Record.Field(4).Span) != 0)
            throw new CryptographicException("Control descriptor successor/handover is not activated.");
        if (payload.Kind != Dmc2ContentKind.GroupControlRendezvous || !payload.ControlRecipient.Span.SequenceEqual(send ? scope.RemoteAccount : scope.LocalAccount))
            throw new CryptographicException("Control carrier has a different intended recipient.");
        var group = root.State.Find(payload.ControlGroup.Span);
        if (group.Fork) throw new CryptographicException("Forked group grants no control capability.");
        var self = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        var other = await DeepIdV2GroupDirectoryAuthority.VerifyAsync(peer, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        var head = await VerifyGroupHeadAsync(group, self, other, own, held, source, ct).ConfigureAwait(false);
        await GroupControlProductionClient.RequireRendezvousAsync((GroupControlRendezvousRecord)payload.Record, head,
            send ? self : other, own.Network, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        if (!send && !GroupMemberSelectors(head.Commit).Any(id => id.AsSpan().SequenceEqual(current.AccountId.Span)) &&
            (group.ForScope(scope.Exact) is not { } invitation || !GroupCodec.Decode("GIV1", invitation.Offer).Field(9).Span.SequenceEqual(current.AccountId.Span)))
            throw new CryptographicException("Control carrier is unsolicited for this group.");
        var retained = group.Controls.SingleOrDefault(control => control.Recipient.AsSpan().SequenceEqual(payload.ControlRecipient.Span));
        var raw = payload.CanonicalBytes.ToArray();
        try
        {
            if (retained is not null && (!retained.Descriptor.AsSpan().SequenceEqual(payload.Record.CanonicalBytes.Span) ||
                !retained.Key.AsSpan().SequenceEqual(raw.AsSpan(592)) || !retained.Scope.AsSpan().SequenceEqual(scope.Exact)))
                throw new CryptographicException("Control carrier changed its retained stream/key/session.");
            if (send && retained is null) throw new CryptographicException("Control send has no original protected stream custody.");
            if (!send && materialize && retained is null)
                group.Controls.Add(new() { Recipient = current.AccountId.ToArray(), Scope = scope.Exact.ToArray(),
                    Descriptor = payload.Record.CanonicalBytes.ToArray(), Key = raw.AsSpan(592).ToArray() });
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    private async Task AdoptGroupChunkAsync(GroupRoot root, VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        Did2MessagingSessionScope scope, GroupCommitChunkRecord incoming, VerifiedDeepIdV2GroupDirectory self,
        VerifiedDeepIdV2GroupDirectory other, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct,
        ReadOnlyMemory<byte> expectedGroup = default)
    {
        // Exact retransmission of an adopted package must not leave an orphan
        // transfer behind after a cold restart.
        foreach (var known in root.State.Groups)
            foreach (var package in known.Packages)
                if (incoming.Field(1).Span.SequenceEqual(GroupCodec.RecordHash("GCP1", package)))
                {
                    if (!expectedGroup.IsEmpty && !known.Id.AsSpan().SequenceEqual(expectedGroup.Span))
                        throw new CryptographicException("Control stream delivered another group's package.");
                    var index = checked((int)BinaryPrimitives.ReadUInt32BigEndian(incoming.Field(4).Span)); var offset = checked(index * 24576);
                    if (BinaryPrimitives.ReadUInt32BigEndian(incoming.Field(2).Span) != checked((uint)package.Length) || offset >= package.Length || !incoming.Field(7).Span[4..].SequenceEqual(package.AsSpan(offset, Math.Min(24576, package.Length - offset)))) throw new CryptographicException("Adopted group fragment changed bytes.");
                    return;
                }
        var transfer = root.State.Chunks.Where(item => item.Scope.AsSpan().SequenceEqual(scope.Exact) &&
            GroupCodec.Decode("GCF1", item.Record).Field(1).Span.SequenceEqual(incoming.Field(1).Span)).ToArray();
        var assembler = new GroupChunkAssembler(); ReadOnlyMemory<byte> complete = default;
        foreach (var item in transfer)
            if (!assembler.TryAdd((GroupCommitChunkRecord)GroupCodec.Decode("GCF1", item.Record), out complete)) throw new CryptographicException("Retained group transfer is inconsistent.");
        if (!assembler.TryAdd(incoming, out complete)) throw new CryptographicException("Group fragment conflicts with retained transfer.");
        if (complete.IsEmpty)
        {
            if (!transfer.Any(item => item.Record.AsSpan().SequenceEqual(incoming.CanonicalBytes.Span)))
                root.State.Chunks.Add(new() { Scope = scope.Exact.ToArray(), Record = incoming.CanonicalBytes.ToArray() });
            return;
        }
        var packageRecord = (GroupCommitPackageRecord)GroupCodec.Decode("GCP1", complete.Span);
        if (!expectedGroup.IsEmpty && !packageRecord.Field(2).Span.SequenceEqual(expectedGroup.Span))
            throw new CryptographicException("Control stream delivered another group's package.");
        var commit = GroupCodec.Decode("DGC1", packageRecord.Field(4).Span[4..]);
        if (!commit.Field(1).Span.SequenceEqual(scope.Network) || !commit.Field(6).Span.SequenceEqual(scope.RemoteAccount)) throw new CryptographicException("Group package is not authored by the authenticated peer owner.");
        var groupId = packageRecord.Field(2).ToArray(); var epoch = BinaryPrimitives.ReadUInt64BigEndian(packageRecord.Field(3).Span);
        var group = root.State.Groups.SingleOrDefault(item => item.Id.AsSpan().SequenceEqual(groupId));
        if (group is not null && group.Fork) throw new CryptographicException("Group package belongs to a different session or fork.");
        if (expectedGroup.IsEmpty && group is not null && epoch >= checked((ulong)group.Packages.Count) &&
            group.Controls.Any(control => control.Recipient.AsSpan().SequenceEqual(current.AccountId.Span)))
            throw new CryptographicException("An installed control stream cannot be bypassed by a new ordinary-mailbox commit.");
        if (epoch == 0)
        {
            _ = await DeepIdV2GroupTransitions.VerifyGenesisAsync(packageRecord, other, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            if (group is null)
            {
                group = new() { Id = groupId }; group.Packages.Add(complete.ToArray()); root.State.Groups.Add(group);
            }
        }
        else if (group is not null && epoch <= checked((ulong)group.Packages.Count))
        {
            var previous = await VerifyGroupHeadAsync(group, self, other, own, held, source, ct, checked((int)epoch - 1)).ConfigureAwait(false);
            var accounts = await ReadGroupAuthoritiesAsync(packageRecord, self, other, own, held, source, ct, group.VerifiedDirectories).ConfigureAwait(false);
            var next = await DeepIdV2GroupTransitions.VerifyActivationAsync(previous, packageRecord, accounts, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var wasMember = GroupMemberSelectors(previous.Commit).Any(id => id.AsSpan().SequenceEqual(current.AccountId.Span));
            var nowMember = GroupMemberSelectors(next.Commit).Any(id => id.AsSpan().SequenceEqual(current.AccountId.Span));
            if (!wasMember && nowMember) RequireGroupLocalConsent(packageRecord, group.ForScope(scope.Exact) ?? throw new CryptographicException("Activation has no actual local invitation."));
            if (epoch == checked((ulong)group.Packages.Count)) group.Packages.Add(complete.ToArray());
        }
        else throw new CryptographicException("Group package has a missing predecessor epoch.");
        if (!group!.Packages[checked((int)epoch)].AsSpan().SequenceEqual(complete.Span))
        {
            group.Fork = true; group.ForkEvidence = complete.ToArray();
            await SaveGroupsUnderLeaseAsync(root, current, held, ct).ConfigureAwait(false);
            throw new CryptographicException("Two verified group heads permanently fork-latched the group.");
        }
        foreach (var item in transfer) { root.State.Chunks.Remove(item); CryptographicOperations.ZeroMemory(item.Scope); CryptographicOperations.ZeroMemory(item.Record); }
    }

    private static int GroupRecordEpoch(GroupRecord record, GroupInvitationRecord? invitation) => checked((int)BinaryPrimitives.ReadUInt64BigEndian(
        record is GroupInvitationRecord ? record.Field(4).Span : record is GroupInvitationAcceptanceRecord ?
            (invitation ?? throw new CryptographicException("Consent lost its invitation.")).Field(4).Span : record.Field(3).Span));

    private static byte[]? RequireGroupAuthoredEvent(ProtectedDid2GroupJournal.State groups, Did2MessagingSessionScope scope,
        ReadOnlySpan<byte> operation, ReadOnlySpan<byte> hash)
    {
        foreach (var item in groups.Outbox)
            if (item.Operation.AsSpan().SequenceEqual(operation) && item.Scope.AsSpan().SequenceEqual(scope.Exact))
            {
                if (!item.Adopted || !SHA256.HashData(item.Event).AsSpan().SequenceEqual(hash)) throw new CryptographicException("Group native send differs from its protected original event.");
                return item.Event.ToArray();
            }
        return null;
    }

    private static void RequireGroupLocalConsent(GroupCommitPackageRecord package, ProtectedDid2GroupJournal.Invitation invitation)
    {
        if (invitation.Offer.Length == 0 || invitation.Acceptance.Length == 0 || BinaryPrimitives.ReadUInt16BigEndian(package.Field(9).Span) != 1)
            throw new CryptographicException("Activation has no retained local consent.");
        var pairs = package.Field(10).Span;
        // Already canonical/fully verified by Protocol; additionally bind the
        // unique pair to this device's actual protected invitation/consent.
        var at = 38; var invitationBytes = checked((int)BinaryPrimitives.ReadUInt32BigEndian(pairs[at..])); at += 4;
        if (!pairs.Slice(at, invitationBytes).SequenceEqual(invitation.Offer)) throw new CryptographicException("Activation changed the retained invitation.");
        at = checked(at + invitationBytes + 38); var acceptanceBytes = checked((int)BinaryPrimitives.ReadUInt32BigEndian(pairs[at..])); at += 4;
        if (pairs.Length != at + acceptanceBytes || !pairs.Slice(at, acceptanceBytes).SequenceEqual(invitation.Acceptance)) throw new CryptographicException("Activation changed the actual local consent.");
    }

    private async Task RequireGroupContactConsentUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        if (!opened.Scope.IsInitiator)
        { await RequireRetainedAcceptanceForTextAsync(opened, application, own, peer, source, held, ct).ConfigureAwait(false); return; }
        var scope = opened.Scope;
        var exact = await application.ReadContactAcceptAsync(current.AccountId, BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]),
            scope.Conversation.ToArray(), scope.RemoteAccount.ToArray(), scope.RemoteDevice.ToArray(), ct).ConfigureAwait(false) ??
            throw new CryptographicException("Group work requires actual explicit contact consent.");
        try
        {
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            using var native = opened.Sql.ReadVerifiedReceiveForEvent(floor, SHA256.HashData(exact)) ?? throw new CryptographicException("Group consent lost native receive custody.");
            using var handoff = await Deep.Client.Shared.Persistence.MessagingV1.AuthenticatedContactAcceptDmc2.FromOwnedCommitAsync(opened,
                Dpe2Codec.Decode(native.ExactEnvelope).OperationId, ReadOnlyMemory<byte>.Empty, storage, own, peer, source, held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
}
