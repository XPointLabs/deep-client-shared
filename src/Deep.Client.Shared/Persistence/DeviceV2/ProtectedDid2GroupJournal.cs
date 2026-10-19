using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Account-protected authoritative custody, never an imported SQL/JSON snapshot.
internal static class ProtectedDid2GroupJournal
{
    internal const string Slot = "deep.store.v2.groups";
    internal const int MaximumBytes = 4 * 1024 * 1024;
    internal sealed class Group
    {
        internal byte[] Id = [], ForkEvidence = [];
        internal readonly List<Invitation> Invitations = [];
        internal Invitation? ForScope(ReadOnlySpan<byte> scope) { foreach (var item in Invitations) if (item.Scope.AsSpan().SequenceEqual(scope)) return item; return null; }
        internal readonly List<byte[]> Packages = [];
        internal readonly List<Control> Controls = [];
        // Never serialized; survives only this actual root/held-lease operation.
        // Protocol independently rechecks currentness whenever it consumes one.
        internal readonly Dictionary<string, VerifiedDeepIdV2GroupDirectory> VerifiedDirectories = new(StringComparer.Ordinal);
        internal bool Fork;
        internal ulong NextMessage = 1;
    }
    internal sealed class Invitation
    {
        internal byte[] Scope = [], Offer = [], InvitationProof = [], Acceptance = [];
    }
    internal sealed class Control
    {
        internal byte[] Recipient = [], Scope = [], Descriptor = [], Key = [], CursorHash = new byte[32];
        internal ulong Cursor;
        internal readonly List<ControlWrite> Writes = [];
    }
    internal sealed class ControlWrite
    {
        internal byte[] Chunk = [], Request = [], Receipt = [];
    }
    internal sealed class Outgoing
    {
        internal byte[] Group = [], Operation = [], Scope = [], Event = [];
        internal bool Adopted;
        // Transient scheduling hint from an actual verified native read, never
        // serialized and never Store/dispatch/ACK authority.
        internal bool NativeCommitted;
    }
    internal sealed class Message
    {
        internal byte[] Group = [], Operation = [], Scope = [], Record = [];
        internal byte Direction;
    }
    internal sealed class Applied
    {
        internal byte[] ScopeHash = [], Operation = [], Hash = [];
    }
    internal sealed class Chunk
    {
        internal byte[] Scope = [], Record = [];
    }
    internal sealed class State : IDisposable
    {
        internal ulong Revision = 1;
        internal readonly List<Group> Groups = [];
        internal readonly List<Outgoing> Outbox = [];
        internal readonly List<Message> Messages = [];
        internal readonly List<Applied> Receives = [];
        internal readonly List<Chunk> Chunks = [];
        internal Group Find(ReadOnlySpan<byte> id)
        { foreach (var group in Groups) if (group.Id.AsSpan().SequenceEqual(id)) return group; throw new InvalidOperationException("Group is absent from protected custody."); }
        public void Dispose()
        {
            foreach (var group in Groups) { group.VerifiedDirectories.Clear(); foreach (var bytes in new[] { group.Id, group.ForkEvidence }.Concat(group.Packages).Concat(group.Invitations.SelectMany(item => new[] { item.Scope, item.Offer, item.InvitationProof, item.Acceptance }))) CryptographicOperations.ZeroMemory(bytes); }
            foreach (var control in Groups.SelectMany(group => group.Controls))
                foreach (var bytes in new[] { control.Recipient, control.Scope, control.Descriptor, control.Key, control.CursorHash }
                    .Concat(control.Writes.SelectMany(write => new[] { write.Chunk, write.Request, write.Receipt }))) CryptographicOperations.ZeroMemory(bytes);
            foreach (var item in Outbox) foreach (var bytes in new[] { item.Group, item.Operation, item.Scope, item.Event }) CryptographicOperations.ZeroMemory(bytes);
            foreach (var item in Messages) foreach (var bytes in new[] { item.Group, item.Operation, item.Scope, item.Record }) CryptographicOperations.ZeroMemory(bytes);
            foreach (var item in Receives) foreach (var bytes in new[] { item.ScopeHash, item.Operation, item.Hash }) CryptographicOperations.ZeroMemory(bytes);
            foreach (var item in Chunks) { CryptographicOperations.ZeroMemory(item.Scope); CryptographicOperations.ZeroMemory(item.Record); }
        }
    }

    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { using var state = new State(); return Encode(state, network, account, instance); }

    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (state.Revision == 0 || state.Groups.Count > 32 || state.Outbox.Count > 512 || state.Messages.Count > 4096 || state.Receives.Count > 8192 || state.Chunks.Count > 342)
            throw new IOException("Protected group capacity is exhausted.");
        using var stream = new MemoryStream(); using var writer = new BinaryWriter(stream);
        writer.Write((byte)3); writer.Write(new byte[3]); writer.Write(network); writer.Write(account); writer.Write(instance); writer.Write(state.Revision);
        writer.Write(checked((ushort)state.Groups.Count)); writer.Write(checked((ushort)state.Outbox.Count));
        writer.Write(checked((ushort)state.Messages.Count)); writer.Write(checked((ushort)state.Receives.Count)); writer.Write(checked((ushort)state.Chunks.Count));
        foreach (var group in state.Groups.OrderBy(group => Convert.ToHexString(group.Id), StringComparer.Ordinal))
        {
            writer.Write(group.Id); writer.Write(group.Fork); writer.Write(group.NextMessage);
            writer.Write(checked((ushort)group.Invitations.Count));
            foreach (var invitation in group.Invitations) { Bytes(writer, invitation.Scope); Bytes(writer, invitation.Offer); Bytes(writer, invitation.InvitationProof); Bytes(writer, invitation.Acceptance); }
            Bytes(writer, group.ForkEvidence);
            writer.Write(checked((byte)group.Packages.Count)); foreach (var package in group.Packages) Bytes(writer, package);
            writer.Write(checked((ushort)group.Controls.Count));
            foreach (var control in group.Controls)
            {
                writer.Write(control.Recipient); Bytes(writer, control.Scope); Bytes(writer, control.Descriptor); writer.Write(control.Key);
                writer.Write(control.Cursor); writer.Write(control.CursorHash); writer.Write(checked((ushort)control.Writes.Count));
                // Once sealed, the exact request already owns the chunk bytes.
                // Do not retain a second plaintext copy in the protected root.
                foreach (var write in control.Writes) { Bytes(writer, write.Request.Length == 0 ? write.Chunk : []); Bytes(writer, write.Request); Bytes(writer, write.Receipt); CheckSize(stream); }
            }
            CheckSize(stream);
        }
        foreach (var item in state.Outbox)
        { writer.Write(item.Group); writer.Write(item.Operation); writer.Write(item.Adopted); Bytes(writer, item.Scope); Bytes(writer, item.Event); CheckSize(stream); }
        foreach (var item in state.Messages)
        { writer.Write(item.Group); writer.Write(item.Operation); writer.Write(item.Direction); Bytes(writer, item.Scope); Bytes(writer, item.Record); CheckSize(stream); }
        foreach (var item in state.Receives) { writer.Write(item.ScopeHash); writer.Write(item.Operation); writer.Write(item.Hash); }
        foreach (var item in state.Chunks) { Bytes(writer, item.Scope); Bytes(writer, item.Record); CheckSize(stream); }
        CheckSize(stream); var result = stream.ToArray();
        try { using var check = Decode(result, network, account, instance); return result; }
        catch { CryptographicOperations.ZeroMemory(result); throw; }
        finally { if (stream.TryGetBuffer(out var buffer)) CryptographicOperations.ZeroMemory(buffer.AsSpan(0, checked((int)stream.Length))); }
    }

    internal static State Decode(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (bytes.Length is < 102 or > MaximumBytes || bytes[0] != 3 || bytes.Slice(1, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            !bytes.Slice(4, 16).SequenceEqual(network) || !bytes.Slice(20, 32).SequenceEqual(account) || !bytes.Slice(52, 32).SequenceEqual(instance))
            throw new InvalidDataException("Protected group registration is missing, foreign or unsupported.");
        var reader = new Reader(bytes[84..]); var state = new State { Revision = reader.U64() };
        try
        {
            if (state.Revision == 0) throw new InvalidDataException("Invalid protected group revision.");
            var groups = reader.Count(32); var outgoing = reader.Count(512); var messages = reader.Count(4096);
            var applied = reader.Count(8192); var chunks = reader.Count(342);
            var ids = new HashSet<string>(StringComparer.Ordinal);
            string? previous = null;
            for (var index = 0; index < groups; index++)
            {
                var group = new Group { Id = reader.Fixed(32), Fork = reader.Bool(), NextMessage = reader.U64() };
                state.Groups.Add(group); RequireId(group.Id); var id = Convert.ToHexString(group.Id);
                if (!ids.Add(id) || previous is not null && StringComparer.Ordinal.Compare(previous, id) >= 0 || group.NextMessage is 0 or >= long.MaxValue)
                    throw new InvalidDataException("Protected groups are noncanonical.");
                previous = id;
                var invitations = reader.Count(100); var invitationScopes = new HashSet<string>(StringComparer.Ordinal);
                for (var invitationIndex = 0; invitationIndex < invitations; invitationIndex++)
                {
                    var invitation = new Invitation { Scope = reader.Bytes(404), Offer = reader.Bytes(669), InvitationProof = reader.Bytes(512 * 1024), Acceptance = reader.Bytes(610) };
                    group.Invitations.Add(invitation); RequireSession(invitation.Scope, network, account, instance);
                    if (!invitationScopes.Add(Convert.ToHexString(invitation.Scope)) || invitation.Offer.Length == 0 || !GroupCodec.Decode("GIV1", invitation.Offer).Field(2).Span.SequenceEqual(group.Id) ||
                        invitation.Acceptance.Length != 0 && !GroupCodec.Decode("GIA1", invitation.Acceptance).Field(2).Span.SequenceEqual(group.Id))
                        throw new InvalidDataException("Protected invitation scope is invalid or repeated.");
                }
                group.ForkEvidence = reader.Bytes(8 * 1024 * 1024);
                var count = reader.Byte(); if (count is < 1 or > 100) throw new InvalidDataException("Unsupported candidate group lineage.");
                if (group.Fork != (group.ForkEvidence.Length != 0)) throw new InvalidDataException("Group fork latch lost its evidence.");
                if (group.Fork) _ = GroupCodec.Decode("GCP1", group.ForkEvidence);
                for (var p = 0; p < count; p++)
                {
                    var package = reader.Bytes(8 * 1024 * 1024); var parsed = GroupCodec.Decode("GCP1", package);
                    if (!parsed.Field(1).Span.SequenceEqual(network) || !parsed.Field(2).Span.SequenceEqual(group.Id) ||
                        BinaryPrimitives.ReadUInt64BigEndian(parsed.Field(3).Span) != checked((ulong)p))
                        throw new CryptographicException("Protected group lineage differs from its scope/epoch.");
                    group.Packages.Add(package);
                }
                var controlCount = reader.Count(100); var recipients = new HashSet<string>(StringComparer.Ordinal);
                for (var c = 0; c < controlCount; c++)
                {
                    var control = new Control { Recipient = reader.Fixed(32), Scope = reader.Bytes(404), Descriptor = reader.Bytes(528),
                        Key = reader.Fixed(32), Cursor = reader.U64(), CursorHash = reader.Fixed(32) };
                    group.Controls.Add(control); RequireId(control.Recipient);
                    var descriptor = (GroupControlRendezvousRecord)GroupCodec.Decode("GSR1", control.Descriptor);
                    if (BinaryPrimitives.ReadUInt64BigEndian(descriptor.Field(4).Span) != 0)
                        throw new CryptographicException("Control descriptor successor/handover is unsupported.");
                    if (!recipients.Add(Convert.ToHexString(control.Recipient)) || !descriptor.Field(1).Span.SequenceEqual(network) ||
                        !GroupControlCipher.PublicKey(control.Key).AsSpan().SequenceEqual(descriptor.Field(9).Span) ||
                        (control.Cursor == 0) != (control.CursorHash.AsSpan().IndexOfAnyExcept((byte)0) < 0)) throw new CryptographicException("Invalid protected control stream custody.");
                    if (control.Scope.Length != 0)
                    {
                        var controlScope = RequireSession(control.Scope, network, account, instance);
                        if (!control.Recipient.AsSpan().SequenceEqual(account) && !control.Recipient.AsSpan().SequenceEqual(controlScope.RemoteAccount))
                            throw new CryptographicException("Control recipient differs from retained pairwise scope.");
                    }
                    else if (!control.Recipient.AsSpan().SequenceEqual(account)) throw new CryptographicException("Remote control stream lost its session.");
                    var writes = reader.Count(512); byte[] previousHash = new byte[32]; var unpreparedTail = false;
                    for (var w = 0; w < writes; w++)
                    {
                        var write = new ControlWrite { Chunk = reader.Bytes(24748), Request = reader.Bytes(33160), Receipt = reader.Bytes(65535) };
                        control.Writes.Add(write);
                        if (write.Request.Length != 0)
                        {
                            if (write.Chunk.Length != 0) throw new CryptographicException("Prepared control work has a noncanonical duplicate plaintext field.");
                            var sealedRequest = (GroupControlWriteRecord)GroupCodec.Decode("GSW1", write.Request);
                            var plaintext = GroupControlCipher.Open(descriptor, control.Key, checked((ulong)w + 1), previousHash,
                                BinaryPrimitives.ReadUInt64BigEndian(sealedRequest.Field(22).Span), sealedRequest.Field(21).Span[4..]);
                            write.Chunk = plaintext.CanonicalBytes.ToArray();
                        }
                        var chunk = GroupCodec.Decode("GCF1", write.Chunk);
                        var originalPackage = group.Packages.SingleOrDefault(package => chunk.Field(1).Span.SequenceEqual(GroupCodec.RecordHash("GCP1", package))) ??
                            throw new CryptographicException("Control write lost its original package.");
                        var chunkOffset = checked((int)BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(4).Span) * 24576);
                        if (BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(2).Span) != originalPackage.Length || chunkOffset >= originalPackage.Length ||
                            !chunk.Field(7).Span[4..].SequenceEqual(originalPackage.AsSpan(chunkOffset, Math.Min(24576, originalPackage.Length - chunkOffset))))
                            throw new CryptographicException("Control fragment differs from retained package bytes.");
                        if (write.Request.Length == 0)
                        {
                            if (write.Receipt.Length != 0) throw new CryptographicException("Unprepared control write has a receipt.");
                            unpreparedTail = true;
                            continue;
                        }
                        if (unpreparedTail) throw new CryptographicException("Prepared control write followed unprepared work.");
                        var request = (GroupControlWriteRecord)GroupCodec.Decode("GSW1", write.Request);
                        if (!request.Field(1).Span.SequenceEqual(network) || !request.Field(16).Span.SequenceEqual(GroupControlProductionClient.Selector(descriptor)) ||
                            !request.Field(17).Span.SequenceEqual(descriptor.ArtifactHash.Span) || BinaryPrimitives.ReadUInt64BigEndian(request.Field(18).Span) != checked((ulong)w + 1) ||
                            !request.Field(19).Span.SequenceEqual(previousHash)) throw new CryptographicException("Control write chain differs from original descriptor/sequence.");
                        if (write.Receipt.Length != 0) _ = GroupCodec.Decode("GSS1", write.Receipt);
                        previousHash = request.Field(20).ToArray();
                    }
                }
                if (group.Fork)
                {
                    var evidence = GroupCodec.Decode("GCP1", group.ForkEvidence);
                    var epoch = BinaryPrimitives.ReadUInt64BigEndian(evidence.Field(3).Span);
                    if (!evidence.Field(1).Span.SequenceEqual(network) || !evidence.Field(2).Span.SequenceEqual(group.Id) ||
                        epoch >= checked((ulong)group.Packages.Count) || group.Packages[checked((int)epoch)].AsSpan().SequenceEqual(group.ForkEvidence))
                        throw new CryptographicException("Protected fork evidence differs from the retained competing head.");
                }

            }
            var packageMaps = state.Groups.ToDictionary(group => Convert.ToHexString(group.Id), group => group.Packages.ToDictionary(package => Convert.ToHexString(GroupCodec.RecordHash("GCP1", package)), package => package, StringComparer.Ordinal), StringComparer.Ordinal);
            var operations = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 0; index < outgoing; index++)
            {
                var item = new Outgoing { Group = reader.Fixed(32), Operation = reader.Fixed(32), Adopted = reader.Bool(), Scope = reader.Bytes(404), Event = reader.Bytes(33082) };
                state.Outbox.Add(item); RequireId(item.Operation);
                if (!ids.Contains(Convert.ToHexString(item.Group)) || !operations.Add(Convert.ToHexString(item.Operation))) throw new InvalidDataException("Unknown/repeated protected group work.");
                var scope = RequireSession(item.Scope, network, account, instance); var parsed = ApplicationCoreCodec.DecodeDmc2(item.Event);
                if (!IsKind(parsed.ContentKind) || !parsed.NetworkId.Span.SequenceEqual(network) || !parsed.SenderAccountId.Span.SequenceEqual(account) ||
                    !parsed.SenderDeviceId.Span.SequenceEqual(scope.LocalDevice) || !parsed.ConversationId.Span.SequenceEqual(scope.Conversation) ||
                    parsed.Flags != Dmc2Flags.None || parsed.ReplyToLogicalMessageId.Length != 0 || parsed.ExpiresAtUnixMilliseconds == 0)
                    throw new CryptographicException("Protected group work differs from its exact sender/session.");
                var record = ((GroupDmc2Payload)parsed.ParsedPayload).Record;
                if (record is GroupCommitChunkRecord chunk)
                {
                    if (!packageMaps[Convert.ToHexString(item.Group)].TryGetValue(Convert.ToHexString(chunk.Field(1).Span), out var package))
                        throw new CryptographicException("Protected group chunk has no exact lineage package.");
                    var offset = checked((int)BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(4).Span) * 24576);
                    if (BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(2).Span) != checked((uint)package.Length) || offset >= package.Length || !chunk.Field(7).Span[4..].SequenceEqual(package.AsSpan(offset, Math.Min(24576, package.Length - offset))))
                        throw new CryptographicException("Protected group chunk differs from retained package bytes.");
                }
                if (record is not GroupCommitChunkRecord &&
                    (!record.Field(1).Span.SequenceEqual(network) || !((GroupDmc2Payload)parsed.ParsedPayload is { Kind: Dmc2ContentKind.GroupControlRendezvous } carrier
                        ? carrier.ControlGroup.Span.SequenceEqual(item.Group) : record.Field(2).Span.SequenceEqual(item.Group))))
                    throw new CryptographicException("Protected group work differs from its exact group custody.");
            }
            for (var index = 0; index < messages; index++)
            {
                var item = new Message { Group = reader.Fixed(32), Operation = reader.Fixed(32), Direction = reader.Byte(), Scope = reader.Bytes(404), Record = reader.Bytes(24946) };
                state.Messages.Add(item); RequireId(item.Operation); RequireSession(item.Scope, network, account, instance);
                if (item.Direction is not (1 or 2) || !ids.Contains(Convert.ToHexString(item.Group)) ||
                    !GroupCodec.Decode("DGM1", item.Record).Field(2).Span.SequenceEqual(item.Group)) throw new InvalidDataException("Invalid protected group message selector.");
            }
            var receives = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 0; index < applied; index++)
            {
                var item = new Applied { ScopeHash = reader.Fixed(32), Operation = reader.Fixed(32), Hash = reader.Fixed(32) }; state.Receives.Add(item);
                RequireId(item.ScopeHash); RequireId(item.Operation); RequireId(item.Hash);
                if (!receives.Add(Convert.ToHexString(item.ScopeHash) + Convert.ToHexString(item.Operation))) throw new InvalidDataException("Repeated group native selector.");
            }
            for (var index = 0; index < chunks; index++)
            {
                var item = new Chunk { Scope = reader.Bytes(404), Record = reader.Bytes(24748) }; state.Chunks.Add(item);
                RequireSession(item.Scope, network, account, instance); _ = GroupCodec.Decode("GCF1", item.Record);
            }
            reader.Complete(); return state;
        }
        catch { state.Dispose(); throw; }
    }
    internal static bool IsKind(Dmc2ContentKind kind) => kind is Dmc2ContentKind.GroupInvite or Dmc2ContentKind.GroupInvitationAcceptance or Dmc2ContentKind.GroupCommitChunk or Dmc2ContentKind.GroupApplicationMessage or Dmc2ContentKind.GroupControlRendezvous;
    private static Did2MessagingSessionScope RequireSession(byte[] exact, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var scope = Did2MessagingSessionScope.RestoreMetadata(exact);
        if (!scope.Network.SequenceEqual(network) || !scope.LocalAccount.SequenceEqual(account) || !scope.Instance.SequenceEqual(instance))
            throw new CryptographicException("Foreign protected group session.");
        return scope;
    }
    private static void RequireId(ReadOnlySpan<byte> id) { if (id.Length != 32 || id.IndexOfAnyExcept((byte)0) < 0) throw new InvalidDataException("Invalid protected group identifier."); }
    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { if (network.Length != 16 || network.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("Invalid group network."); RequireId(account); RequireId(instance); }
    private static void Bytes(BinaryWriter writer, byte[] value) { writer.Write(value.Length); writer.Write(value); }
    private static void CheckSize(MemoryStream stream) { if (stream.Length > MaximumBytes) throw new IOException("Protected group root exceeds capacity."); }
    private ref struct Reader(ReadOnlySpan<byte> bytes)
    {
        private ReadOnlySpan<byte> remaining = bytes;
        internal byte[] Fixed(int count) { if (count < 0 || remaining.Length < count) throw new InvalidDataException("Truncated protected group state."); var result = remaining[..count].ToArray(); remaining = remaining[count..]; return result; }
        internal byte Byte() { if (remaining.IsEmpty) throw new InvalidDataException("Truncated protected group scalar."); var result = remaining[0]; remaining = remaining[1..]; return result; }
        internal bool Bool() => Byte() switch { 0 => false, 1 => true, _ => throw new InvalidDataException("Invalid protected group flag.") };
        internal ulong U64() { if (remaining.Length < 8) throw new InvalidDataException("Truncated group revision."); var result = BinaryPrimitives.ReadUInt64LittleEndian(remaining); remaining = remaining[8..]; return result; }
        internal int Count(int max) { if (remaining.Length < 2) throw new InvalidDataException("Truncated group count."); var count = BinaryPrimitives.ReadUInt16LittleEndian(remaining); remaining = remaining[2..]; if (count > max) throw new InvalidDataException("Protected group count exceeds its bound."); return count; }
        internal byte[] Bytes(int max) { if (remaining.Length < 4) throw new InvalidDataException("Truncated group length."); var count = BinaryPrimitives.ReadInt32LittleEndian(remaining); remaining = remaining[4..]; if (count < 0 || count > max) throw new InvalidDataException("Group field exceeds its bound."); return Fixed(count); }
        internal void Complete() { if (!remaining.IsEmpty) throw new InvalidDataException("Trailing protected group bytes."); }
    }
}
