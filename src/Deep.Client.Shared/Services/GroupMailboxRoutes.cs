using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record GroupMemberMailboxInvitation(
    SessionId Member,
    byte[] CanonicalInvitation);

public sealed record GroupMailboxRouteBundle(
    ConversationId GroupId,
    long GroupRevision,
    byte[] MembershipDigest,
    IReadOnlyList<GroupMemberMailboxInvitation> Invitations);

public sealed record InboundGroupMailboxRouteEnvelope(
    GroupMailboxRouteBundle Bundle,
    SessionId Sender,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string ServerHash);

public interface IGroupMailboxRouteExchange
{
    Task<GroupMailboxRouteBundle?> CaptureForPublishAsync(
        Group group,
        CancellationToken cancellationToken = default);

    Task ImportReceivedAsync(
        SessionId localAccount,
        Group group,
        GroupMailboxRouteBundle bundle,
        CancellationToken cancellationToken = default);
}

public interface IGroupMailboxRouteSyncTransport
{
    Task PublishGroupMailboxRoutesAsync(
        GroupMailboxRouteBundle bundle,
        DateTimeOffset updatedAt,
        IEnumerable<SessionId> recipients,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<InboundGroupMailboxRouteEnvelope>> ReceiveGroupMailboxRoutesAsync(
        SessionId member,
        CancellationToken cancellationToken = default);
}

public sealed class DisabledGroupMailboxRouteSyncTransport : IGroupMailboxRouteSyncTransport
{
    public Task PublishGroupMailboxRoutesAsync(
        GroupMailboxRouteBundle bundle,
        DateTimeOffset updatedAt,
        IEnumerable<SessionId> recipients,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException(
            "A persisted group mailbox route bundle cannot be published without a route-capable transport.");
    }

    public Task<IReadOnlyList<InboundGroupMailboxRouteEnvelope>> ReceiveGroupMailboxRoutesAsync(
        SessionId member,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<InboundGroupMailboxRouteEnvelope>>([]);
    }
}

public static class GroupMailboxRouteBundleCodec
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static ReadOnlySpan<byte> Magic => "GMR1"u8;

    public const byte Version = 1;
    public const int MembershipDigestSize = 32;
    public const int MaxInvitations = 96;
    public const int CanonicalInvitationBytes = ContactMailboxInvitationService.CanonicalBinaryLength;

    private const int SessionIdBytes = 66;
    private const int GroupIdBytes = 66;
    private const int FixedHeaderBytes = 4 + 1 + GroupIdBytes + 8 + MembershipDigestSize + 2;

    public static byte[] Encode(GroupMailboxRouteBundle bundle)
    {
        ValidateCanonical(bundle, inbound: false);
        var writer = new ArrayBufferWriter<byte>();
        Write(writer, Magic);
        WriteByte(writer, Version);
        WriteAscii(writer, bundle.GroupId.Value, GroupIdBytes);
        WriteInt64(writer, bundle.GroupRevision);
        Write(writer, bundle.MembershipDigest);
        WriteUInt16(writer, checked((ushort)bundle.Invitations.Count));
        foreach (var invitation in bundle.Invitations)
        {
            WriteAscii(writer, invitation.Member.Value, SessionIdBytes);
            WriteUInt16(writer, checked((ushort)invitation.CanonicalInvitation.Length));
            Write(writer, invitation.CanonicalInvitation);
        }

        return writer.WrittenSpan.ToArray();
    }

    public static GroupMailboxRouteBundle Decode(ReadOnlySpan<byte> encoded)
    {
        try
        {
            if (encoded.Length < FixedHeaderBytes || encoded.Length > MaximumEncodedBytes)
            {
                throw Invalid("GMR1 length is invalid.");
            }

            var reader = new Reader(encoded);
            if (!reader.Read(Magic.Length).SequenceEqual(Magic) || reader.ReadByte() != Version)
            {
                throw Invalid("GMR1 header is invalid.");
            }

            var groupId = ConversationId.Parse(reader.ReadAscii(GroupIdBytes, "group ID"));
            var revision = reader.ReadInt64();
            var digest = reader.Read(MembershipDigestSize).ToArray();
            var count = reader.ReadUInt16();
            if (count > MaxInvitations)
            {
                throw Invalid("GMR1 invitation count is invalid.");
            }

            var invitations = new GroupMemberMailboxInvitation[count];
            for (var index = 0; index < invitations.Length; index++)
            {
                var member = SessionId.Parse(reader.ReadAscii(SessionIdBytes, "member"));
                var length = reader.ReadUInt16();
                if (length != CanonicalInvitationBytes)
                {
                    throw Invalid("GMR1 invitation length is invalid.");
                }

                invitations[index] = new GroupMemberMailboxInvitation(member, reader.Read(length).ToArray());
            }

            if (!reader.IsAtEnd)
            {
                throw Invalid("GMR1 has trailing bytes.");
            }

            var bundle = new GroupMailboxRouteBundle(groupId, revision, digest, invitations);
            ValidateCanonical(bundle, inbound: true);
            return bundle;
        }
        catch (E2eeProtocolException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or DecoderFallbackException or OverflowException)
        {
            throw new E2eeProtocolException("GMR1 is malformed.", exception);
        }
    }

    public static void ValidateForGroup(GroupMailboxRouteBundle bundle, Group group)
    {
        ArgumentNullException.ThrowIfNull(group);
        ValidateCanonical(bundle, inbound: false);
        if (bundle.GroupId != group.Id || bundle.GroupRevision != group.Revision)
        {
            throw new InvalidOperationException("The group mailbox route bundle is bound to different group state.");
        }

        var expectedDigest = E2eeContentCodec.ComputeGroupMembershipDigest(group);
        if (!bundle.MembershipDigest.AsSpan().SequenceEqual(expectedDigest))
        {
            throw new InvalidOperationException("The group mailbox route bundle membership digest does not match group state.");
        }

        var expectedMembers = group.Members
            .Select(static member => member.SessionId)
            .OrderBy(static member => member.Value, StringComparer.Ordinal)
            .ToArray();
        if (expectedMembers.Length != bundle.Invitations.Count
            || !expectedMembers.SequenceEqual(bundle.Invitations.Select(static invitation => invitation.Member)))
        {
            throw new InvalidOperationException("The group mailbox route bundle does not cover the exact group membership.");
        }
    }

    public static int MaximumEncodedBytes =>
        FixedHeaderBytes + (MaxInvitations * (SessionIdBytes + 2 + CanonicalInvitationBytes));

    private static void ValidateCanonical(GroupMailboxRouteBundle bundle, bool inbound)
    {
        Exception InvalidValue(string message) => inbound
            ? Invalid(message)
            : new ArgumentException(message, nameof(bundle));

        ArgumentNullException.ThrowIfNull(bundle);
        if (bundle.GroupRevision < 1
            || bundle.MembershipDigest is null
            || bundle.MembershipDigest.Length != MembershipDigestSize
            || bundle.Invitations is null
            || bundle.Invitations.Count > MaxInvitations)
        {
            throw InvalidValue("GMR1 metadata is invalid.");
        }

        try
        {
            if (ConversationId.Parse(bundle.GroupId.Value) != bundle.GroupId
                || bundle.GroupId.Value.Length != GroupIdBytes
                || !bundle.GroupId.Value.StartsWith("03", StringComparison.Ordinal)
                || !bundle.GroupId.Value.All(static character =>
                    character is >= '0' and <= '9' or >= 'a' and <= 'f'))
            {
                throw InvalidValue("GMR1 group ID is not canonical.");
            }
        }
        catch (ArgumentException) when (inbound)
        {
            throw Invalid("GMR1 group ID is not canonical.");
        }

        string? previous = null;
        foreach (var invitation in bundle.Invitations)
        {
            if (invitation is null
                || invitation.CanonicalInvitation is null
                || invitation.CanonicalInvitation.Length != CanonicalInvitationBytes)
            {
                throw InvalidValue("GMR1 invitation is invalid.");
            }

            string canonical;
            try
            {
                canonical = SessionId.Parse(invitation.Member.Value).Value;
            }
            catch (ArgumentException) when (inbound)
            {
                throw Invalid("GMR1 member is not canonical.");
            }

            if (!string.Equals(canonical, invitation.Member.Value, StringComparison.Ordinal)
                || (previous is not null && string.CompareOrdinal(previous, canonical) >= 0))
            {
                throw InvalidValue("GMR1 invitations must be unique and ordered by member Session ID.");
            }

            previous = canonical;
        }
    }

    private static void Write(ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> value)
    {
        value.CopyTo(writer.GetSpan(value.Length));
        writer.Advance(value.Length);
    }

    private static void WriteByte(ArrayBufferWriter<byte> writer, byte value)
    {
        writer.GetSpan(1)[0] = value;
        writer.Advance(1);
    }

    private static void WriteUInt16(ArrayBufferWriter<byte> writer, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(writer.GetSpan(2), value);
        writer.Advance(2);
    }

    private static void WriteInt64(ArrayBufferWriter<byte> writer, long value)
    {
        BinaryPrimitives.WriteInt64BigEndian(writer.GetSpan(8), value);
        writer.Advance(8);
    }

    private static void WriteAscii(ArrayBufferWriter<byte> writer, string value, int expectedBytes)
    {
        var bytes = StrictUtf8.GetBytes(value);
        if (bytes.Length != expectedBytes || bytes.Any(static value => value > 0x7f))
        {
            throw new ArgumentException("GMR1 identifier is not canonical ASCII.", nameof(value));
        }

        Write(writer, bytes);
    }

    private static E2eeProtocolException Invalid(string message) => new(message);

    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> source;
        private int offset;

        public Reader(ReadOnlySpan<byte> source)
        {
            this.source = source;
            offset = 0;
        }

        public bool IsAtEnd => offset == source.Length;

        public byte ReadByte() => Read(1)[0];

        public ushort ReadUInt16() => BinaryPrimitives.ReadUInt16BigEndian(Read(2));

        public long ReadInt64() => BinaryPrimitives.ReadInt64BigEndian(Read(8));

        public string ReadAscii(int count, string field)
        {
            var bytes = Read(count);
            for (var index = 0; index < bytes.Length; index++)
            {
                if (bytes[index] > 0x7f)
                {
                    throw Invalid($"GMR1 {field} is not ASCII.");
                }
            }

            return StrictUtf8.GetString(bytes);
        }

        public ReadOnlySpan<byte> Read(int count)
        {
            if (count < 0 || count > source.Length - offset)
            {
                throw Invalid("GMR1 is truncated.");
            }

            var value = source.Slice(offset, count);
            offset += count;
            return value;
        }
    }
}
