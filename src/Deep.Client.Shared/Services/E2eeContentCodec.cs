using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

public enum E2eeContentKind : byte
{
    Message = 1,
    Reaction = 2,
    GroupState = 3,
    GroupRoutes = 4
}

public sealed record E2eeContent(
    E2eeContentKind Kind,
    MessageId MessageId,
    ConversationKind ConversationKind,
    ConversationId ConversationId,
    SessionId Sender,
    SessionId Recipient,
    DateTimeOffset IssuedAt,
    DateTimeOffset ProtocolExpiresAt,
    DateTimeOffset? UserExpiresAt,
    string Body,
    IReadOnlyList<AttachmentMetadata> Attachments,
    MessageReply? Reply = null,
    MessageReactionUpdate? Reaction = null,
    long? GroupRevision = null,
    Group? GroupState = null,
    GroupMailboxRouteBundle? GroupRoutes = null);

public static class E2eeContentCodec
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static ReadOnlySpan<byte> Magic => "DMC1"u8;

    public const byte ProtocolVersion = 2;
    public const int MaxBodyBytes = 64 * 1024;
    public const int MaxAttachments = 32;
    public const int MaxFilenameBytes = 255;
    public const int MaxMimeTypeBytes = 128;
    public const int MaxUriBytes = 2048;
    public const int MaxReplyQuoteBytes = 240;
    public const int MaxReactionBytes = 64;
    public const int MaxGroupNameBytes = 256;
    public const int MaxGroupMembers = 2048;
    public static readonly TimeSpan DefaultMaxFutureSkew = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaxProtocolLifetime =
        TimeSpan.FromSeconds(MailboxClientLimits.MaximumTtlSeconds);

    private const ushort UserExpiryFlag = 1 << 0;
    private const ushort ReplyFlag = 1 << 1;
    private const ushort GroupRevisionFlag = 1 << 2;
    private const ushort KnownFlags = UserExpiryFlag | ReplyFlag | GroupRevisionFlag;
    private const byte PendingRemovalMemberFlag = 1 << 0;
    private const byte KnownMemberFlags = PendingRemovalMemberFlag;
    private const byte DestroyedGroupFlag = 1 << 0;
    private const byte KickedGroupFlag = 1 << 1;
    private const byte KnownGroupFlags = DestroyedGroupFlag | KickedGroupFlag;
    private const int MaxMessageIdBytes = 128;
    private const int MaxConversationIdBytes = 2048;
    private const int MaxAttachmentIdBytes = 128;
    private const int MaxBase64Bytes = 256;
    private const int SessionIdSize = E2eeEnvelopeCodec.SessionIdSize;
    private const int MinimumContentBytes = 4 + 1 + 1 + 1 + 2 + 2 + 1 + 2 + 1 + (SessionIdSize * 2) + 16 + 4 + 2;

    public static byte[] Encode(E2eeContent content)
    {
        ArgumentNullException.ThrowIfNull(content);
        ValidateForEncoding(content);

        var flags = (ushort)0;
        if (content.UserExpiresAt is not null)
        {
            flags |= UserExpiryFlag;
        }

        if (content.Reply is not null)
        {
            flags |= ReplyFlag;
        }

        if (content.GroupRevision is not null)
        {
            flags |= GroupRevisionFlag;
        }

        var writer = new ArrayBufferWriter<byte>();
        WriteBytes(writer, Magic);
        WriteByte(writer, ProtocolVersion);
        WriteByte(writer, (byte)content.Kind);
        WriteByte(writer, EncodeConversationKind(content.ConversationKind));
        WriteUInt16(writer, flags);
        WriteString16(writer, content.MessageId.Value, nameof(content.MessageId), MaxMessageIdBytes, allowEmpty: false);
        WriteString16(writer, content.ConversationId.Value, nameof(content.ConversationId), MaxConversationIdBytes, allowEmpty: false);
        WriteSessionId(writer, content.Sender, nameof(content.Sender));
        WriteSessionId(writer, content.Recipient, nameof(content.Recipient));
        WriteInt64(writer, content.IssuedAt.ToUnixTimeMilliseconds());
        WriteInt64(writer, content.ProtocolExpiresAt.ToUnixTimeMilliseconds());

        if (content.UserExpiresAt is { } userExpiry)
        {
            WriteInt64(writer, userExpiry.ToUnixTimeMilliseconds());
        }

        if (content.Kind == E2eeContentKind.GroupState)
        {
            WriteGroupState(writer, content.GroupState!);
            return FinishEncoding(writer, content);
        }

        if (content.Kind == E2eeContentKind.GroupRoutes)
        {
            var encodedBundle = GroupMailboxRouteBundleCodec.Encode(content.GroupRoutes!);
            WriteUInt32(writer, checked((uint)encodedBundle.Length));
            WriteBytes(writer, encodedBundle);
            return FinishEncoding(writer, content);
        }

        WriteString32(writer, content.Body, nameof(content.Body), MaxBodyBytes, allowEmpty: true);
        WriteUInt16(writer, checked((ushort)content.Attachments.Count));
        foreach (var attachment in content.Attachments)
        {
            WriteAttachment(writer, attachment);
        }

        if (content.Reply is { } reply)
        {
            WriteString16(writer, reply.MessageId.Value, nameof(reply.MessageId), MaxMessageIdBytes, allowEmpty: false);
            WriteSessionId(writer, reply.Sender, nameof(reply.Sender));
            WriteString16(writer, reply.Body, nameof(reply.Body), MaxReplyQuoteBytes, allowEmpty: true);
        }

        if (content.Kind == E2eeContentKind.Reaction)
        {
            var reaction = content.Reaction!;
            WriteString16(writer, reaction.TargetMessageId.Value, nameof(reaction.TargetMessageId), MaxMessageIdBytes, allowEmpty: false);
            WriteString16(writer, reaction.Emoji, nameof(reaction.Emoji), MaxReactionBytes, allowEmpty: false);
            WriteByte(writer, reaction.Remove ? (byte)1 : (byte)0);
        }

        if (content.GroupRevision is { } revision)
        {
            WriteInt64(writer, revision);
        }

        return FinishEncoding(writer, content);
    }

    public static E2eeContent Decode(
        ReadOnlySpan<byte> encoded,
        DateTimeOffset now,
        TimeSpan? maxFutureSkew = null)
    {
        try
        {
            return DecodeCore(encoded, now, maxFutureSkew ?? DefaultMaxFutureSkew);
        }
        catch (E2eeProtocolException)
        {
            throw;
        }
        catch (Exception ex) when (ex is ArgumentException or DecoderFallbackException or FormatException or OverflowException)
        {
            throw new E2eeProtocolException("DMC1 content is malformed.", ex);
        }
    }

    private static E2eeContent DecodeCore(ReadOnlySpan<byte> encoded, DateTimeOffset now, TimeSpan maxFutureSkew)
    {
        if (maxFutureSkew < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maxFutureSkew));
        }

        if (encoded.Length < MinimumContentBytes || encoded.Length > E2eeEnvelopeCodec.MaxPlaintextBytes)
        {
            throw InvalidContent("DMC1 content length is invalid.");
        }

        var reader = new ContentReader(encoded);
        if (!reader.ReadSpan(Magic.Length).SequenceEqual(Magic))
        {
            throw InvalidContent("DMC1 magic is invalid.");
        }

        if (reader.ReadByte() != ProtocolVersion)
        {
            throw InvalidContent("DMC1 version is not supported.");
        }

        var kind = DecodeContentKind(reader.ReadByte());
        var conversationKind = DecodeConversationKind(reader.ReadByte());
        var flags = reader.ReadUInt16();
        if ((flags & ~KnownFlags) != 0)
        {
            throw InvalidContent("DMC1 flags contain unsupported bits.");
        }

        var messageId = new MessageId(reader.ReadString16("message ID", MaxMessageIdBytes, allowEmpty: false));
        var conversationId = new ConversationId(reader.ReadString16("conversation ID", MaxConversationIdBytes, allowEmpty: false));
        var sender = reader.ReadSessionId("sender");
        var recipient = reader.ReadSessionId("recipient");
        var issuedAt = ReadTimestamp(reader.ReadInt64(), "issued time");
        var protocolExpiresAt = ReadTimestamp(reader.ReadInt64(), "protocol expiry");
        DateTimeOffset? userExpiresAt = (flags & UserExpiryFlag) != 0
            ? ReadTimestamp(reader.ReadInt64(), "user expiry")
            : null;

        if (kind == E2eeContentKind.GroupState)
        {
            if (flags != 0)
            {
                throw InvalidContent("DMC1 group state flags are invalid.");
            }

            var group = ReadGroupState(ref reader, conversationId);
            if (!reader.IsAtEnd)
            {
                throw InvalidContent("DMC1 group state has trailing bytes.");
            }

            var groupStateContent = new E2eeContent(
                kind,
                messageId,
                conversationKind,
                conversationId,
                sender,
                recipient,
                issuedAt,
                protocolExpiresAt,
                userExpiresAt,
                string.Empty,
                [],
                GroupState: group);
            ValidateDecoded(groupStateContent, now, maxFutureSkew);
            return groupStateContent;
        }

        if (kind == E2eeContentKind.GroupRoutes)
        {
            if (flags != 0)
            {
                throw InvalidContent("DMC1 group routes flags are invalid.");
            }

            var bundleLength = reader.ReadUInt32Length("group routes", GroupMailboxRouteBundleCodec.MaximumEncodedBytes);
            var bundle = GroupMailboxRouteBundleCodec.Decode(reader.ReadSpan(bundleLength));
            if (!reader.IsAtEnd)
            {
                throw InvalidContent("DMC1 group routes have trailing bytes.");
            }

            var groupRoutesContent = new E2eeContent(
                kind,
                messageId,
                conversationKind,
                conversationId,
                sender,
                recipient,
                issuedAt,
                protocolExpiresAt,
                userExpiresAt,
                string.Empty,
                [],
                GroupRoutes: bundle);
            ValidateDecoded(groupRoutesContent, now, maxFutureSkew);
            return groupRoutesContent;
        }

        var body = reader.ReadString32("body", MaxBodyBytes, allowEmpty: true);

        var attachmentCount = reader.ReadUInt16();
        if (attachmentCount > MaxAttachments)
        {
            throw InvalidContent("DMC1 attachment count exceeds the limit.");
        }

        var attachments = new AttachmentMetadata[attachmentCount];
        for (var index = 0; index < attachments.Length; index++)
        {
            attachments[index] = ReadAttachment(ref reader);
        }

        MessageReply? reply = null;
        if ((flags & ReplyFlag) != 0)
        {
            reply = new MessageReply(
                new MessageId(reader.ReadString16("reply message ID", MaxMessageIdBytes, allowEmpty: false)),
                reader.ReadSessionId("reply sender"),
                reader.ReadString16("reply quote", MaxReplyQuoteBytes, allowEmpty: true));
        }

        MessageReactionUpdate? reaction = null;
        if (kind == E2eeContentKind.Reaction)
        {
            reaction = new MessageReactionUpdate(
                new MessageId(reader.ReadString16("reaction target", MaxMessageIdBytes, allowEmpty: false)),
                reader.ReadString16("reaction", MaxReactionBytes, allowEmpty: false),
                reader.ReadBoolean("reaction remove"));
        }

        long? groupRevision = (flags & GroupRevisionFlag) != 0 ? reader.ReadInt64() : null;
        if (!reader.IsAtEnd)
        {
            throw InvalidContent("DMC1 content has trailing bytes.");
        }

        var content = new E2eeContent(
            kind,
            messageId,
            conversationKind,
            conversationId,
            sender,
            recipient,
            issuedAt,
            protocolExpiresAt,
            userExpiresAt,
            body,
            attachments,
            reply,
            reaction,
            groupRevision);

        ValidateDecoded(content, now, maxFutureSkew);
        return content;
    }

    private static void ValidateForEncoding(E2eeContent content)
    {
        ValidateContentKind(content.Kind, nameof(content.Kind));
        ValidateConversation(content.ConversationKind, content.ConversationId, content.Sender, content.Recipient, content.GroupRevision, false);
        ValidateNfcString(content.MessageId.Value, nameof(content.MessageId), MaxMessageIdBytes, allowEmpty: false);
        ValidateNfcString(content.Body, nameof(content.Body), MaxBodyBytes, allowEmpty: true);

        if (content.ProtocolExpiresAt <= content.IssuedAt ||
            content.ProtocolExpiresAt - content.IssuedAt > MaxProtocolLifetime)
        {
            throw new ArgumentException("Protocol expiry must be later than issue time and no more than 7 days later.", nameof(content));
        }

        if (content.UserExpiresAt is { } userExpiry &&
            (userExpiry <= content.IssuedAt || userExpiry > content.ProtocolExpiresAt))
        {
            throw new ArgumentException("User expiry must be later than issue time and no later than protocol expiry.", nameof(content));
        }

        if (content.Attachments is null || content.Attachments.Count > MaxAttachments)
        {
            throw new ArgumentOutOfRangeException(nameof(content.Attachments));
        }

        foreach (var attachment in content.Attachments)
        {
            ValidateAttachment(attachment, false);
        }

        if (content.Reply is { } reply)
        {
            ValidateNfcString(reply.MessageId.Value, nameof(reply.MessageId), MaxMessageIdBytes, allowEmpty: false);
            ValidateStandardSessionId(reply.Sender, nameof(reply.Sender));
            ValidateNfcString(reply.Body, nameof(reply.Body), MaxReplyQuoteBytes, allowEmpty: true);
        }

        ValidatePayloadShape(content, false);
        if (content.GroupState is { } group)
        {
            ValidateGroupState(group, content.ConversationId, content.IssuedAt, false);
        }
    }

    private static void ValidateDecoded(E2eeContent content, DateTimeOffset now, TimeSpan maxFutureSkew)
    {
        ValidateConversation(content.ConversationKind, content.ConversationId, content.Sender, content.Recipient, content.GroupRevision, true);
        ValidatePayloadShape(content, true);
        if (content.GroupState is { } group)
        {
            ValidateGroupState(group, content.ConversationId, content.IssuedAt, true);
        }

        if (content.ProtocolExpiresAt <= content.IssuedAt ||
            content.ProtocolExpiresAt - content.IssuedAt > MaxProtocolLifetime ||
            content.ProtocolExpiresAt <= now)
        {
            throw InvalidContent("DMC1 protocol expiry is invalid or has elapsed.");
        }

        if (content.UserExpiresAt is { } userExpiry &&
            (userExpiry <= content.IssuedAt || userExpiry > content.ProtocolExpiresAt || userExpiry <= now))
        {
            throw InvalidContent("DMC1 user expiry is invalid or has elapsed.");
        }

        DateTimeOffset latestIssueTime;
        try
        {
            latestIssueTime = now.Add(maxFutureSkew);
        }
        catch (ArgumentOutOfRangeException ex)
        {
            throw new E2eeProtocolException("DMC1 future-skew window is invalid.", ex);
        }

        if (content.IssuedAt > latestIssueTime)
        {
            throw InvalidContent("DMC1 issue time is too far in the future.");
        }
    }

    private static void ValidatePayloadShape(E2eeContent content, bool inbound)
    {
        Func<string, Exception> invalid = inbound
            ? static message => InvalidContent(message)
            : static message => new ArgumentException(message, nameof(content));

        if (content.Kind == E2eeContentKind.Message)
        {
            if (content.GroupState is not null || content.GroupRoutes is not null || content.Reaction is not null ||
                (content.Body.Length == 0 && content.Attachments.Count == 0))
            {
                throw invalid("DMC1 message payload shape is invalid.");
            }

            return;
        }

        if (content.Kind == E2eeContentKind.Reaction)
        {
            if (content.GroupState is not null || content.GroupRoutes is not null || content.Reaction is null || content.Body.Length != 0 ||
                content.Attachments.Count != 0 || content.Reply is not null)
            {
                throw invalid("DMC1 reaction payload shape is invalid.");
            }

            return;
        }

        if (content.Kind == E2eeContentKind.GroupRoutes)
        {
            if (content.GroupState is not null || content.GroupRoutes is null
                || content.GroupRoutes.GroupId != content.ConversationId
                || content.ConversationKind != ConversationKind.GroupV2
                || content.Body.Length != 0 || content.Attachments.Count != 0 || content.Reply is not null
                || content.Reaction is not null || content.GroupRevision is not null || content.UserExpiresAt is not null)
            {
                throw invalid("DMC1 group-routes payload shape is invalid.");
            }

            return;
        }

        if (content.GroupState is null || content.GroupRoutes is not null || content.ConversationKind != ConversationKind.GroupV2 ||
            content.Body.Length != 0 || content.Attachments.Count != 0 || content.Reply is not null ||
            content.Reaction is not null || content.GroupRevision is not null || content.UserExpiresAt is not null)
        {
            throw invalid("DMC1 group-state payload shape is invalid.");
        }
    }

    private static void ValidateConversation(
        ConversationKind kind,
        ConversationId conversationId,
        SessionId sender,
        SessionId recipient,
        long? groupRevision,
        bool inbound)
    {
        Exception Invalid(string message) => inbound
            ? InvalidContent(message)
            : new ArgumentException(message, nameof(conversationId));

        ValidateNfcString(conversationId.Value, nameof(conversationId), MaxConversationIdBytes, allowEmpty: false, inbound);
        ValidateStandardSessionId(sender, nameof(sender), inbound);
        var canonicalRecipient = ValidateStandardSessionId(recipient, nameof(recipient), inbound);

        if (kind == ConversationKind.OneToOne)
        {
            if (!string.Equals(conversationId.Value, canonicalRecipient.Value, StringComparison.Ordinal) || groupRevision is not null)
            {
                throw Invalid("DMC1 one-to-one conversation binding is invalid.");
            }

            return;
        }

        if (kind != ConversationKind.GroupV2 || !IsCanonicalGroupId(conversationId.Value) || groupRevision is < 0)
        {
            throw Invalid("DMC1 group conversation metadata is invalid.");
        }
    }

    private static byte[] FinishEncoding(ArrayBufferWriter<byte> writer, E2eeContent content)
    {
        if (writer.WrittenCount > E2eeEnvelopeCodec.MaxPlaintextBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(content), "DMC1 content exceeds the DPE1 plaintext limit.");
        }

        return writer.WrittenSpan.ToArray();
    }

    private static void WriteGroupState(ArrayBufferWriter<byte> writer, Group group)
    {
        WriteString16(writer, group.Name, nameof(group.Name), MaxGroupNameBytes, allowEmpty: false);
        WriteSessionId(writer, group.CreatedBy, nameof(group.CreatedBy));
        WriteInt64(writer, group.CreatedAt.ToUnixTimeMilliseconds());
        WriteInt64(writer, group.Revision);

        var groupFlags = (byte)0;
        if (group.IsDestroyed)
        {
            groupFlags |= DestroyedGroupFlag;
        }

        if (group.IsKicked)
        {
            groupFlags |= KickedGroupFlag;
        }

        WriteByte(writer, groupFlags);
        WriteUInt16(writer, checked((ushort)group.Members.Count));
        foreach (var member in group.Members)
        {
            WriteSessionId(writer, member.SessionId, nameof(member.SessionId));
            WriteByte(writer, EncodeGroupMemberRole(member.Role));
            WriteInt64(writer, member.JoinedAt.ToUnixTimeMilliseconds());
            WriteByte(writer, member.IsPendingRemoval ? PendingRemovalMemberFlag : (byte)0);
        }
    }

    public static byte[] ComputeGroupMembershipDigest(Group group)
    {
        ArgumentNullException.ThrowIfNull(group);
        ValidateGroupState(group, group.Id, DateTimeOffset.MaxValue, inbound: false);
        var writer = new ArrayBufferWriter<byte>();
        WriteString16(writer, group.Id.Value, nameof(group.Id), MaxConversationIdBytes, allowEmpty: false);
        WriteGroupState(writer, group with { IsKicked = false });
        return SHA256.HashData(writer.WrittenSpan);
    }

    private static Group ReadGroupState(ref ContentReader reader, ConversationId groupId)
    {
        var name = reader.ReadString16("group name", MaxGroupNameBytes, allowEmpty: false);
        var createdBy = reader.ReadSessionId("group creator");
        var createdAt = ReadTimestamp(reader.ReadInt64(), "group creation time");
        var revision = reader.ReadInt64();
        var groupFlags = reader.ReadByte();
        if ((groupFlags & ~KnownGroupFlags) != 0)
        {
            throw InvalidContent("DMC1 group flags contain unsupported bits.");
        }

        var memberCount = reader.ReadUInt16();
        if (memberCount > MaxGroupMembers)
        {
            throw InvalidContent("DMC1 group member count exceeds the limit.");
        }

        var members = new GroupMember[memberCount];
        for (var index = 0; index < members.Length; index++)
        {
            var sessionId = reader.ReadSessionId("group member");
            var role = DecodeGroupMemberRole(reader.ReadByte());
            var joinedAt = ReadTimestamp(reader.ReadInt64(), "group member join time");
            var memberFlags = reader.ReadByte();
            if ((memberFlags & ~KnownMemberFlags) != 0)
            {
                throw InvalidContent("DMC1 group member flags contain unsupported bits.");
            }

            members[index] = new GroupMember(
                sessionId,
                role,
                joinedAt,
                (memberFlags & PendingRemovalMemberFlag) != 0);
        }

        return new Group(
            groupId,
            name,
            createdBy,
            createdAt,
            members,
            (groupFlags & DestroyedGroupFlag) != 0,
            (groupFlags & KickedGroupFlag) != 0,
            revision);
    }

    private static void ValidateGroupState(
        Group group,
        ConversationId conversationId,
        DateTimeOffset updatedAt,
        bool inbound)
    {
        Exception Invalid(string message) => inbound
            ? InvalidContent(message)
            : new ArgumentException(message, nameof(group));

        if (group.Id != conversationId || group.Revision < 1 || group.CreatedAt > updatedAt ||
            group.Members is null || group.Members.Count > MaxGroupMembers)
        {
            throw Invalid("DMC1 group state metadata is invalid.");
        }

        ValidateNfcString(group.Name, nameof(group.Name), MaxGroupNameBytes, allowEmpty: false, inbound);
        ValidateStandardSessionId(group.CreatedBy, nameof(group.CreatedBy), inbound);

        var memberIds = new HashSet<SessionId>();
        foreach (var member in group.Members)
        {
            ValidateStandardSessionId(member.SessionId, nameof(member.SessionId), inbound);
            if (!memberIds.Add(member.SessionId) || member.JoinedAt < group.CreatedAt || member.JoinedAt > updatedAt ||
                member.Role is not GroupMemberRole.Standard and not GroupMemberRole.Admin)
            {
                throw Invalid("DMC1 group member state is invalid.");
            }
        }
    }

    private static void WriteAttachment(ArrayBufferWriter<byte> writer, AttachmentMetadata attachment)
    {
        WriteString16(writer, attachment.AttachmentId, nameof(attachment.AttachmentId), MaxAttachmentIdBytes, allowEmpty: false);
        WriteString16(writer, attachment.FileName, nameof(attachment.FileName), MaxFilenameBytes, allowEmpty: false);
        WriteString16(writer, attachment.ContentType, nameof(attachment.ContentType), MaxMimeTypeBytes, allowEmpty: false);
        WriteInt64(writer, attachment.SizeBytes);
        WriteString16(writer, attachment.RemoteUri!.OriginalString, nameof(attachment.RemoteUri), MaxUriBytes, allowEmpty: false);
        WriteString16(writer, attachment.EncryptionKeyBase64!, nameof(attachment.EncryptionKeyBase64), MaxBase64Bytes, allowEmpty: false);
        WriteString16(writer, attachment.DigestBase64!, nameof(attachment.DigestBase64), MaxBase64Bytes, allowEmpty: false);
        WriteInt32(writer, attachment.Width ?? -1);
        WriteInt32(writer, attachment.Height ?? -1);
        WriteInt64(writer, attachment.Duration?.Ticks ?? -1);
        WriteByte(writer, attachment.IsDocument ? (byte)1 : (byte)0);
        WriteByte(writer, EncodeAttachmentKind(attachment.Kind));
    }

    private static AttachmentMetadata ReadAttachment(ref ContentReader reader)
    {
        var attachment = new AttachmentMetadata(
            reader.ReadString16("attachment ID", MaxAttachmentIdBytes, allowEmpty: false),
            reader.ReadString16("filename", MaxFilenameBytes, allowEmpty: false),
            reader.ReadString16("MIME type", MaxMimeTypeBytes, allowEmpty: false),
            reader.ReadInt64(),
            new Uri(reader.ReadString16("attachment URI", MaxUriBytes, allowEmpty: false), UriKind.Absolute),
            reader.ReadString16("attachment encryption key", MaxBase64Bytes, allowEmpty: false),
            reader.ReadString16("attachment digest", MaxBase64Bytes, allowEmpty: false),
            DecodeOptionalNonNegative(reader.ReadInt32(), "attachment width"),
            DecodeOptionalNonNegative(reader.ReadInt32(), "attachment height"),
            DecodeDuration(reader.ReadInt64()),
            reader.ReadBoolean("attachment document flag"),
            DecodeAttachmentKind(reader.ReadByte()));

        ValidateAttachment(attachment, true);
        return attachment;
    }

    private static void ValidateAttachment(AttachmentMetadata? attachment, bool inbound)
    {
        Exception Invalid(string message) => inbound
            ? InvalidContent(message)
            : new ArgumentException(message, nameof(attachment));

        if (attachment is null)
        {
            throw Invalid("DMC1 attachment metadata is required.");
        }

        ValidateNfcString(attachment.AttachmentId, nameof(attachment.AttachmentId), MaxAttachmentIdBytes, allowEmpty: false, inbound);
        ValidateNfcString(attachment.FileName, nameof(attachment.FileName), MaxFilenameBytes, allowEmpty: false, inbound);
        ValidateNfcString(attachment.ContentType, nameof(attachment.ContentType), MaxMimeTypeBytes, allowEmpty: false, inbound);

        if (attachment.SizeBytes < 0 || attachment.RemoteUri is null || !attachment.RemoteUri.IsAbsoluteUri ||
            attachment.Width is < 0 || attachment.Height is < 0 || attachment.Duration is { } duration && duration < TimeSpan.Zero)
        {
            throw Invalid("DMC1 attachment values are invalid.");
        }

        if (attachment.Kind is not AttachmentKind.File and not AttachmentKind.VoiceMessage ||
            attachment.Kind == AttachmentKind.VoiceMessage &&
            (!attachment.ContentType.StartsWith("audio/", StringComparison.OrdinalIgnoreCase) ||
             attachment.Duration is not { } voiceDuration || voiceDuration <= TimeSpan.Zero ||
             attachment.IsDocument))
        {
            throw Invalid("DMC1 attachment kind is invalid.");
        }

        ValidateNfcString(attachment.RemoteUri.OriginalString, nameof(attachment.RemoteUri), MaxUriBytes, allowEmpty: false, inbound);
        ValidateBase64Key(attachment.EncryptionKeyBase64, "attachment encryption key", inbound);
        ValidateBase64Key(attachment.DigestBase64, "attachment digest", inbound);
    }

    private static void ValidateBase64Key(string? encoded, string fieldName, bool inbound)
    {
        if (string.IsNullOrWhiteSpace(encoded) || encoded.Length > MaxBase64Bytes)
        {
            if (inbound)
            {
                throw InvalidContent($"DMC1 {fieldName} is invalid.");
            }

            throw new ArgumentException($"DMC1 {fieldName} is invalid.", fieldName);
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(encoded);
        }
        catch (FormatException ex)
        {
            if (inbound)
            {
                throw new E2eeProtocolException($"DMC1 {fieldName} is invalid.", ex);
            }

            throw new ArgumentException($"DMC1 {fieldName} is invalid.", fieldName, ex);
        }

        try
        {
            if (decoded.Length != 32)
            {
                if (inbound)
                {
                    throw InvalidContent($"DMC1 {fieldName} length is invalid.");
                }

                throw new ArgumentException($"DMC1 {fieldName} length is invalid.", fieldName);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    private static void WriteSessionId(ArrayBufferWriter<byte> writer, SessionId sessionId, string fieldName)
    {
        var parsed = ValidateStandardSessionId(sessionId, fieldName);
        WriteBytes(writer, Convert.FromHexString(parsed.Value));
    }

    private static SessionId ValidateStandardSessionId(SessionId sessionId, string fieldName, bool inbound = false)
    {
        try
        {
            var parsed = SessionId.Parse(sessionId.Value);
            if (!parsed.Value.StartsWith("05", StringComparison.Ordinal))
            {
                throw new ArgumentException("Only standard 05 Session IDs are supported.", fieldName);
            }

            return parsed;
        }
        catch (ArgumentException ex)
        {
            if (inbound)
            {
                throw new E2eeProtocolException($"DMC1 {fieldName} Session ID is invalid.", ex);
            }

            throw;
        }
    }

    private static void ValidateNfcString(
        string? value,
        string fieldName,
        int maxBytes,
        bool allowEmpty,
        bool inbound = false)
    {
        var valid = value is not null && (allowEmpty || value.Length > 0) && value.IsNormalized(NormalizationForm.FormC);
        if (valid)
        {
            try
            {
                valid = StrictUtf8.GetByteCount(value!) <= maxBytes;
            }
            catch (EncoderFallbackException)
            {
                valid = false;
            }
        }

        if (valid)
        {
            return;
        }

        if (inbound)
        {
            throw InvalidContent($"DMC1 {fieldName} is not strict UTF-8 NFC or exceeds its limit.");
        }

        throw new ArgumentException($"DMC1 {fieldName} must be strict UTF-8 NFC within {maxBytes} bytes.", fieldName);
    }

    private static bool IsCanonicalGroupId(string value) =>
        value.Length == 66 &&
        value.StartsWith("03", StringComparison.Ordinal) &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static byte EncodeGroupMemberRole(GroupMemberRole role) => role switch
    {
        GroupMemberRole.Standard => 0,
        GroupMemberRole.Admin => 1,
        _ => throw new ArgumentOutOfRangeException(nameof(role), "DMC1 group member role is not supported.")
    };

    private static GroupMemberRole DecodeGroupMemberRole(byte value) => value switch
    {
        0 => GroupMemberRole.Standard,
        1 => GroupMemberRole.Admin,
        _ => throw InvalidContent("DMC1 group member role is not supported.")
    };

    private static byte EncodeAttachmentKind(AttachmentKind kind) => kind switch
    {
        AttachmentKind.File => 0,
        AttachmentKind.VoiceMessage => 1,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), "DMC1 attachment kind is not supported.")
    };

    private static AttachmentKind DecodeAttachmentKind(byte value) => value switch
    {
        0 => AttachmentKind.File,
        1 => AttachmentKind.VoiceMessage,
        _ => throw InvalidContent("DMC1 attachment kind is not supported.")
    };

    private static byte EncodeConversationKind(ConversationKind kind) => kind switch
    {
        ConversationKind.OneToOne => 1,
        ConversationKind.GroupV2 => 2,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), "DMC1 supports only one-to-one and group-v2 conversations.")
    };

    private static ConversationKind DecodeConversationKind(byte value) => value switch
    {
        1 => ConversationKind.OneToOne,
        2 => ConversationKind.GroupV2,
        _ => throw InvalidContent("DMC1 conversation kind is not supported.")
    };

    private static E2eeContentKind DecodeContentKind(byte value) => value switch
    {
        1 => E2eeContentKind.Message,
        2 => E2eeContentKind.Reaction,
        3 => E2eeContentKind.GroupState,
        4 => E2eeContentKind.GroupRoutes,
        _ => throw InvalidContent("DMC1 content kind is not supported.")
    };

    private static void ValidateContentKind(E2eeContentKind kind, string fieldName)
    {
        if (kind is not E2eeContentKind.Message and not E2eeContentKind.Reaction
            and not E2eeContentKind.GroupState and not E2eeContentKind.GroupRoutes)
        {
            throw new ArgumentOutOfRangeException(fieldName, "DMC1 content kind is not supported.");
        }
    }

    private static DateTimeOffset ReadTimestamp(long unixMilliseconds, string fieldName)
    {
        try
        {
            return DateTimeOffset.FromUnixTimeMilliseconds(unixMilliseconds);
        }
        catch (ArgumentOutOfRangeException ex)
        {
            throw new E2eeProtocolException($"DMC1 {fieldName} is out of range.", ex);
        }
    }

    private static int? DecodeOptionalNonNegative(int value, string fieldName)
    {
        if (value == -1)
        {
            return null;
        }

        if (value < 0)
        {
            throw InvalidContent($"DMC1 {fieldName} is invalid.");
        }

        return value;
    }

    private static TimeSpan? DecodeDuration(long ticks)
    {
        if (ticks == -1)
        {
            return null;
        }

        if (ticks < 0)
        {
            throw InvalidContent("DMC1 attachment duration is invalid.");
        }

        return TimeSpan.FromTicks(ticks);
    }

    private static void WriteString16(ArrayBufferWriter<byte> writer, string value, string fieldName, int maxBytes, bool allowEmpty)
    {
        ValidateNfcString(value, fieldName, maxBytes, allowEmpty);
        var byteCount = StrictUtf8.GetByteCount(value);
        WriteUInt16(writer, checked((ushort)byteCount));
        var destination = writer.GetSpan(byteCount);
        StrictUtf8.GetBytes(value, destination);
        writer.Advance(byteCount);
    }

    private static void WriteString32(ArrayBufferWriter<byte> writer, string value, string fieldName, int maxBytes, bool allowEmpty)
    {
        ValidateNfcString(value, fieldName, maxBytes, allowEmpty);
        var byteCount = StrictUtf8.GetByteCount(value);
        WriteUInt32(writer, checked((uint)byteCount));
        var destination = writer.GetSpan(byteCount);
        StrictUtf8.GetBytes(value, destination);
        writer.Advance(byteCount);
    }

    private static void WriteByte(ArrayBufferWriter<byte> writer, byte value)
    {
        var destination = writer.GetSpan(1);
        destination[0] = value;
        writer.Advance(1);
    }

    private static void WriteUInt16(ArrayBufferWriter<byte> writer, ushort value)
    {
        var destination = writer.GetSpan(sizeof(ushort));
        BinaryPrimitives.WriteUInt16BigEndian(destination, value);
        writer.Advance(sizeof(ushort));
    }

    private static void WriteUInt32(ArrayBufferWriter<byte> writer, uint value)
    {
        var destination = writer.GetSpan(sizeof(uint));
        BinaryPrimitives.WriteUInt32BigEndian(destination, value);
        writer.Advance(sizeof(uint));
    }

    private static void WriteInt32(ArrayBufferWriter<byte> writer, int value)
    {
        var destination = writer.GetSpan(sizeof(int));
        BinaryPrimitives.WriteInt32BigEndian(destination, value);
        writer.Advance(sizeof(int));
    }

    private static void WriteInt64(ArrayBufferWriter<byte> writer, long value)
    {
        var destination = writer.GetSpan(sizeof(long));
        BinaryPrimitives.WriteInt64BigEndian(destination, value);
        writer.Advance(sizeof(long));
    }

    private static void WriteBytes(ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> value)
    {
        value.CopyTo(writer.GetSpan(value.Length));
        writer.Advance(value.Length);
    }

    private static E2eeProtocolException InvalidContent(string message) => new(message);

    private ref struct ContentReader
    {
        private readonly ReadOnlySpan<byte> encoded;
        private int offset;

        public ContentReader(ReadOnlySpan<byte> encoded)
        {
            this.encoded = encoded;
            offset = 0;
        }

        public bool IsAtEnd => offset == encoded.Length;

        public ReadOnlySpan<byte> ReadSpan(int length)
        {
            if (length < 0 || length > encoded.Length - offset)
            {
                throw InvalidContent("DMC1 content is truncated.");
            }

            var value = encoded.Slice(offset, length);
            offset += length;
            return value;
        }

        public byte ReadByte() => ReadSpan(1)[0];

        public bool ReadBoolean(string fieldName) => ReadByte() switch
        {
            0 => false,
            1 => true,
            _ => throw InvalidContent($"DMC1 {fieldName} is invalid.")
        };

        public ushort ReadUInt16() => BinaryPrimitives.ReadUInt16BigEndian(ReadSpan(sizeof(ushort)));

        public int ReadInt32() => BinaryPrimitives.ReadInt32BigEndian(ReadSpan(sizeof(int)));

        public long ReadInt64() => BinaryPrimitives.ReadInt64BigEndian(ReadSpan(sizeof(long)));

        public string ReadString16(string fieldName, int maxBytes, bool allowEmpty) =>
            ReadString(ReadUInt16(), fieldName, maxBytes, allowEmpty);

        public string ReadString32(string fieldName, int maxBytes, bool allowEmpty)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(ReadSpan(sizeof(uint)));
            if (length > int.MaxValue)
            {
                throw InvalidContent($"DMC1 {fieldName} length is invalid.");
            }

            return ReadString((int)length, fieldName, maxBytes, allowEmpty);
        }

        public int ReadUInt32Length(string fieldName, int maxBytes)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(ReadSpan(sizeof(uint)));
            if (length > maxBytes)
            {
                throw InvalidContent($"DMC1 {fieldName} length is invalid.");
            }

            return checked((int)length);
        }

        public SessionId ReadSessionId(string fieldName)
        {
            var bytes = ReadSpan(SessionIdSize);
            if (bytes[0] != 0x05)
            {
                throw InvalidContent($"DMC1 {fieldName} Session ID is invalid.");
            }

            return SessionId.Parse(Convert.ToHexStringLower(bytes));
        }

        private string ReadString(int length, string fieldName, int maxBytes, bool allowEmpty)
        {
            if (length > maxBytes || (!allowEmpty && length == 0))
            {
                throw InvalidContent($"DMC1 {fieldName} length is invalid.");
            }

            var value = StrictUtf8.GetString(ReadSpan(length));
            ValidateNfcString(value, fieldName, maxBytes, allowEmpty, inbound: true);
            return value;
        }
    }
}
