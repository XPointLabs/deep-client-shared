using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class E2eeContentCodecTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-10T10:00:00Z");
    private static readonly SessionId Alice = SessionId.Parse("05" + new string('a', 64));
    private static readonly SessionId Bob = SessionId.Parse("05" + new string('b', 64));
    private static readonly ConversationId Group = ConversationId.Parse("03" + new string('c', 64));

    [Fact]
    public void OneToOneMessage_RoundTripsReplyAndExpiries()
    {
        var content = CreateDirectMessage() with
        {
            UserExpiresAt = Now.AddHours(1),
            Reply = new MessageReply(new MessageId("prior-message"), Bob, "quoted reply")
        };

        var decoded = RoundTrip(content);

        Assert.Equal(content.Kind, decoded.Kind);
        Assert.Equal(content.MessageId, decoded.MessageId);
        Assert.Equal(content.ConversationKind, decoded.ConversationKind);
        Assert.Equal(content.ConversationId, decoded.ConversationId);
        Assert.Equal(content.Sender, decoded.Sender);
        Assert.Equal(content.Recipient, decoded.Recipient);
        Assert.Equal(content.IssuedAt, decoded.IssuedAt);
        Assert.Equal(content.ProtocolExpiresAt, decoded.ProtocolExpiresAt);
        Assert.Equal(content.UserExpiresAt, decoded.UserExpiresAt);
        Assert.Equal(content.Body, decoded.Body);
        Assert.Equal(content.Reply, decoded.Reply);
        Assert.Empty(decoded.Attachments);
        Assert.Null(decoded.Reaction);
        Assert.Null(decoded.GroupRevision);
    }

    [Fact]
    public void GroupMessage_RoundTripsAttachmentMetadataAndRevision()
    {
        var attachment = CreateAttachment();
        var content = CreateDirectMessage() with
        {
            MessageId = new MessageId("group-message"),
            ConversationKind = ConversationKind.GroupV2,
            ConversationId = Group,
            Body = "report attached",
            Attachments = [attachment],
            GroupRevision = 42
        };

        var decoded = RoundTrip(content);
        var decodedAttachment = Assert.Single(decoded.Attachments);

        Assert.Equal(ConversationKind.GroupV2, decoded.ConversationKind);
        Assert.Equal(Group, decoded.ConversationId);
        Assert.Equal(42, decoded.GroupRevision);
        Assert.Equal(attachment, decodedAttachment);
    }

    [Fact]
    public void DirectMessage_RoundTripsExplicitVoiceAttachmentKind()
    {
        var voice = new AttachmentMetadata(
            "voice-attachment-001",
            "voice-message.wav",
            "audio/wav",
            8_192,
            new Uri("https://files.example.test/download/voice-attachment-001"),
            Convert.ToBase64String(Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray()),
            Convert.ToBase64String(Enumerable.Range(32, 32).Select(static value => (byte)value).ToArray()),
            Duration: TimeSpan.FromSeconds(4),
            Kind: AttachmentKind.VoiceMessage);
        var content = CreateDirectMessage() with
        {
            Body = "[Голосовое сообщение]",
            Attachments = [voice]
        };

        var decoded = RoundTrip(content);

        Assert.Equal(E2eeContentCodec.ProtocolVersion, 2);
        Assert.Equal(voice, Assert.Single(decoded.Attachments));
        Assert.Equal(AttachmentKind.VoiceMessage, decoded.Attachments[0].Kind);
    }

    [Theory]
    [InlineData("application/octet-stream", 4, false)]
    [InlineData("audio/wav", 0, false)]
    [InlineData("audio/wav", 4, true)]
    public void Encode_RejectsInvalidVoiceAttachmentShape(string contentType, int durationSeconds, bool isDocument)
    {
        var invalidVoice = CreateAttachment() with
        {
            ContentType = contentType,
            Duration = TimeSpan.FromSeconds(durationSeconds),
            IsDocument = isDocument,
            Kind = AttachmentKind.VoiceMessage
        };
        var content = CreateDirectMessage() with { Attachments = [invalidVoice] };

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(content));
    }

    [Fact]
    public void Decode_RejectsUnknownAttachmentKind()
    {
        var voice = CreateAttachment() with
        {
            ContentType = "audio/wav",
            Duration = TimeSpan.FromSeconds(4),
            IsDocument = false,
            Kind = AttachmentKind.VoiceMessage
        };
        var encoded = E2eeContentCodec.Encode(CreateDirectMessage() with { Attachments = [voice] });
        encoded[^1] = 0xff;

        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(encoded, Now));
    }

    [Fact]
    public void Encode_RejectsUnknownAttachmentKind()
    {
        var attachment = CreateAttachment() with { Kind = (AttachmentKind)0xff };

        Assert.Throws<ArgumentException>(() =>
            E2eeContentCodec.Encode(CreateDirectMessage() with { Attachments = [attachment] }));
    }

    [Fact]
    public void Decode_RejectsAttachmentMissingRequiredKindByte()
    {
        var voice = CreateAttachment() with
        {
            ContentType = "audio/wav",
            Duration = TimeSpan.FromSeconds(4),
            IsDocument = false,
            Kind = AttachmentKind.VoiceMessage
        };
        var encoded = E2eeContentCodec.Encode(CreateDirectMessage() with { Attachments = [voice] });

        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(encoded[..^1], Now));
    }

    [Theory]
    [InlineData(ConversationKind.OneToOne, false)]
    [InlineData(ConversationKind.OneToOne, true)]
    [InlineData(ConversationKind.GroupV2, false)]
    [InlineData(ConversationKind.GroupV2, true)]
    public void Reaction_RoundTripsForDirectAndGroupConversations(ConversationKind conversationKind, bool remove)
    {
        var content = CreateDirectMessage() with
        {
            Kind = E2eeContentKind.Reaction,
            MessageId = new MessageId("reaction-update"),
            ConversationKind = conversationKind,
            ConversationId = conversationKind == ConversationKind.GroupV2 ? Group : ConversationId.ForOneToOne(Bob),
            Body = string.Empty,
            Reaction = new MessageReactionUpdate(new MessageId("target-message"), "👍", remove),
            GroupRevision = conversationKind == ConversationKind.GroupV2 ? 9 : null
        };

        var decoded = RoundTrip(content);

        Assert.Equal(E2eeContentKind.Reaction, decoded.Kind);
        Assert.Equal(content.Reaction, decoded.Reaction);
        Assert.Equal(content.GroupRevision, decoded.GroupRevision);
        Assert.Empty(decoded.Attachments);
        Assert.Empty(decoded.Body);
    }

    [Fact]
    public void DmcContent_RoundTripsInsideEncryptedEnvelopeWithoutLeakingMarker()
    {
        const string alicePhrase = "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed";
        const string bobPhrase = "update vague zinger boxes ornament renting glass gained island nabbing afield calamity nabbing";
        using var alice = new SessionIdentityProvider(alicePhrase);
        using var bob = new SessionIdentityProvider(bobPhrase);
        var marker = "encrypted-content-marker-49125";
        var content = CreateDirectMessage() with
        {
            Sender = alice.SessionId,
            Recipient = bob.SessionId,
            ConversationId = ConversationId.ForOneToOne(bob.SessionId),
            Body = marker
        };
        var envelope = alice.CreateEnvelopeCodec().EncryptContent(content);
        var authenticated = bob.CreateEnvelopeCodec().DecryptContent(envelope, Now);
        var decoded = authenticated.Content;

        Assert.Equal(marker, decoded.Body);
        Assert.Equal(alice.SessionId, authenticated.Envelope.Sender);
        Assert.Equal(bob.SessionId, authenticated.Envelope.Recipient);
        Assert.False(ContainsSequence(envelope, Encoding.UTF8.GetBytes(marker)));
    }

    [Fact]
    public void ContentEnvelopeConvenienceApi_BindsSenderAndKindButAllowsSenderCopyRecipient()
    {
        const string alicePhrase = "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed";
        const string bobPhrase = "update vague zinger boxes ornament renting glass gained island nabbing afield calamity nabbing";
        using var alice = new SessionIdentityProvider(alicePhrase);
        using var bob = new SessionIdentityProvider(bobPhrase);
        var aliceCodec = alice.CreateEnvelopeCodec();
        var bobCodec = bob.CreateEnvelopeCodec();
        var valid = CreateDirectMessage() with
        {
            Sender = alice.SessionId,
            Recipient = bob.SessionId,
            ConversationId = ConversationId.ForOneToOne(bob.SessionId)
        };

        Assert.Throws<ArgumentException>(() => aliceCodec.EncryptContent(valid with { Sender = Alice }));

        var wrongSender = E2eeContentCodec.Encode(valid with { Sender = Alice });
        var wrongSenderEnvelope = aliceCodec.Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, wrongSender);
        Assert.Throws<E2eeProtocolException>(() => bobCodec.DecryptContent(wrongSenderEnvelope, Now));

        var senderCopyEnvelope = aliceCodec.EncryptContent(valid, alice.SessionId);
        var senderCopy = aliceCodec.DecryptContent(senderCopyEnvelope, Now);
        Assert.Equal(alice.SessionId, senderCopy.Envelope.Recipient);
        Assert.Equal(bob.SessionId, senderCopy.Content.Recipient);

        var reaction = E2eeContentCodec.Encode(valid with
        {
            Kind = E2eeContentKind.Reaction,
            Body = string.Empty,
            Reaction = new MessageReactionUpdate(new MessageId("target"), "x", false)
        });
        var wrongKindEnvelope = aliceCodec.Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, reaction);
        Assert.Throws<E2eeProtocolException>(() => bobCodec.DecryptContent(wrongKindEnvelope, Now));
    }

    [Fact]
    public void GroupState_RoundTripsCanonicalBinaryState()
    {
        var group = new Group(
            Group,
            "Protocol team",
            Alice,
            Now.AddDays(-10),
            [
                new GroupMember(Alice, GroupMemberRole.Admin, Now.AddDays(-10)),
                new GroupMember(Bob, GroupMemberRole.Standard, Now.AddDays(-3), IsPendingRemoval: true)
            ],
            IsDestroyed: true,
            IsKicked: false,
            Revision: 17);
        var content = new E2eeContent(
            E2eeContentKind.GroupState,
            new MessageId("group-state-17"),
            ConversationKind.GroupV2,
            Group,
            Alice,
            Bob,
            Now,
            Now.Add(E2eeContentCodec.MaxProtocolLifetime),
            null,
            string.Empty,
            [],
            GroupState: group);

        var encoded = E2eeContentCodec.Encode(content);
        var decoded = E2eeContentCodec.Decode(encoded, Now);

        Assert.Equal(E2eeContentKind.GroupState, decoded.Kind);
        Assert.Equal(group.Id, decoded.GroupState?.Id);
        Assert.Equal(group.Name, decoded.GroupState?.Name);
        Assert.Equal(group.CreatedBy, decoded.GroupState?.CreatedBy);
        Assert.Equal(group.CreatedAt, decoded.GroupState?.CreatedAt);
        Assert.Equal(group.Revision, decoded.GroupState?.Revision);
        Assert.Equal(group.IsDestroyed, decoded.GroupState?.IsDestroyed);
        Assert.Equal(group.IsKicked, decoded.GroupState?.IsKicked);
        Assert.Equal(group.Members, decoded.GroupState?.Members);
    }

    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)1)]
    [InlineData((byte)3)]
    [InlineData(byte.MaxValue)]
    public void Decode_RejectsEveryNonCurrentVersion(byte unsupportedVersion)
    {
        var valid = E2eeContentCodec.Encode(CreateDirectMessage());
        var version = valid.ToArray();
        version[4] = unsupportedVersion;

        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(version, Now));
    }

    [Fact]
    public void Decode_RejectsUnknownKindsFlagsTruncationAndTrailingBytes()
    {
        var valid = E2eeContentCodec.Encode(CreateDirectMessage());

        var contentKind = valid.ToArray();
        contentKind[5] = 0xff;
        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(contentKind, Now));

        var conversationKind = valid.ToArray();
        conversationKind[6] = 0xff;
        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(conversationKind, Now));

        var flags = valid.ToArray();
        flags[8] = 0x80;
        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(flags, Now));

        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(valid[..^1], Now));
        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(valid[..20], Now));
        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode([.. valid, 0], Now));
    }

    [Fact]
    public void Decode_RejectsInvalidUtf8AndNonNfcInputIsNotEncoded()
    {
        var content = CreateDirectMessage() with { Body = "unique-valid-body-marker" };
        var encoded = E2eeContentCodec.Encode(content);
        var body = Encoding.UTF8.GetBytes(content.Body);
        var bodyOffset = FindSequence(encoded, body);
        Assert.True(bodyOffset >= 0);
        encoded[bodyOffset] = 0xff;

        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(encoded, Now));
        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(content with { Body = "e\u0301" }));
    }

    [Fact]
    public void Encode_EnforcesBodyAttachmentAndAttachmentFieldLimits()
    {
        var maxBody = new string('x', E2eeContentCodec.MaxBodyBytes);
        Assert.Equal(maxBody, RoundTrip(CreateDirectMessage() with { Body = maxBody }).Body);

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            Body = new string('x', E2eeContentCodec.MaxBodyBytes + 1)
        }));

        var maxAttachments = Enumerable.Repeat(CreateAttachment(), E2eeContentCodec.MaxAttachments).ToArray();
        Assert.Equal(E2eeContentCodec.MaxAttachments, RoundTrip(CreateDirectMessage() with { Attachments = maxAttachments }).Attachments.Count);

        Assert.Throws<ArgumentOutOfRangeException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            Attachments = Enumerable.Repeat(CreateAttachment(), E2eeContentCodec.MaxAttachments + 1).ToArray()
        }));

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            Attachments = [CreateAttachment() with { FileName = new string('x', E2eeContentCodec.MaxFilenameBytes + 1) }]
        }));

        var maxUtf8Filename = new string('é', 127) + "x";
        Assert.Equal(
            maxUtf8Filename,
            Assert.Single(RoundTrip(CreateDirectMessage() with
            {
                Attachments = [CreateAttachment() with { FileName = maxUtf8Filename }]
            }).Attachments).FileName);
        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            Attachments = [CreateAttachment() with { FileName = new string('é', 128) }]
        }));

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            Attachments = [CreateAttachment() with { ContentType = new string('x', E2eeContentCodec.MaxMimeTypeBytes + 1) }]
        }));

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            Attachments = [CreateAttachment() with { RemoteUri = new Uri("https://example.test/" + new string('x', E2eeContentCodec.MaxUriBytes)) }]
        }));
    }

    [Fact]
    public void Encode_EnforcesReplyReactionAndPayloadShapeLimits()
    {
        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            Reply = new MessageReply(new MessageId("target"), Bob, new string('x', E2eeContentCodec.MaxReplyQuoteBytes + 1))
        }));

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateReaction() with
        {
            Reaction = new MessageReactionUpdate(new MessageId("target"), new string('x', E2eeContentCodec.MaxReactionBytes + 1), false)
        }));

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateReaction() with { Body = "not allowed" }));
        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with { Body = string.Empty }));
    }

    [Fact]
    public void Decode_RejectsProtocolAndUserExpiryAndExcessiveFutureSkew()
    {
        var protocolExpired = E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            IssuedAt = Now.AddHours(-2),
            ProtocolExpiresAt = Now
        });
        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(protocolExpired, Now));

        var userExpired = E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            IssuedAt = Now.AddHours(-2),
            UserExpiresAt = Now,
            ProtocolExpiresAt = Now.AddHours(1)
        });
        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(userExpired, Now));

        var future = E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            IssuedAt = Now.AddMinutes(6),
            ProtocolExpiresAt = Now.AddHours(2)
        });
        Assert.Throws<E2eeProtocolException>(() => E2eeContentCodec.Decode(future, Now));
        Assert.Equal(Now.AddMinutes(6), E2eeContentCodec.Decode(future, Now, TimeSpan.FromMinutes(6)).IssuedAt);
    }

    [Fact]
    public void Encode_RejectsInvalidExpiryConversationBindingAndGroupRevision()
    {
        Assert.Equal(TimeSpan.FromDays(7), E2eeContentCodec.MaxProtocolLifetime);
        Assert.NotEmpty(E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            ProtocolExpiresAt = Now.Add(E2eeContentCodec.MaxProtocolLifetime)
        }));

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            ProtocolExpiresAt = Now
        }));

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            ProtocolExpiresAt = Now.Add(E2eeContentCodec.MaxProtocolLifetime).AddMilliseconds(1)
        }));

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            UserExpiresAt = Now.AddHours(3)
        }));

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            ConversationId = ConversationId.ForOneToOne(Alice)
        }));

        Assert.Throws<ArgumentException>(() => E2eeContentCodec.Encode(CreateDirectMessage() with
        {
            ConversationKind = ConversationKind.GroupV2,
            ConversationId = Group,
            GroupRevision = -1
        }));
    }

    private static E2eeContent RoundTrip(E2eeContent content) =>
        E2eeContentCodec.Decode(E2eeContentCodec.Encode(content), Now);

    private static E2eeContent CreateDirectMessage() => new(
        E2eeContentKind.Message,
        new MessageId("message-001"),
        ConversationKind.OneToOne,
        ConversationId.ForOneToOne(Bob),
        Alice,
        Bob,
        Now,
        Now.AddHours(2),
        null,
        "hello Bob",
        []);

    private static E2eeContent CreateReaction() => CreateDirectMessage() with
    {
        Kind = E2eeContentKind.Reaction,
        Body = string.Empty,
        Reaction = new MessageReactionUpdate(new MessageId("target"), "❤️", false)
    };

    private static AttachmentMetadata CreateAttachment() => new(
        "attachment-001",
        "quarterly-report.pdf",
        "application/pdf",
        123_456,
        new Uri("https://files.example.test/download/attachment-001"),
        Convert.ToBase64String(Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray()),
        Convert.ToBase64String(Enumerable.Range(32, 32).Select(static value => (byte)value).ToArray()),
        1920,
        1080,
        TimeSpan.FromSeconds(12),
        true);

    private static int FindSequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (var index = 0; index <= haystack.Length - needle.Length; index++)
        {
            if (haystack.Slice(index, needle.Length).SequenceEqual(needle))
            {
                return index;
            }
        }

        return -1;
    }

    private static bool ContainsSequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) =>
        FindSequence(haystack, needle) >= 0;
}
