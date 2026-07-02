using Deep.Client.Shared.Features;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using System.Text;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ClientRuntimeStorageE2ETests
{
    [Fact]
    public async Task ClientRuntime_RoundTripsOneToOneMessageThroughLiveStorage_WhenConfigured()
    {
        var storageUrl = Environment.GetEnvironmentVariable("DEEP_STORAGE_URL");
        if (string.IsNullOrWhiteSpace(storageUrl))
        {
            return;
        }

        var alice = CreateRuntime(storageUrl);
        var bob = CreateRuntime(storageUrl);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Live");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Live");
        var body = $"client-storage-e2e-{Guid.NewGuid():N}";

        var sent = await alice.Messages.SendOneToOneAsync(aliceAccount.SessionId, bobAccount.SessionId, body);
        var received = await bob.Messages.ReceiveAsync(bobAccount.SessionId);

        Assert.Equal(MessageDeliveryState.Sent, sent.DeliveryState);
        Assert.Contains(received, message =>
            message.Body == body &&
            message.Sender == aliceAccount.SessionId &&
            message.Recipient == bobAccount.SessionId &&
            !string.IsNullOrWhiteSpace(message.ServerHash));
    }

    [Fact]
    public async Task ClientRuntime_RoundTripsRepliesAndReactionsThroughLiveStorage_WhenConfigured()
    {
        var storageUrl = Environment.GetEnvironmentVariable("DEEP_STORAGE_URL");
        if (string.IsNullOrWhiteSpace(storageUrl))
        {
            return;
        }

        var alice = CreateRuntime(storageUrl);
        var bob = CreateRuntime(storageUrl);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Reply Live");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Reply Live");
        var original = await alice.Messages.SendOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            $"reply-root-{Guid.NewGuid():N}");
        var bobOriginal = Assert.Single(await bob.Messages.ReceiveAsync(bobAccount.SessionId));
        var reply = await bob.Messages.SendOneToOneAsync(
            bobAccount.SessionId,
            aliceAccount.SessionId,
            "reply-live",
            replyToMessageId: bobOriginal.Id);
        var aliceReply = Assert.Single(await alice.Messages.ReceiveAsync(aliceAccount.SessionId));
        await alice.Messages.SendReactionOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            aliceReply.Id,
            "👍");
        await bob.Messages.ReceiveAsync(bobAccount.SessionId);
        var bobReply = await ((IMessageRepository)bob.Store).GetAsync(reply.Id);

        Assert.Equal(original.Id, aliceReply.ReplyTo?.MessageId);
        Assert.Equal(original.Body, aliceReply.ReplyTo?.Body);
        Assert.Contains(bobReply!.ReactionItems, reaction =>
            reaction.Emoji == "👍" && reaction.Reactor == aliceAccount.SessionId);
    }

    [Fact]
    public async Task ClientRuntime_RoundTripsAttachmentMetadataThroughLiveFileAndStorage_WhenConfigured()
    {
        var storageUrl = Environment.GetEnvironmentVariable("DEEP_STORAGE_URL");
        var fileUrl = Environment.GetEnvironmentVariable("DEEP_FILE_URL");
        if (string.IsNullOrWhiteSpace(storageUrl) || string.IsNullOrWhiteSpace(fileUrl))
        {
            return;
        }

        var alice = CreateRuntime(storageUrl);
        var bob = CreateRuntime(storageUrl);
        var fileTransport = new HttpAttachmentFileTransport(
            new HttpClient(),
            new HttpAttachmentFileTransportOptions(fileUrl));
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Attachment Live");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Attachment Live");
        var attachmentBytes = Encoding.UTF8.GetBytes($"attachment-live-{Guid.NewGuid():N}");
        await using var upload = new MemoryStream(attachmentBytes);
        var attachment = await fileTransport.UploadAsync(new AttachmentFileUpload("proof.txt", "text/plain", upload));

        await alice.Messages.SendOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            "attachment over storage",
            [attachment]);
        var received = await bob.Messages.ReceiveAsync(bobAccount.SessionId);

        var message = Assert.Single(received, item => item.Body == "attachment over storage");
        var receivedAttachment = Assert.Single(message.Attachments);
        Assert.True(receivedAttachment.IsUploaded);
        Assert.True(receivedAttachment.HasEncryptedPointer);

        var download = await fileTransport.DownloadAsync(receivedAttachment);
        Assert.Equal("proof.txt", download.FileName);
        Assert.Equal("text/plain", download.ContentType);
        Assert.Equal(attachmentBytes, download.Content);
    }

    [Fact]
    public async Task ClientRuntime_SyncsGroupStateAndMessagesThroughLiveStorage_WhenConfigured()
    {
        var storageUrl = Environment.GetEnvironmentVariable("DEEP_STORAGE_URL");
        if (string.IsNullOrWhiteSpace(storageUrl))
        {
            return;
        }

        var alice = CreateRuntime(storageUrl);
        var bob = CreateRuntime(storageUrl);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Group Live");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Group Live");
        var group = await alice.Conversations.CreateGroupScaffoldAsync(
            aliceAccount.SessionId,
            $"live-group-{Guid.NewGuid():N}",
            [bobAccount.SessionId]);

        var bobGroupUpdates = await bob.Conversations.ReceiveGroupUpdatesAsync(bobAccount.SessionId);
        var bobGroup = await bob.Conversations.GetGroupAsync(group.Id);

        Assert.Contains(bobGroupUpdates, update => update.Id == group.Id);
        Assert.NotNull(bobGroup);
        Assert.Equal(group.Name, bobGroup!.Name);
        Assert.Contains(bobGroup.Members, member => member.SessionId == aliceAccount.SessionId && member.Role == GroupMemberRole.Admin);
        Assert.Contains(bobGroup.Members, member => member.SessionId == bobAccount.SessionId);

        var body = $"group-live-message-{Guid.NewGuid():N}";
        var sent = await alice.Messages.SendGroupAsync(aliceAccount.SessionId, group.Id, body);
        var received = await bob.Messages.ReceiveGroupAsync(bobAccount.SessionId, group.Id);

        Assert.Equal(MessageDeliveryState.Sent, sent.DeliveryState);
        Assert.Contains(received, message =>
            message.Body == body &&
            message.ConversationId == group.Id &&
            message.Sender == aliceAccount.SessionId &&
            message.Recipient is null &&
            !string.IsNullOrWhiteSpace(message.ServerHash));

        var bobOriginal = received.Single(message => message.Body == body);
        var reply = await bob.Messages.SendGroupAsync(
            bobAccount.SessionId,
            group.Id,
            "group-live-reply",
            replyToMessageId: bobOriginal.Id);
        var aliceReply = Assert.Single(await alice.Messages.ReceiveGroupAsync(aliceAccount.SessionId, group.Id));
        await alice.Messages.SendGroupReactionAsync(
            aliceAccount.SessionId,
            group.Id,
            aliceReply.Id,
            "❤️");
        await bob.Messages.ReceiveGroupAsync(bobAccount.SessionId, group.Id);
        var bobReply = await ((IMessageRepository)bob.Store).GetAsync(reply.Id);

        Assert.Equal(sent.Id, aliceReply.ReplyTo?.MessageId);
        Assert.Contains(bobReply!.ReactionItems, reaction =>
            reaction.Emoji == "❤️" && reaction.Reactor == aliceAccount.SessionId);
    }

    private static ClientRuntime CreateRuntime(string storageUrl) =>
        new(
            new InMemorySessionStore(),
            ClientFeatureFlags.ReleaseDefaults,
            new SystemClock(),
            new SessionStorageMessageTransport(
                new HttpClient(),
                new SessionStorageMessageTransportOptions(storageUrl)),
            new SessionStorageGroupSyncTransport(
                new HttpClient(),
                new SessionStorageGroupSyncTransportOptions(storageUrl)));
}
