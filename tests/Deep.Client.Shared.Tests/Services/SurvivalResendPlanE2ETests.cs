using System.Collections.Concurrent;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Services;

public sealed class SurvivalResendPlanE2ETests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-11T00:00:00Z");

    [Fact]
    public async Task Restart_rejects_prior_cloud_message_replanned_as_all_direct_before_network()
    {
        var path = TempPath();
        var raw = new RetryRawTransport();
        var policy = new MutablePolicy();
        try
        {
            SessionId sender;
            Message pending;
            using (var runtime = CreateRuntime(path, raw, policy))
            {
                sender = (await runtime.Accounts.RegisterAsync("sender")).SessionId;
                var group = await runtime.Conversations.CreateGroupScaffoldAsync(
                    sender, "survival", [SessionId.CreateNew()]);
                pending = await runtime.Messages.QueueGroupAsync(
                    sender, group.Id, "durable route plan");
                raw.FailNextPreparedDispatch = true;
                await Assert.ThrowsAsync<IOException>(() =>
                    runtime.Messages.DispatchGroupAsync(pending));
                Assert.Equal(
                    MessageDeliveryState.Failed,
                    (await runtime.Store.GetAsync(pending.Id))?.DeliveryState);
            }

            var prepareCount = raw.PrepareCount;
            var directCount = raw.DirectSendCount;
            var cloudCount = raw.CloudSendCount;
            policy.Mode = PolicyMode.AllDirect;
            using (var restarted = CreateRuntime(path, raw, policy))
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    restarted.Messages.RetryOutgoingAsync(sender, pending.Id));
                Assert.Equal(
                    MessageDeliveryState.Failed,
                    (await restarted.Store.GetAsync(pending.Id))?.DeliveryState);
            }

            Assert.Equal(prepareCount, raw.PrepareCount);
            Assert.Equal(directCount, raw.DirectSendCount);
            Assert.Equal(cloudCount, raw.CloudSendCount);
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Fact]
    public async Task Restart_preserves_group_snapshot_and_rejects_added_direct_member_replan()
    {
        var path = TempPath();
        var raw = new RetryRawTransport();
        var policy = new MutablePolicy();
        try
        {
            SessionId sender;
            SessionId originalMember;
            SessionId addedMember;
            Message pending;
            using (var runtime = CreateRuntime(path, raw, policy))
            {
                sender = (await runtime.Accounts.RegisterAsync("sender")).SessionId;
                originalMember = SessionId.CreateNew();
                addedMember = SessionId.CreateNew();
                var group = await runtime.Conversations.CreateGroupScaffoldAsync(
                    sender, "survival membership", [originalMember]);
                pending = await runtime.Messages.QueueGroupAsync(
                    sender, group.Id, "immutable recipients");
                raw.FailNextPreparedDispatch = true;
                await Assert.ThrowsAsync<IOException>(() =>
                    runtime.Messages.DispatchGroupAsync(pending));

                var changedGroup = group.AddMember(new GroupMember(
                    addedMember, GroupMemberRole.Standard, Now)) with
                {
                    Revision = group.Revision + 1
                };
                await ((IGroupRepository)runtime.Store).UpsertAsync(changedGroup);
            }

            var prepareCount = raw.PrepareCount;
            var directCount = raw.DirectSendCount;
            var cloudCount = raw.CloudSendCount;
            policy.Mode = PolicyMode.AddedMemberDirect;
            policy.AddedDirectRecipient = addedMember;
            using (var restarted = CreateRuntime(path, raw, policy))
            {
                var stored = Assert.IsType<Message>(
                    await restarted.Store.GetAsync(pending.Id));
                Assert.Equal([originalMember], stored.NotifyRecipients);

                // Simulate the old retry behavior attempting to replace the durable snapshot
                // with current membership. E2EE's independently persisted full plan must stop it.
                await restarted.Store.UpdateAsync(stored with
                {
                    NotifyRecipients = [originalMember, addedMember]
                });
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    restarted.Messages.RetryOutgoingAsync(sender, pending.Id));
            }

            Assert.Equal(prepareCount, raw.PrepareCount);
            Assert.Equal(directCount, raw.DirectSendCount);
            Assert.Equal(cloudCount, raw.CloudSendCount);
            Assert.DoesNotContain(addedMember, raw.DirectRecipients);
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    private static ClientRuntime CreateRuntime(
        string path,
        RetryRawTransport raw,
        MutablePolicy policy) =>
        ClientRuntime.CreatePersistent(
            path,
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            raw,
            requireE2eeTransport: true,
            mailboxDeliveryPolicy: policy);

    private enum PolicyMode
    {
        AllCloud,
        AllDirect,
        AddedMemberDirect
    }

    private sealed class MutablePolicy : IMailboxDeliveryPolicy
    {
        private static readonly OutboxAccountScope Account =
            OutboxAccountScope.FromBytes(Bytes(32, 0x41));
        private static readonly VerifiedOfficialMailboxAuthority Authority = new(
            Bytes(16, 0x42),
            1,
            [Issuer(MailboxCapabilityDomain.Deposit), Issuer(MailboxCapabilityDomain.Retrieve)],
            false,
            static () => false,
            new EmptyRevocations(),
            new FrozenTimeProvider(Now));

        public PolicyMode Mode { get; set; }
        public SessionId? AddedDirectRecipient { get; set; }

        public Task<MailboxDeliveryDecision> DecideAsync(
            MailboxDeliveryRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Mode == PolicyMode.AllDirect ||
                Mode == PolicyMode.AddedMemberDirect &&
                request.Envelope.Recipient == AddedDirectRecipient)
            {
                return Task.FromResult(new MailboxDeliveryDecision(
                    MailboxTransportProtocol.DirectP2p,
                    MailboxInfrastructureOwnership.DirectP2p,
                    null));
            }
            return Task.FromResult(new MailboxDeliveryDecision(
                MailboxTransportProtocol.AuthenticatedMau2,
                MailboxInfrastructureOwnership.UserManaged,
                Authority,
                new MailboxCredentialSelector(
                    Account,
                    request.Envelope.Recipient == request.Envelope.Sender
                        ? MailboxCredentialScopeKind.Self
                        : MailboxCredentialScopeKind.Peer,
                    System.Security.Cryptography.SHA256.HashData(
                        Encoding.UTF8.GetBytes(request.Envelope.Recipient.Value)),
                    Bytes(32, 0x43))));
        }

        private static MailboxCapabilityIssuerAuthority Issuer(
            MailboxCapabilityDomain domain) => new()
            {
                PublicKey = Bytes(32, 0x44),
                Domain = domain,
                AllowedLifecycle = MailboxCapabilityLifecycle.Active,
                MinimumGeneration = 1,
                MaximumGeneration = ulong.MaxValue,
                ValidFromUnixSeconds = 1,
                ValidUntilUnixSeconds = ulong.MaxValue
            };
    }

    private sealed class RetryRawTransport :
        IResumableMailboxIdentityAuthenticatedRawTransport,
        IDirectP2pSessionMessageTransport,
        IAuthenticatedInboxTransport
    {
        private readonly ConcurrentDictionary<string, OutboundMessageEnvelope[]> prepared =
            new(StringComparer.Ordinal);
        private readonly ConcurrentQueue<SessionId> directRecipients = [];
        private int prepareCount;
        private int directSendCount;
        private int cloudSendCount;
        private int failNextPreparedDispatch;

        public bool FailNextPreparedDispatch
        {
            set => Interlocked.Exchange(ref failNextPreparedDispatch, value ? 1 : 0);
        }

        public int PrepareCount => Volatile.Read(ref prepareCount);
        public int DirectSendCount => Volatile.Read(ref directSendCount);
        public int CloudSendCount => Volatile.Read(ref cloudSendCount);
        public IReadOnlyList<SessionId> DirectRecipients => directRecipients.ToArray();

        public Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>?>
            TryResumeScopedMailboxBatchAsync(
            IMailboxOperationSigner signer,
            MailboxLogicalSendBatch batch,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!prepared.TryGetValue(Key(batch), out var envelopes))
                return Task.FromResult<IReadOnlyList<IPreparedMailboxAuthenticatedSend>?>(null);
            return Task.FromResult<IReadOnlyList<IPreparedMailboxAuthenticatedSend>?>(
                envelopes.Select(static envelope =>
                    (IPreparedMailboxAuthenticatedSend)new Prepared(envelope)).ToArray());
        }

        public Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>
            PrepareScopedMailboxLogicalBatchAsync(
            IMailboxOperationSigner signer,
            MailboxLogicalSendBatch batch,
            IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref prepareCount);
            var envelopes = targets.Select(static target => target.Envelope).ToArray();
            prepared[Key(batch)] = envelopes;
            return Task.FromResult<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>(
                envelopes.Select(static envelope =>
                    (IPreparedMailboxAuthenticatedSend)new Prepared(envelope)).ToArray());
        }

        public Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>
            PrepareScopedMailboxBatchAsync(
            IMailboxOperationSigner signer,
            IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Logical preparation is required.");

        public Task SendPreparedMailboxAuthenticatedAsync(
            IPreparedMailboxAuthenticatedSend preparedSend,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _ = Assert.IsType<Prepared>(preparedSend);
            if (Interlocked.Exchange(ref failNextPreparedDispatch, 0) == 1)
                throw new IOException("synthetic prepared dispatch failure");
            Interlocked.Increment(ref cloudSendCount);
            return Task.CompletedTask;
        }

        public Task SendAsync(
            OutboundMessageEnvelope envelope,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            directRecipients.Enqueue(envelope.Recipient);
            Interlocked.Increment(ref directSendCount);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);

        private static string Key(MailboxLogicalSendBatch batch) =>
            $"{(int)batch.Kind}:{batch.SemanticMessageId.Value}:" +
            string.Join('|', batch.Targets.Select(target =>
                $"{target.WireMessageId.Value}:{Convert.ToHexString(target.Selector.ScopeId.Span)}"));

        private sealed record Prepared(OutboundMessageEnvelope Envelope) :
            IPreparedMailboxAuthenticatedSend;
    }

    private sealed class EmptyRevocations : IFreshMailboxCapabilityRevocationSource
    {
        public void ValidateFreshness() { }
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }

    private sealed class FrozenClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }

    private sealed class FrozenTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static string TempPath() => Path.Combine(
        Path.GetTempPath(), $"deep-survival-resend-{Guid.NewGuid():N}.db");

    private static void DeleteFiles(string path)
    {
        SqliteConnection.ClearAllPools();
        foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            if (File.Exists(candidate))
                File.Delete(candidate);
    }

    private static byte[] Bytes(int count, byte start) =>
        Enumerable.Range(0, count)
            .Select(index => unchecked((byte)(start + index)))
            .ToArray();
}
