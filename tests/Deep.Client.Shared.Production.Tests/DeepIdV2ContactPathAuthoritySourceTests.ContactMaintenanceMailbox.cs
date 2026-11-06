using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ContactMaintenanceMailbox_OnlyDurablyConsumedRouteControlPageUsesExactIndependentAck(bool coldRetained)
    {
        // Actual native crypto, encrypted local custody, current signed proof
        // and two signed tombstones. In-process services, not socket/device E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RecoverNativeSenderPublicationAsync();
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        byte[] ciphertext;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId)) ciphertext = sent.ExactEnvelope.ToArray();
        var grants = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var terminal = new OwnedReadTerminal(fixture, ciphertext);
        if (coldRetained)
        {
            var account = fixture.ReopenGrantReader();
            var deferred = await account.ReceiveOwnMailboxAsync(fixture.GrantReaderSource(account), grants, terminal);
            Assert.Equal(1, deferred.ProcessedEnvelopes); Assert.True(deferred.AcknowledgementPending);
            Assert.Equal(0, terminal.AckCalls);
            using var retained = await fixture.ReadPeerMailboxReads();
            Assert.Equal(4, retained.Phase); Assert.NotEmpty(retained.Active!.Page);
            fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        }
        var receiverAccount = fixture.ReopenGrantReader();
        var completed = await receiverAccount.ReceiveContactMaintenanceMailboxPageAsync(
            fixture.GrantReaderSource(receiverAccount), grants, terminal);
        Assert.Equal(1, completed.ProcessedEnvelopes); Assert.Equal(1, completed.DurableTombstones);
        Assert.False(completed.HasMore); Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
        using (var consumed = await fixture.ReadPeerMailboxReads()) { Assert.Equal(0, consumed.Phase); Assert.Null(consumed.Active); }
        using (var native = await fixture.ReceiveOwnedMessage(receiver, ciphertext)) Assert.Equal(3, native.RouteProcessing[0]);
        Assert.Empty(await fixture.ListNativeApplicationMessages(receiver));
        var emptyAccount = fixture.ReopenGrantReader();
        var empty = await emptyAccount.ReceiveContactMaintenanceMailboxPageAsync(fixture.GrantReaderSource(emptyAccount), grants, terminal);
        Assert.Equal(0, empty.ProcessedEnvelopes); Assert.Equal(0, empty.DurableTombstones);
        Assert.Equal(2, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ContactMaintenanceMailbox_MixedOriginalPageStaysDeferredAcrossEncryptedColdReopen()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RecoverNativeSenderPublicationAsync();
        using var route = await fixture.CreateOwnedRouteUpdate(sender);
        byte[] controlCiphertext;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, route.OperationId)) controlCiphertext = sent.ExactEnvelope.ToArray();
        using var message = await fixture.CreateOwnedText(sender, "user text remains before explicit ACK");
        byte[] textCiphertext;
        using (var sent = await fixture.SendOwnedMessage(sender, message.OperationId, ApplicationCoreCodec.DecodeDmc2(message.ExactDmc2.Span)))
            textCiphertext = sent.ExactEnvelope.ToArray();
        var grants = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var first = new OwnedReadTerminal(fixture, controlCiphertext);
        var terminal = new ContactMaintenanceMixedTerminal(first, textCiphertext);
        var account = fixture.ReopenGrantReader();
        var deferred = await account.ReceiveContactMaintenanceMailboxPageAsync(fixture.GrantReaderSource(account), grants, terminal);
        Assert.Equal(2, deferred.ProcessedEnvelopes); Assert.Equal(0, deferred.DurableTombstones);
        Assert.Equal(1, first.RetrieveCalls); Assert.Equal(0, terminal.AckCalls);
        byte[] original;
        using (var pending = await fixture.ReadPeerMailboxReads())
        { Assert.Equal(4, pending.Phase); original = pending.Active!.Page.ToArray(); Assert.Empty(pending.Active.AckBody); }
        fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        var coldAccount = fixture.ReopenGrantReader();
        var cold = await coldAccount.ReceiveContactMaintenanceMailboxPageAsync(fixture.GrantReaderSource(coldAccount), grants, terminal);
        Assert.Equal(2, cold.ProcessedEnvelopes); Assert.Equal(0, cold.DurableTombstones);
        Assert.Equal(1, first.RetrieveCalls); Assert.Equal(0, terminal.AckCalls);
        using (var pending = await fixture.ReadPeerMailboxReads())
        {
            Assert.Equal(4, pending.Phase); Assert.Equal(original, pending.Active!.Page);
            Assert.Equal(0UL, pending.Active.AckCounter); Assert.Empty(pending.Active.AckBody);
        }
        Assert.Equal("user text remains before explicit ACK", Assert.Single(await fixture.ListNativeApplicationMessages(receiver)).Text);
    }

    private sealed class ContactMaintenanceMixedTerminal(OwnedReadTerminal first, byte[] secondCiphertext)
        : IDid2OwnedMailboxTransportFactory, IClientMailboxBinaryIngress, IRouteBoundClientMailboxBinaryIngress
    {
        private IMailboxClientDecodePolicyProvider policy = null!;
        internal int AckCalls;
        public IClientMailboxBinaryIngress Create(Did2OwnedMailboxTransportContext context, IMailboxClientDecodePolicyProvider decoder)
        { _ = first.Create(context, decoder); policy = decoder; return this; }
        public async Task<ReadOnlyMemory<byte>> RetrieveOnRouteAsync(ReadOnlyMemory<byte> exact, ScopedMailboxResolvedRoute route, CancellationToken ct)
        {
            var response = await first.RetrieveOnRouteAsync(exact, route, ct);
            var page = MailboxClientCodec.DecodeRetrievePage(response.Span, policy.GetCurrent());
            var original = Assert.Single(page.Items);
            var second = original.Envelope with
            {
                OperationId = Bytes(16, 0xd8), DeduplicationDigest = SHA256.HashData(secondCiphertext), Ciphertext = secondCiphertext.ToArray()
            };
            return MailboxClientCodec.EncodeRetrievePage(page with
            {
                NextCursor = original.Cursor + 1,
                Items = [original, new() { Cursor = original.Cursor + 1, Envelope = second }]
            });
        }
        public Task<ReadOnlyMemory<byte>> AcknowledgeOnRouteAsync(ReadOnlyMemory<byte> exact, ScopedMailboxResolvedRoute route, CancellationToken ct)
        { AckCalls++; throw new InvalidOperationException("Background must retain the complete mixed page for explicit ACK."); }
        public Task<ReadOnlyMemory<byte>> StoreAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ReadOnlyMemory<byte>> RetrieveAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ReadOnlyMemory<byte>> StoreOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct) => throw new InvalidOperationException();
    }
}
